// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/conductorone/apphub/compute"
	awscompute "github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/credentials/c1directory"
	"github.com/conductorone/apphub/internal/auth"
	"github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/ghappkey"
	"github.com/conductorone/apphub/internal/httpapi"
	"github.com/conductorone/apphub/internal/logs"
	"github.com/conductorone/apphub/internal/mcpserver"
	"github.com/conductorone/apphub/internal/oauth"
	"github.com/conductorone/apphub/internal/secrethandoff"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/worker"
	"github.com/conductorone/apphub/store"
)

// buildValidationTimeout bounds validating every configured target's build
// substrate, which runs one real build per target.
//
// Ten minutes because the cost is task placement and the builder's image pull,
// not the one-layer build itself, and a cold pull on a small task is minutes.
// It is a ceiling on a deployment that is already broken, not a latency budget:
// a healthy worker leaves it long before it expires.
const buildValidationTimeout = 10 * time.Minute

func hostCommand(mode string, args []string, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", getenv("APPHUB_CONFIG"), "operator YAML configuration path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "apphub: unexpected command arguments")
		return 2
	}
	cfg, err := serverconfig.Load(*configPath, mode)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := host(ctx, mode, cfg, *configPath, stderr); err != nil {
		// The error itself, not only the category. Every error reachable from
		// host is already written for an operator to read -- none of them
		// carry a credential, a subject or a repository -- and without it the
		// only way to tell a missing parameter from an unreachable dependency
		// is to reconstruct the startup sequence by hand from outside.
		_, _ = fmt.Fprintf(stderr, "apphub: startup or service dependency failed: %v\n", err)
		return 1
	}
	return 0
}

// targetPolicies reads only operator policy, never cloud credentials. The same
// nonsecret fingerprint is published by the worker and checked by the API.
func targetPolicies(cfg serverconfig.Config) (map[string]controlplane.TargetPolicy, map[string]awscompute.Config, error) {
	targets := make(map[string]controlplane.TargetPolicy, len(cfg.Targets))
	providers := make(map[string]awscompute.Config, len(cfg.Targets))
	repositories := make([]string, 0, len(cfg.Source.Repositories))
	for _, repo := range cfg.Source.Repositories {
		repositories = append(repositories, repo.URL)
	}
	for id, target := range cfg.Targets {
		cloud, err := awscompute.LoadConfig(target.AWSConfigFile)
		if err != nil {
			return nil, nil, err
		}
		p := controlplane.TargetPolicy{ID: id, Label: target.Label, DeployConfig: target.DeployConfig(), MaxReplicas: target.Policy.MaxReplicas, MaxRelationalCapacityUnits: target.Policy.MaxRelationalCapacityUnits, PublicExposure: target.Policy.PublicExposure, Repositories: repositories}
		for _, size := range target.Policy.ResourceSizes {
			p.ResourceSizes = append(p.ResourceSizes, controlplane.ResourceInput{CPU: size.CPU, Memory: size.Memory})
		}
		for _, mode := range target.Policy.ExecutionModes {
			p.ExecutionModes = append(p.ExecutionModes, string(mode))
		}
		encoded, err := json.Marshal(struct {
			Policy controlplane.TargetPolicy
			AWS    awscompute.Config
		}{p, cloud})
		if err != nil {
			return nil, nil, err
		}
		p.ConfigHash = controlplane.Hash(string(encoded))
		targets[id] = p
		providers[id] = cloud
	}
	return targets, providers, nil
}

// isLoopbackDev reports whether cfg is an explicitly-allowed literal loopback
// HTTP deployment -- the same signal internal/auth.safeEndpoint already uses
// to relax other production-only protections (Secure cookies, HTTPS-only
// endpoints) in this codebase, applied here to pick the GitHub App key
// store's backend instead of an operator toggle.
func isLoopbackDev(cfg serverconfig.Config) bool {
	if !cfg.Auth.AllowLoopbackHTTP {
		return false
	}
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// githubAppKeyLocation derives where the admin-managed GitHub App private
// key lives, entirely from already-mandatory deployment coordinates: there
// is no separate operator toggle for this, and nothing to redeploy to turn
// the capability on or off. A loopback development deployment (isLoopbackDev)
// uses a local file next to the loaded configuration -- see
// ghappkey.LocalConfig, development only. Every other deployment always gets
// an SSM-backed store (encrypted at rest as a SecureString), namespaced by
// this deployment's own DynamoDB table name so two deployments sharing a
// region and account can never collide. The operator's task role for "serve"
// and "worker" must still grant exactly the scoped SSM actions
// internal/ghappkey's package doc describes, against this derived parameter
// path.
func githubAppKeyLocation(cfg serverconfig.Config, configPath string) (ghappkey.Config, ghappkey.LocalConfig, bool) {
	if isLoopbackDev(cfg) {
		return ghappkey.Config{}, ghappkey.LocalConfig{Path: filepath.Join(filepath.Dir(configPath), "github-app-key.json")}, true
	}
	return ghappkey.Config{Region: cfg.Store.Region, ParameterName: "/apphub/" + cfg.Store.TableName + "/github-app/private-key"}, ghappkey.LocalConfig{}, false
}

// logsAdapter satisfies controlplane.LogReader over internal/logs.Reader.
// The two packages declare structurally identical but distinct types
// (LogQuery/Query, LogResult/Result, LogEvent/Event) on purpose -- see
// controlplane.LogReader's doc comment -- so a composition-root adapter is
// what bridges them, rather than controlplane importing internal/logs
// directly and reaching the AWS SDK it is not allowed to.
type logsAdapter struct{ reader *logs.Reader }

func (a logsAdapter) Filter(ctx context.Context, logGroup string, q controlplane.LogQuery) (controlplane.LogResult, error) {
	res, err := a.reader.Filter(ctx, logGroup, logs.Query{Start: q.Start, End: q.End, FilterPattern: q.FilterPattern, NextToken: q.NextToken, Limit: q.Limit})
	if err != nil {
		return controlplane.LogResult{}, err
	}
	events := make([]controlplane.LogEvent, len(res.Events))
	for i, e := range res.Events {
		events[i] = controlplane.LogEvent{Timestamp: e.Timestamp, Message: e.Message, LogStreamName: e.LogStreamName}
	}
	return controlplane.LogResult{Events: events, NextToken: res.NextToken}, nil
}

// directoryAdapter bridges credentials/c1directory.Client into
// worker.DirectoryEntitlement. The two packages declare structurally
// identical but distinct types on purpose -- see worker.DirectoryEntitlement's
// doc comment -- so a composition-root adapter is what bridges them, rather
// than internal/worker importing credentials/c1directory directly and
// carrying ConductorOne idiom internal/boundary's c1-idiom-fenced rule
// confines to credentials/c1 and credentials/c1directory. Exactly the pattern
// logsAdapter uses to keep controlplane free of the AWS SDK.
type directoryAdapter struct{ client c1directory.Client }

func (a directoryAdapter) ListGroups(ctx context.Context) ([]worker.DirectoryEntitlement, error) {
	return adaptDirectoryEntitlements(a.client.ListGroups(ctx))
}

func adaptDirectoryEntitlements(ents []c1directory.Entitlement, err error) ([]worker.DirectoryEntitlement, error) {
	if err != nil {
		return nil, err
	}
	out := make([]worker.DirectoryEntitlement, len(ents))
	for i, e := range ents {
		out[i] = worker.DirectoryEntitlement{ID: e.ID, DisplayName: e.DisplayName, Description: e.Description, AppID: e.AppID}
	}
	return out, nil
}

// groupLookupAdapter resolves per-identity membership against the synced
// group catalog, not the user's entire grant list. Crawling every grant
// for a busy ConductorOne user exceeds Eligibility's 8s admission budget
// and caches a truncated set, so a group-gated feature never matches even
// when the identity holds it.
type groupLookupAdapter struct {
	client c1directory.Client
	repo   controlplane.Repository
}

func (a groupLookupAdapter) ListUserGroupIDs(ctx context.Context, email string) ([]string, error) {
	refs, err := catalogGroupRefs(ctx, a.repo)
	if err != nil {
		return nil, err
	}
	return a.client.ListUserHeldEntitlementIDs(ctx, email, refs)
}

func catalogGroupRefs(ctx context.Context, repo controlplane.Repository) ([]c1directory.EntitlementRef, error) {
	var refs []c1directory.EntitlementRef
	cursor := ""
	for range 200 {
		page, err := repo.Query(ctx, controlplane.Query{Kind: controlplane.DirectoryEntitlementKind, Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, r := range page.Records {
			ent, err := controlplane.Decode[controlplane.DirectoryEntitlementRecord](r)
			if err != nil || !ent.Bindable || ent.ID == "" || ent.AppID == "" {
				continue
			}
			refs = append(refs, c1directory.EntitlementRef{ID: ent.ID, AppID: ent.AppID})
		}
		if page.Cursor == "" {
			return refs, nil
		}
		cursor = page.Cursor
	}
	return refs, nil
}

// newC1DirectoryClient builds the shared ConductorOne directory client from
// the environment, or returns (nil, nil) when directory reads are not
// configured. Both newDirectorySyncer (the org-wide catalog sync) and
// newGroupLookup (per-identity role resolution) build on this one client
// rather than each parsing APPHUB_C1_DIRECTORY_* and dialing separately.
func newC1DirectoryClient() (c1directory.Client, error) {
	cfg, err := c1directory.ConfigFromEnv(os.Getenv)
	if errors.Is(err, c1directory.ErrNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("conductorone directory configuration is incomplete: %w", err)
	}
	return c1directory.NewClient(cfg, c1directory.Deps{Secrets: fileSecrets{}})
}

// newDirectorySyncer constructs a DirectorySyncer, or returns (nil, nil)
// when directory reads are not configured -- most deployments never set
// APPHUB_C1_DIRECTORY_*, and a process that refused to start over an optional
// feature would be the wrong failure mode. Production runs this from the
// worker; loopback serve also runs it so local development does not have to
// stand up a credential-bearing worker just to fill the Role assignment tab.
func newDirectorySyncer(repo controlplane.Repository) (*worker.DirectorySyncer, error) {
	client, err := newC1DirectoryClient()
	if err != nil || client == nil {
		return nil, err
	}
	// The production store records audit entries; a repository that does not
	// (such as a test double) gets a syncer that records no summary.
	audit, _ := repo.(controlplane.AuditWriter)
	return worker.NewDirectorySyncer(repo, directoryAdapter{client}, audit)
}

// newGroupLookup constructs the optional per-identity role-resolution
// dependency auth.Eligibility uses, or returns (nil, nil) when directory
// reads are not configured -- every identity then resolves its
// pre-role-mapping default role, exactly as before this feature existed.
func newGroupLookup(repo controlplane.Repository) (auth.GroupLookup, error) {
	client, err := newC1DirectoryClient()
	if err != nil || client == nil {
		return nil, err
	}
	return groupLookupAdapter{client: client, repo: repo}, nil
}

// serviceObservability builds the optional Workspace admin capabilities:
// GitHub App key storage and the log viewer. Both are nil/empty when the
// operator has not configured them, which NewService treats as "this admin
// surface is disabled" rather than a construction failure -- an adopter who
// never sets GitHubAppAdmin or Observability gets a Workspace with less in
// it, not a service that refuses to start.
func serviceObservability(ctx context.Context, cfg serverconfig.Config, configPath string) ([]controlplane.ServiceOption, error) {
	var opts []controlplane.ServiceOption
	ssmCfg, localCfg, useLocal := githubAppKeyLocation(cfg, configPath)
	if useLocal {
		keyStore, err := ghappkey.NewLocalStore(localCfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, controlplane.WithGitHubAppAdmin(keyStore))
	} else {
		keyStore, err := ghappkey.NewStore(ctx, ssmCfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, controlplane.WithGitHubAppAdmin(keyStore))
	}
	if cfg.Observability.AWSRegion != "" && len(cfg.Observability.LogGroups) > 0 {
		reader, err := logs.NewReader(ctx, cfg.Observability.AWSRegion)
		if err != nil {
			return nil, err
		}
		groups := make([]controlplane.LogGroup, 0, len(cfg.Observability.LogGroups))
		for _, g := range cfg.Observability.LogGroups {
			groups = append(groups, controlplane.LogGroup{Name: g.Name, LogGroup: g.LogGroup})
		}
		opts = append(opts, controlplane.WithLogs(logsAdapter{reader}, groups))
	}
	return opts, nil
}

func host(ctx context.Context, mode string, cfg serverconfig.Config, configPath string, stderr io.Writer) error {
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if cfg.Store.AuditTableName == "" {
		cfg.Store.AuditTableName = cfg.Store.TableName + "-audit"
	}
	client, err := store.New(startup, store.Config{Region: cfg.Store.Region, TableName: cfg.Store.TableName, AuditTableName: cfg.Store.AuditTableName, Endpoint: cfg.Store.Endpoint})
	if err != nil {
		return err
	}
	repo, err := store.NewControlPlaneRecords(client)
	if err != nil {
		return err
	}
	if err := repo.Ready(startup); err != nil {
		return err
	}
	targets, cloudConfigs, err := targetPolicies(cfg)
	if err != nil {
		return err
	}
	if mode == serverconfig.ModeWorker {
		// Not startup's deadline. Validating a target runs a real build on the
		// substrate, which means launching a Fargate task and waiting for it:
		// minutes, dominated by task placement and the builder's image pull.
		// Under a deadline sized for a DynamoDB round trip the build is killed
		// partway and every target is reported as broken, whatever its state.
		validate, cancelValidate := context.WithTimeout(ctx, buildValidationTimeout)
		defer cancelValidate()
		leases, err := worker.NewSlotLeases(repo, workerHolderName())
		if err != nil {
			return err
		}
		providers := make(map[string]compute.Provider, len(cloudConfigs))
		for id, cloud := range cloudConfigs {
			// One runner per target, because each target names its own cluster,
			// its own build task definitions and its own slots. NewFromConfig
			// validates it against the live substrate before returning, so a
			// target whose build tasks carry a task role, mount no access
			// point, or cannot run at all fails here rather than on somebody's
			// first deployment.
			runner, err := awscompute.NewSDKBuildTaskRunner(validate, cloud, cfg.Worker.WorkDir, slotLeaser{leases})
			if err != nil {
				return err
			}
			provider, err := awscompute.NewFromConfig(validate, cloud, runner)
			if err != nil {
				return err
			}
			providers[id] = provider
		}
		groups, err := newGroupLookup(repo)
		if err != nil {
			return err
		}
		// The GitHub App key location is always derived (githubAppKeyLocation):
		// there is no separate operator toggle for this capability, so the
		// syncer always runs. Checkout uses the same reader when the operator
		// source list is empty. It is still harmless against a deployment that
		// has never configured an App at all -- GitHubSyncer.tick and
		// loadAdminGitHubApp skip a missing App or key the same way.
		var keyReader worker.GitHubAppKeyReader
		ssmCfg, localCfg, useLocal := githubAppKeyLocation(cfg, configPath)
		if useLocal {
			keyReader, err = ghappkey.NewLocalReader(localCfg)
			if err != nil {
				return err
			}
		} else {
			keyReader, err = ghappkey.NewReader(startup, ssmCfg)
			if err != nil {
				return err
			}
		}
		var workerOptions []worker.Option
		if arn := cfg.Secrets.HandoffKMSKeyARN; arn != "" {
			opener, err := secrethandoff.NewOpener(startup, arn)
			if err != nil {
				return err
			}
			workerOptions = append(workerOptions, worker.WithSecretOpener(opener))
		}
		provisionConfig, err := c1directory.ConfigFromEnv(os.Getenv)
		if err != nil && !errors.Is(err, c1directory.ErrNotConfigured) {
			return err
		}
		if err == nil {
			provisioner, err := c1directory.NewProvisioner(provisionConfig, c1directory.Deps{Secrets: fileSecrets{}})
			if err != nil {
				return err
			}
			workerOptions = append(workerOptions, worker.WithDeploymentProvisioner(provisioner))
		}
		dispatcher, err := worker.New(cfg, repo, auth.NewEligibility(cfg.Auth, repo, groups), providers, targets, keyReader, workerOptions...)
		if err != nil {
			return err
		}
		detector, err := worker.NewDetector(cfg, repo, keyReader)
		if err != nil {
			return err
		}
		syncer, err := worker.NewGitHubSyncer(repo, keyReader)
		if err != nil {
			return err
		}
		directorySyncer, err := newDirectorySyncer(repo)
		if err != nil {
			return err
		}
		ownershipIndexer, err := worker.NewOwnershipIndexer(repo)
		if err != nil {
			return err
		}
		var trafficSyncer *worker.TrafficSyncer
		if cfg.Traffic.LogGroup != "" {
			region := cfg.Traffic.Region
			if region == "" {
				region = cfg.Store.Region
			}
			reader, err := logs.NewTrafficReader(startup, region, cfg.Traffic.LogGroup)
			if err != nil {
				return err
			}
			if trafficSyncer, err = worker.NewTrafficSyncer(repo, trafficAdapter{reader}); err != nil {
				return err
			}
		}
		// Detector (and GitHubSyncer/DirectorySyncer, when configured) run
		// alongside Dispatcher, not inside it: none shares Dispatcher's
		// application-lock fencing or heartbeat machinery, so each is its own
		// loop over the same worker process rather than a branch inside
		// Dispatcher.Run. Any one returning is fatal to this process, matching
		// dispatcher.Run's prior behavior of being the sole thing worker mode
		// ran.
		// The only thing this process prints when it works. Everything above
		// has been validated against the live substrate, including one real
		// build per target, so a worker that reaches this line is a worker
		// that can deploy -- and one that is merely slow to start is no longer
		// indistinguishable from one that is wedged.
		_, _ = fmt.Fprintf(stderr, "apphub: worker ready; %d target(s), store %s\n",
			len(targets), cfg.Store.TableName)

		runErrs := make(chan error, 6)
		go func() { runErrs <- dispatcher.Run(ctx) }()
		go func() { runErrs <- ownershipIndexer.Run(ctx) }()
		go func() { runErrs <- detector.Run(ctx) }()
		go func() { runErrs <- syncer.Run(ctx) }()
		if directorySyncer != nil {
			go func() { runErrs <- directorySyncer.Run(ctx) }()
		}
		if trafficSyncer != nil {
			go func() { runErrs <- trafficSyncer.Run(ctx) }()
		}
		return <-runErrs
	}
	groups, err := newGroupLookup(repo)
	if err != nil {
		return err
	}
	identity, err := auth.New(startup, cfg, repo, groups)
	if err != nil {
		return err
	}
	authority, err := oauth.New(cfg, repo, identity)
	if err != nil {
		return err
	}
	observability, err := serviceObservability(startup, cfg, configPath)
	if err != nil {
		return err
	}
	serviceOptions := append(observability, controlplane.WithPublicOrigin(cfg.PublicOrigin), controlplane.WithTrafficCollection(cfg.Traffic.LogGroup != ""), controlplane.WithAuditReader(repo), controlplane.WithAuditWriter(repo))
	if arn := cfg.Secrets.HandoffKMSKeyARN; arn != "" {
		sealer, err := secrethandoff.NewSealer(startup, arn)
		if err != nil {
			return err
		}
		serviceOptions = append(serviceOptions, controlplane.WithSecretSealer(sealer))
	}
	service, err := controlplane.NewService(repo, identity, targets, serviceOptions...)
	if err != nil {
		return err
	}
	mux := httpapi.NewMux(cfg.StaticDir, repo.Ready)
	identity.Register(mux)
	authority.Register(mux)
	httpapi.Register(mux, service, identity, authority, cfg.PublicOrigin)
	httpapi.RegisterGitHubWebhook(mux, cfg.GitHub.WebhookSecret)
	remote, err := mcpserver.New(service, authority, cfg.PublicOrigin)
	if err != nil {
		return err
	}
	mux.Handle("/mcp", remote)
	// Production catalog sync belongs to the worker. Loopback development
	// never starts that process (NewFromConfig would have to validate live
	// AWS against the stub provider file), so serve itself runs the same
	// DirectorySyncer when APPHUB_C1_DIRECTORY_* is set. Login-time group
	// lookup already uses this client; without this loop the Role assignment
	// tab stays empty forever and the UI reports the directory as unconfigured.
	if isLoopbackDev(cfg) {
		directorySyncer, err := newDirectorySyncer(repo)
		if err != nil {
			return err
		}
		if directorySyncer != nil {
			go func() { _ = directorySyncer.Run(ctx) }()
		}
	}
	server := httpapi.NewServer(cfg.ListenAddress, mux)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	_, _ = fmt.Fprintf(stderr, "apphub: api ready; listening on %s, %d target(s)\n",
		cfg.ListenAddress, len(targets))
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// trafficAdapter adapts the CloudWatch Logs Insights reader to the worker's
// SDK-free TrafficSource, the same split directoryAdapter makes.
type trafficAdapter struct{ reader *logs.TrafficReader }

func (a trafficAdapter) Hourly(ctx context.Context, start, end time.Time) ([]worker.ServiceHour, error) {
	rows, err := a.reader.Hourly(ctx, start, end)
	if err != nil {
		return nil, err
	}
	out := make([]worker.ServiceHour, 0, len(rows))
	for _, r := range rows {
		out = append(out, worker.ServiceHour{Service: r.Service, Hour: r.Hour, Class: r.Class, Requests: r.Requests, First: r.First, Last: r.Last})
	}
	return out, nil
}
