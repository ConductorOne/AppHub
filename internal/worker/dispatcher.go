// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package worker executes durable deployment operations outside the HTTP process.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/modules"
	"github.com/conductorone/apphub/modules/deploy"
)

// PreparedSource is the operation-scoped source port. Injection is available to
// trusted Go assembly (including hermetic integration), never API/config input.
type PreparedSource interface {
	deploy.SourceFetcher
	Prepare(context.Context, deploy.Source) (string, error)
	Close() error
}

// Dispatcher owns concurrency and operation lifetimes. Its production execution
// path always uses the deploy module and a real, per-operation Git checkout.
type Dispatcher struct {
	cfg         serverconfig.Config
	repo        cp.Repository
	eligibility cp.Eligibility
	providers   map[string]compute.Provider
	targets     map[string]cp.TargetPolicy
	checkout    func() (PreparedSource, error)
	opener      SecretOpener
	provisioner DeploymentProvisioner
	started     atomic.Bool
}

// Option configures optional dispatcher capabilities.
type Option func(*Dispatcher)

// WithSecretOpener lets deployments apply the secret values the control plane
// sealed for them. Without it such a deployment fails before touching the target.
func WithSecretOpener(opener SecretOpener) Option {
	return func(d *Dispatcher) { d.opener = opener }
}

// New assembles a dispatcher for native-identity targets and checks that private
// source checkout creation and cleanup work. Run owns claiming and job lifetimes;
// construction neither fetches source nor deploys cloud resources.
func New(cfg serverconfig.Config, repo cp.Repository, eligibility cp.Eligibility, providers map[string]compute.Provider, targets map[string]cp.TargetPolicy, keyReader GitHubAppKeyReader, opts ...Option) (*Dispatcher, error) {
	d, err := NewWithSourceFactory(cfg, repo, eligibility, providers, targets, func() (PreparedSource, error) {
		return newSourceCheckout(cfg, repo, keyReader)
	}, opts...)
	if err != nil {
		return nil, err
	}
	// Refuse readiness if Git, source policy/keys or the owned work directory are
	// unavailable. This validates construction only; it fetches no repository.
	checkout, err := d.checkout()
	if err != nil {
		// Git missing, the work directory unwritable and a source policy that
		// cannot be read are three different things for an operator to fix.
		return nil, fmt.Errorf("worker source acquisition is unavailable: %w", err)
	}
	if err := checkout.Close(); err != nil {
		return nil, errors.New("worker source directory cleanup is unavailable")
	}
	return d, nil
}

// NewWithSourceFactory replaces only source acquisition. Execution still uses
// the real deployment module, durable repository fencing and supplied provider.
func NewWithSourceFactory(cfg serverconfig.Config, repo cp.Repository, eligibility cp.Eligibility, providers map[string]compute.Provider, targets map[string]cp.TargetPolicy, factory func() (PreparedSource, error), opts ...Option) (*Dispatcher, error) {
	if factory == nil {
		return nil, errors.New("worker source factory is required")
	}
	if repo == nil || eligibility == nil || len(targets) == 0 {
		return nil, errors.New("worker requires repository, eligibility and targets")
	}
	w := &cfg.Worker
	if w.MaxConcurrentDeployments == 0 {
		w.MaxConcurrentDeployments = 2
	}
	if w.DeploymentTimeout == 0 {
		w.DeploymentTimeout = 30 * time.Minute
	}
	if w.TeardownTimeout == 0 {
		w.TeardownTimeout = 60 * time.Minute
	}
	if w.HeartbeatInterval == 0 {
		w.HeartbeatInterval = 10 * time.Second
	}
	if w.StaleAfter == 0 {
		w.StaleAfter = 60 * time.Second
	}
	if w.MaxConcurrentDeployments < 1 || w.DeploymentTimeout <= w.HeartbeatInterval || w.TeardownTimeout <= w.HeartbeatInterval || w.HeartbeatInterval <= 0 || w.StaleAfter <= 2*w.HeartbeatInterval || w.HeartbeatInterval >= 60*time.Second {
		return nil, errors.New("worker concurrency or heartbeat/deployment deadlines are invalid")
	}
	ownedProviders := make(map[string]compute.Provider, len(targets))
	ownedTargets := make(map[string]cp.TargetPolicy, len(targets))
	for id, t := range targets {
		p := providers[id]
		if id == "" || t.ID != id || t.ConfigHash == "" || p == nil || p.Name() == "" || t.DeployConfig.WorkloadIdentityMode != "native" {
			return nil, errors.New("worker target requires a configured provider and native workload identity")
		}
		if err := t.DeployConfig.Validate(); err != nil {
			return nil, errors.New("worker target deployment configuration is invalid")
		}
		c := p.Capabilities()
		if !c.Has(compute.CapImageBuild) || !c.Has(compute.CapImageRegistry) || !c.Has(compute.CapContainerService) {
			return nil, errors.New("worker target lacks source container deployment capabilities")
		}
		t.ResourceSizes = slices.Clone(t.ResourceSizes)
		t.ExecutionModes = slices.Clone(t.ExecutionModes)
		t.Repositories = slices.Clone(t.Repositories)
		t.DeployConfig.AllowedSourceHosts = slices.Clone(t.DeployConfig.AllowedSourceHosts)
		ownedProviders[id], ownedTargets[id] = p, t
	}
	d := &Dispatcher{cfg: cfg, repo: repo, eligibility: eligibility, providers: ownedProviders, targets: ownedTargets}
	d.checkout = factory
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// publish is a strong read/CAS update, not an unconditional readiness overwrite.
// A racing worker/configuration update causes this dispatch cycle to stand down.
func (d *Dispatcher) publish(ctx context.Context) error {
	for id, t := range d.targets {
		key := cp.RecordID{Kind: cp.TargetKind, ID: id}
		row, err := d.repo.Read(ctx, key)
		if errors.Is(err, cp.ErrNotFound) {
			row = cp.Record{RecordID: key}
		} else if err != nil {
			return err
		}
		p := d.providers[id]
		descriptor := cp.TargetDescriptor{ID: id, ProviderName: p.Name(), Capabilities: p.Capabilities(), ConfigHash: t.ConfigHash, HeartbeatAt: time.Now().UTC()}
		mutation, err := recordMutation(row, descriptor)
		if err != nil {
			return err
		}
		commitCtx := ctx
		if row.Version > 0 {
			previous, decodeErr := cp.Decode[cp.TargetDescriptor](row)
			if decodeErr == nil && previous.ProviderName == descriptor.ProviderName &&
				previous.ConfigHash == descriptor.ConfigHash &&
				maps.Equal(previous.Capabilities, descriptor.Capabilities) {
				// Persist the renewed lease, but do not crowd the administrator's
				// audit history with a new row on every unchanged heartbeat.
				commitCtx = cp.WithAuditContext(ctx, "system", "target.heartbeat", "target:"+id)
			}
		}
		if err := d.repo.Commit(commitCtx, []cp.Mutation{mutation}); err != nil {
			return err
		}
	}
	return nil
}

// claim never trusts an eventually consistent queue row. The immutable intent,
// active application lock and matching target descriptor are reread strongly;
// the transaction fences all three before execution starts.
func (d *Dispatcher) claim(ctx context.Context, id string, cancel context.CancelFunc) (*operationStore, error) {
	dr, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.DeploymentKind, ID: id})
	if err != nil {
		return nil, err
	}
	dep, err := cp.Decode[cp.DeploymentRecord](dr)
	if err != nil {
		return nil, err
	}
	if dep.ID != id || dep.State != cp.Queued || dep.AttemptID != "" {
		return nil, cp.ErrConflict
	}
	t, ok := d.targets[dep.TargetID]
	if !ok {
		return nil, cp.ErrConflict
	}
	ar, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.ApplicationKind, ID: dep.ApplicationID})
	if err != nil {
		return nil, err
	}
	app, err := cp.Decode[cp.ApplicationRecord](ar)
	if err != nil {
		return nil, err
	}
	if app.ID != dep.ApplicationID || app.ActiveDeploymentID != dep.ID || app.Revision != dep.ApplicationRevision || app.TargetID != dep.TargetID || dep.Application.ID != app.ID {
		return nil, cp.ErrConflict
	}
	tr, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.TargetKind, ID: t.ID})
	if err != nil {
		return nil, err
	}
	target, err := cp.Decode[cp.TargetDescriptor](tr)
	if err != nil {
		return nil, err
	}
	age := time.Since(target.HeartbeatAt)
	if target.ConfigHash != t.ConfigHash || target.ProviderName != d.providers[t.ID].Name() || age < 0 || age >= 60*time.Second {
		return nil, cp.ErrConflict
	}
	dep.State, dep.AttemptID = cp.Running, cp.NewID()
	dep.StartedAt = time.Now().UTC()
	dep.HeartbeatAt = dep.StartedAt
	dep.StepStartedAt = dep.StartedAt
	if dep.Operation == cp.OperationTeardown {
		dep.Step, dep.Message = "", "Deleting the application."
		// Replanned from what this worker's provider can do and what earlier
		// attempts left, so the plan shown is the work this attempt will do.
		dep.PlannedSteps = cp.PlannedTeardown(d.providers[t.ID].Capabilities(), dep.Artifacts)
	} else {
		dep.Step, dep.Message = "preflight", "Checking deployment prerequisites."
		app.Application.Status = deploy.StatusDeploying
	}
	app.UpdatedAt = dep.StartedAt
	dm, err := recordMutation(dr, dep)
	if err != nil {
		return nil, err
	}
	am, err := recordMutation(ar, app)
	if err != nil {
		return nil, err
	}
	tm, err := recordMutation(tr, target)
	if err != nil {
		return nil, err
	}
	// Prepare the independent snapshot before claiming: allocation failure must
	// not abandon an otherwise executable operation after a committed claim.
	operation, err := newOperationStore(d.repo, app, am.Record, dep, dm.Record, cancel)
	if err != nil {
		return nil, err
	}
	if err := d.repo.Commit(ctx, []cp.Mutation{dm, am, tm}); err != nil {
		return nil, err
	}
	return operation, nil
}

// interrupt uses the observed heartbeat as part of the CAS predicate. A fresh
// heartbeat wins over stale discovery; a truly abandoned attempt keeps its app
// lock and can never be claimed a second time.
func (d *Dispatcher) interrupt(ctx context.Context, id string, now time.Time) error {
	dr, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.DeploymentKind, ID: id})
	if err != nil {
		return err
	}
	dep, err := cp.Decode[cp.DeploymentRecord](dr)
	if err != nil {
		return err
	}
	if dep.State != cp.Running || now.Sub(dep.HeartbeatAt) < d.cfg.Worker.StaleAfter {
		return nil
	}
	ar, err := d.repo.Read(ctx, cp.RecordID{Kind: cp.ApplicationKind, ID: dep.ApplicationID})
	if err != nil {
		return err
	}
	app, err := cp.Decode[cp.ApplicationRecord](ar)
	if err != nil {
		return err
	}
	if app.ActiveDeploymentID != dep.ID || app.Revision != dep.ApplicationRevision {
		return cp.ErrConflict
	}
	if dep.Operation == cp.OperationTeardown {
		// A teardown is idempotent, so a lost worker is a reason to run it
		// again rather than an uncertain outcome needing an operator. The
		// application keeps its lock on this operation either way.
		requeueTeardown(&dep, now, "The worker running this deletion stopped responding.")
		dm, err := recordMutation(dr, dep)
		if err != nil {
			return err
		}
		return d.repo.Commit(ctx, []cp.Mutation{dm})
	}
	dep.State = cp.Interrupted
	dep.SealedSecrets = nil
	dep.ErrorCode = "deployment_interrupted"
	dep.Message = "Worker heartbeat expired. Deployment outcome is uncertain; operator resolution is required."
	dep.FinishedAt = now
	app.Application.Status = deploy.StatusFailed
	app.UpdatedAt = now
	dm, err := recordMutation(dr, dep)
	if err != nil {
		return err
	}
	am, err := recordMutation(ar, app)
	if err != nil {
		return err
	}
	return d.repo.Commit(ctx, []cp.Mutation{dm, am})
}

func (d *Dispatcher) reap(ctx context.Context, cursor string) (string, error) {
	page, err := d.repo.Query(ctx, cp.Query{Kind: cp.DeploymentKind, State: string(cp.Running), Limit: 100, Cursor: cursor})
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	for _, row := range page.Records {
		if err := d.interrupt(ctx, row.ID, now); err != nil && !errors.Is(err, cp.ErrConflict) {
			return "", err
		}
	}
	return page.Cursor, nil
}

func (d *Dispatcher) execute(ctx context.Context, s *operationStore) {
	s.mu.Lock()
	dep, application := s.dep, s.app
	s.mu.Unlock()
	// An unexpected provider panic is an uncertain outcome, never permission to
	// release the execution lock or turn another queue scan into an implicit retry.
	defer func() {
		if recover() != nil {
			_ = s.finish(cp.Interrupted, "deployment_interrupted", "Deployment stopped unexpectedly. Operator resolution is required.")
		}
	}()
	stopHeartbeat := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(d.cfg.Worker.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.heartbeat(ctx); err != nil {
					return
				}
			}
		}
	}()
	defer func() { close(stopHeartbeat); <-heartbeatDone }()

	p, err := d.eligibility.CheckPrincipal(ctx, dep.Requester)
	if err != nil {
		var problem *cp.Error
		if errors.As(err, &problem) && (problem.Status == 401 || problem.Status == 403) {
			_ = s.finish(cp.Failed, "requester_ineligible", "The requester is no longer eligible to deploy.")
		} else {
			_ = s.finish(cp.Failed, "eligibility_unavailable", "Current requester eligibility could not be checked. No deployment was started.")
		}
		return
	}
	original := dep.Requester
	if p.UserID == "" || p.UserID != dep.RequesterUserID || p.UserID != original.UserID || p.ProviderID != original.ProviderID || p.Issuer != original.Issuer || p.Subject != original.Subject || !cp.Owns(p, application) {
		_ = s.finish(cp.Failed, "requester_ineligible", "The requester is no longer authorized to deploy this application.")
		return
	}
	if dep.Operation == cp.OperationTeardown {
		state, code, message := d.teardown(ctx, s, d.providers[dep.TargetID])
		_ = s.finish(state, code, message)
		return
	}
	if len(dep.SealedSecrets) > 0 && d.opener == nil {
		_ = s.finish(cp.Failed, "secrets_unavailable", "This worker cannot decrypt secret values. No deployment was started; set the secrets again once the worker is configured.")
		return
	}
	s.mu.Lock()
	s.opener = d.opener
	s.mu.Unlock()
	target := d.targets[dep.TargetID]
	provider := d.providers[dep.TargetID]
	if _, err := cp.MapApplication(dep.ApplicationID, application.Input, target); err != nil {
		_ = s.finish(cp.Failed, "target_policy_changed", "The requested specification is no longer permitted by target policy.")
		return
	}
	if err := deploy.ValidateApplication(target.DeployConfig, &dep.Application, provider.Name(), provider.Capabilities()); err != nil {
		_ = s.finish(cp.Failed, "invalid_specification", "The requested specification is unsupported by this target.")
		return
	}
	pinned := dep.Application.PinnedImage != ""
	var checkout PreparedSource = pinnedSource{}
	if !pinned {
		if checkout, err = d.checkout(); err != nil {
			_ = s.finish(cp.Failed, "source_unavailable", "Source checkout could not be initialized.")
			return
		}
	}
	// Close source before publishing a terminal outcome. A cleanup failure must
	// retain the operation lock instead of silently leaving a private checkout.
	state, code, message := cp.Interrupted, "deployment_interrupted", "Deployment stopped unexpectedly. Operator resolution is required."
	defer func() {
		if err := checkout.Close(); err != nil {
			state, code, message = cp.Interrupted, "source_cleanup_failed", "Source cleanup could not be confirmed. Operator cleanup and resolution are required."
		}
		_ = s.finish(state, code, message)
	}()
	// A pinned deployment reruns an image already built from this revision's
	// recorded commit: no source is fetched, only the runtime is converged.
	commit := dep.ResolvedCommit
	if !pinned {
		if commit, err = checkout.Prepare(ctx, dep.Application.Source); err != nil {
			state, code, message = cp.Failed, "source_preparation_failed", "The approved repository and requested ref could not be prepared."
			return
		}
	}
	if !fullCommit(commit) {
		state, code, message = cp.Failed, "source_preparation_failed", "Source preparation did not return an exact commit."
		return
	}
	if err := s.prepare(ctx, commit); err != nil {
		state, code, message = cp.Interrupted, "deployment_interrupted", "Source preparation could not be recorded durably."
		return
	}
	module, err := deploy.New(provider, s, checkout, nil, target.DeployConfig, installPostgresExtensions)
	if err != nil {
		state, code, message = cp.Failed, "target_unavailable", "The configured deployment module is unavailable."
		return
	}
	result, runErr := module.Execute(modules.WithProgress(ctx, s.report), p.UserID, map[string]any{"applicationId": dep.ApplicationID})
	if runErr == nil && result != nil && result.Success {
		runErr = d.verifyService(ctx, s, dep.ApplicationID, provider, target)
	}
	if runErr != nil || result == nil || !result.Success {
		resultMessage := ""
		if result != nil {
			resultMessage = result.Message
		}
		slog.Error("deployment failed", "deployment", dep.ID, "application", dep.ApplicationID,
			"result", resultMessage, "err", runErr)
	}
	state, code, message = cp.Failed, "deployment_failed", "Deployment failed. Partial resources may remain."
	if ctx.Err() != nil {
		state, code, message = cp.Interrupted, "deployment_interrupted", "Deployment deadline expired or execution was fenced. Operator resolution is required."
	} else if runErr == nil && result != nil && result.Success {
		if err := d.provisionDeployment(ctx, application, target); err != nil {
			slog.Error("external provisioning failed", "deployment", dep.ID,
				"application", dep.ApplicationID, "err", err)
			state, code, message = cp.Failed, "external_provisioning_failed", "The application is deployed, but external access provisioning failed. Check the integration and redeploy."
			return
		}
		state, code, message = cp.Succeeded, "", "Deployment is ready."
		if dep.Application.Execution == deploy.ExecutionScheduled {
			message = "Schedule installed. Its next execution has not been verified."
		}
	}
}

// pinnedSource stands in for a checkout on a pinned-image deployment. Any
// attempt to use source through it is a bug, so it refuses rather than
// returning an empty directory a build could silently succeed on.
type pinnedSource struct{}

func (pinnedSource) Prepare(context.Context, deploy.Source) (string, error) {
	return "", errors.New("a pinned-image deployment prepares no source")
}
func (pinnedSource) Fetch(context.Context, deploy.Source) (string, error) {
	return "", errors.New("a pinned-image deployment fetches no source")
}
func (pinnedSource) Close() error { return nil }

func fullCommit(commit string) bool {
	if len(commit) != 40 && len(commit) != 64 {
		return false
	}
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (d *Dispatcher) verifyService(ctx context.Context, s *operationStore, id string, provider compute.Provider, target cp.TargetPolicy) error {
	app, err := s.GetApplication(ctx, id)
	if err != nil {
		return err
	}
	if app.Execution == deploy.ExecutionScheduled {
		return nil
	}
	runtime, err := provider.Containers()
	if err != nil {
		return err
	}
	replicas := max(1, app.Replicas)
	ready, err := runtime.WaitForService(ctx, app.Artifacts.Workload, replicas, compute.WaitOptions{Timeout: target.DeployConfig.WaitTimeout})
	if err != nil {
		return err
	}
	if ready == nil || ready.ReadyReplicas < replicas {
		return compute.ErrFailed
	}
	status, err := runtime.DescribeService(ctx, app.Artifacts.Workload)
	if err != nil {
		return err
	}
	if status == nil || status.ReadyReplicas < replicas || status.DesiredReplicas != replicas {
		return compute.ErrFailed
	}
	// Addresses stay as the deploy module recorded them. It keeps only the TLS
	// route hosts the provider reported and renders them as https URLs; the raw
	// RouteAddresses are bare hosts on AWS, which the API then drops as unsafe.
	app.DeployStep = "complete"
	return s.SaveApplication(ctx, app)
}

// Run stops claiming on shutdown and lets each independent, deadline-bounded
// operation finish. After the drain bound it cancels/fences remaining attempts;
// their active locks remain until an operator confirms the old worker stopped.
func (d *Dispatcher) Run(ctx context.Context) error {
	if !d.started.CompareAndSwap(false, true) {
		return errors.New("dispatcher has already been run")
	}
	startup, cancel := context.WithTimeout(ctx, persistenceTimeout)
	err := d.repo.Ready(startup)
	if err == nil {
		err = d.publish(startup)
	}
	cancel()
	if err != nil {
		return fmt.Errorf("worker readiness unavailable: %w", err)
	}
	type runningJob struct {
		store    *operationStore
		cancel   context.CancelFunc
		teardown bool
	}
	active := make(map[string]runningJob)
	done := make(chan string, d.cfg.Worker.MaxConcurrentDeployments)
	scanTicker := time.NewTicker(2 * time.Second)
	defer scanTicker.Stop()
	heartbeatTicker := time.NewTicker(d.cfg.Worker.HeartbeatInterval)
	defer heartbeatTicker.Stop()
	queueCursor, runningCursor := "", ""
	advertise := true
	scan := func() {
		bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
		defer cancel()
		next, err := d.reap(bounded, runningCursor)
		if err != nil {
			runningCursor = ""
			return
		}
		runningCursor = next
		slots := d.cfg.Worker.MaxConcurrentDeployments - len(active)
		if slots <= 0 || !advertise || ctx.Err() != nil {
			return
		}
		page, err := d.repo.Query(bounded, cp.Query{Kind: cp.DeploymentKind, State: string(cp.Queued), Limit: min(100, slots), Cursor: queueCursor})
		if err != nil {
			queueCursor = ""
			return
		}
		queueCursor = page.Cursor
		for _, row := range page.Records {
			if ctx.Err() != nil {
				return
			}
			// This context intentionally does not inherit the server or Run context.
			jobCtx, jobCancel := context.WithTimeout(context.Background(), d.timeout(row))
			operation, err := d.claim(bounded, row.ID, jobCancel)
			if err != nil {
				jobCancel()
				continue
			}
			active[row.ID] = runningJob{store: operation, cancel: jobCancel, teardown: operation.dep.Operation == cp.OperationTeardown}
			go func(id string) { defer jobCancel(); d.execute(jobCtx, operation); done <- id }(row.ID)
		}
	}
	scan()
	for {
		select {
		case id := <-done:
			delete(active, id)
		case <-scanTicker.C:
			scan()
		case <-heartbeatTicker.C:
			bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
			advertise = d.publish(bounded) == nil
			cancel()
		case <-ctx.Done():
			// A teardown is resumable, so it is stopped now and requeued rather
			// than holding shutdown for up to an hour.
			for _, job := range active {
				if job.teardown {
					job.cancel()
				}
			}
			drain := time.NewTimer(d.cfg.Worker.DeploymentTimeout + 2*persistenceTimeout)
			defer drain.Stop()
			for len(active) > 0 {
				select {
				case id := <-done:
					delete(active, id)
				case <-drain.C:
					for _, job := range active {
						job.cancel()
					}
					for _, job := range active {
						_ = job.store.finish(cp.Interrupted, "deployment_interrupted", "Worker shutdown exceeded its drain deadline. Operator resolution is required.")
					}
					return ctx.Err()
				}
			}
			return nil
		}
	}
}
