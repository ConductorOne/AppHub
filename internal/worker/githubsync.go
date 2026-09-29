// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/githubapp"
)

// githubSyncInterval is how often GitHubSyncer refreshes installations.
// Installation membership changes rarely (an administrator installing or
// uninstalling the app on GitHub), so this is far less frequent than
// Detector's poll -- there is no interactive admin action waiting on it, only
// the Workspace's next page load.
const githubSyncInterval = 5 * time.Minute

// githubSyncTimeout bounds one ListInstallations call.
const githubSyncTimeout = 30 * time.Second

// GitHubAppKeyReader resolves the admin-managed GitHub App's private key.
// Declared here rather than imported from internal/ghappkey so this package
// does not reach the AWS SDK: internal/boundary's aws-sdk-confined rule
// denies it to every package that is not a named provider boundary, and
// worker is not one -- only internal/ghappkey and the composition root ever
// construct the SSM client behind this interface, the same split
// Dispatcher's PreparedSource keeps around Git.
type GitHubAppKeyReader interface {
	Get(ctx context.Context) (credentials.Secret, error)
}

// githubInstallationsAPI is the one githubapp.App capability GitHubSyncer
// needs, narrowed for tests.
type githubInstallationsAPI interface {
	ListInstallations(ctx context.Context) ([]githubapp.Installation, error)
	ListInstallationRepositories(ctx context.Context, installationID int64) ([]string, error)
}

// GitHubSyncer periodically syncs the admin-managed GitHub App's
// installations from GitHub into durable records the Workspace admin UI
// reads.
//
// It runs independently of Dispatcher and Detector for the same reason
// Detector does: this touches no application, deployment, or provider state,
// so it needs none of Dispatcher's fencing or heartbeat machinery.
//
// A tick that finds no App configured yet, or fails to resolve or use its
// key, is silently skipped rather than treated as an error: this syncer
// always runs (cmd/apphub derives its key store automatically, with no
// operator toggle), but most administrators will never get around to
// creating an App at all, and "not yet configured" must read the same as
// "transiently unavailable" from a worker that has no way to distinguish an
// administrator who has not gotten to the Workspace yet from one whose key
// is temporarily unreachable.
type GitHubSyncer struct {
	repo      cp.Repository
	keyReader GitHubAppKeyReader
	newApp    func(appID int64, key credentials.Secret, baseURL string) (githubInstallationsAPI, error)
}

// NewGitHubSyncer constructs a GitHubSyncer. keyReader is typically
// internal/ghappkey.Reader.
func NewGitHubSyncer(repo cp.Repository, keyReader GitHubAppKeyReader) (*GitHubSyncer, error) {
	if repo == nil {
		return nil, errors.New("github syncer requires a repository")
	}
	if keyReader == nil {
		return nil, errors.New("github syncer requires a key reader")
	}
	return &GitHubSyncer{repo: repo, keyReader: keyReader, newApp: func(appID int64, key credentials.Secret, baseURL string) (githubInstallationsAPI, error) {
		return githubapp.NewApp(githubapp.AppConfig{AppID: appID, PrivateKeyPEM: key, BaseURL: baseURL})
	}}, nil
}

// Run polls until ctx is done. It never returns a non-nil error for a single
// failed sync: see the type doc for why a missing or unreachable
// configuration is not this loop's failure to report.
func (g *GitHubSyncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(githubSyncInterval)
	defer ticker.Stop()
	for {
		g.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (g *GitHubSyncer) tick(ctx context.Context) {
	bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
	r, err := g.repo.Read(bounded, cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID})
	cancel()
	if err != nil {
		return
	}
	cfg, err := cp.Decode[cp.GitHubAppConfigRecord](r)
	if err != nil || cfg.AppID <= 0 {
		return
	}

	keyCtx, keyCancel := context.WithTimeout(ctx, persistenceTimeout)
	key, err := g.keyReader.Get(keyCtx)
	keyCancel()
	if err != nil {
		return
	}

	app, err := g.newApp(cfg.AppID, key, cfg.APIBaseURL)
	if err != nil {
		return
	}

	listCtx, listCancel := context.WithTimeout(ctx, githubSyncTimeout)
	installs, err := app.ListInstallations(listCtx)
	listCancel()
	truncated := errors.Is(err, githubapp.ErrInstallationsTruncated)
	if err != nil && !truncated {
		return
	}

	g.upsert(ctx, app, installs)
	if !truncated {
		// A truncated list is not authoritative about what no longer exists;
		// pruning against it would delete a record for an installation that
		// is still there, past the safety cap. See githubapp.ErrInstallationsTruncated.
		g.prune(ctx, installs)
	}
}

func (g *GitHubSyncer) upsert(ctx context.Context, api githubInstallationsAPI, installs []githubapp.Installation) {
	now := time.Now().UTC()
	for _, inst := range installs {
		if ctx.Err() != nil {
			return
		}
		id := strconv.FormatInt(inst.ID, 10)
		recID := cp.RecordID{Kind: cp.GitHubInstallationKind, ID: id}
		bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
		current, readErr := g.repo.Read(bounded, recID)
		cancel()
		var version int64
		var previous []string
		switch {
		case readErr == nil:
			version = current.Version
			if existing, err := cp.Decode[cp.GitHubInstallationRecord](current); err == nil {
				previous = existing.Repositories
			}
		case errors.Is(readErr, cp.ErrNotFound):
			version = 0
		default:
			continue
		}
		repos := previous
		if inst.SuspendedAt == nil {
			listCtx, listCancel := context.WithTimeout(ctx, githubSyncTimeout)
			listed, err := api.ListInstallationRepositories(listCtx, inst.ID)
			listCancel()
			if err == nil {
				repos = listed
				slices.Sort(repos)
			}
		} else {
			repos = nil
		}
		rec := cp.GitHubInstallationRecord{ID: id, InstallationID: inst.ID, AccountLogin: inst.Account.Login, AccountType: inst.Account.Type, RepositorySelection: inst.RepositorySelection, Repositories: repos, Permissions: inst.Permissions, HTMLURL: inst.HTMLURL, SyncedAt: now}
		if inst.SuspendedAt != nil {
			rec.SuspendedAt = inst.SuspendedAt.UTC()
		}
		m, err := cp.Encode(recID, version+1, rec)
		if err != nil {
			continue
		}
		commitCtx, commitCancel := context.WithTimeout(ctx, persistenceTimeout)
		// A CAS loss here means an administrator's ForgetGitHubAppInstallation
		// or a racing sync tick already touched this row; either is fine to
		// drop rather than retry mid-tick.
		_ = g.repo.Commit(commitCtx, []cp.Mutation{{Record: m, ExpectedVersion: version}})
		commitCancel()
	}
}

func (g *GitHubSyncer) prune(ctx context.Context, installs []githubapp.Installation) {
	keep := make(map[string]bool, len(installs))
	for _, inst := range installs {
		keep[strconv.FormatInt(inst.ID, 10)] = true
	}
	bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
	page, err := g.repo.Query(bounded, cp.Query{Kind: cp.GitHubInstallationKind, Limit: 100})
	cancel()
	if err != nil {
		return
	}
	for _, row := range page.Records {
		if ctx.Err() != nil {
			return
		}
		if keep[row.ID] {
			continue
		}
		delCtx, delCancel := context.WithTimeout(ctx, persistenceTimeout)
		_ = g.repo.Commit(delCtx, []cp.Mutation{{Record: cp.Record{RecordID: row.RecordID}, ExpectedVersion: row.Version, Delete: true}})
		delCancel()
	}
}
