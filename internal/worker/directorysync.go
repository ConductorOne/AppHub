// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// directorySyncInterval is how often DirectorySyncer refreshes the C1 group
// catalog. Group membership changes rarely enough that there is no
// interactive admin action waiting on it, only the Workspace's next page
// load -- the same reasoning as githubSyncInterval.
const directorySyncInterval = 5 * time.Minute

// directorySyncTimeout bounds one catalog fetch. Pagination of a large tenant
// is several HTTP pages, so this is longer than a single request timeout.
const directorySyncTimeout = 2 * time.Minute

// DirectoryEntitlement is one entry from an operator-configured identity
// directory, narrowed to what DirectorySyncer needs.
//
// Declared here rather than imported from credentials/c1directory so this
// package carries no ConductorOne idiom -- internal/boundary's
// c1-idiom-fenced rule confines that to credentials/c1 and
// credentials/c1directory, and internal/worker is not one of those two. The
// composition root bridges credentials/c1directory.Entitlement into this
// shape, the same pattern cmd/apphub's logsAdapter uses to keep
// internal/controlplane free of the AWS SDK.
type DirectoryEntitlement struct {
	ID, DisplayName, Description, AppID string
}

// directoryAPI is the one capability DirectorySyncer needs from a directory
// source, narrowed for tests.
type directoryAPI interface {
	// ListGroups returns ConductorOne groups (isAutomated entitlements),
	// the catalog Role assignment and feature-flag group pickers read.
	ListGroups(ctx context.Context) ([]DirectoryEntitlement, error)
}

// DirectorySyncer periodically syncs ConductorOne groups into durable
// records the Workspace admin UI reads. The full entitlement catalog is
// not synced: role mappings and group-gated flags are group membership,
// and a tenant's unfiltered entitlement list is too large to be a picker.
//
// It runs independently of Dispatcher and Detector for the same reason
// GitHubSyncer does: this touches no application, deployment, or provider
// state. Most deployments never configure a directory source at all, so a
// nil client (checked at the composition root, mirroring GitHubSyncer's
// optional construction) means this loop is never started rather than
// started to do nothing.
type DirectorySyncer struct {
	repo   cp.Repository
	client directoryAPI
	// audit receives one summary entry per successful sync. Nil records none.
	audit cp.AuditWriter
}

// directorySyncTarget is the audit target of the summary entry. The catalog as
// a whole changed, not one record, so no record ID belongs in it.
const directorySyncTarget = "directory:groups"

// NewDirectorySyncer constructs a DirectorySyncer. client is typically
// credentials/c1directory.Client, adapted to directoryAPI by the composition
// root. audit may be nil, which records no summary entries.
func NewDirectorySyncer(repo cp.Repository, client directoryAPI, audit cp.AuditWriter) (*DirectorySyncer, error) {
	if repo == nil {
		return nil, errors.New("directory syncer requires a repository")
	}
	if client == nil {
		return nil, errors.New("directory syncer requires a directory client")
	}
	return &DirectorySyncer{repo: repo, client: client, audit: audit}, nil
}

// Run polls until ctx is done. It never returns a non-nil error for a single
// failed sync: an unreachable directory is not this loop's failure to
// report, and the Workspace simply shows what it last synced.
func (d *DirectorySyncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(directorySyncInterval)
	defer ticker.Stop()
	for {
		d.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (d *DirectorySyncer) tick(ctx context.Context) {
	listCtx, cancel := context.WithTimeout(ctx, directorySyncTimeout)
	groups, err := d.client.ListGroups(listCtx)
	cancel()
	if err != nil {
		// Keep whatever is already stored; a failed sync is not a reason to
		// wipe it, the same reasoning githubsync.go states for its own tick.
		// The error itself is credhttp-shaped (no tenant URL, no secret): log
		// it so a loopback operator is not left staring at an empty Role
		// assignment tab with no explanation.
		slog.Warn("directory catalog sync failed", "err", err)
		return
	}

	// Label the per-group writes so the store leaves them out of the audit
	// log; the summary below stands for the whole run.
	writeCtx := cp.WithAuditContext(ctx, "system", cp.DirectorySyncAction, directorySyncTarget)
	written := d.upsert(writeCtx, groups)
	removed := d.prune(writeCtx, groups)
	slog.Info("directory catalog synced", "groups", len(groups), "written", written, "removed", removed)
	d.recordSync(ctx, len(groups), written, removed)
}

// recordSync appends the run's single audit entry. It doubles as evidence that
// the worker is running, so it is written even when nothing changed.
func (d *DirectorySyncer) recordSync(ctx context.Context, groups, written, removed int) {
	if d.audit == nil {
		return
	}
	details := map[string]string{
		"groups":  strconv.Itoa(groups),
		"written": strconv.Itoa(written),
		"removed": strconv.Itoa(removed),
	}
	bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
	defer cancel()
	err := d.audit.AppendAudit(bounded, "system", cp.DirectorySyncAction, directorySyncTarget, details)
	if err != nil {
		slog.Warn("directory catalog sync was not recorded in the audit log", "err", err)
	}
}

// upsert writes every group and returns how many writes committed.
func (d *DirectorySyncer) upsert(ctx context.Context, groups []DirectoryEntitlement) int {
	now := time.Now().UTC()
	written := 0
	for _, ent := range groups {
		if ctx.Err() != nil {
			return written
		}
		recID := cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: ent.ID}
		bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
		current, readErr := d.repo.Read(bounded, recID)
		cancel()
		var version int64
		switch {
		case readErr == nil:
			version = current.Version
		case errors.Is(readErr, cp.ErrNotFound):
			version = 0
		default:
			continue
		}
		rec := cp.DirectoryEntitlementRecord{ID: ent.ID, DisplayName: ent.DisplayName, Description: ent.Description, AppID: ent.AppID, Bindable: true, SyncedAt: now}
		m, err := cp.Encode(recID, version+1, rec)
		if err != nil {
			continue
		}
		commitCtx, commitCancel := context.WithTimeout(ctx, persistenceTimeout)
		// A CAS loss here means a racing sync tick already touched this row;
		// fine to drop rather than retry mid-tick, same as GitHubSyncer.
		if d.repo.Commit(commitCtx, []cp.Mutation{{Record: m, ExpectedVersion: version}}) == nil {
			written++
		}
		commitCancel()
	}
	return written
}

// prune deletes groups the directory no longer lists and returns how many
// deletes committed.
func (d *DirectorySyncer) prune(ctx context.Context, groups []DirectoryEntitlement) int {
	keep := make(map[string]bool, len(groups))
	for _, ent := range groups {
		keep[ent.ID] = true
	}
	removed := 0
	cursor := ""
	for range 200 {
		bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
		page, err := d.repo.Query(bounded, cp.Query{Kind: cp.DirectoryEntitlementKind, Limit: 100, Cursor: cursor})
		cancel()
		if err != nil {
			return removed
		}
		for _, row := range page.Records {
			if ctx.Err() != nil {
				return removed
			}
			if keep[row.ID] {
				continue
			}
			delCtx, delCancel := context.WithTimeout(ctx, persistenceTimeout)
			del := cp.Mutation{Record: cp.Record{RecordID: row.RecordID}, ExpectedVersion: row.Version, Delete: true}
			if d.repo.Commit(delCtx, []cp.Mutation{del}) == nil {
				removed++
			}
			delCancel()
		}
		if page.Cursor == "" {
			return removed
		}
		cursor = page.Cursor
	}
	return removed
}
