// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// ownershipIndexInterval is how often OwnershipIndexer rechecks every
// application's owner index. The service writes the index atomically with
// every owner change, so after the first pass this only repairs; an hour is
// plenty.
const ownershipIndexInterval = time.Hour

// ownershipIndexTimeout bounds one pass over every application.
const ownershipIndexTimeout = 5 * time.Minute

// OwnershipIndexer files the ApplicationOwnerKind index entries an
// application's owner set names but the store lacks.
//
// It exists for applications written before owner sets: those carry one
// ownerUserId, read as a one-user owner set (see ApplicationRecord's
// UnmarshalJSON), and have no index entry, so "my applications" would miss
// them. It only ever creates index entries, never touches an application
// record, so it cannot fence a running deployment.
type OwnershipIndexer struct {
	repo cp.Repository
}

// NewOwnershipIndexer builds an indexer over repo.
func NewOwnershipIndexer(repo cp.Repository) (*OwnershipIndexer, error) {
	if repo == nil {
		return nil, errors.New("ownership indexer requires a repository")
	}
	return &OwnershipIndexer{repo: repo}, nil
}

// Run indexes once at start and then every ownershipIndexInterval until ctx
// ends. A failed pass is logged and retried on the next tick.
func (o *OwnershipIndexer) Run(ctx context.Context) error {
	ticker := time.NewTicker(ownershipIndexInterval)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, ownershipIndexTimeout)
		filed, err := o.index(pass)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("ownership index pass failed; retrying next interval", "error", err)
		} else if filed > 0 {
			slog.Info("filed missing application owner index entries", "count", filed)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// index walks every application once and returns how many entries it filed.
func (o *OwnershipIndexer) index(ctx context.Context) (int, error) {
	filed, cursor := 0, ""
	for {
		page, err := o.repo.Query(ctx, cp.Query{Kind: cp.ApplicationKind, Limit: 100, Cursor: cursor})
		if err != nil {
			return filed, err
		}
		for _, row := range page.Records {
			app, err := cp.Decode[cp.ApplicationRecord](row)
			if err != nil {
				return filed, err
			}
			n, err := o.indexApplication(ctx, app)
			filed += n
			if err != nil {
				return filed, err
			}
		}
		if page.Cursor == "" {
			return filed, nil
		}
		cursor = page.Cursor
	}
}

func (o *OwnershipIndexer) indexApplication(ctx context.Context, app cp.ApplicationRecord) (int, error) {
	var missing []cp.ApplicationOwner
	for _, owner := range app.Owners {
		_, err := o.repo.Read(ctx, cp.OwnerRecordID(app.ID, owner))
		if errors.Is(err, cp.ErrNotFound) {
			missing = append(missing, owner)
			continue
		}
		if err != nil {
			return 0, err
		}
	}
	if len(missing) == 0 {
		return 0, nil
	}
	mutations, err := cp.OwnerIndexMutations(app.ID, nil, missing, nil)
	if err != nil {
		return 0, err
	}
	// A conflict means the service or a second worker filed them first.
	if err := o.repo.Commit(ctx, mutations); err != nil && !errors.Is(err, cp.ErrConflict) {
		return 0, err
	}
	return len(missing), nil
}
