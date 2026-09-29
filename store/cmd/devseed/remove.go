// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// maxDemoDeployments bounds how many deployments history gives one application.
const maxDemoDeployments = 8

// remove deletes every record seed can have written. Deployment IDs are
// derived, not queried, so nothing that was not seeded can be matched.
func (s *seeder) remove(ctx context.Context, out io.Writer) error {
	apps := 0
	for _, app := range demoApps {
		removed, err := s.removeApplication(ctx, stableID("app:"+app.repo), app.repo)
		if err != nil {
			return fmt.Errorf("remove %q: %w", app.name, err)
		}
		if removed {
			apps++
		}
	}
	users := 0
	for _, u := range demoUsers {
		id := stableID("user:" + u.email + "@" + demoDomain)
		removed, err := s.deleteIfPresent(ctx, id, "user.delete", "user:"+id, []cp.RecordID{{Kind: cp.UserKind, ID: id}})
		if err != nil {
			return fmt.Errorf("remove user %s: %w", u.email, err)
		}
		if removed {
			users++
		}
	}
	_, err := fmt.Fprintf(out, "removed %d application(s) and %d user(s)\n", apps, users)
	return err
}

func (s *seeder) removeApplication(ctx context.Context, id, repo string) (bool, error) {
	row, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.ApplicationKind, ID: id})
	if errors.Is(err, cp.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	app, err := cp.Decode[cp.ApplicationRecord](row)
	if err != nil {
		return false, fmt.Errorf("decode application: %w", err)
	}
	ids := []cp.RecordID{row.RecordID, {Kind: cp.ApplicationUsageKind, ID: id}}
	for k := range maxDemoDeployments {
		ids = append(ids, cp.RecordID{Kind: cp.DeploymentKind, ParentID: id, ID: stableID(fmt.Sprintf("deployment:%s:%d", repo, k))})
	}
	for _, o := range app.Owners {
		ids = append(ids, cp.OwnerRecordID(id, o))
	}
	for _, host := range app.ReservedHostnames {
		ids = append(ids, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: host})
	}
	return s.deleteIfPresent(ctx, app.Owners[0].ID, "application.delete", "application:"+id, ids)
}

// deleteIfPresent deletes whichever of ids exist, in one transaction.
func (s *seeder) deleteIfPresent(ctx context.Context, actor, action, auditTarget string, ids []cp.RecordID) (bool, error) {
	var mutations []cp.Mutation
	for _, id := range ids {
		row, err := s.repo.Read(ctx, id)
		if errors.Is(err, cp.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		mutations = append(mutations, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
	}
	if len(mutations) == 0 {
		return false, nil
	}
	return true, s.repo.Commit(cp.WithAuditContext(ctx, actor, action, auditTarget), mutations)
}
