// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

type fakeDirectoryAPI struct {
	groups    []DirectoryEntitlement
	groupsErr error
}

func (f *fakeDirectoryAPI) ListGroups(context.Context) ([]DirectoryEntitlement, error) {
	return f.groups, f.groupsErr
}

func TestDirectorySyncerSkipsOnGroupsFailure(t *testing.T) {
	repo := testutil.NewRepository()
	seedDirectoryEntitlement(t, repo, "keep-me", true)
	d, err := NewDirectorySyncer(repo, &fakeDirectoryAPI{groupsErr: errors.New("tenant unreachable")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.DirectoryEntitlementKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("a failed sync must not touch what is already stored, got %+v", page.Records)
	}
}

func TestDirectorySyncerUpsertsAndPrunesGroups(t *testing.T) {
	repo := testutil.NewRepository()
	api := &fakeDirectoryAPI{
		groups: []DirectoryEntitlement{
			{ID: "ent-1", DisplayName: "Engineering", AppID: "app-1"},
			{ID: "ent-2", DisplayName: "Platform"},
		},
	}
	d, err := NewDirectorySyncer(repo, api, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())

	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.DirectoryEntitlementKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(page.Records), page.Records)
	}
	byID := map[string]cp.DirectoryEntitlementRecord{}
	for _, rec := range page.Records {
		decoded, err := cp.Decode[cp.DirectoryEntitlementRecord](rec)
		if err != nil {
			t.Fatal(err)
		}
		byID[decoded.ID] = decoded
	}
	if !byID["ent-1"].Bindable || !byID["ent-2"].Bindable {
		t.Error("every synced group must be bindable for role assignment")
	}
	if byID["ent-1"].SyncedAt.IsZero() {
		t.Error("SyncedAt was not set")
	}

	api.groups = []DirectoryEntitlement{{ID: "ent-1", DisplayName: "Engineering", AppID: "app-1"}}
	d.tick(context.Background())
	page, err = repo.Query(context.Background(), cp.Query{Kind: cp.DirectoryEntitlementKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected pruning to leave 1 group, got %d: %+v", len(page.Records), page.Records)
	}
}

func TestDirectorySyncerPrunesMoreThanOneQueryPage(t *testing.T) {
	repo := testutil.NewRepository()
	for i := 0; i < 120; i++ {
		seedDirectoryEntitlement(t, repo, fmt.Sprintf("old-%03d", i), false)
	}
	api := &fakeDirectoryAPI{
		groups: []DirectoryEntitlement{{ID: "ent-1", DisplayName: "Engineering"}},
	}
	d, err := NewDirectorySyncer(repo, api, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.DirectoryEntitlementKind, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	n := len(page.Records)
	if page.Cursor != "" {
		rest, err := repo.Query(context.Background(), cp.Query{Kind: cp.DirectoryEntitlementKind, Limit: 100, Cursor: page.Cursor})
		if err != nil {
			t.Fatal(err)
		}
		n += len(rest.Records)
	}
	if n != 1 {
		t.Fatalf("expected pruning to leave the 1 synced group across pages, got %d", n)
	}
}

func seedDirectoryEntitlement(t *testing.T, repo cp.Repository, id string, bindable bool) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: id}, 0, cp.DirectoryEntitlementRecord{ID: id, DisplayName: "Engineering", Bindable: bindable, SyncedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec}}); err != nil {
		t.Fatal(err)
	}
}

type syncAuditEntry struct {
	actor, action, target string
	details               map[string]string
}

type recordingSyncAudit struct{ entries []syncAuditEntry }

func (r *recordingSyncAudit) AppendAudit(_ context.Context, actor, action, target string, details map[string]string) error {
	r.entries = append(r.entries, syncAuditEntry{actor, action, target, details})
	return nil
}

func TestDirectorySyncerRecordsOneAuditEntryPerRun(t *testing.T) {
	repo := testutil.NewRepository()
	seedDirectoryEntitlement(t, repo, "gone", true)
	api := &fakeDirectoryAPI{groups: []DirectoryEntitlement{{ID: "ent-1"}, {ID: "ent-2"}, {ID: "ent-3"}}}
	audit := &recordingSyncAudit{}
	d, err := NewDirectorySyncer(repo, api, audit)
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())
	d.tick(context.Background())

	if len(audit.entries) != 2 {
		t.Fatalf("audit entries = %+v; want one per run", audit.entries)
	}
	first := audit.entries[0]
	if first.actor != "system" || first.action != cp.DirectorySyncAction || first.target != directorySyncTarget {
		t.Fatalf("summary entry = %+v", first)
	}
	want := map[string]string{"groups": "3", "written": "3", "removed": "1"}
	for k, v := range want {
		if first.details[k] != v {
			t.Fatalf("first run details = %v; want %v", first.details, want)
		}
	}
	if got := audit.entries[1].details["removed"]; got != "0" {
		t.Fatalf("second run removed = %q; want 0, since nothing changed", got)
	}
}

func TestDirectorySyncerRecordsNothingWhenTheDirectoryFails(t *testing.T) {
	audit := &recordingSyncAudit{}
	d, err := NewDirectorySyncer(testutil.NewRepository(), &fakeDirectoryAPI{groupsErr: errors.New("down")}, audit)
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())
	if len(audit.entries) != 0 {
		t.Fatalf("a failed sync recorded %+v", audit.entries)
	}
}
