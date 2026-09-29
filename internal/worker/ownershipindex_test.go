// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestOwnershipIndexerFilesWhatALegacyApplicationLacks(t *testing.T) {
	f := newWorkerFixture(t)
	indexer, err := NewOwnershipIndexer(f.repo)
	if err != nil {
		t.Fatal(err)
	}
	owner := cp.ApplicationOwner{Kind: cp.OwnerUser, ID: "user-one"}
	if !gone(t, f.repo, cp.OwnerRecordID(f.app.ID, owner)) {
		t.Fatal("the fixture already has an index entry, so this test proves nothing")
	}
	filed, err := indexer.index(context.Background())
	if err != nil || filed != 1 {
		t.Fatalf("first pass filed %d, %v; want 1", filed, err)
	}
	if gone(t, f.repo, cp.OwnerRecordID(f.app.ID, owner)) {
		t.Fatal("the owner's index entry was not filed")
	}
	if filed, err := indexer.index(context.Background()); err != nil || filed != 0 {
		t.Fatalf("second pass filed %d, %v; want nothing left to do", filed, err)
	}
	page, err := f.repo.Query(context.Background(), cp.Query{Kind: cp.ApplicationOwnerKind, OwnerKey: owner.Key()})
	if err != nil || len(page.Records) != 1 || page.Records[0].ParentID != f.app.ID {
		t.Fatalf("the owner's listing = %+v, %v", page, err)
	}
}

func TestAGroupOwnerMayDeploy(t *testing.T) {
	f := newWorkerFixture(t)
	row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID})
	if err != nil {
		t.Fatal(err)
	}
	app := f.application(t)
	app.Owners = []cp.ApplicationOwner{{Kind: cp.OwnerGroup, ID: "grp-platform"}}
	m, err := recordMutation(row, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}
	f.d.eligibility = workerEligibility{groups: []string{"grp-platform"}}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	if dep := f.deployment(t); dep.State != cp.Succeeded {
		t.Fatalf("a requester owning through a group was refused: %s %s", dep.State, dep.ErrorCode)
	}
}

func TestLeavingTheOwningGroupStopsAQueuedDeployment(t *testing.T) {
	f := newWorkerFixture(t)
	row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID})
	if err != nil {
		t.Fatal(err)
	}
	app := f.application(t)
	app.Owners = []cp.ApplicationOwner{{Kind: cp.OwnerGroup, ID: "grp-platform"}}
	m, err := recordMutation(row, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	if dep := f.deployment(t); dep.State != cp.Failed || dep.ErrorCode != "requester_ineligible" {
		t.Fatalf("a requester no longer in the owning group deployed: %s %s", dep.State, dep.ErrorCode)
	}
}
