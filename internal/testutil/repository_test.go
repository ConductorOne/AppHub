// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package testutil_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

func record(t *testing.T, id controlplane.RecordID, value any) controlplane.Record {
	t.Helper()
	r, err := controlplane.Encode(id, 900, value)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func commit(t *testing.T, repo *testutil.Repository, mutations ...controlplane.Mutation) {
	t.Helper()
	if err := repo.Commit(context.Background(), mutations); err != nil {
		t.Fatal(err)
	}
}

func readRecord(t *testing.T, repo *testutil.Repository, id controlplane.RecordID) controlplane.Record {
	t.Helper()
	r, err := repo.Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func userOwner(id string) []controlplane.ApplicationOwner {
	return []controlplane.ApplicationOwner{{Kind: controlplane.OwnerUser, ID: id}}
}

// owned is a new application and its owner index entries, as the service
// commits it on create.
func owned(t *testing.T, id string, owners ...controlplane.ApplicationOwner) []controlplane.Mutation {
	t.Helper()
	app := record(t, controlplane.RecordID{Kind: controlplane.ApplicationKind, ID: id}, controlplane.ApplicationRecord{ID: id, Owners: owners})
	index, err := controlplane.OwnerIndexMutations(id, nil, owners, nil)
	if err != nil {
		t.Fatal(err)
	}
	return append([]controlplane.Mutation{{Record: app}}, index...)
}

func TestCommitRollsBackEntireBatch(t *testing.T) {
	repo := testutil.NewRepository()
	ctx := context.Background()
	userID := controlplane.RecordID{Kind: controlplane.UserKind, ID: "user"}
	user := record(t, userID, controlplane.User{ID: userID.ID})
	commit(t, repo, controlplane.Mutation{Record: user})
	identityID := controlplane.RecordID{Kind: controlplane.IdentityKind, ParentID: "https://issuer.example", ID: "subject"}
	identity := record(t, identityID, controlplane.ExternalIdentity{Issuer: identityID.ParentID, Subject: identityID.ID, UserID: "user"})
	before := readRecord(t, repo, userID)
	err := repo.Commit(ctx, []controlplane.Mutation{
		{Record: identity},
		{Record: user, ExpectedVersion: 2, Delete: true},
	})
	if !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	if _, err := repo.Read(ctx, identityID); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("identity leaked from failed transaction: %v", err)
	}
	after := readRecord(t, repo, userID)
	if after.Version != 1 || !bytes.Equal(before.Value, after.Value) {
		t.Fatal("failed transaction changed user")
	}
	// A duplicate mutation cannot delete then recreate an identity in one batch.
	err = repo.Commit(ctx, []controlplane.Mutation{
		{Record: user, ExpectedVersion: 1, Delete: true},
		{Record: user, ExpectedVersion: 1},
	})
	if err == nil || len(repo.Snapshot()) != 1 || readRecord(t, repo, userID).Version != 1 {
		t.Fatal("duplicate mutation partially applied")
	}
	commit(t, repo, controlplane.Mutation{Record: identity}, controlplane.Mutation{Record: user, ExpectedVersion: 1, Delete: true})
	if _, err := repo.Read(ctx, userID); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("successful transaction retained deleted user: %v", err)
	}
	if readRecord(t, repo, identityID).Version != 1 {
		t.Fatal("caller-supplied version was trusted")
	}
}

func TestConcurrentCASPublishesOneCompleteTransaction(t *testing.T) {
	repo := testutil.NewRepository()
	id := controlplane.RecordID{Kind: controlplane.UserKind, ID: "user"}
	initial := record(t, id, map[string]int{"winner": -1})
	commit(t, repo, controlplane.Mutation{Record: initial})
	const contenders = 24
	batches := make([][]controlplane.Mutation, contenders)
	for i := range batches {
		batches[i] = []controlplane.Mutation{
			{Record: record(t, id, map[string]int{"winner": i}), ExpectedVersion: 1},
			{Record: record(t, controlplane.RecordID{Kind: controlplane.AccessKind, ID: fmt.Sprint(i)}, map[string]int{"winner": i})},
		}
	}
	start := make(chan struct{})
	results := make(chan error, contenders)
	var workers sync.WaitGroup
	for _, batch := range batches {
		workers.Go(func() {
			<-start
			results <- repo.Commit(context.Background(), batch)
		})
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, controlplane.ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful conflicting transactions = %d", winners)
	}
	user := readRecord(t, repo, id)
	if user.Version != 2 {
		t.Fatalf("committed version = %d", user.Version)
	}
	values, err := controlplane.Decode[map[string]int](user)
	if err != nil {
		t.Fatal(err)
	}
	proof := readRecord(t, repo, controlplane.RecordID{Kind: controlplane.AccessKind, ID: fmt.Sprint(values["winner"])})
	if len(repo.Snapshot()) != 2 || !bytes.Equal(proof.Value, user.Value) {
		t.Fatal("winning transaction did not publish both records exclusively")
	}
}

func TestRecordsAreCopyIsolatedAcrossEveryObservation(t *testing.T) {
	repo := testutil.NewRepository()
	id := controlplane.RecordID{Kind: controlplane.ApplicationKind, ID: "app"}
	input := record(t, id, controlplane.ApplicationRecord{ID: id.ID, Owners: userOwner("owner")})
	want := bytes.Clone(input.Value)
	commit(t, repo, controlplane.Mutation{Record: input})
	input.Value[0] = '!'
	observed := readRecord(t, repo, id)
	observed.Value[0] = '?'
	snapshot := repo.Snapshot()
	snapshot[0].Value[0] = '#'
	snapshot[0].Version = 700
	page, err := repo.Query(context.Background(), controlplane.Query{Kind: controlplane.ApplicationKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("application page = %#v", page)
	}
	page.Records[0].Value[0] = '$'
	stored := readRecord(t, repo, id)
	if stored.Version != 1 || !bytes.Equal(stored.Value, want) {
		t.Fatal("a caller mutated persisted data through an alias")
	}
	// New writes must not mutate records already returned to a caller, either.
	update := record(t, id, controlplane.ApplicationRecord{ID: id.ID, Owners: userOwner("other")})
	commit(t, repo, controlplane.Mutation{Record: update, ExpectedVersion: 1})
	if !bytes.Equal(stored.Value, want) {
		t.Fatal("commit changed an earlier observation")
	}
}

func TestIdentityAndDeploymentUniqueness(t *testing.T) {
	repo := testutil.NewRepository()
	for _, issuer := range []string{"https://issuer.example", "https://issuer.example/"} {
		id := controlplane.RecordID{Kind: controlplane.IdentityKind, ParentID: issuer, ID: "ExactSubject"}
		commit(t, repo, controlplane.Mutation{Record: record(t, id, controlplane.ExternalIdentity{Issuer: issuer, Subject: id.ID, UserID: issuer})})
	}
	for _, issuer := range []string{"https://issuer.example", "https://issuer.example/"} {
		id := controlplane.RecordID{Kind: controlplane.IdentityKind, ParentID: issuer, ID: "ExactSubject"}
		identity, err := controlplane.Decode[controlplane.ExternalIdentity](readRecord(t, repo, id))
		if err != nil || identity.UserID != issuer {
			t.Fatalf("exact issuer identity = %#v, %v", identity, err)
		}
		id.ID = "exactsubject"
		if _, err := repo.Read(context.Background(), id); !errors.Is(err, controlplane.ErrNotFound) {
			t.Fatal("subject was normalized")
		}
	}
	id := controlplane.RecordID{Kind: controlplane.DeploymentKind, ParentID: "app", ID: "deploy"}
	deployment := controlplane.DeploymentRecord{ID: id.ID, ApplicationID: id.ParentID, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), State: controlplane.Queued}
	commit(t, repo, controlplane.Mutation{Record: record(t, id, deployment)})
	direct := controlplane.RecordID{Kind: id.Kind, ID: id.ID}
	if readRecord(t, repo, direct).RecordID != id {
		t.Fatal("direct lookup lost deployment parent")
	}
	other := id
	other.ParentID = "other-app"
	deployment.ApplicationID = other.ParentID
	if err := repo.Commit(context.Background(), []controlplane.Mutation{{Record: record(t, other, deployment)}}); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("duplicate global deployment identity = %v", err)
	}
	commit(t, repo, controlplane.Mutation{Record: controlplane.Record{RecordID: id}, ExpectedVersion: 1, Delete: true})
	if _, err := repo.Read(context.Background(), direct); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("deleted deployment direct lookup = %v", err)
	}
}

func TestPaginationPreservesOwnerBoundaryAndDeletionPosition(t *testing.T) {
	repo := testutil.NewRepository()
	for _, app := range []struct{ id, owner string }{{"c", "owner"}, {"a", "owner"}, {"b", "owner"}, {"d", "other"}} {
		commit(t, repo, owned(t, app.id, userOwner(app.owner)...)...)
	}
	query := controlplane.Query{Kind: controlplane.ApplicationOwnerKind, OwnerKey: "user:owner", Limit: 1}
	first, err := repo.Query(context.Background(), query)
	if err != nil || len(first.Records) != 1 || first.Records[0].ParentID != "a" || first.Cursor == "" {
		t.Fatalf("first page = %#v, %v", first, err)
	}
	commit(t, repo, controlplane.Mutation{Record: first.Records[0], ExpectedVersion: 1, Delete: true})
	query.Cursor, query.Limit = first.Cursor, 2
	second, err := repo.Query(context.Background(), query)
	if err != nil || len(second.Records) != 2 || second.Records[0].ParentID != "b" || second.Records[1].ParentID != "c" || second.Cursor != "" {
		t.Fatalf("page after deleted cursor record = %#v, %v", second, err)
	}
	query.OwnerKey = "user:other"
	if _, err := repo.Query(context.Background(), query); err == nil {
		t.Fatal("owner cursor accepted in another scope")
	}
	if _, err := repo.Query(context.Background(), controlplane.Query{Kind: controlplane.ApplicationKind, Cursor: first.Cursor}); err == nil {
		t.Fatal("owner cursor accepted as admin inventory cursor")
	}
}

func TestOutageAndCancellationDoNotPublishWrites(t *testing.T) {
	repo := testutil.NewRepository()
	id := controlplane.RecordID{Kind: controlplane.UserKind, ID: "user"}
	user := record(t, id, controlplane.User{ID: id.ID})
	commit(t, repo, controlplane.Mutation{Record: user})
	repo.SetError(controlplane.ErrUnavailable)
	ctx := context.Background()
	if err := repo.Ready(ctx); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatalf("outage readiness = %v", err)
	}
	if _, err := repo.Read(ctx, id); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatalf("outage read = %v", err)
	}
	if _, err := repo.Query(ctx, controlplane.Query{Kind: controlplane.ApplicationKind}); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatalf("outage query = %v", err)
	}
	mutation := controlplane.Mutation{Record: user, ExpectedVersion: 1, Delete: true}
	if err := repo.Commit(ctx, []controlplane.Mutation{mutation}); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatalf("outage commit = %v", err)
	}
	if snapshot := repo.Snapshot(); len(snapshot) != 1 || snapshot[0].Version != 1 {
		t.Fatalf("outage inspection = %#v", snapshot)
	}
	repo.SetError(nil)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := repo.Commit(cancelled, []controlplane.Mutation{mutation}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled commit = %v", err)
	}
	if readRecord(t, repo, id).Version != 1 {
		t.Fatal("failed delete changed persisted record")
	}
	commit(t, repo, mutation)
	if _, err := repo.Read(ctx, id); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("recovered delete = %v", err)
	}
}

func TestOwnerIndexCommitsWithApplicationAndListsPerKey(t *testing.T) {
	repo := testutil.NewRepository()
	eng := controlplane.ApplicationOwner{Kind: controlplane.OwnerGroup, ID: "eng"}
	for _, id := range []string{"b", "a"} {
		commit(t, repo, owned(t, id, userOwner("alice")[0], eng)...)
	}
	page, err := repo.Query(context.Background(), controlplane.Query{Kind: controlplane.ApplicationOwnerKind, OwnerKey: "group:eng"})
	if err != nil || len(page.Records) != 2 || page.Records[0].ParentID != "a" || page.Records[1].ParentID != "b" {
		t.Fatalf("group listing = %#v, %v", page, err)
	}
	// An existing entry fails the whole batch.
	late := owned(t, "late", userOwner("carol")[0], eng)
	late[2].Record = readRecord(t, repo, controlplane.RecordID{Kind: controlplane.ApplicationOwnerKind, ParentID: "a", ID: "group:eng"})
	if err := repo.Commit(context.Background(), late); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("existing owner entry overwritten: %v", err)
	}
	if _, err := repo.Read(context.Background(), controlplane.RecordID{Kind: controlplane.ApplicationKind, ID: "late"}); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("application committed without its index: %v", err)
	}
	if _, err := repo.Read(context.Background(), controlplane.RecordID{Kind: controlplane.ApplicationOwnerKind, ID: "group:eng"}); err == nil || errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("owner entry read without its application: %v", err)
	}
}

func TestRefusesWhatTheStoreRefusesForOwners(t *testing.T) {
	repo := testutil.NewRepository()
	appID := controlplane.RecordID{Kind: controlplane.ApplicationKind, ID: "app"}
	alice := userOwner("alice")[0]
	tooMany := make([]controlplane.ApplicationOwner, controlplane.MaxApplicationOwners+1)
	for i := range tooMany {
		tooMany[i] = controlplane.ApplicationOwner{Kind: controlplane.OwnerUser, ID: fmt.Sprintf("user-%02d", i)}
	}
	for name, value := range map[string]any{
		"empty":     controlplane.ApplicationRecord{ID: "app"},
		"duplicate": controlplane.ApplicationRecord{ID: "app", Owners: []controlplane.ApplicationOwner{alice, alice}},
		"kind":      controlplane.ApplicationRecord{ID: "app", Owners: []controlplane.ApplicationOwner{{Kind: "robot", ID: "alice"}}},
		"separator": controlplane.ApplicationRecord{ID: "app", Owners: []controlplane.ApplicationOwner{{Kind: controlplane.OwnerGroup, ID: "a#b"}}},
		"too many":  controlplane.ApplicationRecord{ID: "app", Owners: tooMany},
		"legacy":    map[string]string{"id": "app", "ownerUserId": "alice"},
	} {
		if err := repo.Commit(context.Background(), []controlplane.Mutation{{Record: record(t, appID, value)}}); err == nil {
			t.Fatalf("%s owner set accepted", name)
		}
	}
	good := controlplane.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "group:eng", Kind: controlplane.OwnerGroup, OwnerID: "eng"}
	entryID := controlplane.RecordID{Kind: controlplane.ApplicationOwnerKind, ParentID: "app", ID: "group:eng"}
	for name, entry := range map[string]struct {
		id    controlplane.RecordID
		value controlplane.ApplicationOwnerRecord
	}{
		"other application": {entryID, controlplane.ApplicationOwnerRecord{ApplicationID: "other", OwnerKey: good.OwnerKey, Kind: good.Kind, OwnerID: good.OwnerID}},
		"other key":         {entryID, controlplane.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "group:ops", Kind: good.Kind, OwnerID: good.OwnerID}},
		"other kind":        {entryID, controlplane.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: good.OwnerKey, Kind: controlplane.OwnerUser, OwnerID: good.OwnerID}},
		"other owner":       {entryID, controlplane.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: good.OwnerKey, Kind: good.Kind, OwnerID: "ops"}},
		"no application":    {controlplane.RecordID{Kind: controlplane.ApplicationOwnerKind, ID: "group:eng"}, good},
		"unparsed key":      {controlplane.RecordID{Kind: controlplane.ApplicationOwnerKind, ParentID: "app", ID: "eng"}, controlplane.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "eng", Kind: good.Kind, OwnerID: "eng"}},
	} {
		if err := repo.Commit(context.Background(), []controlplane.Mutation{{Record: record(t, entry.id, entry.value)}}); err == nil {
			t.Fatalf("%s owner entry accepted", name)
		}
	}
	for _, unsupported := range []controlplane.Query{
		{Kind: controlplane.ApplicationKind, OwnerUserID: "alice"},
		{Kind: controlplane.ApplicationKind, OwnerKey: "user:alice"},
		{Kind: controlplane.ApplicationOwnerKind},
		{Kind: controlplane.ApplicationOwnerKind, OwnerKey: "alice"},
		{Kind: controlplane.ApplicationOwnerKind, OwnerKey: "user:alice", OwnerUserID: "alice"},
		{Kind: controlplane.SessionKind, OwnerUserID: "alice", OwnerKey: "user:alice"},
	} {
		if _, err := repo.Query(context.Background(), unsupported); err == nil {
			t.Fatalf("unsupported query accepted: %+v", unsupported)
		}
	}
	if len(repo.Snapshot()) != 0 {
		t.Fatal("malformed owner data persisted")
	}
	commit(t, repo, controlplane.Mutation{Record: record(t, entryID, good)})
}
