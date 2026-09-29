// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func cpTestRepository(t *testing.T) (*ControlPlaneRecords, *fakeDynamo) {
	t.Helper()
	fake := newFakeDynamo("control-plane-test")
	repo, err := NewControlPlaneRecords(newTestClient(fake))
	if err != nil {
		t.Fatal(err)
	}
	return repo, fake
}
func cpTestRecord(t *testing.T, id cp.RecordID, value any) cp.Record {
	t.Helper()
	record, err := cp.Encode(id, 0, value)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
func cpTestApplication(t *testing.T, id, owner string) cp.Record {
	t.Helper()
	return cpTestRecord(t, cp.RecordID{Kind: cp.ApplicationKind, ID: id}, cp.ApplicationRecord{ID: id, Owners: []cp.ApplicationOwner{cpTestUser(owner)}, TargetID: "test-target", Revision: 1})
}
func cpTestUser(id string) cp.ApplicationOwner {
	return cp.ApplicationOwner{Kind: cp.OwnerUser, ID: id}
}
func cpTestGroup(id string) cp.ApplicationOwner {
	return cp.ApplicationOwner{Kind: cp.OwnerGroup, ID: id}
}

// cpTestOwned is a new application and its owner index entries, the batch the
// service commits on create.
func cpTestOwned(t *testing.T, id string, owners ...cp.ApplicationOwner) []cp.Mutation {
	t.Helper()
	app := cpTestRecord(t, cp.RecordID{Kind: cp.ApplicationKind, ID: id}, cp.ApplicationRecord{ID: id, Owners: owners, TargetID: "test-target", Revision: 1})
	index, err := cp.OwnerIndexMutations(id, nil, owners, nil)
	if err != nil {
		t.Fatal(err)
	}
	return append([]cp.Mutation{{Record: app}}, index...)
}

// cpTestOwnedIDs lists the applications an owner key owns, through the index.
func cpTestOwnedIDs(t *testing.T, repo *ControlPlaneRecords, key string) []string {
	t.Helper()
	var ids []string
	for _, entry := range cpTestAll(t, repo, cp.Query{Kind: cp.ApplicationOwnerKind, OwnerKey: key}) {
		ids = append(ids, entry.ParentID)
	}
	return ids
}
func cpTestCommit(t *testing.T, repo *ControlPlaneRecords, mutations ...cp.Mutation) {
	t.Helper()
	if err := repo.Commit(context.Background(), mutations); err != nil {
		t.Fatal(err)
	}
}
func cpTestRead(t *testing.T, repo *ControlPlaneRecords, id cp.RecordID) cp.Record {
	t.Helper()
	record, err := repo.Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
func cpTestAll(t *testing.T, repo *ControlPlaneRecords, query cp.Query) []cp.Record {
	t.Helper()
	var records []cp.Record
	for range 100 {
		page, err := repo.Query(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, page.Records...)
		if page.Cursor == "" {
			return records
		}
		query.Cursor = page.Cursor
	}
	t.Fatal("pagination did not terminate")
	return nil
}

func TestControlPlaneParallelIdempotencyIsAtomic(t *testing.T) {
	repo, _ := cpTestRepository(t)
	const writers = 20
	id := cp.RecordID{Kind: cp.IdempotencyKind, ParentID: "owner", ID: "create\x00key-hash"}
	batches := make([][]cp.Mutation, writers)
	for i := range batches {
		appID := fmt.Sprintf("app-%02d", i)
		batches[i] = append(cpTestOwned(t, appID, cpTestUser("owner")),
			cp.Mutation{Record: cpTestRecord(t, id, cp.IdempotencyRecord{PrincipalID: "owner", Operation: "create", RequestHash: "request", ApplicationID: appID})})
	}
	start := make(chan struct{})
	results := make(chan error, writers)
	var wait sync.WaitGroup
	for _, batch := range batches {
		wait.Add(1)
		go func() { defer wait.Done(); <-start; results <- repo.Commit(context.Background(), batch) }()
	}
	close(start)
	wait.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, cp.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != writers-1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
	result, err := cp.Decode[cp.IdempotencyRecord](cpTestRead(t, repo, id))
	if err != nil {
		t.Fatal(err)
	}
	owned := cpTestOwnedIDs(t, repo, "user:owner")
	if len(owned) != 1 || owned[0] != result.ApplicationID {
		t.Fatalf("partial or duplicate application transaction: %+v", owned)
	}
	inventory := cpTestAll(t, repo, cp.Query{Kind: cp.ApplicationKind})
	if len(inventory) != 1 || inventory[0].ID != result.ApplicationID {
		t.Fatalf("directory diverged: %+v", inventory)
	}
}

func TestControlPlaneIdentityClaimDoesNotLeaveLosingUser(t *testing.T) {
	repo, _ := cpTestRepository(t)
	identity := cp.RecordID{Kind: cp.IdentityKind, ParentID: "https://issuer.example", ID: "exact-subject"}
	batch := func(user string) []cp.Mutation {
		return []cp.Mutation{
			{Record: cpTestRecord(t, cp.RecordID{Kind: cp.UserKind, ID: user}, cp.User{ID: user, Email: "same@example.com"})},
			{Record: cpTestRecord(t, identity, cp.ExternalIdentity{UserID: user, Issuer: identity.ParentID, Subject: identity.ID})},
		}
	}
	cpTestCommit(t, repo, batch("first")...)
	if err := repo.Commit(context.Background(), batch("loser")); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("claim error=%v", err)
	}
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.UserKind, ID: "loser"}); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("losing user persisted: %v", err)
	}
	other := cp.RecordID{Kind: cp.IdentityKind, ParentID: "https://other.example", ID: identity.ID}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, other, cp.ExternalIdentity{UserID: "second", Issuer: other.ParentID, Subject: other.ID})})
	first, _ := cp.Decode[cp.ExternalIdentity](cpTestRead(t, repo, identity))
	second, _ := cp.Decode[cp.ExternalIdentity](cpTestRead(t, repo, other))
	if first.UserID == second.UserID {
		t.Fatal("issuer identities merged")
	}
}

func TestControlPlaneCASLossRollsBackReservationsAndDirectory(t *testing.T) {
	repo, _ := cpTestRepository(t)
	app := cpTestApplication(t, "app", "owner")
	cpTestCommit(t, repo, cp.Mutation{Record: app})
	cpTestCommit(t, repo, cp.Mutation{Record: app, ExpectedVersion: 1})
	hostID := cp.RecordID{Kind: cp.HostnameKind, ParentID: "test-target", ID: "claimed"}
	host := cpTestRecord(t, hostID, cp.HostnameReservation{TargetID: hostID.ParentID, Hostname: hostID.ID, ApplicationID: app.ID})
	other := cpTestApplication(t, "other", "owner")
	err := repo.Commit(context.Background(), []cp.Mutation{{Record: host}, {Record: other}, {Record: app, ExpectedVersion: 1}})
	if !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("stale mutation error=%v", err)
	}
	for _, id := range []cp.RecordID{hostID, other.RecordID} {
		if _, err := repo.Read(context.Background(), id); !errors.Is(err, cp.ErrNotFound) {
			t.Fatalf("partial write %v: %v", id, err)
		}
	}
	apps := cpTestAll(t, repo, cp.Query{Kind: cp.ApplicationKind})
	if len(apps) != 1 || apps[0].ID != app.ID || apps[0].Version != 2 {
		t.Fatalf("directory or revision changed: %+v", apps)
	}
	cpTestCommit(t, repo, cp.Mutation{Record: host})
	conflicting := cpTestRecord(t, hostID, cp.HostnameReservation{TargetID: hostID.ParentID, Hostname: hostID.ID, ApplicationID: "other"})
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: conflicting}}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("hostname overwrite=%v", err)
	}
}

func TestControlPlaneDeploymentHistoryDirectLookupAndQueue(t *testing.T) {
	repo, _ := cpTestRepository(t)
	created := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	makeDeployment := func(id string, when time.Time) cp.Record {
		return cpTestRecord(t, cp.RecordID{Kind: cp.DeploymentKind, ID: id, ParentID: "app"}, cp.DeploymentRecord{ID: id, ApplicationID: "app", State: cp.Queued, CreatedAt: when})
	}
	first := makeDeployment("z-first", created.In(time.FixedZone("plus14", 14*60*60)))
	second := makeDeployment("a-second", created.Add(time.Nanosecond))
	cpTestCommit(t, repo, cp.Mutation{Record: second}, cp.Mutation{Record: first})
	history := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, ApplicationID: "app", Limit: 1})
	if len(history) != 2 || history[0].ID != second.ID || history[1].ID != first.ID {
		t.Fatalf("history is not newest first: %+v", history)
	}
	direct := cpTestRead(t, repo, cp.RecordID{Kind: cp.DeploymentKind, ID: first.ID})
	if !reflect.DeepEqual(direct, history[1]) {
		t.Fatalf("direct and history disagree: %+v / %+v", direct, history[1])
	}
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.DeploymentKind, ID: first.ID, ParentID: "wrong"}); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("wrong parent error=%v", err)
	}
	deployment, _ := cp.Decode[cp.DeploymentRecord](direct)
	deployment.State = cp.Running
	running := cpTestRecord(t, first.RecordID, deployment)
	cpTestCommit(t, repo, cp.Mutation{Record: running, ExpectedVersion: 1})
	queued := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, State: string(cp.Queued)})
	active := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, State: string(cp.Running)})
	if len(queued) != 1 || queued[0].ID != second.ID || len(active) != 1 || active[0].ID != first.ID || active[0].Version != 2 {
		t.Fatalf("queue state diverged: queued=%+v active=%+v", queued, active)
	}
	deployment.CreatedAt = deployment.CreatedAt.Add(time.Second)
	changedKey := cpTestRecord(t, first.RecordID, deployment)
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: changedKey, ExpectedVersion: 2}}); err == nil {
		t.Fatal("mutable history timestamp accepted")
	}
	deployment.CreatedAt = created
	deployment.State = cp.Succeeded
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, first.RecordID, deployment), ExpectedVersion: 2})
	if got := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, State: string(cp.Running)}); len(got) != 0 {
		t.Fatalf("terminal deployment remains queued: %+v", got)
	}
	duplicate := deployment
	duplicate.ApplicationID = "other-app"
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: cpTestRecord(t, cp.RecordID{Kind: cp.DeploymentKind, ID: first.ID, ParentID: duplicate.ApplicationID}, duplicate)}}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("duplicate global deployment=%v", err)
	}
	if got := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, ApplicationID: "other-app"}); len(got) != 0 {
		t.Fatal("losing history row persisted")
	}
	cpTestCommit(t, repo, cp.Mutation{Record: cp.Record{RecordID: cp.RecordID{Kind: cp.DeploymentKind, ID: first.ID}}, ExpectedVersion: 3, Delete: true})
	if _, err := repo.Read(context.Background(), first.RecordID); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("direct lookup survived deletion: %v", err)
	}
	remaining := cpTestAll(t, repo, cp.Query{Kind: cp.DeploymentKind, ApplicationID: "app"})
	if len(remaining) != 1 || remaining[0].ID != second.ID {
		t.Fatalf("history survived deletion: %+v", remaining)
	}
}

func TestControlPlanePaginationScopesAndLimits(t *testing.T) {
	repo, fake := cpTestRepository(t)
	for _, id := range []string{"c", "a", "b"} {
		cpTestCommit(t, repo, cpTestOwned(t, id, cpTestUser("owner"))...)
	}
	cpTestCommit(t, repo, cpTestOwned(t, "foreign", cpTestUser("other"))...)
	query := cp.Query{Kind: cp.ApplicationOwnerKind, OwnerKey: "user:owner", Limit: 1}
	page, err := repo.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].ParentID != "a" || page.Cursor == "" {
		t.Fatalf("first page=%+v", page)
	}
	query.Cursor, query.Limit = page.Cursor, 2
	next, err := repo.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Records) != 2 || next.Records[0].ParentID != "b" || next.Records[1].ParentID != "c" || next.Cursor != "" {
		t.Fatalf("next page=%+v", next)
	}
	for _, changed := range []cp.Query{
		{Kind: cp.ApplicationOwnerKind, OwnerKey: "user:other", Cursor: page.Cursor},
		{Kind: cp.ApplicationOwnerKind, OwnerKey: "group:owner", Cursor: page.Cursor},
		{Kind: cp.ApplicationKind, Cursor: page.Cursor},
		{Kind: cp.SessionKind, OwnerUserID: "owner", Cursor: page.Cursor},
		{Kind: cp.ApplicationOwnerKind, OwnerKey: "user:owner", Cursor: "not base64!"},
		{Kind: cp.ApplicationOwnerKind, OwnerKey: "user:owner", Cursor: strings.Repeat("a", cpCursorLimit+1)},
	} {
		if _, err := repo.Query(context.Background(), changed); !errors.Is(err, cp.ErrInvalidCursor) {
			t.Fatalf("invalid cursor accepted: %+v err=%v", changed, err)
		}
	}
	for _, unsupported := range []cp.Query{
		{Kind: cp.ApplicationKind, State: "running"}, {Kind: cp.DeploymentKind}, {Kind: cp.DeploymentKind, State: "succeeded"}, {Kind: cp.SessionKind}, {Kind: cp.ApplicationKind, Limit: 101}, {Kind: cp.ApplicationKind, Limit: -1},
		// The single-owner application listing is gone; the owner index replaces it.
		{Kind: cp.ApplicationKind, OwnerUserID: "owner"}, {Kind: cp.ApplicationKind, OwnerKey: "user:owner"},
		{Kind: cp.ApplicationOwnerKind}, {Kind: cp.ApplicationOwnerKind, OwnerUserID: "owner"}, {Kind: cp.ApplicationOwnerKind, OwnerKey: "user:owner", ApplicationID: "a"},
		{Kind: cp.ApplicationOwnerKind, OwnerKey: "owner"}, {Kind: cp.ApplicationOwnerKind, OwnerKey: "robot:owner"}, {Kind: cp.ApplicationOwnerKind, OwnerKey: "user:"}, {Kind: cp.ApplicationOwnerKind, OwnerKey: "user:a#b"},
		{Kind: cp.SessionKind, OwnerUserID: "owner", OwnerKey: "user:owner"},
	} {
		if _, err := repo.Query(context.Background(), unsupported); err == nil {
			t.Fatalf("unsupported query accepted: %+v", unsupported)
		}
	}
	if fake.callCount("Scan") != 0 {
		t.Fatal("control plane scanned table")
	}
}

// staleControlPlaneDynamo returns a previously observed index snapshot but never
// substitutes for GetItem: owner/state authorization must come from strong reads.
type staleControlPlaneDynamo struct {
	*fakeDynamo
	stale                            []map[string]types.AttributeValue
	getError, queryError, writeError error
	readyDeadline                    time.Time
}

func (f *staleControlPlaneDynamo) GetItem(ctx context.Context, input *dynamodb.GetItemInput, options ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if !aws.ToBool(input.ConsistentRead) {
		return nil, errors.New("authoritative read was not strong")
	}
	if strings.HasPrefix(cpText(input.Key, attrPK), "CONTROLPLANE#") {
		f.readyDeadline, _ = ctx.Deadline()
	}
	if f.getError != nil {
		return nil, f.getError
	}
	return f.fakeDynamo.GetItem(ctx, input, options...)
}
func (f *staleControlPlaneDynamo) Query(ctx context.Context, input *dynamodb.QueryInput, options ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if f.queryError != nil {
		return nil, f.queryError
	}
	if f.stale != nil {
		return &dynamodb.QueryOutput{Items: f.stale}, nil
	}
	return f.fakeDynamo.Query(ctx, input, options...)
}
func (f *staleControlPlaneDynamo) TransactWriteItems(ctx context.Context, input *dynamodb.TransactWriteItemsInput, options ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if f.writeError != nil {
		return nil, f.writeError
	}
	return f.fakeDynamo.TransactWriteItems(ctx, input, options...)
}

func TestControlPlaneStaleOwnerIndexCannotLeakNewOwnerRecord(t *testing.T) {
	repo, fake := cpTestRepository(t)
	oldOwner, newOwner := []cp.ApplicationOwner{cpTestUser("old-owner")}, []cp.ApplicationOwner{cpTestUser("new-owner")}
	cpTestCommit(t, repo, cpTestOwned(t, "app", oldOwner...)...)
	fake.mu.Lock()
	stale := copyItem(fake.items["APP#app"]["OWNER#user:old-owner"])
	fake.mu.Unlock()
	existing := map[string]cp.Record{"user:old-owner": cpTestRead(t, repo, cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "user:old-owner"})}
	index, err := cp.OwnerIndexMutations("app", oldOwner, newOwner, existing)
	if err != nil {
		t.Fatal(err)
	}
	app := cpTestRecord(t, cp.RecordID{Kind: cp.ApplicationKind, ID: "app"}, cp.ApplicationRecord{ID: "app", Owners: newOwner, TargetID: "test-target", Revision: 2})
	cpTestCommit(t, repo, append([]cp.Mutation{{Record: app, ExpectedVersion: 1}}, index...)...)
	seam := &staleControlPlaneDynamo{fakeDynamo: fake, stale: []map[string]types.AttributeValue{stale}}
	repo.client.api = seam
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.ApplicationOwnerKind, OwnerKey: "user:old-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("stale owner index leaked record: %+v", page)
	}
	seam.stale = nil
	if got := cpTestOwnedIDs(t, repo, "user:new-owner"); len(got) != 1 || got[0] != "app" {
		t.Fatalf("new owner entry unavailable: %+v", got)
	}
	if got := cpTestOwnedIDs(t, repo, "user:old-owner"); len(got) != 0 {
		t.Fatalf("removed owner entry survived: %+v", got)
	}
}

func TestControlPlaneErrorsAreUnavailableNotEmptyOrCredentialLeaks(t *testing.T) {
	repo, fake := cpTestRepository(t)
	app := cpTestApplication(t, "app", "owner")
	cpTestCommit(t, repo, cp.Mutation{Record: app})
	seam := &staleControlPlaneDynamo{fakeDynamo: fake}
	repo.client.api = seam
	canary := errors.New("SDK endpoint credential SECRET_CANARY")
	assertUnavailable := func(err error) {
		t.Helper()
		if !errors.Is(err, cp.ErrUnavailable) || strings.Contains(err.Error(), "SECRET_CANARY") {
			t.Fatalf("unsanitized or wrong storage error: %v", err)
		}
	}
	seam.getError = canary
	_, err := repo.Read(context.Background(), app.RecordID)
	assertUnavailable(err)
	_, err = repo.Query(context.Background(), cp.Query{Kind: cp.ApplicationKind})
	assertUnavailable(err)
	assertUnavailable(repo.Ready(context.Background()))
	if seam.readyDeadline.IsZero() || time.Until(seam.readyDeadline) > 3*time.Second {
		t.Fatal("readiness read is unbounded")
	}
	seam.getError = nil
	seam.queryError = canary
	_, err = repo.Query(context.Background(), cp.Query{Kind: cp.ApplicationKind})
	assertUnavailable(err)
	seam.writeError = canary
	assertUnavailable(repo.Commit(context.Background(), []cp.Mutation{{Record: app, ExpectedVersion: 1}}))
	if got := cpTestRead(t, repo, app.RecordID); got.Version != 1 {
		t.Fatal("failed write changed revision")
	}
	seam.queryError, seam.writeError = nil, nil
	if err := repo.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestControlPlaneExpiryIsCleanupNotAuthorization(t *testing.T) {
	repo, _ := cpTestRepository(t)
	expired := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, kind := range []cp.RecordKind{cp.SessionKind, cp.FamilyKind} {
		for _, user := range []string{"owner", "other"} {
			value := map[string]any{"id": "display-" + user, "userId": user, "expiresAt": expired, "revoked": true}
			record := cpTestRecord(t, cp.RecordID{Kind: kind, ID: "hash-" + user}, value)
			cpTestCommit(t, repo, cp.Mutation{Record: record})
		}
		page := cpTestAll(t, repo, cp.Query{Kind: kind, OwnerUserID: "owner"})
		if len(page) != 1 || page[0].ID != "hash-owner" {
			t.Fatalf("expired records hidden or cross-owner listing: %+v", page)
		}
	}
	refresh := cpTestRecord(t, cp.RecordID{Kind: cp.RefreshKind, ID: "consumed-hash"}, cp.OAuthToken{FamilyID: "family", ExpiresAt: expired, Consumed: true})
	cpTestCommit(t, repo, cp.Mutation{Record: refresh})
	read := cpTestRead(t, repo, refresh.RecordID)
	token, err := cp.Decode[cp.OAuthToken](read)
	if err != nil || !token.Consumed {
		t.Fatalf("consumed tombstone lost: %+v %v", token, err)
	}
	item, err := cpItem(read)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := item["TTL"]; exists {
		t.Fatal("refresh tombstone expires before family replay protection")
	}
}

func TestControlPlaneRejectsMalformedAndOversizeRecordsBeforeWriting(t *testing.T) {
	repo, fake := cpTestRepository(t)
	id := cp.RecordID{Kind: cp.LoginKind, ID: "hash"}
	for _, payload := range []json.RawMessage{json.RawMessage("   "), json.RawMessage("[]"), json.RawMessage(`{"expiresAt":"not-a-time"}`), json.RawMessage(`{"data":"` + strings.Repeat("x", cpPayloadLimit) + `"}`)} {
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: cp.Record{RecordID: id, Value: payload}}}); err == nil {
			t.Fatal("malformed or oversized payload accepted")
		}
	}
	large := cpTestRecord(t, cp.RecordID{Kind: cp.ApplicationKind, ID: "app"}, map[string]any{"id": "app", "owners": []cp.ApplicationOwner{cpTestUser("owner")}, "targetId": "target", "input": map[string]string{"name": strings.Repeat("x", cpSpecificationLimit)}})
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: large}}); err == nil {
		t.Fatal("oversized specification accepted")
	}
	if fake.callCount("TransactWriteItems") != 0 {
		t.Fatal("invalid payload reached storage")
	}
	valid := cpTestApplication(t, "valid", "owner")
	cpTestCommit(t, repo, cp.Mutation{Record: valid})
	fake.mu.Lock()
	fake.items["APP#valid"][skMetadata]["Payload"] = cpString(`{"id":"valid","owners":[{"kind":"user","id":"owner"}],"targetId":"target","application":123}`)
	fake.mu.Unlock()
	if _, err := repo.Read(context.Background(), valid.RecordID); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("corrupt record was accepted: %v", err)
	}
}

func TestFakeDynamoTransactionUpdateAndConditionCheckAreAtomic(t *testing.T) {
	fake := newFakeDynamo("test")
	ctx := context.Background()
	item := cpKey("USER#user", skMetadata)
	item["Version"] = cpNumber(1)
	if _, err := fake.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String("test"), Item: item}); err != nil {
		t.Fatal(err)
	}
	update := types.TransactWriteItem{Update: &types.Update{TableName: aws.String("test"), Key: cpKey("USER#user", skMetadata), UpdateExpression: aws.String("SET #v = #v + :one"), ExpressionAttributeNames: map[string]string{"#v": "Version"}, ExpressionAttributeValues: map[string]types.AttributeValue{":one": cpNumber(1)}}}
	check := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String("test"), Key: cpKey("GUARD#guard", skMetadata), ConditionExpression: aws.String("attribute_exists(PK)")}}
	if _, err := fake.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{update, check}}); err == nil {
		t.Fatal("missing guard condition succeeded")
	}
	getVersion := func() string {
		out, err := fake.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String("test"), Key: cpKey("USER#user", skMetadata)})
		if err != nil {
			t.Fatal(err)
		}
		return out.Item["Version"].(*types.AttributeValueMemberN).Value
	}
	if getVersion() != "1" {
		t.Fatal("failed transaction partially applied update")
	}
	if _, err := fake.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String("test"), Item: cpKey("GUARD#guard", skMetadata)}); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{update, check}}); err != nil {
		t.Fatal(err)
	}
	if getVersion() != "2" {
		t.Fatal("successful transaction omitted update")
	}
}

func TestControlPlaneVersionsRemainExactAboveFloatPrecision(t *testing.T) {
	repo, fake := cpTestRepository(t)
	app := cpTestApplication(t, "app", "owner")
	cpTestCommit(t, repo, cp.Mutation{Record: app})
	const version int64 = 1<<53 + 1
	fake.mu.Lock()
	fake.items["APP#app"][skMetadata]["Version"] = cpNumber(version)
	fake.items["APP#app"]["DIRECTORY"]["Version"] = cpNumber(version)
	fake.mu.Unlock()
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: app, ExpectedVersion: version - 1}}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("adjacent stale version accepted: %v", err)
	}
	app.Version = 42
	cpTestCommit(t, repo, cp.Mutation{Record: app, ExpectedVersion: version})
	if got := cpTestRead(t, repo, app.RecordID).Version; got != version+1 {
		t.Fatalf("persisted version=%d, want %d", got, version+1)
	}
}

func TestControlPlaneAbsentDeleteStillChecksVersionZero(t *testing.T) {
	repo, _ := cpTestRepository(t)
	for _, id := range []cp.RecordID{{Kind: cp.ApplicationKind, ID: "app"}, {Kind: cp.DeploymentKind, ID: "deploy"}} {
		cpTestCommit(t, repo, cp.Mutation{Record: cp.Record{RecordID: id}, Delete: true})
	}
	app := cpTestApplication(t, "app", "owner")
	deployment := cpTestRecord(t, cp.RecordID{Kind: cp.DeploymentKind, ID: "deploy", ParentID: "app"}, cp.DeploymentRecord{ID: "deploy", ApplicationID: "app", State: cp.Queued, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	cpTestCommit(t, repo, cp.Mutation{Record: app}, cp.Mutation{Record: deployment})
	for _, record := range []cp.Record{app, deployment} {
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: record, Delete: true}}); !errors.Is(err, cp.ErrConflict) {
			t.Fatalf("version-zero delete removed an existing record: %v", err)
		}
		if got := cpTestRead(t, repo, record.RecordID); got.Version != 1 {
			t.Fatalf("failed deletion changed record: %+v", got)
		}
	}
}

func TestControlPlanePaginationSurvivesDeletedCursorRow(t *testing.T) {
	repo, _ := cpTestRepository(t)
	for _, id := range []string{"a", "b", "c"} {
		cpTestCommit(t, repo, cp.Mutation{Record: cpTestApplication(t, id, "owner")})
	}
	query := cp.Query{Kind: cp.ApplicationKind, Limit: 1}
	page, err := repo.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].ID != "a" || page.Cursor == "" {
		t.Fatalf("unexpected first page: %+v", page)
	}
	cpTestCommit(t, repo, cp.Mutation{Record: page.Records[0], ExpectedVersion: 1, Delete: true})
	query.Cursor = page.Cursor
	remaining := cpTestAll(t, repo, query)
	if len(remaining) != 2 || remaining[0].ID != "b" || remaining[1].ID != "c" {
		t.Fatalf("deleted cursor row broke pagination: %+v", remaining)
	}
}

func TestControlPlaneDetectionQueueAndTerminalRead(t *testing.T) {
	repo, _ := cpTestRepository(t)
	now := time.Now().UTC()
	queued := cp.DetectionRecord{ID: "det-1", RequesterUserID: "user-1", TargetID: "target-1", URL: "https://github.com/example/approved.git", State: cp.DetectionQueued, CreatedAt: now}
	id := cp.RecordID{Kind: cp.DetectionKind, ID: queued.ID}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, id, queued)})

	// A second, unrelated queued detection must not be conflated with the first.
	other := cp.DetectionRecord{ID: "det-2", RequesterUserID: "user-2", TargetID: "target-1", URL: "https://github.com/example/other.git", State: cp.DetectionQueued, CreatedAt: now.Add(time.Second)}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.DetectionKind, ID: other.ID}, other)})

	queuedPage := cpTestAll(t, repo, cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if len(queuedPage) != 2 || queuedPage[0].ID != "det-1" || queuedPage[1].ID != "det-2" {
		t.Fatalf("queue query = %+v", queuedPage)
	}

	// The worker finishes det-1: a CAS transition out of Queued must remove it
	// from the queue directory but keep it directly readable by ID.
	finished := queued
	finished.State, finished.Result.SuggestedPort, finished.FinishedAt = cp.DetectionSucceeded, 8080, now.Add(time.Minute)
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, id, finished), ExpectedVersion: 1})

	afterPage := cpTestAll(t, repo, cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if len(afterPage) != 1 || afterPage[0].ID != "det-2" {
		t.Fatalf("finished detection remained queued: %+v", afterPage)
	}

	read := cpTestRead(t, repo, id)
	decoded, err := cp.Decode[cp.DetectionRecord](read)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.State != cp.DetectionSucceeded || decoded.Result.SuggestedPort != 8080 {
		t.Fatalf("terminal detection not readable by ID: %+v", decoded)
	}
}

func TestControlPlaneGitHubAppConfigSingletonAndInstallationListing(t *testing.T) {
	repo, _ := cpTestRepository(t)

	cfgID := cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}
	cfg := cp.GitHubAppConfigRecord{ID: cp.GitHubAppConfigID, AppID: 12345, PrivateKeyConfigured: true, UpdatedAt: time.Now().UTC(), UpdatedBy: "admin-1"}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cfgID, cfg)})
	readCfg := cpTestRead(t, repo, cfgID)
	decodedCfg, err := cp.Decode[cp.GitHubAppConfigRecord](readCfg)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCfg.AppID != 12345 || !decodedCfg.PrivateKeyConfigured {
		t.Fatalf("unexpected config: %+v", decodedCfg)
	}
	// A second write is a CAS update to the same singleton, not a new record.
	cfg.AppID = 99999
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cfgID, cfg), ExpectedVersion: 1})
	readCfg = cpTestRead(t, repo, cfgID)
	decodedCfg, err = cp.Decode[cp.GitHubAppConfigRecord](readCfg)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCfg.AppID != 99999 {
		t.Fatalf("update did not apply: %+v", decodedCfg)
	}

	for _, id := range []string{"111", "222", "333"} {
		inst := cp.GitHubInstallationRecord{ID: id, InstallationID: 100, AccountLogin: "org-" + id, SyncedAt: time.Now().UTC()}
		cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.GitHubInstallationKind, ID: id}, inst)})
	}
	installs := cpTestAll(t, repo, cp.Query{Kind: cp.GitHubInstallationKind})
	if len(installs) != 3 {
		t.Fatalf("installation listing = %d, want 3", len(installs))
	}
	// Forgetting one locally removes it from the listing.
	cpTestCommit(t, repo, cp.Mutation{Record: installs[0], ExpectedVersion: 1, Delete: true})
	remaining := cpTestAll(t, repo, cp.Query{Kind: cp.GitHubInstallationKind})
	if len(remaining) != 2 {
		t.Fatalf("installation listing after delete = %d, want 2", len(remaining))
	}

	for _, id := range []string{"eng-admins", "eng-readonly"} {
		ent := cp.DirectoryEntitlementRecord{ID: id, DisplayName: "Group " + id, Bindable: true, SyncedAt: time.Now().UTC()}
		cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: id}, ent)})
	}
	entitlements := cpTestAll(t, repo, cp.Query{Kind: cp.DirectoryEntitlementKind})
	if len(entitlements) != 2 {
		t.Fatalf("directory entitlement listing = %d, want 2", len(entitlements))
	}
	cpTestCommit(t, repo, cp.Mutation{Record: entitlements[0], ExpectedVersion: 1, Delete: true})
	remainingEntitlements := cpTestAll(t, repo, cp.Query{Kind: cp.DirectoryEntitlementKind})
	if len(remainingEntitlements) != 1 {
		t.Fatalf("directory entitlement listing after delete = %d, want 1", len(remainingEntitlements))
	}
}

func TestControlPlaneUserDirectoryListingAndLegacyBackfill(t *testing.T) {
	repo, fake := cpTestRepository(t)

	userID := cp.RecordID{Kind: cp.UserKind, ID: "user-1"}
	user := cp.User{ID: "user-1", Email: "dana@acme.dev", Name: "Dana", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, userID, user)})

	listed := cpTestAll(t, repo, cp.Query{Kind: cp.UserKind})
	if len(listed) != 1 || listed[0].ID != "user-1" {
		t.Fatalf("user listing = %+v, want [user-1]", listed)
	}

	// Simulate a user record written before the Users directory companion
	// existed: only its primary row survives.
	delete(fake.items["USER#user-1"], "DIRECTORY")
	if legacy := cpTestAll(t, repo, cp.Query{Kind: cp.UserKind}); len(legacy) != 0 {
		t.Fatalf("legacy user unexpectedly listed before its next write: %+v", legacy)
	}

	// That user's next write (its next sign-in) must still succeed even
	// though the companion row was never created, and must backfill it.
	user.Name = "Dana Whitfield"
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, userID, user), ExpectedVersion: 1})
	readBack := cpTestRead(t, repo, userID)
	decoded, err := cp.Decode[cp.User](readBack)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "Dana Whitfield" {
		t.Fatalf("legacy user update did not apply: %+v", decoded)
	}
	backfilled := cpTestAll(t, repo, cp.Query{Kind: cp.UserKind})
	if len(backfilled) != 1 || backfilled[0].ID != "user-1" {
		t.Fatalf("user listing after backfill = %+v, want [user-1]", backfilled)
	}

	// A third write keeps the primary and companion versions in lockstep, the
	// same strict condition every other companion always enforced.
	user.Name = "D. Whitfield"
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, userID, user), ExpectedVersion: 2})
	if again := cpTestAll(t, repo, cp.Query{Kind: cp.UserKind}); len(again) != 1 {
		t.Fatalf("user listing after third write = %+v, want 1 entry", again)
	}
}

func TestControlPlaneRoleMappingListingAndGroupMembershipDirectRead(t *testing.T) {
	repo, _ := cpTestRepository(t)

	for _, id := range []string{"eng-admins", "eng-readonly"} {
		mapping := cp.RoleMappingRecord{ID: id, Role: cp.RoleAdmin, UpdatedAt: time.Now().UTC(), UpdatedBy: "admin-1"}
		cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.RoleMappingKind, ID: id}, mapping)})
	}
	mappings := cpTestAll(t, repo, cp.Query{Kind: cp.RoleMappingKind})
	if len(mappings) != 2 {
		t.Fatalf("role mapping listing = %d, want 2", len(mappings))
	}
	cpTestCommit(t, repo, cp.Mutation{Record: mappings[0], ExpectedVersion: 1, Delete: true})
	remainingMappings := cpTestAll(t, repo, cp.Query{Kind: cp.RoleMappingKind})
	if len(remainingMappings) != 1 {
		t.Fatalf("role mapping listing after delete = %d, want 1", len(remainingMappings))
	}

	// GroupMembershipKind is read only by its own ID: no listing directory
	// backs it, unlike every kind above.
	memberID := cp.RecordID{Kind: cp.GroupMembershipKind, ID: "dana@acme.dev"}
	membership := cp.GroupMembershipRecord{ID: "dana@acme.dev", GroupIDs: []string{"eng-admins"}, SyncedAt: time.Now().UTC()}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, memberID, membership)})
	readBack := cpTestRead(t, repo, memberID)
	decoded, err := cp.Decode[cp.GroupMembershipRecord](readBack)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.GroupIDs) != 1 || decoded.GroupIDs[0] != "eng-admins" {
		t.Fatalf("unexpected membership: %+v", decoded)
	}
	if _, err := repo.Query(t.Context(), cp.Query{Kind: cp.GroupMembershipKind}); err == nil {
		t.Fatal("GroupMembershipKind accepted an unsupported listing query")
	}
}

func TestControlPlaneGitHubManifestStateReadOnlyByIDAndTTLed(t *testing.T) {
	repo, fake := cpTestRepository(t)

	stateID := cp.RecordID{Kind: cp.GitHubManifestKind, ID: "a1b2c3"}
	now := time.Now().UTC()
	state := cp.GitHubManifestStateRecord{ID: "a1b2c3", UserID: "admin-1", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, stateID, state)})

	readBack := cpTestRead(t, repo, stateID)
	decoded, err := cp.Decode[cp.GitHubManifestStateRecord](readBack)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.UserID != "admin-1" {
		t.Fatalf("unexpected state record: %+v", decoded)
	}

	// It is read only by its own ID -- no listing directory backs it, the
	// same shape as GroupMembershipKind.
	if _, err := repo.Query(t.Context(), cp.Query{Kind: cp.GitHubManifestKind}); err == nil {
		t.Fatal("GitHubManifestKind accepted an unsupported listing query")
	}

	// It carries a DynamoDB TTL derived from ExpiresAt, so an unconsumed
	// token is eventually reclaimed even if CompleteGitHubAppManifest never runs.
	item := fake.items["GHMANIFEST#a1b2c3"][skMetadata]
	if item["TTL"] == nil {
		t.Fatal("GitHubManifestKind record carries no TTL attribute")
	}

	// Single-use: consuming it (the same delete-on-read shape
	// CompleteGitHubAppManifest and internal/auth's login callback both use)
	// leaves nothing for a replayed callback to read.
	cpTestCommit(t, repo, cp.Mutation{Record: readBack, ExpectedVersion: readBack.Version, Delete: true})
	if _, err := repo.Read(t.Context(), stateID); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after consuming the state, got %v", err)
	}
}

func TestControlPlaneFeatureFlagListingAndUpdate(t *testing.T) {
	repo, _ := cpTestRepository(t)

	flag := cp.FeatureFlagRecord{ID: cp.FeatureVulnerabilities, Mode: cp.FeatureFlagGroup, GroupEntitlementIDs: []string{"ent-security", "ent-eng"}, UpdatedAt: time.Now().UTC(), UpdatedBy: "admin-1"}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.FeatureFlagKind, ID: cp.FeatureVulnerabilities}, flag)})

	flags := cpTestAll(t, repo, cp.Query{Kind: cp.FeatureFlagKind})
	if len(flags) != 1 {
		t.Fatalf("feature flag listing = %d, want 1", len(flags))
	}
	decoded, err := cp.Decode[cp.FeatureFlagRecord](flags[0])
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != cp.FeatureFlagGroup || len(decoded.GroupEntitlementIDs) != 2 || decoded.GroupEntitlementIDs[0] != "ent-security" || decoded.GroupEntitlementIDs[1] != "ent-eng" {
		t.Fatalf("unexpected flag: %+v", decoded)
	}

	// A CAS update to the same key, not a new record.
	flag.Mode, flag.GroupEntitlementIDs = cp.FeatureFlagOn, nil
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, cp.RecordID{Kind: cp.FeatureFlagKind, ID: cp.FeatureVulnerabilities}, flag), ExpectedVersion: 1})
	updated := cpTestAll(t, repo, cp.Query{Kind: cp.FeatureFlagKind})
	if len(updated) != 1 {
		t.Fatalf("feature flag listing after update = %d, want 1", len(updated))
	}
	decodedUpdated, err := cp.Decode[cp.FeatureFlagRecord](updated[0])
	if err != nil {
		t.Fatal(err)
	}
	if decodedUpdated.Mode != cp.FeatureFlagOn || len(decodedUpdated.GroupEntitlementIDs) != 0 {
		t.Fatalf("update did not apply: %+v", decodedUpdated)
	}
}

func TestControlPlaneOwnerIndexCommitsWithApplicationAndPagesPerKey(t *testing.T) {
	repo, fake := cpTestRepository(t)
	for _, id := range []string{"c", "a", "b"} {
		cpTestCommit(t, repo, cpTestOwned(t, id, cpTestUser("alice"), cpTestGroup("eng"))...)
	}
	cpTestCommit(t, repo, cpTestOwned(t, "solo", cpTestUser("bob"))...)
	fake.mu.Lock()
	entry := copyItem(fake.items["APP#a"]["OWNER#group:eng"])
	app := copyItem(fake.items["APP#a"][skMetadata])
	fake.mu.Unlock()
	if cpText(entry, "GSI1PK") != "OWNER#group:eng" || cpText(entry, "GSI1SK") != "APP#a" || cpText(entry, "ParentID") != "a" {
		t.Fatalf("owner entry layout: %+v", entry)
	}
	if _, indexed := app["GSI1PK"]; indexed {
		t.Fatal("application row still carries a single-owner index entry")
	}
	query := cp.Query{Kind: cp.ApplicationOwnerKind, OwnerKey: "group:eng", Limit: 2}
	page, err := repo.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 || page.Records[0].ParentID != "a" || page.Records[1].ParentID != "b" || page.Cursor == "" {
		t.Fatalf("first group page=%+v", page)
	}
	entryValue, err := cp.Decode[cp.ApplicationOwnerRecord](page.Records[0])
	if err != nil || entryValue != (cp.ApplicationOwnerRecord{ApplicationID: "a", OwnerKey: "group:eng", Kind: cp.OwnerGroup, OwnerID: "eng"}) {
		t.Fatalf("owner entry value=%+v err=%v", entryValue, err)
	}
	query.Cursor = page.Cursor
	rest, err := repo.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest.Records) != 1 || rest.Records[0].ParentID != "c" || rest.Cursor != "" {
		t.Fatalf("second group page=%+v", rest)
	}
	if got := cpTestOwnedIDs(t, repo, "user:alice"); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("user owner listing=%v", got)
	}
	if got := cpTestOwnedIDs(t, repo, "user:bob"); !reflect.DeepEqual(got, []string{"solo"}) {
		t.Fatalf("other user's listing=%v", got)
	}
	// An index entry that already exists fails the whole batch: the
	// application is not created without its complete owner index.
	conflicting := cpTestOwned(t, "late", cpTestUser("carol"), cpTestGroup("eng"))
	conflicting[2].Record.ParentID, conflicting[2].Record.Value = "a", json.RawMessage(`{"applicationId":"a","ownerKey":"group:eng","kind":"group","ownerId":"eng"}`)
	if err := repo.Commit(context.Background(), conflicting); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("existing owner entry overwritten: %v", err)
	}
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: "late"}); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("application committed without its index: %v", err)
	}
	if got := cpTestOwnedIDs(t, repo, "user:carol"); len(got) != 0 {
		t.Fatalf("partial owner index committed: %v", got)
	}
}

func TestControlPlaneOwnerEntryDeleteChecksVersionAndLeavesListing(t *testing.T) {
	repo, _ := cpTestRepository(t)
	cpTestCommit(t, repo, cpTestOwned(t, "app", cpTestUser("alice"), cpTestGroup("eng"))...)
	id := cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "group:eng"}
	entry := cpTestRead(t, repo, id)
	if entry.Version != 1 {
		t.Fatalf("owner entry version=%d", entry.Version)
	}
	for _, stale := range []int64{0, 2} {
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: entry, ExpectedVersion: stale, Delete: true}}); !errors.Is(err, cp.ErrConflict) {
			t.Fatalf("delete at version %d: %v", stale, err)
		}
	}
	cpTestCommit(t, repo, cp.Mutation{Record: cp.Record{RecordID: id}, ExpectedVersion: 1, Delete: true})
	if _, err := repo.Read(context.Background(), id); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("deleted owner entry readable: %v", err)
	}
	if got := cpTestOwnedIDs(t, repo, "group:eng"); len(got) != 0 {
		t.Fatalf("deleted owner entry listed: %v", got)
	}
	if got := cpTestOwnedIDs(t, repo, "user:alice"); !reflect.DeepEqual(got, []string{"app"}) {
		t.Fatalf("other owner entry lost: %v", got)
	}
	// The entry is addressed only through its application.
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationOwnerKind, ID: "user:alice"}); err == nil || errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("owner entry read without its application: %v", err)
	}
}

func TestControlPlaneRefusesMalformedOwnerSetsAndEntries(t *testing.T) {
	repo, fake := cpTestRepository(t)
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: "app"}
	tooMany := make([]map[string]string, cp.MaxApplicationOwners+1)
	for i := range tooMany {
		tooMany[i] = map[string]string{"kind": "user", "id": fmt.Sprintf("user-%02d", i)}
	}
	for name, owners := range map[string]any{
		"absent":    nil,
		"empty":     []any{},
		"duplicate": []map[string]string{{"kind": "user", "id": "alice"}, {"kind": "user", "id": "alice"}},
		"kind":      []map[string]string{{"kind": "robot", "id": "alice"}},
		"blank id":  []map[string]string{{"kind": "group", "id": ""}},
		"separator": []map[string]string{{"kind": "group", "id": "a#b"}},
		"long key":  []map[string]string{{"kind": "group", "id": strings.Repeat("g", 256)}},
		"too many":  tooMany,
		"not array": "user:alice",
	} {
		value := map[string]any{"id": "app", "targetId": "test-target"}
		if owners != nil {
			value["owners"] = owners
		}
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: cpTestRecord(t, appID, value)}}); err == nil {
			t.Fatalf("%s owner set accepted", name)
		}
	}
	for name, value := range map[string]map[string]any{
		"legacy only": {"id": "app", "targetId": "test-target", "ownerUserId": "alice"},
		"both":        {"id": "app", "targetId": "test-target", "ownerUserId": "alice", "owners": []cp.ApplicationOwner{cpTestUser("alice")}},
	} {
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: cpTestRecord(t, appID, value)}}); err == nil {
			t.Fatalf("%s application written", name)
		}
	}
	good := cp.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "group:eng", Kind: cp.OwnerGroup, OwnerID: "eng"}
	entryID := cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "group:eng"}
	for name, entry := range map[string]struct {
		id    cp.RecordID
		value cp.ApplicationOwnerRecord
	}{
		"other application": {entryID, cp.ApplicationOwnerRecord{ApplicationID: "other", OwnerKey: good.OwnerKey, Kind: good.Kind, OwnerID: good.OwnerID}},
		"other key":         {entryID, cp.ApplicationOwnerRecord{ApplicationID: good.ApplicationID, OwnerKey: "group:ops", Kind: good.Kind, OwnerID: good.OwnerID}},
		"other kind":        {entryID, cp.ApplicationOwnerRecord{ApplicationID: good.ApplicationID, OwnerKey: good.OwnerKey, Kind: cp.OwnerUser, OwnerID: good.OwnerID}},
		"other owner":       {entryID, cp.ApplicationOwnerRecord{ApplicationID: good.ApplicationID, OwnerKey: good.OwnerKey, Kind: good.Kind, OwnerID: "ops"}},
		"no application":    {cp.RecordID{Kind: cp.ApplicationOwnerKind, ID: "group:eng"}, cp.ApplicationOwnerRecord{OwnerKey: good.OwnerKey, Kind: good.Kind, OwnerID: good.OwnerID}},
		"unparsed key":      {cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "eng"}, cp.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "eng", Kind: good.Kind, OwnerID: "eng"}},
		"unknown kind":      {cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "robot:eng"}, cp.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "robot:eng", Kind: "robot", OwnerID: "eng"}},
		"empty owner":       {cp.RecordID{Kind: cp.ApplicationOwnerKind, ParentID: "app", ID: "group:"}, cp.ApplicationOwnerRecord{ApplicationID: "app", OwnerKey: "group:", Kind: good.Kind}},
	} {
		if err := repo.Commit(context.Background(), []cp.Mutation{{Record: cpTestRecord(t, entry.id, entry.value)}}); err == nil {
			t.Fatalf("%s owner entry accepted", name)
		}
	}
	if fake.callCount("TransactWriteItems") != 0 {
		t.Fatal("malformed owner data reached storage")
	}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, entryID, good)})
}

func TestControlPlaneReadsLegacySingleOwnerApplication(t *testing.T) {
	repo, fake := cpTestRepository(t)
	payload := `{"id":"legacy","ownerUserId":"alice","targetId":"test-target","revision":3}`
	row := cpKey("APP#legacy", skMetadata)
	row["Kind"], row["ID"], row["Version"], row["Payload"] = cpString(string(cp.ApplicationKind)), cpString("legacy"), cpNumber(3), cpString(payload)
	row["GSI1PK"], row["GSI1SK"] = cpString("OWNER#alice"), cpString("APP#legacy")
	directory := cpKey("APP#legacy", "DIRECTORY")
	directory["Kind"], directory["ID"], directory["Version"] = cpString(string(cp.ApplicationKind)), cpString("legacy"), cpNumber(3)
	directory["GSI1PK"], directory["GSI1SK"] = cpString("APPLICATIONS"), cpString("APP#legacy")
	for _, item := range []map[string]types.AttributeValue{row, directory} {
		if _, err := fake.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String("control-plane-test"), Item: item}); err != nil {
			t.Fatal(err)
		}
	}
	id := cp.RecordID{Kind: cp.ApplicationKind, ID: "legacy"}
	read := cpTestRead(t, repo, id)
	app, err := cp.Decode[cp.ApplicationRecord](read)
	if err != nil || !reflect.DeepEqual(app.Owners, []cp.ApplicationOwner{cpTestUser("alice")}) || read.Version != 3 {
		t.Fatalf("legacy application=%+v version=%d err=%v", app, read.Version, err)
	}
	if listed := cpTestAll(t, repo, cp.Query{Kind: cp.ApplicationKind}); len(listed) != 1 || listed[0].ID != "legacy" {
		t.Fatalf("legacy application not in the directory: %+v", listed)
	}
	// A legacy row whose index entry names someone else is not the row the old
	// layout wrote, and stays unreadable.
	fake.mu.Lock()
	fake.items["APP#legacy"][skMetadata]["GSI1PK"] = cpString("OWNER#mallory")
	fake.mu.Unlock()
	if _, err := repo.Read(context.Background(), id); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("mismatched legacy index accepted: %v", err)
	}
	fake.mu.Lock()
	fake.items["APP#legacy"][skMetadata]["GSI1PK"] = cpString("OWNER#alice")
	fake.mu.Unlock()
	// Rewriting it in the current shape drops the single-owner index entry.
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, id, app), ExpectedVersion: 3})
	fake.mu.Lock()
	rewritten := copyItem(fake.items["APP#legacy"][skMetadata])
	fake.mu.Unlock()
	if _, indexed := rewritten["GSI1PK"]; indexed {
		t.Fatal("rewritten application kept its legacy owner index entry")
	}
	if got := cpTestRead(t, repo, id); got.Version != 4 {
		t.Fatalf("rewritten version=%d", got.Version)
	}
}

func TestControlPlaneBuildSlotLeaseIsExclusiveByVersion(t *testing.T) {
	repo, _ := cpTestRepository(t)
	slot := "apphub-build-0:3"
	id := cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(slot)}
	now := time.Now().UTC()
	lease := cp.BuildSlotLease{ID: id.ID, Slot: slot, LeaseID: "lease-a", Holder: "worker-a", AcquiredAt: now, ExpiresAt: now.Add(time.Minute)}
	cpTestCommit(t, repo, cp.Mutation{Record: cpTestRecord(t, id, lease)})

	// A second worker that also saw the slot free loses: its create expects no record.
	rival := lease
	rival.LeaseID, rival.Holder = "lease-b", "worker-b"
	if err := repo.Commit(t.Context(), []cp.Mutation{{Record: cpTestRecord(t, id, rival)}}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("a second holder's create = %v, want a conflict", err)
	}
	row, err := repo.Read(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	held, err := cp.Decode[cp.BuildSlotLease](row)
	if err != nil || held.LeaseID != "lease-a" || held.Slot != slot {
		t.Fatalf("lease after a lost race = %+v, %v", held, err)
	}
	mismatched := lease
	mismatched.ID = "not-its-id"
	if err := repo.Commit(t.Context(), []cp.Mutation{{Record: cpTestRecord(t, id, mismatched), ExpectedVersion: row.Version}}); err == nil {
		t.Fatal("a lease whose ID does not match its record was stored")
	}
	cpTestCommit(t, repo, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
	if _, err := repo.Read(t.Context(), id); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("a released lease still reads: %v", err)
	}
}
