// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package lifecycletest is the conformance suite for lifecycle.Records.
//
// It exists because a fake is only useful if it behaves like the real thing. Two
// implementations that merely compile against the same interface agree about
// nothing: the interesting behaviour of Records is in its error sentinels, its
// revision arithmetic, and which records a list method leaves out -- none of
// which a type check can see. Both credentials/lifecycle/fake and store are run
// through RunConformance, so a behaviour a test relies on against the fake is a
// behaviour production has too.
//
// It imports testing, like net/http/httptest and testing/fstest, because a test
// helper that cannot be imported by another package's tests is not a helper.
package lifecycletest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

// Providers the suite expects in the annotation registry.
const (
	// ProviderDeclared declares exactly one annotation key: lifecycle.AnnotationRegion.
	ProviderDeclared = "conformance-declared"

	// ProviderSilent registers no schema at all, and must therefore be unable to
	// persist any annotation. It is the case the allowlist exists for: a provider
	// nobody wrote a schema for gets no free pass.
	ProviderSilent = "conformance-silent"
)

// Base is the suite's reference instant. Fixed rather than time.Now so that a
// failure is reproducible and so nothing here depends on a clock.
var Base = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// NewRegistry builds the annotation registry the suite's records are written
// against.
func NewRegistry(t *testing.T) *lifecycle.AnnotationRegistry {
	t.Helper()
	reg := lifecycle.NewAnnotationRegistry()
	if err := reg.Register(ProviderDeclared, lifecycle.AnnotationRegion); err != nil {
		t.Fatalf("register %s: %v", ProviderDeclared, err)
	}
	return reg
}

// Factory builds an empty Records that validates annotations against reg.
//
// It is called once per subtest, and must hand back storage with nothing in it:
// subtests assert on the full contents of list results, so leakage between them
// would show up as a confusing failure somewhere else.
type Factory func(t *testing.T, reg *lifecycle.AnnotationRegistry) lifecycle.Records

// RunConformance runs every behavioural requirement of lifecycle.Records against
// the implementation newRecords builds.
func RunConformance(t *testing.T, newRecords Factory) {
	t.Helper()

	for _, tc := range []struct {
		name string
		run  func(*testing.T, lifecycle.Records)
	}{
		{"CreateThenGetRoundTrips", testCreateThenGetRoundTrips},
		{"CreateSetsFirstRevision", testCreateSetsFirstRevision},
		{"CreateRejectsDuplicateID", testCreateRejectsDuplicateID},
		{"CreateRequiresIDAndStatus", testCreateRequiresIDAndStatus},
		{"GetMissingIsErrNotFound", testGetMissingIsErrNotFound},
		{"UpdateAdvancesRevision", testUpdateAdvancesRevision},
		{"UpdateStaleRevisionIsErrConflict", testUpdateStaleRevisionIsErrConflict},
		{"UpdateMissingIsErrNotFound", testUpdateMissingIsErrNotFound},
		{"SchedulerCannotClobberOperatorRevoke", testSchedulerCannotClobberOperatorRevoke},
		{"ConcurrentUpdatesElectOneWinner", testConcurrentUpdatesElectOneWinner},
		{"DeleteRemovesRecord", testDeleteRemovesRecord},
		{"DeleteMissingIsErrNotFound", testDeleteMissingIsErrNotFound},
		{"ListByRequesterIsScopedAndNewestFirst", testListByRequesterIsScopedAndNewestFirst},
		{"ListByApplicationHonoursActiveOnly", testListByApplicationHonoursActiveOnly},
		{"ListByStatusIsExact", testListByStatusIsExact},
		{"ListExpiringExcludesTerminal", testListExpiringExcludesTerminal},
		{"ListExpiringExcludesNeverExpires", testListExpiringExcludesNeverExpires},
		{"ListExpiringIsInclusiveOfBoundary", testListExpiringIsInclusiveOfBoundary},
		{"ListExpiringHandlesSubSecondPrecision", testListExpiringHandlesSubSecondPrecision},
		{"ListExpiringSweepsOffsetZoneExpiry", testListExpiringSweepsOffsetZoneExpiry},
		{"ListExpiringIsZoneIndependent", testListExpiringIsZoneIndependent},
		{"DeclaredAnnotationRoundTrips", testDeclaredAnnotationRoundTrips},
		{"UndeclaredAnnotationIsRejected", testUndeclaredAnnotationIsRejected},
		{"ProviderWithoutSchemaPersistsNoAnnotations", testProviderWithoutSchemaPersistsNoAnnotations},
		{"UpdateValidatesAnnotations", testUpdateValidatesAnnotations},
		{"ReturnedRecordsAreCopies", testReturnedRecordsAreCopies},
		{"NoMaterialSurvivesARoundTrip", testNoMaterialSurvivesARoundTrip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newRecords(t, NewRegistry(t)))
		})
	}
}

// NewRecord builds a valid record for tests to vary. Exported so a caller can
// build fixtures that this suite will accept.
func NewRecord(id string) *lifecycle.Record {
	return &lifecycle.Record{
		ID:             id,
		ProviderID:     ProviderDeclared,
		Type:           credentials.CredentialTypeDynamic,
		Name:           "conformance-" + id,
		PlatformKeyID:  "platform-" + id,
		IdempotencyKey: "idem-" + id,
		Requester: lifecycle.Requester{
			ID:    "requester-1",
			Type:  "user",
			Email: "requester@example.com",
		},
		Status:              lifecycle.StatusActive,
		GrantedScope:        []string{"read"},
		RequestedScope:      []string{"read", "write"},
		ApplicationID:       "app-1",
		SecretRef:           credentials.SecretRef{Store: "aws-ssm", Name: "/apphub/" + id, EnvVar: "TOKEN"},
		ExpiresAt:           Base.Add(time.Hour),
		ExpiryAuthoritative: true,
		CreatedAt:           Base,
		UpdatedAt:           Base,
	}
}

func testCreateThenGetRoundTrips(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	want := NewRecord("round-trip")
	mustCreate(t, recs, want)

	got, err := recs.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSameRecord(t, want, got)
}

func testCreateSetsFirstRevision(t *testing.T, recs lifecycle.Records) {
	rec := NewRecord("first-revision")
	// Deliberately nonsense, to prove Create does not trust it: a caller that
	// pre-set a revision must not be able to start a record at an arbitrary one.
	rec.Revision = 41
	mustCreate(t, recs, rec)

	if rec.Revision != 1 {
		t.Fatalf("Create left caller revision %d, want 1", rec.Revision)
	}
	got := mustGet(t, recs, rec.ID)
	if got.Revision != 1 {
		t.Fatalf("stored revision %d, want 1", got.Revision)
	}
}

func testCreateRejectsDuplicateID(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	mustCreate(t, recs, NewRecord("dupe"))

	// A colliding ID means two vends believe they own one credential; overwriting
	// would lose the first one's audit trail and its platform key.
	second := NewRecord("dupe")
	second.Name = "the-overwriter"
	err := recs.Create(ctx, second)
	if !errors.Is(err, lifecycle.ErrAlreadyExists) {
		t.Fatalf("Create duplicate: got %v, want ErrAlreadyExists", err)
	}

	got := mustGet(t, recs, "dupe")
	if got.Name != "conformance-dupe" {
		t.Fatalf("duplicate Create overwrote the record: name is %q", got.Name)
	}
}

func testCreateRequiresIDAndStatus(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	noID := NewRecord("")
	if err := recs.Create(ctx, noID); err == nil {
		t.Error("Create with empty ID succeeded; the issuer must assign the ID before vending")
	}

	noStatus := NewRecord("no-status")
	noStatus.Status = ""
	if err := recs.Create(ctx, noStatus); err == nil {
		t.Error("Create with empty Status succeeded; defaulting it would mark an unconfirmed vend live")
	}
}

func testGetMissingIsErrNotFound(t *testing.T, recs lifecycle.Records) {
	// The source returned (nil, nil) here, which the compiler cannot force anyone
	// to check.
	got, err := recs.Get(context.Background(), "absent")
	if !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("Get absent: got err %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Fatalf("Get absent returned a record: %+v", got)
	}
}

func testUpdateAdvancesRevision(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	rec := NewRecord("advance")
	mustCreate(t, recs, rec)

	rec.Status = lifecycle.StatusPendingRevoke
	if err := recs.Update(ctx, rec); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if rec.Revision != 2 {
		t.Fatalf("caller revision %d after Update, want 2", rec.Revision)
	}

	got := mustGet(t, recs, rec.ID)
	if got.Revision != 2 {
		t.Fatalf("stored revision %d, want 2", got.Revision)
	}
	if got.Status != lifecycle.StatusPendingRevoke {
		t.Fatalf("stored status %q, want %q", got.Status, lifecycle.StatusPendingRevoke)
	}

	// The caller's copy must remain usable for a second write, which is the point
	// of advancing it in place.
	rec.Status = lifecycle.StatusRevoked
	if err := recs.Update(ctx, rec); err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if rec.Revision != 3 {
		t.Fatalf("caller revision %d after second Update, want 3", rec.Revision)
	}
}

func testUpdateStaleRevisionIsErrConflict(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	rec := NewRecord("stale")
	mustCreate(t, recs, rec)

	stale := mustGet(t, recs, rec.ID) // revision 1

	rec.Status = lifecycle.StatusRevoked
	if err := recs.Update(ctx, rec); err != nil {
		t.Fatalf("first Update: %v", err)
	}

	stale.Status = lifecycle.StatusExpired
	err := recs.Update(ctx, stale)
	if !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("stale Update: got %v, want ErrConflict", err)
	}

	got := mustGet(t, recs, rec.ID)
	if got.Status != lifecycle.StatusRevoked {
		t.Fatalf("stale Update was applied anyway: status %q", got.Status)
	}
	if got.Revision != 2 {
		t.Fatalf("stale Update moved the revision to %d, want 2", got.Revision)
	}
}

func testUpdateMissingIsErrNotFound(t *testing.T, recs lifecycle.Records) {
	// ErrNotFound and ErrConflict must be distinguishable: one is terminal, the
	// other says re-read and retry. A caller that retries a vanished record loops
	// forever.
	rec := NewRecord("never-created")
	rec.Revision = 1
	err := recs.Update(context.Background(), rec)
	if !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("Update missing: got %v, want ErrNotFound", err)
	}
	if errors.Is(err, lifecycle.ErrConflict) {
		t.Error("Update missing reported ErrConflict as well; the two must be distinguishable")
	}
}

// testSchedulerCannotClobberOperatorRevoke reproduces the source system's race.
//
// jobs/credential_scheduler.go:102-109 and services/credential.go:1045-1056 both
// wrote the whole record guarded only by attribute_exists(PK). Both read first,
// so an expiry pass landing after an operator's revoke overwrote it, and the
// operator was told the revoke had succeeded. This is the test that says it
// cannot happen any more.
func testSchedulerCannotClobberOperatorRevoke(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	mustCreate(t, recs, NewRecord("contested"))

	// Both actors read the same version.
	operatorView := mustGet(t, recs, "contested")
	schedulerView := mustGet(t, recs, "contested")

	revokedAt := Base.Add(30 * time.Minute)
	operatorView.Status = lifecycle.StatusRevoked
	operatorView.RevokeOutcome = lifecycle.RevokeOutcomeUpstream
	operatorView.RevokedAt = &revokedAt
	if err := recs.Update(ctx, operatorView); err != nil {
		t.Fatalf("operator revoke: %v", err)
	}

	// The scheduler now tries to finalise the same record as merely expired.
	schedulerView.Status = lifecycle.StatusExpired
	err := recs.Update(ctx, schedulerView)
	if !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("scheduler write over an operator revoke: got %v, want ErrConflict", err)
	}

	got := mustGet(t, recs, "contested")
	if got.Status != lifecycle.StatusRevoked || got.RevokeOutcome != lifecycle.RevokeOutcomeUpstream {
		t.Fatalf("operator revoke was lost: status %q outcome %q", got.Status, got.RevokeOutcome)
	}
}

// testConcurrentUpdatesElectOneWinner checks the revision guard under real
// concurrency, so the race detector has something to look at.
func testConcurrentUpdatesElectOneWinner(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	mustCreate(t, recs, NewRecord("concurrent"))

	const writers = 8
	views := make([]*lifecycle.Record, writers)
	for i := range views {
		views[i] = mustGet(t, recs, "concurrent") // all at revision 1
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
	)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			view := views[i]
			view.Name = fmt.Sprintf("writer-%d", i)
			err := recs.Update(ctx, view)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, lifecycle.ErrConflict):
				conflicts++
			default:
				t.Errorf("writer %d: unexpected error %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Exactly one write may be built on revision 1. Anything else means a lost
	// update, which is the bug this field exists to prevent.
	if succeeded != 1 {
		t.Errorf("%d writers succeeded from the same revision, want exactly 1", succeeded)
	}
	if conflicts != writers-1 {
		t.Errorf("%d conflicts, want %d", conflicts, writers-1)
	}

	got := mustGet(t, recs, "concurrent")
	if got.Revision != 2 {
		t.Errorf("stored revision %d after %d contending writes, want 2", got.Revision, writers)
	}
}

func testDeleteRemovesRecord(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	mustCreate(t, recs, NewRecord("deletable"))

	if err := recs.Delete(ctx, "deletable"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := recs.Get(ctx, "deletable"); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

func testDeleteMissingIsErrNotFound(t *testing.T, recs lifecycle.Records) {
	// Deleting is administrative cleanup of an audit trail. A silent success on an
	// ID that was never there reads to the operator as a completed cleanup.
	err := recs.Delete(context.Background(), "absent")
	if !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("Delete absent: got %v, want ErrNotFound", err)
	}
}

func testListByRequesterIsScopedAndNewestFirst(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	older := NewRecord("older")
	older.CreatedAt = Base
	mustCreate(t, recs, older)

	newer := NewRecord("newer")
	newer.CreatedAt = Base.Add(time.Hour)
	mustCreate(t, recs, newer)

	other := NewRecord("other-owner")
	other.Requester.ID = "requester-2"
	mustCreate(t, recs, other)

	got, err := recs.ListByRequester(ctx, "requester-1")
	if err != nil {
		t.Fatalf("ListByRequester: %v", err)
	}
	assertIDsInOrder(t, got, "newer", "older")

	// Another requester's credentials must not appear: this list is what an
	// operator is shown as "who holds what".
	single, err := recs.ListByRequester(ctx, "requester-2")
	if err != nil {
		t.Fatalf("ListByRequester(requester-2): %v", err)
	}
	assertIDsInOrder(t, single, "other-owner")

	empty, err := recs.ListByRequester(ctx, "requester-nobody")
	if err != nil {
		t.Fatalf("ListByRequester(unknown): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListByRequester for an unknown requester returned %d records", len(empty))
	}
}

func testListByApplicationHonoursActiveOnly(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	active := NewRecord("app-active")
	active.Status = lifecycle.StatusActive
	mustCreate(t, recs, active)

	revoked := NewRecord("app-revoked")
	revoked.Status = lifecycle.StatusRevoked
	revoked.CreatedAt = Base.Add(-time.Hour)
	mustCreate(t, recs, revoked)

	elsewhere := NewRecord("other-app")
	elsewhere.ApplicationID = "app-2"
	mustCreate(t, recs, elsewhere)

	all, err := recs.ListByApplication(ctx, "app-1", false)
	if err != nil {
		t.Fatalf("ListByApplication(all): %v", err)
	}
	assertIDsInOrder(t, all, "app-active", "app-revoked")

	onlyActive, err := recs.ListByApplication(ctx, "app-1", true)
	if err != nil {
		t.Fatalf("ListByApplication(activeOnly): %v", err)
	}
	assertIDsInOrder(t, onlyActive, "app-active")
}

func testListByStatusIsExact(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	for status, id := range map[lifecycle.Status]string{
		lifecycle.StatusPending:       "s-pending",
		lifecycle.StatusActive:        "s-active",
		lifecycle.StatusPendingRevoke: "s-pending-revoke",
		lifecycle.StatusRevoked:       "s-revoked",
	} {
		rec := NewRecord(id)
		rec.Status = status
		mustCreate(t, recs, rec)
	}

	// The reconciler drives pending_revoke off this query; a status that leaked in
	// would have it retry a revoke on a credential nobody asked to revoke.
	got, err := recs.ListByStatus(ctx, lifecycle.StatusPendingRevoke)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	assertIDsInOrder(t, got, "s-pending-revoke")

	none, err := recs.ListByStatus(ctx, lifecycle.StatusOrphaned)
	if err != nil {
		t.Fatalf("ListByStatus(orphaned): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListByStatus(orphaned) returned %d records", len(none))
	}
}

func testListExpiringExcludesTerminal(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	past := Base.Add(-time.Hour)

	for status, id := range map[lifecycle.Status]string{
		lifecycle.StatusActive:        "e-active",
		lifecycle.StatusPending:       "e-pending",
		lifecycle.StatusPendingRevoke: "e-pending-revoke",
		lifecycle.StatusRevoked:       "e-revoked",
		lifecycle.StatusExpired:       "e-expired",
		lifecycle.StatusOrphaned:      "e-orphaned",
	} {
		rec := NewRecord(id)
		rec.Status = status
		rec.ExpiresAt = past
		mustCreate(t, recs, rec)
	}

	got, err := recs.ListExpiring(ctx, Base)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	// Non-terminal only, and all three non-terminal states -- not just active. A
	// credential that expired while its vend was unconfirmed is exactly what the
	// reconciler must see; the source filtered on active alone and missed it.
	assertIDSet(t, got, "e-active", "e-pending", "e-pending-revoke")
}

func testListExpiringExcludesNeverExpires(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	forever := NewRecord("no-expiry")
	forever.ExpiresAt = time.Time{}
	forever.ExpiryAuthoritative = false
	mustCreate(t, recs, forever)

	expiring := NewRecord("does-expire")
	expiring.ExpiresAt = Base.Add(-time.Minute)
	mustCreate(t, recs, expiring)

	got, err := recs.ListExpiring(ctx, Base)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	// A zero ExpiresAt means "does not expire". Sweeping those up would have the
	// reconciler retire credentials that still work -- and a zero timestamp is
	// before every possible "now", so a naive comparison collects all of them.
	assertIDSet(t, got, "does-expire")
}

func testListExpiringIsInclusiveOfBoundary(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	exactly := NewRecord("exactly-now")
	exactly.ExpiresAt = Base
	mustCreate(t, recs, exactly)

	future := NewRecord("later")
	future.ExpiresAt = Base.Add(time.Second)
	mustCreate(t, recs, future)

	got, err := recs.ListExpiring(ctx, Base)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	assertIDSet(t, got, "exactly-now")
}

// testListExpiringHandlesSubSecondPrecision pins the fractional-second edge.
//
// The stored timestamp format drops trailing zeros, so string ordering is not
// time ordering across differing precisions: an expiry on a whole second sorts
// after one with a fractional part in the same second. An implementation that
// compares stored strings without accounting for that silently fails to expire
// the whole-second record.
func testListExpiringHandlesSubSecondPrecision(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	whole := NewRecord("whole-second")
	whole.ExpiresAt = Base
	mustCreate(t, recs, whole)

	fraction := NewRecord("sub-second")
	fraction.ExpiresAt = Base.Add(500 * time.Millisecond)
	mustCreate(t, recs, fraction)

	notYet := NewRecord("next-second")
	notYet.ExpiresAt = Base.Add(1500 * time.Millisecond)
	mustCreate(t, recs, notYet)

	// "now" carries a fractional part, which is the case that breaks a naive
	// string comparison against the whole-second record.
	got, err := recs.ListExpiring(ctx, Base.Add(900*time.Millisecond))
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	assertIDSet(t, got, "whole-second", "sub-second")
}

// testListExpiringSweepsOffsetZoneExpiry is the reviewer's exact reproduction.
//
// 2026-01-01 12:00:00 +14:00 is 2025-12-31T22:00:00Z -- an hour in the past at the
// time asked about. The record is expired on any reading of the clock, but its
// timestamp *spells* a later year, so an implementation that compares stored text
// instead of instants omits it: a credential that has expired and will never be
// swept, which the platform then believes live indefinitely.
func testListExpiringSweepsOffsetZoneExpiry(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	rec := NewRecord("far-east-expiry")
	rec.ExpiresAt = time.Date(2026, 1, 1, 12, 0, 0, 0, time.FixedZone("+14", 14*3600))
	mustCreate(t, recs, rec)

	now := time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC)
	// Guard the premise: if this ever stops holding, the test below is vacuous.
	if !rec.Expired(now) {
		t.Fatalf("premise: %s is not expired at %s", rec.ExpiresAt, now)
	}

	got, err := recs.ListExpiring(ctx, now)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	assertIDSet(t, got, "far-east-expiry")
}

// testListExpiringIsZoneIndependent is the same defect stated as a class rather
// than a case, because the case-by-case version is how the offset bug survived two
// earlier ordering fixes: what a record is *swept* on must depend only on the
// instant, never on the zone it was written in.
func testListExpiringIsZoneIndependent(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	// One instant -- 2026-03-01T11:00:00Z -- written five different ways. Every one
	// is an hour before the "now" below, so all five must be swept together.
	instant := time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC)
	zones := map[string]*time.Location{
		"utc":       time.UTC,
		"plus14":    time.FixedZone("+14", 14*3600),
		"minus11":   time.FixedZone("-11", -11*3600),
		"plus0530":  time.FixedZone("+0530", 5*3600+1800),
		"minus0330": time.FixedZone("-0330", -(3*3600 + 1800)),
	}

	var want []string
	for name, loc := range zones {
		rec := NewRecord("zoned-" + name)
		rec.ExpiresAt = instant.In(loc)
		if !rec.ExpiresAt.Equal(instant) {
			t.Fatalf("premise: %s in %s is not the same instant", instant, name)
		}
		mustCreate(t, recs, rec)
		want = append(want, "zoned-"+name)
	}

	// A record an hour the other side of the line, to prove the sweep is still
	// selective rather than simply returning everything.
	future := NewRecord("zoned-future")
	future.ExpiresAt = instant.Add(2 * time.Hour).In(zones["plus14"])
	mustCreate(t, recs, future)

	got, err := recs.ListExpiring(ctx, instant.Add(time.Hour))
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	assertIDSet(t, got, want...)
}

func testDeclaredAnnotationRoundTrips(t *testing.T, recs lifecycle.Records) {
	rec := NewRecord("annotated")
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationRegion: "us-west-2"}
	mustCreate(t, recs, rec)

	got := mustGet(t, recs, "annotated")
	if got.Annotations[lifecycle.AnnotationRegion] != "us-west-2" {
		t.Fatalf("annotations round-tripped as %#v", got.Annotations)
	}
}

func testUndeclaredAnnotationIsRejected(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	rec := NewRecord("undeclared")
	// ProviderDeclared declared only AnnotationRegion.
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationDeviceID: "device-1"}

	err := recs.Create(ctx, rec)
	if !errors.Is(err, lifecycle.ErrUndeclaredAnnotation) {
		t.Fatalf("Create with an undeclared annotation: got %v, want ErrUndeclaredAnnotation", err)
	}
	// Failing the write, rather than dropping the key and carrying on: a caller
	// that is told the write succeeded believes it stored something it did not.
	if _, err := recs.Get(ctx, "undeclared"); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("record was written despite a rejected annotation: %v", err)
	}
}

func testProviderWithoutSchemaPersistsNoAnnotations(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()

	rec := NewRecord("silent")
	rec.ProviderID = ProviderSilent
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationRegion: "us-west-2"}

	// A provider that declared nothing persists nothing, even for a key another
	// provider legitimately declares.
	if err := recs.Create(ctx, rec); !errors.Is(err, lifecycle.ErrUndeclaredAnnotation) {
		t.Fatalf("Create for a provider with no schema: got %v, want ErrUndeclaredAnnotation", err)
	}

	// With no annotations at all it must still be storable: having no schema is
	// not a reason to be unable to record that a credential exists.
	rec.Annotations = nil
	if err := recs.Create(ctx, rec); err != nil {
		t.Fatalf("Create for a provider with no schema and no annotations: %v", err)
	}
}

func testUpdateValidatesAnnotations(t *testing.T, recs lifecycle.Records) {
	ctx := context.Background()
	rec := NewRecord("update-annotations")
	mustCreate(t, recs, rec)

	// Validation on Create alone would leave the obvious way in wide open.
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationAccountAlias: "sneaky"}
	if err := recs.Update(ctx, rec); !errors.Is(err, lifecycle.ErrUndeclaredAnnotation) {
		t.Fatalf("Update with an undeclared annotation: got %v, want ErrUndeclaredAnnotation", err)
	}
}

func testReturnedRecordsAreCopies(t *testing.T, recs lifecycle.Records) {
	rec := NewRecord("copies")
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationRegion: "us-west-2"}
	mustCreate(t, recs, rec)

	got := mustGet(t, recs, "copies")
	got.Status = lifecycle.StatusRevoked
	got.GrantedScope[0] = "mutated"
	got.Annotations[lifecycle.AnnotationRegion] = "mutated"

	// An implementation handing out a window into its own state makes a test pass
	// against the fake and fail against the database, which is the one thing a
	// fake must never do.
	again := mustGet(t, recs, "copies")
	if again.Status != lifecycle.StatusActive {
		t.Errorf("mutating a returned record changed the stored status: %q", again.Status)
	}
	if again.GrantedScope[0] != "read" {
		t.Errorf("mutating a returned slice changed stored state: %#v", again.GrantedScope)
	}
	if again.Annotations[lifecycle.AnnotationRegion] != "us-west-2" {
		t.Errorf("mutating a returned map changed stored state: %#v", again.Annotations)
	}
}

// testNoMaterialSurvivesARoundTrip is a standing guard on Record's central
// property: it can carry a locator but never the credential itself. If someone
// adds a material-shaped field, the round-trip below is where it shows up.
func testNoMaterialSurvivesARoundTrip(t *testing.T, recs lifecycle.Records) {
	rec := NewRecord("locator-only")
	rec.SecretRef = credentials.SecretRef{
		Store:   "aws-ssm",
		Name:    "/apphub/credentials/locator-only",
		Version: "3",
		EnvVar:  "API_TOKEN",
	}
	mustCreate(t, recs, rec)

	got := mustGet(t, recs, "locator-only")
	if got.SecretRef != rec.SecretRef {
		t.Fatalf("SecretRef round-tripped as %+v, want %+v", got.SecretRef, rec.SecretRef)
	}
}

func mustCreate(t *testing.T, recs lifecycle.Records, rec *lifecycle.Record) {
	t.Helper()
	if err := recs.Create(context.Background(), rec); err != nil {
		t.Fatalf("Create(%s): %v", rec.ID, err)
	}
}

func mustGet(t *testing.T, recs lifecycle.Records, id string) *lifecycle.Record {
	t.Helper()
	got, err := recs.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return got
}

// assertSameRecord compares every field, using Equal for timestamps so that a
// stored-and-reparsed time compares by instant rather than by representation.
func assertSameRecord(t *testing.T, want, got *lifecycle.Record) {
	t.Helper()

	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if got.ProviderID != want.ProviderID {
		t.Errorf("ProviderID = %q, want %q", got.ProviderID, want.ProviderID)
	}
	if got.Type != want.Type {
		t.Errorf("Type = %q, want %q", got.Type, want.Type)
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
	if got.PlatformKeyID != want.PlatformKeyID {
		t.Errorf("PlatformKeyID = %q, want %q", got.PlatformKeyID, want.PlatformKeyID)
	}
	if got.IdempotencyKey != want.IdempotencyKey {
		t.Errorf("IdempotencyKey = %q, want %q", got.IdempotencyKey, want.IdempotencyKey)
	}
	if got.Requester != want.Requester {
		t.Errorf("Requester = %+v, want %+v", got.Requester, want.Requester)
	}
	if got.Status != want.Status {
		t.Errorf("Status = %q, want %q", got.Status, want.Status)
	}
	if got.RevokeOutcome != want.RevokeOutcome {
		t.Errorf("RevokeOutcome = %q, want %q", got.RevokeOutcome, want.RevokeOutcome)
	}
	assertSameStrings(t, "GrantedScope", got.GrantedScope, want.GrantedScope)
	assertSameStrings(t, "RequestedScope", got.RequestedScope, want.RequestedScope)
	if got.ApplicationID != want.ApplicationID {
		t.Errorf("ApplicationID = %q, want %q", got.ApplicationID, want.ApplicationID)
	}
	if got.SecretRef != want.SecretRef {
		t.Errorf("SecretRef = %+v, want %+v", got.SecretRef, want.SecretRef)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %s, want %s", got.ExpiresAt, want.ExpiresAt)
	}
	if got.ExpiryAuthoritative != want.ExpiryAuthoritative {
		t.Errorf("ExpiryAuthoritative = %v, want %v", got.ExpiryAuthoritative, want.ExpiryAuthoritative)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %s, want %s", got.CreatedAt, want.CreatedAt)
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("UpdatedAt = %s, want %s", got.UpdatedAt, want.UpdatedAt)
	}
	if !got.LastRefreshedAt.Equal(want.LastRefreshedAt) {
		t.Errorf("LastRefreshedAt = %s, want %s", got.LastRefreshedAt, want.LastRefreshedAt)
	}
	switch {
	case (got.RevokedAt == nil) != (want.RevokedAt == nil):
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, want.RevokedAt)
	case got.RevokedAt != nil && !got.RevokedAt.Equal(*want.RevokedAt):
		t.Errorf("RevokedAt = %s, want %s", got.RevokedAt, want.RevokedAt)
	}
	if len(got.Annotations) != len(want.Annotations) {
		t.Errorf("Annotations = %#v, want %#v", got.Annotations, want.Annotations)
	}
	for k, v := range want.Annotations {
		if got.Annotations[k] != v {
			t.Errorf("Annotations[%q] = %q, want %q", k, got.Annotations[k], v)
		}
	}
}

func assertSameStrings(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %#v, want %#v", field, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %#v, want %#v", field, got, want)
			return
		}
	}
}

// assertIDsInOrder asserts the exact IDs in the exact order given.
func assertIDsInOrder(t *testing.T, got []lifecycle.Record, want ...string) {
	t.Helper()
	gotIDs := make([]string, 0, len(got))
	for _, rec := range got {
		gotIDs = append(gotIDs, rec.ID)
	}
	if len(gotIDs) != len(want) {
		t.Fatalf("got IDs %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("got IDs %v, want %v", gotIDs, want)
		}
	}
}

// assertIDSet asserts the exact set of IDs, order-independent. Used where the
// contract does not promise an order, so that a conforming implementation is not
// held to one it never agreed to.
func assertIDSet(t *testing.T, got []lifecycle.Record, want ...string) {
	t.Helper()
	gotSet := make(map[string]struct{}, len(got))
	for _, rec := range got {
		gotSet[rec.ID] = struct{}{}
	}
	if len(gotSet) != len(want) {
		t.Fatalf("got IDs %v, want set %v", keys(gotSet), want)
	}
	for _, id := range want {
		if _, ok := gotSet[id]; !ok {
			t.Fatalf("got IDs %v, want set %v", keys(gotSet), want)
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
