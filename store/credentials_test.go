// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/conductorone/apphub/credentials/lifecycle"
	"github.com/conductorone/apphub/credentials/lifecycle/lifecycletest"
)

const testTable = "apphub-test-table"

// TestConformance runs the same suite the in-memory fake passes, against the real
// store code and its real expression strings.
//
// This is what makes the fake trustworthy as a stand-in: not that both types
// satisfy lifecycle.Records, but that both satisfy the same behavioural
// requirements. Everything here is hermetic -- no table, no credentials, no
// network.
func TestConformance(t *testing.T) {
	lifecycletest.RunConformance(t, func(t *testing.T, reg *lifecycle.AnnotationRegistry) lifecycle.Records {
		t.Helper()
		recs, err := NewCredentialRecords(newTestClient(newFakeDynamo(testTable)), reg)
		if err != nil {
			t.Fatalf("NewCredentialRecords: %v", err)
		}
		return recs
	})
}

func newRecordsForTest(t *testing.T) (*CredentialRecords, *fakeDynamo) {
	t.Helper()
	db := newFakeDynamo(testTable)
	recs, err := NewCredentialRecords(newTestClient(db), lifecycletest.NewRegistry(t))
	if err != nil {
		t.Fatalf("NewCredentialRecords: %v", err)
	}
	return recs, db
}

func TestNewCredentialRecordsRequiresRegistry(t *testing.T) {
	// Fail closed: neither "allow everything" nor a store that rejects every
	// annotated write is a safe reading of a nil registry.
	if _, err := NewCredentialRecords(newTestClient(newFakeDynamo(testTable)), nil); err == nil {
		t.Error("NewCredentialRecords accepted a nil annotation registry")
	}
	if _, err := NewCredentialRecords(nil, lifecycletest.NewRegistry(t)); err == nil {
		t.Error("NewCredentialRecords accepted a nil client")
	}
}

// TestListByRequesterUsesTheIndexNotAScan guards the one query that has a GSI
// behind it. If it silently became a Scan the results would still be right and
// the cost would grow with the table.
func TestListByRequesterUsesTheIndexNotAScan(t *testing.T) {
	recs, db := newRecordsForTest(t)
	ctx := context.Background()

	rec := lifecycletest.NewRecord("indexed")
	if err := recs.Create(ctx, rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := recs.ListByRequester(ctx, rec.Requester.ID); err != nil {
		t.Fatalf("ListByRequester: %v", err)
	}

	if db.callCount("Query") == 0 {
		t.Error("ListByRequester issued no Query")
	}
	if got := db.callCount("Scan"); got != 0 {
		t.Errorf("ListByRequester issued %d Scans; it has a GSI for this", got)
	}
}

// TestPaginationCollectsEveryPage is the regression test for a bug in the source.
//
// The source's ListByRequester read one Query page and returned it as the whole
// answer (internal/database/credential.go:136-153), so a requester with enough
// credentials to exceed DynamoDB's 1 MB response limit silently lost the tail.
// Silently is the problem: the caller cannot tell a short list from a complete
// one. The double pages at two items, so anything above that exercises the loop.
func TestPaginationCollectsEveryPage(t *testing.T) {
	recs, db := newRecordsForTest(t)
	ctx := context.Background()

	const total = 7
	for i := range total {
		rec := lifecycletest.NewRecord(string(rune('a'+i)) + "-paged")
		rec.CreatedAt = lifecycletest.Base.Add(time.Duration(i) * time.Minute)
		if err := recs.Create(ctx, rec); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	got, err := recs.ListByRequester(ctx, "requester-1")
	if err != nil {
		t.Fatalf("ListByRequester: %v", err)
	}
	if len(got) != total {
		t.Fatalf("ListByRequester returned %d of %d records; pagination is dropping pages", len(got), total)
	}
	if db.callCount("Query") < 2 {
		t.Fatalf("expected more than one Query page, got %d", db.callCount("Query"))
	}

	// Newest first must hold across the page boundary, not just within a page.
	for i := 1; i < len(got); i++ {
		if got[i].CreatedAt.After(got[i-1].CreatedAt) {
			t.Fatalf("results are not newest-first at index %d", i)
		}
	}

	byStatus, err := recs.ListByStatus(ctx, lifecycle.StatusActive)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(byStatus) != total {
		t.Fatalf("ListByStatus returned %d of %d records; Scan pagination is dropping pages", len(byStatus), total)
	}
}

// TestScanSurvivesAPageWithNoMatches covers the shape that breaks a naive
// pagination loop: DynamoDB filters after reading, so a page can come back with
// zero items and a LastEvaluatedKey set. Stopping there loses everything after it.
func TestScanSurvivesAPageWithNoMatches(t *testing.T) {
	recs, db := newRecordsForTest(t)
	ctx := context.Background()

	// The double pages in key order (PK ascending). Two non-matching records sort
	// ahead of the matching one, so the first page matches nothing at all.
	for _, id := range []string{"aaa-other", "bbb-other"} {
		rec := lifecycletest.NewRecord(id)
		rec.Status = lifecycle.StatusRevoked
		if err := recs.Create(ctx, rec); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	wanted := lifecycletest.NewRecord("zzz-wanted")
	wanted.Status = lifecycle.StatusPendingRevoke
	if err := recs.Create(ctx, wanted); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if db.pageSize != 2 {
		t.Fatalf("test assumes a page size of 2, got %d", db.pageSize)
	}
	got, err := recs.ListByStatus(ctx, lifecycle.StatusPendingRevoke)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(got) != 1 || got[0].ID != "zzz-wanted" {
		t.Fatalf("got %d records %v, want just zzz-wanted; an empty first page ended the scan early", len(got), ids(got))
	}
}

// TestUpdateWritesAConditionalExpression asserts the mechanism rather than only
// its effect. The conformance suite proves a stale write is refused; this proves
// it is refused by a conditional write on Revision, which is the thing that makes
// it hold when two processes race rather than two calls in one test.
func TestUpdateWritesAConditionalExpression(t *testing.T) {
	db := newFakeDynamo(testTable)
	recs, err := NewCredentialRecords(newTestClient(db), lifecycletest.NewRegistry(t))
	if err != nil {
		t.Fatalf("NewCredentialRecords: %v", err)
	}
	ctx := context.Background()

	spy := &conditionSpy{fakeDynamo: db}
	recs.client = &Client{api: spy, tableName: testTable}

	rec := lifecycletest.NewRecord("conditional")
	if err := recs.Create(ctx, rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := spy.conditions[0]; got != "attribute_not_exists(PK)" {
		t.Errorf("Create condition = %q, want attribute_not_exists(PK)", got)
	}

	if err := recs.Update(ctx, rec); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updateCond := spy.conditions[1]
	if !strings.Contains(updateCond, "Revision = :rev") {
		t.Errorf("Update condition = %q, want it to guard on Revision", updateCond)
	}
	if !strings.Contains(updateCond, "attribute_exists(PK)") {
		t.Errorf("Update condition = %q, want it to require the item to exist", updateCond)
	}
	// The guard must name the revision the caller read, not the one being written.
	if got := spy.values[1][":rev"]; attrString2(got) != "1" {
		t.Errorf("Update guarded on revision %q, want the caller's revision 1", attrString2(got))
	}
	if spy.returnValues[1] != types.ReturnValuesOnConditionCheckFailureAllOld {
		t.Errorf("Update did not request the old item on condition failure; "+
			"ErrNotFound and ErrConflict cannot be distinguished without it (got %q)",
			spy.returnValues[1])
	}
}

// TestDeleteIsConditional pins that Delete distinguishes "removed" from "was
// never there" with a condition rather than by reading first, which would be a
// race.
func TestDeleteIsConditional(t *testing.T) {
	db := newFakeDynamo(testTable)
	recs, err := NewCredentialRecords(newTestClient(db), lifecycletest.NewRegistry(t))
	if err != nil {
		t.Fatalf("NewCredentialRecords: %v", err)
	}
	if err := recs.Delete(context.Background(), "absent"); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("Delete absent: got %v, want ErrNotFound", err)
	}
	if db.callCount("GetItem") != 0 {
		t.Error("Delete read the item before deleting; the condition should do that work atomically")
	}
}

// TestExpiryFilterExcludesNeverExpiresServerSide checks that a record with no
// expiry is excluded by the filter expression, not merely dropped after it comes
// back. Both are correct; only one avoids shipping every never-expiring
// credential to the client on every reconciler pass.
func TestExpiryFilterExcludesNeverExpiresServerSide(t *testing.T) {
	recs, db := newRecordsForTest(t)
	ctx := context.Background()

	forever := lifecycletest.NewRecord("forever")
	forever.ExpiresAt = time.Time{}
	if err := recs.Create(ctx, forever); err != nil {
		t.Fatalf("Create: %v", err)
	}

	filter := "#type = :type AND ExpiresAt > :zeroExpiry AND ExpiresAt <= :bound" +
		" AND #status <> :revoked AND #status <> :expired AND #status <> :orphaned"
	item := db.all()[0]
	ok, err := evalExpression(filter, item,
		map[string]string{"#type": "Type", "#status": "Status"},
		map[string]types.AttributeValue{
			":type":       &types.AttributeValueMemberS{Value: entityCredential},
			":zeroExpiry": &types.AttributeValueMemberS{Value: instantZero},
			":bound":      &types.AttributeValueMemberS{Value: encodeInstant(lifecycletest.Base)},
			":revoked":    &types.AttributeValueMemberS{Value: string(lifecycle.StatusRevoked)},
			":expired":    &types.AttributeValueMemberS{Value: string(lifecycle.StatusExpired)},
			":orphaned":   &types.AttributeValueMemberS{Value: string(lifecycle.StatusOrphaned)},
		})
	if err != nil {
		t.Fatalf("evalExpression: %v", err)
	}
	if ok {
		t.Error("the expiry filter admits a record with no expiry; every one of them " +
			"would be read on every reconciler pass")
	}
}

// --- The ordering invariant, tested as a property ------------------------------
//
// Three defects in this package were the same defect wearing different clothes: a
// lexical ordering standing in for a temporal one. The first two were fixed
// case-by-case, with a test each, and that is precisely why the third survived --
// each gap sat one generalisation away from a test already written.
//
// So the property is tested, not the cases:
//
//	for any two instants a and b, encodeInstant(a) < encodeInstant(b)
//	                             if and only if a is before b
//
// A new zone, precision, or era cannot slip past that the way a third case could.

// orderingCorpus is deliberately adversarial about the things that broke before:
// zones east and west of UTC (including the +14:00 that hid an expired
// credential), whole seconds against sub-second values inside the same second,
// and the zero instant that means "no expiry".
func orderingCorpus() []time.Time {
	plus14 := time.FixedZone("+14", 14*3600)
	minus11 := time.FixedZone("-11", -11*3600)
	kolkata := time.FixedZone("+0530", 5*3600+1800)

	return []time.Time{
		{}, // the zero instant
		time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC),
		time.Date(2025, 12, 31, 22, 0, 0, 0, time.UTC),
		// The same instant as the line above, spelled in a zone that sorts a year
		// later. This is the pair that was silently reordered.
		time.Date(2026, 1, 1, 12, 0, 0, 0, plus14),
		time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 5, 0, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 5, 1, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 5, 500_000_000, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 5, 999_999_999, time.UTC),
		time.Date(2026, 3, 1, 12, 0, 6, 0, time.UTC),
		time.Date(2026, 3, 1, 7, 30, 6, 0, minus11),
		time.Date(2026, 3, 1, 17, 30, 6, 0, kolkata),
		time.Date(2030, 6, 15, 8, 9, 10, 123_456_789, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC),
	}
}

// TestEncodeInstantOrderIsTemporalOrder is the invariant itself: byte order and
// chronology agree, over every pair in the corpus.
func TestEncodeInstantOrderIsTemporalOrder(t *testing.T) {
	t.Parallel()
	corpus := orderingCorpus()

	for i, a := range corpus {
		for j, b := range corpus {
			lexicalLess := encodeInstant(a) < encodeInstant(b)
			temporalLess := a.Before(b)
			if lexicalLess != temporalLess {
				t.Errorf("corpus[%d]=%s vs corpus[%d]=%s: encoded %q vs %q sorts less=%v, but Before=%v",
					i, a, j, b, encodeInstant(a), encodeInstant(b), lexicalLess, temporalLess)
			}
			// Equal instants must encode identically, or a bound comparison at the
			// boundary depends on which spelling was stored.
			if a.Equal(b) && encodeInstant(a) != encodeInstant(b) {
				t.Errorf("equal instants %s and %s encode differently: %q vs %q",
					a, b, encodeInstant(a), encodeInstant(b))
			}
		}
	}
}

// TestEncodeInstantIsFixedWidth pins the mechanism the invariant rests on. Every
// encoding is the same length and ends in Z; either property failing is what makes
// byte order stop agreeing with chronology.
func TestEncodeInstantIsFixedWidth(t *testing.T) {
	t.Parallel()
	width := len(instantZero)
	for _, at := range orderingCorpus() {
		got := encodeInstant(at)
		if len(got) != width {
			t.Errorf("encodeInstant(%s) = %q is %d bytes, want %d", at, got, len(got), width)
		}
		if !strings.HasSuffix(got, "Z") {
			t.Errorf("encodeInstant(%s) = %q does not end in Z; a zone offset reorders it", at, got)
		}
	}
	if got := encodeInstant(time.Time{}); got != instantZero {
		t.Errorf("the zero instant encodes as %q, but the ListExpiring filter compares against %q", got, instantZero)
	}
}

// TestRFC3339NanoWouldViolateTheInvariant records why the SDK default is not used,
// so that "just store a time.Time" cannot come back without this failing first.
func TestRFC3339NanoWouldViolateTheInvariant(t *testing.T) {
	t.Parallel()
	corpus := orderingCorpus()

	var violations int
	for _, a := range corpus {
		for _, b := range corpus {
			lexical := a.Format(time.RFC3339Nano) < b.Format(time.RFC3339Nano)
			if lexical != a.Before(b) {
				violations++
			}
		}
	}
	// Both original defects are in here: the variable-width fractional part and
	// the offset spelling. If this ever reaches zero the SDK's default has changed
	// and the custom encoding deserves a fresh look.
	if violations == 0 {
		t.Error("RFC3339Nano now preserves order over this corpus; re-examine whether instant is still needed")
	}
}

// TestStoredTimestampsAreOrderPreserving checks the invariant where it actually
// matters: on the bytes a write puts in the table, for every timestamp on the
// record rather than only ExpiresAt.
func TestStoredTimestampsAreOrderPreserving(t *testing.T) {
	t.Parallel()
	recs, db := newRecordsForTest(t)

	plus14 := time.FixedZone("+14", 14*3600)
	revoked := time.Date(2026, 1, 1, 12, 0, 0, 0, plus14)

	rec := lifecycletest.NewRecord("zoned")
	rec.ExpiresAt = time.Date(2026, 1, 1, 12, 0, 0, 0, plus14)
	rec.CreatedAt = time.Date(2026, 1, 1, 9, 0, 0, 0, plus14)
	rec.UpdatedAt = time.Date(2026, 1, 1, 10, 0, 0, 0, plus14)
	rec.LastRefreshedAt = time.Date(2026, 1, 1, 11, 0, 0, 0, plus14)
	rec.RevokedAt = &revoked
	if err := recs.Create(context.Background(), rec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	item := db.all()[0]
	for _, attr := range []string{"ExpiresAt", "CreatedAt", "UpdatedAt", "LastRefreshedAt", "RevokedAt"} {
		got := stringAttr(item, attr)
		if got == "" {
			t.Errorf("%s was not stored as a string attribute", attr)
			continue
		}
		if !strings.HasSuffix(got, "Z") {
			t.Errorf("%s stored as %q, which carries a zone offset and sorts wrongly", attr, got)
		}
		if len(got) != len(instantZero) {
			t.Errorf("%s stored as %q, %d bytes, want the fixed %d", attr, got, len(got), len(instantZero))
		}
	}
	// The sort key is built from the same encoding, so it inherits the invariant
	// rather than restating it.
	if sk := stringAttr(item, "GSI1SK"); !strings.HasSuffix(sk, "Z") {
		t.Errorf("GSI1SK = %q does not carry an order-preserving timestamp", sk)
	}
}

// TestStoredItemCarriesNoMaterial is a standing check on the fence's other half.
// If a field capable of holding credential material is ever added to the stored
// item, this is where it surfaces.
func TestStoredItemCarriesNoMaterial(t *testing.T) {
	recs, db := newRecordsForTest(t)
	rec := lifecycletest.NewRecord("no-material")
	rec.Annotations = lifecycle.Annotations{lifecycle.AnnotationRegion: "us-west-2"}
	if err := recs.Create(context.Background(), rec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	item := db.all()[0]
	for _, banned := range []string{
		"Secret", "SecretValue", "Value", "Material", "Token", "Password",
		"AccessKey", "SecretAccessKey", "PrivateKey", "ApiKey", "APIKey", "Credential",
	} {
		if _, present := item[banned]; present {
			t.Errorf("stored item has attribute %q; the record holds locators, never material", banned)
		}
	}
	// The locator itself is expected, and is not material.
	if stringAttr(item, "SecretName") == "" {
		t.Error("stored item lost the secret locator")
	}
}

func attrString2(v types.AttributeValue) string {
	if n, ok := v.(*types.AttributeValueMemberN); ok {
		return n.Value
	}
	return ""
}

func ids(recs []lifecycle.Record) []string {
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.ID)
	}
	return out
}

// conditionSpy records the conditional-write arguments the store sends.
type conditionSpy struct {
	*fakeDynamo
	conditions   []string
	values       []map[string]types.AttributeValue
	returnValues []types.ReturnValuesOnConditionCheckFailure
}

func (s *conditionSpy) PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	cond := ""
	if in.ConditionExpression != nil {
		cond = *in.ConditionExpression
	}
	s.conditions = append(s.conditions, cond)
	s.values = append(s.values, in.ExpressionAttributeValues)
	s.returnValues = append(s.returnValues, in.ReturnValuesOnConditionCheckFailure)
	return s.fakeDynamo.PutItem(ctx, in, opts...)
}

// --- The read path, and what the query cannot see (review round 3) ------------
//
// The write path is correct: every instant is stored fixed-width in UTC. The read
// path used to accept any RFC 3339 string, which read as support for older rows.
// It was not support. ListExpiring's filter compares stored bytes, so an
// offset-spelled expiry is excluded before any unmarshal runs -- the permissive
// reader decoded such a row happily through Get while the sweep that matters could
// not see it. Coverage where it was not needed, none where it was.
//
// So the reader is strict now, and these tests pin both halves of that: what it
// refuses, and the residual it does not pretend to fix.

// legacyItem is a row as an older build would have written it: RFC3339Nano with a
// zone offset. Nothing in this repository has ever written one -- store/ was
// introduced with the canonical encoding and nothing is deployed -- so this is a
// hypothetical row, injected below the store to test the read path directly.
func legacyItem(id, expiresAt string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK":                  &types.AttributeValueMemberS{Value: pkPrefixCredential + id},
		"SK":                  &types.AttributeValueMemberS{Value: skMetadata},
		"Type":                &types.AttributeValueMemberS{Value: entityCredential},
		"ID":                  &types.AttributeValueMemberS{Value: id},
		"Revision":            &types.AttributeValueMemberN{Value: "1"},
		"ProviderID":          &types.AttributeValueMemberS{Value: lifecycletest.ProviderDeclared},
		"CredentialType":      &types.AttributeValueMemberS{Value: "dynamic"},
		"Name":                &types.AttributeValueMemberS{Value: id},
		"PlatformKeyID":       &types.AttributeValueMemberS{Value: "k"},
		"RequesterID":         &types.AttributeValueMemberS{Value: "requester-1"},
		"RequesterType":       &types.AttributeValueMemberS{Value: "user"},
		"Status":              &types.AttributeValueMemberS{Value: string(lifecycle.StatusActive)},
		"ExpiresAt":           &types.AttributeValueMemberS{Value: expiresAt},
		"ExpiryAuthoritative": &types.AttributeValueMemberBOOL{Value: true},
		"CreatedAt":           &types.AttributeValueMemberS{Value: "2025-12-01T00:00:00.000000000Z"},
	}
}

// TestStrictReaderRefusesNonCanonicalEncodings is the withdrawal of the permissive
// claim. A row that cannot be ordered correctly must not be read as though it
// could: an error is noisy and fixable, a silently mis-sorted expiry is neither.
func TestStrictReaderRefusesNonCanonicalEncodings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, value string }{
		{"offset zone", "2026-01-01T12:00:00+14:00"},
		{"RFC3339Nano, trailing zeros trimmed", "2026-01-01T12:00:00Z"},
		{"sub-second but not nine digits", "2026-01-01T12:00:00.5Z"},
		{"no zone at all", "2026-01-01T12:00:00.000000000"},
		{"lowercase zone marker", "2026-01-01T12:00:00.000000000z"},
		{"not a time", "definitely-not-a-time-at-all-ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got instant
			err := got.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberS{Value: tc.value})
			if err == nil {
				t.Fatalf("accepted %q, which a range filter cannot order correctly", tc.value)
			}
		})
	}

	// The canonical encoding must of course round-trip, or the strictness is just
	// breakage.
	at := time.Date(2026, 3, 1, 12, 0, 5, 500_000_000, time.UTC)
	var got instant
	if err := got.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberS{Value: encodeInstant(at)}); err != nil {
		t.Fatalf("rejected its own encoding: %v", err)
	}
	if !got.Time().Equal(at) {
		t.Errorf("round-tripped to %s, want %s", got.Time(), at)
	}

	// An absent value is not a mis-encoded one.
	for _, av := range []types.AttributeValue{
		&types.AttributeValueMemberNULL{Value: true},
		&types.AttributeValueMemberS{Value: ""},
	} {
		var zero instant
		if err := zero.UnmarshalDynamoDBAttributeValue(av); err != nil {
			t.Errorf("%T rejected: %v", av, err)
		}
		if !zero.Time().IsZero() {
			t.Errorf("%T decoded to %s, want the zero instant", av, zero.Time())
		}
	}
}

// TestNonCanonicalRowIsRefusedOnRead records exactly what a hypothetical
// mis-encoded row does now, end to end, including the part that is still not
// fixed and is not claimed to be.
func TestNonCanonicalRowIsRefusedOnRead(t *testing.T) {
	t.Parallel()
	recs, db := newRecordsForTest(t)
	ctx := context.Background()

	// A canonical row that must be swept, so this test cannot pass by returning
	// nothing at all.
	canonical := lifecycletest.NewRecord("canonical")
	canonical.ExpiresAt = time.Date(2025, 12, 31, 22, 0, 0, 0, time.UTC)
	if err := recs.Create(ctx, canonical); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The same instant, spelled with a +14:00 offset, injected beneath the store.
	db.items[pkPrefixCredential+"legacy"] = map[string]map[string]types.AttributeValue{
		skMetadata: legacyItem("legacy", "2026-01-01T12:00:00+14:00"),
	}

	// Read directly: refused, loudly, naming the reason.
	if _, err := recs.Get(ctx, "legacy"); err == nil {
		t.Error("Get accepted a row whose encoding cannot be ordered; the permissive reader is back")
	}

	now := time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC)
	got, err := recs.ListExpiring(ctx, now)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}

	// The canonical row is swept. This is the assertion that matters, and the one
	// the offset fix bought.
	assertContainsID(t, got, "canonical")

	// And the honest part: the mis-encoded row is *not* returned, and cannot be.
	// DynamoDB applies the filter to stored bytes before anything is decoded, so no
	// reader -- strict or permissive -- gets a say. This is asserted rather than
	// left implicit so the limitation is impossible to mistake for a fix: strictness
	// makes such a row detectable on every read path except the one that filters it
	// out first.
	for _, rec := range got {
		if rec.ID == "legacy" {
			t.Fatal("the filter now returns offset-spelled rows; if that is intended, " +
				"the comment on decodeInstant about migration passes needs rewriting")
		}
	}
}

func assertContainsID(t *testing.T, recs []lifecycle.Record, want string) {
	t.Helper()
	for _, rec := range recs {
		if rec.ID == want {
			return
		}
	}
	t.Fatalf("records %v do not include %q", ids(recs), want)
}
