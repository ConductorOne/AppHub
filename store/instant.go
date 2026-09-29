// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The invariant this file exists to hold:
//
//	Every instant this package persists is stored in a form whose lexical order
//	is its temporal order.
//
// It is stated as an invariant rather than left implicit because three separate
// defects in this package have been the same defect: a lexical ordering standing
// in for a temporal one.
//
//  1. The source system compared ExpiresAt against a time.RFC3339Nano string.
//     That format drops trailing zeros, so "…:05Z" sorts after "…:05.5Z" and an
//     expiry landing on a whole second could be skipped while genuinely expired.
//  2. The same format in a GSI sort key made "newest first" approximate within
//     any given second.
//  3. An expiry written in a non-UTC zone -- 2026-01-01T12:00:00+14:00, an
//     instant already an hour in the past at 2025-12-31T23:00:00Z -- sorted above
//     a UTC bound and was never swept. A credential that had expired, that the
//     platform believed live indefinitely.
//
// Each was found separately and the first two were patched separately, which is
// how the third survived: every fix named a case and none named the class. So
// there is one encoding, one type, and one property test over it, and nothing in
// this package writes a timestamp any other way.
//
// The encoding is RFC 3339 in UTC with the fractional part fixed at nine digits.
// Fixed width is what makes byte order agree with chronology -- DynamoDB compares
// strings bytewise and has no idea they are times -- and normalising the zone is
// what stops an offset spelling from reordering the value. Both are required;
// either alone leaves a hole, and holes 1 and 3 above are exactly those two
// halves.
const (
	// instantLayout renders an instant. The zone suffix is appended rather than
	// formatted, because a bare "Z" is not a layout token and Z07:00 would render
	// "+00:00" for some values -- which would break the very ordering this exists
	// to guarantee.
	instantLayout = "2006-01-02T15:04:05.000000000"

	// instantZone is the only zone suffix this package ever writes.
	instantZone = "Z"

	// instantZero is the encoding of the zero instant, which means "no expiry" on
	// a credential record. ListExpiring filters it out server-side; it is spelled
	// here so that the filter and the encoding cannot drift apart.
	instantZero = "0001-01-01T00:00:00.000000000Z"
)

// instant is a time.Time that persists in the order-preserving encoding above.
//
// It is a distinct type rather than a convention, because a convention is a thing
// people remember and this one has been forgotten three times. A plain time.Time
// on credentialItem would marshal through the SDK's default encoder, which is
// RFC3339Nano in whatever zone the value happens to carry -- the exact behaviour
// that produced all three defects.
type instant time.Time

// Compile-time proof that the SDK will route through the methods below rather
// than its default time encoder. Without these assertions a signature typo would
// silently reinstate the default, which is the bug rather than a variant of it.
var (
	_ interface {
		MarshalDynamoDBAttributeValue() (types.AttributeValue, error)
	} = instant{}
	_ interface {
		UnmarshalDynamoDBAttributeValue(types.AttributeValue) error
	} = (*instant)(nil)
)

// MarshalDynamoDBAttributeValue writes the order-preserving encoding.
func (i instant) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberS{Value: encodeInstant(time.Time(i))}, nil
}

// UnmarshalDynamoDBAttributeValue reads it back, accepting only the encoding
// above.
//
// This used to accept any RFC 3339 string, on the reasoning that a record written
// by an older build should stay readable. Review showed that to be false comfort,
// and the way it was false is worth recording.
//
// A permissive reader sits *downstream of the query*. ListExpiring's filter
// compares stored bytes lexically, so an offset-spelled expiry is excluded before
// any unmarshal runs: the permissive path decoded such a row perfectly well
// through Get, while the sweep that actually matters could not see it at all. That
// is coverage exactly where it is not needed and none where it is -- which reads,
// to anyone scanning this file, as support for a case that is not supported.
//
// So the claim is withdrawn rather than half-honoured. Nothing has ever written
// another encoding: store/ was introduced with this encoding, and no deployment
// exists. If a differently-spelled row ever appears it is an out-of-band write or
// a bug, and failing loudly is the right answer, because the alternative is the
// defect this whole file exists to prevent -- a credential that expired and that
// nothing will ever sweep. An error on read is noisy and fixable; a row that
// silently sorts wrong is neither.
//
// If a migration ever does become necessary, the answer is a migration pass, not a
// permanently widened scan bound: widening the bound enough to catch a +14:00
// spelling means reading more than a day of extra records on every reconciler pass
// forever, to protect against data that does not exist.
func (i *instant) UnmarshalDynamoDBAttributeValue(av types.AttributeValue) error {
	switch v := av.(type) {
	case *types.AttributeValueMemberNULL:
		// An explicitly null attribute is an absent value, not a mis-encoded one.
		*i = instant(time.Time{})
		return nil

	case *types.AttributeValueMemberS:
		if v.Value == "" {
			// Likewise an empty string: absent, not wrong.
			*i = instant(time.Time{})
			return nil
		}
		t, err := decodeInstant(v.Value)
		if err != nil {
			return err
		}
		*i = instant(t)
		return nil

	default:
		return fmt.Errorf("store: instant must be a string attribute, got %T", av)
	}
}

// decodeInstant parses the canonical encoding and nothing else.
//
// The check is a round trip, and that is deliberate: "canonical" is defined as
// "what encodeInstant produces", so asking whether re-encoding reproduces the
// input is the definition rather than a proxy for it. An earlier version checked
// the length, the zone suffix and the layout separately; mutation testing showed
// the first two were unreachable behind the third, which is dead weight in a
// function whose whole job is to be obviously right.
//
// It also makes the error useful. A caller is told the exact string the row should
// have contained, which is what a migration would need to write.
func decodeInstant(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: parsing instant %q: %w", v, err)
	}
	if canonical := encodeInstant(t); canonical != v {
		return time.Time{}, fmt.Errorf(
			"store: instant %q is not the canonical encoding (want %q): only fixed-width UTC is stored, "+
				"because a range filter compares these bytes and any other spelling sorts wrongly -- "+
				"which is how an expired credential goes unswept",
			v, canonical)
	}
	return t.UTC(), nil
}

// Time returns the instant as a time.Time in UTC.
func (i instant) Time() time.Time { return time.Time(i).UTC() }

// encodeInstant renders t so that byte order is chronological order.
//
// Normalising to UTC first is not cosmetic. The same instant written
// 2026-01-01T12:00:00+14:00 and 2025-12-31T22:00:00Z are equal, but as strings
// the first sorts a year later, and a range filter comparing them against a UTC
// bound silently omits it.
func encodeInstant(t time.Time) string {
	return t.UTC().Format(instantLayout) + instantZone
}
