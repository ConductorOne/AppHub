// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials/c1"
)

// The two populations every handle test quantifies over.
//
// They are populations rather than cases on purpose. The first version of a test
// like this on this project named thirteen cases and every gap it missed sat one
// generalisation away from a case it had. So the property is stated -- "every
// segment inside the grammar round-trips, and every segment outside it is
// refused" -- and both sides are generated.
//
// Both are asserted non-empty by every test that uses them, because a derivation
// that returns nothing passes every check made over it.
func validSegments() []string {
	return []string{
		"a",                            // one character, the shortest the grammar allows
		"A0",                           // mixed case
		"1234567890123456789012345",    // a service-principal-shaped identifier
		"abcdefghijklmnopqrstuvwxy",    // all lower
		"quick-brown-12345",            // a credential-shaped identifier
		"with.dots.inside",             // interior dot
		"with_underscores",             // interior underscore
		"a" + strings.Repeat("x", 127), // the longest the grammar allows
		"0start",                       // digit first
		"mIxEd-Case_and.dots-9",        // everything at once
	}
}

// invalidSegments is the population of things that must never become half of a
// handle.
//
// It contains more than the shapes the implementation happens to enumerate,
// which is the point: a fixture whose population contains only cases the
// implementation already handles is a control that cannot fire. Several of these
// are here because they are what a path-traversal attempt looks like after one
// layer of decoding has already happened.
func invalidSegments() []string {
	return []string{
		"",                             // empty
		".",                            // dot segment
		"..",                           // parent segment
		"...",                          // leading dot at all
		".hidden",                      // leading dot
		"-leading",                     // leading dash
		"_leading",                     // leading underscore
		"has/slash",                    // the separator itself
		"has%2Fslash",                  // the separator, encoded once
		"has%252Fslash",                // the separator, encoded twice
		"..%2f..",                      // traversal, encoded
		"../../etc/passwd",             // traversal, plain
		"has space",                    // whitespace
		"has\ttab",                     // whitespace, other
		"has\nnewline",                 // a line break, which would also split a log line
		"has\x00null",                  // a NUL
		"has?query",                    // a query delimiter
		"has#fragment",                 // a fragment delimiter
		"has:colon",                    // a scheme delimiter
		"has@at",                       // a userinfo delimiter
		"has\\backslash",               // a separator on another platform
		"café",                         // non-ASCII
		"a" + strings.Repeat("x", 128), // one byte over the grammar's length
		strings.Repeat("x", 4096),      // far over it
	}
}

func TestFormatAndParseRoundTripEveryValidPair(t *testing.T) {
	valid := validSegments()
	if len(valid) < 2 {
		t.Fatalf("the valid population is %d segments; a population this small cannot exercise a grammar", len(valid))
	}

	pairs := 0
	for _, sp := range valid {
		for _, cred := range valid {
			ref := c1.Ref{ServicePrincipalID: sp, CredentialID: cred}
			handle, err := c1.FormatHandle(ref)
			if err != nil {
				t.Fatalf("FormatHandle refused a pair inside the grammar (segment lengths %d/%d): %v",
					len(sp), len(cred), err)
			}
			got, err := c1.ParseHandle(handle)
			if err != nil {
				t.Fatalf("ParseHandle refused a handle FormatHandle built (segment lengths %d/%d): %v",
					len(sp), len(cred), err)
			}
			if got != ref {
				t.Fatalf("round trip changed the reference (segment lengths %d/%d)", len(sp), len(cred))
			}
			pairs++
		}
	}
	if pairs != len(valid)*len(valid) {
		t.Fatalf("exercised %d pairs, expected %d", pairs, len(valid)*len(valid))
	}
	t.Logf("round-tripped %d pairs", pairs)
}

func TestEverySegmentOutsideTheGrammarIsRefused(t *testing.T) {
	invalid := invalidSegments()
	if len(invalid) == 0 {
		t.Fatal("the invalid population is empty, so this test cannot fail")
	}
	// One known-good partner, so a refusal is attributable to the segment under
	// test rather than to the pair.
	good := validSegments()[0]

	checked := 0
	for _, bad := range invalid {
		for _, ref := range []c1.Ref{
			{ServicePrincipalID: bad, CredentialID: good},
			{ServicePrincipalID: good, CredentialID: bad},
		} {
			if _, err := c1.FormatHandle(ref); !errors.Is(err, c1.ErrMalformedHandle) {
				t.Errorf("FormatHandle accepted a segment outside the grammar (length %d, quoted-len %d): err=%v",
					len(bad), len(bad), err)
			}
			checked++
		}
		// Parsing is the direction that matters at revoke time: the value arrives
		// from the platform's own persisted record, so it has never been through
		// FormatHandle in this process.
		if _, err := c1.ParseHandle(good + "/" + bad); err == nil {
			t.Errorf("ParseHandle accepted a credential segment outside the grammar (length %d)", len(bad))
		}
		if _, err := c1.ParseHandle(bad + "/" + good); err == nil {
			t.Errorf("ParseHandle accepted a principal segment outside the grammar (length %d)", len(bad))
		}
		checked += 2
	}
	if checked != len(invalid)*4 {
		t.Fatalf("exercised %d refusals, expected %d", checked, len(invalid)*4)
	}
	t.Logf("refused %d out-of-grammar inputs", checked)
}

func TestParseHandleRequiresExactlyOneSeparator(t *testing.T) {
	good := validSegments()[0]
	other := validSegments()[1]

	// Zero separators, and every count above one. A handle with two separators is
	// the interesting one: a tolerant parser that split on the first and ignored
	// the rest would accept "a/b/../../c" as naming credential "b".
	for _, in := range []string{
		"",
		good,
		good + other,
		good + "/" + other + "/" + good,
		good + "//" + other,
		"/" + good,
		good + "/",
		"/",
		"//",
		good + "/" + other + "/",
	} {
		if _, err := c1.ParseHandle(in); !errors.Is(err, c1.ErrMalformedHandle) {
			t.Errorf("ParseHandle accepted a handle with a separator count other than one (length %d): err=%v", len(in), err)
		}
	}
}

func TestMalformedHandleErrorsCarryNothingFromTheInput(t *testing.T) {
	// A platformKeyID arrives from the platform's persisted record. If that record
	// ever held credential material -- which is precisely what
	// credentials.CreateNotDeliveredError exists to stop happening, and therefore
	// precisely what a record may contain if something went wrong -- an error that
	// quoted it would publish it.
	const sentinel = "Zx7Zx7Zx7Zx7Zx7Zx7Zx7Zx7Zx7Zx7Zx7"
	for _, in := range []string{
		sentinel,
		sentinel + "/" + sentinel + "/" + sentinel,
		"../" + sentinel,
		sentinel + "/has space",
	} {
		_, err := c1.ParseHandle(in)
		if err == nil {
			t.Fatalf("ParseHandle accepted %d bytes it should have refused", len(in))
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("ParseHandle's error rendered its input")
		}
	}
	_, err := c1.FormatHandle(c1.Ref{ServicePrincipalID: sentinel + "/x", CredentialID: sentinel})
	if err == nil {
		t.Fatal("FormatHandle accepted a segment containing a separator")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Error("FormatHandle's error rendered its input")
	}
}

func TestRefIsZeroNeedsBothHalves(t *testing.T) {
	good := validSegments()[0]
	for _, ref := range []c1.Ref{
		{},
		{ServicePrincipalID: good},
		{CredentialID: good},
	} {
		if !ref.IsZero() {
			t.Errorf("Ref with a missing half reported IsZero() == false")
		}
	}
	if (c1.Ref{ServicePrincipalID: good, CredentialID: good}).IsZero() {
		t.Error("a complete Ref reported IsZero() == true")
	}
}
