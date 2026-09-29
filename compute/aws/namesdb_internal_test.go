// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"strings"
	"testing"
)

// TestSanitizeIsSanitizeWithTheFullStop pins that the two entry points cannot
// diverge.
//
// [sanitize] delegates to [sanitizeWith] today, so the assertion is trivially
// true — which is the point. There is one implementation of the construction and
// one place its injectivity is argued, and if somebody re-inlines the body into
// [sanitize] "for clarity" this test is what notices. A comment saying "these
// agree" is the artefact-drifts-from-code defect in its cheapest form.
//
// Quantified over the shared corpus rather than over three names, for the same
// reason everything else about this function is.
func TestSanitizeIsSanitizeWithTheFullStop(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"", "apphub-", "apphub/"} {
		for _, limit := range []int{maxIAMRoleName, maxECRRepositoryName} {
			for _, name := range injectivityCorpus(t, prefix, limit, digestMarker) {
				wantName, wantErr := sanitizeWith(prefix, name, limit, digestMarker)
				gotName, gotErr := sanitize(prefix, name, limit)
				if gotName != wantName || (gotErr == nil) != (wantErr == nil) {
					t.Fatalf("sanitize(%q, %q, %d) = (%q, %v), sanitizeWith with the full stop = "+
						"(%q, %v); the two have diverged, so the construction now has two "+
						"implementations and only one of them has been argued sound",
						prefix, name, limit, gotName, gotErr, wantName, wantErr)
				}
			}
		}
	}
}

// TestRDSIdentifiersAreInjectiveAndLegal states the property the relational
// port's naming has to have, and states it as a conjunction.
//
// Two halves, and the reason they are asserted together rather than separately is
// CONTRACT lesson 8: a name that is injective and illegal is a provisioning
// failure at deploy time, a name that is legal and not injective is two
// applications sharing one database, and each half verified on its own leaves the
// interaction — which is where both failures actually live — unchecked.
//
// The population is [injectivityCorpus], the same set the full-stop marker is
// quantified over. It includes punctuation, whitespace, case variants, leading
// digits, the length boundary, and strings shaped like a rendered name under this
// marker.
//
// # Why case behaves the way it does here
//
// [sanitizeWith]'s verbatim clause requires clean == name byte for byte, so
// "MyDB" is never verbatim and always digests while "mydb" is verbatim. That
// asymmetry is correct rather than a wart, and it is correct *because* of RDS: RDS
// lowercases an identifier server-side, so two names differing only in case would
// otherwise resolve to one cluster. Do not "fix" it.
func TestRDSIdentifiersAreInjectiveAndLegal(t *testing.T) {
	t.Parallel()

	// A prefix is required for the relational port and validated at
	// construction, because it is what supplies RDS's leading-letter rule. The
	// empty prefix is included anyway, with a name that begins with a digit, to
	// show that the legality half of the conjunction is a real check and not one
	// that happens to be satisfied by the fixture.
	for _, prefix := range []string{"apphub-", "db", "a", ""} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			t.Parallel()
			corpus := injectivityCorpus(t, prefix, maxRDSIdentifier, rdsDigestMarker)
			if len(corpus) < 20 {
				// A derivation returning nothing passes every check over it.
				t.Fatalf("the corpus has only %d entries, which is too few for the property to "+
					"mean anything", len(corpus))
			}
			seen := map[string]string{}
			legal := 0
			for _, name := range corpus {
				got, err := sanitizeWith(prefix, name, maxRDSIdentifier, rdsDigestMarker)
				if err != nil {
					// A refusal is a legal answer and collides with nothing.
					continue
				}
				// Legality, at the resolution the failure lives at: RDS is what
				// rejects this string, so the grammar is what it is checked
				// against.
				if !rdsIdentifier.MatchString(got) {
					if rdsPrefix.MatchString(prefix) {
						t.Errorf("sanitizeWith(%q, %q) = %q, which is not a legal RDS identifier "+
							"even though the prefix is one this provider would accept; RDS "+
							"requires a leading letter, single hyphens, and no trailing hyphen",
							prefix, name, got)
					}
					// With a prefix the provider would refuse at construction,
					// an illegal identifier is the expected outcome rather than
					// a defect — but it still must not be reported as usable, so
					// it is excluded from the injectivity population below
					// rather than counted as a collision.
					continue
				}
				legal++
				if len(got) > maxRDSIdentifier {
					t.Errorf("sanitizeWith(%q, %q) produced %d characters, over RDS's %d",
						prefix, name, len(got), maxRDSIdentifier)
				}
				if first, dup := seen[got]; dup {
					t.Errorf("COLLISION: %q and %q both resolve to RDS identifier %q. Two "+
						"applications would share one Aurora cluster, both would carry this "+
						"platform's ownership tag and the same component tag, and the ownership "+
						"check cannot tell two legitimate callers apart — so one application's "+
						"data is reachable by the other", first, name, got)
					continue
				}
				seen[got] = name
			}
			if rdsPrefix.MatchString(prefix) && legal < 20 {
				t.Errorf("only %d of %d corpus entries produced a legal RDS identifier under "+
					"prefix %q; the injectivity half of this property was quantified over almost "+
					"nothing", legal, len(corpus), prefix)
			}
		})
	}
}

// TestTheTwoMarkersDifferInExactlyTheWayTheMechanismAssumes asserts the premise
// the hasDigestTail exclusion exists for, rather than leaving it in a comment.
//
// The premise is one sentence: the full stop **cannot** appear in a verbatim
// rendering, and the RDS hyphen **can**. That is precisely why the full-stop
// marker needs no exclusion clause and the RDS marker does — and if the premise
// ever stopped holding, the clause would be either dead code with a stale
// justification or a missing check with a live collision behind it.
//
// It also pins that a name rendered with the RDS marker is a legal RDS
// identifier, which is the other half of why that marker was chosen.
func TestTheTwoMarkersDifferInExactlyTheWayTheMechanismAssumes(t *testing.T) {
	t.Parallel()

	// A name that is already lossless and contains a hyphen renders verbatim,
	// so the hyphen survives into the output.
	verbatim, err := sanitizeWith("", "app-x9", maxRDSIdentifier, rdsDigestMarker)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if !strings.Contains(verbatim, rdsDigestMarker) {
		t.Fatalf("the verbatim rendering of %q is %q and does not contain the RDS marker %q; the "+
			"hasDigestTail exclusion in sanitizeWith is then dead code and its justification is "+
			"stale", "app-x9", verbatim, rdsDigestMarker)
	}
	if strings.Contains(verbatim, digestMarker) {
		t.Fatalf("a verbatim rendering contains the full-stop marker %q, which is the property "+
			"USOSS-10's disjointness argument rests on", digestMarker)
	}
	// And the exclusion actually fires: a name spelled exactly like a rendered
	// one must not be granted verbatim status.
	lookalike := "app" + rdsDigestMarker + strings.Repeat("a", digestLength)
	got, err := sanitizeWith("", lookalike, maxRDSIdentifier, rdsDigestMarker)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got == lookalike {
		t.Errorf("%q was rendered verbatim as %q, so it occupies the same string as the digested "+
			"form of some other name and the two sets are not disjoint", lookalike, got)
	}

	if !rdsIdentifier.MatchString("a" + rdsDigestMarker + strings.Repeat("0", digestLength)) {
		t.Fatalf("a name rendered with rdsDigestMarker %q is not a legal RDS identifier, so every "+
			"digested relational name would be refused", rdsDigestMarker)
	}
}

// TestHasDigestTailKeysOffTheDigestLengthConstant is the drift check USOSS-10
// asked for.
//
// A literal in place of [digestLength] would turn the verbatim exclusion off
// silently the day the digest length changed — the name would still render with
// the new length, and a verbatim candidate with the *old* length would slip
// through the clause meant to exclude it. The property is asserted by
// construction: a tail of exactly digestLength hex digits is recognised and one
// of any other length is not.
func TestHasDigestTailKeysOffTheDigestLengthConstant(t *testing.T) {
	t.Parallel()
	hex := strings.Repeat("a", digestLength)
	if !hasDigestTail("app"+rdsDigestMarker+hex, rdsDigestMarker) {
		t.Errorf("a tail of exactly %d hex digits was not recognised", digestLength)
	}
	for _, off := range []int{-1, 1} {
		n := digestLength + off
		if n < 1 {
			continue
		}
		if hasDigestTail("app"+rdsDigestMarker+strings.Repeat("a", n), rdsDigestMarker) {
			t.Errorf("a tail of %d hex digits was recognised, but the digest is %d; hasDigestTail "+
				"is not keyed off the constant the renderer uses", n, digestLength)
		}
	}
	// Not hex, so not a digest.
	if hasDigestTail("app"+rdsDigestMarker+strings.Repeat("z", digestLength), rdsDigestMarker) {
		t.Error("a non-hexadecimal tail was recognised as a digest")
	}
	// The marker is what separates the tail. A tail with no marker before it is
	// part of the name.
	if hasDigestTail("app"+hex, rdsDigestMarker) {
		t.Error("a tail with no marker before it was recognised as a digest")
	}
}

// TestSanitizeWithDigestsTheOriginalName is the half USOSS-10 verified and asked
// the next port to verify too.
//
// Digesting the slug instead of the input would make two names that slug
// identically digest identically — the punctuation collision one layer down, with
// the fix closing nothing. It is asserted rather than read: two names that slug
// to the same string must render to different identifiers.
func TestSanitizeWithDigestsTheOriginalName(t *testing.T) {
	t.Parallel()
	for _, marker := range []string{digestMarker, rdsDigestMarker} {
		// Both slug to "app-x9", and both are lossy, so both take the digest
		// path. If the digest were over the slug they would be equal.
		a, errA := sanitizeWith("db-", "app_x9", maxRDSIdentifier, marker)
		b, errB := sanitizeWith("db-", "app!!x9", maxRDSIdentifier, marker)
		if errA != nil || errB != nil {
			t.Fatalf("unexpected refusal: %v / %v", errA, errB)
		}
		if a == b {
			t.Errorf("marker %q: %q and %q both render as %q; the digest is over the sanitized "+
				"slug rather than over the original name, so the punctuation collision has moved "+
				"one layer down rather than being closed", marker, "app_x9", "app!!x9", a)
		}
	}
}

// TestRelationalNamesRefuseAnOversizedPrefix pins that the writer-instance
// suffix does not get its room by truncating an already-injective identifier.
//
// Truncating the cluster identifier to fit "-w" would drop digest characters, and
// two clusters whose identifiers agreed on their first 61 characters would share
// one instance. Refusing is the answer, and this is the branch that does it.
func TestRelationalNamesRefuseAnOversizedPrefix(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Relational: &RelationalConfig{
		NamePrefix: strings.Repeat("a", maxRDSIdentifier-digestLength) + "-",
	}}}
	if _, err := p.relationalNames("some-application"); err == nil {
		t.Error("a prefix that leaves no room for a digest and a writer suffix was accepted")
	}
}
