// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package errhygiene

// The mechanism's own tests.
//
// Everything here is about resolution: whether the leak checks can see a defect
// the size of the ones this repository has actually shipped. Three of the four
// live holes review found in this fixture's ancestors were invisible to a check
// that was looking, at a resolution below the failure -- a whole-string
// containment test against a one-byte leak, a six-byte window against a five-byte
// field, a verb list against a path that asks no value to render itself. So each
// of those is a case below rather than a property asserted in a comment.
//
// What is NOT here is a test that Assert fails for a bad Subject, because Assert
// takes a *testing.T and there is no honest way to fake one. That half is covered
// by the eight packages that drive it: a new exported input, a new error type and
// a reverted sanitisation were each mutated into those packages and each failed.

import (
	"reflect"
	"strings"
	"testing"
)

// TestTheSentinelsAreDisjointAndEqualLength restates the init() guard as a test,
// because a panic in init is a build failure in whatever package happens to import
// this one, and that is not where a reader looks for the reason.
func TestTheSentinelsAreDisjointAndEqualLength(t *testing.T) {
	if len(sentinelA) != len(sentinelB) {
		t.Fatalf("the sentinels are %d and %d bytes; a permitted count would then read as a "+
			"difference between the two runs", len(sentinelA), len(sentinelB))
	}
	if len(sentinelA) == 0 {
		t.Fatal("the sentinels are empty, so every check over them passes")
	}
	for i := range len(sentinelA) {
		if sentinelA[i] == sentinelB[i] {
			t.Fatalf("the sentinels share byte %d (%q); a shared byte is a byte the differential "+
				"check cannot see, which is exactly how encoding/json's one-quoted-byte leak "+
				"survived the first version of this fixture", i, sentinelA[i])
		}
	}
	// Renderings are scrubbed of 0x... addresses, so the scrub must not be able to
	// eat a sentinel. Note what the property is and is not: both sentinels DO
	// contain hexadecimal digits ("Qz3", "Wk8"), and an earlier comment on this
	// fixture claimed neither alphabet was hexadecimal, which was simply false. What
	// is true, and what the scrub actually needs, is that the pattern cannot match a
	// sentinel -- Q, z, W and k are not hex, so no run of sentinel bytes is an
	// address.
	for _, sent := range []string{sentinelA, sentinelB} {
		if got := addr.ReplaceAllString(sent, "0xADDR"); got != sent {
			t.Errorf("the address scrub rewrites a sentinel to %q, so it could hide a leak", got)
		}
	}
	// A sentinel that is re-encoded on the way through a URL or a JSON body changes
	// length, and equal lengths are what makes a permitted count agree between the
	// two runs.
	if strings.ContainsAny(sentinelA+sentinelB, "\"\\/?#&= ") {
		t.Error("a sentinel contains a byte that JSON or a URL would escape, so its length would " +
			"change in transit and a count would read as a difference")
	}
}

// slots builds a reachable from literal texts, for the comparisons below.
func slots(texts ...string) reachable {
	return reachable{Texts: texts, Paths: labels("slot", len(texts))}
}

// TestOneByteQuotedIntoAMessageIsSeenByTheDifferentialAndNotByLeakedSlots pins
// which half of the mechanism sees the failure this repository has paid for three
// times: encoding/json's "invalid character 'R'", which quotes exactly one byte of
// its input into a longer message.
//
// It matters that this is written down, because the two halves have different
// resolutions and the difference is not obvious. leakedSlots compares the
// REPRESENTATION slot for slot, and its spliced-text branch deliberately stops at
// embedWindow bytes -- below that, a same-offset match in two runs is not evidence,
// because a four-byte coincidence in random ciphertext is already 2^-32 and a
// one-byte one is not rare at all. The differential comparison of the whole
// RENDERING has no such floor: two runs that render identically cannot differ by
// one byte, so a single quoted byte fails it.
//
// The consequence, stated so nobody removes the wrong half: neither check alone
// holds the invariant. Deleting the whole-rendering comparison would lose the
// one-byte case; deleting leakedSlots would lose every path that asks no value to
// render itself.
func TestOneByteQuotedIntoAMessageIsSeenByTheDifferentialAndNotByLeakedSlots(t *testing.T) {
	msgA := "invalid character '" + sentinelA[0:1] + "' looking for beginning of value"
	msgB := "invalid character '" + sentinelB[0:1] + "' looking for beginning of value"
	if strings.Contains(msgA, sentinelA) {
		t.Fatal("this case is meant to be invisible to containment; it is not")
	}
	if leakedSlots(slots(msgA), slots(msgB), sentinelA, sentinelB) != "" {
		t.Error("leakedSlots reported a one-byte splice. That is a stronger claim than its " +
			"embedWindow floor supports; if it is now true, say why here rather than leaving the " +
			"floor documented and unused")
	}
	a, b := renderAll([]any{errString(msgA)}), renderAll([]any{errString(msgB)})
	if a.Text == b.Text {
		t.Error("two renderings that quote one byte of two byte-disjoint inputs came out identical, " +
			"so the differential check is below the resolution the failure lives at")
	}
}

func TestLeakedSlotsSeesAWholeFieldOfAnyLength(t *testing.T) {
	// A plaintext field, at every length from one byte to the whole sentinel, at
	// every offset. Review escaped an earlier version with a five-byte field that a
	// six-byte window stepped over, so the bound is asserted over the range rather
	// than at one convenient size.
	for l := 1; l <= len(sentinelA); l++ {
		for o := 0; o+l <= len(sentinelA); o++ {
			a, b := slots(sentinelA[o:o+l]), slots(sentinelB[o:o+l])
			if leakedSlots(a, b, sentinelA, sentinelB) == "" {
				t.Fatalf("a %d-byte field at input offset %d was not seen", l, o)
			}
		}
	}
}

func TestLeakedSlotsSeesInputSplicedIntoLongerText(t *testing.T) {
	for l := embedWindow; l <= len(sentinelA); l++ {
		a := slots("dial tcp " + sentinelA[:l] + ".example.com:443: connect: refused")
		b := slots("dial tcp " + sentinelB[:l] + ".example.com:443: connect: refused")
		if leakedSlots(a, b, sentinelA, sentinelB) == "" {
			t.Fatalf("%d bytes of the input spliced into a longer string was not seen", l)
		}
	}
}

func TestLeakedSlotsDoesNotFireOnConstantText(t *testing.T) {
	// The control. A check that reports a leak for everything is not a check, and
	// two runs of a driver that renders only repository constants are identical.
	same := "credentials: a provider created a credential and could not deliver its material"
	if got := leakedSlots(slots(same, "", "[NOT RENDERED]"), slots(same, "", "[NOT RENDERED]"),
		sentinelA, sentinelB); got != "" {
		t.Errorf("constant text reported as a leak: %s", got)
	}
}

func TestLeakedSlotsRefusesToCompareDifferentShapes(t *testing.T) {
	// A driver whose output shape depends on its input cannot be compared slot for
	// slot, and silently comparing the prefix would be a check that looked at less
	// than it claimed.
	if got := leakedSlots(slots("a", "b"), slots("a"), sentinelA, sentinelB); got == "" {
		t.Error("two runs of different shapes compared clean; the pairing that buys the one-byte " +
			"resolution does not exist between them")
	}
}

// TestReachableTextReadsUnexportedFields is one of the two live holes review
// found. reflect.Value.String does not require an exported field, so a type that
// keeps caller text in an unexported string and relies on every reader going
// through an accessor is a check rather than a construction.
func TestReachableTextReadsUnexportedFields(t *testing.T) {
	type holder struct {
		hidden string
		Bytes  []byte
	}
	got := reachableText([]any{&holder{hidden: sentinelA, Bytes: []byte(sentinelA)}})
	var sawString, sawBytes bool
	for i, p := range got.Paths {
		if strings.HasSuffix(p, ".hidden") && got.Texts[i] == sentinelA {
			sawString = true
		}
		if strings.HasSuffix(p, ".Bytes") && got.Texts[i] == sentinelA {
			sawBytes = true
		}
	}
	if !sawString {
		t.Error("the walk did not read an unexported string field")
	}
	if !sawBytes {
		t.Error("the walk did not read a byte slice")
	}
	if got.Truncated {
		t.Error("the walk truncated on a two-field struct, so its bounds are wrong")
	}
}

// TestReachableTextOrdersMapsDeterministically is the property the whole
// slot-for-slot pairing rests on, and it is the reason this walk is not
// internal/reachable's. Go randomises map iteration; two runs that disagree about
// slot order compare noise.
func TestReachableTextOrdersMapsDeterministically(t *testing.T) {
	build := func() map[string]string {
		return map[string]string{"zeta": "3", "alpha": "1", "mu": "2", "beta": "4", "omega": "5"}
	}
	first := reachableText([]any{build()})
	for range 32 {
		got := reachableText([]any{build()})
		if !reflect.DeepEqual(got.Texts, first.Texts) {
			t.Fatalf("two walks of equal maps produced different slot orders:\n%v\n%v",
				first.Texts, got.Texts)
		}
	}
	if len(first.Texts) == 0 {
		t.Fatal("the walk found nothing in a five-entry map")
	}
}

// revealer has an exported zero-argument method that hands back what it holds.
// This is USOSS-43's shape, and the shape review used to escape an earlier version
// of this fixture: no verb reaches it, and text/template calls it by name.
type revealer struct{ held string }

func (r revealer) Reveal() string { return r.held }

func TestMethodAndTemplateTextReachesAZeroArgumentMethod(t *testing.T) {
	got := methodAndTemplateText([]any{revealer{held: sentinelA}})
	direct, viaTemplate := false, false
	for i, p := range got.Paths {
		if got.Texts[i] != sentinelA {
			continue
		}
		if strings.Contains(p, "(direct)") {
			direct = true
		}
		if strings.Contains(p, "template") {
			viaTemplate = true
		}
	}
	if !direct {
		t.Error("calling the method directly did not recover what it holds")
	}
	if !viaTemplate {
		t.Error("{{.Reveal}} did not recover what it holds, which is the path USOSS-43 tracks and " +
			"the one no list of fmt verbs can reach")
	}
}

// TestRenderAllCountsOnlyWhatCanBecomeText pins the difference between "nothing
// rendered the input" and "nothing was rendered", which is the distinction the
// per-driver Count check rests on.
func TestRenderAllCountsOnlyWhatCanBecomeText(t *testing.T) {
	type opaque struct{ N int }
	if got := renderAll([]any{opaque{N: 1}, nil, (*opaque)(nil)}); got.Count != 0 {
		t.Errorf("a struct with no path to text counted as %d rendered value(s)", got.Count)
	}
	if got := renderAll([]any{errString(sentinelA)}); got.Count != 1 {
		t.Errorf("an error counted as %d rendered value(s), want 1", got.Count)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestDeriveFilesEveryExportedCallable runs the derivation and the independent
// recount against this package, which is a real one with exported functions,
// exported types and unexported everything else.
//
// Two categories -- an exported var of func type, and an exported func-typed
// struct field -- are empty in every package this repository has today, exactly as
// they were before USOSS-52. They are the two shapes that defeated the first,
// syntactic derivation, so they are named here rather than left to be noticed:
// nothing in this repository exercises them, and the code that files them is
// covered by review's original reproductions rather than by a running test.
func TestDeriveFilesEveryExportedCallable(t *testing.T) {
	s, err := derive("github.com/conductorone/apphub/internal/errhygiene")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(s.Entries) == 0 {
		t.Fatal("derived no exported inputs from a package that exports several")
	}
	total := countExportedCallables(s.pkg)
	if got := len(s.Entries) + len(s.Parameterless); got != total+s.promotedFields {
		t.Errorf("the recount reports %d exported callables (+%d promoted); the derivation filed %d",
			total, s.promotedFields, got)
	}
	if s.deepEmbedding {
		t.Error("the field walk hit its embedding bound on this package")
	}
	if s.Pkg != "errhygiene" {
		t.Errorf("the derivation named the package %q", s.Pkg)
	}
}

// TestTheSweepFindsWhatTheTypeCheckerFinds runs the build-constraint-free syntax
// sweep over this package and requires every declaration it names to be one the
// type checker also reports. The two mechanisms are meant to disagree only when a
// constrained file exists, and this package has none.
func TestTheSweepFindsWhatTheTypeCheckerFinds(t *testing.T) {
	s, err := derive("github.com/conductorone/apphub/internal/errhygiene")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	known := map[string]bool{}
	for k := range s.Entries {
		known[k] = true
	}
	for k := range s.Parameterless {
		known[k] = true
	}
	for k := range s.Renderers {
		known[k] = true
	}

	files, decls, where, err := sweep(".")
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if files == 0 || len(decls) == 0 {
		t.Fatalf("the sweep parsed %d file(s) and %d declaration(s); it would pass vacuously",
			files, len(decls))
	}
	for _, alts := range decls {
		if !anyKnown(known, alts) {
			t.Errorf("%s is declared in %s and the go/types derivation does not know it",
				alts[0], where[alts[0]])
		}
	}
}
