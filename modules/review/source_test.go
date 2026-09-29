// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules/review"
)

// TestValidateOwnerRepoAcceptsEveryNameAHostWouldAccept is the acceptance half
// of the control. It matters because the validator is the only thing standing
// between a caller and a request path, so a validator that refused everything
// would be perfectly secure and completely useless -- and every "this is
// refused" assertion below would still pass.
func TestValidateOwnerRepoAcceptsEveryNameAHostWouldAccept(t *testing.T) {
	names := []string{
		"a", "A", "9", "ab", "a-b", "a_b", "a.b", "a.b.c", "a--b", "a__b",
		"AppHub", "apphub-2", "9lives", "x" + strings.Repeat("y", 37),
	}
	checked := 0
	for _, owner := range names {
		for _, repo := range names {
			checked++
			if err := review.ValidateOwnerRepo(owner, repo); err != nil {
				t.Errorf("ValidateOwnerRepo(%q, %q) = %v, want accepted", owner, repo, err)
			}
		}
	}
	// The two length bounds, exactly at the limit.
	if err := review.ValidateOwnerRepo(strings.Repeat("a", review.MaxOwnerLen), strings.Repeat("b", review.MaxRepoLen)); err != nil {
		t.Errorf("names of exactly the maximum length were refused: %v", err)
	}
	t.Logf("accepted %d owner/repo pairs", checked)
}

// TestValidateOwnerRepoRefusesEveryUnsafeShape quantifies over each unsafe
// fragment in each of the two positions, so a validator that checked only the
// owner would fail here rather than pass on an example that happened to use it.
func TestValidateOwnerRepoRefusesEveryUnsafeShape(t *testing.T) {
	bad := []string{
		"", ".", "..", "-x", ".x", "_x", "a/b", "a b", "a\tb", "a\nb", "a\x00b",
		"a:b", "a?b", "a#b", "a%b", "a\\b", "a|b", "a;b", "a&b", "a*b", "a[b",
		"a~b", "a^b", "a`b", "a$b", "a'b", "a\"b", "é", "a@b", "a=b", "a+b",
	}
	checked := 0
	for _, b := range bad {
		checked++
		if err := review.ValidateOwnerRepo(b, "ok"); err == nil {
			t.Errorf("ValidateOwnerRepo(%q, \"ok\") accepted an unsafe owner", b)
		}
		checked++
		if err := review.ValidateOwnerRepo("ok", b); err == nil {
			t.Errorf("ValidateOwnerRepo(\"ok\", %q) accepted an unsafe repo", b)
		}
	}
	// The two length bounds differ, so each needs its own case. An earlier
	// version of this test applied the owner bound to both positions and
	// reported a defect that was not there: a name one character over the
	// owner limit is a perfectly ordinary repository name.
	if err := review.ValidateOwnerRepo(strings.Repeat("a", review.MaxOwnerLen+1), "ok"); err == nil {
		t.Errorf("ValidateOwnerRepo accepted an owner over the length bound")
	}
	if err := review.ValidateOwnerRepo("ok", strings.Repeat("a", review.MaxRepoLen+1)); err == nil {
		t.Errorf("ValidateOwnerRepo accepted a repo name over the length bound")
	}
	t.Logf("refused %d unsafe owner/repo names", checked)
}

// TestIsSafeRefAcceptsRealRevisions is the acceptance control.
func TestIsSafeRefAcceptsRealRevisions(t *testing.T) {
	refs := []string{
		"main", "master", "v1.2.3", "release/2026-q2.1", "feature/x_y-z",
		"refs/heads/main", "refs/tags/v1", "0123456789abcdef0123456789abcdef01234567",
		"a", "a/b/c/d/e",
	}
	for _, r := range refs {
		if !review.IsSafeRef(r) {
			t.Errorf("IsSafeRef(%q) = false, want true", r)
		}
	}
	t.Logf("accepted %d revisions", len(refs))
}

// TestIsSafeRefRefusesEveryUnsafeShape inserts each unsafe fragment at each
// position of a multi-segment ref, so "the check only looks at the first
// segment" fails here.
func TestIsSafeRefRefusesEveryUnsafeShape(t *testing.T) {
	fragments := []string{
		"..", "a..b", "a b", "a\tb", "a\nb", "a\rb", "a\x00b", "a:b", "a?b",
		"a#b", "a%b", "a\\b", "a|b", "a;b", "a&b", "a*b", "a[b", "a~b", "a^b",
		"a`b", "a$b", "a'b", "a\"b", "é", "a@b", "", "a b",
	}
	bases := [][]string{{"x"}, {"refs", "heads", "x"}, {"a", "b", "c"}}
	checked := 0
	for _, frag := range fragments {
		for _, base := range bases {
			for pos := 0; pos <= len(base); pos++ {
				segments := make([]string, 0, len(base)+1)
				segments = append(segments, base[:pos]...)
				segments = append(segments, frag)
				segments = append(segments, base[pos:]...)
				ref := strings.Join(segments, "/")
				checked++
				if review.IsSafeRef(ref) {
					t.Errorf("IsSafeRef(%q) = true, want false", ref)
				}
			}
		}
	}
	// A leading dash is refused wherever the ref would be read as an option.
	for _, r := range []string{"-x", "-", "--force", "", strings.Repeat("a", review.MaxRefLen+1)} {
		checked++
		if review.IsSafeRef(r) {
			t.Errorf("IsSafeRef(%q) = true, want false", r)
		}
	}
	if !review.IsSafeRef(strings.Repeat("a", review.MaxRefLen)) {
		t.Errorf("IsSafeRef refused a ref of exactly MaxRefLen; the bound is off by one")
	}
	t.Logf("refused %d unsafe revisions", checked)
}

// TestCoordinatesAuthenticatedTracksTheInstallation states the property the
// public/installation split rests on, over the boundary and both sides of it.
func TestCoordinatesAuthenticatedTracksTheInstallation(t *testing.T) {
	for _, id := range []int64{-1, 0} {
		if (review.Coordinates{InstallationID: id}).Authenticated() {
			t.Errorf("Coordinates{InstallationID: %d}.Authenticated() = true, want false", id)
		}
	}
	for _, id := range []int64{1, 2, 1 << 40} {
		if !(review.Coordinates{InstallationID: id}).Authenticated() {
			t.Errorf("Coordinates{InstallationID: %d}.Authenticated() = false, want true", id)
		}
	}
}

// TestIntegerParamsReadEveryShapeAJSONDecoderProduces is the reason the
// readers exist: a parameter map decoded from JSON carries float64, and a
// programmatic caller passes int. A reader that handled one would silently
// reject half its callers, which is what it did in the source before this
// shape was added.
func TestIntegerParamsReadEveryShapeAJSONDecoderProduces(t *testing.T) {
	for _, v := range []any{float64(7), int(7), int32(7), int64(7)} {
		got, ok := review.PositiveIntParam(map[string]any{"k": v}, "k")
		if !ok || got != 7 {
			t.Errorf("PositiveIntParam with %T(7) = (%d, %v), want (7, true)", v, got, ok)
		}
	}
	// Zero is positive to neither reader and non-negative to one of them, and
	// a fractional value is a caller error rather than a rounding opportunity.
	rejectedByPositive := []any{float64(0), int(0), float64(-1), int64(-1), float64(1.5), "7", nil, true, []any{7}}
	for _, v := range rejectedByPositive {
		if _, ok := review.PositiveIntParam(map[string]any{"k": v}, "k"); ok {
			t.Errorf("PositiveIntParam accepted %#v", v)
		}
	}
	for _, v := range []any{float64(0), int(0), int64(0)} {
		if got, ok := review.NonNegativeIntParam(map[string]any{"k": v}, "k"); !ok || got != 0 {
			t.Errorf("NonNegativeIntParam with %T(0) = (%d, %v), want (0, true)", v, got, ok)
		}
	}
	for _, v := range []any{float64(-1), int(-1), float64(0.5), "0", nil} {
		if _, ok := review.NonNegativeIntParam(map[string]any{"k": v}, "k"); ok {
			t.Errorf("NonNegativeIntParam accepted %#v", v)
		}
	}
	// A missing key is absent, not zero.
	if _, ok := review.PositiveIntParam(map[string]any{}, "k"); ok {
		t.Errorf("PositiveIntParam reported a missing key as present")
	}
	if _, ok := review.StringParam(map[string]any{"k": ""}, "k"); ok {
		t.Errorf("StringParam reported an empty string as present")
	}
	if got, ok := review.StringParam(map[string]any{"k": "v"}, "k"); !ok || got != "v" {
		t.Errorf("StringParam(%q) = (%q, %v)", "v", got, ok)
	}
}
