// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/conductorone/apphub/modules/review"
)

// The tests in this file state properties and quantify over a generated
// population, rather than naming the cases that were thought of. Each one also
// runs its control in the other direction: a sanitiser that rejected
// everything would satisfy every "this is refused" assertion on its own.

// safePathSegments are segments a repository path is built from. The
// acceptance population is every combination of these up to three deep, so it
// covers depth as well as content.
var safePathSegments = []string{"a", "src", "main.go", "x-y", "x_y", "x.y", "9", "A"}

func acceptablePaths() []string {
	var out []string
	for _, a := range safePathSegments {
		out = append(out, a)
		for _, b := range safePathSegments {
			out = append(out, a+"/"+b)
			for _, c := range safePathSegments {
				out = append(out, a+"/"+b+"/"+c)
			}
		}
	}
	return out
}

func TestSanitisePathAcceptsEveryWellFormedRelativePath(t *testing.T) {
	population := acceptablePaths()
	if len(population) < 500 {
		t.Fatalf("the acceptance population is %d paths, which is too small to be quantifying over", len(population))
	}
	for _, p := range population {
		if got := review.SanitisePath(p); got != p {
			t.Errorf("SanitisePath(%q) = %q, want it returned unchanged", p, got)
		}
	}
	t.Logf("accepted %d well-formed paths", len(population))
}

// TestSanitisePathRefusesEveryUnsafeShape is the other direction, and it is
// generated rather than listed: each unsafe fragment is inserted at every
// position of every well-formed path, so the property being checked is "no
// placement of this fragment survives" rather than "this one example does not".
func TestSanitisePathRefusesEveryUnsafeShape(t *testing.T) {
	fragments := []string{
		"..", ".", "",
		"a b", "a\tb", "a\nb", "a\x00b",
		"a:b", "a?b", "a#b", "a%2e", "a\\b", "a|b", "a;b", "a&b",
		"a*b", "a[b", "a~b", "a^b", "a`b", "a$b", "a'b", "a\"b",
		"é", " ", "\u200b",
	}
	bases := [][]string{
		{"x"},
		{"x", "y"},
		{"src", "pkg", "file.go"},
	}
	checked := 0
	for _, frag := range fragments {
		for _, base := range bases {
			for pos := 0; pos <= len(base); pos++ {
				segments := make([]string, 0, len(base)+1)
				segments = append(segments, base[:pos]...)
				segments = append(segments, frag)
				segments = append(segments, base[pos:]...)
				p := strings.Join(segments, "/")
				checked++
				if got := review.SanitisePath(p); got != "" {
					t.Errorf("SanitisePath(%q) = %q, want it refused", p, got)
				}
			}
		}
	}
	// Absolute paths and the length bound, which are not segment-shaped.
	for _, p := range []string{"/x", "//x", "/", strings.Repeat("a", review.MaxPathBytes+1)} {
		checked++
		if got := review.SanitisePath(p); got != "" {
			t.Errorf("SanitisePath(%q) = %q, want it refused", p, got)
		}
	}
	// The boundary itself is accepted, so the bound is a bound and not an
	// off-by-one that refuses one byte early.
	atLimit := strings.Repeat("a", review.MaxPathBytes)
	if got := review.SanitisePath(atLimit); got != atLimit {
		t.Errorf("SanitisePath refused a path of exactly MaxPathBytes; the bound is off by one")
	}
	t.Logf("refused %d unsafe paths", checked)
}

// TestTruncateUTF8AlwaysProducesValidUTF8 quantifies over every cut position
// of strings built from multi-byte runes, which is where a byte-offset slice
// splits a codepoint. A test that cut one string at one offset would pass on
// an implementation that happened to land on a boundary.
func TestTruncateUTF8AlwaysProducesValidUTF8(t *testing.T) {
	inputs := []string{
		strings.Repeat("é", 400),
		strings.Repeat("€", 400),
		strings.Repeat("\U0001d11e", 400),
		strings.Repeat("aé€\U0001d11e", 200),
		strings.Repeat("a", 400),
		strings.Repeat("á", 300),
	}
	checked := 0
	for _, in := range inputs {
		for limit := 1; limit <= len(in); limit++ {
			got := review.TruncateUTF8(in, limit)
			checked++
			if !utf8.ValidString(got) {
				t.Fatalf("TruncateUTF8(<%d bytes>, %d) produced invalid UTF-8", len(in), limit)
			}
			// The result must also survive the encoder, which is the failure
			// the rune-boundary cut exists to prevent.
			if _, err := json.Marshal(got); err != nil {
				t.Fatalf("TruncateUTF8(<%d bytes>, %d) produced something json cannot encode: %v", len(in), limit, err)
			}
			if limit >= len(in) && got != in {
				t.Fatalf("TruncateUTF8 changed a string that was already within the limit")
			}
		}
	}
	t.Logf("checked %d truncations", checked)
}

// TestNormaliseSeverityAdmitsTheLadderAndNothingElse runs both directions over
// a derived population: the ladder comes from [review.Severities], so a value
// added to the type is covered without this test being edited.
func TestNormaliseSeverityAdmitsTheLadderAndNothingElse(t *testing.T) {
	ladder := review.Severities()
	if len(ladder) < 2 {
		t.Fatalf("the severity ladder has %d entries; there is nothing to distinguish", len(ladder))
	}
	for _, s := range ladder {
		if got := review.NormaliseSeverity(string(s)); got != s {
			t.Errorf("NormaliseSeverity(%q) = %q, want it unchanged", s, got)
		}
	}
	// Everything else collapses to info, including near-misses that a
	// case-insensitive or prefix match would let through.
	outside := []string{
		"", " ", "CRITICAL", "Critical", "critical ", " critical", "crit",
		"criticals", "criticalx", "xcritical", "highest", "sev1", "urgent",
		"none", "unknown", "info ", "INFO", "0", "9",
	}
	for _, s := range outside {
		if got := review.NormaliseSeverity(s); got != review.SeverityInfo {
			t.Errorf("NormaliseSeverity(%q) = %q, want %q", s, got, review.SeverityInfo)
		}
	}
	t.Logf("admitted %d ladder values, collapsed %d others", len(ladder), len(outside))
}

// TestHighestSeverityRanksTheWholeLadder checks every ordered pair, so the
// ranking is exercised as an order rather than at one comparison.
func TestHighestSeverityRanksTheWholeLadder(t *testing.T) {
	ladder := review.Severities()
	for i, a := range ladder {
		for j, b := range ladder {
			findings := []review.Finding{{Severity: a}, {Severity: b}}
			want := a
			if j < i {
				want = b
			}
			if got := review.HighestSeverity(findings); got != want {
				t.Errorf("HighestSeverity(%q, %q) = %q, want %q", a, b, got, want)
			}
		}
	}
	if got := review.HighestSeverity(nil); got != review.SeverityInfo {
		t.Errorf("HighestSeverity(nil) = %q, want %q", got, review.SeverityInfo)
	}
	// An invented severity must not win, which is the reason normalisation
	// happens before ranking rather than after.
	mixed := []review.Finding{{Severity: review.SeverityLow}, {Severity: "catastrophic"}}
	if got := review.HighestSeverity(mixed); got != review.SeverityLow {
		t.Errorf("HighestSeverity with an invented severity = %q, want %q", got, review.SeverityLow)
	}
	t.Logf("checked %d ordered severity pairs", len(ladder)*len(ladder))
}

// TestSanitiseIsIdempotentAndTotal checks the whole-finding sanitiser over a
// generated population, and checks that applying it twice changes nothing --
// which is the property a consumer relies on when it re-sanitises something it
// read back.
func TestSanitiseIsIdempotentAndTotal(t *testing.T) {
	paths := []string{"", "ok/path.go", "../escape", "/absolute", "a b", strings.Repeat("x", review.MaxPathBytes+1)}
	severities := []string{"critical", "high", "medium", "low", "info", "invented", ""}
	snippets := []string{"", "short", strings.Repeat("é", review.MaxSnippetBytes)}
	lines := []int{-5, 0, 1, 4000}

	checked := 0
	for _, p := range paths {
		for _, s := range severities {
			for _, sn := range snippets {
				for _, ln := range lines {
					f := review.Finding{Path: p, Severity: review.Severity(s), Snippet: sn, Line: ln, Title: "t"}
					once := f.Sanitise()
					twice := once.Sanitise()
					checked++
					if once != twice {
						t.Fatalf("Sanitise is not idempotent for %+v: %+v then %+v", f, once, twice)
					}
					if !severityIsOnLadder(once.Severity) {
						t.Fatalf("Sanitise left the off-ladder severity %q", once.Severity)
					}
					if once.Path != "" && review.SanitisePath(once.Path) != once.Path {
						t.Fatalf("Sanitise left the unsafe path %q", once.Path)
					}
					if once.Path == "" && once.Line != 0 {
						t.Fatalf("Sanitise left line %d on a finding with no path", once.Line)
					}
					if once.Line < 0 {
						t.Fatalf("Sanitise left the negative line %d", once.Line)
					}
					if len(once.Snippet) > review.MaxSnippetBytes+len("...") {
						t.Fatalf("Sanitise left a snippet of %d bytes", len(once.Snippet))
					}
					if !utf8.ValidString(once.Snippet) {
						t.Fatalf("Sanitise left an invalid-UTF-8 snippet")
					}
				}
			}
		}
	}
	t.Logf("checked %d findings", checked)
}

func severityIsOnLadder(s review.Severity) bool {
	for _, v := range review.Severities() {
		if v == s {
			return true
		}
	}
	return false
}

// TestSanitisedFindingsAlwaysEncode is the end of the chain the sanitiser
// exists for: whatever a scanner returns, the result can be serialised. A
// store that cannot write the findings turns a successful scan into a failure.
func TestSanitisedFindingsAlwaysEncode(t *testing.T) {
	var findings []review.Finding
	for i, p := range []string{"a/b.go", "../x", "", "/abs"} {
		findings = append(findings, review.Finding{
			CheckID:  fmt.Sprintf("check-%d", i),
			Severity: "invented",
			Title:    strings.Repeat("é", 300),
			Detail:   "\x1b[31m",
			Path:     p,
			Line:     -1,
			Snippet:  strings.Repeat("\U0001d11e", 500),
		}.Sanitise())
	}
	if _, err := json.Marshal(findings); err != nil {
		t.Fatalf("sanitised findings did not encode: %v", err)
	}
	t.Logf("encoded %d sanitised findings", len(findings))
}
