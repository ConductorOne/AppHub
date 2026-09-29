// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package disclosure_test

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/conductorone/apphub/internal/disclosure"
)

// repoRoot is the tree this gate is about. The test runs from
// internal/disclosure, so the repository root is two levels up.
const repoRoot = "../.."

// TestTheModuleTreePublishesNoDetectionVocabulary is the gate.
//
// It walks every package under modules/ rather than naming review and fix, so
// a module added later is covered without this file being edited.
func TestTheModuleTreePublishesNoDetectionVocabulary(t *testing.T) {
	findings, coverage, err := disclosure.Scan(os.DirFS(repoRoot), "modules")
	if err != nil {
		t.Fatalf("scanning the module tree: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
	// A scan that read nothing would report no findings, which is the failure
	// mode this whole class of check has.
	if coverage.Packages < 3 || coverage.Files == 0 || coverage.Bytes == 0 {
		t.Fatalf("read %d package(s), %d file(s), %d byte(s); the walk is not covering the tree",
			coverage.Packages, coverage.Files, coverage.Bytes)
	}
	t.Logf("scanned %d package(s), %d file(s), %d byte(s) against %d identifier shape(s)",
		coverage.Packages, coverage.Files, coverage.Bytes, len(disclosure.Shapes))
}

// TestEveryShapeHasBothControls exercises each pattern in both directions. A
// pattern that matched nothing would let the gate pass over any tree at all.
//
// Every example here is invented. A control for a rule about not publishing
// real terms must not publish real terms to prove itself, which is the same
// rule the project applies to detection rules generally.
func TestEveryShapeHasBothControls(t *testing.T) {
	controls := map[string]struct {
		positive []string
		negative []string
	}{
		"ranked web-application risk category": {
			positive: []string{"Z99:PlaceholderClass", "a Q00:Example here", `"Y42:Thing"`},
			negative: []string{"Z9:Short", "1234:Numeric", "AB:NoDigits", "Z999:TooMany", "Z99Colonless"},
		},
		"software-weakness catalogue entry": {
			positive: []string{"QQQ-12", "see ZZZ-9999 for detail"},
			negative: []string{"AB-12", "QQQQ-12", "QQQ-1", "qqq-12", "QQQ12"},
		},
		"dotted check identifier": {
			positive: []string{"placeholder.example-check", "a xyz.abc-def-ghi token"},
			negative: []string{"caps.go", "pnpm-lock.yaml", "ab.cd-ef", "docs/decisions/", "x.y", "Foo.Bar-Baz"},
		},
	}
	if len(controls) != len(disclosure.Shapes) {
		t.Fatalf("%d shape(s) are declared and %d are exercised; a shape with no control is a shape "+
			"with no evidence", len(disclosure.Shapes), len(controls))
	}
	checked := 0
	for _, shape := range disclosure.Shapes {
		control, ok := controls[shape.Name]
		if !ok {
			t.Fatalf("the shape %q has no control", shape.Name)
		}
		for _, p := range control.positive {
			checked++
			if !shape.Pattern.MatchString(p) {
				t.Errorf("the %q pattern does not match %q, so it would not catch one", shape.Name, p)
			}
		}
		for _, n := range control.negative {
			checked++
			if shape.Pattern.MatchString(n) {
				t.Errorf("the %q pattern matches %q, which is not one", shape.Name, n)
			}
		}
	}
	t.Logf("exercised %d control(s) across %d shape(s)", checked, len(disclosure.Shapes))
}

// TestPlantedVocabularyIsCaught runs the real Scan over a synthetic tree
// carrying one planted line per shape, in the two places the defect actually
// occurred: a doc comment and a test fixture.
//
// This is the fixture the project's rule about gates asks for -- it fails
// before the guard exists and passes after -- and it exercises the walk rather
// than the patterns, which the controls above cover separately.
func TestPlantedVocabularyIsCaught(t *testing.T) {
	planted := fstest.MapFS{
		"modules/example/doc.go": &fstest.MapFile{Data: []byte(
			"package example\n\n// CheckID is a slug, e.g. \"placeholder.example-check\".\n")},
		"modules/example/example_test.go": &fstest.MapFile{Data: []byte(
			"package example\n\nvar categories = []string{\"Z99:PlaceholderClass\", \"QQQ-798\"}\n")},
	}
	findings, coverage, err := disclosure.Scan(planted, "modules")
	if err != nil {
		t.Fatalf("scanning the planted tree: %v", err)
	}
	if coverage.Files != 2 || coverage.Packages != 1 {
		t.Fatalf("read %d file(s) in %d package(s), want 2 in 1", coverage.Files, coverage.Packages)
	}
	shapes := map[string]int{}
	for _, f := range findings {
		shapes[f.Shape.Name]++
	}
	if len(shapes) != len(disclosure.Shapes) {
		t.Fatalf("the planted tree produced findings for %d of %d shape(s): %v",
			len(shapes), len(disclosure.Shapes), shapes)
	}
	// Both files, so the walk covers a comment and a fixture alike.
	files := map[string]bool{}
	for _, f := range findings {
		files[f.File] = true
	}
	if len(files) != 2 {
		t.Fatalf("findings came from %d file(s), want both: %v", len(files), files)
	}
	t.Logf("caught %d planted finding(s) across %d shape(s) in %d file(s)",
		len(findings), len(shapes), len(files))
}

// TestACleanTreeProducesNothing is the negative control on Scan itself: a tree
// with no vocabulary must produce no findings, so the gate is not simply
// reporting everything it reads.
func TestACleanTreeProducesNothing(t *testing.T) {
	clean := fstest.MapFS{
		"modules/example/doc.go": &fstest.MapFile{Data: []byte(
			"package example\n\n// CheckID is a slug the scanner chooses.\n")},
		"modules/example/example.go": &fstest.MapFile{Data: []byte(
			"package example\n\nvar paths = []string{\"pnpm-lock.yaml\", \"go.sum\", \"caps.go\"}\n")},
	}
	findings, coverage, err := disclosure.Scan(clean, "modules")
	if err != nil {
		t.Fatalf("scanning the clean tree: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a clean tree produced %d finding(s): %v", len(findings), findings)
	}
	if coverage.Files != 2 {
		t.Fatalf("read %d file(s), want 2", coverage.Files)
	}
}
