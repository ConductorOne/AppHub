// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package citations

import (
	"strings"
	"testing"
	"testing/fstest"
)

func mapFile(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

// goFile returns valid, parseable Go source of exactly n lines: a package
// clause plus n-1 comment lines. scanGoFile parses every ".go" file it walks,
// citations or not, so a fixture standing in for a real source file must
// still be real Go -- only its line count matters to the tests here.
func goFile(n int) *fstest.MapFile {
	lines := make([]string, n)
	lines[0] = "package pkg"
	for i := 1; i < n; i++ {
		lines[i] = "// x"
	}
	return mapFile(strings.Join(lines, "\n") + "\n")
}

// TestOutOfRangeCitationIsDangling reproduces USOSS-68's defect exactly: a
// citation past the end of the file it names. store/dynamo.go was 138 lines
// and cited as :150-156; this fixture is the same shape at a size a test can
// hold. Red-then-green: the citation is wrong in the fixture as written
// (Dangling), and correcting the range (the second case) turns it Local.
func TestOutOfRangeCitationIsDangling(t *testing.T) {
	t.Parallel()

	fiveLines := "package store\n\n// line3\n// line4\n// line5\n"

	cases := []struct {
		name string
		body string
		want Kind
	}{
		{
			name: "red: past the end of a 5-line file",
			body: "// See dynamo.go:6-8 for the fence this mirrors.\npackage aws\n",
			want: Dangling,
		},
		{
			name: "green: the same citation corrected to an in-range line",
			body: "// See dynamo.go:3-4 for the fence this mirrors.\npackage aws\n",
			want: Local,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fsys := fstest.MapFS{
				"dynamo.go": mapFile(fiveLines),
				"citing.go": mapFile(tc.body),
			}
			_, all, err := Check(fsys)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if len(all) != 1 {
				t.Fatalf("found %d citations, want 1: %+v", len(all), all)
			}
			if all[0].Kind != tc.want {
				t.Fatalf("kind = %s, want %s (%+v)", all[0].Kind, tc.want, all[0])
			}
		})
	}
}

// TestOffByTwoAtTheLeadingEdgeIsDangling reproduces the shape of USOSS-68's
// third instance -- names.go:277-291, "off by two lines at the leading edge" --
// as an inverted or below-range citation, which is the only part of that
// defect a mechanical check can see at all (the rest of it was substantively
// correct content one line off, which is [Check]'s documented blind spot: see
// TestASemanticMismatchInAnInRangeCitationIsNotDetected below).
func TestOffByTwoAtTheLeadingEdgeIsDangling(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"names.go":  goFile(10),
		"citing.go": mapFile("// names.go:0-3 names the ownership marker.\npackage aws\n"),
	}
	findings, _, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
}

// TestASemanticMismatchInAnInRangeCitationIsNotDetected pins the package doc
// comment's central claim: a citation that is real and in-range, but about
// something other than what the comment claims, produces no finding.
// compute/aws/identity.go:99-104 was exactly this shape -- in-range code about
// rendering a trust policy, cited by a comment claiming it was about
// ownership -- and USOSS-68's own retrospective says a lexical check cannot
// tell the two apart. This test measures that limit rather than asserting
// around it.
func TestASemanticMismatchInAnInRangeCitationIsNotDetected(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"identity.go": mapFile("package aws\n\nfunc renderTrustPolicy() {\n\t// nothing to do with ownership\n}\n"),
		"citing.go": mapFile(
			"// Ownership is checked at write time; identity.go:3-4 records the same finding.\n" +
				"package aws\n"),
	}
	findings, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a content mismatch produced a finding this package cannot make: %+v", findings)
	}
	if len(all) != 1 || all[0].Kind != Local {
		t.Fatalf("citation = %+v, want one Local citation", all)
	}
}

// TestBareCitationResolvesAgainstItsOwnDirectorySibling reproduces USOSS-71's
// silent defect: a comment in one package cites another system's file by its
// bare name, and that name collides with a real sibling in the citing
// comment's own directory. This package resolves the bare name the way a
// careless reader would -- against the sibling -- which is what makes the
// out-of-range half of the class ([TestSiblingCollisionOutOfRangeIsCaught])
// decidable at all.
func TestBareCitationResolvesAgainstItsOwnDirectorySibling(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"pkg/sibling.go": goFile(50),
		"pkg/citing.go":  mapFile("// Replaces the DynamoDB path (sibling.go:10-12).\npackage pkg\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("found %d citations, want 1: %+v", len(all), all)
	}
	if all[0].Kind != Local || all[0].Resolved != "pkg/sibling.go" {
		t.Fatalf("citation = %+v, want Local against pkg/sibling.go", all[0])
	}
}

// TestSiblingCollisionOutOfRangeIsCaught is the case USOSS-71 actually found
// ten of: the bare citation above, but with a range past the sibling's end --
// exactly what capability.go's "Replaces the ECS service path
// (container.go:527-935)" looked like against a 343-line compute/container.go.
func TestSiblingCollisionOutOfRangeIsCaught(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"pkg/sibling.go": goFile(50),
		"pkg/citing.go":  mapFile("// Replaces the ECS service path (sibling.go:100-200).\npackage pkg\n"),
	}
	findings, _, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
}

// TestGroupMembershipOverridesAnOtherwiseDanglingSibling is the second signal
// USOSS-71 asked for: one group member citing a file this repository does not
// carry anywhere proves the whole group is about that other system, even when
// another member's bare name would otherwise resolve -- in this case, resolve
// to a range past its sibling's end, which would be reported as Dangling on
// its own (see the previous test). capability.go's CapSecretStore citation,
// "(container.go:301-334, :1138-1154, postgres_roles.go:230-248)", is this
// exact shape: postgres_roles.go exists nowhere in the repository.
func TestGroupMembershipOverridesAnOtherwiseDanglingSibling(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"pkg/sibling.go": goFile(50),
		"pkg/citing.go": mapFile(
			"// mechanism (sibling.go:100-200, :210-220, absent.go:1-2).\npackage pkg\n"),
	}
	findings, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("group membership should have cleared the dangling sibling citation: %+v", findings)
	}
	if len(all) != 3 {
		t.Fatalf("found %d citations, want 3: %+v", len(all), all)
	}
	for _, c := range all {
		if c.Kind != External {
			t.Errorf("%s: kind = %s, want External (one group member is provably external)", c.Text, c.Kind)
		}
	}
}

// TestGroupWithNoExternalMemberIsJudgedOnItsOwnMerits is the control for the
// previous test: without a provably-external member, the group signal must
// not fire, and each citation is judged on whether its own target resolves.
func TestGroupWithNoExternalMemberIsJudgedOnItsOwnMerits(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"pkg/a.go":      goFile(10),
		"pkg/b.go":      goFile(10),
		"pkg/citing.go": mapFile("// see (a.go:1-2, b.go:20-30).\npackage pkg\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("found %d citations, want 2: %+v", len(all), all)
	}
	if all[0].Kind != Local {
		t.Errorf("a.go:1-2 = %s, want Local", all[0].Kind)
	}
	if all[1].Kind != Dangling {
		t.Errorf("b.go:20-30 = %s, want Dangling (b.go only has 10 lines)", all[1].Kind)
	}
}

// TestDirectoryQualifiedCitationIsCheckedAtItsExactPath asserts that a
// citation carrying its own directory component -- "compute/aws/identity.go",
// not "identity.go" -- is resolved against that exact repository path rather
// than a sibling, regardless of which file cites it.
func TestDirectoryQualifiedCitationIsCheckedAtItsExactPath(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"compute/aws/identity.go": goFile(400),
		"credentials/aws/api.go":  mapFile("// See compute/aws/identity.go:99-104.\npackage aws\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 1 || all[0].Kind != Local || all[0].Resolved != "compute/aws/identity.go" {
		t.Fatalf("citation = %+v, want Local against compute/aws/identity.go", all)
	}
}

// TestNonexistentTargetIsExternal is the "self-announcing" majority case:
// most of this repository's citations name the source system it
// was ported from, which this repository does not carry under any path.
func TestNonexistentTargetIsExternal(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"citing.go": mapFile("// The source system does this in build.go:100-200.\npackage aws\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 1 || all[0].Kind != External {
		t.Fatalf("citation = %+v, want External", all)
	}
}

// TestBareFilenameWithNoRangeIsNotTracked pins the documented scope limit:
// a filename mention with no line number carries nothing this package could
// check, so it produces no [Citation] at all.
func TestBareFilenameWithNoRangeIsNotTracked(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"citing.go": mapFile("// It is store/dynamo.go's fence, applied here for the same reason.\npackage aws\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("a rangeless mention was tracked as a citation: %+v", all)
	}
}

// TestContinuationAcrossCommentLines reproduces the shape config.go actually
// uses: a bare ":N-M" continuation on the *next* `//` line, still inheriting
// the file name a comma introduced it with. If this package flattened each
// comment line independently instead of joining the group, the continuation
// would have nothing to inherit and would be silently dropped.
func TestContinuationAcrossCommentLines(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"pkg/sibling.go": goFile(50),
		"pkg/citing.go": mapFile(
			"// recovers a VPC from the first subnet alone (sibling.go:1-2,\n" +
				"// :40-60), and lets CreateLoadBalancer fail if the rest disagree.\n" +
				"package pkg\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("found %d citations, want 2 (the continuation was dropped): %+v", len(all), all)
	}
	if all[0].Target != "sibling.go" || all[1].Target != "sibling.go" {
		t.Fatalf("continuation did not inherit the file name: %+v", all)
	}
	if all[1].From != 40 || all[1].To != 60 {
		t.Fatalf("continuation range = %d-%d, want 40-60", all[1].From, all[1].To)
	}
}

// TestMarkdownParagraphBoundaryEndsAGroup asserts that a blank line -- a
// paragraph break -- ends a citation group, so a citation opening one bullet
// is never joined to a citation opening the next merely because both happen
// to sit in the same file.
func TestMarkdownParagraphBoundaryEndsAGroup(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"a.go": goFile(10),
		"b.go": goFile(10),
		"doc.md": mapFile(
			"First, see `a.go:1-2`,\n\n" +
				"and separately `b.go:1-2` in the next paragraph.\n"),
	}
	_, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("found %d citations, want 2: %+v", len(all), all)
	}
	if all[0].Kind != Local || all[1].Kind != Local {
		t.Fatalf("citations = %+v, want both Local (each resolves on its own)", all)
	}
}

// TestEmptyTreeReportsNothingRatherThanErroring asserts Check tolerates a tree
// with no citations at all -- an empty result is not itself a failure the way
// it is for [internal/decisions], because most packages legitimately cite
// nothing.
func TestEmptyTreeReportsNothingRatherThanErroring(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"a.go": mapFile("package a\n")}
	findings, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 0 || len(all) != 0 {
		t.Fatalf("findings=%v all=%v, want both empty", findings, all)
	}
}

// TestTestdataAndDotDirectoriesAreSkipped asserts fixture trees are not
// themselves scanned for citations -- a deliberately-broken fixture under
// testdata/ must never fail this repository's own citation check.
func TestTestdataAndDotDirectoriesAreSkipped(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"testdata/broken.go": mapFile("// broken.go:9999-9999 is nowhere near this file.\npackage x\n"),
		".hidden/broken.go":  mapFile("// broken.go:9999-9999 is nowhere near this file.\npackage x\n"),
	}
	findings, all, err := Check(fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 0 || len(all) != 0 {
		t.Fatalf("a fixture or dot directory was scanned: findings=%v all=%v", findings, all)
	}
}

func TestKindString(t *testing.T) {
	t.Parallel()
	for k, want := range map[Kind]string{Local: "local", Dangling: "dangling", External: "external"} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}
