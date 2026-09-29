// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/modules/fix"
	"github.com/conductorone/apphub/modules/review"
)

func testLimits() fix.Limits {
	return fix.Limits{
		MaxFiles:             fix.SuggestedMaxFiles,
		MaxLines:             fix.SuggestedMaxLines,
		MaxBytesPerFile:      fix.SuggestedMaxBytesPerFile,
		MaxEncodedPatchBytes: fix.SuggestedMaxEncodedPatchBytes,
		TerminalWriteTimeout: 5 * time.Second,
	}
}

// TestSupplyChainCategoryAdmitsOnlyItsOwnSet is the check on the one input
// that widens what a patch may touch. It runs in both directions over a
// derived population: every member of the set is admitted, and every
// perturbation of every member is refused.
//
// The perturbations are the shapes the source admitted. It split the category
// on separators and accepted it if any fragment was in the set, so
// "artificial-intelligence/ci" unlocked the workflow directory -- and the
// category is a string a model wrote while reading a repository this process
// does not control.
func TestSupplyChainCategoryAdmitsOnlyItsOwnSet(t *testing.T) {
	set := fix.SupplyChainCategories()
	if len(set) < 10 {
		t.Fatalf("the supply-chain set has %d entries; there is not enough here to be quantifying over", len(set))
	}
	for _, c := range set {
		if !fix.IsSupplyChainCategory(c) {
			t.Errorf("IsSupplyChainCategory(%q) = false for a member of its own set", c)
		}
		// The three spellings normalisation is documented to fold.
		for _, variant := range []string{strings.ToUpper(c), " " + c + " ", strings.ReplaceAll(c, "-", "_")} {
			if !fix.IsSupplyChainCategory(variant) {
				t.Errorf("IsSupplyChainCategory(%q) = false; it is %q under the documented normalisation", variant, c)
			}
		}
	}

	refused := 0
	for _, c := range set {
		perturbations := []string{
			c + "/x", "x/" + c, // the source's separator split
			c + " x", "x " + c,
			c + ",x", "x," + c,
			c + ";x", c + "+x", c + "|x",
			c + "x", "x" + c, // substring, which an earlier source version admitted
			c + "-x", "x-" + c,
			c + ".", "." + c,
		}
		for _, p := range perturbations {
			refused++
			if fix.IsSupplyChainCategory(p) {
				t.Errorf("IsSupplyChainCategory(%q) = true; it is not the whole of a category in the set", p)
			}
		}
	}
	// Two of these were classifier identifiers copied out of the source
	// scanner's system prompt. A test fixture is a publication surface, and
	// reproducing a real classifier reproduces part of what the scanner looks
	// for, so they are gone. The property does not need real ones -- it needs
	// strings that are not in the set -- and internal/disclosure now refuses
	// the shape outright, invented instances included.
	for _, c := range []string{
		"", " ", "security", "injection", "crypto", "auth",
		"social", "specific", "artificial",
		"classifier", "catalogue-entry",
	} {
		refused++
		if fix.IsSupplyChainCategory(c) {
			t.Errorf("IsSupplyChainCategory(%q) = true", c)
		}
	}
	t.Logf("admitted %d categories (each in 4 spellings) and refused %d perturbations", len(set), refused)
}

// TestProtectedPathsCoverTheirWholeFamily runs both directions over generated
// placements: a protected name is protected at any depth, and an ordinary
// source file is not protected wherever it sits.
func TestProtectedPathsCoverTheirWholeFamily(t *testing.T) {
	protected := []string{
		".github/workflows/ci.yml",
		".github/workflows/nested/deep.yaml",
		".github/actions/thing/action.yml",
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
		"poetry.lock", "composer.lock", "Gemfile.lock", "Cargo.lock",
		"Dockerfile", "dockerfile", "Dockerfile.dev", "Dockerfile.prod",
		"anything.lock", "some/nested/thing.lock",
	}
	prefixes := []string{"", "a/", "a/b/", "deeply/nested/dir/"}
	checkedProtected := 0
	for _, p := range protected {
		for _, prefix := range prefixes {
			// A prefix on a path that is itself anchored at .github is a
			// different path, so only the basename family is re-anchored.
			if strings.HasPrefix(p, ".github/") && prefix != "" {
				continue
			}
			candidate := prefix + p
			checkedProtected++
			if !fix.IsProtectedPath(candidate) {
				t.Errorf("IsProtectedPath(%q) = false", candidate)
			}
			// Case is not a way through.
			if !fix.IsProtectedPath(strings.ToUpper(candidate)) {
				t.Errorf("IsProtectedPath(%q) = false", strings.ToUpper(candidate))
			}
		}
	}

	ordinary := []string{
		"main.go", "src/app.ts", "README.md", "go.mod", "package.json",
		"lockfile.go", "mylock.go", "docker/compose.yml", "a/.github.md",
		"locked.txt", "workflows/ci.yml", "b/.github/notes.md",
	}
	for _, p := range ordinary {
		if fix.IsProtectedPath(p) {
			t.Errorf("IsProtectedPath(%q) = true; ordinary source is not protected", p)
		}
	}
	t.Logf("protected %d paths, left %d ordinary ones alone", checkedProtected, len(ordinary))
}

// TestEnforceLimitsRefusesEveryViolation walks each bound and each structural
// rule. The rows say what is wrong, so a bound that stops being enforced fails
// under its own name rather than in a heap.
func TestEnforceLimitsRefusesEveryViolation(t *testing.T) {
	tree := newTree(map[string]string{
		"a.go": "package a\n", "b.go": "package b\n", "c.go": "", "d.go": "",
		"e.go": "", "f.go": "", ".github/workflows/ci.yml": "on: push\n",
		"go.sum": "x\n",
	})
	limits := testLimits()

	cases := []struct {
		name     string
		files    []fix.FileChange
		category string
	}{
		{"too many files", manyFiles(limits.MaxFiles + 1), ""},
		{"a path that traverses", []fix.FileChange{{Path: "../x", Contents: "x"}}, ""},
		{"an absolute path", []fix.FileChange{{Path: "/a.go", Contents: "x"}}, ""},
		{"a path with a space", []fix.FileChange{{Path: "a b.go", Contents: "x"}}, ""},
		{"an empty path", []fix.FileChange{{Path: "  ", Contents: "x"}}, ""},
		{"the same file twice", []fix.FileChange{{Path: "a.go", Contents: "x"}, {Path: "a.go", Contents: "y"}}, ""},
		{"a file that is not in the tree", []fix.FileChange{{Path: "new.go", Contents: "x"}}, ""},
		{"a protected path without a supply-chain finding", []fix.FileChange{{Path: ".github/workflows/ci.yml", Contents: "x"}}, "injection"},
		{"a protected path under a category the source would have split", []fix.FileChange{{Path: "go.sum", Contents: "x"}}, "artificial-intelligence/ci"},
		{"one file over the byte cap", []fix.FileChange{{Path: "a.go", Contents: strings.Repeat("x", limits.MaxBytesPerFile+1)}}, ""},
		{"the line cap, cumulatively", []fix.FileChange{
			{Path: "a.go", Contents: strings.Repeat("x\n", limits.MaxLines)},
			{Path: "b.go", Contents: "y\n"},
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := fix.EnforceLimits(tc.files, tc.category, tree, limits)
			if err == nil {
				t.Fatalf("EnforceLimits accepted %s", tc.name)
			}
			if out != nil {
				t.Errorf("EnforceLimits returned %d files alongside its refusal", len(out))
			}
		})
	}

	// Both directions. A patch inside every bound is accepted, its line counts
	// are derived rather than taken from the caller, and a supply-chain
	// category does unlock a dependency lockfile -- otherwise every assertion
	// above would be satisfied by a function that refused everything.
	accepted, lines, err := fix.EnforceLimits([]fix.FileChange{
		{Path: "a.go", Contents: "one\ntwo\n", Lines: 999},
		{Path: "b.go", Contents: "three"},
	}, "", tree, limits)
	if err != nil {
		t.Fatalf("EnforceLimits refused a patch inside every bound: %v", err)
	}
	if len(accepted) != 2 {
		t.Fatalf("accepted %d files, want 2", len(accepted))
	}
	if accepted[0].Lines != 2 || accepted[1].Lines != 1 {
		t.Errorf("line counts = %d and %d, want 2 and 1 derived from the contents", accepted[0].Lines, accepted[1].Lines)
	}
	if lines != 3 {
		t.Errorf("total lines = %d, want 3", lines)
	}
	for _, category := range fix.SupplyChainCategories() {
		if _, _, err := fix.EnforceLimits([]fix.FileChange{{Path: "go.sum", Contents: "x\n"}}, category, tree, limits); err != nil {
			t.Errorf("EnforceLimits refused a lockfile change for the supply-chain category %q: %v", category, err)
		}
	}
	t.Logf("refused %d violations and accepted a conforming patch under %d supply-chain categories", len(cases), len(fix.SupplyChainCategories()))
}

// A model controls the finding category, so even every recognized supply-chain
// category must be unable to unlock paths that can execute on the next push.
func TestEnforceLimitsAlwaysRefusesPlatformExecutedCI(t *testing.T) {
	paths := []string{
		".github/workflows/ci.yml",
		".github/workflows/nested/release.yaml",
		".github/actions/thing/action.yml",
		".github/actions/thing/scripts/run.sh",
		".GITHUB/WORKFLOWS/CI.YML",
		".GITHUB/ACTIONS/THING/ACTION.YML",
	}
	treeFiles := make(map[string]string, len(paths)+2)
	for _, path := range paths {
		treeFiles[path] = "original\n"
	}
	treeFiles["go.sum"] = "original\n"
	treeFiles["Dockerfile"] = "FROM alpine\n"
	tree := newTree(treeFiles)
	categories := append(fix.SupplyChainCategories(), "", "injection", "CI", "supply-chain", "artificial-intelligence/ci")
	for _, path := range paths {
		for _, category := range categories {
			t.Run(path+"/"+category, func(t *testing.T) {
				files, lines, err := fix.EnforceLimits([]fix.FileChange{{Path: path, Contents: "changed\n"}}, category, tree, testLimits())
				if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "platform-executed CI") {
					t.Fatalf("path %q category %q: files=%v lines=%d err=%v; want CI refusal", path, category, files, lines, err)
				}
				if files != nil || lines != 0 {
					t.Fatalf("refused patch returned files=%v lines=%d", files, lines)
				}
			})
		}
	}
	for _, path := range []string{"go.sum", "Dockerfile"} {
		for _, category := range []string{"ci", "supply-chain", "dependencies"} {
			if _, _, err := fix.EnforceLimits([]fix.FileChange{{Path: path, Contents: "changed\n"}}, category, tree, testLimits()); err != nil {
				t.Errorf("category %q could not change %q: %v", category, path, err)
			}
		}
		if _, _, err := fix.EnforceLimits([]fix.FileChange{{Path: path, Contents: "changed\n"}}, "injection", tree, testLimits()); err == nil {
			t.Errorf("unrelated category could change protected %q", path)
		}
	}
}

// TestCountLinesCountsAnUnterminatedLastLine is the arithmetic the caps rest
// on, checked over generated content rather than at one example.
func TestCountLinesCountsAnUnterminatedLastLine(t *testing.T) {
	for n := 0; n < 50; n++ {
		terminated := strings.Repeat("x\n", n)
		if got := fix.CountLines(terminated); got != n {
			t.Errorf("CountLines of %d terminated lines = %d", n, got)
		}
		unterminated := terminated + "y"
		if got := fix.CountLines(unterminated); got != n+1 {
			t.Errorf("CountLines of %d terminated lines plus a partial = %d, want %d", n, got, n+1)
		}
	}
	if got := fix.CountLines(""); got != 0 {
		t.Errorf("CountLines(\"\") = %d, want 0", got)
	}
	t.Logf("checked 100 line counts")
}

func manyFiles(n int) []fix.FileChange {
	out := make([]fix.FileChange, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fix.FileChange{Path: fmt.Sprintf("f%d.go", i), Contents: "x"})
	}
	return out
}

// newTree is the in-memory snapshot the fix tests run against.
type stubTree struct {
	files map[string][]byte
	modes map[string]string
}

func newTree(files map[string]string) *stubTree {
	t := &stubTree{files: map[string][]byte{}, modes: map[string]string{}}
	for path, content := range files {
		t.files[path] = []byte(content)
	}
	return t
}

func (t *stubTree) List() []string {
	out := make([]string, 0, len(t.files))
	for p := range t.files {
		out = append(out, p)
	}
	return out
}

func (t *stubTree) Read(p string) ([]byte, bool) {
	b, ok := t.files[p]
	return b, ok
}

func (t *stubTree) Mode(p string) (string, bool) {
	m, ok := t.modes[p]
	return m, ok
}

var _ review.Tree = (*stubTree)(nil)
