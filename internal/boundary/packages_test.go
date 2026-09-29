// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This is the test the two directory bypasses were missing.
//
// Round one excluded `node_modules`, which the go command compiles. Round two
// excluded every directory named `vendor`, when the go command compiles
// `cmd/vendor` itself. Both were hand-written restatements of the toolchain's
// behaviour, both diverged from it, and both divergences were silent until review
// went looking. A restatement that is not checked against the thing it restates is
// a hole with a schedule.
//
// So the rule is checked against the toolchain, generatively, on every run:
// build a module containing every combination of directory-name shape, ask the
// real `go list` which of them are packages, and require that PackageDirs
// contains every one.
//
// Containment rather than equality, deliberately. The toolchain's package set is
// pattern-root dependent -- `go list ./...` from the root omits `cmd/vendor/sub`
// while `go list ./cmd/vendor/...` reports it -- so equality would force this
// walker to mirror quirks that do not matter for a security fence, and would fail
// for over-approximating in the safe direction. Containment is the property that
// matters: the walker may never miss a package the toolchain has.

// dirShapes are the directory-name kinds whose treatment differs, or has been
// wrongly assumed to differ. Combinations of these are what the generated module
// is built from.
var dirShapes = []string{
	"plain",
	"vendor",
	"testdata",
	"node_modules",
	"vendorish",      // near-miss: prefix matching would wrongly exclude it
	"testdata_thing", // near-miss on the other side
	"_under",
	".dot",
}

// generateShapeModule writes a module containing one package per combination of
// dirShapes up to depth 3, plus a nested module, and returns its directory.
//
// Every file is plain and unconstrained: this test is about the *path* rule, so
// build-constraint selection must not be a variable in it.
func generateShapeModule(t *testing.T) (dir string, nested string) {
	t.Helper()
	dir = t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module shapes\n\ngo 1.25.0\n")
	write("f.go", "package shapes\n")

	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		if depth == 0 {
			return
		}
		for _, shape := range dirShapes {
			rel := shape
			if prefix != "" {
				rel = prefix + "/" + shape
			}
			// The package name never matters to the enumeration and a directory
			// beginning with a dot cannot be a package clause, so use a fixed one.
			write(rel+"/f.go", "package p\n")
			walk(rel, depth-1)
		}
	}
	walk("", 3)

	// A nested module: a different module, and neither the toolchain nor the
	// walker may report its packages as this module's.
	nested = "plain/nestedmod"
	write(nested+"/go.mod", "module nestedmod\n\ngo 1.25.0\n")
	write(nested+"/f.go", "package p\n")
	write(nested+"/inner/f.go", "package p\n")
	return dir, nested
}

// goListDirs runs `go list -e <pattern>` in dir and returns the package import
// paths, with the module prefix stripped so they read as relative directories.
func goListDirs(t *testing.T, dir, pattern string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-e", pattern)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "GOPROXY=off")
	out, err := cmd.Output()
	if err != nil {
		// A pattern that matches nothing is a warning on stderr and an error
		// here; that is an answer, not a failure.
		return nil
	}
	var dirs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", strings.HasPrefix(line, "go:"), strings.HasPrefix(line, "./"):
			// A warning, or the pattern echoed back because it resolved to nothing.
			continue
		case line == "shapes":
			dirs = append(dirs, ".")
		case strings.HasPrefix(line, "shapes/"):
			dirs = append(dirs, strings.TrimPrefix(line, "shapes/"))
		}
	}
	sort.Strings(dirs)
	return dirs
}

// The invariant: every package the toolchain finds must be enumerated here.
func TestPackageDirsCoversEveryToolchainPackage(t *testing.T) {
	t.Parallel()
	dir, nested := generateShapeModule(t)

	mine, err := PackageDirs(dir)
	if err != nil {
		t.Fatalf("PackageDirs: %v", err)
	}
	have := map[string]bool{}
	for _, d := range mine {
		have[d] = true
	}

	// The module-root pattern, plus a pattern rooted at every first-level
	// directory. The second half matters: it is how `cmd/vendor/sub` becomes a
	// package, and a walker that only matched `./...` would miss it.
	patterns := []string{"./..."}
	for _, shape := range dirShapes {
		patterns = append(patterns, "./"+shape+"/...")
	}

	var missing []string
	seen := map[string]bool{}
	for _, pattern := range patterns {
		for _, d := range goListDirs(t, dir, pattern) {
			if seen[d] {
				continue
			}
			seen[d] = true
			// A nested module's packages belong to that module, not this one.
			if d == nested || strings.HasPrefix(d, nested+"/") {
				t.Errorf("the toolchain reported %s for pattern %s, but it is inside a "+
					"nested module; this test's assumptions are wrong", d, pattern)
				continue
			}
			if !have[d] {
				missing = append(missing, d+" (via "+pattern+")")
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("the toolchain reported no packages at all, so this test proved nothing")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("PackageDirs misses %d directory/directories the toolchain compiles, which is a "+
			"silent bypass of every view at once:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}

// The two historical mistakes, named, so a regression reads as itself rather than
// as an arithmetic failure in the test above.
func TestPackageDirsIncludesTheTwoDirectoriesThatWereWronglyExcluded(t *testing.T) {
	t.Parallel()
	dir, _ := generateShapeModule(t)
	mine, err := PackageDirs(dir)
	if err != nil {
		t.Fatalf("PackageDirs: %v", err)
	}
	have := map[string]bool{}
	for _, d := range mine {
		have[d] = true
	}

	for _, tc := range []struct {
		dir, why string
	}{
		{"node_modules", "bypass sixteen: the go command has no rule for node_modules"},
		{"node_modules/plain", "likewise beneath it"},
		{"vendor", "bypass seventeen: a directory named vendor is itself a package (go help packages)"},
		{"plain/vendor", "likewise when nested"},
		{"vendor/plain", "beneath a vendor element: enumerated anyway, since a pattern rooted inside reaches it"},
		{"vendorish", "a near-miss name that prefix matching would wrongly exclude"},
		{"testdata_thing", "a near-miss name on the other side"},
	} {
		if !have[tc.dir] {
			t.Errorf("PackageDirs must include %q -- %s", tc.dir, tc.why)
		}
	}

	// And the exclusions, each with the reason it is safe. Every one of these is
	// unreachable by any `...` pattern, which the toolchain confirms below.
	for _, excluded := range []string{"testdata", "testdata/plain", "_under", "_under/plain", ".dot", ".dot/plain"} {
		if have[excluded] {
			t.Errorf("PackageDirs must not include %q: it holds fixtures or is ignored by "+
				"every pattern, and including it would judge code no build compiles", excluded)
		}
	}
	for _, excluded := range []string{"testdata", "_under", ".dot"} {
		if got := goListDirs(t, dir, "./"+excluded+"/..."); len(got) != 0 {
			t.Errorf("the toolchain reaches %v under ./%s/..., so excluding it is no longer safe",
				got, excluded)
		}
	}
}

// A nested module is not this module's, in either direction.
func TestPackageDirsStopsAtANestedModule(t *testing.T) {
	t.Parallel()
	dir, nested := generateShapeModule(t)
	mine, err := PackageDirs(dir)
	if err != nil {
		t.Fatalf("PackageDirs: %v", err)
	}
	for _, d := range mine {
		if d == nested || strings.HasPrefix(d, nested+"/") {
			t.Errorf("%s belongs to a nested module and must not be enumerated here", d)
		}
	}
}

// A directory holding only files the go command unconditionally ignores is not a
// package -- and the toolchain agrees, which is why this is safe to skip.
func TestPackageDirsSkipsADirectoryWithNoCompilableFileName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module shapes\n\ngo 1.25.0\n")
	write("real/f.go", "package p\n")
	write("hidden/_f.go", "package p\n")
	write("hidden/.g.go", "package p\n")
	// A directory whose only file IS compilable but is excluded by a constraint no
	// configuration selects: this one must be enumerated, and is the case that
	// makes deriving the set from `go list` unsound.
	write("constrained/f.go", "//go:build ignore\n\npackage p\n")

	mine, err := PackageDirs(dir)
	if err != nil {
		t.Fatalf("PackageDirs: %v", err)
	}
	have := map[string]bool{}
	for _, d := range mine {
		have[d] = true
	}
	if have["hidden"] {
		t.Error("a directory holding only ignored file names is not a package")
	}
	if !have["real"] {
		t.Error("an ordinary package must be enumerated")
	}
	if !have["constrained"] {
		t.Error("a directory whose only file is behind an unsatisfied constraint MUST be " +
			"enumerated: that is the case the union graph exists for, and the one the " +
			"toolchain's own ./... omits")
	}
	// The measurement that rules out deriving the package set from the toolchain,
	// asserted rather than remembered.
	if got := goListDirs(t, dir, "./..."); contains(got, "constrained") {
		t.Error("go list ./... now reports a directory whose files are all excluded; if that " +
			"is really true, deriving the package set from the toolchain becomes possible " +
			"and this whole file should be revisited")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
