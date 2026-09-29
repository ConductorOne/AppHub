// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The two claims this file checks are the ones the ticket asked to be verified
// rather than assumed, and both are about the whole of a package's source
// rather than about any file in it. So they are derived by reading the tree:
// a claim about a set that is checked by naming its members is a claim about
// the members that were named.
//
// `make boundary` proves a different and complementary thing -- that no
// package outside store/ can reach the DynamoDB SDK in any build configuration
// -- over a union import graph. It does not bound the rest of a cloud SDK, and
// nothing else in this repository does either, which is why these are here.
//
// # What the first version got wrong, twice
//
// It named `github.com/aws/aws-sdk-go`, which does not prefix
// `github.com/aws/aws-sdk-go-v2/aws`; the planted-import control found that.
// And it claimed a closure over the standard library while admitting *any*
// package under modules/ without looking at that package's own imports, so a
// transitive third-party dependency reached through a sibling package was
// invisible -- a review planted one and both tests passed. The claim was wider
// than the check.
//
// Both are fixed by not enumerating. There is no cloud-SDK organisation list
// any more: no package under modules/ may import anything third-party at all,
// which subsumes every cloud SDK including ones nobody has heard of. And the
// closure is computed rather than asserted.

const modulePath = "github.com/conductorone/apphub"

// firstParty is this repository's own prefix, and moduleTree is the subtree
// these rules govern.
const (
	firstParty = modulePath + "/"
	moduleTree = modulePath + "/modules"
)

// TestNoModuleImportsAnythingThirdParty is the machine check for the rule
// modules/doc.go states: a module reaches a cloud API through a compute
// provider and never through an SDK.
//
// It is stated as "nothing third-party" rather than "no cloud SDK" because
// that is a rule with no list in it. modules/deploy will import compute/, and
// modules/review and modules/fix are held to something stricter below; what no
// module may do is depend on a package outside this repository.
func TestNoModuleImportsAnythingThirdParty(t *testing.T) {
	pkgs := packagesUnder(t, modulesDir(t))
	if len(pkgs) < 3 {
		// modules, modules/review, modules/fix at the least. A walk that found
		// fewer found the wrong tree, and a rule checked over an empty
		// population passes without checking anything.
		t.Fatalf("walked %d packages under modules/, expected at least 3; the walk is not covering the tree", len(pkgs))
	}
	total := 0
	for _, pkg := range pkgs {
		total += len(pkg.imports)
		for _, imp := range pkg.imports {
			if isStandardLibrary(imp) || strings.HasPrefix(imp, firstParty) || imp == modulePath {
				continue
			}
			t.Errorf("%s imports %q, which is outside this repository; a module reaches a cloud API "+
				"through a compute provider, and everything else it needs it declares an interface for",
				pkg.path, imp)
		}
	}
	if total == 0 {
		t.Fatalf("walked %d packages and found no imports at all; the parser is not reading these files", len(pkgs))
	}
	t.Logf("checked %d import(s) across %d package(s) under modules/", total, len(pkgs))
}

// TestReviewAndFixHaveAStandardLibraryClosure is the stronger claim, and this
// time it is a closure rather than a statement about two packages.
//
// Starting from modules/review and modules/fix it follows every first-party
// import to the package it names and repeats, so a third-party dependency
// reached through any number of sibling packages is caught. The fixpoint must
// stay inside modules/: reaching a first-party package this walker did not
// parse is a failure, because the claim cannot be checked beyond the tree the
// walk covers, and a claim that outruns its evidence is the defect this
// replaces.
func TestReviewAndFixHaveAStandardLibraryClosure(t *testing.T) {
	root := modulesDir(t)
	byPath := map[string]parsedPackage{}
	for _, pkg := range packagesUnder(t, root) {
		byPath[pkg.path] = pkg
	}
	if len(byPath) < 3 {
		t.Fatalf("parsed %d packages under modules/; the walk is not covering the tree", len(byPath))
	}

	seeds := []string{moduleTree + "/review", moduleTree + "/fix"}
	reached := map[string]bool{}
	queue := append([]string(nil), seeds...)
	imports := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if reached[current] {
			continue
		}
		reached[current] = true
		pkg, ok := byPath[current]
		if !ok {
			t.Fatalf("the closure reaches %q, which this walk did not parse; the claim cannot be "+
				"checked outside the tree it covers", current)
		}
		if len(pkg.imports) == 0 {
			t.Fatalf("%s parsed with no imports; the parser is not reading these files", current)
		}
		for _, imp := range pkg.imports {
			imports++
			switch {
			case isStandardLibrary(imp):
			case imp == current:
				// An external test package importing the package it tests.
			case imp == moduleTree || strings.HasPrefix(imp, moduleTree+"/"):
				queue = append(queue, imp)
			default:
				t.Errorf("%s imports %q, which is neither the standard library nor part of the "+
					"modules tree, so the closure is not over the standard library", current, imp)
			}
		}
	}
	// The set has to be closed under the import relation, checked separately
	// from the walk that built it. A walk that stopped expanding would produce
	// a smaller set that still satisfied every assertion above -- it is the
	// set's own property that says it is a closure, not the loop's.
	for pkgPath := range reached {
		for _, imp := range byPath[pkgPath].imports {
			if imp == pkgPath || !strings.HasPrefix(imp, moduleTree) {
				continue
			}
			if !reached[imp] {
				t.Errorf("%s imports %s, which is not in the closure; the set is not closed under "+
					"the import relation, so it is not a closure", pkgPath, imp)
			}
		}
	}
	if len(reached) <= len(seeds) {
		t.Fatalf("the closure reached %d package(s) from %d seed(s); these packages import the "+
			"framework, so a closure that added nothing did not expand", len(reached), len(seeds))
	}
	t.Logf("closure over %d package(s) and %d import(s) from %d seed(s), all standard library",
		len(reached), imports, len(seeds))
}

// isStandardLibrary reports whether an import path names a standard library
// package.
//
// The discriminator is that the first path element of anything else is a
// domain, and a domain contains a dot. That is exact rather than approximate:
// the standard library reserves the paths with no dot in their first element,
// and a module path without one cannot be fetched.
func isStandardLibrary(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

type parsedPackage struct {
	// dir is where the package's files are.
	dir string
	// path is its import path, derived from dir rather than declared, so a
	// package added under modules/ joins the closure without being listed.
	path string
	// imports is every path imported by any of its files, tests included. Test
	// imports count: a test-only dependency is still a dependency of this
	// repository, and excluding them would make the claim quieter than the
	// thing it is about.
	imports []string
}

// modulesDir returns the modules/ directory, from this test's own location.
func modulesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	// This test lives in modules/review, so modules/ is its parent.
	dir := filepath.Dir(wd)
	if filepath.Base(dir) != "modules" {
		t.Fatalf("expected to be running inside modules/review, but the parent of %s is %s", wd, dir)
	}
	return dir
}

// packagesUnder walks root and parses every directory holding Go files.
//
// A directory that cannot be read is fatal rather than skipped. A walk that
// silently steps over what it could not open reports the same success as one
// that covered everything.
func packagesUnder(t *testing.T, root string) []parsedPackage {
	t.Helper()
	var out []parsedPackage
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		entries, rerr := os.ReadDir(path)
		if rerr != nil {
			return rerr
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				out = append(out, packageAt(t, path))
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

// packageAt parses every Go file in one directory, tests included, and returns
// its imports. Test files are included deliberately: a test-only dependency is
// still a dependency of this repository, and excluding them would make the
// claim quieter than the thing it is about.
// importPathOf derives a package's import path from its directory, by
// anchoring on the modules/ directory this test lives under. Derived rather
// than passed in, so the two walks cannot disagree about what a package is
// called.
func importPathOf(t *testing.T, dir string) string {
	t.Helper()
	root := modulesDir(t)
	if dir == root {
		return moduleTree
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatalf("resolving %s against %s: %v", dir, root, err)
	}
	return moduleTree + "/" + filepath.ToSlash(rel)
}

func packageAt(t *testing.T, dir string) parsedPackage {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	seen := map[string]struct{}{}
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		files++
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		for _, spec := range f.Imports {
			value, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				t.Fatalf("unquoting the import %s in %s: %v", spec.Path.Value, path, uerr)
			}
			seen[value] = struct{}{}
		}
	}
	if files == 0 {
		t.Fatalf("%s holds no Go files", dir)
	}
	out := parsedPackage{dir: dir, path: importPathOf(t, dir)}
	for imp := range seen {
		out.imports = append(out.imports, imp)
	}
	return out
}
