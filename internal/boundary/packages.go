// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file answers one question, and it is the question this package has now got
// wrong twice in opposite directions:
//
//	which directories of a module could be compiled as first-party packages?
//
// Round one *excluded* `node_modules`, which the go command does not ignore.
// Round two *excluded* every directory named `vendor`, when the go command
// excludes only what is beneath a vendor element -- `cmd/vendor` is an ordinary
// package, as `go help packages` says outright. Both were full silent bypasses: a
// first-party package parked in such a directory, with its import behind a
// constraint no compatibility target selects, was invisible to the union, to the
// file scan, and to every concrete build at once.
//
// Two wrongs in opposite directions is a signal about the *shape* of the answer,
// not about the two names. What follows is an attempt to fix the shape.
//
// # Why the set is not simply asked of the toolchain
//
// The obvious repair is to stop restating anything and let `go list ./...` name
// the packages. It is the right instinct and it does not work. Two measurements,
// both taken rather than assumed:
//
//  1. `go list -e -json ./...` does not report a directory whose files are ALL
//     excluded by build constraints. A directory holding one `//go:build ignore`
//     file is absent from its output entirely. That directory is not a corner case
//     here, it is the *central* case: the union graph exists to judge code behind
//     constraints no supported configuration selects. Deriving the package set
//     from a concrete `go list` would reintroduce exactly the configuration
//     dependence USOSS-28 removes, in the silent direction.
//
//  2. The toolchain's package set is *pattern-root dependent*, so there is no
//     single set to copy. `go list ./...` from the module root omits
//     `cmd/vendor/sub`, while `go list ./cmd/vendor/...` reports it. Asking the
//     toolchain therefore replaces one restatement with a choice about which
//     question to ask -- and the narrower answer is a hole.
//
// `go list` conflates "is this path a package directory?" (configuration- and
// pattern-independent, and what is needed here) with "does this configuration
// select any of its files?" and "does this pattern root reach it?". Only the
// latter two are available separately.
//
// # So the rule is maximal, and the invariant tested against the toolchain is
// # containment rather than equality
//
// This walker deliberately over-approximates: it enumerates every directory that
// could be compiled under *any* pattern or reached by an import, and excludes only
// what nothing can reach and one thing this repository must exclude by policy.
//
//	skip a directory and its subtree when its name is `testdata`, or begins with
//	`.` or `_`, or it holds a nested go.mod. Everything else is a candidate,
//	including `vendor`, everything beneath `vendor`, and `node_modules`.
//
// Each exclusion has a reason that is not "it looks like build output":
//
//   - `testdata`, `.x`, `_x`: no `...` pattern reaches these from any root -- measured:
//     `go list ./testdata/...` reports "matched no packages", likewise for a `.` or
//     `_` prefixed directory. Only naming the exact directory reaches them.
//     `testdata` is additionally where this repository keeps fixtures that
//     deliberately violate the rules, so excluding it is a stated policy and not
//     an accident of resemblance.
//   - a nested `go.mod`: a different module, governed by its own rules. `go build
//     ./...` here never compiles it, and an import of it is a fatal unresolvable
//     import (see [ModuleSet.Resolve]), so it cannot hide reachability either.
//
// Everything else is included even when the go command's own `./...` would skip
// it, because over-approximating costs a possible false positive and
// under-approximating costs a silent hole -- and this package has now paid that
// price twice. Notably that means a `vendor` subtree *is* enumerated: a vendor tree
// at the module root is fatal long before this runs (see rejectVendorTree), so the
// only effect is that a regression there would produce loud false positives
// instead of silence.
//
// TestPackageDirsCoversEveryToolchainPackage pins the invariant that matters:
// over a generated module containing every combination of directory-name shape,
// with plain unconstrained files so file selection cannot be a factor, **every**
// package the toolchain reports must appear in this set. Containment, not
// equality -- so the toolchain gaining a package can never open a hole, and this
// walker losing one fails CI. Both earlier bypasses would have been caught by it
// before review saw them.
//
// Note what none of this affects: import resolution. A package inside an excluded
// directory that something actually imports is still resolved, parsed and judged,
// because [Union.node] never consults any of this. The rule decides what is
// *enumerated as a first-party root*, not what is reachable.

// PackageDirs returns every directory beneath root that could be compiled as a
// package, as slash-separated paths relative to root, sorted, with "." for the
// root itself.
//
// A directory is included when the rule above admits it *and* it holds at least
// one Go file the go command would not unconditionally ignore. Files whose names
// begin with `.` or `_` do not count towards that, because no configuration
// compiles them -- so a directory holding only those is not a package. (Inside a
// directory that *is* a package they are still parsed: over-approximating within
// a package is the safe direction; inventing a package the toolchain does not
// have is not.)
//
// This is the single implementation of the question for the whole repository.
// Anything that needs to know which directories are packages should call it
// rather than restate it; the restatement is what produced two bypasses.
func PackageDirs(root string) ([]string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []string
	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		if p != absRoot {
			if unreachableDir(d.Name()) {
				return fs.SkipDir
			}
			// A nested go.mod is a different module. Its packages are not part of
			// this build and are governed by their own module's rules -- which is
			// also what the go command does when it expands ./... .
			if _, statErr := os.Stat(filepath.Join(p, "go.mod")); statErr == nil {
				return fs.SkipDir
			}
		}
		rel, relErr := filepath.Rel(absRoot, p)
		if relErr != nil {
			return relErr
		}
		hasGo, hasErr := holdsCompilableName(p)
		if hasErr != nil {
			return hasErr
		}
		if hasGo {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// unreachableDir reports whether a directory name puts it and its whole subtree
// outside anything a build could compile.
//
// It is deliberately short. Every name that is *not* here is enumerated, so a
// name nobody thought about is over-approximated rather than skipped -- which is
// the direction the last two mistakes should have failed in.
func unreachableDir(name string) bool {
	return name == "testdata" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// holdsCompilableName reports whether a directory holds a `.go` file whose name
// the go command does not unconditionally ignore.
//
// "Unconditionally" is the operative word: a build constraint is a configuration,
// and this package judges every configuration, so constraints are irrelevant
// here. A leading `.` or `_` in a *file name* is not a configuration -- no
// configuration compiles such a file -- so a directory holding only those is not
// a package under any of them.
func holdsCompilableName(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			continue
		}
		return true, nil
	}
	return false, nil
}
