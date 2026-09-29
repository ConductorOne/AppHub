// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute_test

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestAllCapabilitiesMatchesTheConstBlock cross-checks [compute.AllCapabilities]
// against the constants it restates.
//
// # Why this test exists rather than a review comment
//
// A hand-maintained restatement of a set drifts from the set. This project has
// paid for that repeatedly — the go-command directory rules were restated and
// wrong in both directions, and the Granter port list was a hand-written map that a
// port carrying Granter walked straight past. AllCapabilities is the same shape: a
// slice literal claiming to be the whole population of a const block above it.
//
// # Why it uses go/types, after two syntax-based versions were defeated
//
// The first version matched `Name Capability = "literal"` with go/ast. A reviewer
// defeated it with
//
//	const CapReviewComputed = CapImageRegistry + "-review-computed"
//
// which is semantically a Capability — its type is inferred from the operand — and
// was silently skipped, so a capability could go missing from the published matrix
// with nothing turning red.
//
// The second version added the `Capability("literal")` conversion form and made
// anything else fatal. **It still missed the same counter-example**, because that
// constant carries no type *node* and its value is a binary expression: the code
// classified it as "not a Capability" rather than as "a Capability I cannot read".
// The doc comment described the case and the code did not catch it, which is worse
// than either — a promise the implementation does not keep.
//
// The lesson is the one this repository keeps relearning: **syntax is not the
// population.** A constant's type is a semantic property, and no amount of pattern
// matching over expression shapes recovers it. So this typechecks the package and
// asks the type checker, which is the only thing that actually knows. Computed
// constants are evaluated rather than refused, so the reviewer's counter-example is
// now caught *by inclusion* — it appears in the derived set and its absence from
// AllCapabilities is reported — which is a better outcome than fatalling on it.
//
// It costs about a second and needs nothing beyond the standard library.
//
// # What keeps the derivation from passing vacuously
//
// A derivation that returns nothing satisfies every check written over it. Three
// emptiness gates close that: the file set must be non-empty and every file's
// package clause must match; the typechecked constant set must be non-empty; and
// [compute.AllCapabilities] must be non-empty.
//
// # The one limit, stated
//
// This typechecks the default build configuration. A Capability declared behind a
// build tag that no supported configuration selects would not appear. Nothing in
// this package uses build tags today, and the import-boundary checker independently
// enumerates every declared import across the OS/arch matrix — so such a
// declaration would not be invisible to the repository, but it would be invisible
// to this test, and that is the honest boundary.
func TestAllCapabilitiesMatchesTheConstBlock(t *testing.T) {
	t.Parallel()

	declared := declaredCapabilities(t, packageDir(t))
	if len(declared) == 0 {
		t.Fatal("no Capability constants were found in package compute; the derivation returned " +
			"nothing, which would make every assertion below vacuous")
	}

	exported := compute.AllCapabilities()
	if len(exported) == 0 {
		t.Fatal("compute.AllCapabilities() is empty; a support matrix built from it would " +
			"render as a provider supporting nothing rather than as a bug")
	}

	got := make([]string, 0, len(exported))
	seen := map[string]bool{}
	for _, c := range exported {
		if seen[string(c)] {
			t.Errorf("compute.AllCapabilities() lists %q twice", c)
		}
		seen[string(c)] = true
		got = append(got, string(c))
	}
	sort.Strings(got)

	want := make([]string, 0, len(declared))
	for v := range declared {
		want = append(want, v)
	}
	sort.Strings(want)

	if strings.Join(got, ",") == strings.Join(want, ",") {
		return
	}
	for _, v := range want {
		if !seen[v] {
			t.Errorf("capability %q (declared as %s) is a Capability constant in this package "+
				"and is missing from compute.AllCapabilities(); every consumer that enumerates "+
				"the population — including the public support matrix — would omit it silently",
				v, declared[v])
		}
	}
	for _, v := range got {
		if _, ok := declared[v]; !ok {
			t.Errorf("compute.AllCapabilities() lists %q, which is not the value of any "+
				"Capability constant in this package", v)
		}
	}
}

// TestAllCapabilitiesIsSorted pins the ordering AllCapabilities documents, so a
// caller may render it without sorting and a diff of two matrices lines up.
func TestAllCapabilitiesIsSorted(t *testing.T) {
	t.Parallel()
	got := compute.AllCapabilities()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("compute.AllCapabilities() is not sorted: %q precedes %q", got[i-1], got[i])
		}
	}
}

// TestTheAuditSeesComputedConstants guards the audit itself against the regression
// that defeated both of its previous versions.
//
// Each version of this audit was defeated by one form more than it recognised:
// two syntax-based versions missed a computed constant (the second even described
// it in a comment), and the first go/types version missed a constant declared
// through an ALIAS, because its type is *types.Alias rather than *types.Named.
// The fixture therefore carries every declaration form at once — plain, computed,
// converted, aliased — plus an untyped decoy that must not be collected, so a
// future version cannot pass by recognising three of the four.
//
// It builds its own small package rather than mutating compute, because a fixture
// that requires editing the package under audit is one nobody runs.
func TestTheAuditSeesComputedConstants(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	source := `package fixture

type Capability string

const (
	CapPlain Capability = "plain"
	// Semantically a Capability, inferred from the operand, with a value only
	// known after constant folding. Both earlier audits skipped this silently.
	CapComputed = CapPlain + "-computed"
	// The conversion form.
	CapConverted = Capability("converted")
	// Declared through an ALIAS of Capability. Its type is *types.Alias rather
	// than *types.Named, so the first go/types version skipped it silently --
	// the same failure as the syntax versions, one level up.
	CapAliased CapAlias = "aliased"
	// Not a Capability at all, and must not be collected.
	somethingElse = "not-a-capability"
)

// CapAlias is an alias, not a new type: constants declared with it ARE
// Capability constants and belong in the population.
type CapAlias = Capability

// Referenced so the fixture has no unused-constant concerns for future linters.
func use() string {
	return string(CapPlain) + string(CapComputed) + string(CapConverted) +
		string(CapAliased) + somethingElse
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(source), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	found := capabilityConstantsIn(t, dir, "fixture")
	for _, want := range []string{"plain", "plain-computed", "converted", "aliased"} {
		if _, ok := found[want]; !ok {
			t.Errorf("the audit did not find the capability %q; it found %v", want, keysOf(found))
		}
	}
	if _, ok := found["not-a-capability"]; ok {
		t.Error("the audit collected an untyped constant that is not a Capability")
	}
	if len(found) != 4 {
		t.Errorf("the audit found %d constants, want 4: %v", len(found), keysOf(found))
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// packageDir returns the directory holding this test's source.
func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test's source file")
	}
	return filepath.Dir(file)
}

// declaredCapabilities returns every constant in package compute whose type is
// Capability, keyed by its evaluated string value.
func declaredCapabilities(t *testing.T, dir string) map[string]string {
	t.Helper()
	return capabilityConstantsIn(t, dir, "compute")
}

// capabilityConstantsIn typechecks the package in dir and returns every
// package-scope constant whose named type is "Capability", keyed by value.
//
// wantPackage is the package clause every non-test file must declare, so pointing
// this at the wrong directory is a failure rather than an empty result.
func capabilityConstantsIn(t *testing.T, dir, wantPackage string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		if file.Name.Name != wantPackage {
			t.Fatalf("%s declares package %q, want %q; this scan is pointed at the wrong "+
				"directory", name, file.Name.Name, wantPackage)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatalf("no non-test Go files were parsed out of %s", dir)
	}

	// The source importer resolves this package's own imports from source, which
	// needs no dependency beyond the standard library.
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check(wantPackage, fset, files, nil)
	if err != nil {
		t.Fatalf("typechecking %s: %v\nThe audit derives the capability population from the "+
			"type checker, so a package that does not typecheck makes the population unknown "+
			"rather than empty.", dir, err)
	}

	out := map[string]string{}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		konst, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		// types.Unalias before the assertion, because a constant declared through
		// an ALIAS of Capability has type *types.Alias, not *types.Named, and the
		// version without this skipped it silently. That is the same defect as
		// the two syntax-based versions, one level up: moving to the type checker
		// removed the need to recognise expression forms, and left a type form to
		// miss. A semantic authority is still an authority about something.
		typ := types.Unalias(konst.Type())
		named, ok := typ.(*types.Named)
		if !ok || named.Obj().Name() != "Capability" {
			// Unrecognised-is-fatal survives the move to go/types, but it has to
			// fire on a type FORM this code cannot interpret rather than on a type
			// it can. The first attempt at this fatal asked whether the type's
			// name mentioned "Capability" and immediately false-positived on
			// compute.WorkloadCapability -- a genuinely different type that the
			// type checker is authoritative about. Asking "is this named
			// something like the thing I want" is the pattern-matching this audit
			// was rewritten to escape, reintroduced in the guard against it.
			//
			// What is genuinely unclassifiable is a constant whose type is not a
			// named type, an alias, or an untyped basic. Those three exhaust the
			// forms a constant's type can take, so this fires only on a form that
			// did not exist when it was written -- which is the case worth being
			// fatal about, because that is how each previous version was defeated.
			switch typ.(type) {
			case *types.Named, *types.Alias, *types.Basic:
			default:
				t.Fatalf("constant %s has type %s (%T), which is not a named type, an alias, "+
					"or an untyped basic. The audit cannot classify that form, and skipping "+
					"what it cannot classify is how both previous versions of this check were "+
					"defeated.", name, typ, typ)
			}
			continue
		}
		if konst.Val().Kind() != constant.String {
			t.Fatalf("constant %s has type Capability and a non-string value (%s); the "+
				"population this derives would be incomplete", name, konst.Val())
		}
		out[constant.StringVal(konst.Val())] = name
	}
	return out
}
