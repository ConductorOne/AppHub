// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestEveryNarrowingConversionIsBounded derives the population of narrowing
// conversions in this package and requires every one of them to be bounded.
//
// # Why this is derived rather than a list of call sites
//
// Two review rounds found two wrong bounds on this one operation:
//
//   - round three found `ScaleService` bounding only the lower end behind
//     `//nolint:gosec // bounded by the check above`, and fixed that function;
//   - round seven found `EnsureService` doing exactly the same thing, with the
//     same suppression, three lines of code away.
//
// The round-three fix was aimed at the function the defect was reported in rather
// than at the operation, so it left the sibling. A test naming the call sites it
// knew about would have had the same shape as that fix and the same blind spot.
// *A route to a thing is not the population of things.*
//
// # Why it typechecks instead of pattern-matching the callee's NAME
//
// The first version of this test walked the syntax and matched a callee spelled
// `int32`. Round eight defeated it in one line: a type alias.
//
//	type reviewInt32 = int32
//	reviewInt32(value)   // unbounded, and the gate reported 2 of 2 bounded
//
// **Deriving from syntax is still a list -- the list of spellings.** `go/ast` sees
// an identifier; it cannot see what the identifier denotes. So this asks the type
// checker whether the callee *is* the type `int32`, however it is written, which
// is the same move this package has now made three times: accessors, then the
// capability constants, and now here. Deriving from the code rather than from the
// text of the code.
//
// # What it does not cover, stated rather than implied
//
//   - It proves every narrowing conversion is *routed through a bound*, not that
//     the bound is right. [TestTheBoundsThemselvesRefuseWhatTheyClaimTo] is that.
//   - It looks for conversions to **int32** specifically, because that is the
//     width the Kubernetes API types use and the width both defects were in.
//     There are no conversions to any other narrower integer type in this package
//     (checked, not assumed), so widening the gate would assert over an empty set.
//   - This package only. compute/aws carries one narrowing conversion of its own,
//     inside `sdkSTS.AssumeRole`, which is another ticket's to judge and which
//     this test deliberately does not reach across a package boundary to police.
func TestEveryNarrowingConversionIsBounded(t *testing.T) {
	t.Parallel()

	dir := packageDirForTest(t)
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
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("no non-test Go files were parsed out of " + dir)
	}

	// The package's imports are not resolved: this needs to know what a callee
	// DENOTES, and `int32` is a universe-scope type, so it resolves without any
	// import. Type errors from unresolved imports are collected and ignored
	// rather than fatal -- but see the vacuity gate below, which is what stops
	// "everything failed to typecheck" from reading as "nothing to report".
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Error: func(error) {}, Importer: nil}
	_, _ = conf.Check("k8s", fset, files, info)

	// The functions permitted to hold a raw conversion, because they ARE the
	// bound. Named by identifier so moving them between files is safe.
	bounded := map[string]bool{"narrowPort": true, "narrowCount": true}

	found, inHelper := 0, 0
	// byType records every conversion the TYPE scan recognised, so the spelled
	// scan below can assert it is a subset. See the lower-bound check.
	byType := map[*ast.CallExpr]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				// A conversion is a call whose callee is a TYPE. Anything else is
				// an ordinary call and cannot narrow.
				tv, known := info.Types[call.Fun]
				if !known || !tv.IsType() {
					return true
				}
				// Underlying(), not a direct assertion: `type T int32` is a
				// *types.Named whose UNDERLYING type is int32, and a conversion
				// through it narrows exactly the same way. Asserting on the type
				// itself caught int32 and its aliases and missed defined types --
				// round nine, and the third form this one check has missed.
				basic, ok := types.Unalias(tv.Type).Underlying().(*types.Basic)
				if !ok || basic.Kind() != types.Int32 {
					return true
				}
				// A literal constant cannot be out of range at runtime; the
				// compiler refuses one that is.
				if _, isLiteral := call.Args[0].(*ast.BasicLit); isLiteral {
					return true
				}
				found++
				byType[call] = true
				pos := fset.Position(call.Pos())
				if bounded[fn.Name.Name] {
					inHelper++
					return true
				}
				t.Errorf("%s:%d: %s converts to int32 outside a bounded helper.\n"+
					"On a 64-bit platform this truncates silently: a value past the int32 "+
					"range wraps rather than failing, so a replica count becomes negative and "+
					"a port becomes a different port. Route it through narrowPort or "+
					"narrowCount (see narrow.go). Two wrong bounds on this operation were "+
					"found in two separate review rounds, both behind a //nolint:gosec "+
					"asserting the bound existed -- which is why this is checked by "+
					"derivation, and checked against the TYPE rather than the spelling.",
					filepath.Base(pos.Filename), pos.Line, fn.Name.Name)
				return true
			})
		}
	}

	// Logged BEFORE any gate below can abort, on purpose. When a check Fatals, a
	// trailing Logf never runs -- and an aborted run then produces no derived line
	// at all, which is indistinguishable from a run that derived nothing. That
	// exact ambiguity cost real time while verifying this gate: an attempted
	// mutation was a no-op, the output had no derived line, and a non-result read
	// as a negative result. Silence should never be one of the answers.
	t.Logf("derived %d int32 conversions by TYPE, %d inside the bounded helpers", found, inHelper)

	// # The typed scan must cover the spelled scan, or type info degraded
	//
	// This runs without resolving imports, which is safe for `int32` because it is
	// universe-scope -- but it means incomplete type information is a real
	// possibility, and the failure mode is that a callee simply does not appear in
	// info.Types and the conversion becomes invisible. The empty-population fatal
	// below catches a TOTAL degrade. It cannot catch a PARTIAL one, which is the
	// same distinction round eight found in the previous version of this gate:
	// total blindness is loud, partial blindness looks like coverage.
	//
	// So the syntax scan is kept, not as the check, but as a LOWER BOUND. Every
	// conversion spelled literally `int32(x)` must also have been found by type.
	// The typed scan legitimately finds MORE (aliases, defined types); it must
	// never find fewer. If it does, type info degraded and the gate is blind by an
	// amount this comparison names.
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "int32" {
					return true
				}
				if _, isLiteral := call.Args[0].(*ast.BasicLit); isLiteral {
					return true
				}
				if _, seen := byType[call]; !seen {
					pos := fset.Position(call.Pos())
					t.Errorf("%s:%d: a conversion spelled int32(...) was NOT seen by the type "+
						"scan. The typechecker runs without resolving imports, so this means its "+
						"type information is incomplete here -- and the gate is therefore blind "+
						"to an unknown number of conversions it cannot see at all, including any "+
						"spelled through an alias. A gate that silently finds less is the "+
						"failure this whole check exists to prevent, one level up.",
						filepath.Base(pos.Filename), pos.Line)
				}
				return true
			})
		}
	}

	// A derivation that found nothing is not a pass: if the typecheck degraded so
	// far that no callee resolved to a type, every conversion would be invisible.
	if found == 0 {
		t.Fatal("no int32 conversions were found in this package at all. This asserts a property " +
			"of a population and an empty population makes it vacuous -- either the scan is " +
			"pointed at the wrong directory, or the typecheck degraded so far that no callee " +
			"resolved to a type.")
	}
	if inHelper == 0 {
		t.Errorf("found %d int32 conversions and none inside narrowPort or narrowCount; the "+
			"helpers this test exists to funnel conversions into appear to be gone", found)
	}
}

// TestTheGateSeesAConversionThroughATypeAlias is the round-eight (c) regression,
// and it is here because the empty-population gate above could not have caught it.
//
// An alias-spelled conversion sat beside two recognised ones and the syntax
// version reported "2 of 2 bounded" -- a true statement about the population it
// could see. **A guard against an EMPTY population does not catch a population
// missing ONE member:** total blindness is loud, partial blindness is silent and
// looks exactly like coverage.
//
// So this asserts the classifier directly, on a fixture package it writes itself,
// containing the alias form that defeated the previous version alongside the plain
// form that did not.
func TestTheGateSeesAConversionThroughATypeAlias(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	source := `package fixture

// AliasedInt32 is an alias, not a new type: a conversion through it IS a
// conversion to int32 and narrows exactly the same way.
type AliasedInt32 = int32

// DefinedInt32 is a DEFINED type whose underlying type is int32. A conversion
// through it narrows too, and both a spelling-based check and a check that
// asserts on the type instead of its underlying type miss it.
type DefinedInt32 int32

func plain(v int) int32        { return int32(v) }
func aliased(v int) AliasedInt32 { return AliasedInt32(v) }
func defined(v int) DefinedInt32 { return DefinedInt32(v) }
func literal() int32          { return int32(1) }
func unrelated(v int) int64   { return int64(v) }
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(source), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	found := narrowingConversionsIn(t, dir)
	// plain and aliased both narrow to int32. literal is excluded because a
	// constant cannot be out of range at runtime, and unrelated is not int32.
	// defined() converts through a DEFINED type, which is the form round nine
	// found: the first version of this fixture declared DefinedInt32 and never
	// converted through it, so the classifier's blindness went unnoticed and both
	// tests passed. A fixture that contains the ingredient without exercising it
	// asserts nothing about it.
	want := map[string]bool{"plain": true, "aliased": true, "defined": true}
	for fn := range want {
		if !found[fn] {
			t.Errorf("the gate did not see the int32 conversion in %s(); it found %v.\n"+
				"An alias-spelled conversion is what defeated the syntax version of this "+
				"check, and the empty-population gate could not catch it because the "+
				"population was not empty -- only incomplete.", fn, keysOfBool(found))
		}
	}
	for fn := range found {
		if !want[fn] {
			t.Errorf("the gate reported a narrowing conversion in %s(), which has none", fn)
		}
	}
}

// narrowingConversionsIn typechecks a directory and returns the names of the
// functions containing a non-literal conversion to int32. It is the classifier
// from the gate above, exposed so the gate's own blind spots can be tested.
func narrowingConversionsIn(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Error: func(error) {}}
	if _, err := conf.Check("fixture", fset, files, info); err != nil {
		t.Fatalf("typechecking the fixture: %v", err)
	}
	out := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				tv, known := info.Types[call.Fun]
				if !known || !tv.IsType() {
					return true
				}
				// Underlying(), not a direct assertion: `type T int32` is a
				// *types.Named whose UNDERLYING type is int32, and a conversion
				// through it narrows exactly the same way. Asserting on the type
				// itself caught int32 and its aliases and missed defined types --
				// round nine, and the third form this one check has missed.
				basic, ok := types.Unalias(tv.Type).Underlying().(*types.Basic)
				if !ok || basic.Kind() != types.Int32 {
					return true
				}
				if _, isLiteral := call.Args[0].(*ast.BasicLit); isLiteral {
					return true
				}
				out[fn.Name.Name] = true
				return true
			})
		}
	}
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// packageDirForTest locates this package's source directory from this file's own
// path, so the scan cannot be pointed at the wrong tree by a change of working
// directory.
func packageDirForTest(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test's source file")
	}
	return filepath.Dir(self)
}

// TestTheBoundsThemselvesRefuseWhatTheyClaimTo is the other half: the test above
// proves every conversion is routed through a bound, and this proves the bounds
// reject what they say they reject. Routed-through-a-bound and correctly-bounded
// are different properties and a passing population check does not imply the
// second.
func TestTheBoundsThemselvesRefuseWhatTheyClaimTo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p, _ := newProvider(t, cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	identity := mustIdentity(t, p, "api")

	base := func(replicas int, ports []compute.PortSpec) compute.ServiceSpec {
		return compute.ServiceSpec{
			Name:      "api",
			Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  replicas,
			Ports:     ports,
			Identity:  identity,
		}
	}
	ok := []compute.PortSpec{{Number: 8080}}

	// Replica counts. The upper bound is the one two review rounds found wrong,
	// on two different methods, so both methods are driven.
	for name, count := range map[string]int{
		"negative":            -1,
		"past int32":          math.MaxInt32 + 1,
		"absurdly past int32": math.MaxInt64 / 2,
	} {
		if _, err := rt.EnsureService(ctx, base(count, ok)); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureService with %s replicas (%d) returned %v, want compute.ErrInvalidSpec. "+
				"ScaleService was fixed in round three and this sibling path kept the "+
				"lower-bound-only check for four more rounds.", name, count, err)
		}
	}

	// Ports, on the three conversions that were each guarded by their own
	// hand-written check before the bound was centralised.
	for name, port := range map[string]int{
		"zero":                                 0,
		"negative":                             -1,
		"past 65535":                           70000,
		"past int32":                           math.MaxInt32 + 1,
		"wraps to a valid port when truncated": math.MaxInt32 + 1 + 8080,
	} {
		_, err := rt.EnsureService(ctx, base(1, []compute.PortSpec{{Number: port}}))
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureService with a %s container port (%d) returned %v, want "+
				"compute.ErrInvalidSpec", name, port, err)
		}
	}

	// The OTHER two port paths. Centralising the bound deleted three
	// hand-written port checks, and only one of them -- the container port -- was
	// covered by any test in this repository: nothing drove an out-of-range
	// ingress-rule port or route target port, before this change or after it. So
	// "the guards were replaced, not lost" was an unverified claim about two of
	// the three, which is exactly the kind of claim this branch keeps finding.
	// Driving them here makes the refactor falsifiable.
	for name, port := range map[string]int{
		"zero": 0, "negative": -1, "past 65535": 70000, "past int32": math.MaxInt32 + 1,
	} {
		ingress := base(1, ok)
		ingress.Ingress = []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerInternet}, Port: port},
		}
		if _, err := rt.EnsureService(ctx, ingress); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureService with a %s ingress-rule port (%d) returned %v, want "+
				"compute.ErrInvalidSpec", name, port, err)
		}

		route := base(1, ok)
		route.Routes = []compute.Route{
			{Host: "app.invalid", TargetPort: port, AllowPlaintext: true},
		}
		if _, err := rt.EnsureService(ctx, route); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureService with a %s route target port (%d) returned %v, want "+
				"compute.ErrInvalidSpec", name, port, err)
		}
	}

	// The control: a representable spec still succeeds, so none of the above is
	// a blanket refusal.
	if _, err := rt.EnsureService(ctx, base(2, ok)); err != nil {
		t.Errorf("EnsureService refused a representable spec: %v", err)
	}
}

// callersOfGrantPullAccess returns the names of the package functions that call
// [Provider.grantPullAccess], derived from the package's own source.
//
// # Why the type checker and not a selector match
//
// Matching `.grantPullAccess(` as text is a spelling census, and this branch has
// been defeated by one three times: a callee spelled `int32`, then an alias of it,
// then a defined type whose underlying type it was. So the callee is resolved to a
// [types.Func] and compared against the declaration's own object. A rename follows
// automatically; a wrapper that forwards to it does not, and that is stated at the
// call site rather than implied.
//
// Type-checking here runs without resolving imports, which is safe for the same
// reason it is safe in [TestEveryNarrowingConversionIsBounded]: the identifier
// being resolved is declared in this package, so no import is needed to reach it.
// The caller asserts the result is non-empty, which is what catches a degraded
// typecheck -- a derivation that finds nothing is not a pass.
func callersOfGrantPullAccess(t *testing.T) map[string]bool {
	t.Helper()

	dir := packageDirForTest(t)
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
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, f)
	}
	info := &types.Info{
		Uses: map[*ast.Ident]types.Object{},
		Defs: map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Error: func(error) {}}
	_, _ = conf.Check("k8s", fset, files, info)

	// The declaration's own object, so the comparison is on identity rather than
	// on the name.
	var target types.Object
	for ident, obj := range info.Defs {
		if ident.Name == "grantPullAccess" && obj != nil {
			target = obj
			break
		}
	}
	if target == nil {
		t.Fatal("grantPullAccess has no definition the type checker could resolve; the derivation " +
			"below would return an empty set and agree with any table")
	}

	out := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if info.Uses[sel.Sel] == target {
					out[fn.Name.Name] = true
				}
				return true
			})
		}
	}
	// The declaration itself is not a caller.
	delete(out, "grantPullAccess")
	return out
}
