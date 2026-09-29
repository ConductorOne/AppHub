// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestNoArmOfWrapReturnsTheIncomingError is the (a) property asserted over
// [secretStore.wrap]'s ARMS rather than over its callers or its outputs.
//
// # Why this is structural and not a table of inputs
//
// Round one fixed six arms and tested them by planting a marker in a foreign
// error and driving every method. That test is real and it stays -- but it can
// only see arms it has a row for, and round two found a SEVENTH: the context
// arm, added by the round-one fix itself, which recognised a cancellation from
// the incoming error and then returned that error. Returning the thing you
// recognised is exactly what the other six stopped doing.
//
// Two guards missed it. The data-driven test had no cancellation row, and its
// completeness check compared a literal map against a literal 6 -- two
// hand-written numbers agreeing, which cannot see a new arm at all. A guard
// against an unclassified arm that is satisfied by its own table is a tautology.
//
// So the property is read off the source: NO RETURN INSIDE wrap MAY MENTION THE
// err PARAMETER. Not by returning it, not by passing it to fmt.Errorf, not with
// %w and not with %v. An eighth arm cannot pass this without being written to,
// and the check needs no input at all.
//
// errors.Is(err, ...) is permitted, and only there: classification reads the
// incoming error, which is the entire point. What may not happen is the read
// value reaching a returned value.
func TestNoArmOfWrapReturnsTheIncomingError(t *testing.T) {
	t.Parallel()

	fn, fset := wrapDecl(t)

	// The parameter's own name, taken from the declaration rather than assumed:
	// renaming it must not silently disable this test.
	var errParam string
	for _, f := range fn.Type.Params.List {
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "error" && len(f.Names) == 1 {
			errParam = f.Names[0].Name
		}
	}
	if errParam == "" {
		t.Fatal("wrap has no single error parameter; this test cannot identify what it must not " +
			"return, so it would pass vacuously")
	}

	returns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		for _, res := range ret.Results {
			// Any mention of the parameter anywhere in a returned expression,
			// however deeply nested in a call.
			ast.Inspect(res, func(m ast.Node) bool {
				id, ok := m.(*ast.Ident)
				if !ok || id.Name != errParam {
					return true
				}
				// errors.Is(err, ...) inside a returned expression would be a
				// boolean, not a wrapped error; wrap has none, and if one
				// appears it should be looked at rather than excused here.
				t.Errorf("%s: a return inside wrap mentions %q. The incoming error is written by "+
					"whoever supplied the ParameterStore -- including SSMParameterStore, which "+
					"carries the SDK's message -- so no arm may return it, wrap it with %%w, or "+
					"format it with %%v. Classify it and answer with text this package owns",
					fset.Position(id.Pos()), errParam)
				return false
			})
		}
		return true
	})

	if returns < 8 {
		t.Errorf("wrap has %d return statements and at least eight arms are expected; if arms were "+
			"removed this test is guarding less than it claims", returns)
	}
}

// TestEveryArmOfWrapIsCovered derives the classifier's arm count FROM THE SWITCH
// rather than from a number somebody typed next to a table.
//
// The check it replaces was `if len(arms) != 6`, comparing a literal map to a
// literal 6. Both were hand-written, both were in the test, and they agreed --
// so adding a seventh arm left it green. A denominator asserted against itself is
// worse than a denominator merely reported.
func TestEveryArmOfWrapIsCovered(t *testing.T) {
	t.Parallel()

	fn, _ := wrapDecl(t)

	var cases int
	var sentinels []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			cases++
			if cc.List == nil {
				sentinels = append(sentinels, "default")
				continue
			}
			for _, e := range cc.List {
				call, ok := e.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					continue
				}
				// BOTH shapes. The first version handled only SelectorExpr, so
				// errors.Is(err, ErrParameterNotFound) -- a plain Ident, this
				// package's own sentinel -- was invisible and five of the eight
				// arms silently vanished from the derivation. The guard against a
				// narrow population, with a narrow population.
				switch a := call.Args[1].(type) {
				case *ast.SelectorExpr:
					sentinels = append(sentinels, a.Sel.Name)
				case *ast.Ident:
					sentinels = append(sentinels, a.Name)
				default:
					t.Errorf("arm %d classifies against a %T, which this derivation cannot name; "+
						"extend it rather than letting the arm go uncounted", cases, a)
				}
			}
		}
		return false
	})

	if cases == 0 {
		t.Fatal("no switch found in wrap, so this test derived nothing and would pass vacuously")
	}
	// TWO derived quantities, both checked. cases counts case clauses; sentinels
	// counts the ones this derivation could NAME. They must agree, or an arm
	// whose classification expression has a shape the extractor does not handle
	// is counted and then silently dropped from the comparison below -- which is
	// exactly what happened: an arm written as `errors.Is(err, X) && cond` is a
	// BinaryExpr, not a CallExpr, so it incremented cases, produced no name, and
	// left the name-length check passing. Counted is not named.
	if len(sentinels) != cases {
		t.Fatalf("wrap has %d arms and this derivation could name %d of them (%v). An arm it "+
			"cannot name is an arm it cannot check: extend the extractor rather than leaving the "+
			"comparison below to run on a short list", cases, len(sentinels), sentinels)
	}
	t.Logf("wrap classifies %d arms: %s", cases, strings.Join(sentinels, ", "))

	// The behavioural table in secret_test.go must have a row per classified
	// sentinel. Named here rather than counted, so a rename fails loudly.
	want := []string{
		"ErrParameterNotFound", "ErrParameterTooLarge", "ErrParameterExists",
		"ErrThrottled", "ErrDenied", "Canceled", "DeadlineExceeded", "default",
	}
	if len(sentinels) != len(want) {
		t.Fatalf("wrap classifies %v; this test expects %v. A new arm needs a row in "+
			"TestNoForeignErrorTextReachesACaller and a name here -- which is the point: the "+
			"seventh arm slipped past a guard that compared two hand-written numbers",
			sentinels, want)
	}
	for i := range want {
		if sentinels[i] != want[i] {
			t.Errorf("arm %d classifies %s, expected %s", i, sentinels[i], want[i])
		}
	}
}

// wrapDecl parses this package's own source and returns wrap's declaration.
func wrapDecl(t *testing.T) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "secret.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing secret.go: %v", err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "wrap" && fn.Recv != nil {
			return fn, fset
		}
	}
	t.Fatal("no wrap method found in secret.go; a rename must fail this test rather than skip it")
	return nil, nil
}
