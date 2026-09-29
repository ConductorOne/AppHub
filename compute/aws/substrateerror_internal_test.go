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

// TestNoArmOfSubstrateErrorReturnsTheIncomingError is [substrateError]'s half
// of USOSS-76, structured exactly like
// [TestNoArmOfWrapReturnsTheIncomingError] in wrap_internal_test.go: the
// property is read off the source rather than off a table of inputs, so an
// arm added later without a matching row cannot slip past it.
//
// Every member of [Substrate] is an interface a caller can supply an adapter
// for -- ECR, IAM, STS and Builder among them, and none of the rest are any
// more trustworthy: the SDK-backed implementations carry the AWS SDK's own
// message, and the in-memory ones are this package's own fixtures, but the
// PORT itself is what a third party can implement, and substrateError has no
// way to tell which adapter produced the err it was handed. So NO ARM MAY
// RETURN err, wrap it with %w, or format it with %v -- classify it with
// errors.Is and answer with text this package owns, the same rule
// [secretStore.wrap] was fixed to follow in #19.
func TestNoArmOfSubstrateErrorReturnsTheIncomingError(t *testing.T) {
	t.Parallel()

	fn, fset := substrateErrorDecl(t)

	var errParam string
	for _, f := range fn.Type.Params.List {
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "error" && len(f.Names) == 1 {
			errParam = f.Names[0].Name
		}
	}
	if errParam == "" {
		t.Fatal("substrateError has no single error parameter; this test cannot identify what it " +
			"must not return, so it would pass vacuously")
	}

	returns := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		for _, res := range ret.Results {
			ast.Inspect(res, func(m ast.Node) bool {
				id, ok := m.(*ast.Ident)
				if !ok || id.Name != errParam {
					return true
				}
				t.Errorf("%s: a return inside substrateError mentions %q. Every [Substrate] member "+
					"is an interface a caller can supply an adapter for, so the incoming error's "+
					"text is not this package's to show: classify it and answer with a fixed "+
					"message, the way secretStore.wrap does",
					fset.Position(id.Pos()), errParam)
				return false
			})
		}
		return true
	})

	if returns < 10 {
		t.Errorf("substrateError has %d return statements and at least ten arms (nil, seven "+
			"sentinels, two context arms, the retryable hook and the default) are expected; if "+
			"arms were removed this test is guarding less than it claims", returns)
	}
}

// TestEveryArmOfSubstrateErrorIsCovered derives the classifier's arm count and
// names FROM THE SWITCH, the same way TestEveryArmOfWrapIsCovered does for
// [secretStore.wrap] -- so a new arm without a matching row here is a build
// failure, not a silent gap.
func TestEveryArmOfSubstrateErrorIsCovered(t *testing.T) {
	t.Parallel()

	fn, _ := substrateErrorDecl(t)

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
			named := false
			for _, e := range cc.List {
				switch expr := e.(type) {
				case *ast.CallExpr:
					if len(expr.Args) != 2 {
						continue
					}
					switch a := expr.Args[1].(type) {
					case *ast.SelectorExpr:
						sentinels = append(sentinels, a.Sel.Name)
						named = true
					case *ast.Ident:
						sentinels = append(sentinels, a.Name)
						named = true
					default:
						t.Errorf("arm %d classifies against a %T, which this derivation cannot "+
							"name; extend it rather than letting the arm go uncounted", cases, a)
					}
				case *ast.BinaryExpr:
					// p.cfg.IsRetryable != nil && p.cfg.IsRetryable(err): the
					// operator hook, which is not an errors.Is call and so has
					// no sentinel to read off -- named explicitly instead.
					sentinels = append(sentinels, "IsRetryable")
					named = true
				}
			}
			if !named {
				t.Errorf("arm %d (case == nil? %v) has a case list this derivation could not name "+
					"at all; extend it rather than leaving the arm uncounted", cases, cc.List == nil)
			}
		}
		return false
	})

	if cases == 0 {
		t.Fatal("no switch found in substrateError, so this test derived nothing and would pass " +
			"vacuously")
	}
	if len(sentinels) != cases {
		t.Fatalf("substrateError has %d arms and this derivation could name %d of them (%v). An "+
			"arm it cannot name is an arm it cannot check: extend the extractor rather than "+
			"leaving the comparison below to run on a short list", cases, len(sentinels), sentinels)
	}
	t.Logf("substrateError classifies %d arms: %s", cases, strings.Join(sentinels, ", "))

	want := []string{
		"ErrNoSuchResource", "ErrThrottled", "ErrNameTaken", "ErrAlreadyExists", "ErrConflict",
		"ErrDenied", "ErrMalformed", "Canceled", "DeadlineExceeded", "IsRetryable", "default",
	}
	if len(sentinels) != len(want) {
		t.Fatalf("substrateError classifies %v; this test expects %v. A new arm needs a row in "+
			"the marker-driven test in substrateerror_test.go and a name here",
			sentinels, want)
	}
	for i := range want {
		if sentinels[i] != want[i] {
			t.Errorf("arm %d classifies %s, expected %s", i, sentinels[i], want[i])
		}
	}
}

// substrateErrorDecl parses this package's own source and returns
// substrateError's declaration.
func substrateErrorDecl(t *testing.T) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "provider.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing provider.go: %v", err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "substrateError" && fn.Recv != nil {
			return fn, fset
		}
	}
	t.Fatal("no substrateError method found in provider.go; a rename must fail this test rather " +
		"than skip it")
	return nil, nil
}
