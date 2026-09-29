// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestEveryCoveredByClaimIsBoundToACall closes the gap that made CoveredBy
// unfalsifiable.
//
// # What was wrong
//
// undrivenPortMethods lets an entry say "this method is not driven here, but check
// X exercises it". Nothing checked that X does. plausibleCheckName validates the
// *shape* of the name — that it looks like a check this suite could have — and
// nothing at all validated the relation. So both RevokeExternal calls could be
// deleted from the named check: it compiled, the whole suite passed, and the
// CoveredBy claim went on asserting coverage that no longer existed.
//
// **A name that is validated for shape and never resolved is a restatement
// nothing compares against its source** — which is the defect this table exists
// to prevent, arriving in the table's own escape hatch.
//
// # What this does
//
// Resolves the claim rather than inspecting it. It parses this package for the
// Check literals that register each check, maps every check name to the function
// registered for it, and requires that function's body to contain a call to the
// method the entry claims it covers. Deleting the call now fails here.
//
// # What it establishes, corrected: SPELLING, not execution
//
// An earlier version of this comment said the floor was "a call that is really
// made". **It is not, and this test cannot see the difference.** It searches the
// function's syntax for a call expression whose selector is the method, so an
// identifier in a position that never runs satisfies it. Both real revokes were
// replaced with an uninvoked closure containing `granter.RevokeExternal` — this
// test, the whole suite and the fake conformance run all stayed green while the
// call the claim named was never executed.
//
// That is the same shape as the defect this file was written for, one level in:
// matching how a thing is *written* and calling it evidence of what the thing
// *does*. A selector is not an invocation, the way an error-code string is not a
// typed exception.
//
// So this test's guarantee is stated as what it is: **the named check's source
// mentions a call to the method.** That is worth having — it fails when somebody
// deletes the call outright, which was the original gap — and it is not a claim
// about execution.
//
// Execution is established separately and behaviourally, by
// [TestEveryCoveredByClaimIsBoundToAnExecutedCall]: it runs the check against a
// provider whose granter records every call and asserts both methods were
// invoked. Syntax here, execution there, and neither pretending to the other.
//
// # What NEITHER does, stated because the boundary is a population
//
// Neither binds what the call *asserts*. A check that invoked the method and
// ignored the result satisfies both. That is a weaker guarantee than the
// obligation table's, and deliberately so: the alternative is asserting on
// assertions, which has no floor.
func TestEveryCoveredByClaimIsBoundToACall(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	files := parseThisPackage(t, fset)
	registered := registeredChecks(t, files)
	if len(registered) < 5 {
		t.Fatalf("resolved %d check registrations from this package's source, which cannot be "+
			"right; a derivation that finds nothing passes every claim over it", len(registered))
	}

	bodies := functionBodies(files)
	claims := 0
	for iface, methods := range undrivenPortMethods() {
		for method, x := range methods {
			if x.CoveredBy == "" {
				continue
			}
			claims++
			// The claimed name is the first token; anything after it is prose.
			claimed := strings.Fields(x.CoveredBy)[0]

			if ex, exempt := unresolvableCoveredBy[exemptionKey{iface, method, claimed}]; exempt {
				// Keyed by the whole triple, and fatal-by-default for anything not
				// listed. See [exemptionKey] for why the check name alone was not a
				// key.
				t.Logf("%s.%s: %q is exempt from resolution -- %s", iface, method, claimed, ex.Reason)
				continue
			}

			// A wildcard claim names a FAMILY of checks, because port check names
			// are computed and one obligation can be discharged by several. It
			// resolves to every registered name with that prefix, and must resolve
			// to at least one -- a pattern matching nothing is the same defect as
			// a name resolving to nothing, and it is easier to write by accident.
			if prefix, wild := strings.CutSuffix(claimed, "*"); wild {
				matches := 0
				for name, fn := range registered {
					if !strings.HasPrefix(name, prefix) {
						continue
					}
					matches++
					body, ok := bodies[fn]
					if !ok {
						t.Errorf("%s.%s claims coverage by %q, which matches check %q registered "+
							"as %s, and that function's declaration is not in this package",
							iface, method, claimed, name, fn)
						continue
					}
					if !callsMethod(body, method) {
						t.Errorf("%s.%s claims coverage by the pattern %q, and check %q (function "+
							"%s) matches it without calling %s. Every check a pattern claims must "+
							"exercise the method, or the pattern is wider than the coverage",
							iface, method, claimed, name, fn, method)
					}
				}
				if matches == 0 {
					t.Errorf("%s.%s claims coverage by the pattern %q and no registered check name "+
						"begins with %q. A pattern that matches nothing asserts coverage over an "+
						"empty set, which passes any check made over it -- if the checks do not "+
						"exist yet the claim is a forward reference and belongs in "+
						"unresolvableCoveredBy", iface, method, claimed, prefix)
				}
				continue
			}

			fn, ok := registered[claimed]
			if !ok {
				t.Errorf("%s.%s claims to be covered by %q and no check is registered under that "+
					"name. plausibleCheckName only validates the SHAPE of a name; this resolves "+
					"it, which is the difference between a claim and a binding. If the check is "+
					"registered with a computed name, name it by its literal suffix; if it does "+
					"not exist yet, the claim is a forward reference and belongs in "+
					"unresolvableCoveredBy with the reason", iface, method, claimed)
				continue
			}
			if fn == "" {
				t.Errorf("%s.%s claims coverage by %q, which is registered with a non-identifier "+
					"Fn, so this cannot resolve the function to check. Register it with a named "+
					"function or exempt it explicitly", iface, method, claimed)
				continue
			}
			body, ok := bodies[fn]
			if !ok {
				t.Errorf("%s.%s claims coverage by %q, registered as %s, and that function's "+
					"declaration is not in this package", iface, method, claimed, fn)
				continue
			}
			if !callsMethod(body, method) {
				t.Errorf("%s.%s claims to be covered by %q (function %s) and that function does "+
					"not call %s. The claim asserted coverage that the check does not perform — "+
					"delete the claim, or make the check drive the method",
					iface, method, claimed, fn, method)
			}
		}
	}
	if claims == 0 {
		t.Log("no CoveredBy claims exist today; this check is a tripwire for the first one")
	}
}

// parseThisPackage parses every non-test Go file in this directory.
func parseThisPackage(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var out []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatal("no non-test Go files found; a derivation that reads nothing passes everything")
	}
	return out
}

// registeredChecks maps a check's Name to the identifier registered as its Fn.
//
// Only Fn values that are plain identifiers are resolvable; a check registered
// with a call expression (checkExtLookup(port), say) is recorded as unresolvable
// rather than skipped, so a CoveredBy naming one fails loudly instead of silently
// finding nothing.
func registeredChecks(t *testing.T, files []*ast.File) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var name, fn string
			resolvable := true
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Name":
					if s, ok := kv.Value.(*ast.BasicLit); ok && s.Kind == token.STRING {
						if v, err := strconv.Unquote(s.Value); err == nil {
							name = v
						}
					}
				case "Fn":
					if id, ok := kv.Value.(*ast.Ident); ok {
						fn = id.Name
					} else {
						resolvable = false
					}
				}
			}
			if name == "" {
				return true
			}
			if !resolvable {
				out[name] = ""
				return true
			}
			if fn != "" {
				out[name] = fn
			}
			return true
		})
	}
	return out
}

// functionBodies maps a top-level function name to its body.
func functionBodies(files []*ast.File) map[string]*ast.BlockStmt {
	out := map[string]*ast.BlockStmt{}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			out[fn.Name.Name] = fn.Body
		}
	}
	return out
}

// callsMethod reports whether body contains a call whose selector is method.
func callsMethod(body *ast.BlockStmt, method string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
			found = true
			return false
		}
		return true
	})
	return found
}

// exemptionKey identifies exactly ONE CoveredBy claim: the interface that carries
// the undriven method, the method, and the check name the claim gives.
//
// # Why the check name alone was not a key
//
// It was, for one round. Keying on the claim text meant an entry written for one
// claim silently excused **every** claim naming the same check — so adding a second
// undriven method whose CoveredBy pointed at the same absent check inherited the
// exemption without anybody writing it down, and the stale-entry check still saw
// the entry as used. One reviewed decision quietly became a standing licence for a
// population nobody had reviewed.
//
// That is the failure the exemption mechanism exists to prevent, arriving in the
// mechanism's own key: a name validated for shape, matched by one of its parts, and
// never resolved to the thing it was written about.
//
// The triple fixes it by construction rather than by detection. Each (interface,
// method) pair carries at most one CoveredBy in [undrivenPortMethods], so a triple
// matches at most one claim — **there is no second claim for an entry to absorb.**
// A second method needing the same excuse now needs its own entry, reviewed on its
// own terms, and until it has one the binding test is fatal on it.
type exemptionKey struct {
	// Interface is the port interface's name as [undrivenPortMethods] keys it.
	Interface string
	// Method is the undriven method.
	Method string
	// Claim is the check name the CoveredBy names -- its first field, not the
	// prose after it.
	Claim string
}

// String renders a key for a failure message.
func (k exemptionKey) String() string {
	return k.Interface + "." + k.Method + " -> " + k.Claim
}

// exemption is a CoveredBy claim this test cannot resolve, with the reason and a
// MACHINE-CHECKABLE retirement condition.
type exemption struct {
	// Reason is why the claim cannot be resolved.
	Reason string
	// RetiredWhen is a substring of a check name. When any check registered in
	// this package has a name containing it, the exemption's precondition is gone
	// and the entry is fatal.
	//
	// A substring rather than a full name because port check names are computed —
	// "port/" + portName + suffix — so no literal of the whole name exists to
	// match. The distinguishing suffix does exist as a literal, which is enough.
	RetiredWhen string
}

// unresolvableCoveredBy exempts CoveredBy claims this test cannot resolve.
//
// # Why the retirement condition is code and not prose
//
// The first version recorded "remove this entry when #19 lands" as a sentence.
// **That makes the exemption's correctness depend on somebody remembering** — and
// the moment #19 lands the recorded reason becomes false, leaving an entry that
// excuses something no longer needing excuse and reads as a decision somebody
// still stands behind.
//
// That is precisely the class this file exists to catch, in this file. The gate
// makes an *unlisted* claim fatal; **a stale listed entry is the other half.** So
// the retirement condition is checked: an exemption naming an absent check is
// valid, and **an exemption naming a present one is fatal.** The entry deletes
// itself by turning red the moment it becomes unnecessary, and the merge order of
// two unrelated pull requests stops mattering.
//
// Note the direction. A tripwire fires when something breaks; this fires when
// something **succeeds** — the case nobody watches for, and the reason "not yet"
// records rot silently.
var unresolvableCoveredBy = map[exemptionKey]exemption{
	// EMPTY, and it emptied itself.
	//
	// It held one entry: SecretStore.DeleteScope -> "port/secret/delete-scope-*",
	// a forward reference to USOSS-26 / PR #19. That PR merged, and
	// TestNoExemptionOutlivesItsPrecondition fired on the next rebase naming both
	// checks that now carry the substring -- so the exemption was deleted because
	// a test said it was excusing nothing, not because somebody remembered.
	//
	// That is the whole design working once, in production, on its first
	// opportunity: the entry retired itself the moment its subject arrived. Left
	// empty rather than deleted because the mechanism is the point, and the next
	// forward reference should land in a table that already exists with its
	// obligations written down.
}

// TestNoExemptionOutlivesItsPrecondition is the other half of the gate.
//
// [unresolvableCoveredBy] excuses claims that cannot be resolved because the checks
// they name do not exist. When those checks arrive, the excuse is obsolete — and an
// obsolete exemption is indistinguishable from a live one, which is how a "not yet"
// record becomes a permanent hole.
//
// So each entry names a substring, and this fails when a registered check contains
// it. **The exemption is valid exactly while its subject is absent.**
func TestNoExemptionOutlivesItsPrecondition(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	files := parseThisPackage(t, fset)
	names := checkNameLiterals(files)
	if len(names) < 20 {
		t.Fatalf("collected %d check-name literals from this package, which cannot be right; a "+
			"derivation that finds nothing retires no exemption", len(names))
	}

	// The claims that exist, keyed the way an exemption is keyed. A map rather
	// than a set of check names: an exemption is now a statement about one
	// (interface, method) pair, so what has to exist for it to be live is that
	// pair making that claim -- not the check name appearing anywhere.
	claims := map[exemptionKey]bool{}
	for iface, methods := range undrivenPortMethods() {
		for method, x := range methods {
			if x.CoveredBy != "" {
				claims[exemptionKey{iface, method, strings.Fields(x.CoveredBy)[0]}] = true
			}
		}
	}

	for key, ex := range unresolvableCoveredBy {
		if ex.RetiredWhen == "" {
			t.Errorf("the exemption for %s has no retirement condition, so nothing can ever "+
				"retire it. An exemption with no expiry is where an obligation goes to be "+
				"forgotten", key)
			continue
		}
		for _, n := range names {
			if strings.Contains(n, ex.RetiredWhen) {
				t.Errorf("the exemption for %s is retired: a check named %q now contains %q, so "+
					"the claim it excuses can be resolved and the exemption is excusing nothing. "+
					"Delete the exemption and let the binding check the claim -- which will then "+
					"either pass or be a real finding", key, n, ex.RetiredWhen)
			}
		}
		// EXACTLY ONE claim, and it is this triple's. The triple can match at
		// most one entry in undrivenPortMethods, so the "at most" half holds by
		// construction; this is the "at least" half. An exemption whose interface,
		// method or claim text has drifted -- because the method was renamed, the
		// entry deleted, or the CoveredBy retargeted -- now names nothing, and
		// that is a finding rather than a quiet no-op.
		//
		// Under the old check-name key this could only ask whether the NAME was
		// claimed somewhere, which stayed true while the entry it was written for
		// disappeared, and stayed true for arbitrarily many entries it had never
		// been reviewed against.
		if !claims[key] {
			t.Errorf("the exemption for %s matches no CoveredBy claim. %s carries no claim on "+
				"%q -- the entry it was written for was renamed, retargeted or deleted, so the "+
				"exemption excuses nothing and any claim that DOES need excusing is now "+
				"unlisted and fatal, which is the correct default but not what this entry says",
				key, key.Interface+"."+key.Method, key.Claim)
		}
	}
}

// checkNameLiterals collects every string literal appearing in a Check's Name,
// including the literal parts of a concatenation.
//
// The literal parts are what makes a computed name matchable: "port/" + pt.Name +
// "/ensure-is-idempotent" yields two literals, and the distinguishing one is the
// suffix.
func checkNameLiterals(files []*ast.File) []string {
	var out []string
	collect := func(e ast.Expr) {
		ast.Inspect(e, func(n ast.Node) bool {
			if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if v, err := strconv.Unquote(b.Value); err == nil {
					out = append(out, v)
				}
			}
			return true
		})
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Name" {
					collect(kv.Value)
				}
			}
			return true
		})
	}
	return out
}
