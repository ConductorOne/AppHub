// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// The Granter audit, derived rather than restated.
//
// The first version of this test held a hand-written map of "every exported
// interface in compute" and checked that map against [compute.WorkloadGrantPorts].
// A reviewer defeated it in one line: an exported `ReviewOnlyPort interface {
// Granter }` outside the map, and the test still passed. The guard I claimed
// made a fourth Granter a red build could not see a fourth port at all.
//
// That is the same defect twice over. It is the defect the audit exists to
// prevent — a rule enforced by a restatement of a set drifts from the set — and
// it is the defect the repository already learned once elsewhere, where a
// hand-maintained package list was replaced by a derived one with a toolchain
// cross-check. A restatement of a set is not a check on that set.
//
// So the set is derived. These tests parse the package's own source with go/ast
// and enumerate every exported interface declaration, which is the thing
// reflection cannot do: a Go program cannot list the types in a package, but a
// Go program can read the package.
//
// Two checks, and both matter:
//
//   - [TestEveryExportedPortIsAuditedForGranter] compares the derived set
//     against [compute.WorkloadGrantPorts] directly. A new exported interface
//     carrying Grant/Revoke is a failure whether or not anybody remembered it.
//   - [TestDerivedPortSetMatchesTheReflectedOne] cross-checks the derivation
//     against the reflect-based view in contract_test.go, so a parser that
//     silently stopped finding anything — the failure mode of any derivation —
//     is itself caught. A derivation that returns the empty set passes every
//     check written over it, which is why this one is written over both.
//
// Scope is package compute. compute/ext is audited separately by its own closed
// port list: nothing there claims portability, and its ports declare Grant and
// Revoke explicitly rather than embedding Granter precisely so they are not
// mistaken for core ones.

// astInterface is one exported interface declaration, with its method set
// resolved through any interfaces it embeds from this package.
type astInterface struct {
	name    string
	methods map[string]bool
}

// exportedInterfaces parses the package in dir and returns every exported
// interface type declaration, with embedded local interfaces flattened.
//
// It reads non-test files only: a test fixture interface is not part of the
// package's contract, and including them would make the audit fail on its own
// negative-test scaffolding.
func exportedInterfaces(t *testing.T, dir string) map[string]astInterface {
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
		if file.Name.Name != "compute" {
			t.Fatalf("%s declares package %q; the audit is parsing the wrong directory",
				name, file.Name.Name)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatalf("no non-test Go files in %s", dir)
	}

	// First pass: every interface declaration, exported or not, because an
	// exported one may embed an unexported one.
	raw := map[string]*ast.InterfaceType{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if it, ok := ts.Type.(*ast.InterfaceType); ok {
					raw[ts.Name.Name] = it
				}
			}
		}
	}
	if len(raw) == 0 {
		t.Fatal("the audit found no interface declarations in package compute, which cannot be " +
			"true; a derivation that returns nothing passes every check written over it, so this " +
			"is a failure rather than a clean run")
	}

	out := map[string]astInterface{}
	for name := range raw {
		if !ast.IsExported(name) {
			continue
		}
		methods := map[string]bool{}
		collectMethods(raw, name, methods, map[string]bool{})
		out[name] = astInterface{name: name, methods: methods}
	}
	return out
}

// collectMethods flattens an interface's method set, following embedded
// interfaces declared in the same package. An embedded type from another
// package is ignored: this audit is about compute's own Granter.
func collectMethods(raw map[string]*ast.InterfaceType, name string, into, seen map[string]bool) {
	if seen[name] {
		return
	}
	seen[name] = true
	it, ok := raw[name]
	if !ok || it.Methods == nil {
		return
	}
	for _, field := range it.Methods.List {
		if len(field.Names) > 0 {
			for _, n := range field.Names {
				into[n.Name] = true
			}
			continue
		}
		if id, ok := field.Type.(*ast.Ident); ok {
			collectMethods(raw, id.Name, into, seen)
		}
	}
}

// carriesGranter reports whether an interface's flattened method set contains
// what [compute.Granter] requires.
//
// By method name rather than by full signature, deliberately: a port that
// declared a differently-shaped Grant would still be a port claiming to grant,
// and the reflect check in TestDerivedPortSetMatchesTheReflectedOne is where
// exact-shape agreement is enforced. Between them, neither an embedded Granter
// nor a hand-declared one can slip past.
func (i astInterface) carriesGranter() bool {
	return i.methods["Grant"] && i.methods["Revoke"]
}

func TestEveryExportedPortIsAuditedForGranter(t *testing.T) {
	t.Parallel()

	found := exportedInterfaces(t, ".")

	audited := map[string]bool{}
	for _, name := range compute.WorkloadGrantPorts() {
		if _, ok := found[name]; !ok {
			t.Fatalf("WorkloadGrantPorts names %q, which is not an exported interface in this "+
				"package", name)
		}
		audited[name] = true
	}

	var names []string
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if name == "Granter" {
			// Granter carries Grant and Revoke by definition; it is the rule,
			// not a port subject to it.
			continue
		}
		switch has := found[name].carriesGranter(); {
		case has && !audited[name]:
			t.Errorf("exported interface %s can grant to a workload identity and is not in "+
				"WorkloadGrantPorts. Either its substrate authorises by workload identity — in "+
				"which case audit it, add it, and say so in Granter's doc comment — or it does "+
				"not, and a provider will be forced to invent a principal or mint a credential "+
				"to implement Grant. That has happened three times already: "+
				"RelationalProvisioner, ImageRegistry, and this one.", name)
		case !has && audited[name]:
			t.Errorf("%s is in WorkloadGrantPorts but no longer carries Grant and Revoke; the "+
				"audit and the interface disagree", name)
		}
	}
}

// TestDerivedPortSetMatchesTheReflectedOne is the toolchain cross-check.
//
// The derivation above is the authority on *which* interfaces exist, because
// only source can answer that. The reflect view in contract_test.go is the
// authority on what they *are*, because only the type system can answer that.
// Comparing them catches the failure mode neither can catch alone: a parser
// that stops finding declarations, or a reflected list that drifts from the
// package.
func TestDerivedPortSetMatchesTheReflectedOne(t *testing.T) {
	t.Parallel()

	derived := exportedInterfaces(t, ".")
	reflected := reflectedPorts()

	for name := range derived {
		if name == "Granter" {
			continue
		}
		if _, ok := reflected[name]; !ok {
			t.Errorf("exported interface %s exists in the package and not in contract_test.go's "+
				"reflected set; the reflect-based checks are not seeing it, so whatever they "+
				"assert about the package is incomplete", name)
		}
	}
	for name := range reflected {
		if _, ok := derived[name]; !ok {
			t.Errorf("contract_test.go reflects %s, which the parser did not find as an exported "+
				"interface; either the type was removed or the derivation is broken", name)
		}
	}

	// A derivation is only useful if it found something. Stated as its own
	// assertion because "found nothing" is the way a derived check dies quietly.
	if len(derived) < len(reflected) || len(derived) == 0 {
		t.Fatalf("the derivation found %d exported interfaces and reflection knows %d; a "+
			"derivation that shrinks is how a generated set stops being a check",
			len(derived), len(reflected))
	}
}
