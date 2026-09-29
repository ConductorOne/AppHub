// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"go/importer"
	"go/token"
	"go/types"
	"testing"
)

// The port population, from the compiler rather than from a syntax walk.
//
// USOSS-32 built this suite's coverage claims on portInterfaces(), which derives
// the port interfaces from compute.Provider's accessors. That was a derivation of
// the wrong set: four ports are reached through a lookup helper rather than an
// accessor, so twelve methods were outside the population every "driven or named"
// assertion was made against, and nothing said so. The list looked complete
// because everything in its population was accounted for.
//
// **Non-emptiness proves a derivation found something, never that it looked
// everywhere.** USOSS-32 asserted the former and skipped the latter.
//
// The first fix for that was a go/ast walk over both packages. It was rejected,
// correctly, and the reason is worth keeping here because it is the fourth
// instance of one shape on this project: a syntax walk recognises a hardcoded set
// of forms, and the next form is always available. That draft followed an
// embedded interface only when it was a bare identifier — a same-package embed —
// and *silently ignored* a selector, so an ext port embedding compute.Granter
// would have had two methods vanish from its method set with no complaint. It
// also saw only `type X interface{...}` and would have missed an alias. Two
// shrugs, in the audit written to stop things being silently missed.
//
// So this asks the type checker instead. types.Scope gives the compiler's own
// answer to what a package exports; *types.Interface.NumMethods gives the
// complete method set with promotion through embedding already resolved,
// whatever syntax produced it; and an alias resolves through Underlying. There is
// no set of recognised forms left to forget, and nothing to keep in sync with a
// second count.
//
// The cost is real and worth stating: type-checking two packages from source is
// slower than parsing them. It is a few seconds, once, in a package whose own
// tests take milliseconds.

// TestEveryExportedInterfaceIsClassified requires every exported interface in
// compute and compute/ext to be a port this suite accounts for, or to be named
// as not being one.
//
// This is the guard the USOSS-39 audit found missing. Without it, a port added
// to compute/ext — or a fifth lookup helper — joins the tree with zero coverage
// and nothing objects, which is what had already happened four times over.
func TestEveryExportedInterfaceIsClassified(t *testing.T) {
	t.Parallel()

	declared := map[string]map[string]bool{}
	for _, path := range []string{
		"github.com/conductorone/apphub/compute",
		"github.com/conductorone/apphub/compute/ext",
	} {
		for name, methods := range exportedInterfaces(t, path) {
			if existing, dup := declared[name]; dup {
				t.Errorf("interface %q is declared in two of the audited packages (%d and %d "+
					"methods); the classification tables key on the bare name and cannot tell "+
					"them apart", name, len(existing), len(methods))
			}
			declared[name] = methods
		}
	}
	if len(declared) == 0 {
		t.Fatal("the audit found no exported interfaces in compute or compute/ext, which cannot " +
			"be true; a derivation that returns nothing passes every check written over it")
	}

	known := map[string]bool{}
	for _, iface := range allPortInterfaces() {
		known[iface.Name()] = true
	}
	notPort := notPorts()
	undriven := undrivenPortMethods()

	for name, methods := range declared {
		switch {
		case known[name] && notPort[name] != "":
			t.Errorf("interface %q is both a port the suite drives and named as not a port; one "+
				"of the two is wrong", name)
		case known[name]:
			// Its methods are checked one by one by
			// TestEveryPortMethodIsDrivenOrNamed. What matters here is that the
			// type checker's method set and the reflected one agree: two views
			// of the same interface disagreeing is the failure mode of any
			// derivation, and it is why this is written over both.
			reflected := map[string]bool{}
			for _, iface := range allPortInterfaces() {
				if iface.Name() != name {
					continue
				}
				for _, m := range methodNames(iface) {
					reflected[m] = true
				}
			}
			for m := range methods {
				if !reflected[m] {
					t.Errorf("%s.%s is in the type checker's method set and absent from the "+
						"reflected one the suite enumerates; the two views disagree", name, m)
				}
			}
			for m := range reflected {
				if !methods[m] {
					t.Errorf("%s.%s is in the reflected method set and absent from the type "+
						"checker's; the two views disagree", name, m)
				}
			}
		case notPort[name] != "":
			// Classified as not a port, with a reason.
		case len(undriven[name]) > 0:
			t.Errorf("interface %q has named undriven methods but is not in the port population, "+
				"so nothing checks the rest of its methods", name)
		default:
			t.Errorf("exported interface %q is in compute or compute/ext and this suite has never "+
				"heard of it: not a port the population covers, not named in notPorts. A port "+
				"that joins the tree unclassified gets no coverage and nothing objects, which is "+
				"how twelve methods went missing before USOSS-39. Add it to the population, or "+
				"say why it is not a port", name)
		}
	}

	// The reverse direction: a table entry for something no longer declared. A
	// stale entry is how a list stops describing anything while still looking
	// maintained.
	for name := range notPort {
		if _, ok := declared[name]; !ok {
			t.Errorf("notPorts names %q, which is not an exported interface in compute or "+
				"compute/ext; the entry is stale", name)
		}
	}
	for _, iface := range allPortInterfaces() {
		if _, ok := declared[iface.Name()]; !ok {
			t.Errorf("the port population includes %q, which the type checker does not find "+
				"exported by compute or compute/ext; either it moved or this audit is looking in "+
				"the wrong place", iface.Name())
		}
	}
}

// exportedInterfaces type-checks the package at path and returns every exported
// interface's complete method set.
//
// "Complete" is the point: NumMethods on a type-checked interface has already
// resolved promotion through embedding, whatever syntax expressed it and whatever
// package it came from. That is the half a syntax walk gets wrong.
func exportedInterfaces(t *testing.T, path string) map[string]map[string]bool {
	t.Helper()

	fset := token.NewFileSet()
	pkg, err := importer.ForCompiler(fset, "source", nil).Import(path)
	if err != nil {
		t.Fatalf("type-checking %s: %v", path, err)
	}
	scope := pkg.Scope()
	if len(scope.Names()) == 0 {
		t.Fatalf("%s type-checked to an empty scope, which cannot be right; a derivation that "+
			"returns nothing passes every check over it", path)
	}

	out := map[string]map[string]bool{}
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		// Only a type name can be an interface. Anything else — a func, a var, a
		// const — is not a candidate, and this is a classification rather than a
		// shrug: the type checker has already told us what the object is.
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		iface, ok := tn.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		if !iface.IsMethodSet() {
			// A constraint interface — type sets, unions — is not a port and
			// cannot be implemented at runtime. Named rather than skipped
			// silently, because "this walk did not understand it" and "this is
			// not a port" must not look the same.
			t.Logf("%s.%s is a constraint interface rather than a method set, so it is not a "+
				"port", path, name)
			continue
		}
		methods := map[string]bool{}
		for i := range iface.NumMethods() {
			methods[iface.Method(i).Name()] = true
		}
		if len(methods) == 0 {
			t.Errorf("%s.%s is an exported interface with no methods; this audit cannot tell "+
				"whether it is a port and will not guess", path, name)
			continue
		}
		out[name] = methods
	}
	return out
}
