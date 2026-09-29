// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package errhygiene states one invariant, and lets each package obliged to hold
// it drive that invariant on itself.
//
// The invariant:
//
//	No error a package returns contains any text that did not come from a
//	constant in this repository, a numeric count, or a Go type name.
//
// # Why a package drives this on itself
//
// The first version of this package was a test fixture with a hard-coded list of
// the five packages it covered, and it drove each one from the outside. Driving an
// entry point means calling it, and calling into a package means importing it, so
// the list was also a list of imports. That failed twice over.
//
// It failed on the boundary: credentials/c1 is the one package nothing may import
// (the "c1-optional" rule in internal/boundary, which deliberately covers
// first-party test imports so that a test cannot be the wedge that widens it), and
// it is also the package most in need of the check. USOSS-8 declined to spend an
// allowlist entry on a fixture, correctly, and restated the whole invariant inside
// credentials/c1 instead. Two packages then held the same machinery.
//
// And it failed as a list: every package with an error surface needs this check, so
// a central list of packages is a hand-maintained restatement of *which packages
// have errors*, which grows and goes stale like any other.
//
// Reversing the direction fixes both. A package's own external test declares its
// [Subject] and calls [Assert]; nothing here imports the package under test, no
// allowlist entry is needed, and the invariant lives with the package obliged to
// satisfy it. The import that used to be forbidden now runs the other way, where
// it is ordinary.
//
// # What a caller writes
//
// One test, in the package's external test package:
//
//	func TestErrorHygiene(t *testing.T) {
//		errhygiene.Assert(t, errhygiene.Subject{
//			ImportPath: "github.com/conductorone/apphub/credentials/workload",
//			Drivers:    drivers,
//		})
//	}
//
// [Assert] derives the package's exported surface, requires every exported callable
// that takes an argument to be driven or to carry a named exemption, drives each
// one with two sentinels, and asserts that nothing derived from either sentinel
// reaches text by any path this repository can be read by.
//
// # The implementation, split by job
//
//   - surface.go derives the exported surface two independent ways and accounts for
//     every exported callable each one reports;
//   - render.go turns a value into text every way this repository can be read, and
//     separately walks everything reachable from it by reflection;
//   - assert.go holds the assertions.
//
// Read surface.go first, for why the surface is derived twice rather than listed,
// and why a new exported input fails the test instead of being skipped.
//
// # This package imports "testing" from non-test files, on purpose
//
// It is a test helper whose whole job is to be importable by a package's own test.
// That is the same shape as net/http/httptest and credentials/lifecycle/lifecycletest.
// Nothing in a production build reaches it: it is under internal/, and the only
// importers are _test.go files.
package errhygiene

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Driver drives one derived entry point, or records why it is exempt.
//
// Exactly one of Run and Why is set. An entry point with neither fails the
// cross-check, which is the property that makes a new exported input a test failure
// rather than a silent gap: the derivation finds it, and nothing claims it.
type Driver struct {
	// Run drives the entry point with one sentinel and returns every value it
	// produced. How hard those values are looked at is not the driver's choice:
	// see renderAll.
	//
	// A driver returns the values it wants checked. A value that holds the input
	// by design -- a registry storing the IDs it was handed, a configuration
	// holding the URL an operator supplied, a transport this fixture built -- is
	// simply not returned, and the driver says so where it would have been.
	Run func(t *testing.T, sentinel string) []any

	// Why is the justification for an entry point that is deliberately not driven.
	Why string

	// ReachableExempt, when set, is why THIS DRIVER's returned values are not put
	// through the reflective and method-set checks.
	//
	// It is deliberately per driver and not per type. The first version of this
	// mechanism excluded credentials.Metadata by type, at any depth, and review put
	// a Metadata inside CreateNotDeliveredError and walked the map through the
	// returned error while every test passed. An exemption that propagates through
	// composition is not the exemption that was documented.
	ReachableExempt string
}

// Population names one of the sets the derivation produces, for a subject that
// asserts a set is empty.
//
// An empty set passes every check made over it, so "this package has none of those"
// is a claim that gets stated and verified rather than left to be inferred from a
// test that quietly did nothing. It is checked in both directions: a population
// named here that turns out to be non-empty fails, and one that is empty without
// being named here fails too.
type Population string

const (
	// PopulationRenderers is the set of exported types with a rendering method
	// (Error, String, GoString, Format, LogValue, or one of the three marshalers).
	PopulationRenderers Population = "rendering types"
	// PopulationTextProducers is the set of exported zero-argument methods whose
	// results can carry text.
	PopulationTextProducers Population = "text-producing zero-argument methods"
)

// Subject is one package's statement of the invariant over itself.
type Subject struct {
	// ImportPath is the package the invariant is stated over. It is type-checked
	// from source, so it needs no build of anything.
	ImportPath string

	// Dir is the package's directory, for the build-constraint-free syntax sweep.
	// Empty means ".", which is where `go test` runs a package's tests, and is
	// what every caller wants.
	Dir string

	// Drivers maps a derived entry-point key to how it is driven. The keys are
	// checked against the derivation in both directions.
	Drivers map[string]Driver

	// EmptyPopulations are the derived sets this package asserts are empty. See
	// [Population].
	EmptyPopulations []Population

	// RendererExemptions are types with a rendering method that no driver
	// produces, keyed by "pkg.Type", with the reason. Each one should be a
	// decision recorded elsewhere in the repository, restated here so that a type
	// is never omitted by accident.
	RendererExemptions map[string]string

	// TextProducerExemptions are types with an exported zero-argument
	// text-producing method that no driver produces a value of, keyed by
	// "pkg.Type", with the reason.
	TextProducerExemptions map[string]string

	// PlatformExcluded names declarations that exist only under a build constraint
	// the type checker's configuration does not satisfy, with the reason. The
	// syntax sweep applies no build constraints, so it finds them; this is where
	// they are accounted for.
	PlatformExcluded map[string]string
}

// Assert states the invariant over one subject.
//
// Every check is a subtest, so a failure names which half of the mechanism found
// it. They are:
//
//	Derivation           the surface is non-empty and every population is accounted for
//	Accounting           every exported callable the type checker reports was filed
//	Population           no declaration escapes the derivation, with build constraints ignored
//	DrivenOrExempt       every derived entry point is claimed, and every driver claims one
//	NoForeignText        the invariant itself, per entry point
//	RenderersExercised   every rendering type is produced by some driver
//	TextProducersInvoked every text-producing zero-argument method was actually called
func Assert(t *testing.T, s Subject) {
	t.Helper()
	if s.ImportPath == "" {
		t.Fatal("errhygiene: a Subject needs an ImportPath")
	}
	if len(s.Drivers) == 0 {
		t.Fatal("errhygiene: a Subject with no drivers claims nothing, and every check over it would pass")
	}

	derived, err := derive(s.ImportPath)
	if err != nil {
		t.Fatalf("errhygiene: %v", err)
	}

	// invoked records every (type, method) pair the zero-argument probe called, so
	// that TextProducersInvoked checks the derived class against what was actually
	// exercised rather than against a list of names. It is per Assert call and not
	// package-level, so the checks below do not depend on test ordering.
	invoked := map[string]bool{}

	t.Run("Derivation", func(t *testing.T) { s.assertDerivation(t, derived) })
	t.Run("Accounting", func(t *testing.T) { s.assertAccounting(t, derived) })
	t.Run("Population", func(t *testing.T) { s.assertPopulation(t, derived) })
	t.Run("DrivenOrExempt", func(t *testing.T) { s.assertDrivenOrExempt(t, derived) })
	t.Run("NoForeignText", func(t *testing.T) { s.assertNoForeignText(t, derived, invoked) })
	t.Run("RenderersExercised", func(t *testing.T) { s.assertRenderersExercised(t, derived) })
	t.Run("TextProducersInvoked", func(t *testing.T) { s.assertTextProducersInvoked(t, derived, invoked) })
}

// dir is the directory the syntax sweep reads.
func (s Subject) dir() string {
	if s.Dir == "" {
		return "."
	}
	return s.Dir
}

// declaresEmpty reports whether the subject claims the named population is empty.
func (s Subject) declaresEmpty(p Population) bool {
	for _, got := range s.EmptyPopulations {
		if got == p {
			return true
		}
	}
	return false
}

// checkPopulation compares a derived set's size against what the subject claimed,
// in both directions.
func (s Subject) checkPopulation(t *testing.T, p Population, n int, members []string) {
	t.Helper()
	declared := s.declaresEmpty(p)
	switch {
	case n == 0 && !declared:
		t.Errorf("this package has no %s, so every check over that set passes vacuously. "+
			"If that is right, say so by adding %q to Subject.EmptyPopulations; if it is not, "+
			"the derivation has a hole.", p, p)
	case n > 0 && declared:
		sort.Strings(members)
		t.Errorf("Subject.EmptyPopulations says this package has no %s, and the derivation found "+
			"%d: %s. Each one needs a driver that proves what it renders, or the claim is stale.",
			p, n, strings.Join(members, ", "))
	default:
		t.Logf("%d %s", n, p)
	}
}

// keyOwner turns "pkg.(*Type).Method" into "pkg.Type", and returns "" for anything
// that is not a method key.
func keyOwner(key string) string {
	lp, rp := strings.Index(key, ".("), strings.Index(key, ").")
	if lp < 0 || rp < lp {
		return ""
	}
	return key[:lp] + "." + strings.TrimPrefix(key[lp+2:rp], "*")
}

// sortedKeys returns a map's keys in a stable order, so a failing run names things
// in the same sequence as the one before it.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
