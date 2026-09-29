// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"testing"
)

// The failure injector has two durations and the difference is load-bearing, so
// both are pinned here (USOSS-60).
//
// The defect these tests exist for was not a wrong mapping. It was that the
// injector had only a one-shot form, so a gate driving many methods in one armed
// window had its arming consumed by the first intercepted call — whichever verb
// that was — and every method after it was scored as unexercised. The suite
// reported partial coverage as though it were complete.
//
// What makes that worth a test rather than a comment is how it was nearly fixed
// wrong. The first diagnosis was "the injector is consulted by writes and not by
// reads", inferred from the shape of the results across three providers. It was
// false: TestAReadAloneConsultsTheInjector below is the measurement that killed
// it. Both hypotheses predict the same symptom — only the first driven method
// surfaces the failure — so the wrong fix would have widened nothing and shipped
// reporting coverage that had not improved. **A population inferred from an
// outcome is not a derived population.**

var errProbe = errors.New("aws: probe failure")

// TestFailNextIsStillOneShot is the pin the USOSS-60 ruling asked for.
//
// FailNext must keep arming exactly one call. It has a legitimate use that
// FailUntilStopped cannot serve — a single induced failure whose retry succeeds,
// which is what conformance.Options.InduceTransient documents — and making it
// sticky would silently change what every existing caller measures: a test that
// arms one failure and asserts the retry succeeds would start asserting nothing,
// because the retry would fail too. That is mutating a contract rather than
// adding a capability.
func TestFailNextIsStillOneShot(t *testing.T) {
	t.Parallel()
	var f failNext

	stop := f.FailNext(errProbe)
	defer stop()

	if got := f.take(); !errors.Is(got, errProbe) {
		t.Fatalf("the first take returned %v, want the injected error", got)
	}
	if got := f.take(); got != nil {
		t.Errorf("the second take returned %v; FailNext arms one call, and a caller that arms "+
			"one failure to assert its retry succeeds depends on the second call being clean",
			got)
	}
	if !f.injectionFired() {
		t.Error("the injector does not report having fired, though a take consumed it")
	}
}

// TestFailUntilStoppedArmsEveryCallUntilStopped is the new capability.
func TestFailUntilStoppedArmsEveryCallUntilStopped(t *testing.T) {
	t.Parallel()
	var f failNext

	stop := f.FailUntilStopped(errProbe)
	// Four is arbitrary and more than one is the point: the one-shot form passed
	// the first of these and failed every one after it.
	for i := range 4 {
		if got := f.take(); !errors.Is(got, errProbe) {
			t.Fatalf("take %d returned %v, want the injected error; an arming that does not "+
				"survive the second call cannot support a gate that drives many methods",
				i+1, got)
		}
	}
	stop()
	if got := f.take(); got != nil {
		t.Errorf("take after stop returned %v, want nil; an arming that outlives its stop "+
			"function leaks a failure into whatever runs next", got)
	}
}

// TestNothingArmedInducesNothing is the control in the other direction, and it is
// the one that stops the whole mechanism being vacuous: an injector that returned
// its error unconditionally would pass both tests above.
func TestNothingArmedInducesNothing(t *testing.T) {
	t.Parallel()
	var f failNext

	if got := f.take(); got != nil {
		t.Errorf("an unarmed injector returned %v", got)
	}
	if f.injectionFired() {
		t.Error("an unarmed injector reports having fired")
	}

	// And after an arming has been stopped, which is the state a run leaves
	// behind.
	stop := f.FailUntilStopped(errProbe)
	_ = f.take()
	stop()
	if got := f.take(); got != nil {
		t.Errorf("a stopped injector returned %v", got)
	}
}

// TestArmingResetsWhetherItFired keeps injectionFired honest across armings, so
// "this injection was observed to fire" cannot be satisfied by an earlier one.
func TestArmingResetsWhetherItFired(t *testing.T) {
	t.Parallel()
	var f failNext

	stop := f.FailNext(errProbe)
	_ = f.take()
	stop()
	if !f.injectionFired() {
		t.Fatal("the injector does not report the first arming as having fired")
	}

	stop = f.FailUntilStopped(errProbe)
	defer stop()
	if f.injectionFired() {
		t.Error("a fresh arming reports having already fired, so a cell whose injection was " +
			"never reached would be counted as evidence on the strength of a previous one")
	}
}
