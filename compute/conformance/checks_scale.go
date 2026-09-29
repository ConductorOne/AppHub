// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"reflect"

	"github.com/conductorone/apphub/compute"
)

// The imperative-scale checks (USOSS-39).
//
// [compute.ContainerRuntime.ScaleService] was driven by nothing before this. Its
// whole documented contract is two sentences — "sets the desired instance count
// without otherwise changing the spec. Zero pauses." — and both halves have a
// plausible provider mistake behind them:
//
//   - A provider that implements Scale as an Ensure with a modified spec loses
//     every field its internal spec does not carry. That is not hypothetical:
//     it is the same create-or-add shape the convergence checks exist for, from
//     the other direction.
//   - A provider that maps zero replicas onto "remove the workload" makes a
//     pause into a delete. The caller then finds its service gone and its
//     network identity released, which is not what pausing means.
//
// These live in their own file rather than in checks_lifecycle.go deliberately:
// USOSS-26's PR #19 is adding secret-scope checks there and there is no reason
// for two workers to contend over one file for unrelated checks.
func scaleChecks(e *Env) []Check {
	if !e.Provider.Capabilities().Has(compute.CapContainerService) {
		return nil
	}
	return []Check{
		{
			Name:      "port/container-service/scale-to-zero-pauses-rather-than-deletes",
			Port:      "container-service",
			Class:     Async,
			Invariant: "scaling to zero pauses the service rather than removing it",
			Fn:        checkScaleToZeroPauses,
		},
		{
			Name:      "port/container-service/scale-changes-only-the-instance-count",
			Port:      "container-service",
			Class:     Async,
			Invariant: "ScaleService changes the desired instance count and nothing else in the spec",
			Fn:        checkScaleChangesOnlyReplicas,
		},
	}
}

// scaleTarget ensures a service and returns the port operations and its ref.
func scaleTarget(tb TB, e *Env, inv, stem string) (*portOps, compute.Ref) {
	tb.Helper()
	var svc Port
	for _, pt := range availablePorts(e) {
		if pt.Name == "container-service" {
			svc = pt
			break
		}
	}
	if svc.ops == nil {
		fatal(tb, "container-service", inv, "the provider advertises %q and the suite has no "+
			"container-service port for it, which is a suite bug", compute.CapContainerService)
	}
	o, err := svc.ops(tb, e, e.Provider)
	if err != nil {
		fatal(tb, "container-service", inv, "the provider advertises %q but the port could not "+
			"be acquired: %v", compute.CapContainerService, err)
	}
	if o.Scale == nil {
		fatal(tb, "container-service", inv, "the container-service port exposes no Scale "+
			"operation, so this check cannot run; that is a suite bug rather than a provider one")
	}
	ref, _, err := o.Ensure(e.Name(stem), Base)
	if err != nil {
		fatal(tb, "container-service", inv, "Ensure failed: %v", redact(err))
	}
	return o, ref
}

// checkScaleToZeroPauses pins the second sentence of ScaleService's contract.
func checkScaleToZeroPauses(tb TB, e *Env) {
	const inv = "scaling to zero pauses the service rather than removing it"
	o, ref := scaleTarget(tb, e, inv, "scale-zero")

	if err := o.Scale(ref, 0); err != nil {
		fail(tb, "container-service", inv, "scaling to zero was refused with %v; zero is a legal "+
			"instance count and the documented way to pause", redact(err))
		return
	}

	st, err := o.Describe(ref)
	if err != nil {
		fail(tb, "container-service", inv, "after scaling to zero the service could not be "+
			"described (%v); a paused service still exists and a caller has to be able to read "+
			"it back to unpause it", redact(err))
		return
	}
	if st.Phase == compute.PhaseGone {
		fail(tb, "container-service", inv, "after scaling to zero the service reports PhaseGone. "+
			"Pausing is not deleting: the definition and the network identity persist and nothing "+
			"runs, and a caller that reads Gone concludes the service was removed and recreates it")
		return
	}
	if st.Phase == compute.PhaseFailed {
		fail(tb, "container-service", inv, "after scaling to zero the service reports PhaseFailed; "+
			"a service with no instances by request has not failed")
	}
	observed, err := o.Observed(ref)
	if err != nil {
		fail(tb, "container-service", inv, "reading the service back after a scale failed: %v",
			redact(err))
		return
	}
	if got := observed["desired-replicas"]; got != "0" {
		fail(tb, "container-service", inv, "after scaling to zero the desired instance count "+
			"reads %q, so the scale did not take effect", got)
	}
}

// checkScaleChangesOnlyReplicas pins the first sentence: "sets the desired
// instance count *without otherwise changing the spec*".
//
// The first version of this compared two marker substrings of the stringified
// spec, and a reviewer defeated it in one edit: a defect that preserved Env —
// and therefore both markers — while deleting Ports, Secrets, Ingress, Routes
// and Labels passed the named check, with all 167 checks green. Two markers are
// not the population "everything except replicas"; they are two members of it,
// and the gap between them and the population is where the defect lived.
//
// So the whole effective spec is compared, normalised for exactly the one field
// a scale is allowed to change. It is checkable at all only because the USOSS-2
// amendment made every read-back carry its effective spec.
func checkScaleChangesOnlyReplicas(tb TB, e *Env) {
	const inv = "ScaleService changes the desired instance count and nothing else in the spec"
	o, ref := scaleTarget(tb, e, inv, "scale-spec")
	if o.Spec == nil {
		skipBecause(tb, e, inv, "the container-service port exposes no effective spec to compare "+
			"before and after a scale, so a scale that rewrote the object could not be "+
			"distinguished from one that changed the count")
		return
	}

	before, err := o.Spec(ref)
	if err != nil {
		fail(tb, "container-service", inv, "reading the effective spec before the scale: %v",
			redact(err))
		return
	}
	const scaled = 1
	if err := o.Scale(ref, scaled); err != nil {
		fail(tb, "container-service", inv, "scaling to %d was refused: %v", scaled, redact(err))
		return
	}
	after, err := o.Spec(ref)
	if err != nil {
		fail(tb, "container-service", inv, "reading the effective spec after the scale: %v",
			redact(err))
		return
	}

	beforeSpec, okBefore := before.(compute.ServiceSpec)
	afterSpec, okAfter := after.(compute.ServiceSpec)
	if !okBefore || !okAfter {
		// Not a violation of this invariant, and not something to pass over
		// either: the comparison this check is cannot be made.
		skipBecause(tb, e, inv, fmt.Sprintf("the container-service read-back returned %T before "+
			"and %T after rather than a compute.ServiceSpec, so the effective spec cannot be "+
			"compared field by field", before, after))
		return
	}

	// Normalise the one field a scale is allowed to move, then require equality.
	// Anything else that differs is the provider rewriting an object it was asked
	// only to resize.
	if afterSpec.Replicas != scaled {
		fail(tb, "container-service", inv, "after scaling to %d the effective spec reports %d "+
			"replicas, so the scale did not take effect", scaled, afterSpec.Replicas)
	}
	normalised := beforeSpec
	normalised.Replicas = afterSpec.Replicas
	if reflect.DeepEqual(normalised, afterSpec) {
		return
	}
	for _, field := range differingFields(normalised, afterSpec) {
		fail(tb, "container-service", inv, "ServiceSpec.%s differs before and after a scale. A "+
			"scale implemented as an Ensure of the spec its own scale path carries loses every "+
			"field that path does not carry, and it is silent: the caller asked only for a "+
			"different instance count", field)
	}
}

// differingFields names the top-level fields of two specs that are not equal, so
// a failure says which part of the object moved rather than that something did.
func differingFields(before, after compute.ServiceSpec) []string {
	t := reflect.TypeOf(before)
	bv, av := reflect.ValueOf(before), reflect.ValueOf(after)
	var out []string
	for i := range t.NumField() {
		if !reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
			out = append(out, t.Field(i).Name)
		}
	}
	if len(out) == 0 {
		// DeepEqual disagreed with a field-by-field walk, which can only mean an
		// unexported field or a comparison this walk cannot see. Say so rather
		// than reporting nothing.
		out = append(out, "<a difference this field-by-field walk cannot locate>")
	}
	return out
}
