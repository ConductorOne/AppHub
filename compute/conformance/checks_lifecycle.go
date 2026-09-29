// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// lifecycleChecks are the per-port behavioural invariants.
//
// Which ones apply is decided by [Port.Class] and nothing else. The asynchronous
// class gets prompt-return, PhaseGone-after-delete, and the three Wait
// invariants; the synchronous class gets their mirror images. An earlier draft of
// the design document said these applied to "every port", which would have
// produced a suite asserting a phase on a type that has none.
func lifecycleChecks(e *Env) []Check {
	var checks []Check
	for _, pt := range availablePorts(e) {
		pt := pt
		checks = append(checks,
			Check{
				Name:      "port/" + pt.Name + "/ensure-is-idempotent",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "Ensure twice with the same spec yields the same Ref and no error",
				Fn:        withPort(pt, checkIdempotent(pt)),
			},
			Check{
				Name:      "port/" + pt.Name + "/ensure-converges-rather-than-accumulating",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "a declarative element present in the first spec and absent from the second is gone",
				Fn:        withPort(pt, checkConverges(pt)),
			},
			Check{
				Name:      "port/" + pt.Name + "/read-back-does-not-alias-provider-state",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "mutating a returned read-back does not change what the provider reports next",
				Fn:        withPort(pt, checkReadBackDoesNotAlias(pt)),
			},
			Check{
				Name:      "port/" + pt.Name + "/delete-is-idempotent",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "deleting an absent resource returns nil, and deleting twice returns nil",
				Fn:        withPort(pt, checkDeleteIdempotent(pt)),
			},
			Check{
				Name:      "port/" + pt.Name + "/name-is-deterministic-across-instances",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "the same logical Name yields the same physical resource from a second provider instance",
				Fn:        checkDeterministic(pt),
			},
			Check{
				Name:      "port/" + pt.Name + "/refuses-a-resource-it-does-not-own",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "an Ensure that finds an unowned resource under the name it would claim returns ErrNotOwned",
				Fn:        withPort(pt, checkOwnership(pt)),
			},
		)

		if _, ok := pt.Methods[opEmpty]; ok {
			checks = append(checks, Check{
				Name:      "port/" + pt.Name + "/empty-is-idempotent-and-leaves-a-deletable-resource",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: emptyInvariant,
				Fn:        withPort(pt, checkEmpty(pt)),
			})
		}

		if pt.Class == Async {
			checks = append(checks,
				Check{
					Name:      "port/" + pt.Name + "/async/ensure-does-not-block",
					Port:      pt.Name,
					Class:     Async,
					Invariant: "Ensure returns promptly with a Status, possibly PhasePending, rather than waiting for readiness",
					Fn:        withPort(pt, checkEnsureDoesNotBlock(pt)),
				},
				Check{
					Name:      "port/" + pt.Name + "/async/describe-after-delete-is-gone",
					Port:      pt.Name,
					Class:     Async,
					Invariant: "Describe on a deleted or never-created resource reports PhaseGone, not an error",
					Fn:        withPort(pt, checkDescribeAfterDelete(pt)),
				},
				Check{
					Name:      "port/" + pt.Name + "/async/wait-honours-its-deadline",
					Port:      pt.Name,
					Class:     Async,
					Invariant: "Wait returns ErrTimeout within its deadline plus a small margin and never hangs",
					Fn:        withPort(pt, checkWaitDeadline(pt)),
				},
				Check{
					Name:      "port/" + pt.Name + "/async/wait-requires-a-deadline",
					Port:      pt.Name,
					Class:     Async,
					Invariant: "a Wait with neither a timeout nor a context deadline is ErrInvalidSpec",
					Fn:        withPort(pt, checkWaitRequiresDeadline(pt)),
				},
				Check{
					Name:      "port/" + pt.Name + "/async/wait-reports-progress",
					Port:      pt.Name,
					Class:     Async,
					Invariant: "OnUpdate fires at least once and never after the call returns",
					Fn:        withPort(pt, checkWaitProgress(pt)),
				},
			)
		} else {
			checks = append(checks,
				Check{
					Name:      "port/" + pt.Name + "/sync/ensure-returns-something-usable",
					Port:      pt.Name,
					Class:     Sync,
					Invariant: "Ensure returns a usable resource or an error, with no third state",
					Fn:        withPort(pt, checkEnsureUsable(pt)),
				},
				Check{
					Name:      "port/" + pt.Name + "/sync/read-back-after-delete-is-not-found",
					Port:      pt.Name,
					Class:     Sync,
					Invariant: "a read-back after a delete is ErrNotFound",
					Fn:        withPort(pt, checkReadBackAfterDelete(pt)),
				},
			)
		}
	}
	checks = append(checks, Check{
		Name:      "port/relational-database/an-immutable-field-is-not-silently-substituted",
		Port:      "relational-database",
		Class:     Async,
		Invariant: "a re-Ensure whose spec changes a field the provider cannot change either fails or reports the new value; it never reports success carrying the old one",
		Fn:        checkRelationalImmutablesNotSubstituted,
	})
	return append(checks, secretScopeChecks()...)
}

// checkRelationalImmutablesNotSubstituted is the no-silent-substitution
// invariant, driven at the port that has the most to substitute.
//
// [compute.RelationalProvisioner] states the rule for one field in as many
// words -- "a provider must reject a spec whose version it cannot supply rather
// than substitute a different one" -- and the rule is not really about versions.
// A relational endpoint's database name and admin username are fixed at
// creation on every managed-SQL substrate the interface targets, and the arm of
// an Ensure that converges the mutable fields is exactly where a provider
// forgets that the immutable ones were asked to change.
//
// What makes it checkable without the suite knowing which fields a given
// substrate can change: there are two acceptable answers and they are both
// observable. Either the call fails, or it succeeds and the effective spec
// reports what was asked for. A provider that CAN rename a database converges
// and passes; one that cannot must say so. The single forbidden outcome is
// success carrying the old value, which tells the caller its spec was applied
// when it was not.
//
// The admin username half is the one with teeth. It is half of the credential
// the caller stored before provisioning -- the ordering
// [compute.RelationalSpec.AdminPassword] insists on -- so a caller that changes
// it and is told the deploy succeeded now holds a credential for an account
// that does not exist, and learns at a connection attempt far from the change
// that caused it.
//
// The engine version is not driven here, and the omission is deliberate rather
// than an oversight: the suite is given one version in
// [Options.EngineVersion], and asking for any other would be asking for one the
// provider may legitimately not offer -- so the refusal it got back would prove
// nothing about substitution. The fields below need no such second value.
func checkRelationalImmutablesNotSubstituted(tb TB, e *Env) {
	const inv = "a re-Ensure whose spec changes a field the provider cannot change either fails or reports the new value; it never reports success carrying the old one"
	if !e.Provider.Capabilities().Has(compute.CapRelationalDatabase) {
		skip(tb, e, inv, "the "+string(compute.CapRelationalDatabase)+" capability")
		return
	}
	rp, err := e.Provider.Relational()
	if err != nil {
		fatal(tb, "relational-database", inv, "Relational() refused: %v", err)
	}
	name := e.Name("immutable")
	base := e.RelationalSpec(name, Base, e.AdminPassword())
	if _, err := rp.EnsureRelational(e.ctx, base); err != nil {
		fatal(tb, "relational-database", inv, "the first EnsureRelational failed: %v", redact(err))
	}

	for _, tc := range []struct {
		field  string
		change func(*compute.RelationalSpec)
		want   func(compute.RelationalSpec) string
		asked  string
		why    string
	}{
		{
			field:  "DatabaseName",
			change: func(s *compute.RelationalSpec) { s.DatabaseName += "2" },
			want:   func(s compute.RelationalSpec) string { return s.DatabaseName },
			asked:  base.DatabaseName + "2",
			why:    "every connection string above this interface names it",
		},
		{
			field:  "AdminUsername",
			change: func(s *compute.RelationalSpec) { s.AdminUsername += "2" },
			want:   func(s compute.RelationalSpec) string { return s.AdminUsername },
			asked:  base.AdminUsername + "2",
			why: "it is half of the credential the caller stored before provisioning, so a " +
				"green deploy that did not change it leaves that copy naming an account which " +
				"does not exist",
		},
	} {
		changed := e.RelationalSpec(name, Base, e.AdminPassword())
		tc.change(&changed)
		st, err := rp.EnsureRelational(e.ctx, changed)
		if err != nil {
			// A refusal is the expected answer for a substrate that cannot make
			// the change. It has to be typed as a spec problem, because the spec
			// is what the caller has to change -- ErrFailed would send them to
			// the substrate.
			if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrUnsupported) {
				fail(tb, "relational-database", inv, "re-Ensuring with a changed %s was refused "+
					"with %v, which is neither compute.ErrInvalidSpec nor compute.ErrUnsupported; "+
					"the spec is what has to change, and an error that does not say so sends the "+
					"operator to the substrate", tc.field, redact(err))
			}
			continue
		}
		if st == nil {
			fail(tb, "relational-database", inv, "re-Ensuring with a changed %s returned no "+
				"status and no error", tc.field)
			continue
		}
		if got := tc.want(st.Spec); got != tc.asked {
			fail(tb, "relational-database", inv, "re-Ensuring with %s=%q reported success and an "+
				"effective spec of %q -- the live value, not the one asked for. A provider that "+
				"cannot change this field has to refuse; substituting reports a spec as applied "+
				"when it was not, and %s", tc.field, tc.asked, got, tc.why)
		}
	}
}

// secretScopeChecks are the invariants on [compute.SecretStore.DeleteScope].
//
// They sit outside the per-port loop because the loop drives one resource under
// one logical name and this method is about the set. [portOps] has no shape for
// it, and no other port has an equivalent.
//
// Before these, the suite never called DeleteScope at all — a method on the
// interface with no coverage. That is not a small gap on this particular method:
// it is the call that stops a torn-down application's credentials from
// outliving it, and the interface documents it as existing precisely because the
// caller does not reliably know the set (the source system tracked it in a
// SecretNames slice on the application row that any failed deploy could leave
// incomplete, container.go:1152).
func secretScopeChecks() []Check {
	return []Check{
		{
			Name:      "port/secret/delete-scope-removes-the-scope-and-nothing-else",
			Port:      "secret",
			Class:     Sync,
			Invariant: "DeleteScope removes every secret in the scope, leaves other scopes alone, and is re-runnable",
			Fn:        checkDeleteScope,
		},
		{
			Name:      "port/secret/delete-scope-refuses-an-empty-scope",
			Port:      "secret",
			Class:     Sync,
			Invariant: "DeleteScope with an empty scope is ErrInvalidSpec, not a deletion of everything",
			Fn:        checkDeleteScopeRefusesEmpty,
		},
	}
}

// secretScopeFixture stores n secrets in a fresh scope and returns the scope and
// the references.
func secretScopeFixture(tb TB, e *Env, store compute.SecretStore, inv, stem string, n int) (string, []compute.Ref) {
	tb.Helper()
	scope := e.Name(stem)
	refs := make([]compute.Ref, 0, n)
	for i := range n {
		stored, err := store.Put(e.ctx, compute.SecretSpec{
			Name:   e.Name("scoped"),
			Scope:  scope,
			Value:  compute.NewSecretValue(secretSentinel),
			Labels: map[string]string{"owner": "conformance"},
		})
		if err != nil {
			fatal(tb, "secret", inv, "storing fixture %d in scope %q failed: %v", i, scope, redact(err))
		}
		refs = append(refs, stored.Ref)
	}
	return scope, refs
}

func checkDeleteScope(tb TB, e *Env) {
	const inv = "DeleteScope removes every secret in the scope, leaves other scopes alone, and is re-runnable"
	if !e.Provider.Capabilities().Has(compute.CapSecretStore) {
		skip(tb, e, inv, "the "+string(compute.CapSecretStore)+" capability")
		return
	}
	store, err := e.Provider.Secrets()
	if err != nil {
		fatal(tb, "secret", inv, "Secrets() refused: %v", err)
	}
	// Two secrets in the scope being torn down, so that a provider deleting only
	// the first is caught, and one in a neighbouring scope, so that a provider
	// deleting by prefix rather than by scope is caught too.
	doomed, doomedRefs := secretScopeFixture(tb, e, store, inv, "scope", 2)
	_, keptRefs := secretScopeFixture(tb, e, store, inv, "scope", 1)

	if err := store.DeleteScope(e.ctx, doomed); err != nil {
		fatal(tb, "secret", inv, "DeleteScope(%q) failed: %v", doomed, redact(err))
	}
	for i, ref := range doomedRefs {
		if _, err := store.Get(e.ctx, ref); err == nil {
			fail(tb, "secret", inv, "secret %d of %d in the deleted scope is still readable; a "+
				"torn-down application's credentials outliving it is the failure this method exists "+
				"to prevent", i+1, len(doomedRefs))
		} else if !errors.Is(err, compute.ErrNotFound) {
			fail(tb, "secret", inv, "reading a secret from the deleted scope returned %v, which "+
				"does not match compute.ErrNotFound", redact(err))
		}
	}
	for _, ref := range keptRefs {
		if _, err := store.Get(e.ctx, ref); err != nil {
			fail(tb, "secret", inv, "a secret in a different scope was deleted too (%v); scopes are "+
				"how one application's teardown is kept from reaching another's material", redact(err))
		}
	}
	// Teardown runs again after a failure and finds some of its work done.
	if err := store.DeleteScope(e.ctx, doomed); err != nil {
		fail(tb, "secret", inv, "the second DeleteScope returned %v; a failed deploy leaves a "+
			"partial set of resources and the retry deletes the ones that are already gone",
			redact(err))
	}
}

func checkDeleteScopeRefusesEmpty(tb TB, e *Env) {
	const inv = "DeleteScope with an empty scope is ErrInvalidSpec, not a deletion of everything"
	if !e.Provider.Capabilities().Has(compute.CapSecretStore) {
		skip(tb, e, inv, "the "+string(compute.CapSecretStore)+" capability")
		return
	}
	store, err := e.Provider.Secrets()
	if err != nil {
		fatal(tb, "secret", inv, "Secrets() refused: %v", err)
	}
	_, refs := secretScopeFixture(tb, e, store, inv, "scope", 1)

	err = store.DeleteScope(e.ctx, "")
	if err == nil {
		fail(tb, "secret", inv, "DeleteScope(\"\") was accepted. An empty scope is not a scope, and "+
			"a provider that treats it as one deletes every secret it holds")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "secret", inv, "DeleteScope(\"\") was refused with %v, which does not match "+
			"compute.ErrInvalidSpec; an empty scope is a caller bug, not an infrastructure failure",
			redact(err))
	}
	for _, ref := range refs {
		if _, err := store.Get(e.ctx, ref); err != nil {
			fail(tb, "secret", inv, "a secret in a named scope was deleted by DeleteScope(\"\") (%v)",
				redact(err))
		}
	}
}

func checkIdempotent(pt Port) func(TB, *Env, *portOps) {
	const inv = "Ensure twice with the same spec yields the same Ref and no error"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		first, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "the first Ensure failed: %v", err)
		}
		second, _, err := o.Ensure(name, Base)
		if err != nil {
			// "Already exists" must be a success, not an error: the whole call
			// style above this interface is ensure-then-use.
			fatal(tb, pt.Name, inv, "the second Ensure with an identical spec failed with %v; "+
				"repeat calls must converge, and 'already exists' is a success", err)
		}
		if second != first {
			fail(tb, pt.Name, inv, "the two calls returned different references (%s then %s); a "+
				"teardown that reconstructs the reference from the logical name would address the "+
				"wrong resource, or nothing", first, second)
		}
		// Asserted on the Ref rather than on a "created" flag, deliberately: the
		// interface has no such flag and a provider must not need one.
		if o.Describe != nil {
			if _, err := o.Describe(first); err != nil {
				fail(tb, pt.Name, inv, "Describe on the ensured resource failed: %v", err)
			}
		}
	}
}

// checkReadBackDoesNotAlias is the invariant a reviewer found the reference
// provider breaking.
//
// Mutating a map on a returned read-back changed what the next Describe
// reported, with no Ensure in between: the provider handed out the map it
// stored. A caller holding a spec and adjusting a label would have silently
// rewritten what the provider believed it had deployed.
//
// It is checked here rather than only in the fake because it is a property of
// every provider, and because the fake is what the AWS implementations will be
// written against — a reference that aliases teaches six providers that
// aliasing is acceptable, and the test that should catch it runs against the
// reference that does it too.
func checkReadBackDoesNotAlias(pt Port) func(TB, *Env, *portOps) {
	const inv = "mutating a returned read-back does not change what the provider reports next"
	return func(tb TB, e *Env, o *portOps) {
		if o.Spec == nil {
			skip(tb, e, inv, "a read-back carrying the effective spec")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}

		before := effectiveSpec(tb, pt, inv, o, ref)

		// Reach into whatever the read-back handed back and change every map
		// and slice in it. A provider that shares storage will show this on the
		// next read.
		spec, err := o.Spec(ref)
		if err != nil {
			fatal(tb, pt.Name, inv, "reading the effective spec back failed: %v", err)
		}
		mutateEverythingMutable(reflect.ValueOf(spec))

		if after := effectiveSpec(tb, pt, inv, o, ref); after != before {
			fail(tb, pt.Name, inv, "mutating the returned spec changed what the provider reports, "+
				"with no Ensure in between: the read-back shares storage with the provider's own "+
				"state. A caller that keeps a spec and edits a label would be rewriting what the "+
				"provider believes it deployed.\n  before: %s\n   after: %s", before, after)
		}
	}
}

// mutateEverythingMutable writes a marker into every map, slice element and
// settable string reachable from v. It is deliberately indiscriminate: the check
// is about storage being shared at all, not about one field.
//
// Note that it does not require settability to do useful damage. A map or a
// slice reached through a non-addressable struct still refers to the same
// backing storage, which is exactly the aliasing being hunted — a provider that
// returns a struct by value but shares the maps inside it has shared its state.
const aliasMarker = "conformance-mutated-outside-provider"

func mutateEverythingMutable(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Interface:
		mutateEverythingMutable(v.Elem())
	case reflect.Map:
		if v.IsNil() || v.Type().Key().Kind() != reflect.String {
			return
		}
		iter := v.MapRange()
		for iter.Next() {
			if v.Type().Elem().Kind() == reflect.String {
				v.SetMapIndex(iter.Key(), reflect.ValueOf(aliasMarker).Convert(v.Type().Elem()))
				continue
			}
			mutateEverythingMutable(iter.Value())
		}
	case reflect.Slice:
		for i := range v.Len() {
			mutateEverythingMutable(v.Index(i))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			mutateEverythingMutable(v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			mutateEverythingMutable(v.Field(i))
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(aliasMarker)
		}
	default:
	}
}

func checkConverges(pt Port) func(TB, *Env, *portOps) {
	const inv = "a declarative element present in the first spec and absent from the second is gone"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "the base Ensure failed: %v", err)
		}

		var before map[string]string
		if o.Observed != nil {
			if before, err = o.Observed(ref); err != nil {
				fatal(tb, pt.Name, inv, "observing the base state failed: %v", err)
			}
		}
		renderedBefore := renderedFor(e.rendered(tb), name)
		specBefore := ""
		if o.Spec != nil {
			specBefore = effectiveSpec(tb, pt, inv, o, ref)
		}

		changed, _, err := o.Ensure(name, Changed)
		if err != nil {
			fatal(tb, pt.Name, inv, "re-Ensuring with a modified spec failed with %v; a redeploy "+
				"that changes configuration is the ordinary case", err)
		}
		if changed != ref {
			fail(tb, pt.Name, inv, "changing the spec changed the reference (%s -> %s); the "+
				"resource is meant to converge, not to be replaced", ref, changed)
		}

		// What the interface exposes.
		switch {
		case o.Observed == nil || len(o.ChangedKeys) == 0:
			if o.Spec == nil {
				e.note("port %s: nothing the interface exposes reflects a declarative change at "+
					"all, not even a provider-reported effective spec", pt.Name)
			}
		default:
			after, err := o.Observed(ref)
			if err != nil {
				fatal(tb, pt.Name, inv, "observing the changed state failed: %v", err)
			}
			for _, key := range o.ChangedKeys {
				if before[key] == after[key] {
					fail(tb, pt.Name, inv, "%q is %q both before and after the spec changed; the "+
						"provider appears not to have reconciled to the second spec (this is the "+
						"property that replaces the source system's detach and reconcile helpers, "+
						"and the one an implementation is most likely to get wrong by implementing "+
						"Ensure as create-or-add)", key, after[key])
				}
			}
		}

		// What the provider says about itself. This is the weaker half and it is
		// labelled as such: Spec is the provider's report of its own effective
		// desired state, not an observation of the substrate, so a provider that
		// reports the new spec while leaving the old object in place passes it.
		// A reviewer built exactly that. It still catches the common failure —
		// Ensure implemented as create-or-add, which accumulates and then
		// reports the accumulation — so it is worth running, but it cannot
		// stand in for looking at the substrate.
		if o.Spec != nil && o.RemovedFromSpec != "" {
			specAfter := effectiveSpec(tb, pt, inv, o, ref)
			switch {
			case !strings.Contains(specBefore, o.RemovedFromSpec):
				fail(tb, pt.Name, inv, "the effective spec after the base Ensure does not contain "+
					"%q, so the provider is not reporting the state it was given; a Spec that does "+
					"not echo the caller's spec can verify nothing", o.RemovedFromSpec)
			case strings.Contains(specAfter, o.RemovedFromSpec):
				fail(tb, pt.Name, inv, "%q is still in the effective spec after an Ensure that "+
					"omits it; the provider added rather than converged, and then reported the "+
					"accumulated state as though it were desired", o.RemovedFromSpec)
			}
		}

		// The substrate observation, which is the invariant. Without it this
		// check does not pass — it is recorded as unverified.
		//
		// The alternative is what this check used to do: fall back to the
		// provider's own report and go green. That accepts a provider whose
		// read-back lies about state it never wrote, which is precisely what
		// "an element removed from a spec is gone" is supposed to rule out.
		// Nothing a provider reports about itself can establish it, so a
		// provider that supplies no observer has not demonstrated convergence
		// and the report must say so rather than imply otherwise.
		if e.Options.Rendered == nil {
			skip(tb, e, inv, "Options.Rendered, an observation of what the provider actually "+
				"wrote to its substrate. The effective-spec read-back above is the provider "+
				"reporting on itself, and a provider that reports the new spec while leaving the "+
				"old object in place satisfies it — so convergence is not verified for "+
				"port "+pt.Name+" without a substrate observer")
			return
		}
		if o.RemovedFromRendered == "" {
			return
		}
		renderedAfter := renderedFor(e.rendered(tb), name)
		if !containsAny(renderedBefore, o.RemovedFromRendered) {
			// Not a provider failure: the marker may simply not be part of what
			// this provider renders. Said out loud so the check's weakening is
			// visible.
			e.note("port %s: the rendered artefacts never contained %q, so the removal half of the "+
				"convergence invariant was not exercised for this provider",
				pt.Name, o.RemovedFromRendered)
			return
		}
		if containsAny(renderedAfter, o.RemovedFromRendered) {
			fail(tb, pt.Name, inv, "%q is still present in the provider's rendered state after a "+
				"spec that omits it; Ensure added rather than converged", o.RemovedFromRendered)
		}
	}
}

func checkEnsureDoesNotBlock(pt Port) func(TB, *Env, *portOps) {
	const inv = "Ensure returns promptly with a Status, possibly PhasePending, rather than waiting for readiness"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		start := time.Now()
		ref, st, err := o.Ensure(name, Base)
		elapsed := time.Since(start)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if elapsed > e.Options.EnsureBudget {
			fail(tb, pt.Name, inv, "Ensure took %s, which is over the %s budget; provisioning that "+
				"blocks inline means a caller cannot choose its own timeout and cannot provision two "+
				"resources concurrently instead of adding their worst cases together",
				elapsed.Round(time.Millisecond), e.Options.EnsureBudget)
		}
		if st == nil {
			fatal(tb, pt.Name, inv, "Ensure returned a nil Status; an asynchronous port's Ensure "+
				"must report where the resource is")
			return
		}
		switch st.Phase {
		case compute.PhasePending, compute.PhaseReady:
		case compute.PhaseFailed:
			fail(tb, pt.Name, inv, "Ensure returned PhaseFailed with message %q rather than an "+
				"error; a spec that cannot be satisfied is an error, and a phase is for a resource "+
				"that is converging", st.Message)
		default:
			fail(tb, pt.Name, inv, "Ensure returned phase %q; only pending and ready make sense "+
				"for a resource that was just accepted", st.Phase)
		}
		if st.Ref != ref {
			fail(tb, pt.Name, inv, "Status.Ref (%s) does not address the resource Ensure returned (%s)",
				st.Ref, ref)
		}
		if st.UpdatedAt.IsZero() {
			fail(tb, pt.Name, inv, "Status.UpdatedAt is zero, so an operator cannot tell how stale "+
				"the observation is")
		}
	}
}

func checkEnsureUsable(pt Port) func(TB, *Env, *portOps) {
	const inv = "Ensure returns a usable resource or an error, with no third state"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if o.Describe == nil {
			e.note("port %s: %s", pt.Name, o.NoReadBack)
			return
		}
		// Usable when the call returns means the read-back works immediately,
		// with no waiting and no retry loop.
		if _, err := o.Describe(ref); err != nil {
			fail(tb, pt.Name, inv, "the resource could not be read back immediately after Ensure "+
				"returned (%v); a synchronous port must not hand back a half-created resource and "+
				"leave the caller to find out", err)
		}
	}
}

func checkDescribeAfterDelete(pt Port) func(TB, *Env, *portOps) {
	const inv = "Describe on a deleted or never-created resource reports PhaseGone, not an error"
	return func(tb TB, e *Env, o *portOps) {
		if o.Describe == nil {
			skip(tb, e, inv, "a read-back for this port ("+o.NoReadBack+")")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := o.Delete(ref); err != nil {
			fatal(tb, pt.Name, inv, "Delete failed: %v", err)
		}
		st, err := o.Describe(ref)
		if err != nil {
			fail(tb, pt.Name, inv, "Describe after Delete returned %v; teardown and reconciliation "+
				"must be re-runnable without distinguishing 'deleted' from 'never existed'", err)
			return
		}
		if st == nil {
			fail(tb, pt.Name, inv, "Describe after Delete returned a nil Status and no error")
			return
		}
		if st.Phase != compute.PhaseGone && st.Phase != compute.PhaseDeleting {
			fail(tb, pt.Name, inv, "Describe after Delete reported phase %q, want %q (or %q while "+
				"teardown is in progress)", st.Phase, compute.PhaseGone, compute.PhaseDeleting)
		}
	}
}

func checkReadBackAfterDelete(pt Port) func(TB, *Env, *portOps) {
	const inv = "a read-back after a delete is ErrNotFound"
	return func(tb TB, e *Env, o *portOps) {
		if o.Describe == nil {
			skip(tb, e, inv, "a read-back for this port ("+o.NoReadBack+")")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := o.Delete(ref); err != nil {
			fatal(tb, pt.Name, inv, "Delete failed: %v", err)
		}
		_, err = o.Describe(ref)
		if err == nil {
			fail(tb, pt.Name, inv, "the resource was still readable after Delete; a synchronous "+
				"port has no PhaseGone to report, so the deletion has to be visible as ErrNotFound")
			return
		}
		if !errors.Is(err, compute.ErrNotFound) {
			fail(tb, pt.Name, inv, "the read-back after Delete returned %v, which does not match "+
				"compute.ErrNotFound; a caller cannot tell a deleted resource from a broken provider", err)
		}
	}
}

func checkDeleteIdempotent(pt Port) func(TB, *Env, *portOps) {
	const inv = "deleting an absent resource returns nil, and deleting twice returns nil"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := o.Delete(ref); err != nil {
			fatal(tb, pt.Name, inv, "the first Delete failed: %v", err)
		}
		if err := o.Delete(ref); err != nil {
			fail(tb, pt.Name, inv, "the second Delete returned %v; teardown has to be re-runnable, "+
				"because a failed deploy leaves a partial set of resources and the retry deletes "+
				"the ones that are already gone", err)
		}
	}
}

const emptyInvariant = "emptying an absent resource returns nil, emptying twice returns nil, " +
	"an emptied resource is still there, and a Delete after it succeeds"

// checkEmpty drives the destructive empty call through the states teardown meets.
//
// A resource that was never emptied, one emptied already, and one deleted
// already, because a teardown that failed partway is retried from the top and
// meets all three. The read-back between Empty and Delete is the half that is
// easy to get wrong in the other direction: an Empty that deleted the resource
// would satisfy "Delete afterwards succeeds" trivially, because Delete is
// idempotent, and it would destroy every grant on the resource with it.
func checkEmpty(pt Port) func(TB, *Env, *portOps) {
	return func(tb TB, e *Env, o *portOps) {
		ref, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, emptyInvariant, "Ensure failed: %v", err)
		}
		if err := o.Empty(ref); err != nil {
			fatal(tb, pt.Name, emptyInvariant, "the first Empty failed: %v", err)
		}
		if err := o.Empty(ref); err != nil {
			fail(tb, pt.Name, emptyInvariant, "the second Empty returned %v; teardown has to be "+
				"re-runnable, and a retry empties a resource that is already empty", err)
		}
		if o.Describe != nil {
			if _, err := o.Describe(ref); err != nil {
				fail(tb, pt.Name, emptyInvariant, "the read-back after Empty returned %v; emptying "+
					"removes the data and must leave the resource, and its grants, in place", err)
			}
		}
		if err := o.Delete(ref); err != nil {
			fail(tb, pt.Name, emptyInvariant, "Delete after Empty returned %v; the point of "+
				"emptying is that the delete which follows it can succeed", err)
		}
		if err := o.Empty(ref); err != nil {
			fail(tb, pt.Name, emptyInvariant, "Empty on a deleted resource returned %v; a "+
				"teardown retried after its delete succeeded meets an absent resource, and "+
				"absent is empty", err)
		}
	}
}

func checkDeterministic(pt Port) func(TB, *Env) {
	const inv = "the same logical Name yields the same physical resource from a second provider instance"
	return func(tb TB, e *Env) {
		tb.Helper()
		first, err := pt.ops(tb, e, e.Provider)
		if err != nil {
			fatal(tb, pt.Name, inv, "acquiring the port failed: %v", err)
		}
		name := e.Name(pt.Name)
		refA, _, err := first.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure on the first instance failed: %v", err)
		}

		other := e.Factory(tb)
		second, err := pt.ops(tb, e, other)
		if err != nil {
			fatal(tb, pt.Name, inv, "acquiring the port from a second instance failed: %v", err)
		}
		refB, _, err := second.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure on the second instance failed with %v; the factory must "+
				"return providers over the same substrate", err)
		}
		if refB != refA {
			fail(tb, pt.Name, inv, "the same name produced %s on one instance and %s on another; "+
				"teardown depends on reconstructing a reference for a resource whose provisioned "+
				"identifier may never have been persisted", refA, refB)
		}
	}
}

func checkOwnership(pt Port) func(TB, *Env, *portOps) {
	const inv = "an Ensure that finds an unowned resource under the name it would claim returns ErrNotOwned"
	return func(tb TB, e *Env, o *portOps) {
		if e.Options.CreateUnowned == nil {
			skip(tb, e, inv, "Options.CreateUnowned, which has to create a resource without the "+
				"provider's ownership marker and is therefore substrate-specific")
			return
		}
		name := e.Name(pt.Name)
		// The reference is derived from the name deterministically, so creating
		// the resource, deleting it, and putting an unowned one back reproduces
		// the collision a mutable application name can cause.
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := o.Delete(ref); err != nil {
			fatal(tb, pt.Name, inv, "Delete failed: %v", err)
		}
		if err := e.Options.CreateUnowned(e.ctx, e.Provider, ref); err != nil {
			fatal(tb, pt.Name, inv, "the CreateUnowned hook failed for %s: %v", ref, err)
		}
		_, _, err = o.Ensure(name, Base)
		if err == nil {
			fail(tb, pt.Name, inv, "Ensure adopted a resource this platform does not own; resource "+
				"names derive from mutable application names, so reconciling one means mutating "+
				"somebody else's infrastructure")
			return
		}
		if !errors.Is(err, compute.ErrNotOwned) {
			fail(tb, pt.Name, inv, "Ensure refused an unowned resource with %v, which does not "+
				"match compute.ErrNotOwned; a caller cannot tell 'somebody else owns this name' "+
				"from an ordinary failure", err)
		}
	}
}

func checkWaitDeadline(pt Port) func(TB, *Env, *portOps) {
	const inv = "Wait returns ErrTimeout within its deadline plus a small margin and never hangs"
	return func(tb TB, e *Env, o *portOps) {
		if o.Wait == nil {
			e.note("port %s is asynchronous but the interface gives it no Wait method, so a caller "+
				"has no supported way to block until it converges", pt.Name)
			skip(tb, e, inv, "a Wait method on this port")
			return
		}
		if e.Options.Stall == nil {
			skip(tb, e, inv, "Options.Stall, which has to make a resource stop converging and is "+
				"therefore substrate-specific")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := e.Options.Stall(e.ctx, e.Provider, ref); err != nil {
			fatal(tb, pt.Name, inv, "the Stall hook failed for %s: %v", ref, err)
		}

		timeout := e.Options.WaitTimeout
		start := time.Now()
		_, err = o.Wait(ref, compute.WaitOptions{Timeout: timeout})
		elapsed := time.Since(start)

		if err == nil {
			fail(tb, pt.Name, inv, "Wait reported success for a resource that is not converging")
			return
		}
		if errors.Is(err, compute.ErrFailed) {
			fail(tb, pt.Name, inv, "Wait returned ErrFailed (%v) for a resource that has not "+
				"failed; distinguishing a timeout from a terminal failure is what lets a caller "+
				"decide whether to wait again", err)
		} else if !errors.Is(err, compute.ErrTimeout) {
			fail(tb, pt.Name, inv, "Wait returned %v, which does not match compute.ErrTimeout", err)
		}
		if elapsed > timeout+e.Options.WaitMargin {
			fail(tb, pt.Name, inv, "Wait returned after %s with a %s timeout, which is more than "+
				"the %s margin allows; a provider that overruns its deadline takes the choice of "+
				"how long to wait away from the caller",
				elapsed.Round(time.Millisecond), timeout, e.Options.WaitMargin)
		}
	}
}

func checkWaitRequiresDeadline(pt Port) func(TB, *Env, *portOps) {
	const inv = "a Wait with neither a timeout nor a context deadline is ErrInvalidSpec"
	return func(tb TB, e *Env, o *portOps) {
		if o.Wait == nil {
			skip(tb, e, inv, "a Wait method on this port")
			return
		}
		if e.Options.Stall == nil {
			// Without a stall hook the resource may converge before the check can
			// observe the refusal, so the assertion would be racy rather than
			// wrong. Say so instead of asserting something flaky.
			skip(tb, e, inv, "Options.Stall, without which a converging resource could satisfy the "+
				"Wait before the missing-deadline refusal could be observed")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := e.Options.Stall(e.ctx, e.Provider, ref); err != nil {
			fatal(tb, pt.Name, inv, "the Stall hook failed for %s: %v", ref, err)
		}

		done := make(chan error, 1)
		go func() {
			_, err := o.Wait(ref, compute.WaitOptions{})
			done <- err
		}()
		// The suite's own context has no deadline, so a provider that waits
		// forever would hang the test rather than fail it. Bounding the check
		// here turns that into a reportable failure.
		select {
		case err := <-done:
			if err == nil {
				fail(tb, pt.Name, inv, "Wait with no deadline reported success for a resource that "+
					"is not converging")
				return
			}
			if !errors.Is(err, compute.ErrInvalidSpec) {
				fail(tb, pt.Name, inv, "Wait with neither WaitOptions.Timeout nor a context "+
					"deadline returned %v; it must be refused as ErrInvalidSpec, because no path "+
					"may wait forever", err)
			}
		case <-time.After(e.Options.WaitTimeout + e.Options.WaitMargin):
			fail(tb, pt.Name, inv, "Wait with neither WaitOptions.Timeout nor a context deadline "+
				"was still blocked after %s; it must refuse instead of waiting",
				e.Options.WaitTimeout+e.Options.WaitMargin)
		}
	}
}

func checkWaitProgress(pt Port) func(TB, *Env, *portOps) {
	const inv = "OnUpdate fires at least once and never after the call returns"
	return func(tb TB, e *Env, o *portOps) {
		if o.Wait == nil {
			skip(tb, e, inv, "a Wait method on this port")
			return
		}
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}

		var (
			updates  []compute.Status
			returned bool
			after    int
		)
		opts := compute.WaitOptions{
			Timeout: 5 * time.Second,
			OnUpdate: func(st compute.Status) {
				if returned {
					after++
					return
				}
				updates = append(updates, st)
			},
		}
		_, err = o.Wait(ref, opts)
		returned = true
		if err != nil {
			fatal(tb, pt.Name, inv, "Wait failed for a resource that should converge: %v", err)
		}
		// A short settle: a provider that reports progress from a goroutine it
		// does not join would fire here.
		time.Sleep(20 * time.Millisecond)

		if len(updates) == 0 {
			fail(tb, pt.Name, inv, "OnUpdate never fired; it exists so a deploy can report progress "+
				"from observed state instead of interpolating a percentage from a loop counter")
		}
		if after > 0 {
			fail(tb, pt.Name, inv, "OnUpdate fired %d time(s) after Wait returned; it is documented "+
				"as called synchronously from the waiting goroutine, and a caller may have torn "+
				"down whatever the callback touches", after)
		}
		for _, st := range updates {
			if st.Ref != ref {
				fail(tb, pt.Name, inv, "an OnUpdate reported Ref %s while waiting on %s", st.Ref, ref)
				break
			}
		}
	}
}

// rendered reads the provider's rendered artefacts, or nil when no hook is set.
func (e *Env) rendered(tb TB) []string {
	tb.Helper()
	if e.Options.Rendered == nil {
		return nil
	}
	out, err := e.Options.Rendered(e.ctx, e.Provider)
	if err != nil {
		tb.Fatalf("conformance: the Options.Rendered hook failed: %v", err)
	}
	return out
}

func containsAny(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// renderedFor narrows a provider's rendered artefacts to the ones describing the
// named resource.
//
// Without this the convergence check would search every artefact in the
// substrate, and a sibling resource created by another check with the base spec
// would keep the removed marker alive forever. The suite's logical names are
// unique per run and a rendered artefact names its resource, so matching the name
// followed by a separator is enough; matching the bare name would let "cf-x-1"
// find "cf-x-12".
func renderedFor(all []string, name string) []string {
	var out []string
	for _, artefact := range all {
		if strings.Contains(artefact, name+":") || strings.Contains(artefact, name+".") {
			out = append(out, artefact)
		}
	}
	return out
}

// effectiveSpec marshals a port's effective spec for the removal check.
//
// Marshalling rather than comparing field by field keeps one check uniform over
// nine spec types that share no structure, and matches how the rendered-artefact
// half already works.
func effectiveSpec(tb TB, pt Port, inv string, o *portOps, ref compute.Ref) string {
	spec, err := o.Spec(ref)
	if err != nil {
		fatal(tb, pt.Name, inv, "reading the effective spec back failed: %v", err)
		return ""
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		fatal(tb, pt.Name, inv, "the effective spec does not marshal: %v", err)
		return ""
	}
	return string(encoded)
}
