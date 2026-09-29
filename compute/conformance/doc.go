// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package conformance is the executable form of the Compute provider contract.
//
// Every provider runs the same suite against itself: compute/fake runs it in CI,
// hermetically, and a substrate-backed provider runs it out of band. The point
// is that "implements compute.Provider" is a statement about method sets and
// says nothing about behaviour, while almost everything the contract requires is
// behavioural — an Ensure converges rather than accumulating, a Describe after a
// delete is not an error, a refusal is typed, a secret does not reach a log.
//
// # Scope is per port class, not universal
//
// The interface has two classes of port and they have different obligations.
// Asynchronous ports (container services, scheduled jobs, functions, function
// endpoints, relational endpoints, key-value tables) carry a [compute.Status]:
// their Ensure returns promptly and possibly [compute.PhasePending], their
// Describe reports [compute.PhaseGone] after a delete, and they have a Wait with
// a caller-chosen deadline. Synchronous ports (image repositories, buckets,
// secrets, workload identities) have none of that: their Ensure returns a usable
// resource or an error, and a read-back after a delete is
// [compute.ErrNotFound].
//
// A suite that applied phase and Wait rules to every port would be asserting an
// invariant on types that have no phase — a broken test rather than a caught
// bug. So [Port.Class] carries the distinction and each check declares which
// class it applies to. The same is true of grants: [compute.Granter] is on the
// ports whose substrate authorises by workload identity, and driving grant
// invariants against [compute.RelationalProvisioner] would be a suite bug, not a
// provider bug.
//
// # Using it
//
//	func TestConformance(t *testing.T) {
//	    store := fake.NewStore()
//	    conformance.Run(t, func(conformance.TB) compute.Provider {
//	        return fake.New(store, fake.Config{})
//	    }, conformance.Options{
//	        Placement: "default",
//	        // ... the substrate facts and hooks the suite cannot invent
//	    })
//	}
//
// compute/fake runs it in CI. A substrate-backed provider runs the same call
// behind a build tag (`//go:build substrate`, say) so that `go test ./...` stays
// credential-free for everybody else, and supplies the same [Options] pointed at
// its own substrate.
//
// The factory is called more than once, and every call must return a provider
// addressing the *same* substrate: one invariant is that a second provider
// instance finds what the first one created, because teardown has to reconstruct
// a reference from a logical name that may never have been persisted.
//
// # Hooks, and what happens without them
//
// Several invariants are behavioural in a way the interface cannot express:
// whether a grant actually permits a read, whether an anonymous request is
// refused, whether the original admin password still works, what the provider
// rendered into its substrate. Those arrive as hooks on [Options]. A hook left
// nil does not silently drop the invariant — the check skips with a message
// naming the invariant and the missing hook, and [Report] counts it, because a
// suite that quietly covered less than it claimed would be worse than one that
// covered nothing.
//
// Designed by USOSS-16 against docs/design/compute-provider.md §7.
package conformance
