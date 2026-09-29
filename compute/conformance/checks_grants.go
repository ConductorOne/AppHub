// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"

	"github.com/conductorone/apphub/compute"
)

// grantChecks are the [compute.Granter] invariants.
//
// They run only against the ports that implement Granter — image repositories,
// buckets, and key-value tables — because Granter is on a port only when the
// substrate's own access control is expressed in terms of the workload identity.
// Driving them at [compute.RelationalProvisioner] would be a suite bug, not a
// provider bug: relational access control is SQL roles and GRANT statements,
// above this interface.
func grantChecks(e *Env) []Check {
	checks := []Check{
		{
			Name:      "grants/relational-database/port-has-no-granter",
			Port:      "relational-database",
			Invariant: "the relational port does not implement Granter",
			Fn: func(tb TB, e *Env) {
				const inv = "the relational port does not implement Granter"
				if !e.Provider.Capabilities().Has(compute.CapRelationalDatabase) {
					skip(tb, e, inv, "the "+string(compute.CapRelationalDatabase)+" capability")
					return
				}
				rp, err := e.Provider.Relational()
				if err != nil {
					fatal(tb, "relational-database", inv, "Relational() refused: %v", err)
				}
				if _, ok := rp.(compute.Granter); ok {
					// A provider is free to expose extra methods, but implementing
					// Granter here invites a caller to use it, and there is no
					// general mapping from a substrate workload identity to a SQL
					// principal for it to mean anything.
					fail(tb, "relational-database", inv,
						"the relational port implements compute.Granter; access to a relational "+
							"database is granted with SQL above this interface, and an IAM role maps "+
							"to a Postgres role only with rds-iam enabled while a Kubernetes "+
							"ServiceAccount has no Postgres meaning at all")
				}
			},
		},
	}

	// CapWorkloadGrants decides which half of the grant contract applies.
	//
	// The capability exists because a Granter port's substrate may be able to
	// authorise a workload identity in principle and not in a given deployment —
	// an S3-compatible store federates the cluster's issuer or it does not. The
	// suite used to schedule the positive checks from HasGranter alone, so a
	// provider that correctly declined the capability and correctly refused
	// Grant still failed, and the suite was demanding behaviour the provider had
	// said it did not have. That is the same defect the capability was added to
	// prevent, in the checker rather than in a provider.
	grantsAdvertised := e.Provider.Capabilities().Has(compute.CapWorkloadGrants)

	for _, pt := range availablePorts(e) {
		pt := pt
		if !pt.HasGranter {
			continue
		}
		if !grantsAdvertised {
			checks = append(checks, Check{
				Name:      "grants/" + pt.Name + "/refused-without-the-capability",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "a provider without CapWorkloadGrants refuses Grant and DescribeGrant with ErrUnsupported naming that capability",
				Fn:        withPort(pt, checkGrantRefused(pt)),
			})
			continue
		}
		checks = append(checks,
			Check{
				Name:      "grants/" + pt.Name + "/access-level-decides-what-succeeds",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "after AccessRead a read succeeds and a write fails; after AccessReadWrite both succeed; after Revoke both fail",
				Fn:        withPort(pt, checkGrantBehaviour(pt)),
			},
			Check{
				Name:      "grants/" + pt.Name + "/grant-is-idempotent-and-last-write-wins",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "Grant is idempotent and narrowing the level replaces it rather than adding a second grant",
				Fn:        withPort(pt, checkGrantIdempotent(pt)),
			},
			Check{
				Name:      "grants/" + pt.Name + "/revoking-an-absent-grant-is-nil",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "revoking an absent grant returns nil",
				Fn:        withPort(pt, checkRevokeAbsent(pt)),
			},
			Check{
				Name:      "grants/" + pt.Name + "/a-grant-names-one-resource",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "a Grant or Revoke on one resource leaves the same identity's grants on every other resource alone",
				Fn:        withPort(pt, checkGrantScopedToPair(pt)),
			},
			Check{
				Name:      "grants/" + pt.Name + "/the-read-back-reports-what-stands",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "DescribeGrant reports no grant before one is made, the level that was granted after, a narrowed level as narrowed, and no grant after Revoke",
				Fn:        withPort(pt, checkGrantReadBack(pt)),
			},
			Check{
				Name:      "grants/" + pt.Name + "/the-read-back-is-keyed-on-the-pair",
				Port:      pt.Name,
				Class:     pt.Class,
				Invariant: "DescribeGrant answers for the pair it names: a Revoke on one resource leaves the read-back on another unchanged",
				Fn:        withPort(pt, checkGrantReadBackScopedToPair(pt)),
			},
		)
	}
	return checks
}

func checkGrantBehaviour(pt Port) func(TB, *Env, *portOps) {
	const inv = "after AccessRead a read succeeds and a write fails; after AccessReadWrite both succeed; after Revoke both fail"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not; "+
				"that is a suite bug, not a provider bug")
		}
		if e.Options.Read == nil || e.Options.Write == nil {
			skip(tb, e, inv, "Options.Read and Options.Write, which have to perform a data-plane "+
				"operation as a workload identity — the hardest part of the harness, and the only "+
				"way to check a grant without asserting on a policy document that only one "+
				"substrate could pass")
			return
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		ref, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}

		read := func() error { return e.Options.Read(e.ctx, e.Provider, ref, identity) }
		write := func() error { return e.Options.Write(e.ctx, e.Provider, ref, identity) }

		// Before any grant, neither works. A resource that is readable by an
		// identity nothing granted access to makes every later assertion vacuous.
		if err := read(); err == nil {
			fail(tb, pt.Name, inv, "a read as %s succeeded before any grant was made; the grant "+
				"invariants below cannot mean anything if access is ambient", identity)
		}

		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead); err != nil {
			fatal(tb, pt.Name, inv, "Grant(AccessRead) failed: %v", err)
		}
		if err := read(); err != nil {
			fail(tb, pt.Name, inv, "after Grant(AccessRead) a read as %s failed: %v", identity, err)
		}
		if err := write(); err == nil {
			fail(tb, pt.Name, inv, "after Grant(AccessRead) a write as %s succeeded; read access "+
				"that permits writing is not read access", identity)
		}

		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessReadWrite); err != nil {
			fatal(tb, pt.Name, inv, "Grant(AccessReadWrite) failed: %v", err)
		}
		if err := read(); err != nil {
			fail(tb, pt.Name, inv, "after Grant(AccessReadWrite) a read failed: %v", err)
		}
		if err := write(); err != nil {
			fail(tb, pt.Name, inv, "after Grant(AccessReadWrite) a write failed: %v", err)
		}

		// Narrowing must actually narrow. This is the case an implementation gets
		// wrong by adding a second policy statement instead of replacing one.
		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead); err != nil {
			fatal(tb, pt.Name, inv, "re-granting AccessRead after AccessReadWrite failed: %v", err)
		}
		if err := write(); err == nil {
			fail(tb, pt.Name, inv, "a write still succeeded after the level was narrowed from "+
				"read-write to read; the grant accumulated instead of being replaced")
		}

		if err := o.Granter.Revoke(e.ctx, ref, identity); err != nil {
			fatal(tb, pt.Name, inv, "Revoke failed: %v", err)
		}
		if err := read(); err == nil {
			fail(tb, pt.Name, inv, "a read as %s still succeeded after Revoke", identity)
		}
		if err := write(); err == nil {
			fail(tb, pt.Name, inv, "a write as %s still succeeded after Revoke", identity)
		}
	}
}

// checkGrantScopedToPair is the pair-scoping half of the grant contract.
//
// [compute.Granter] is keyed on the (resource, identity) pair: "last write wins"
// is about the *level* for one pair, and a call naming one resource says nothing
// about any other. Every other invariant in this file drives one resource, so a
// provider keyed on the identity alone — one grant per role, replaced wholesale
// — passes all of them.
//
// That is not hypothetical. USOSS-14's AWS key-value port wrote every grant
// under one provider-wide inline IAM policy name, and an inline policy name is
// what PutRolePolicy replaces and DeleteRolePolicy removes. So a second grant on
// a second table destroyed the first table's document, a revoke of either
// removed both, and both calls returned nil. The suite was green. The mistake is
// available to any provider whose substrate has a natural per-identity container
// for permissions — an IAM role, a Kubernetes Role, a service account — which is
// most of them, so the invariant belongs here rather than in one provider's
// tests.
//
// The failure is an under-grant, which is why it needs a check rather than a
// review: an over-grant is visible in a policy document, and an under-grant is
// visible only when the application it broke tries to read, long after the
// deploy that reported success.
func checkGrantScopedToPair(pt Port) func(TB, *Env, *portOps) {
	const inv = "a Grant or Revoke on one resource leaves the same identity's grants on every other resource alone"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not; "+
				"that is a suite bug, not a provider bug")
		}
		if e.Options.Read == nil {
			skip(tb, e, inv, "Options.Read, which has to perform a data-plane operation as a "+
				"workload identity — the pair-scoping is only observable behaviourally, since "+
				"asserting on a policy document would only ever check one substrate's policy "+
				"language")
			return
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		// Two resources, one identity. Two is the whole point: one resource
		// cannot distinguish a store keyed on the pair from one keyed on the
		// identity.
		first, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure of the first resource failed: %v", err)
		}
		second, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure of the second resource failed: %v", err)
		}

		readFirst := func() error { return e.Options.Read(e.ctx, e.Provider, first, identity) }
		readSecond := func() error { return e.Options.Read(e.ctx, e.Provider, second, identity) }

		if err := o.Granter.Grant(e.ctx, first, identity, compute.AccessRead); err != nil {
			fatal(tb, pt.Name, inv, "Grant on the first resource failed: %v", err)
		}
		if err := readFirst(); err != nil {
			fatal(tb, pt.Name, inv, "a read of the first resource failed straight after granting "+
				"on it: %v; the pair-scoping below cannot mean anything if the grant itself does "+
				"not take effect", err)
		}

		// The Grant half. A grant naming the second resource must not be a
		// grant that replaces the first.
		if err := o.Granter.Grant(e.ctx, second, identity, compute.AccessRead); err != nil {
			fatal(tb, pt.Name, inv, "Grant on the second resource failed: %v", err)
		}
		if err := readFirst(); err != nil {
			fail(tb, pt.Name, inv, "granting %s access on a second resource destroyed the same "+
				"identity's grant on the first: a read of %s as %s now fails with %v. Granter is "+
				"keyed on the (resource, identity) pair, so a call naming one resource must leave "+
				"every other alone — an application with two of these and one identity loses "+
				"access to the first at runtime, after a deploy that reported success",
				compute.AccessRead, first, identity, err)
			// Restoring it, so the Revoke half below is checked against a known
			// state rather than against the wreckage of this one.
			if err := o.Granter.Grant(e.ctx, first, identity, compute.AccessRead); err != nil {
				fatal(tb, pt.Name, inv, "re-granting on the first resource failed: %v", err)
			}
		}

		// The Revoke half, which is the same defect through the other verb: a
		// provider that deletes a per-identity container rather than one entry
		// in it revokes everything the identity had.
		if err := o.Granter.Revoke(e.ctx, second, identity); err != nil {
			fatal(tb, pt.Name, inv, "Revoke on the second resource failed: %v", err)
		}
		if err := readFirst(); err != nil {
			fail(tb, pt.Name, inv, "revoking on the second resource destroyed the same identity's "+
				"grant on the first: a read of %s as %s now fails with %v. Revoke's resource "+
				"argument is load-bearing; teardown of one resource must not take an unrelated "+
				"one's access with it", first, identity, err)
		}
		if err := readSecond(); err == nil {
			fail(tb, pt.Name, inv, "a read of %s as %s still succeeded after Revoke named it; the "+
				"revoke did not narrow to the pair it was given", second, identity)
		}
	}
}

// checkGrantReadBack is the round-trip half of the grant contract.
//
// # Why this is not a duplicate of the access-level check
//
// checkGrantBehaviour asserts the same property — the level that was granted is
// the level in force — and asserts something strictly stronger, because it goes
// through the data plane: it establishes that the grant *authorises*, which no
// read-back can. So why both?
//
// Because that check needs Options.Read and Options.Write, and skips without
// them. Those two hooks have to perform a data-plane operation as a workload
// identity, which is the hardest part of a provider's harness and the part a
// provider is most likely not to have supplied — and a check that skips is a
// contract nobody asserted. This one needs nothing but the interface, so it runs
// wherever the port does.
//
// The two are therefore ordered rather than redundant: the behavioural check is
// the stronger statement where it runs, and this is the floor everywhere. A
// provider whose Revoke removes nothing fails here with no harness at all, and
// one did pass the entire suite before this existed.
//
// # What it cannot see
//
// That a grant authorises anything. A provider whose Grant writes to a store
// only DescribeGrant reads, and whose substrate never sees it, passes this and
// fails checkGrantBehaviour. That is the division of labour, and it is why
// neither check is removable in favour of the other.
func checkGrantReadBack(pt Port) func(TB, *Env, *portOps) {
	const inv = "DescribeGrant reports no grant before one is made, the level that was granted after, a narrowed level as narrowed, and no grant after Revoke"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not; "+
				"that is a suite bug, not a provider bug")
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		ref, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}

		// Before any grant. A provider that reports a grant nobody made makes
		// every assertion below vacuous, in the same way ambient data-plane
		// access would.
		if info, err := o.Granter.DescribeGrant(e.ctx, ref, identity); !errors.Is(err, compute.ErrNotFound) {
			fail(tb, pt.Name, inv, "DescribeGrant before any Grant returned (%v, %v), want "+
				"compute.ErrNotFound; a read-back that reports a grant nobody made cannot be "+
				"reconciled against, and every check below it means nothing", info, err)
		}

		// The level that was granted is the level reported.
		for _, level := range []compute.AccessLevel{compute.AccessRead, compute.AccessReadWrite} {
			if err := o.Granter.Grant(e.ctx, ref, identity, level); err != nil {
				fatal(tb, pt.Name, inv, "Grant(%s) failed: %v", level, err)
			}
			info, err := o.Granter.DescribeGrant(e.ctx, ref, identity)
			if err != nil {
				fail(tb, pt.Name, inv, "DescribeGrant after Grant(%s) returned %v; a grant that "+
					"was just made has to be readable, or teardown and reconciliation have "+
					"nothing to work from", level, err)
				continue
			}
			if info == nil {
				fail(tb, pt.Name, inv, "DescribeGrant after Grant(%s) returned a nil GrantInfo and "+
					"a nil error; a caller dereferences what it is handed", level)
				continue
			}
			if info.Level != level {
				fail(tb, pt.Name, inv, "DescribeGrant after Grant(%s) reports level %q. The level a "+
					"provider reports has to be the one that stands, and this is the direction that "+
					"matters: reported low, an operator grants again and widens nothing; reported "+
					"high, an access review passes a resource nobody can reach",
					level, info.Level)
			}
			if info.Resource.IsZero() || info.Identity.IsZero() {
				fail(tb, pt.Name, inv, "DescribeGrant returned a GrantInfo with a zero Resource "+
					"(%v) or Identity (%v); a caller correlating a batch of read-backs cannot tell "+
					"which pair an answer belongs to", info.Resource, info.Identity)
			}
		}

		// Narrowing. This is the case an implementation gets wrong by adding a
		// second policy statement rather than replacing one, and until now it was
		// observable only through the data plane -- checkGrantIdempotent says so
		// in as many words where it declines to assert it.
		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead); err != nil {
			fatal(tb, pt.Name, inv, "re-granting AccessRead after AccessReadWrite failed: %v", err)
		}
		if info, err := o.Granter.DescribeGrant(e.ctx, ref, identity); err != nil {
			fail(tb, pt.Name, inv, "DescribeGrant after narrowing returned %v", err)
		} else if info != nil && info.Level != compute.AccessRead {
			fail(tb, pt.Name, inv, "after narrowing from %s to %s the read-back still reports %q; "+
				"the grant accumulated instead of being replaced, which leaves the wider level in "+
				"force while the caller believes it narrowed",
				compute.AccessReadWrite, compute.AccessRead, info.Level)
		}

		// And after Revoke there is nothing.
		if err := o.Granter.Revoke(e.ctx, ref, identity); err != nil {
			fatal(tb, pt.Name, inv, "Revoke failed: %v", err)
		}
		if info, err := o.Granter.DescribeGrant(e.ctx, ref, identity); !errors.Is(err, compute.ErrNotFound) {
			fail(tb, pt.Name, inv, "DescribeGrant after Revoke returned (%v, %v), want "+
				"compute.ErrNotFound. A Revoke that reports success and removes nothing is a "+
				"security control failing open, and this is the assertion that sees it without a "+
				"data-plane harness", info, err)
		}
	}
}

// checkGrantReadBackScopedToPair is pair-scoping, observed through the interface.
//
// checkGrantScopedToPair owns this property and states the case it exists for:
// USOSS-14's key-value port wrote every grant under one provider-wide inline
// policy name, so a second grant destroyed the first and a revoke of either
// removed both, and every call returned nil. That check needs Options.Read and
// skips without it, which means the defect it was written for is invisible on any
// provider that has not supplied a data-plane hook -- and the mistake is
// available to any substrate with a natural per-identity container for
// permissions, which is most of them.
//
// So this is the same property with no harness requirement. It is deliberately
// the Revoke half only: the Grant half is a strictly weaker statement here,
// because a provider keyed on the identity alone would still report the level it
// last wrote for whichever pair is asked about, and only a removal makes the
// difference visible in stored state.
func checkGrantReadBackScopedToPair(pt Port) func(TB, *Env, *portOps) {
	const inv = "DescribeGrant answers for the pair it names: a Revoke on one resource leaves the read-back on another unchanged"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not")
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		// Two resources, one identity. One resource cannot distinguish a store
		// keyed on the pair from one keyed on the identity.
		first, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure of the first resource failed: %v", err)
		}
		second, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure of the second resource failed: %v", err)
		}
		for _, ref := range []compute.Ref{first, second} {
			if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead); err != nil {
				fatal(tb, pt.Name, inv, "Grant on %s failed: %v", ref, err)
			}
		}
		// Both readable first, so that a failure below is the revoke's doing
		// rather than a grant that never landed.
		for _, ref := range []compute.Ref{first, second} {
			if _, err := o.Granter.DescribeGrant(e.ctx, ref, identity); err != nil {
				fatal(tb, pt.Name, inv, "DescribeGrant on %s straight after granting on it "+
					"returned %v; the scoping below cannot mean anything if the grant itself is "+
					"not readable", ref, err)
			}
		}

		if err := o.Granter.Revoke(e.ctx, second, identity); err != nil {
			fatal(tb, pt.Name, inv, "Revoke on the second resource failed: %v", err)
		}
		info, err := o.Granter.DescribeGrant(e.ctx, first, identity)
		if err != nil {
			fail(tb, pt.Name, inv, "revoking on the second resource removed the same identity's "+
				"grant on the first: DescribeGrant on %s now returns %v. Revoke's resource argument "+
				"is load-bearing, and teardown of one resource must not take an unrelated one's "+
				"access with it -- an under-grant nothing reports until the application it broke "+
				"tries to read", first, err)
		} else if info != nil && info.Level != compute.AccessRead {
			fail(tb, pt.Name, inv, "after revoking on the second resource the first reports level "+
				"%q, and %q was granted", info.Level, compute.AccessRead)
		}
		if info, err := o.Granter.DescribeGrant(e.ctx, second, identity); !errors.Is(err, compute.ErrNotFound) {
			fail(tb, pt.Name, inv, "DescribeGrant on %s after Revoke named it returned (%v, %v), "+
				"want compute.ErrNotFound; the revoke did not narrow to the pair it was given",
				second, info, err)
		}
	}
}

func checkGrantIdempotent(pt Port) func(TB, *Env, *portOps) {
	const inv = "Grant is idempotent and narrowing the level replaces it rather than adding a second grant"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not")
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		ref, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		for i := range 2 {
			if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessReadWrite); err != nil {
				fail(tb, pt.Name, inv, "Grant(AccessReadWrite) call %d failed: %v; a redeploy "+
					"re-applies every grant it made last time", i+1, err)
			}
		}
		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead); err != nil {
			fail(tb, pt.Name, inv, "narrowing to AccessRead failed: %v", err)
		}
		// Whether it actually narrowed used to be behavioural, so without the
		// data-plane hooks this check could only note that it was not asserting
		// the thing it is named for. DescribeGrant makes the stored level
		// observable through the interface, so the note is an assertion now.
		//
		// The behavioural check above still owns the stronger statement -- that
		// the narrowed level is what the substrate *enforces* -- and this owns the
		// floor: the provider's own record of the grant narrowed.
		if info, derr := o.Granter.DescribeGrant(e.ctx, ref, identity); derr != nil {
			fail(tb, pt.Name, inv, "DescribeGrant after narrowing to %s returned %v; a grant that "+
				"was just written has to be readable", compute.AccessRead, derr)
		} else if info != nil && info.Level != compute.AccessRead {
			fail(tb, pt.Name, inv, "after two Grant(%s) calls and one Grant(%s), the read-back "+
				"reports %q. The narrowing accumulated instead of replacing, which is what adding "+
				"a second policy statement looks like from outside and leaves the wider level in "+
				"force", compute.AccessReadWrite, compute.AccessRead, info.Level)
		}
		if err := o.Granter.Grant(e.ctx, ref, identity, compute.AccessLevel("not-a-level")); err == nil {
			fail(tb, pt.Name, inv, "Grant accepted an access level the interface does not define; "+
				"a typo in a caller would silently become some provider default")
		}
	}
}

func checkRevokeAbsent(pt Port) func(TB, *Env, *portOps) {
	const inv = "revoking an absent grant returns nil"
	return func(tb TB, e *Env, o *portOps) {
		if o.Granter == nil {
			fatal(tb, pt.Name, inv, "the suite believes this port implements Granter and it does not")
		}
		identity := e.ContainerIdentity(tb, e.Provider)
		ref, _, err := o.Ensure(e.Name(pt.Name), Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		if err := o.Granter.Revoke(e.ctx, ref, identity); err != nil {
			fail(tb, pt.Name, inv, "Revoke on a resource with no grant returned %v; teardown "+
				"revokes what it believes it granted, and a failed deploy leaves that set "+
				"incomplete", err)
		}
		if err := o.Granter.Revoke(e.ctx, ref, identity); err != nil {
			fail(tb, pt.Name, inv, "a second Revoke returned %v", err)
		}
	}
}

// checkGrantRefused is the negative half of the grant contract.
//
// A provider that does not advertise [compute.CapWorkloadGrants] still vends
// ports that carry Granter — the port shape is about what the substrate can
// express, the capability about whether this deployment does. What it must do
// is refuse, with an error that names the capability the caller should have
// checked, rather than one naming the port's own capability (which it has) or
// failing somewhere deeper.
func checkGrantRefused(pt Port) func(TB, *Env, *portOps) {
	const inv = "a provider without CapWorkloadGrants refuses Grant and DescribeGrant with ErrUnsupported naming that capability"
	return func(tb TB, e *Env, o *portOps) {
		name := e.Name(pt.Name)
		ref, _, err := o.Ensure(name, Base)
		if err != nil {
			fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
		}
		identity := e.ContainerIdentity(tb, e.Provider)

		err = o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead)
		if err == nil {
			fail(tb, pt.Name, inv, "Grant succeeded on a provider that does not advertise %s; "+
				"either the capability is being under-reported, in which case a caller cannot "+
				"plan around it, or the grant did not take effect and the caller has been told "+
				"access exists when it does not", compute.CapWorkloadGrants)
			return
		}
		if !errors.Is(err, compute.ErrUnsupported) {
			fail(tb, pt.Name, inv, "Grant refused with %v, which does not match "+
				"compute.ErrUnsupported; a capability a caller checks in advance has to fail as "+
				"an unsupported capability when it is absent", err)
			return
		}
		var unsupported *compute.UnsupportedError
		if errors.As(err, &unsupported) && unsupported.Capability != compute.CapWorkloadGrants {
			fail(tb, pt.Name, inv, "the refusal names capability %q, which this provider "+
				"advertises. It has to name %q — the one that is missing — or an operator reads "+
				"the message and reconfigures the wrong thing",
				unsupported.Capability, compute.CapWorkloadGrants)
		}

		// The read-back refuses on the same terms, and the reason is not symmetry.
		// A provider that cannot express a grant holds none, so a DescribeGrant
		// that answered would report "no grant on this pair" -- which is
		// indistinguishable from having looked, and a caller reconciling on it
		// would keep issuing grants the substrate cannot express while being told
		// each time that none exist.
		info, derr := o.Granter.DescribeGrant(e.ctx, ref, identity)
		if derr == nil {
			fail(tb, pt.Name, inv, "DescribeGrant returned (%v, nil) on a provider that does not "+
				"advertise %s. A provider that cannot make a grant cannot have one to report, so "+
				"an answer here is either invented or a report about a substrate this provider is "+
				"not authorising against", info, compute.CapWorkloadGrants)
			return
		}
		if !errors.Is(derr, compute.ErrUnsupported) {
			fail(tb, pt.Name, inv, "DescribeGrant refused with %v, which does not match "+
				"compute.ErrUnsupported. Reporting the absence as ErrNotFound is the specific "+
				"mistake worth naming: it says the pair has no grant, when what is true is that "+
				"this provider cannot hold one", derr)
			return
		}
		var dunsupported *compute.UnsupportedError
		if errors.As(derr, &dunsupported) && dunsupported.Capability != compute.CapWorkloadGrants {
			fail(tb, pt.Name, inv, "DescribeGrant's refusal names capability %q rather than %q",
				dunsupported.Capability, compute.CapWorkloadGrants)
		}
	}
}
