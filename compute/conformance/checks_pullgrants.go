// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// The image-pull grant checks (USOSS-39).
//
// [compute.ImagePullGranter] had no coverage of any kind before this, which the
// USOSS-39 audit called the cheapest real coverage on the board: its two methods
// document exactly the invariants the suite already checks for [compute.Granter]
// at the bucket and key-value ports — GrantPull is "Idempotent", RevokePull
// "Revoking an absent one returns nil" — so the contract was already written
// down and simply not applied here.
//
// It is not a hypothetical port either. compute/fake advertises
// [compute.CapImagePullGrants] by default, and compute/k8s advertises it when
// configured for pull-by-workload-identity, because a kubelet credential
// provider handed a pod-bound ServiceAccount token is a real identity-scoped
// pull authorisation. A capability with two implementations and no checks is the
// shape this whole ticket is about.
//
// What is *not* checked here, and what a reviewer had to prove because the first
// version implied otherwise: whether a grant exists at all. The grant checks for
// the core ports assert behaviour through Options.Read and Options.Write,
// because a policy document a provider merely wrote proves nothing. There is no
// equivalent for a registry pull — no hook says "pull this image as this
// identity" — so a provider whose GrantPull and RevokePull both return nil and
// do nothing satisfies everything here. These checks establish that the calls
// are shaped as documented, and nothing about the authorisation behind them.
// unverifiedObligations records what closing that would need.
func pullGrantChecks(e *Env) []Check {
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapImageRegistry) {
		return nil
	}
	if !caps.Has(compute.CapImagePullGrants) {
		return []Check{{
			Name:      "grants/image-repository/pull-grants-refused-without-the-capability",
			Port:      "image-repository",
			Class:     Sync,
			Invariant: "a provider without CapImagePullGrants refuses a pull grant, naming that capability",
			Fn:        checkPullGrantRefused,
		}}
	}
	return []Check{
		{
			Name:      "grants/image-repository/pull-grant-is-idempotent",
			Port:      "image-repository",
			Class:     Sync,
			Invariant: "granting pull twice returns nil twice, and revoking twice returns nil twice",
			Fn:        checkPullGrantIdempotent,
		},
		{
			Name:      "grants/image-repository/revoking-an-absent-pull-grant-is-nil",
			Port:      "image-repository",
			Class:     Sync,
			Invariant: "revoking a pull grant that was never made returns nil",
			Fn:        checkRevokePullAbsent,
		},
		{
			Name:      "grants/image-repository/pull-grants-refuse-a-foreign-ref",
			Port:      "image-repository",
			Class:     Sync,
			Invariant: "a pull grant on a repository issued by another provider is ErrForeignRef",
			Fn:        checkPullGrantForeignRef,
		},
	}
}

// pullTarget prepares a repository and an identity to grant pull on.
func pullTarget(tb TB, e *Env, inv string) (compute.ImagePullGranter, compute.Ref, compute.Ref) {
	tb.Helper()
	reg, err := e.Provider.Registry()
	if err != nil {
		fatal(tb, "image-repository", inv, "the provider advertises %q but Registry() refused: %v",
			compute.CapImageRegistry, err)
	}
	g, err := compute.ImagePullGrants(e.Provider, reg)
	if err != nil {
		fatal(tb, "image-repository", inv, "the provider advertises %q and ImagePullGrants "+
			"refused with %v; the capability and the interface disagree",
			compute.CapImagePullGrants, err)
	}
	repo, err := reg.EnsureRepository(e.ctx, compute.RepositorySpec{
		Name:   e.Name("pull-grant"),
		Labels: map[string]string{"owner": "conformance"},
	})
	if err != nil {
		fatal(tb, "image-repository", inv, "EnsureRepository failed: %v", err)
	}
	return g, repo.Ref, e.ContainerIdentity(tb, e.Provider)
}

// checkPullGrantIdempotent pins as much of GrantPull's documented idempotency as
// this interface can observe, which is less than the first version claimed.
//
// A caller reconciles: it grants pull on every deploy because it cannot cheaply
// know whether last week's grant is still there. A provider that errors on the
// second grant turns a no-op reconcile into a failed deploy. That much is
// checkable.
//
// What is NOT checkable, and what this check claimed until review: that two
// grants are not *two* grants. The first version inferred it from a second
// revoke succeeding, and a reviewer defeated it with a provider whose GrantPull
// returned nil idempotently and whose RevokePull was a no-op — an authorisation
// left permanently in place satisfied the check. Both revokes returning nil
// cannot establish removal, because nil is also what a provider that does
// nothing returns.
//
// There is no hook that performs a pull as an identity and no policy
// observation, so the claim is narrowed to what a probe can establish rather
// than replaced with a cleverer probe against a surface that cannot answer. What
// removal would need is recorded in unverifiedObligations.
func checkPullGrantIdempotent(tb TB, e *Env) {
	const inv = "granting pull twice returns nil twice, and revoking twice returns nil twice"
	g, repo, identity := pullTarget(tb, e, inv)

	if err := g.GrantPull(e.ctx, repo, identity); err != nil {
		fail(tb, "image-repository", inv, "the first GrantPull failed: %v", redact(err))
		return
	}
	if err := g.GrantPull(e.ctx, repo, identity); err != nil {
		fail(tb, "image-repository", inv, "the second GrantPull failed with %v; a caller "+
			"reconciles, so it grants pull on every deploy without knowing whether the last one "+
			"is still in place, and an error here turns a no-op into a failed deploy", redact(err))
		return
	}
	if err := g.RevokePull(e.ctx, repo, identity); err != nil {
		fail(tb, "image-repository", inv, "RevokePull after two grants failed: %v", redact(err))
		return
	}
	if err := g.RevokePull(e.ctx, repo, identity); err != nil {
		fail(tb, "image-repository", inv, "a second RevokePull failed with %v; revoking an "+
			"authorisation that is already gone has to be a no-op, because teardown runs more "+
			"than once", redact(err))
	}
}

// checkRevokePullAbsent pins the documented "revoking an absent one returns
// nil". Teardown has to be re-runnable: a revoke that fails because there was
// nothing to revoke turns a retried teardown into a permanent failure.
func checkRevokePullAbsent(tb TB, e *Env) {
	const inv = "revoking a pull grant that was never made returns nil"
	g, repo, identity := pullTarget(tb, e, inv)

	if err := g.RevokePull(e.ctx, repo, identity); err != nil {
		fail(tb, "image-repository", inv, "RevokePull on a grant that was never made returned "+
			"%v; teardown runs more than once and cannot distinguish 'already revoked' from "+
			"'failed to revoke'", redact(err))
	}
}

// checkPullGrantForeignRef mirrors the foreign-Ref invariant every other port
// carries: a reference this provider did not issue is refused as foreign, not
// reported as absent.
func checkPullGrantForeignRef(tb TB, e *Env) {
	const inv = "a pull grant on a repository issued by another provider is ErrForeignRef"
	g, _, identity := pullTarget(tb, e, inv)
	foreign := compute.Ref{
		Provider: foreignProvider,
		Kind:     compute.KindImageRepository,
		ID:       "some-other-registry-id",
	}

	check := func(method string, err error) {
		if err == nil {
			fail(tb, "image-repository", inv, "%s accepted a repository Ref issued by %q; a "+
				"platform reconfigured from one substrate to another would hand this provider "+
				"another one's identifiers and authorise a pull against something it does not own",
				method, foreignProvider)
			return
		}
		if errors.Is(err, compute.ErrNotFound) {
			fail(tb, "image-repository", inv, "%s reported a foreign Ref as ErrNotFound (%v); a "+
				"caller would conclude the repository had been deleted", method, err)
		}
		if !errors.Is(err, compute.ErrForeignRef) {
			fail(tb, "image-repository", inv, "%s refused a foreign Ref with %v, which does not "+
				"match compute.ErrForeignRef", method, err)
		}
	}
	check("GrantPull", g.GrantPull(e.ctx, foreign, identity))
	check("RevokePull", g.RevokePull(e.ctx, foreign, identity))
}

// checkPullGrantRefused is the negative: a provider that cannot authorise a pull
// by workload identity must say so through the lookup, typed and named, rather
// than accepting a grant it will not honour.
//
// The obligation that survives is on [compute.ImageRegistry] itself: such a
// provider still guarantees its own workloads can pull the images they name. A
// refusal here is the provider declining a mechanism, not declining the
// guarantee.
func checkPullGrantRefused(tb TB, e *Env) {
	const inv = "a provider without CapImagePullGrants refuses a pull grant, naming that capability"
	reg, err := e.Provider.Registry()
	if err != nil {
		fatal(tb, "image-repository", inv, "the provider advertises %q but Registry() refused: %v",
			compute.CapImageRegistry, err)
	}

	// The supported route must refuse.
	if _, err := compute.ImagePullGrants(e.Provider, reg); err == nil {
		fail(tb, "image-repository", inv, "the provider does not advertise %q and "+
			"ImagePullGrants handed out a granter anyway; a caller that grants pull through it "+
			"believes an authorisation exists that the substrate cannot express",
			compute.CapImagePullGrants)
	} else {
		if !errors.Is(err, compute.ErrUnsupported) {
			fail(tb, "image-repository", inv, "the refusal %v does not match "+
				"compute.ErrUnsupported, so a caller that already branches on the sentinel "+
				"misses it", err)
		}
		if !strings.Contains(err.Error(), string(compute.CapImagePullGrants)) {
			fail(tb, "image-repository", inv, "the refusal %q does not name %q, so an operator "+
				"reading it cannot tell which capability to configure",
				err.Error(), compute.CapImagePullGrants)
		}
	}

	// And so must the port itself, for the provider whose registry implements the
	// interface anyway.
	//
	// This half is the one that matters, and it is about the provider rather than
	// about compute's lookup helper. A registry may satisfy the interface at
	// compile time and be configured for a substrate that cannot authorise a
	// pull; the method has to refuse rather than accept a grant it will not
	// honour. A silent no-op here is worse than an error: the caller records an
	// authorisation, the workload cannot pull, and the failure surfaces at
	// launch as an image-pull error with nothing pointing back to the grant.
	g, ok := reg.(compute.ImagePullGranter)
	if !ok {
		// Legitimate: a registry that does not implement the optional interface
		// at all. Nothing more to drive, and the lookup refusal above is the
		// whole contract for it.
		return
	}
	identity := e.ContainerIdentity(tb, e.Provider)
	repo, err := reg.EnsureRepository(e.ctx, compute.RepositorySpec{Name: e.Name("pull-refused")})
	if err != nil {
		fatal(tb, "image-repository", inv, "EnsureRepository failed: %v", err)
	}
	err = g.GrantPull(e.ctx, repo.Ref, identity)
	switch {
	case err == nil:
		fail(tb, "image-repository", inv, "GrantPull succeeded on a provider that does not "+
			"advertise %q. The grant is silently a no-op: the caller records an authorisation "+
			"that does not exist, and the workload's failure to pull surfaces at launch with "+
			"nothing pointing back to here", compute.CapImagePullGrants)
	case !errors.Is(err, compute.ErrUnsupported):
		fail(tb, "image-repository", inv, "GrantPull refused with %v, which does not match "+
			"compute.ErrUnsupported", err)
	case !strings.Contains(err.Error(), string(compute.CapImagePullGrants)):
		fail(tb, "image-repository", inv, "GrantPull's refusal %q names neither the capability "+
			"an operator would configure nor anything they could act on", err.Error())
	}
}
