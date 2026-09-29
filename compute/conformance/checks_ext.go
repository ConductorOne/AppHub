// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// extPositiveChecks drives the ext lookup helpers' *behaviour*, not merely
// their reachability.
//
// [checkExtLookup] (checks_negative.go) already asserts that a lookup succeeds
// exactly when [Options.ImplementsExt] says it should, and that the refusal is
// typed when it does not. That is the reachability half of the contract named
// in Options.ImplementsExt's doc comment: "a provider that implements a port
// must be reachable through it". This file is the other half: "one that does
// [implement it] must ... behave correctly" once reached.
//
// # Why this exists now and not earlier
//
// undrivenPortMethods (drive.go) excused EnsureTableBucket, DeleteTableBucket,
// Grant and Revoke on both ext.TableBucketProvisioner and
// ext.VectorBucketProvisioner with the same reason: "implemented only on an
// unmerged branch (USOSS-13, PR #20)", expiring on "PR #20 merging". PR #20
// merged as 77aa0f6 ("USOSS-13: AWS object storage on S3, with IAM grants and
// the ext bucket ports (#20)"), so compute/aws has implemented all eight
// methods since before this file existed, and the table's own rule is *drive
// it, do not excuse it* -- the correction PR #35 (USOSS-37) already made for
// GrantExternal and RevokeExternal for the same reason.
//
// ext.ExternalAccessGranter's own two methods are already driven, by
// checkExternalGrantConstraints in checks_negative.go. This file drives the
// other two ports; nothing here re-drives ExternalAccessGranter.
//
// # Named functions, not a shared generic
//
// TestEveryCoveredByClaimIsBoundToACall resolves a CoveredBy claim by parsing
// this package's source for a literal call to the claimed method inside the
// literally-named function registered for the check. A generic helper reached
// through an interface adapter (calling p.Ensure rather than
// p.EnsureTableBucket, say) would hide the real method name from that reader,
// so table and vector variants are written out rather than shared behind one
// indirection -- the duplication is the price of staying legible to the tool
// that verifies coverage, the same trade [checks_grants.go]'s per-port
// functions make.
func extPositiveChecks(_ *Env) []Check {
	return []Check{
		{
			Name:      "ext/table-bucket/ensure-table-bucket-and-delete-table-bucket-round-trip",
			Port:      "ext.TableBucketProvisioner",
			Class:     Sync,
			Invariant: "EnsureTableBucket is idempotent and returns a usable bucket; DeleteTableBucket removes it and is idempotent",
			Fn:        checkTableBucketLifecycle,
		},
		{
			Name:      "ext/table-bucket/table-bucket-grant-then-table-bucket-revoke",
			Port:      "ext.TableBucketProvisioner",
			Class:     Sync,
			Invariant: "Grant and Revoke on a table bucket succeed, are idempotent, and revoking an absent grant is nil",
			Fn:        checkTableBucketGrant,
		},
		{
			Name:      "ext/vector-bucket/ensure-vector-bucket-and-delete-vector-bucket-round-trip",
			Port:      "ext.VectorBucketProvisioner",
			Class:     Sync,
			Invariant: "EnsureVectorBucket is idempotent and returns a usable bucket; DeleteVectorBucket removes it and is idempotent",
			Fn:        checkVectorBucketLifecycle,
		},
		{
			Name:      "ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke",
			Port:      "ext.VectorBucketProvisioner",
			Class:     Sync,
			Invariant: "Grant and Revoke on a vector bucket succeed, are idempotent, and revoking an absent grant is nil",
			Fn:        checkVectorBucketGrant,
		},
	}
}

// tableBucketStore resolves the object store and the TableBucketProvisioner,
// or reports why the check could not run and returns ok=false.
func tableBucketStore(tb TB, e *Env, inv string) (ext.TableBucketProvisioner, bool) {
	tb.Helper()
	const port = "ext.TableBucketProvisioner"
	if !e.Options.ImplementsExt[port] {
		skipBecause(tb, e, inv, "this provider does not document "+port+"; the lookup check "+
			"(ext/"+port+"/lookup-matches-what-the-provider-documents) already covers the "+
			"refusal a provider that does not implement it must give")
		return nil, false
	}
	if !e.Provider.Capabilities().Has(compute.CapObjectStore) {
		fail(tb, port, inv, "Options.ImplementsExt claims %s and the provider does not advertise "+
			"%s, so there is no object store to reach the port through", port, compute.CapObjectStore)
		return nil, false
	}
	store, err := e.Provider.ObjectStores()
	if err != nil {
		fatal(tb, port, inv, "ObjectStores() refused: %v", err)
		return nil, false
	}
	p, err := ext.TableBuckets(e.Provider.Name(), store)
	if err != nil {
		fatal(tb, port, inv, "Options.ImplementsExt claims %s and the lookup refused: %v", port, err)
		return nil, false
	}
	return p, true
}

// vectorBucketStore is tableBucketStore for ext.VectorBucketProvisioner.
func vectorBucketStore(tb TB, e *Env, inv string) (ext.VectorBucketProvisioner, bool) {
	tb.Helper()
	const port = "ext.VectorBucketProvisioner"
	if !e.Options.ImplementsExt[port] {
		skipBecause(tb, e, inv, "this provider does not document "+port+"; the lookup check "+
			"(ext/"+port+"/lookup-matches-what-the-provider-documents) already covers the "+
			"refusal a provider that does not implement it must give")
		return nil, false
	}
	if !e.Provider.Capabilities().Has(compute.CapObjectStore) {
		fail(tb, port, inv, "Options.ImplementsExt claims %s and the provider does not advertise "+
			"%s, so there is no object store to reach the port through", port, compute.CapObjectStore)
		return nil, false
	}
	store, err := e.Provider.ObjectStores()
	if err != nil {
		fatal(tb, port, inv, "ObjectStores() refused: %v", err)
		return nil, false
	}
	p, err := ext.VectorBuckets(e.Provider.Name(), store)
	if err != nil {
		fatal(tb, port, inv, "Options.ImplementsExt claims %s and the lookup refused: %v", port, err)
		return nil, false
	}
	return p, true
}

// checkTableBucketLifecycle drives EnsureTableBucket and DeleteTableBucket:
// idempotent Ensure, a spec the port cannot express refused rather than
// silently dropped, and an idempotent Delete.
func checkTableBucketLifecycle(tb TB, e *Env) {
	const inv = "EnsureTableBucket is idempotent and returns a usable bucket; DeleteTableBucket removes it and is idempotent"
	const port = "ext.TableBucketProvisioner"
	p, ok := tableBucketStore(tb, e, inv)
	if !ok {
		return
	}

	name := e.Name("table-bucket")
	spec := compute.BucketSpec{Name: name}
	first, err := p.EnsureTableBucket(e.ctx, spec)
	if err != nil {
		fatal(tb, port, inv, "EnsureTableBucket: %v", err)
	}
	if first.Ref.IsZero() {
		fail(tb, port, inv, "EnsureTableBucket returned a zero Ref")
	}

	// Idempotent: a second Ensure of the same spec must adopt, not fail and not
	// create a second bucket under a different ref.
	second, err := p.EnsureTableBucket(e.ctx, spec)
	if err != nil {
		fail(tb, port, inv, "a second EnsureTableBucket of the same spec failed: %v; a redeploy "+
			"re-applies the same spec every time", err)
	} else if second.Ref != first.Ref {
		fail(tb, port, inv, "a second EnsureTableBucket of the same spec returned ref %s, want "+
			"%s; it adopted a different resource instead of the one already provisioned",
			second.Ref, first.Ref)
	}

	// A spec field the port cannot express must be refused, not silently
	// dropped and echoed back as though it took effect -- accept-and-ignore
	// would report a gap as configured state.
	zonal := compute.BucketSpec{Name: e.Name("table-bucket-zonal"), Class: compute.ObjectClassZonal}
	if _, err := p.EnsureTableBucket(e.ctx, zonal); !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, port, inv, "EnsureTableBucket with Class=%q returned %v, want an error wrapping "+
			"compute.ErrInvalidSpec; this port has no storage class, and accepting one it cannot "+
			"honour and reporting it as effective would turn a gap into a lie",
			compute.ObjectClassZonal, err)
	}

	if err := p.DeleteTableBucket(e.ctx, first.Ref); err != nil {
		fail(tb, port, inv, "DeleteTableBucket: %v", err)
	}
	// Idempotent delete: a second Delete of the same, now-absent, resource must
	// be nil. Teardown has to be re-runnable.
	if err := p.DeleteTableBucket(e.ctx, first.Ref); err != nil {
		fail(tb, port, inv, "a second DeleteTableBucket of the same ref returned %v, want nil", err)
	}
}

// checkVectorBucketLifecycle is checkTableBucketLifecycle for
// ext.VectorBucketProvisioner.
func checkVectorBucketLifecycle(tb TB, e *Env) {
	const inv = "EnsureVectorBucket is idempotent and returns a usable bucket; DeleteVectorBucket removes it and is idempotent"
	const port = "ext.VectorBucketProvisioner"
	p, ok := vectorBucketStore(tb, e, inv)
	if !ok {
		return
	}

	name := e.Name("vector-bucket")
	spec := compute.BucketSpec{Name: name}
	first, err := p.EnsureVectorBucket(e.ctx, spec)
	if err != nil {
		fatal(tb, port, inv, "EnsureVectorBucket: %v", err)
	}
	if first.Ref.IsZero() {
		fail(tb, port, inv, "EnsureVectorBucket returned a zero Ref")
	}

	second, err := p.EnsureVectorBucket(e.ctx, spec)
	if err != nil {
		fail(tb, port, inv, "a second EnsureVectorBucket of the same spec failed: %v; a redeploy "+
			"re-applies the same spec every time", err)
	} else if second.Ref != first.Ref {
		fail(tb, port, inv, "a second EnsureVectorBucket of the same spec returned ref %s, want "+
			"%s; it adopted a different resource instead of the one already provisioned",
			second.Ref, first.Ref)
	}

	zonal := compute.BucketSpec{Name: e.Name("vector-bucket-zonal"), Class: compute.ObjectClassZonal}
	if _, err := p.EnsureVectorBucket(e.ctx, zonal); !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, port, inv, "EnsureVectorBucket with Class=%q returned %v, want an error wrapping "+
			"compute.ErrInvalidSpec; this port has no storage class, and accepting one it cannot "+
			"honour and reporting it as effective would turn a gap into a lie",
			compute.ObjectClassZonal, err)
	}

	if err := p.DeleteVectorBucket(e.ctx, first.Ref); err != nil {
		fail(tb, port, inv, "DeleteVectorBucket: %v", err)
	}
	if err := p.DeleteVectorBucket(e.ctx, first.Ref); err != nil {
		fail(tb, port, inv, "a second DeleteVectorBucket of the same ref returned %v, want nil", err)
	}
}

// checkTableBucketGrant drives Grant and Revoke on ext.TableBucketProvisioner.
//
// ext.TableBucketProvisioner.Grant mirrors compute.Granter exactly, and
// compute/aws documents (ext.go) that it inherits its general-purpose
// Grant/Revoke for both S3-shaped ports rather than reimplementing them. What
// this checks -- error-free, idempotent, and a nil revoke of an absent grant --
// is the portable half.
//
// It also reads the grant back, which the first version of this check could not:
// USOSS-73 added DescribeGrant to this port for the same reason it added it to
// compute.Granter, and it needs no Options hook. So "a provider whose Grant and
// Revoke both return nil and do nothing would satisfy this" -- which the
// obligation entry for this port said in as many words one commit ago -- is no
// longer true.
//
// What it still does NOT assert is that a grant actually AUTHORISES access.
// Unlike the core bucket and key-value ports, no Options hook performs a
// data-plane read or write through a table or vector bucket, so that half stays
// unverified here for the same documented reason checkGrantIdempotent gives for
// the core ports when Options.Read/Options.Write are nil. The read-back is the
// floor; the data plane is the ceiling, and only the floor is reachable here.
func checkTableBucketGrant(tb TB, e *Env) {
	const inv = "Grant and Revoke on a table bucket succeed, are idempotent, revoking an absent grant is nil, and the read-back reports what stands"
	const port = "ext.TableBucketProvisioner"
	p, ok := tableBucketStore(tb, e, inv)
	if !ok {
		return
	}
	if !e.Provider.Capabilities().Has(compute.CapWorkloadGrants) {
		skip(tb, e, inv, "the "+string(compute.CapWorkloadGrants)+" capability")
		return
	}

	bucket, err := p.EnsureTableBucket(e.ctx, compute.BucketSpec{Name: e.Name("table-bucket-grant")})
	if err != nil {
		fatal(tb, port, inv, "EnsureTableBucket: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)

	for i := range 2 {
		if err := p.Grant(e.ctx, bucket.Ref, identity, compute.AccessReadWrite); err != nil {
			fail(tb, port, inv, "Grant(AccessReadWrite) call %d failed: %v; a redeploy re-applies "+
				"every grant it made last time", i+1, err)
		}
	}
	granted, err := p.DescribeGrant(e.ctx, bucket.Ref, identity)
	extGrantReadBack(tb, port, inv, granted, err)

	// Still not asserted here, and recorded once as a static obligation rather
	// than a per-run note: that a grant authorises anything at all. See
	// unverifiedObligations's ext.TableBucketProvisioner.Grant entry in drive.go
	// for why -- no Options hook performs a data-plane read or write through this
	// port, on any provider, so a note here would fire on every run including the
	// reference provider's and never close.

	if err := p.Revoke(e.ctx, bucket.Ref, identity); err != nil {
		fail(tb, port, inv, "Revoke: %v", err)
	}
	revoked, err := p.DescribeGrant(e.ctx, bucket.Ref, identity)
	extRevokeReadBack(tb, port, inv, revoked, err)
	if err := p.Revoke(e.ctx, bucket.Ref, identity); err != nil {
		fail(tb, port, inv, "a second Revoke of the same, now-ungranted, pair returned %v, want "+
			"nil; teardown has to be re-runnable", err)
	}
}

// extGrantReadBack asserts that the level just granted is the level that stands.
//
// It takes the read-back's RESULT rather than a function to call it with, so that
// the DescribeGrant call itself stays in the body of the check that claims to
// drive it. TestEveryCoveredByClaimIsBoundToACall resolves a CoveredBy claim to
// the named function and requires the call to appear there; a helper invoked with
// a method value satisfies neither that gate nor the reason it exists, which is
// that an identifier is not an invocation. The assertion text is still shared,
// because the two ext bucket ports are the same shape and their failure messages
// should not drift apart.
//
// The core ports' equivalent lives in checks_grants.go and says more; this is the
// subset that applies where there is no data plane to check against.
func extGrantReadBack(tb TB, port, inv string, info *compute.GrantInfo, err error) {
	if err != nil {
		fail(tb, port, inv, "DescribeGrant after Grant(%s) returned %v; a grant that was just "+
			"made has to be readable, or nothing here establishes that Grant did anything",
			compute.AccessReadWrite, err)
		return
	}
	if info == nil {
		fail(tb, port, inv, "DescribeGrant returned a nil GrantInfo and a nil error; a caller "+
			"dereferences what it is handed")
		return
	}
	if info.Level != compute.AccessReadWrite {
		fail(tb, port, inv, "DescribeGrant after Grant(%s) reports level %q. Reported low, an "+
			"operator grants again and widens nothing; reported high, an access review passes a "+
			"resource nobody can reach", compute.AccessReadWrite, info.Level)
	}
}

// extRevokeReadBack asserts that a Revoke removed something.
//
// This is the assertion that makes a do-nothing Revoke fail on these ports. It
// needs no data-plane hook, which is the whole reason it can be here at all.
// Takes the result rather than the call, as [extGrantReadBack] does and for the
// same reason.
func extRevokeReadBack(tb TB, port, inv string, info *compute.GrantInfo, err error) {
	if !errors.Is(err, compute.ErrNotFound) {
		fail(tb, port, inv, "DescribeGrant after Revoke returned (%v, %v), want "+
			"compute.ErrNotFound. A Revoke that reports success and removes nothing is a security "+
			"control failing open, and on this port there is no data-plane hook that would catch "+
			"it instead", info, err)
	}
}

// checkVectorBucketGrant is checkTableBucketGrant for
// ext.VectorBucketProvisioner.
func checkVectorBucketGrant(tb TB, e *Env) {
	const inv = "Grant and Revoke on a vector bucket succeed, are idempotent, revoking an absent grant is nil, and the read-back reports what stands"
	const port = "ext.VectorBucketProvisioner"
	p, ok := vectorBucketStore(tb, e, inv)
	if !ok {
		return
	}
	if !e.Provider.Capabilities().Has(compute.CapWorkloadGrants) {
		skip(tb, e, inv, "the "+string(compute.CapWorkloadGrants)+" capability")
		return
	}

	bucket, err := p.EnsureVectorBucket(e.ctx, compute.BucketSpec{Name: e.Name("vector-bucket-grant")})
	if err != nil {
		fatal(tb, port, inv, "EnsureVectorBucket: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)

	for i := range 2 {
		if err := p.Grant(e.ctx, bucket.Ref, identity, compute.AccessReadWrite); err != nil {
			fail(tb, port, inv, "Grant(AccessReadWrite) call %d failed: %v; a redeploy re-applies "+
				"every grant it made last time", i+1, err)
		}
	}
	granted, err := p.DescribeGrant(e.ctx, bucket.Ref, identity)
	extGrantReadBack(tb, port, inv, granted, err)

	// Still not asserted here, and recorded once as a static obligation rather
	// than a per-run note: that a grant authorises anything at all. See
	// unverifiedObligations's ext.VectorBucketProvisioner.Grant entry in drive.go
	// for why -- no Options hook performs a data-plane read or write through this
	// port, on any provider, so a note here would fire on every run including the
	// reference provider's and never close.

	if err := p.Revoke(e.ctx, bucket.Ref, identity); err != nil {
		fail(tb, port, inv, "Revoke: %v", err)
	}
	revoked, err := p.DescribeGrant(e.ctx, bucket.Ref, identity)
	extRevokeReadBack(tb, port, inv, revoked, err)
	if err := p.Revoke(e.ctx, bucket.Ref, identity); err != nil {
		fail(tb, port, inv, "a second Revoke of the same, now-ungranted, pair returned %v, want "+
			"nil; teardown has to be re-runnable", err)
	}
}
