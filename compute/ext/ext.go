// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package ext

import (
	"context"
	"fmt"

	"github.com/conductorone/apphub/compute"
)

// ErrNotImplemented reports that a provider does not implement a non-portable
// port. It wraps [compute.ErrUnsupported], so callers that already branch on
// that sentinel handle it without a second case.
//
// Reaching an ext port is a runtime lookup rather than a compile-time
// guarantee, so this error is the mechanism by which a substrate's inability
// becomes explicit. It names the port; a caller must surface it, not swallow
// it.
type ErrNotImplemented struct {
	// Provider is the [compute.Provider.Name] that does not implement it.
	Provider string
	// Port is the interface that was asked for.
	Port string
}

func (e *ErrNotImplemented) Error() string {
	return fmt.Sprintf("compute/ext: provider %q does not implement %s", e.Provider, e.Port)
}

// Unwrap makes errors.Is(err, compute.ErrUnsupported) true.
func (e *ErrNotImplemented) Unwrap() error { return compute.ErrUnsupported }

// TableBucketProvisioner provisions analytic table storage that the
// application addresses through a table-oriented API rather than an object API.
//
// # Portability: none
//
// This is AWS S3 Tables (bucket.go:338-364). It is Iceberg-backed table storage
// exposed as a first-class bucket type with its own service API and its own
// permission model (bucket.go:461-478). No other substrate surveyed has an
// equivalent, and the reason it cannot be faked is not that the storage is hard
// — it is that the *application* speaks the s3tables API directly, using an ARN
// handed to it in an environment variable (bucket.go:404-405). Backing that
// with something else does not produce a working application, it produces an
// application that cannot connect.
//
// If a comparable managed-Iceberg product appears elsewhere, this port is where
// a second implementation goes, and this comment is where the claim gets
// revised. Until then, an application configured for a table bucket is an
// AWS-only application, and that fact should reach the operator when they
// choose the bucket type, not when the deploy fails.
type TableBucketProvisioner interface {
	// EnsureTableBucket creates or returns an analytic table bucket.
	// Idempotent.
	EnsureTableBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error)

	// DeleteTableBucket removes one. Idempotent.
	DeleteTableBucket(ctx context.Context, ref compute.Ref) error

	// Grant gives a workload identity access to the bucket, mirroring
	// [compute.Granter] so that the grant path is uniform even though the
	// resource is not portable.
	Grant(ctx context.Context, resource compute.Ref, identity compute.Ref, level compute.AccessLevel) error

	// Revoke removes that access. Idempotent.
	Revoke(ctx context.Context, resource compute.Ref, identity compute.Ref) error

	// DescribeGrant reports the access identity has, mirroring
	// [compute.Granter.DescribeGrant] with the same contract.
	//
	// It is here for the reason the other two are, and the reason is mechanical
	// rather than aesthetic. These signatures are identical to the core ones, so a
	// provider serves both with one method — compute/aws does — but a caller that
	// reached this port through [TableBuckets] holds a TableBucketProvisioner, and
	// getting the read-back off it without this would mean asserting back to
	// [compute.Granter]. A bare type assertion is exactly what the lookup helpers
	// in this file exist to keep callers from writing.
	DescribeGrant(ctx context.Context, resource compute.Ref, identity compute.Ref) (*compute.GrantInfo, error)
}

// VectorBucketProvisioner provisions native vector-index storage.
//
// # Portability: none, as specified here
//
// This is AWS S3 Vectors (bucket.go:366-392). The nuance worth stating: vector
// search itself is not an AWS-only idea — pgvector, Qdrant, and half a dozen
// managed services do it. What is AWS-only is *this shape of it*: a bucket you
// provision, addressed by name and ARN in an environment variable
// (bucket.go:406-410), spoken to with the s3vectors API and its index/query
// verbs (bucket.go:481-494).
//
// A genuinely portable "vector index" port is a plausible future design, and it
// would live in package compute, not here, because it would define the
// application's contract rather than mirror one substrate's. Introducing it
// would change what deployed applications talk to, which is a migration and not
// an abstraction. Until somebody does that work, this stays here and stays
// honest about what it is.
type VectorBucketProvisioner interface {
	// EnsureVectorBucket creates or returns a vector bucket. Idempotent.
	EnsureVectorBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error)

	// DeleteVectorBucket removes one. Idempotent.
	DeleteVectorBucket(ctx context.Context, ref compute.Ref) error

	// Grant gives a workload identity access to the bucket.
	Grant(ctx context.Context, resource compute.Ref, identity compute.Ref, level compute.AccessLevel) error

	// Revoke removes that access. Idempotent.
	Revoke(ctx context.Context, resource compute.Ref, identity compute.Ref) error

	// DescribeGrant reports the access identity has, as
	// [TableBucketProvisioner.DescribeGrant] does and for the same reason.
	DescribeGrant(ctx context.Context, resource compute.Ref, identity compute.Ref) (*compute.GrantInfo, error)
}

// ExternalPrincipal identifies something outside this platform's trust domain
// that should be allowed to reach a resource.
//
// Every field is caller-supplied configuration. There is no default, no
// built-in registry of known partners, and no code path that fills any of this
// in — the source system hardcodes three real cross-account role ARNs as
// constants (bucket.go:508-513), and that is precisely the pattern this type
// exists to replace.
type ExternalPrincipal struct {
	// ID identifies the principal in the provider's own vocabulary — an IAM
	// role ARN on AWS, a service-account email elsewhere. Opaque to apphub:
	// it is passed through to the provider and never parsed.
	ID string

	// Constraints are agreed correlation values the external party must present
	// when assuming the granted access. AWS's external ID is the canonical
	// example.
	//
	// They are deliberately **not** secret material and are not typed as such.
	// An external ID is documented by AWS as not-secret: its purpose is to stop
	// a confused deputy — a third party that holds access to many tenants
	// being tricked into using it on the wrong one — not to authenticate the
	// caller. Typing these as [compute.SecretValue] would claim a property they
	// do not have and would push callers toward handling them as credentials,
	// which is both wasted ceremony and a misleading signal in an audit.
	//
	// The not-secret property is corroborated by the producing system, not
	// inferred from AWS's documentation alone: ConductorOne serves the value
	// from an API that requires only a viewer role, and renders it in its own
	// admin UI in plaintext with a copy-to-clipboard control. Nobody puts a copy
	// button on credential material.
	//
	// At least one is required. A cross-domain grant constrained only by the
	// principal lets in every other tenant reachable through that principal,
	// which is the failure mode the source system's own comment warns about
	// (bucket.go:645-652). See [ExternalAccessGranter.GrantExternal] for the
	// other half of that rule, which concerns a grant that already exists.
	//
	// Plural per grant, singular per tenant. ConductorOne issues one external ID
	// per tenant -- the request carries no parameters, so there is nothing to
	// vary by -- and the source system's list is plural because it allowlists
	// *several tenants* on one application's role (MaxC1ExternalIDs = 10,
	// bucket.go:536). So a ten-element list means ten tenants share the
	// resource, not ten values for one tenant. Do not collapse this to a scalar.
	//
	// A flow with no correlation value is not a grant with an empty list; it is
	// not a grant. ConductorOne also has AWS-shaped integrations that
	// authenticate with static access keys rather than role assumption, and
	// those never reach this port: the credential *is* the identity, so there is
	// no external principal for a resource policy to name. Somebody routing one
	// of those through GrantExternal will meet the refusal above, and the
	// correct response is to keep refusing.
	Constraints []string
}

// ExternalAccessGranter grants a principal outside this platform's trust domain
// access to a resource inside it.
//
// # Portability: cross-domain trust has no portable model
//
// Cross-account role assumption with an external-ID condition is an AWS
// mechanism. The nearest equivalents elsewhere — workload identity federation,
// signed URLs, cross-tenant app registrations — differ in what the external
// party presents, what apphub has to configure, and what can be revoked. There
// is no shared vocabulary to abstract over.
//
// # Scope
//
// No core deploy path calls this, and no *production* provider in this
// repository implements it -- compute/fake does, and drives it. It exists so
// that an optional integration which needs cross-domain sharing has a seam to
// reach a provider through without importing one, and without that
// integration's requirements leaking into the core object-store contract.
//
// # Which integration, precisely
//
// The prospective consumer is the source system's ConductorOne *datasource
// binding*: EnsureC1DatasourceRole (bucket.go:668-767) creates a cross-account
// IAM trust so that vendor's product can read an application's bucket as an
// external datasource. That feature is excluded from v1 -- see
// docs/decisions/usoss-13-cross-domain-object-access-is-not-ported.md -- and
// will arrive, if it arrives, as its own ticket with its own review.
//
// It is *not* the ConductorOne credential provider in credentials/c1. An earlier
// version of this comment said it was, and that was wrong: credential vending is
// an outbound HTTPS call to a tenant API -- mint, get and revoke a
// service-principal credential -- which touches no object store and has nothing
// to grant anyone access to. credentials/c1 has zero dependency on package
// compute, tests included. Two different ConductorOne integrations, and only the
// unported one needs this seam.
//
// So this port has no *production* implementation today, which does not make it
// inert. compute/fake implements it, asserts so at compile time, and drives
// grant and revoke in its own tests -- including the refusal below -- which
// makes it the reference for this contract rather than a stand-in. And the
// conformance suite requires every provider that does *not* document the port
// to refuse the lookup legibly, so a caller cannot reach a non-portable port a
// provider never promised.
//
// The integration supplies the principals. AppHub ships none.
type ExternalAccessGranter interface {
	// GrantExternal allows principal the stated access to resource, replacing
	// any previous external grant to the same principal. Idempotent.
	//
	// A grant carrying no constraints must be refused, and the refusal must not
	// mutate anything: see [ExternalPrincipal.Constraints]. An error return that
	// also deletes a grant is a worse contract than either half of it.
	//
	// That refusal is necessary and not sufficient, and the gap it leaves is the
	// one that leaks in practice. A configuration edit is how a constraint list
	// becomes empty, so the realistic path to an unpinned grant is not a call
	// with an empty list -- it is a grant that was correctly pinned yesterday
	// and that the configuration no longer names. No creation-time check sits on
	// that path.
	//
	// Closing it is the reconciling caller's obligation and not this method's. A
	// per-principal call cannot see that a principal has vanished from a set it
	// was never given, so the layer holding desired state must call
	// RevokeExternal for a principal it no longer intends to grant. The source
	// system closes the gap because its equivalent *is* a reconciler over the
	// whole set: with no trust statements left it deletes the role rather than
	// leaving an unpinned one (bucket.go:681-698). That is the shape a caller of
	// this interface has to supply for itself, and it is the reason the
	// obligation is written down here rather than assumed.
	//
	// The obligation stays the caller's. What it no longer has to do is track the
	// standing set by memory: [ExternalAccessGranter.ExternalGrants] enumerates
	// what is actually there, so a reconciler can compare its desired set against
	// the real one instead of against its own record of what it believes it wrote.
	// A record of intent cannot show a grant somebody else made, or one this
	// platform made and lost track of, and those are the two grants that outlive
	// a configuration edit.
	GrantExternal(ctx context.Context, resource compute.Ref, principal ExternalPrincipal, level compute.AccessLevel) error

	// RevokeExternal removes principal's access. Idempotent.
	//
	// A provider must refuse, with [compute.ErrNotOwned], to revoke or mutate a
	// grant it did not create. Grants live on named resources whose names
	// derive from mutable application names, so a collision is possible, and
	// deleting a stranger's trust relationship is not a recoverable mistake —
	// the source system guards exactly this with an ownership tag check
	// (bucket.go:829-853) and any implementation must do the same.
	RevokeExternal(ctx context.Context, resource compute.Ref, principal ExternalPrincipal) error

	// ExternalGrants reports every external grant standing on resource.
	//
	// [compute.ErrNotFound] when there is no such resource, [compute.ErrForeignRef]
	// for a Ref this provider did not issue. A resource with no external grants is
	// an empty slice and a nil error: "nobody outside the trust domain can reach
	// this" is an answer, and it is the answer a reconciler most needs to be able
	// to trust.
	//
	// # Why this enumerates where [compute.Granter.DescribeGrant] takes a pair
	//
	// Because the gap it has to close is a gap a per-principal call cannot see,
	// and GrantExternal's comment above says so in as many words: "a per-principal
	// call cannot see that a principal has vanished from a set it was never
	// given". The realistic path to an unpinned cross-domain grant is not a call
	// with an empty constraint list — that is refused — it is a grant that was
	// correctly pinned yesterday and that the configuration no longer names. A
	// caller holding desired state can only find that by comparing its set
	// against the set that stands, so the read-back has to be the set.
	//
	// The core [compute.Granter] cannot do this and says why: its substrates
	// store a grant on the identity, so enumerating a resource's grants means
	// enumerating every identity. Here the storage is the other way round — a
	// cross-domain grant is a *resource* policy, which is the specific reason
	// compute/aws refuses to implement this port at all (see [ExternalPrincipal]
	// and compute/aws/ext.go) — so the resource is exactly what the substrate
	// holds the whole set on. The asymmetry between the two read-backs is the
	// asymmetry between where the two kinds of grant live, not a style drift.
	//
	// # Every grant, not only ours
	//
	// A provider reports what it can see, and marks ownership in
	// [ExternalGrant.Managed] rather than filtering. Returning only this
	// platform's own grants would make a foreign principal with standing access
	// invisible to the one call whose purpose is to answer "who outside this
	// trust domain can reach this resource" — and it would hide precisely the
	// collision RevokeExternal's [compute.ErrNotOwned] exists for. The
	// determination is one a provider already has to make on every
	// RevokeExternal, so no provider is being asked for a fact it does not have.
	ExternalGrants(ctx context.Context, resource compute.Ref) ([]ExternalGrant, error)
}

// ExternalGrant is one standing cross-domain grant, as the provider holds it.
//
// It carries the stored state rather than the request that produced it. That
// distinction is the whole value: compute/fake asserts replacement, constraint
// preservation and last-write-wins against its own private store today, because
// nothing portable could observe them, and a provider whose RevokeExternal did
// nothing at all passed the conformance suite and the entire fake package. The
// suite can now check those against any implementation of this port.
type ExternalGrant struct {
	// Principal is the principal the grant names, with the constraints that
	// stand — not the ones a caller last passed.
	//
	// The constraint list is here in full and deliberately: "preservation of
	// every constraint, so storing N copies of the first conforms" was one of the
	// seven properties recorded as unverifiable for this port, and a count would
	// not have caught it.
	Principal ExternalPrincipal

	// Level is the access that stands.
	Level compute.AccessLevel

	// Managed reports whether this platform created the grant.
	//
	// False means somebody else did, and it is the flag a caller must consult
	// before revoking: RevokeExternal refuses a grant it did not create with
	// [compute.ErrNotOwned], so a reconciler that treats every standing grant as
	// its own to remove learns that one call at a time. Reported rather than
	// filtered on — see [ExternalAccessGranter.ExternalGrants].
	Managed bool
}

// TableBuckets returns store's [TableBucketProvisioner], or an error that wraps
// [compute.ErrUnsupported].
//
// The three lookup helpers below are the supported way to reach an ext port.
// They exist so the failure is uniform and so a caller cannot write a bare type
// assertion that panics or, worse, one with a discarded `ok` that leaves a nil
// interface to be called later.
//
// Nothing stops a package that may import ext from asserting the interface
// directly — that is a property of Go, not a gap that more prose closes. What
// is enforced mechanically is *who may import this package at all*: the
// "ext-is-optional" rule in internal/boundary limits it to the short allowlist
// recorded there, so growing the set of packages that can reach an AWS-shaped
// port is a build failure until somebody edits that list in a reviewable diff.
func TableBuckets(providerName string, store compute.ObjectStore) (TableBucketProvisioner, error) {
	if p, ok := store.(TableBucketProvisioner); ok {
		return p, nil
	}
	return nil, &ErrNotImplemented{Provider: providerName, Port: "ext.TableBucketProvisioner"}
}

// VectorBuckets returns store's [VectorBucketProvisioner], or an error that
// wraps [compute.ErrUnsupported].
func VectorBuckets(providerName string, store compute.ObjectStore) (VectorBucketProvisioner, error) {
	if p, ok := store.(VectorBucketProvisioner); ok {
		return p, nil
	}
	return nil, &ErrNotImplemented{Provider: providerName, Port: "ext.VectorBucketProvisioner"}
}

// ExternalAccess returns store's [ExternalAccessGranter], or an error that
// wraps [compute.ErrUnsupported].
func ExternalAccess(providerName string, store compute.ObjectStore) (ExternalAccessGranter, error) {
	if g, ok := store.(ExternalAccessGranter); ok {
		return g, nil
	}
	return nil, &ErrNotImplemented{Provider: providerName, Port: "ext.ExternalAccessGranter"}
}
