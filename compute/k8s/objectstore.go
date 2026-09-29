// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"fmt"

	"github.com/conductorone/apphub/compute"
)

// objectStore implements [compute.ObjectStore] against the S3-compatible
// service the operator configured.
//
// Kubernetes has no object storage, so "a Kubernetes provider's object store"
// means MinIO, Ceph RGW, or a cloud bucket service — which the design document
// says, and which this implementation confirms is workable. The port's embedded
// [compute.Granter] is implementable here for one specific reason: an
// S3-compatible store can federate the cluster's OIDC issuer and authorise the
// projected ServiceAccount token directly, so "grant this identity read access"
// really is a policy write against the identity. Contrast [imageRegistry],
// where the same embedded interface has no honest implementation.
//
// A store that does *not* federate the cluster is a different matter, and this
// provider refuses the grant rather than minting a static access key behind the
// caller's back.
//
// # Ownership here is account-scoped, and an operator has to know that
//
// This port decides whether a bucket is its own by reading a **bucket tag**. S3
// offers no other per-bucket metadata, and the marker has to be a value the
// provider can recompute in order to recognise buckets it created, so it is
// reproducible by construction. The consequence, stated here rather than only in
// the decision record because this is where an operator meets it:
//
//	Anything in the account that can tag a bucket can present itself as this
//	platform, and a bucket it tags with the marker will be treated as ours.
//
// This is not a defect in the classifier and no classifier can recover from it. It
// is a property of using resource tags as an ownership marker at all, which is
// what ownership-as-a-property-of-access means on a substrate with no other place
// to put the marker. Two things follow for whoever operates this:
//
//   - The ownership boundary is the **account's own tagging permissions**. Restrict
//     who may tag buckets in the account and the boundary holds; do not read
//     ownership refusals as protection against a co-tenant who can tag.
//   - A **cross-tenant deployment** — one where mutually untrusted callers share
//     the configured store's account — is outside what this port can enforce.
//     Separate accounts, not separate tags.
//
// [BucketClaim] carries the mechanics and the untagged-bucket concession that sits
// alongside this.
type objectStore struct{ p *Provider }

var _ compute.ObjectStore = (*objectStore)(nil)

// bucketName applies the store's namespace rules. S3-compatible names are
// lowercase DNS labels of at least three characters, which is tighter than the
// interface promises, so short names are padded deterministically.
func bucketName(logical string) string {
	name := sanitize("", logical)
	for len(name) < 3 {
		name += "-b"
	}
	return name
}

func (s *objectStore) EnsureBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	class := spec.Class
	if class == "" {
		class = compute.ObjectClassStandard
	}
	switch class {
	case compute.ObjectClassStandard:
		if spec.Zone != "" {
			return nil, fmt.Errorf("%w: a zone is only meaningful for %q",
				compute.ErrInvalidSpec, compute.ObjectClassZonal)
		}
	case compute.ObjectClassZonal:
		// No S3-compatible store surveyed offers a single-zone class, and
		// quietly returning a standard bucket would satisfy the signature while
		// breaking the latency guarantee the caller asked for.
		return nil, &compute.UnsupportedError{
			Provider:   s.p.name,
			Capability: compute.CapObjectStoreZonal,
			Detail: "object store " + s.p.cfg.ObjectStore.Endpoint + " has no single-zone bucket " +
				"class; returning a standard bucket would break the latency guarantee that is the " +
				"only reason to ask for a zonal one",
		}
	default:
		return nil, fmt.Errorf("%w: %q is not an object class this interface defines",
			compute.ErrInvalidSpec, spec.Class)
	}

	name := bucketName(spec.Name)
	existing, found, err := s.p.sub.Objects.GetBucket(ctx, name)
	if err != nil {
		return nil, s.p.storeError(err)
	}
	// The refusal is on Claimable rather than on "is it ours", because an
	// existing bucket carrying no ownership record at all is claimable: it is
	// most likely one this provider created and failed to tag, and refusing it
	// makes that failure permanent. [BucketClaim] carries the reasoning and the
	// residual risk.
	//
	// This check and the one inside [S3ObjectStore.PutBucket] now read the same
	// field from the same classifier. They used to be two authorities that
	// disagreed, and the disagreement was invisible because the correct one was
	// second: this line refused an untagged bucket before PutBucket's assessment
	// ever ran, so a test written at PutBucket passed while the two-Ensure
	// reproduction still failed.
	if found && !existing.Claim.Claimable() {
		return nil, fmt.Errorf("%w: bucket %q exists and is %s, so this provider will not write to it",
			compute.ErrNotOwned, name, existing.Claim)
	}
	if err := s.p.sub.Objects.PutBucket(ctx, BucketState{
		Name:  name,
		Class: class,
		// PublicAccess false is applied, not merely omitted: the store's
		// anonymous-read path checks this flag.
		PublicRead: spec.PublicAccess,
		Labels:     spec.Labels,
		Claim:      ClaimOurs,
	}); err != nil {
		return nil, s.p.storeError(err)
	}
	return s.bucket(name, class, spec), nil
}

func (s *objectStore) DescribeBucket(ctx context.Context, ref compute.Ref) (*compute.Bucket, error) {
	_, name, err := s.p.resolve(ref, compute.KindBucket)
	if err != nil {
		return nil, err
	}
	b, ok, err := s.p.sub.Objects.GetBucket(ctx, name)
	if err != nil {
		return nil, s.p.storeError(err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: bucket %q", compute.ErrNotFound, name)
	}
	return s.bucket(b.Name, b.Class, compute.BucketSpec{
		Name:         b.Name,
		Class:        b.Class,
		PublicAccess: b.PublicRead,
		Labels:       copyLabels(b.Labels),
	}), nil
}

func (s *objectStore) DeleteBucket(ctx context.Context, ref compute.Ref) error {
	_, name, err := s.p.resolve(ref, compute.KindBucket)
	if err != nil {
		return err
	}
	// Objects are left to the store's own lifecycle rules rather than deleted
	// inline: a provider must not silently delete data a caller did not know was
	// there. A caller that wants them gone calls [objectStore.EmptyBucket] first.
	if err := s.p.sub.Objects.DeleteBucket(ctx, name); err != nil {
		return s.p.storeError(err)
	}
	return nil
}

// EmptyBucket implements [compute.ObjectStore].
//
// The refusal is on "is it ours", not on [BucketClaim.Claimable]. An Ensure may
// claim an unclaimed bucket because claiming writes a marker and deletes
// nothing; emptying one would destroy data this platform never marked as its
// own, and nothing about an untagged bucket says whose data it is.
func (s *objectStore) EmptyBucket(ctx context.Context, ref compute.Ref) error {
	_, name, err := s.p.resolve(ref, compute.KindBucket)
	if err != nil {
		return err
	}
	existing, found, err := s.p.sub.Objects.GetBucket(ctx, name)
	if err != nil {
		return s.p.storeError(err)
	}
	if !found {
		return nil
	}
	if existing.Claim != ClaimOurs {
		return fmt.Errorf("%w: bucket %q is %s, so its objects are not this platform's to delete",
			compute.ErrNotOwned, name, existing.Claim)
	}
	if err := s.p.sub.Objects.EmptyBucket(ctx, name); err != nil {
		return s.p.storeError(err)
	}
	return nil
}

func (s *objectStore) bucket(name string, class compute.ObjectClass, spec compute.BucketSpec) *compute.Bucket {
	spec.Name = name
	spec.Class = class
	return &compute.Bucket{
		Ref:   s.p.ref(compute.KindBucket, "", name),
		Name:  name,
		Class: class,
		URI:   s.p.cfg.ObjectStore.URIScheme + "://" + name,
		Spec:  spec,
	}
}

func (s *objectStore) Grant(ctx context.Context, resource, identity compute.Ref, level compute.AccessLevel) error {
	if err := validateLevel(level); err != nil {
		return err
	}
	_, bucket, err := s.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return err
	}
	if !s.p.cfg.ObjectStore.TrustsClusterOIDC {
		return &compute.UnsupportedError{
			Provider: s.p.name,
			// The missing capability, not this port's. The provider has
			// CapObjectStore; what it lacks is the ability to authorise a
			// workload identity against a bucket, and naming the port would
			// send an operator to reconfigure the wrong thing.
			Capability: compute.CapWorkloadGrants,
			Detail: "object store " + s.p.cfg.ObjectStore.Endpoint + " does not federate this " +
				"cluster's OIDC issuer, so there is no principal a ServiceAccount maps to; the " +
				"alternative — minting a static access key and hiding it in a Secret — is a " +
				"credential the caller cannot see or rotate",
		}
	}
	ns, name, err := s.p.identityRef(ctx, identity)
	if err != nil {
		return err
	}
	// Last-write-wins, which is what narrowing requires: a second policy
	// statement would widen instead.
	if err := s.p.sub.Objects.SetPolicy(ctx, bucket, subjectFor(ns, name), level); err != nil {
		return s.p.storeError(err)
	}
	return nil
}

func (s *objectStore) Revoke(ctx context.Context, resource, identity compute.Ref) error {
	_, bucket, err := s.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return err
	}
	ns, name, err := s.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	if err := s.p.sub.Objects.ClearPolicy(ctx, bucket, subjectFor(ns, name)); err != nil {
		return s.p.storeError(err)
	}
	return nil
}

// DescribeGrant reports the access an identity has to a bucket.
//
// The capability refusal is repeated here rather than left to the store, and it
// names [compute.CapWorkloadGrants] for the same reason Grant does: a store that
// does not federate this cluster's issuer holds no grants, so a read that fell
// through to it would report "no grant" — indistinguishable from a bucket that
// genuinely has none, and a caller reconciling on that answer would keep writing
// grants nothing can express. [S3ObjectStore.GetPolicy] makes the same argument
// one layer down.
//
// The identity is resolved rather than fetched from the cluster, as Revoke does
// and Grant does not. Grant needs the ServiceAccount to exist because it is about
// to authorise it; a read is a question about stored policy, and refusing to
// answer it because the subject has since been deleted would hide exactly the
// grant a teardown most needs to find.
func (s *objectStore) DescribeGrant(ctx context.Context, resource, identity compute.Ref) (*compute.GrantInfo, error) {
	_, bucket, err := s.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return nil, err
	}
	if !s.p.cfg.ObjectStore.TrustsClusterOIDC {
		return nil, &compute.UnsupportedError{
			Provider:   s.p.name,
			Capability: compute.CapWorkloadGrants,
			Detail: "object store " + s.p.cfg.ObjectStore.Endpoint + " does not federate this " +
				"cluster's OIDC issuer, so no ServiceAccount maps to a principal it could hold a " +
				"grant for; reporting that a bucket has no grants would be indistinguishable from " +
				"having been able to look",
		}
	}
	ns, name, err := s.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return nil, err
	}
	level, granted, err := s.p.sub.Objects.GetPolicy(ctx, bucket, subjectFor(ns, name))
	if err != nil {
		return nil, s.p.storeError(err)
	}
	if !granted {
		return nil, fmt.Errorf("%w: bucket %q holds no grant for %q",
			compute.ErrNotFound, bucket, subjectFor(ns, name))
	}
	return &compute.GrantInfo{Resource: resource, Identity: identity, Level: level}, nil
}
