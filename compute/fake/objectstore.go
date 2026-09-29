// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// objectStore implements [compute.ObjectStore]. A bucket is a synchronous
// resource: the source system creates and hardens one with no polling loop
// (bucket.go:217-288), and it is usable when the call returns.
type objectStore struct{ p *Provider }

// EnsureBucket implements [compute.ObjectStore].
func (o objectStore) EnsureBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	return o.ensure(spec, compute.ObjectClassStandard, "")
}

// ensure is shared by the core bucket path and the ext bucket types. kind is the
// internal namespace prefix, empty for a plain bucket.
func (o objectStore) ensure(spec compute.BucketSpec, class compute.ObjectClass, prefix string) (*compute.Bucket, error) {
	if err := o.p.validateName("bucket", spec.Name); err != nil {
		return nil, err
	}

	if prefix == "" {
		var err error
		class, err = o.resolveClass(spec)
		if err != nil {
			return nil, err
		}
	}

	effective := spec
	effective.Class = class
	if class != compute.ObjectClassZonal {
		effective.Zone = ""
	}

	key := spec.Name
	if prefix != "" {
		key = prefix + "/" + spec.Name
	}
	rec, _, err := ensureRecord(o.p, o.p.store.buckets, compute.KindBucket, key, effective, false, nil)
	if err != nil {
		return nil, err
	}

	o.p.store.mu.Lock()
	if _, ok := o.p.store.objects[rec.ref.ID]; !ok {
		o.p.store.objects[rec.ref.ID] = map[string][]byte{}
	}
	o.p.store.mu.Unlock()

	return o.bucket(rec, prefix), nil
}

// resolveClass applies the zonal capability rule.
//
// A provider without [compute.CapObjectStoreZonal] must refuse rather than hand
// back a standard bucket: the caller asked for a latency property, and quietly
// substituting one satisfies the type signature while breaking the reason they
// asked.
func (o objectStore) resolveClass(spec compute.BucketSpec) (compute.ObjectClass, error) {
	switch spec.Class {
	case "", compute.ObjectClassStandard:
		if spec.Zone != "" {
			return "", fmt.Errorf("fake: bucket %q names zone %q but is not zonal: %w",
				spec.Name, spec.Zone, compute.ErrInvalidSpec)
		}
		return compute.ObjectClassStandard, nil
	case compute.ObjectClassZonal:
		if !o.p.caps.Has(compute.CapObjectStoreZonal) {
			if o.p.broken(DefectSilentZonalFallback) {
				return compute.ObjectClassStandard, nil
			}
			return "", fmt.Errorf("fake: bucket %q asks for a zonal bucket, which requires %q: %w",
				spec.Name, compute.CapObjectStoreZonal, compute.ErrUnsupported)
		}
		if spec.Zone == "" {
			return "", fmt.Errorf("fake: bucket %q is zonal but names no zone: %w",
				spec.Name, compute.ErrInvalidSpec)
		}
		for _, z := range o.p.cfg.Zones {
			if z == spec.Zone {
				return compute.ObjectClassZonal, nil
			}
		}
		return "", fmt.Errorf("fake: bucket %q names zone %q, which this provider does not offer "+
			"(have %s): %w", spec.Name, spec.Zone, strings.Join(o.p.cfg.Zones, ", "), compute.ErrInvalidSpec)
	default:
		return "", fmt.Errorf("fake: bucket %q names storage class %q: %w",
			spec.Name, spec.Class, compute.ErrInvalidSpec)
	}
}

// DescribeBucket implements [compute.ObjectStore].
func (o objectStore) DescribeBucket(_ context.Context, ref compute.Ref) (*compute.Bucket, error) {
	rec, err := lookup(o.p, o.p.store.buckets, ref, compute.KindBucket)
	if err != nil {
		return nil, err
	}
	prefix := ""
	if idx := strings.Index(rec.name, "/"); idx >= 0 {
		prefix = rec.name[:idx]
	}
	return o.bucket(rec, prefix), nil
}

// DeleteBucket implements [compute.ObjectStore].
//
// This provider does not empty a non-empty bucket: it deletes the bucket and
// the objects in it go with it, because there is nowhere else for in-memory
// state to live. A real provider must document its own behaviour — the
// interface deliberately does not promise they agree, and a caller that wants
// the objects gone on every provider calls [objectStore.EmptyBucket] first.
func (o objectStore) DeleteBucket(_ context.Context, ref compute.Ref) error {
	return deleteSync(o.p, o.p.store.buckets, ref, compute.KindBucket)
}

// EmptyBucket implements [compute.ObjectStore].
//
// The data plane is one map per bucket and has no versions, so emptying it is
// replacing that map. The bucket itself, and every grant on it, stays: emptying
// is not deleting, and a caller that conflated the two would find its grants
// gone on this provider and present on every real one.
//
// Fault injection is the delete's, because this is a delete -- of the data
// rather than the resource -- and a check that arms a delete failure is asking
// what a teardown does when removal fails.
func (o objectStore) EmptyBucket(_ context.Context, ref compute.Ref) error {
	id, err := o.p.resolve(ref, compute.KindBucket)
	if err != nil {
		return err
	}
	if err := o.p.injected(OpDelete, compute.KindBucket); err != nil {
		return err
	}
	o.p.store.mu.Lock()
	defer o.p.store.mu.Unlock()
	rec, ok := o.p.store.buckets[id]
	if !ok {
		return nil
	}
	if !rec.owned {
		return fmt.Errorf("fake: bucket %s exists and was not created by this platform, so its "+
			"objects are not this platform's to delete: %w", ref, compute.ErrNotOwned)
	}
	o.p.store.objects[id] = map[string][]byte{}
	return nil
}

func (o objectStore) bucket(rec *record[compute.BucketSpec], prefix string) *compute.Bucket {
	o.p.store.mu.Lock()
	defer o.p.store.mu.Unlock()
	// The provider's namespace rules apply, so the actual name differs from the
	// requested one. That is deliberate: a caller that assumed otherwise would
	// break against a real substrate, and the interface says to use what came
	// back.
	name := o.p.cfg.Name + "-" + strings.ReplaceAll(rec.name, "/", "-")
	scheme := "fake"
	if prefix != "" {
		scheme = "fake-" + prefix
	}
	return &compute.Bucket{
		Ref:   rec.ref,
		Name:  name,
		Class: rec.spec.Class,
		URI:   scheme + "://" + name,
		Spec:  deepCopy(rec.spec),
	}
}

// Grant implements [compute.Granter].
func (o objectStore) Grant(ctx context.Context, resource compute.Ref, identity compute.Ref, level compute.AccessLevel) error {
	return o.granter().Grant(ctx, resource, identity, level)
}

// Revoke implements [compute.Granter].
func (o objectStore) Revoke(ctx context.Context, resource compute.Ref, identity compute.Ref) error {
	return o.granter().Revoke(ctx, resource, identity)
}

// DescribeGrant implements [compute.Granter].
func (o objectStore) DescribeGrant(ctx context.Context, resource compute.Ref, identity compute.Ref) (*compute.GrantInfo, error) {
	return o.granter().DescribeGrant(ctx, resource, identity)
}

func (o objectStore) granter() granter {
	return granter{p: o.p, kind: compute.KindBucket, exists: func(id string) bool {
		o.p.store.mu.Lock()
		defer o.p.store.mu.Unlock()
		_, ok := o.p.store.buckets[id]
		return ok
	}}
}

var _ compute.ObjectStore = objectStore{}

// extObjectStore is an object store on a substrate that also has the
// non-portable bucket types.
//
// Whether a provider implements an ext port is a property of its *type*, because
// that is how [ext.TableBuckets] and its siblings find it. Two concrete types is
// therefore the honest way to model "this configuration has the feature and that
// one does not", and it is what lets the conformance suite check that a lookup
// succeeds exactly when the provider says it should.
type extObjectStore struct{ objectStore }

// EnsureTableBucket implements [ext.TableBucketProvisioner].
func (e extObjectStore) EnsureTableBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if spec.Class != "" && spec.Class != compute.ObjectClassStandard {
		return nil, fmt.Errorf("fake: a table bucket has no storage class, and %q was named: %w",
			spec.Class, compute.ErrInvalidSpec)
	}
	return e.ensure(spec, compute.ObjectClassStandard, "table")
}

// DeleteTableBucket implements [ext.TableBucketProvisioner].
func (e extObjectStore) DeleteTableBucket(ctx context.Context, ref compute.Ref) error {
	return e.DeleteBucket(ctx, ref)
}

// EnsureVectorBucket implements [ext.VectorBucketProvisioner].
func (e extObjectStore) EnsureVectorBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if spec.Class != "" && spec.Class != compute.ObjectClassStandard {
		return nil, fmt.Errorf("fake: a vector bucket has no storage class, and %q was named: %w",
			spec.Class, compute.ErrInvalidSpec)
	}
	return e.ensure(spec, compute.ObjectClassStandard, "vector")
}

// DeleteVectorBucket implements [ext.VectorBucketProvisioner].
func (e extObjectStore) DeleteVectorBucket(ctx context.Context, ref compute.Ref) error {
	return e.DeleteBucket(ctx, ref)
}

// GrantExternal implements [ext.ExternalAccessGranter].
//
// AppHub ships no principals: everything about the principal is
// caller-supplied, and this provider has no registry of known partners to
// consult.
func (e extObjectStore) GrantExternal(_ context.Context, resource compute.Ref, principal ext.ExternalPrincipal, level compute.AccessLevel) error {
	id, err := e.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return err
	}
	if principal.ID == "" {
		return fmt.Errorf("fake: an external principal needs an identifier: %w", compute.ErrInvalidSpec)
	}
	if len(principal.Constraints) == 0 {
		// A cross-domain grant constrained only by the principal lets in every
		// other tenant reachable through that principal.
		return fmt.Errorf("fake: external grant to %q has no constraints: %w",
			principal.ID, compute.ErrInvalidSpec)
	}
	e.p.store.mu.Lock()
	defer e.p.store.mu.Unlock()
	if _, ok := e.p.store.buckets[id]; !ok {
		return fmt.Errorf("fake: no bucket %s: %w", resource, compute.ErrNotFound)
	}
	key := grantKey{resource: id, subject: principal.ID}
	if existing, ok := e.p.store.external[key]; ok && !existing.owned {
		return fmt.Errorf("fake: an external grant to %q on %s exists and was not created by this "+
			"platform: %w", principal.ID, resource, compute.ErrNotOwned)
	}
	e.p.store.external[key] = externalGrant{
		level:       level,
		constraints: append([]string(nil), principal.Constraints...),
		owned:       true,
	}
	return nil
}

// RevokeExternal implements [ext.ExternalAccessGranter].
func (e extObjectStore) RevokeExternal(_ context.Context, resource compute.Ref, principal ext.ExternalPrincipal) error {
	id, err := e.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return err
	}
	e.p.store.mu.Lock()
	defer e.p.store.mu.Unlock()
	key := grantKey{resource: id, subject: principal.ID}
	existing, ok := e.p.store.external[key]
	if !ok {
		return nil
	}
	if !existing.owned {
		// Deleting a stranger's trust relationship is not a recoverable
		// mistake, and these grants live on names derived from mutable
		// application names, so a collision is possible.
		return fmt.Errorf("fake: the external grant to %q on %s was not created by this platform: %w",
			principal.ID, resource, compute.ErrNotOwned)
	}
	if e.p.broken(DefectRevokeExternalDoesNothing) {
		// Success, and the grant stands. Placed after the ownership refusal and
		// before the delete, so the defect is exactly "the removal did not
		// happen" -- it does not also weaken the ErrNotOwned guard, which is a
		// different property with its own contract.
		return nil
	}
	delete(e.p.store.external, key)
	return nil
}

// ExternalGrants implements [ext.ExternalAccessGranter].
//
// The set is what the store holds, foreign grants included, with ownership on the
// [ext.ExternalGrant.Managed] flag rather than expressed by omission. Filtering
// them out here would make this package unable to drive the [compute.ErrNotOwned]
// half of RevokeExternal's contract through the interface, which is one of the
// seven properties USOSS-73 records as previously unobservable.
//
// Ordered by principal, because an unordered read-back invites a caller to depend
// on map iteration order and invites a check to pass on a lucky run.
func (e extObjectStore) ExternalGrants(_ context.Context, resource compute.Ref) ([]ext.ExternalGrant, error) {
	id, err := e.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return nil, err
	}
	e.p.store.mu.Lock()
	defer e.p.store.mu.Unlock()
	if _, ok := e.p.store.buckets[id]; !ok {
		return nil, fmt.Errorf("fake: no bucket %s: %w", resource, compute.ErrNotFound)
	}
	// Empty and non-nil: "nothing outside the trust domain can reach this" is an
	// answer a reconciler acts on, and a nil slice reads as one a caller might
	// mistake for an unanswered question.
	out := []ext.ExternalGrant{}
	for key, grant := range e.p.store.external {
		if key.resource != id {
			continue
		}
		out = append(out, ext.ExternalGrant{
			Principal: ext.ExternalPrincipal{
				ID: key.subject,
				// Copied, not aliased. A read-back that shares storage with the
				// store lets a caller mutate provider state by appending to what
				// it was handed -- the hazard copyExternalGrant exists for, on
				// the one path that leaves this package.
				Constraints: append([]string(nil), grant.constraints...),
			},
			Level:   grant.level,
			Managed: grant.owned,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal.ID < out[j].Principal.ID })
	return out, nil
}

var (
	_ ext.TableBucketProvisioner  = extObjectStore{}
	_ ext.VectorBucketProvisioner = extObjectStore{}
	_ ext.ExternalAccessGranter   = extObjectStore{}
)
