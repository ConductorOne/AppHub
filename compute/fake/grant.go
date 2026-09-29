// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"

	"github.com/conductorone/apphub/compute"
)

// granter implements [compute.Granter] for the ports whose substrate authorises
// by workload identity — image repositories, buckets, and key-value tables.
//
// It is deliberately not available on the relational port. Access to a
// relational database is granted with SQL, and there is no general mapping from
// a substrate workload identity to a SQL principal, so a provider offering only
// managed Postgres would be forced to implement a method whose only honest
// answer is "unsupported" (design doc §3.5).
type granter struct {
	p    *Provider
	kind compute.Kind
	// exists reports whether the resource is present. Callers hold no lock.
	exists func(id string) bool
}

// Grant implements [compute.Granter].
func (g granter) Grant(_ context.Context, resource compute.Ref, identity compute.Ref, level compute.AccessLevel) error {
	// The port carries Granter because the substrate can express the grant; the
	// capability says whether this configuration does. A provider that does not
	// advertise it must refuse, naming the capability the caller should have
	// checked rather than the port's own — an operator who reads the wrong
	// capability reconfigures the wrong thing.
	if !g.p.caps.Has(compute.CapWorkloadGrants) {
		return &compute.UnsupportedError{
			Provider:   g.p.cfg.Name,
			Capability: compute.CapWorkloadGrants,
			Detail: "this provider is not configured to authorise its workload identities " +
				"against the resources it provisions",
		}
	}
	resourceID, subjectID, err := g.pair(resource, identity)
	if err != nil {
		return err
	}
	if err := g.p.injected(OpGrant, g.kind); err != nil {
		return err
	}
	switch level {
	case compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin:
	default:
		return fmt.Errorf("fake: access level %q is not one this interface defines: %w",
			level, compute.ErrInvalidSpec)
	}

	g.p.store.mu.Lock()
	defer g.p.store.mu.Unlock()
	key := grantKey{resource: resourceID, subject: subjectID}
	if g.p.broken(DefectGrantIsAdditive) {
		// Keeps the widest level ever granted, so narrowing does nothing. This
		// is what "add a second policy statement" looks like from the outside.
		if old, ok := g.p.store.grants[key]; ok && rank(old) > rank(level) {
			return nil
		}
	}
	if g.p.broken(DefectGrantClobbersOtherResources) {
		// Keyed on the identity alone: this grant replaces every grant the
		// identity holds anywhere. This is what one inline policy name per
		// provider looks like from the outside, and it reports success.
		for k := range g.p.store.grants {
			if k.subject == subjectID {
				delete(g.p.store.grants, k)
			}
		}
	}
	// One entry per (resource, identity) pair: last write wins on level, so
	// granting read after read-write narrows rather than accumulating.
	g.p.store.grants[key] = level
	return nil
}

// Revoke implements [compute.Granter].
func (g granter) Revoke(_ context.Context, resource compute.Ref, identity compute.Ref) error {
	resourceID, subjectID, err := g.pair(resource, identity)
	if err != nil {
		return err
	}
	if err := g.p.injected(OpRevoke, g.kind); err != nil {
		return err
	}
	g.p.store.mu.Lock()
	defer g.p.store.mu.Unlock()
	key := grantKey{resource: resourceID, subject: subjectID}
	if _, ok := g.p.store.grants[key]; !ok {
		if g.p.broken(DefectRevokeAbsentFails) {
			return fmt.Errorf("fake: %s has no grant to %s: %w", resource, identity, compute.ErrNotFound)
		}
		return nil
	}
	if g.p.broken(DefectRevokeDoesNothing) {
		// Reports success and removes nothing. The grant was found above, so this
		// is not the absent-grant path -- it is a revoke that had something to do
		// and did not do it.
		return nil
	}
	if g.p.broken(DefectGrantClobbersOtherResources) {
		// The other half: a revoke that removes the identity's grant everywhere,
		// which is what deleting a provider-wide policy name does.
		for k := range g.p.store.grants {
			if k.subject == subjectID {
				delete(g.p.store.grants, k)
			}
		}
		return nil
	}
	delete(g.p.store.grants, key)
	return nil
}

// DescribeGrant implements [compute.Granter].
//
// It reads the store, which is what makes this package's grant defects visible
// through the interface rather than only through a harness method.
// [DefectGrantIsAdditive] keeps the widest level ever granted, so a narrowing
// Grant followed by this reports the wide level and the round-trip check fails —
// which is the point: before the read-back, that defect was observable only by
// performing a data-plane write.
func (g granter) DescribeGrant(_ context.Context, resource compute.Ref, identity compute.Ref) (*compute.GrantInfo, error) {
	// The capability gate comes first, as it does in Grant, and for the same
	// reason: a provider that cannot authorise its identities has nothing to
	// report, and an operator reading the refusal must be sent to the capability
	// that is missing rather than to this port's own.
	if !g.p.caps.Has(compute.CapWorkloadGrants) {
		return nil, &compute.UnsupportedError{
			Provider:   g.p.cfg.Name,
			Capability: compute.CapWorkloadGrants,
			Detail: "this provider is not configured to authorise its workload identities " +
				"against the resources it provisions, so it holds no grants to describe",
		}
	}
	resourceID, subjectID, err := g.pair(resource, identity)
	if err != nil {
		return nil, err
	}
	if err := g.p.injected(OpDescribe, g.kind); err != nil {
		return nil, err
	}
	g.p.store.mu.Lock()
	defer g.p.store.mu.Unlock()
	level, ok := g.p.store.grants[grantKey{resource: resourceID, subject: subjectID}]
	if !ok {
		return nil, fmt.Errorf("fake: %s holds no grant to %s: %w", resource, identity, compute.ErrNotFound)
	}
	return &compute.GrantInfo{Resource: resource, Identity: identity, Level: level}, nil
}

func (g granter) pair(resource compute.Ref, identity compute.Ref) (string, string, error) {
	resourceID, err := g.p.resolve(resource, g.kind)
	if err != nil {
		return "", "", err
	}
	if !g.exists(resourceID) {
		return "", "", fmt.Errorf("fake: no %s %s to grant access to: %w", g.kind, resource, compute.ErrNotFound)
	}
	subjectID, err := g.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return "", "", err
	}
	g.p.store.mu.Lock()
	_, ok := g.p.store.identities[subjectID]
	g.p.store.mu.Unlock()
	if !ok {
		return "", "", fmt.Errorf("fake: no workload identity %s: %w", identity, compute.ErrNotFound)
	}
	return resourceID, subjectID, nil
}

func rank(l compute.AccessLevel) int {
	switch l {
	case compute.AccessRead:
		return 1
	case compute.AccessReadWrite:
		return 2
	case compute.AccessAdmin:
		return 3
	default:
		return 0
	}
}

// permits reports whether the identity may perform the operation on the
// resource. Callers hold no lock.
//
// This is the substrate's own access check, and it exists so that a grant can be
// verified behaviourally — read succeeds, write fails — rather than by
// inspecting a generated policy document, which would only ever test one
// provider's policy language.
func (s *Store) permits(resourceID, subjectID string, write bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	level, ok := s.grants[grantKey{resource: resourceID, subject: subjectID}]
	if !ok {
		return false
	}
	if write {
		return rank(level) >= rank(compute.AccessReadWrite)
	}
	return rank(level) >= rank(compute.AccessRead)
}

var _ compute.Granter = granter{}

// granted reports whether a grant exists for the pair.
//
// It exists for DefectPullGrantNotIdempotent, which has to fail the *second*
// grant rather than the first: a defect that fires on call one cannot show that
// a check observes call two.
func (p *Provider) granted(resource, identity compute.Ref) bool {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	_, ok := p.store.grants[grantKey{resource: resource.ID, subject: identity.ID}]
	return ok
}
