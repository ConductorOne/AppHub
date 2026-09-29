// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
)

// identityService implements [compute.IdentityService].
//
// Workload identity is not capability-gated: a provider that can run anything
// must be able to give what it runs an identity. The fake's identities are
// synchronous — there is no phase and no Wait — which matches every real
// substrate's identity object.
type identityService struct{ p *Provider }

// FakeAttestationMethod is the scheme this provider's workloads attest with.
//
// It is [workload.MethodK8sServiceAccount] rather than the AWS scheme on
// purpose. The fake is what most tests run against, so if it attested with
// MethodAWSSTSCallerIdentity every downstream test would be written against the
// AWS scheme and the vocabulary would become structurally privileged again —
// the exact defect the shared contract exists to prevent. A subject shaped like
// a service account also makes it obvious that nothing here calls AWS.
const FakeAttestationMethod = workload.MethodK8sServiceAccount

// EnsureWorkloadIdentity implements [compute.IdentityService].
func (s identityService) EnsureWorkloadIdentity(_ context.Context, spec compute.WorkloadIdentitySpec) (*compute.WorkloadIdentity, error) {
	if err := s.p.validateName("workload identity", spec.Name); err != nil {
		return nil, err
	}
	switch spec.RunsOn {
	case compute.RuntimeContainer, compute.RuntimeFunction:
	default:
		return nil, fmt.Errorf("fake: workload identity %q names runtime %q: %w",
			spec.Name, spec.RunsOn, compute.ErrInvalidSpec)
	}

	placement, err := s.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, fmt.Errorf("fake: workload identity %q: %w", spec.Name, err)
	}

	// The runtime is part of the identity's name because on some substrates an
	// identity is not interchangeable between runtimes. Encoding it here means
	// the same logical name used for a container and for a function yields two
	// identities rather than one that only works in one place.
	//
	// So is the placement, since F3: an identity is scoped to one, and two specs
	// differing only in placement are two identities rather than one that a
	// workload in the wrong place cannot use.
	key := spec.Name + "." + string(spec.RunsOn) + "." + placement
	effective := spec
	effective.Placement = compute.Placement{Name: placement}
	rec, _, err := ensureRecord(s.p, s.p.store.identities, compute.KindWorkloadIdentity, key, effective, false, nil)
	if err != nil {
		return nil, err
	}
	return s.identity(rec), nil
}

// DescribeWorkloadIdentity implements [compute.IdentityService].
func (s identityService) DescribeWorkloadIdentity(_ context.Context, ref compute.Ref) (*compute.WorkloadIdentity, error) {
	rec, err := lookup(s.p, s.p.store.identities, ref, compute.KindWorkloadIdentity)
	if err != nil {
		return nil, err
	}
	return s.identity(rec), nil
}

// DeleteWorkloadIdentity implements [compute.IdentityService].
func (s identityService) DeleteWorkloadIdentity(_ context.Context, ref compute.Ref) error {
	id, err := s.p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	// Every other port's delete goes through deleteSync/deleteAsync, which
	// consult the injected failure; this one is hand-rolled because deleting an
	// identity also revokes its grants, and it did not. So
	// FailNext(OpDelete, KindWorkloadIdentity) was silently ignored, and the
	// substrate-error mapping for the one method every provider has could not be
	// exercised. Found by the USOSS-32 retry gate the first time it drove more
	// than one call.
	if err := s.p.injected(OpDelete, compute.KindWorkloadIdentity); err != nil {
		return err
	}
	s.p.store.mu.Lock()
	defer s.p.store.mu.Unlock()
	if _, ok := s.p.store.identities[id]; !ok {
		if s.p.broken(DefectDeleteNotIdempotent) {
			return fmt.Errorf("fake: no workload identity %s to delete: %w", ref, compute.ErrNotFound)
		}
		return nil
	}
	delete(s.p.store.identities, id)
	// Deleting an identity removes every grant made to it, per the interface.
	for k := range s.p.store.grants {
		if k.subject == id {
			delete(s.p.store.grants, k)
		}
	}
	return nil
}

func (s identityService) identity(rec *record[compute.WorkloadIdentitySpec]) *compute.WorkloadIdentity {
	return &compute.WorkloadIdentity{
		Ref:  rec.ref,
		Spec: deepCopy(rec.spec),
		Attestation: workload.ExpectedAttestation{
			Method: FakeAttestationMethod,
			// A subject shaped like the scheme's, and derived from the identity
			// rather than from anything site-specific. No account, no cluster,
			// no domain.
			Subject:  "system:serviceaccount:" + s.p.cfg.Name + ":" + rec.name,
			Issuer:   "https://issuer.invalid/" + s.p.cfg.Name,
			Audience: "apphub",
		},
	}
}

var _ compute.IdentityService = identityService{}
