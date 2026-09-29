// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
)

// identityService implements [compute.IdentityService] with ServiceAccounts.
//
// This is the most natural mapping in the whole interface, and the probe found
// two things worth reporting anyway.
//
// # RunsOn has no meaning here
//
// [compute.WorkloadIdentitySpec.RunsOn] exists because an AWS role trusted by
// ecs-tasks.amazonaws.com cannot be assumed by Lambda. A ServiceAccount has no
// such restriction: the same one can be attached to a Deployment, a CronJob's
// pods, and a Knative Service. A Kubernetes provider therefore has two options
// and both are slightly dishonest — encode RunsOn into the object name, which
// invents a distinction the substrate does not have and doubles the number of
// ServiceAccounts an application needs, or ignore it, which makes two logically
// distinct identities silently alias. This provider ignores it and records it
// on the object so an operator can at least see what the caller asked for.
//
// # Deleting an identity cannot delete its grants
//
// [compute.IdentityService.DeleteWorkloadIdentity] is documented as removing
// "an identity and every grant made to it". On AWS that is free: the grants are
// inline policies on the role. Here the grants are in the object store's policy
// document and in the registry's robot accounts — two systems the identity port
// does not own and, in a production provider, may not even have credentials
// for. This implementation does cascade, because it can reach all three, and
// the cascade is the finding: the interface obliges every provider to make a
// cross-substrate guarantee it gives them no mechanism for.
type identityService struct{ p *Provider }

var _ compute.IdentityService = (*identityService)(nil)

// subjectFor renders the OIDC subject a projected ServiceAccount token carries.
// It is the one string that ties a workload to a grant on another substrate.
func subjectFor(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}

// annotationRunsOn records the runtime the caller said the identity was for.
const annotationRunsOn = "apphub.dev/runs-on"

func (s *identityService) EnsureWorkloadIdentity(ctx context.Context, spec compute.WorkloadIdentitySpec) (*compute.WorkloadIdentity, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	switch spec.RunsOn {
	case compute.RuntimeContainer, compute.RuntimeFunction, "":
	default:
		return nil, fmt.Errorf("%w: RunsOn %q is not a runtime this interface defines",
			compute.ErrInvalidSpec, spec.RunsOn)
	}
	// Identities live in the provider's default placement: the interface gives
	// WorkloadIdentitySpec no Placement, so there is nowhere else to put them.
	// On AWS that is invisible because a role is global; here it means an
	// identity cannot be namespaced with the workload that uses it.
	// The spec carries a placement now: a pod may only run as a ServiceAccount
	// in its own namespace, so before the amendment every identity landed in the
	// default namespace and a workload placed anywhere else could run as none.
	pc, err := s.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	name := sanitize("", spec.Name)

	if _, err := s.p.claim(ctx, gvkServiceAccount, pc.Namespace, name); err != nil {
		return nil, err
	}
	sa := &corev1.ServiceAccount{}
	sa.ObjectMeta = objectMeta(pc.Namespace, name, ownershipLabels(name, "workload-identity", nil))
	effective := spec
	effective.Placement = compute.Placement{Name: pc.Name}
	sa.Annotations = annotationsFor(spec.Labels, map[string]string{
		annotationRunsOn: string(spec.RunsOn),
		annotationSpec:   encodeSpec(effective),
	})
	// Preserve the imagePullSecrets a registry grant attached, which are not
	// part of the caller's spec and must not be reconciled away by it.
	if existing, err := s.p.sub.Cluster.Get(ctx, gvkServiceAccount, pc.Namespace, name); err == nil {
		if prev, ok := existing.(*corev1.ServiceAccount); ok {
			sa.ImagePullSecrets = prev.ImagePullSecrets
		}
	} else if !errors.Is(err, ErrObjectNotFound) {
		return nil, s.p.substrateError(err)
	}
	if err := s.p.apply(ctx, gvkServiceAccount, sa); err != nil {
		return nil, err
	}
	return s.identityFrom(pc.Namespace, name, effective), nil
}

func (s *identityService) DescribeWorkloadIdentity(ctx context.Context, ref compute.Ref) (*compute.WorkloadIdentity, error) {
	ns, name, err := s.p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return nil, err
	}
	obj, err := s.p.sub.Cluster.Get(ctx, gvkServiceAccount, ns, name)
	if err != nil {
		return nil, s.p.substrateError(err)
	}
	spec := compute.WorkloadIdentitySpec{}
	if sa, ok := obj.(*corev1.ServiceAccount); ok {
		// A malformed effective-spec annotation on a ServiceAccount is a defect
		// worth surfacing: DescribeWorkloadIdentity is the only source of
		// WorkloadIdentitySpec for a caller, so silently reporting the zero spec
		// (no requirements at all) would understate a real identity's grants
		// rather than admit it cannot be read.
		var err error
		spec, err = decodeSpec[compute.WorkloadIdentitySpec](sa.Annotations)
		if err != nil {
			return nil, fmt.Errorf("workload identity %s/%s: %w", ns, name, err)
		}
	}
	return s.identityFrom(ns, name, spec), nil
}

func (s *identityService) DeleteWorkloadIdentity(ctx context.Context, ref compute.Ref) error {
	ns, name, err := s.p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	subject := subjectFor(ns, name)
	// The cascade the interface requires, across three substrates.
	if s.p.sub.Objects != nil {
		buckets, err := s.p.sub.Objects.BucketNames(ctx)
		if err != nil {
			return s.p.storeError(err)
		}
		for _, bucket := range buckets {
			if err := s.p.sub.Objects.ClearPolicy(ctx, bucket, subject); err != nil {
				return s.p.storeError(err)
			}
		}
	}
	if s.p.sub.Registry != nil {
		token, hasToken, err := s.p.sub.Registry.CredentialFor(ctx, subject)
		if err != nil {
			return s.p.registryError(err)
		}
		repos, err := s.p.sub.Registry.RepositoryNames(ctx)
		if err != nil {
			return s.p.registryError(err)
		}
		for _, repo := range repos {
			if err := s.p.sub.Registry.Revoke(ctx, repo, subject); err != nil {
				return s.p.registryError(err)
			}
			if hasToken {
				if err := s.p.sub.Registry.Revoke(ctx, repo, token); err != nil {
					return s.p.registryError(err)
				}
			}
		}
	}
	if err := s.p.sub.Cluster.Delete(ctx, gvkServiceAccount, ns, name); err != nil {
		return s.p.substrateError(err)
	}
	return nil
}

// identity builds the value the interface returns.
//
// The attestation is the cluster's OIDC discovery document plus the subject the
// projected token will carry. A provider whose operator has not configured an
// issuer leaves the zero value, whose empty Method a verifier must refuse —
// which is the correct outcome for a cluster with no projected-token issuer,
// and is information rather than a failure.
func (s *identityService) identityFrom(namespace, name string, spec compute.WorkloadIdentitySpec) *compute.WorkloadIdentity {
	id := &compute.WorkloadIdentity{
		Ref:  s.p.ref(compute.KindWorkloadIdentity, namespace, name),
		Spec: spec,
	}
	if s.p.cfg.OIDCIssuer == "" {
		return id
	}
	id.Attestation = workload.ExpectedAttestation{
		Method:   workload.MethodK8sServiceAccount,
		Subject:  subjectFor(namespace, name),
		Issuer:   s.p.cfg.OIDCIssuer,
		Audience: s.p.cfg.OIDCAudience,
	}
	return id
}

// identityRef resolves a workload identity a spec names, checking it exists.
//
// Every workload spec requires one, and a provider must reject a spec rather
// than fall back to an ambient credential — which on this substrate would be
// the namespace's "default" ServiceAccount, a real and easy mistake.
func (p *Provider) identityRef(ctx context.Context, ref compute.Ref) (namespace, name string, err error) {
	if ref.IsZero() {
		return "", "", fmt.Errorf("%w: the spec names no workload identity, and a workload with "+
			"none would run as the namespace's default ServiceAccount", compute.ErrInvalidSpec)
	}
	ns, n, err := p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return "", "", err
	}
	if _, err := p.sub.Cluster.Get(ctx, gvkServiceAccount, ns, n); err != nil {
		return "", "", p.substrateError(err)
	}
	return ns, n, nil
}
