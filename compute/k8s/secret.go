// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/conductorone/apphub/compute"
)

// secretDataKey is the key inside a Kubernetes Secret that holds the value.
//
// A Kubernetes Secret is a map, and [compute.SecretSpec] is a single value, so
// the provider picks a key and a [compute.SecretBinding] resolves to it. That
// is fine, and it is worth noticing that the interface's single-value model is
// the *narrower* one: it cannot express a bound credential pair, which is what
// most Secrets in a cluster actually are.
const secretDataKey = "value"

// secretStore implements [compute.SecretStore] with Kubernetes Secrets.
//
// # The namespace problem
//
// This port is described in the interface as the most portable of the lot, and
// the CRUD half of that is right. The binding half is not, and the reason is
// specific to this substrate: a Pod's secretKeyRef can only name a Secret in
// the Pod's own namespace, while [compute.SecretSpec] has no Placement field
// and therefore no way to say which namespace a secret should live in. A
// provider must put every secret somewhere fixed, and a workload placed
// elsewhere then cannot bind it. This one refuses that binding with
// [compute.ErrInvalidSpec] rather than copying the material into a second
// namespace, because copying it doubles the number of places an audit has to
// look. See container.go for the refusal and
// docs/design/k8s-contract-probe.md for the proposed amendment.
type secretStore struct{ p *Provider }

var _ compute.SecretStore = (*secretStore)(nil)

func (s *secretStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	// Both refusals name the half of the identity that IS present. An error
	// reading only "the resource name is empty" cannot be placed by whoever reads
	// it out of a log, and it is not evidence for the conformance suite either:
	// security/secret-material-does-not-appear-in-errors searches these refusals
	// for the value the spec carried, and a refusal composed from none of the
	// spec is clean whatever this store does with the material.
	if err := validateName(spec.Name); err != nil {
		return compute.StoredSecret{}, fmt.Errorf("k8s: secret in scope %q: %w", spec.Scope, err)
	}
	if spec.Scope == "" {
		return compute.StoredSecret{}, fmt.Errorf("%w: secret %q needs a scope; teardown deletes by "+
			"scope, and a secret in none is one nothing will ever remove", compute.ErrInvalidSpec, spec.Name)
	}
	if err := validateLabels(spec.Labels); err != nil {
		return compute.StoredSecret{}, err
	}
	// The spec carries a placement now (F3). A secretKeyRef resolves only within
	// the pod's own namespace, so before the amendment every secret landed in the
	// default namespace and a workload placed anywhere else could bind none of
	// them — with the only alternative being to copy material into a second
	// namespace, which the interface forbids in as many words.
	pc, err := s.p.cfg.placement(spec.Placement)
	if err != nil {
		return compute.StoredSecret{}, err
	}
	name := s.name(spec.Scope, spec.Name)
	if _, err := s.p.claim(ctx, gvkSecret, pc.Namespace, name); err != nil {
		return compute.StoredSecret{}, err
	}
	sec := &corev1.Secret{Type: corev1.SecretTypeOpaque}
	sec.ObjectMeta = objectMeta(pc.Namespace, name, ownershipLabels(name, "secret", map[string]string{
		labelScope: hash8(spec.Scope),
	}))
	sec.Annotations = annotationsFor(spec.Labels, nil)
	sec.Data = map[string][]byte{secretDataKey: []byte(compute.RevealSecret(spec.Value))}
	if err := s.p.apply(ctx, gvkSecret, sec); err != nil {
		return compute.StoredSecret{}, err
	}
	// No version. A Kubernetes Secret has no content version anywhere in the
	// object, so there is nothing honest to report here — and reporting the empty
	// string is the point rather than a shortfall: a caller that needs a pin
	// learns this provider cannot give it one *before* it builds a workload
	// specification, rather than from a refusal later.
	//
	// The object's resourceVersion is not a candidate. It is an
	// optimistic-concurrency token: opaque, and changed by writes the caller
	// never made. Returning it would satisfy every type check, look exactly like
	// a version, and give a caller a value that pins nothing.
	return compute.StoredSecret{Ref: s.p.ref(compute.KindSecret, pc.Namespace, name)}, nil
}

func (s *secretStore) Get(ctx context.Context, ref compute.Ref) (compute.SecretValue, error) {
	ns, name, err := s.p.resolve(ref, compute.KindSecret)
	if err != nil {
		return compute.SecretValue{}, err
	}
	obj, err := s.p.sub.Cluster.Get(ctx, gvkSecret, ns, name)
	if err != nil {
		return compute.SecretValue{}, s.p.substrateError(err)
	}
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return compute.SecretValue{}, fmt.Errorf("%w: %s is not a Secret", compute.ErrFailed, ref)
	}
	return compute.NewSecretValue(string(sec.Data[secretDataKey])), nil
}

// Describe implements [compute.SecretStore].
//
// It asks the substrate for the object's METADATA and reports the placement the
// namespace belongs to. It does not call [Cluster.Get].
//
// The first version of this did call Get, and did not look at sec.Data — which
// review correctly refused as metadata-only in intent and not in effect: the
// whole corev1.Secret, every value in it, had been fetched and deserialized into
// this process before the function chose to ignore it. *Not looking at material
// you have fetched is not the same as not fetching it*, and the property this
// operation exists to deliver is least exposure rather than good manners.
//
// TestDescribeNeverReachesTheValueBearingRead is the control, and it is written
// against the substrate rather than against this function: it fails if Get is
// reached at all.
func (s *secretStore) Describe(ctx context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	ns, name, err := s.p.resolve(ref, compute.KindSecret)
	if err != nil {
		return nil, err
	}
	if _, err := s.p.sub.Cluster.GetMetadata(ctx, gvkSecret, ns, name); err != nil {
		return nil, s.p.substrateError(err)
	}
	placement, err := s.p.cfg.placementForNamespace(ns)
	if err != nil {
		return nil, err
	}
	return &compute.SecretInfo{
		Ref:            ref,
		PlacementScope: compute.SecretPlacementScoped,
		Placement:      compute.Placement{Name: placement},
	}, nil
}

func (s *secretStore) Delete(ctx context.Context, ref compute.Ref) error {
	ns, name, err := s.p.resolve(ref, compute.KindSecret)
	if err != nil {
		return err
	}
	return s.p.substrateError(s.p.sub.Cluster.Delete(ctx, gvkSecret, ns, name))
}

func (s *secretStore) DeleteScope(ctx context.Context, scope string) error {
	if scope == "" {
		return fmt.Errorf("%w: DeleteScope needs a scope", compute.ErrInvalidSpec)
	}
	pc, err := s.p.cfg.placement(compute.Placement{})
	if err != nil {
		return err
	}
	objs, err := s.p.sub.Cluster.List(ctx, gvkSecret, pc.Namespace, map[string]string{
		labelManagedBy: managedByValue,
		labelScope:     hash8(scope),
	})
	if err != nil {
		return s.p.substrateError(err)
	}
	for _, obj := range objs {
		sec, ok := obj.(*corev1.Secret)
		if !ok {
			continue
		}
		if err := s.p.sub.Cluster.Delete(ctx, gvkSecret, sec.Namespace, sec.Name); err != nil {
			return s.p.substrateError(err)
		}
	}
	return nil
}

// name derives the Secret's object name.
//
// [compute.SecretSpec.Name] is unique within a Scope, not globally, and a
// Kubernetes namespace is one flat map, so the scope has to survive into the
// name. It goes in as a digest prefix rather than as text because a scope is an
// application identifier the caller chose and nothing says it is a legal DNS
// label.
func (s *secretStore) name(scope, logical string) string {
	return sanitize("s"+hash8(scope)+"-", logical)
}

// bindingFor resolves a [compute.SecretBinding] into the secretKeyRef a pod
// spec carries, refusing anything the kubelet could not resolve.
func (p *Provider) bindingFor(ctx context.Context, workloadNamespace string, b compute.SecretBinding) (corev1.EnvVar, error) {
	if b.EnvName == "" {
		return corev1.EnvVar{}, fmt.Errorf("%w: a secret binding with no environment variable name "+
			"binds the secret to nothing", compute.ErrInvalidSpec)
	}
	if b.Version != "" {
		// Refused, not ignored. This substrate has no revision to pin to, and a
		// provider that accepted the field and bound the current value would hand
		// back a workload its caller believed was pinned — the silent degradation
		// compute.SecretBinding.Version was added to close, reappearing one layer
		// in and now with a field in the interface implying otherwise.
		//
		// The nearest thing Kubernetes offers is convention: a new Secret name per
		// revision, which is the caller's scheme and not something a provider can
		// synthesise. So there is no honest implementation to defer to, only a
		// dishonest one, and this returns a typed refusal instead.
		return corev1.EnvVar{}, fmt.Errorf("%w: binding %q asks for revision %q of secret %s",
			compute.ErrVersionPinningUnsupported, b.EnvName, b.Version, b.Secret)
	}
	ns, name, err := p.resolve(b.Secret, compute.KindSecret)
	if err != nil {
		return corev1.EnvVar{}, err
	}
	if ns != workloadNamespace {
		// The interface states this rule directly on compute.SecretBinding: a
		// binding across placements is ErrInvalidSpec, and a provider must not
		// copy material to satisfy one. Now that SecretSpec carries a placement,
		// the caller has somewhere to put the secret instead.
		return corev1.EnvVar{}, fmt.Errorf("%w: secret %s is in placement namespace %q and the "+
			"workload is in %q; a secretKeyRef resolves only within the pod's own namespace, and "+
			"copying the material across would double the places an audit has to look",
			compute.ErrInvalidSpec, b.Secret, ns, workloadNamespace)
	}
	if _, err := p.sub.Cluster.Get(ctx, gvkSecret, ns, name); err != nil {
		return corev1.EnvVar{}, p.substrateError(err)
	}
	return corev1.EnvVar{
		Name: b.EnvName,
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: name},
			Key:                  secretDataKey,
		}},
	}, nil
}
