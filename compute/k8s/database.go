// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/conductorone/apphub/compute"
)

// relationalProvisioner implements [compute.RelationalProvisioner] with an
// in-cluster Postgres operator's cluster resource.
//
// This port is the one PR #3 changed on the strength of a Kubernetes thought
// experiment, and writing it confirms the change was right: all four methods
// have natural implementations, none of them needs a mapping from a
// ServiceAccount to a SQL principal, and the port would have been unimplementable
// with [compute.Granter] still embedded in it.
//
// Two smaller things did turn up.
//
//   - [compute.CapacityRange] is a translation, as the design document says.
//     What the document does not say is which direction the loss goes: the
//     operators surveyed take fixed requests and limits, not a range, so
//     MinUnits becomes the request and MaxUnits the limit and *nothing scales*.
//     A caller who reads "0.5 to 4 units" as elasticity gets a fixed 4-unit
//     ceiling with a 0.5-unit reservation. The provider records the range it was
//     given in an annotation and says so in Status.Message, which is the most the
//     interface allows.
//   - The admin password has to be written to a Kubernetes Secret before the
//     cluster resource exists, and must not be rewritten afterwards. That is
//     exactly the ordering the interface requires, and it is checkable here.
type relationalProvisioner struct{ p *Provider }

var _ compute.RelationalProvisioner = (*relationalProvisioner)(nil)

// adminSecretName is the Secret the operator reads the initial password from.
func adminSecretName(cluster string) string { return cluster + "-superuser" }

func (r *relationalProvisioner) EnsureRelational(ctx context.Context, spec compute.RelationalSpec) (*compute.RelationalStatus, error) {
	cfg := r.p.cfg.PostgresOperator
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	if spec.Engine != compute.EnginePostgres {
		return nil, &compute.UnsupportedError{
			Provider:   r.p.name,
			Capability: compute.CapRelationalDatabase,
			Detail:     fmt.Sprintf("the configured operator speaks %q, not %q", compute.EnginePostgres, spec.Engine),
		}
	}
	if !slices.Contains(cfg.Versions, spec.EngineVersion) {
		return nil, fmt.Errorf("%w: engine version %q is not one this operator has images for (%v); "+
			"substituting a different major version would be a silent data-compatibility decision",
			compute.ErrInvalidSpec, spec.EngineVersion, cfg.Versions)
	}
	if spec.DatabaseName == "" || spec.AdminUsername == "" {
		return nil, fmt.Errorf("%w: a relational endpoint needs a database name and an admin username",
			compute.ErrInvalidSpec)
	}
	if spec.AdminPassword.IsZero() {
		return nil, fmt.Errorf("%w: a relational endpoint needs an admin password; the caller "+
			"generates it and stores it before provisioning so that a failure leaves a recoverable "+
			"account", compute.ErrInvalidSpec)
	}
	if err := validateCapacity(spec.Capacity); err != nil {
		return nil, err
	}
	pc, err := r.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}

	name := sanitize(prefixDatabase, spec.Name)
	existing, err := r.p.claim(ctx, r.gvk(), pc.Namespace, name)
	if err != nil {
		return nil, err
	}

	// The password Secret is written once and never again. The interface makes
	// this a hard requirement — the caller's stored copy would silently become
	// wrong — and it is why this is a create rather than an apply.
	secretName := adminSecretName(name)
	if _, getErr := r.p.sub.Cluster.Get(ctx, gvkSecret, pc.Namespace, secretName); errors.Is(getErr, ErrObjectNotFound) {
		sec := &corev1.Secret{Type: corev1.SecretTypeBasicAuth}
		sec.ObjectMeta = objectMeta(pc.Namespace, secretName,
			ownershipLabels(name, "relational-admin", nil))
		sec.Annotations = annotationsFor(nil, nil)
		sec.Data = map[string][]byte{
			corev1.BasicAuthUsernameKey: []byte(spec.AdminUsername),
			corev1.BasicAuthPasswordKey: []byte(compute.RevealSecret(spec.AdminPassword)),
		}
		if err := r.p.apply(ctx, gvkSecret, sec); err != nil {
			return nil, err
		}
	} else if getErr != nil {
		return nil, r.p.substrateError(getErr)
	}

	units := capacityUnits(spec.Capacity)
	requests, limits := cfg.translate(spec.Capacity)
	cluster := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": cfg.APIVersion,
		"kind":       cfg.Kind,
		"spec": map[string]any{
			"instances": int64(1),
			"imageName": "postgres:" + spec.EngineVersion,
			"storage":   map[string]any{"storageClass": pc.StorageClass, "size": "10Gi"},
			"resources": map[string]any{"requests": requests, "limits": limits},
			"bootstrap": map[string]any{"initdb": map[string]any{
				"database": spec.DatabaseName,
				"owner":    spec.AdminUsername,
				// By reference. The operator reads the Secret; apphub does not
				// put the material into the cluster resource.
				"secret": map[string]any{"name": secretName},
			}},
		},
	}}
	cluster.SetNamespace(pc.Namespace)
	cluster.SetName(name)
	cluster.SetLabels(ownershipLabels(name, "relational-database", nil))
	effective := spec
	effective.Placement = compute.Placement{Name: pc.Name}
	// The admin password never reaches the annotation: a spec carried on an
	// object is a spec anybody with read access can see.
	effective.AdminPassword = compute.SecretValue{}
	cluster.SetAnnotations(annotationsFor(spec.Labels, map[string]string{
		annotationSpec:          encodeSpec(effective),
		annotationCapacityUnits: units,
	}))
	if existing != nil {
		// Preserve the storage the operator provisioned: a re-Ensure must not
		// look like a request to shrink a volume.
		if prev, ok := existing.(*unstructured.Unstructured); ok {
			if size, found, _ := unstructured.NestedString(prev.Object, "spec", "storage", "size"); found {
				_ = unstructured.SetNestedField(cluster.Object, size, "spec", "storage", "size")
			}
		}
	}
	if err := r.p.apply(ctx, r.gvk(), cluster); err != nil {
		return nil, err
	}

	policy, err := r.p.networkPolicy(ctx, pc, name,
		ownershipLabels(name, "relational-database", nil), spec.Ingress)
	if err != nil {
		return nil, err
	}
	if err := r.p.apply(ctx, gvkNetworkPolicy, policy); err != nil {
		return nil, err
	}
	return r.DescribeRelational(ctx, r.p.ref(compute.KindRelational, pc.Namespace, name))
}

// validateCapacity refuses a range that cannot be satisfied.
func validateCapacity(c compute.CapacityRange) error {
	if c.MinUnits < 0 || c.MaxUnits < 0 {
		return fmt.Errorf("%w: a capacity range cannot be negative", compute.ErrInvalidSpec)
	}
	if c.MaxUnits > 0 && c.MinUnits > c.MaxUnits {
		return fmt.Errorf("%w: the capacity floor (%g units) is above the ceiling (%g units)",
			compute.ErrInvalidSpec, c.MinUnits, c.MaxUnits)
	}
	return nil
}

func capacityUnits(c compute.CapacityRange) string {
	return strconv.FormatFloat(c.MinUnits, 'g', -1, 64) + "-" + strconv.FormatFloat(c.MaxUnits, 'g', -1, 64)
}

// translate turns abstract units into the requests and limits the operator
// takes. The mapping is the operator's, configured, and documented; it is not
// an equivalence and the provider says so in Status.Message.
func (c *PostgresOperatorConfig) translate(r compute.CapacityRange) (requests, limits map[string]any) {
	minUnits, maxUnits := r.MinUnits, r.MaxUnits
	if minUnits == 0 {
		minUnits = 0.5
	}
	if maxUnits == 0 {
		maxUnits = 2
	}
	q := func(units float64) map[string]any {
		return map[string]any{
			"cpu":    strconv.Itoa(int(units*float64(c.InstanceMillicoresPerUnit))) + "m",
			"memory": strconv.Itoa(int(units*float64(c.InstanceMiBPerUnit))) + "Mi",
		}
	}
	return q(minUnits), q(maxUnits)
}

func (r *relationalProvisioner) gvk() schemaGVK {
	cfg := r.p.cfg.PostgresOperator
	group, version, _ := parseAPIVersion(cfg.APIVersion)
	return schemaGVK{Group: group, Version: version, Kind: cfg.Kind}
}

func (r *relationalProvisioner) DescribeRelational(ctx context.Context, ref compute.Ref) (*compute.RelationalStatus, error) {
	ns, name, err := r.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return nil, err
	}
	obj, err := r.p.sub.Cluster.Get(ctx, r.gvk(), ns, name)
	if errors.Is(err, ErrObjectNotFound) {
		return &compute.RelationalStatus{Status: r.p.gone(ref)}, nil
	}
	if err != nil {
		return nil, r.p.substrateError(err)
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a %s", compute.ErrFailed, ref, r.p.cfg.PostgresOperator.Kind)
	}
	phaseText, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	phase := compute.PhasePending
	// Same reasoning as the other Describe* methods: a malformed spec here
	// would report the database as having no engine, no version and no
	// storage class rather than admit its effective spec cannot be read.
	spec, err := decodeSpec[compute.RelationalSpec](u.GetAnnotations())
	if err != nil {
		return nil, fmt.Errorf("relational database %s: %w", ref, err)
	}
	st := &compute.RelationalStatus{Spec: spec}
	if phaseText == postgresPhaseHealthy {
		phase = compute.PhaseReady
		db, _, _ := unstructured.NestedString(u.Object, "spec", "bootstrap", "initdb", "database")
		host, _, _ := unstructured.NestedString(u.Object, "status", "writeService")
		st.Endpoint = compute.SQLEndpoint{
			Host:         host,
			Port:         5432,
			DatabaseName: db,
			// The operators surveyed all issue a server certificate and require
			// clients to use it.
			RequireTLS: true,
		}
	}
	message := ""
	if units := u.GetAnnotations()[annotationCapacityUnits]; units != "" {
		cpu, _, _ := unstructured.NestedString(u.Object, "spec", "resources", "limits", "cpu")
		mem, _, _ := unstructured.NestedString(u.Object, "spec", "resources", "limits", "memory")
		message = fmt.Sprintf("capacity %s units translated to fixed requests and limits "+
			"(ceiling %s CPU, %s memory); this operator does not scale between them", units, cpu, mem)
	}
	st.Status = r.p.status(ref, phase, message)
	return st, nil
}

func (r *relationalProvisioner) WaitForRelational(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.RelationalStatus, error) {
	var last *compute.RelationalStatus
	st, err := r.p.waitFor(ctx, opts, ref, func() (compute.Status, bool, error) {
		s, err := r.DescribeRelational(ctx, ref)
		if err != nil {
			return compute.Status{}, false, err
		}
		last = s
		return s.Status, s.Phase == compute.PhaseReady, nil
	})
	if last == nil {
		return nil, err
	}
	last.Status = st
	return last, err
}

func (r *relationalProvisioner) DeleteRelational(ctx context.Context, ref compute.Ref) error {
	ns, name, err := r.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return err
	}
	for _, gvk := range []schemaGVK{gvkNetworkPolicy, r.gvk()} {
		if err := r.p.sub.Cluster.Delete(ctx, gvk, ns, name); err != nil {
			return r.p.substrateError(err)
		}
	}
	// The admin Secret goes with the endpoint it belongs to; leaving it would
	// leave credential material for a database that no longer exists.
	return r.p.substrateError(r.p.sub.Cluster.Delete(ctx, gvkSecret, ns, adminSecretName(name)))
}

// parseAPIVersion splits "group/version" or a core "version".
func parseAPIVersion(apiVersion string) (group, version string, ok bool) {
	for i := range len(apiVersion) {
		if apiVersion[i] == '/' {
			return apiVersion[:i], apiVersion[i+1:], true
		}
	}
	return "", apiVersion, apiVersion != ""
}
