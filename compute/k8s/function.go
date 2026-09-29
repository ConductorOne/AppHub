// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/conductorone/apphub/compute"
)

// functionRuntime implements [compute.FunctionRuntime] as the design document's
// second honest option: a Deployment wrapping the bundle in an operator-supplied
// runtime image, with the cold-start and billing consequences documented rather
// than hidden.
//
// # What writing it found
//
//   - The runtime vocabulary really is provider-owned, and the interface's
//     instruction to "validate against the set it supports and return
//     ErrInvalidSpec listing them" is enough. This provider's runtime names come
//     from [Config.FunctionRuntimes] and are whatever the operator called them;
//     nothing here understands "nodejs20.x".
//   - [compute.FunctionSpec.Handler] does not survive. It is a Lambda concept —
//     the symbol the AWS runtime shim calls — and on a substrate where a
//     function is a container the only thing a provider can do with it is pass
//     it to the image as an environment variable and hope the image implements
//     the same convention. That is an out-of-band contract between the operator
//     and the image, and the interface has no way to describe it.
//   - [compute.FunctionSpec] has no reachability field, unlike every other
//     workload spec. On Lambda that is right: a function has no inbound network
//     surface. Here it is a pod, and a pod with no NetworkPolicy is reachable by
//     everything in the cluster. This provider writes a default-deny policy, and
//     the endpoint's permission to invoke becomes a second, separate policy —
//     see [functionRuntime.EnsureEndpoint].
type functionRuntime struct{ p *Provider }

var _ compute.FunctionRuntime = (*functionRuntime)(nil)

const (
	// envHandler is the out-of-band contract with the runtime image.
	envHandler = "APPHUB_FUNCTION_HANDLER"
	// envTimeout tells the runtime image how long an invocation may take,
	// because a pod has no per-request timeout of its own.
	envTimeout = "APPHUB_FUNCTION_TIMEOUT_SECONDS"
	// bundleKey is where the deployable bundle lands in its ConfigMap.
	bundleKey = "bundle"
)

func (f *functionRuntime) EnsureFunction(ctx context.Context, spec compute.FunctionSpec) (*compute.FunctionStatus, error) {
	image, ok := f.p.cfg.FunctionRuntimes[spec.Runtime]
	if !ok {
		return nil, fmt.Errorf("%w: runtime %q is not one this provider offers; the runtimes "+
			"configured here are %v, and substituting a different one silently would run the "+
			"caller's bundle under an interpreter it was not built for",
			compute.ErrInvalidSpec, spec.Runtime, sortedKeys(f.p.cfg.FunctionRuntimes))
	}
	if spec.Handler == "" {
		return nil, fmt.Errorf("%w: a function needs a handler", compute.ErrInvalidSpec)
	}
	if spec.Resources.MemoryMiB <= 0 {
		return nil, fmt.Errorf("%w: a function needs a positive memory allocation", compute.ErrInvalidSpec)
	}
	if spec.Resources.CPUMillicores < 0 {
		return nil, fmt.Errorf("%w: a function's CPU allocation cannot be negative", compute.ErrInvalidSpec)
	}
	if spec.Timeout <= 0 {
		return nil, fmt.Errorf("%w: a function needs a positive invocation timeout", compute.ErrInvalidSpec)
	}
	switch spec.Architecture {
	case "", compute.ArchAMD64, compute.ArchARM64:
	default:
		return nil, fmt.Errorf("%w: %q is not an architecture this interface defines",
			compute.ErrInvalidSpec, spec.Architecture)
	}
	bundle, err := f.p.resolveBundle(ctx, spec.Code)
	if err != nil {
		return nil, err
	}

	// The spec now carries a CPU allocation (F19). Zero still means "derive it",
	// which on this substrate means Lambda's ratio — but that is now a
	// documented fallback a caller can override rather than the only behaviour.
	res := spec.Resources
	if res.CPUMillicores == 0 {
		res.CPUMillicores = cpuForMemory(res.MemoryMiB)
	}
	w, err := f.p.buildWorkload(ctx, prefixFunction, "function", spec.Name, spec.Placement,
		compute.ImageRef(image), res,
		spec.Env, spec.Secrets, spec.Identity, spec.Capabilities,
		// FunctionSpec carries reachability now (F11); an empty set still
		// compiles to a default-deny policy, which is the right default.
		spec.Ingress, spec.Labels)
	if err != nil {
		return nil, err
	}
	w.container.Env = append(w.container.Env,
		corev1.EnvVar{Name: envHandler, Value: spec.Handler},
		corev1.EnvVar{Name: envTimeout, Value: fmt.Sprint(int(spec.Timeout.Seconds()))},
	)
	w.container.VolumeMounts = []corev1.VolumeMount{{Name: "bundle", MountPath: "/var/task", ReadOnly: true}}

	effective := spec
	effective.Placement = compute.Placement{Name: w.placement.Name}
	effective.Resources = res
	w.annotations[annotationSpec] = encodeSpec(effective)

	// Ownership refusal first, then the grant. See Provider.grantPullAccess and
	// the ordering note on EnsureService: claim is a read that can return
	// ErrNotOwned, and granting before it meant a failed ownership collision had
	// already widened repository read authorization.
	if _, err := f.p.claim(ctx, gvkDeployment, w.namespace, w.objectName); err != nil {
		return nil, err
	}
	if err := f.p.grantPullAccess(ctx, w, compute.ImageRef(image)); err != nil {
		return nil, err
	}

	cm := &corev1.ConfigMap{}
	cm.ObjectMeta = objectMeta(w.namespace, w.objectName, w.labels)
	cm.Annotations = annotationsFor(nil, nil)
	cm.BinaryData = map[string][]byte{bundleKey: bundle}
	if err := f.p.apply(ctx, gvkConfigMap, cm); err != nil {
		return nil, err
	}

	one := int32(1)
	dep := &appsv1.Deployment{}
	dep.ObjectMeta = objectMeta(w.namespace, w.objectName, w.labels)
	dep.Annotations = w.annotations
	dep.Spec.Replicas = &one
	dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
		labelManagedBy: managedByValue,
		labelName:      w.objectName,
	}}
	dep.Spec.Template = w.podTemplate(nil)
	dep.Spec.Template.Spec.Volumes = []corev1.Volume{{
		Name: "bundle",
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: w.objectName},
		}},
	}}
	if err := f.p.apply(ctx, gvkDeployment, dep); err != nil {
		return nil, err
	}

	svc := &corev1.Service{}
	svc.ObjectMeta = objectMeta(w.namespace, w.objectName, w.labels)
	svc.Spec.Selector = dep.Spec.Selector.MatchLabels
	svc.Spec.Ports = []corev1.ServicePort{{
		Name: "http", Port: functionPort, Protocol: corev1.ProtocolTCP,
		TargetPort: intstr.FromInt32(functionPort),
	}}
	if err := f.p.apply(ctx, gvkService, svc); err != nil {
		return nil, err
	}
	if err := f.p.apply(ctx, gvkNetworkPolicy, w.policy); err != nil {
		return nil, err
	}
	return f.DescribeFunction(ctx, f.p.ref(compute.KindFunction, w.namespace, w.objectName))
}

// functionPort is the port the runtime images listen on. It is a convention
// between the operator and the image, like the handler.
const functionPort = 8080

// cpuForMemory reproduces Lambda's memory-to-CPU derivation, used only when a
// caller leaves [compute.Resources.CPUMillicores] at zero. Before F19 it was the
// only path, which put an AWS pricing fact in every pod this provider created.
func cpuForMemory(memoryMiB int) int {
	millicores := memoryMiB * 1000 / 1769
	if millicores < 100 {
		return 100
	}
	return millicores
}

// resolveBundle reads the deployable bundle, enforcing the substrate's limit.
func (p *Provider) resolveBundle(ctx context.Context, code compute.CodeSource) ([]byte, error) {
	switch {
	case len(code.Inline) > 0 && code.Object != nil:
		return nil, fmt.Errorf("%w: exactly one of an inline bundle and an object reference may be set",
			compute.ErrInvalidSpec)

	case len(code.Inline) > 0:
		if limit := p.cfg.maxInlineBundle(); len(code.Inline) > limit {
			return nil, fmt.Errorf("%w: the inline bundle is %d bytes and this provider stores it "+
				"in a ConfigMap, whose limit is %d bytes; truncating it would produce a function "+
				"that deploys and does not run",
				compute.ErrInvalidSpec, len(code.Inline), limit)
		}
		return code.Inline, nil

	case code.Object != nil:
		if p.sub.Objects == nil {
			return nil, &compute.UnsupportedError{
				Provider: p.name, Capability: compute.CapObjectStore,
				Detail: "the bundle is in an object store and none is configured",
			}
		}
		_, bucket, err := p.resolve(code.Object.Bucket, compute.KindBucket)
		if err != nil {
			return nil, err
		}
		key := code.Object.Key
		if key == "" || strings.HasPrefix(key, "/") || path.Clean(key) != key || strings.HasPrefix(path.Clean(key), "..") {
			return nil, fmt.Errorf("%w: object key %q traverses outside the bucket namespace",
				compute.ErrInvalidSpec, key)
		}
		_, ok, err := p.sub.Objects.GetBucket(ctx, bucket)
		if err != nil {
			return nil, p.storeError(err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: bucket %q", compute.ErrNotFound, bucket)
		}
		// The provider records the location; the runtime image fetches it at
		// start-up with the workload's own identity.
		return []byte("object://" + bucket + "/" + key), nil

	default:
		return nil, fmt.Errorf("%w: a function needs a code bundle", compute.ErrInvalidSpec)
	}
}

func (f *functionRuntime) DescribeFunction(ctx context.Context, ref compute.Ref) (*compute.FunctionStatus, error) {
	ns, name, err := f.p.resolve(ref, compute.KindFunction)
	if err != nil {
		return nil, err
	}
	obj, err := f.p.sub.Cluster.Get(ctx, gvkDeployment, ns, name)
	if errors.Is(err, ErrObjectNotFound) {
		return &compute.FunctionStatus{Status: f.p.gone(ref)}, nil
	}
	if err != nil {
		return nil, f.p.substrateError(err)
	}
	dep, ok := obj.(*appsv1.Deployment)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a Deployment", compute.ErrFailed, ref)
	}
	phase := compute.PhasePending
	if dep.Status.ReadyReplicas > 0 {
		phase = compute.PhaseReady
	}
	// Same reasoning as DescribeService: a malformed spec here would be
	// reported as though the function had no code, no routes, and no
	// resources, rather than admit its effective spec cannot be read.
	spec, err := decodeSpec[compute.FunctionSpec](dep.Annotations)
	if err != nil {
		return nil, fmt.Errorf("function %s: %w", ref, err)
	}
	return &compute.FunctionStatus{
		Spec: spec,
		Status: f.p.status(ref, phase,
			"this provider runs functions as long-lived pods, so cold-start and cost behave like "+
				"a service rather than like a per-invocation runtime"),
		Revision: templateHash(dep.Spec.Template),
	}, nil
}

func (f *functionRuntime) WaitForFunction(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.FunctionStatus, error) {
	var last *compute.FunctionStatus
	st, err := f.p.waitFor(ctx, opts, ref, func() (compute.Status, bool, error) {
		s, err := f.DescribeFunction(ctx, ref)
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

func (f *functionRuntime) DeleteFunction(ctx context.Context, ref compute.Ref) error {
	ns, name, err := f.p.resolve(ref, compute.KindFunction)
	if err != nil {
		return err
	}
	for _, gvk := range []schemaGVK{gvkNetworkPolicy, gvkService, gvkDeployment, gvkConfigMap} {
		if err := f.p.sub.Cluster.Delete(ctx, gvk, ns, name); err != nil {
			return f.p.substrateError(err)
		}
	}
	return nil
}

// --- endpoints -------------------------------------------------------------------

// EnsureEndpoint puts a function behind a hostname with a Gateway and an
// HTTPRoute.
//
// # Why this needs the Gateway API, and what that says about ListenerSpec
//
// [compute.ListenerSpec] is a port plus an optional certificate. On AWS that is
// an ALB listener. On Kubernetes, networking.k8s.io/v1 Ingress cannot express
// it at all: an Ingress is served on whatever ports the ingress controller
// happens to listen on — in practice 80 and 443 — and its TLS section is keyed
// by hostname, not by port. So a provider backed only by an Ingress controller
// must decline [compute.CapFunctionEndpoint], and this one does; see
// [Config.capabilities].
//
// The Gateway API does express it, and the comparison is the finding. A Gateway
// listener has a name, a port, a *protocol*, a hostname, and a TLS block. Ours
// has a port and a TLS block, which is why USOSS-16 could not write the check
// that §7.23 asks for: "an HTTPS listener with no certificate" is
// unrepresentable when nil TLS is the only way to say plaintext. The substrate
// that got this right has the field we are missing.
func (f *functionRuntime) EnsureEndpoint(ctx context.Context, spec compute.EndpointSpec) (*compute.EndpointStatus, error) {
	if !f.p.caps.Has(compute.CapFunctionEndpoint) {
		return nil, &compute.UnsupportedError{
			Provider:   f.p.name,
			Capability: compute.CapFunctionEndpoint,
			Detail: "this cluster has no Gateway API; a networking.k8s.io Ingress cannot serve a " +
				"caller-chosen port with a caller-chosen certificate, and pretending otherwise " +
				"would put the endpoint on a port nothing listens on",
		}
	}
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	if len(spec.Listeners) == 0 {
		return nil, fmt.Errorf("%w: an endpoint needs at least one listener", compute.ErrInvalidSpec)
	}
	targetNS, targetName, err := f.p.resolve(spec.Target, compute.KindFunction)
	if err != nil {
		return nil, err
	}
	if _, err := f.p.sub.Cluster.Get(ctx, gvkDeployment, targetNS, targetName); err != nil {
		return nil, f.p.substrateError(err)
	}
	pc, err := f.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if pc.Namespace != targetNS {
		return nil, fmt.Errorf("%w: the endpoint is placed in namespace %q and its target function "+
			"is in %q", compute.ErrInvalidSpec, pc.Namespace, targetNS)
	}
	for _, rule := range spec.Ingress {
		if rule.From.Kind != compute.PeerInternet {
			return nil, fmt.Errorf("%w: a Gateway has no way to restrict who may reach a listener, "+
				"so this provider can only honour a %q rule on an endpoint and will not pretend to "+
				"honour a %q one", compute.ErrInvalidSpec, compute.PeerInternet, rule.From.Kind)
		}
	}

	name := sanitize(prefixEndpoint, spec.Name)
	// F14: the caller may name the hostname it wants, so the party choosing the
	// certificate and the party choosing the name it is served under are the
	// same one. A provider that cannot honour a request refuses rather than
	// substituting its own.
	hostname, err := f.resolveHostname(name, spec.Hostnames)
	if err != nil {
		return nil, err
	}
	listeners, err := f.p.gatewayListeners(spec.Listeners, hostname)
	if err != nil {
		return nil, err
	}
	if _, err := f.p.claim(ctx, gvkGateway, pc.Namespace, name); err != nil {
		return nil, err
	}

	labels := ownershipLabels(name, "function-endpoint", nil)
	gw := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvkGateway.GroupVersion().String(),
		"kind":       kindGateway,
		"spec": map[string]any{
			"gatewayClassName": pc.IngressClassName,
			"listeners":        listeners,
		},
	}}
	gw.SetNamespace(pc.Namespace)
	gw.SetName(name)
	gw.SetLabels(labels)
	effective := spec
	effective.Placement = compute.Placement{Name: pc.Name}
	effective.Hostnames = []string{hostname}
	gw.SetAnnotations(annotationsFor(spec.Labels, map[string]string{
		annotationEndpointHostname: hostname,
		annotationSpec:             encodeSpec(effective),
	}))
	if err := f.p.apply(ctx, gvkGateway, gw); err != nil {
		return nil, err
	}

	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvkHTTPRoute.GroupVersion().String(),
		"kind":       kindHTTPRoute,
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": name}},
			"hostnames":  []any{hostname},
			"rules": []any{map[string]any{
				"backendRefs": []any{map[string]any{
					"name": targetName, "port": int64(functionPort),
				}},
			}},
		},
	}}
	route.SetNamespace(pc.Namespace)
	route.SetName(name)
	route.SetLabels(labels)
	route.SetAnnotations(annotationsFor(nil, nil))
	if err := f.p.apply(ctx, gvkHTTPRoute, route); err != nil {
		return nil, err
	}

	// "Granting the endpoint permission to invoke its target" is a Lambda
	// resource policy on AWS and a NetworkPolicy here. It is a separate object
	// from the function's own default-deny policy on purpose: if the two shared
	// a name, the next EnsureFunction would reconcile this rule away, and the
	// interface gives the function spec no way to declare it.
	if err := f.p.apply(ctx, gvkNetworkPolicy, f.invokePolicy(pc, name, targetName, labels)); err != nil {
		return nil, err
	}
	return f.DescribeEndpoint(ctx, f.p.ref(compute.KindFunctionEndpoint, pc.Namespace, name))
}

// hostname synthesises the address the endpoint answers on.
//
// [compute.EndpointSpec] has no hostname field — a [compute.Route] does, but an
// endpoint does not — so the provider composes one from operator configuration
// and reports it in [compute.EndpointStatus.Hostname]. The consequence is that
// the caller chooses the certificate and the provider chooses the name it is
// served under, which are decisions that have to agree.
// resolveHostname honours a requested hostname or composes one.
func (f *functionRuntime) resolveHostname(name string, requested []string) (string, error) {
	switch len(requested) {
	case 0:
		return f.hostname(name), nil
	case 1:
		if f.p.cfg.EndpointDomain != "" && !strings.HasSuffix(requested[0], "."+f.p.cfg.EndpointDomain) {
			return "", fmt.Errorf("%w: hostname %q is not under the domain %q this provider serves; "+
				"it would resolve nowhere", compute.ErrInvalidSpec, requested[0], f.p.cfg.EndpointDomain)
		}
		return requested[0], nil
	default:
		return "", fmt.Errorf("%w: a Gateway listener carries one hostname and %d were requested",
			compute.ErrInvalidSpec, len(requested))
	}
}

func (f *functionRuntime) hostname(name string) string {
	domain := f.p.cfg.EndpointDomain
	if domain == "" {
		return name
	}
	return name + "." + domain
}

// gatewayListeners compiles [compute.ListenerSpec]s.
func (p *Provider) gatewayListeners(specs []compute.ListenerSpec, hostname string) ([]any, error) {
	seen := map[int]bool{}
	out := make([]any, 0, len(specs))
	for i, l := range specs {
		if l.Port <= 0 || l.Port > 65535 {
			return nil, fmt.Errorf("%w: listener port %d is not a port", compute.ErrInvalidSpec, l.Port)
		}
		if seen[l.Port] {
			return nil, fmt.Errorf("%w: two listeners on port %d", compute.ErrInvalidSpec, l.Port)
		}
		seen[l.Port] = true
		name := l.Name
		if name == "" {
			name = fmt.Sprintf("l%d", i)
		}
		listener := map[string]any{
			"name":     name,
			"port":     int64(l.Port),
			"hostname": hostname,
			// Taken from the spec, never guessed from the port number. The
			// source system selects HTTPS for any port other than 80 and then
			// never populates a certificate, which is the defect a protocol
			// field makes impossible to reproduce by accident (F5).
			"protocol": protocolHTTP,
		}
		protocol := l.Protocol
		if protocol == "" {
			protocol = compute.ListenerHTTP
		}
		switch protocol {
		case compute.ListenerHTTP:
			if l.TLS != nil {
				return nil, fmt.Errorf("%w: listener %d on port %d is plaintext and carries a "+
					"certificate; a provider must not have to guess which of the two was meant",
					compute.ErrInvalidSpec, i, l.Port)
			}
		case compute.ListenerHTTPS:
			if l.TLS == nil {
				return nil, fmt.Errorf("%w: listener %d on port %d asks for TLS and names no "+
					"certificate at all", compute.ErrInvalidSpec, i, l.Port)
			}
			secret, err := p.certificateSecret(l.TLS.CertificateRef)
			if err != nil {
				return nil, err
			}
			listener["protocol"] = protocolHTTPS
			listener["tls"] = map[string]any{
				"mode":            "Terminate",
				"certificateRefs": []any{map[string]any{"kind": "Secret", "name": secret}},
			}
		default:
			return nil, fmt.Errorf("%w: listener %d names protocol %q",
				compute.ErrInvalidSpec, i, protocol)
		}
		out = append(out, listener)
	}
	return out, nil
}

// certificateSecret resolves an operator-configured certificate reference.
func (p *Provider) certificateSecret(ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("%w: a TLS listener names no certificate, and no provider may invent "+
			"a default", compute.ErrInvalidSpec)
	}
	secret, ok := p.cfg.Certificates[ref]
	if !ok {
		return "", fmt.Errorf("%w: certificate %q is not one this provider can resolve (%v)",
			compute.ErrInvalidSpec, ref, sortedKeys(p.cfg.Certificates))
	}
	return secret, nil
}

// invokePolicy lets the gateway's pods reach the target function.
func (f *functionRuntime) invokePolicy(pc PlacementConfig, name, targetName string, labels map[string]string) *networkingv1.NetworkPolicy {
	np := &networkingv1.NetworkPolicy{}
	np.ObjectMeta = objectMeta(pc.Namespace, name, labels)
	np.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{
		labelManagedBy: managedByValue,
		labelName:      targetName,
	}}
	np.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	port := intstr.FromInt32(functionPort)
	proto := corev1.ProtocolTCP
	np.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
		From:  []networkingv1.NetworkPolicyPeer{selectorPeer(f.p.cfg.IngressProxy)},
		Ports: []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: &port}},
	}}
	return np
}

func (f *functionRuntime) DescribeEndpoint(ctx context.Context, ref compute.Ref) (*compute.EndpointStatus, error) {
	ns, name, err := f.p.resolve(ref, compute.KindFunctionEndpoint)
	if err != nil {
		return nil, err
	}
	obj, err := f.p.sub.Cluster.Get(ctx, gvkGateway, ns, name)
	if errors.Is(err, ErrObjectNotFound) {
		return &compute.EndpointStatus{Status: f.p.gone(ref)}, nil
	}
	if err != nil {
		return nil, f.p.substrateError(err)
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a Gateway", compute.ErrFailed, ref)
	}
	// A Gateway's effective spec is advisory here -- DescribeEndpoint's own
	// Hostname/Phase logic below reads the Gateway's live status, not the
	// spec -- but reporting an EndpointSpec is still part of the contract, so
	// a malformed one is refused rather than silently reported as an
	// endpoint with no listeners.
	spec, err := decodeSpec[compute.EndpointSpec](u.GetAnnotations())
	if err != nil {
		return nil, fmt.Errorf("function endpoint %s: %w", ref, err)
	}
	st := &compute.EndpointStatus{
		Status: f.p.status(ref, compute.PhasePending, ""),
		Spec:   spec,
	}
	addresses, _, _ := unstructured.NestedSlice(u.Object, "status", "addresses")
	if len(addresses) > 0 {
		if m, ok := addresses[0].(map[string]any); ok {
			host, _, _ := unstructured.NestedString(m, "value")
			st.Hostname = host
			st.Status = f.p.status(ref, compute.PhaseReady, "")
		}
	}
	return st, nil
}

func (f *functionRuntime) WaitForEndpoint(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.EndpointStatus, error) {
	var last *compute.EndpointStatus
	st, err := f.p.waitFor(ctx, opts, ref, func() (compute.Status, bool, error) {
		s, err := f.DescribeEndpoint(ctx, ref)
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

func (f *functionRuntime) DeleteEndpoint(ctx context.Context, ref compute.Ref) error {
	ns, name, err := f.p.resolve(ref, compute.KindFunctionEndpoint)
	if err != nil {
		return err
	}
	for _, gvk := range []schemaGVK{gvkNetworkPolicy, gvkHTTPRoute, gvkGateway} {
		if err := f.p.sub.Cluster.Delete(ctx, gvk, ns, name); err != nil {
			return f.p.substrateError(err)
		}
	}
	return nil
}
