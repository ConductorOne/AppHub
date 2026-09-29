// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/conductorone/apphub/compute"
)

// containerRuntime implements [compute.ContainerRuntime] with a Deployment, a
// Service, a NetworkPolicy, an Ingress per route, and a CronJob.
//
// The design document's sketch of this mapping is accurate. What follows are
// the four places writing it found the interface short, each expanded where it
// bites.
type containerRuntime struct{ p *Provider }

var _ compute.ContainerRuntime = (*containerRuntime)(nil)

// workload is the shape both a service and a scheduled job reduce to, so the
// two translations share one validator.
type builtWorkload struct {
	objectName   string
	namespace    string
	placement    PlacementConfig
	identityName string
	container    corev1.Container
	labels       map[string]string
	annotations  map[string]string
	policy       *networkingv1.NetworkPolicy
}

// grantPullAccess discharges the [compute.ImageRegistry] pull obligation for a
// built workload, scoped to that workload's own images.
//
// # It is separate from buildWorkload because it WRITES
//
// It grants repository read, and on a cluster that cannot pull by workload
// identity it also mints a robot credential and attaches a pull secret. Those are
// mutations of registry authorization state, and they used to happen inside
// buildWorkload -- which meant every validation that ran after it could refuse a
// spec that had already been granted access. Round nine reproduced it: a service
// with a route target port of 70000 was correctly refused with ErrInvalidSpec and
// left the repository's robot count incremented.
//
// The scope is the workload's own image rather than the identity, because an
// identity-wide grant would authorise every repository the platform has -- which
// is what the first version of this did.
func (p *Provider) grantPullAccess(ctx context.Context, w *builtWorkload, images ...compute.ImageRef) error {
	if !p.caps.Has(compute.CapImageRegistry) {
		return nil
	}
	return (&imageRegistry{p: p}).ensurePullAccess(ctx, w.namespace, w.identityName, images...)
}

// buildWorkload validates the portable half of a workload spec and compiles it.
func (p *Provider) buildWorkload(
	ctx context.Context,
	prefix, component, logicalName string,
	placement compute.Placement,
	image compute.ImageRef,
	res compute.Resources,
	env []compute.EnvVar,
	secrets []compute.SecretBinding,
	identity compute.Ref,
	capabilities []compute.WorkloadCapability,
	ingress []compute.IngressRule,
	labels map[string]string,
) (*builtWorkload, error) {
	if err := validateName(logicalName); err != nil {
		return nil, err
	}
	if err := validateLabels(labels); err != nil {
		return nil, err
	}
	if image == "" {
		return nil, fmt.Errorf("%w: the spec names no image", compute.ErrInvalidSpec)
	}
	pc, err := p.cfg.placement(placement)
	if err != nil {
		return nil, err
	}
	if res.CPUMillicores <= 0 || res.MemoryMiB <= 0 {
		return nil, fmt.Errorf("%w: a workload needs a positive CPU and memory allocation, got "+
			"%dm/%dMiB", compute.ErrInvalidSpec, res.CPUMillicores, res.MemoryMiB)
	}
	idNS, idName, err := p.identityRef(ctx, identity)
	if err != nil {
		return nil, err
	}
	if idNS != pc.Namespace {
		// Same rule as the secret binding, and the same reason it is now
		// fixable: a ServiceAccount is namespace-scoped, so an identity has to
		// be placed with the workload that runs as it.
		return nil, fmt.Errorf("%w: workload identity %s is in placement namespace %q and the "+
			"workload is in %q; a pod may only run as a ServiceAccount in its own namespace, so "+
			"place the identity with the workload",
			compute.ErrInvalidSpec, identity, idNS, pc.Namespace)
	}
	// The ImageRegistry pull obligation used to be discharged HERE, and that made
	// buildWorkload a writer. See [Provider.grantPullAccess]: it grants, mints a
	// credential and attaches a pull secret, so a spec refused by any validation
	// AFTER this point had already changed registry authorization state. Round
	// nine found it through the acceptance phase this function now serves --
	// extending that phase to ScaleService's provenance check meant a READ about
	// whether Ensure would accept a spec was granting registry access as a side
	// effect of asking.
	//
	// So buildWorkload validates and compiles, and nothing else. Each Ensure path
	// calls grantPullAccess itself, once its whole acceptance phase has passed.
	if err := p.validateWorkloadCapabilities(capabilities); err != nil {
		return nil, err
	}

	name := sanitize(prefix, logicalName)
	vars := make([]corev1.EnvVar, 0, len(env)+len(secrets))
	for _, e := range env {
		if e.Name == "" {
			return nil, fmt.Errorf("%w: an environment variable with no name", compute.ErrInvalidSpec)
		}
		vars = append(vars, corev1.EnvVar{Name: e.Name, Value: e.Value})
	}
	for _, b := range secrets {
		v, err := p.bindingFor(ctx, pc.Namespace, b)
		if err != nil {
			return nil, err
		}
		vars = append(vars, v)
	}

	quantities := corev1.ResourceList{
		corev1.ResourceCPU:    *resource.NewMilliQuantity(int64(res.CPUMillicores), resource.DecimalSI),
		corev1.ResourceMemory: *resource.NewQuantity(int64(res.MemoryMiB)*1024*1024, resource.BinarySI),
	}
	container := corev1.Container{
		Name:  "app",
		Image: string(image),
		Env:   vars,
		// Requests and limits are set to the same value because
		// [compute.Resources] is a single number. That makes every workload
		// Guaranteed QoS, which is a scheduling and cost decision the caller
		// did not make; see docs/design/k8s-contract-probe.md.
		Resources: corev1.ResourceRequirements{Requests: quantities, Limits: quantities.DeepCopy()},
	}

	objLabels := ownershipLabels(name, component, nil)
	policy, err := p.networkPolicy(ctx, pc, name, objLabels, ingress)
	if err != nil {
		return nil, err
	}
	return &builtWorkload{
		objectName:   name,
		namespace:    pc.Namespace,
		placement:    pc,
		identityName: idName,
		container:    container,
		labels:       objLabels,
		annotations:  annotationsFor(labels, nil),
		policy:       policy,
	}, nil
}

// validateWorkloadCapabilities refuses a capability this provider cannot back.
//
// Enumerated against [compute.WorkloadCapabilities] rather than switched on, so
// that a capability added to the interface later is refused by default instead
// of being silently accepted and never granted.
func (p *Provider) validateWorkloadCapabilities(want []compute.WorkloadCapability) error {
	required := map[compute.WorkloadCapability]compute.Capability{
		compute.WorkloadCapabilityModelInference: compute.CapModelInference,
	}
	for _, wc := range want {
		need, known := required[wc]
		if !known {
			return fmt.Errorf("%w: workload capability %q is not one this interface defines (%v)",
				compute.ErrInvalidSpec, wc, compute.WorkloadCapabilities())
		}
		if !p.caps.Has(need) {
			return &compute.UnsupportedError{
				Provider:   p.name,
				Capability: need,
				Detail: fmt.Sprintf("a workload asked for %q; a plain Kubernetes cluster has no "+
					"managed foundation-model service to grant a ServiceAccount access to", wc),
			}
		}
	}
	return nil
}

// podTemplate assembles the pod template both workload kinds share.
func (w *builtWorkload) podTemplate(annotations map[string]string) corev1.PodTemplateSpec {
	labels := map[string]string{}
	for k, v := range w.labels {
		labels[k] = v
	}
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
		Spec: corev1.PodSpec{
			ServiceAccountName: w.identityName,
			Containers:         []corev1.Container{w.container},
			NodeSelector:       w.placement.NodeSelector,
		},
	}
}

// --- reachability --------------------------------------------------------------

// networkPolicy compiles [compute.IngressRule]s into a NetworkPolicy.
//
// This is the part of the abstraction that works best. Every peer kind is a
// role, and a role is a namespace plus a label selector, which is what a
// NetworkPolicy peer is. Nothing here needs a network identifier from the
// caller, and the two rules that fail closed — a platform-ingress peer with no
// configured proxy, and a control-plane peer with no configured control plane —
// are refusals rather than the source system's silent widening to 0.0.0.0/0.
//
// The honest caveat, recorded as a finding: [compute.PeerInternet] compiles to
// an ipBlock of 0.0.0.0/0, which on Kubernetes admits every pod in the cluster
// as well as the internet, because a NetworkPolicy has no way to say "not from
// inside". A rule the caller meant as "public" is therefore *wider* here than
// on a security group, and the interface has no vocabulary for the difference.
func (p *Provider) networkPolicy(
	ctx context.Context,
	pc PlacementConfig,
	name string,
	labels map[string]string,
	rules []compute.IngressRule,
) (*networkingv1.NetworkPolicy, error) {
	np := &networkingv1.NetworkPolicy{}
	np.ObjectMeta = objectMeta(pc.Namespace, name, labels)
	np.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{
		labelManagedBy: managedByValue,
		labelName:      name,
	}}
	// Ingress only. The interface models no egress at all, so the provider must
	// not write an egress section: an empty one would mean deny-all and cut the
	// workload off from its own database. See the finding of the same name.
	np.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}

	for _, rule := range rules {
		peer, err := p.compilePeer(ctx, rule.From)
		if err != nil {
			return nil, err
		}
		proto, err := protocolOf(rule.Protocol)
		if err != nil {
			return nil, err
		}
		port32, err := narrowPort(rule.Port, "ingress rule port")
		if err != nil {
			return nil, err
		}
		port := intstr.FromInt32(port32)
		np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
			From:  []networkingv1.NetworkPolicyPeer{peer},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: &port}},
		})
	}
	return np, nil
}

func protocolOf(p compute.Protocol) (corev1.Protocol, error) {
	switch p {
	case "", compute.ProtocolTCP:
		return corev1.ProtocolTCP, nil
	case compute.ProtocolUDP:
		return corev1.ProtocolUDP, nil
	default:
		return "", fmt.Errorf("%w: %q is not a protocol this interface defines",
			compute.ErrInvalidSpec, p)
	}
}

func (p *Provider) compilePeer(ctx context.Context, peer compute.Peer) (networkingv1.NetworkPolicyPeer, error) {
	if peer.Kind != compute.PeerWorkload && !peer.Workload.IsZero() {
		return networkingv1.NetworkPolicyPeer{}, fmt.Errorf(
			"%w: a %q peer carries a workload reference, which is only meaningful for %q",
			compute.ErrInvalidSpec, peer.Kind, compute.PeerWorkload)
	}
	switch peer.Kind {
	case compute.PeerInternet:
		return networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
		}, nil

	case compute.PeerPlatformIngress:
		if p.cfg.IngressProxy.IsZero() {
			return networkingv1.NetworkPolicyPeer{}, fmt.Errorf(
				"%w: provider %q has no platform ingress proxy configured, so a rule naming %q "+
					"cannot be compiled; widening it to the internet instead is the source "+
					"system's behaviour and is a defect, not a fallback",
				compute.ErrInvalidSpec, p.name, compute.PeerPlatformIngress)
		}
		return selectorPeer(p.cfg.IngressProxy), nil

	case compute.PeerControlPlane:
		if p.cfg.ControlPlane.IsZero() {
			return networkingv1.NetworkPolicyPeer{}, fmt.Errorf(
				"%w: provider %q has no control-plane pod selector configured, so a rule naming "+
					"%q cannot be compiled", compute.ErrInvalidSpec, p.name, compute.PeerControlPlane)
		}
		return selectorPeer(p.cfg.ControlPlane), nil

	case compute.PeerWorkload:
		if peer.Workload.IsZero() {
			return networkingv1.NetworkPolicyPeer{}, fmt.Errorf(
				"%w: a %q peer names no workload", compute.ErrInvalidSpec, compute.PeerWorkload)
		}
		ns, name, err := p.resolve(peer.Workload, compute.KindService)
		if err != nil {
			return networkingv1.NetworkPolicyPeer{}, err
		}
		if _, err := p.sub.Cluster.Get(ctx, gvkDeployment, ns, name); err != nil {
			return networkingv1.NetworkPolicyPeer{}, p.substrateError(err)
		}
		return selectorPeer(PodSelector{
			Namespace: ns,
			Labels:    map[string]string{labelManagedBy: managedByValue, labelName: name},
		}), nil

	default:
		return networkingv1.NetworkPolicyPeer{}, fmt.Errorf(
			"%w: %q is not a peer kind this interface defines; a provider that fell back to any "+
				"particular role would be inventing a reachability decision",
			compute.ErrInvalidSpec, peer.Kind)
	}
}

func selectorPeer(s PodSelector) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
			"kubernetes.io/metadata.name": s.Namespace,
		}},
		PodSelector: &metav1.LabelSelector{MatchLabels: s.Labels},
	}
}

// --- routes ----------------------------------------------------------------------

// routeIngress compiles [compute.Route]s into one Ingress object.
//
// # Route has no certificate, and that is a fail-open hazard
//
// [compute.ListenerSpec] carries a [compute.TLSConfig]; [compute.Route] does
// not. So the interface can say "this function endpoint serves HTTPS with this
// certificate" but cannot say the same about an application's own public
// hostname — which is the one every deployed application actually gets. A
// provider therefore has three options: serve the route as plaintext, which is
// fail-open and is what a naive Ingress does; invent a certificate, which the
// interface forbids elsewhere ("no provider may invent a default"); or require
// the operator to configure one and refuse the route otherwise. This provider
// takes the third, so a misconfigured platform fails a deploy instead of
// publishing an application over HTTP.
func (p *Provider) routeIngress(
	pc PlacementConfig,
	name string,
	labels map[string]string,
	serviceName string,
	routes []compute.Route,
) (*networkingv1.Ingress, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	ing := &networkingv1.Ingress{}
	ing.ObjectMeta = objectMeta(pc.Namespace, name, labels)
	ing.Annotations = map[string]string{}
	if pc.IngressClassName != "" {
		ing.Spec.IngressClassName = &pc.IngressClassName
	}
	var hosts []string
	routeSecrets := map[string][]string{}
	pathType := networkingv1.PathTypePrefix
	for _, r := range routes {
		// No internal ingress class or address is operator-enforced here.
		// Never attach an internal route to the public Ingress, even when
		// another route in this service is public.
		if r.Internal {
			return nil, fmt.Errorf("%w: route %q requests internal ingress, but this provider has no internal ingress class or address",
				compute.ErrInvalidSpec, r.Host)
		}
		if r.Host == "" {
			return nil, fmt.Errorf("%w: a route with no host routes nothing", compute.ErrInvalidSpec)
		}
		targetPort, err := narrowPort(r.TargetPort, fmt.Sprintf("route %q target port", r.Host))
		if err != nil {
			return nil, err
		}
		if r.MCPAuthApplicationID != "" {
			return nil, &compute.UnsupportedError{
				Provider:   p.name,
				Capability: compute.CapMCPAuth,
				Detail:     "this ingress cannot install AppHub's app-specific MCP OAuth and discovery routes",
			}
		}
		// F4: a route carries its own certificate now, so the fail-closed rule
		// is stated by the interface rather than invented by this provider. A
		// route with neither a resolvable certificate nor an explicit
		// AllowPlaintext is refused; a platform-wide default certificate still
		// serves as a fallback for a route that names none.
		secret, err := p.routeTLSSecret(r)
		if err != nil {
			return nil, err
		}
		if secret != "" {
			routeSecrets[secret] = append(routeSecrets[secret], r.Host)
		}
		if r.RequireAuth {
			return nil, p.unsupported(compute.CapIngressAuth,
				"networking.k8s.io/v1 Ingress has no configured controller-enforced authentication; refusing to publish an unauthenticated route")
		}
		if len(r.PublicPaths) != 0 {
			return nil, fmt.Errorf("%w: route %q lists public paths without RequireAuth; authentication exemptions require an authenticated route",
				compute.ErrInvalidSpec, r.Host)
		}
		prefixes := r.PathPrefixes
		if len(prefixes) == 0 {
			prefixes = []string{"/"}
		}
		var paths []networkingv1.HTTPIngressPath
		for _, prefix := range prefixes {
			paths = append(paths, networkingv1.HTTPIngressPath{
				Path:     prefix,
				PathType: &pathType,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
					Name: serviceName,
					Port: networkingv1.ServiceBackendPort{Number: targetPort},
				}},
			})
		}
		ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{
			Host:             r.Host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths}},
		})
		hosts = append(hosts, r.Host)
	}
	for _, secret := range sortedKeys(routeSecrets) {
		ing.Spec.TLS = append(ing.Spec.TLS,
			networkingv1.IngressTLS{Hosts: routeSecrets[secret], SecretName: secret})
	}
	_ = hosts
	return ing, nil
}

// --- services -----------------------------------------------------------------

// acceptedService is everything the acceptance phase of a service spec produces:
// the validated spec's compiled objects, so a caller that has just validated does
// not have to build them twice.
type acceptedService struct {
	w        *builtWorkload
	replicas int32
	ports    []corev1.ContainerPort
	ingress  *networkingv1.Ingress
}

// acceptService answers one question -- **would EnsureService accept this spec** --
// and it is the ONLY thing that answers it.
//
// # Why this exists, and why the previous attempt was not enough
//
// [containerRuntime.ScaleService] has to know whether the effective spec it read
// back is one a successful Ensure could have written, or it mutates a fabricated
// spec (review round seven). The first fix delegated that to Ensure's own
// validators rather than restating their rules, which was the right structure --
// a second list of invariants beside Ensure's own is a list that drifts.
//
// It drew the boundary in the wrong place. It called buildWorkload, narrowCount
// and containerPorts: three real validators, assembled BY HAND. **A list of calls
// is still a list, and it drifts exactly the way a list of rules does** -- it
// omitted route validation and the exec-capability check, so a spec with a route
// target port of 70000 was refused by EnsureService and accepted by ScaleService
// (round eight). The remedy is not to add the two that were missing; that closes
// one reproduction and leaves the next field.
//
// So acceptance is a PHASE with a name, and both paths call it. A validation added
// here is asked by both automatically, and the two cannot diverge by editing one
// of them, because there is only one.
//
// # It also moved route validation ahead of every side effect
//
// EnsureService used to validate routes at the point of applying them -- after the
// Deployment, Service and NetworkPolicy had already been written. So a spec with a
// bad route was refused, correctly, but only after three objects existed. Route
// validation needs nothing that the applies produce (routeIngress is a pure
// builder over the workload's placement, name and labels), so it belongs in the
// acceptance phase, and a refused spec now changes nothing. That was not the
// reported defect; it is what naming the phase made visible.
func (r *containerRuntime) acceptService(ctx context.Context, spec compute.ServiceSpec) (*acceptedService, error) {
	w, err := r.p.buildWorkload(ctx, prefixService, "service", spec.Name, spec.Placement,
		spec.Image, spec.Resources, spec.Env, spec.Secrets, spec.Identity,
		spec.Capabilities, spec.Ingress, spec.Labels)
	if err != nil {
		return nil, err
	}
	// Bounded at BOTH ends. See narrow.go: this was a lower-bound-only check plus
	// a //nolint:gosec asserting otherwise, on two methods, found two rounds apart.
	replicas, err := narrowCount(spec.Replicas, "a service's replica count")
	if err != nil {
		return nil, err
	}
	// Currently UNREACHABLE, and that is measured rather than assumed:
	// Config.capabilities() puts CapWorkloadExec in the unconditional set, so
	// p.caps.Has is true for every Config including the zero value, and this
	// branch cannot fire. It is kept because the capability set is derived from
	// configuration by design and a future config could make exec conditional --
	// but it means the equivalence between this phase and ScaleService cannot be
	// tested on this rule, so TestScaleAndEnsureAgreeOnEverySpecTheyRefuse
	// deliberately does not claim to. An untestable rule is worth naming; a gap
	// that looks covered is not.
	if spec.ExecEnabled && !r.p.caps.Has(compute.CapWorkloadExec) {
		return nil, r.p.unsupported(compute.CapWorkloadExec, "")
	}
	ports, err := containerPorts(spec.Ports)
	if err != nil {
		return nil, err
	}
	// The service name is the object name, so this needs nothing the applies
	// produce and can be validated before any of them run.
	ing, err := r.p.routeIngress(w.placement, w.objectName, w.labels, w.objectName, spec.Routes)
	if err != nil {
		return nil, err
	}
	return &acceptedService{w: w, replicas: replicas, ports: ports, ingress: ing}, nil
}

func (r *containerRuntime) EnsureService(ctx context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	// The whole acceptance phase, in one call. See acceptService for why this is a
	// named phase rather than a sequence of validators inlined here: ScaleService
	// has to ask the same question, and every version that asked it by assembling
	// validators drifted from this one.
	accepted, err := r.acceptService(ctx, spec)
	if err != nil {
		return nil, err
	}
	w, replicas, ports, ing := accepted.w, accepted.replicas, accepted.ports, accepted.ingress

	effective := spec
	effective.Placement = compute.Placement{Name: w.placement.Name}
	w.annotations[annotationSpec] = encodeSpec(effective)
	w.container.Ports = ports

	// The read-only ownership refusal runs BEFORE the first write, and that
	// ordering is the fix for round ten.
	//
	// claim is a Get plus an ownership check: it writes nothing and it can return
	// ErrNotOwned. grantPullAccess writes. With the grant first, a spec refused
	// *because the object belongs to somebody else* had already widened repository
	// read authorization -- a failed ownership collision granting access is the
	// worst direction for this to fail in, which is why it is (a) rather than (b).
	//
	// Round nine moved the write out of the validation phase and left the claim on
	// the wrong side of it: the phase boundary was right and one refusal was
	// outside it. Every refusal now precedes every write on this path.
	//
	// This closes the route, NOT the class: a later apply can still fail with the
	// grant already made, which needs grant-last or compensation and is not
	// something this ordering fixes.
	if _, err := r.p.claim(ctx, gvkDeployment, w.namespace, w.objectName); err != nil {
		return nil, err
	}

	// The first write on this path, after every refusal above it.
	if err := r.p.grantPullAccess(ctx, w, spec.Image); err != nil {
		return nil, err
	}

	dep := &appsv1.Deployment{}
	dep.ObjectMeta = objectMeta(w.namespace, w.objectName, w.labels)
	dep.Annotations = w.annotations
	dep.Spec.Replicas = &replicas
	dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{
		labelManagedBy: managedByValue,
		labelName:      w.objectName,
	}}
	dep.Spec.Template = w.podTemplate(nil)
	if err := r.p.apply(ctx, gvkDeployment, dep); err != nil {
		return nil, err
	}

	svcName := w.objectName
	if len(ports) > 0 {
		svc := &corev1.Service{}
		svc.ObjectMeta = objectMeta(w.namespace, svcName, w.labels)
		svc.Spec.Selector = dep.Spec.Selector.MatchLabels
		for _, p := range ports {
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
				Name:       p.Name,
				Port:       p.ContainerPort,
				Protocol:   p.Protocol,
				TargetPort: intstr.FromInt32(p.ContainerPort),
			})
		}
		if err := r.p.apply(ctx, gvkService, svc); err != nil {
			return nil, err
		}
	}

	if err := r.p.apply(ctx, gvkNetworkPolicy, w.policy); err != nil {
		return nil, err
	}

	// Already validated and built by acceptService, before anything was applied.
	if ing != nil {
		if err := r.p.apply(ctx, gvkIngress, ing); err != nil {
			return nil, err
		}
	} else if err := r.p.sub.Cluster.Delete(ctx, gvkIngress, w.namespace, w.objectName); err != nil {
		// Declarative: a spec with no routes must leave none behind.
		return nil, r.p.substrateError(err)
	}

	return r.DescribeService(ctx, r.p.ref(compute.KindService, w.namespace, w.objectName))
}

func containerPorts(ports []compute.PortSpec) ([]corev1.ContainerPort, error) {
	var out []corev1.ContainerPort
	for _, p := range ports {
		number, err := narrowPort(p.Number, "container port")
		if err != nil {
			return nil, err
		}
		proto, err := protocolOf(p.Protocol)
		if err != nil {
			return nil, err
		}
		out = append(out, corev1.ContainerPort{
			Name:          p.Name,
			ContainerPort: number,
			Protocol:      proto,
		})
	}
	return out, nil
}

func (r *containerRuntime) DescribeService(ctx context.Context, ref compute.Ref) (*compute.ServiceStatus, error) {
	ns, name, err := r.p.resolve(ref, compute.KindService)
	if err != nil {
		return nil, err
	}
	obj, err := r.p.sub.Cluster.Get(ctx, gvkDeployment, ns, name)
	if errors.Is(err, ErrObjectNotFound) {
		return &compute.ServiceStatus{Status: r.p.gone(ref)}, nil
	}
	if err != nil {
		return nil, r.p.substrateError(err)
	}
	dep, ok := obj.(*appsv1.Deployment)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a Deployment", compute.ErrFailed, ref)
	}
	desired := int32(1)
	if dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}
	phase := compute.PhasePending
	if dep.Status.ReadyReplicas >= desired {
		phase = compute.PhaseReady
	}
	// A malformed annotation here means DescribeService's own
	// RouteAddresses/DesiredReplicas fields would be computed from a spec
	// that does not match what is actually deployed -- worth refusing rather
	// than reporting, since the caller could otherwise "successfully"
	// describe a service with routes and replicas it does not have.
	effective, err := decodeSpec[compute.ServiceSpec](dep.Annotations)
	if err != nil {
		return nil, fmt.Errorf("service %s: %w", ref, err)
	}
	return &compute.ServiceStatus{
		Status: r.p.status(ref, phase, ""),
		Spec:   effective,
		// Where the ingress controller answers, once it is answering. An
		// Ingress does nothing until DNS points at this address, and before F13
		// the provider could read it and had nowhere to put it.
		RouteAddresses:  r.p.routeAddresses(effective.Routes, phase),
		DesiredReplicas: int(desired),
		ReadyReplicas:   int(dep.Status.ReadyReplicas),
		// The pod-template digest, which is what a ReplicaSet's
		// pod-template-hash label carries: it changes when the effective
		// configuration changes and is stable across a pure scale.
		Revision: templateHash(dep.Spec.Template),
	}, nil
}

func (r *containerRuntime) WaitForService(ctx context.Context, ref compute.Ref, minReady int, opts compute.WaitOptions) (*compute.ServiceStatus, error) {
	var last *compute.ServiceStatus
	st, err := r.p.waitFor(ctx, opts, ref, func() (compute.Status, bool, error) {
		s, err := r.DescribeService(ctx, ref)
		if err != nil {
			return compute.Status{}, false, err
		}
		last = s
		return s.Status, s.ReadyReplicas >= minReady && s.Phase != compute.PhaseGone, nil
	})
	if last == nil {
		return nil, err
	}
	last.Status = st
	return last, err
}

func (r *containerRuntime) ScaleService(ctx context.Context, ref compute.Ref, replicas int) error {
	// Bounded at both ends by the one helper every narrowing conversion in this
	// package goes through. It used to be an inline two-ended check here, which
	// was correct but was the third of four differently-written guards -- and the
	// sibling EnsureService path still had the half-true suppression, which is
	// what round seven found. See narrow.go for why the bound lives in one place.
	n, err := narrowCount(replicas, "a service's replica count")
	if err != nil {
		return err
	}
	ns, name, err := r.p.resolve(ref, compute.KindService)
	if err != nil {
		return err
	}
	obj, err := r.p.sub.Cluster.Get(ctx, gvkDeployment, ns, name)
	if err != nil {
		return r.p.substrateError(err)
	}
	dep, ok := obj.(*appsv1.Deployment)
	if !ok {
		return fmt.Errorf("%w: %s is not a Deployment", compute.ErrFailed, ref)
	}
	dep.Spec.Replicas = &n
	// # The effective-spec annotation has to move with the object
	//
	// DescribeService rebuilds the effective spec from annotationSpec, not from
	// the Deployment's fields, so a mutation that changes the object without
	// re-encoding the annotation makes the two disagree: ServiceStatus.DesiredReplicas
	// would report the new count, read from dep.Spec.Replicas, while
	// ServiceStatus.Spec.Replicas reported the old one. That is precisely the
	// disagreement USOSS-2's effective-spec read-back exists to make impossible,
	// and it is worse than cosmetic — a caller reconciling from Spec sees the old
	// count, concludes there is nothing to do, and never converges.
	//
	// Found by USOSS-39's scale check, and only after that check was strengthened
	// to compare the whole spec rather than two marker substrings of it -- because
	// comparing two members of a population cannot see a defect in the rest of it.
	//
	// Attributed rather than asserted: the weak version of that check never landed,
	// so this cannot be reproduced from the repository. The account is the check
	// author's own, recorded in checks_scale.go's doc comment at the commit that
	// strengthened it, which reports the substring form staying green while Ports,
	// Secrets, Ingress, Routes and Labels were deleted. Corroborated by a
	// contemporaneous note in the code, not by me re-running it.
	//
	// **This is the only mutating method on any port that changes an
	// annotationSpec-bearing object outside its own Ensure path.** Derived, with a
	// denominator: six ports write annotationSpec and read it back — service,
	// scheduled job, function, endpoint, workload identity and relational — and
	// across all six the only methods that write are Ensure, Delete, and this one.
	// (imageRegistry.attachPullSecret also mutates a ServiceAccount, which does
	// carry the annotation, but it changes imagePullSecrets, which
	// WorkloadIdentitySpec does not describe, so the annotation stays accurate.)
	// A new mutator added later has to do this too, which is what
	// TestScalingDoesNotStaleTheEffectiveSpec is positioned to notice.
	//
	// The third argument is the PROVENANCE question, and it delegates to the same
	// validator EnsureService runs rather than restating its invariants. Round
	// seven found why that distinction matters: the byte round-trip inside
	// reencodeSpec establishes only that an annotation is in this build's exact
	// format, and the canonical zero spec satisfies that -- it is genuinely a
	// fixed point -- while being a value no successful Ensure can produce. Asking
	// buildWorkload cannot drift from what Ensure accepts, because it IS what
	// Ensure asks.
	if err := reencodeSpec(dep.Annotations, func(effective compute.ServiceSpec) compute.ServiceSpec {
		effective.Replicas = replicas
		return effective
	}, func(effective compute.ServiceSpec) error {
		// The provenance question, asked by calling the acceptance phase itself.
		// The previous version called buildWorkload, narrowCount and
		// containerPorts -- three real validators, assembled by hand -- and
		// omitted route and exec-capability validation, so EnsureService refused
		// specs ScaleService accepted. A list of calls drifts exactly like a list
		// of rules; this cannot, because it is the same function.
		_, err := r.acceptService(ctx, effective)
		return err
	}); err != nil {
		return err
	}
	return r.p.apply(ctx, gvkDeployment, dep)
}

func (r *containerRuntime) DeleteService(ctx context.Context, ref compute.Ref) error {
	ns, name, err := r.p.resolve(ref, compute.KindService)
	if err != nil {
		return err
	}
	// Four objects, one logical resource. Nothing in the interface makes this
	// visible, which is fine — but note that it is not atomic and the interface
	// has no vocabulary for a partial teardown either.
	for _, gvk := range []schemaGVK{gvkIngress, gvkNetworkPolicy, gvkService, gvkDeployment} {
		if err := r.p.sub.Cluster.Delete(ctx, gvk, ns, name); err != nil {
			return r.p.substrateError(err)
		}
	}
	return nil
}

// validateSchedule checks a [compute.Schedule] against the grammar the
// interface pins.
//
// Pinning it is what makes the field portable: the source system passes the
// operator's string straight through to EventBridge Scheduler, and a CronJob's
// dialect is not EventBridge's. A provider that accepted whatever it was given
// would produce a job that runs at a different time on each substrate.
func validateSchedule(s compute.Schedule) error {
	expr := strings.TrimSpace(s.Expression)
	switch {
	case expr == "":
		return fmt.Errorf("%w: a scheduled job needs a schedule expression", compute.ErrInvalidSpec)
	case rateExpression.MatchString(expr):
		// A rate expression has no CronJob equivalent; the provider converts
		// the ones it can and refuses the rest rather than approximating.
		if _, err := rateToCron(expr); err != nil {
			return err
		}
	case len(strings.Fields(expr)) != 5:
		return fmt.Errorf("%w: %q is neither a five-field cron expression nor a rate expression",
			compute.ErrInvalidSpec, expr)
	}
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return fmt.Errorf("%w: %q is not an IANA timezone name", compute.ErrInvalidSpec, s.Timezone)
		}
	}
	return nil
}

// rateExpression matches the "rate(<n> <unit>)" form the interface admits.
var rateExpression = regexp.MustCompile(`^rate\(\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*\)$`)

// rateToCron converts a rate expression into the cron form a CronJob accepts.
//
// Only the rates that divide evenly convert. "rate(7 minutes)" does not mean
// "every seventh minute of the hour", so the provider refuses it instead of
// producing a schedule that drifts — which is the kind of silent
// almost-equivalence the design document warns about for CapacityRange.
func rateToCron(expr string) (string, error) {
	m := rateExpression.FindStringSubmatch(expr)
	if m == nil {
		return "", fmt.Errorf("%w: %q is not a rate expression", compute.ErrInvalidSpec, expr)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return "", fmt.Errorf("%w: %q has a non-positive interval", compute.ErrInvalidSpec, expr)
	}
	switch {
	case strings.HasPrefix(m[2], "minute") && n < 60 && 60%n == 0:
		return fmt.Sprintf("*/%d * * * *", n), nil
	case strings.HasPrefix(m[2], "hour") && n < 24 && 24%n == 0:
		return fmt.Sprintf("0 */%d * * *", n), nil
	case strings.HasPrefix(m[2], "day") && n == 1:
		return "0 0 * * *", nil
	}
	return "", fmt.Errorf("%w: %q has no exact cron equivalent, and a provider that rounded it "+
		"would run the job at a different cadence than the caller asked for",
		compute.ErrInvalidSpec, expr)
}

// --- scheduled jobs ---------------------------------------------------------------

func (r *containerRuntime) EnsureScheduledJob(ctx context.Context, spec compute.ScheduledJobSpec) (*compute.ScheduledJobStatus, error) {
	if !r.p.caps.Has(compute.CapScheduledJob) {
		return nil, r.p.unsupported(compute.CapScheduledJob, "")
	}
	w, err := r.p.buildWorkload(ctx, prefixJob, "scheduled-job", spec.Name, spec.Placement,
		spec.Image, spec.Resources, spec.Env, spec.Secrets, spec.Identity,
		spec.Capabilities, spec.Ingress, spec.Labels)
	if err != nil {
		return nil, err
	}
	if err := validateSchedule(spec.Schedule); err != nil {
		return nil, err
	}
	effective := spec
	effective.Placement = compute.Placement{Name: w.placement.Name}
	w.annotations[annotationSpec] = encodeSpec(effective)
	// Ownership refusal before the grant, as on the service path. See the note
	// there: a job refused because the CronJob is somebody else's must not have
	// widened repository read first.
	if _, err := r.p.claim(ctx, gvkCronJob, w.namespace, w.objectName); err != nil {
		return nil, err
	}

	// The first write on this path, after validateSchedule and the claim.
	if err := r.p.grantPullAccess(ctx, w, spec.Image); err != nil {
		return nil, err
	}

	suspend := spec.Schedule.Paused
	cj := &batchv1.CronJob{}
	cj.ObjectMeta = objectMeta(w.namespace, w.objectName, w.labels)
	cj.Annotations = w.annotations
	cj.Spec.Schedule = spec.Schedule.Expression
	if rateExpression.MatchString(strings.TrimSpace(spec.Schedule.Expression)) {
		converted, err := rateToCron(strings.TrimSpace(spec.Schedule.Expression))
		if err != nil {
			return nil, err
		}
		cj.Spec.Schedule = converted
	}
	cj.Spec.Suspend = &suspend
	if spec.Schedule.Timezone != "" {
		tz := spec.Schedule.Timezone
		cj.Spec.TimeZone = &tz
	}
	cj.Spec.JobTemplate.Spec.Template = w.podTemplate(nil)
	cj.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
	if err := r.p.apply(ctx, gvkCronJob, cj); err != nil {
		return nil, err
	}
	if err := r.p.apply(ctx, gvkNetworkPolicy, w.policy); err != nil {
		return nil, err
	}
	return r.DescribeScheduledJob(ctx, r.p.ref(compute.KindScheduledJob, w.namespace, w.objectName))
}

func (r *containerRuntime) DescribeScheduledJob(ctx context.Context, ref compute.Ref) (*compute.ScheduledJobStatus, error) {
	ns, name, err := r.p.resolve(ref, compute.KindScheduledJob)
	if err != nil {
		return nil, err
	}
	obj, err := r.p.sub.Cluster.Get(ctx, gvkCronJob, ns, name)
	if errors.Is(err, ErrObjectNotFound) {
		// Synchronous port: an absent resource is ErrNotFound, not a phase.
		return nil, fmt.Errorf("%w: scheduled job %s/%s", compute.ErrNotFound, ns, name)
	}
	if err != nil {
		return nil, r.p.substrateError(err)
	}
	cj, ok := obj.(*batchv1.CronJob)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a CronJob", compute.ErrFailed, ref)
	}
	sched := compute.Schedule{Expression: cj.Spec.Schedule}
	if cj.Spec.TimeZone != nil {
		sched.Timezone = *cj.Spec.TimeZone
	}
	sched.Paused = cj.Spec.Suspend != nil && *cj.Spec.Suspend
	// A CronJob is live the moment the API server accepts it: there is nothing
	// to become ready, and no controller writes a readiness condition. That was
	// the evidence for F8, and the port is in the synchronous class now, so this
	// returns a descriptor rather than a phase it would always report Ready.
	// Same reasoning as DescribeService: a malformed spec here would report a
	// schedule and a spec.Schedule field for the CronJob that could disagree,
	// so it is refused instead of guessed at.
	spec, err := decodeSpec[compute.ScheduledJobSpec](cj.Annotations)
	if err != nil {
		return nil, fmt.Errorf("scheduled job %s: %w", ref, err)
	}
	return &compute.ScheduledJobStatus{
		Ref:      ref,
		Spec:     spec,
		Schedule: sched,
	}, nil
}

func (r *containerRuntime) DeleteScheduledJob(ctx context.Context, ref compute.Ref) error {
	ns, name, err := r.p.resolve(ref, compute.KindScheduledJob)
	if err != nil {
		return err
	}
	for _, gvk := range []schemaGVK{gvkNetworkPolicy, gvkCronJob} {
		if err := r.p.sub.Cluster.Delete(ctx, gvk, ns, name); err != nil {
			return r.p.substrateError(err)
		}
	}
	return nil
}

// routeAddresses reports where the platform's ingress answers for a service's
// routes. Empty when the service has no routes, when it is not yet serving, or
// when the operator has not told the provider its ingress address — a caller
// publishing DNS for an address nothing answers on is worse off than one that
// waits.
func (p *Provider) routeAddresses(routes []compute.Route, phase compute.Phase) []string {
	if len(routes) == 0 || phase != compute.PhaseReady || p.cfg.IngressAddress == "" {
		return nil
	}
	return []string{p.cfg.IngressAddress}
}

// routeTLSSecret resolves the certificate a route is served with, and enforces
// the interface's fail-closed rule.
//
// The rule is compute.Route's: nil TLS is plaintext, and plaintext requires
// AllowPlaintext. Before F4 the route had no certificate field at all, so this
// provider's only options were to serve plaintext (fail-open, the defect class
// the interface exists to remove), invent a certificate (forbidden), or refuse
// every route unless the operator had configured a platform-wide secret. It
// refused, which was right and was one provider's decision; it is the
// interface's now.
func (p *Provider) routeTLSSecret(r compute.Route) (string, error) {
	switch {
	case r.TLS != nil && r.TLS.CertificateRef != "":
		secret, ok := p.cfg.Certificates[r.TLS.CertificateRef]
		if !ok {
			return "", fmt.Errorf("%w: route %q names certificate %q, which provider %q cannot "+
				"resolve; a provider must not invent one", compute.ErrInvalidSpec, r.Host,
				r.TLS.CertificateRef, p.name)
		}
		return secret, nil
	case r.TLS != nil:
		return "", fmt.Errorf("%w: route %q asks for TLS and names no certificate",
			compute.ErrInvalidSpec, r.Host)
	case r.AllowPlaintext:
		return "", nil
	default:
		// No platform-wide default is applied here, deliberately. This provider
		// used to require Config.RouteTLSSecret and serve every route with it,
		// because Route carried no certificate and refusing was the only
		// alternative to serving plaintext. Now that the route names its own,
		// silently substituting a platform certificate would decide for the
		// caller which name is served under which key.
		return "", fmt.Errorf("%w: route %q names no certificate and does not set "+
			"AllowPlaintext; publishing an application over HTTP has to be something somebody "+
			"asked for", compute.ErrInvalidSpec, r.Host)
	}
}
