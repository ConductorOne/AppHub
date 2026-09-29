// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// The endpoint half of [compute.FunctionRuntime]: one [compute.EndpointSpec]
// becomes a security group, an application load balancer, a Lambda-type target
// group, a resource-policy statement on the function, a target registration and
// one listener per declared listener.
//
// # What "expose this workload at a URL" turned out to mean
//
// The interface question this port exists to answer was whether function
// exposure and container exposure need one shape. They do not, and the source
// system settles it with a denominator: of twenty-one files on the deploy path,
// exactly one uses ELBv2 and it is lambda.go. A container is exposed by
// registering with a reverse proxy that already exists — Traefik labels on the
// task definition — and a function is exposed by provisioning a load balancer of
// its own. Those are different operations on different objects, and
// [compute.Route] and [compute.EndpointSpec] are right to be two shapes.
//
// What is *not* right is that neither shape contains the other. See the report
// accompanying this ticket: a [compute.Route] can express path-prefix routing
// and platform authentication and an [compute.EndpointSpec] cannot, so a caller
// wanting an authenticated function endpoint has nowhere to say so. That is an
// interface finding, reported rather than worked around, and it is why this file
// does not advertise [compute.CapIngressAuth].
//
// # The five listener and reachability rules, all fail-closed
//
// Every one of them is a place the source system fails open, and each is
// enforced by refusing a spec rather than by adjusting one:
//
//  1. A [compute.ListenerHTTPS] listener needs a certificate this provider can
//     resolve. The source picks the HTTPS protocol enum for any port other than
//     80 (lambda.go:487-490) and never populates a Certificates field
//     (lambda.go:697-708), so every port other than 80 gets a listener that
//     cannot complete a handshake.
//  2. A [compute.ListenerHTTP] listener must not carry one, so that a caller
//     who supplied a certificate learns its listener is plaintext.
//  3. The protocol comes from [compute.ListenerSpec.Protocol] and never from the
//     port number.
//  4. Every listener port needs a reachability rule. A listener with none
//     accepts no traffic, which is a working-looking endpoint that answers
//     nothing.
//  5. A peer this provider cannot resolve is refused, never widened. See
//     [Provider.ingressRules].
//
// # Least privilege on the invoke grant
//
// The grant is scoped to the target group's ARN, which is the narrowest
// condition the elasticloadbalancing principal can be given: it authorises that
// one target group and no other load balancer in the account. The source system
// scopes it the same way (lambda.go:668-677) and this keeps that. What it does
// not keep is the constant statement identifier — see [invokeStatementID] — nor
// the tolerance of a failed grant, which the interface folds into this call for
// exactly that reason.

// EnsureEndpoint creates or converges the hostname a function answers on, and
// grants the endpoint permission to invoke it.
func (f *functionRuntime) EnsureEndpoint(ctx context.Context, spec compute.EndpointSpec) (*compute.EndpointStatus, error) {
	p := f.p
	if !p.caps.Has(compute.CapFunctionEndpoint) {
		return nil, &compute.UnsupportedError{
			Provider:   p.name,
			Capability: compute.CapFunctionEndpoint,
			Detail: "no load balancer is configured on this provider; a function is still " +
				"invocable through the control plane, which is what the source system does " +
				"whenever its needsAlb parameter is false",
		}
	}
	req, err := p.endpointRequest(ctx, spec)
	if err != nil {
		return nil, err
	}

	groupID, err := p.endpointEnsureIngressGroup(ctx, req.network, req.name,
		componentEndpointIngress, req.rules, req.ingressTags)
	if err != nil {
		return nil, err
	}
	lb, err := p.ensureLoadBalancer(ctx, req, groupID)
	if err != nil {
		return nil, err
	}
	tg, err := p.ensureTargetGroup(ctx, req)
	if err != nil {
		return nil, err
	}

	// The grant before the registration, and both before the listeners. A target
	// group whose target cannot be invoked is a load balancer answering 502, and
	// a listener is the thing that starts sending it traffic, so the last step
	// is the one that makes the endpoint live.
	if err := p.ensureInvokeGrant(ctx, req, tg); err != nil {
		return nil, err
	}
	if err := p.convergeTargets(ctx, tg.ARN, req.targetARN); err != nil {
		return nil, err
	}
	if err := p.convergeListeners(ctx, req, lb, tg); err != nil {
		return nil, err
	}
	return p.endpointStatus(ctx, req.network, lb)
}

// endpointRequest is a validated endpoint spec resolved against configuration
// and the substrate.
type endpointRequest struct {
	// name is the physical name of all three objects. See [Provider.endpointName]
	// for why there is one and not two.
	name        string
	network     networkPlacement
	scheme      string
	listeners   []CreateListenerRequest
	rules       []EndpointSecurityGroupRule
	tags        map[string]string
	targetTags  map[string]string
	ingressTags map[string]string
	targetName  string
	targetARN   string
	statementID string
}

func (p *Provider) endpointRequest(ctx context.Context, spec compute.EndpointSpec) (endpointRequest, error) {
	var out endpointRequest
	if err := validateName(spec.Name); err != nil {
		return out, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return out, err
	}
	if len(spec.Listeners) == 0 {
		return out, fmt.Errorf("%w: an endpoint needs at least one listener", compute.ErrInvalidSpec)
	}
	if len(spec.Hostnames) > 0 {
		// [compute.EndpointSpec.Hostnames] says a provider that cannot honour a
		// requested hostname returns ErrInvalidSpec rather than substituting its
		// own, and this provider cannot: a load balancer answers on the name
		// ELBv2 assigns it, and serving a caller's name would mean this package
		// managing DNS — a zone it was not given, a record it would then own,
		// and a hostname suffix compiled in, which is the shape of the internal
		// domain the source system hardcodes (source system @
		// backend/internal/modules/deploy/container.go) and
		// which must not exist in this repository.
		return out, fmt.Errorf("%w: this provider cannot serve a requested hostname (%v); a load "+
			"balancer answers on the name ELBv2 assigns it, reported in EndpointStatus.Hostname, "+
			"and pointing a name at it is DNS management this package does not do",
			compute.ErrInvalidSpec, spec.Hostnames)
	}

	np, err := p.resolveNetwork(spec.Placement)
	if err != nil {
		return out, err
	}
	out.network, err = p.describeNetwork(ctx, np)
	if err != nil {
		return out, err
	}
	if out.name, err = p.endpointName(spec.Name); err != nil {
		return out, err
	}
	out.statementID = invokeStatementID(out.name)

	if out.listeners, err = p.listeners(out.network, spec.Listeners); err != nil {
		return out, err
	}
	if out.rules, err = p.endpointIngressRules(out.network, spec.Ingress); err != nil {
		return out, err
	}
	if err := coversEveryListener(spec.Listeners, spec.Ingress); err != nil {
		return out, err
	}
	out.scheme = schemeFor(spec.Ingress)

	// The target is resolved and read back, so that an endpoint is never created
	// in front of a function that does not exist or that this platform does not
	// own. The source system registers whatever ARN it was handed
	// (lambda.go:472-480).
	if out.targetName, err = p.resolve(spec.Target, compute.KindFunction); err != nil {
		return out, err
	}
	fn, err := p.sub.Lambda.GetFunction(ctx, out.targetName)
	if err != nil {
		if errors.Is(err, ErrNoSuchResource) {
			return out, fmt.Errorf("%w: %s does not exist, so there is nothing for this endpoint "+
				"to forward to", compute.ErrInvalidSpec, spec.Target)
		}
		return out, p.substrateError(err)
	}
	if err := checkOwned(fn.Tags, "Lambda function", componentFunction, out.targetName); err != nil {
		return out, err
	}
	out.targetARN = fn.ARN

	effective := spec
	effective.Placement = compute.Placement{Name: out.network.Name}
	out.tags = ownershipTags(out.name, componentEndpoint, spec.Labels)
	out.tags[tagPlacement] = out.network.Name
	out.tags[tagTarget] = out.targetName
	// The target group and the security group carry the caller's labels too, so
	// that an operator filtering a console by one label sees the whole endpoint
	// rather than a third of it.
	out.targetTags = ownershipTags(out.name, componentEndpointTargets, spec.Labels)
	out.ingressTags = ownershipTags(out.name, componentEndpointIngress, spec.Labels)
	return out, nil
}

// listeners compiles [compute.ListenerSpec] into ELBv2 listener requests.
//
// Rules 1 to 3 of the five on this file live here. The protocol is taken from
// the spec and never from the port, which is what makes a certificate-less HTTPS
// listener a *representable and therefore testable* spec rather than a shape
// nobody can express — see [compute.ListenerSpec] for why that mattered enough
// to put a protocol field in the interface.
func (p *Provider) listeners(np networkPlacement, specs []compute.ListenerSpec) ([]CreateListenerRequest, error) {
	out := make([]CreateListenerRequest, 0, len(specs))
	seen := map[int]struct{}{}
	for _, l := range specs {
		if l.Port < 1 || l.Port > 65535 {
			return nil, fmt.Errorf("%w: listener port %d is not a port", compute.ErrInvalidSpec, l.Port)
		}
		if _, ok := seen[l.Port]; ok {
			return nil, fmt.Errorf("%w: two listeners on port %d; a load balancer accepts one",
				compute.ErrInvalidSpec, l.Port)
		}
		seen[l.Port] = struct{}{}

		proto := l.Protocol
		if proto == "" {
			proto = compute.ListenerHTTP
		}
		req := CreateListenerRequest{Port: l.Port}
		switch proto {
		case compute.ListenerHTTP:
			if l.TLS != nil {
				return nil, fmt.Errorf("%w: the listener on port %d is %q and carries a "+
					"certificate reference; a plaintext listener does not serve one, and accepting "+
					"this would leave a caller believing the port was encrypted",
					compute.ErrInvalidSpec, l.Port, compute.ListenerHTTP)
			}
			req.Protocol = ListenerProtocolHTTP
		case compute.ListenerHTTPS:
			if l.TLS == nil || strings.TrimSpace(l.TLS.CertificateRef) == "" {
				return nil, fmt.Errorf("%w: the listener on port %d is %q with no certificate; "+
					"ELBv2 will create such a listener and it cannot complete a handshake, which "+
					"is what the source system produces for every port other than 80",
					compute.ErrInvalidSpec, l.Port, compute.ListenerHTTPS)
			}
			arn, ok := np.Certificates[l.TLS.CertificateRef]
			if !ok || strings.TrimSpace(arn) == "" {
				// No default, ever. [compute.TLSConfig] says no provider may
				// invent one, and a substituted certificate is a certificate for
				// a name the caller did not ask to serve.
				return nil, fmt.Errorf("%w: certificate reference %q is not configured for "+
					"placement %q; the references available there are %v. This provider resolves "+
					"a reference and never invents one",
					compute.ErrInvalidSpec, l.TLS.CertificateRef, np.Name,
					sortedKeys(np.Certificates))
			}
			req.Protocol = ListenerProtocolHTTPS
			req.CertificateARN = arn
		default:
			return nil, fmt.Errorf("%w: %q is not a listener protocol this interface defines",
				compute.ErrInvalidSpec, l.Protocol)
		}
		out = append(out, req)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// coversEveryListener enforces rule 4: a listener with no reachability rule
// accepts no traffic.
//
// This is a fail-closed refusal rather than a fail-open one, and the direction
// is worth naming. The alternative to refusing is to open the port, which is
// what the source system does — it authorises every ALB port to 0.0.0.0/0 with
// no rule set to consult at all (lambda.go:576-586). Refusing costs a caller one
// line of spec; guessing costs them a port open to the internet they did not
// ask for.
func coversEveryListener(listeners []compute.ListenerSpec, rules []compute.IngressRule) error {
	covered := make(map[int]struct{}, len(rules))
	for _, r := range rules {
		covered[r.Port] = struct{}{}
	}
	for _, l := range listeners {
		if _, ok := covered[l.Port]; !ok {
			return fmt.Errorf("%w: the listener on port %d has no ingress rule, so it would accept "+
				"no traffic. This provider refuses rather than opening the port for you, which is "+
				"what the source system does", compute.ErrInvalidSpec, l.Port)
		}
	}
	return nil
}

// schemeFor derives the load balancer's scheme from the reachability the caller
// declared.
//
// Derived rather than configured, and that is the substantive design choice
// here. The source system hardcodes internet-facing (lambda.go:614) for every
// endpoint it creates, so an endpoint intended to be reachable only from the
// platform's own proxy still gets public addresses — the security group is then
// the only thing standing in front of it, and a security group is a rule set
// somebody can widen. A configuration knob would be no better: the caller has
// already said who may reach the endpoint, in [compute.EndpointSpec.Ingress],
// and asking an operator to keep a second setting in step with it is asking for
// the two to disagree.
//
// So: an endpoint any of whose rules names [compute.PeerInternet] is
// internet-facing, and one whose rules name only peers inside the platform is
// internal. The default direction is the closed one — an empty rule set cannot
// reach here, because [coversEveryListener] refuses it.
func schemeFor(rules []compute.IngressRule) string {
	for _, r := range rules {
		if r.From.Kind == compute.PeerInternet {
			return SchemeInternetFacing
		}
	}
	return SchemeInternal
}

// ensureLoadBalancer creates or adopts the load balancer, and converges the
// security groups attached to it.
func (p *Provider) ensureLoadBalancer(ctx context.Context, req endpointRequest, groupID string) (*LoadBalancerRecord, error) {
	lb, err := p.sub.ELBv2.DescribeLoadBalancer(ctx, req.name)
	switch {
	case err == nil:
		if err := checkOwned(lb.Tags, "load balancer", componentEndpoint, req.name); err != nil {
			return nil, err
		}
		// A scheme cannot be changed after creation, so a spec that would change
		// it is refused rather than silently ignored. Ignoring would leave an
		// endpoint the caller believes is internal answering on public
		// addresses, which is the worst of the two directions.
		if lb.Scheme != req.scheme {
			return nil, fmt.Errorf("%w: load balancer %q exists as %q and this spec's ingress "+
				"rules make it %q; ELBv2 cannot change a scheme after creation, so this needs a "+
				"differently-named endpoint rather than a converging one",
				compute.ErrInvalidSpec, req.name, lb.Scheme, req.scheme)
		}
		if !sameStrings(lb.SecurityGroupIDs, []string{groupID}) {
			if err := p.sub.ELBv2.SetSecurityGroups(ctx, lb.ARN, []string{groupID}); err != nil {
				return nil, p.substrateError(err)
			}
		}
	case errors.Is(err, ErrNoSuchResource):
		lb, err = p.sub.ELBv2.CreateLoadBalancer(ctx, CreateLoadBalancerRequest{
			Name:             req.name,
			SubnetIDs:        req.network.SubnetIDs,
			SecurityGroupIDs: []string{groupID},
			Scheme:           req.scheme,
			Tags:             req.tags,
		})
		if err != nil {
			return nil, p.substrateError(err)
		}
	default:
		return nil, p.substrateError(err)
	}

	put, remove := tagDelta(lb.Tags, req.tags)
	if len(remove) > 0 {
		if err := p.sub.ELBv2.RemoveTags(ctx, lb.ARN, remove); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.ELBv2.AddTags(ctx, lb.ARN, put); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(put) == 0 && len(remove) == 0 {
		return lb, nil
	}
	// Re-read, because the tags are part of the effective spec and two of them
	// are the *only* record of what this endpoint points at and where it is
	// placed ([tagTarget], [tagPlacement]). Returning the record read before the
	// write would report the previous target after an endpoint had been
	// re-pointed — a read-back describing the state the provider had just
	// replaced. A test found exactly that.
	//
	// Conditional on there being a write, so that the common path — an unchanged
	// spec, or a create whose tags went in with the create call — costs no extra
	// request.
	lb, err = p.sub.ELBv2.DescribeLoadBalancer(ctx, req.name)
	if err != nil {
		return nil, p.substrateError(err)
	}
	return lb, nil
}

// ensureTargetGroup creates or adopts the Lambda-type target group.
func (p *Provider) ensureTargetGroup(ctx context.Context, req endpointRequest) (*TargetGroupRecord, error) {
	tg, err := p.sub.ELBv2.DescribeTargetGroup(ctx, req.name)
	switch {
	case err == nil:
		// A distinct component from the load balancer's, even though the two
		// share a name. That is what makes sharing the name safe: neither object
		// can be adopted as the other.
		if err := checkOwned(tg.Tags, "target group", componentEndpointTargets, req.name); err != nil {
			return nil, err
		}
		if tg.TargetType != TargetTypeLambda {
			return nil, fmt.Errorf("%w: target group %q exists with target type %q and this port "+
				"registers a function; a target type cannot be changed after creation",
				compute.ErrInvalidSpec, req.name, tg.TargetType)
		}
	case errors.Is(err, ErrNoSuchResource):
		tg, err = p.sub.ELBv2.CreateTargetGroup(ctx, CreateTargetGroupRequest{
			Name:       req.name,
			TargetType: TargetTypeLambda,
			Tags:       req.targetTags,
		})
		if err != nil {
			return nil, p.substrateError(err)
		}
	default:
		return nil, p.substrateError(err)
	}

	put, remove := tagDelta(tg.Tags, req.targetTags)
	if len(remove) > 0 {
		if err := p.sub.ELBv2.RemoveTags(ctx, tg.ARN, remove); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.ELBv2.AddTags(ctx, tg.ARN, put); err != nil {
			return nil, p.substrateError(err)
		}
	}
	return tg, nil
}

// ensureInvokeGrant gives this endpoint, and only this endpoint, permission to
// invoke its target.
//
// Three differences from the source system's grantALBLambdaPermission
// (lambda.go:665-678), and the first two are the ones that matter:
//
//   - **The statement identifier is per-endpoint.** The source uses the constant
//     "AllowALBInvoke", so a second endpoint in front of the same function gets
//     a conflict instead of a second statement — and the source swallows that
//     conflict with a logged warning (lambda.go:461-467), leaving an endpoint
//     that was created, reported success, and cannot invoke anything.
//   - **A failed grant fails the call.** [compute.FunctionRuntime.EnsureEndpoint]
//     folds the grant into this method for precisely this reason: "an endpoint
//     that cannot invoke its target is not a partially-working endpoint, it is a
//     broken one."
//   - **The grant is idempotent by reading first.** Lambda has no upsert for a
//     resource-policy statement, so an unconditional AddPermission conflicts on
//     every reconcile of an unchanged spec. Listing the statement identifiers is
//     enough to tell — and it is deliberately identifiers rather than the policy
//     document, so nothing here parses a policy language.
//
// The scope is unchanged and already correct: the target group's ARN as the
// source condition, which authorises that one target group rather than the
// elasticloadbalancing principal at large.
func (p *Provider) ensureInvokeGrant(ctx context.Context, req endpointRequest, tg *TargetGroupRecord) error {
	ids, err := p.sub.Lambda.ListStatementIDs(ctx, req.targetName)
	if err != nil && !errors.Is(err, ErrNoSuchResource) {
		return p.substrateError(err)
	}
	for _, id := range ids {
		if id == req.statementID {
			// A statement under this endpoint's identifier already exists.
			// Replaced rather than assumed correct: the target group it is scoped
			// to may have been recreated, and a grant naming a target group that
			// no longer exists is a grant this endpoint cannot use.
			if err := p.sub.Lambda.RemovePermission(ctx, req.targetName, id); err != nil &&
				!errors.Is(err, ErrNoSuchResource) {
				return p.substrateError(err)
			}
			break
		}
	}
	err = p.sub.Lambda.AddPermission(ctx, AddPermissionRequest{
		Name:        req.targetName,
		StatementID: req.statementID,
		Action:      invokeAction,
		Principal:   elbPrincipal,
		SourceARN:   tg.ARN,
	})
	return p.substrateError(err)
}

// The one action and the one principal this port ever grants.
//
// Both are constants rather than parameters, and that is the least-privilege
// property expressed as code: there is no path through this package that grants
// a different action, or grants anything to a different principal, so a reviewer
// asking "what can this port authorise" gets a complete answer from these two
// lines rather than from following a string.
const (
	invokeAction = "lambda:InvokeFunction"
	elbPrincipal = "elasticloadbalancing.amazonaws.com"
)

// convergeTargets registers the endpoint's target and deregisters anything else.
//
// The deregistration half is what makes an endpoint re-pointable. Without it, an
// endpoint whose [compute.EndpointSpec.Target] changed forwards to both
// functions — a target group load-balances across its targets — so half the
// traffic reaches the function the caller stopped asking for.
func (p *Provider) convergeTargets(ctx context.Context, targetGroupARN, want string) error {
	current, err := p.sub.ELBv2.DescribeTargets(ctx, targetGroupARN)
	if err != nil {
		return p.substrateError(err)
	}
	var stale []string
	registered := false
	for _, t := range current {
		if t.ID == want {
			registered = true
			continue
		}
		stale = append(stale, t.ID)
	}
	if !registered {
		if err := p.sub.ELBv2.RegisterTargets(ctx, targetGroupARN, []string{want}); err != nil {
			return p.substrateError(err)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		if err := p.sub.ELBv2.DeregisterTargets(ctx, targetGroupARN, stale); err != nil {
			return p.substrateError(err)
		}
	}
	return nil
}

// convergeListeners reconciles the load balancer's listeners onto the declared
// set.
//
// Both halves. The source system only ever adds: ensureListener returns early
// when it finds a listener on the port (lambda.go:683-696) and there is no path
// that removes one, so a port dropped from a spec keeps accepting traffic
// forever. It also tolerates a failed create with a logged warning
// (lambda.go:485-495), producing an endpoint that reports success with a
// listener missing.
//
// A listener whose protocol or certificate changed is replaced rather than
// mutated, because ELBv2's modify call is a second code path to get wrong and
// the delete-then-create pair is the same two calls the create path already
// uses. Create precedes delete on a changed port so that the window is one of
// two listeners rather than none — except that ELBv2 will not accept two
// listeners on one port, so the order is forced the other way and the window is
// real. It is bounded by one API call and it only occurs on a spec change that
// alters a listener's protocol or certificate, which is stated here rather than
// hidden because it is the honest cost of not having an atomic replace.
func (p *Provider) convergeListeners(ctx context.Context, req endpointRequest, lb *LoadBalancerRecord, tg *TargetGroupRecord) error {
	current, err := p.sub.ELBv2.DescribeListeners(ctx, lb.ARN)
	if err != nil {
		return p.substrateError(err)
	}
	byPort := make(map[int]ListenerRecord, len(current))
	for _, l := range current {
		byPort[l.Port] = l
	}
	want := make(map[int]struct{}, len(req.listeners))

	for _, l := range req.listeners {
		want[l.Port] = struct{}{}
		l.LoadBalancerARN = lb.ARN
		l.TargetGroupARN = tg.ARN
		existing, ok := byPort[l.Port]
		if ok && existing.Protocol == l.Protocol &&
			existing.CertificateARN == l.CertificateARN &&
			existing.TargetGroupARN == l.TargetGroupARN {
			continue
		}
		if ok {
			if err := p.sub.ELBv2.DeleteListener(ctx, existing.ARN); err != nil &&
				!errors.Is(err, ErrNoSuchResource) {
				return p.substrateError(err)
			}
		}
		if _, err := p.sub.ELBv2.CreateListener(ctx, l); err != nil {
			return p.substrateError(err)
		}
	}
	for _, l := range current {
		if _, ok := want[l.Port]; ok {
			continue
		}
		if err := p.sub.ELBv2.DeleteListener(ctx, l.ARN); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}
	return nil
}

// DescribeEndpoint returns current state, or [compute.PhaseGone].
func (f *functionRuntime) DescribeEndpoint(ctx context.Context, ref compute.Ref) (*compute.EndpointStatus, error) {
	p := f.p
	name, err := p.resolve(ref, compute.KindFunctionEndpoint)
	if err != nil {
		return nil, err
	}
	lb, err := p.sub.ELBv2.DescribeLoadBalancer(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return &compute.EndpointStatus{Status: compute.Status{
			Ref: ref, Phase: compute.PhaseGone, UpdatedAt: time.Now().UTC(),
		}}, nil
	}
	if err != nil {
		return nil, p.substrateError(err)
	}
	// A Ref that was valid once is not a capability: the load balancer behind it
	// can have been deleted and a same-named one created by somebody else, so
	// ownership is re-established here rather than inherited from issuance.
	if err := checkOwned(lb.Tags, "load balancer", componentEndpoint, name); err != nil {
		return nil, err
	}
	// The placement is resolved **best-effort and for one purpose only**: naming
	// the peer of a platform-ingress rule. Nothing else in the status needs it,
	// because every read below finds its object by name or by ownership marker.
	//
	// An earlier revision bailed out to a degraded status here when the placement
	// could not be resolved, and the degraded status carried no ingress rules at
	// all — so removing a placement from configuration made this method report
	// that nothing may reach an endpoint that was in fact reachable. The
	// resolution is not a better fallback; it is that the read no longer depends
	// on the placement.
	resolved := networkPlacement{PlacementConfig: PlacementConfig{Name: lb.Tags[tagPlacement]}}
	if np, err := p.resolveNetwork(compute.Placement{Name: lb.Tags[tagPlacement]}); err == nil {
		if full, err := p.describeNetwork(ctx, np); err == nil {
			resolved = full
		} else {
			resolved = np
		}
	}
	return p.endpointStatus(ctx, resolved, lb)
}

// WaitForEndpoint blocks until the endpoint is serving, fails, or the deadline
// elapses.
func (f *functionRuntime) WaitForEndpoint(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.EndpointStatus, error) {
	p := f.p
	name, err := p.resolve(ref, compute.KindFunctionEndpoint)
	if err != nil {
		return nil, err
	}
	var last *compute.EndpointStatus
	err = p.await(ctx, opts, func(ctx context.Context) (compute.Status, bool, error) {
		// Only the load balancer's own state is polled, not the whole endpoint.
		// Waiting is about convergence and the other five objects are created
		// synchronously; re-reading them on every poll would turn a wait into a
		// stream of describe calls against three rate-limited APIs.
		lb, err := p.sub.ELBv2.DescribeLoadBalancer(ctx, name)
		if errors.Is(err, ErrNoSuchResource) {
			last = &compute.EndpointStatus{Status: compute.Status{
				Ref: ref, Phase: compute.PhaseGone, UpdatedAt: time.Now().UTC(),
			}}
			return last.Status, true, nil
		}
		if err != nil {
			return compute.Status{}, false, p.substrateError(err)
		}
		// Same re-check as DescribeEndpoint, for the same reason: this loop reads
		// the substrate directly rather than through DescribeEndpoint, so it does
		// not inherit that check for free.
		if err := checkOwned(lb.Tags, "load balancer", componentEndpoint, name); err != nil {
			return compute.Status{}, false, err
		}
		// The load balancer **and** its target's health. Polling only the load
		// balancer is what made an earlier revision report ready for an endpoint
		// whose sole target answers every request with a 502; see
		// [endpointPhase]. The listeners are still not re-read on every poll —
		// they are created synchronously and have no convergence state — so this
		// is two describes per poll and not six.
		health, err := p.targetHealth(ctx, name)
		if err != nil {
			return compute.Status{}, false, err
		}
		last = p.endpointStatusFromLoadBalancer(ref, lb, nil, health)
		return last.Status, settled(last.Phase), nil
	})
	if err != nil {
		return last, err
	}
	if last.Phase == compute.PhaseFailed {
		return last, fmt.Errorf("%w: %s", compute.ErrFailed, last.Message)
	}
	// The effective spec is filled in only once, on the way out, for the same
	// reason the poll does not read it.
	if full, err := f.DescribeEndpoint(ctx, ref); err == nil {
		return full, nil
	}
	return last, nil
}

// DeleteEndpoint removes an endpoint. Idempotent.
//
// The order is forced by dependencies and each step tolerates an absent
// resource, which is what makes the whole thing re-runnable: listeners before
// the target group they forward to, the target group before the load balancer,
// the invoke grant whenever, and the security group last because ELBv2 holds
// network interfaces in it until the load balancer is gone.
//
// # The two-call teardown, which is the ordinary path and not an edge case
//
// On a real account, deleting a load balancer is asynchronous and its network
// interfaces are released minutes later, so the security group delete at the end
// fails on the first call with EC2's DependencyViolation. That is reported as
// [compute.ErrTransient] — see [sdkEC2.err] — and the caller's retry is what
// finishes the job. So the **second** call is the one that actually removes the
// security group, and on that call the load balancer is already gone.
//
// An earlier revision returned nil from exactly there. It read the placement off
// the load balancer's tag, found no load balancer, and returned success with the
// security group still in place — a teardown reporting success while leaving a
// resource behind, which is the class of the worst finding on this project. Two
// things make it work now: all three objects share one physical name, so the
// group is locatable from the reference alone (see [Provider.endpointName]), and
// with no load balancer to name the placement every configured placement is
// searched, each with the ownership check applied.
//
// The contract this method now meets: **it removes everything it created, or it
// reports what remains.** There is no third outcome, and in particular there is
// no path that returns nil having left a group behind — a group whose ownership
// tags mean the next Ensure of the same name would adopt it, with the old rule
// set, instead of creating a fresh one.
func (f *functionRuntime) DeleteEndpoint(ctx context.Context, ref compute.Ref) error {
	p := f.p
	name, err := p.resolve(ref, compute.KindFunctionEndpoint)
	if err != nil {
		return err
	}
	lb, err := p.sub.ELBv2.DescribeLoadBalancer(ctx, name)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		lb = nil
	case err != nil:
		return p.substrateError(err)
	default:
		if err := checkOwned(lb.Tags, "load balancer", componentEndpoint, name); err != nil {
			return err
		}
	}

	if lb != nil {
		listeners, err := p.sub.ELBv2.DescribeListeners(ctx, lb.ARN)
		if err != nil && !errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
		for _, l := range listeners {
			if err := p.sub.ELBv2.DeleteListener(ctx, l.ARN); err != nil &&
				!errors.Is(err, ErrNoSuchResource) {
				return p.substrateError(err)
			}
		}
	}

	// The invoke grant is withdrawn from the *function*, which outlives the
	// endpoint. Nothing else does this: a grant left behind is a statement in a
	// live function's resource policy naming a target group that no longer
	// exists, and the next endpoint under the same name would find the stale
	// statement rather than create its own.
	if lb != nil {
		if target := lb.Tags[tagTarget]; target != "" {
			err := p.sub.Lambda.RemovePermission(ctx, target, invokeStatementID(name))
			if err != nil && !errors.Is(err, ErrNoSuchResource) {
				return p.substrateError(err)
			}
		}
	}

	tg, err := p.sub.ELBv2.DescribeTargetGroup(ctx, name)
	switch {
	case errors.Is(err, ErrNoSuchResource):
	case err != nil:
		return p.substrateError(err)
	default:
		if err := checkOwned(tg.Tags, "target group", componentEndpointTargets, name); err != nil {
			return err
		}
		if err := p.sub.ELBv2.DeleteTargetGroup(ctx, tg.ARN); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}

	if lb != nil {
		if err := p.sub.ELBv2.DeleteLoadBalancer(ctx, lb.ARN); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}

	// The security group, by its ownership marker and not by any placement.
	//
	// This used to read the placement off the load balancer's tag and search the
	// configured placements if that failed. Both halves were scoped by
	// configuration, and configuration is what changes underneath a resource
	// created earlier: with the original placement removed, the group's VPC was
	// in neither population and the teardown returned success with the group
	// still there. See [Provider.deleteIngressGroupsByMarker].
	//
	// Note this runs whether or not the load balancer was found. The group
	// outlives the load balancer by construction — that is the whole reason the
	// second call exists — so making its removal conditional on the load balancer
	// still being there is the shape of the original defect.
	return p.endpointDeleteIngressGroupsByMarker(ctx, name, componentEndpointIngress)
}

// endpointStatus assembles the full status, including the effective spec
// reconstructed from the substrate.
func (p *Provider) endpointStatus(ctx context.Context, np networkPlacement, lb *LoadBalancerRecord) (*compute.EndpointStatus, error) {
	ref := p.ref(compute.KindFunctionEndpoint, lb.Name)
	listeners, err := p.sub.ELBv2.DescribeListeners(ctx, lb.ARN)
	if err != nil && !errors.Is(err, ErrNoSuchResource) {
		return nil, p.substrateError(err)
	}
	// By marker, not by np.VpcID. The same reasoning as the teardown: a
	// placement-scoped read of a resource created earlier is scoped by what
	// configuration says now. An earlier revision reported an effective spec with
	// **no ingress rules** once the endpoint's placement was removed from
	// configuration — a read-back asserting an empty rule set over a group full of
	// them, which is the same wrong-population shape one method along.
	var rules []compute.IngressRule
	groups, err := p.endpointFindIngressGroups(ctx, lb.Name, componentEndpointIngress)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		stored, err := p.sub.EndpointEC2.DescribeSecurityGroupRules(ctx, g.ID)
		if err != nil {
			return nil, p.substrateError(err)
		}
		described, err := p.endpointDescribeIngress(stored, componentEndpointIngress)
		if err != nil {
			return nil, err
		}
		rules = append(rules, described...)
	}
	health, err := p.targetHealth(ctx, lb.Name)
	if err != nil {
		return nil, err
	}
	st := p.endpointStatusFromLoadBalancer(ref, lb, listeners, health)
	st.Spec.Placement = compute.Placement{Name: np.Name}
	st.Spec.Ingress = rules
	return st, nil
}

// targetHealth reads the health of the targets registered with an endpoint's
// target group.
//
// An absent target group is not an error: it is what a partially-created or
// partially-deleted endpoint looks like, and reporting it as a failure would
// make a Describe on a half-torn-down endpoint fail rather than describe it.
func (p *Provider) targetHealth(ctx context.Context, name string) ([]TargetHealth, error) {
	tg, err := p.sub.ELBv2.DescribeTargetGroup(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, nil
	}
	if err != nil {
		return nil, p.substrateError(err)
	}
	health, err := p.sub.ELBv2.DescribeTargets(ctx, tg.ARN)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, nil
	}
	if err != nil {
		return nil, p.substrateError(err)
	}
	return health, nil
}

// endpointStatusFromLoadBalancer builds the part of the status that needs only
// the load balancer and its target health, so that a Wait's poll and a degraded
// Describe share one mapping.
func (p *Provider) endpointStatusFromLoadBalancer(ref compute.Ref, lb *LoadBalancerRecord, listeners []ListenerRecord, health []TargetHealth) *compute.EndpointStatus {
	phase, message := endpointPhase(lb, health)
	spec := compute.EndpointSpec{
		Name:      nameFromTags(lb),
		Placement: compute.Placement{Name: lb.Tags[tagPlacement]},
		Labels:    labelsFromTags(lb.Tags),
	}
	if target := lb.Tags[tagTarget]; target != "" {
		spec.Target = p.ref(compute.KindFunction, target)
	}
	for _, l := range listeners {
		spec.Listeners = append(spec.Listeners, p.listenerSpec(lb, l))
	}
	sort.Slice(spec.Listeners, func(i, j int) bool { return spec.Listeners[i].Port < spec.Listeners[j].Port })
	return &compute.EndpointStatus{
		Status: compute.Status{
			Ref: ref, Phase: phase, Message: message, UpdatedAt: time.Now().UTC(),
		},
		Spec:     spec,
		Hostname: lb.DNSName,
	}
}

// listenerSpec is the inverse of the compiler in [Provider.listeners].
//
// The certificate is reported as the *reference* the caller used rather than as
// the ARN it resolved to, recovered by inverting the placement's configured map.
// Reporting the ARN would put an account identifier into a value that travels
// out through [compute] — the one thing this package's configuration rules exist
// to prevent — and would also not round-trip: a caller comparing the effective
// spec against what it sent would see a string it had never written.
func (p *Provider) listenerSpec(lb *LoadBalancerRecord, l ListenerRecord) compute.ListenerSpec {
	out := compute.ListenerSpec{Port: l.Port}
	if l.Protocol != ListenerProtocolHTTPS {
		out.Protocol = compute.ListenerHTTP
		return out
	}
	out.Protocol = compute.ListenerHTTPS
	pc, ok := p.cfg.Placements[lb.Tags[tagPlacement]]
	if !ok {
		return out
	}
	for ref, arn := range pc.Certificates {
		if arn == l.CertificateARN {
			out.TLS = &compute.TLSConfig{CertificateRef: ref}
			break
		}
	}
	return out
}

// endpointPhase maps the load balancer's state **and its target's health** onto
// one phase.
//
// # Why the target is part of readiness
//
// [compute.PhaseReady] means serving, and
// [compute.FunctionRuntime.WaitForEndpoint] promises to block until the endpoint
// *is* serving. An earlier revision mapped an active load balancer straight to
// ready, which is a correctly-counted wrong population: one of the endpoint's
// six objects was active and the whole construction was called serving. A load
// balancer whose only target is unhealthy answers every request with a 502.
//
// Registration is not health, and the distinction was being lost below the
// substrate seam: the adapter already called DescribeTargetHealth and discarded
// every state, keeping only the identifiers. It keeps the state now.
//
// The three-way split matters as much as including health at all:
//
//   - **no targets at all** is pending, not failed — it is what an endpoint
//     looks like between its create and its registration;
//   - **[TargetInitial]** is pending, because ELBv2 has not finished checking
//     and a Wait should keep waiting rather than give up;
//   - anything else that is not [TargetHealthy] is **failed**, carrying ELBv2's
//     own reason, because a caller that cannot distinguish "not yet" from
//     "never" has to choose between waiting forever and abandoning early.
func endpointPhase(lb *LoadBalancerRecord, health []TargetHealth) (compute.Phase, string) {
	switch lb.State {
	case LoadBalancerFailed:
		return compute.PhaseFailed, lb.StateReason
	case LoadBalancerActive:
	default:
		return compute.PhasePending, lb.StateReason
	}
	if len(health) == 0 {
		return compute.PhasePending, "the load balancer is active and no target is registered yet"
	}
	for _, t := range health {
		switch t.State {
		case TargetHealthy:
		case TargetInitial, "":
			return compute.PhasePending, "the load balancer is active and its target is still " +
				"being health-checked"
		default:
			return compute.PhaseFailed, fmt.Sprintf(
				"the load balancer is active and its target is %q: %s", t.State, t.Reason)
		}
	}
	return compute.PhaseReady, ""
}

func nameFromTags(lb *LoadBalancerRecord) string {
	if n := lb.Tags[tagName]; n != "" {
		return n
	}
	return lb.Name
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// renderListeners formats a listener set for a rendered artefact.
//
// The format is "<port>/plaintext" and "<port>/tls", and the certificate appears
// only when there is one. A listener rendered as `certificate=""` is exactly the
// artefact the conformance suite hunts for — the source system's
// certificate-less HTTPS listener — so this must not be able to emit one, and it
// cannot: the token is written only inside the branch that has an ARN.
func renderListeners(listeners []ListenerRecord) string {
	parts := make([]string, 0, len(listeners))
	for _, l := range listeners {
		if l.Protocol == ListenerProtocolHTTPS {
			parts = append(parts, strconv.Itoa(l.Port)+"/tls(certificate="+l.CertificateARN+")")
			continue
		}
		parts = append(parts, strconv.Itoa(l.Port)+"/plaintext")
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
