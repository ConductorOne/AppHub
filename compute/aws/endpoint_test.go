// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// endpointSpec is an endpoint spec this provider accepts, so that each test can
// change one thing.
func endpointSpec(name string, target compute.Ref) compute.EndpointSpec {
	return compute.EndpointSpec{
		Name:   name,
		Target: target,
		Listeners: []compute.ListenerSpec{
			{Port: 80, Protocol: compute.ListenerHTTP},
			{Port: 443, Protocol: compute.ListenerHTTPS,
				TLS: &compute.TLSConfig{CertificateRef: testCertificateRef}},
		},
		Ingress: []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerInternet}, Port: 80},
			{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443},
		},
		Labels: map[string]string{"owner": "test"},
	}
}

// endpointFixture builds a provider, a function and the port, since every test
// below needs all three.
func endpointFixture(t *testing.T, mutate func(*aws.Config)) (*aws.Provider, *aws.Substrate, compute.FunctionRuntime, compute.Ref) {
	t.Helper()
	p, sub := newProvider(t, mutate)
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "endpoint")
	fn, err := rt.EnsureFunction(context.Background(), functionSpec("endpoint-target", id))
	if err != nil {
		t.Fatalf("seeding the target function: %v", err)
	}
	return p, sub, rt, fn.Ref
}

// --- fail closed ------------------------------------------------------------

// TestAListenerWithNoReachabilityRuleIsRefused is the fail-closed rule the
// conformance suite does not cover, and the direction matters.
//
// The alternative to refusing is to open the port, which is what the source
// system does: it authorises every load balancer port to 0.0.0.0/0 and ::/0 with
// no rule set to consult at all (lambda.go:576-586). Refusing costs a caller one
// line of spec. Guessing costs them a port open to the internet they did not ask
// for.
func TestAListenerWithNoReachabilityRuleIsRefused(t *testing.T) {
	t.Parallel()

	_, _, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("uncovered", fn)
	// Two listeners, one rule.
	spec.Ingress = spec.Ingress[:1]
	_, err := rt.EnsureEndpoint(context.Background(), spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a listener with no ingress rule was answered with %v. It has to be "+
			"ErrInvalidSpec: the listener would accept no traffic, and the only other option is "+
			"opening the port for the caller, which is the source system's defect", err)
	}
	if !strings.Contains(err.Error(), "443") {
		t.Errorf("the refusal does not name the uncovered port: %v", err)
	}
}

// TestAPeerThisProviderCannotResolveIsRefusedRatherThanWidened is the same rule
// one layer down, as a table over every peer kind.
//
// A class rather than a case: the property is "a peer this provider cannot
// resolve is refused", and the table covers all four kinds so that adding a
// PeerKind to the interface forces a decision here rather than falling through
// to a default.
func TestAPeerThisProviderCannotResolveIsRefusedRatherThanWidened(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		kind     compute.PeerKind
		accepted bool
		why      string
	}{
		{compute.PeerInternet, true, "a public endpoint is what the source system builds"},
		{compute.PeerPlatformIngress, true, "configured on this placement"},
		{compute.PeerControlPlane, false,
			"this package holds no configuration naming apphub's own control plane"},
		{compute.PeerWorkload, false,
			"a Lambda function has no security group for a workload peer to name"},
	}

	// The table above is a hand-maintained restatement of the interface's peer
	// enumeration, and a restatement drifts from its source. So it is
	// cross-checked against the source generatively: every declared PeerKind must
	// appear here with a decision recorded, accept or refuse.
	//
	// This is the assertion that makes the *other* test's axis honest. That one
	// ranges over the accepted kinds, which means a peer kind added to the
	// interface and refused by this port would quietly not be ranged over — an
	// axis that cannot traverse passes. Here it fails, loudly, and names what to
	// decide.
	declared := declaredPeerKinds(t)
	covered := make(map[compute.PeerKind]bool, len(cases))
	for _, tc := range cases {
		covered[tc.kind] = true
	}
	for _, kind := range declared {
		if !covered[kind] {
			t.Errorf("compute declares PeerKind %q and this table records no decision for it. "+
				"Decide whether this port accepts or refuses it — and if it accepts it, the "+
				"removed-placement transition will range over it too", kind)
		}
	}
	if len(covered) != len(declared) {
		t.Errorf("the table records %d peer kinds and the interface declares %d; a table larger "+
			"than its source is as stale as one smaller", len(covered), len(declared))
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			_, _, rt, fn := endpointFixture(t, nil)
			spec := endpointSpec("peer", fn)
			spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
			spec.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: tc.kind}, Port: 80}}
			_, err := rt.EnsureEndpoint(ctx, spec)
			switch {
			case tc.accepted && err != nil:
				t.Fatalf("a %q rule was refused with %v, and %s", tc.kind, err, tc.why)
			case !tc.accepted && err == nil:
				t.Fatalf("a %q rule was accepted; %s, so it was either ignored — leaving a "+
					"listener nothing can reach — or widened to something this provider can "+
					"resolve, which is the source system's defect", tc.kind, tc.why)
			case !tc.accepted && !errors.Is(err, compute.ErrInvalidSpec):
				t.Fatalf("a %q rule was refused with %v, want ErrInvalidSpec", tc.kind, err)
			}
		})
	}
}

// TestAPlatformIngressPeerIsRefusedWhenNoProxyIsConfigured is the case
// CONTRACT.md names explicitly: the source system reads its ingress security
// group from TRAEFIK_SECURITY_GROUP_ID and, when it is unset, opens the port to
// 0.0.0.0/0 instead (build.go:822-848). A missing configuration value widening a
// security boundary.
//
// It also checks the capability, because compute.CapPlatformIngress exists so
// that a caller can discover this before it deploys rather than by having an
// EnsureEndpoint fail.
func TestAPlatformIngressPeerIsRefusedWhenNoProxyIsConfigured(t *testing.T) {
	t.Parallel()

	p, _, rt, fn := endpointFixture(t, func(cfg *aws.Config) {
		for name, pc := range cfg.Placements {
			pc.PlatformIngressSecurityGroupID = ""
			// CapPlatformIngress is provider-wide, not per-port: it also derives
			// from the container port's own (differently-shaped)
			// PlatformIngressSecurityGroups, since compute.CapPlatformIngress
			// documents "the same provider code has it when an operator has told
			// it where the ingress proxy is" with no per-port qualification. "No
			// proxy configured" therefore has to clear both fields, or the
			// container port's fixture value keeps the capability advertised.
			pc.PlatformIngressSecurityGroups = nil
			cfg.Placements[name] = pc
		}
	})
	if p.Capabilities().Has(compute.CapPlatformIngress) {
		t.Error("the provider advertises platform-ingress with no ingress proxy configured; a " +
			"capability a caller checks before deploying has to mean the spec will be accepted")
	}

	spec := endpointSpec("no-proxy", fn)
	spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 80},
	}
	_, err := rt.EnsureEndpoint(context.Background(), spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a platform-ingress rule with no proxy configured was answered with %v, want "+
			"ErrInvalidSpec. The source system widens it to the internet here", err)
	}
}

// TestTheSchemeFollowsTheDeclaredReachability.
//
// The source system hardcodes internet-facing (lambda.go:614) for every endpoint
// it creates, so an endpoint meant to be reachable only from the platform's own
// proxy still gets public addresses and the security group becomes the only thing
// in front of it. Here the scheme is derived from the rules the caller already
// wrote, so the two cannot disagree — which a second configuration knob would
// eventually let them do.
func TestTheSchemeFollowsTheDeclaredReachability(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		what string
		peer compute.PeerKind
		want string
	}{
		{"a public endpoint", compute.PeerInternet, "internet-facing"},
		{"an endpoint only the platform proxy may reach", compute.PeerPlatformIngress, "internal"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			p, _, rt, fn := endpointFixture(t, nil)
			spec := endpointSpec("scheme", fn)
			spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
			spec.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: tc.peer}, Port: 80}}
			if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
				t.Fatalf("EnsureEndpoint failed: %v", err)
			}
			if !renderedContains(t, p, "scheme="+tc.want) {
				t.Fatalf("%s was not created with scheme=%s.\n%s",
					tc.what, tc.want, strings.Join(rendered(t, p), "\n"))
			}
		})
	}
}

// TestARequestedHostnameIsRefusedRatherThanSubstituted.
//
// compute.EndpointSpec.Hostnames says a provider that cannot honour a requested
// hostname returns ErrInvalidSpec rather than substituting its own, and this one
// cannot: a load balancer answers on the name ELBv2 assigns it. Serving a
// caller's name would mean this package managing DNS, and composing one would
// mean a hostname suffix compiled in — which is the shape of the internal domain
// the source system hardcodes and which must not exist in this repository.
func TestARequestedHostnameIsRefusedRatherThanSubstituted(t *testing.T) {
	t.Parallel()

	_, _, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("hostname", fn)
	spec.Hostnames = []string{"app.example.invalid"}
	_, err := rt.EnsureEndpoint(context.Background(), spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a requested hostname was answered with %v. Accepting it and then answering on "+
			"a different name is the failure the interface's own comment describes: the caller "+
			"chooses the certificate and the provider chooses the name it is served under, and "+
			"the two have to agree", err)
	}
}

// --- least privilege --------------------------------------------------------

// TestTheInvokeGrantIsScopedToOneTargetGroup.
//
// CONTRACT.md: least privilege in every generated IAM policy, and a grant widened
// to satisfy an interface has already been caught in review once on this project.
// AddPermission is the grant this port makes, and there are three things to
// check: that it names a source condition at all, that the condition is the
// target group rather than anything wider, and that the action is the single one
// this port needs.
func TestTheInvokeGrantIsScopedToOneTargetGroup(t *testing.T) {
	t.Parallel()

	p, _, rt, fn := endpointFixture(t, nil)
	if _, err := rt.EnsureEndpoint(context.Background(), endpointSpec("grant", fn)); err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}

	policy := renderedMatching(t, p, "FunctionPolicy ")
	if len(policy) == 0 {
		t.Fatal("no resource-policy statement was written, so the endpoint cannot invoke its " +
			"target. The interface folds the grant into EnsureEndpoint precisely because an " +
			"endpoint that cannot invoke its target is a broken one, not a partial one")
	}
	for _, st := range policy {
		if !strings.Contains(st, "when source is arn:") {
			t.Errorf("a grant carries no source condition, so it authorises every load balancer "+
				"the elasticloadbalancing principal can act for: %s", st)
		}
		if !strings.Contains(st, ":targetgroup/") {
			t.Errorf("a grant's source condition is not a target group, so it is wider than the "+
				"one thing that has to be able to invoke: %s", st)
		}
		if !strings.Contains(st, "lambda:InvokeFunction") {
			t.Errorf("a grant names an action other than lambda:InvokeFunction: %s", st)
		}
		for _, wildcard := range []string{"\"*\"", " * ", ":*"} {
			if strings.Contains(st, wildcard) {
				t.Errorf("a grant contains a wildcard (%q): %s", wildcard, st)
			}
		}
	}
}

// TestTwoEndpointsOnOneFunctionEachGetTheirOwnGrant.
//
// The source system uses the constant statement identifier "AllowALBInvoke"
// (lambda.go:670), so a second endpoint in front of the same function gets a
// conflict rather than a second statement — and it swallows that conflict with a
// logged warning (lambda.go:461-467), leaving an endpoint that was created,
// reported success, and cannot invoke anything.
//
// This is also the test that shows the statement identifier is derived from the
// endpoint rather than fixed, which is what makes the withdrawal in
// DeleteEndpoint able to name one grant.
func TestTwoEndpointsOnOneFunctionEachGetTheirOwnGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _, rt, fn := endpointFixture(t, nil)
	for _, name := range []string{"first-endpoint", "second-endpoint"} {
		if _, err := rt.EnsureEndpoint(ctx, endpointSpec(name, fn)); err != nil {
			t.Fatalf("EnsureEndpoint(%s) failed: %v", name, err)
		}
	}
	statements := renderedMatching(t, p, "FunctionPolicy ")
	if len(statements) != 2 {
		t.Fatalf("two endpoints produced %d resource-policy statements, want 2. With one "+
			"statement the second endpoint cannot invoke the function:\n%s",
			len(statements), strings.Join(statements, "\n"))
	}
	// And they are distinguishable, which is what lets one be withdrawn.
	if statements[0] == statements[1] {
		t.Fatal("the two statements are identical, so withdrawing one endpoint's grant would " +
			"withdraw the other's")
	}
}

// TestDeletingAnEndpointWithdrawsItsGrantFromTheFunction.
//
// The function outlives the endpoint, so a grant left behind is a live statement
// in its resource policy naming a target group that no longer exists. Nothing in
// the source system does this: it has no teardown for the ALB path at all.
func TestDeletingAnEndpointWithdrawsItsGrantFromTheFunction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _, rt, fn := endpointFixture(t, nil)
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("withdrawn", fn))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	if got := len(renderedMatching(t, p, "FunctionPolicy ")); got != 1 {
		t.Fatalf("expected one grant before the delete, got %d", got)
	}
	if err := rt.DeleteEndpoint(ctx, ep.Ref); err != nil {
		t.Fatalf("DeleteEndpoint failed: %v", err)
	}
	if got := renderedMatching(t, p, "FunctionPolicy "); len(got) != 0 {
		t.Fatalf("the invoke grant survived the endpoint's deletion: %v. It names a target group "+
			"that no longer exists, and the next endpoint under the same name would find it", got)
	}
}

// --- the declarative half ---------------------------------------------------

// TestARuleRemovedFromASpecIsRevokedWhateverItsDescription is the invariant the
// whole RevokeSecurityGroupIngress argument rests on, quantified over the
// description rather than asserted for one value of it.
//
// compute.IngressRule is declarative: the set attached to a spec is the desired
// state, reconciled to exactly that set on every Ensure. An implementation that
// only authorises passes every test that checks a rule is present, and leaves
// every rule ever asked for open forever — so "I removed that rule" silently
// means "I stopped asking for it". A security control failing open.
//
// # Why the description is the parameter
//
// An earlier revision read ownership from IngressRule.Description, and its test
// used the empty-description path — the one case the discriminator recognised.
// So the test proved the property for exactly the input that could not falsify
// it, while a caller who described their own rule got a port that stayed open
// after they closed it. That is CONTRACT lesson 3 in its stated form: the gap
// sat one generalisation away from the test already written.
//
// The description is now the loop variable, and the empty case is one row of
// several rather than the only row. Ownership is a tag, which a caller cannot
// write.
//
// The observation is of the substrate, not of the effective spec, because a
// provider that reported the new spec while leaving the old rule in place would
// satisfy any interface-level check — compute.Status says so, and a reviewer on
// this project built exactly that.
func TestARuleRemovedFromASpecIsRevokedWhateverItsDescription(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, description := range []string{
		"",
		// The case that was live: ordinary human text, with no marker in it.
		"public HTTPS for customers",
		// Text that mentions the project, which the old substring test would
		// have recognised. Kept so the table covers both sides of the boundary
		// the old mechanism drew, rather than only the side that used to fail.
		"apphub-managed HTTPS",
		"not managed by apphub",
		// Text shaped like the old default, which is the adversarial case: a
		// caller spelling the marker exactly must not get different treatment
		// from a caller spelling anything else.
		"apphub",
	} {
		t.Run("description="+description, func(t *testing.T) {
			t.Parallel()
			p, _, rt, fn := endpointFixture(t, nil)

			spec := endpointSpec("revoked", fn)
			for i := range spec.Ingress {
				spec.Ingress[i].Description = description
			}
			if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
				t.Fatalf("the first Ensure failed: %v", err)
			}
			if !renderedContains(t, p, "tcp/443/0.0.0.0/0") {
				t.Fatalf("the port 443 rule was never authorised, so this test cannot show it "+
					"being revoked:\n%s", strings.Join(rendered(t, p), "\n"))
			}

			// Drop the 443 listener and its rule, which is what a caller
			// disabling TLS on an application does.
			spec.Listeners = spec.Listeners[:1]
			spec.Ingress = spec.Ingress[:1]
			if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
				t.Fatalf("the second Ensure failed: %v", err)
			}
			if renderedContains(t, p, "tcp/443/0.0.0.0/0") {
				t.Fatalf("the port 443 rule survived a spec that omits it, with description %q. "+
					"Ingress accumulated rather than converging, so a caller who closed a port "+
					"did not close it:\n%s", description, strings.Join(rendered(t, p), "\n"))
			}
			if renderedContains(t, p, "443/tls") {
				t.Fatalf("the port 443 listener survived a spec that omits it:\n%s",
					strings.Join(rendered(t, p), "\n"))
			}
			// And the rule the spec still names stayed. Without this the test
			// would pass against a provider that revoked everything.
			if !renderedContains(t, p, "tcp/80/0.0.0.0/0") {
				t.Error("the port 80 rule was revoked too; convergence removed a rule the spec " +
					"still names")
			}
		})
	}
}

// TestARuleThisProviderDidNotCreateSurvivesConvergence is the other direction,
// and it is a *destructive* failure rather than a fail-open one.
//
// The revoke set has to be narrowed to rules this provider created, because an
// operator or an account policy may have added one to a group apphub created
// and reconciling a spec is not the same as taking over a resource. An earlier
// revision narrowed it by searching the description for "apphub", so an
// operator's rule whose text merely mentioned the project was deleted — by an
// *unchanged* Ensure, which is the worst possible trigger.
//
// The table covers both sides of that boundary and the sibling-port case:
//
//   - text with no mention of the project, which the old mechanism happened to
//     get right;
//   - text that mentions it, which it got wrong;
//   - text that is exactly the old marker, which it got most wrong;
//   - a rule carrying apphub's own owner tag under a *different* component,
//     which is what a sibling AWS port's rule in the same VPC looks like and
//     which no description test could ever have distinguished.
func TestARuleThisProviderDidNotCreateSurvivesConvergence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		what string
		rule aws.EndpointSecurityGroupRule
	}{
		{
			what: "an operator rule with unrelated text",
			rule: aws.EndpointSecurityGroupRule{
				Protocol: "tcp", Port: 8443, CIDRv4: "10.0.0.0/8",
				Description: "opened by the account owner for a health probe",
			},
		},
		{
			what: "an operator rule whose text mentions the project",
			rule: aws.EndpointSecurityGroupRule{
				Protocol: "tcp", Port: 8444, CIDRv4: "10.0.0.0/8",
				Description: "operator: not managed by apphub",
			},
		},
		{
			what: "an operator rule whose text is exactly the old marker",
			rule: aws.EndpointSecurityGroupRule{
				Protocol: "tcp", Port: 8445, CIDRv4: "10.0.0.0/8",
				Description: "apphub",
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			p, sub, rt, fn := endpointFixture(t, nil)
			spec := endpointSpec("operator-rule", fn)
			if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
				t.Fatalf("the first Ensure failed: %v", err)
			}

			// Added out of band and **untagged**, which is what a rule this
			// platform did not create looks like.
			mem, ok := sub.EndpointEC2.(*aws.MemoryEndpointEC2)
			if !ok {
				t.Fatal("expected the in-memory EC2 substrate")
			}
			mem.PutUntaggedRule(findSecurityGroup(t, sub, "operator-rule"), tc.rule)

			needle := fmt.Sprintf("tcp/%d/10.0.0.0/8", tc.rule.Port)
			if !renderedContains(t, p, needle) {
				t.Fatalf("the operator's rule was not planted, so this test proved nothing:\n%s",
					strings.Join(rendered(t, p), "\n"))
			}
			// An unchanged Ensure, which is the trigger that made the earlier
			// defect so bad: nothing about the caller's spec changed.
			if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
				t.Fatalf("the second Ensure failed: %v", err)
			}
			if !renderedContains(t, p, needle) {
				t.Fatalf("%s was revoked by an unchanged Ensure. Reconciling a spec is not the "+
					"same as taking over a resource, and ownership must not be readable from text "+
					"an operator chose:\n%s", tc.what, strings.Join(rendered(t, p), "\n"))
			}
		})
	}
}

// TestARuleOwnedByAnotherComponentSurvivesConvergence is the sibling-port case,
// separated because it is the one a description could never have caught.
//
// A rule carrying apphub's owner tag under a different component is what a
// sibling AWS port's rule in the same security group looks like. Only the
// component tag distinguishes it, which is why isOwnRule checks both — the same
// reasoning checkOwned applies to resources, applied to rules.
func TestARuleOwnedByAnotherComponentSurvivesConvergence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, sub, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("sibling-rule", fn)
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}

	group := findSecurityGroup(t, sub, "sibling-rule")
	if err := sub.EndpointEC2.AuthorizeSecurityGroupIngress(ctx, group, []aws.EndpointSecurityGroupRule{{
		Protocol: "tcp", Port: 9443, CIDRv4: "10.0.0.0/8",
	}}, map[string]string{
		"apphub:managed-by": "apphub",
		"apphub:name":       "sibling-rule",
		"apphub:component":  "container-service",
	}); err != nil {
		t.Fatalf("planting the sibling port's rule: %v", err)
	}

	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the second Ensure failed: %v", err)
	}
	if !renderedContains(t, p, "tcp/9443/10.0.0.0/8") {
		t.Fatalf("a rule apphub owns as a different component was revoked. The owner tag alone "+
			"makes every rule this platform created interchangeable:\n%s",
			strings.Join(rendered(t, p), "\n"))
	}
}

// TestAnEndpointCanBeRepointedAtAnotherFunction.
//
// A target group load-balances across its targets, so an endpoint whose target
// changed and whose old registration survived forwards half its traffic to the
// function the caller stopped asking for. Nothing in the source system
// deregisters anything.
func TestAnEndpointCanBeRepointedAtAnotherFunction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _, rt, first := endpointFixture(t, nil)
	second, err := rt.EnsureFunction(ctx, functionSpec("second-target",
		functionIdentity(t, p, "second")))
	if err != nil {
		t.Fatalf("seeding the second function: %v", err)
	}

	spec := endpointSpec("repointed", first)
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}
	spec.Target = second.Ref
	st, err := rt.EnsureEndpoint(ctx, spec)
	if err != nil {
		t.Fatalf("re-pointing the endpoint failed: %v", err)
	}
	if st.Spec.Target != second.Ref {
		t.Errorf("the effective spec still reports %s as the target, want %s",
			st.Spec.Target, second.Ref)
	}
	for _, line := range renderedMatching(t, p, "TargetGroup ") {
		if strings.Contains(line, ":function:apphub") && strings.Count(line, ":function:") > 1 {
			t.Fatalf("the target group has more than one registered target, so half the "+
				"endpoint's traffic still reaches the function the caller stopped asking for: %s",
				line)
		}
	}
}

// --- what must never leave the interface ------------------------------------

// TestNoAWSNetworkIdentifierReachesAComputeType is the boundary this ticket was
// asked to hold, checked rather than asserted.
//
// The acceptance criterion is "no ELBv2/EC2/IAM concepts above the interface".
// The values that would violate it are known exactly — they are the fixtures the
// in-memory substrate reports — so the check is to walk everything the interface
// hands back and look for them. That is stronger than reading the type
// definitions: a load balancer ARN reaching a caller through
// EndpointStatus.Message would not show up in a type at all.
func TestNoAWSNetworkIdentifierReachesAComputeType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, _, rt, fn := endpointFixture(t, nil)
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("boundary", fn))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	fnStatus, err := rt.DescribeFunction(ctx, fn)
	if err != nil {
		t.Fatalf("DescribeFunction failed: %v", err)
	}
	epStatus, err := rt.DescribeEndpoint(ctx, ep.Ref)
	if err != nil {
		t.Fatalf("DescribeEndpoint failed: %v", err)
	}

	// Everything the interface hands a caller, rendered. Marshalling rather than
	// walking field by field, because the point is that no path carries one and
	// a field-by-field check only covers the fields somebody thought of.
	surface := strings.Join([]string{
		spew(t, fnStatus), spew(t, epStatus), spew(t, ep), spew(t, fn),
	}, "\n")

	for _, forbidden := range []struct {
		value string
		what  string
	}{
		{aws.MemoryVPC, "a VPC identifier"},
		{aws.MemorySubnetA, "a subnet identifier"},
		{aws.MemorySubnetB, "a subnet identifier"},
		{aws.MemoryIngressGroup, "a security group identifier"},
		{aws.MemoryAccount, "an account identifier"},
		{testCertificateARN, "a certificate ARN"},
		{":loadbalancer/", "a load balancer ARN"},
		{":targetgroup/", "a target group ARN"},
		{":function:", "a Lambda function ARN"},
		{":role/", "an IAM role ARN"},
		{"internet-facing", "an ELBv2 scheme"},
	} {
		if strings.Contains(surface, forbidden.value) {
			t.Errorf("%s (%q) reached a compute type. The whole point of Placement carrying a "+
				"name and nothing else is that these never enter the interface:\n%s",
				forbidden.what, forbidden.value, surface)
		}
	}

	// The control: the one thing that IS meant to come out. Without this the
	// test would pass against a provider that returned nothing at all.
	if epStatus.Hostname == "" {
		t.Error("EndpointStatus.Hostname is empty. It is the one output the caller actually " +
			"consumes, and a test that only checks for absences would not notice")
	}
}

// TestTheCertificateComesBackAsTheReferenceNotTheARN.
//
// The ARN would put an account identifier into a value travelling out through
// compute — the one thing this package's configuration rules exist to prevent —
// and it would also not round-trip: a caller comparing the effective spec against
// what it sent would see a string it had never written.
func TestTheCertificateComesBackAsTheReferenceNotTheARN(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, _, rt, fn := endpointFixture(t, nil)
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("cert", fn))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	st, err := rt.DescribeEndpoint(ctx, ep.Ref)
	if err != nil {
		t.Fatalf("DescribeEndpoint failed: %v", err)
	}
	var found bool
	for _, l := range st.Spec.Listeners {
		if l.Protocol != compute.ListenerHTTPS {
			continue
		}
		found = true
		switch {
		case l.TLS == nil:
			t.Error("a TLS listener reads back with no certificate, so a caller cannot tell " +
				"which one it is serving")
		case l.TLS.CertificateRef == testCertificateARN:
			t.Error("the effective spec reports the certificate's ARN rather than the reference " +
				"the caller supplied; the ARN carries an account identifier and does not " +
				"round-trip")
		case l.TLS.CertificateRef != testCertificateRef:
			t.Errorf("the effective spec reports certificate reference %q, want %q",
				l.TLS.CertificateRef, testCertificateRef)
		}
	}
	if !found {
		t.Fatal("no TLS listener read back, so this test checked nothing")
	}
}

// --- placement validation ---------------------------------------------------

// TestAMisconfiguredPlacementIsReportedAgainstThePlacement is a table over the
// three network checks this provider makes and the source system does not, each
// of which is a real failure it lets through.
func TestAMisconfiguredPlacementIsReportedAgainstThePlacement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		what    string
		subnets []string
		says    string
	}{
		{
			what:    "one subnet",
			subnets: []string{aws.MemorySubnetA},
			says:    "an application load balancer needs two",
		},
		{
			what:    "two subnets in one availability zone",
			subnets: []string{aws.MemorySubnetA, aws.MemorySubnetSameZone},
			says: "the source system lets CreateLoadBalancer report this, after the security " +
				"group has already been created and tagged",
		},
		{
			what:    "subnets in two VPCs",
			subnets: []string{aws.MemorySubnetA, aws.MemorySubnetOtherVPC},
			says: "the source recovers the VPC from subnet zero alone, so the security group " +
				"lands in one VPC and the load balancer cannot use the other's subnets",
		},
		{
			what:    "a subnet that does not exist",
			subnets: []string{aws.MemorySubnetA, "subnet-placeholder-missing"},
			says:    "the source passes the list straight into CreateLoadBalancer",
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			// Configured on a *second* placement, because Config.Endpoint makes
			// New check the subnet count on every placement and a one-subnet
			// default would be refused at construction instead — which is the
			// right behaviour and would make the substrate checks unreachable.
			if len(tc.subnets) < minSubnetsForALoadBalancer {
				// The too-few-subnets case cannot be reached from here at all:
				// Config.Endpoint makes New check the count on every placement,
				// so a provider carrying such a placement never gets built. That
				// is the right layer for it — the operator who configured it is
				// the person who can act on it — and it is checked by
				// TestAPlacementWithTooFewSubnetsIsRefusedAtConstruction. Named
				// as a skip rather than dropped from the table so that the case
				// stays visible next to its three siblings.
				t.Skip("refused at construction; see " +
					"TestAPlacementWithTooFewSubnetsIsRefusedAtConstruction")
			}
			p, _ := newProvider(t, func(cfg *aws.Config) {
				pc := endpointPlacement()
				pc.SubnetIDs = tc.subnets
				cfg.Placements["broken"] = pc
			})
			rt := functionsOf(t, p)
			id := functionIdentity(t, p, "broken")
			fn, err := rt.EnsureFunction(context.Background(), functionSpec("broken-target", id))
			if err != nil {
				t.Fatalf("seeding the function: %v", err)
			}
			spec := endpointSpec("broken", fn.Ref)
			spec.Placement = compute.Placement{Name: "broken"}
			_, err = rt.EnsureEndpoint(context.Background(), spec)
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("a placement with %s was answered with %v, want ErrInvalidSpec naming "+
					"the placement; %s", tc.what, err, tc.says)
			}
			if !strings.Contains(err.Error(), "broken") {
				t.Errorf("the refusal does not name the placement: %v", err)
			}
		})
	}
}

// TestAPlacementWithTooFewSubnetsIsRefusedAtConstruction.
//
// At construction rather than at the first Ensure, because a placement that
// cannot carry a load balancer is a misconfiguration and the operator who wrote
// it is the person who can act on it — not the deploy that happened to need it.
func TestAPlacementWithTooFewSubnetsIsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	cfg := fullConfig()
	pc := endpointPlacement()
	pc.SubnetIDs = []string{aws.MemorySubnetA}
	cfg.Placements["thin"] = pc
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Fatal("a provider with an endpoint configured and a one-subnet placement was " +
			"constructed; every spec naming that placement would fail, and the operator would " +
			"learn it from a deploy")
	}
}

// TestAnEndpointWithoutAFunctionRuntimeIsRefusedAtConstruction.
//
// An endpoint fronts a function, so the combination is meaningless. Refusing it
// outright is better than advertising neither capability and leaving a caller to
// infer why.
func TestAnEndpointWithoutAFunctionRuntimeIsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	cfg := fullConfig()
	cfg.Function = nil
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Fatal("a provider with an endpoint and no function runtime was constructed")
	}
}

// minSubnetsForALoadBalancer mirrors the provider's own minimum. Stated here
// rather than reached into so that the table above reads without the provider's
// internals, and a change to one that is not matched in the other turns a case
// into a skip rather than into a silent pass.
const minSubnetsForALoadBalancer = 2

// --- helpers ----------------------------------------------------------------

func rendered(t *testing.T, p *aws.Provider) []string {
	t.Helper()
	out, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("reading the rendered artefacts: %v", err)
	}
	return out
}

func renderedContains(t *testing.T, p *aws.Provider, needle string) bool {
	t.Helper()
	for _, line := range rendered(t, p) {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func renderedMatching(t *testing.T, p *aws.Provider, prefix string) []string {
	t.Helper()
	var out []string
	for _, line := range rendered(t, p) {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

// findSecurityGroup recovers the identifier of the group behind an endpoint, so
// that a test can act on it the way an operator would.
func findSecurityGroup(t *testing.T, sub *aws.Substrate, name string) string {
	t.Helper()
	group, err := sub.EndpointEC2.DescribeSecurityGroup(context.Background(), aws.MemoryVPC, name)
	if err != nil {
		t.Fatalf("locating the endpoint's security group: %v", err)
	}
	return group.ID
}

// spew renders everything reachable from a value as text, so that a forbidden
// identifier anywhere inside it is findable.
//
// JSON rather than a %v verb, and the difference is the whole reason this helper
// exists: %v and %#v print a pointer as an address, so an identifier one level
// down behind a *TLSConfig would be invisible to the check. Marshalling walks
// it. This is the same choice conformance's own effective-spec comparison makes,
// for the same reason.
func spew(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("rendering the interface surface: %v", err)
	}
	return string(encoded)
}

// --- the two-call teardown --------------------------------------------------

// TestTheDeleteRetryRemovesTheSecurityGroup drives the teardown path the
// implementation documents as ordinary, rather than the one-call synchronous
// deletion the memory substrate makes easy.
//
// On a real account the first DeleteEndpoint deletes the load balancer and then
// fails to delete the security group, because ELBv2 releases its network
// interfaces minutes later. The caller retries. **On that retry there is no load
// balancer**, so nothing is left to say which placement the group was created
// in — and an earlier revision returned nil from exactly there, reporting a
// successful teardown with the security group still in place.
//
// A teardown reporting success while leaving a resource behind is the class of
// the worst finding on this project. The contract is: remove everything, or
// report what remains.
//
// The failure is injected at the substrate rather than simulated, so the call
// order under test is the real one: two DeleteEndpoint calls, the first failing
// the way AWS fails it.
func TestTheDeleteRetryRemovesTheSecurityGroup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, sub, rt, fn := endpointFixture(t, func(cfg *aws.Config) {
		// One placement, so the retry's search has exactly one VPC to look in
		// and a pass cannot come from a coincidence in another.
		delete(cfg.Placements, "secondary")
	})
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("teardown", fn))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	group := findSecurityGroup(t, sub, "teardown")

	// The first delete fails exactly where AWS fails it, and only there.
	mem, ok := sub.EndpointEC2.(*aws.MemoryEndpointEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	stop := mem.FailNextDelete(aws.ErrConflict)

	err = rt.DeleteEndpoint(ctx, ep.Ref)
	if err == nil {
		t.Fatal("the first delete reported success while the security group could not yet be " +
			"removed; the whole point of the ErrTransient contract is that the caller is told")
	}
	if !errors.Is(err, compute.ErrTransient) {
		t.Fatalf("the first delete returned %v, want compute.ErrTransient so the caller retries", err)
	}
	stop()

	// The retry. The load balancer is already gone.
	if _, err := sub.ELBv2.DescribeLoadBalancer(ctx, "teardown"); err == nil {
		t.Fatal("the load balancer survived the first delete, so this test is not exercising " +
			"the retry path it exists for")
	}
	if err := rt.DeleteEndpoint(ctx, ep.Ref); err != nil {
		t.Fatalf("the retry failed with %v; the first call told the caller to retry", err)
	}

	// Observed on the substrate, not inferred from the nil return — which is
	// precisely what the earlier revision's nil return would have satisfied.
	if _, err := sub.EndpointEC2.DescribeSecurityGroup(ctx, aws.MemoryVPC, "teardown"); err == nil {
		t.Fatalf("DeleteEndpoint reported success and the security group %q survives. Its "+
			"ownership tags mean the next Ensure of this name would adopt it, with the old rule "+
			"set, instead of creating a fresh one", group)
	}
}

// TestTeardownReportsWhatItCannotInspect is the other half of "remove
// everything, or report what remains".
//
// With no load balancer to name the placement, the group is found by searching
// the configured placements. A placement that cannot be inspected means the
// search did not cover everything, so the teardown has not established that
// nothing remains — and it says so rather than returning nil.
func TestTeardownReportsWhatItCannotInspect(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, sub, rt, fn := endpointFixture(t, nil)
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("uninspectable", fn))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	// Delete the load balancer out of band, so the teardown takes the search
	// path, and make one placement's subnets unreadable.
	lb, err := sub.ELBv2.DescribeLoadBalancer(ctx, "uninspectable")
	if err != nil {
		t.Fatalf("locating the load balancer: %v", err)
	}
	if err := sub.ELBv2.DeleteLoadBalancer(ctx, lb.ARN); err != nil {
		t.Fatalf("deleting the load balancer: %v", err)
	}
	mem, ok := sub.EndpointEC2.(*aws.MemoryEndpointEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	mem.FailNext(aws.ErrThrottled)

	err = rt.DeleteEndpoint(ctx, ep.Ref)
	if err == nil {
		t.Fatal("the teardown reported success while one placement could not be inspected, so " +
			"it cannot have established that nothing remains")
	}
}

// --- readiness ---------------------------------------------------------------

// TestReadinessRequiresTheTargetToBeHealthy checks both directions, because a
// one-directional check cannot distinguish "includes health" from "never ready".
//
// compute.PhaseReady means serving and WaitForEndpoint promises to block until
// the endpoint is serving. An earlier revision mapped an active load balancer
// straight to ready — a correctly-counted wrong population: one of the
// endpoint's objects was active and the whole construction was called serving.
// A load balancer whose only target is unhealthy answers every request with a
// 502.
func TestReadinessRequiresTheTargetToBeHealthy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("an active load balancer with a healthy target is ready", func(t *testing.T) {
		t.Parallel()
		_, _, rt, fn := endpointFixture(t, nil)
		ep, err := rt.EnsureEndpoint(ctx, endpointSpec("healthy", fn))
		if err != nil {
			t.Fatalf("EnsureEndpoint failed: %v", err)
		}
		st, err := rt.WaitForEndpoint(ctx, ep.Ref, compute.WaitOptions{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("WaitForEndpoint failed for an endpoint that should converge: %v", err)
		}
		if st.Phase != compute.PhaseReady {
			t.Fatalf("phase is %q, want %q; without this direction the test could not tell "+
				"\"includes health\" from \"never ready\"", st.Phase, compute.PhaseReady)
		}
	})

	t.Run("an active load balancer with an unhealthy target is not ready", func(t *testing.T) {
		t.Parallel()
		_, sub, rt, fn := endpointFixture(t, nil)
		ep, err := rt.EnsureEndpoint(ctx, endpointSpec("unhealthy", fn))
		if err != nil {
			t.Fatalf("EnsureEndpoint failed: %v", err)
		}
		mem, ok := sub.ELBv2.(*aws.MemoryELBv2)
		if !ok {
			t.Fatal("expected the in-memory ELBv2 substrate")
		}
		// The load balancer stays active; only the target is unhealthy. That
		// separation is the point: anything that polled the load balancer alone
		// would report ready here.
		mem.SetTargetHealth("unhealthy", "unhealthy")

		st, err := rt.DescribeEndpoint(ctx, ep.Ref)
		if err != nil {
			t.Fatalf("DescribeEndpoint failed: %v", err)
		}
		if st.Phase == compute.PhaseReady {
			t.Fatal("the endpoint reports ready with an unhealthy target. Registration is not " +
				"health, and a load balancer whose only target is unhealthy answers 502")
		}
		if st.Message == "" {
			t.Error("the phase is not ready and Status.Message is empty, so an operator has " +
				"nothing to act on")
		}
		if _, err := rt.WaitForEndpoint(ctx, ep.Ref, compute.WaitOptions{
			Timeout: 200 * time.Millisecond,
		}); err == nil {
			t.Fatal("WaitForEndpoint reported success for an endpoint whose target is unhealthy")
		}
	})

	t.Run("an active load balancer with no target registered is not ready", func(t *testing.T) {
		t.Parallel()
		_, sub, rt, fn := endpointFixture(t, nil)
		ep, err := rt.EnsureEndpoint(ctx, endpointSpec("untargeted", fn))
		if err != nil {
			t.Fatalf("EnsureEndpoint failed: %v", err)
		}
		tg, err := sub.ELBv2.DescribeTargetGroup(ctx, "untargeted")
		if err != nil {
			t.Fatalf("locating the target group: %v", err)
		}
		health, err := sub.ELBv2.DescribeTargets(ctx, tg.ARN)
		if err != nil {
			t.Fatalf("reading the target health: %v", err)
		}
		ids := make([]string, 0, len(health))
		for _, h := range health {
			ids = append(ids, h.ID)
		}
		if err := sub.ELBv2.DeregisterTargets(ctx, tg.ARN, ids); err != nil {
			t.Fatalf("deregistering: %v", err)
		}

		st, err := rt.DescribeEndpoint(ctx, ep.Ref)
		if err != nil {
			t.Fatalf("DescribeEndpoint failed: %v", err)
		}
		// Pending and not failed: an endpoint between its create and its
		// registration looks like this, and a caller that cannot tell "not yet"
		// from "never" has to choose between waiting forever and giving up early.
		if st.Phase != compute.PhasePending {
			t.Fatalf("phase is %q with nothing registered, want %q", st.Phase, compute.PhasePending)
		}
	})
}

// --- the transitions an operator reaches by editing configuration -----------

// TestTeardownFindsTheGroupAfterItsPlacementWasRemoved is the review's
// removed-placement transition, as a finished construction rather than a state.
//
// Every individual state here is correct: an endpoint in placement A is right, a
// provider configured with only placement B is right. The *move* between them is
// what was broken — and an operator editing configuration is the only thing that
// produces it, which is why no test constructed it by accident.
//
// The defect it pins: teardown was scoped by the placements configuration names
// *now*, and configuration is the thing that changed. With A removed, the group's
// VPC was in no population the search looked at, so DeleteEndpoint deleted the
// load balancer and the target group, returned nil, and left an owned security
// group in a VPC nothing was looking at any more. Widening the search to include
// B would have left the same unsoundness at a larger size.
//
// The fix is that teardown searches by this provider's own ownership marker,
// which no configuration edit can move.
func TestTeardownFindsTheGroupAfterItsPlacementWasRemoved(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// One substrate, two providers over it: the second is the same account after
	// an operator edited the placement set. Sharing the substrate is what makes
	// this a transition rather than two unrelated worlds.
	sub := aws.NewMemorySubstrate()

	before, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	rt := functionsOf(t, before)
	fn, err := rt.EnsureFunction(ctx, functionSpec("moved-target",
		functionIdentity(t, before, "moved")))
	if err != nil {
		t.Fatalf("seeding the function: %v", err)
	}
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("moved", fn.Ref))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	if _, err := sub.EndpointEC2.DescribeSecurityGroup(ctx, aws.MemoryVPC, "moved"); err != nil {
		t.Fatalf("the security group was not created in the original VPC, so this test cannot "+
			"show it being left behind: %v", err)
	}

	// The operator removes the placement the endpoint was created in and
	// configures a valid replacement in a different VPC.
	after := fullConfig()
	delete(after.Placements, "default")
	delete(after.Placements, "secondary")
	replacement := endpointPlacement()
	replacement.SubnetIDs = []string{aws.MemorySubnetOtherVPC, aws.MemorySubnetOtherVPCB}
	after.Placements["replacement"] = replacement
	// This test is about the endpoint's own teardown, and it removes every
	// placement the sample config's Relational and KeyValue configuration could
	// hold a database or a table in -- so it drops those two capabilities rather
	// than fabricate network coordinates for ports it never exercises.
	after.Relational = nil
	after.KeyValue = nil
	after.DefaultPlacement = "replacement"
	moved, err := aws.New(sub, after)
	if err != nil {
		t.Fatalf("constructing the provider after the placement edit: %v", err)
	}
	movedRT, err := moved.Functions()
	if err != nil {
		t.Fatalf("acquiring the function port after the edit: %v", err)
	}

	err = movedRT.DeleteEndpoint(ctx, ep.Ref)

	// Observed on the substrate, in the *original* VPC. Either the group is gone
	// or the call said it could not establish that — success with the group still
	// there is the one outcome that is not allowed.
	_, findErr := sub.EndpointEC2.DescribeSecurityGroup(ctx, aws.MemoryVPC, "moved")
	switch {
	case findErr == nil && err == nil:
		t.Fatal("DeleteEndpoint reported success after the endpoint's placement was removed from " +
			"configuration, and its security group survives in the original VPC. Teardown must " +
			"search where the resource was, not where configuration says it is now")
	case findErr == nil:
		t.Logf("the group survives and DeleteEndpoint refused (%v), which is a legal outcome", err)
	case err != nil:
		t.Fatalf("the group was removed and DeleteEndpoint still failed: %v", err)
	}
}

// TestTheEffectiveIngressSurvivesItsPlacementBeingRemoved is the same class one
// method along, and it is a read rather than a delete.
//
// DescribeEndpoint read the security group by the VPC of the placement recorded
// on the load balancer. With that placement gone from configuration the read
// could not be made, and the endpoint was reported with an **empty ingress rule
// set** — a read-back asserting that nothing may reach an endpoint that is in
// fact reachable. That is worse than the delete case in one respect: it is the
// answer a caller would act on.
func TestTheEffectiveIngressSurvivesItsPlacementBeingRemoved(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sub := aws.NewMemorySubstrate()
	before, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	rt := functionsOf(t, before)
	fn, err := rt.EnsureFunction(ctx, functionSpec("orphan-target",
		functionIdentity(t, before, "orphan")))
	if err != nil {
		t.Fatalf("seeding the function: %v", err)
	}
	ep, err := rt.EnsureEndpoint(ctx, endpointSpec("orphan", fn.Ref))
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	st, err := rt.DescribeEndpoint(ctx, ep.Ref)
	if err != nil {
		t.Fatalf("DescribeEndpoint failed: %v", err)
	}
	if len(st.Spec.Ingress) == 0 {
		t.Fatal("no ingress rules were reported before the edit, so this test proves nothing")
	}
	want := len(st.Spec.Ingress)

	after := fullConfig()
	delete(after.Placements, "default")
	delete(after.Placements, "secondary")
	replacement := endpointPlacement()
	replacement.SubnetIDs = []string{aws.MemorySubnetOtherVPC, aws.MemorySubnetOtherVPCB}
	after.Placements["replacement"] = replacement
	// This test is about the endpoint's own teardown, and it removes every
	// placement the sample config's Relational and KeyValue configuration could
	// hold a database or a table in -- so it drops those two capabilities rather
	// than fabricate network coordinates for ports it never exercises.
	after.Relational = nil
	after.KeyValue = nil
	after.DefaultPlacement = "replacement"
	moved, err := aws.New(sub, after)
	if err != nil {
		t.Fatalf("constructing the provider after the placement edit: %v", err)
	}
	movedRT, err := moved.Functions()
	if err != nil {
		t.Fatalf("acquiring the function port: %v", err)
	}

	st, err = movedRT.DescribeEndpoint(ctx, ep.Ref)
	if err != nil {
		t.Fatalf("DescribeEndpoint failed after the placement edit: %v", err)
	}
	if got := len(st.Spec.Ingress); got != want {
		t.Fatalf("the effective spec reports %d ingress rule(s) after the endpoint's placement was "+
			"removed from configuration, and %d before. A read-back that loses a rule set because "+
			"configuration moved is asserting that nothing may reach an endpoint that is reachable",
			got, want)
	}
}

// --- description convergence ------------------------------------------------

// TestChangingAnIngressDescriptionConverges is the review's should-fix.
//
// compute.IngressRule.Description is public desired state and explicitly
// operator-facing. ruleKey excludes it from a rule's *identity*, which is right —
// folding it in would make every wording edit a revoke-and-reauthorise, a window
// of lost reachability for a change that alters no permission. But "not identity"
// is not "not desired state", and an earlier revision treated a matching key as
// fully converged, so the old text stayed on the EC2 rule and in the effective
// spec.
//
// Checked in both places, and the substrate is the one that matters: the
// effective spec is the provider reporting on itself, and this is precisely a
// case where it was reporting something the substrate did not have.
func TestChangingAnIngressDescriptionConverges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _, rt, fn := endpointFixture(t, nil)

	spec := endpointSpec("described", fn)
	spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
	spec.Ingress = []compute.IngressRule{{
		From: compute.Peer{Kind: compute.PeerInternet}, Port: 80,
		Description: "first description",
	}}
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}
	if !renderedContains(t, p, "(first description)") {
		t.Fatalf("the first description never reached the rule, so this test cannot show it "+
			"changing:\n%s", strings.Join(rendered(t, p), "\n"))
	}

	spec.Ingress[0].Description = "updated description"
	st, err := rt.EnsureEndpoint(ctx, spec)
	if err != nil {
		t.Fatalf("the second Ensure failed: %v", err)
	}

	// The substrate.
	if renderedContains(t, p, "(first description)") {
		t.Errorf("the old description survives on the EC2 rule after a spec that changed it:\n%s",
			strings.Join(rendered(t, p), "\n"))
	}
	if !renderedContains(t, p, "(updated description)") {
		t.Errorf("the new description never reached the EC2 rule:\n%s",
			strings.Join(rendered(t, p), "\n"))
	}
	// And the read-back, which is what a caller compares against what it sent.
	for _, r := range st.Spec.Ingress {
		if r.Port != 80 {
			continue
		}
		if r.Description != "updated description" {
			t.Errorf("the effective ingress description is %q, want %q",
				r.Description, "updated description")
		}
	}

	// The permission itself must not have been disturbed. Without this the test
	// would pass against an implementation that revoked and reauthorised, which
	// is the fix that closes a port for as long as two calls take.
	if !renderedContains(t, p, "tcp/80/0.0.0.0/0") {
		t.Error("the port 80 permission is gone after a description-only change")
	}
}

// TestADescriptionOnlyChangeDoesNotRevokeAnything is the half the test above
// cannot see: that convergence chose to *update* rather than to replace.
//
// The distinction is invisible in the finished state — both leave the right text
// on the right permission — and it is the whole difference between a wording edit
// and a moment with no rule at all. So it is checked at the substrate call rather
// than in the result.
func TestADescriptionOnlyChangeDoesNotRevokeAnything(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, sub, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("stable-id", fn)
	spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
	spec.Ingress = []compute.IngressRule{{
		From: compute.Peer{Kind: compute.PeerInternet}, Port: 80, Description: "before",
	}}
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}

	group := findSecurityGroup(t, sub, "stable-id")
	idsBefore := ruleIDs(t, sub, group)
	if len(idsBefore) == 0 {
		t.Fatal("no rules were authorised, so this test proves nothing")
	}

	spec.Ingress[0].Description = "after"
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("the second Ensure failed: %v", err)
	}

	// A revoke-and-reauthorise mints new rule identifiers; an in-place update
	// keeps them. That is the observable difference.
	idsAfter := ruleIDs(t, sub, group)
	if strings.Join(idsBefore, ",") != strings.Join(idsAfter, ",") {
		t.Fatalf("a description-only change replaced the rules (%v -> %v). The permission is "+
			"unchanged, so the rule should be updated in place; replacing it closes the port for "+
			"as long as the two calls take", idsBefore, idsAfter)
	}
	_ = p
}

func ruleIDs(t *testing.T, sub *aws.Substrate, groupID string) []string {
	t.Helper()
	rules, err := sub.EndpointEC2.DescribeSecurityGroupRules(context.Background(), groupID)
	if err != nil {
		t.Fatalf("reading the rules back: %v", err)
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

// --- the accepted-peer axis, derived rather than listed ---------------------

// declaredPeerKinds parses every compute.PeerKind constant out of the interface's
// own source.
//
// Derived, not listed, and the reason is the defect that made it necessary: the
// removed-placement transition below was originally written with one peer kind
// planted, so it verified the fix for the half that was planted and passed
// vacuously over the half that was not. A hand-written list has exactly that
// failure mode — it looks like an axis and does not traverse — and a list that
// goes stale when the interface gains a peer kind is the same thing a year later.
//
// Parsing the declarations means **a new PeerKind makes this test fail** rather
// than silently reducing its coverage, which is the property the enumeration is
// for. compute has no exported list to read, so the source is the source.
func declaredPeerKinds(t *testing.T) []compute.PeerKind {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "network.go"))
	if err != nil {
		t.Fatalf("reading the interface's source to enumerate PeerKind: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*Peer\w+\s+PeerKind\s*=\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 2 {
		t.Fatalf("found %d PeerKind declarations in compute/network.go; the enumeration is "+
			"derived from that file and a derivation returning almost nothing passes every check "+
			"over it", len(matches))
	}
	out := make([]compute.PeerKind, 0, len(matches))
	for _, m := range matches {
		out = append(out, compute.PeerKind(m[1]))
	}
	return out
}

// acceptedPeerKinds reports which declared peer kinds this port actually accepts
// on an endpoint, by asking it rather than by asserting it.
//
// Behaviour, not a table. The refusals are a deliberate design decision
// (TestAPeerThisProviderCannotResolveIsRefusedRatherThanWidened pins them), and
// deriving the accepted set from the port means the transition test below ranges
// over exactly what is accepted today — so implementing PeerWorkload later
// extends the transition's coverage automatically instead of leaving a gap
// nobody notices.
func acceptedPeerKinds(t *testing.T) []compute.PeerKind {
	t.Helper()
	ctx := context.Background()
	var accepted []compute.PeerKind
	for _, kind := range declaredPeerKinds(t) {
		_, _, rt, fn := endpointFixture(t, nil)
		spec := endpointSpec(fmt.Sprintf("probe-%s", strings.ReplaceAll(string(kind), "-", "")), fn)
		spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
		spec.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: kind}, Port: 80}}
		if _, err := rt.EnsureEndpoint(ctx, spec); err == nil {
			accepted = append(accepted, kind)
		}
	}
	if len(accepted) < 2 {
		t.Fatalf("only %d of the declared peer kinds are accepted (%v); the transition test ranges "+
			"over the accepted set, and a set this small means it is proving almost nothing",
			len(accepted), accepted)
	}
	return accepted
}

// TestTheEffectiveIngressSurvivesItsPlacementBeingRemovedForEveryAcceptedPeer is
// the round-three finding: the same transition, ranged over the axis.
//
// The original planted only compute.PeerInternet, whose peer is a CIDR and
// therefore classifiable from the rule alone. compute.PeerPlatformIngress is a
// peer *group*, and the only thing that distinguished it from any other
// group-peer rule was a comparison against the operator's **current**
// configuration — so removing the placement left an owned rule that could not be
// named, and an unnameable rule was dropped. DescribeEndpoint reported an
// endpoint with no ingress at all when it had two rules.
//
// A caller reconciling against that reading does not restore what it cannot see,
// so a silent drop in a read path becomes a silent divergence in every write path
// below it.
func TestTheEffectiveIngressSurvivesItsPlacementBeingRemovedForEveryAcceptedPeer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, kind := range acceptedPeerKinds(t) {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			sub := aws.NewMemorySubstrate()
			before, err := aws.New(sub, fullConfig())
			if err != nil {
				t.Fatalf("constructing the provider: %v", err)
			}
			rt, err := before.Functions()
			if err != nil {
				t.Fatalf("acquiring the function port: %v", err)
			}
			fn, err := rt.EnsureFunction(ctx, functionSpec("axis-target",
				functionIdentity(t, before, "axis")))
			if err != nil {
				t.Fatalf("seeding the function: %v", err)
			}

			spec := endpointSpec("axis", fn.Ref)
			spec.Listeners = []compute.ListenerSpec{
				{Port: 80, Protocol: compute.ListenerHTTP},
				{Port: 443, Protocol: compute.ListenerHTTPS,
					TLS: &compute.TLSConfig{CertificateRef: testCertificateRef}},
			}
			spec.Ingress = []compute.IngressRule{
				{From: compute.Peer{Kind: kind}, Port: 80},
				{From: compute.Peer{Kind: kind}, Port: 443},
			}
			ep, err := rt.EnsureEndpoint(ctx, spec)
			if err != nil {
				t.Fatalf("EnsureEndpoint failed: %v", err)
			}
			st, err := rt.DescribeEndpoint(ctx, ep.Ref)
			if err != nil {
				t.Fatalf("DescribeEndpoint failed: %v", err)
			}
			want := len(st.Spec.Ingress)
			if want == 0 {
				t.Fatalf("no ingress rules reported before the edit for peer %q, so this "+
					"subtest proves nothing", kind)
			}

			// The operator removes the placement the endpoint was created in and
			// configures a valid replacement in another VPC — with a *different*
			// ingress-proxy group, which is what makes the group-peer case bite.
			after := fullConfig()
			delete(after.Placements, "default")
			delete(after.Placements, "secondary")
			replacement := endpointPlacement()
			replacement.SubnetIDs = []string{aws.MemorySubnetOtherVPC, aws.MemorySubnetOtherVPCB}
			replacement.PlatformIngressSecurityGroupID = "sg-placeholder-other-ingress"
			after.Placements["replacement"] = replacement
			// This test is about the endpoint's own teardown, and it removes every
			// placement the sample config's Relational and KeyValue configuration
			// could hold a database or a table in -- so it drops those two
			// capabilities rather than fabricate network coordinates for ports it
			// never exercises.
			after.Relational = nil
			after.KeyValue = nil
			after.DefaultPlacement = "replacement"
			moved, err := aws.New(sub, after)
			if err != nil {
				t.Fatalf("constructing the provider after the placement edit: %v", err)
			}
			movedRT, err := moved.Functions()
			if err != nil {
				t.Fatalf("acquiring the function port after the edit: %v", err)
			}

			// The PUBLIC entry point, not the internal read.
			st, err = movedRT.DescribeEndpoint(ctx, ep.Ref)
			if err != nil {
				t.Fatalf("DescribeEndpoint failed after the placement edit: %v", err)
			}
			if got := len(st.Spec.Ingress); got != want {
				t.Fatalf("peer %q: the effective spec reports %d ingress rule(s) after the "+
					"endpoint's placement was removed from configuration, and %d before. "+
					"Reporting no ingress for an endpoint that has some is a reading a caller "+
					"reconciles against, so a silent drop here becomes a silent divergence in "+
					"every write path below it", kind, got, want)
			}
			for _, r := range st.Spec.Ingress {
				if r.From.Kind != kind {
					t.Errorf("peer %q read back as %q; the peer kind is recorded at the write "+
						"precisely so the read does not have to guess", kind, r.From.Kind)
				}
			}
		})
	}
}

// TestTheTwoSubstratesAgreeOnRefusingAnUnfilteredSearch aligns the seam.
//
// A fake that returns everything where the real SDK refuses is a fake that
// certifies a query no substrate will honour, and the failure direction is the
// bad one: the test passes against the fake by matching *all* groups, and the
// call is rejected outright in production.
//
// The general form is worth stating because it is not specific to this call:
// **whichever way a fake diverges from its substrate, the fake is the thing that
// gets tested.** So the agreement is asserted rather than assumed.
func TestTheTwoSubstratesAgreeOnRefusingAnUnfilteredSearch(t *testing.T) {
	t.Parallel()

	sub := aws.NewMemorySubstrate()
	_, err := sub.EndpointEC2.FindSecurityGroups(context.Background(), nil)
	if err == nil {
		t.Fatal("the in-memory substrate accepted an unfiltered security group search. The SDK " +
			"adapter refuses it, so a test that passed here by matching every group would be " +
			"certifying a call production rejects")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("the refusal was %v; the two seams should agree on the sentinel as well as on "+
			"refusing", err)
	}
}

// --- the state a previous version left behind -------------------------------

// TestAnEndpointWhoseRulesPredateThePeerTagConverges is the migration witness.
//
// Recording the peer kind at the write replaced an inference with a stored fact,
// and **a recorded fact is only as good as its coverage of the records that
// already exist.** The store had an answer only for rules written after the
// change, so on any deployment that predates it the first reconcile met rules with
// no peer kind — and because an unclassifiable owned rule is (correctly) an error
// rather than an omission, the public EnsureEndpoint refused at its own read-back
// on rules it had just declined to touch.
//
// "We changed the write path" never retroactively changes what is stored.
//
// The legacy state cannot arise by accident, because the current write path always
// records the peer kind. So it is constructed deliberately — which is the only way
// a migration path gets a witness at all.
func TestAnEndpointWhoseRulesPredateThePeerTagConverges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, sub, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("legacy", fn)
	spec.Listeners = []compute.ListenerSpec{{Port: 80, Protocol: compute.ListenerHTTP}}
	spec.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 80}}
	created, err := rt.EnsureEndpoint(ctx, spec)
	if err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}

	mem, ok := sub.EndpointEC2.(*aws.MemoryEndpointEC2)
	if !ok {
		t.Fatal("expected the in-memory EC2 substrate")
	}
	group := findSecurityGroup(t, sub, "legacy")

	// Replace the group's rules with the same permissions carrying the ownership
	// tags a previous version wrote — and **no peer tag**.
	legacyTags := map[string]string{
		"apphub:managed-by": "apphub",
		"apphub:name":       "legacy",
		"apphub:component":  "function-endpoint-ingress",
	}
	existing, err := sub.EndpointEC2.DescribeSecurityGroupRules(ctx, group)
	if err != nil {
		t.Fatalf("reading the rules: %v", err)
	}
	ids := make([]string, 0, len(existing))
	for _, r := range existing {
		ids = append(ids, r.ID)
	}
	if err := sub.EndpointEC2.RevokeSecurityGroupIngress(ctx, group, ids); err != nil {
		t.Fatalf("clearing the rules: %v", err)
	}
	for _, r := range existing {
		r.Tags = nil
		mem.PutRuleWithTags(group, r, legacyTags)
	}

	// The state is genuinely the legacy one: owned, and carrying no peer kind.
	stored, err := sub.EndpointEC2.DescribeSecurityGroupRules(ctx, group)
	if err != nil {
		t.Fatalf("reading the legacy rules: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("no legacy rules were planted, so this test proves nothing")
	}
	for _, r := range stored {
		if r.Tags["apphub:peer"] != "" {
			t.Fatalf("rule %q carries a peer tag, so the legacy state was not constructed", r.ID)
		}
	}

	// The PUBLIC entry point, with an UNCHANGED spec — which is the reported
	// reproduction: nothing about the caller's request differs, so a refusal here
	// is a provider that cannot reconcile what it previously created.
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("re-Ensuring an unchanged spec over rules that predate the peer tag failed: %v\n"+
			"An upgrade must be able to converge the state the previous version wrote", err)
	}

	// And the read-back works afterwards, with the right peer kind recovered from
	// the declared spec rather than guessed from the rule's shape.
	st, err := rt.DescribeEndpoint(ctx, created.Ref)
	if err != nil {
		t.Fatalf("DescribeEndpoint after convergence failed: %v", err)
	}
	if len(st.Spec.Ingress) == 0 {
		t.Fatal("the effective spec reports no ingress after convergence")
	}
	for _, r := range st.Spec.Ingress {
		if r.From.Kind != compute.PeerInternet {
			t.Errorf("recovered peer kind is %q, want %q", r.From.Kind, compute.PeerInternet)
		}
	}
	_ = p
}

// --- one authorise call per peer kind ---------------------------------------

// TestRulesOfDifferentPeerKindsEachCarryTheirOwnPeerTag pins the property the
// migration fix depends on, and which nothing asserted.
//
// EC2 applies a single TagSpecification per AuthorizeSecurityGroupIngress call, so
// rules needing different peer tags cannot share one call. Batching them and
// tagging with whichever peer came first would write a **wrong** peer kind onto a
// real rule — worse than the inference it replaced, because a wrong recorded answer
// survives every later read where a failed inference at least fails.
//
// The reasoning was in the code and in the report; the assertion was nowhere.
// Deleting every authorisation batch after the first left the whole package green,
// because no fixture mixed two peer kinds in one spec. A mixed fixture is the whole
// test.
func TestRulesOfDifferentPeerKindsEachCarryTheirOwnPeerTag(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, sub, rt, fn := endpointFixture(t, nil)
	spec := endpointSpec("mixed", fn)
	spec.Listeners = []compute.ListenerSpec{
		{Port: 80, Protocol: compute.ListenerHTTP},
		{Port: 443, Protocol: compute.ListenerHTTPS,
			TLS: &compute.TLSConfig{CertificateRef: testCertificateRef}},
	}
	// Two peer kinds in one spec, which is what makes the batching observable.
	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerInternet}, Port: 80},
		{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 443},
	}
	st, err := rt.EnsureEndpoint(ctx, spec)
	if err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}

	// On the substrate, per rule: the peer tag must match the peer declared for
	// that rule's port, not the peer of whichever rule was authorised first.
	wantByPort := map[int]string{80: string(compute.PeerInternet), 443: string(compute.PeerPlatformIngress)}
	stored, err := sub.EndpointEC2.DescribeSecurityGroupRules(ctx, findSecurityGroup(t, sub, "mixed"))
	if err != nil {
		t.Fatalf("reading the rules back: %v", err)
	}
	seen := 0
	for _, r := range stored {
		want, ok := wantByPort[r.Port]
		if !ok {
			continue
		}
		seen++
		if got := r.Tags["apphub:peer"]; got != want {
			t.Errorf("the rule on port %d (%s) records peer %q, want %q. Rules of different peer "+
				"kinds cannot share one authorise call, and a wrong recorded peer survives every "+
				"later read", r.Port, ruleTarget(r), got, want)
		}
	}
	if seen < 3 {
		// Two families for the internet rule plus one group-peer rule.
		t.Fatalf("only %d rules matched the declared ports, so the mixed fixture is not "+
			"exercising both peer kinds", seen)
	}

	// And the read-back agrees, per port.
	for _, r := range st.Spec.Ingress {
		if want := wantByPort[r.Port]; want != "" && string(r.From.Kind) != want {
			t.Errorf("the effective spec reports peer %q on port %d, want %q",
				r.From.Kind, r.Port, want)
		}
	}
}

func ruleTarget(r aws.EndpointSecurityGroupRule) string {
	switch {
	case r.CIDRv4 != "":
		return r.CIDRv4
	case r.CIDRv6 != "":
		return r.CIDRv6
	default:
		return r.PeerGroupID
	}
}
