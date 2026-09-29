// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// WHAT USED TO BE HERE, AND WHY IT IS NOT.
//
// This file carried five more tests, all of them about the EC2 layer: the
// reconciler's two tolerated races, a wide port range being revocable, a
// rendering refusal not being read as absence, the two CIDR families going in
// different EC2 fields, and a rule surviving the round trip through the SDK
// shapes.
//
// That layer is USOSS-14's now (network.go, awssdkdb.go), and it landed first.
// Every one of those five has an equivalent there, and three of them under the
// same name -- which is what two ports independently deriving the same
// properties from the same substrate looks like. Two of USOSS-14's are strictly
// better than the versions deleted here: the round trip compares field by field
// rather than spot-checking, and the IPv6 case is exercised in both directions
// rather than only on the way out.
//
// Deleted rather than kept alongside, because a second test of somebody else's
// code is a second thing to update when they change it, and it fails in a way
// that reads as their regression rather than as this port's stale copy.
//
// What is left in this file is what USOSS-14's layer does NOT cover, because its
// port cannot reach it: the container port's own COMPILER, which is the only
// thing in this package that emits a SourceCIDR at all, and the inline-policy
// reconcile.

// TestPeerInternetCompilesToBothAddressFamilies is the compiler half of a
// property USOSS-14's adapter tests cover on the substrate half only.
//
// Their compiler never emits a SourceCIDR -- a database reachable from the
// internet is the outcome that provider exists to prevent -- so nothing over
// there drives a rule with one through a COMPILE. This does, and it is the case
// that would break every internet-facing service and only those: a rule that
// opened v4 alone leaves an IPv6-reachable workload unreachable on an address it
// has, and an operator adding the v6 rule by hand then loses it to the next
// convergence, correctly, because apphub did not put it there.
func TestPeerInternetCompilesToBothAddressFamilies(t *testing.T) {
	t.Parallel()
	// The internet peer needs no placement configuration -- that is the whole
	// difference between it and the two that do -- so the bare placement the
	// sibling test uses is the right fixture here too.
	pc := PlacementConfig{Name: "bare", VPC: MemoryVPC}
	p := &Provider{name: "test", sub: &Substrate{EC2: NewMemoryEC2()}}
	rules, err := p.compileIngress(context.Background(), pc, []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443},
	})
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("one internet rule compiled to %d substrate rule(s), want 2 (one per address "+
			"family)", len(rules))
	}
	families := map[string]bool{}
	for _, r := range rules {
		if r.SourceCIDR == "" {
			t.Fatalf("an internet rule compiled to a rule with no CIDR: %+v", r)
		}
		families[map[bool]string{true: "v6", false: "v4"}[strings.Contains(r.SourceCIDR, ":")]] = true
	}
	if !families["v4"] || !families["v6"] {
		t.Errorf("the compiled rules cover %v, want both address families", families)
	}
}

// TestCompileIngressRefusesEveryUnresolvablePeer enumerates the peer kinds
// rather than naming the one that motivated the rule.
//
// The source system widens instead of refusing when its platform-ingress
// configuration is missing (build.go:836-848). The generalisation is that ANY
// peer whose configuration can be absent has to refuse, so the switch is driven
// over every kind the interface defines and an unresolvable one must never
// produce a rule.
func TestCompileIngressRefusesEveryUnresolvablePeer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// A placement with nothing configured, so every peer that needs
	// configuration is unresolvable.
	bare := PlacementConfig{Name: "bare", VPC: MemoryVPC}
	p := &Provider{name: "test", sub: &Substrate{EC2: NewMemoryEC2()}}

	needConfig := []compute.PeerKind{compute.PeerPlatformIngress, compute.PeerControlPlane}
	for _, kind := range needConfig {
		rules := []compute.IngressRule{{From: compute.Peer{Kind: kind}, Port: 8080}}
		got, err := p.compileIngress(ctx, bare, rules)
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("peer %q with no configuration compiled to %+v (err %v), want ErrInvalidSpec",
				kind, got, err)
		}
		for _, r := range got {
			if r.SourceCIDR != "" {
				t.Errorf("peer %q with no configuration produced a CIDR rule %+v — this is the "+
					"widening the source system does and this port must not", kind, r)
			}
		}
	}

	// An unknown kind is refused rather than ignored: ignoring it would drop a
	// reachability rule the caller believes is in force.
	if _, err := p.compileIngress(ctx, bare, []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerKind("not-a-peer")}, Port: 8080},
	}); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("an unknown peer kind returned %v, want ErrInvalidSpec", err)
	}

	// And a workload peer naming nothing.
	if _, err := p.compileIngress(ctx, bare, []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerWorkload}, Port: 8080},
	}); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a workload peer with a zero ref returned %v, want ErrInvalidSpec", err)
	}

	// PeerInternet needs no configuration, so it must still work from a bare
	// placement — otherwise this test would pass on an implementation that
	// refused everything.
	got, err := p.compileIngress(ctx, bare, []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080},
	})
	if err != nil {
		t.Fatalf("PeerInternet from a bare placement failed: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("PeerInternet produced %d rule(s), want 2 (one per address family): %+v", len(got), got)
	}
	var families []string
	for _, r := range got {
		families = append(families, r.SourceCIDR)
	}
	if !strings.Contains(strings.Join(families, " "), anyIPv6) {
		t.Errorf("PeerInternet produced %v, missing the IPv6 family", families)
	}
}

// TestReconcileRolePoliciesProvesOwnershipItself is the round-five class:
// *moving a check leaves it wherever the next write is not.*
//
// # Why this has to be internal
//
// The end-to-end version cannot reach the state. `ensureExecutionRole` checks
// ownership and then calls this function, so a marker revoked before the Ensure
// is caught by the caller's own check and a marker revoked during it needs
// interleaving the in-memory substrate does not do. The first version of this
// test was written end-to-end and was GREEN against the defect — the same trap
// USOSS-12 and USOSS-14 each reported hitting on their own ports, and the reason
// the sibling's equivalent test is internal too.
//
// So this calls the write directly with a role whose marker has been revoked,
// which is what "a caller decided earlier and was right at the time" looks like
// from inside.
func TestReconcileRolePoliciesProvesOwnershipItself(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	iam := NewMemoryIAM()
	p := &Provider{name: "test", sub: &Substrate{IAM: iam}}

	const role = "exec-billing"
	if _, err := iam.CreateRole(ctx, CreateRoleRequest{
		Name: role,
		Tags: ownershipTags(role, componentExecutionRole, nil),
	}); err != nil {
		t.Fatalf("creating the role: %v", err)
	}
	grant := map[string]string{policySecretRead: `{"Version":"2012-10-17","Statement":[]}`}

	// Baseline: while it IS ours, the write succeeds. Without this the test
	// could pass on an implementation that refuses everything.
	if err := p.reconcileRolePolicies(ctx, role, componentExecutionRole, grant); err != nil {
		t.Fatalf("writing to a role we own: %v", err)
	}
	if _, ok := iam.RolePolicies(role)[policySecretRead]; !ok {
		t.Fatal("the baseline write did not land, so the refusal below proves nothing")
	}

	for _, tc := range []struct {
		name   string
		revoke func()
	}{
		{"the owner marker is removed", func() {
			_ = iam.UntagRole(ctx, role, []string{tagManagedBy})
		}},
		{"the component marker is removed", func() {
			_ = iam.UntagRole(ctx, role, []string{tagComponent})
		}},
		{"the component becomes another port's", func() {
			_ = iam.TagRole(ctx, role, map[string]string{tagComponent: componentIdentity})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh role per subtest, so one revocation cannot mask another.
			name := role + "-" + strings.ReplaceAll(tc.name, " ", "-")
			if _, err := iam.CreateRole(ctx, CreateRoleRequest{
				Name: name,
				Tags: ownershipTags(name, componentExecutionRole, nil),
			}); err != nil {
				t.Fatalf("creating: %v", err)
			}
			if err := p.reconcileRolePolicies(ctx, name, componentExecutionRole, grant); err != nil {
				t.Fatalf("baseline write: %v", err)
			}
			before := iam.RolePolicies(name)

			switch tc.name {
			case "the owner marker is removed":
				_ = iam.UntagRole(ctx, name, []string{tagManagedBy})
			case "the component marker is removed":
				_ = iam.UntagRole(ctx, name, []string{tagComponent})
			default:
				_ = iam.TagRole(ctx, name, map[string]string{tagComponent: componentIdentity})
			}

			err := p.reconcileRolePolicies(ctx, name, componentExecutionRole,
				map[string]string{policyExec: execPolicy})
			if !errors.Is(err, compute.ErrNotOwned) {
				t.Fatalf("got %v, want ErrNotOwned", err)
			}
			after := iam.RolePolicies(name)
			if _, planted := after[policyExec]; planted {
				t.Error("the refused write attached its grant anyway; a refusal that writes first " +
					"is not a refusal")
			}
			if len(after) != len(before) {
				t.Errorf("policies changed across a refused write: %d before, %d after",
					len(before), len(after))
			}
		})
	}
}
