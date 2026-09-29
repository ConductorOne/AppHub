// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// This file compiles [compute.IngressRule] onto security-group rules, and owns
// the per-service security group's lifecycle.
//
// It is the policy half of the split with the EC2 primitive layer: network.go
// makes one API call per method and decides nothing, and everything that decides
// what a rule means is here.

// componentServiceSecurityGroup is the ownership component for the group this
// port creates per service.
//
// Distinct from every other component in this package, for the reason stated on
// [componentContainerService]: a group created for one purpose must not be
// adoptable as another.
const componentServiceSecurityGroup = "service-security-group"

// anyIPv4 and anyIPv6 are what [compute.PeerInternet] compiles to.
//
// Both, not just IPv4. A rule that opened only 0.0.0.0/0 would leave an
// IPv6-reachable workload unreachable on the address it actually has, and an
// operator would "fix" it by adding ::/0 by hand — which then survives every
// convergence because apphub did not put it there. Naming both is the honest
// version of what [compute.PeerInternet] means.
const (
	anyIPv4 = "0.0.0.0/0"
	anyIPv6 = "::/0"
)

// securityGroupName renders the per-service security group's name.
func (p *Provider) securityGroupName(serviceName string) (string, error) {
	// EC2 group names admit a wide character set, but not a leading "sg-", and
	// they are bounded at 255. The shared helper's digest marker is legal here,
	// so unlike an ECS service name this needs no extra grammar check beyond
	// what sanitize already guarantees.
	name, err := sanitize("", serviceName, 255)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(name, "sg-") {
		return "", fmt.Errorf("%w: the security group name %q would start with \"sg-\", which EC2 "+
			"reserves for group identifiers", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// WorkloadSecurityGroupID resolves a service reference to the security group
// this port created for it.
//
// It exists for the sibling ports that need to express "this workload may reach
// me" — a relational database authorising its application (the source system's
// addRDSIngress, database.go:196-198). Those ports must not guess at this
// port's naming, so the lookup is exported rather than conventional.
//
// Ownership is re-established here rather than inherited from the reference. A
// reference that was valid once is not a capability: the resource behind it can
// be replaced, so a caller handed a group ID for a service somebody else now
// owns would authorise a stranger's workload.
func (p *Provider) WorkloadSecurityGroupID(ctx context.Context, ref compute.Ref) (string, error) {
	if p.sub.EC2 == nil {
		return "", p.unsupported(compute.CapContainerService,
			"no EC2 substrate is configured, so this provider creates no per-service security groups")
	}
	name, pc, err := p.serviceTarget(ref)
	if err != nil {
		return "", err
	}
	// The service has to exist and be ours before its group is named to
	// anybody.
	rec, err := p.sub.ECS.DescribeService(ctx, pc.ClusterARN, name)
	if errors.Is(err, ErrNoSuchResource) {
		return "", fmt.Errorf("%w: %s does not exist", compute.ErrNotFound, ref)
	}
	if err != nil {
		return "", p.substrateError(err)
	}
	if ownErr := p.checkServiceOwned(ctx, ref, rec); ownErr != nil {
		return "", ownErr
	}
	groupName, err := p.securityGroupName(name)
	if err != nil {
		return "", err
	}
	group, err := p.sub.EC2.DescribeSecurityGroupByName(ctx, groupName, pc.VPC)
	if errors.Is(err, ErrNoSuchResource) {
		return "", fmt.Errorf("%w: %s has no security group yet", compute.ErrNotFound, ref)
	}
	if err != nil {
		return "", p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue ||
		group.Tags[tagComponent] != componentServiceSecurityGroup {
		return "", fmt.Errorf("%w: the security group %q is not one this provider created for a "+
			"service", compute.ErrNotOwned, groupName)
	}
	return group.ID, nil
}

// ensureServiceSecurityGroup creates or converges the group for one service and
// returns its ID.
//
// The rule set converges FULLY, in both directions. That is the correct
// treatment for this collection and it is worth saying why, because the same
// answer is wrong for tags: a rule on a group this provider created is either
// one apphub put there or one nobody asked for, and the second is a security
// finding rather than an operator's deliberate configuration. A `CostCenter` tag
// is the opposite — deliberate, and not ours to delete. So tags converge by
// namespace and rules converge entirely.
func (p *Provider) ensureServiceSecurityGroup(
	ctx context.Context,
	serviceName string,
	pc PlacementConfig,
	rules []compute.IngressRule,
	labels map[string]string,
) (string, error) {
	groupName, err := p.securityGroupName(serviceName)
	if err != nil {
		return "", err
	}
	desired, err := p.compileIngress(ctx, pc, rules)
	if err != nil {
		return "", err
	}
	tags := ownershipTags(groupName, componentServiceSecurityGroup, labels)

	group, err := p.sub.EC2.DescribeSecurityGroupByName(ctx, groupName, pc.VPC)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		group, err = p.sub.EC2.CreateSecurityGroup(ctx, CreateSecurityGroupRequest{
			Name: groupName,
			VPC:  pc.VPC,
			// EC2 requires a description and will not let it be changed later.
			// It says what created the group, and names nothing deployment
			// specific.
			Description: "apphub-managed workload ingress",
			Tags:        tags,
		})
		if err != nil {
			return "", p.substrateError(err)
		}
	case err != nil:
		return "", p.substrateError(err)
	default:
		if group.Tags[tagManagedBy] != managedByValue ||
			group.Tags[tagComponent] != componentServiceSecurityGroup {
			return "", fmt.Errorf("%w: the security group %q in %q is not one this provider "+
				"created", compute.ErrNotOwned, groupName, pc.VPC)
		}
		put, remove := tagDelta(group.Tags, tags)
		if len(put) > 0 {
			if err := p.sub.EC2.TagSecurityGroup(ctx, group.ID, put); err != nil {
				return "", p.substrateError(err)
			}
		}
		if len(remove) > 0 {
			if err := p.sub.EC2.UntagSecurityGroup(ctx, group.ID, remove); err != nil {
				return "", p.substrateError(err)
			}
		}
	}

	if err := p.reconcileIngress(ctx, group, desired); err != nil {
		return "", err
	}
	return group.ID, nil
}

// The ingress reconciler and its set arithmetic are NOT here.
//
// [Provider.reconcileIngress], ruleDelta and sortRules were written on this
// branch and on USOSS-14's independently, and USOSS-14's landed first
// (network.go). They are the same function: compute the delta, revoke before
// authorising, and tolerate ErrNoSuchResource on a revoke and ErrAlreadyExists
// on an authorise -- the tolerances belong at the call site rather than in the
// substrate, because [EC2API] has to keep reporting what EC2 reports.
//
// The two versions differed on ONE point, which network.go's own comment
// records: this port's original defaulted the other way on the authorise
// tolerance. That version is gone rather than reconciled, because two
// implementations of one reconciler is two places for the revoke half to be
// forgotten, and the revoke half is the whole security property.
//
// What stays in this file is what is genuinely this port's: the per-service
// group's name, ownership and lifecycle, and the COMPILER from
// [compute.IngressRule] to [SecurityGroupRule]. That one cannot be shared.
// USOSS-14's ingressRules refuses the internet, platform-ingress and workload
// peers -- correctly, because a database endpoint is reachable by none of them
// -- and the container port has to serve all three.

// deleteServiceSecurityGroup removes the group for a service. Idempotent.
func (p *Provider) deleteServiceSecurityGroup(ctx context.Context, serviceName string, pc PlacementConfig) error {
	if p.sub.EC2 == nil {
		return nil
	}
	groupName, err := p.securityGroupName(serviceName)
	if err != nil {
		return err
	}
	group, err := p.sub.EC2.DescribeSecurityGroupByName(ctx, groupName, pc.VPC)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	if err != nil {
		return p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue ||
		group.Tags[tagComponent] != componentServiceSecurityGroup {
		return fmt.Errorf("%w: the security group %q is not one this provider created, so "+
			"teardown will not delete it", compute.ErrNotOwned, groupName)
	}
	if err := p.revokeReferencingIngress(ctx, group.ID, pc.VPC); err != nil {
		return err
	}
	if err := p.sub.EC2.DeleteSecurityGroup(ctx, group.ID); err != nil &&
		!errors.Is(err, ErrNoSuchResource) {
		return p.substrateError(err)
	}
	return nil
}

// revokeReferencingIngress removes every ingress rule, on every other
// apphub-managed security group in vpc, that names id as its source.
//
// It runs before [EC2API.DeleteSecurityGroup] on id, not after. A database's
// group carries a workload-peer rule sourced from its application's service
// group (see [Plan.RelationalIngress]), so deleting the service group first
// -- teardown's order, since nothing may write while data is deleted -- hits
// EC2's DependencyViolation on every attempt: unlike the lingering-ENI case,
// which clears once ECS drains a task, a rule on another group never clears by
// itself. [sdkEC2.err] still maps that refusal to [compute.ErrTransient], so a
// teardown that only retried would loop until its deadline forever instead of
// converging, which is the bug this method closes.
//
// Scoped to groups this provider manages: an operator's own security group is
// not this teardown's rule set to edit, and reaching in to revise it is also
// not a case that arises in practice, since authoring a rule sourced from
// apphub's internal group ID requires knowing that ID.
//
// Idempotent. A rule already revoked, by an earlier attempt or concurrently,
// is absent from the read-back and nothing is sent for it; [EC2API.RevokeIngress]
// tolerating [ErrNoSuchResource] covers the race where it was removed between
// the read and the revoke.
func (p *Provider) revokeReferencingIngress(ctx context.Context, id, vpc string) error {
	referrers, err := p.sub.EC2.DescribeSecurityGroupsReferencing(ctx, id, vpc)
	if err != nil {
		return p.substrateError(err)
	}
	for _, referrer := range referrers {
		if referrer.Tags[tagManagedBy] != managedByValue {
			continue
		}
		var stale []SecurityGroupRule
		for _, r := range referrer.Ingress {
			if r.SourceGroup == id {
				stale = append(stale, r)
			}
		}
		if len(stale) == 0 {
			continue
		}
		if err := p.sub.EC2.RevokeIngress(ctx, referrer.ID, stale); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}
	return nil
}

// compileIngress turns reachability stated between roles into security-group
// rules.
//
// # Every peer is either resolved or refused
//
// The source system's fallback is the thing this must not reproduce: when
// TRAEFIK_SECURITY_GROUP_ID is unset it opens the application's port to
// 0.0.0.0/0 (build.go:836-848), so a missing piece of configuration silently
// becomes the widest possible rule. [compute.PeerPlatformIngress] documents the
// opposite requirement — refuse rather than widen — and that is what happens
// here for every peer whose configuration is absent.
func (p *Provider) compileIngress(ctx context.Context, pc PlacementConfig, rules []compute.IngressRule) ([]SecurityGroupRule, error) {
	out := make([]SecurityGroupRule, 0, len(rules)*2)
	for _, r := range rules {
		proto := strings.ToLower(string(r.Protocol))
		if proto == "" {
			proto = string(compute.ProtocolTCP)
		}
		if proto != string(compute.ProtocolTCP) && proto != string(compute.ProtocolUDP) {
			return nil, fmt.Errorf("%w: %q is not a protocol this interface defines",
				compute.ErrInvalidSpec, r.Protocol)
		}
		if err := checkPort("an ingress rule's Port", r.Port); err != nil {
			return nil, err
		}
		base := singlePort(proto, r.Port, r.Description)

		switch r.From.Kind {
		case compute.PeerInternet:
			v4, v6 := base, base
			v4.SourceCIDR = anyIPv4
			v6.SourceCIDR = anyIPv6
			out = append(out, v4, v6)

		case compute.PeerPlatformIngress:
			if len(pc.PlatformIngressSecurityGroups) == 0 {
				return nil, fmt.Errorf("%w: the spec names the platform-ingress peer and "+
					"placement %q has no PlatformIngressSecurityGroups configured. Refusing "+
					"rather than widening this to the internet, which is what the source system "+
					"does when its equivalent configuration is missing",
					compute.ErrInvalidSpec, pc.Name)
			}
			for _, id := range pc.PlatformIngressSecurityGroups {
				rule := base
				rule.SourceGroup = id
				out = append(out, rule)
			}

		case compute.PeerControlPlane:
			if len(pc.ControlPlaneSecurityGroups) == 0 {
				return nil, fmt.Errorf("%w: the spec names the control-plane peer and placement "+
					"%q has no ControlPlaneSecurityGroups configured",
					compute.ErrInvalidSpec, pc.Name)
			}
			for _, id := range pc.ControlPlaneSecurityGroups {
				rule := base
				rule.SourceGroup = id
				out = append(out, rule)
			}

		case compute.PeerWorkload:
			if r.From.Workload.IsZero() {
				return nil, fmt.Errorf("%w: a workload peer names no workload",
					compute.ErrInvalidSpec)
			}
			id, err := p.WorkloadSecurityGroupID(ctx, r.From.Workload)
			if err != nil {
				return nil, fmt.Errorf("resolving the workload peer %s: %w", r.From.Workload, err)
			}
			rule := base
			rule.SourceGroup = id
			out = append(out, rule)

		default:
			return nil, fmt.Errorf("%w: %q is not a peer this interface defines",
				compute.ErrInvalidSpec, r.From.Kind)
		}
	}
	// De-duplicated, because two spec rules can legitimately compile to one
	// substrate rule and EC2 rejects a duplicate authorisation.
	return dedupeRules(out), nil
}

func dedupeRules(in []SecurityGroupRule) []SecurityGroupRule {
	seen := make(map[SecurityGroupRule]struct{}, len(in))
	out := make([]SecurityGroupRule, 0, len(in))
	for _, r := range in {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sortRules(out)
	return out
}
