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

	"github.com/conductorone/apphub/compute"
)

// This file is the EC2 layer: resolving a [compute.Placement] to the network
// coordinates AWS needs, compiling [compute.IngressRule] into security group
// rules, and converging a security group onto a declared rule set.
//
// # Why it is here and not in the port that uses it
//
// Nothing in this file mentions a load balancer or a function. It is shared
// deliberately: the container port (USOSS-11) needs the same primitives for an
// ECS service's own security group and the same compiler for
// [compute.ServiceSpec.Ingress], and two ports each writing their own would be
// two definitions of one thing — which is how a peer that one port fails closed
// on becomes a peer the other widens.
//
// The division agreed with USOSS-11 and approved by the supervisor: this file
// owns the primitives and the compiler; that port extends the peer switch with
// the two cases this port refuses, and owns the service-side call sites.
//
// # No AWS network identifier appears above [Substrate]
//
// A VPC identifier, a subnet identifier and a security group identifier all
// exist in this file and none of them exists in any type [compute] can see.
// They enter through [PlacementConfig] and they leave through [EC2API]. That is
// the property [compute.Placement] documents at length and the reason it carries
// a name and nothing else.

// networkPlacement is a placement resolved against what EC2 actually reports.
type networkPlacement struct {
	// PlacementConfig is the operator's configuration for the placement.
	PlacementConfig
	// VpcID is the VPC every subnet in the placement belongs to.
	VpcID string
	// SubnetIDs are the placement's subnets, in configuration order.
	SubnetIDs []string
	// Zones are the distinct availability zones those subnets span, sorted.
	Zones []string
}

// resolveNetwork turns a [compute.Placement] into the coordinates a load
// balancer and a security group need.
//
// It checks three things the source system does not, and each one is a real
// failure it lets through:
//
//   - **Every subnet exists.** The source passes the configured list straight
//     into CreateLoadBalancer (lambda.go:611) and describes only subnet zero
//     (lambda.go:418-422). A stale identifier in the list is discovered by
//     ELBv2, in an error naming a subnet the caller never chose.
//   - **Every subnet is in one VPC.** The source recovers the VPC from subnet
//     zero alone (getVPCFromSubnet, lambda.go:736-753) and creates the security
//     group there. A list spanning two VPCs therefore yields a security group
//     in one of them and a load balancer that cannot use the other's subnets —
//     and the security group is created and tagged before that is discovered.
//   - **They span two availability zones.** An application load balancer
//     requires it. The source lets CreateLoadBalancer report it.
//
// All three are configuration errors, so all three are [compute.ErrInvalidSpec]
// naming the placement, not the caller's spec.
func (p *Provider) resolveNetwork(placement compute.Placement) (networkPlacement, error) {
	// The region refusal comes first, and it is the ruling that placement on AWS
	// is refused rather than ignored. See [Provider.regionalPlacement].
	pc, err := p.regionalPlacement(placement)
	if err != nil {
		return networkPlacement{}, err
	}
	if len(pc.SubnetIDs) < minEndpointSubnets {
		return networkPlacement{}, fmt.Errorf("%w: placement %q configures %d subnets and a load "+
			"balancer needs at least %d; see Config.Placements[%q].SubnetIDs",
			compute.ErrInvalidSpec, pc.Name, len(pc.SubnetIDs), minEndpointSubnets, pc.Name)
	}
	return networkPlacement{PlacementConfig: pc, SubnetIDs: pc.SubnetIDs}, nil
}

// describeNetwork completes a [networkPlacement] with what EC2 reports, and is
// where the three checks above are actually made.
//
// Split from [Provider.resolveNetwork] because the configuration half needs no
// context and no substrate call, so a teardown path that only needs to know
// which placement a resource was in does not pay for a DescribeSubnets.
func (p *Provider) describeNetwork(ctx context.Context, in networkPlacement) (networkPlacement, error) {
	pc := in.PlacementConfig
	subnets, err := p.sub.EndpointEC2.DescribeSubnets(ctx, pc.SubnetIDs)
	if err != nil {
		if errors.Is(err, ErrNoSuchResource) {
			return networkPlacement{}, fmt.Errorf("%w: placement %q names a subnet that does not "+
				"exist: %w", compute.ErrInvalidSpec, pc.Name, err)
		}
		return networkPlacement{}, p.substrateError(err)
	}
	if len(subnets) != len(pc.SubnetIDs) {
		// A partial answer is the same configuration error as a missing one, and
		// proceeding on a subset would place a load balancer somewhere narrower
		// than the operator configured.
		return networkPlacement{}, fmt.Errorf("%w: placement %q names %d subnets and EC2 reported "+
			"%d; one of them does not exist", compute.ErrInvalidSpec, pc.Name,
			len(pc.SubnetIDs), len(subnets))
	}

	out := in
	zones := map[string]struct{}{}
	for _, sn := range subnets {
		switch {
		case out.VpcID == "":
			out.VpcID = sn.VpcID
		case sn.VpcID != out.VpcID:
			return networkPlacement{}, fmt.Errorf("%w: placement %q spans more than one VPC; "+
				"subnet %q is in a different one from the first. A security group belongs to one "+
				"VPC, so a load balancer placed across two cannot be given one that reaches all "+
				"of its subnets", compute.ErrInvalidSpec, pc.Name, sn.ID)
		}
		zones[sn.AvailabilityZone] = struct{}{}
	}
	for z := range zones {
		out.Zones = append(out.Zones, z)
	}
	sort.Strings(out.Zones)
	if len(out.Zones) < minEndpointZones {
		return networkPlacement{}, fmt.Errorf("%w: placement %q spans %d availability zone(s) and "+
			"an application load balancer needs at least %d; the subnets configured for it are "+
			"all in %v", compute.ErrInvalidSpec, pc.Name, len(out.Zones), minEndpointZones, out.Zones)
	}
	return out, nil
}

// The CIDRs [compute.PeerInternet] compiles to.
//
// Both families, because a load balancer with only the IPv4 rule is reachable
// over IPv6 by nobody and a caller asking for "the internet" did not ask for
// half of it. The source system authorises both (lambda.go:576-586), and this
// is the one thing on that path it gets right.
const (
	cidrAnyV4 = "0.0.0.0/0"
	cidrAnyV6 = "::/0"
)

// ingressRules compiles a declared reachability set into security group rules.
//
// This is the peer-to-network translation [compute.PeerKind] exists to make
// possible: the rules above are between roles in the system, the rules below are
// between network objects, and this is the only place the two vocabularies meet.
//
// Two peers are refused rather than approximated, and saying which and why is
// the point:
//
//   - [compute.PeerControlPlane] would need the security groups apphub's own
//     control plane runs under, and this package has no configuration for them.
//     The source system authorises "every control-plane security group"
//     (database.go:206-219) on the database path; there is no equivalent for a
//     load balancer, and inventing a configuration field to hold one for a rule
//     nothing asks for would be inventing a network model.
//   - [compute.PeerWorkload] would need the security group of another workload
//     this platform deployed. This port creates none — a Lambda function has no
//     security group — so the only honest answer today is a refusal. The
//     container port (USOSS-11) does create them, and when it does the case
//     becomes implementable; the switch is written so that adding it is one arm.
//
// Both refusals are [compute.ErrInvalidSpec], which is what a caller can act on:
// the alternative to refusing an unresolvable peer is widening it, and widening
// a peer to make a spec work is the source system's defect
// (build.go:836-848), not a workaround.
func (p *Provider) endpointIngressRules(np networkPlacement, rules []compute.IngressRule) ([]EndpointSecurityGroupRule, error) {
	out := make([]EndpointSecurityGroupRule, 0, 2*len(rules))
	for _, r := range rules {
		if r.Port < 1 || r.Port > 65535 {
			return nil, fmt.Errorf("%w: %d is not a port", compute.ErrInvalidSpec, r.Port)
		}
		proto := r.Protocol
		if proto == "" {
			proto = compute.ProtocolTCP
		}
		switch proto {
		case compute.ProtocolTCP, compute.ProtocolUDP:
		default:
			return nil, fmt.Errorf("%w: %q is not a protocol this interface defines",
				compute.ErrInvalidSpec, r.Protocol)
		}
		// A workload reference on any other peer kind is ErrInvalidSpec, which
		// [compute.Peer] states outright. Checking it matters because ignoring
		// it silently would let a caller believe it had narrowed a rule it had
		// in fact left wide.
		if r.From.Kind != compute.PeerWorkload && r.From.Workload != (compute.Ref{}) {
			return nil, fmt.Errorf("%w: a %q peer carries a workload reference (%s), which is "+
				"only meaningful on a %q peer", compute.ErrInvalidSpec, r.From.Kind,
				r.From.Workload, compute.PeerWorkload)
		}

		// The description is carried through unchanged, including empty. It is
		// operator-facing text and nothing reads it: see
		// [EndpointSecurityGroupRule.Description] for why an earlier revision writing a
		// marker here was a defect rather than a convenience.
		// The peer kind travels with the rule, because the finished EC2 rule will
		// not preserve it and the read-back must not have to guess. See [tagPeer].
		base := EndpointSecurityGroupRule{
			Protocol: string(proto), Port: r.Port, Description: r.Description,
			Tags: map[string]string{tagPeer: string(r.From.Kind)},
		}
		switch r.From.Kind {
		case compute.PeerInternet:
			v4, v6 := base, base
			v4.CIDRv4, v6.CIDRv6 = cidrAnyV4, cidrAnyV6
			out = append(out, v4, v6)
		case compute.PeerPlatformIngress:
			id := strings.TrimSpace(np.PlatformIngressSecurityGroupID)
			if id == "" {
				return nil, fmt.Errorf("%w: this rule names the platform's ingress proxy as a "+
					"peer and placement %q has no PlatformIngressSecurityGroupID configured. "+
					"Refusing rather than widening the rule to %q, which is what the source "+
					"system does when its equivalent setting is unset; configure "+
					"Config.Placements[%q].PlatformIngressSecurityGroupID",
					compute.ErrInvalidSpec, np.Name, compute.PeerInternet, np.Name)
			}
			peer := base
			peer.PeerGroupID = id
			out = append(out, peer)
		case compute.PeerControlPlane:
			return nil, fmt.Errorf("%w: this provider cannot resolve a %q peer; it holds no "+
				"configuration naming apphub's own control plane, and it will not widen the rule "+
				"to something it can resolve", compute.ErrInvalidSpec, r.From.Kind)
		case compute.PeerWorkload:
			return nil, fmt.Errorf("%w: this provider cannot resolve a %q peer for this resource; "+
				"a Lambda function has no security group for one to name",
				compute.ErrInvalidSpec, r.From.Kind)
		default:
			return nil, fmt.Errorf("%w: %q is not a peer this interface defines",
				compute.ErrInvalidSpec, r.From.Kind)
		}
	}
	return endpointDedupeRules(out), nil
}

// endpointRuleKey is a rule's identity for the purpose of converging a set.
//
// The description is deliberately excluded. EC2 stores it, but two rules
// differing only in their text are one permission, and treating them as two
// would make an edited [compute.IngressRule.Description] revoke and reauthorise
// a rule that never changed — a window, however brief, in which traffic the
// caller never asked to block is blocked.
//
// The tags are excluded for the same reason, and the identifier because a rule
// this package is about to create does not have one yet.
func endpointRuleKey(r EndpointSecurityGroupRule) string {
	return strings.Join([]string{
		r.Protocol, strconv.Itoa(r.Port), r.CIDRv4, r.CIDRv6, r.PeerGroupID,
	}, "|")
}

// endpointDedupeRules collapses rules with the same identity, keeping the first.
//
// Needed because two [compute.IngressRule] values can legitimately compile to
// one permission — the same peer and port declared twice, or once with an
// explicit tcp and once with the empty protocol that means it — and EC2 rejects
// a duplicate within one AuthorizeSecurityGroupIngress call.
func endpointDedupeRules(in []EndpointSecurityGroupRule) []EndpointSecurityGroupRule {
	seen := make(map[string]struct{}, len(in))
	out := make([]EndpointSecurityGroupRule, 0, len(in))
	for _, r := range in {
		k := endpointRuleKey(r)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// endpointIsOwnRule reports whether this platform created a rule, as this component.
//
// # Why this reads a tag and not the description
//
// An earlier revision of this package read ownership from
// [EndpointSecurityGroupRule.Description], on the argument that a security group rule
// had nowhere else to put a marker. **That argument was wrong** — a rule is a
// first-class taggable EC2 object with its own identifier — and the mechanism it
// justified failed in both directions at once, which is what makes this a class
// and not a bug:
//
//   - A rule this provider created with an ordinary caller-supplied description
//     was **never revoked**, because the caller's text replaced the marker. A
//     port removed from a spec stayed open. The security control failed open on
//     the most ordinary input there is — a caller who described their own rule.
//   - An operator's own rule whose text merely mentioned the project was
//     **deleted** on the next unchanged Ensure.
//
// The general form, and the reason this is stated at length: **an ownership
// signal is only as trustworthy as the permission needed to forge it.**
// Free text needs none. A tag needs `ec2:CreateTags` on the resource. So the
// claim lives outside the thing being claimed, in a field the caller cannot
// write, and it is matched exactly rather than searched for — a longer substring
// or a prefix test closes the witness in front of you and leaves the next
// spelling available.
//
// Both tags are checked, for the same reason [checkOwned] checks both: this port
// creates four objects and a sibling port creates more, so "apphub made this"
// is not specific enough to act on.
func endpointIsOwnRule(r EndpointSecurityGroupRule, component string) bool {
	return r.Tags[tagManagedBy] == managedByValue && r.Tags[tagComponent] == component
}

// endpointRuleDelta reports which rules have to be authorised and which revoked to
// converge current onto desired.
//
// The revoke half is the one that matters and the one the source system has no
// equivalent of on this path. [compute.IngressRule] is declarative: the set
// attached to a spec is the desired state, reconciled to exactly that set on
// every Ensure. An implementation that only authorises passes every test that
// checks a rule is present, and leaves every rule ever asked for open forever —
// so "I removed that rule" means "I stopped asking for it". The source system
// needed a separate ReconcileContainerPortIngress helper (build.go:888-940) to
// patch exactly this, which a caller has to remember to invoke.
//
// Only rules this provider created *as this component* are eligible for
// revoking, on the same principle as [tagDelta]: an operator or an account
// policy may have added a rule to a group apphub created, and reconciling a
// spec is not the same as taking over a resource. Eligibility is decided by
// [endpointIsOwnRule], on a tag.
//
// Revocation returns identifiers rather than rules, because an identifier names
// exactly one rule and a reconstructed permission asks EC2 to match.
//
// The fourth set is the migration one, and it exists because **a recorded fact is
// only as good as its coverage of the records that already exist.** [tagPeer]
// replaced an inference with a stored answer, and the store only had an answer for
// rules written after the change — so on any deployment that predates it, the
// first reconcile met rules with no peer kind and [Provider.describeIngress]
// refused. Retagging on encounter makes that state reachable rather than fatal,
// without reinstating the guess: see the case body for why recovering the kind
// from the desired rule is a match and not an inference.
//
// The third set is descriptions. [endpointRuleKey] excludes the description from a
// rule's identity, and that is right — folding it in would make every wording
// edit a revoke-and-reauthorise, a window of lost reachability for a change that
// alters no permission. But "not identity" is not "not desired state":
// [compute.IngressRule.Description] is public desired state and explicitly
// operator-facing, so a changed one has to reach the rule or the effective spec
// reports text the substrate does not have. An earlier revision treated a
// matching key as fully converged and left the old text on both.
func endpointRuleDelta(current, desired []EndpointSecurityGroupRule, component string) (
	authorize []EndpointSecurityGroupRule,
	redescribe []EndpointSecurityGroupRule,
	retag []EndpointSecurityGroupRule,
	revoke []string,
) {
	want := make(map[string]struct{}, len(desired))
	for _, r := range desired {
		want[endpointRuleKey(r)] = struct{}{}
	}
	// Only rules this provider owns count as already-present. A rule an operator
	// added that happens to match a desired one is left alone and the provider
	// authorises its own alongside it, because adopting it would mean this
	// package revoking a rule it did not create the next time the spec changed.
	have := make(map[string]EndpointSecurityGroupRule, len(current))
	for _, r := range current {
		if endpointIsOwnRule(r, component) {
			have[endpointRuleKey(r)] = r
		}
	}
	for _, r := range desired {
		existing, ok := have[endpointRuleKey(r)]
		if ok && existing.Tags[tagPeer] != r.Tags[tagPeer] {
			// An owned rule whose recorded peer kind is missing or stale. The
			// commonest cause is a rule written before this package recorded the
			// peer kind at all, which is every rule on any deployment that
			// existed before that change — "we changed the write path" does not
			// retroactively change what is stored.
			//
			// The peer kind is recovered from the **desired** rule, and that is a
			// match rather than an inference: the caller has declared that this
			// exact permission is for this peer, and the stored rule carries that
			// exact permission. Nothing is being guessed from the shape of the
			// rule, which is the thing [tagPeer] exists to stop.
			//
			// An owned untagged rule matching *no* desired rule needs no recovery:
			// it is revoked below, by identifier, and its peer kind never enters
			// the decision.
			fresh := existing
			fresh.Tags = copyTags(existing.Tags)
			if fresh.Tags == nil {
				fresh.Tags = map[string]string{}
			}
			fresh.Tags[tagPeer] = r.Tags[tagPeer]
			retag = append(retag, fresh)
		}
		switch {
		case !ok:
			authorize = append(authorize, r)
		case existing.Description != r.Description:
			// Same permission, different operator-facing text. Rewritten in
			// place rather than replaced: the permission is unchanged, and a
			// revoke-and-reauthorise would close a port the caller never asked
			// to close for as long as the two calls take.
			//
			// The identifier comes from the *stored* rule and the text from the
			// desired one, which is the whole content of this case.
			update := existing
			update.Description = r.Description
			redescribe = append(redescribe, update)
		}
	}
	for _, r := range current {
		if !endpointIsOwnRule(r, component) {
			continue
		}
		if _, ok := want[endpointRuleKey(r)]; ok {
			continue
		}
		if r.ID == "" {
			// A rule this provider owns and cannot name. Unreachable through
			// [EC2API], which always reports an identifier; here so that a
			// substrate which did not would fail loudly rather than silently
			// skipping a revocation.
			continue
		}
		revoke = append(revoke, r.ID)
	}
	sort.Slice(authorize, func(i, j int) bool { return endpointRuleKey(authorize[i]) < endpointRuleKey(authorize[j]) })
	sort.Slice(redescribe, func(i, j int) bool { return redescribe[i].ID < redescribe[j].ID })
	sort.Slice(retag, func(i, j int) bool { return retag[i].ID < retag[j].ID })
	sort.Strings(revoke)
	return authorize, redescribe, retag, revoke
}

// ensureIngressGroup creates or converges the security group that fronts one
// resource, and returns its identifier.
//
// The shape is the source system's ensureSecurityGroup (lambda.go:527-590) with
// three of its behaviours removed:
//
//   - It adopts whatever group it finds under the name it wanted, with no
//     ownership check, so a group an operator created gets this platform's
//     rules written onto it. Here [checkOwned] runs first, on both tags.
//   - It authorises rules only on the create path and returns early when it
//     finds an existing group, so a changed port never opens and the old one
//     never closes. Here the rule set converges on every call.
//   - It tolerates a failure of AuthorizeSecurityGroupIngress with a logged
//     warning (lambda.go:588-590), which leaves a group that admits nothing —
//     and because of the early return above, the next reconcile adopts that
//     group and never repairs it. Here the failure is the call's failure.
func (p *Provider) endpointEnsureIngressGroup(
	ctx context.Context,
	np networkPlacement,
	name, component string,
	desired []EndpointSecurityGroupRule,
	tags map[string]string,
) (string, error) {
	group, err := p.sub.EndpointEC2.DescribeSecurityGroup(ctx, np.VpcID, name)
	switch {
	case err == nil:
		if err := checkOwned(group.Tags, "security group", component, name); err != nil {
			return "", err
		}
	case errors.Is(err, ErrNoSuchResource):
		group, err = p.sub.EndpointEC2.CreateSecurityGroup(ctx, EndpointCreateSecurityGroupRequest{
			Name:        name,
			Description: p.cfg.Endpoint.description(),
			VpcID:       np.VpcID,
			Tags:        tags,
		})
		if err != nil {
			return "", p.substrateError(err)
		}
	default:
		return "", p.substrateError(err)
	}

	current, err := p.sub.EndpointEC2.DescribeSecurityGroupRules(ctx, group.ID)
	if err != nil {
		return "", p.substrateError(err)
	}
	authorize, redescribe, retag, revoke := endpointRuleDelta(current, desired, component)
	// Retagging comes first, so that an Ensure over rules that predate [tagPeer]
	// heals them before anything reads them back. The order is the whole fix: the
	// reported defect was the public EnsureEndpoint refusing at its own read-back
	// on rules it had just declined to touch.
	for _, r := range retag {
		if err := p.sub.EndpointEC2.CreateTags(ctx, r.ID, r.Tags); err != nil {
			return "", p.substrateError(err)
		}
	}
	// Authorise before revoking. Both orders leave a window on a rule that is
	// being replaced; this one errs towards a moment of extra reachability
	// rather than a moment of none, which is the right way round for a rule the
	// caller is keeping and has only re-described. A rule the caller genuinely
	// removed is not in the authorise set at all, so this does not delay
	// closing anything.
	// One authorise call per peer kind, not one per convergence.
	//
	// EC2 applies a single TagSpecification to every rule a call creates, so rules
	// that must carry different [tagPeer] values cannot share one call. Batching
	// them and tagging with whichever peer came first would put the wrong peer
	// kind on a real rule — which is worse than the inference this replaced,
	// because a wrong recorded answer survives every later read.
	for _, peer := range endpointPeerKindsOf(authorize) {
		batch := endpointRulesForPeer(authorize, peer)
		// The group's ownership tags, plus the peer kind. The ownership tags are
		// what let the revocation above tell this platform's rules from an
		// operator's without reading anything the caller can write; the peer tag
		// is what lets the read-back describe them without guessing.
		ruleTags := copyTags(tags)
		if ruleTags == nil {
			ruleTags = map[string]string{}
		}
		ruleTags[tagPeer] = peer
		if err := p.sub.EndpointEC2.AuthorizeSecurityGroupIngress(ctx, group.ID, batch, ruleTags); err != nil {
			return "", p.substrateError(err)
		}
	}
	if len(redescribe) > 0 {
		if err := p.sub.EndpointEC2.UpdateSecurityGroupRuleDescriptions(ctx, group.ID, redescribe); err != nil {
			return "", p.substrateError(err)
		}
	}
	if len(revoke) > 0 {
		if err := p.sub.EndpointEC2.RevokeSecurityGroupIngress(ctx, group.ID, revoke); err != nil {
			return "", p.substrateError(err)
		}
	}

	put, remove := tagDelta(group.Tags, tags)
	if len(remove) > 0 {
		if err := p.sub.EndpointEC2.DeleteTags(ctx, group.ID, remove); err != nil {
			return "", p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.EndpointEC2.CreateTags(ctx, group.ID, put); err != nil {
			return "", p.substrateError(err)
		}
	}
	return group.ID, nil
}

// describeIngress reads a security group's rule set back as reachability rules.
//
// The inverse of [Provider.ingressRules], and it has to collapse what that
// function expanded: a [compute.PeerInternet] rule compiles to two EC2 rules, one
// per address family, and reporting two would tell a caller its spec had grown a
// rule it never wrote. Keying the result on protocol and port does that, and it is
// exact rather than approximate because this provider never authorises a partial
// pair.
//
// # The peer kind is read, never inferred
//
// An earlier revision inferred it: an "any" CIDR meant the internet, and a peer
// group matching the placement's configured ingress proxy meant the platform
// proxy. The second half was **fail-open through a read**. A placement removed
// from configuration, or an ingress proxy group changed, left an owned rule whose
// peer could not be named — and an unnameable rule was omitted, so
// DescribeEndpoint reported an endpoint with **no ingress at all** when it had
// two rules. A caller reconciling against that reading does not restore what it
// cannot see, so a silent drop in a read path becomes a silent divergence in
// every write path below it.
//
// The information was destroyed before the classifier ran, which is why the fix
// is not another branch: the peer kind is now recorded at the write ([tagPeer])
// and read here.
//
// An owned rule carrying no recognisable peer kind is an **error**, not an
// omission. It is unreachable through this package's own writes, so it means
// something else wrote a rule under this platform's ownership tags — and the one
// thing this function must never do again is answer "no rule" for a rule that
// exists.
func (p *Provider) endpointDescribeIngress(rules []EndpointSecurityGroupRule, component string) ([]compute.IngressRule, error) {
	type key struct {
		proto string
		port  int
	}
	seen := map[key]struct{}{}
	var out []compute.IngressRule
	for _, r := range rules {
		if !endpointIsOwnRule(r, component) {
			continue
		}
		kind := compute.PeerKind(r.Tags[tagPeer])
		switch kind {
		case compute.PeerInternet, compute.PeerPlatformIngress,
			compute.PeerControlPlane, compute.PeerWorkload:
		default:
			// Named remedy, because this is reachable on a deployment whose rules
			// predate [tagPeer] and the caller needs to know it heals rather than
			// being stuck. An Ensure retags on encounter; see [endpointRuleDelta].
			//
			// Still an error rather than an omission, and deliberately not weakened
			// into a fallback inference: answering "no rule" for a rule that exists
			// is what the peer tag was introduced to stop, and guessing the kind
			// here is the guess it replaced.
			return nil, fmt.Errorf("%w: security group rule %q carries this platform's ownership "+
				"tags and peer kind %q, which is not one this interface defines. A rule written "+
				"before this provider recorded the peer kind looks like this; re-Ensure the "+
				"endpoint to converge it, which retags such rules from the declared spec",
				compute.ErrFailed, r.ID, r.Tags[tagPeer])
		}
		k := key{r.Protocol, r.Port}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, compute.IngressRule{
			From:        compute.Peer{Kind: kind},
			Port:        r.Port,
			Protocol:    compute.Protocol(r.Protocol),
			Description: r.Description,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].From.Kind < out[j].From.Kind
	})
	return out, nil
}

// findIngressGroups locates every security group this provider created under a
// logical name, by its own ownership marker and **not** by any placement.
//
// This is the read that closes a defect the placement-scoped one could not. See
// [EC2API.FindSecurityGroups] for the argument in full; the short form is that
// a security group is addressed by VPC and name, the VPC comes from
// configuration, and configuration is the thing that changes underneath a
// resource created earlier. A teardown or a read-back has to look where the
// resource *was*.
//
// The marker is sufficient, which is what makes this possible rather than a
// widening: the three ownership tags are ANDed, and one of them is the physical
// name, so the widest thing this can return is a group this platform created as
// this component under the name the reference names.
func (p *Provider) endpointFindIngressGroups(ctx context.Context, name, component string) ([]EndpointSecurityGroupRecord, error) {
	groups, err := p.sub.EndpointEC2.FindSecurityGroups(ctx, ownershipTags(name, component, nil))
	if err != nil {
		return nil, p.substrateError(err)
	}
	// The tag filter is the substrate's; the ownership check is this package's,
	// and it runs again on what came back. A filter is a query and a check is a
	// decision, and trusting the query would mean a substrate that ignored a
	// filter could hand this package somebody else's group to delete.
	kept := groups[:0]
	for _, g := range groups {
		if checkOwned(g.Tags, "security group", component, name) == nil {
			kept = append(kept, g)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })
	return kept, nil
}

// deleteIngressGroupsByMarker removes every security group this provider created
// under a logical name, wherever it is.
//
// It replaces a search over the currently configured placements. That search was
// correctly executed over the wrong population: a placement removed from
// configuration is absent from it, so the group it created was never inspected
// and the teardown returned success with the group still in place. Widening the
// population by one case would have left the same unsoundness at a larger size,
// so the population is no longer configuration at all.
//
// Every match is deleted rather than the first. Two placements can share a region
// and hold two groups of one name in two VPCs — reachable by editing placements
// between deploys — and "removes everything it created" means all of them.
//
// Finding nothing is success: teardown is idempotent, and a second call has
// nothing left to do.
//
// There is deliberately **no** VPC-scoped sibling of this function any more. One
// existed, kept for "a caller told which VPC to act in by a spec", and nothing
// called it — which made it dead code in the shape of the unsound path, sitting
// there for the next person to reach for. Removing it is the difference between a
// rule nobody violates and a construction that cannot express the violation.
func (p *Provider) endpointDeleteIngressGroupsByMarker(ctx context.Context, name, component string) error {
	groups, err := p.endpointFindIngressGroups(ctx, name, component)
	if err != nil {
		return err
	}
	for _, g := range groups {
		err := p.sub.EndpointEC2.DeleteSecurityGroup(ctx, g.ID)
		if err != nil && !errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}
	return nil
}

// endpointPeerKindsOf reports the distinct peer kinds in a rule set, sorted, so the
// authorise calls are deterministic.
func endpointPeerKindsOf(rules []EndpointSecurityGroupRule) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range rules {
		peer := r.Tags[tagPeer]
		if _, ok := seen[peer]; ok {
			continue
		}
		seen[peer] = struct{}{}
		out = append(out, peer)
	}
	sort.Strings(out)
	return out
}

// endpointRulesForPeer narrows a rule set to one peer kind.
func endpointRulesForPeer(rules []EndpointSecurityGroupRule, peer string) []EndpointSecurityGroupRule {
	out := make([]EndpointSecurityGroupRule, 0, len(rules))
	for _, r := range rules {
		if r.Tags[tagPeer] == peer {
			out = append(out, r)
		}
	}
	return out
}

// endpointRenderRules formats a rule set for a rendered artefact. Peer-and-port only,
// which is what an operator or a conformance check needs to see.
func endpointRenderRules(rules []EndpointSecurityGroupRule) string {
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		peer := r.PeerGroupID
		switch {
		case r.CIDRv4 != "":
			peer = r.CIDRv4
		case r.CIDRv6 != "":
			peer = r.CIDRv6
		}
		rendered := fmt.Sprintf("%s/%d/%s", r.Protocol, r.Port, peer)
		if r.Description != "" {
			// Included so that a description change is observable in the
			// substrate and not only in the effective spec. The provider's own
			// read-back cannot establish that the text reached the rule, which is
			// exactly the gap that let a stale description survive.
			rendered += "(" + r.Description + ")"
		}
		parts = append(parts, rendered)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
