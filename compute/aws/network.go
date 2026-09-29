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
	"sync"

	"github.com/conductorone/apphub/compute"
)

// The EC2 surface, its in-memory implementation, and the compiler that turns
// [compute.IngressRule] values into security-group rules.
//
// # Who owns this file
//
// The supervisor addendum to USOSS-10's friction document splits EC2 between
// two other tickets: USOSS-12 owns the primitive layer (this interface, its
// implementations, and the placement resolver) because it needs it for the load
// balancer's security group, and USOSS-11 owns the compiler because
// ServiceSpec.Ingress belongs to its port.
//
// USOSS-14 wrote it anyway, and the reason is not impatience.
// [compute.RelationalSpec.Ingress] is on *this* port, and an Aurora cluster is
// unreachable without a security group, so the relational port cannot exist
// without both halves. Shipping them under the filename the addendum assigns is
// deliberate: whoever rebases second gets a whole-file conflict, which is loud,
// rather than a duplicate symbol reported from wherever the linker happens to
// notice it. Both siblings have been sent the exact shape.

// SecurityGroupRecord is what EC2 reports about one security group.
type SecurityGroupRecord struct {
	// ID is the group's identifier.
	//
	// It is read back and never composed, for the same reason
	// [RepositoryRecord.ARN] is: it is assigned by EC2, it is a network
	// identifier this package must not hold as configuration, and it is the
	// value every later call keys on.
	ID string
	// Name is the group name, which is what this provider looks a group up by.
	Name string
	// VPC is the VPC the group belongs to.
	VPC string
	// Ingress is the group's complete inbound rule set, as EC2 reported it.
	//
	// Read back in full because [compute.IngressRule] is declarative: a
	// provider that could only add rules would leave a port open after the
	// caller removed it, which is the defect the source system patched with a
	// separate reconcile function (build.go:888-940).
	Ingress []SecurityGroupRule
	// Tags are the group's tags.
	Tags map[string]string
}

// SecurityGroupRule is one inbound permission on a security group.
//
// It is a value type with no AWS types in it, and it is comparable, so the
// provider can diff a desired set against an observed one with ordinary set
// arithmetic rather than by walking nested SDK structures.
type SecurityGroupRule struct {
	// Protocol is the IP protocol, lowercase: "tcp", "udp", "icmp", "icmpv6",
	// or "-1" for every protocol.
	Protocol string
	// FromPort and ToPort are the span, and whether EC2 stated one at all.
	//
	// Optional rather than plain integers because the SDK's FromPort and ToPort
	// are *int32 and an all-protocol permission legitimately omits both. Turning
	// a nil into a zero and rendering a non-nil zero back is not the permission
	// EC2 returned, and the revoke is built from the permission.
	//
	// Their meaning is protocol-dependent, which is why nothing here interprets
	// them: for TCP and UDP they are ports, for ICMP and ICMPv6 they are the type
	// and the code, and -1 is the documented wildcard for both of those. -1 is
	// therefore a legal value that this package must carry, not a marker it may
	// mint -- see the history note below.
	FromPort OptionalPort
	ToPort   OptionalPort
	// SourceGroup, SourceCIDR and SourcePrefixList are the source. Exactly one
	// is set, because a permission carrying several sources is read as one rule
	// per source -- each is separately revocable, which is what reconciliation
	// needs.
	//
	// SourceGroup is a security group this provider or another system allowed.
	SourceGroup string
	// SourceGroupOwner is the account owning SourceGroup, when EC2 states one.
	//
	// Carried because a cross-account pair is a rule on this group and revoking
	// it needs the owner: two accounts can each have a group with the same id
	// shape, and a revoke that drops the UserId is a revoke of a different rule
	// or of nothing.
	SourceGroupOwner string
	// SourceCIDR is an address range, v4 or v6.
	//
	// This provider never writes one. The field exists so that a rule an
	// operator or another system added is *visible* to the ownership and
	// convergence logic rather than invisible to it: a provider that could not
	// see a CIDR rule would report a group as converged while 0.0.0.0/0 stood
	// open on it.
	SourceCIDR string
	// SourcePrefixList is a managed prefix list allowed to connect.
	//
	// Same reason as SourceCIDR and a sharper one. A permission whose only
	// source is a prefix list used to produce *no rules at all*, so it could
	// never enter the removal set and stayed authorised with nothing pointing at
	// it -- a worse failure than the sentinel this struct's history is about,
	// because a strange value in a read-back is an anomaly somebody may notice
	// and zero rules is indistinguishable from an empty group. Silent omission
	// is the fail-open with the evidence removed.
	SourcePrefixList string
	// Description is operator-facing text, and whether EC2 stated one.
	//
	// Optional for the same reason as the ports: the SDK's Description is a
	// *string on every source arm, the description is carried into the revoke,
	// and **a permission with no description and a permission with an empty one
	// are different permissions.** Rendering an absent description as a pointer
	// to "" is the nil-to-zero defect in another field.
	//
	// Found by USOSS-11's generated cross product over types.IpPermission, which
	// is the instrument that can find this class and a hand-written table cannot.
	Description OptionalString
}

// OptionalString is a string, or the absence of one.
//
// The same shape and the same reason as [OptionalPort]: comparable, because rules
// are diffed by equality, with absence having exactly one representation.
type OptionalString struct {
	Set   bool
	Value string
}

// Text states a description.
func Text(v string) OptionalString { return OptionalString{Set: true, Value: v} }

// NoText is the absence of a stated description.
func NoText() OptionalString { return OptionalString{} }

func optionalStringFrom(v *string) OptionalString {
	if v == nil {
		return NoText()
	}
	return Text(*v)
}

// OptionalPort is a port, an ICMP type or code, or the absence of one.
//
// Comparable, because rules are diffed by equality and used as map keys, which a
// pointer would break: two rules meaning the same thing must compare equal.
// [OptionalPort.Set] false always carries Value 0 so that absence has exactly one
// representation.
type OptionalPort struct {
	Set   bool
	Value int
}

// Port states a port, an ICMP type, or an ICMP code.
func Port(v int) OptionalPort { return OptionalPort{Set: true, Value: v} }

// NoPort is the absence of a stated port, which an all-protocol permission has.
func NoPort() OptionalPort { return OptionalPort{} }

func optionalPortFrom(v *int32) OptionalPort {
	if v == nil {
		return NoPort()
	}
	return Port(int(*v))
}

// singlePort builds a rule admitting exactly one port.
//
// It exists so that the single-port invariant is established by construction
// rather than by two fields a caller has to remember to set equal. A literal
// that set FromPort and forgot ToPort would compile and mean "every port from
// here down to 0" -- or, now, "no span stated at all" -- and both are failure
// modes worth making unreachable.
func singlePort(protocol string, port int, description string) SecurityGroupRule {
	return SecurityGroupRule{
		Protocol:    protocol,
		FromPort:    Port(port),
		ToPort:      Port(port),
		Description: Text(description),
	}
}

// EC2API is the network surface the relational port uses.
type EC2API interface {
	// DescribeSecurityGroupByName returns the group with this name in this VPC,
	// or [ErrNoSuchResource].
	DescribeSecurityGroupByName(ctx context.Context, name, vpc string) (*SecurityGroupRecord, error)
	// DescribeSecurityGroupByID returns the group with this identifier, or
	// [ErrNoSuchResource]. It is how a workload peer's group is resolved.
	DescribeSecurityGroupByID(ctx context.Context, id string) (*SecurityGroupRecord, error)
	// DescribeSecurityGroupsReferencing returns every security group in vpc
	// whose inbound rules name id as a source, or an empty slice if none do.
	//
	// It exists for the delete side of a workload peer rule: EC2 refuses to
	// delete a group that another group's rule still names
	// (DependencyViolation), so a caller about to delete id has to find that
	// rule from the referenced end -- by then it has only the ID, never the
	// referencing group's name. See [Provider.revokeReferencingIngress].
	DescribeSecurityGroupsReferencing(ctx context.Context, id, vpc string) ([]*SecurityGroupRecord, error)
	// CreateSecurityGroup creates one, or returns [ErrAlreadyExists].
	CreateSecurityGroup(ctx context.Context, in CreateSecurityGroupRequest) (*SecurityGroupRecord, error)
	// DeleteSecurityGroup removes a group. An absent group is
	// [ErrNoSuchResource]. A group another group's rule still references is
	// [ErrConflict], EC2's DependencyViolation.
	DeleteSecurityGroup(ctx context.Context, id string) error
	// AuthorizeIngress adds inbound rules. A rule that is already present is
	// [ErrAlreadyExists].
	AuthorizeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error
	// RevokeIngress removes inbound rules. A rule that is already absent is
	// [ErrNoSuchResource].
	//
	// The source system has no revoke at all, which is why an ingress rule it
	// authorised once outlives the spec that asked for it.
	RevokeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error
	// TagSecurityGroup adds or replaces tags.
	TagSecurityGroup(ctx context.Context, id string, tags map[string]string) error
	// UntagSecurityGroup removes tags by key.
	UntagSecurityGroup(ctx context.Context, id string, keys []string) error
}

// CreateSecurityGroupRequest is what it takes to create a security group.
type CreateSecurityGroupRequest struct {
	// Name is the group name.
	Name string
	// VPC is the VPC to create it in.
	VPC string
	// Description is EC2's required group description.
	Description string
	// Tags are the group's tags, including the ownership marker. They are set
	// at creation rather than afterwards so that a group is never briefly
	// unowned: a concurrent Ensure that read it in that window would refuse a
	// group this platform had just created.
	Tags map[string]string
}

// --- the ingress compiler ----------------------------------------------------

// ingressRules compiles a caller's declarative rule set into security-group
// rules.
//
// Every peer kind is resolved from configuration or refused. There is no branch
// that widens: the source system's equivalent, when it has no security group to
// name, opens the port to 0.0.0.0/0, and the whole reason
// [compute.PeerPlatformIngress] exists is that widening was accepted as a
// behaviour change to be reversed. Here the reversal is total — a rule this
// provider cannot satisfy is an error, and there is no code path that produces
// a [SecurityGroupRule] with a SourceCIDR at all.
func (p *Provider) ingressRules(
	ctx context.Context, rules []compute.IngressRule, pc PlacementConfig,
) ([]SecurityGroupRule, error) {
	out := make([]SecurityGroupRule, 0, len(rules))
	for i, r := range rules {
		if r.Port <= 0 || r.Port > 65535 {
			return nil, fmt.Errorf("%w: ingress rule %d names port %d", compute.ErrInvalidSpec, i, r.Port)
		}
		if err := checkRuleDescription(r.Description); err != nil {
			return nil, fmt.Errorf("%w: ingress rule %d: %w", compute.ErrInvalidSpec, i, err)
		}
		protocol := "tcp"
		switch r.Protocol {
		case "", compute.ProtocolTCP:
		case compute.ProtocolUDP:
			protocol = "udp"
		default:
			return nil, fmt.Errorf("%w: ingress rule %d names protocol %q; this interface defines "+
				"%q and %q", compute.ErrInvalidSpec, i, r.Protocol, compute.ProtocolTCP,
				compute.ProtocolUDP)
		}
		switch r.From.Kind {
		case compute.PeerControlPlane:
			if !r.From.Workload.IsZero() {
				return nil, fmt.Errorf("%w: ingress rule %d sets a workload reference on a %q peer",
					compute.ErrInvalidSpec, i, r.From.Kind)
			}
			if len(pc.ControlPlaneSecurityGroups) == 0 {
				// Fail closed, and this is the case the source system gets
				// wrong in the other direction: without this rule, deploy-time
				// role and extension provisioning connects from the control
				// plane and the packets are silently dropped, which it
				// documents having hit (database.go:200-205). The two ways to
				// not satisfy the rule are to leave the port shut — a SYN
				// timeout nothing traces back to a missing setting — and to
				// open it to everything. Refusing at the spec is neither.
				return nil, fmt.Errorf("%w: ingress rule %d names the control plane, and placement "+
					"%q is configured with no control-plane security groups; set "+
					"PlacementConfig.ControlPlaneSecurityGroups, because the alternatives are a "+
					"connection that times out with no diagnosis and a port open to everything",
					compute.ErrInvalidSpec, i, pc.Name)
			}
			for _, sg := range pc.ControlPlaneSecurityGroups {
				if strings.TrimSpace(sg) == "" {
					return nil, fmt.Errorf("%w: placement %q has an empty entry in "+
						"ControlPlaneSecurityGroups; the source system skips one silently "+
						"(database.go:207-210), which turns a typo into a rule that was never "+
						"written", compute.ErrInvalidSpec, pc.Name)
				}
				rule := singlePort(protocol, r.Port, ruleDescription(r, "apphub control plane"))
				rule.SourceGroup = sg
				out = append(out, rule)
			}
		case compute.PeerWorkload:
			switch {
			case r.From.Workload.IsZero():
				return nil, fmt.Errorf("%w: ingress rule %d names a workload peer with no "+
					"reference, so there is no workload for the rule to be about",
					compute.ErrInvalidSpec, i)
			case r.From.Workload.Provider != p.name:
				return nil, fmt.Errorf("%w: ingress rule %d names a workload issued by %q, and "+
					"this provider is %q", compute.ErrForeignRef, i, r.From.Workload.Provider, p.name)
			}
			// Resolved through the container port rather than by naming
			// convention, because the service's group is that port's resource
			// and the lookup re-checks it is still ours.
			id, err := p.WorkloadSecurityGroupID(ctx, r.From.Workload)
			if err != nil {
				return nil, fmt.Errorf("ingress rule %d: resolving the workload peer %s: %w",
					i, r.From.Workload, err)
			}
			rule := singlePort(protocol, r.Port, ruleDescription(r, "apphub workload"))
			rule.SourceGroup = id
			out = append(out, rule)
		case compute.PeerInternet:
			// A managed database reachable from the internet is the outcome
			// this whole provider is written to make impossible, so it is
			// refused at the spec rather than left to an operator's security
			// group review.
			return nil, fmt.Errorf("%w: ingress rule %d would make a database endpoint reachable "+
				"from the internet; this provider does not write such a rule, and an application "+
				"reaches its database as a workload peer", compute.ErrInvalidSpec, i)
		case compute.PeerPlatformIngress:
			return nil, fmt.Errorf("%w: ingress rule %d names the platform ingress proxy, which "+
				"fronts HTTP workloads and cannot carry a database wire protocol",
				compute.ErrInvalidSpec, i)
		default:
			return nil, fmt.Errorf("%w: ingress rule %d names peer kind %q; an unrecognised role "+
				"must not fall back to any particular one", compute.ErrInvalidSpec, i, r.From.Kind)
		}
	}
	return out, nil
}

// maxRuleDescription is EC2's limit on a rule description: fewer than 256
// characters.
const maxRuleDescription = 255

// ruleDescriptionPunctuation is the punctuation EC2 accepts in a rule
// description, alongside letters, digits and the space.
const ruleDescriptionPunctuation = "._-:/()#,@[]+=&;{}!$*"

// checkRuleDescription refuses a description EC2 would reject.
//
// EC2 answers such a description with InvalidParameterValue, which reaches the
// caller as a bare "could not parse this input" long after the rest of the
// deploy has run. Checking here names the character at fault before anything is
// written.
func checkRuleDescription(d string) error {
	if len(d) > maxRuleDescription {
		return fmt.Errorf("description is %d bytes and EC2 accepts at most %d",
			len(d), maxRuleDescription)
	}
	for _, c := range d {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ' ':
		case strings.ContainsRune(ruleDescriptionPunctuation, c):
		default:
			return fmt.Errorf("description %q contains %q; EC2 accepts letters, digits, spaces "+
				"and %s", d, c, ruleDescriptionPunctuation)
		}
	}
	return nil
}

// ruleDescription renders the operator-facing text on a rule.
//
// The caller's description is used when there is one, and a role-naming default
// otherwise. It is deliberately not an identifier: EC2 stores it, an operator
// reads it, and nothing in this package parses it back.
func ruleDescription(r compute.IngressRule, role string) string {
	if strings.TrimSpace(r.Description) != "" {
		return r.Description
	}
	return "apphub: " + role
}

// reconcileIngress converges a security group's inbound rules onto desired.
//
// It revokes as well as authorises, and the removal half is the point. The
// source system authorises ingress once and has no revoke on this path at all,
// so a rule it wrote outlives the spec that asked for it: "I removed that rule"
// silently means "I stopped asking for it", which is a security control failing
// open. [compute.IngressRule] is explicit that the set attached to a spec is the
// desired state.
//
// Everything on the group is eligible for removal, unlike a tag. The group is
// created by this provider for one database and carries the ownership marker, so
// a rule on it that this provider did not write is not an operator's metadata to
// preserve — it is an unexplained hole, and a rule with a SourceCIDR is the one
// shape this provider can never have produced.
func (p *Provider) reconcileIngress(ctx context.Context, group *SecurityGroupRecord, desired []SecurityGroupRule) error {
	want := make(map[SecurityGroupRule]struct{}, len(desired))
	for _, r := range desired {
		want[r] = struct{}{}
	}
	have := make(map[SecurityGroupRule]struct{}, len(group.Ingress))
	for _, r := range group.Ingress {
		have[r] = struct{}{}
	}

	var add, remove []SecurityGroupRule
	for r := range want {
		if _, ok := have[r]; !ok {
			add = append(add, r)
		}
	}
	for r := range have {
		if _, ok := want[r]; !ok {
			remove = append(remove, r)
		}
	}
	sortRules(add)
	sortRules(remove)

	// Revoke first. An Ensure that narrows a rule set and fails halfway should
	// fail with the narrower set in place rather than the wider one.
	//
	// An absent rule is tolerated, and the tolerance belongs here rather than in
	// the substrate. [EC2API.RevokeIngress] reports [ErrNoSuchResource] because
	// that is what EC2 does, and a substrate that swallowed it would hide a real
	// mistake — a provider revoking a rule it never wrote. But *this* caller
	// computed its removal set from a read that may be a moment stale, so a rule
	// somebody else removed in between is a race and not a failure, and failing
	// an Ensure for it means a concurrent teardown breaks a deploy. USOSS-11
	// reached the opposite default in its own compiler and raised it; this is
	// the reconciliation, and it is the shape that passes both suites *and*
	// survives the merge.
	//
	// The same reasoning applies to an already-present rule on the authorise
	// side: [ErrAlreadyExists] means somebody added the rule this call was about
	// to add, and the desired state is reached either way.
	if len(remove) > 0 {
		err := p.sub.EC2.RevokeIngress(ctx, group.ID, remove)
		if err != nil && !errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}
	if len(add) > 0 {
		err := p.sub.EC2.AuthorizeIngress(ctx, group.ID, add)
		if err != nil && !errors.Is(err, ErrAlreadyExists) {
			return p.substrateError(err)
		}
	}
	return nil
}

// sortRules puts a rule slice in a stable order, so that a substrate call and a
// rendered artefact do not depend on map iteration order.
func sortRules(rules []SecurityGroupRule) {
	sort.Slice(rules, func(i, j int) bool { return ruleKey(rules[i]) < ruleKey(rules[j]) })
}

// portSpan renders a rule's span for a sort key and for the rendered artefact.
//
// One number when the span is one port, "from-to" when it is a range, and "any"
// when the permission stated none -- which an all-protocol rule legitimately
// does. The three cases are distinguishable in the output because they are
// distinguishable in the rule.
func portSpan(r SecurityGroupRule) string {
	switch {
	case !r.FromPort.Set && !r.ToPort.Set:
		return "any"
	case r.FromPort == r.ToPort:
		return strconv.Itoa(r.FromPort.Value)
	default:
		return optionalPortString(r.FromPort) + "-" + optionalPortString(r.ToPort)
	}
}

// optionalStringKey distinguishes an absent description from an empty one in the
// sort key, so two rules that differ only in that do not collide.
func optionalStringKey(s OptionalString) string {
	if !s.Set {
		return "\x00absent"
	}
	return s.Value
}

func optionalPortString(p OptionalPort) string {
	if !p.Set {
		return "any"
	}
	return strconv.Itoa(p.Value)
}

func ruleKey(r SecurityGroupRule) string {
	return r.Protocol + "/" + portSpan(r) + "/" + r.SourceGroup + "/" + r.SourceGroupOwner +
		"/" + r.SourceCIDR + "/" + r.SourcePrefixList + "/" + optionalStringKey(r.Description)
}

// --- the in-memory EC2 -------------------------------------------------------

// MemoryEC2 is an in-memory network service.
//
// It models the parts of EC2 the relational port depends on and refuses what
// EC2 refuses: a duplicate group name in one VPC, a duplicate ingress rule, and
// a revoke of a rule that is not there. Those refusals are what make the
// convergence and idempotence invariants mean something — a mock that accepted
// everything would pass them without the provider being right.
type MemoryEC2 struct {
	failNext
	mu     sync.Mutex
	groups map[string]*SecurityGroupRecord
	next   int
}

var _ EC2API = (*MemoryEC2)(nil)

// NewMemoryEC2 returns an empty network service.
func NewMemoryEC2() *MemoryEC2 { return &MemoryEC2{groups: map[string]*SecurityGroupRecord{}} }

// MemoryVPC is the placeholder this substrate uses where a VPC identifier would
// go.
//
// A word rather than "vpc-" plus hex, for the same reason [MemoryAccount] is
// not a twelve-digit number: a fixture that imitates the real shape is a fixture
// somebody eventually fills in with the real value, and a scanner cannot tell
// the two apart.
const MemoryVPC = "apphub-test-vpc"

// groupID is how this substrate assigns a security group identifier. It is
// assigned by the substrate and read back by the provider, never composed.
func (m *MemoryEC2) groupID() string {
	m.next++
	return "apphub-test-sg-" + strconv.Itoa(m.next)
}

// PutUnowned puts a security group into the substrate without apphub's
// ownership tag, so an Ensure has a collision to refuse.
func (m *MemoryEC2) PutUnowned(name, vpc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.groupID()
	m.groups[id] = &SecurityGroupRecord{
		ID: id, Name: name, VPC: vpc,
		Tags: map[string]string{"created-by": "somebody-else"},
	}
}

// PutOwnedAs puts a security group into the substrate carrying apphub's
// ownership tag and a component of the caller's choosing.
//
// It is the decoy the ownership check's *second* half needs. CreateUnowned
// exercises "somebody else made this"; this exercises "apphub made this, as
// something else", which is the case the ownership tag alone cannot catch and the
// reason [checkOwned] requires the component tag to match too.
func (m *MemoryEC2) PutOwnedAs(name, vpc, component string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.groupID()
	m.groups[id] = &SecurityGroupRecord{
		ID: id, Name: name, VPC: vpc,
		Tags: map[string]string{tagManagedBy: managedByValue, tagComponent: component, tagName: name},
	}
}

// DescribeSecurityGroupByName implements [EC2API].
func (m *MemoryEC2) DescribeSecurityGroupByName(_ context.Context, name, vpc string) (*SecurityGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.groups {
		if g.Name == name && g.VPC == vpc {
			return copyGroup(g), nil
		}
	}
	return nil, fmt.Errorf("%w: security group %q in %q", ErrNoSuchResource, name, vpc)
}

// DescribeSecurityGroupByID implements [EC2API].
func (m *MemoryEC2) DescribeSecurityGroupByID(_ context.Context, id string) (*SecurityGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return nil, fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
	}
	return copyGroup(g), nil
}

// CreateSecurityGroup implements [EC2API].
func (m *MemoryEC2) CreateSecurityGroup(_ context.Context, in CreateSecurityGroupRequest) (*SecurityGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.groups {
		if g.Name == in.Name && g.VPC == in.VPC {
			return nil, fmt.Errorf("%w: security group %q in %q", ErrAlreadyExists, in.Name, in.VPC)
		}
	}
	id := m.groupID()
	g := &SecurityGroupRecord{ID: id, Name: in.Name, VPC: in.VPC, Tags: copyTags(in.Tags)}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	m.groups[id] = g
	return copyGroup(g), nil
}

// DeleteSecurityGroup implements [EC2API].
//
// Real EC2 refuses this with DependencyViolation while another group's rule
// still names id, not only while an ENI is attached to it -- the two are
// different dependents and this substrate models both, because a mock that
// accepted a delete no real account would have made passes the reconciliation
// and idempotence invariants without the provider being right. See
// [MemoryEC2.firstReferrer].
func (m *MemoryEC2) DeleteSecurityGroup(_ context.Context, id string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[id]; !ok {
		return fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
	}
	if referrer := m.firstReferrer(id); referrer != "" {
		return fmt.Errorf("%w: DependencyViolation: resource %s has a dependent object %s",
			ErrConflict, id, referrer)
	}
	delete(m.groups, id)
	return nil
}

// firstReferrer returns the name of a group other than id whose ingress rules
// still source from id, or "" once none do. Deterministic over sorted names,
// so a test asserting on the message is not at the mercy of map order.
func (m *MemoryEC2) firstReferrer(id string) string {
	for _, gid := range sortedMapKeys(m.groups) {
		if gid == id {
			continue
		}
		for _, r := range m.groups[gid].Ingress {
			if r.SourceGroup == id {
				return m.groups[gid].Name
			}
		}
	}
	return ""
}

// DescribeSecurityGroupsReferencing implements [EC2API].
func (m *MemoryEC2) DescribeSecurityGroupsReferencing(_ context.Context, id, vpc string) ([]*SecurityGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*SecurityGroupRecord
	for _, gid := range sortedMapKeys(m.groups) {
		if gid == id {
			continue
		}
		g := m.groups[gid]
		if g.VPC != vpc {
			continue
		}
		for _, r := range g.Ingress {
			if r.SourceGroup == id {
				out = append(out, copyGroup(g))
				break
			}
		}
	}
	return out, nil
}

// AuthorizeIngress implements [EC2API].
func (m *MemoryEC2) AuthorizeIngress(_ context.Context, id string, rules []SecurityGroupRule) error {
	return m.withGroup(id, func(g *SecurityGroupRecord) error {
		for _, r := range rules {
			for _, have := range g.Ingress {
				if have == r {
					// EC2's InvalidPermission.Duplicate, which the source
					// system reaches by matching a substring of the error text
					// (database.go:237). Here it is a sentinel, so the provider
					// branches on a value rather than on a message.
					return fmt.Errorf("%w: ingress %v on security group %q", ErrAlreadyExists, r, id)
				}
			}
			g.Ingress = append(g.Ingress, r)
		}
		sortRules(g.Ingress)
		return nil
	})
}

// RevokeIngress implements [EC2API].
func (m *MemoryEC2) RevokeIngress(_ context.Context, id string, rules []SecurityGroupRule) error {
	return m.withGroup(id, func(g *SecurityGroupRecord) error {
		for _, r := range rules {
			found := false
			for i, have := range g.Ingress {
				if have == r {
					g.Ingress = append(g.Ingress[:i], g.Ingress[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: ingress %v on security group %q", ErrNoSuchResource, r, id)
			}
		}
		return nil
	})
}

// TagSecurityGroup implements [EC2API].
func (m *MemoryEC2) TagSecurityGroup(_ context.Context, id string, tags map[string]string) error {
	return m.withGroup(id, func(g *SecurityGroupRecord) error {
		for k, v := range tags {
			g.Tags[k] = v
		}
		return nil
	})
}

// UntagSecurityGroup implements [EC2API].
func (m *MemoryEC2) UntagSecurityGroup(_ context.Context, id string, keys []string) error {
	return m.withGroup(id, func(g *SecurityGroupRecord) error {
		for _, k := range keys {
			delete(g.Tags, k)
		}
		return nil
	})
}

func (m *MemoryEC2) withGroup(id string, fn func(*SecurityGroupRecord) error) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
	}
	return fn(g)
}

// Groups returns a copy of every security group, for a test that needs to change
// one behind the provider's back.
//
// It exists for the concurrent-change assertions: the only way to show that
// reconciliation tolerates a rule somebody else removed is for somebody else to
// remove one, and "somebody else" has to be the substrate rather than the
// provider.
func (m *MemoryEC2) Groups() []*SecurityGroupRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*SecurityGroupRecord, 0, len(m.groups))
	for _, id := range sortedMapKeys(m.groups) {
		out = append(out, copyGroup(m.groups[id]))
	}
	return out
}

// Dump renders every security group, for the conformance suite's
// rendered-artefact invariants.
func (m *MemoryEC2) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		g := m.groups[id]
		fields := make([]string, 0, len(g.Ingress)+1)
		for _, r := range g.Ingress {
			source := r.SourceGroup
			switch {
			case source != "":
				if r.SourceGroupOwner != "" {
					source = r.SourceGroupOwner + "/" + source
				}
			case r.SourceCIDR != "":
				source = r.SourceCIDR
			default:
				source = r.SourcePrefixList
			}
			fields = append(fields, "ingress="+source+":"+portSpan(r)+"/"+r.Protocol)
		}
		if pairs := sortedPairs(g.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("SecurityGroup %s: %s", g.Name, strings.Join(fields, " ")))
	}
	return out
}

// copyGroup returns a record sharing no storage with the stored one, so a
// provider cannot mutate the substrate by editing what it read.
func copyGroup(in *SecurityGroupRecord) *SecurityGroupRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	out.Ingress = append([]SecurityGroupRule(nil), in.Ingress...)
	return &out
}
