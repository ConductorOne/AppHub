// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
)

// identityService implements [compute.IdentityService] with IAM roles.
//
// It is in this package rather than in the ECS one because
// [compute.IdentityService] is not capability-gated: every provider must be
// able to give what it runs an identity, so a provider that vends only an image
// registry and a builder still has to have one. It is the source system's
// ensureAppTaskRole (build.go:619-666), with three differences.
//
// **The role starts with no permission policies, and this one keeps it that
// way.** The source creates the role bare and then attaches ssmmessages and
// Bedrock statements from the deploy path (build.go:670-750). Those are a
// container-service capability and a workload capability respectively, and they
// belong to the ports that own them (USOSS-11, and [compute.CapModelInference]).
// A role this package creates carries a trust policy and tags and nothing else.
//
// **The ownership marker is read before the role is written.** The source
// adopts whatever role it finds under the name it wanted. Role names derive
// from mutable application names, so that is a real collision, and adopting an
// operator's role means writing policies onto it.
//
// **RunsOn decides the trust policy, and a changed RunsOn converges.** An AWS
// role trusted by ecs-tasks.amazonaws.com cannot be assumed by Lambda, which is
// exactly why [compute.WorkloadIdentitySpec.RunsOn] exists — this is the
// substrate the field was written for.
type identityService struct{ p *Provider }

var _ compute.IdentityService = (*identityService)(nil)

// The service principals a workload identity can be trusted by.
//
// A closed set, because an open one would let a caller name any AWS service in
// a trust policy this package writes.
const (
	principalECSTasks = "ecs-tasks.amazonaws.com"
	principalLambda   = "lambda.amazonaws.com"
)

// trustPolicyFor renders the trust policy for a runtime.
//
// It is the source system's document (build.go:640-647) with the runtime made a
// parameter instead of a constant. An unrecognised runtime is
// [compute.ErrInvalidSpec] rather than a default: defaulting would silently
// give a function identity an ECS trust policy, and the failure would arrive at
// invocation time as an assume-role error nobody can trace back to here.
// trustStatement is one statement of a trust policy. It is a separate type from
// [statement] on purpose: a trust policy must name a Principal and a session
// policy must not, and two documents sharing one shape is how a principal ends
// up in the one that must not have it.
type trustStatement struct {
	Effect    string            `json:"Effect"`
	Principal map[string]string `json:"Principal"`
	Action    []string          `json:"Action"`
}

type trustPolicy struct {
	Version   string           `json:"Version"`
	Statement []trustStatement `json:"Statement"`
}

func trustPolicyFor(runsOn compute.RuntimeKind) (string, error) {
	var principal string
	switch runsOn {
	case compute.RuntimeContainer, "":
		// Empty means "the caller did not say", and a container is what the
		// source system's only identity is for. The effective spec records the
		// resolved value, so a read-back does not repeat the caller's silence.
		principal = principalECSTasks
	case compute.RuntimeFunction:
		principal = principalLambda
	default:
		return "", fmt.Errorf("%w: RunsOn %q is not a runtime this interface defines",
			compute.ErrInvalidSpec, runsOn)
	}
	raw, err := json.Marshal(trustPolicy{
		Version: "2012-10-17",
		Statement: []trustStatement{{
			Effect:    "Allow",
			Principal: map[string]string{"Service": principal},
			Action:    []string{"sts:AssumeRole"},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the trust policy: %w", compute.ErrFailed, err)
	}
	return string(raw), nil
}

// ownedRole is proof that a role exists and that this platform owns it.
//
// Same construction as [ownedRepository], for the same reason and after the same
// finding: the ownership check guarded EnsureWorkloadIdentity and
// DeleteWorkloadIdentity walked past it, destroying an unowned role that had
// taken over a formerly-valid Ref's name. Ownership is established at use.
type ownedRole struct{ rec RoleRecord }

// owned resolves a caller's [compute.Ref] to a role this platform may act on.
func (s *identityService) owned(ctx context.Context, ref compute.Ref) (*ownedRole, error) {
	name, err := s.p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return nil, err
	}
	got, found, err := s.ownedByName(ctx, name)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, fmt.Errorf("%w: IAM role %q", compute.ErrNotFound, name)
	}
	return got, nil
}

// ownedByName resolves a physical name, reporting absence rather than erroring
// on it.
func (s *identityService) ownedByName(ctx context.Context, name string) (*ownedRole, bool, error) {
	role, err := s.p.sub.IAM.GetRole(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, s.p.substrateError(err)
	}
	// Both tags, not just the ownership one. An IAM role is account-global and
	// every AWS port in this package creates roles, so a role apphub owns as
	// something else is exactly what must not be adopted here.
	if err := checkOwned(role.Tags, "IAM role", componentIdentity, name); err != nil {
		return nil, false, err
	}
	return &ownedRole{rec: *role}, true, nil
}

// EnsureWorkloadIdentity creates or converges the role for spec.
func (s *identityService) EnsureWorkloadIdentity(ctx context.Context, spec compute.WorkloadIdentitySpec) (*compute.WorkloadIdentity, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	trust, err := trustPolicyFor(spec.RunsOn)
	if err != nil {
		return nil, err
	}
	// An IAM role is account-global, so this provider does not place it
	// anywhere — which is exactly the case [compute.WorkloadIdentitySpec.Placement]
	// predicts. The placement is still resolved, because an unconfigured one is
	// a caller mistake worth reporting whether or not this substrate would have
	// used it, and because the effective spec has to echo the resolved name.
	pc, err := s.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	name, err := s.p.roleName(spec.Name)
	if err != nil {
		return nil, err
	}

	effective := spec
	effective.Placement = compute.Placement{Name: pc.Name}
	if effective.RunsOn == "" {
		effective.RunsOn = compute.RuntimeContainer
	}
	desired := ownershipTags(name, componentIdentity, spec.Labels)

	owned, found, err := s.ownedByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !found {
		role, err := s.p.sub.IAM.CreateRole(ctx, CreateRoleRequest{
			Name:                name,
			Path:                s.p.cfg.Identity.PathPrefix,
			AssumeRolePolicy:    trust,
			PermissionsBoundary: s.p.cfg.Identity.PermissionsBoundary,
			Tags:                desired,
		})
		if err != nil {
			return nil, s.p.substrateError(err)
		}
		owned = &ownedRole{rec: *role}
		return s.identity(&owned.rec, effective), nil
	}

	// The whole trust policy is compared, not the runtime it happens to
	// mention.
	//
	// The previous version reduced the existing document to one RuntimeKind and
	// updated only if that differed. So a role could carry any amount of extra
	// trust — a wildcard AWS principal, a second service, a federated
	// principal, an extra action — and Ensure would find the expected principal,
	// conclude nothing had changed, and report success. A wildcard trust
	// principal is "anyone in this partition may assume this", so converging the
	// set is the security property rather than tidiness.
	//
	// Unlike tags, this converges the *whole* document, and the difference is
	// ownership rather than data type. Every statement in a trust policy this
	// provider writes is one it authored; a principal nobody asked for is a
	// finding, not an operator's deliberate configuration the way a CostCenter
	// tag is. See convergeTags for the other half of the rule.
	//
	// The comparison is semantic. IAM normalises a policy — reordering keys,
	// changing whitespace, collapsing a one-element Action array to a string,
	// and returning the whole thing URL-encoded — so a byte comparison would be
	// false on every call after the first and would rewrite the policy on every
	// reconcile of an unchanged spec.
	same, err := samePolicyDocument(owned.rec.AssumeRolePolicy, trust)
	if err != nil {
		return nil, fmt.Errorf("%w: the trust policy on IAM role %q cannot be read, so this "+
			"provider will not decide whether it matches: %w", compute.ErrFailed, name, err)
	}
	if !same {
		if err := s.p.sub.IAM.UpdateAssumeRolePolicy(ctx, name, trust); err != nil {
			return nil, s.p.substrateError(err)
		}
		owned.rec.AssumeRolePolicy = trust
	}
	put, remove := tagDelta(owned.rec.Tags, desired)
	if len(remove) > 0 {
		if err := s.p.sub.IAM.UntagRole(ctx, name, remove); err != nil {
			return nil, s.p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := s.p.sub.IAM.TagRole(ctx, name, put); err != nil {
			return nil, s.p.substrateError(err)
		}
	}
	return s.identity(&owned.rec, effective), nil
}

// samePolicyDocument reports whether two IAM policy documents mean the same
// thing.
//
// It canonicalises rather than comparing fields, so a statement carrying a
// Condition, a NotAction, or anything else this package does not model is still
// *seen*: an unmodelled difference has to show up as a difference, or the
// convergence check has a blind spot exactly where an attacker would put
// something. Three normalisations are applied, and they are the three ways IAM
// legitimately rewrites a document:
//
//   - a scalar where a list is allowed becomes a one-element list, so
//     Action:"sts:AssumeRole" and Action:["sts:AssumeRole"] compare equal;
//   - lists of strings are sorted, since their order carries no meaning;
//   - object keys are sorted, which encoding/json does for a map already.
func samePolicyDocument(a, b string) (bool, error) {
	ca, err := canonicalPolicy(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalPolicy(b)
	if err != nil {
		return false, err
	}
	return ca == cb, nil
}

func canonicalPolicy(doc string) (string, error) {
	if strings.TrimSpace(doc) == "" {
		return "", nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return "", err
	}
	out, err := json.Marshal(canonicalValue(parsed))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// canonicalValue rewrites a decoded policy into a comparable shape.
//
// Every value is visited, including ones this package has no model for, because
// the point is to detect a difference rather than to understand it.
func canonicalValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			// The fields where AWS accepts a scalar or a list interchangeably.
			// Everything else keeps its shape, so a scalar that became an
			// object is still a difference.
			if scalarOrList[k] {
				out[k] = canonicalStringList(val)
				continue
			}
			out[k] = canonicalValue(val)
		}
		return out
	case []any:
		items := make([]any, 0, len(t))
		for _, item := range t {
			items = append(items, canonicalValue(item))
		}
		// Rendered and sorted, so two documents differing only in statement
		// order compare equal. json.Marshal cannot fail on a decoded document.
		rendered := make([]string, 0, len(items))
		for _, item := range items {
			b, err := json.Marshal(item)
			if err != nil {
				return items
			}
			rendered = append(rendered, string(b))
		}
		sort.Strings(rendered)
		return rendered
	default:
		return v
	}
}

// scalarOrList names the policy fields AWS accepts either way. Principal is not
// in it: a Principal is an object whose *values* are scalar-or-list, and
// canonicalValue reaches those by recursion.
var scalarOrList = map[string]bool{
	"Action":        true,
	"NotAction":     true,
	"Resource":      true,
	"NotResource":   true,
	"AWS":           true,
	"Service":       true,
	"Federated":     true,
	"CanonicalUser": true,
}

// canonicalStringList normalises a scalar-or-list field to a sorted list.
func canonicalStringList(v any) any {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				// Not the shape this normalisation is for; leave it alone
				// rather than lose the difference.
				return canonicalValue(v)
			}
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	default:
		return canonicalValue(v)
	}
}

// DescribeWorkloadIdentity reads a role back through the interface.
func (s *identityService) DescribeWorkloadIdentity(ctx context.Context, ref compute.Ref) (*compute.WorkloadIdentity, error) {
	owned, err := s.owned(ctx, ref)
	if err != nil {
		return nil, err
	}
	// The effective spec is recovered from the role itself: its tags for the
	// labels, its trust policy for the runtime. Nothing is remembered in
	// process, so a read-back reports what IAM has rather than what the last
	// Ensure believed it wrote.
	spec := compute.WorkloadIdentitySpec{
		Name:      owned.rec.Tags[tagName],
		Placement: compute.Placement{Name: s.p.cfg.DefaultPlacement},
		RunsOn:    runtimeFromTrustPolicy(owned.rec.AssumeRolePolicy),
		Labels:    labelsFromTags(owned.rec.Tags),
	}
	if spec.Name == "" {
		spec.Name = owned.rec.Name
	}
	return s.identity(&owned.rec, spec), nil
}

// runtimeFromTrustPolicy reads the runtime back out of a trust policy.
//
// A policy naming neither principal yields the empty runtime, which a caller
// reads as "this provider cannot tell" rather than as a wrong answer.
func runtimeFromTrustPolicy(doc string) compute.RuntimeKind {
	var parsed struct {
		Statement []struct {
			Principal map[string]json.RawMessage `json:"Principal"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return ""
	}
	for _, st := range parsed.Statement {
		raw, ok := st.Principal["Service"]
		if !ok {
			continue
		}
		var service string
		if err := json.Unmarshal(raw, &service); err != nil {
			continue
		}
		switch service {
		case principalECSTasks:
			return compute.RuntimeContainer
		case principalLambda:
			return compute.RuntimeFunction
		}
	}
	return ""
}

// DeleteWorkloadIdentity removes a role.
//
// [compute.IdentityService] asks a provider to remove the grants made to an
// identity through its own [compute.Granter] ports as well, and this package
// vends none — the image registry has no Granter, for the reasons set out on
// [imageRegistry]. On AWS a grant is an inline policy on the role, and it does
// NOT vanish with it: IAM refuses DeleteRole with DeleteConflictException while
// any inline policy remains attached, so this removes every one of them first.
// A role this package creates carries no managed policy attachments (see the
// type doc), so there is nothing to detach. What does not vanish either way is a
// policy attached by another port, which is why the ports that attach them
// (USOSS-11 onward) own their own detach.
func (s *identityService) DeleteWorkloadIdentity(ctx context.Context, ref compute.Ref) error {
	name, err := s.p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	owned, found, err := s.ownedByName(ctx, name)
	switch {
	case err != nil:
		return err
	case !found:
		return nil
	}
	if err := s.deleteInlinePolicies(ctx, owned.rec.Name); err != nil {
		return err
	}
	err = s.p.sub.IAM.DeleteRole(ctx, owned.rec.Name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	return s.p.substrateError(err)
}

// deleteInlinePolicies removes every inline policy on roleName, so the
// DeleteRole that follows does not refuse it with DeleteConflictException.
//
// This does not use [Provider.reconcileRolePolicies]: that function's pruning
// deliberately spares a workload identity's data grants (the key-value and
// object-store ports write theirs on this same role), because an ordinary
// reconcile must not revoke a grant it does not own. Here the role itself is
// being destroyed, so every inline policy on it — data grants included — goes,
// which is why this is a separate, unfiltered walk rather than a call with a
// wider desired set.
func (s *identityService) deleteInlinePolicies(ctx context.Context, roleName string) error {
	names, err := s.p.sub.IAM.ListRolePolicyNames(ctx, roleName)
	if err != nil {
		return s.p.substrateError(err)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := s.p.sub.IAM.DeleteRolePolicy(ctx, roleName, name); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return s.p.substrateError(err)
		}
	}
	return nil
}

// identity builds the value the interface returns.
//
// The attestation's subject is the role ARN IAM reported, because that is what
// the verifier resolves a presigned sts:GetCallerIdentity to
// (auth/sts_verify.go:21-52). It is read back rather than composed: composing
// it would mean this package holding an account identifier, and the whole point
// of the configuration rules here is that it does not.
func (s *identityService) identity(role *RoleRecord, spec compute.WorkloadIdentitySpec) *compute.WorkloadIdentity {
	spec.Labels = copyTags(spec.Labels)
	id := &compute.WorkloadIdentity{
		Ref:  s.p.ref(compute.KindWorkloadIdentity, role.Name),
		Spec: spec,
	}
	if role.ARN != "" {
		id.Attestation = workload.ExpectedAttestation{
			Method:  workload.MethodAWSSTSCallerIdentity,
			Subject: role.ARN,
		}
	}
	return id
}
