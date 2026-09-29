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
)

// This file holds the two IAM surfaces the container port owns: the task
// execution role, which is the agent's identity while it starts a task, and the
// reconciliation of workload capabilities onto the workload's own role.
//
// The workload identity itself is not here. It belongs to
// [identityService] (USOSS-10), and a role that service creates carries a trust
// policy and tags and nothing else. What this port adds are the grants
// [compute.ServiceSpec.Capabilities] and [compute.ServiceSpec.ExecEnabled] ask
// for — and it adds and REMOVES them, because both fields are declarative.

// The inline policy names this provider owns on a role.
//
// Every one carries the same prefix, and the prefix is what makes the removal
// half of reconciliation safe: the set of policies this provider may delete is
// exactly the set carrying it, so an operator's own inline policy on the same
// role survives every Ensure. Same argument as [tagLabelPrefix] for tags.
const (
	policyPrefix = "apphub-"

	policyExec        = policyPrefix + "ecs-exec"
	policySecretRead  = policyPrefix + "secret-read"
	policyLogWrite    = policyPrefix + "log-write"
	policyImagePull   = policyPrefix + "image-pull"
	policyCapPrefix   = policyPrefix + "cap-"
	maxExecutionRole  = maxIAMRoleName
	execRoleNameInfix = "exec-"
)

// capabilityPolicyName is the inline policy name for one workload capability.
//
// Derived from the capability rather than mapped by hand, so a capability added
// to the interface cannot silently acquire no name — and, more importantly, so
// the removal half cannot fall out of step with the addition half.
func capabilityPolicyName(c compute.WorkloadCapability) string {
	return policyCapPrefix + string(c)
}

// executionRoleName renders the per-service execution role name.
//
// It is derived from the PHYSICAL service name rather than the logical one, and
// carries no second copy of [ContainerConfig.NamePrefix] — the service name
// already has it. That matters for teardown: a [compute.Ref] carries the
// physical name and not the logical one, so a role name derived from the
// logical name would be unreachable from a Ref and the role would survive every
// delete.
func (p *Provider) executionRoleName(serviceName string) (string, error) {
	name, err := sanitize(execRoleNameInfix, serviceName, maxExecutionRole)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Container.NamePrefix)", err)
	}
	if !iamRoleName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal IAM role name; check "+
			"Config.Container.NamePrefix", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// ensureExecutionRole creates or converges the ECS task execution role for one
// service, and returns the ARN the substrate reported for it.
//
// # Why this is per-service, which is the substantive change from the source
//
// The source system uses one shared execution role for every application
// (container.go:742 reads clusterConfig.TaskExecutionRoleARN), and Terraform
// grants that one role ssm:GetParameter and ssm:GetParameters on
// `…:parameter{ssm_prefix}/apps/*` (terraform/modules/ecs/iam.tf:30-49, the
// statement is even labelled ReadAppSecrets). Every deployed application's
// agent can therefore read every other application's secrets.
//
// The wildcard is not an independent mistake, which is why narrowing it is not
// the fix: with one role shared by every service, a grant scoped to one
// service's parameters would break every other service, so the wildcard is the
// only thing that *works* under that design. Per-service roles are what make
// least privilege expressible at all. Once each service has its own role, the
// grant is the exact parameter ARNs that service binds — and it comes from the
// secret store, which is the only component that knows what reading one of its
// parameters requires.
//
// The cost is honest and worth stating: one IAM role per service consumes an
// account-level quota, and an operator with thousands of services will feel it.
// A shared role that can read every tenant's secrets is not an acceptable way
// to save quota.
func (p *Provider) ensureExecutionRole(
	ctx context.Context,
	serviceName string,
	pc PlacementConfig,
	image compute.ImageRef,
	secretRefs []SecretParameterRef,
	labels map[string]string,
) (string, error) {
	roleName, err := p.executionRoleName(serviceName)
	if err != nil {
		return "", err
	}
	// The agent that starts the task is an ECS task principal, the same
	// principal the workload's own role trusts. They are different roles with
	// different contents, not different trust.
	trust, err := trustPolicyFor(compute.RuntimeContainer)
	if err != nil {
		return "", err
	}
	tags := ownershipTags(roleName, componentExecutionRole, labels)

	// Everything the agent may do, rebuilt from this spec each time and
	// reconciled in both directions.
	//
	// Composed BEFORE the ownership decision below, not after, and the ordering
	// is the point. [Provider.imagePullPolicy] reads the registry, so composing
	// these after the check would put a foreign round trip between "this role is
	// ours" and the first write to it — and a role whose ownership marker was
	// removed in that interval would still be written, with this service's
	// secret-read grant attached to a principal somebody else now controls.
	// USOSS-10 hit the same class on its lifecycle write ("a decision that was
	// valid several round trips ago is not a licence to write now"); this is that
	// lesson applied here.
	//
	// The window narrows to zero foreign calls rather than closing: IAM has no
	// conditional write, so the check and the write cannot be made one operation.
	// Stated rather than overclaimed.
	desired := map[string]string{}
	if len(secretRefs) > 0 {
		resolver := p.secretResolver()
		if resolver == nil {
			// Unreachable from EnsureService, which refuses a spec with bindings
			// and no resolver before it gets here. Stated rather than assumed:
			// this function is the one that ATTACHES the grant, and a nil
			// dereference at the attach point would be a panic in the middle of
			// a write sequence.
			return "", fmt.Errorf("%w: %d resolved secret reference(s) with no secret resolver "+
				"configured", compute.ErrFailed, len(secretRefs))
		}
		doc, err := resolver.SecretReadPolicy(secretRefs)
		if err != nil {
			return "", err
		}
		if err := assertNoWildcardResource(doc, policySecretRead); err != nil {
			return "", err
		}
		desired[policySecretRead] = doc
	}
	if doc := p.logWritePolicy(serviceName, pc); doc != "" {
		desired[policyLogWrite] = doc
	}
	if doc, err := p.imagePullPolicy(ctx, image); err != nil {
		return "", err
	} else if doc != "" {
		desired[policyImagePull] = doc
	}

	rec, err := p.sub.IAM.GetRole(ctx, roleName)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		path := p.executionRolePath()
		rec, err = p.sub.IAM.CreateRole(ctx, CreateRoleRequest{
			Name:                roleName,
			Path:                path,
			AssumeRolePolicy:    trust,
			PermissionsBoundary: p.executionRoleBoundary(),
			Tags:                tags,
		})
		if err != nil {
			return "", p.substrateError(err)
		}
	case err != nil:
		return "", p.substrateError(err)
	default:
		// An existing role must be one of ours, and one of ours *of this
		// component*. An IAM role is account-global and several ports here
		// create roles, so adopting by owner alone would let a role created as
		// something else be repurposed as an execution role — which would
		// attach this service's secret-read grant to a principal with a
		// different trust relationship.
		if rec.Tags[tagManagedBy] != managedByValue || rec.Tags[tagComponent] != componentExecutionRole {
			return "", fmt.Errorf("%w: the IAM role %q is not an execution role this provider owns",
				compute.ErrNotOwned, roleName)
		}
		if err := p.convergeRoleTags(ctx, roleName, rec.Tags, tags); err != nil {
			return "", err
		}
	}

	if err := p.reconcileRolePolicies(ctx, roleName, componentExecutionRole, desired); err != nil {
		return "", err
	}
	return rec.ARN, nil
}

func (p *Provider) executionRolePath() string {
	if p.cfg.Container != nil && p.cfg.Container.ExecutionRolePathPrefix != "" {
		return p.cfg.Container.ExecutionRolePathPrefix
	}
	return p.cfg.Identity.PathPrefix
}

func (p *Provider) executionRoleBoundary() string {
	if p.cfg.Container != nil && p.cfg.Container.ExecutionRolePermissionsBoundary != "" {
		return p.cfg.Container.ExecutionRolePermissionsBoundary
	}
	return p.cfg.Identity.PermissionsBoundary
}

// assertNoWildcardResource refuses a policy document whose scoped resources
// contain a wildcard.
//
// The secret-read document comes from another component, and this is the one
// property this port must not take on trust: it is the difference between "this
// service may read its own secrets" and the cross-tenant grant the source
// system ships. Checking it here rather than trusting the producer is cheap,
// and the failure it catches is one a reviewer of either side alone would not
// see.
func assertNoWildcardResource(doc, name string) error {
	var parsed struct {
		Statement []struct {
			Action   any `json:"Action"`
			Resource any `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return fmt.Errorf("%w: the %s policy is not a policy document: %w",
			compute.ErrFailed, name, err)
	}
	if len(parsed.Statement) == 0 {
		return fmt.Errorf("%w: the %s policy has no statements, so it grants nothing; a document "+
			"that grants nothing is a configuration error rather than a safe default",
			compute.ErrFailed, name)
	}
	for _, st := range parsed.Statement {
		for _, r := range asStrings(st.Resource) {
			if r == "*" || strings.Contains(r, "*") {
				return fmt.Errorf("%w: the %s policy names the resource %q. A wildcard here is the "+
					"cross-tenant grant this provider exists to avoid; refusing rather than "+
					"attaching it", compute.ErrFailed, name, r)
			}
		}
	}
	return nil
}

func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// logWritePolicy grants the agent the right to write this service's logs, and
// only this service's.
//
// Empty when no log group prefix is configured, because this provider will not
// choose a destination for somebody's application logs. The source system
// relies on a broader grant added to the shared execution role
// (terraform/modules/ecs/iam.tf:59-70, which exists because the AWS-managed
// policy grants CreateLogStream but not CreateLogGroup).
func (p *Provider) logWritePolicy(serviceName string, pc PlacementConfig) string {
	if p.cfg.Container == nil || p.cfg.Container.LogGroupPrefix == "" {
		return ""
	}
	group := strings.TrimSuffix(p.cfg.Container.LogGroupPrefix, "/") + "/" + serviceName
	// A log-group ARN is composed rather than read back, and it is the one
	// place in this package that composes one. The reason it is acceptable is
	// that it contains no account identifier and no deployment identifier: the
	// region comes from the placement and the group name from operator
	// configuration, and CloudWatch has no describe call that would report an
	// ARN for a group that does not exist yet — which is exactly the case here,
	// since the agent creates it. Stated rather than assumed, because the
	// read-it-back rule is otherwise absolute in this package.
	//
	// CreateLogGroup is authorized on the log group itself. CreateLogStream and
	// PutLogEvents are authorized on the streams under it. A single resource of
	// "...:log-group:<name>:*" matches streams and does not match the group, so
	// the agent is denied CreateLogGroup and the group is never created.
	groupARN := fmt.Sprintf("arn:%s:logs:%s:*:log-group:%s",
		partitionForRegion(pc.Region), pc.Region, group)
	doc, err := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []statement{
			{
				Sid:      "CreateThisServicesLogGroup",
				Effect:   "Allow",
				Action:   []string{"logs:CreateLogGroup"},
				Resource: []string{groupARN},
			},
			{
				Sid:      "WriteThisServicesLogs",
				Effect:   "Allow",
				Action:   []string{"logs:CreateLogStream", "logs:PutLogEvents"},
				Resource: []string{groupARN + ":*"},
			},
		},
	})
	if err != nil {
		// policyDocument is a fixed shape of strings; a marshal failure is not
		// reachable. Returning empty rather than panicking means the worst case
		// is a service whose agent cannot write logs, which fails visibly.
		return ""
	}
	return string(doc)
}

// imagePullPolicy grants the agent pull access to exactly the repository the
// service's image lives in, when that repository is one this provider issued.
//
// This is deliberately narrower than the source system's arrangement, which
// attaches the AWS-managed AmazonECSTaskExecutionRolePolicy
// (terraform/modules/ecs/iam.tf:25-28) — that policy allows BatchGetImage and
// GetDownloadUrlForLayer on every repository in the account.
//
// An image this provider's registry did not issue gets no policy rather than a
// wildcard one. That is the fail-closed direction and it has a visible failure
// mode: a private image from elsewhere will not pull, and the operator has to
// say so in their own boundary or bring the image into the registry. A public
// base image needs no grant at all.
func (p *Provider) imagePullPolicy(ctx context.Context, image compute.ImageRef) (string, error) {
	if p.sub.ECR == nil {
		return "", nil
	}
	repo, _, err := splitImageRef(string(image))
	if err != nil {
		// Not a registry-qualified reference this provider recognises — a bare
		// public image, say. No grant, and not an error: refusing the deploy
		// would make a public base image unusable.
		return "", nil //nolint:nilerr // an unrecognised reference means "no grant", deliberately.
	}
	rec, err := p.sub.ECR.DescribeRepository(ctx, repo)
	if errors.Is(err, ErrNoSuchResource) {
		return "", nil
	}
	if err != nil {
		return "", p.substrateError(err)
	}
	// The reference has to reconstruct from the URI the registry reported,
	// exactly as the builder's destination check does. Without it,
	// "somewhere-else.invalid/app:v1" would find the repository "app" in the
	// configured registry and be granted pull on it.
	if !strings.HasPrefix(string(image), rec.URI) {
		return "", nil
	}
	doc, err := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []statement{
			{
				// ECR requires this one at registry level; the token it vends is
				// itself bounded by the intersection with the scoped statement
				// below, so the unscoped action widens nothing.
				Sid:      "RegistryAuth",
				Effect:   "Allow",
				Action:   []string{"ecr:GetAuthorizationToken"},
				Resource: "*",
			},
			{
				Sid:    "PullThisImageOnly",
				Effect: "Allow",
				Action: []string{
					"ecr:BatchCheckLayerAvailability",
					"ecr:BatchGetImage",
					"ecr:GetDownloadUrlForLayer",
				},
				Resource: []string{rec.ARN},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the image-pull policy: %w", compute.ErrFailed, err)
	}
	return string(doc), nil
}

// reconcileRolePolicies makes the inline policies this provider owns on a role
// equal to desired, and removes the ones it owns that are not wanted.
//
// The set to consider removing is read from the role rather than restated here.
// A hand-maintained list of "policies we know how to add" would leave a revoked
// grant attached the moment the two fell out of step, and a revoked grant that
// is still attached is a security control that reports success and does
// nothing.
//
// # Ownership is proved HERE, not by whoever called
//
// This function writes IAM grants, so it re-reads the role's ownership itself
// rather than trusting a decision its caller made earlier. Its callers do check
// — and that is exactly the arrangement USOSS-10's fifth review round rejected
// on its own port, in the sentence worth copying: *moving a check leaves it
// wherever the next write is not.* An earlier revision of this port ordered the
// caller's check next to this call, which said nothing about the next write
// somebody adds above it.
//
// So the proof is part of the write. A caller that forgets has nothing to call,
// and the component is a parameter because the same function reconciles grants
// on two different kinds of role — the execution role this port owns, and the
// workload identity the identity service owns — and adopting one as the other is
// the collision the component tag exists to stop.
//
// The window is one round trip and is not zero: IAM has no conditional write, so
// a marker removed between this read and the first Put is not caught. Stated
// rather than implied.
func (p *Provider) reconcileRolePolicies(ctx context.Context, roleName, component string, desired map[string]string) error {
	rec, err := p.sub.IAM.GetRole(ctx, roleName)
	if err != nil {
		return p.substrateError(err)
	}
	if err := checkOwned(rec.Tags, "IAM role", component, roleName); err != nil {
		return err
	}
	current, err := p.sub.IAM.ListRolePolicyNames(ctx, roleName)
	if err != nil {
		return p.substrateError(err)
	}
	// Sorted so that two runs against the same state make the same calls in the
	// same order, which is what makes a recorded run comparable.
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := p.sub.IAM.PutRolePolicy(ctx, roleName, name, desired[name]); err != nil {
			return p.substrateError(err)
		}
	}
	stale := make([]string, 0, len(current))
	for _, name := range current {
		if _, wanted := desired[name]; wanted {
			continue
		}
		if p.reconciledPolicy(component, name) {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		if err := p.sub.IAM.DeleteRolePolicy(ctx, roleName, name); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return p.substrateError(err)
		}
	}
	return nil
}

// reconciledPolicy reports whether name is an inline policy that
// [Provider.reconcileRolePolicies] manages on a role of this component, and so
// may remove when it is not desired.
//
// Every "apphub-" policy is in scope except, on a workload identity, the data
// grants. That role is shared: the key-value and object-store ports write their
// grants on it under the same prefix, and neither is this reconcile's to revoke.
// Pruning by prefix alone deleted every data grant the moment the service was
// ensured, leaving the application unable to reach its own table or bucket.
func (p *Provider) reconciledPolicy(component, name string) bool {
	if !strings.HasPrefix(name, policyPrefix) {
		return false
	}
	return component != componentIdentity || !p.isDataGrantPolicy(name)
}

// isDataGrantPolicy reports whether name is the policy a key-value or
// object-store Grant writes.
func (p *Provider) isDataGrantPolicy(name string) bool {
	keyValuePrefix := DefaultGrantPolicyName
	if p.cfg.KeyValue != nil {
		keyValuePrefix = p.cfg.KeyValue.grantPolicyPrefix()
	}
	if strings.HasPrefix(name, keyValuePrefix+"-") {
		return true
	}
	for _, flavour := range []string{flavourBucket, flavourTableBucket, flavourVectorBucket} {
		if strings.HasPrefix(name, policyPrefix+flavour+"-") {
			return true
		}
	}
	return false
}

// convergeRoleTags makes a role's tags equal the desired set, removing only
// keys this provider owns.
func (p *Provider) convergeRoleTags(ctx context.Context, roleName string, current, desired map[string]string) error {
	put, remove := tagDelta(current, desired)
	if len(put) > 0 {
		if err := p.sub.IAM.TagRole(ctx, roleName, put); err != nil {
			return p.substrateError(err)
		}
	}
	if len(remove) > 0 {
		if err := p.sub.IAM.UntagRole(ctx, roleName, remove); err != nil {
			return p.substrateError(err)
		}
	}
	return nil
}

// deleteExecutionRole removes the execution role for a service, and its
// policies first because IAM refuses to delete a role that still has any.
//
// Idempotent: an absent role is not an error, so a teardown can be re-run.
func (p *Provider) deleteExecutionRole(ctx context.Context, serviceName string) error {
	roleName, err := p.executionRoleName(serviceName)
	if err != nil {
		return err
	}
	rec, err := p.sub.IAM.GetRole(ctx, roleName)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	if err != nil {
		return p.substrateError(err)
	}
	// Only delete a role this provider created as an execution role. A role
	// under the same name that is not ours is left alone and reported, rather
	// than deleted on the way past.
	if rec.Tags[tagManagedBy] != managedByValue || rec.Tags[tagComponent] != componentExecutionRole {
		return fmt.Errorf("%w: the IAM role %q is not an execution role this provider owns, so "+
			"teardown will not delete it", compute.ErrNotOwned, roleName)
	}
	if err := p.reconcileRolePolicies(ctx, roleName, componentExecutionRole, nil); err != nil {
		return err
	}
	if err := p.sub.IAM.DeleteRole(ctx, roleName); err != nil && !errors.Is(err, ErrNoSuchResource) {
		return p.substrateError(err)
	}
	return nil
}

// --- workload capabilities ----------------------------------------------------

// reconcileWorkloadCapabilities makes the grants on a workload's own role equal
// to what the spec asks for.
//
// # Declarative in both directions, which the source system is not
//
// [compute.ServiceSpec.Capabilities] says omitting a previously granted
// capability revokes it. The source system attaches Bedrock when either of two
// flags is set and detaches only when both are off (container.go:490-500, and
// detachBedrockPolicy at build.go:764) — so that half is declarative — but
// attachECSExecPolicy (build.go:670-697) has NO counterpart at all: nothing ever
// removes the ssmmessages grant, and both service calls turn ECS Exec on
// unconditionally. So a workload that once had exec keeps the grant for the rest
// of its life.
//
// Here the wanted set is computed and the unwanted set is removed, so revoking
// is the same code path as granting and cannot be forgotten separately.
func (p *Provider) reconcileWorkloadCapabilities(
	ctx context.Context,
	taskRoleName string,
	pc PlacementConfig,
	want []compute.WorkloadCapability,
	execEnabled bool,
) error {
	// The universe of capabilities is derived from the interface, not restated.
	// A restatement drifts, and it drifts in the direction of a capability this
	// provider silently ignores.
	known := compute.WorkloadCapabilities()
	if len(known) == 0 {
		return fmt.Errorf("%w: compute.WorkloadCapabilities() is empty, so this reconcile would "+
			"remove every grant it is supposed to manage", compute.ErrFailed)
	}
	valid := make(map[compute.WorkloadCapability]struct{}, len(known))
	for _, c := range known {
		valid[c] = struct{}{}
	}

	desired := map[string]string{}
	for _, c := range want {
		if _, ok := valid[c]; !ok {
			return fmt.Errorf("%w: %q is not a workload capability this interface defines",
				compute.ErrInvalidSpec, c)
		}
		if required := c.Requires(); required != "" && !p.caps.Has(required) {
			return p.unsupported(required, fmt.Sprintf(
				"the spec asks for the workload capability %q, which this provider does not offer", c))
		}
		doc, err := p.workloadCapabilityPolicy(c, pc)
		if err != nil {
			return err
		}
		desired[capabilityPolicyName(c)] = doc
	}

	if execEnabled {
		if !p.caps.Has(compute.CapWorkloadExec) {
			return p.unsupported(compute.CapWorkloadExec,
				"the spec sets ExecEnabled and this provider does not offer interactive sessions")
		}
		desired[policyExec] = execPolicy
	}

	// Only the policies this reconcile is responsible for are in scope, so the
	// secret-read and log-write policies on an *execution* role are never
	// touched by a capability reconcile even if the two roles were ever the
	// same one.
	// The task role belongs to the identity service, not to this port, so the
	// component proved here is that one. Passing this port's own component
	// would refuse every legitimate capability grant — and passing nothing
	// would let a capability policy be attached to an execution role.
	return p.reconcileRolePolicies(ctx, taskRoleName, componentIdentity, desired)
}

// execPolicy is the grant that makes a task reachable for an interactive
// session.
//
// Resource "*" is not a widening: ssmmessages has no resource-level
// permissions, so the four channel actions cannot be scoped to anything. What
// bounds an interactive session is who may *open* one, which is an
// authorisation on the operator's principal and deliberately outside this
// interface — see [compute.ServiceSpec.ExecEnabled], which explains why exec is
// not modelled as a capability granted to the workload.
//
// Ported verbatim from the source system (build.go:671-683).
const execPolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"InteractiveSession",` +
	`"Effect":"Allow","Action":["ssmmessages:CreateControlChannel",` +
	`"ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel",` +
	`"ssmmessages:OpenDataChannel"],"Resource":"*"}]}`

// workloadCapabilityPolicy renders the grant for one workload capability.
func (p *Provider) workloadCapabilityPolicy(c compute.WorkloadCapability, pc PlacementConfig) (string, error) {
	switch c {
	case compute.WorkloadCapabilityModelInference:
		return bedrockPolicy(pc.Region)
	default:
		// Unreachable while the caller validates against
		// compute.WorkloadCapabilities() first, and a refusal rather than a
		// silent no-op if a capability is ever added to the interface without
		// being added here. The alternative — returning an empty document —
		// would report success for a grant that was never made.
		return "", fmt.Errorf("%w: this provider has no policy for the workload capability %q; it "+
			"was added to the interface without being added here", compute.ErrFailed, c)
	}
}

// bedrockPolicy grants model invocation.
//
// # Why the region is a wildcard, which looks wrong and is not
//
// Ported with its scope intact from the source system (build.go:717-750), and
// the reasoning is carried across because without it the next reader tightens
// it and breaks cross-region inference. A caller invoking a system-defined
// inference profile — the usual case — has the call routed to a foundation
// model in some other region within the profile's geography, and IAM evaluates
// the request against the foundation-model ARN in the *destination* region. Pin
// these to the deployment region and every cross-region inference profile fails
// with AccessDenied against a region nobody named.
//
// What makes the wildcard acceptable rather than merely necessary: a
// foundation-model ARN carries no account identifier, so this composes no
// deployment-specific string, and invocation is independently gated by
// per-account model access that IAM does not control. The partition is derived
// from the region because a wildcard there would cross a partition boundary,
// which is a real trust boundary rather than a routing detail.
func bedrockPolicy(region string) (string, error) {
	if strings.TrimSpace(region) == "" {
		return "", fmt.Errorf("%w: the model-inference capability needs a region to derive the "+
			"partition from", compute.ErrInvalidSpec)
	}
	partition := partitionForRegion(region)
	doc, err := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []statement{{
			Sid:    "InvokeFoundationModels",
			Effect: "Allow",
			Action: []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"},
			Resource: []string{
				fmt.Sprintf("arn:%s:bedrock:*::foundation-model/*", partition),
				fmt.Sprintf("arn:%s:bedrock:*:*:inference-profile/*", partition),
			},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the model-inference policy: %w", compute.ErrFailed, err)
	}
	return string(doc), nil
}

// partitionForRegion derives the ARN partition from a region name.
//
// Ported from the source system (build.go:753-762). It is a derivation from a
// prefix rather than a table of regions, so a region added to a partition later
// does not need this updated — the failure mode of a table here would be a
// policy written into the wrong partition.
func partitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}
