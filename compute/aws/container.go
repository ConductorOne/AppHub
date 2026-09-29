// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// containerRuntime implements [compute.ContainerRuntime] on ECS with the
// Fargate launch type.
//
// # What the source system did, and where this differs
//
// There is no EnsureService to port. The source system's container path is 933
// lines inline in one Execute (container.go:62-995), so this is a
// re-derivation against the interface rather than a move, and every difference
// below is therefore a decision rather than a translation. The ones that
// change behaviour are named on the methods that make them, but four are worth
// collecting because each is a control that fails open in the source:
//
//   - **ECS Exec is always on there.** Both service calls pass
//     EnableExecuteCommand unconditionally (container.go:879, :901), and there
//     is no counterpart to attachECSExecPolicy — nothing ever removes the
//     ssmmessages grant. Here [compute.ServiceSpec.ExecEnabled] decides, it
//     converges in both directions, and false is enforced rather than assumed.
//   - **DesiredCount is hardcoded to 1** on create *and on update*
//     (container.go:877, :899), so a redeploy silently resets whatever an
//     operator scaled a service to, and [compute.ServiceSpec.Replicas] of zero
//     — the interface's "paused" — is not expressible at all.
//   - **A failed DescribeServices is read as "the service does not exist"**
//     (container.go:855-861 discards the error and leaves serviceExists
//     false), so a throttle on the read leads to a CreateService on a service
//     that is already there.
//   - **The task execution role is shared by every application and granted
//     ssm:GetParameter on `{prefix}/apps/*`** (terraform/modules/ecs/iam.tf:30-49),
//     so every deployed application's agent can read every other
//     application's secrets. See [executionRole] for why the fix is a
//     per-service role rather than a narrower wildcard.
//
// # What this port does not do yet, and refuses rather than ignores
//
// [compute.ServiceSpec.Ingress] and [compute.ServiceSpec.Routes] are refused.
// Both need substrate this package does not have yet — per-service security
// groups for the first (the EC2 layer, USOSS-12) and the platform ingress
// proxy's configuration for the second — and a provider that accepted a
// reachability rule it does not implement would report success for a
// security control it never applied. That is the one outcome worse than not
// having the feature. The refusal names the field and the owning ticket.
type containerRuntime struct{ p *Provider }

var _ compute.ContainerRuntime = (*containerRuntime)(nil)

// componentContainerService and componentExecutionRole are this port's
// ownership components.
//
// They are distinct from each other and from every other port's, which is
// load-bearing rather than tidy: an IAM role is account-global and several AWS
// ports create roles, so a role created as an execution role must not be
// adoptable as a workload identity. The ownership check compares the component
// as well as the owner for exactly that reason.
const (
	componentContainerService = "container-service"
	componentExecutionRole    = "task-execution-role"
)

// ECS's own name grammars.
//
// An ECS service name and a task-definition family admit letters, digits,
// underscores and hyphens — and NOT a full stop. The shared [sanitize] helper
// separates a derived name from its digest with [digestMarker], which IS a full
// stop, so every name [sanitize] derives rather than passes through verbatim is
// illegal on this substrate.
//
// That is a narrow hole rather than a wide one, and it is worth being precise
// about which names fall in it. [sanitize] returns a name verbatim when
// sanitisation changed nothing byte-for-byte, so the ordinary case — lowercase
// letters, digits and single hyphens — passes through untouched and is legal
// here. What is refused is a logical name containing anything else: an uppercase
// letter, an underscore, a space, a full stop, or one long enough to need
// truncating.
//
// The emitted name is therefore validated against the grammar, exactly as
// [Provider.repositoryName] and [Provider.roleName] validate theirs, and a
// refusal names the cause. Refusing is the only safe option available to this
// port: emitting the name anyway would fail against the API for long or
// punctuated names only, which is the worst possible failure distribution, and
// deriving names with a different marker here would fork the one naming helper
// three ports share — which is how the truncation defect came to have two
// halves in the first place. The fix is a marker parameter on the shared
// helper, which belongs to the port that owns it (USOSS-10); this port has
// asked for one and validates until it arrives.
var (
	ecsServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)
	ecsTaskFamily  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)
)

const (
	maxECSServiceName = 255
	maxECSTaskFamily  = 255
)

// serviceName renders a logical name as an ECS service name.
func (p *Provider) serviceName(logical string) (string, error) {
	prefix := ""
	if p.cfg.Container != nil {
		prefix = p.cfg.Container.NamePrefix
	}
	name, err := sanitize(prefix, logical, maxECSServiceName)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Container.NamePrefix)", err)
	}
	if !ecsServiceName.MatchString(name) {
		return "", fmt.Errorf("%w: the logical name %q derives the ECS service name %q, which ECS "+
			"will not accept: it admits letters, digits, hyphens and underscores, and the shared "+
			"name helper separates a derived name from its digest with %q. Use a logical name of "+
			"lowercase letters, digits and single hyphens, which passes through verbatim",
			compute.ErrInvalidSpec, logical, name, digestMarker)
	}
	return name, nil
}

// taskFamily renders a logical name as a task-definition family.
//
// It is derived from the same logical name as the service rather than from the
// service name, so that the two are independently checkable and a change to
// one prefix cannot silently re-point a service at another family.
func (p *Provider) taskFamily(logical string) (string, error) {
	prefix := ""
	if p.cfg.Container != nil {
		prefix = p.cfg.Container.NamePrefix
	}
	name, err := sanitize(prefix, logical, maxECSTaskFamily)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Container.NamePrefix)", err)
	}
	if !ecsTaskFamily.MatchString(name) {
		return "", fmt.Errorf("%w: the logical name %q derives the task-definition family %q, "+
			"which ECS will not accept; see Provider.serviceName for the grammar and why",
			compute.ErrInvalidSpec, logical, name)
	}
	return name, nil
}

// EnsureService creates or converges an ECS service.
//
// It returns without waiting: an ECS service accepts a task definition
// immediately and reaches its desired count later, which is the asynchronous
// class [compute.Status] describes. The status carries [compute.PhasePending]
// until the substrate reports enough running tasks.
func (c *containerRuntime) EnsureService(ctx context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	if err := checkReplicas(spec.Replicas); err != nil {
		return nil, err
	}
	// Ports were previously copied into the task definition unchecked and
	// narrowed to int32 at the SDK, so 70000 arrived as 4464 — a rule for a port
	// the caller never named. Validated here, at the boundary, against the one
	// derived bound.
	for i, port := range spec.Ports {
		if err := checkPort(fmt.Sprintf("Ports[%d].Number", i), port.Number); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(string(spec.Image)) == "" {
		return nil, fmt.Errorf("%w: a service needs an image", compute.ErrInvalidSpec)
	}
	// Resolved before anything is written, because a request this substrate
	// cannot express is a spec error and not a deploy failure.
	cpuUnits, memoryMiB, sizeNote, err := taskSize(spec.Resources)
	if err != nil {
		return nil, err
	}
	pc, err := c.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	name, err := c.p.serviceName(spec.Name)
	if err != nil {
		return nil, err
	}
	family, err := c.p.taskFamily(spec.Name)
	if err != nil {
		return nil, err
	}
	ref := c.p.ref(compute.KindService, name)

	// The workload's identity, resolved to a role ARN the substrate reported.
	// Required by the interface, and refused rather than defaulted: a service
	// that fell back to an ambient credential would run as whatever the agent
	// happens to hold.
	taskRoleName, taskRoleARN, err := c.p.resolveIdentity(ctx, spec.Identity)
	if err != nil {
		return nil, err
	}

	// Secret bindings become addresses before anything is written, so a
	// missing secret is a spec error now rather than an opaque task failure
	// later.
	secretRefs, err := c.p.resolveSecrets(ctx, pc.Name, spec.Secrets)
	if err != nil {
		return nil, err
	}

	// OWNERSHIP IS ESTABLISHED BEFORE THE FIRST WRITE, NOT BEFORE THE LAST ONE.
	//
	// The source system adopts whatever it finds under the name it wanted;
	// service names derive from mutable application names, so a foreign service
	// under this name is a live collision rather than a theoretical one.
	//
	// This check used to sit after reconcileWorkloadCapabilities,
	// ensureExecutionRole and ensureServiceSecurityGroup, which made an
	// ErrNotOwned refusal DESTRUCTIVE rather than inert: the capability
	// reconciliation is declarative in both directions, so it revoked the live
	// workload's grants on the way to telling the caller it may not touch the
	// service; and the execution role (carrying an SSM read grant) and the
	// security group (carrying an authorized rule) were created for a service
	// this provider then refused to manage -- unreapable, because DeleteService
	// refuses the same name for the same reason.
	//
	// It is the ordering PR #46 pinned for compute/k8s on all three of its
	// granting paths. Everything above this line is a read or a pure
	// computation; everything below it writes. The pair therefore goes at the
	// boundary, and [TestARefusedEnsureWritesNothing] asserts that a refused
	// Ensure leaves the substrate byte-identical rather than merely that it
	// returned the right sentinel.
	existing, err := c.p.sub.ECS.DescribeService(ctx, pc.ClusterARN, name)
	switch {
	case err == nil:
		if ownErr := c.p.checkServiceOwned(ctx, ref, existing); ownErr != nil {
			return nil, ownErr
		}
	case errors.Is(err, ErrNoSuchResource):
		existing = nil
	default:
		// Not read as absence. A throttled describe followed by a create is
		// how the source system creates a service that already exists.
		return nil, c.p.substrateError(err)
	}

	// The workload's own capabilities are reconciled onto its identity, in both
	// directions. Omitting one that was granted revokes it, which is what
	// [compute.ServiceSpec.Capabilities] promises.
	if err := c.p.reconcileWorkloadCapabilities(ctx, taskRoleName, pc, spec.Capabilities, spec.ExecEnabled); err != nil {
		return nil, err
	}

	// The execution role is this port's, one per service, carrying only what
	// starting *this* service requires.
	execRoleARN, err := c.p.ensureExecutionRole(ctx, name, pc, spec.Image, secretRefs, spec.Labels)
	if err != nil {
		return nil, err
	}

	// Routes are compiled before anything is written, so a route this provider
	// cannot serve is a spec error rather than a half-deployed service.
	routeLabels, routeAddresses, err := c.p.renderRoutes(name, pc, spec.Routes)
	if err != nil {
		return nil, err
	}

	// The per-service security group, with its rule set converged in both
	// directions. This is the collection that converges FULLY: a rule on a
	// group this provider created is either one apphub put there or one
	// nobody asked for.
	groupID, err := c.p.ensureServiceSecurityGroup(ctx, name, pc, spec.Ingress, spec.Labels)
	if err != nil {
		return nil, err
	}

	tags := ownershipTags(name, componentContainerService, spec.Labels)

	taskDefARN, err := c.p.sub.ECS.RegisterTaskDefinition(ctx, TaskDefinitionRequest{
		Family:           family,
		CPUUnits:         cpuUnits,
		MemoryMiB:        memoryMiB,
		ExecutionRoleARN: execRoleARN,
		TaskRoleARN:      taskRoleARN,
		Container:        c.p.containerRequest(name, spec, secretRefs, routeLabels),
		Tags:             tags,
	})
	if err != nil {
		return nil, c.p.substrateError(err)
	}

	req := ServiceRequest{
		Cluster:           pc.ClusterARN,
		Name:              name,
		TaskDefinitionARN: taskDefARN,
		DesiredCount:      spec.Replicas,
		SubnetIDs:         pc.Subnets,
		// The service's own group first, then any baseline groups the operator
		// configured. Both: the per-service group carries this spec's ingress
		// rules, and an operator's baseline group carries whatever they attach
		// to everything.
		SecurityGroupIDs: append([]string{groupID}, pc.SecurityGroups...),
		AssignPublicIP:   pc.AssignPublicIP,
		ExecEnabled:      spec.ExecEnabled,
		Tags:             tags,
	}

	var rec *ServiceRecord
	if existing == nil || strings.EqualFold(existing.Status, ecsStatusInactive) {
		// An INACTIVE service still holds its name, so a redeploy of a
		// previously deleted service is a create rather than an update. ECS
		// itself allows the name to be reused; treating INACTIVE as "present"
		// would make a torn-down application impossible to redeploy.
		rec, err = c.p.sub.ECS.CreateService(ctx, req)
	} else {
		rec, err = c.p.sub.ECS.UpdateService(ctx, req)
	}
	if err != nil {
		return nil, c.p.substrateError(err)
	}

	// Tags converge separately because ECS applies them only on create, so an
	// update would otherwise never pick up a changed label — and a label the
	// caller dropped has to be removed, not merely stop being sent.
	if err := c.p.convergeServiceTags(ctx, rec, tags); err != nil {
		return nil, err
	}

	st := c.p.serviceStatus(ref, spec, rec, pc)
	st.RouteAddresses = routeAddresses
	// The rounding note is the caller's only notice that they did not get the
	// size they asked for, so it goes in front of any phase detail rather than
	// being appended where a truncating reader would lose it.
	if sizeNote != "" {
		if st.Message == "" {
			st.Message = sizeNote
		} else {
			st.Message = sizeNote + "; " + st.Message
		}
	}
	return st, nil
}

// ecsStatusInactive is the substrate's word for a deleted service whose name is
// still taken.
const (
	ecsStatusInactive = "INACTIVE"
	ecsStatusActive   = "ACTIVE"
	ecsStatusDraining = "DRAINING"
)

// The substrate's own verdicts on a deployment's rollout.
const (
	rolloutCompleted  = "COMPLETED"
	rolloutInProgress = "IN_PROGRESS"
	rolloutFailed     = "FAILED"
)

// resolveIdentity turns [compute.ServiceSpec.Identity] into a role name and the
// ARN the substrate reports for it.
//
// The ARN is read back rather than composed, so this package holds no account
// identifier — the decision recorded for USOSS-10 and binding here.
func (p *Provider) resolveIdentity(ctx context.Context, ref compute.Ref) (name, arn string, err error) {
	if ref.IsZero() {
		return "", "", fmt.Errorf("%w: a service needs an Identity; a workload with no identity "+
			"cannot be granted access to anything, and this provider will not fall back to an "+
			"ambient credential", compute.ErrInvalidSpec)
	}
	name, err = p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return "", "", err
	}
	rec, err := p.sub.IAM.GetRole(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return "", "", fmt.Errorf("%w: the workload identity %s does not exist; ensure it before "+
			"the service that runs as it", compute.ErrNotFound, ref)
	}
	if err != nil {
		return "", "", p.substrateError(err)
	}
	return name, rec.ARN, nil
}

// resolveSecrets turns bindings into substrate addresses.
//
// A spec carrying bindings against a provider with no secret resolver is
// refused. Deploying without them would either crash the workload on a missing
// variable — the good case — or start it in a degraded mode nobody asked for.
func (p *Provider) resolveSecrets(
	ctx context.Context, placement string, bindings []compute.SecretBinding,
) ([]SecretParameterRef, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	resolver := p.secretResolver()
	if resolver == nil {
		return nil, fmt.Errorf("%w: the spec binds %d secret(s) and this provider has no secret "+
			"store configured (neither Config.Container.Secrets nor Config.Secrets); refusing "+
			"rather than starting a workload without the secrets it asked for",
			compute.ErrInvalidSpec, len(bindings))
	}
	in := make([]SecretBindingRef, 0, len(bindings))
	for _, b := range bindings {
		if strings.TrimSpace(b.EnvName) == "" {
			return nil, fmt.Errorf("%w: a secret binding has no EnvName", compute.ErrInvalidSpec)
		}
		// Validated HERE rather than left to the resolver, and that is the whole
		// point: [SecretResolver] is a caller-supplied interface, so delegating
		// this would make the port's fail-closed behaviour a property of
		// whichever resolver it was handed. A permissive resolver would become a
		// fail-open at the port, which is the seam-sealing lesson USOSS-26's own
		// review arrived at from the other direction.
		//
		// The suite caught this the moment it stopped being vacuous. Until a
		// secret store existed in the same provider, the container-service arm
		// of "a workload's secrets move by reference" could not run at all, and
		// the stub resolver these tests use accepts anything -- so a foreign
		// reference was resolved rather than refused, and the workload would
		// have started without the value or not at all.
		if b.Secret.Provider != p.Name() {
			return nil, fmt.Errorf("%w: the secret binding for %q names provider %q and this is "+
				"provider %q. A binding is resolved against this provider's own store, so a "+
				"foreign reference cannot be resolved at launch -- refused here rather than "+
				"becoming a container that starts without the value it asked for",
				compute.ErrForeignRef, b.EnvName, b.Secret.Provider, p.Name())
		}
		if b.Secret.Kind != compute.KindSecret {
			return nil, fmt.Errorf("%w: the secret binding for %q references a %q, not a %q",
				compute.ErrInvalidSpec, b.EnvName, b.Secret.Kind, compute.KindSecret)
		}
		in = append(in, SecretBindingRef{
			EnvName:  b.EnvName,
			Provider: b.Secret.Provider,
			Kind:     string(b.Secret.Kind),
			ID:       b.Secret.ID,
			Version:  b.Version,
		})
	}
	// A BINDING MAY NOT CROSS A PLACEMENT BOUNDARY.
	//
	// Identities and secrets are placement-scoped, and an SSM parameter is
	// REGIONAL -- its ARN carries the region, and [PlacementConfig.Region]
	// exists precisely so two placements can differ in one. An ECS task cannot
	// resolve a parameter from another region, so a workload in one placement
	// bound to a secret from another produces a task definition whose valueFrom
	// resolves to nothing at launch: a container that never starts, reported as
	// a deploy failure minutes later rather than as the spec error it is.
	//
	// The only other way to satisfy such a binding is to COPY the material into
	// this placement, which doubles the places an audit has to look for material
	// this seam is otherwise careful never to let apphub read. Refusing is the
	// only remaining direction, and it is what
	// security/secrets-do-not-cross-placements requires.
	//
	// Asked HERE and compared HERE, for the reason the two checks above are:
	// [SecretResolver] is caller-supplied, so a resolver left to make this
	// decision would make the port's fail-closed behaviour a property of
	// whichever resolver it was handed. The resolver reports where the secret
	// lives; the refusal is the port's.
	//
	// The comparison is on the RESOLVED placement name from both sides.
	// Config.placement fills in a caller's empty "use the default" here, and the
	// store records the resolved name at Put for the same reason -- two
	// placements have to be spelled the same way from both sides or the
	// comparison is against a formatting difference.
	for _, b := range in {
		stored, err := resolver.SecretPlacement(ctx, b)
		if err != nil {
			return nil, err
		}
		if stored != placement {
			return nil, fmt.Errorf("%w: the secret bound to %q is stored for placement %q and "+
				"this service is placed in %q. A secret does not cross a placement boundary: "+
				"the parameter is regional, so the reference would resolve to nothing when the "+
				"task starts, and copying the material into this placement would double the "+
				"places it has to be audited",
				compute.ErrInvalidSpec, b.EnvName, stored, placement)
		}
	}
	refs, err := resolver.SecretParameterARNs(ctx, in)
	if err != nil {
		return nil, err
	}
	// The resolver's contract is one ref per binding, in order. Checked rather
	// than trusted: a resolver that dropped one would produce a workload
	// missing a variable it asked for, and the grant would be built from the
	// short list too, so the failure would look like a permissions problem.
	if len(refs) != len(in) {
		return nil, fmt.Errorf("%w: the secret resolver returned %d address(es) for %d binding(s)",
			compute.ErrFailed, len(refs), len(in))
	}
	for i, r := range refs {
		if r.EnvName != in[i].EnvName {
			return nil, fmt.Errorf("%w: the secret resolver returned an address for %q where %q "+
				"was asked for", compute.ErrFailed, r.EnvName, in[i].EnvName)
		}
		if strings.TrimSpace(r.ARN) == "" {
			return nil, fmt.Errorf("%w: the secret resolver returned an empty address for %q",
				compute.ErrFailed, r.EnvName)
		}
		// A PIN THE RESOLVER DID NOT HONOUR IS REFUSED, NOT DROPPED.
		//
		// Checked here rather than trusted, for the reason the foreign-provider,
		// wrong-kind and placement checks above are: [SecretResolver] is
		// caller-supplied, so a resolver that ignored Version would make this
		// port silently unpin every workload it resolved -- and silence is
		// exactly what [compute.SecretBinding.Version] exists to prevent. A
		// resolver that CANNOT pin should say so, and
		// [compute.ErrVersionPinningUnsupported] is the sentinel for it; one
		// that accepts a pin and returns an unpinned address has reported
		// success for work it did not do.
		//
		// The comparison is on presence, not on equality. A store is entitled to
		// normalise a revision -- the SSM one parses through strconv and emits
		// the canonical form, so "007" comes back as "7" -- and requiring the
		// string to round-trip unchanged would refuse a correct normalisation.
		// What cannot happen is a pinned binding coming back with no pin at all.
		if in[i].Version != "" && r.Version == "" {
			return nil, fmt.Errorf("%w: the secret binding for %q pinned revision %q and the "+
				"secret resolver returned an address with no revision. A workload deployed from "+
				"it would follow the latest value while the caller believed it was pinned; a "+
				"resolver that cannot pin must refuse with %v rather than resolve",
				compute.ErrFailed, r.EnvName, in[i].Version, compute.ErrVersionPinningUnsupported)
		}
	}
	return refs, nil
}

// containerRequest renders the container definition.
//
// Env is sorted and secrets are in the resolver's order, so two registrations
// of one spec produce identical revisions and a rendered artefact is
// comparable. Nothing here holds secret material: a binding becomes a
// [SecretReference] carrying an ARN, and the substrate does the reading.
func (p *Provider) containerRequest(name string, spec compute.ServiceSpec, secretRefs []SecretParameterRef, routeLabels map[string]string) ContainerRequest {
	env := make([]KeyValue, 0, len(spec.Env))
	for _, e := range spec.Env {
		env = append(env, KeyValue{Name: e.Name, Value: e.Value})
	}
	sort.Slice(env, func(i, j int) bool { return env[i].Name < env[j].Name })

	secrets := make([]SecretReference, 0, len(secretRefs))
	for _, r := range secretRefs {
		secrets = append(secrets, SecretReference{Name: r.EnvName, ValueFrom: r.ARN})
	}

	ports := make([]int, 0, len(spec.Ports))
	for _, pp := range spec.Ports {
		ports = append(ports, pp.Number)
	}

	logGroup := ""
	if p.cfg.Container != nil && p.cfg.Container.LogGroupPrefix != "" {
		logGroup = strings.TrimSuffix(p.cfg.Container.LogGroupPrefix, "/") + "/" + name
	}

	return ContainerRequest{
		Name:    name,
		Image:   string(spec.Image),
		Ports:   ports,
		Env:     env,
		Secrets: secrets,
		// A readiness probe is deliberately not translated into an ECS
		// container health check. They are different things: a container health
		// check decides whether ECS *replaces* a task, and
		// [compute.ServiceSpec.Readiness] decides when an instance counts as
		// serving. Wiring the second onto the first would turn a slow-starting
		// workload into a restart loop. What Readiness means here is documented
		// on WaitForService, which is the method that uses it.
		LogGroup:     logGroup,
		DockerLabels: routeLabels,
	}
}

// checkServiceOwned refuses a service this provider did not create.
func (p *Provider) checkServiceOwned(ctx context.Context, ref compute.Ref, rec *ServiceRecord) error {
	tags := rec.Tags
	if len(tags) == 0 && rec.ARN != "" {
		// A describe may not carry tags; read them by ARN rather than
		// concluding the service is unowned from their absence.
		read, err := p.sub.ECS.ListServiceTags(ctx, rec.ARN)
		if err != nil {
			return p.substrateError(err)
		}
		tags = read
	}
	if tags[tagManagedBy] == managedByValue && tags[tagComponent] == componentContainerService {
		return nil
	}
	// The error does not describe what it found. A refusal that echoed the
	// foreign resource's tags would disclose somebody else's metadata to a
	// caller that has just been told it may not touch it.
	return fmt.Errorf("%w: %s names an ECS service this provider does not own", compute.ErrNotOwned, ref)
}

// convergeServiceTags makes the service's tags equal the desired set, removing
// only keys this provider owns.
func (p *Provider) convergeServiceTags(ctx context.Context, rec *ServiceRecord, desired map[string]string) error {
	if rec.ARN == "" {
		return nil
	}
	current, err := p.sub.ECS.ListServiceTags(ctx, rec.ARN)
	if err != nil {
		return p.substrateError(err)
	}
	put, remove := tagDelta(current, desired)
	if len(put) > 0 {
		if err := p.sub.ECS.TagService(ctx, rec.ARN, put); err != nil {
			return p.substrateError(err)
		}
	}
	if len(remove) > 0 {
		if err := p.sub.ECS.UntagService(ctx, rec.ARN, remove); err != nil {
			return p.substrateError(err)
		}
	}
	return nil
}

// serviceStatus renders a substrate record as a [compute.ServiceStatus].
func (p *Provider) serviceStatus(ref compute.Ref, spec compute.ServiceSpec, rec *ServiceRecord, pc PlacementConfig) *compute.ServiceStatus {
	effective := spec
	effective.Placement = compute.Placement{Name: pc.Name}
	effective.Replicas = rec.DesiredCount
	effective.ExecEnabled = rec.ExecEnabled

	phase, message := servicePhase(rec)
	return &compute.ServiceStatus{
		Status: compute.Status{
			Ref:       ref,
			Phase:     phase,
			Message:   message,
			UpdatedAt: time.Now(),
		},
		Spec:            effective,
		DesiredReplicas: rec.DesiredCount,
		// The PRIMARY deployment's running count, not the service-level one.
		// [compute.ServiceStatus.ReadyReplicas] is "how many instances are
		// currently serving", and an instance of the revision this spec
		// replaced is not serving this spec. The service-level count includes
		// those, so using it would report a rollout complete before it started.
		ReadyReplicas: readyReplicas(rec),
		// The task definition revision is the identity of the deployed
		// configuration: ECS registers a new revision exactly when the
		// rendered definition differs, so it is stable across a no-op Ensure
		// and changes when the effective configuration does — which is what
		// [compute.ServiceStatus.Revision] asks for.
		Revision: rec.TaskDefinitionARN,
	}
}

// servicePhase maps a substrate record onto the interface's phase vocabulary.
//
// The interesting case is a paused service. [compute.ServiceSpec.Replicas] of
// zero is legal and means "the definition and network identity persist, nothing
// runs", so a service at its desired count of zero has converged and is
// reported [compute.PhaseReady] with a message saying it is paused. Reporting
// PhasePending would be worse than merely inaccurate: a caller waiting for
// convergence would wait forever for a state the substrate is already in.
func servicePhase(rec *ServiceRecord) (compute.Phase, string) {
	ready := readyReplicas(rec)
	switch {
	case strings.EqualFold(rec.Status, ecsStatusInactive):
		return compute.PhaseGone, "the ECS service is INACTIVE"
	case strings.EqualFold(rec.Status, ecsStatusDraining):
		return compute.PhaseDeleting, "the ECS service is draining"
	case strings.EqualFold(rec.RolloutState, rolloutFailed):
		// The substrate has given up. That is not a slow rollout and a caller
		// waiting for it would wait until its deadline for a state that will
		// not arrive, so it is reported as failed with the substrate's own
		// reason rather than as pending.
		return compute.PhaseFailed, strings.TrimSpace("the deployment failed: " +
			firstNonEmpty(rec.RolloutReason, "the substrate gave no reason") + latestEvent(rec))
	case rec.RunningCount > ready || rec.PendingCount > 0 || (rec.DesiredCount == 0 && rec.RunningCount > 0) ||
		(rec.DesiredCount > 0 && rec.RolloutState != "" && !strings.EqualFold(rec.RolloutState, rolloutCompleted)):
		// Reaching the new revision's replica count does not mean the old
		// revision's tasks (and their ingress labels) have been retired.
		return compute.PhasePending, "waiting for the rollout and previous tasks to finish" + latestEvent(rec)
	case rec.DesiredCount == 0:
		return compute.PhaseReady, "paused: the service is at its desired count of zero"
	case ready >= rec.DesiredCount:
		return compute.PhaseReady, ""
	default:
		return compute.PhasePending, fmt.Sprintf("%d of %d task(s) of the current revision "+
			"running%s", ready, rec.DesiredCount, latestEvent(rec))
	}
}

// readyReplicas is how many instances of the revision this spec asked for are
// running.
//
// It reads the primary deployment's count when the substrate reported one, and
// falls back to the service-level count only when it did not. The fallback is
// not a shrug: a substrate that reports no deployment at all is one this
// provider cannot say anything sharper about, and reporting the looser number
// is better than reporting zero and stalling a wait forever. See
// [ServiceRecord] for why the sharper number is the correct one when available.
func readyReplicas(rec *ServiceRecord) int {
	if rec.PrimaryTaskDefinitionARN != "" {
		return rec.PrimaryRunningCount
	}
	return rec.RunningCount
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// latestEvent appends the substrate's most recent event, which is the only
// diagnosis ECS offers for a task that will never start.
func latestEvent(rec *ServiceRecord) string {
	if len(rec.Events) == 0 {
		return ""
	}
	return "; " + rec.Events[0]
}

// DescribeService reports current state.
//
// A service that was deleted or never created is [compute.PhaseGone] rather
// than an error, so reconciliation and teardown do not have to tell the two
// apart.
func (c *containerRuntime) DescribeService(ctx context.Context, ref compute.Ref) (*compute.ServiceStatus, error) {
	name, pc, err := c.p.serviceTarget(ref)
	if err != nil {
		return nil, err
	}
	rec, err := c.p.sub.ECS.DescribeService(ctx, pc.ClusterARN, name)
	if errors.Is(err, ErrNoSuchResource) {
		return &compute.ServiceStatus{
			Status: compute.Status{Ref: ref, Phase: compute.PhaseGone, UpdatedAt: time.Now()},
		}, nil
	}
	if err != nil {
		return nil, c.p.substrateError(err)
	}
	if ownErr := c.p.checkServiceOwned(ctx, ref, rec); ownErr != nil {
		return nil, ownErr
	}
	spec, err := c.p.effectiveSpec(ctx, name, rec, pc)
	if err != nil {
		return nil, err
	}
	st := c.p.serviceStatus(ref, spec, rec, pc)
	for _, r := range spec.Routes {
		st.RouteAddresses = append(st.RouteAddresses, r.Host)
	}
	return st, nil
}

// effectiveSpec reconstructs the desired state from what the substrate holds.
//
// [compute.ServiceStatus] requires every read-back to carry the effective spec,
// and most of that state lives on the task-definition revision rather than on
// the service — the image, the allocation, the environment and the secret
// references are all there. So this reads the revision the service is running
// and rebuilds from it, rather than echoing back the spec a caller passed to a
// previous Ensure, which the provider does not keep and should not.
//
// # What cannot be recovered, stated rather than quietly dropped
//
//   - A secret binding's [compute.Ref]. The revision holds the substrate
//     address the agent resolves, and mapping an address back to the reference
//     it came from would need the secret store this port deliberately does not
//     talk to. The binding is reported with its environment variable name and a
//     zero Ref, which is honest: the name is what the workload sees and the
//     address is not the caller's vocabulary.
//   - A route's original form. Routes are rendered into proxy labels, and while
//     the hostnames come back exactly, whether a route asked for TLS or
//     explicitly allowed plaintext is recoverable only by parsing label values.
//     Only the hostnames are reported, and they are also what
//     [compute.ServiceStatus.RouteAddresses] is for.
//   - The exact requested allocation. The provider rounds up to a Fargate size
//     and reports the size it got, which is the state that is actually in
//     force. The rounding itself is reported at Ensure time in
//     [compute.Status.Message], because that is the only moment the request and
//     the result are both known.
func (p *Provider) effectiveSpec(ctx context.Context, name string, rec *ServiceRecord, pc PlacementConfig) (compute.ServiceSpec, error) {
	spec := compute.ServiceSpec{
		Name:        name,
		Placement:   compute.Placement{Name: pc.Name},
		Replicas:    rec.DesiredCount,
		ExecEnabled: rec.ExecEnabled,
		Labels:      labelsFromTags(rec.Tags),
	}
	if rec.TaskDefinitionARN != "" {
		def, err := p.sub.ECS.DescribeTaskDefinition(ctx, rec.TaskDefinitionARN)
		if err != nil && !errors.Is(err, ErrNoSuchResource) {
			return compute.ServiceSpec{}, p.substrateError(err)
		}
		if def != nil {
			spec.Image = compute.ImageRef(def.Container.Image)
			spec.Resources = compute.Resources{
				// Back into the interface's units. 1024 ECS units is one core
				// is 1000 millicores.
				CPUMillicores: def.CPUUnits * 1000 / cpuUnitsPerCore,
				MemoryMiB:     def.MemoryMiB,
			}
			for _, port := range def.Container.Ports {
				spec.Ports = append(spec.Ports, compute.PortSpec{Number: port})
			}
			for _, kv := range def.Container.Env {
				spec.Env = append(spec.Env, compute.EnvVar{Name: kv.Name, Value: kv.Value})
			}
			for _, sec := range def.Container.Secrets {
				spec.Secrets = append(spec.Secrets, compute.SecretBinding{EnvName: sec.Name})
			}
			for _, host := range hostsFromLabels(def.Container.DockerLabels) {
				spec.Routes = append(spec.Routes, compute.Route{Host: host})
			}
			if def.TaskRoleARN != "" {
				// The identity is reported as the reference this provider would
				// have issued for the role the task actually runs as, recovered
				// from the ARN's resource name rather than composed from an
				// account identifier.
				if roleName := roleNameFromARN(def.TaskRoleARN); roleName != "" {
					spec.Identity = p.ref(compute.KindWorkloadIdentity, roleName)
				}
			}
		}
	}
	if p.sub.EC2 != nil {
		rules, err := p.serviceObservedIngress(ctx, name, pc)
		if err != nil {
			return compute.ServiceSpec{}, err
		}
		spec.Ingress = rules
	}
	return spec, nil
}

// roleNameFromARN recovers the role name from an IAM role ARN.
//
// It reads the last path segment rather than parsing the ARN's fields, so it
// holds no assumption about the account or partition positions and cannot
// reconstruct an identifier this package does not want. An ARN it does not
// understand yields the empty string and the identity is simply not reported,
// which is better than reporting a wrong one.
func roleNameFromARN(arn string) string {
	idx := strings.LastIndex(arn, "/")
	if idx < 0 || idx == len(arn)-1 {
		return ""
	}
	return arn[idx+1:]
}

// hostsFromLabels recovers the hostnames from rendered proxy labels.
//
// Only the hostnames: see [Provider.effectiveSpec] for why the rest of a route
// is not reconstructed.
func hostsFromLabels(labels map[string]string) []string {
	seen := map[string]struct{}{}
	for key, value := range labels {
		if !strings.HasSuffix(key, ".rule") {
			continue
		}
		const marker = "Host(`"
		start := strings.Index(value, marker)
		if start < 0 {
			continue
		}
		rest := value[start+len(marker):]
		end := strings.Index(rest, "`")
		if end <= 0 {
			continue
		}
		seen[rest[:end]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// serviceObservedIngress reads back the reachability rules actually in force on
// a SERVICE's group, as [compute.IngressRule] values.
//
// Named for the service because USOSS-14 has a [Provider.observedIngress] for a
// database's group (database.go). The two read different groups and answer to
// different callers, so they are two functions rather than one with a mode
// argument -- but they must not share a name, and the unqualified one is
// USOSS-14's because it landed first.
//
// It is a translation back out of the substrate rather than a memory of what was
// asked for, which is the point: a rule an operator added by hand shows up here,
// and the next Ensure removes it.
func (p *Provider) serviceObservedIngress(ctx context.Context, serviceName string, pc PlacementConfig) ([]compute.IngressRule, error) {
	groupName, err := p.securityGroupName(serviceName)
	if err != nil {
		return nil, err
	}
	group, err := p.sub.EC2.DescribeSecurityGroupByName(ctx, groupName, pc.VPC)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, nil
	}
	if err != nil {
		return nil, p.substrateError(err)
	}
	out := make([]compute.IngressRule, 0, len(group.Ingress))
	for _, r := range group.Ingress {
		rule := compute.IngressRule{
			Port:        r.FromPort.Value,
			Protocol:    compute.Protocol(r.Protocol),
			Description: r.Description.Value,
		}
		if r.ToPort != r.FromPort {
			// compute.IngressRule has one port, so a range read back from the
			// substrate cannot be reported faithfully. Saying so in the
			// description is better than reporting the low port alone as though
			// it were the whole rule: a caller comparing the effective spec
			// against what it asked for would otherwise see a rule it recognises
			// where a wider one is in force. The next Ensure revokes it either
			// way, because the compiler never produces a range.
			rule.Description = fmt.Sprintf("%s [substrate rule spans ports %s-%s]",
				r.Description.Value, optionalPortString(r.FromPort), optionalPortString(r.ToPort))
		}
		switch {
		case r.SourceCIDR == anyIPv4 || r.SourceCIDR == anyIPv6:
			rule.From = compute.Peer{Kind: compute.PeerInternet}
		case contains(pc.PlatformIngressSecurityGroups, r.SourceGroup):
			rule.From = compute.Peer{Kind: compute.PeerPlatformIngress}
		case contains(pc.ControlPlaneSecurityGroups, r.SourceGroup):
			rule.From = compute.Peer{Kind: compute.PeerControlPlane}
		default:
			// A group this provider cannot name a role for. Reported as a
			// workload peer with no reference rather than omitted: a rule that
			// exists and is not reported is a rule nothing will ever converge
			// away.
			rule.From = compute.Peer{Kind: compute.PeerWorkload}
		}
		out = append(out, rule)
	}
	// De-duplicated on the way out, because PeerInternet compiles to two
	// substrate rules (v4 and v6) and reporting it twice would make an
	// idempotent Ensure look like it changed something.
	return dedupeIngress(out), nil
}

func dedupeIngress(in []compute.IngressRule) []compute.IngressRule {
	seen := make(map[compute.IngressRule]struct{}, len(in))
	out := make([]compute.IngressRule, 0, len(in))
	for _, r := range in {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

func contains(set []string, want string) bool {
	for _, have := range set {
		if have == want {
			return true
		}
	}
	return false
}

// serviceTarget resolves a ref to a service name and the placement it lives in.
//
// A [compute.Ref] carries no placement, so a provider with more than one
// placement has to find the service. It is looked up in the default placement
// first and then the rest in sorted order, and the search is deterministic
// rather than map-ordered so that an operator reading an error twice sees the
// same one.
func (p *Provider) serviceTarget(ref compute.Ref) (string, PlacementConfig, error) {
	name, err := p.resolve(ref, compute.KindService)
	if err != nil {
		return "", PlacementConfig{}, err
	}
	pc, err := p.cfg.placement(compute.Placement{})
	if err == nil {
		return name, pc, nil
	}
	// No default placement. With exactly one configured placement the answer is
	// unambiguous; with several it is not, and guessing would address a
	// different service from the one the caller meant.
	names := p.cfg.placementNames()
	if len(names) == 1 {
		pc := p.cfg.Placements[names[0]]
		pc.Name = names[0]
		if pc.Region == "" {
			pc.Region = p.cfg.Region
		}
		return name, pc, nil
	}
	return "", PlacementConfig{}, fmt.Errorf("%w: %s does not say which placement it is in and "+
		"this provider has %d of them with no default; configure Config.DefaultPlacement",
		compute.ErrInvalidSpec, ref, len(names))
}

// WaitForService blocks until minReady instances are serving.
//
// # What "serving" means on this substrate, which the interface requires a provider to state
//
// It means ECS reports at least minReady tasks in RUNNING state. This provider
// does not translate [compute.ServiceSpec.Readiness] into anything, and that is
// a real limitation rather than an omission: an ECS task's readiness is decided
// by a load balancer target group's health check, and this port does not create
// a target group — nothing in the source system's container path creates an
// ELBv2 object (1 of 21 files in the source's deploy package references elbv2,
// and it is the Lambda one). So RUNNING is the strongest signal available here.
//
// The gap is worth naming precisely, because it is the one the interface warns
// about: a task can be RUNNING and not yet answering, so a caller that waits
// here and then shifts traffic may shift it early. The source system has the
// same gap and a smaller one — it returns as soon as RunningCount is above zero
// (container.go:1113-1116), ignoring how many were asked for.
func (c *containerRuntime) WaitForService(ctx context.Context, ref compute.Ref, minReady int, opts compute.WaitOptions) (*compute.ServiceStatus, error) {
	if minReady < 0 {
		return nil, fmt.Errorf("%w: minReady is %d", compute.ErrInvalidSpec, minReady)
	}
	deadline, err := waitDeadline(ctx, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var last *compute.ServiceStatus
	for {
		st, err := c.DescribeService(ctx, ref)
		if err != nil {
			return nil, err
		}
		if last == nil || st.Phase != last.Phase || st.ReadyReplicas != last.ReadyReplicas {
			if opts.OnUpdate != nil {
				opts.OnUpdate(st.Status)
			}
		}
		last = st
		switch {
		case st.Phase == compute.PhaseGone:
			return st, fmt.Errorf("%w: %s does not exist", compute.ErrNotFound, ref)
		case st.Phase == compute.PhaseFailed:
			return st, fmt.Errorf("%w: %s: %s", compute.ErrFailed, ref, st.Message)
		case st.ReadyReplicas >= minReady && (minReady < st.DesiredReplicas || st.Phase == compute.PhaseReady):
			return st, nil
		}
		// The sleep is context-aware, so a cancelled wait returns at once
		// rather than up to a poll interval later.
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("%w: %s reached %d of %d ready task(s) in time: %s",
				compute.ErrTimeout, ref, last.ReadyReplicas, minReady, last.Message)
		case <-time.After(servicePollInterval):
		}
	}
}

// servicePollInterval is how often a wait re-reads the substrate. It matches
// the source system's two seconds (container.go:1131).
const servicePollInterval = 2 * time.Second

// waitDeadline resolves the deadline a wait must respect.
//
// A wait with neither a timeout nor a context deadline is [compute.ErrInvalidSpec]
// rather than an unbounded block, which is what [compute.WaitOptions] requires.
func waitDeadline(ctx context.Context, opts compute.WaitOptions) (time.Time, error) {
	if opts.Timeout > 0 {
		return time.Now().Add(opts.Timeout), nil
	}
	if d, ok := ctx.Deadline(); ok {
		return d, nil
	}
	return time.Time{}, fmt.Errorf("%w: a wait needs either WaitOptions.Timeout or a context "+
		"deadline; refusing to wait forever", compute.ErrInvalidSpec)
}

// ScaleService sets the desired instance count and changes nothing else.
func (c *containerRuntime) ScaleService(ctx context.Context, ref compute.Ref, replicas int) error {
	if err := checkReplicas(replicas); err != nil {
		return err
	}
	name, pc, err := c.p.serviceTarget(ref)
	if err != nil {
		return err
	}
	rec, err := c.p.sub.ECS.DescribeService(ctx, pc.ClusterARN, name)
	if errors.Is(err, ErrNoSuchResource) {
		return fmt.Errorf("%w: %s does not exist", compute.ErrNotFound, ref)
	}
	if err != nil {
		return c.p.substrateError(err)
	}
	if ownErr := c.p.checkServiceOwned(ctx, ref, rec); ownErr != nil {
		return ownErr
	}
	// SetDesiredCount rather than UpdateService: an update carrying a task
	// definition would roll the service as a side effect of scaling it.
	return c.p.substrateError(c.p.sub.ECS.SetDesiredCount(ctx, pc.ClusterARN, name, replicas))
}

// DeleteService removes a service. Idempotent.
//
// It does not delete the workload identity or the secrets the service used —
// those have their own lifetimes and owners — but it does delete the execution
// role, because that role is this port's own and exists only to start this
// service.
func (c *containerRuntime) DeleteService(ctx context.Context, ref compute.Ref) error {
	name, pc, err := c.p.serviceTarget(ref)
	if err != nil {
		return err
	}
	rec, err := c.p.sub.ECS.DescribeService(ctx, pc.ClusterARN, name)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		// Already gone. Still try the role and the group, so a teardown
		// interrupted between the halves completes on a second run rather than
		// leaving either behind for ever.
		if roleErr := c.p.deleteExecutionRole(ctx, name); roleErr != nil {
			return roleErr
		}
		return c.p.deleteServiceSecurityGroup(ctx, name, pc)
	case err != nil:
		return c.p.substrateError(err)
	}
	if ownErr := c.p.checkServiceOwned(ctx, ref, rec); ownErr != nil {
		return ownErr
	}
	// An INACTIVE service has already been deleted, and ECS refuses to delete it
	// again with ServiceNotActiveException -- which the adapter classifies as
	// transient, because on the create path it is. So a teardown retried after
	// its security group refused (see [sdkEC2.err]) would answer "try again" at
	// this step until ECS forgot the service, and never reach the group. The
	// retry skips the delete that already happened and goes on to the halves
	// that have not.
	if !strings.EqualFold(rec.Status, ecsStatusInactive) {
		if err := c.p.sub.ECS.DeleteService(ctx, pc.ClusterARN, name); err != nil &&
			!errors.Is(err, ErrNoSuchResource) {
			return c.p.substrateError(err)
		}
	}
	if err := c.p.deleteExecutionRole(ctx, name); err != nil {
		return err
	}
	// The security group last: EC2 refuses to delete a group still attached to
	// a network interface, and the interfaces go when the tasks do.
	return c.p.deleteServiceSecurityGroup(ctx, name, pc)
}
