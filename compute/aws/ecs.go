// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"time"
)

// This file adds the ECS half of [Substrate], and the IAM role-policy calls the
// container port needs on top of the role lifecycle USOSS-10 ported.
//
// The methods it adds to [MemoryIAM] and the SDK IAM adapter live in
// ecsmemory.go and ecsclient.go rather than alongside their siblings. That is
// deliberate and not an accident of authorship: Go allows a type's methods to be
// spread across files in one package, and keeping this port's additions in this
// port's files means the container work and the image-build work can be reviewed
// and rebased independently. The one thing that cannot be moved is the method
// set of [IAMAPI] itself, which is declared with the rest of the substrate.

// ServiceRecord is what the container substrate reports about one service.
//
// It is what ECS returns, reduced to the fields the port reads. Nothing here is
// interpreted: the provider decides what "serving" means, what phase a service
// is in, and whether a status is owned, so that the in-memory substrate cannot
// implement a different contract from the SDK one.
type ServiceRecord struct {
	// Name is the service name within the cluster.
	Name string
	// ARN is the service ARN, as ECS reported it. Read back, never composed.
	ARN string
	// Status is the substrate's own lifecycle word: ACTIVE, DRAINING or
	// INACTIVE. A deleted ECS service lingers as INACTIVE rather than
	// disappearing, which is why the port has to see this rather than infer
	// existence from the absence of an error.
	Status string
	// TaskDefinitionARN is the revision the service is running.
	TaskDefinitionARN string
	// DesiredCount is what ECS is targeting.
	DesiredCount int
	// RunningCount is how many tasks are RUNNING across EVERY deployment, which
	// is what the service-level field means and why it must not drive readiness.
	// Running is also not serving; see [containerRuntime.WaitForService].
	RunningCount int
	// PendingCount is how many tasks are starting.
	PendingCount int

	// The PRIMARY deployment: the one running the revision this service was
	// last asked to run.
	//
	// # Why readiness cannot be computed without these
	//
	// ECS's service-level RunningCount counts tasks of ANY revision. During a
	// rollout the old revision's tasks are still running, so immediately after
	// an update RunningCount already equals DesiredCount while nothing of the
	// new revision has started. A provider that read only the service-level
	// count would report a deployment ready before it had begun — and a caller
	// that waits and then shifts traffic would shift it to the old revision.
	//
	// This port had exactly that defect. It is the shape USOSS-12 named on their
	// own port: an adapter that narrows a response decides what the layers above
	// it are able to know. The SDK adapter was keeping the counts and discarding
	// the Deployments array, so the question had been asked of the service and
	// thrown away, and no amount of care above the seam could recover it.
	PrimaryTaskDefinitionARN string
	// PrimaryDesiredCount and PrimaryRunningCount are that deployment's own
	// counts, and they are what readiness is computed from.
	PrimaryDesiredCount int
	PrimaryRunningCount int
	// RolloutState is the substrate's own verdict on the primary deployment:
	// COMPLETED, IN_PROGRESS or FAILED. A FAILED rollout is a deployment that
	// will not converge without a change to the spec, which is
	// [compute.PhaseFailed] rather than a wait that eventually times out.
	RolloutState string
	// RolloutReason is the substrate's explanation for the state, relayed to the
	// caller and never branched on.
	RolloutReason string
	// ExecEnabled reports whether the service has ECS Exec turned on, so that
	// [compute.ServiceSpec.ExecEnabled] can converge rather than only apply at
	// creation.
	ExecEnabled bool
	// Events are the substrate's most recent event messages, newest first.
	//
	// They are the only diagnosis ECS offers for a task that will never start —
	// an unpullable image, a subnet with no route to the registry, an
	// exhausted capacity provider — and without them a failed wait can say
	// nothing but "timed out". They are substrate-authored text, so the port
	// treats them as a diagnostic to relay and never as something to branch on.
	Events []string
	// Tags are the service's tags, including the ownership marker.
	Tags map[string]string
}

// TaskDefinitionRequest is one revision of a workload definition.
//
// It is deliberately not a copy of ECS's RegisterTaskDefinitionInput: the launch
// type, network mode and compatibility list are constants for this provider and
// live in the adapter, because they are facts about how this provider runs a
// container rather than choices a caller or the port makes.
type TaskDefinitionRequest struct {
	// Family is the task-definition family name. A new revision is registered
	// under the same family on every change.
	Family string
	// CPUUnits and MemoryMiB are the resolved Fargate task size, in ECS's own
	// vocabulary: 1024 CPU units is one vCPU.
	//
	// Already resolved, rather than the interface's millicores, because
	// choosing which discrete size a request maps to is a decision the caller
	// has to be TOLD about — [compute.Resources] requires a provider that
	// cannot honour a request exactly to round up and say so in
	// [compute.Status.Message]. A conversion buried in the adapter could not
	// produce that message. See [taskSize].
	CPUUnits  int
	MemoryMiB int
	// ExecutionRoleARN is the role the ECS agent itself assumes, to pull the
	// image and to resolve secret references. It is NOT the workload's
	// identity.
	ExecutionRoleARN string
	// TaskRoleARN is the workload's own identity — the role the process inside
	// the container assumes.
	TaskRoleARN string
	// Container is the single container definition.
	Container ContainerRequest
	// Tags are the revision's tags, including the ownership marker.
	Tags map[string]string
}

// ContainerRequest is one container inside a task definition.
type ContainerRequest struct {
	// Name is the container name.
	Name string
	// Image is the fully-qualified image reference.
	Image string
	// Ports are the container ports to expose.
	Ports []int
	// Env is the non-secret environment, sorted by name so that two
	// registrations of one spec produce identical revisions.
	Env []KeyValue
	// Secrets are secret environment variables, each naming a parameter the
	// agent resolves at task start. The value never passes through this
	// process: this carries an ARN, not material, which is the whole reason
	// secret injection is expressible without the provider reading a secret.
	Secrets []SecretReference
	// LogGroup is the log group to write to, or empty for no log configuration.
	LogGroup string
	// HealthCheck is the container-level health check, or nil.
	HealthCheck *ContainerHealthCheck
	// DockerLabels are the labels the platform's reverse proxy reads to route
	// to this container. See routes.go.
	DockerLabels map[string]string
}

// KeyValue is one non-secret environment variable.
type KeyValue struct {
	Name  string
	Value string
}

// SecretReference binds an environment variable to a stored secret by
// reference.
//
// ValueFrom is a parameter ARN that the substrate resolves at task start. This
// type is the reason [compute.ServiceSpec.Secrets] can be honoured without this
// package ever holding secret material: apphub writes the *name of the place*
// into the task definition and the substrate does the reading.
type SecretReference struct {
	// Name is the environment variable the workload sees.
	Name string
	// ValueFrom is the parameter ARN the substrate resolves.
	ValueFrom string
}

// ContainerHealthCheck is the substrate-side liveness probe.
type ContainerHealthCheck struct {
	// Command is the container health-check command.
	Command []string
	// Interval, Timeout, StartPeriod and Retries bound it.
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration
	Retries     int
}

// ServiceRequest is a create-or-update of a long-running service.
type ServiceRequest struct {
	// Cluster is the cluster the service lives in.
	Cluster string
	// Name is the service name.
	Name string
	// TaskDefinitionARN is the revision to run.
	TaskDefinitionARN string
	// DesiredCount is the instance count. Zero is legal and means paused.
	DesiredCount int
	// SubnetIDs and SecurityGroupIDs are the awsvpc network configuration.
	// They are substrate identifiers and they stop here: nothing above
	// [Substrate] holds either.
	SubnetIDs        []string
	SecurityGroupIDs []string
	// AssignPublicIP requests a public address for each task.
	AssignPublicIP bool
	// ExecEnabled turns ECS Exec on for the service.
	ExecEnabled bool
	// Tags are the service's tags, including the ownership marker. ECS applies
	// tags only on create, so the port converges them separately.
	Tags map[string]string
}

// ECSAPI is the container surface this provider uses.
//
// Every method is one AWS API call, named after it, and interprets nothing —
// the same rule the rest of [Substrate] follows.
type ECSAPI interface {
	// RegisterTaskDefinition registers a new revision and returns its ARN.
	RegisterTaskDefinition(ctx context.Context, in TaskDefinitionRequest) (string, error)

	// DescribeTaskDefinition returns a registered revision by ARN, or
	// [ErrNoSuchResource].
	//
	// It exists because [compute.ServiceStatus.Spec] has to echo the effective
	// desired state, and the task definition is where most of that state
	// actually lives: the image, the allocation, the environment and the secret
	// references are all on the revision rather than on the service. A Describe
	// that could not read it would have to return a spec containing only a
	// name, and the conformance suite is right that a spec which does not echo
	// the caller's spec can verify nothing.
	DescribeTaskDefinition(ctx context.Context, arn string) (*TaskDefinitionRequest, error)

	// DescribeService returns one service, or [ErrNoSuchResource].
	//
	// An ECS service that has been deleted is reported by the API as INACTIVE
	// rather than omitted, and a never-created one is omitted. The adapter maps
	// only the second to [ErrNoSuchResource] and reports the first as a record
	// with its Status, because the difference is one the port has to see: an
	// INACTIVE service still holds its name.
	DescribeService(ctx context.Context, cluster, name string) (*ServiceRecord, error)

	// CreateService creates one, or returns [ErrAlreadyExists].
	CreateService(ctx context.Context, in ServiceRequest) (*ServiceRecord, error)

	// UpdateService converges an existing one.
	UpdateService(ctx context.Context, in ServiceRequest) (*ServiceRecord, error)

	// SetDesiredCount changes only the instance count.
	//
	// Separate from UpdateService because [compute.ContainerRuntime.ScaleService]
	// promises to change the count "without otherwise changing the spec", and
	// an UpdateService carrying a task definition would silently roll the
	// service as a side effect of scaling it.
	SetDesiredCount(ctx context.Context, cluster, name string, count int) error

	// DeleteService removes a service. An absent one is [ErrNoSuchResource].
	DeleteService(ctx context.Context, cluster, name string) error

	// ListServiceTags reads a service's tags by ARN.
	ListServiceTags(ctx context.Context, arn string) (map[string]string, error)
	// TagService adds or replaces tags.
	TagService(ctx context.Context, arn string, tags map[string]string) error
	// UntagService removes tags by key.
	UntagService(ctx context.Context, arn string, keys []string) error
}

// RolePolicyDocument is NOT declared here any more.
//
// This port introduced it as the argument to an inline-policy write, on the
// reasoning that a name and a document travel together. USOSS-14 landed
// [RolePolicyAPI] first with flat arguments and a Get as well, and flat is what
// the SDK takes -- so the struct was one shape of the same call, and the two
// versions of PutRolePolicy could not both exist on [IAMAPI].
//
// What this port actually needed from that interface was the LISTING, which
// [RolePolicyAPI] does not carry because a [compute.Granter] writes and removes
// a grant it can name and never has to ask what else is attached. A declarative
// reconcile does: the set of policies this provider may remove has to be derived
// from the role rather than from a hand-maintained list of the ones it knows how
// to add. So [IAMAPI.ListRolePolicyNames] is the addition that survives.

// SecretParameterRef and the resolver below are the hand-off between
// [compute.SecretStore] and this port.
//
// The type itself now lives in policy.go, with the SSM-backed store that
// produces it (USOSS-26 / #19). It was declared HERE first, with a comment
// saying it was a placeholder "so that the container port compiles and is
// testable before the SSM-backed store lands" — and when that store landed the
// two declarations collided in one package, which is the loud outcome the
// placeholder was written to produce rather than a surprise. The placeholder is
// deleted rather than reconciled: both spellings were the same two fields, so
// there is nothing to converge and a second definition would only be a second
// thing to keep in step.

// SecretResolver turns [compute.SecretBinding] values into substrate ARNs, and
// says what a principal must be granted to read exactly those.
//
// # Why this is an interface rather than a direct call
//
// The container port must not read secret material, and this interface is how
// that is expressed as a type rather than as a rule. Everything it returns is
// an *address* and a *grant*; there is no method that returns a value, so no
// implementation of the container port can accidentally hold one.
//
// It is satisfied by the SSM-backed secret store (USOSS-26) through
// [Provider.SecretResolver], and [var _ SecretResolver] assertions in this
// package keep that true by construction. It said "it is satisfied by" for one
// release without either the adapter or the assertion, and the two spellings
// had already drifted -- the store's own methods take [compute.SecretBinding]
// and return a [PolicyDocument], which is neither of the shapes named here.
// Both spellings are kept: the store's are the ones its own callers and tests
// use, and the adapter is the only thing that has to know both. The two are
// separated because the grant is the store's business — it knows which actions
// reading one of its parameters requires, and whether a customer-managed key
// makes a decrypt grant necessary — while attaching that grant to the ECS
// execution role is this port's business, because this port owns that role.
// Neither half can be written correctly by the other.
type SecretResolver interface {
	// SecretParameterARNs resolves each binding, in order, reading each ARN
	// back from the substrate.
	//
	// It refuses rather than omits: a binding this provider did not issue is
	// [compute.ErrForeignRef], one naming an unconfigured placement or the
	// wrong kind is [compute.ErrInvalidSpec], and a secret that does not exist
	// is [compute.ErrNotFound]. The last one is the reason this happens here
	// rather than at task start: a missing secret becomes a spec error the
	// caller can act on instead of an opaque agent failure minutes later.
	SecretParameterARNs(ctx context.Context, bindings []SecretBindingRef) ([]SecretParameterRef, error)

	// SecretReadPolicy returns the least-privilege document granting read of
	// exactly the resolved refs, and nothing else.
	//
	// It takes resolved refs rather than bindings so that it cannot invent an
	// ARN: every resource it names came back from the substrate.
	SecretReadPolicy(refs []SecretParameterRef) (string, error)

	// SecretPlacement reports the placement the referenced secret was stored
	// for, as the resolved placement NAME.
	//
	// It exists because security/secrets-do-not-cross-placements is not
	// answerable without it. A [compute.SecretBinding] carries a
	// [compute.Ref] and nothing else, and a Ref carries {Provider, Kind, ID}
	// -- so a runtime handed a binding has no portable way to ask where the
	// secret belongs, and a workload in one placement binding a secret from
	// another produced a task definition whose valueFrom resolves to nothing
	// at launch. The store records the placement it was Put with (USOSS-26 /
	// #49); this is the seam that lets the workload's side READ it.
	//
	// It reports a fact and does not make the decision. The comparison and the
	// refusal are [containerRuntime.EnsureService]'s, for the same reason the
	// foreign-provider and wrong-kind checks are: this is a caller-supplied
	// interface, so a resolver that answered the placement question
	// permissively would turn the port's fail-closed behaviour into a property
	// of whichever resolver it was handed.
	//
	// A placement is a name an operator chose, not secret material, so this
	// does not widen what the seam can carry -- the invariant
	// [TestTheSecretSeamCannotCarryAValue] asserts by reflection still holds.
	//
	// "The placement is not recorded" is an error rather than an empty string.
	// A secret stored before the store recorded placements and a secret stored
	// for the default placement are different facts, and a consumer comparing
	// them would silently read the first as the second.
	SecretPlacement(ctx context.Context, binding SecretBindingRef) (string, error)
}

// SecretBindingRef is one binding to resolve: the variable name, and the
// reference to the stored secret.
//
// It mirrors [compute.SecretBinding] rather than using it so that this seam
// carries no dependency in the direction that would let a secret store reach
// back into the compute types it is being called from.
type SecretBindingRef struct {
	// EnvName is the environment variable the workload sees.
	EnvName string
	// Provider, Kind and ID are the reference to the stored secret, flattened
	// so the resolver can validate each part and say which one is wrong.
	Provider string
	Kind     string
	ID       string

	// Version is the revision [compute.SecretBinding.Version] pinned, empty
	// when it pinned none. Opaque: this port passes it through and never parses
	// it, because what a revision looks like is the store's business.
	//
	// IT IS ON THIS SEAM BECAUSE ITS ABSENCE WAS A SILENT UNPINNING. USOSS-35
	// added the field to [compute.SecretBinding] and taught the SSM store to
	// honour it; this type flattens a binding for the resolver and did not
	// carry it, so every pin a caller set was dropped between the port and the
	// store it was meant to reach. The workload then followed the latest value
	// while the caller believed it was pinned -- which is the exact degradation
	// the field was added to close, reintroduced one layer up.
	//
	// Nothing about the container port made the pin unsupportable: an SSM
	// parameter ARN takes a ":<revision>" selector, and an ECS valueFrom takes
	// that ARN, so honouring it is a matter of not discarding it.
	Version string
}
