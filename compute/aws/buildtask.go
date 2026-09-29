// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"time"
)

// This file is the substrate surface a build task needs, and nothing else.
//
// # Why this is not more methods on ECSAPI
//
// [ECSAPI] is the *service* surface: register a revision, create, converge and
// scale a long-lived service. A build is the opposite shape — one task, run
// once, watched to completion, and then gone — and the two share only the word
// "task". Putting RunTask on [ECSAPI] would oblige [MemoryECS], which exists to
// fake service convergence for the container port's tests, to implement calls it
// has no business with.
//
// It is the same reasoning [ImagePusher] is a second port rather than a second
// method on [BuildRunner]: one interface with one shape is one concern.

// BuildTaskConfig configures the ECS-backed [BuildTaskRunner].
//
// Nil on [BuildConfig] means this provider has no way to run a build, and
// [LoadConfig] refuses rather than falling back to running the builder as a
// subprocess of apphub — which is the construction [ExecRunner] represents and
// which the hosted path forbids by type (see validateHostedRunner).
type BuildTaskConfig struct {
	// Cluster is the ECS cluster build tasks run in. Required.
	//
	// It may be the same cluster deployed applications run in. The isolation
	// that matters is not the cluster: it is that the task definitions below
	// carry no task role and that the security groups below reach nothing in
	// the VPC.
	Cluster string `yaml:"cluster" json:"cluster"`

	// TaskDefinitions are the build task definitions, one per concurrency slot.
	// Required, and at least one.
	//
	// One per slot rather than one shared definition, because each is bound to
	// its own EFS access point and an access point is what confines a build to
	// its own directory. A single definition mounting a shared root would let
	// one build read and write another's context, which is the cross-build
	// path this whole arrangement exists to close.
	//
	// The number of them is the runner's concurrency limit. It must be at least
	// worker.maxConcurrentDeployments or builds queue behind a free slot; that
	// is a delay, never a failure.
	TaskDefinitions []string `yaml:"taskDefinitions" json:"taskDefinitions"`

	// ContainerName is the container in each task definition whose command is
	// overridden with the builder invocation. Required.
	ContainerName string `yaml:"containerName" json:"containerName"`

	// Subnets are the subnets a build task is placed in. Required.
	//
	// Private ones: a build task is given no public address, and its egress to
	// the public internet is whatever the subnet's route table provides. A
	// build that cannot reach a package mirror fails honestly; a build that can
	// reach the control plane is the thing being prevented.
	Subnets []string `yaml:"subnets" json:"subnets"`

	// SecurityGroups are the groups a build task runs with. Required.
	//
	// This is the network boundary, and it is the one that replaced an
	// operator's assertion with the substrate's own enforcement. Nothing in the
	// VPC accepts traffic from these groups unless an operator has written a
	// rule saying so, so the control plane, the state store and every deployed
	// application are unreachable by construction rather than by a firewall
	// rule somebody remembered to install.
	SecurityGroups []string `yaml:"securityGroups" json:"securityGroups"`

	// SlotSecurityGroups is one NFS egress security group per task definition.
	// Entry N may reach only slot N's EFS mount targets; SecurityGroups above
	// provides the common network posture. Missing or mismatched entries must
	// fail before a build launches, not fall back to the shared network group.
	SlotSecurityGroups []string `yaml:"slotSecurityGroups" json:"slotSecurityGroups"`

	// SharePath is where the worker sees the directory holding every build
	// slot, an absolute directory. Required.
	//
	// One subdirectory per slot, named by its number: the worker's access point
	// is rooted at the same directory each slot access point is rooted one
	// level inside, so slot N is SharePath/N here and [Config.SlotPath] there.
	// The two have to name the same directory or a build reads an empty
	// context.
	//
	// The runner writes each build's context under it and reads each build's
	// output back out of it. See [BuildTaskRunner] for why a shared filesystem
	// and not a signed URL.
	SharePath string `yaml:"sharePath" json:"sharePath"`

	// SlotPath is where a build task sees its own slot, an absolute directory.
	// Required.
	//
	// It is one path rather than one per slot because each task definition
	// mounts its own access point at the same place: a build cannot tell which
	// slot it is in, and has no name for any other.
	SlotPath string `yaml:"slotPath" json:"slotPath"`

	// LogGroup and LogStreamPrefix name where the builder's output lands, and
	// must match the awslogs configuration on the task definitions. Required.
	//
	// The runner reads it back and writes it to the caller's log writer.
	// [compute.BuildRequest.Logs] is the channel the interface documents for
	// builder output, and a runner that produced none would fail conformance's
	// logs-receive-the-builder-output check — correctly, since an operator
	// debugging a failed build has nothing else to read.
	LogGroup        string `yaml:"logGroup" json:"logGroup"`
	LogStreamPrefix string `yaml:"logStreamPrefix" json:"logStreamPrefix"`

	// Timeout bounds one build, from RunTask to the task reaching STOPPED. Zero
	// means [DefaultBuildTaskTimeout].
	//
	// It bounds repository-authored work, so it is generous rather than tight;
	// the durable deployment timeout above it is what an operator tunes.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// PollInterval is how often the runner re-reads the task and its logs. Zero
	// means [DefaultBuildTaskPollInterval].
	PollInterval time.Duration `yaml:"pollInterval" json:"pollInterval"`
}

// The build task defaults.
const (
	// DefaultBuildTaskTimeout bounds one build task. Forty-five minutes is long
	// enough for a large multi-stage build on a cold cache -- and this path has
	// no layer cache at all (USOSS-41) -- and short enough that a wedged build
	// releases its slot the same working day.
	DefaultBuildTaskTimeout = 45 * time.Minute

	// DefaultBuildTaskPollInterval is how often a running task is re-read.
	//
	// Five seconds rather than one: DescribeTasks and GetLogEvents are both
	// throttled per account, and a provider polling every second on behalf of
	// several concurrent builds spends its own rate limit on latency nobody
	// perceives in a build measured in minutes.
	DefaultBuildTaskPollInterval = 5 * time.Second

	// buildSlotOutputDir is where a build's outputs land inside its slot. Its
	// sibling is "context", written by the runner and read by the builder; see
	// copyContext for why the context crosses as a tree rather than an archive.
	buildSlotOutputDir = "out"
)

// BuildTaskRequest is one build task launch.
//
// **It has no environment field, and that absence is deliberate.** USOSS-41's
// rule is that the phase which executes repository-authored code cannot be
// handed anything, and a struct with nowhere to put an environment variable is
// a struct no later edit can quietly start putting a credential in.
// [BuildCommand.Env] is therefore not forwarded -- the same choice the
// container-backed runner made by ignoring it.
type BuildTaskRequest struct {
	// Cluster is the cluster to run in.
	Cluster string
	// TaskDefinition is the revision to run, a family name or an ARN.
	TaskDefinition string
	// ContainerName is the container whose command is overridden.
	ContainerName string
	// Command is the argv appended to the image entrypoint (kaniko flags).
	// ECS command overrides replace CMD, not ENTRYPOINT; the task definition
	// already sets entryPoint to /kaniko/executor.
	Command []string
	// Subnets and SecurityGroups are the awsvpc network configuration. A build
	// task is never given a public address.
	Subnets        []string
	SecurityGroups []string
	// StartedBy is an opaque marker recorded on the task, so an operator
	// looking at a cluster can tell which builds are apphub's.
	StartedBy string
}

// BuildTaskRecord is one task's observed state.
//
// Every field is AWS's own text. None of it is repository-authored: a container's
// exit code is the substrate's, and StoppedReason is ECS's explanation of why it
// stopped. That is what makes it safe to write to the caller's log; the
// builder's own output travels the log channel instead, and neither reaches a
// returned error. See [BuildRunner] for the obligation.
type BuildTaskRecord struct {
	// ARN identifies the task.
	ARN string
	// LastStatus is ECS's lifecycle state: PROVISIONING, PENDING, RUNNING,
	// DEACTIVATING, STOPPING, DEPROVISIONING or STOPPED.
	LastStatus string
	// StopCode and StoppedReason are why it stopped, when it has.
	StopCode      string
	StoppedReason string
	// Containers is per-container status.
	Containers []BuildTaskContainerStatus
}

// Stopped reports whether the task has reached its terminal state.
func (r BuildTaskRecord) Stopped() bool { return r.LastStatus == "STOPPED" }

// BuildTaskContainerStatus is one container's outcome.
type BuildTaskContainerStatus struct {
	// Name is the container's name in the task definition.
	Name string
	// ExitCode is its exit status, or nil when it never ran or is still
	// running. Nil is not zero, and conflating them is how a task that failed
	// to start reads as a successful build that wrote nothing.
	ExitCode *int
	// Reason is AWS's explanation when there is no exit code.
	Reason string
}

// BuildTaskDefinition is what [BuildTaskRunner.Validate] needs to read back
// about a registered revision.
//
// Deliberately not [TaskDefinitionRequest]: that type is the container port's
// round-trip shape for converging a *service*, and it carries neither the
// network mode nor the volumes, which are two of the four things worth
// asserting here.
type BuildTaskDefinition struct {
	// ARN is the revision's ARN.
	ARN string
	// TaskRoleARN is the workload identity the task runs with.
	//
	// For a build task it MUST be empty, and that single fact is what the whole
	// arrangement rests on. On Fargate every container in a task shares one
	// network namespace, so the task metadata credentials endpoint is reachable
	// from the container executing the Dockerfile: a task role is a credential
	// a RUN instruction can read, whichever container it was meant for.
	TaskRoleARN string
	// NetworkMode must be awsvpc, which is what gives the task its own ENI and
	// therefore its own security groups.
	NetworkMode string
	// EphemeralStorageGiB is the task's scratch space. kaniko unpacks every
	// layer of the image it is building into it.
	EphemeralStorageGiB int
	// Containers are the declared containers, by name and image.
	Containers []BuildTaskDefinitionContainer
	// Volumes are the declared volumes.
	Volumes []BuildTaskVolume
}

// BuildTaskDefinitionContainer is one declared container.
type BuildTaskDefinitionContainer struct {
	Name  string
	Image string
}

// BuildTaskVolume is one declared volume. Only the EFS shape is described,
// because it is the only one a build task may have: an ephemeral volume would
// not reach the worker, and a host bind mount does not exist on Fargate.
type BuildTaskVolume struct {
	// Name is the volume's name in the task definition.
	Name string
	// FileSystemID is the EFS file system, empty for a non-EFS volume.
	FileSystemID string
	// AccessPointID is the access point the volume is mounted through. Empty
	// means the file system root, which is refused: an access point's root
	// directory is what confines a build to its own slot.
	AccessPointID string
	// TransitEncryption reports whether the mount is encrypted in flight.
	TransitEncryption bool
}

// BuildTaskAPI runs one build task and watches it.
//
// Every method is one AWS API call, named after it, and interprets nothing --
// the same rule [ECSAPI] and the rest of [Substrate] follow. The waiting, the
// polling and the decision about what a non-zero exit means all live in
// [BuildTaskRunner], above this line.
type BuildTaskAPI interface {
	// RunTask launches one task and returns its ARN.
	RunTask(ctx context.Context, in BuildTaskRequest) (string, error)
	// ListBuildTasks returns tasks in this slot's task-definition family whose
	// lastStatus is not STOPPED, across revisions and both ECS desired statuses.
	// A STOPPING task still owns its slot. Errors or incomplete ECS reads must
	// fail closed so a lease is not reused while a task can still write to EFS.
	ListBuildTasks(ctx context.Context, cluster, taskDefinition string) ([]string, error)
	// DescribeTask returns one task's state, or [ErrNoSuchResource].
	DescribeTask(ctx context.Context, cluster, taskARN string) (*BuildTaskRecord, error)
	// StopTask asks ECS to stop a task. Stopping an already-stopped task is not
	// an error: cleanup runs on a path where the task's state is unknown.
	StopTask(ctx context.Context, cluster, taskARN, reason string) error
	// DescribeBuildTaskDefinition reads back a registered revision, or returns
	// [ErrNoSuchResource].
	DescribeBuildTaskDefinition(ctx context.Context, taskDefinition string) (*BuildTaskDefinition, error)
}

// BuildLogEvent is one line the builder wrote.
type BuildLogEvent struct {
	// Timestamp is when the builder emitted it.
	Timestamp time.Time
	// Message is the line, exactly as written. It is repository-authored: a
	// Dockerfile RUN instruction prints whatever it likes, so this reaches the
	// caller's log writer and never a returned error.
	Message string
}

// BuildLogAPI reads the builder's output back.
//
// Narrow on purpose, and separate from [github.com/conductorone/apphub/internal/logs]:
// that package is the serve process's read-only viewer over operator-named log
// groups, scoped and justified as exactly that. A provider tailing one stream
// of its own build is a different caller with a different lifetime, and
// widening the other package to serve both would widen the one the API process
// holds.
type BuildLogAPI interface {
	// GetLogEvents reads forward from token, oldest first. It returns the
	// events read and the token to pass next; an unchanged token means nothing
	// new has arrived yet. A stream that does not exist yet is not an error:
	// awslogs creates it when the container first writes, which may be well
	// after the task starts.
	GetLogEvents(ctx context.Context, group, stream, token string) ([]BuildLogEvent, string, error)
}

func (c *BuildTaskConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultBuildTaskTimeout
	}
	return c.Timeout
}

func (c *BuildTaskConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return DefaultBuildTaskPollInterval
	}
	return c.PollInterval
}
