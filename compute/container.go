// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"
	"time"
)

// Resources is the compute allocation for one workload instance.
//
// Millicores and mebibytes, not the substrate's units. The source system passes
// ECS CPU units and a memory string (source system @
// backend/internal/modules/deploy/container.go); a thousand
// millicores is one core everywhere, and a provider maps to whatever discrete
// sizes it offers.
//
// A provider that cannot honour the request exactly must round *up* and say so
// in [Status.Message], or return [ErrInvalidSpec] if it cannot even do that.
// Rounding down is never acceptable: it turns a capacity decision into a
// silent, intermittent out-of-memory failure at runtime.
//
// One allocation, not a request/limit pair. Fargate has one — a task is sized
// and that is what it gets — so there was nothing in the source system to model
// a range from. The consequence on a substrate that distinguishes them is that
// requests and limits are equal, which on Kubernetes means every workload lands
// in Guaranteed QoS: predictable, and more expensive than a burstable workload
// needs to be. Recorded as a concession rather than fixed, because a second
// field with no call site would be a guess at what callers want to burst to.
type Resources struct {
	// CPUMillicores is the CPU allocation. 1000 = one core.
	CPUMillicores int
	// MemoryMiB is the memory allocation in mebibytes.
	MemoryMiB int
}

// EnvVar is a non-secret environment variable.
//
// Non-secret is enforced by convention plus the existence of [SecretBinding]:
// anything sensitive goes there, so that it is never written into a task
// definition, a pod spec, or a deploy log. A provider must not accept a value
// here and store it encrypted "to be helpful" — the caller chose the visible
// channel and downstream tooling will treat it as visible.
type EnvVar struct {
	// Name is the variable name.
	Name string
	// Value is the value.
	Value string
}

// HealthCheck is how the substrate decides an instance is serving.
//
// It exists because [ContainerRuntime.WaitForService] promises instances that
// are *serving* and, without this, only the provider knew what that meant.
type HealthCheck struct {
	// Path is an HTTP GET path that must answer 2xx. Empty means a TCP connect
	// to Port is enough.
	Path string
	// Port is the port to probe. Zero means the workload's first port.
	Port int
	// InitialDelay is how long to wait before the first probe. Zero means the
	// provider's default.
	InitialDelay time.Duration
	// Period is the interval between probes. Zero means the provider's default.
	Period time.Duration
	// Timeout bounds one probe. Zero means the provider's default.
	Timeout time.Duration
	// FailureThreshold is how many consecutive failures make an instance not
	// serving. Zero means the provider's default.
	FailureThreshold int
}

// PortSpec is a port the workload listens on.
type PortSpec struct {
	// Number is the container port.
	Number int
	// Protocol defaults to [ProtocolTCP] when empty.
	Protocol Protocol
	// Name optionally labels the port for a [Route] to target by name rather
	// than number.
	Name string
}

// ServiceSpec is the desired state of a long-running replicated workload.
//
// It is complete: what is here is what the workload will have, and a field left
// empty means "none", not "leave whatever was there". That is what makes
// [ContainerRuntime.EnsureService] safely re-runnable, and it is why grants
// like [WorkloadCapability] are revoked by omission.
type ServiceSpec struct {
	// Name is the logical service name, stable across deploys. The provider
	// sanitises it for its own naming rules; the same Name must always produce
	// the same physical resource, because that determinism is what lets a
	// redeploy find what the last deploy created.
	Name string

	// Placement says where to run it.
	Placement Placement

	// Image is what to run.
	Image ImageRef

	// Resources is the per-instance allocation.
	Resources Resources

	// Replicas is the desired instance count. Zero is legal and means paused —
	// the workload's definition and network identity persist, nothing runs.
	// That is how an application is paused and resumed without teardown.
	Replicas int

	// Ports are the ports the container listens on.
	Ports []PortSpec

	// Env are non-secret environment variables.
	Env []EnvVar

	// Secrets are secret environment variables, resolved by the runtime at
	// launch from the provider's own [SecretStore].
	Secrets []SecretBinding

	// Identity is the [WorkloadIdentity] the instances run as. Required: a
	// workload with no identity cannot be granted resource access, and a
	// provider must reject the spec rather than fall back to an ambient
	// credential.
	Identity Ref

	// Capabilities are platform-level grants to the workload's own identity.
	// Declarative: omitting one that was previously granted revokes it.
	Capabilities []WorkloadCapability

	// Readiness decides when an instance counts toward
	// [ContainerRuntime.WaitForService]'s minReady.
	//
	// Nil means the provider's default, which a provider MUST document, because
	// "serving" otherwise means a different thing on every substrate: a
	// Kubernetes pod with no readiness probe is Ready as soon as its container
	// starts, while an AWS service behind a target group is not until a health
	// check passes. A deploy that waits for readiness and then shifts traffic
	// behaves differently on the two, and the difference is invisible to the
	// caller.
	Readiness *HealthCheck

	// ExecEnabled makes running instances reachable for an interactive
	// operator session. Requires [CapWorkloadExec].
	//
	// It requests reachability; it does not promise that false prevents it. On
	// some substrates a pod is exec-able whenever the *caller's* authorisation
	// permits it and there is nothing a provider can put on the workload to
	// change that, so false is silently a no-op there. A provider MUST document
	// which of the two states it can actually enforce. A caller that sets it
	// false believing it has closed something may not have.
	//
	// This is runtime operability, not a workload-identity capability, and the
	// distinction is a security one rather than a taxonomic one. The principal
	// that opens a shell is the *operator*, not the workload. Modelling exec as
	// something granted to the workload's identity gets that backwards, and the
	// backwards version is not merely useless — on Kubernetes, RBAC on
	// pods/exec authorises the caller, so granting it to the target Pod's own
	// ServiceAccount would let the workload exec into pods while still not
	// letting an operator exec into the workload. The generalisation was
	// tempting because ECS needs ssmmessages permissions on the *task* role
	// (build.go:670-697), but that is one substrate's mechanism for making the
	// target reachable, not evidence about who the caller is.
	//
	// So this field expresses only the target half: make this workload
	// available for interactive sessions. Authorising which operators may open
	// one is a control-plane concern — an IAM policy or an RBAC binding on the
	// operator's principal — configured by the operator alongside the provider
	// and deliberately outside this interface. A provider must not widen the
	// workload's own identity to satisfy this field beyond what the substrate
	// requires of the target.
	ExecEnabled bool

	// Ingress is the complete set of inbound reachability rules. Reconciled to
	// exactly this set on every Ensure.
	Ingress []IngressRule

	// Routes make the service reachable at hostnames through the platform's
	// ingress.
	Routes []Route

	// Labels are non-secret metadata: ownership tagging, and correlation
	// identifiers the platform needs to map a running workload back to the
	// application that owns it.
	Labels map[string]string
}

// ServiceStatus is the observed state of a service.
type ServiceStatus struct {
	Status

	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec ServiceSpec

	// RouteAddresses are the addresses the platform's ingress answers on for
	// this service's [Route]s, empty until known.
	//
	// DNS is a non-goal of this interface, but a caller that cannot learn the
	// address cannot delegate DNS either — and on Kubernetes an Ingress does
	// nothing at all until a record points at the controller, an address the
	// provider can read and previously had nowhere to put. [EndpointStatus]
	// reports a hostname for the function case; this is the same courtesy for
	// the service case.
	RouteAddresses []string

	// DesiredReplicas is what the provider is targeting.
	DesiredReplicas int
	// ReadyReplicas is how many instances are currently serving.
	ReadyReplicas int
	// Revision identifies the deployed version of the spec. It changes when the
	// effective configuration changes and is stable when it does not, so a
	// caller can tell a real rollout from a no-op Ensure. Opaque.
	Revision string
}

// Schedule is when a scheduled job runs.
type Schedule struct {
	// Expression is a cron expression in the five-field POSIX form, or a rate
	// expression of the form "rate(<n> <unit>)". The source system passes the
	// operator's string straight through to EventBridge Scheduler (source system
	// @ backend/internal/modules/deploy/container.go); pinning a syntax here
	// against a stated grammar and translates, rather than each substrate
	// accepting a different dialect of "cron".
	Expression string
	// Timezone is an IANA timezone name. Empty means UTC.
	Timezone string
	// Paused suspends the schedule without deleting it.
	Paused bool
}

// ScheduledJobSpec is the desired state of a workload that runs on a cadence
// rather than continuously.
//
// It carries a full workload definition rather than referencing a service,
// because the two are not the same object on most substrates and coupling them
// would force a provider to keep a paused service around purely as a template.
type ScheduledJobSpec struct {
	// Name is the logical job name, stable across deploys.
	Name string
	// Schedule is when to run.
	Schedule Schedule
	// Placement says where to run it.
	Placement Placement
	// Image is what to run.
	Image ImageRef
	// Resources is the per-run allocation.
	Resources Resources
	// Env are non-secret environment variables.
	Env []EnvVar
	// Secrets are secret environment variables.
	Secrets []SecretBinding
	// Identity is the [WorkloadIdentity] each run assumes. Required.
	Identity Ref
	// Capabilities are platform-level grants to the run's own identity.
	Capabilities []WorkloadCapability
	// Ingress is the reachability rule set for each run. Usually empty: a
	// scheduled job that nothing connects to needs none.
	Ingress []IngressRule
	// Labels are non-secret metadata.
	Labels map[string]string
}

// ScheduledJobStatus is the observed state of a scheduled job.
//
// It is a descriptor, not a phase-bearing status, because this port is in the
// synchronous class — see [Status]. A cron entry is live the moment the
// substrate accepts it: no controller writes a readiness condition for a
// Kubernetes CronJob, and the source system creates its EventBridge schedule
// with no polling loop (source system @
// backend/internal/modules/deploy/container.go), unlike every genuinely
// asynchronous path it has. The port was in the asynchronous class with no Wait
// method, which left three conformance invariants unverifiable; adding
// WaitForScheduledJob would have been a method that exists to satisfy a
// taxonomy and returns immediately on every substrate anybody has named.
type ScheduledJobStatus struct {
	// Ref addresses the scheduled job.
	Ref Ref
	// Spec is the effective desired state, as the provider understood it.
	Spec ScheduledJobSpec
	// Schedule is the schedule currently in effect.
	Schedule Schedule
}

// ContainerRuntime runs container images.
//
// # What is deliberately absent
//
// No task definition, no revision registration, no cluster ARN, no launch type,
// no network mode, no execution-role-versus-task-role distinction, no public-IP
// assignment, no log-driver configuration. Every one of those appears in the
// call it replaces (source system @ backend/internal/modules/deploy/container.go)
// and every one is a fact
// about ECS rather than about running a container. They become provider
// configuration attached to a [Placement], or provider-internal detail.
//
// # Sketch: how a Kubernetes provider satisfies this
//
// EnsureService writes a Deployment (image, resources, replicas, env,
// secretKeyRef bindings, the Identity's ServiceAccount) plus a Service, plus a
// NetworkPolicy compiled from Ingress, plus an Ingress object per Route, and
// returns immediately with [PhasePending]. WaitForService watches the
// Deployment's readyReplicas. ScaleService patches spec.replicas.
// EnsureScheduledJob writes a CronJob, live on acceptance. ExecEnabled is close
// to a no-op, since a
// Pod is exec-able whenever the *caller's* RBAC permits it, which is a
// control-plane binding the provider does not own.
// WorkloadCapabilityModelInference has no Kubernetes equivalent, so a plain
// Kubernetes provider does not advertise [CapModelInference] and rejects a spec
// requesting it — which is the intended outcome, and visible rather than
// silent.
type ContainerRuntime interface {
	// EnsureService creates or updates a service. Idempotent. Returns without
	// waiting for readiness; see [Status].
	EnsureService(ctx context.Context, spec ServiceSpec) (*ServiceStatus, error)

	// DescribeService returns current state. A deleted or never-created service
	// is reported as [PhaseGone], not as an error, so reconciliation and
	// teardown do not have to distinguish the two.
	DescribeService(ctx context.Context, ref Ref) (*ServiceStatus, error)

	// WaitForService blocks until at least minReady instances are serving, the
	// service fails, or the wait deadline elapses ([ErrTimeout]).
	WaitForService(ctx context.Context, ref Ref, minReady int, opts WaitOptions) (*ServiceStatus, error)

	// ScaleService sets the desired instance count without otherwise changing
	// the spec. Zero pauses.
	ScaleService(ctx context.Context, ref Ref, replicas int) error

	// DeleteService removes a service. Idempotent; deleting an absent service
	// returns nil. It does not delete the workload identity, secrets, or data
	// resources the service used: those have their own lifetimes and their own
	// owners.
	DeleteService(ctx context.Context, ref Ref) error

	// EnsureScheduledJob creates or updates a scheduled job. Requires
	// [CapScheduledJob].
	EnsureScheduledJob(ctx context.Context, spec ScheduledJobSpec) (*ScheduledJobStatus, error)

	// DescribeScheduledJob returns an existing scheduled job, or [ErrNotFound].
	DescribeScheduledJob(ctx context.Context, ref Ref) (*ScheduledJobStatus, error)

	// DeleteScheduledJob removes a scheduled job. Idempotent.
	DeleteScheduledJob(ctx context.Context, ref Ref) error
}
