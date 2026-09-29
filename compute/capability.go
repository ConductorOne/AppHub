// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import "sort"

// Capability names one thing a provider either can or cannot do.
//
// The set is deliberately small and coarse. A capability is not a feature flag
// for a knob on a spec — it is a whole port, or a whole class of behaviour that
// a substrate may structurally lack. "Can this provider run containers at all"
// is a capability; "does this provider support 4 GiB of memory" is a validation
// error on a spec.
//
// Capabilities exist so that a non-AWS provider's inability is a fact the
// caller can discover and act on, rather than a call that fails deep inside an
// implementation with a message about a service the caller never heard of.
type Capability string

const (
	// CapImageRegistry is the ability to host container image repositories the
	// provider's own runtimes can pull from. Replaces ECR repository management
	// (build.go:282-433).
	CapImageRegistry Capability = "image-registry"

	// CapImageBuild is the ability to turn a source tree into a pushed image.
	// Separate from CapImageRegistry on purpose: a Kubernetes provider is
	// likely to build with the same tool (kaniko, buildkit) while pushing to
	// somebody else's registry. Replaces the kaniko subprocess and its scoped
	// push credentials (build.go:453-578, kaniko_creds.go).
	CapImageBuild Capability = "image-build"

	// CapContainerService is the ability to run an image as a long-lived,
	// replicated service. Replaces the ECS service path (source system @
	// backend/internal/modules/deploy/container.go).
	CapContainerService Capability = "container-service"

	// CapScheduledJob is the ability to run a container on a cron schedule.
	// Separate from CapContainerService because a substrate can plausibly have
	// one without the other. Replaces EventBridge Scheduler (source system @
	// backend/internal/modules/deploy/container.go).
	CapScheduledJob Capability = "scheduled-job"

	// CapWorkloadExec is the ability to make a running instance reachable for an
	// interactive operator session. Replaces the ssmmessages grant that makes a
	// task ECS-Exec-able (build.go:670-697).
	//
	// The interface exposes it as [ServiceSpec.ExecEnabled], not as a method and
	// not as a [WorkloadCapability]: apphub makes the target reachable, it does
	// not proxy the session and it does not decide who may open one. Authorising
	// the operator's principal is a control-plane concern outside this
	// interface.
	CapWorkloadExec Capability = "workload-exec"

	// CapFunction is the ability to run a code bundle as an invocable function.
	// Replaces the Lambda path (lambda.go:194-290).
	CapFunction Capability = "function"

	// CapFunctionEndpoint is the ability to put a function behind a stable
	// public hostname. Replaces the ALB / target-group / listener path
	// (lambda.go:392-734).
	CapFunctionEndpoint Capability = "function-endpoint"

	// CapObjectStore is the ability to provision general-purpose object
	// storage. Replaces s3.CreateBucket and its hardening calls
	// (bucket.go:217-288).
	CapObjectStore Capability = "object-store"

	// CapObjectStoreZonal is the ability to provision object storage pinned to
	// a single availability zone for latency. Replaces S3 Express One Zone
	// directory buckets (bucket.go:290-336). It is a capability rather than an
	// ext port because the application-facing contract is identical to
	// [ObjectClassStandard] — same API, same binding — and only the placement
	// differs. A provider without it must not silently fall back to standard:
	// the caller asked for a latency guarantee.
	CapObjectStoreZonal Capability = "object-store-zonal"

	// CapRelationalDatabase is the ability to provision a managed
	// SQL endpoint. Replaces the Aurora path (source system @
	// backend/internal/modules/deploy/database.go).
	CapRelationalDatabase Capability = "relational-database"

	// CapKeyValueTable is the ability to provision a managed key-value table.
	// Replaces the DynamoDB path (source system @
	// backend/internal/modules/deploy/database.go).
	CapKeyValueTable Capability = "key-value-table"

	// CapSecretStore is the ability to store named secret material and bind it
	// into a workload without the value passing through apphub's own memory at
	// launch time. Replaces SSM Parameter Store plus the ECS Secrets ValueFrom
	// mechanism (source system @ backend/internal/modules/deploy/container.go
	// and postgres_roles.go).
	CapSecretStore Capability = "secret-store"

	// CapPlatformIngress is the ability to name the platform's reverse proxy as
	// a reachability peer — a [PeerPlatformIngress] rule, or a [Route].
	//
	// It is configuration-derived rather than implementation-derived: the same
	// provider code has it when an operator has told it where the ingress proxy
	// is and lacks it when they have not. That is the case
	// [Provider.Capabilities] already covers with "may legitimately differ
	// between two instances of the same implementation". Without the constant,
	// a caller discovers a proxy-less platform when EnsureService fails, and the
	// fail-closed refusal that replaced the source system's silent widening to
	// 0.0.0.0/0 becomes undiscoverable rather than merely strict.
	CapPlatformIngress Capability = "platform-ingress"

	// CapIngressAuth is the ability of that ingress to authenticate a request
	// before forwarding it — [Route.RequireAuth]. Separate from
	// [CapPlatformIngress] because an ingress that routes is common and one that
	// can also enforce authentication is not: most controllers can (nginx
	// auth-url, Traefik ForwardAuth) but a provider whose ingress cannot must
	// fail the spec rather than route unauthenticated traffic to a workload that
	// asked not to receive it.
	CapIngressAuth Capability = "ingress-auth"

	// CapMCPAuth is the ability to protect only a route's /mcp endpoint with
	// the platform OAuth server while serving MCP protected-resource discovery
	// on the application's own hostname — [Route.MCPAuthApplicationID].
	//
	// It is separate from [CapIngressAuth]: generic whole-route authentication
	// does not imply that an ingress can install app-specific OAuth discovery,
	// preserve the MCP audience, inject verified identity, and strip the bearer
	// credential before forwarding it.
	CapMCPAuth Capability = "mcp-auth"

	// CapWorkloadGrants is the ability to authorise the workload identities this
	// provider issues against the resources it provisions — every [Granter]
	// method on every port that has one.
	//
	// It exists because the [Granter] rule is about what a substrate *can*
	// express while a deployment may still be configured without it. An
	// S3-compatible object store authorises by identity when it federates the
	// platform's issuer and cannot when it does not; the port keeps its Granter
	// either way, and this capability is how a caller learns which it is
	// dealing with before it provisions something it will not be able to grant
	// access to.
	//
	// A provider advertising it must be able to grant on every Granter port it
	// vends. One that can grant on some but not others must not advertise it and
	// must return [ErrUnsupported] from every Grant — a conservative answer, and
	// deliberately so: a caller that is told grants work and then finds they work
	// on one port is worse off than one told nothing works.
	CapWorkloadGrants Capability = "workload-grants"

	// CapImagePullGrants is the ability to authorise an image pull to a workload
	// identity — [ImagePullGranter].
	//
	// Most registries cannot: they authenticate a robot account or an IAM
	// principal, and on ECS the principal that pulls is the task execution role
	// rather than the workload. At least one substrate can, through the
	// Kubernetes kubelet credential provider's pod-bound ServiceAccount token.
	// That unevenness is exactly what a capability is for, and asserting the
	// impossibility instead was the mistake this constant corrects.
	//
	// Absent, a caller still gets the [ImageRegistry] obligation: a workload can
	// pull the image its spec names. Present, a caller can additionally
	// authorise a specific identity against a specific repository.
	CapImagePullGrants Capability = "image-pull-grants"

	// CapModelInference is the ability to grant a workload access to a managed
	// foundation-model inference service. Replaces the Bedrock inline policy
	// (build.go:715-779). A provider that has no such service does not have
	// this capability, and a spec that requests it fails loudly rather than
	// deploying a workload that will get an authorization error at runtime.
	CapModelInference Capability = "model-inference"
)

// AllCapabilities returns every capability this package defines, sorted.
//
// It exists so a caller — a support matrix in the public documentation, an
// admin UI, a conformance check driving the capabilities a provider does *not*
// advertise — can enumerate the population instead of restating it. A
// restatement of a set drifts from the set, so this one does not stand on its
// own: [TestAllCapabilitiesMatchesTheConstBlock] parses this file with go/ast,
// collects every constant declared with type [Capability], and fails unless the
// two sets are equal and non-empty. Adding a constant without adding it here is
// a red build.
//
// The returned slice is freshly allocated, so a caller may sort or filter it
// without affecting anybody else.
func AllCapabilities() []Capability {
	out := []Capability{
		CapImageRegistry,
		CapImageBuild,
		CapContainerService,
		CapScheduledJob,
		CapWorkloadExec,
		CapFunction,
		CapFunctionEndpoint,
		CapObjectStore,
		CapObjectStoreZonal,
		CapRelationalDatabase,
		CapKeyValueTable,
		CapSecretStore,
		CapPlatformIngress,
		CapIngressAuth,
		CapMCPAuth,
		CapWorkloadGrants,
		CapImagePullGrants,
		CapModelInference,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CapabilitySet is the set of capabilities a provider implements. The zero
// value is a valid empty set.
type CapabilitySet map[Capability]struct{}

// NewCapabilitySet returns a set containing caps.
func NewCapabilitySet(caps ...Capability) CapabilitySet {
	s := make(CapabilitySet, len(caps))
	for _, c := range caps {
		s[c] = struct{}{}
	}
	return s
}

// Has reports whether the set contains c.
func (s CapabilitySet) Has(c Capability) bool {
	_, ok := s[c]
	return ok
}

// List returns the capabilities in the set, sorted, for stable output in logs,
// admin UIs, and conformance-test failure messages.
func (s CapabilitySet) List() []Capability {
	out := make([]Capability, 0, len(s))
	for c := range s {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
