// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"
	"io"
	"time"
)

// ImageRef addresses a container image a runtime can pull.
//
// It is a string because that is what the ecosystem standardised on: a
// registry-qualified reference with a tag or digest. Nothing in this interface
// parses it. The source system does parse it — a regexp over
// "<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>" to recover the region
// and build ECR repository ARNs (kaniko_creds.go:26-63) — and that parsing is
// exactly the provider-internal work the boundary is here to contain.
type ImageRef string

// RetentionPolicy bounds how much a repository accumulates.
//
// Two shapes, because the source system needs both and for different reasons:
// application images are pruned by count ("keep last 20", build.go:320-336) and
// build-cache layers by age ("expire after 14 days", build.go:392-406, because
// each cached layer is its own image and a count-based rule evicts live cache
// entries after two builds). Both map onto any registry with a lifecycle
// feature; a registry with none must return [ErrUnsupported] rather than accept
// a policy it will not apply and grow without bound.
type RetentionPolicy struct {
	// KeepLast retains the N most recently pushed images. Zero means no
	// count-based rule.
	KeepLast int
	// MaxAge expires images older than this. Zero means no age-based rule.
	MaxAge time.Duration
}

// RepositorySpec describes an image repository.
type RepositorySpec struct {
	// Name is the logical repository name. The provider applies whatever
	// naming rules its registry has and returns the usable reference in
	// [Repository.Prefix]; callers must not assume Name appears in it verbatim.
	Name string
	// Retention bounds the repository's growth.
	Retention RetentionPolicy
	// ScanOnPush asks the registry to vulnerability-scan pushed images. A
	// registry that cannot scan may ignore this; unlike Retention, ignoring it
	// costs nothing but a missing signal, and refusing would make scanning
	// impossible to request portably.
	ScanOnPush bool
	// Labels are non-secret metadata for ownership tagging.
	Labels map[string]string
}

// Repository is a provisioned image repository.
type Repository struct {
	// Ref addresses the repository.
	Ref Ref
	// Prefix is the registry-qualified prefix to append a tag to, e.g.
	// "registry.example/team/app". Callers build an [ImageRef] as
	// Prefix + ":" + tag and otherwise treat it as opaque.
	Prefix string
	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec RepositorySpec
}

// ImageRegistry hosts container image repositories.
//
// # Why this port does not require a Granter
//
// It embedded one, and every provider had to implement it. That was the defect:
// not that authorising a pull by workload identity is impossible, but that it is
// **not universally supported**, and a required method is a claim that it is.
//
//   - Most registries cannot express it. Harbor, GAR, Quay and ECR authenticate
//     a robot account or an IAM principal holding a token; there is no policy to
//     write that says "this ServiceAccount may pull". A provider forced to
//     implement Grant against one of those can only mint a credential — material
//     created as a side effect of a call the caller believes is a policy write,
//     that nothing rotates and no audit surface mentions.
//   - On ECS the principal that pulls is not the workload at all. The task
//     *execution* role pulls, not the task role, so a grant naming the
//     application's identity authorises a principal that never makes the
//     request. The source system confirms it from the other side: its app task
//     role is created with no policies (build.go:619-666) and accumulates
//     DynamoDB, S3, Bedrock and ssmmessages statements — never ECR — because
//
// pulls run under the operator-configured execution role apphub does not
// manage (source system @ backend/internal/modules/deploy/container.go).
//
// But it is not impossible everywhere, and an earlier revision of this comment
// said it was. Kubernetes' kubelet credential provider can pass a pod-bound
// ServiceAccount token to a credential plugin, which is exactly
// authorise-the-pull-by-workload-identity. So the honest shape is the one used
// for every other unevenly-supported ability in this package: an optional
// interface behind an advertised capability. See [ImagePullGranter] and
// [CapImagePullGrants].
//
// # The obligation on every provider
//
// Whether or not it can express the grant, a provider still has to make its own
// workloads able to start:
//
//	A provider MUST arrange that a workload it runs can pull the image its spec
//	names, when that image is in a repository the same provider issued.
//
//	Whatever it arranges MUST be scoped as narrowly as the substrate allows: to
//	the repositories the workload's own spec references, and to that workload,
//	wherever the substrate can express either. Blanket access to every
//	repository the provider has ever issued is not an acceptable reading, and a
//	provider that can only express something broader MUST say so in
//	[Status.Message].
//
//	It MUST NOT expose any credential it creates to the caller.
//
// The narrowing is not cosmetic. An earlier revision of this obligation said "any
// image from a repository the same provider issued", which every workload
// satisfied with one project-wide credential — a least-privilege regression
// introduced by a fix for a least-privilege problem. Least privilege is a
// standing constraint here, not a preference, so the obligation is stated in
// terms of what a workload actually needs to pull.
//
// A caller that needs to grant pull access to something that is *not* one of
// this provider's own workloads is asking for cross-domain sharing, which is
// compute/ext territory.
type ImageRegistry interface {
	// EnsureRepository creates or updates a repository. Idempotent, including
	// the retention policy, which is re-applied on every call so that an
	// existing repository picks up a changed rule.
	EnsureRepository(ctx context.Context, spec RepositorySpec) (*Repository, error)

	// DescribeRepository returns an existing repository, or [ErrNotFound].
	//
	// Every registry a platform would plausibly use has a read-back — Harbor's
	// repository GET, GAR's repositories.get, ECR's DescribeRepositories — so
	// its absence was the interface's gap rather than any substrate's. Without
	// it nothing above the interface can ask whether a repository exists, what
	// retention is in force, or whether a delete took effect.
	DescribeRepository(ctx context.Context, ref Ref) (*Repository, error)

	// DeleteRepository removes a repository and its images. Deleting an absent
	// repository returns nil.
	DeleteRepository(ctx context.Context, ref Ref) error
}

// ImagePullGranter is optionally implemented by an [ImageRegistry] whose
// substrate can authorise an image pull to a workload identity.
//
// It is not on [ImageRegistry] because most registries cannot do it — see there
// for which and why — and a required method every provider answers with
// [ErrUnsupported] is the stub-interface problem [Provider] exists to avoid. It
// is not absent either, because at least one substrate genuinely can: a
// Kubernetes kubelet credential provider can be handed a pod-bound
// ServiceAccount token, which is a real identity-scoped pull authorisation and
// not a minted credential in disguise.
//
// It is deliberately narrower than [Granter]. [AccessLevel] has no third meaning
// on a repository: pull and push are the only two, push belongs to the builder's
// scoped credential rather than to a running workload, and an admin level would
// have to be aliased to one of them or refused. Two methods that say what they
// do beat three levels where one is a lie.
//
// Reach it through [ImagePullGrants], which checks the capability first.
type ImagePullGranter interface {
	// GrantPull authorises identity to pull from repository. Idempotent.
	GrantPull(ctx context.Context, repository Ref, identity Ref) error

	// RevokePull removes that authorisation. Revoking an absent one returns nil.
	RevokePull(ctx context.Context, repository Ref, identity Ref) error
}

// ImagePullGrants returns reg's [ImagePullGranter], or an error wrapping
// [ErrUnsupported].
//
// The capability is checked before the type assertion, and both have to agree:
// a provider that implements the methods without advertising
// [CapImagePullGrants] is treated as not having it, because the capability is
// what a caller checks before it plans a deploy around the feature. A provider
// that advertises it and does not implement the interface is a provider bug, and
// the error says so rather than reporting a missing capability.
func ImagePullGrants(p Provider, reg ImageRegistry) (ImagePullGranter, error) {
	if !p.Capabilities().Has(CapImagePullGrants) {
		return nil, &UnsupportedError{
			Provider:   p.Name(),
			Capability: CapImagePullGrants,
			Detail: "this registry cannot express an image pull as an authorisation of a " +
				"workload identity; the provider still guarantees its own workloads can pull " +
				"the images they name, per the obligation on ImageRegistry",
		}
	}
	g, ok := reg.(ImagePullGranter)
	if !ok {
		return nil, &UnsupportedError{
			Provider:   p.Name(),
			Capability: CapImagePullGrants,
			Detail: "the provider advertises the capability and its ImageRegistry does not " +
				"implement ImagePullGranter, which is a provider bug rather than a substrate " +
				"limitation",
		}
	}
	return g, nil
}

// BuildSource is where the build gets its input.
//
// The confinement rule is portable and load-bearing: a provider MUST reject a
// Dockerfile path that resolves outside the context. The source system checks
// this (build.go:462-467) and losing it reintroduces a traversal escape.
//
// The locality assumption is not portable, and saying so is the point. The
// source system's builder is a subprocess of apphub, so "a local directory" is
// exactly right for it; a build pod in a cluster cannot read apphub's disk. So:
//
//	A provider whose builder does not share the caller's filesystem MUST
//	transport the context itself, and MUST document the size limit at which it
//	refuses. Silently shipping an unbounded tree across a network is not an
//	acceptable reading of this field.
type BuildSource struct {
	// ContextDir is a local directory containing the build context.
	ContextDir string
	// Dockerfile is the build recipe's path relative to ContextDir. Empty means
	// "Dockerfile" at the root.
	Dockerfile string
}

// BuildRequest asks for an image.
type BuildRequest struct {
	// Source is the input.
	Source BuildSource
	// Destinations are the fully-qualified references to push, typically a
	// ":latest" and an immutable per-deploy tag. At least one is required.
	Destinations []ImageRef
	// Cache optionally names a repository to read and write layer cache
	// entries in. A build with no cache is slower but correct, so a provider
	// that cannot cache should log and proceed rather than fail.
	Cache *BuildCache
	// BuildArgs are non-secret build-time variables.
	//
	// Non-secret is a contract, not a hint: build arguments are recorded in
	// image metadata and readable by anyone who can pull the image. A secret a
	// build needs must be handled by the provider's own mechanism, never here.
	BuildArgs map[string]string
	// Logs, when set, receives the builder's output as it is produced. The
	// caller owns the writer and any bounding of it — the source system keeps a
	// capped tail so a build failure's diagnostic can be persisted onto a
	// 400 KB DynamoDB item (build.go:44-89), which is a caller policy, not a
	// provider one.
	Logs io.Writer
}

// BuildCache names a repository used for build-layer cache entries.
type BuildCache struct {
	// Repository is the cache repository's prefix, from [Repository.Prefix].
	Repository string
	// MaxAge is how old a cached layer may be before the builder ignores it.
	// This bounds the real cost of caching: a cached package-install layer
	// keeps serving whatever it captured, so without a TTL an upstream security
	// fix never reaches a rebuild of an unchanged recipe. Zero means the
	// provider's default, which must not be "forever".
	MaxAge time.Duration
}

// BuildResult reports what was produced.
type BuildResult struct {
	// Images are the references that were pushed, in the order requested.
	Images []ImageRef
	// Digest is the content digest of the built image, when the builder
	// reports one. Empty otherwise; callers must not require it.
	Digest string
}

// ImageBuilder turns a source tree into pushed container images.
//
// # Why this is a port and not a method on ContainerRuntime
//
// Building is not running. The source system's builder is not even an API
// client — it execs /kaniko/executor as a subprocess (build.go:539-576) — and a
// Kubernetes provider would plausibly reuse that exact builder while pushing to
// a registry that has nothing to do with its cluster. Fusing the two would make
// every runtime implementation own a build toolchain it may not need.
//
// # Why credential minting is not on this interface
//
// Before invoking the builder, the source system assumes a dedicated role under
// an STS session policy scoped to exactly the destination repositories, for
// fifteen minutes, and hands the subprocess an allowlisted environment
// containing only those credentials (kaniko_creds.go:161-190, :106-149). The
// reason is that Dockerfile RUN instructions execute arbitrary
// repository-authored code, so a builder that inherits the platform's own
// credentials hands them to whoever wrote the repository.
//
// That requirement is portable; the mechanism is not. So it is stated as an
// obligation on the implementation rather than as an interface method:
//
//	A provider MUST NOT expose ambient platform credentials to the build.
//	Credentials made available to a build MUST be scoped to no more than push
//	access to Destinations and Cache, and MUST be short-lived.
//
// A provider that cannot meet this must not implement [CapImageBuild]. Putting
// a MintPushCredentials method on the interface would have forced every
// substrate to have AWS-shaped session policies, and — worse — would have made
// the credentials visible to the caller, which is the one place they have no
// business being.
//
// # The strongest form of it, described rather than required
//
// "Scoped and short-lived" is what a portable interface can ask for. It is not
// the strongest thing a provider can do, and the difference is worth writing down
// where the obligation is rather than only in the one provider that took it:
// scoping bounds what a stolen credential reaches, and a builder that executes
// repository-authored code in a process holding one can still have it stolen.
// kaniko unpacks the image into the container it runs in and shares a PID
// namespace with the commands it runs, so this is a demonstrated read rather than
// a modelled one.
//
// So compute/aws builds with no registry credential at all and pushes the
// artefact from a separate process, minting only after the builder has returned
// (USOSS-41). This paragraph deliberately states no additional MUST or SHOULD:
// whether a provider *can* separate the two is a property of its substrate, the
// suite cannot observe the separation through this interface, and an obligation
// nothing checks is one this project treats as a gap rather than a bar. It is
// here so that an implementer reads it before deciding that a scoped credential
// in the builder's environment is the end of the design.
type ImageBuilder interface {
	// Build produces and pushes the requested images. It blocks: unlike
	// provisioning, a build has no meaningful intermediate resource to poll and
	// its output stream is the progress signal. Cancellation is via ctx.
	Build(ctx context.Context, req BuildRequest) (*BuildResult, error)
}
