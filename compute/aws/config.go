// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// DefaultName is the [compute.Provider.Name] this implementation reports unless
// an operator overrides it. Every [compute.Ref] records it, so it is stable
// across releases by contract.
const DefaultName = "aws"

// Config is everything site-specific this provider needs.
//
// The rule this struct exists to enforce: **no identifier belonging to any
// deployment of apphub is compiled in.** Not an account, not a role, not a
// registry host, not a repository prefix, not a region. Every one of them is a
// field here with no default, because the source system hardcodes several of
// them and this repository is going public. A provider built from a zero Config
// can do nothing, which is the intended failure mode for a misconfigured
// deployment rather than a surprise in production.
type Config struct {
	// Name overrides [DefaultName]. An operator running two providers against
	// two accounts needs to tell their [compute.Ref] values apart.
	Name string `yaml:"name" json:"name"`

	// Region is the AWS region every regional client addresses. Required.
	//
	// The source system has no region parameter on its build path and recovers
	// one by regexp from a push destination's hostname
	// (kaniko_creds.go:52-63). That is a value derived from caller input where
	// a configured one was available; this provider is told, and the
	// destination is checked against what it was told rather than the other way
	// round.
	Region string `yaml:"region" json:"region"`

	// Placements maps a [compute.Placement] name onto AWS coordinates. A spec
	// naming a placement not in here is [compute.ErrInvalidSpec] — the provider
	// refuses rather than guessing, which is the behaviour the source system
	// lacks when it degrades an unusable region to a logged warning.
	Placements map[string]PlacementConfig `yaml:"placements" json:"placements"`

	// DefaultPlacement is the placement an empty [compute.Placement] resolves
	// to. Empty means the provider has no default and an empty placement is
	// refused.
	DefaultPlacement string `yaml:"defaultPlacement" json:"defaultPlacement"`

	// Identity configures the IAM-backed workload-identity port. Required:
	// [compute.IdentityService] is not capability-gated, because a workload
	// with no identity cannot be granted access to anything.
	Identity IdentityConfig `yaml:"identity" json:"identity"`

	// Registry configures ECR. Nil means this provider does not offer
	// [compute.CapImageRegistry].
	Registry *RegistryConfig `yaml:"registry" json:"registry"`

	// Build configures the image builder. Nil means this provider does not
	// offer [compute.CapImageBuild].
	Build *BuildConfig `yaml:"build" json:"build"`

	// Secrets configures the secret store on SSM Parameter Store. Nil means the
	// port is unsupported, which is the honest state for a provider with no
	// parameter prefix to write under.
	Secrets *SecretConfig `yaml:"secrets" json:"secrets"`
	// ObjectStore configures general-purpose object storage. Nil means this
	// provider does not offer [compute.CapObjectStore].
	ObjectStore *ObjectStoreConfig `yaml:"objectStore" json:"objectStore"`

	// IsRetryable widens this provider's idea of a transient failure. Nil, the
	// default, means the classification in [classifier] stands as written.
	//
	// # Why this exists, and what it costs you
	//
	// This provider used to derive the answer from the retryer of the client the
	// error came from, so that an operator who extended a client with
	// retry.AddWithErrorCodes got the same answer from both. That turned out to
	// depend on how the error was wrapped rather than on what it was, and the
	// two disagreed in the direction that abandons a deploy that would have
	// worked. See [classifier].
	//
	// So the coupling is explicit now, and the cost is yours to pay rather than
	// this package's to hide: **extending an SDK client's retryable codes no
	// longer tells this provider anything.** A caller that does one must do the
	// other, here.
	//
	// # What belongs here, and what does not
	//
	// This hook is for a retryable condition **this package cannot know about**.
	// Two real shapes:
	//
	//   - a code AWS adds after this release. The set is not closed and this
	//     package is not redeployed when it grows, so an operator who meets a new
	//     one has nowhere else to say so;
	//   - a code that is not AWS's at all. An authenticating egress proxy, a
	//     PrivateLink appliance or a partition-local endpoint can rewrite or
	//     inject an error, and no amount of knowledge about AWS covers a fault
	//     injected by something in front of it.
	//
	//	cfg.IsRetryable = func(err error) bool {
	//		var api smithy.APIError
	//		return errors.As(err, &api) && api.ErrorCode() == "ProxyThrottledUpstream"
	//	}
	//
	// **The EC2 teardown case is deliberately not the example here, and an
	// earlier revision of this comment used it.** DependencyViolation on a
	// security group that a load balancer still holds interfaces in *is*
	// retryable, and this package classifies it itself
	// ([sdkEC2.err]) — because it is not an operator's local knowledge. The
	// function-endpoint port creates the load balancer and the security group and
	// deletes them in that order, so the dependency is a fact about a sequence
	// this package performs. Routing it through this hook would make **correct
	// teardown depend on operator configuration**, and an unconfigured provider
	// would report a terminal failure for a condition that clears on its own —
	// an availability bug dressed as configurability.
	//
	// The rule the two halves come from: **a port handles the facts it creates;
	// this hook is for the facts it cannot see.**
	//
	// It is consulted **in addition to** this package's classification and never
	// instead of it, so it can only move an error from terminal to
	// [compute.ErrTransient]. It cannot make a denial, a missing resource, or a
	// cancelled context retryable, and it cannot suppress a retry this provider
	// would already have advised: a hook that returns false changes nothing.
	// That direction is deliberate. Widening costs a caller a wasted retry;
	// narrowing costs it a deploy, and a configuration field should not be able
	// to do the second.
	IsRetryable func(error) bool `yaml:"-" json:"-"`

	// Function configures the Lambda-backed [compute.FunctionRuntime]. Nil
	// means this provider does not offer [compute.CapFunction].
	Function *FunctionConfig `yaml:"function" json:"function"`

	// Endpoint configures the ELBv2-backed half of that port. Nil means this
	// provider does not offer [compute.CapFunctionEndpoint].
	//
	// Separate from [Config.Function] because the interface separates the
	// capabilities, and the separation is real on AWS: a deployment can run
	// functions invoked through the control plane with no load balancer, no
	// subnets and no certificates configured at all, which is what the source
	// system does whenever its needsAlb parameter is false (lambda.go:123).
	Endpoint *EndpointConfig `yaml:"endpoint" json:"endpoint"`

	// Relational configures Aurora. Nil means this provider does not offer
	// [compute.CapRelationalDatabase].
	Relational *RelationalConfig `yaml:"relational" json:"relational"`

	// PollInterval is how often a Wait* method re-reads a converging resource.
	// Zero means [DefaultPollInterval]; a positive value is honoured down to
	// [MinPollInterval].
	//
	// It is configuration because the right answer differs by three orders of
	// magnitude between a hermetic test and a real account, and because getting
	// it wrong is not a performance problem: the SDK's retryer bounds failures,
	// not successful reads, so a provider that polls a real Aurora creation
	// every millisecond issues about a thousand reads a second until AWS
	// throttles it — and then reports ErrTransient instead of continuing the
	// caller's Wait. Measured on this port before it was configurable: a 40ms
	// wait made 38 successful reads.
	PollInterval time.Duration `yaml:"pollInterval" json:"pollInterval"`

	// KeyValue configures DynamoDB. Nil means this provider does not offer
	// [compute.CapKeyValueTable].
	//
	// Separate from [Config.Relational] because the two are separate
	// capabilities with separate access-control models, and an operator who has
	// only one of them configured should advertise only one. See
	// [compute.RelationalProvisioner] for the argument.
	KeyValue *KeyValueConfig `yaml:"keyValue" json:"keyValue"`

	// Container configures the ECS-backed container runtime. Nil means this
	// provider does not offer [compute.CapContainerService].
	Container *ContainerConfig `yaml:"container" json:"container"`
}

// ContainerConfig configures the ECS-backed [compute.ContainerRuntime].
type ContainerConfig struct {
	// NamePrefix is prepended to every ECS service name and task-definition
	// family, e.g. "apphub-".
	//
	// The source system hardcodes a product name into both (container.go:429).
	// A hardcoded prefix in a
	// public library is a deployment identifier compiled in, so it is
	// configuration; empty is legal.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// ExecutionRolePathPrefix is the IAM path the per-service task execution
	// roles are created under. Empty means [IdentityConfig.PathPrefix], and
	// failing that IAM's own default.
	//
	// It is separate from the workload identity's path because the two roles
	// have different blast radii and an operator writing an account guardrail
	// wants to be able to say so about one and not the other: a task role is
	// the workload, an execution role is the agent that starts it.
	ExecutionRolePathPrefix string `yaml:"executionRolePathPrefix" json:"executionRolePathPrefix"`

	// ExecutionRolePermissionsBoundary is the ARN of a policy applied as a
	// permissions boundary to every execution role this provider creates.
	// Empty means none; see [IdentityConfig.PermissionsBoundary] for what that
	// costs.
	ExecutionRolePermissionsBoundary string `yaml:"executionRolePermissionsBoundary" json:"executionRolePermissionsBoundary"`

	// LogGroupPrefix is the CloudWatch log group prefix task output is written
	// under, e.g. "/apphub/". Empty means this provider configures no log
	// driver at all, and says so rather than picking a destination for
	// somebody's application logs.
	LogGroupPrefix string `yaml:"logGroupPrefix" json:"logGroupPrefix"`

	// IngressAuthMiddleware names the platform ingress's authentication
	// middleware, for [compute.Route.RequireAuth].
	//
	// Empty means this provider cannot authenticate a route, and a route asking
	// for it is refused. That is the fail-closed direction and it matters more
	// than it looks: the alternative is a route that reports deployed and
	// serves an application to anyone who finds its hostname.
	IngressAuthMiddleware string `yaml:"ingressAuthMiddleware" json:"ingressAuthMiddleware"`

	// IngressCookieStripMiddleware names the ingress middleware that removes
	// the platform's shared-domain SSO cookie before forwarding to an
	// application. Every application-host router, including public, internal,
	// MCP, and discovery routes, requires it. An empty name refuses routes
	// rather than disclosing the platform cookie to an application.
	IngressCookieStripMiddleware string `yaml:"ingressCookieStripMiddleware" json:"ingressCookieStripMiddleware"`

	// InternalEntrypoint is the proxy entrypoint that only the internal load
	// balancer reaches, for [compute.Route.Internal]. TLS for it terminates at
	// that load balancer, so its routers carry no certificate resolver.
	//
	// Empty means this provider has no internal ingress, and an internal
	// route is refused: putting it on a public entrypoint instead would
	// publish an application its owner asked to keep inside the network.
	InternalEntrypoint string `yaml:"internalEntrypoint" json:"internalEntrypoint"`

	// MCPAuthBackendURL is the operator-owned AppHub API origin reachable from
	// the platform ingress, for [compute.Route.MCPAuthApplicationID]. It serves
	// ForwardAuth and app-specific OAuth metadata. Empty means this provider
	// cannot protect hosted MCP endpoints.
	MCPAuthBackendURL string `yaml:"mcpAuthBackendUrl" json:"mcpAuthBackendUrl"`

	// TLSTermination says who holds the certificate for published HTTPS routes.
	//
	// "ingress" (default, empty): Traefik terminates TLS. A route with a
	// CertificateRef is put on the websecure entrypoint with tls.certresolver
	// set to the resolved certificate name.
	//
	// "edge": TLS is terminated in front of Traefik — an ALB with an ACM
	// wildcard, matching Union Station. A route with a CertificateRef is still
	// accepted (the control plane names one, and an unresolvable reference is
	// still refused) but the router is put on the plaintext entrypoint with no
	// TLS labels, because Traefik sees HTTP from a trusted load balancer. A
	// route with neither a certificate nor AllowPlaintext is still refused.
	//
	// Any other value is refused at construction. The field exists so that
	// serving a public hostname on HTTP inside the VPC is a topology the
	// operator wrote down, not an inference from an empty certificate map.
	TLSTermination string `yaml:"tlsTermination" json:"tlsTermination"`

	// Secrets resolves [compute.SecretBinding] values to substrate ARNs and
	// says what reading exactly those requires.
	//
	// Nil DEFAULTS to this provider's own SSM secret store when [Config.Secrets]
	// is configured; see [Provider.SecretResolver]. Connecting a provider to
	// itself is the ordinary configuration, and requiring an operator to
	// hand-write the glue for it is how this port shipped with its headline
	// capability composed nowhere but in a test stub. Set it explicitly only to
	// bind this container port to a DIFFERENT provider's store, which is the
	// reason it is an interface at all.
	//
	// Nil with no [Config.Secrets] either means this provider cannot inject
	// secrets, and a spec carrying [compute.ServiceSpec.Secrets] is refused
	// rather than deployed without them. Refusing is the only safe direction: a
	// workload silently started without the secrets it asked for either crashes
	// on a missing variable — the good case — or runs in a degraded mode the
	// caller did not ask for and cannot see.
	//
	// It is an interface rather than a concrete store so that this port holds an
	// address resolver and never a value; see [SecretResolver].
	Secrets SecretResolver `yaml:"-" json:"-"`
}

// PlacementConfig is what an operator attaches to a [compute.Placement] name.
//
// This is where the AWS network identifiers live and the only place they live.
// [compute.Placement] carries a name and nothing else — see its documentation
// for the thirteen source-system call sites that thread raw subnet identifiers
// around, and for why keeping them out of the interface is the load-bearing
// decision of the whole network model. An operator configures what a placement
// name means here; a caller names one.
//
// It began nearly empty, because an image registry, an image builder and an IAM
// role are not placed anywhere: ECR is regional, IAM is global, and a build runs
// wherever apphub runs. The network fields arrived with the function-endpoint
// and relational ports, which are the first things in this package that have to
// be put somewhere on a network — and they are exactly the identifiers
// [compute.Placement] exists to keep out of the interface. They live here,
// supplied by an operator, and never appear in a [compute] spec.
//
// The network fields are the function port's (USOSS-12). The container port
// (USOSS-11) adds its own — a cluster and a public-IP policy — and shares
// [PlacementConfig.SubnetIDs] and
// [PlacementConfig.PlatformIngressSecurityGroupID] rather than defining a second
// spelling of either.
type PlacementConfig struct {
	// Name is the placement's configured name, filled in by the lookup rather
	// than by the operator so a resolved placement can be echoed into an
	// effective spec without the caller's empty "use the default" surviving.
	Name string `yaml:"-" json:"-"`

	// Region is the region this placement's regional resources live in. Empty
	// means [Config.Region]. It is here because [compute.Placement] is the
	// documented answer to multi-region and a placement that could not differ
	// in region would not be one.
	Region string `yaml:"region" json:"region"`

	// SubnetIDs are the subnets a load balancer placed here is created in.
	// Required by [compute.CapFunctionEndpoint] and unused without it.
	//
	// An application load balancer needs at least two, in at least two
	// availability zones, and this provider checks both against what EC2
	// reports rather than taking the list as given. The source system does not:
	// it reads whatever the ECS cluster config row holds (lambda.go:406-416),
	// recovers a VPC from the *first* subnet alone (lambda.go:418-422,
	// :739-750), and lets CreateLoadBalancer fail if the rest disagree. A list
	// spanning two VPCs is the interesting case, because the security group is
	// created in the VPC of subnet zero and the load balancer then cannot use
	// the others.
	SubnetIDs []string `yaml:"subnetIds" json:"subnetIds"`

	// PlatformIngressSecurityGroupID is the security group of the reverse proxy
	// that fronts deployed applications in this placement — what a
	// [compute.PeerPlatformIngress] rule resolves to.
	//
	// Empty means this placement has no ingress proxy, and then a rule naming
	// that peer is [compute.ErrInvalidSpec] and [compute.CapPlatformIngress] is
	// not advertised. That is a deliberate divergence: the source system reads
	// this from TRAEFIK_SECURITY_GROUP_ID and, when it is unset, opens the port
	// to 0.0.0.0/0 instead (build.go:822-848) — a missing configuration value
	// widening a security boundary. [compute.PeerPlatformIngress] forbids that
	// in as many words, and the refusal is what makes it observable.
	//
	// Per-placement rather than per-provider because the proxy lives in a VPC
	// and a second placement is a second VPC. The name is the container port's;
	// the two ports resolve the same peer through the same field.
	PlatformIngressSecurityGroupID string `yaml:"platformIngressSecurityGroupId" json:"platformIngressSecurityGroupId"`

	// Certificates maps a [compute.TLSConfig.CertificateRef] onto the ARN of a
	// certificate in this placement's region. Required for a
	// [compute.ListenerHTTPS] listener.
	//
	// It is a map rather than a client because the interface is explicit that
	// certificate lifecycle is not managed here and that "no provider may invent
	// a default": a certificate reference is operator configuration passed
	// through by the caller. So the operator says which references exist and
	// what each resolves to, a reference outside the map is
	// [compute.ErrInvalidSpec], and this package never calls a certificate API
	// at all. The source system has nothing to port here — it never populates a
	// Certificates field on any listener it creates (lambda.go:697-708).
	//
	// Per-placement because ACM is regional and a certificate in one region
	// cannot be served by a load balancer in another.
	//
	// Shared with the container port's routes (USOSS-11), which resolves the
	// same reference the same way for an interactive-session route's listener --
	// one map, not two definitions of "what a CertificateRef means here".
	Certificates map[string]string `yaml:"certificates" json:"certificates"`

	// VPC is the VPC this placement's network resources are created in.
	// Required for [compute.CapRelationalDatabase], which has to create a
	// security group; unused by every other port.
	//
	// The source system recovers it by calling DescribeSubnets on a configured
	// subnet purely to read the VPC back out (build.go:943-954,
	// lambda.go:737-750). That is a network lookup standing in for a
	// configuration value the operator already has, and it fails in a way that
	// reads as an AWS problem rather than as a missing setting, so this
	// provider is told instead.
	VPC string `yaml:"vpc" json:"vpc"`

	// Subnets are the subnets a DB subnet group is built from. Required for
	// [compute.CapRelationalDatabase]; RDS needs at least two, in different
	// availability zones, and refuses fewer.
	Subnets []string `yaml:"subnets" json:"subnets"`

	// ControlPlaneSecurityGroups are the security groups apphub's own
	// backend and job runner run in, and therefore what a
	// [compute.PeerControlPlane] ingress rule resolves to.
	//
	// It has no default, and the absence is a refusal rather than a widening.
	// A rule naming the control plane on a provider that was not told where the
	// control plane is cannot be satisfied, and the two ways to not satisfy it
	// are to leave the port closed — provisioning then fails with a connection
	// timeout nothing traces back to here, which is the failure the source
	// system documents having hit (database.go:200-205) — or to open the port
	// to everything. Refusing at the spec is the third option and the only
	// honest one.
	ControlPlaneSecurityGroups []string `yaml:"controlPlaneSecurityGroups" json:"controlPlaneSecurityGroups"`

	// ClusterARN is the ECS cluster services in this placement run in.
	// Required when a container runtime is configured.
	//
	// The source system reads one ECSClusterConfig row and every application
	// lands in it (container.go:839). Making it a placement field is what turns
	// "the cluster" into "this placement's cluster" without putting a cluster
	// concept above the interface.
	ClusterARN string `yaml:"clusterArn" json:"clusterArn"`

	// SecurityGroups are the security groups every task in this placement is
	// attached to, in ADDITION to the per-service group the container port
	// creates from [compute.ServiceSpec.Ingress]. Required when a container
	// runtime is configured.
	//
	// It is the operator's baseline network posture. apphub attaches what it is
	// told to attach here and makes no per-service claim about reachability
	// through THIS field; the per-service claims live on the per-service group.
	//
	// The source system creates a security group per application instead
	// (build.go:785-954), and this port does the same, over the EC2 primitives
	// USOSS-14 landed in network.go.
	SecurityGroups []string `yaml:"securityGroups" json:"securityGroups"`

	// PlatformIngressSecurityGroups are the security groups belonging to the
	// reverse proxy that fronts deployed applications. Empty means this
	// placement has no platform ingress.
	//
	// It is [compute.PeerPlatformIngress] resolved. Empty is legal and is
	// FAIL-CLOSED: a rule naming that peer is refused rather than widened. The
	// source system does the opposite — with its equivalent configuration unset
	// it opens the application's port to 0.0.0.0/0 (build.go:836-848) — and
	// that is the single most important behaviour difference in this file.
	PlatformIngressSecurityGroups []string `yaml:"platformIngressSecurityGroups" json:"platformIngressSecurityGroups"`

	// AssignPublicIP gives each task a public address.
	//
	// It defaults to false, which is the safe direction and matches the source
	// system's own default (container.go:768-771 assigns one only when the
	// cluster configuration asks). A task with a public address is reachable
	// from the internet subject only to its security group, so this is an
	// operator decision and never a per-spec one.
	AssignPublicIP bool `yaml:"assignPublicIp" json:"assignPublicIp"`
}

// IdentityConfig configures the IAM-backed [compute.IdentityService].
type IdentityConfig struct {
	// PathPrefix is the IAM path every role this provider creates is created
	// under, e.g. "/apphub/". It is how an operator can write an
	// account-level guardrail that applies to apphub's roles and nothing
	// else. Empty means "/", which IAM's own default is.
	PathPrefix string `yaml:"pathPrefix" json:"pathPrefix"`

	// NamePrefix is prepended to every role name. The source system has no
	// prefix and takes the application name directly, which means an apphub
	// role and an operator's own role compete for one namespace; a prefix an
	// operator chooses is how that collision stops being possible.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// PermissionsBoundary is the ARN of an IAM policy applied as a permissions
	// boundary to every role this provider creates.
	//
	// Empty is permitted and is what the source system does, but it is worth
	// naming what that costs: without a boundary, the ceiling on what any role
	// apphub creates can ever be granted is whatever apphub's own principal
	// may grant. A boundary makes that ceiling explicit and account-owned.
	PermissionsBoundary string `yaml:"permissionsBoundary" json:"permissionsBoundary"`
}

// RegistryConfig configures the ECR-backed [compute.ImageRegistry].
type RegistryConfig struct {
	// NamePrefix is prepended to every repository name, e.g. "apphub/".
	//
	// The source system hardcodes a product name here (build.go:256). A
	// hardcoded prefix in a public repository is a deployment identifier
	// compiled into a library, so it is configuration; empty is legal and
	// means the repository is named after the caller's logical name alone.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// ImmutableTags asks ECR to refuse a push that would move an existing tag.
	//
	// The source system sets MUTABLE (build.go:307, :390). That is a
	// deliberate difference rather than an oversight on its part — it pushes a
	// ":latest" — so this is a knob and not a fixed hardening: a caller whose
	// Destinations include a floating tag cannot use an immutable repository.
	ImmutableTags bool `yaml:"immutableTags" json:"immutableTags"`
}

// ObjectStoreConfig configures general-purpose object storage.
type ObjectStoreConfig struct {
	// NamePrefix is prepended to every bucket name.
	//
	// Unlike the registry and identity prefixes this one is close to mandatory
	// in practice, because an S3 bucket name is globally unique across every
	// AWS account: an unprefixed "assets" will already exist, owned by somebody
	// else, and the failure arrives as an authorization error rather than as a
	// name collision. [Config.Validate] does not require it -- a caller whose
	// logical names are already globally distinctive is entitled to no prefix --
	// but the refusal a collision produces names this field.
	//
	// This prefix is not a tenant boundary. The object-store ownership check is
	// AWS-account scoped: anything in the same account that can set the
	// reserved apphub ownership and component tags on a bucket under this
	// prefix can present that bucket as managed by this provider. Cross-tenant
	// deployment on one shared account is therefore unsupported unless the
	// tenants share that trust boundary; isolate tenants by AWS account or an
	// equivalent tag-write boundary.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// TableBuckets enables the S3 Tables port, reached only through
	// [ext.TableBucketProvisioner]. Off by default: a table bucket is not
	// portable and no core deploy path asks for one.
	TableBuckets bool `yaml:"tableBuckets" json:"tableBuckets"`

	// VectorBuckets enables the S3 Vectors port, reached only through
	// [ext.VectorBucketProvisioner]. Off by default, same reasoning.
	VectorBuckets bool `yaml:"vectorBuckets" json:"vectorBuckets"`
}

// BuildConfig configures the kaniko-backed [compute.ImageBuilder].
type BuildConfig struct {
	// ExecutorPath is the absolute path of the kaniko executor binary.
	// Required. The source system hardcodes "/kaniko/executor"
	// (build.go:539); where a builder lives is a property of the image apphub
	// runs in, which is an operator's choice.
	//
	// This provider composes a command line, so it depends on what that binary
	// accepts. Beyond the flags the source system already used it needs
	// --no-push, --no-push-cache and --tar-path, all three present in Kaniko
	// v1.28.4. --tar-path replaced --tarPath, which is still accepted as a
	// deprecated alias; a binary old enough to have only the old spelling will
	// fail at the first build with Kaniko's own unknown-flag error.
	ExecutorPath string `yaml:"executorPath" json:"executorPath"`

	// PusherPath is the absolute path of the binary that publishes what the
	// build produced. Required, with no default.
	//
	// It exists because the build does not push (USOSS-41): a Dockerfile RUN
	// instruction executes repository-authored code in the builder's own process,
	// so a builder that pushes is a builder whose environment holds a live
	// registry credential. The build writes a tarball and this binary uploads it,
	// with the credential, from a process that never ran the Dockerfile.
	//
	// The contract on it is one line of argv:
	//
	//	<PusherPath> push <tarball> <destination>
	//
	// which is crane's (github.com/google/go-containerregistry, Apache-2.0). It
	// must resolve registry credentials the way a docker client does — from the
	// configuration under DOCKER_CONFIG, which this provider writes per build and
	// which maps each destination registry onto the "ecr-login" helper, and from
	// the AWS credentials in its environment. crane does; so does anything built
	// on go-containerregistry's default keychain.
	//
	// An operator who needs a different tool, or who can run the push somewhere
	// more isolated than a sibling process, implements [ImagePusher] instead of
	// setting this. See [ImagePusher] for what that buys.
	PusherPath string `yaml:"pusherPath" json:"pusherPath"`

	// PushRoleARN is the role a build assumes in order to push, under a
	// session policy scoped to exactly the repositories it may touch.
	//
	// Required, and there is no fallback. The source system reads this from
	// the ECR_PUSH_ROLE_ARN environment variable and refuses the build when it
	// is unset rather than falling back to the job runner's own task role
	// (kaniko_creds.go:160-166), because that fallback is the vulnerability:
	// Dockerfile RUN instructions execute repository-authored code, so a build
	// that inherits the platform's credentials hands them to whoever wrote the
	// repository. That refusal is preserved. Reading the environment is not:
	// this package takes configuration through this struct, and where an
	// operator keeps the value is the composition root's business.
	PushRoleARN string `yaml:"pushRoleArn" json:"pushRoleArn"`

	// SessionDuration bounds the life of the minted push credential. Zero
	// means [DefaultSessionDuration], which is the source system's fifteen
	// minutes (kaniko_creds.go:184).
	//
	// It is bounded above by [MaxSessionDuration]. A build that needs a longer
	// credential than that has a problem the credential's lifetime is the
	// wrong place to fix.
	SessionDuration time.Duration `yaml:"sessionDuration" json:"sessionDuration"`

	// CacheTTL is how old a cached layer may be before kaniko ignores it and
	// re-runs the instruction, when a [compute.BuildCache] does not say. Zero
	// means [DefaultCacheTTL].
	//
	// A TTL is not a performance knob. A cached "apt-get install" layer keeps
	// serving whatever packages it captured, so without one an upstream
	// security fix never reaches a rebuild of an unchanged recipe
	// (build.go:262-266). "Forever" is not an acceptable default and this
	// provider has no way to express it.
	//
	// **It currently has no effect, and the field is kept rather than removed.**
	// Since USOSS-41 the build phase runs with no registry credential, so it can
	// neither read nor write a registry layer cache and there is no cache for a
	// TTL to bound — see [imageBuilder.cacheArgs] for why that trade was made and
	// what would undo it. The field stays because the constraint it encodes is
	// the one any restored caching has to satisfy, and because deleting it would
	// silently accept a configuration that names a TTL, which is a worse answer
	// than a documented no-op.
	CacheTTL time.Duration `yaml:"cacheTtl" json:"cacheTtl"`

	// Task configures the ECS task each build runs in. Required.
	//
	// There is no other shape. The alternative a caller might expect -- run the
	// builder here, as a subprocess -- is [ExecRunner], which the hosted path
	// refuses by type: see validateHostedRunner, and USOSS-41 for why a process
	// that executes a Dockerfile must not be a process this one shares anything
	// with.
	Task *BuildTaskConfig `yaml:"task" json:"task"`

	// MaxContextBytes bounds the build context this provider will hand the
	// builder. Zero means [DefaultMaxContextBytes].
	//
	// [compute.BuildSource] obliges a provider whose builder does not share
	// the caller's filesystem to document the size limit at which it refuses.
	// This provider's builder is a subprocess and does share it, so the bound
	// is not a transport limit — it is a bound on how much repository-authored
	// content one build can be asked to read and unpack.
	MaxContextBytes int64 `yaml:"maxContextBytes" json:"maxContextBytes"`
}

// FunctionConfig configures the Lambda-backed [compute.FunctionRuntime].
type FunctionConfig struct {
	// NamePrefix is prepended to every function name. Empty is legal.
	//
	// The source system has no prefix and takes the application name directly
	// (lambda.go:117), so an apphub function and an operator's own function
	// compete for one namespace. A prefix an operator chooses is how that
	// collision stops being possible. It must satisfy [namePrefixGrammar] —
	// see [markerDoubleDash] for why that is a correctness requirement and not
	// a style rule.
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// Runtimes is the set of [compute.FunctionSpec.Runtime] values this
	// provider accepts. Required, with no default.
	//
	// [compute.FunctionSpec.Runtime] says a provider "must validate against the
	// set it supports and return ErrInvalidSpec listing them, rather than
	// silently substituting", and calls itself the least portable field in the
	// interface. Two reasons this is operator configuration rather than a list
	// compiled in here. The set AWS supports changes on AWS's schedule, and a
	// hardcoded copy goes stale in the direction of refusing a runtime that
	// works. And an operator may want to allow fewer than AWS does — pinning a
	// fleet to the runtimes they have a patching story for is a reasonable
	// policy and this is the only place to express it.
	//
	// The source system accepts any string the caller sends and substitutes
	// "nodejs20.x" for an empty one (lambda.go:84-87), so a typo reaches the
	// Lambda API as an unrecognised runtime and a caller who names nothing gets
	// a runtime they did not choose. Neither is reproduced.
	Runtimes []string `yaml:"runtimes" json:"runtimes"`

	// DefaultArchitecture is what an empty [compute.FunctionSpec.Architecture]
	// resolves to. Empty means [DefaultFunctionArchitecture].
	DefaultArchitecture compute.Architecture `yaml:"defaultArchitecture" json:"defaultArchitecture"`

	// MaxInlineBytes bounds an inline code bundle. Zero means
	// [DefaultMaxInlineBytes].
	//
	// [compute.CodeSource.Inline] obliges a provider to "return ErrInvalidSpec
	// naming its limit rather than truncate". A truncated zip is not a smaller
	// deployment, it is a corrupt one, and Lambda would report it as a runtime
	// error in a function that had deployed successfully.
	MaxInlineBytes int64 `yaml:"maxInlineBytes" json:"maxInlineBytes"`

	// Description is the description recorded on every function this provider
	// creates. Empty means [DefaultFunctionDescription].
	//
	// Configuration because the source system hardcodes a product name here
	// (lambda.go:213, :231), and a product name in a public library is a
	// deployment identifier compiled in.
	Description string `yaml:"description" json:"description"`
}

// EndpointConfig configures the ELBv2-backed [compute.CapFunctionEndpoint] half.
type EndpointConfig struct {
	// NamePrefix is prepended to a load balancer name, a target group name and
	// a security group name. Empty is legal, and short is wise: the ELBv2
	// ceiling is 32 characters ([maxELBName]) and the prefix is spent out of
	// the same budget as the caller's name. It must satisfy
	// [namePrefixGrammar].
	NamePrefix string `yaml:"namePrefix" json:"namePrefix"`

	// Description is recorded on every security group this provider creates.
	// Empty means [DefaultEndpointDescription]. Configuration for the same
	// reason [FunctionConfig.Description] is: the source system puts a product
	// name here (lambda.go:546).
	Description string `yaml:"description" json:"description"`
}

// The function and endpoint defaults.
const (
	// DefaultFunctionArchitecture is arm64, which is the source system's
	// default (lambda.go:90-92) and the cheaper of the two on Lambda. It is a
	// default rather than a requirement because a bundle built for one
	// architecture will not run on the other, so a caller that cares says so
	// and a caller that does not gets the effective value reported back in
	// [compute.FunctionStatus.Spec].
	DefaultFunctionArchitecture = compute.ArchARM64

	// DefaultMaxInlineBytes is 50 MiB, which is Lambda's own ceiling on a
	// bundle uploaded in the request rather than fetched from an object store.
	DefaultMaxInlineBytes int64 = 50 << 20

	// DefaultFunctionDescription is what a function this provider created says
	// about itself, with no deployment named in it.
	DefaultFunctionDescription = "Managed by apphub"

	// DefaultEndpointDescription is the same for a security group, which is the
	// one EC2 requires a description on.
	DefaultEndpointDescription = "Managed by apphub"

	// minEndpointSubnets and minEndpointZones are what an application load
	// balancer requires. Checked here rather than left to CreateLoadBalancer so
	// that a misconfigured placement is reported against the placement.
	minEndpointSubnets = 2
	minEndpointZones   = 2
)

// The build defaults, and the ceiling on the one that can be widened.
const (
	// DefaultSessionDuration is the source system's fifteen minutes. STS will
	// not issue a role-chained session longer than an hour anyway, and fifteen
	// minutes is its floor.
	DefaultSessionDuration = 15 * time.Minute

	// MaxSessionDuration is the longest push credential this provider will
	// ask for. Widening least-privilege machinery to make something work is a
	// finding to report, not a configuration change, so the knob has a
	// ceiling.
	MaxSessionDuration = time.Hour

	// MinSessionDuration is the shortest credential the security token service
	// will issue. Below it, AssumeRole fails with a validation error from
	// inside a credential mint.
	//
	// It is refused rather than rounded up, for the same reason a MaxAge that
	// ECR cannot express is refused: silently issuing a credential that lives
	// longer than the operator asked for is a decision about a security bound,
	// and it is theirs.
	MinSessionDuration = 15 * time.Minute

	// DefaultCacheTTL is a week, which is the source system's value
	// (build.go:267) and the bound it argues for: a security update reaches an
	// unchanged recipe within a week of a deploy.
	//
	// Inert while [BuildConfig.CacheTTL] is, and kept for the same reason.
	DefaultCacheTTL = 168 * time.Hour

	// DefaultMaxContextBytes is 2 GiB.
	DefaultMaxContextBytes int64 = 2 << 30
)

// Who terminates TLS for published container routes. Empty is
// [TLSTerminationIngress].
const (
	TLSTerminationIngress = "ingress"
	TLSTerminationEdge    = "edge"
)

func validateTLSTermination(c *ContainerConfig) error {
	if c == nil {
		return nil
	}
	switch c.TLSTermination {
	case "", TLSTerminationIngress, TLSTerminationEdge:
		return nil
	default:
		return fmt.Errorf("aws: container.tlsTermination %q is not %q or %q",
			c.TLSTermination, TLSTerminationIngress, TLSTerminationEdge)
	}
}

func (c *Config) name() string {
	if c.Name != "" {
		return c.Name
	}
	return DefaultName
}

// capabilities derives what this instance can do from what it was configured
// with. Two instances of this implementation legitimately differ.
func (c *Config) capabilities() compute.CapabilitySet {
	caps := compute.NewCapabilitySet()
	add := func(ok bool, want compute.Capability) {
		if ok {
			caps[want] = struct{}{}
		}
	}
	add(c.Registry != nil, compute.CapImageRegistry)
	add(c.Build != nil && c.Registry != nil, compute.CapImageBuild)
	add(c.Function != nil, compute.CapFunction)
	// An endpoint is reached through the function port, so a configuration with
	// an endpoint and no function runtime advertises neither. [New] refuses that
	// combination outright rather than leaving a caller to infer it from a
	// missing capability.
	add(c.Endpoint != nil && c.Function != nil, compute.CapFunctionEndpoint)
	add(c.Endpoint != nil && c.Function != nil && c.hasPlatformIngress(),
		compute.CapPlatformIngress)
	add(c.Secrets != nil, compute.CapSecretStore)
	add(c.Relational != nil, compute.CapRelationalDatabase)
	add(c.KeyValue != nil, compute.CapKeyValueTable)
	add(c.ObjectStore != nil, compute.CapObjectStore)
	// CapWorkloadGrants is derived from the set of [compute.Granter] ports this
	// configuration actually vends, and the derivation has to be re-read every
	// time a port lands here.
	//
	// The capability's own contract is why: "a provider advertising it must be
	// able to grant on every Granter port it vends", and one that can grant on
	// some but not others must advertise nothing. So this is not "does the
	// key-value port exist" — it is "is every Granter port I vend grantable".
	// USOSS-13's object store is the second one, which is what the previous
	// version of this comment predicted would happen and asked to be updated
	// for: both ports grant, so vending either is enough, and vending both is
	// still enough only because BOTH can.
	// [TestWorkloadGrantsMatchesEveryGranterPortVended] drives a grant on every
	// Granter port compute.Provider vends and fails if one of them refuses as
	// unsupported, so this line cannot quietly outlive a third port that cannot.
	add(c.KeyValue != nil || c.ObjectStore != nil, compute.CapWorkloadGrants)

	add(c.Container != nil, compute.CapContainerService)
	// CapWorkloadExec is advertised whenever the container runtime is, because
	// on ECS apphub really can enforce both states of
	// [compute.ServiceSpec.ExecEnabled]: the flag on the service and the
	// ssmmessages grant on the task role are both ours to set and unset. That
	// is the substrate distinction the field's doc comment asks a provider to
	// document, and this is the side that can enforce it.
	add(c.Container != nil, compute.CapWorkloadExec)
	// CapModelInference is advertised whenever the container runtime is: the
	// grant is an inline policy on the workload's own role, which this port
	// attaches and detaches. Whether the account has model access enabled is
	// outside IAM and outside this provider, and a spec asking for it will fail
	// at invocation rather than at deploy — that is a property of Bedrock, and
	// it is stated on [workloadPolicies] rather than hidden.
	add(c.Container != nil, compute.CapModelInference)
	// CapPlatformIngress only when EVERY configured placement can resolve the
	// peer. A provider that could honour a platform-ingress rule in one
	// placement and not another must not advertise the capability, on the same
	// reasoning CapWorkloadGrants documents -- and the condition is agreed with
	// USOSS-12 so that one capability does not mean two things across two
	// ports.
	add(c.Container != nil && c.everyPlacementHasIngress(), compute.CapPlatformIngress)
	// Route-specific auth capabilities also require the shared-cookie
	// boundary: without it every application-host route is refused.
	routesSafe := c.Container != nil && strings.TrimSpace(c.Container.IngressCookieStripMiddleware) != ""
	add(routesSafe && c.Container.IngressAuthMiddleware != "", compute.CapIngressAuth)
	add(routesSafe && c.Container.MCPAuthBackendURL != "", compute.CapMCPAuth)
	// Deliberately absent, each for a reason a caller can act on:
	//
	//   CapObjectStoreZonal — S3 Express One Zone directory buckets. The source
	//     system provisions them (bucket.go:290-336) and this provider refuses
	//     ObjectClassZonal, because the ownership check the contract requires
	//     cannot be built on them: a directory bucket has no bucket-level
	//     tagging, so there is nowhere to put the marker that distinguishes a
	//     bucket this platform created from one it merely found. See
	//     docs/decisions/usoss-13-the-aws-provider-does-not-offer-zonal-object-storage.md.
	//   CapImagePullGrants — ECR authorises an IAM principal, and on ECS the
	//     principal that pulls is the task *execution* role rather than the
	//     workload. A grant naming the application's identity would authorise a
	//     principal that never makes the request. See [imageRegistry] for the
	//     evidence from the source system's own side.
	//
	//   CapIngressAuth — [compute.Route.RequireAuth] is a property of the
	//     platform's reverse proxy, and this port creates a load balancer of its
	//     own rather than registering with that proxy. An ALB can authenticate
	//     with authenticate-oidc, but [compute.EndpointSpec] has no field
	//     through which a caller could ask for it, so there is nothing to
	//     advertise. See the report accompanying USOSS-12.
	return caps
}

// placement resolves a [compute.Placement] against the configured set.
//
// An unconfigured name is [compute.ErrInvalidSpec] rather than a fallback. The
// source system's equivalent — an unusable region degraded to a logged warning
// and a silent default — strands a resource somewhere nothing addresses.
func (c *Config) placement(p compute.Placement) (PlacementConfig, error) {
	name := p.Name
	if name == "" {
		name = c.DefaultPlacement
		if name == "" {
			return PlacementConfig{}, fmt.Errorf(
				"%w: the spec names no placement and this provider has no default; configure "+
					"Config.DefaultPlacement or name one of %v",
				compute.ErrInvalidSpec, c.placementNames())
		}
	}
	pc, ok := c.Placements[name]
	if !ok {
		return PlacementConfig{}, fmt.Errorf(
			"%w: placement %q is not configured on this provider; configured placements are %v",
			compute.ErrInvalidSpec, name, c.placementNames())
	}
	pc.Name = name
	if pc.Region == "" {
		pc.Region = c.Region
	}
	return pc, nil
}

// everyPlacementHasIngress reports whether a platform-ingress rule could be
// honoured in every configured placement.
func (c *Config) everyPlacementHasIngress() bool {
	if len(c.Placements) == 0 {
		return false
	}
	for _, pc := range c.Placements {
		if len(pc.PlatformIngressSecurityGroups) == 0 {
			return false
		}
	}
	return true
}

func (c *Config) placementNames() []string {
	out := make([]string, 0, len(c.Placements))
	for name := range c.Placements {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (c *BuildConfig) sessionDuration() time.Duration {
	if c.SessionDuration <= 0 {
		return DefaultSessionDuration
	}
	if c.SessionDuration > MaxSessionDuration {
		return MaxSessionDuration
	}
	return c.SessionDuration
}

// validateSessionDuration refuses a configured duration the security token
// service would reject. Checked at construction, so a deployment that would fail
// on its first build fails on start instead.
func (c *BuildConfig) validateSessionDuration() error {
	if c.SessionDuration != 0 && c.SessionDuration < MinSessionDuration {
		return fmt.Errorf("Config.Build.SessionDuration is %s and the security token service "+
			"will not issue a credential shorter than %s; it is refused rather than rounded up, "+
			"because how long a credential that can write to a registry lives is the "+
			"operator's decision", c.SessionDuration, MinSessionDuration)
	}
	return nil
}

func (c *BuildConfig) maxContextBytes() int64 {
	if c.MaxContextBytes <= 0 {
		return DefaultMaxContextBytes
	}
	return c.MaxContextBytes
}

// hasPlatformIngress reports whether every configured placement names an ingress
// proxy.
//
// Every, not any, and the conservative reading is deliberate. The capability is
// provider-level while the configuration is per-placement, so a provider that
// had it in one placement and not another would advertise a capability that is
// true for some specs and false for others — and the whole point of
// [compute.CapPlatformIngress] is that a caller can find out *before* it
// deploys. [compute.CapWorkloadGrants] states the same rule for the same reason:
// "a caller that is told grants work and then finds they work on one port is
// worse off than one told nothing works."
func (c *Config) hasPlatformIngress() bool {
	if len(c.Placements) == 0 {
		return false
	}
	for _, pc := range c.Placements {
		if strings.TrimSpace(pc.PlatformIngressSecurityGroupID) == "" {
			return false
		}
	}
	return true
}

// runtimes is the configured runtime set, sorted, for a stable refusal message.
func (c *FunctionConfig) runtimes() []string {
	out := make([]string, 0, len(c.Runtimes))
	out = append(out, c.Runtimes...)
	sort.Strings(out)
	return out
}

// allowsRuntime reports whether the operator configured this runtime.
func (c *FunctionConfig) allowsRuntime(runtime string) bool {
	for _, r := range c.Runtimes {
		if r == runtime {
			return true
		}
	}
	return false
}

func (c *FunctionConfig) defaultArchitecture() compute.Architecture {
	if c.DefaultArchitecture == "" {
		return DefaultFunctionArchitecture
	}
	return c.DefaultArchitecture
}

func (c *FunctionConfig) maxInlineBytes() int64 {
	if c.MaxInlineBytes <= 0 {
		return DefaultMaxInlineBytes
	}
	return c.MaxInlineBytes
}

func (c *FunctionConfig) description() string {
	if c.Description == "" {
		return DefaultFunctionDescription
	}
	return c.Description
}

func (c *EndpointConfig) description() string {
	if c.Description == "" {
		return DefaultEndpointDescription
	}
	return c.Description
}
