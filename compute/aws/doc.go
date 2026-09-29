// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package aws implements the Compute provider interface on AWS.
//
// This is the first-class production implementation: container services and
// scheduled jobs on ECS, functions on Lambda behind an ALB, object storage on S3,
// databases on DynamoDB and Aurora, and image builds into ECR (USOSS-10 through
// USOSS-14 and USOSS-33).
//
// Landed so far: the image registry, the image builder and workload identity
// (USOSS-10), the container runtime with secret injection by reference,
// interactive-session and model-inference grants, per-service security groups
// and platform-ingress routes (USOSS-11), the function runtime with
// function-endpoint (USOSS-12), and EventBridge Scheduler backed scheduled jobs
// (USOSS-33).
//
// # Two fail-closed rules that run through the whole package
//
// Both are places the source system fails open, and both are enforced by
// refusing a spec rather than by adjusting one, because the alternative to
// refusing is always a boundary widened on the caller's behalf.
//
//   - **A configuration value that is missing never widens anything.** No
//     ingress proxy configured means a [compute.PeerPlatformIngress] rule is
//     refused, not turned into [compute.PeerInternet]. No certificate
//     configured for a reference means a TLS listener is refused, not created
//     without one. No placement configured under the name a caller gave means a
//     refusal, not the default.
//   - **A field this substrate cannot honour is refused, not ignored.** A
//     placement in another region, an explicit CPU allocation on Lambda, a
//     secret binding Lambda cannot resolve at launch, an ingress rule on a
//     function that has no inbound surface. Accepting any of them would report
//     something the provider did not do.
//
// # Three rules review had to establish, which generalise past this package
//
//   - **An ownership marker goes on a tag, never on caller-influenceable free
//     text.** A signal is only as trustworthy as the permission needed to forge
//     it, and free text needs none. Reading ownership from a description failed
//     in both directions at once here — a rule with an ordinary caller
//     description was never revoked, and an operator rule whose wording merely
//     mentioned the project was deleted. Match the tag exactly; a longer
//     substring closes one witness and leaves the next spelling available.
//   - **Teardown removes everything it created, or reports what remains.** No
//     third outcome. See [functionRuntime.DeleteEndpoint]: its documented
//     two-call path returned success while leaving a security group behind, and
//     the surviving group's own ownership tags meant the next Ensure would adopt
//     it with the old rule set.
//   - **Readiness is the whole construction, not its first object.** An active
//     load balancer whose only target is unhealthy answers every request with a
//     502. See [endpointPhase]. The distinction was being destroyed below
//     [Substrate]: the adapter called DescribeTargetHealth and kept only the
//     identifiers, so the layer above could only treat registration as health.
//
// # What is here today
//
// USOSS-10, which is the image path: [compute.ImageRegistry] on ECR,
// [compute.ImageBuilder] on kaniko — building with no credential and pushing from
// a second process, per USOSS-41 — and [compute.IdentityService] on IAM roles.
// The last of those is here rather than with the container runtime because it
// is not capability-gated — every provider must be able to give what it runs an
// identity — so a provider that vends only a registry and a builder still needs
// one.
//
// USOSS-12, which is the function path: [compute.FunctionRuntime] on Lambda for
// the function half and on ELBv2 for the endpoint half, over its own EC2
// primitive layer (endpointnetwork.go, [EndpointEC2API]) that resolves a
// [compute.Placement] to network coordinates and compiles [compute.IngressRule]
// into security group rules for the load balancer's security group.
//
// That layer is deliberately *not* shared with [EC2API] — the relational port
// (USOSS-14) and the container port (USOSS-11) each independently wrote their
// own EC2 primitive layer under the filename this port's own design document
// assigned it, before either could rebase onto the other; see the doc comment
// on [Substrate.EndpointEC2] for why converging onto one shared interface was a
// larger and riskier change than keeping this port's own, once two other ports
// were already built and tested against [EC2API]'s narrower, untagged shape.
//
// It creates **no IAM role**. A function's execution role arrives as
// [compute.FunctionSpec.Identity] and is resolved through the workload-identity
// port that already owns that account-global namespace, with the trust policy
// checked so that a container identity cannot silently produce a function Lambda
// cannot start.
//
// Every other port refuses at acquisition, typed, naming the provider, the
// capability, and the ticket that owns it. None of them is a stub that accepts
// a call and does nothing.
//
// # What an operator supplies
//
// Everything site-specific, and there are no defaults. No account identifier,
// ARN, role name, registry host, repository prefix, region, VPC, subnet, or
// security-group ID appears anywhere in this package: [Config] is the complete
// list of what has to be configured, and a provider built from a zero Config
// can do nothing, which is the intended failure mode for a misconfigured
// deployment.
//
// The rule is stronger than "no secrets". An AWS account ID is twelve digits
// with no entropy and an internal hostname is just a hostname; neither is
// secret in the cryptographic sense and both are disclosures this repository
// must not make. So the provider never *composes* one either: a repository's
// ARN, its registry-qualified URI, and a role's ARN are all read back from the
// service that owns them, and the identifiers a [compute.Ref] carries are
// resource names rather than ARNs.
//
// # The AWS account is the ownership trust boundary
//
// Ownership is by exact AWS tags, not by names or descriptions. That is the
// right boundary inside one operator-controlled account, and it is not a
// cryptographic attestation: any principal in the same AWS account that can set
// the reserved `apphub:` ownership tags on a resource can make that resource
// present as one this provider owns. For object storage, a bucket carrying
// `apphub:managed-by=apphub` and `apphub:component=object-bucket` is inside
// the provider's ownership set.
//
// Treat that as an account/trust-boundary limitation, not as a provider bug.
// Cross-tenant deployment on a shared AWS account is not supported unless every
// tenant is inside the same trust boundary; otherwise give each tenant an
// isolated AWS account or an equivalent boundary that prevents it from writing
// the reserved tag namespace. The publication audit should carry this as an
// accepted limitation; see
// docs/decisions/usoss-62-ownership-by-tag-is-aws-account-scoped.md.
//
// # The credential path, which is the sharp edge
//
// A Dockerfile RUN instruction executes code the repository's author wrote,
// inside a process this package starts. So:
//
//   - The build assumes a dedicated role under an STS session policy scoped to
//     exactly the repositories it may push to, for fifteen minutes. Both halves
//     are least-privilege machinery preserved from the source system, and
//     widening either to make something work is a finding to report rather than
//     a change to make. See [pushSessionPolicy].
//   - A build with no push role configured is refused at construction. There is
//     no fallback to apphub's own credentials, because that fallback is the
//     vulnerability. See [BuildConfig.PushRoleARN].
//   - The build's environment is an allowlist built from scratch, never a
//     filtered copy of apphub's. The ambient container-credential variables
//     are not in it. See [buildEnvAllowlist].
//   - The credential is a [credentials.Secret] from the moment it exists, and
//     becomes a string in exactly two functions — one that puts it in the
//     builder's process environment and one that takes it back out of an error.
//     See [withCredentials] and [redactCredentials].
//   - A destination must resolve to a repository this provider itself issued,
//     checked before any credential is minted, so a build cannot ask for a
//     scope the operator never configured. See [imageBuilder] for the full list
//     of what an attacker who controls a build input can and cannot reach.
//
// # Testing
//
// [Substrate] is the seam. The conformance suite runs against
// [NewMemorySubstrate] with no network, no credentials, and no account;
// [NewSDKSubstrate] wires the real clients, and everything above the seam is
// the same code either way. The fixtures the in-memory substrate reports
// contain no AWS identifier of any kind — see [MemoryAccount] for why that is a
// deliberate property and not an oversight.
//
// The conformance suite is the contract and this provider passes it. The suite
// scopes itself to the ports a provider advertises, so the counts differ per
// configuration; re-derive them rather than trusting this paragraph after a
// change, which is why the command is written down. Counting
// `go test -run '^TestConformance…$' -v` output:
//
//   - the full configuration runs 163 checks, 158 pass and 5 skip;
//   - the registryless one runs 65, of which 40 pass and 25 skip;
//   - the endpointless one runs 149, of which 144 pass and 5 skip.
//
// These three counts grew from the port's original 83/43/69 once this branch
// rebased onto the relational and key-value ports (USOSS-14), the deploy
// module (USOSS-15), the container runtime (USOSS-11), and general-purpose
// object storage (USOSS-13): fullConfig now advertises every port those
// tickets add alongside function and function-endpoint, and the
// registryless/endpointless configurations inherit the same growth because
// they are fullConfig with one or two capabilities removed rather than a
// config built from nothing. Re-derive them again rather than trusting this
// paragraph after the next change.
//
// Nothing fails in any of the three. There are three configurations rather than
// two because one invariant is unreachable from either of the others:
// a provider that advertises [compute.CapFunction] and not
// [compute.CapFunctionEndpoint] is the only one whose EnsureEndpoint has a
// refusal to observe.
//
// **Three** of the skips matter and none is silently accepted:
//
//   - the two secret-material gates need a secret store to plant their sentinel,
//     and this provider has none;
//   - placement-is-an-operator-configured-name drives the container, bucket,
//     relational and secret ports, so it skips here even though **both** of this
//     package's ports take a [compute.Placement]. That is a gap in the suite
//     rather than in this package;
//
// Each has a local replacement that names the check it stands in for.
//
// The authorization-failure check used to be a fourth, and how it stopped being
// one is worth recording. It skipped here for want of an Options.InduceDenial
// hook while this provider still mapped a denial to [compute.ErrFailed]; USOSS-55
// landed the mapping and the hook together, which is exactly what that pairing
// was for. But the check is **provider-level**, so it then went green on this
// provider by driving the two ports the hook armed — an image repository and a
// workload identity — while the two function ports fell to its default arm and
// were never exercised. Measured: 2 of 4 ports, with the check passing either
// way. Arming them takes it to 4 of 4. The only reason the gap was visible is
// that the check names the ports it drove.
//
// It was four until USOSS-32, and the two corrections it made are worth
// recording because they cut both ways. The [compute.ErrTransient] gate used to
// skip for want of a secret store and now drives whichever port a provider has,
// so it **runs** here — this package's own per-method test is now a stronger
// population rather than the only coverage. And secret-material-in-artefacts
// used to report a vacuous *pass*, scanning for a sentinel nobody planted; it
// now reports an honest skip. Re-derive these rather than trusting this
// paragraph. They have moved five times in one session, once holding constant
// across USOSS-32 purely by coincidence with one check moving each way — and a
// number stable for the wrong reason is worse than one that moved, because it
// actively reassures.
package aws
