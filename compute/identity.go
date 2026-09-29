// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"

	"github.com/conductorone/apphub/credentials/workload"
)

// WorkloadIdentitySpec asks a provider for a runtime identity a workload can
// run as.
//
// Every deployed application needs one: something the substrate authenticates
// it as, so that access to a bucket or a table can be granted to *it* rather
// than to a shared credential. On AWS this is an IAM role with a trust policy
// naming ecs-tasks.amazonaws.com or lambda.amazonaws.com (build.go:619-666,
// lambda.go:935-985); on Kubernetes it is a ServiceAccount. The interface names
// the need and lets the provider pick the mechanism — no trust-policy JSON, no
// service principals, no role ARNs.
type WorkloadIdentitySpec struct {
	// Name is the logical name, stable across deploys of the same application.
	Name string

	// Placement says where the identity lives, and it must match the placement
	// of every workload that will run as it.
	//
	// This field looks redundant on AWS, where an IAM role is account-global and
	// the provider places nothing. It is still validated there rather than
	// ignored: a provider has one placement and a spec naming one it was not
	// configured with is [ErrInvalidSpec], because a caller that asked for one
	// region and silently got another has been handed a resource it did not ask
	// for. An earlier draft said such a provider "can ignore it", which is wrong
	// in the fail-open direction. It is load-bearing everywhere the
	// substrate scopes identity: a Kubernetes pod may only run as a
	// ServiceAccount in its own namespace, and a [Placement] is a namespace. So
	// without this field, a provider must put every identity in one fixed place
	// and a workload placed anywhere else cannot run as any identity at all —
	// which bites the first time a platform has two placements, and [Placement]
	// is the documented answer to multi-region.
	//
	// Empty means the provider's default placement; a provider with no default
	// returns [ErrInvalidSpec] rather than guess.
	Placement Placement

	// RunsOn says which runtime will assume this identity, because on some
	// substrates the identity is not interchangeable between them: an AWS role
	// trusted by ecs-tasks.amazonaws.com cannot be assumed by Lambda.
	//
	// It is advisory. A provider whose identities are interchangeable between
	// runtimes MAY ignore it — a Kubernetes ServiceAccount attaches equally to a
	// Deployment, a CronJob's pods, and a Knative Service — in which case two
	// specs differing only in RunsOn name the same identity and return the same
	// [Ref]. A caller that needs two distinct identities MUST give them two
	// names rather than rely on this field to separate them.
	RunsOn RuntimeKind

	// Labels are non-secret metadata for operator tooling and ownership
	// tagging.
	Labels map[string]string
}

// RuntimeKind names which runtime a workload identity is for.
type RuntimeKind string

// The runtimes an identity can be scoped to.
const (
	RuntimeContainer RuntimeKind = "container"
	RuntimeFunction  RuntimeKind = "function"
)

// WorkloadIdentity is a provider-issued runtime identity.
//
// # The compute / credentials boundary
//
// The source system entangles the two layers. Deploy injects environment
// variables and a rotating secret into the container (source system @
// backend/internal/modules/deploy/container.go) so
// that the application can, at runtime, presign an STS GetCallerIdentity call
// and trade it plus the secret for a short-lived token; the platform side
// replays that call against AWS STS to learn the caller's IAM role ARN and
// decide whether it matches the application (auth/sts_verify.go:21-52). AWS STS
// is therefore in the request path of every deployed application, and the check
// that authorises it lives in the credential layer while the identity it checks
// is created here.
//
// The split, which is normative and is owned by the shared contract rather than
// by this package:
//
//   - Compute *creates and reports*. It provisions the identity, arranges for
//     the runtime to hold it, and reports a [workload.ExpectedAttestation]
//     describing what a valid proof will have to resolve to. It never mints,
//     transports, validates, caches, or stores a proof, and it never calls a
//     credential API.
//   - The credential layer *verifies*. It receives that expected value and the
//     proof a workload submitted, and checks one against the other. It never
//     learns what an IAM role or a ServiceAccount is.
//   - The deploy layer *persists and joins*. It stores the expected attestation
//     when a deploy succeeds, and it performs the one conversion from the
//     credential layer's secret references to [SecretBinding] — see
//     [SecretBinding] for why that conversion cannot live in either package.
//
// The vocabulary for all of this is defined once, in credentials/workload, and
// imported here. It used to be defined twice, and the two definitions did not
// compose: same type name, two different meanings, two spellings of the same
// AWS scheme identifier. A parallel definition in this package is a bug against
// the contract even if it is field-for-field identical.
type WorkloadIdentity struct {
	// Ref addresses the identity. It is what a spec's Identity field and every
	// Grant call takes.
	Ref Ref

	// Attestation is the stored policy describing what a valid proof of this
	// identity must resolve to. It carries no secret material, so the deploy
	// layer can persist it on the application record and the verifier can read
	// it back on every token request.
	//
	// A provider whose substrate offers no way for a running workload to prove
	// its identity outward leaves the zero value here, whose Method is empty. A
	// verifier handed an empty Method must refuse rather than improvise: it
	// means workload identity does not work on that provider, which is
	// information, not a failure of the interface.
	Attestation workload.ExpectedAttestation

	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec WorkloadIdentitySpec
}

// AccessLevel is the coarse permission a workload gets on a resource.
//
// Coarse on purpose. The source system writes bespoke IAM statements per
// resource type — five S3 actions for a general bucket, eleven for an S3 Tables
// bucket, eight DynamoDB actions plus an index wildcard (source system @
// backend/internal/modules/deploy/bucket.go and database.go).
// Reproducing that granularity portably would mean either
// inventing a policy language, or admitting AWS action strings into the
// interface. Neither is worth it for a set of grants whose real cardinality is
// "the app can read its own bucket" and "the app can write its own table".
//
// The cost is stated in the design doc: two providers implementing
// [AccessReadWrite] will not produce identical permission sets, and a
// least-privilege audit has to be done per provider, against that provider's
// documented mapping. The conformance suite checks behaviour ("after
// AccessRead, a read succeeds and a write fails"), which is the part that is
// actually portable.
type AccessLevel string

const (
	// AccessRead permits reading data and the metadata needed to find it.
	AccessRead AccessLevel = "read"
	// AccessReadWrite permits reading, writing, and deleting data.
	AccessReadWrite AccessLevel = "read-write"
	// AccessAdmin permits schema or structural changes as well as data access.
	AccessAdmin AccessLevel = "admin"
)

// WorkloadCapability is a platform-level ability granted to *the workload's own
// identity*, not tied to a specific resource.
//
// The qualifier is the whole definition, and getting it wrong is a privilege
// escalation rather than a missing feature. A capability belongs here only if
// the principal exercising it is the workload itself. Interactive shell access
// does not qualify — the principal there is the operator opening the session,
// not the workload receiving it — and is modelled as [ServiceSpec.ExecEnabled]
// instead. See that field for the full argument.
//
// Capabilities are declarative. The set on a spec is the complete desired set,
// so removing one revokes it — which is what the source system open-codes as a
// detach call whose omission would silently leave the grant in place
// (build.go:763-779).
type WorkloadCapability string

const (
	// WorkloadCapabilityModelInference lets the workload call the substrate's
	// managed foundation-model service with its own runtime identity, instead
	// of apphub vending it a separate, expiring API credential. Requires
	// [CapModelInference].
	//
	// This one genuinely is a workload-identity capability: the calling
	// principal is the application, at runtime, using the identity this grant
	// is attached to.
	WorkloadCapabilityModelInference WorkloadCapability = "model-inference"
)

// Requires reports the [Capability] a provider must advertise before a spec may
// request this workload capability.
//
// It exists so the relationship is data rather than prose. The conformance
// suite enumerates [WorkloadCapabilities] and drives each one against a
// provider that lacks its capability, expecting [ErrUnsupported]; with the
// requirement written only in a doc comment, that enumeration could not be
// written and a capability added later would be silently uncovered.
//
// An unrecognised value returns the empty [Capability], which a provider must
// treat as [ErrInvalidSpec] rather than as "no requirement".
func (c WorkloadCapability) Requires() Capability {
	switch c {
	case WorkloadCapabilityModelInference:
		return CapModelInference
	default:
		return ""
	}
}

// WorkloadCapabilities returns every valid [WorkloadCapability].
//
// Exported so a provider can validate a spec against the closed set and so the
// conformance suite can drive every capability the provider does not advertise
// and require [ErrUnsupported]. The list is deliberately short; see
// [WorkloadCapability] for what disqualifies a candidate.
func WorkloadCapabilities() []WorkloadCapability {
	return []WorkloadCapability{
		WorkloadCapabilityModelInference,
	}
}

// WorkloadGrantPorts names every core interface that embeds [Granter], as
// decided by the audit documented there.
//
// It is a list of names rather than of types because its only consumer is a
// test that reflects over the package's interfaces and compares the two sets.
// Adding Granter to a port without adding it here — or the reverse — fails that
// test, which is the mechanism that turns the rule from a convention into a
// build failure.
func WorkloadGrantPorts() []string {
	return []string{"KeyValueProvisioner", "ObjectStore"}
}

// IdentityService manages runtime identities. It is not a capability of its
// own: every provider that can run anything must be able to give what it runs
// an identity, even if that identity is only meaningful locally.
type IdentityService interface {
	// EnsureWorkloadIdentity creates or returns the identity for spec.
	// Idempotent.
	EnsureWorkloadIdentity(ctx context.Context, spec WorkloadIdentitySpec) (*WorkloadIdentity, error)

	// DescribeWorkloadIdentity returns an existing identity, or [ErrNotFound].
	// Teardown and the verifier-refresh path need to read an identity back
	// without recreating it.
	DescribeWorkloadIdentity(ctx context.Context, ref Ref) (*WorkloadIdentity, error)

	// DeleteWorkloadIdentity removes an identity. Deleting an absent identity
	// returns nil.
	//
	// A provider SHOULD also remove grants made to the identity through its own
	// [Granter] ports, and MUST return [ErrFailed] if it cannot — a silently
	// orphaned grant outlives the identity's name and can be inherited by the
	// next identity that claims it.
	//
	// It is only SHOULD, and only for this provider's own ports, because the
	// stronger reading is a promise the interface provides no mechanism for. On
	// AWS the grants are inline policies on the role and vanish with it; on a
	// composed provider they live in an object store's policy document and a
	// registry's account list — separate systems, possibly separate credentials,
	// not always enumerable. Requiring a cascade across all of them would oblige
	// a guarantee with no way to report partial failure. Grants made on a
	// substrate this provider does not administer are the caller's to revoke.
	DeleteWorkloadIdentity(ctx context.Context, ref Ref) error
}

// Granter is implemented by the ports that own resources whose access control
// is expressed in terms of a substrate workload identity.
//
// # The rule, and why it is a rule
//
//	Granter goes on a port only when the substrate's own access control can be
//	expressed in terms of the workload identities this provider issues.
//
// "Can" is about the substrate, not about one deployment's configuration. A
// port whose substrate has an identity-based policy model keeps Granter even
// where a particular backend is not federated; it reports that as
// [ErrUnsupported] from Grant, and advertises the absence of
// [CapWorkloadGrants] so a caller can find out before it deploys rather than
// after. A port whose substrate has no such model *anywhere* does not get
// Granter at all, because the only implementation is one that invents a
// principal or mints a credential behind the caller's back.
//
// This rule was written once and then not applied, which is how the same defect
// reached three ports. It is now enforced by test rather than by memory:
// [WorkloadGrantPorts] is the audited list and compute/contract_test.go fails
// the build if the set of core interfaces embedding Granter stops matching it.
// A fourth instance is a red build, not a fifth review.
//
// # The audit
//
//   - [ObjectStore] — keeps it. S3 authorises by IAM principal natively; an
//     S3-compatible store federating the cluster's OIDC issuer authorises a
//     ServiceAccount subject. The model exists; a deployment may lack it.
//   - [KeyValueProvisioner] — keeps it. DynamoDB grants to an IAM role and has
//     no database-internal principal at all.
//   - The compute/ext bucket ports — keep it. Same substrate, same IAM.
//   - [RelationalProvisioner] — removed. Access is a SQL role created with
//     ordinary SQL above this interface, and no substrate identity maps to one.
//   - [ImageRegistry] — removed. No registry federates any identity provider,
//     and the principal that pulls is the node or the execution role rather
//     than the workload. See [ImageRegistry] for the full argument.
//   - [SecretStore], [ContainerRuntime], [FunctionRuntime], [ImageBuilder] —
//     never had it and must not. They consume identities or hold obligations;
//     none of them owns a resource a workload is granted access to.
//
// Keeping the shape identical across the ports that do have it is what lets the
// conformance suite test grant semantics once.
type Granter interface {
	// Grant gives identity the stated level of access to resource. Idempotent,
	// and last-write-wins on level: granting [AccessRead] after
	// [AccessReadWrite] narrows the access rather than adding a second grant.
	Grant(ctx context.Context, resource Ref, identity Ref, level AccessLevel) error

	// Revoke removes any access identity has to resource. Revoking an absent
	// grant returns nil.
	Revoke(ctx context.Context, resource Ref, identity Ref) error

	// DescribeGrant reports the access identity currently has to resource.
	//
	// [ErrNotFound] when the pair has no grant, [ErrForeignRef] for a Ref this
	// provider did not issue, and the same [UnsupportedError] Grant returns when
	// the provider does not advertise [CapWorkloadGrants] — a provider that
	// cannot make a grant cannot be asked what it made.
	//
	// It must report what the substrate holds, never what a caller asked for.
	// Returning the last requested level from memory would satisfy every check
	// below while making a grant that never reached the substrate look present,
	// which is the failure this method exists to expose rather than to hide.
	//
	// # Why the pair, and not an enumeration
	//
	// The obvious shape is "list the grants on this resource", and it is the one
	// shape neither substrate here can serve. A grant is stored wherever the
	// substrate's access control puts it, and the two in this repository put it
	// at opposite ends:
	//
	//   - compute/aws writes an inline IAM policy on the *identity's* role
	//     (compute/aws/objectstore.go:498-521, compute/aws/keyvalue.go:251-306),
	//     because a resource policy is one document per resource that two
	//     providers would contend for. Enumerating a bucket's grants there means
	//     enumerating every role in the account.
	//   - compute/k8s writes a policy on the *bucket* keyed by OIDC subject
	//     (compute/k8s/objectstore.go:183-215). Enumerating an identity's grants
	//     there means enumerating every bucket in the store.
	//
	// So each substrate can enumerate cheaply in one direction and only by brute
	// force in the other, and the two directions are not the same one. The pair
	// is what both hold directly, and it is what the interface is already keyed
	// on: Grant and Revoke "affect only the pair they name" is stated above and
	// checked by the conformance suite. A read-back keyed on anything else would
	// be answering a question the write side cannot ask.
	//
	// [ext.ExternalAccessGranter] resolves this the other way and says why: a
	// cross-domain grant lives in a resource policy, so there the enumeration is
	// the cheap direction *and* the only shape that closes the reconciliation
	// gap that port documents.
	//
	// # What it is for
	//
	// Reconciliation, and observability of this interface's own contract.
	//
	// Before it, every consumer that needed to verify its own behaviour had to
	// reach outside the interface: compute/aws grew Harness.Grants and
	// compute/fake grew Harness.ExternalGrants, independently, each a
	// non-portable harness method added because an unobservable contract cannot
	// be asserted portably. Two providers proving their own compliance with
	// their own instrument is not two providers being checked against one
	// contract. USOSS-73 recorded the third instance as the trigger.
	//
	// The conformance suite's grant invariants could otherwise only be checked
	// behaviourally, through the Options.Read and Options.Write data-plane hooks
	// — the hardest part of a provider's harness, and absent often enough that
	// the checks that need them skip. With this, "the level that was granted is
	// the level that stands" is observable through the interface itself, so a
	// provider whose Revoke does nothing fails whether or not it supplied a
	// harness. One did pass the entire suite; see USOSS-37.
	DescribeGrant(ctx context.Context, resource Ref, identity Ref) (*GrantInfo, error)
}

// GrantInfo is what [Granter.DescribeGrant] reports about one standing grant.
//
// # Why the resource does not have to exist for the answer to be meaningful
//
// It does not, and both absences are [ErrNotFound]. A resource that is not there
// holds no grants, so "there is no grant on this pair" is true either way, and it
// is the fact a reconciling caller acts on. A caller that needs to tell the two
// apart already has a port read-back — [ObjectStore.DescribeBucket],
// [KeyValueProvisioner.DescribeKeyValueTable] — and asking it is one call rather than a
// second sentinel every provider would have to get right.
//
// # Why there is no "level: none"
//
// Because [AccessLevel] has three values and none of them means "no access". An
// absent grant reported as a fourth level would put the distinction between "no
// access" and "some access" inside a string comparison on a type whose zero value
// is the empty string, which is the shape a caller gets wrong by forgetting a
// case. [ErrNotFound] is the answer a caller cannot forget to handle, and it is
// what [SecretStore.Describe] already returns for the same question.
type GrantInfo struct {
	// Resource is the resource the grant is on, as the provider recognises it.
	Resource Ref
	// Identity is the workload identity that holds it, likewise.
	Identity Ref
	// Level is the access that stands, read from the substrate.
	//
	// It is the level a provider would have to render the same policy from
	// again, not a level it remembered writing. A provider whose substrate holds
	// a grant it cannot map back onto one of the three defined levels — because
	// something outside this platform rewrote it — returns [ErrFailed] rather
	// than guessing, since guessing low under-reports an access that exists and
	// guessing high reports one that does not.
	Level AccessLevel
}
