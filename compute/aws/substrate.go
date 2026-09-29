// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Substrate is every AWS service this provider talks to, behind an interface
// each.
//
// # Why the seam is here and not at the SDK client
//
// Two reasons, and the second is the one that matters.
//
// The first is testability: the conformance suite is the contract, and it has
// to run with no network, no credentials, and no account. [NewMemorySubstrate]
// supplies in-memory implementations that behave like the services do, and
// awssdk.go supplies the real ones. Everything above this struct — every line
// where the compute contract and an AWS API have to be reconciled — is the same
// code either way.
//
// The second is that it is the only place a credential-bearing call can be
// counted. [STSAPI] has exactly one method; a reviewer asking "where can this
// package mint a credential" gets a complete answer by reading one interface,
// rather than by trusting that a grep for AssumeRole found every call site.
type Substrate struct {
	// ECR is the container registry. Nil when no registry is configured.
	ECR ECRAPI
	// IAM is the identity service. Required: every provider must be able to
	// give what it runs an identity.
	IAM IAMAPI
	// STS mints the build's scoped push credential. Nil when no builder is
	// configured.
	STS STSAPI
	// Builder runs the image build. Nil when no builder is configured.
	//
	// It is handed no credential, and [BuildCommand] has no field that could
	// carry one. See [ImagePusher] for the other half.
	Builder BuildRunner
	// Pusher publishes what the build produced. Nil when no builder is
	// configured.
	//
	// A second port rather than a second method on [BuildRunner], because the
	// separation is the security property: the process that executes the
	// Dockerfile and the process that holds the push credential must be
	// different processes, and two interfaces is how an implementation is
	// stopped from quietly being one.
	Pusher ImagePusher

	// Lambda runs code bundles as functions. Nil when no function runtime is
	// configured.
	Lambda LambdaAPI
	// ELBv2 fronts a function with a load balancer. Nil when no function
	// endpoint is configured.
	ELBv2 ELBv2API
	// EndpointEC2 is the network surface a function endpoint's security group
	// needs. Nil when no function endpoint is configured.
	//
	// A second network field rather than a reused [EC2API]: the relational port
	// (USOSS-14) and this one each independently wrote an EC2 primitive layer
	// before either rebased onto the other, and [EC2API] is [RDS]'s -- narrower
	// on protocol (no ICMP, no prefix lists) and untagged at the rule level,
	// which is what that port needs and no more. This port's rules need their
	// own identifier and tags -- see [EndpointSecurityGroupRule] -- so the two
	// surfaces stay distinct rather than one being bent to fit the other's
	// caller.
	EndpointEC2 EndpointEC2API

	// Parameters is SSM Parameter Store, and it is the only member the secret
	// store uses. Narrow on purpose -- but NOT value-free, and the earlier
	// wording here said it was: [ParameterStore.Get] returns a value, because
	// something has to. The accurate claim is narrower and still worth making:
	// exactly one of the port's seven operations returns material, it has exactly
	// one caller, and no operation LISTS values -- so there is no
	// correct-looking path that reads a value without meaning to.
	//
	// A doc claiming the interface has no value-returning method, in the port
	// whose subject is keeping values off surfaces, is the worst place for that
	// sentence to be wrong.
	Parameters ParameterStore

	// RDS is the managed-SQL service. Nil when no relational database is
	// configured.
	RDS RDSAPI
	// EC2 is the network service. Nil when neither a relational database nor a
	// container runtime is configured: it carries the security group that
	// fronts a database endpoint (USOSS-14) and the per-service group a
	// container service's ingress rules are written onto (USOSS-11), and
	// nothing else in this package is placed on a network.
	EC2 EC2API
	// DynamoDB is the key-value service. Nil when no key-value table is
	// configured.
	DynamoDB DynamoDBAPI

	// ECS runs container services. Nil when no container runtime is
	// configured (USOSS-11).
	ECS ECSAPI
	// Scheduler runs ECS tasks on a cadence. Nil when the scheduled-job
	// capability is not configured.
	Scheduler SchedulerAPI
	// S3 is general-purpose object storage. Nil when object storage is not
	// configured.
	S3 S3API
	// S3Tables provisions table buckets, reached only through
	// [ext.TableBucketProvisioner]. Nil when not configured, which is the
	// common case: a table bucket is not portable and no core path asks for
	// one.
	S3Tables S3TablesAPI
	// S3Vectors provisions vector buckets, reached only through
	// [ext.VectorBucketProvisioner]. Nil when not configured.
	S3Vectors S3VectorsAPI
}

// The substrate's own error vocabulary.
//
// A substrate reports these; [Provider.substrateError] maps them onto the
// [compute] taxonomy. They are sentinels rather than a mapping done inside each
// adapter so that the in-memory substrate and the SDK one reach the taxonomy
// through the same code, and a defect in the mapping is one defect rather than
// two.
var (
	// ErrNoSuchResource is the substrate's 404.
	ErrNoSuchResource = errors.New("aws: no such resource")

	// ErrAlreadyExists is a create that raced another create.
	ErrAlreadyExists = errors.New("aws: the resource already exists")

	// ErrThrottled is a request the service refused for rate reasons, and the
	// single most common retryable failure on AWS. It maps to
	// [compute.ErrTransient] and must not map to [compute.ErrFailed]: a caller
	// told its spec has to change abandons a deploy that would have worked on
	// a second attempt.
	ErrThrottled = errors.New("aws: the service throttled this request")

	// ErrDenied is an authorization failure. It is terminal for the call: a
	// retry with the same principal cannot help.
	ErrDenied = errors.New("aws: the service denied this request")

	// ErrMalformed is an input the service could not parse: a badly-formed
	// identifier, a permission specification it cannot read.
	//
	// It exists because collapsing it into [ErrNoSuchResource] is a live defect
	// and not a tidiness question. **Malformed, invalid and absent are three
	// answers, not two.** Absence is a state a caller may create — so a provider
	// that reads it takes the create branch, or reports "nothing is here" — and
	// a malformed input is a mistake the caller must fix. Review found
	// EC2's `InvalidGroupId.Malformed` in this package's not-found set, where it
	// made a malformed security-group identifier return **success with zero
	// ingress rules**: a read-back saying nothing may reach a database, produced
	// by a typo.
	//
	// It maps onto [compute.ErrInvalidSpec], not [compute.ErrFailed]: the caller
	// can act on it, and what they must do is fix an input.
	ErrMalformed = errors.New("aws: the service could not parse this input")
	// ErrNameTaken is a create refused because the name belongs to a resource
	// in ANOTHER account.
	//
	// Distinct from [ErrAlreadyExists], which is this account racing itself and
	// resolves on the next reconcile. This one never resolves: the name is in a
	// global namespace and somebody else has it, so a retry is a loop and the
	// only fix is a different name. [Provider.substrateError] maps it to
	// [compute.ErrNotOwned] for exactly that reason -- "the desired name is
	// taken by a resource this platform does not own".
	//
	// S3 is the only service in this package with a global namespace, and it is
	// the only one that can report this: CreateBucket answers BucketAlreadyExists
	// for another account's name and BucketAlreadyOwnedByYou for this account's,
	// which is the one place S3 says which of the two happened without ambiguity.
	// A HEAD does not -- see [S3API.HeadBucket].
	ErrNameTaken = errors.New("aws: the name belongs to another account")
)

// RepositoryRecord is what a registry reports about one repository.
type RepositoryRecord struct {
	// Name is the repository name within the registry.
	Name string
	// ARN is the repository's ARN, as the registry reported it.
	//
	// It is read back rather than composed. The source system builds it from a
	// template after recovering the account and region by regexp from a push
	// destination (kaniko_creds.go:26-47); that template is a second definition
	// of a string only AWS owns, and it is the definition the session policy
	// depends on being right.
	ARN string
	// URI is the registry-qualified prefix a tag is appended to.
	URI string
	// ScanOnPush reports the repository's scanning configuration.
	ScanOnPush bool
	// ImmutableTags reports whether the repository refuses a tag move.
	ImmutableTags bool
}

// ECRAPI is the registry surface this provider uses.
//
// Every method is one AWS API call, named after it. Nothing here composes calls
// or interprets results: the provider does that, so the in-memory substrate
// cannot accidentally implement a different contract from the SDK one.
type ECRAPI interface {
	// DescribeRepository returns one repository, or [ErrNoSuchResource].
	DescribeRepository(ctx context.Context, name string) (*RepositoryRecord, error)
	// DescribeImage returns the manifest digest the registry stored for one
	// image. tag and digest identify it; exactly one is set. Absence is
	// [ErrNoSuchResource].
	//
	// The digest a builder writes while constructing an image is not this
	// value. crane re-encodes the tarball on push, and ECS pulls the manifest
	// the registry kept.
	DescribeImage(ctx context.Context, repository, tag, digest string) (string, error)
	// CreateRepository creates one, or returns [ErrAlreadyExists].
	CreateRepository(ctx context.Context, name string, scanOnPush, immutableTags bool, tags map[string]string) (*RepositoryRecord, error)
	// DeleteRepository removes a repository and its images. An absent
	// repository is [ErrNoSuchResource].
	DeleteRepository(ctx context.Context, name string) error
	// PutImageScanningConfiguration converges scan-on-push.
	PutImageScanningConfiguration(ctx context.Context, name string, scanOnPush bool) error
	// PutImageTagMutability converges whether the repository refuses a tag
	// move.
	PutImageTagMutability(ctx context.Context, name string, immutableTags bool) error
	// GetLifecyclePolicy returns the policy document, or [ErrNoSuchResource]
	// when the repository has none.
	GetLifecyclePolicy(ctx context.Context, name string) (string, error)
	// PutLifecyclePolicy replaces the policy document.
	PutLifecyclePolicy(ctx context.Context, name, policy string) error
	// DeleteLifecyclePolicy removes it. Removing an absent one is
	// [ErrNoSuchResource].
	DeleteLifecyclePolicy(ctx context.Context, name string) error
	// ListTags reads a repository's tags by ARN.
	ListTags(ctx context.Context, arn string) (map[string]string, error)
	// TagResource adds or replaces tags.
	TagResource(ctx context.Context, arn string, tags map[string]string) error
	// UntagResource removes tags by key.
	UntagResource(ctx context.Context, arn string, keys []string) error
}

// RoleRecord is what IAM reports about one role.
type RoleRecord struct {
	// Name is the role name.
	Name string
	// ARN is the role's ARN, as IAM reported it. It is the subject a workload
	// attestation has to resolve to, so it is read back rather than composed
	// from an account identifier this package deliberately does not hold.
	ARN string
	// AssumeRolePolicy is the trust policy document.
	AssumeRolePolicy string
	// Tags are the role's tags.
	Tags map[string]string
}

// IAMAPI is the identity surface this provider uses.
//
// It embeds [RolePolicyAPI] rather than listing its three methods, so that a
// reviewer asking "where can this package change what a principal is permitted
// to do" gets a one-interface answer. Every grant any port here makes is one of
// those calls.
type IAMAPI interface {
	RolePolicyAPI

	// GetRole returns one role, or [ErrNoSuchResource].
	GetRole(ctx context.Context, name string) (*RoleRecord, error)
	// CreateRole creates one, or returns [ErrAlreadyExists].
	CreateRole(ctx context.Context, in CreateRoleRequest) (*RoleRecord, error)
	// UpdateAssumeRolePolicy replaces a role's trust policy, so a spec whose
	// RunsOn changed converges instead of keeping the first answer.
	UpdateAssumeRolePolicy(ctx context.Context, name, policy string) error
	// DeleteRole removes a role. An absent role is [ErrNoSuchResource].
	DeleteRole(ctx context.Context, name string) error
	// TagRole adds or replaces tags.
	TagRole(ctx context.Context, name string, tags map[string]string) error
	// UntagRole removes tags by key.
	UntagRole(ctx context.Context, name string, keys []string) error

	// ListRolePolicyNames returns the inline policy names on a role.
	//
	// Put and Delete come from the embedded [RolePolicyAPI] (USOSS-14); this is
	// the one inline-policy operation that interface does not carry, because a
	// [compute.Granter] writes and removes a grant it can name and never has to
	// ask what else is attached.
	//
	// The container port does. It exists so that a declarative reconcile can
	// derive the set of policies to REMOVE from the role itself rather than
	// from a hand-maintained list of the ones this provider knows how to add.
	// A list that drifts from the set it restates leaves a revoked grant
	// attached, which is a security control failing open.
	ListRolePolicyNames(ctx context.Context, roleName string) ([]string, error)
}

// CreateRoleRequest is what it takes to create a role.
type CreateRoleRequest struct {
	// Name is the role name.
	Name string
	// Path is the IAM path, e.g. "/apphub/".
	Path string
	// AssumeRolePolicy is the trust policy document.
	AssumeRolePolicy string
	// PermissionsBoundary is the ARN of the boundary policy, or empty.
	PermissionsBoundary string
	// Tags are the role's tags, including the ownership marker.
	Tags map[string]string
}

// AssumeRoleRequest is a scoped, short-lived credential request.
type AssumeRoleRequest struct {
	// RoleARN is the role to assume.
	RoleARN string
	// SessionName names the session in CloudTrail.
	SessionName string
	// Policy is the session policy. It is an intersection, not a grant: the
	// session gets the role's permissions *and* this document's, so a policy
	// that omits a resource cannot be worked around by the role having it.
	Policy string
	// Duration bounds the credential's life.
	Duration time.Duration
}

// PushCredentials is a minted, repository-scoped, short-lived AWS credential.
//
// Every field is a [credentials.Secret] rather than a string, including the
// access key ID. The ID is an identifier rather than material, but a temporary
// session's three values are only useful together and only dangerous together,
// and a struct where two of three fields redact is a struct somebody will
// eventually format with %v.
//
// The type is never returned to a caller of the [compute] interface. It exists
// between [STSAPI] and [BuildRunner] and nowhere else; see [compute.ImageBuilder]
// for why credential minting is deliberately not on that interface.
type PushCredentials struct {
	// AccessKeyID is the session's key identifier.
	AccessKeyID credentials.Secret
	// SecretAccessKey is the session's signing key.
	SecretAccessKey credentials.Secret
	// SessionToken is the session token the other two are only valid with.
	SessionToken credentials.Secret
	// Expires is when the credential stops working. It carries no material and
	// exists so a build that outlives its credential fails with a diagnosis
	// rather than with an authorization error from the middle of a push.
	Expires time.Time
}

// IsZero reports whether the credential is empty, without revealing anything.
func (c PushCredentials) IsZero() bool {
	return c.AccessKeyID.IsZero() && c.SecretAccessKey.IsZero() && c.SessionToken.IsZero()
}

// STSAPI mints the build's push credential. One method, on purpose: this is the
// only place in the package where a credential can come into existence.
type STSAPI interface {
	AssumeRole(ctx context.Context, in AssumeRoleRequest) (PushCredentials, error)
}

// BuildCommand is a build invocation. **It has no field that can carry a
// credential, and that absence is the point.**
//
// USOSS-41. This type used to hold the minted push credential, and the argument
// for that was a good one as far as it went: Env was non-secret and safe to
// render, the credential sat in a separate field of [credentials.Secret] values,
// and only the runner about to exec turned it into an environment variable. What
// it could not do is stop the credential from reaching the environment of a
// process that executes repository-authored code, because that is exactly what
// it was for — kaniko unpacks the image into the container it runs in and shares
// a PID namespace with the commands it runs, so a Dockerfile RUN instruction
// reads the executor's own environment.
//
// So the field is gone rather than guarded. A build phase that cannot be handed
// a credential cannot leak one, and there is no code path left to review: the
// credential lives in [PushCommand], which is executed by [ImagePusher] after
// the build has finished and by a process that never ran the Dockerfile. See
// [ImagePusher] for what that does and does not close.
type BuildCommand struct {
	// Executable is the builder binary.
	Executable string
	// Args are its arguments.
	Args []string
	// Dir is the working directory.
	Dir string
	// Env is the complete environment, already reduced to an allowlist by the
	// caller. It is not merged with the parent process's, and it holds no
	// credential material.
	Env []string
	// Output receives the builder's combined output as it is produced, or is
	// nil.
	Output io.Writer
}

// BuildRunner executes a build, and pushes nothing.
//
// One obligation, and it is the one the source system does not meet:
//
//	A runner MUST NOT put the builder's output into the error it returns.
//
// The builder's output is repository-authored: kaniko unpacks the image into the
// same container it runs in, so a Dockerfile RUN instruction can print whatever
// it can read. The source system appends a tail of that output to the error it
// returns (build.go:566-572) and that error is persisted onto a job record and
// rendered in an interface.
//
// What the rule protects has changed, and saying so is more useful than leaving
// the old reason in place. It used to be this build's push credential, which the
// runner's own environment held. Since USOSS-41 it does not — [BuildCommand] has
// no credential field — so what a leaked tail now moves into durable storage is
// the build context, the recipe, and whatever a RUN instruction chose to print.
// That is still repository-authored content in a persisted record, and it is
// still not the provider's to put there.
//
// The diagnostic is not lost by this rule, it is relocated:
// [compute.BuildRequest.Logs] receives the whole stream, and the interface is
// explicit that bounding and persisting it is the caller's policy.
type BuildRunner interface {
	// Run blocks until the build finishes. A non-zero exit is an error.
	Run(ctx context.Context, cmd BuildCommand) error
}

// PushCommand is a push invocation. It is the only place in this package's
// substrate surface where credential material and an executable meet.
//
// Everything in Env is non-secret and safe to log, render, or put in an error;
// the credential is in Credentials, and the only code that turns it into an
// environment variable is the pusher that is about to exec. A recording pusher —
// which is what the conformance suite's rendered-artefact invariant reads — never
// has the material to leak, so "secret material does not appear in rendered
// artefacts" holds by construction rather than by review.
type PushCommand struct {
	// Executable is the pusher binary.
	Executable string
	// Args are its arguments. See [imageBuilder.push] for the grammar this
	// provider composes and why its two positional arguments cannot be read as
	// flags.
	Args []string
	// Dir is the working directory.
	Dir string
	// Env is the complete non-secret environment, already reduced to an
	// allowlist by the caller. It is not merged with the parent process's.
	Env []string
	// Credentials is the scoped push credential, and the only secret material a
	// build's substrate calls carry.
	Credentials PushCredentials
	// Output receives the pusher's combined output as it is produced, or is
	// nil.
	Output io.Writer
}

// ImagePusher publishes a built artefact to a registry.
//
// # Why this is a second port
//
// It is the construction USOSS-41 asks for: build with no push credential, and
// push from a process that never ran the Dockerfile. A single port could not
// express it — one interface with one command type is one process, and the
// credential would have to be reachable from wherever the Dockerfile ran.
//
// One obligation, the same one [BuildRunner] carries and for a sharper reason:
//
//	A pusher MUST NOT put its own output into the error it returns.
//
// A pusher's output is not repository-authored, but its *environment* holds the
// credential, so a tool that echoes its environment on failure — several do —
// puts live material into whatever persists that error. This provider redacts
// where it consumes a pusher's output for exactly that reason; see
// [redactingWriter].
//
// # What the separation closes, and what it does not
//
// It closes the direct path: at no point does a process executing a Dockerfile
// have the credential in its own environment, and while such a process runs no
// credential for the build exists at all — [imageBuilder.build] mints after the
// builder returns.
//
// It does not by itself close every path, and the residue is worth naming rather
// than leaving for someone to find. [ExecRunner] and [ExecPusher] are subprocesses
// of one apphub process, running as one user in one PID namespace. Same-user
// processes can read each other's /proc/<pid>/environ, so a build that overlaps
// in time with *another* build's push can still observe that push's credential.
// Nothing inside this package can close that: it needs the push to run under a
// different user, in a different namespace, or in a different container, which is
// a property of the deployment. That is why this is an interface — an operator
// who can supply that isolation implements it here — and it is what makes
// [redactingWriter] worth keeping rather than deleting.
type ImagePusher interface {
	// Push blocks until the push finishes. A non-zero exit is an error.
	Push(ctx context.Context, cmd PushCommand) error
}

// --- Lambda -------------------------------------------------------------------

// FunctionRecord is what Lambda reports about one function.
type FunctionRecord struct {
	// Name is the function name.
	Name string
	// ARN is the function's ARN, as Lambda reported it. Read back and never
	// composed, for the same reason [RoleRecord.ARN] is: composing it would
	// mean this package holding an account identifier. It is what an ELBv2
	// target group registers as its target, so it does leave the provider —
	// downwards, into another AWS API, never upwards through [compute].
	ARN string
	// Runtime is the runtime identifier.
	Runtime string
	// Handler is the entrypoint within the bundle.
	Handler string
	// RoleARN is the execution role's ARN.
	RoleARN string
	// MemoryMiB is the memory allocation.
	MemoryMiB int
	// TimeoutSeconds bounds one invocation.
	TimeoutSeconds int
	// Architecture is the architecture the bundle was built for, in Lambda's
	// own vocabulary ("arm64", "x86_64").
	Architecture string
	// Env is the function's environment. Non-secret by construction: this
	// provider refuses a spec that would put credential material here. See
	// [functionRuntime] for why.
	Env map[string]string
	// State and LastUpdateStatus are Lambda's two convergence signals, in its
	// own vocabulary. A function is invocable only when both are settled, which
	// is why the source system checks both (lambda.go:1000-1013).
	State            string
	LastUpdateStatus string
	// StateReason carries Lambda's explanation of a failure. It must never be
	// put anywhere a credential could reach; it is operator-facing text.
	StateReason string
	// Revision identifies the deployed configuration and code together.
	Revision string
	// CodeDigest identifies the deployed bundle alone. The provider uses it to
	// decide whether a code update is needed at all, which is what keeps the
	// common redeploy down to a single mutation. See [functionRuntime].
	CodeDigest string
	// Tags are the function's tags. They carry the ownership marker, so a
	// record with no tags is a function this platform did not create — which is
	// what the source system's functions all are, because it writes none.
	Tags map[string]string
}

// The Lambda convergence states this provider reasons about, in Lambda's own
// vocabulary rather than translated, because the substrate is the authority on
// them and a second spelling is a second thing to keep in step.
const (
	// FunctionStatePending is a function that is not yet invocable.
	FunctionStatePending = "Pending"
	// FunctionStateActive is a function that is invocable.
	FunctionStateActive = "Active"
	// FunctionStateFailed is a function that will not become invocable.
	FunctionStateFailed = "Failed"

	// UpdateStatusInProgress is a mutation Lambda has accepted and not
	// finished. A second mutation during it is refused, which is the whole
	// reason [FunctionRuntime.WaitForFunction] exists.
	UpdateStatusInProgress = "InProgress"
	// UpdateStatusSuccessful is a finished mutation.
	UpdateStatusSuccessful = "Successful"
	// UpdateStatusFailed is a mutation that will not finish.
	UpdateStatusFailed = "Failed"
)

// ErrConflict is a mutation the substrate refused because another mutation of
// the same resource is still in flight.
//
// It is its own sentinel rather than an instance of [ErrThrottled] because the
// two are different facts even though both map to [compute.ErrTransient]: a
// throttle is about request rate and a conflict is about the resource's own
// state machine. Lambda serialises configuration and code updates on a single
// function, so this is the ordinary outcome of asking for both at once, and the
// provider has to be able to say so in an error a caller can read.
var ErrConflict = errors.New("aws: another update to this resource is still in progress")

// FunctionCode is where a function's bundle comes from. Exactly one of the two
// is set, which the provider guarantees before calling.
type FunctionCode struct {
	// Zip is the bundle itself.
	Zip []byte
	// Bucket and Key address a bundle already in an object store.
	Bucket string
	Key    string
}

// CreateFunctionRequest is what it takes to create a function.
type CreateFunctionRequest struct {
	Name           string
	Runtime        string
	Handler        string
	RoleARN        string
	MemoryMiB      int
	TimeoutSeconds int
	Architecture   string
	Env            map[string]string
	Code           FunctionCode
	Description    string
	Tags           map[string]string
}

// UpdateFunctionConfigurationRequest is everything about a function except its
// code. Lambda mutates the two separately and refuses to do both at once.
type UpdateFunctionConfigurationRequest struct {
	Name           string
	Runtime        string
	Handler        string
	RoleARN        string
	MemoryMiB      int
	TimeoutSeconds int
	Env            map[string]string
	Description    string
}

// AddPermissionRequest grants one principal the right to invoke one function.
type AddPermissionRequest struct {
	// Name is the function.
	Name string
	// StatementID identifies this grant within the function's resource policy,
	// so that two grants can coexist and either can be withdrawn.
	StatementID string
	// Action is the API action granted.
	Action string
	// Principal is the service principal granted it.
	Principal string
	// SourceARN narrows the grant to one caller. It is required by this
	// package: a grant with no source condition lets every load balancer in
	// every account reachable by that principal invoke the function.
	SourceARN string
}

// LambdaAPI is the function surface this provider uses. One method per AWS API
// call, named after it.
type LambdaAPI interface {
	// GetFunction returns one function, or [ErrNoSuchResource].
	GetFunction(ctx context.Context, name string) (*FunctionRecord, error)
	// CreateFunction creates one, or returns [ErrAlreadyExists].
	CreateFunction(ctx context.Context, in CreateFunctionRequest) (*FunctionRecord, error)
	// UpdateFunctionConfiguration mutates everything but the code, or returns
	// [ErrConflict] when another update is in flight.
	UpdateFunctionConfiguration(ctx context.Context, in UpdateFunctionConfigurationRequest) (*FunctionRecord, error)
	// UpdateFunctionCode replaces the bundle, or returns [ErrConflict].
	UpdateFunctionCode(ctx context.Context, name string, arch string, code FunctionCode) (*FunctionRecord, error)
	// DeleteFunction removes a function. An absent function is
	// [ErrNoSuchResource].
	DeleteFunction(ctx context.Context, name string) error
	// AddPermission adds a statement to the function's resource policy.
	AddPermission(ctx context.Context, in AddPermissionRequest) error
	// RemovePermission removes one by statement identifier. An absent statement
	// is [ErrNoSuchResource].
	RemovePermission(ctx context.Context, name, statementID string) error
	// ListStatementIDs reports the statement identifiers in the function's
	// resource policy, or [ErrNoSuchResource] when it has none.
	//
	// It returns identifiers rather than the policy document on purpose. The
	// provider only ever needs to know which of its own grants exist, and
	// handing it a document would invite it to parse a policy language it has no
	// business understanding.
	ListStatementIDs(ctx context.Context, name string) ([]string, error)
	// ListTags reads a function's tags by ARN.
	ListTags(ctx context.Context, arn string) (map[string]string, error)
	// TagResource adds or replaces tags.
	TagResource(ctx context.Context, arn string, tags map[string]string) error
	// UntagResource removes tags by key.
	UntagResource(ctx context.Context, arn string, keys []string) error
}

// --- ELBv2 --------------------------------------------------------------------

// LoadBalancerRecord is what ELBv2 reports about one load balancer.
type LoadBalancerRecord struct {
	// Name is the load balancer's name.
	Name string
	// ARN is its ARN, as ELBv2 reported it.
	ARN string
	// DNSName is where it answers. This is the one value the whole endpoint
	// path exists to produce, and the only one that reaches a caller.
	DNSName string
	// Scheme is "internet-facing" or "internal".
	Scheme string
	// State is ELBv2's convergence signal, in its own vocabulary.
	State string
	// StateReason is operator-facing text.
	StateReason string
	// SecurityGroupIDs are the security groups attached to it.
	SecurityGroupIDs []string
	// SubnetIDs are the subnets it is placed in.
	SubnetIDs []string
	// Tags are its tags.
	Tags map[string]string
}

// The ELBv2 load balancer schemes and states this provider reasons about.
const (
	// SchemeInternetFacing is a load balancer with public addresses.
	SchemeInternetFacing = "internet-facing"
	// SchemeInternal is a load balancer reachable only from inside the VPC.
	SchemeInternal = "internal"

	// LoadBalancerProvisioning is a load balancer that is not yet serving.
	LoadBalancerProvisioning = "provisioning"
	// LoadBalancerActive is a load balancer that is serving.
	LoadBalancerActive = "active"
	// LoadBalancerFailed is one that will not serve.
	LoadBalancerFailed = "failed"
)

// CreateLoadBalancerRequest is what it takes to create one.
type CreateLoadBalancerRequest struct {
	Name             string
	SubnetIDs        []string
	SecurityGroupIDs []string
	Scheme           string
	Tags             map[string]string
}

// TargetGroupRecord is what ELBv2 reports about one target group.
type TargetGroupRecord struct {
	// Name is the target group's name.
	Name string
	// ARN is its ARN.
	ARN string
	// TargetType is "lambda" for every group this provider creates.
	TargetType string
	// Tags are its tags.
	Tags map[string]string
}

// TargetTypeLambda is the only target type this provider creates.
const TargetTypeLambda = "lambda"

// TargetHealth is one registered target and what ELBv2 says about it.
type TargetHealth struct {
	// ID is the target's identifier — for a Lambda target group, the function's
	// ARN.
	ID string
	// State is ELBv2's health state, in its own vocabulary.
	State string
	// Reason is operator-facing text explaining a state that is not healthy.
	Reason string
}

// The ELBv2 target health states this provider reasons about.
//
// Only two of the seven are named, because only two decisions depend on them:
// healthy means serving, and everything else does not. Enumerating the rest
// would be a restatement of somebody else's set with nothing depending on it.
const (
	// TargetHealthy is the one state that means the endpoint can serve.
	TargetHealthy = "healthy"
	// TargetInitial is a target ELBv2 has not finished checking. Named because
	// it is the ordinary state immediately after a registration, and telling it
	// apart from a failure is what lets a Wait keep waiting rather than fail.
	TargetInitial = "initial"
)

// CreateTargetGroupRequest is what it takes to create a target group.
type CreateTargetGroupRequest struct {
	Name       string
	TargetType string
	Tags       map[string]string
}

// ListenerRecord is what ELBv2 reports about one listener.
type ListenerRecord struct {
	// ARN is the listener's ARN.
	ARN string
	// Port is the port it accepts traffic on.
	Port int
	// Protocol is "HTTP" or "HTTPS", in ELBv2's own vocabulary.
	Protocol string
	// CertificateARN is the certificate it serves, empty for HTTP.
	CertificateARN string
	// TargetGroupARN is the group its default action forwards to.
	TargetGroupARN string
}

// The ELBv2 listener protocols this provider creates.
const (
	// ListenerProtocolHTTP is plaintext.
	ListenerProtocolHTTP = "HTTP"
	// ListenerProtocolHTTPS is TLS.
	ListenerProtocolHTTPS = "HTTPS"
)

// CreateListenerRequest is what it takes to create a listener.
type CreateListenerRequest struct {
	LoadBalancerARN string
	Port            int
	Protocol        string
	// CertificateARN is required for [ListenerProtocolHTTPS] and must be empty
	// otherwise. The provider enforces that before calling; ELBv2 does not,
	// which is how the source system creates HTTPS listeners that serve no
	// certificate (lambda.go:487-490, :697-708).
	CertificateARN string
	TargetGroupARN string
}

// ELBv2API is the load balancing surface this provider uses.
type ELBv2API interface {
	// DescribeLoadBalancer returns one by name, or [ErrNoSuchResource].
	DescribeLoadBalancer(ctx context.Context, name string) (*LoadBalancerRecord, error)
	// CreateLoadBalancer creates one, or returns [ErrAlreadyExists].
	CreateLoadBalancer(ctx context.Context, in CreateLoadBalancerRequest) (*LoadBalancerRecord, error)
	// DeleteLoadBalancer removes one by ARN. An absent one is
	// [ErrNoSuchResource].
	DeleteLoadBalancer(ctx context.Context, arn string) error
	// SetSecurityGroups replaces the security groups attached to one, so that a
	// load balancer created before a placement's ingress configuration changed
	// converges instead of keeping the first answer.
	SetSecurityGroups(ctx context.Context, arn string, securityGroupIDs []string) error

	// DescribeTargetGroup returns one by name, or [ErrNoSuchResource].
	DescribeTargetGroup(ctx context.Context, name string) (*TargetGroupRecord, error)
	// CreateTargetGroup creates one, or returns [ErrAlreadyExists].
	CreateTargetGroup(ctx context.Context, in CreateTargetGroupRequest) (*TargetGroupRecord, error)
	// DeleteTargetGroup removes one by ARN.
	DeleteTargetGroup(ctx context.Context, arn string) error
	// DescribeTargets returns the targets registered with a group, each with its
	// health.
	//
	// Its own method rather than a field on [TargetGroupRecord] because it is
	// its own AWS call, and this interface keeps one method per call so that the
	// in-memory substrate cannot accidentally implement a different contract
	// from the SDK one.
	//
	// It returns health and not only identifiers, and that is the correction
	// that matters: ELBv2 reports registrations *through* target health, so an
	// adapter that reached DescribeTargetHealth and kept only the identifiers
	// would be discarding the answer to "is this endpoint serving" while
	// appearing to have asked the question. Readiness is about health;
	// registration is not health.
	DescribeTargets(ctx context.Context, targetGroupARN string) ([]TargetHealth, error)
	// RegisterTargets adds targets to a group.
	RegisterTargets(ctx context.Context, targetGroupARN string, targets []string) error
	// DeregisterTargets removes targets from a group, so that an endpoint
	// re-pointed at a different function stops forwarding to the old one.
	DeregisterTargets(ctx context.Context, targetGroupARN string, targets []string) error

	// DescribeListeners returns every listener on a load balancer.
	DescribeListeners(ctx context.Context, loadBalancerARN string) ([]ListenerRecord, error)
	// CreateListener creates one.
	CreateListener(ctx context.Context, in CreateListenerRequest) (*ListenerRecord, error)
	// DeleteListener removes one by ARN, which is the half the source system
	// has no equivalent of: it only ever adds (lambda.go:683-710), so a port
	// removed from a spec stays open.
	DeleteListener(ctx context.Context, arn string) error

	// ListTags reads tags by ARN.
	ListTags(ctx context.Context, arn string) (map[string]string, error)
	// AddTags adds or replaces tags.
	AddTags(ctx context.Context, arn string, tags map[string]string) error
	// RemoveTags removes tags by key.
	RemoveTags(ctx context.Context, arn string, keys []string) error
}

// --- EC2 ----------------------------------------------------------------------

// EndpointSecurityGroupRule is one inbound permission on a security group.
//
// Exactly one of CIDRv4, CIDRv6 and PeerGroupID is set. A rule with a CIDR and
// a peer group would be two rules to EC2 and one to this package, which is the
// kind of mismatch that makes a revoke miss something.
type EndpointSecurityGroupRule struct {
	// ID is EC2's identifier for the rule, empty on a rule this package is about
	// to create and set on every rule it reads back.
	//
	// It exists because a rule is a first-class taggable object with its own
	// identifier, which is what makes tag-based ownership possible here at all,
	// and because revoking by identifier is exact where revoking by
	// reconstructed permission is a match.
	ID string
	// Protocol is the transport protocol, in EC2's vocabulary ("tcp", "udp").
	Protocol string
	// Port is the single destination port. This package never authorises a
	// range: [compute.IngressRule] carries one port, and widening to a range
	// would authorise ports nobody asked for.
	Port int
	// CIDRv4 is an IPv4 CIDR the rule admits.
	CIDRv4 string
	// CIDRv6 is an IPv6 CIDR the rule admits.
	CIDRv6 string
	// PeerGroupID is a security group whose members the rule admits.
	PeerGroupID string
	// Description is operator-facing text, carried through from
	// [compute.IngressRule.Description].
	//
	// **It is not an ownership signal and must never become one.** It is
	// caller-supplied free text, so anything that read ownership from it would
	// be trusting a value the caller controls: a caller's own wording could make
	// a rule invisible to revocation, and an operator's wording could make their
	// rule look like this platform's. Ownership is [EndpointSecurityGroupRule.Tags],
	// which needs a permission to forge.
	//
	// It is also not part of a rule's identity — see [ruleKey] — so editing it
	// does not churn the security group.
	Description string
	// Tags are the rule's tags, carrying the ownership marker. Empty on a rule
	// this package is about to create; the tags are supplied to
	// [EndpointEC2API.AuthorizeSecurityGroupIngress] and read back here.
	Tags map[string]string
}

// EndpointSecurityGroupRecord is what EC2 reports about one security group.
type EndpointSecurityGroupRecord struct {
	// ID is the security group identifier.
	ID string
	// Name is its name, unique within its VPC.
	Name string
	// VpcID is the VPC it lives in.
	VpcID string
	// Tags are its tags.
	Tags map[string]string
}

// EndpointCreateSecurityGroupRequest is what it takes to create one.
//
// It carries no rules. Creating a group and authorising its rules are two AWS
// calls and this interface keeps them two, so that the convergence path and the
// creation path go through the same authorise code. The source system creates
// with no rules and then authorises (lambda.go:543-590), and then tolerates a
// failure of the second step with a logged warning — leaving a group that
// admits nothing, which its own next reconcile adopts and never repairs because
// it returns early on finding the group.
type EndpointCreateSecurityGroupRequest struct {
	Name        string
	Description string
	VpcID       string
	Tags        map[string]string
}

// EndpointSubnetRecord is what EC2 reports about one subnet.
type EndpointSubnetRecord struct {
	// ID is the subnet identifier.
	ID string
	// VpcID is the VPC it belongs to.
	VpcID string
	// AvailabilityZone is the zone it is in. The provider reads it to check
	// that a placement spans the two zones an application load balancer
	// requires, which the source system does not: it takes the operator's
	// subnet list as given and lets CreateLoadBalancer fail.
	AvailabilityZone string
}

// EndpointEC2API is the network surface this provider uses.
//
// It is the primitive layer only: one method per AWS API call, no policy. The
// translation from [compute.IngressRule] to [EndpointSecurityGroupRule] lives above it,
// in network.go, so that the container port (USOSS-11) and this one share one
// compiler rather than writing two.
type EndpointEC2API interface {
	// DescribeSecurityGroup returns one by VPC and name, or
	// [ErrNoSuchResource]. Both, because a security group name is unique only
	// within its VPC and a lookup by name alone would find another VPC's.
	//
	// Only for a call that has been *told* which VPC to look in — which means a
	// caller's spec. Anything reading back or tearing down a resource this
	// package created must use [EndpointEC2API.FindSecurityGroups] instead; see there
	// for why.
	DescribeSecurityGroup(ctx context.Context, vpcID, name string) (*EndpointSecurityGroupRecord, error)
	// FindSecurityGroups returns every security group carrying all of tags,
	// across the whole region the client addresses.
	//
	// # Why a read that is not scoped by VPC has to exist
	//
	// Because **configuration is the thing that changed.** A security group is
	// addressed by VPC and name, and the VPC comes from a
	// [PlacementConfig]. So every read scoped that way is scoped by what the
	// operator's configuration says *now*, and a teardown or a read-back of a
	// resource created earlier needs to find it where it *was*.
	//
	// An earlier revision searched the currently configured placements and
	// returned success when a placement had since been removed, leaving the
	// group it created in the VPC nothing was looking at any more. Widening that
	// search by one more case would have been the same defect with a larger
	// population.
	//
	// The resolution is that this provider owns what it created and can find it
	// from its own ownership marker, which no configuration edit can move. The
	// tags are ANDed, so a caller passing the three ownership tags gets exactly
	// the groups this platform created as that component under that name —
	// bounded by the account and region the client addresses, and by nothing an
	// operator can retype.
	FindSecurityGroups(ctx context.Context, tags map[string]string) ([]EndpointSecurityGroupRecord, error)
	// CreateSecurityGroup creates one, or returns [ErrAlreadyExists].
	CreateSecurityGroup(ctx context.Context, in EndpointCreateSecurityGroupRequest) (*EndpointSecurityGroupRecord, error)
	// DeleteSecurityGroup removes one by identifier.
	DeleteSecurityGroup(ctx context.Context, id string) error
	// DescribeSecurityGroupRules returns a group's complete inbound rule set,
	// each rule carrying its own identifier and tags.
	//
	// Its own call rather than a field on [EndpointSecurityGroupRecord], because it is
	// its own AWS API and because the rule set is the only place the ownership
	// tags this package reconciles on actually live. Reading the permissions off
	// DescribeSecurityGroups instead would give the rules without their
	// identifiers or their tags, which is what forced an earlier revision of
	// this package to read ownership from the description — a caller-supplied
	// string — and get it wrong in both directions.
	DescribeSecurityGroupRules(ctx context.Context, groupID string) ([]EndpointSecurityGroupRule, error)
	// AuthorizeSecurityGroupIngress adds inbound rules, tagging each one.
	//
	// The tags are a parameter rather than a field on each rule because EC2
	// applies one TagSpecification to every rule created by the call, and a
	// per-rule field would imply a granularity the API does not have.
	AuthorizeSecurityGroupIngress(ctx context.Context, groupID string, rules []EndpointSecurityGroupRule, tags map[string]string) error
	// UpdateSecurityGroupRuleDescriptions rewrites the operator-facing text on
	// rules that already exist, identified by [EndpointSecurityGroupRule.ID].
	//
	// It exists because [compute.IngressRule.Description] is desired state.
	// [ruleKey] deliberately excludes it from a rule's *identity* — folding it in
	// would make every wording edit a revoke-and-reauthorise, which is a window
	// of lost reachability for a change that alters no permission — but "not
	// identity" is not "not desired state". Without this call a changed
	// description never reaches the rule, and the effective spec reports the old
	// text: the read-back saying something the substrate does not.
	UpdateSecurityGroupRuleDescriptions(ctx context.Context, groupID string, rules []EndpointSecurityGroupRule) error
	// RevokeSecurityGroupIngress removes inbound rules by identifier.
	//
	// The half without which ingress only accumulates. [compute.IngressRule] is
	// declarative — the set attached to a spec is the desired state — so a rule
	// dropped from a spec has to be withdrawn, or "I removed that rule" means
	// "I stopped asking for it" and a security control fails open. The source
	// system has the call (build.go:769) but not on this path.
	//
	// By identifier and not by reconstructed permission, because an identifier
	// names exactly one rule. Reconstructing a permission asks EC2 to match, and
	// a match can be wrong in both directions.
	RevokeSecurityGroupIngress(ctx context.Context, groupID string, ruleIDs []string) error
	// CreateTags adds or replaces tags on any EC2 resource.
	CreateTags(ctx context.Context, resourceID string, tags map[string]string) error
	// DeleteTags removes tags by key.
	DeleteTags(ctx context.Context, resourceID string, keys []string) error
	// DescribeSubnets returns the named subnets, or [ErrNoSuchResource] when any
	// of them does not exist.
	DescribeSubnets(ctx context.Context, ids []string) ([]EndpointSubnetRecord, error)
}

// S3API is the general-purpose object-storage surface this provider uses.
//
// Deliberately not the SDK's shape: no method takes or returns an SDK type, so
// the in-memory substrate cannot implement a different contract from the real
// one. It carries no policy — which flags to set, which algorithm to require,
// and whether a bucket may be adopted are decisions in [objectStore].
type S3API interface {
	// HeadBucket reports whether the bucket exists and is reachable by these
	// credentials: [ErrNoSuchResource] when this account has no such bucket,
	// [ErrDenied] when the credentials could not answer the question.
	//
	// **A HEAD cannot tell a caller that a name is somebody else's**, and an
	// earlier version of this contract said it could. S3's own HeadBucket
	// documentation says an inaccessible bucket comes back as 400, 403 or 404 and
	// declines to say when, which is deliberate: an answer that distinguished
	// "absent" from "exists elsewhere" would turn a HEAD into an enumeration tool
	// for a global namespace. So a foreign name arrives here as either
	// [ErrDenied] or [ErrNoSuchResource], and a provider that handles one and not
	// the other is handling half of a documented case.
	//
	// [CreateBucket] is where the question is answerable. See [ErrNameTaken].
	HeadBucket(ctx context.Context, name string) error
	// CreateBucket creates one in region.
	//
	// [ErrAlreadyExists] when this account already has it -- two reconciles
	// racing, which the loser resolves by adopting -- and [ErrNameTaken] when the
	// name belongs to another account, which no retry resolves. S3 distinguishes
	// them with two exception types and this contract keeps the distinction,
	// because collapsing them is a retry loop on a name that will never be free.
	CreateBucket(ctx context.Context, name, region string) error
	// DeleteBucket removes an empty bucket. An absent bucket is
	// [ErrNoSuchResource]; a non-empty one is an error from S3.
	DeleteBucket(ctx context.Context, name string) error
	// IsEmpty reports whether the bucket holds no objects.
	//
	// Its own method rather than a failed DeleteBucket, because the provider
	// refuses a non-empty delete deliberately and a caller deserves that
	// answer before the destructive call rather than as its failure.
	IsEmpty(ctx context.Context, name string) (bool, error)
	// ListObjectVersions returns the first page of the bucket's object versions
	// and delete markers, at most [s3MaxKeys] of them, and an empty slice when the
	// bucket holds none. An absent bucket is [ErrNoSuchResource].
	//
	// Versions rather than objects, because a versioned bucket that lists no
	// current objects can still hold noncurrent versions and delete markers, and
	// S3 refuses to delete a bucket while it holds any. An unversioned bucket's
	// objects are reported with the version ID "null", which is S3's own answer.
	//
	// Always the first page and never a continuation: the one caller deletes each
	// page before asking for the next, so the first page of what is left IS the
	// next page, and a marker into a listing that has since been deleted would be
	// state with nothing left to point at.
	ListObjectVersions(ctx context.Context, name string) ([]ObjectVersion, error)
	// DeleteObjectVersions permanently deletes up to [s3MaxKeys] versions in one
	// request. A version that is already gone is not an error, which is S3's own
	// behaviour. A batch larger than [s3MaxKeys] is [ErrMalformed].
	//
	// Any per-key failure S3 reports inside a successful response fails the whole
	// call. S3 answers a batch delete 200 OK with the refusals in its body, so an
	// adapter that read only the status would report a denied or throttled key as
	// deleted -- and the caller's next listing would find it again, forever.
	DeleteObjectVersions(ctx context.Context, name string, versions []ObjectVersion) error
	// GetBucketLocation returns the bucket's region.
	GetBucketLocation(ctx context.Context, name string) (string, error)
	// PutPublicAccessBlock turns on all four public-access controls.
	PutPublicAccessBlock(ctx context.Context, name string) error
	// GetPublicAccessBlock reports whether all four are on.
	GetPublicAccessBlock(ctx context.Context, name string) (bool, error)
	// PutBucketEncryption sets default server-side encryption to algorithm.
	PutBucketEncryption(ctx context.Context, name, algorithm string) error
	// GetBucketEncryption returns the default algorithm, or empty.
	GetBucketEncryption(ctx context.Context, name string) (string, error)
	// GetBucketTagging returns the bucket's tags, empty when it has none.
	GetBucketTagging(ctx context.Context, name string) (map[string]string, error)
	// PutBucketTagging replaces the bucket's **entire** tag set.
	//
	// The whole-set semantics are S3's, not this interface's choice, and they
	// are the reason [mergedBucketTags] exists: sending only the tags this
	// provider owns deletes an operator's cost-allocation and compliance tags
	// and reports success.
	PutBucketTagging(ctx context.Context, name string, tags map[string]string) error
}

// s3MaxKeys is the most keys one S3 listing page returns and one batch delete
// accepts. Both limits are S3's, and they are the same number, which is what lets
// [objectStore.EmptyBucket] delete each listed page in exactly one request.
const s3MaxKeys = 1000

// ObjectVersion names one object version or delete marker in a bucket.
type ObjectVersion struct {
	// Key is the object key.
	Key string
	// VersionID is the version, "null" for an object in a bucket that has never
	// had versioning enabled.
	VersionID string
}

// TableBucketRecord is what S3 Tables reports about one table bucket.
type TableBucketRecord struct {
	// Name is the table bucket name.
	Name string
	// ARN is the ARN S3 Tables reported. Read back rather than composed: a
	// table bucket ARN carries the account identifier, and this package
	// deliberately holds no account identifier to compose one from.
	ARN string
	// Tags are the table bucket's tags.
	Tags map[string]string
}

// S3TablesAPI provisions table buckets.
//
// Reached only through [ext.TableBucketProvisioner]. Tagging is at create time
// because that is what the service offers: there is no separate tag call in the
// shape this provider needs, so an untagged table bucket is a create that
// failed rather than a converge that has not run yet.
type S3TablesAPI interface {
	// GetTableBucket returns one, or [ErrNoSuchResource].
	GetTableBucket(ctx context.Context, name string) (*TableBucketRecord, error)
	// CreateTableBucket creates one with tags, or returns [ErrAlreadyExists].
	CreateTableBucket(ctx context.Context, name string, tags map[string]string) (*TableBucketRecord, error)
	// DeleteTableBucket removes one. An absent one is [ErrNoSuchResource].
	DeleteTableBucket(ctx context.Context, arn string) error
}

// VectorBucketRecord is what S3 Vectors reports about one vector bucket.
type VectorBucketRecord struct {
	// Name is the vector bucket name.
	Name string
	// ARN is the ARN the service reported.
	//
	// Present even though every s3vectors *call* addresses a bucket by name,
	// because a grant does not: an IAM policy names resources by ARN, so the
	// ARN has to come from somewhere. Reading it back is the only honest source
	// -- it carries the account identifier, and this package holds none to
	// compose one from.
	ARN string
	// Tags are the vector bucket's tags.
	Tags map[string]string
}

// S3VectorsAPI provisions vector buckets.
//
// Reached only through [ext.VectorBucketProvisioner]. Every method addresses a
// bucket by *name* rather than by ARN, which is the asymmetry with
// [S3TablesAPI] and is the service's rather than this interface's -- but the
// record still carries the ARN, because a grant has to name one.
type S3VectorsAPI interface {
	// GetVectorBucket returns one, or [ErrNoSuchResource].
	GetVectorBucket(ctx context.Context, name string) (*VectorBucketRecord, error)
	// CreateVectorBucket creates one with tags, or returns [ErrAlreadyExists].
	CreateVectorBucket(ctx context.Context, name string, tags map[string]string) (*VectorBucketRecord, error)
	// DeleteVectorBucket removes one. An absent one is [ErrNoSuchResource].
	DeleteVectorBucket(ctx context.Context, name string) error
}
