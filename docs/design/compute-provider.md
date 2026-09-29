# The Compute provider interface

**Ticket:** USOSS-2 · **Status:** amended after falsification · **Package:** [`compute/`](../../compute)

**Amended twice.** Once against two implementations, and again against a third
independent review that defeated three of the guarantees the first amendment
claimed. §9 records both, including what the first amendment got wrong: the
`ImageRegistry` justification, an audit that could not see a new port, and a
read-back a lying provider satisfied. §9.10 is the summary of that round.

**Amendment round 1.** The interface has since been implemented
twice — a reference provider with a conformance suite (USOSS-16) and a complete
Kubernetes provider written to falsify it (USOSS-27) — and amended against what
they found. Thirty-five findings between them; §9 records what changed, what was
deliberately left open, and why. The abstraction itself held: no AWS network
identifier reaches an interface input, verified structurally *and* from the
complement over a full Kubernetes operator configuration; role-based
reachability, opaque refs, capability refusal over emulation, and every
fail-closed behaviour survived contact with a second substrate.

This document explains what the interface in `compute/` is, why each part has
the shape it does, and — the part that matters most — exactly where it stops
being portable. A design doc that claims more portability than it delivers is
worse than one that admits the gaps, because the gaps get discovered by the
second provider instead of by the reviewer.

---

## 1. What is being replaced

In the source system, `backend/internal/modules/deploy/` contains roughly 93
direct AWS SDK call sites across nine files, and **48 function signatures take
an `aws.Config` or a concrete AWS client**. Those signatures are the literal
seam. Four call sites originate the config in the first place
(`container.go:136`, `lambda.go:107`, `kaniko_creds.go:172`,
`postgres_roles.go:272`), and everything downstream inherits AWS from them.

Replacing them is not a matter of swapping one client for another. The
signatures are AWS-shaped all the way down: a function that ensures a security
group returns a security-group ID, which is threaded into a call that registers
a task definition, which distinguishes an execution role from a task role. The
data flowing between deploy steps *is* AWS.

So the interface is derived from the question each step is actually answering,
not from the API it calls to answer it. Where those two diverge, this document
says so.

## 2. Design rules

These are the rules the interface was built to, stated up front so a reviewer
can check the design against them rather than against taste.

1. **Name the need, not the API.** A method called `RegisterTaskDefinition` is a
   design failure. So is one called `EnsureSecurityGroup`.
2. **No substrate identifier crosses the boundary.** No ARNs, VPC IDs, subnet
   IDs, security-group IDs, account IDs, parameter-store paths, or IAM policy
   documents appear in `compute/`. A [`Ref`](../../compute/ref.go) is opaque and
   is never parsed by a caller.
3. **Specs are declarative and complete.** `Ensure*` takes the desired state.
   Omitting something that was there removes it. This is what makes redeploys
   and reconciliation safe, and it deletes a class of "remember to also call the
   detach function" bug the source system has.
4. **Provisioning does not block.** `Ensure*` returns promptly with a phase;
   waiting is a separate call with a caller-chosen deadline.
5. **A capability only one substrate can satisfy does not belong in `compute/`.**
   It belongs in [`compute/ext`](../../compute/ext), which promises nothing.

## 3. The capability map

Five capabilities become five implementation tickets. A sixth capability exists
in the call sites and **has no ticket** — see §3.6.

### 3.1 Image build and registry — USOSS-10

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `build.go:282-348` | `ecr.DescribeRepositories`, `CreateRepository`, `PutLifecyclePolicy` ("keep last 20") |
| `build.go:367-433` | Cache repository: same, but `ScanOnPush: false` and age-based expiry (14 days) |
| `build.go:453-578` | Shells out to `/kaniko/executor`; writes `/kaniko/.docker/config.json` (`build.go:580-611`) |
| `kaniko_creds.go:161-190` | `sts.AssumeRole` under a session policy scoped to the destination repositories, 900 s |
| `kaniko_creds.go:26-63` | Regexp-parses the ECR destination host to recover account and region |
| `kaniko_creds.go:106-149` | Builds the subprocess environment from an allowlist |

**What the logic needs.** A place to push images that the runtime can pull
from, with a retention rule so it does not grow without bound; and a way to turn
a checked-out repository into a pushed image without handing the build the
platform's own credentials.

**Interface.** Two ports, [`ImageRegistry`](../../compute/image.go) and
[`ImageBuilder`](../../compute/image.go), behind two capabilities.
`ImageRegistry` has no `Granter` — see §9.1, which is the most important thing
in this revision — and gained a `DescribeRepository`, because every registry a
platform would use has a read-back and its absence was the interface's gap
rather than any substrate's. They are
separate because building is not running and neither is hosting: a Kubernetes
provider is likely to build with the same tool (kaniko or buildkit, in a pod)
while pushing to a registry that has nothing to do with its cluster. Fusing them
would make every runtime own a build toolchain.

**Deliberately left out.** There is no `MintPushCredentials` method, even though
the security property it delivers is essential. The requirement is portable —
"a build must never see ambient platform credentials, and what it does see must
be scoped to the push destinations and short-lived" — but the mechanism (STS
assume-role plus an inline session policy) is not. It is therefore stated as an
obligation on the implementation, in the [`ImageBuilder`](../../compute/image.go)
doc comment, in normative language. A provider that cannot meet it must not
advertise `CapImageBuild`. Putting it on the interface would have forced every
substrate to have AWS-shaped session policies *and* would have made the
credentials visible to the caller, which is the one place they have no business
being.

Also left out: `writeKanikoDockerConfig`, the ECR credential-helper scoping, and
the destination-host parsing. All three are consequences of using kaniko against
ECR and none is a fact about building an image.

**Where AWS is fenced.** Everything above, inside `compute/aws`. The one thing
that crosses is the log stream, and the caller owns the bounding of it — the
source system keeps a capped tail so a failure diagnostic fits in a 400 KB
DynamoDB item (`build.go:44-89`), which is a caller policy, not a provider one.

### 3.2 Container service and scheduled jobs — USOSS-11

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `container.go:746-807` | `ecs.RegisterTaskDefinition` — family, cpu/memory strings, execution + task role ARNs, one container definition, port mapping, `awslogs` config, docker labels, env, SSM-backed secrets |
| `container.go:855-910` | `DescribeServices` / `UpdateService` / `CreateService` — Fargate, `awsvpc`, subnets, security groups, public-IP assignment, execute-command |
| `container.go:1090-1133` | Poll `DescribeServices` up to 60×2 s for `RunningCount > 0` |
| `container.go:1418-1480` | EventBridge Scheduler `GetSchedule` / `UpdateSchedule` / `CreateSchedule` with an `EcsParameters` target |
| `container.go:1495-1567` | IAM role trusting `scheduler.amazonaws.com`, with `ecs:RunTask` and `iam:PassRole` |
| `services/application.go:2708-2732` | `UpdateService` with a desired count, for pause and resume |
| `services/application.go:4407-4433` | Scale to zero, then `DeleteService` |
| `services/application.go:4824` | `DeregisterTaskDefinition` |

**What the logic needs.** Run this image, N instances, this much CPU and memory,
these ports, these environment variables, these secrets, as this identity, in
this placement, reachable by these peers, routed from these hostnames. Then tell
me when it is serving. Later: scale it, or delete it. Separately: run the same
thing on a cron cadence instead.

**Interface.** [`ContainerRuntime`](../../compute/container.go) with
`EnsureService` / `DescribeService` / `WaitForService` / `ScaleService` /
`DeleteService`, plus `EnsureScheduledJob` / `DescribeScheduledJob` /
`DeleteScheduledJob` behind `CapScheduledJob`.

**Deliberately left out.** Task definitions and their revisions, cluster ARNs,
launch types, network modes, the execution-role/task-role distinction,
public-IP assignment, and log-driver configuration. Every one of those appears
in the call it replaces and every one is a fact about ECS. They become provider
configuration attached to a named [`Placement`](../../compute/network.go), or
provider-internal detail. `DeregisterTaskDefinition` has no analogue at all — it
is garbage collection for an ECS-specific object.

Pause is `ScaleService(ref, 0)` rather than a `Pause` method, because that is
what it means and because a substrate with no notion of "paused" can still
express it.

Three things are modelled explicitly that the source system open-codes:

* **Cron syntax.** [`Schedule.Expression`](../../compute/container.go) is pinned
  to five-field POSIX cron or `rate(n unit)`. The source system passes the
  operator's string straight to EventBridge (`container.go:1434`). Pinning a
  grammar means a provider validates and translates rather than each substrate
  accepting a different dialect of "cron".
* **Progress.** [`WaitOptions.OnUpdate`](../../compute/status.go) reports
  observed state changes. The source system interpolates a percentage from the
  loop counter (`container.go:1094-1096`), which reports progress for a service
  making none.
* **Resource units.** Millicores and MiB, with a normative rule that a provider
  rounds *up* or fails. Rounding down turns a capacity decision into an
  intermittent runtime OOM.

**Where AWS is fenced.** `compute/aws` owns the task-definition shape, the
Fargate CPU/memory legal-pair table, the `awslogs` driver options, the
security-group synthesis, and the EventBridge Scheduler role.

### 3.3 Function and endpoint — USOSS-12

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `lambda.go:194-260` | `GetFunction` / `CreateFunction` / `UpdateFunctionConfiguration` / `UpdateFunctionCode` |
| `lambda.go:987-1025` | Poll `GetFunction` for `State: Active` and `LastUpdateStatus: Successful` |
| `lambda.go:595-630` | `DescribeLoadBalancers` / `CreateLoadBalancer` |
| `lambda.go:633-663` | `DescribeTargetGroups` / `CreateTargetGroup` (`TargetType: Lambda`) |
| `lambda.go:666-677` | `AddPermission` letting `elasticloadbalancing.amazonaws.com` invoke |
| `lambda.go:471-479` | `RegisterTargets` |
| `lambda.go:680-710` | `DescribeListeners` / `CreateListener` |
| `lambda.go:713-734` | Poll `DescribeLoadBalancers` for `active` |
| `services/application.go:4104-4114, 4214-4270` | `DeleteFunction`, listener/ALB/target-group teardown |

**What the logic needs.** Deploy this bundle as an invocable function with this
runtime, handler, memory, timeout and architecture; tell me when it is
invocable. Then: put it behind a hostname on these ports.

**Interface.** [`FunctionRuntime`](../../compute/function.go). The ALB, target
group, listener, invoke permission, and target registration — five separately
provisioned, ARN-addressed objects in the source — collapse into one
`EnsureEndpoint` returning a hostname. The hostname is the only output the
caller ever actually consumes; the rest (`lambda.go:509-520`) is bookkeeping.

**A defect fixed in the type system.** The source system chooses the HTTPS
protocol enum for any listener port other than 80 (`lambda.go:487-490`) and
never populates a `Certificates` field (`lambda.go:696-708`). Every HTTPS
listener it creates has no certificate. [`ListenerSpec`](../../compute/function.go)
makes `TLS` a required field for a non-plaintext listener, and a provider must
reject the spec as `ErrInvalidSpec` otherwise. Certificate lifecycle is not
managed here; `CertificateRef` is operator configuration passed through.

The invoke permission is granted *inside* `EnsureEndpoint` rather than as a
separate call, because an endpoint that cannot invoke its target is not
partially working, it is broken. The source system splits them and then
tolerates the grant failing with a log warning (`lambda.go:461-467`), which
produces exactly that state.

**Deliberately left out.** `FunctionSpec.Runtime` is a free string. This is the
least portable field in the whole interface and it is deliberate: the values
(`nodejs20.x`, `python3.12`) originate with AWS and are what application owners
already have stored. A provider validates against the set it supports and
returns `ErrInvalidSpec` listing them. Inventing a portable runtime enum would
have required a migration of existing application records for no benefit to the
one substrate that exists today.

### 3.4 Object storage — USOSS-13

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `bucket.go:217-288` | `s3.CreateBucket`, `PutPublicAccessBlock` (all four flags), `PutBucketEncryption` (AES256), `PutBucketTagging` |
| `bucket.go:290-336` | Directory bucket (S3 Express One Zone) with AZ + single-AZ redundancy |
| `bucket.go:338-364` | `s3tables.CreateTableBucket` — see §4.1 |
| `bucket.go:366-392` | `s3vectors.CreateVectorBucket` — see §4.1 |
| `bucket.go:184-215` | `sts.GetCallerIdentity` and deterministic ARN templates per bucket type |
| `bucket.go:416-497` | Per-bucket-type inline IAM policy on the app's task role |
| `bucket.go:683-867` | The C1 cross-account datasource role — see §4.4 |

**What the logic needs.** A bucket, not public, encrypted, that a named workload
can read and write, addressed by something the application can be told.

**Interface.** [`ObjectStore`](../../compute/objectstore.go) with
`EnsureBucket` / `DescribeBucket` / `DeleteBucket` and the shared `Granter`
methods.

**The four bucket types become two things, not four.** The source system's
`general`, `directory`, `table`, `vector` are not four points on one axis:

* `general` vs `directory` differ in **placement and latency** while presenting
  the same API and the same binding to the application. That is
  [`ObjectClass`](../../compute/objectstore.go) — `standard` and `zonal` — with
  `CapObjectStoreZonal` for the substrates that lack it. A provider without it
  must return `ErrUnsupported`, not quietly hand back a standard bucket: the
  caller asked for a latency property.
* `table` and `vector` change **what the application talks to** — a different
  service API, a different client, different environment variables. Those are
  not in `compute/` at all. See §4.1.

**Deliberately left out.** Encryption at rest is not a field. Every target
substrate encrypts by default or can be made to at the account level, the source
system only ever sets the provider default, and making it optional invites a
spec that turns it off. It is a provider obligation instead.

The `APP_S3_BUCKET_NAME` family of environment variables (`bucket.go:394-412`)
stays *above* the interface. Those names are an apphub convention, not a
provider one; the provider returns facts (`Name`, `URI`, `Class`) and the deploy
module decides what to call them.

**Where AWS is fenced.** The `us-east-1` `LocationConstraint` special case, the
`BucketAlreadyOwnedByYou` idempotency handling, availability-zone IDs, the ARN
templates, and the per-type IAM action lists.

**Operational boundary.** The AWS object-store implementation proves ownership
with reserved AWS tags, so the proof is scoped to the AWS account/trust boundary
that controls who can write those tags. A bucket in the same account carrying
`apphub:managed-by=apphub` and `apphub:component=object-bucket` can present as
this platform's bucket even if a different tenant or workload wrote the tags.
That is an accepted trust-boundary limitation, not a provider bug. Cross-tenant
deployment is not supported on a shared AWS account unless the tenants share that
trust boundary; otherwise each tenant needs an isolated AWS account or an
equivalent boundary that prevents writes to the reserved `apphub:` tag
namespace. See
[`USOSS-62`](../decisions/usoss-62-ownership-by-tag-is-aws-account-scoped.md).

### 3.5 Databases — USOSS-14

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `database.go:50-107` | DynamoDB `DescribeTable` / `CreateTable` (PAY_PER_REQUEST, fixed PK/SK), then poll for `ACTIVE` |
| `database.go:111-149` | Inline IAM policy: eight DynamoDB actions on the table and its index wildcard |
| `database.go:247-275` | `DescribeDBSubnetGroups` / `CreateDBSubnetGroup` |
| `database.go:279-347` | `CreateDBCluster` (aurora-postgresql, major version "16", 0.5–4 ACU, encrypted), poll 120×5 s |
| `database.go:351-403` | `CreateDBInstance` (`db.serverless`), poll 120×5 s |
| `container.go:292-334` | `DescribeDBClusters` before generating a password; `ssm.PutParameter` + `AddTagsToResource` |
| `services/application.go:4447-4657` | `DeleteDBInstance`, `DeleteDBCluster`, `DeleteDBSubnetGroup`, `DeleteTable` |

**What the logic needs.** A Postgres endpoint of a given major version, with an
admin account whose password the caller already generated and stored, bounded
compute, reachable by the app and by the control plane. Or: a key-value table
with a partition key and a sort key.

**Interface.** Two ports, not one:
[`RelationalProvisioner`](../../compute/database.go) and
[`KeyValueProvisioner`](../../compute/database.go), vended by two accessors
gated on their own capabilities.

They were one port with an unconditional `Granter` in the first draft, and the
Kubernetes thought experiment is what showed that to be wrong. Access to a
relational database is granted by creating a SQL role and issuing GRANT
statements — which this design correctly leaves above the interface — and there
is no general mapping from a substrate workload identity to a SQL principal. An
IAM role maps to a Postgres role only with `rds-iam` authentication enabled; a
Kubernetes ServiceAccount has no Postgres meaning at all. So a provider offering
only operator-managed Postgres was being required to implement
`Grant(resource, workloadIdentity, level)` and answer `ErrUnsupported` — a
required method that cannot be implemented, which is precisely the
stub-interface failure the `Provider` accessor design exists to prevent.

A key-value table is the opposite case and keeps `Granter`: the source system
grants the application's task role eight DynamoDB actions on the table
(`database.go:111-149`), with no notion of a database-internal principal.
Every substrate that has this product at all authorises it by workload identity.

The general rule this produced: **`Granter` goes on a port only when the
substrate's own access control is expressed in terms of the workload identity.**
It is not a convenience mixin.

**Deliberately left out.** The cluster/instance two-object model. Aurora requires
creating a cluster and then separately creating an instance inside it; that is
an Aurora fact and a caller asking for a Postgres endpoint should not learn it.
The provider does whatever its substrate requires and reports one resource. DB
subnet groups likewise vanish into `Placement`.

Also left out: everything the source system does to the database *after* it
exists. Creating Postgres roles, granting privileges, enabling row-level
security, and installing extensions (`postgres_roles.go:25-121`,
`database_extensions.go:26-73`) are vanilla SQL over a standard driver and
belong above this interface. Those two files touch AWS only to fetch the admin
password from Parameter Store, which becomes a `SecretStore.Get`. That is the
whole of their AWS coupling and it is the single clearest win in the port.

**Two normative rules that come from real bugs.**

* A provider must **not** rotate `AdminPassword` on a re-`Ensure`. The source
  system guards this by checking for an existing cluster before generating a
  password at all (`container.go:288-300`), with a comment saying why. If a
  provider rotated it, the caller's stored copy would silently become wrong and
  role provisioning would fail on the next deploy with an authentication error.
* Capacity is expressed in abstract units, not ACUs. An ACU is an AWS billing
  construct. `MaxUnits` unset means the provider's default ceiling, which must
  be finite: an unbounded default is a billing incident.
* Both ports are in the **asynchronous class** (§2, rule 4), so both return a
  status-bearing type from every `Ensure` and `Describe`. `KeyValueStatus`
  embeds `Status` for that reason: table creation genuinely is asynchronous —
  the source system polls `DescribeTable` sixty times waiting for `ACTIVE`
  (`database.go:88-105`) — and a plain descriptor with no phase would have
  forced either a blocking `Ensure` or a caller that cannot tell "created" from
  "usable".

### 3.6 Secret store — **no ticket exists for this**

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `container.go:308-327` | Store the generated Aurora master password (SecureString, overwrite, tag separately) |
| `container.go:1138-1154` | `storeDBConfigInSSM` — the generic "put these config values where the container can read them" mechanism |
| `container.go:683-690` | ECS `Secrets` with `ValueFrom` pointing at SSM paths — the *consumption* side |
| `postgres_roles.go:154-165` | `GetParameter` with decryption, for the master password |
| `postgres_roles.go:230-248` | `PutParameter` + `AddTagsToResource` per provisioned role |
| `workload/rotator.go:270-298` | The deploy-signature parameter |

This is a distinct capability — [`SecretStore`](../../compute/secret.go) — and it
is the most portable one in the interface: `Put`/`Get`/`Delete` over an
encrypted namespace maps onto SSM, Secrets Manager, Vault, GCP Secret Manager,
Azure Key Vault, and a Kubernetes Secret with almost no impedance.

**It is called out here because the ticket breakdown does not have a home for
it.** USOSS-10 through USOSS-14 are image build, container service, function,
object storage, and database. Secret storage is none of those and every one of
them depends on it. Recommend either a sixth implementation ticket or an
explicit assignment to USOSS-11, which is where the majority of its call sites
are.

**The one real constraint.** A runtime can only resolve a secret reference to a
store it natively understands, so a workload's `SecretBinding` values must come
from the same `Provider` that runs the workload. Mixing — Vault secrets into
ECS, say — needs a sidecar or an init container and is out of scope for v1. A
provider must return `ErrForeignRef` rather than pretend. This is stated
because the survey correctly identified the consumption side as the leaky half,
and the honest resolution is a documented constraint, not a fake abstraction.

`DeleteScope` exists because teardown needs to remove every secret an
application accumulated, and the caller does not reliably know the set — the
source system tracks it in a `SecretNames` slice on the application row
(`container.go:1152`) that any failed deploy can leave incomplete.

### 3.7 Workload identity and access grants — cross-cutting, not a port

**Call sites replaced**

| Source | What it does |
| --- | --- |
| `build.go:619-666` | Per-app ECS task role, trust `ecs-tasks.amazonaws.com` |
| `build.go:670-697` | `ssmmessages:*` inline policy so operators can exec into the container |
| `build.go:715-779` | Bedrock invoke policy, attached or detached by two feature flags |
| `lambda.go:935-985` | Lambda execution role, trust `lambda.amazonaws.com`, plus the managed basic-execution policy, plus a 10 s sleep for IAM propagation |
| `database.go:111-149`, `bucket.go:416-497` | Per-resource inline policies |
| `container.go:1495-1567` | The scheduler's role |

The ticket says IAM should be invisible above the interface. It is, and the way
it disappears is worth stating precisely, because "we hid it" is not a design.

IAM dissolves into four things:

1. **[`WorkloadIdentitySpec`](../../compute/identity.go)** — "give this workload
   an identity it can run as". The trust policy, the service principal, and the
   role name are provider-internal. `RunsOn` exists because on AWS an identity
   is not interchangeable between runtimes: a role trusted by
   `ecs-tasks.amazonaws.com` cannot be assumed by Lambda.
2. **[`Granter`](../../compute/identity.go)**, implemented by the ports whose
   substrate authorises by workload identity — "this identity may read/write
   this resource". Not every port: see §3.5 for the relational port and §9.1 for
   the image registry. The rule is now enforced by a test rather than by memory
   ([`compute.WorkloadGrantPorts`](../../compute/identity.go)), which is the
   whole subject of §9.1. The same shape wherever it does appear is what lets
   the conformance suite test grant semantics once.
3. **[`WorkloadCapability`](../../compute/identity.go)** — platform-level grants
   to the workload's *own identity*, not tied to a resource. Exactly one value:
   `model-inference`. Declarative, so omitting one revokes it. This is the
   direct answer to `attachBedrockPolicy`/`detachBedrockPolicy`, a pair whose
   correctness depends on the caller remembering to call the second one
   (`container.go:496-505`).
4. **[`ServiceSpec.ExecEnabled`](../../compute/container.go)** — runtime
   operability, and deliberately *not* a workload capability. See below.

**Why exec is not a workload capability.** It was one, and that was a security
error rather than a taxonomic one. The principal that opens an interactive
session is the **operator**, not the workload. The generalisation was tempting
because ECS needs `ssmmessages` permissions on the *task* role
(`build.go:670-697`) — but that is one substrate's mechanism for making the
*target* reachable, not evidence about who the caller is. On Kubernetes the
distinction is unmistakable: RBAC on `pods/exec` authorises the caller, so
granting it to the target Pod's own ServiceAccount would let **the workload exec
into pods** and still not let an operator exec into the workload. The principal
is backwards and the failure mode is privilege escalation, not a missing
feature.

So the interface splits it:

* `ServiceSpec.ExecEnabled` says *make this workload available for interactive
  sessions*. That is the target half, and it is the half a compute provider owns
  — on AWS it implies the `ssmmessages` grant on the task role; on Kubernetes it
  is close to a no-op.
* *Who* may open a session is authorised on the operator's principal — an IAM
  policy or an RBAC binding — configured by the operator alongside the provider,
  and deliberately outside this interface. AppHub makes the target reachable;
  it does not proxy the session and it does not decide who may open one.

The general rule: a capability belongs on the workload's identity only if the
principal exercising it is the workload. `model-inference` passes that test —
the application calls the model API at runtime, as itself. Exec does not.

The IAM propagation sleep (`lambda.go:982`) does not survive. A hardcoded
ten-second sleep in business logic is a provider's eventual-consistency problem;
`compute/aws` may sleep, retry, or poll, and no other provider inherits it.

**`AccessLevel` is coarse and that has a cost.** The source system writes bespoke
statements per resource type — five S3 actions for a general bucket, eleven for
a table bucket, eight DynamoDB actions plus an index wildcard. Reproducing that
portably means either inventing a policy language or admitting AWS action
strings into the interface. Neither is worth it for a grant set whose real
cardinality is "the app can use its own bucket" and "the app can use its own
table". The consequence is in §5.

---

## 4. The four hard problems

### 4.1 S3 Tables and S3 Vectors are AWS-exclusive

**The problem.** `bucket.go:338-378` provisions two bucket types no other
substrate has. It is tempting to treat this as a storage-backend question. It is
not, and that is the whole difficulty: the *application* talks to these
directly. A table bucket's ARN is handed to the app in
`APP_S3_TABLE_BUCKET_ARN` (`bucket.go:404-405`) and the app speaks the
`s3tables` API to it. Backing that with something else does not produce a
working application; it produces one that cannot connect.

**The mechanism chosen: an optional interface in a package named for its
non-portability, reached through a lookup helper.**

`compute/ext` holds [`TableBucketProvisioner`](../../compute/ext/ext.go) and
[`VectorBucketProvisioner`](../../compute/ext/ext.go). A provider implements
them only if its substrate has the feature natively. A caller reaches them
through `ext.TableBuckets(providerName, store)`, which returns either the port
or an `*ext.ErrNotImplemented` that wraps `compute.ErrUnsupported`.

**Why not the alternatives.**

* *Capability probe alone.* `Supports(CapTableBucket)` keeps AWS-only methods on
  the core interface, so every provider must implement them and return errors
  from methods the contract says it supports. The type system would assert
  portability that does not exist.
* *Exclusion from core with the interface in `compute/aws`.* Then the deploy
  module imports a provider, and the abstraction is decorative.
* *Emulation.* A vector bucket over pgvector satisfies a test and breaks a
  deployed application.

**How the inability becomes explicit.** Three ways, in increasing order of how
early they fire:

1. The lookup returns an error naming the provider and the port. There is no
   nil interface to call later and no discarded `ok`, because the only supported
   way in is a helper that returns `(T, error)`. Tested in
   [`compute/ext/ext_test.go`](../../compute/ext/ext_test.go).
2. That error wraps `compute.ErrUnsupported`, so a caller's existing branch
   catches it with no second case.
3. The refusal is a property of the *provider*, not of a runtime code path, so a
   platform can enumerate it and refuse to offer the bucket type in the UI at
   all. That is the outcome to aim for: an operator should learn that a table
   bucket is AWS-only when they pick it, not when the deploy fails.

**What this does not fix.** An application configured for a table or vector
bucket is an AWS-only application. The interface makes that fact visible; it
cannot make it false.

### 4.2 The network model

**The problem.** About thirteen call sites across `lambda.go`, `database.go` and
`build.go` pass raw AWS network-object identifiers: subnet IDs into
`CreateService` (`container.go:903-908`), `CreateDBSubnetGroup`
(`database.go:262`) and `CreateLoadBalancer` (`lambda.go:611`); a
`DescribeSubnets` call whose only purpose is to recover a VPC ID that
`CreateSecurityGroup` then needs (`build.go:943-954`, `lambda.go:737-750`);
security-group IDs threaded between `ensureAppSecurityGroup`,
`addRDSIngress`, and every create call downstream.

The tempting abstraction is `Placement{ Subnets []string }`. That is the fake
the brief warns about: it keeps every AWS network ID in the interface, gives a
Kubernetes provider a field it must ignore, and leaves the conformance suite
with nothing to check.

**The model chosen: named placement, plus reachability between roles.**

* **[`Placement`](../../compute/network.go) carries a name and nothing else.** An
  operator configures what the name means when they construct the provider —
  subnets, security groups, cluster and public-IP policy for AWS; namespace,
  node selector and default network policy for Kubernetes. The identifiers never
  enter `compute/`.
* **[`IngressRule`](../../compute/network.go) expresses reachability between
  *roles in the system*, not between network objects.** The peer kinds are
  `internet`, `platform-ingress`, `control-plane`, and `workload`. Every rule the
  source system creates is one of these four:

  | Source | Rule |
  | --- | --- |
  | `build.go:822-834` | platform-ingress → app on the container port |
  | `build.go:836-848` | internet → app on the container port (the no-proxy fallback) |
  | `lambda.go:580-586` | internet → ALB on each listener port |
  | `database.go:196-204` | workload(app) → database on 5432 |
  | `database.go:206-219` | control-plane → database on 5432 |

  "The platform's ingress proxy may reach this app on its container port" is a
  sentence a Kubernetes NetworkPolicy, an AWS security group and an on-prem
  firewall can each implement. "sg-0123 may reach sg-4567" is a sentence only
  AWS can hear.
* **Rules are declarative and attached to the spec, not provisioned
  separately.** The caller never sees a firewall object. This deletes a real bug:
  in the source system ingress is authorised once at security-group creation
  (`build.go:785-855`), so changing an application's container port later leaves
  the old port open and the new one closed — a defect patched by a separate
  `ReconcileContainerPortIngress` (`build.go:888-940`) that the caller must
  remember to invoke.
* **[`Route`](../../compute/network.go) carries hostname routing intent**, which
  on AWS becomes the Traefik docker labels written into the task definition
  (`container.go:1252-1380`) and on Kubernetes becomes an Ingress.

**Stated costs.**

* AppHub can no longer make per-deploy network decisions. It could not really
  make them before — the source system has exactly one `ECSClusterConfig` row
  and every application lands in it — but if that changes, the answer is more
  named placements, not network fields in `compute/`.
* Egress is **not modelled at all**. The source system never restricts it, so
  there was no behaviour to port, and inventing an egress model with no call
  site to validate it against would be speculation. This is a real gap: a
  deployed application can reach anything the placement can reach. Flagged in §5
  and recommended as a ticket.
* **Per-application region selection becomes per-application placement
  selection.** The source system stores a region string on the application row
  and builds the AWS config from it (`database/application.go:798-810`). A region
  is a location, so it is a placement; an operator who wants two regions
  configures two placements. This is stricter than what exists — an unusable
  region string currently degrades to a logged warning and a silent fallback,
  leaving resources stranded in a region nothing addresses — but it is a change
  in behaviour and in admin UX, and whoever ports the admin surface owns it.
* `PeerPlatformIngress` requires the provider to have been configured with an
  ingress proxy identity. The source system silently widens to `0.0.0.0/0` when
  `TRAEFIK_SECURITY_GROUP_ID` is unset (`build.go:836-848`) — that is, a missing
  environment variable turns a proxy-only port into an internet-facing one. The
  interface requires a provider to *reject* the rule instead. This is a
  behaviour change and it is deliberate.

### 4.3 Workload identity: the boundary with USOSS-3

**The problem.** `container.go:696-742` injects three environment variables and a
rotating secret into every deployed container so that the application's SDK can,
at runtime, presign an `sts:GetCallerIdentity` call and trade it plus the secret
for a short-lived token. The platform side (`auth/sts_verify.go:21-52`) replays
that signed request against AWS STS, reads back the caller's IAM role ARN, and
decides whether it matches the application.

So AWS STS is not merely a provisioning dependency — it is in the request path
of every deployed application. And the check that authorises it lives in the
credential layer while the identity it checks is created by the compute layer.
It crosses the USOSS-2 / USOSS-3 boundary in both directions.

**The first attempt did not compose, and this is the part worth recording.**
USOSS-2 and USOSS-3 were designed in parallel with no shared artifact. Both
produced a type called `Attestation`. They meant different things: this side's
was the *expected* identity a verifier should check against; the other side's
was the *runtime proof* a workload submits. The AWS scheme was spelled
`"aws-sts-caller-identity"` here and `"aws-sts"` there, so a registry keyed on
one would silently fail to select a verifier registered under the other. And the
verifier's signature had no parameter that could receive an expected subject at
all. Two good designs, zero composition.

The resolution is a **supervisor-owned normative contract**, and this section
now restates it rather than proposing it. Where this document and that contract
differ, the contract wins.

**Ownership: `credentials/workload` owns the vocabulary; `compute` imports it.**
The direction is chosen because `credentials` has no dependencies, so the edge
cannot cycle. There is exactly one definition of each type. A field-for-field
identical parallel definition in `compute` is still a bug against the contract,
and [`compute/contract_test.go`](../../compute/contract_test.go) fails if one
appears.

**The two concepts are permanently separate types.**

| Type | Meaning | Produced by | Consumed by |
| --- | --- | --- | --- |
| [`workload.ExpectedAttestation`](../../credentials/workload/attestation.go) | The **stored policy**: what identity a valid workload must prove. Configuration, not evidence. No secret material. | Compute, when a workload is provisioned; persisted by the deploy layer | The verifier, at check time |
| `workload.AttestationProof` | The **runtime evidence** a workload submits. Carries secret material. | The running workload | The verifier, at check time |

Never merged, never conflated. `ExpectedAttestation` never holds material;
`AttestationProof` is never persisted.

**What compute produces.** `WorkloadIdentity.Attestation` is an
`ExpectedAttestation` with four fields, none secret:

| Field | Meaning | AWS today | Kubernetes |
| --- | --- | --- | --- |
| `Method` | scheme | `MethodAWSSTSCallerIdentity` | `MethodK8sServiceAccount` |
| `Subject` | what a valid proof must resolve to | the IAM role ARN | `system:serviceaccount:ns:name` |
| `Issuer` | issuer whose keys validate a proof | empty | the cluster's OIDC issuer |
| `Audience` | required audience | empty | the configured audience |

Scheme identifiers are defined once, in
[`credentials/workload`](../../credentials/workload/attestation.go), and a string
literal naming a scheme anywhere else is a bug against the contract. `"aws-sts"`
is retired. Both properties are pinned by test.

**The verification boundary** is `Verify(ctx, expected, proof) (Identity, error)`,
owned by `credentials`. The expected value is an explicit parameter, not an
undocumented lookup inside the implementation, because a verifier that fetches
its own expectations cannot be reasoned about or tested in isolation. Every
failure returns one error: telling an unauthenticated caller which half of its
proof was correct is an oracle.

**Provisioning sequence.** `Provisioner.Rotate`, then `Provisioner.Materials`,
passing the returned revision into `Materials`. No third credential-facing
method — both reviews independently confirmed two suffice. Compute sets
`Materials.Env` verbatim and wires `Materials.Secrets` by reference; the compute
layer never reads a secret value, never calls a credential API, and never knows
what any of it means.

**The secret-reference adapter, and why it is nobody's package.** The credential
layer's reference names a store, a name, a version and a target variable;
`compute.SecretBinding` holds a provider-issued `compute.Ref`. **The deploy layer
owns exactly one conversion between them**, and it must validate that the named
store belongs to the selected compute provider and fail loudly otherwise. Only
the deploy layer knows which provider is in play: putting the adapter in
`credentials` would make it aware of a provider selection it has no business
seeing, and putting it in `compute` would make compute import a credential
locator it otherwise never touches. `ErrForeignRef` is the backstop when the
conversion is done wrong.

**Split of obligations — authoritative.**

| Obligation | Owner |
| --- | --- |
| Create the workload identity; report what it is | `compute` |
| Persist the `ExpectedAttestation` for a workload | deploy layer |
| Rotate the deploy secret each deployment | `credentials` (`Provisioner.Rotate`) |
| Deliver opaque materials into the workload environment | `compute` |
| Convert the credential secret reference to a `SecretBinding` | deploy layer |
| Verify an `AttestationProof` against an `ExpectedAttestation` | `credentials` |
| Mint the workload token after successful verification | `credentials` |

**What is deliberately not in `compute/`.** The rotating deploy-signature
secret's *value*. It is a platform mechanism — a second factor the verifier
requires in addition to the substrate proof — and it needs nothing from a
compute provider beyond a `SecretBinding`. Both reviews confirmed this call was
right and it is preserved.

**Honest note on a provider with no attestation.** A provider may leave
`Attestation` zero, meaning its running workloads have no way to prove their
identity outward. That is a legitimate answer for a minimal substrate, and a
verifier handed an empty `Method` must refuse rather than improvise. It means
workload identity does not work on that provider — information, not a failure of
the interface.

**What this bought.** `Method` is now a value rather than an assumption. Today's
behaviour is `MethodAWSSTSCallerIdentity`; a Kubernetes provider attests with a
projected service-account token without linking the AWS SDK. If any part of an
implementation makes the AWS scheme structurally privileged, that is a bug
against the contract.

### 4.4 The hardcoded ConductorOne account IDs

**The problem.** `bucket.go:508-513` defines three real AWS account IDs as IAM
role ARN constants, in a file that is a direct extraction candidate. They must
not survive into a repository that is going public, and per the standing
contract, no package outside `credentials/c1` may require ConductorOne at all.

**What was done.**

1. **None of the three values appear anywhere in this PR.** Not in the
   interface, not in the design doc, not in a comment, not in a test fixture.
2. **The capability is out of core.** Cross-account datasource binding is a
   ConductorOne integration, not something an application deploy needs. Core
   `ObjectStore.Grant` handles the portable case — a workload in this platform's
   own trust domain gets access to a bucket. That is `attachBucketPolicy`, and it
   is all the deploy path calls.
3. **The cross-domain case gets a seam in `ext`, with no identifiers.**
   [`ExternalAccessGranter`](../../compute/ext/ext.go) exists so that the
   cross-account **datasource binding** of item 2 — `EnsureC1DatasourceRole` in
   the source system — has somewhere to reach a provider through without
   importing one, if it is ever ported.

   Not the ConductorOne *credential provider*: an earlier version of this
   sentence said `credentials/c1` (USOSS-8), and that is false. Credential
   vending is an outbound HTTPS call to a tenant API and `credentials/c1` has
   zero dependency on package `compute`, verified with
   `go list -test -deps ./credentials/c1`. Two integrations with the same
   vendor's name, and only the unported one needs this seam. See
   `docs/decisions/usoss-37-the-cross-domain-grant-seam-stays-with-no-production-implementation.md`.
   Its [`ExternalPrincipal`](../../compute/ext/ext.go) is entirely
   caller-supplied: an opaque `ID` and a required non-empty `Constraints`. No
   default, no built-in registry of known partners, no environment-name-to-ARN
   lookup table. **AppHub ships zero principals.** Whoever operates a
   ConductorOne integration supplies theirs as configuration.
4. **`Constraints` is required, not optional.** A cross-domain grant with no
   constraint beyond the principal lets every other tenant reachable through
   that principal in — the failure mode the source system's own comment warns
   about (`bucket.go:645-652`).

   The field was called `SharedSecrets` in the first draft, which named the
   values secrets while storing them as plain strings. That is the worst of both
   readings. AWS documents an external ID as not-secret; its job is to stop a
   confused deputy — a third party holding access to many tenants being tricked
   into using it on the wrong one — not to authenticate the caller. Typing them
   as `SecretValue` would claim a property they do not have and push callers
   into credential-handling ceremony for nothing, while leaving the misleading
   signal in any audit. They are constraints, so they are called `Constraints`.
5. **Revocation must refuse to touch a grant it did not create.** Grants live on
   named resources whose names derive from mutable application names, so
   collisions are possible and deleting a stranger's trust relationship is not
   recoverable. The source system guards this with an ownership tag
   (`bucket.go:829-853`); the interface generalises it to `ErrNotOwned` on every
   port.

**A second identifier of the same class, found while doing this.**
`container.go:1327` and `:1360` build routed hostnames against a hardcoded
internal domain suffix. It is not in scope for USOSS-2, but it is the same
category of leak and it lives in a file USOSS-11 and USOSS-15 will port.
[`Route.Host`](../../compute/network.go) takes a whole hostname precisely so the
suffix stays operator configuration. Flagged for the supervisor.

---

## 5. What this abstraction does not make portable

Every item here is a place where implementing the interface faithfully still
does not get you an equivalent system.

**S3 Tables and S3 Vectors.** No portable equivalent exists, and the
non-portability reaches the application, not just the provisioning code. An
application configured for either is an AWS-only application. Fenced in
`compute/ext`; see §4.1.

**Cross-trust-domain access grants.** Cross-account role assumption with an
external-ID condition is an AWS mechanism. The nearest equivalents elsewhere —
workload identity federation, signed URLs, cross-tenant app registrations —
differ in what the external party presents, what apphub must configure, and
what can be revoked. There is no shared vocabulary to abstract over. Fenced in
`compute/ext`.

**Permission granularity.** `AccessLevel` has three values, and it only exists
on the ports whose substrate authorises by workload identity. Two providers
implementing `AccessReadWrite` will not produce identical permission sets, and a
least-privilege audit must be done per provider against that provider's
documented mapping. The conformance suite can only check behaviour — after
`AccessRead`, a read succeeds and a write fails — which is the portable part.
If a specific grant needs to be narrower than the substrate's natural
`read-write`, that is a provider-configuration concern, not an interface one.

**Function runtimes.** `FunctionSpec.Runtime` is a free string whose vocabulary
came from AWS. A provider validates against its own set. Two providers will not
accept the same values, and an application record naming `nodejs20.x` is not
portable as written.

**Capacity semantics.** `CapacityRange` in abstract units is a translation, not
an equivalence. 0.5–4 units on Aurora Serverless v2 autoscales continuously
within the range and bills per second; the same range on an operator-managed
Postgres is a requests/limits pair with entirely different behaviour under load.
Same spec, different economics and different failure modes.

**Relational engine versions.** `EngineVersion: "16"` means "the latest 16.x the
substrate offers". Two providers will offer different minors with different
bundled extension versions. The source system pins the major deliberately and
documents why (`database.go:299-304`); the interface preserves the intent, not a
guarantee of identical bytes.

**Key-value semantics.** `KeyValueSpec` describes a partition key and a sort key
because that is what the source system's convention needs. It does not specify a
consistency model, a transaction model, or a size limit. A provider whose
key-value store differs on any of those will run the application's code and
produce different results. This is why a provider that cannot match DynamoDB's
semantics should decline `CapKeyValueTable` rather than approximate it: a hard
`ErrUnsupported` at deploy time is better than data corruption at runtime.

**Network egress.** Not modelled. A deployed workload can reach whatever its
placement can reach. Two providers will differ, and neither is constrained by
anything in this interface.

**Log delivery.** Not modelled. The source system configures the `awslogs`
driver inline in the task definition (`container.go:550-558`) and reads logs from
CloudWatch elsewhere (`services/logs.go`). Where a provider sends logs, and how
an operator reads them, is entirely outside this interface. That is a
deliberate v1 scope decision and a visible gap: "deploy an app and see its
logs" is table stakes, and the second provider will need an answer.

**Metrics, autoscaling, and cost.** Not modelled. The source system does none of
them for deployed applications.

**DNS.** `Route.Host` states a desired hostname. Nothing in the interface
registers it. On AWS the record already exists as a wildcard; another substrate
may need explicit registration, and the caller will have to do it.

**Deletion of non-empty resources.** `DeleteBucket` deliberately does not
specify whether a non-empty bucket is emptied first. It is a destructive-data
policy, it differs per substrate, and the source system handles it in a separate
scheduled path. Providers must document their behaviour; the interface does not
promise it is the same.

**Relational access control.** Not modelled at all, by the same reasoning that
removed `Granter` from the relational port (§3.5): SQL roles and grants are
ordinary SQL, above this interface. The consequence is that a caller wanting a
database reachable only by one workload gets that from the network layer
(`IngressRule`) plus SQL, not from a single portable call.

**Who may open an interactive session.** `ExecEnabled` makes a workload
reachable; authorising the operator's principal is operator configuration
outside this interface (§3.7). Two providers will express that authorisation in
entirely different systems — an IAM policy and an RBAC binding — with different
blast radii, and nothing here constrains either.

**Image pull authorisation.** Not expressible as a grant, on any substrate, and
no longer pretended to be. It is a provider obligation instead (§9.1), which
means two providers discharge it differently and a caller cannot audit it
through this interface at all. That is a real loss of visibility, accepted
because the alternative was a method whose only honest implementation minted a
credential the caller could not see.

**Retry policy.** [`ErrTransient`](../../compute/errors.go) says a failure may
succeed if retried; it does not say how many times, how fast, or with what
backoff. A provider retries internally on its own budget, bounded only by the
caller's context deadline. Two providers will differ in how long an operation
takes to give up, and nothing here constrains that.

**"Serving".** [`HealthCheck`](../../compute/container.go) makes readiness
expressible, but a nil `Readiness` still means the provider's default, and those
defaults differ: a pod with no probe is ready when its process starts, an ECS
task behind a target group when a health check passes. A caller that leaves the
field nil is still getting a substrate-defined answer — it can now find out by
supplying one.

**Ordering and atomicity.** Nothing here is transactional. A deploy that
provisions a bucket, a database, and a service can fail in the middle and leave
two of the three. The source system has the same property. The interface makes
retries safe (everything is idempotent) but does not make partial failure
disappear.

---

## 6. Falsification: sketching a Kubernetes provider (USOSS-19)

The point of this section is to find the places where the interface only
*looks* portable. Each port below is followed by what a Kubernetes provider
actually does, and the ones that hurt are called out.

| Port | Kubernetes implementation |
| --- | --- |
| `IdentityService` | ServiceAccount per workload. `ExpectedAttestation` is `MethodK8sServiceAccount`, subject `system:serviceaccount:<ns>:<name>`, issuer from the cluster's OIDC discovery document. |
| `ImageRegistry` | Whatever registry the operator configured — Harbor, GAR, ECR. Retention via that registry's policy API, or `ErrUnsupported` if it has none. |
| `ImageBuilder` | kaniko or buildkit in a pod. Push credentials from a short-lived registry token, mounted only into the build pod. |
| `ContainerRuntime` | Deployment + Service + NetworkPolicy (from `Ingress`) + Ingress objects (from `Routes`). `ScaleService` patches `spec.replicas`. `EnsureScheduledJob` writes a CronJob. |
| `ObjectStore` | MinIO, Ceph RGW, or a cloud bucket service. `Grant` becomes a bucket policy or an IAM-equivalent binding. |
| `RelationalProvisioner` | CloudNativePG, Zalando, or Crunchy. Capacity becomes requests/limits, placement a namespace and storage class, the endpoint the operator's Service DNS name. No substrate identity system required — which is the point of it not embedding `Granter`. |
| `KeyValueProvisioner` | Declined; see below. |
| `SecretStore` | Secret objects, bound via `secretKeyRef`. |
| `FunctionRuntime` | Knative or OpenFaaS, or decline. |

**Where it hurts, honestly:**

* **`CapKeyValueTable` has no answer.** A Kubernetes provider will decline it.
  Any application configured for DynamoDB simply cannot be deployed there. This
  is the correct outcome — see §5 — but it means "multi-cloud" is qualified: the
  *platform* is portable, a given *application's configuration* may not be.
* **`CapFunction` has three answers and two of them are compromises.** Knative
  changes cold-start and scaling behaviour; a Deployment wrapping the bundle
  changes the execution model entirely. Declining is the cleanest.
* **`Route.RequireAuth` depends on the cluster's ingress controller supporting
  external authentication.** Most do (nginx `auth-url`, Traefik ForwardAuth),
  but a provider whose ingress cannot enforce it must fail the spec rather than
  route unauthenticated traffic to a workload that asked not to receive it.
* **Exec is where this exercise earned its keep.** The first draft made exec a
  `WorkloadCapability`, granted to the workload's identity. Mapping that to
  Kubernetes exposes it as a security error rather than an awkward fit: RBAC on
  `pods/exec` authorises the *caller*, so the mapping would have granted the
  workload the right to exec into pods while still leaving operators unable to
  exec into the workload. It is now `ServiceSpec.ExecEnabled` — the target half
  — with operator authorisation outside the interface (§3.7). Even corrected,
  the two substrates differ in blast radius: an RBAC binding is cluster-scoped
  where an ECS grant is per-task, and that difference is in §5.
* **`WorkloadCapabilityModelInference` has no Kubernetes answer**, so a plain
  provider does not advertise `CapModelInference` and rejects a spec requesting
  it.

Nothing in the list is a method only AWS can satisfy, which was the ticket's
sanity check. But four capabilities land on "decline", and that is the honest
shape of the result: the interface lets a substrate say no clearly, and USOSS-19
should be read as a test of *how clearly*, not of whether everything works.

Two of the three blockers in the first review came out of running exactly this
exercise — the relational `Granter` and the exec principal. That is the argument
for USOSS-19 existing at all, and for it running before any of USOSS-10..14 get
far.

---

## 7. How the conformance suite should test a provider (USOSS-16)

The suite verifies this contract, so it should be organised around the
obligations stated above rather than around methods. Suggested structure: one
exported function, `conformance.Run(t *testing.T, p compute.Provider, opts
Options)`, that a provider's own test package calls. `compute/fake` runs it in
CI, hermetically; `compute/aws` and `compute/k8s` run it behind a build tag
against a real substrate, out of band.

**Provider-level invariants**

1. **Capability/accessor agreement.** For every `Capability`,
   `Capabilities().Has(c)` is true if and only if the corresponding accessor
   returns a nil error. This is the one invariant no other test catches, and a
   provider that fails it is lying about itself.
2. **Refusals are typed.** Every accessor for an absent capability returns an
   error satisfying `errors.Is(err, ErrUnsupported)`, and the message names the
   provider and the capability.
3. **`Name()` is stable and non-empty**, and every `Ref` the provider issues
   carries it.
4. **Foreign refs are refused.** Hand each method a `Ref` with a different
   `Provider` field and require `ErrForeignRef` — not `ErrNotFound`, which would
   let a caller conclude the resource had been deleted.
5. **Kind is checked.** Hand a method a `Ref` of the wrong `Kind` and require an
   error rather than an attempt.

**Scope: which invariants apply to which ports.** Items 6, 7, 9 and 14–18 apply
to every port. Items 8, 10, 11, 12 and 13 apply only to the **asynchronous**
ports — container services, scheduled jobs, functions, function endpoints,
relational endpoints, key-value tables — because only those have a phase and a
Wait. The **synchronous** ports (image repositories, buckets, secrets) instead
get the mirror-image invariant stated under item 8.
[`compute/status.go`](../../compute/status.go) defines the two classes and is
the authority; an earlier draft of this document
said "every port", which would have produced a suite asserting a `PhaseGone` on
a type with no phase.

**Per-port behavioural invariants:**

6. **Ensure is idempotent.** Twice with the same spec yields the same `Ref` and
   no error. Assert on the `Ref`, not on a "created" flag.
7. **Ensure converges.** Ensure, then Ensure with a modified spec, then Describe:
   the observed state reflects the second spec. Specifically for declarative
   fields — `Ingress`, `Capabilities`, `Env` — assert that a value present in the
   first spec and absent from the second is *gone*, not merely not-added. This is
   the property that replaces `detachBedrockPolicy` and
   `ReconcileContainerPortIngress`, and it is the one an implementation is most
   likely to get wrong by implementing Ensure as create-or-add.
8. **Ensure does not block** *(asynchronous ports)*. Ensure returns within a
   small bound (a few seconds) even for resources that take minutes to converge,
   and may return `PhasePending`. A provider that blocks fails.

   The synchronous ports get the mirror-image invariant instead: **Ensure
   returns something usable.** The resource is usable when the call returns, or
   the call returned an error. There is no third state, and a provider must not
   return a half-created resource.
9. **Delete is idempotent.** Deleting an absent resource returns nil. Delete
   twice; the second returns nil.
10. **Describe after Delete is `PhaseGone`, not an error** *(asynchronous
    ports)*. Teardown must be re-runnable without distinguishing the two. For a
    synchronous port, Describe after Delete is `ErrNotFound`.
11. **Wait honours its deadline.** With a deliberately short `WaitOptions.Timeout`
    against a resource that will not converge, the call returns
    `ErrTimeout` — distinguishable from `ErrFailed` — within the timeout plus a
    small margin, and never hangs.
12. **`WaitOptions` with neither a timeout nor a context deadline is
    `ErrInvalidSpec`.** No path may wait forever.
13. **`OnUpdate` fires at least once and never after the call returns.**

**Ownership and naming**

14. **Determinism.** The same logical `Name` yields the same physical resource
    across separate `Ensure` calls, separate provider instances, and process
    restarts. Teardown depends on reconstructing names that may never have been
    persisted.
15. **Ownership refusal.** Pre-create a resource with the name a spec would
    claim, without the provider's ownership marker, then Ensure. Require
    `ErrNotOwned`. A provider that adopts it fails. This test needs a hook in
    `Options` to create the foreign resource, since doing so is
    substrate-specific.

**Grants** — only for the ports that implement `Granter`: `ImageRegistry`,
`ObjectStore`, `KeyValueProvisioner`, and the `ext` ports. Driving these against
`RelationalProvisioner` is a suite bug, not a provider bug: relational access
control is SQL, above the interface (§3.5).

16. **Behavioural, not structural.** After `Grant(res, id, AccessRead)`, a read
    performed *as that identity* succeeds and a write fails; after
    `AccessReadWrite`, both succeed; after `Revoke`, both fail. Asserting on
    policy documents would test AWS, not the contract. This requires the suite to
    be able to act as a workload identity, which is the hardest part of the
    harness and should be an `Options` hook.
17. **Grant is idempotent and last-write-wins on level.** `AccessReadWrite` then
    `AccessRead` narrows; it does not leave two grants.
18. **Revoking an absent grant returns nil.**

**Security properties** — these are the ones worth writing even though they feel
paranoid, because this repository is going public:

19. **Secrets do not appear in errors.** Put a sentinel string as a
    `SecretValue`, drive every method that touches it into a failure, and assert
    the sentinel appears in no returned error's `Error()` output and no `Status`
    field.
20. **Secrets do not appear in non-secret channels.** Assert the sentinel does
    not appear in anything the provider writes that is inspectable — a task
    definition, a pod spec, a build log — via an `Options` hook that lets the
    suite dump the provider's rendered artefacts.
21. **`AdminPassword` is not rotated on re-Ensure.** Ensure a relational
    endpoint, Ensure again with a *different* `AdminPassword`, then connect with
    the original. The original must still work. This is the invariant that keeps
    a redeploy from locking the platform out of its own database.
22. **Public access is off by default.** A bucket created with
    `PublicAccess: false` rejects an anonymous read.
23. **An HTTPS listener with no `TLSConfig` is `ErrInvalidSpec`.** Reachable
    since `ListenerSpec` gained a protocol (§9.7); it used to be unrepresentable,
    and the suite said so at runtime rather than checking it. Also check the
    inverse — a plaintext listener carrying a certificate — and a `Route` with
    neither a certificate nor `AllowPlaintext` (§9.4).

**Capability-specific negatives**

24. For every capability the provider does *not* advertise, drive the
    corresponding spec through and require `ErrUnsupported` — for example
    `ObjectClassZonal` without `CapObjectStoreZonal`, a
    `WorkloadCapabilityModelInference` in a `ServiceSpec` without
    `CapModelInference`, and `ExecEnabled: true` without `CapWorkloadExec`.
    Enumerate `compute.WorkloadCapabilities()` rather than hardcoding the list,
    so a capability added later is covered without editing the suite.
25. **Exec does not widen the workload's identity.** With `ExecEnabled: true`,
    assert that the workload's own identity gained no ability to open sessions
    against *other* workloads. This is the regression guard for the principal
    error corrected in §3.7, and it is behavioural, so the suite can state it
    without knowing what an RBAC binding or an IAM policy looks like.
26. **`ext` lookups match reality.** For each `ext` port, the lookup helper
    succeeds if and only if the provider documents that it implements it. Already
    unit-tested for the helper mechanics in
    [`compute/ext/ext_test.go`](../../compute/ext/ext_test.go); the suite checks
    the provider's side.

**Cross-package composition** — not the compute conformance suite's job, but it
needs an owner and this is the only place it is written down. After both sides
land, something must check that a `workload.ExpectedAttestation` produced by a
compute provider is accepted by a `credentials` verifier for the same `Method`,
end to end, against the fake provider. Neither package's own suite can see both
halves. Recommend it live with the deploy layer's tests (USOSS-15), since the
deploy layer is where the two are joined.

**What the suite should *not* do:** assert on generated policy documents,
resource names, tags, or ARN formats. Every one of those is a provider's
business, and a suite that checks them is a suite that only AWS can pass.

---

## 8. Open items for the supervisor

0. **Read §9 first.** The amendment round changed the interface after two
   implementations falsified it, and §9.9 lists what was deliberately left open.
   Items 1–9 below predate it and are unchanged except where §9 says otherwise.
1. **Secret storage has no implementation ticket.** See §3.6. It is a sixth
   capability with call sites in five files.
2. **Teardown call sites live outside the surveyed directory.** The delete half
   of every port here was derived from `services/application.go:4104-4824`,
   which the compute-callsites survey did not cover. The enumeration in §3 is
   from a direct grep, not from a reviewed inventory, and should be checked
   before USOSS-10..14 estimate their work.
3. **A second hardcoded internal identifier.** `container.go:1327`, `:1360` — the
   routed-hostname domain suffix. Same class as the account IDs. Belongs to
   USOSS-11/USOSS-15.
4. **Egress is unmodelled** (§5). Recommend a ticket.
5. **Log delivery is unmodelled** (§5). Recommend a ticket before the second
   provider lands, since "deploy an app and see its logs" is table stakes.
6. **Behaviour changes proposed by this design**, each of which needs a
   decision rather than silent adoption:
   * HTTPS listeners require a certificate (§3.3) — the source system's
     behaviour here is a defect.
   * A missing ingress-proxy configuration becomes an error rather than an
     open-to-the-internet fallback (§4.2).
   * Provisioning no longer blocks inline; callers choose their own timeouts
     (§2, rule 4).
   * Per-application region becomes per-application placement (§4.2), which
     changes the admin surface from a free-text region to a choice among
     configured placements.
7. **`credentials/workload/attestation.go` is in this PR, and it should not
   have to be.** The shared contract puts the workload-identity vocabulary in
   `credentials/workload`, and `compute` cannot compile without
   `ExpectedAttestation` and `Method` existing. USOSS-3 is writing the rest of
   that package in parallel. This PR therefore adds exactly the contract's two
   declarations in a **separate file**, so the two branches touch different
   files and only collide if USOSS-3 also declares them — in which case the
   resolution is to delete one copy, since both are transcriptions of the same
   normative snippet. Flagged rather than coordinated around, because
   coordinating without a shared artifact is what produced the original defect.
8. **Composition is not covered by either package's tests.** Nothing checks that
   an `ExpectedAttestation` from a compute provider is accepted by a
   `credentials` verifier end to end, because neither suite can see both halves.
   §7 recommends it live with USOSS-15. It needs an owner.
9. **The `ext` import allowlist includes `modules/deploy`.** That is the one core
   package permitted to reach a non-portable port, and it is permitted because an
   application may genuinely be configured for an AWS-only bucket type. It makes
   the rule weaker than it looks. The alternative — a dedicated composition
   package that owns every ext call — is structure invented for code that does
   not exist yet, so it was not built. Worth revisiting when `modules/deploy` is
   real (USOSS-15).

---

## 9. The amendment round

Two implementations were written against this interface and reported thirty-five
findings between them: a reference provider plus a conformance suite (USOSS-16,
ten places the interface was underspecified for conformance purposes) and a
complete Kubernetes provider written specifically to falsify it (USOSS-27,
twenty-five findings, four blockers). They overlap, and the overlap was the most
informative part — two workers reaching the same gap from opposite directions is
a much stronger signal than either alone.

Every amendment below is verified against both. `compute/fake` and `compute/k8s`
each pass the conformance suite after it, and where an amendment introduced a new
invariant the suite gained a check and the fake gained a deliberate defect that
the check catches.

### 9.1 `Granter` — the rule, and the audit it should have had

This is the finding worth reading even if nothing else here is.

`ImageRegistry` embedded `Granter`, and no OCI registry can implement it as a
grant. Two independent reasons: no registry federates a workload identity
provider — Harbor, GAR, Quay and ECR all authenticate a robot account holding a
token — and the principal that pulls an image is not the workload but the
kubelet, or on ECS the task *execution* role. So the only implementation that
compiles is one where `Grant` mints a credential, stores it in a secret, and
attaches it to the identity: long-lived material created as an invisible side
effect of a call the caller believes is a policy write, that nothing rotates, and
that `Revoke` has to remember to undo.

**This was the third instance of one shape.** A reviewer found it on
`DatabaseProvisioner`; the fix split the port and, at the time, wrote the general
rule down:

> `Granter` goes on a port only when the substrate authorises by workload
> identity.

The rule was right. It was stated and then not applied to the other ports, which
is how a fourth reviewer would have found a fourth instance. The lesson is the
one `docs/decisions/` already records about checks versus types, and it applies
to design rules too: **a rule enforced by memory is not a rule.**

**And the first justification for the fix was wrong, in a way worth recording.**
It said no registry path can authorise a pull by workload identity — a universal
claim, defended with evidence that is only about ECS. A third reviewer produced
the counterexample: a Kubernetes kubelet credential provider can present a
[pod-bound ServiceAccount token](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/#service-account-token-for-image-pulls)
to a credential plugin, which is identity-scoped pull authorisation and not a
minted credential in disguise.

The conclusion survives and the reasoning changes, which is a distinction worth
making explicit rather than quietly patching. `Granter` stays off the required
interface **not because the thing is impossible but because it is not universally
supported** — and forcing every provider to implement something most substrates
cannot express is what made the original defect a defect. That is a capability
question, and this package already has a shape for capability questions.

So the amendment is four things.

1. **`Granter` is off `ImageRegistry`.** No provider is required to implement it.

2. **[`ImagePullGranter`](../../compute/image.go) exists for the substrates that
   can**, behind [`CapImagePullGrants`](../../compute/capability.go) and reached
   through `compute.ImagePullGrants`, which checks the capability before the
   type assertion. It is narrower than `Granter` on purpose: `AccessLevel` has no
   third meaning on a repository, so it is `GrantPull`/`RevokePull` rather than
   three levels one of which would be a lie.

3. **Every provider still owes an obligation, and it is scoped.** The first
   version said "a workload can pull *any* image from a repository the provider
   issued", which every workload satisfied with one project-wide credential — a
   least-privilege regression introduced by a fix for a least-privilege problem,
   and least privilege is a standing constraint rather than a preference. It now
   reads:

   > A provider MUST arrange that a workload it runs can pull **the image its
   > spec names**, when that image is in a repository the same provider issued.
   > Whatever it arranges MUST be scoped as narrowly as the substrate allows —
   > to the repositories the workload's own spec references, and to that
   > workload, wherever the substrate can express either. A provider that can
   > only express something broader MUST say so in `Status.Message`. It MUST NOT
   > expose any credential it creates to the caller.

   The Kubernetes provider discharges it at workload creation rather than at
   identity creation, because only the workload's spec names an image; granting
   at identity creation could only be scoped to every repository the platform
   owns, which is what it did before.

4. **Every port was audited against the rule, and the audit is written down** in
   [`Granter`](../../compute/identity.go)'s doc comment:

   | Port | Substrate authorises by workload identity? | Verdict |
   | --- | --- | --- |
   | `ObjectStore` | Yes. S3 by IAM principal natively; an S3-compatible store federating the cluster's issuer authorises a ServiceAccount subject. A deployment may lack it — see `CapWorkloadGrants` below. | **Keeps** |
   | `KeyValueProvisioner` | Yes. DynamoDB grants to an IAM role and has no database-internal principal at all. | **Keeps** |
   | `ext` bucket ports | Yes. Same substrate, same IAM. | **Keep** |
   | `RelationalProvisioner` | No. Access is a SQL role created with ordinary SQL above this interface, and no substrate identity maps to one. | Removed earlier |
   | `ImageRegistry` | Not universally. Optional capability instead. | **Removed from the required interface** |
   | `SecretStore`, `ContainerRuntime`, `FunctionRuntime`, `ImageBuilder` | Not applicable — they consume identities or hold obligations; none owns a grantable resource. | Never had it |

   The audit found no fourth instance. It also found a confirming detail: **the
   source system never grants ECR access to an application's task role either.**
   That role is created with no policies (`build.go:619-666`) and accumulates
   DynamoDB, S3, Bedrock and `ssmmessages` statements — never ECR — because pulls
   run under the operator-configured execution role apphub does not manage
   (`container.go:742`). That is evidence about ECS, and it is cited as evidence
   about ECS.

**The rule is now derived, not restated — and that took two attempts.** The first
version of the audit test held a hand-written map of "every exported interface in
compute" and checked it against
[`compute.WorkloadGrantPorts`](../../compute/identity.go). A reviewer defeated it
in one line: an exported `ReviewOnlyPort interface { Granter }` outside the map,
and the test passed. The guard that was supposed to make a fourth `Granter` a red
build could not see a fourth port at all.

That is the same failure the audit exists to prevent, one level up — and the same
one this repository already learned elsewhere, where a hand-maintained package
list drifted from the real set twice in opposite directions before being derived
with a toolchain cross-check. So:

* [`compute/granteraudit_test.go`](../../compute/granteraudit_test.go) parses the
  package with `go/ast` and enumerates every exported interface declaration,
  flattening embedded interfaces. A Go program cannot list a package's types, but
  it can read the package. Both forms of the reviewer's fixture — embedding
  `Granter`, and declaring `Grant`/`Revoke` directly — now fail the build.
* The reflect-based list in `contract_test.go` remains, and is no longer the
  authority on anything: a cross-check requires the two to agree in both
  directions, so a parser that quietly stops finding declarations is caught too.
  A derivation that returns nothing passes every check written over it, which is
  the failure mode a derived check dies of.

### 9.2 Transient failures, and a sentinel renamed

Found independently by both: USOSS-16 declined to write a retry invariant rather
than invent semantics the interface did not define, and USOSS-27 hit it from the
substrate side. Kubernetes returns HTTP 409 for two unrelated things — "that name
is taken", and "your copy is stale, read it again", the latter being the most
common retryable failure on the substrate. The taxonomy had nowhere to put the
second, so a provider had to swallow it and retry on a budget the caller could
neither see nor bound.

* **[`ErrTransient`](../../compute/errors.go)** is the only sentinel that says
  "try again". A provider may retry internally — most substrates need to — but
  must not retry past the caller's context deadline, and must return this rather
  than `ErrFailed` when it gives up on something that could still succeed.
  `ErrFailed` tells a caller the spec has to change, and a caller that believes
  that about a throttling error stops a deploy that would have worked.
* **`ErrConflict` is now `ErrNotOwned`.** The rename is the more valuable half.
  The old name invited exactly the mis-mapping the finding predicted: an
  implementer porting a Kubernetes client reaches for a sentinel called
  "conflict" when they see a 409, and a caller branching on it concludes its
  deploy collided with somebody else's infrastructure. The name was the trap.

### 9.3 Placement reaches identity and secrets

`WorkloadIdentitySpec` and `SecretSpec` carried no `Placement`, which is
invisible on AWS — an IAM role and an SSM parameter are account-global — and
disabling on any substrate that scopes them. A Kubernetes pod may only run as a
ServiceAccount in its own namespace and may only resolve a `secretKeyRef` in its
own, and a `Placement` is a namespace. So every identity and every secret landed
in one fixed place and a workload placed anywhere else could use neither.

`Placement` is the abstraction that replaced AWS network identifiers, and it is
the documented answer to multi-region. An abstraction two of its own specs cannot
reach is incomplete, not merely leaky. Both specs carry one now, with the same
"empty means the provider's default" rule as everywhere else, and
[`SecretBinding`](../../compute/secret.go) states the corollary: a binding across
placements is `ErrInvalidSpec`, and **a provider must not copy secret material
between placements to satisfy one** — copying doubles the places an audit has to
look for material this interface is otherwise careful never to let apphub read.

### 9.4 A route can be served encrypted

`ListenerSpec` has required a certificate for TLS since the first draft, on the
fail-closed argument. `Route` — the hostname every deployed application actually
gets — carried none, so a provider could serve plaintext (fail-open), invent a
certificate (forbidden in as many words), or refuse every route. Serving an
application's own hostname over HTTP by omission is the same defect as the source
system's certificate-less HTTPS listener, one layer down.

[`Route.TLS`](../../compute/network.go) and `Route.AllowPlaintext`. Plaintext is
still possible — a platform may terminate TLS at an edge this interface cannot
see — but it is now something somebody wrote down rather than the consequence of
leaving a field nil.

### 9.5 Every read-back carries its effective spec — and what that does not prove

The largest of the conformance gaps. §7.7 asks a provider to show that an element
present in the first spec and absent from the second is *gone* rather than merely
not-added — the property that replaces the source system's detach and reconcile
helpers, and the one an implementation is most likely to get wrong. No port's
read-back exposed any declarative state, so it could only be checked through a
provider-supplied hook, which a provider is free not to supply.

Kubernetes made the omission worse rather than better, which is the instructive
part: the object is *holding* the desired state, and a `Describe` could return it
for free. The interface was discarding information the substrate had.

Every status and descriptor now carries a `Spec`. `SecretStore` is the one
exception, for a stated reason: a secret's declarative state is its value, `Get`
already returns it, and a descriptor echoing the rest would add a second place
material could leak from. Where a spec contains material it is zeroed
(`RelationalSpec.AdminPassword`).

**The claim about what this buys was too strong, and a reviewer showed it.** The
first version of this section said the field took the strongest invariant in the
suite off a provider-supplied hook, and reported that the reference provider went
from six contract observations to zero. The reviewer wrapped the fake so that
`Describe`, `Wait` and `ServiceStatus.Spec` all reported the new spec while the
underlying object kept the old one, ran the suite with `Options.Rendered` unset,
and the named convergence check passed. The hook had been made optional, not
replaced.

The honest position, now written into
[`Status`](../../compute/status.go) as well as here:

* `Spec` is **provider-reported effective desired state**, not an observation of
  the substrate. Nothing a provider says about itself can establish what it did.
* It genuinely catches the common failure — an `Ensure` implemented as
  create-or-add accumulates and then reports the accumulation — so it earns its
  place and runs on every port.
* It does **not** establish convergence, and the suite no longer behaves as
  though it does. Without `Options.Rendered`, the convergence check is recorded
  as **not verified** rather than passing. A provider that supplies no substrate
  observer has not demonstrated convergence, and the report says so.

That is a smaller claim than the one it replaces. It is also the true one, and
`compute/fake/defects_test.go` keeps the reviewer's wrapper as a standing test:
if the check ever goes green without an observer again, it fails.

**A second thing every read-back must not do: alias.** A reviewer mutated the
`Labels` map on a returned `Repository.Spec` and the next `Describe` reported the
mutation, with no `Ensure` in between — the provider was handing out the map it
stored. Small in the fake, large in what the fake is *for*: six AWS providers
will be written against it, and a reference implementation that aliases teaches
all six that aliasing is fine, with the test that should catch it running against
the reference that does the same thing.

`port/<name>/read-back-does-not-alias-provider-state` is now a conformance
invariant on every port, and it earned its keep immediately: beyond the image
repository the reviewer found, it caught the fake's relational read-back and
**two more instances in the Kubernetes provider** that nobody had noticed.

### 9.6 Scheduled jobs are synchronous

The port had a phase-bearing status and no `Wait`, which left three conformance
invariants unverifiable and gave a caller no supported way to block. USOSS-16
offered "add the method or move the port"; USOSS-27 argued for moving it, and
that is the right call: a cron entry is live the moment the substrate accepts it,
no controller writes a readiness condition for a Kubernetes CronJob, and the
source system creates its EventBridge schedule with no polling loop
(`container.go:1382-1490`) unlike every genuinely asynchronous path it has. A
`Wait` here would exist to satisfy a taxonomy and return immediately on every
substrate anybody has named.

### 9.7 Listeners have a protocol

§7.23 of this document asserted that "an HTTPS listener with no `TLSConfig` is
`ErrInvalidSpec`" — a state that was **unrepresentable**, because nil TLS was the
only way to say plaintext. An invariant nobody can construct a violation of is
not an invariant, and the suite had to say so at runtime instead of checking it.

[`ListenerProtocol`](../../compute/function.go) makes the defect representable,
so the rule is now tested rather than merely asserted. It also matches the
substrates that model listeners at all: a Gateway API `Listener` is `{Name,
Hostname, Port, Protocol, TLS}`.

### 9.8 The smaller amendments

| Finding | Amendment |
| --- | --- |
| No capability for "an ingress proxy is configured", nor for "the ingress can authenticate" | `CapPlatformIngress`, `CapIngressAuth`. The former is configuration-derived; the latter requires a controller-enforced authentication path. Kubernetes does not currently implement one and refuses `RequireAuth` rather than advertising the capability based on an inert annotation. |
| `WorkloadCapability` → `Capability` was prose | `WorkloadCapability.Requires()`, so the suite can enumerate rather than hardcode. |
| `ImageRegistry` had no read-back | `DescribeRepository`. |
| `ServiceSpec` had no readiness model | `HealthCheck`, with a normative "a provider MUST document its default". |
| `ServiceStatus` reported no address for its routes | `RouteAddresses`. DNS is still not managed; a caller that cannot learn the address could not delegate it either. |
| `EndpointSpec` had no hostname | `Hostnames`. The caller chose the certificate and the provider chose the name it was served under — two decisions that have to agree and that no single party made. |
| `FunctionSpec` had no reachability | `Ingress`, for symmetry with every other workload spec. The invoke permission stays owned by the endpoint, with a stated rule that a provider must not express it where the next `EnsureFunction` would reconcile it away. |
| `FunctionSpec` had a memory field and no CPU | `Resources`, with zero CPU meaning "derive it". Otherwise every non-Lambda provider hardcodes Lambda's memory-to-CPU ratio, which is what the Kubernetes provider had to do. |
| `DeleteWorkloadIdentity` obliged a cross-substrate cascade with no mechanism | Narrowed to SHOULD, scoped to the provider's own `Granter` ports, with `ErrFailed` on partial failure. |
| No egress model | Documented as a normative obligation: a provider MUST NOT restrict egress, because the interface gives a caller no way to declare what a workload needs to reach. The consequence — on a default-deny-egress cluster the interface's inputs are insufficient to let an app reach its own database — is stated where a reader will find it. |
| `Status.UpdatedAt` had no clock, `Message` no obligations | Both specified. `UpdatedAt` is the provider's observation, not the substrate's transition time; the two differ by minutes on a watch cache. |
| `RunsOn` has no meaning on some substrates | Documented as advisory, with the corollary that a caller needing two identities must give them two names. |
| `ExecEnabled` is two-state with one enforceable state | Documented: it requests reachability and does not promise that false prevents it; a provider must document which states it can enforce. |
| `PeerInternet` is wider on Kubernetes | Documented on the constant. It is the one peer where the non-AWS provider is the *less* restrictive. |
| `Provider.Name` implies one substrate | Documented: a name identifies a configuration, and swapping what sits behind a port invalidates the refs issued for it. |
| `Resources` collapses requests and limits | Documented as a concession, with the Guaranteed-QoS consequence named. |
| `BuildSource.ContextDir` assumes a shared filesystem | Obligation stated: a provider whose builder does not share the caller's filesystem must transport the context and must document its size limit. |

### 9.9 Deliberately not closed

Each of these was considered and left open. Saying which omissions are decisions
is the point of the section.

* **A portable egress model (`EgressRule`).** The vocabulary already exists and
  the shape is obvious, but no call site in the source system needs one, so
  there is nothing to validate a design against. The obligation in §9.8 makes the
  status quo safe; inventing the type would be guessing. Recommended as a ticket.
* **`Granter.RevokeAll`.** Proposed alongside the narrowed delete cascade. The
  narrowing already bounds the obligation to something a provider can meet, and
  a method with no caller is surface bought before it is needed. Reconsider when
  the teardown path is real (USOSS-15).
* **`BuildSource.Context fs.FS` and `Exclude`.** The unstated *obligation* was
  the real defect and it is stated now. The fields would be unused by any caller
  today, and a spec field every provider must honour is not free.
* **A retry invariant in the conformance suite.** `ErrTransient` makes it
  writable in principle, but "a provider returns ErrTransient for a retryable
  substrate failure" needs a substrate hook that induces one, which is
  provider-specific. The suite checks the taxonomy instead: no error may match
  both `ErrTransient` and a terminal sentinel. Recommend the hook to USOSS-16's
  owner.
* **Ownership refusal and behavioural grant checks still need provider hooks.**
  Inherent, not an oversight: "create a resource this platform does not own" and
  "read this resource as this identity" have no portable expression, and should
  not — the second is the application's job. Both are `Options` hooks and the
  suite skips loudly without them.
* **Splitting `Provider` per substrate.** A Kubernetes provider satisfying every
  port is four systems behind one name. Splitting would be a much larger change
  and the composition is genuinely useful; the consequence is documented on
  `Provider.Name` instead.
* **`Resources` requests/limits, `Labels` selectability, `Handler` semantics.**
  Documented concessions. Each would add a field for a caller that does not exist
  yet.
* **Log delivery, metrics, DNS registration, cost.** Unchanged from §5. Logs
  remain the one I would prioritise: "deploy an app and see its logs" is table
  stakes and the second provider will need an answer.

### 9.10 What the third review changed, and the shape it found

A third reviewer, on a model family distinct from the two that produced the
findings in §9, read the amendment and defeated three of its guarantees with
working fixtures. It confirmed the source ECR audit, the sentinel rename, the
scheduled-job reclassification and the rebase; it broke the parts that had been
*asserted* rather than *attacked*.

| Claim in the first amendment | What defeated it | Where the fix is |
| --- | --- | --- |
| "A fourth `Granter` is a red build" | An exported `ReviewOnlyPort interface { Granter }` outside the hand-maintained candidate map. The test passed. | §9.1 — the port set is derived from source with a toolchain cross-check |
| "No registry can authorise a pull by workload identity" | Kubernetes' kubelet credential provider carries a pod-bound ServiceAccount token | §9.1 — the conclusion holds, the justification is narrowed, and the ability is an optional capability |
| "The effective spec closed the convergence gap" | A wrapper reporting the new spec while the substrate kept the old one, with `Options.Rendered` unset | §9.5 — the claim is narrowed and the check reports unverified rather than passing |
| "The fake is the reference six providers are written against" | Mutating a returned `Spec.Labels` changed the next `Describe` | §9.5 — a portable aliasing invariant, which then found three more instances |
| `CapWorkloadGrants` | The suite ignored it entirely | §9.8 |

**Three of the five are one shape: a guarantee asserted, and tested by something
that does not test it.** Every one of them was green. That is the standing rule
about a check proving nothing until somebody tries to defeat it, arriving at the
conformance layer — the place whose entire job is to be that somebody.

The working practice that follows, and that this round used: **when a check is
added or changed, revert the fix and watch the named check fail before trusting
it.** Each fix in this section was verified that way, and the reverts are listed
in the pull request. It is the same discipline the fake's defect fixtures already
encode, applied to the checks themselves rather than only to the provider they
run against.

One more observation worth keeping. The aliasing invariant was written to close a
bug a reviewer found in one place, and immediately found three more — one in the
fake's relational port and two in the Kubernetes provider — that three rounds of
review had not. A portable invariant is worth more than a fix, because a fix
closes one instance and an invariant closes the class.

## 10. The capability matrix is generated, not written (USOSS-19, for USOSS-20)

Section 2 says a capability exists so that "a non-AWS provider's inability is a
fact the caller can discover and act on". That is a promise to a caller at run
time, and USOSS-20 needs the same answer published as documentation. The two must
not disagree, and a hand-written table is exactly the artifact that eventually
does.

So it is derived. [`docs/design/capability-matrix.md`](capability-matrix.md) is
generated by `compute/matrix` and compared byte for byte with the committed file
on every test run; a provider whose capabilities change turns the build red until
it is regenerated. The derivation restates nothing it could read instead: the
capability-gated accessors come out of `compute.Provider`'s reflected method set,
the capability population from `compute.AllCapabilities` (itself cross-checked
against its own const block by a `go/ast` scan), and each cell from what the
provider's accessor actually returned.

Two things about it are worth carrying into any future provider.

**The matrix reports a third answer besides "available" and "declined".** A
`stub` is a port whose accessor handed something back and whose every method
refuses — the failure mode this section's `(port, error)` design exists to
prevent, moved from acquisition to call time. Nothing in the type system forbids
it and a capability set can agree with the accessors while it is happening, so it
is detected by probing rather than assumed absent. Publishing a stub is a defect,
and the document's own test fails if one appears.

**`compute/aws` has no column, and its absence is the statement.** There is no
provider to derive one from yet. A column appears when there is, by naming the
provider in `compute/matrix/document_test.go` — at which point the test insists
the document be regenerated, so the matrix cannot quietly describe two providers
while three exist.
