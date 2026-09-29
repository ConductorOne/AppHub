<!--
Copyright 2026 ConductorOne, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Deploying AppHub on AWS

Terraform for one AppHub deployment: the control-plane API, the dedicated
Fargate worker, isolated build tasks, and the ingress that publishes what it
deploys -- Traefik with an oauth2-proxy ForwardAuth middleware in front of it.

**Status matches the repository's.** AppHub is pre-alpha and this is not a
supported upgrade path. Nothing here has been through the real-AWS,
external-identity-provider and adversarial container-isolation acceptance the
[root README](../README.md) says must pass before production use. In
particular no kaniko build has been run against a real account from here --
read [How a build is isolated](#how-a-build-is-isolated) before running
untrusted repositories through it.

## Contents

- [Shape](#shape)
- [Why the ingress looks like this](#why-the-ingress-looks-like-this)
- [Bringing one up](#bringing-one-up)
- [Make targets](#make-targets)
- [How a build is isolated](#how-a-build-is-isolated)
- [Secrets](#secrets)
- [Changing the configuration](#changing-the-configuration)
- [What this does not do](#what-this-does-not-do)

## Shape

```
                     internet
                        │
        ┌───────────────┴───────────────┐
        │                               │
   ALB :443 (ACM)                  apps load balancer
   apphub.<zone>                   *.apps.<zone>
        │                               │
   ┌────┴─────┐                    ┌────┴────┐
   │ apphub   │                    │ Traefik │──ForwardAuth──▶ oauth2-proxy
   │  serve   │                    └────┬────┘                 (Cloud Map)
   │ (Fargate)│                         │ ECS label discovery
   └────┬─────┘                    ┌────┴────────────────┐
        │                          │ deployed application│
        │                          │ tasks (Fargate)     │
        │                          └─────────────────────┘
        │                               ▲
   DynamoDB ◀───────────────────────────┤ creates
        ▲                          ┌────┴──────────────┐
        └──────────────────────────│ apphub worker     │
                                   │ (Fargate) + crane │
                                   └────┬──────────────┘
                                        │ RunTask, one per build
                                   ┌────┴──────────────────┐
                                   │ build task (Fargate)  │
                                   │ kaniko, no task role  │
                                   └────┬──────────────────┘
                                        │ EFS, one access point per slot
                                   ┌────┴──────────────────┐
                                   │ build share           │
                                   └───────────────────────┘
```

`ingress_tls_mode` chooses the apps load balancer:

| Mode | Load balancer | TLS | Traefik |
| --- | --- | --- | --- |
| `alb-wildcard` (default) | ALB | ACM certificate for `*.apps.<zone>` | HTTP only, two replicas. Union Station's shape. |
| `strict` | NLB, TCP passthrough | Traefik ACME per hostname | `websecure` + certresolver, one replica, ACME on EFS |

Modules, in dependency order. Each is small and the graph has no cycles, which
is what makes the configuration renderable at all -- see
[`modules/config`](modules/config).

| Module | What it owns |
| --- | --- |
| [`network`](modules/network) | VPC, public and private subnets, NAT, and **every long-lived security group** |
| [`cluster`](modules/cluster) | ECS cluster, Cloud Map namespace, task execution role, AppHub's two ECR repositories |
| [`state`](modules/state) | Separate control-plane state and chronological audit DynamoDB tables |
| [`ingress`](modules/ingress) | Apps load balancer, Traefik, oauth2-proxy, wildcard DNS. ALB+ACM wildcard or NLB+Traefik ACME, selected by `ingress_tls_mode` |
| [`deploy-target`](modules/deploy-target) | The IAM ceiling around everything AppHub creates, and the build's push role |
| [`config`](modules/config) | Renders `apphub.yaml` and `aws.yaml` into Parameter Store; optionally publishes the operator-supplied RDS CA PEM for the worker |
| [`control-plane`](modules/control-plane) | Portal ALB, ACM certificate, DNS, the `apphub serve` service |
| [`build`](modules/build) | The build share, one access point and task definition per slot, and the builder |
| [`worker`](modules/worker) | The `apphub worker` service |

Security groups live in `network` rather than beside the services that use
them because `config` has to name the ingress and control-plane groups in a
document the services then read. Putting each group next to its service would
make that a cycle.

## Why the ingress looks like this

The portal always has its own ALB and ACM certificate. One fixed hostname
known at apply time is the case ACM handles best, and keeping the portal off
the applications ingress means a Traefik rollout cannot take down the thing
you would use to fix it.

Published applications share a wildcard hostname `*.apps.<zone>`. Two ways to
put TLS in front of them, selected by `ingress_tls_mode`:

**`alb-wildcard` (default)** is Union Station's shape. An application load
balancer terminates TLS with an ACM certificate for `*.apps.<zone>` and
forwards HTTP to Traefik on port 80. Traefik has only the `web` entrypoint, no
ACME, no EFS, and two replicas. `container.tlsTermination` is `edge`:
`compute/aws/routes.go` still requires a resolvable certificate reference on
every public route (the control plane never sets `AllowPlaintext`) but puts
the router on `web` with no `tls.certresolver`, because Traefik is not the
TLS terminator.

**`strict`** is TCP passthrough. A network load balancer forwards 80 and 443
to Traefik, which issues a Let's Encrypt certificate per hostname over a
Route53 DNS-01 challenge. `tlsTermination` is `ingress`: routers land on
`websecure` with `tls.certresolver`. Consequences:

- **Traefik runs one replica.** Its ACME store is a single JSON file with no
  leader election; two replicas race into duplicate and then rate-limited
  issuance.
- **Use the ACME staging directory while bringing the ingress up.**
  `acme_ca_server` is a variable for exactly this. Production issuance limits
  are low enough that a handful of rebuilds exhausts them for a week.

Switching modes replaces the load balancer and requires redeploying every
published application so its Traefik labels match the new entrypoint.

These values have to agree across the ingress and rendered configuration. The
environment passes one value to both sides of each:

| Value | Ingress | AppHub configuration |
| --- | --- | --- |
| `certificate_resolver` | Traefik's ACME resolver name (strict) | `deployConfig.routeCertificate`, and what the placement's `certificates` map resolves it to |
| `ingress_auth_middleware` | the oauth2-proxy ForwardAuth middleware's name | `container.ingressAuthMiddleware` |
| `ingress_cookie_strip_middleware` | the first-party plugin middleware's name | `container.ingressCookieStripMiddleware`; last on every application router |
| `mcp_auth_backend_url` | the API's `apphub-api.<namespace>:8080` Cloud Map address | `container.mcpAuthBackendUrl` |
| `ingress_tls_mode` | ALB+wildcard or NLB+ACME | `container.tlsTermination` (`edge` or `ingress`) |
| `apps_subdomain` | the wildcard DNS record and cookie domain | `deployConfig.routeDomain` |

A mismatch is a route that fails to load, or that sits on an entrypoint nothing
reaches. Both sides fail closed rather than serving without the authentication
or certificate the caller asked for. The control plane registers `apphub-api`
in Cloud Map so Traefik can fetch app-specific MCP metadata and call
`/authz/app-mcp` without leaving the VPC. That ForwardAuth path is distinct
from oauth2-proxy: it validates the application's OAuth audience and
`app:access` scope, returns verified identity headers, and the per-application
middleware removes the bearer token before forwarding `/mcp`. Other paths on a
public application stay behind oauth2-proxy.

Traefik checks the shared oauth2-proxy session cookie with ForwardAuth, then
the first-party cookie-strip plugin removes that cookie (including split
sessions and CSRF cookies) before forwarding to any application. Other
application cookies survive. A stock Traefik image cannot provide this
middleware and must not be substituted. Application routers also discard
incoming identity headers before their authentication middleware sets verified
values; unauthenticated routes never pass client-supplied identity headers.

## Bringing one up

You need: an AWS account, a Route53 public hosted zone, an S3 bucket for
Terraform state, an OAuth client from your identity provider, Docker for
building images, and an ECR repository for the first-party Traefik image.

```sh
cp -r terraform/environments/example terraform/environments/prod
cd terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars backend.tf
cd ../../..  # back to the AppHub repository root for Docker builds
```

`terraform.tfvars` and `backend.tf` are the two files that name your account
and domain. `terraform.tfvars` is gitignored.

Before `make tf-up`, build and push the ingress image from this repository
to an ECR repository readable by the ECS execution role in the deployment
account (create that repository separately). Pin its pushed digest, not a
mutable tag, in `terraform.tfvars` as `traefik_image`. This image contains
`terraform/plugins/cookiestrip`, built into the pinned Traefik base:

```sh
INGRESS_REPO="<account>.dkr.ecr.<region>.amazonaws.com/apphub-traefik"
aws ecr create-repository --repository-name apphub-traefik --region "<region>"
aws ecr get-login-password --region "<region>" | \
  docker login --username AWS --password-stdin "<account>.dkr.ecr.<region>.amazonaws.com"
docker build --platform linux/amd64 -f terraform/plugins/cookiestrip/Dockerfile.traefik -t "$INGRESS_REPO:initial" .
docker push "$INGRESS_REPO:initial"
aws ecr describe-images --repository-name apphub-traefik --region "<region>" \
  --image-ids imageTag=initial --query 'imageDetails[0].imageDigest' --output text
# terraform.tfvars: traefik_image = "<account>.dkr.ecr.<region>.amazonaws.com/apphub-traefik@sha256:<digest>"
```

Use the same AWS region as
`aws_region`. Do not deploy until the digest has been published; an absent or
misconfigured plugin makes application routers unavailable, not unfiltered.
For upgrades, publish a new image digest, apply `traefik_image`, and roll
Traefik with `make promote-ingress`.

**Aurora prerequisite (enabled in the example).** DynamoDB remains the
control-plane store and the key-value application option. The example also
enables the existing Aurora Serverless v2 relational port for application
PostgreSQL 18; Terraform does not pre-create an application database. The
worker creates an encrypted Aurora cluster, writer instance, DB subnet group
and scoped security group when an application requests a relational database.
To make TLS `verify-full` work for deploy-time PostgreSQL extensions,
download the official RDS *regional* trust bundle for `aws_region` from
[AWS RDS trust store](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
and set `rds_ca_pem_file` to its absolute local path in `terraform.tfvars`:

```sh
AWS_REGION=us-west-2 # use the same region as aws_region
mkdir -p "$HOME/.config/apphub"
curl --fail --location --output "$HOME/.config/apphub/rds-$AWS_REGION-bundle.pem" \
  "https://truststore.pki.rds.amazonaws.com/$AWS_REGION/$AWS_REGION-bundle.pem"
# terraform.tfvars: rds_ca_pem_file = "/home/<operator>/.config/apphub/rds-us-west-2-bundle.pem"
```

Keep the PEM outside version control. Terraform refuses an empty or missing
file when `enable_relational_port = true` (the example default), publishes its
contents as a Parameter Store String, and the worker's init container copies
it into its read-only `/config/rds-ca.pem` mount. The rendered
`targets.<id>.deployConfig.postgresRootCertPath` names that mounted file. Use
the regional bundle rather than the much larger global bundle: Parameter
Store values have an 8 KiB maximum, and Terraform rejects a larger file at
plan time. Renew a rotated CA bundle with
`make tf-apply TF_ENV=prod` and `make promote-worker TF_ENV=prod`; a running
task does not reread the parameter. Set `enable_relational_port = false` to
disable Aurora and omit the CA file entirely; DynamoDB remains enabled.

Extensions are optional per PostgreSQL application, not installed globally.
The allowlist is `vector`, `pg_trgm`, `pgcrypto`, `fuzzystrmatch`, `unaccent`,
`citext`, `hstore`, `btree_gin`, `btree_gist`, and `uuid-ossp`; preload-dependent
extensions are excluded. The worker uses the database admin account to
install these after readiness, over a hostname-verified TLS connection. A
missing/wrong CA or unsupported extension fails deployment rather than
silently skipping setup. Aurora is a separately billed database: clusters,
writer capacity (ACUs), storage and I/O can accrue charges while idle and
per application. Review scaling/capacity and deletion/backup obligations
before enabling requests, and budget for NAT/network and database charges.

Set `relational_max_capacity_units` for the maximum capacity an application
may request; the default is 2 abstract units (4 ACU with the example's 2:1
conversion). Terraform renders the same ceiling into the API target policy and
the worker's AWS relational configuration, so a direct provider caller cannot
bypass the application admission check. Raising it permits a larger bill per
application; set a deliberate budget before increasing it.

**1. Deploy.** `make tf-up` creates the cluster and its ECR repositories, builds
and pushes the API, worker, and builder images, applies the rest, then
**promotes** onto ECS (`make promote`). The API and worker run each
repository's `:latest` tag. The builder is digest-pinned (the runner refuses a
tag): the first apply reads `builder_image.auto.tfvars`, and later pins are
new task-definition revisions from `make promote-builder`, not a terraform
apply.

You are not asked for `server_image`, `worker_image`, `builder_image`, or
`source_repositories`. After the stack is up, register the GitHub App in the
Workspace UI; installations of that App are the deploy allowlist.
`source_repositories` remains an optional extra restrictor of exact URLs.

The first bring-up is `make tf-up`, not `make tf-apply`. Apply alone has no
builder digest yet, and ECS refuses to register a build task definition with
an empty image. If a partial apply already created ECR, `make push-builder`
writes `builder_image.auto.tfvars` and a following `make tf-apply` can finish.

The builder is this repository's `builder.Dockerfile`: a pin of
`ghcr.io/osscontainertools/kaniko` (supported Kaniko OSS), not the archived
`gcr.io/kaniko-project/executor` image. osscontainertools does not support
copying the executor into another base, so the file is a pin, not a wrapper.

```sh
make tf-init  TF_ENV=prod TF_BACKEND_ARGS='-backend-config=bucket=... -backend-config=key=apphub/prod/terraform.tfstate -backend-config=region=us-west-2'
make tf-up    TF_ENV=prod
```

A later image change is push then promote, with no terraform apply:

```sh
make push  TF_ENV=prod
make promote  TF_ENV=prod
```

`make promote` registers digest-pinned build-task revisions, force-deploys the
API and worker together, and waits until both are stable. A configuration or
infra change is still `make tf-apply`, then `make promote` if the processes
need to restart.

**2. Register the redirect URIs and set the secrets.**

```sh
make tf-output TF_ENV=prod     # register_with_identity_provider, secrets_to_set
```

Register every URI under `register_with_identity_provider` with the matching
OAuth client -- one per portal provider, plus oauth2-proxy's callback on the
`auth` label of the applications domain. Then set each parameter listed
under `secrets_to_set`; see [Secrets](#secrets).

**3. Confirm the worker validated its build tasks.**

```sh
make tf-logs-worker TF_ENV=prod
```

The worker validates every build task definition and runs a real validation
build before it claims any work, so a worker that reached steady state has
already proved the arrangement works. One that refuses to start says which
property failed.

**4. Become an administrator.** Nobody is one on a fresh deployment, by
design: email is never an administrator identifier. Sign in at the portal, copy
the Subject shown at `/settings/sessions`, add it to `auth_admins` in
`terraform.tfvars`, and apply again.

```sh
make tf-apply TF_ENV=prod && make promote-api TF_ENV=prod
```

## Make targets

`TF_ENV` selects the environment directory and defaults to `example`.

| Target | Effect |
| --- | --- |
| `make tf-init` | `terraform init`; pass `TF_BACKEND_ARGS` to configure the backend on the command line |
| `make tf-plan` | Plan changes; does not apply |
| `make tf-apply` | Apply this environment (Terraform plans interactively; no saved plan file) |
| `make tf-up` | Create ECR, build and push images, apply infra, `make promote` onto ECS |
| `make tf-output` | Portal URL, redirect URIs to register, secrets still to set |
| `make tf-destroy` | Destroy. Both control-plane state and audit tables are `prevent_destroy` and survive |
| `make tf-fmt` / `make tf-fmt-check` | Format, or fail on unformatted files |
| `make tf-validate` | Validate the configuration |
| `make tf-check` | `tf-fmt-check` and `tf-validate`: everything that needs no credentials |
| `make ecr-login` | Log the local Docker client into this environment's ECR registry |
| `make push-server` / `push-worker` / `push-builder` / `push` | Build and push from `Dockerfile` / `worker.Dockerfile` / `builder.Dockerfile` to ECR |
| `make promote` | Promote builder revisions, then roll API and worker together; waits until both are stable |
| `make promote-services` | Roll API and worker together onto `:latest`; waits until both are stable |
| `make promote-api` / `promote-worker` / `promote-builder` / `promote-ingress` | Promote one of those independently. `promote-ingress` restarts Traefik and oauth2-proxy so they re-read Parameter Store |
| `make release` | Build and push both images, then roll API and worker together. Does not apply Terraform |
| `make release-api` / `release-worker` | Build, push, and roll that service. Does not apply Terraform |
| `make release` | Build and push the API and worker, then roll both. Does not apply Terraform or touch the builder |
| `make tf-logs-api` / `tf-logs-worker` / `tf-logs-build` / `tf-logs-ingress` | `aws logs tail --follow` |

None of these run in CI and none should. A `terraform apply` is a change to a
real account, and the gate on it is a person. `make hermetic` asserts that
everything CI *does* run needs no cloud credentials.

## How a build is isolated

Every build runs as its own ECS task, launched by the worker through the ECS
API. The task runs kaniko and nothing else.

**The property everything rests on: the build task carries no task role.** On
Fargate every container in a task shares one network namespace, so the task
credentials endpoint is reachable from the container executing the Dockerfile —
a role attached for *any* container's benefit is a credential a `RUN` line can
read. There is no sidecar arrangement that survives it, which is why the build
task has no role and why the build context and the finished image cross on a
filesystem rather than through a signed URL. See
[`docs/decisions/`](../docs/decisions/) for the long version.

| Property | How it is established | Who enforces it |
| --- | --- | --- |
| No credential of any kind | `aws_ecs_task_definition.build` sets no `task_role_arn` | AWS, and the runner refuses a definition with one |
| Nothing in the VPC is reachable except its own share | The baseline build security group has no ingress or VPC egress; each task adds only its slot's NFS security group | AWS security groups |
| No public address | `assign_public_ip` is `DISABLED` and not configurable | AWS |
| No instance metadata | Fargate exposes none | AWS |
| Builds cannot see each other | One filesystem and access point per slot, with a distinct mount-target security group reachable only by that slot's task | AWS EFS, VPC security groups, and runner validation |
| A pinned builder | First apply pins a digest; `make promote-builder` registers later revisions | Terraform create, then the runner on every worker start |
| Bounded scratch space | `ephemeral_storage_gib` on the task | AWS |
| Bounded context | 512 MiB, refused by the runner before anything launches | AppHub |

Everything in the right-hand column is a fact AWS reports about a resource. That
is the difference from the arrangement this replaced: a dedicated EC2 host whose
egress policy was three Docker network labels, made true by `iptables` rules in
a bootstrap script that the code could only take on trust.

`BuildTaskRunner.Validate` re-checks the no-role, slot-filesystem isolation,
and pinned-image rows against the live task definitions on **every worker
start**, then runs a real one-layer build end to end — proving that the volume
mounted, the slot is writable, and worker and task see the same filesystem.
A worker whose build tasks have drifted refuses to start rather than failing
on somebody's first deployment. There is no flag to skip it.

After a build stops, the worker opens `out` through a root confined to its
leased slot, refuses symlinked output directories or files, and copies only
bounded regular `image.tar` and digest outputs into its private directory.
Invalid output aborts the push; a build cannot make a symlink to another slot's
image or worker-readable files become the image being published.

### Deployment worker IAM ceiling

The worker may create workload and execution roles only with the workload
permissions boundary, under non-root IAM paths. Terraform-managed roles,
including the ECR push role, live at the root instead. The deploy policy also
explicitly denies all IAM actions on the push role's ARN, even if someone
configures a broader workload name prefix. The push role has its own ECR-only
permissions boundary: its inline policy and a build's session policy narrow
access, but neither would cap an additional policy attached to the role.

Reserve the workload and execution IAM paths for boundary-capped AppHub roles.
The worker's name/path grants cannot prove who created a pre-existing role in
those paths; do not put an unbounded operator-managed role there. IAM ownership
tags alone are not a substitute: a worker allowed to tag roles could also
forge the tag on a colliding role.

The deployment policy now uses application-only ECS service and task-definition
names, separate from Terraform's API, worker, Traefik and oauth2-proxy names.
It explicitly denies mutations of those control-plane services and task
definitions and the control-plane/audit DynamoDB tables. It grants no
deployment-target `StopTask` or `ExecuteCommand` on opaque task IDs. Optional
S3 grants require a nonempty application bucket prefix; Lambda endpoint ELBv2
mutations require their own load-balancer/target-group/listener prefix.
Security-group tags may be created only as part of resource creation, or
changed on a group already carrying the ownership tag. The worker's separate
build-task IAM permission is constrained to tasks marked at launch; inspect
both attached policy sets, not just the deploy-target policy.

Before applying this policy to an existing account, check for names outside
the new application prefixes: previously created services, tables or
endpoints may need an operator-led migration rather than a silent loss of
management authority. Use `aws iam simulate-principal-policy` on the actual
worker role to confirm control-plane ECS and DynamoDB mutations are denied,
unrelated S3 buckets and ELBv2 load balancers are denied, and
`ec2:CreateTags` cannot adopt an untagged Terraform-owned security group.
Check the positive application resources too. IAM simulations and live
deployments require AWS credentials and cannot be replaced by Terraform
`validate`.

On installations predating the push-role boundary, applying it replaces the
push role because its IAM path changes; schedule an interruption to image
pushes. Verify the worker's effective policy with
`aws iam simulate-principal-policy` for
`iam:PutRolePolicy`, `iam:AttachRolePolicy`, and
`iam:UpdateAssumeRolePolicy` against the push role ARN: all three must return
`explicitDeny`. For the push role, simulate an IAM mutation and access outside
the application ECR repository prefix; the boundary must deny both. Test a
broader attached policy only in a disposable account, never on a live push
role. Remove any unexpected attached policies and revoke existing push-role
sessions if the role may already have been compromised; a newly applied
boundary does not invalidate previously issued sessions immediately.

### Slots

A volume is declared on a task definition, not on a `RunTask` override, so the
filesystem and access point that confine a build cannot be chosen per call.
Concurrency is therefore a provisioned set: `build_slots` task definitions,
`build_slots` separate EFS filesystems, and one mount-target security group per
slot. The worker mounts each filesystem under its slot index and grants a
build task only the matching slot security group. Keep
`worker_max_concurrent_deployments` at or below `build_slots`, or builds wait
for a free slot — a delay, never a failure.

A slot is held until ECS reports its task `STOPPED`, including after a failed
build. An expired lease is quarantined rather than reassigned: ECS listings
are eventually consistent, so an empty list alone is not proof the previous
task cannot resume. To recover a slot, verify the old task and all tasks in
its task-definition family are `STOPPED` in ECS, investigate any failed stop,
then explicitly clear only that slot's lease record in the control-plane
repository. Never delete a lease solely because its timestamp expired.
On an existing installation, drain all builds before applying the per-slot
filesystem change; the shared EFS volume is replaced and active build data
is not migrated.

## Secrets

Terraform generates what is genuinely its to generate and refuses to hold the
rest.

**Generated, and therefore in state:** the session transaction key (exactly 32
raw bytes, stored base64), the GitHub webhook HMAC secret (standard base64 of
32 raw bytes; paste that string into the GitHub App), and the oauth2-proxy
cookie secret. State must be an encrypted, versioned bucket readable only by
people who may operate this deployment. `terraform output github_webhook`
names the parameter and the webhook URL; it does not print the secret.

**Created empty, set out of band:** every OAuth client secret, the optional
ConductorOne directory client secret, and every GitHub App private key.
Terraform creates the parameter with a placeholder and `ignore_changes` on
its value, so it never reads or rewrites one.

```sh
aws ssm put-parameter --overwrite --type SecureString \
  --name /apphub/prod/auth/google/client-secret --value "$SECRET"
```

`terraform output secrets_to_set` lists every one. A parameter still holding
its placeholder is a sign-in that fails at the token exchange -- not one that
succeeds without a secret.

**Injected as environment variables, not files.** The API and worker task
definitions' `secrets` blocks name Parameter Store ARNs. ECS (the execution
role) writes each value into the process environment at start: client ids,
client secrets, the base64 transaction key, the GitHub webhook secret, GitHub
App ids and PEMs, and the optional ConductorOne directory credential. The
YAML documents name those environment variables (`clientIdEnv`,
`clientSecretEnv`, `transactionKeyEnv`, `webhookSecretEnv`, …) and never
hold the values. The webhook secret is injected into the API container only.

The two YAML documents themselves still arrive as files, because they can
exceed the environment-variable size budget; the init container fetches these
and, when relational is enabled, the public RDS CA PEM. The worker mounts this
configuration volume read-only; the CA PEM is not a credential.

**Never held by the API.** The admin-managed GitHub App key lives at a path
`cmd/apphub` derives from the table name and offers no way to configure. The
API's role has `ssm:PutParameter` and `ssm:DescribeParameters` on it and an
explicit `Deny` on every read; the worker's role has the read. That mirrors
`internal/ghappkey`, which hands `serve` a write-only type and `worker` the
reader, and it is defense in depth for the repository's rule that the API never
holds source credentials. Repository-scoped GitHub App PEMs are injected only
into the worker task.

## Audit storage

`modules/state` creates a separate `${table_name}-audit` DynamoDB table,
rendered as `store.auditTableName` in the shared API/worker configuration.
The table uses string `PK`/`SK` keys for reverse-chronological queries, with no
secondary index. Audit items set `expiresAt` to 400 days after occurrence;
DynamoDB TTL deletion is asynchronous, so this is eligibility for removal,
not a guaranteed deletion date. Point-in-time recovery, encryption at rest,
and deletion protection follow the control-plane table's settings.

The API role may append and query events; the worker may append but not query.
Neither deployed workloads nor the worker's application-table management grant
may alter the audit table schema or remove the table.

## Changing the configuration

`modules/config` renders **one** YAML document that both `serve` and `worker`
read. That is deliberate: AppHub blocks submission when the two processes
disagree about a target descriptor, and two hand-maintained documents drift.
`internal/serverconfig` validates the serve-only fields only in serve mode and
the worker-only fields only in worker mode, so one document satisfies both.

A configuration change is a `terraform apply` followed by a restart of whichever
process needs it:

```sh
make tf-apply TF_ENV=prod
make promote-api      TF_ENV=prod   # the init container refetches YAML; ECS re-injects secrets
make promote-worker   TF_ENV=prod   # the init container refetches YAML; ECS re-injects secrets
make promote-ingress  TF_ENV=prod   # oauth2-proxy re-reads its client id and secret
```

To read back exactly what a process will load, rather than what you think you
configured:

```sh
make tf-output TF_ENV=prod            # config_parameters names both documents
aws ssm get-parameter --name /apphub/prod/config/apphub.yaml \
  --query Parameter.Value --output text
```

## What this does not do

- **Build or promote images during `terraform apply`.** Terraform creates the ECR
  repositories and runs `:latest` for the API and worker unless you pin a
  digest. The builder's first digest is `builder_image.auto.tfvars`; later pins
  are `make promote-builder`. `make push` builds and pushes; `make promote`
  rolls ECS. Nothing in this directory does either inside an apply.
- **Autoscale.** Neither the API nor the worker scales, and build concurrency is
  a provisioned set of slots rather than something that grows with demand. Add
  `aws_appautoscaling_target` for the API when you have a load shape to size
  against; raising build concurrency is raising `build_slots`.
- **Cache image layers.** kaniko's cache is a registry repository and reading or
  writing it needs a credential the build deliberately does not have. A build is
  slower and correct; see `docs/decisions/` on USOSS-41 for what would restore
  it.
- **Run more than one worker.** It is safe — the control plane claims each
  deployment in a fenced transaction, and each build slot is leased through the
  control-plane store, so no two builds share a slot's directory — but every
  worker draws on the same fixed set of build slots, so raising
  `worker_desired_count` without raising `build_slots` only moves the queue. To
  run more deploys at once, raising `build_slots` and
  `worker.maxConcurrentDeployments` on one worker is usually enough. A lost worker is a case AppHub models explicitly: the attempt
  becomes `interrupted`, keeps its execution lock, and never reruns until an
  administrator resolves it with `apphub deployments resolve-interrupted`.
- **Create anything per application.** Repositories, task roles, security
  groups, log groups, tables and buckets are created by AppHub at deploy time
  under the prefixes `deploy-target` scopes its IAM against. A Terraform
  resource with the same name would race it.
- **Span regions.** One region per deployment. A second region is a second
  target with its own provider configuration, which is what
  `compute.Placement` is for.
