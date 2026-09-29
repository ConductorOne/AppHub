<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/src/assets/logo-wordmark-dark.png">
    <img src="frontend/src/assets/logo-wordmark-light.png" alt="AppHub" height="64">
  </picture>
</h1>

AppHub is a pre-alpha toolkit for describing application infrastructure once
and realizing it through explicit provider interfaces. It is aimed at teams that
need deploy, review, fix, compute, and credential-vending primitives without
hard-wiring those primitives to one vendor.

**Status: pre-alpha.** The authenticated deployment control plane includes a
React portal, HTTP API, durable worker, CLI, and MCP adapters. There is no release
or supported upgrade path. Hermetic verification is not production validation:
real AWS, external identity-provider, and adversarial container-isolation
acceptance must pass in an operator-approved environment before production use.

## What you need

- Go, at the toolchain version pinned in [`go.mod`](go.mod).
- `make`, if you want the repository checks described in
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- An AWS account and operator-supplied AWS configuration for the production
  compute provider. The provider has no compiled-in account, region, role,
  network, registry, or repository defaults.
- DynamoDB for the v1 control-plane persistence implementation in [`store/`](store/).
  The AWS deployment's optional application database choice also offers Aurora
  PostgreSQL 18; this does not replace the DynamoDB control-plane tables.
- ConductorOne only if you choose the optional
  [`credentials/c1`](credentials/c1) credential provider. Library packages do not
  depend on ConductorOne. The executable imports `credentials/c1` for its explicit
  `providers` command; build a composition root without that import if your
  distribution must omit the package entirely.

## Quickstart

```sh
git clone https://github.com/conductorone/apphub.git
cd apphub
go run ./cmd/apphub --help
```

With no configuration, the command prints usage and exits. `apphub providers`
retains the credential-provider inventory command. `serve` and `worker` require
explicit operator configuration and fail closed rather than falling back to
test compute, anonymous authentication, or an unisolated build executor.

To use ConductorOne-backed credential vending, configure the environment variables
documented by [`credentials/c1`](credentials/c1) and run `apphub providers`. A
partial ConductorOne configuration is a startup error rather than a fallback to "off".

## Local development

Use the Go toolchain pinned in `go.mod` and Node 24. The API and credential-bearing
worker are separate processes. Docker is required for local infrastructure and
for the real isolated worker, not for the hermetic browser fixture below.

Install Docker with the Compose v2 plugin, then:

```sh
make infra-up       # start DynamoDB Local, the admin UI, and separate state/audit tables
make config-init    # write a gitignored loopback serve skeleton under .local/
make dynamo-seed    # insert active, pending, and revoked non-secret examples
make dynamo-scan    # inspect every item as JSON
make providers      # inspect credential providers without starting a service
```

`make config-init` creates `.local/server.yaml`, a 32-byte transaction key, a
placeholder OAuth client secret, and a parse-valid AWS stub so `serve` can start.
Replace the Google client id and `.local/client.secret` before signing in. The
AWS stub is not a real account and cannot deploy.

`make config-init` preserves an existing `.local/server.yaml`. Existing local
configurations derive the audit table name as `<tableName>-audit`; run
`make dynamo-init` before restarting `serve` or `worker`. Set
`store.auditTableName` explicitly when the audit table uses another name.

No one is an admin on a fresh checkout: `server.yaml` ships one placeholder
`auth.admins` entry that cannot match a real identity. Sign in once as
`developer@example.invalid`, copy the "Subject" value shown at
`/settings/sessions`, replace the placeholder subject in `.local/server.yaml`
with it, and restart `serve` to gain `role: admin` and see `/workspace`.
When `APPHUB_C1_DIRECTORY_*` is configured, an administrator can instead map a
synced directory group to a role from `/workspace`'s Role assignment tab,
granting it to every member holding that group without editing `server.yaml`.
Mapping a group to `vuln-admin` there grants cross-application vulnerability
finding visibility without the broader `admin` role.

`/vulnerabilities` and every application's Vulnerabilities tab are hidden
until an administrator turns on the `vulnerabilities` feature flag from
`/workspace`'s Feature flags tab (off, on for everyone, or limited to a
synced directory group) -- "off" hides it from every identity, administrators
included.

Workspace administrators can also independently enable `C1 application creation`
and `ShortLink creation` under Feature flags. Both are off by default, apply to
subsequent successful deployments, and require the worker's
`APPHUB_C1_DIRECTORY_*` OAuth configuration (see
[`credentials/c1directory`](credentials/c1directory)). When enabled, the worker
reconciles an application with Access and Admin entitlements in ConductorOne.
These catalog entries do not change the deployed service's authorization policy.
The separate ShortLink option uses the AppHub application name as its alias
and the deployed route URL as its destination. The name must already be a valid
lowercase ShortLink route without spaces; it is not silently renamed. ShortLink
creation is Private Beta and requires a published HTTPS route (scheduled jobs
without a URL cannot create one).

If C1 provisioning fails, the deployment reports that partial failure so
operators can correct the integration and redeploy; no external write occurs
when both settings are off.

Deleting a deployed AppHub application also removes its AppHub-owned C1
application, if one exists, before removing the AppHub records. This cleanup
runs even if C1 application creation was turned off after deployment. If C1
rejects deletion, the AppHub teardown stays failed and locked for retry; keep
the worker's directory credentials configured until deletion completes.

`make dev APPHUB_CONFIG=/absolute/path/to/.local/server.yaml` runs the API and Vite together.
Start infrastructure and the worker separately. Vite listens on
`http://127.0.0.1:5173` and proxies reserved API paths to `127.0.0.1:8081`;
override `APPHUB_API_TARGET` if the API uses another address. `/authorize` remains
a portal route, not an `/auth` proxy prefix match.

| Target | Effect |
| --- | --- |
| `make config-init` | Write a gitignored loopback serve skeleton under `.local/`. |
| `make infra-up` / `make infra-down` | Start or stop DynamoDB Local and its admin UI while preserving data. |
| `make infra-reset` | Delete the local DynamoDB data directory, then recreate the state and audit tables. |
| `make dynamo-reset` | Recreate the AppHub state and audit tables. Destructive: removes audit history. |
| `make dynamo-seed` | Idempotently insert non-secret lifecycle examples. |
| `make demo-seed` / `make demo-remove` | Add or delete 14 demo users and 47 applications that look deployed, for screenshots. Needs `APPHUB_CONFIG` and, to seed, `DEMO_OWNER_EMAIL`. |
| `make dynamo-scan` / `make dynamo-tables` | Inspect the table contents or list local tables as JSON. |
| `make run` / `make serve` | Run the HTTP API using `APPHUB_CONFIG`. |
| `make worker` | Run the deployment dispatcher using `APPHUB_WORKER_CONFIG`. |
| `make frontend` | Run Vite; install dependencies with `npm --prefix frontend ci`. |
| `make providers` | Report configured credential providers. |

The first local DynamoDB command generates random signing values in
`.env.local`, permissioned `0600` and ignored by Git. DynamoDB Local accepts
the values but they are not AWS credentials. The targets always set
`AWS_ENDPOINT_URL` to the local endpoint after sourcing that file, so a
leftover cloud profile or another DynamoDB Local on port 8000 cannot steal
the request. DynamoDB Local listens on `127.0.0.1:18000` so it can run beside
another instance on the default 8000 port; the admin UI is at
`http://127.0.0.1:18001`. Table data is stored in `.dynamodb/`, which is
ignored by Git. Override `DYNAMODB_ENDPOINT`, `DYNAMODB_REGION`, or
`DYNAMODB_TABLE` when connecting to another compatible local endpoint.

Workspace administrators can inspect recent mutations in the Audit log tab. Entries
are read from a separate DynamoDB table rather than the application state table;
the API does not expose this history to non-admins. Records carry safe
actor/action/target metadata and allowlisted deployment state, role and flag mode,
not request bodies, credential values, or application secret payloads. Audited
domain changes and their entry share one DynamoDB transaction;
an unavailable audit table prevents those changes. Successful GitHub App
private-key changes are recorded separately after the SSM write, so an interruption
between SSM and DynamoDB can leave an unaudited key change. Worker cloud effects
are represented by durable deployment checkpoints, not an independent cloud event
stream. Ephemeral login challenges, membership-cache refreshes and unchanged worker
heartbeats are excluded. The directory group sync records one `directory.sync`
entry per successful run, with group, written and removed counts, instead of one
entry per group; a recent entry shows the worker's sync loop is running. DynamoDB TTL makes entries eligible for removal after
400 days, but deletion is asynchronous, not an exact retention boundary.

## Authenticated deployment control plane

The external contract is [`api/openapi.yaml`](api/openapi.yaml). The Go SDK and
portal types are generated from it, not independently maintained wire models.
`internal/controlplane` owns authorization, revisions, idempotency, application
ownership, and deployment admission; neither HTTP nor MCP executes cloud work.

### Operator configuration

`apphub serve --config /absolute/path/server.yaml` and
`apphub worker --config /absolute/path/worker.yaml` read strict YAML. Unknown
fields, partial configuration, and invalid target policy fail startup. Relative
file paths resolve relative to the configuration file. The schema is
[`internal/serverconfig/config.go`](internal/serverconfig/config.go).

| Section | Required policy and separation |
| --- | --- |
| `publicOrigin` | Canonical HTTPS origin with lowercase host and no default port, path, query, or fragment. Used consistently for cookies, CSRF, OIDC callbacks, OAuth issuer, and resource audiences. |
| `listenAddress`, `staticDir` | API bind address and built `frontend/dist` directory. Terminate public TLS at an operator-managed ingress; do not trust forwarded headers to select the issuer. |
| `store` | Explicit `region`, `tableName`, and optional `auditTableName` (defaults to `<tableName>-audit`) and local `endpoint`. Keep audit records in a separate table; initialize both tables before starting the API or worker. Never reset shared tables or production audit history. |
| `auth.providers[]` | Unique `id`, `label`, `kind: google\|oidc`, and exact `allowedEmails` or `allowedDomains`. Client id is `clientId` or `clientIdEnv` (the name of an environment variable ECS injects from Parameter Store). Generic OIDC requires `issuer`; Google uses its fixed issuer. Register exactly `{publicOrigin}/auth/{id}/callback`. |
| API-only secrets | Each provider's `clientSecretFile` or `clientSecretEnv`; `auth.transactionKeyFile` (exactly 32 raw bytes) or `auth.transactionKeyEnv` (base64 of those 32 bytes). File mounts and env injection are mutually exclusive. Env injection is how ECS delivers Parameter Store values; mount files only into the API. |
| `auth.admins[]` | Explicit `{providerId, subject}` pairs. Email is never an administrator identifier or an identity-merging key. |
| `auth.clients[]` | Optional public OAuth clients with `id` and exact HTTPS `redirectUris`; native `apphub-cli` is pre-registered. General remote MCP clients may use validated client metadata documents (CIMD), whose `redirect_uris` may be exact HTTPS redirects or `http://localhost`/`127.0.0.1`/`[::1]` loopback redirects (RFC 8252 §7.3/§8.3); an authorize call matches a registered loopback redirect on scheme, hostname, path, and query while supplying its own explicit ephemeral port. |
| `targets.<id>` | `label`, `awsConfigFile`, `deployConfig`, and `policy`. The API and worker must share the same nonsecret target configuration; descriptor mismatch or stale worker readiness prevents submission. |
| `deployConfig` | Explicit resource prefix, placement name, source hosts, wait timeout, and `workloadIdentityMode: native`. Public exposure additionally requires the operator's route suffix and certificate. When deploying PostgreSQL extensions, `postgresRootCertPath` points to a trusted RDS CA PEM readable by the worker for TLS `verify-full`. |
| `policy` | Approved CPU/memory pairs, maximum replicas, enabled `service`/`scheduled` modes, whether public exposure is permitted, and `maxRelationalCapacityUnits`. The relational ceiling defaults to 2 abstract capacity units when omitted; configure the same bound in the worker's AWS relational provider. Both the API and worker reject requests above their respective bounds before database mutations. |
| `source.repositories[]` | Exact approved HTTPS `url` and `auth: public\|githubApp`. Private repositories require repository-scoped GitHub App `appId`/`appIdEnv`, `installationId`/`installationIdEnv`, and worker-only `privateKeyFile`/`privateKeyEnv`; only `contents:read` installation access is requested. |
| `worker` | Private absolute `workDir`, concurrency, deployment timeout, heartbeat interval, and stale threshold. These are worker-only runtime inputs. Build isolation is not here: a build runs in a task the compute provider launches, so it is configured under the provider's own `build.task`. |

The provider-owned AWS file is decoded by
[`compute/aws/LoadConfig`](compute/aws/load.go) without acquiring credentials.
Supply actual approved region, ECS cluster/VPC/subnets/security groups, registry,
IAM paths/boundaries, and build/push configuration. There are no sample account
IDs to substitute blindly and no topology derived from the environment.
Production construction remains in `compute/aws.NewFromConfig`; the API reads
policy but never constructs the credential-bearing compute provider.
Give the API only its persistence permissions. Give the dedicated worker scoped
compute/persistence/source/push permissions, never upstream login secrets.

The [Terraform example](terraform/README.md#bringing-one-up) enables both
DynamoDB and the existing Aurora Serverless v2 application option by default.
Supply an AWS regional RDS CA PEM with `rds_ca_pem_file` before applying;
Terraform publishes it to Parameter Store and mounts it at
`/config/rds-ca.pem` for the worker. You can disable Aurora with
`enable_relational_port = false`. PostgreSQL applications may request allowed
extensions (`vector`, `pg_trgm`, `pgcrypto`, `fuzzystrmatch`, `unaccent`, `citext`,
`hstore`, `btree_gin`, `btree_gist`, `uuid-ossp`); preload-dependent extensions are not
supported. The worker installs them with the admin account over verified TLS.
Aurora clusters and writer capacity incur additional charges and require
operator review of capacity, backups, deletion, and RDS CA rotation.

For local browser development only, set `publicOrigin` to
`http://127.0.0.1:5173`, `listenAddress` to `127.0.0.1:8081`, and
`auth.allowLoopbackHTTP: true`. The explicit loopback exception is not a
production HTTP mode. Do not commit secrets or environment-specific deployment
identifiers in configuration.

`make serve` sources `.env.local` when present. IDs and secrets may live there
instead of in YAML or side files: name the variable in configuration
(`clientIdEnv`, `clientSecretEnv`, `transactionKeyEnv`, or
`APPHUB_C1_DIRECTORY_CLIENT_SECRET` instead of `CLIENT_SECRET_REF`) and put
the value in the environment. In ECS, Terraform publishes those values to
Parameter Store and the task definition's `secrets` block injects them; the
YAML holds only the variable names. The portal frontend is served by
`apphub serve` from `staticDir` and has no operator secrets of its own.

### Where a build runs

Each build runs in its own ECS task, launched by the worker through the ECS API
and configured under `build.task` in the provider configuration file. The task
runs the digest-pinned builder and nothing else.

**The build task carries no task role.** On Fargate every container in a task
shares one network namespace, so the task credentials endpoint is reachable
from the container executing the Dockerfile: a role attached for any container's
benefit is a credential repository-authored code can read. There is no sidecar
arrangement that survives it, which is why the build context and the finished
image cross on a shared filesystem rather than through a signed URL — a signed
URL is credential material, in exactly that environment. See
[`docs/decisions/`](docs/decisions/).

The operator supplies the cluster, the subnets, the security groups, the shared
filesystem's mount points, and one task definition per concurrent build. The
task definitions are one per build because a volume is declared on a task
definition rather than on a run-time override, and the EFS access point each
one mounts is what confines a build to its own directory: a build can neither
name nor reach another's.

Before it claims any work, the worker re-reads every configured build task
definition and refuses to start unless each carries no task role, uses `awsvpc`,
names a digest-pinned builder, declares enough ephemeral storage, and mounts its
volume through an access point with transit encryption. It then runs a real
one-layer validation build end to end, which also proves the volume mounted and
that the worker and the task see the same filesystem. There is no flag to skip
any of it.

What the substrate enforces rather than what an operator asserts: the build task
has no public address, Fargate exposes no instance metadata, and nothing in the
VPC admits the build security group. The remaining bounds are AppHub's — a build
context is refused above 512 MiB, and the image that crosses back is bounded on
the way. No Git credential, push credential, or worker filesystem is exposed to
repository code; the credential-bearing pusher runs afterwards, in the worker,
from a process that never executed the Dockerfile.

### Identity and operation semantics

Users are identified by verified `(issuer, subject)`, not email. Different
issuers never merge accounts. Sessions retain their establishing provider's
admission policy even when another client of the same issuer signs in.
Cookie mutations require exact Origin and session-bound CSRF. Upstream tokens
are discarded after sign-in. Local disablement and policy removal apply on the
next request; upstream IdP deprovisioning is not detected immediately without an
upstream signal.

OAuth tokens are opaque, scoped, and audience-bound. Management clients receive
tokens for exactly one of `{publicOrigin}/api` or `{publicOrigin}/mcp`. A public
application with `exposure.mcpAuthEnabled: true` receives its own OAuth issuer,
`app:access` scope, and `https://<application-host>/mcp` audience. Access lifetime
is 15 minutes; rotating refresh families have an absolute 30-day lifetime.
Refresh replay revokes the family. Session settings revocation requires browser
authentication and CSRF; delegated clients revoke their own credentials through
the issuer's `/oauth/revoke`.

Creation persists a draft. Submission atomically persists the operation,
application execution lock, and idempotency result before returning 202.
Disconnects stop observation, not deployment. Retry uncertain requests with the
original idempotency key and operation ID. Updates require an exact revision.
No edit or second deployment can pass an active or unresolved interrupted lock.
Published or uncertain hostnames remain reserved through draft edits and failed
attempts; obsolete reservations are released only with successful reconciliation.
At most 64 pending hostname reservations may accumulate before a successful
deployment is required.

Service success requires all requested replicas and completion of old-revision
draining. Switching execution modes retires the old service or schedule before
creating the new mode; a failed retirement retains its reference. Removing a
schedule stops future dispatch, not already-launched executions. Scheduled
success means **Schedule installed**, not successful job execution.
Every published application URL, public or private, sits behind the platform
sign-in (oauth2-proxy). The application receives the signed-in user as
`X-Auth-Request-User` and `X-Auth-Request-Email` and implements no login of its
own. The optional `mcpAuthEnabled` exposure setting changes how `/mcp` alone is
authenticated: after that revision is deployed, AppHub publishes OAuth discovery
on the application hostname and protects `/mcp` with AppHub OAuth instead, so
MCP clients can connect with a bearer token. It forwards verified identity as
`X-AppHub-User-ID` and `X-AppHub-Email`, strips the bearer token and internal
routing headers before the request reaches the application, and leaves every
other path behind the platform sign-in. Disabling the setting invalidates app-scoped
tokens immediately; deploying the new revision removes the ingress routes.

A stale attempt becomes `interrupted`, never automatically reruns, and retains
its execution lock. After independently stopping the old worker and build
container, an administrator may acknowledge the uncertainty:

```sh
apphub deployments resolve-interrupted <operation-id> --worker-stopped --reason "<operator explanation>"
```

This releases the lock without claiming success or deleting resources. A later
explicit deployment is a new attempt, not resume-from-step. Graceful worker
shutdown stops new claims and drains accepted operations.

### CLI, MCP, and verification

```sh
apphub login --server https://apphub.example --no-browser
apphub whoami --json
apphub apps create --file application.json --json
apphub apps update <application-id> --file application.json --revision <revision>
apphub deploy <application-id> --revision <revision> --wait --json
apphub deployments get <operation-id> --json
apphub mcp stdio
```

AppHub's management MCP uses authenticated Streamable HTTP at `/mcp`; local
stdio uses the CLI's authenticated HTTP context. Both expose the same target,
owned-application, and deployment tools. This is separate from hosted
application MCPs: an application opts its own `/mcp` into AppHub OAuth through
`exposure.mcpAuthEnabled`.

CLI credentials are server/resource/client-bound, cross-process locked, and
privately stored in the OS user configuration directory. JSON commands emit one
stdout value; progress and recovery details use stderr. Failed/interrupted
deployments return nonzero. Ctrl-C while waiting preserves the server-side
operation and prints recovery information.

```sh
make test boundary
npm --prefix frontend ci
npm --prefix frontend run build
go generate ./sdk/go
npm --prefix frontend run generate
go build -o /tmp/apphub ./cmd/apphub
go test -race ./internal/integration -count=1
```

The explicitly opt-in browser fixture runs signed local OIDC and the actual
HTTP/OAuth/MCP/service/dispatcher/module paths with **test compute**, not AWS:

```sh
APPHUB_BROWSER_FIXTURE=1 go test ./internal/integration -run '^TestBrowserHarness$' -v -timeout 35m
npm --prefix frontend run dev
```

It binds the backend to loopback port 8081 and expires after 30 minutes. Its
loopback-only outage/failure controls are compiled only into tests. For real
DynamoDB Local persistence, initialize an isolated table and set
`APPHUB_INTEGRATION_DYNAMO_ENDPOINT` and `APPHUB_INTEGRATION_DYNAMO_TABLE` before
running `TestDynamoDBDurableDeployment`; use local-only signing values.

Before production, an operator must validate real Google and generic OIDC
callbacks; a benign and an adversarial Dockerfile on the actual isolated runtime;
and UI/CLI/MCP deployments against a dedicated approved AWS namespace. Confirm
exact commits, immutable pushed images, replica readiness, TLS/DNS/HTTP response,
redeployment, IAM/data access, interruption fencing, and reviewed teardown.
Missing AWS/IdP credentials, DNS/TLS, or isolated runtime is a blocked acceptance
check, not permission to substitute fake production behavior.

The import proof permits only exact composition roots to wire existing provider
boundaries: the executable in production and named integration/worker fixtures
in tests. Direct SDK imports, non-boundary wrappers, and portable library
dependencies remain forbidden by both union and concrete graph checks.

## Repository map

| Path | Role |
| --- | --- |
| [`modules/`](modules/) | The `Module` contract plus deploy, review, and fix modules. |
| [`compute/`](compute/) | Provider-agnostic compute ports and capability declarations. |
| [`compute/aws/`](compute/aws/) | AWS implementation over ECS, Lambda, S3, DynamoDB/Aurora, ECR, IAM, and related services. |
| [`compute/fake/`](compute/fake/) | Hermetic in-memory provider used by tests and examples. |
| [`compute/k8s/`](compute/k8s/) | Kubernetes provider and memory-backed seams for conformance. |
| [`credentials/`](credentials/) | CredentialProvider, provider registry, redacting types, and credential providers. |
| [`credentials/lifecycle/`](credentials/lifecycle/) | Credential issue/revoke/reconcile lifecycle that outlives one vend call. |
| [`store/`](store/) | DynamoDB-backed v1 persistence fence. |
| [`cmd/apphub`](cmd/apphub/) | Executable API/worker composition and CLI dispatch. |
| [`internal/controlplane`](internal/controlplane/) | Portable application and durable deployment service. |
| [`api/openapi.yaml`](api/openapi.yaml) | External HTTP contract shared with generated clients. |
| [`sdk/go`](sdk/go/) | Authenticated Go HTTP client and CLI credential lifecycle. |
| [`frontend`](frontend/) | React deployment portal. |
| [`examples/notes`](examples/notes/) | Reference application to deploy when trying AppHub: a per-user notes service on a DynamoDB table. |
| [`docs/`](docs/) | Public architecture, provider authoring guides, design notes, and decision records. |

## Capabilities and provider support

The compute provider capability matrix is generated from the provider instances
the test suite can construct without crossing provider-boundary import fences:
[`docs/design/capability-matrix.md`](docs/design/capability-matrix.md). Today
that generated table covers the fake and Kubernetes configurations. The AWS
provider is the production implementation and is documented in
[`compute/aws`](compute/aws/); it is kept out of that generator so the matrix test
does not import AWS-specific packages into the Kubernetes provider package.

## Design and authoring guides

- [`docs/architecture.md`](docs/architecture.md) explains the module,
  provider, credential, lifecycle, and store layers.
- [`docs/provider-authoring/compute.md`](docs/provider-authoring/compute.md)
  covers writing a compute provider and updating the generated matrix.
- [`docs/provider-authoring/credentials.md`](docs/provider-authoring/credentials.md)
  covers writing a credential provider safely.
- [`docs/design/compute-provider.md`](docs/design/compute-provider.md) and
  [`docs/design/credential-vending.md`](docs/design/credential-vending.md) hold
  deeper design rationale.
- [`docs/decisions/`](docs/decisions/) records binding project decisions.

## Contributing and security

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Contributions use DCO sign-off,
tests must stay hermetic, and public text must not include private deployment
identifiers, account-shaped literals, private URLs, or credential material.

Report security problems privately through [`SECURITY.md`](SECURITY.md), not in
a public issue or pull request.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
