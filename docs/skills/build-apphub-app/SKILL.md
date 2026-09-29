---
name: build-apphub-app
description: Build an application that deploys cleanly on AppHub (containers built from a GitHub repo and run on AWS ECS Fargate behind AppHub's ingress), and optionally deploy it through AppHub's MCP server. Use when asked to create, port, or prepare an app for AppHub, or to deploy one with the AppHub MCP tools.
---

# Build an app for AppHub

AppHub takes a GitHub repository, builds its Dockerfile, and runs the image as a
service or a scheduled job. It can also provision a DynamoDB table, an S3 bucket,
or a Postgres database for the app, and wires each one in through environment
variables. The app never creates or names its own cloud resources.

Your job: produce a repository that satisfies the contract below, then (if asked)
deploy it with the MCP flow at the end.

## The contract, in one screen

| Area | Rule |
| --- | --- |
| Source | A GitHub repo `https://github.com/<owner>/<repo>` whose owner has the AppHub GitHub App installed (or that the target lists explicitly). Shallow clone, no submodules, **no Git LFS** (LFS files arrive as pointers). No symlinks pointing outside the repo. |
| Build | One `Dockerfile`, path relative to the repo root; the **build context is always the repo root**. Built by Kaniko with no layer cache, **no build args**, and **no registry credentials** — base images must be public. Multi-stage is fine. 45-minute build limit. |
| Architecture | Produce a **linux/amd64** image. Do not pin `--platform` to arm64. |
| Port | Listen on **one** HTTP port on `0.0.0.0`. You choose the number and give it in the spec (`port`). **`PORT` is not set for you** — hardcode a default or read your own variable. Put a literal `EXPOSE <port>` in the Dockerfile so detection suggests it. |
| Readiness | There is **no HTTP health check**. A deploy is ready when the task starts and stays running. A process that exits or crash-loops fails the deploy. Start fast; don't block startup on optional dependencies. |
| Logs | Write to stdout/stderr. |
| Shutdown | Handle `SIGTERM` and exit within ~30 s (ECS default grace). |
| Auth | Every published HTTP route sits behind AppHub SSO. **Do not build a login.** Read the user from request headers (below). |
| Reserved paths | Don't serve `/oauth2/*`, `/.well-known/oauth-protected-resource*`. With MCP auth on, `/mcp` and `/mcp/*` are reserved for your MCP endpoint. |
| AWS | Credentials come from the ECS task role via the **default AWS SDK credential chain**. Never ask for keys; never set `AWS_*` yourself. Don't hardcode a region; use the SDK's default resolution. |
| Config | Only environment variables. Resource names come from AppHub; everything else comes from owner-managed secrets. |

## Environment variables AppHub sets

Set on every deploy, only when the resource is attached:

| Resource | Variable | Holds |
| --- | --- | --- |
| Key-value table (DynamoDB) | `TABLE_NAME` | table name |
| Bucket (S3) | `BUCKET_NAME` | bucket name |
| | `BUCKET_URI` | bucket URI |
| Relational (Aurora Postgres) | `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER` | connection details |
| | `DATABASE_PASSWORD` | password (injected from the secret store) |

Read them at startup and fail with a clear message if one you need is missing.
For local development, fall back to local values (e.g. DynamoDB Local, MinIO,
a local Postgres) behind the same variable names, with AWS endpoint overrides
kept in your own non-reserved variables such as `LOCAL_DYNAMO_ENDPOINT`.

**Owner secrets** are extra env vars the owner adds after creation. Names must
match `^[A-Z_][A-Z0-9_]*$` (≤100 chars), and may not be `PORT`, `TABLE_NAME`,
`BUCKET_NAME`, `BUCKET_URI`, or start with `DATABASE_`, `APPHUB_`, `AWS_`, `ECS_`.
At most 50 per app, 4096 bytes each. Changing a secret redeploys the app. Put
API keys and third-party tokens here, and document every variable the app reads
in the README.

## Identity: who is calling

Normal HTTP routes (oauth2-proxy in front; client-sent copies are stripped):

- `X-Auth-Request-Email` — the signed-in user's email
- `X-Auth-Request-User` — the user identifier

The MCP endpoint, when `mcpAuthEnabled` is on:

- `X-AppHub-User-ID` — AppHub user id
- `X-AppHub-Email` — email

Trust these headers; they are set by the ingress, never by the client. Treat a
request missing them as unauthenticated (it can only happen locally) — in
production, return 401 rather than falling back to an anonymous user.

## Data resources

### Key-value table (DynamoDB)

- Keys are **strings named `pk` (partition) and `sk` (sort)** unless the spec
  names others. Design a single-table layout on those, e.g.
  `pk = "USER#<id>"`, `sk = "PROFILE"` / `sk = "ORDER#<ts>"`.
- On-demand billing. The app may `GetItem`, `PutItem`, `UpdateItem`,
  `DeleteItem`, `Query`, `Scan`, `BatchGetItem`, `BatchWriteItem`.
- **No GSIs/LSIs, no `DescribeTable`, no `CreateTable`, no TTL config.** Model
  every access pattern with `pk`/`sk` queries. If you need an inverted lookup,
  write a second item (e.g. `pk = "EMAIL#<email>"`, `sk = "USER"`).

### Bucket (S3)

- Access is `read-write` (default) or `read`. Read gives `GetObject`,
  `GetObjectVersion`, `ListBucket`, `GetBucketLocation`; read-write adds
  `PutObject`, `DeleteObject`, `AbortMultipartUpload`.
- The bucket is never public. Serve files through the app (stream them, or hand
  out **presigned GET URLs**, which work with these permissions).
- No bucket policy, CORS, or lifecycle changes from the app.

### Relational (Aurora Serverless v2, Postgres)

- `engine: "postgres"`, `engineVersion` must be one the target lists (usually
  `"18"`). `databaseName` (from the app name), `adminUsername` (`appuser`) and
  `capacity` (`minUnits`/`maxUnits`, default 0.5–4 ACU) are optional.
- **Connect with TLS** (`sslmode=require`, or `verify-full` with the RDS CA
  bundle in the image).
- AppHub runs no SQL. **Run migrations yourself at startup**, idempotently
  (e.g. `golang-migrate`, Alembic, Prisma `migrate deploy`), guarded so parallel
  replicas don't collide (advisory lock, or migrate in one replica).
- Only the app can reach the database — there is no local access path, so seed
  data through the app or a migration.

## Execution modes

- **`service`** — a long-running HTTP server. 1 to `maxReplicas` replicas
  (usually ≤4); keep it stateless so replicas are interchangeable.
- **`scheduled`** — a run-to-completion job: do the work, then exit. There are no
  routes, no retries, and no overlap protection, so make each run
  **idempotent** and bounded in time. The expression is either
  `rate(<n> minutes|hours|days)` or five-field POSIX cron (`0 9 * * 1-5`).
  Cron limits: digits, `*`, `,`, `-`, `/` only (no names, no `?`); restrict
  day-of-month **or** day-of-week, not both; day-of-week is `0`–`6` (0 = Sunday)
  as single days, ascending ranges, or lists — no steps and no `7`. Timezone is
  an IANA name (default UTC). A successful deploy means "schedule installed",
  not "job ran".

## Exposure

- **`private`** — reachable on the internal ingress (behind SSO) at
  `<hostname>.<internal domain>`; hostname optional.
- **`public`** — services only; `hostname` is one lowercase DNS label
  (`[a-z0-9-]`, ≤63, no leading/trailing `-`), published over TLS as
  `<hostname>.<route domain>`. **Still behind SSO.**
- **`mcpAuthEnabled: true`** (public only) — `/mcp` is authenticated with AppHub
  OAuth instead of SSO, so MCP clients (Claude, IDEs) can connect with a bearer
  token. Build it like this:
  - Serve a **Streamable HTTP** MCP server at `/mcp`.
  - Implement **no OAuth** and no `/.well-known` routes — AppHub serves discovery
    and validates the token, then strips `Authorization` before the request
    reaches you.
  - Authorize on `X-AppHub-User-ID` / `X-AppHub-Email`.
  - Keep your web UI (if any) on other paths; they use the SSO headers.

## Resource sizes

`resources` must exactly equal one of the target's sizes, typically
`{cpu: 256, memory: 512}`, `{512, 1024}`, `{1024, 2048}`, `{2048, 4096}`
(millicores / MiB). Check `targets_list` for the real list. Pick the smallest
that fits; size the runtime (JVM heap, Node `--max-old-space-size`, worker
counts) to the memory limit.

## Dockerfile template

Adapt to the language; the shape matters, not the toolchain.

```dockerfile
# syntax=docker/dockerfile:1
FROM public.ecr.aws/docker/library/golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/app"]
```

Rules this follows: public base images, everything copied from the repo root
context, no `ARG` whose value must be supplied, an explicit `EXPOSE`, a non-root
user, and an exec-form entrypoint so `SIGTERM` reaches the process. Add a
`.dockerignore` (`.git`, `node_modules`, local data, `.env*`).

## Repository checklist

Before calling the app done, confirm each:

- [ ] `Dockerfile` at the repo root builds with `docker build --platform linux/amd64 .` and no build args.
- [ ] The container listens on `0.0.0.0:<port>` with that same port in `EXPOSE`.
- [ ] It starts with none of the optional env vars set, or exits with a clear message naming the missing one.
- [ ] It reads `TABLE_NAME` / `BUCKET_NAME` / `DATABASE_*` only — no hardcoded resource names, regions, or credentials.
- [ ] It uses the default AWS SDK credential chain.
- [ ] DynamoDB access uses only `pk`/`sk` queries (no indexes).
- [ ] Identity comes from the ingress headers; there is no login page and no OAuth code.
- [ ] It handles `SIGTERM`; a scheduled job exits 0 on success and is safe to re-run.
- [ ] Postgres (if used): TLS on, migrations at startup, idempotent.
- [ ] `README.md` lists: port, execution mode, resources needed, every env var and secret it reads, and a local-run recipe.
- [ ] No LFS files, submodules, or out-of-tree symlinks; secrets are not committed.

## Deploying with the AppHub MCP server

The AppHub MCP server is Streamable HTTP at `<apphub-origin>/mcp` with OAuth
(scopes `applications:read`, `applications:write`, `deployments:read`,
`deployments:write`), or locally via `apphub login --server <origin>` then
`apphub mcp stdio`. The repo must already be pushed to GitHub.

1. **Discover the target.** Call `targets_list` (or read
   `apphub://deployment-options`). Pick a target with `ready: true` and note its
   `id`, `executionModes`, `resourceSizes`, `maxReplicas`, `databaseKinds`,
   `bucketKinds`, public-exposure support, and `repositories`. Only request what
   it offers.
2. **Create the draft** with `applications_create` and a stable
   `idempotencyKey` (e.g. `create-<repo>-v1`). It has no cloud effects yet.

   ```json
   {
     "idempotencyKey": "create-notes-app-v1",
     "application": {
       "name": "Notes",
       "targetId": "<target id>",
       "source": { "url": "https://github.com/<owner>/<repo>", "ref": "main", "dockerfile": "Dockerfile" },
       "execution": "service",
       "port": 8080,
       "resources": { "cpu": 256, "memory": 512 },
       "replicas": 1,
       "exposure": { "mode": "public", "hostname": "notes", "mcpAuthEnabled": false },
       "database": { "kind": "key-value" },
       "bucket": { "kind": "standard", "access": "read-write" }
     }
   }
   ```

   Omit `database` / `bucket` when not needed. `"database": {"kind": "key-value"}`
   gets `pk`/`sk` keys. A scheduled job adds
   `"schedule": {"expression": "rate(1 hour)", "timezone": "UTC", "paused": false}`
   and uses `"exposure": {"mode": "private"}`. Keep the returned `id` and
   `revision`.
3. **Add secrets** (only if the app needs them) with `secrets_deploy`:
   `{applicationId, idempotencyKey, changes: {applicationRevision, changes: [{name, action: "set", value}]}}`.
   This also starts a deployment, so step 4 can be skipped when you use it
   (poll the deployment it returns).
4. **Deploy** with `deployments_create`:
   `{applicationId, idempotencyKey: "deploy-<id>-r<revision>", deployment: {applicationRevision: <revision>}}`.
   It builds `source.ref` as it resolves at that moment.
5. **Poll** `deployments_get` with the `deploymentId`, waiting `pollAfterMs`
   between calls, until the state is terminal: `succeeded`, `failed`, or
   `interrupted`. On success, `addresses` holds the app's URLs.
6. **Change it later** with `applications_update` (full spec plus the exact
   current `revision`; the target cannot change; blocked while a deploy runs),
   then `deployments_create` for the new revision.

Rules for the MCP calls:

- Every write takes an `idempotencyKey` (≤256 chars). Reuse the **same** key to
  retry after a timeout or `outcome_uncertain`; a new key for a new intent. Reusing
  a key for a different request is a 409.
- `hostname_conflict` (409): pick another hostname.
- `target_unavailable` (503): the target's worker is down; wait or pick another target.
- `interrupted` deployments need an AppHub admin; don't loop on retries.
- `applications_delete` destroys the table, bucket contents, and database
  **without a snapshot**. Never call it unless the user asked, and pass
  `confirmName` equal to the app's exact name.
- There is no logs tool. If a deploy fails, report `step`, `errorCode` and
  `message` from `deployments_get` to the user; the common causes are a Dockerfile
  that doesn't build without args or private images, and a process that exits on
  startup (missing env var, wrong port bind, failed migration).
