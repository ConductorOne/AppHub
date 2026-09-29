# Databases and storage

An application may attach one database (relational or key-value) and one object storage bucket. AppHub creates and names these resources and injects connection details as environment variables; your application never supplies or hardcodes a resource name.

## Key-value table (DynamoDB)

- Keyed by a string partition key, and optionally a string sort key. Leave both empty to get `pk` (partition) and `sk` (sort); naming only a partition key creates a table with no sort key.
- On-demand billing, with no configuration for it.
- There are no secondary indexes, no `CreateTable`/`DescribeTable`, and no TTL configuration — model every access pattern with partition/sort key queries, adding an extra item for an inverted lookup if you need one.

Environment variable injected: `TABLE_NAME`.

## Relational database (Aurora Serverless v2 PostgreSQL)

The portal prefills every field below, so you can pick **Relational SQL** and deploy without changing anything. API and MCP callers can omit every field except the engine version, which the server requires:

| Field | Default | Notes |
| --- | --- | --- |
| Engine | `postgres` | PostgreSQL is the only engine actually provisioned. MySQL is accepted as an option in the form and the API's schema, but the AWS compute provider refuses it at deploy time — pick PostgreSQL. |
| Engine version | `18` (portal only) | Required in API and MCP requests. Must be a major version the target offers. |
| Database name | derived from the application name | Lowercased, non-letters/digits collapsed to single underscores, truncated to 63 characters, and never a reserved name (`rdsadmin`, `postgres`, `template0`, `template1`); falls back to `app` if nothing survives. |
| Admin username | `appuser` | The database's master account. AppHub generates and stores its password; no password field is ever accepted from a caller. |
| Capacity | 0.5–4 Aurora Capacity Units | Shown in the form as abstract "capacity units" (default 0.25–2), which this deployment's default configuration converts to ACUs at a 2:1 ratio. The target policy and AWS worker each cap requested capacity at 2 abstract units by default; only an operator may raise both ceilings for a heavier workload. |

> [!NOTE]
> Renaming an application does not rename its existing database. Once a database exists, its engine, database name, and admin username stay fixed for that application; only a database new to the application picks up a fresh default.

Optional PostgreSQL extensions (installed by AppHub's worker over a verified TLS connection, after the database is ready): `btree_gin`, `btree_gist`, `citext`, `fuzzystrmatch`, `hstore`, `pg_trgm`, `pgcrypto`, `unaccent`, `uuid-ossp`, `vector`. Extensions that require a preload configuration are not supported.

Environment variables injected: `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`.

Connect with TLS (`sslmode=require`, or `verify-full` against the RDS CA bundle if your operator has configured one). AppHub runs no SQL of its own — run your own migrations at startup, idempotently, guarded so concurrent replicas don't collide. There is no access path to the database other than through your application.

## Object storage (S3 bucket)

- Bucket kind is `standard` or `zonal` (a zonal bucket additionally needs a zone matching the target's approved placements).
- Access is `read-write` (default) or `read`. Read grants `GetObject`, `GetObjectVersion`, `ListBucket`, and `GetBucketLocation`; read-write adds `PutObject`, `DeleteObject`, and `AbortMultipartUpload`.
- The bucket is never public. Serve files through your application, or hand out presigned GET URLs (which work with either access level).
- No bucket policy, CORS, or lifecycle configuration is available from the application.

Environment variables injected: `BUCKET_NAME`, `BUCKET_URI`.

## Deleting an application deletes its data

Removing a database, key-value table, or bucket from an application's specification, or deleting the application itself, deletes the underlying data with no snapshot. See [Deployments](deployments.md) for what a deletion (teardown) does.
