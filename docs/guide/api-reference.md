# API reference

AppHub's external HTTP contract is a single OpenAPI document: [`api/openapi.yaml`](../../api/openapi.yaml). It's the source of truth — the generated Go SDK ([`sdk/go`](../../sdk/go)) and the portal's own client are generated from it, not maintained by hand alongside it.

## Base paths

- `/api/v1/...` — the authenticated application and workspace API (targets, categories, applications, owners, secrets, deployments, sessions, admin endpoints).
- `/auth/...` and `/.well-known/oauth-authorization-server` / `/.well-known/oauth-protected-resource/*` — browser sign-in and OAuth discovery.
- `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` — the OAuth flow used by the CLI, MCP clients, and any other public OAuth client.
- `/mcp` — AppHub's own management MCP server; see [Connect an agent over MCP](connect-an-agent-mcp.md).

## Authentication

Two independent mechanisms protect this API, and a request uses one or the other, never both:

- **Browser session** — a cookie set at sign-in, checked alongside an exact `Origin` and a session-bound CSRF token on any mutating request. This is what the portal itself uses.
- **OAuth bearer token** — scoped and audience-bound to exactly one resource (`{origin}/api`, `{origin}/mcp`, or one public application's own `/mcp`). This is what the CLI, `apphub mcp stdio`, and remote MCP clients use. Scopes are `applications:read`, `applications:write`, `deployments:read`, `deployments:write` (plus `app:access` for a hosted application's own `/mcp`).

## Idempotency and durable operations

Every mutating write that has a lasting effect (creating an application, submitting a deployment, changing secrets, deleting an application) takes an `Idempotency-Key`. Retry a timed-out or uncertain request with the *same* key to get the original outcome rather than a duplicate; use a new key only for a genuinely new intent. Deployments and deletions are accepted immediately (`202`) and observed afterward by polling their operation resource — see [Deployments](deployments.md).

## Where to look first

Within `api/openapi.yaml`, the schemas named `ApplicationInput`, `TargetView`, `DeploymentView`, and `DatabaseInput`/`BucketInput` correspond directly to the concepts in this guide — see [Concepts](concepts.md) and [Databases and storage](databases-and-storage.md).
