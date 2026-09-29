# Connect an agent over MCP

AppHub's management surface — the same targets, applications, and deployments the portal and CLI use — is also available as an MCP server, so an agent such as Claude Code can create and deploy applications on your behalf.

> [!NOTE]
> This is AppHub's own management MCP server, used to operate AppHub itself. It's different from an individual application's own `/mcp` endpoint (see [Access and exposure](access-and-exposure.md#mcp-authentication-for-a-public-application)), which is something *your deployed application* can choose to expose to its own users.

## What the tools can do

The server exposes read tools (`targets_list`, `categories_list`, `applications_list`, `applications_get`, `applications_directory`, `applications_usage`, `owners_list`, `principals_search`, `secrets_list`, `deployments_get`, `deployments_list`) and write tools (`applications_create`, `applications_update`, `applications_delete`, `owners_add`, `owners_remove`, `secrets_deploy`, `deployments_create`). Every write requires an idempotency key; retrying with the same key is safe, a new key means a new intent. Neither the portal, the CLI, nor this server ever runs deployment work itself — they submit durable operations that AppHub's worker executes; see [Concepts](concepts.md#deployment-operation).

An access token carries a subset of four scopes: `applications:read`, `applications:write`, `deployments:read`, `deployments:write`. What a given tool needs is described in its own tool description.

For step-by-step guidance on building and deploying an application through this server (environment contract, resource sizes, exact request shapes, common failure causes), see [`docs/skills/build-apphub-app/SKILL.md`](../skills/build-apphub-app/SKILL.md).

## Connect Claude Code to it

The endpoint is Streamable HTTP at `https://<your-apphub-host>/mcp`, protected by OAuth. Add it as a remote server:

```sh
claude mcp add --transport http apphub https://<your-apphub-host>/mcp
```

The first time a tool is called, Claude Code discovers AppHub's OAuth metadata, registers itself (AppHub accepts a client id that is itself an `https://` URL to a client metadata document — a CIMD — as long as it declares a public client with an HTTPS or loopback redirect), and opens your browser to sign in and approve the requested scopes. From then on it holds a short-lived access token (15 minutes) backed by a rotating refresh token (30 days), scoped to exactly this MCP resource.

## Connect over local stdio instead

If you'd rather not expose a remote OAuth client, sign in with the CLI once and bridge stdio through it:

```sh
apphub login --server https://<your-apphub-host>
claude mcp add apphub -- apphub mcp stdio
```

`apphub mcp stdio` reuses the CLI's own authenticated session rather than negotiating a separate OAuth flow — it exposes the same tools as the remote endpoint.

## Managing access afterward

Every MCP connection — remote or via `mcp stdio` — is a delegated session, listed alongside your browser sessions on **Settings → Active sessions**. Revoking one there ends that agent's access immediately; it does not affect a deployment a worker has already accepted.
