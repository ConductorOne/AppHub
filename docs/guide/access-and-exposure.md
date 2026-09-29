# Access and exposure

Normal application routes require sign-in. Choosing "public" exposure means the address is reachable from the internet, not that its normal routes are anonymous; they still use your organization's identity provider. Explicit public paths (for example a health check) and OAuth discovery endpoints are exceptions and do not carry a verified user identity.

## Private

Reachable only inside your organization's network, on targets that offer an internal route. The hostname label is optional — leave it empty for a stable, generated one derived from the application's ID. On a target with no internal route configured, a private application with no other route has no address at all: nothing can open a connection to it, which is the right choice for a worker that only makes outbound calls. Scheduled jobs never have a route, private or public.

The Kubernetes provider does not have an isolated internal ingress. It refuses
an internal route instead of putting a supposedly private service on the public
ingress; use a target/provider with an enforced internal entrypoint to publish
private services. A private workload without a route remains supported.

## Public

Reachable over HTTPS at `<hostname>.<operator's route domain>`, where `<hostname>` is a lowercase DNS label you choose (letters, digits, hyphens; not starting or ending with a hyphen; at most 63 characters). Only continuous services can be public — scheduled jobs cannot. Publishing publicly requires acknowledging, in the portal, that anyone your identity provider admits can open the address. There is no plaintext option and no custom domain support yet; public applications are served under the workspace's managed domain.

## Sign-in and public paths

Every route -- private or public -- requires sign-in by default. From the application's **Authentication** tab, an owner can turn sign-in off for the route, which publishes it to anyone who can reach it: for a public application that means anyone with the URL, and for a private one it means anyone inside the network the internal ingress already limits it to. Turning sign-in off asks for confirmation, since it changes who can reach the application without going through your identity provider.

While sign-in is on, the same tab lets an owner list **public paths**: exact paths that bypass sign-in on an otherwise-authenticated route, for things like health checks, webhooks, and static assets. Paths match exactly; end a path with `/*` to also exempt everything below it (`/api/webhooks/*` exempts `/api/webhooks/anything`, not `/api/webhooksevil`). A bare `/*` is refused -- turn sign-in off instead of exempting every path. Public paths never carry a verified identity: treat a request on one exactly like a request from the open internet.

Public path rules are kept on the application's specification even while sign-in is off, so turning sign-in back on restores them without re-entering anything. Changes to either setting apply on the application's next deploy, the same as other specification changes.

## How sign-in reaches your application

Every request to a normal route passes through the platform's own sign-in proxy (oauth2-proxy) first. Your application reads the verified identity from request headers:

- `X-Auth-Request-User` — the signed-in user's identifier
- `X-Auth-Request-Email` — the signed-in user's email

AppHub removes client-sent `X-Auth-Request-User`, `X-Auth-Request-Email`, `X-AppHub-User-ID`, `X-AppHub-Email`, `X-AppHub-Application-ID`, and `X-AppHub-MCP-Host` before authentication; only authenticated routes receive verified identity values. Never infer identity from headers on a public path. The shared oauth2-proxy session and CSRF cookies are also removed after ingress authentication, before the request reaches your application; your own application cookies remain available.

The Kubernetes provider currently has no controller-enforced sign-in
middleware. It refuses routes requiring ingress authentication or public-path
exemptions rather than publishing them without protection; the deployed AWS
ingress supplies the behavior above.

## MCP authentication for a public application

A public service may also turn on **Require AppHub OAuth for /mcp**. This changes how requests to `/mcp` (and only that path) are authenticated:

- AppHub publishes OAuth discovery on the application's own hostname and protects `/mcp` with AppHub OAuth instead of the sign-in proxy, so MCP clients (Claude Code, IDEs, other agents) can connect with a bearer token instead of a browser session.
- Every other path on the same application stays behind the normal sign-in proxy.
- AppHub verifies the token, then forwards the request with `X-AppHub-User-ID` and `X-AppHub-Email` headers, stripping the bearer token and any internal routing headers first. Your `/mcp` handler should implement no OAuth of its own and authorize using those two headers.
- Disabling this setting invalidates its issued tokens immediately; deploying the change removes the `/mcp` route AppHub added for it.

This is separate from AppHub's own management MCP server, which agents use to create and deploy applications — see [Connect an agent over MCP](connect-an-agent-mcp.md). Building an application that itself serves an MCP endpoint is covered in [`docs/skills/build-apphub-app/SKILL.md`](../skills/build-apphub-app/SKILL.md).

## What isn't supported yet

Custom (bring-your-own) domains are not available — public applications are always published under the workspace's managed wildcard domain.
