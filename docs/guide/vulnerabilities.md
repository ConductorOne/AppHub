# Vulnerabilities

A workspace-wide **Vulnerabilities** page and a per-application **Vulnerabilities** tab list package findings by severity.

> [!IMPORTANT]
> This is a preview surface. Vulnerability scanning isn't connected yet — the findings shown are illustrative, seeded per application, and not the result of a real scan. Treat everything on this page as a preview of the eventual feature, not as security signal.

## Turning it on

The page and tab are hidden entirely until a workspace administrator turns on the `vulnerabilities` feature flag from **Workspace → Feature flags**. A flag can be:

- **Off** — hidden for everyone, including administrators.
- **On** — visible to everyone.
- **Groups** — visible only to members of selected synced directory groups.

## Who sees what

- A member or app owner sees findings only for applications they own.
- An administrator, or anyone granted the separate **vulnerability admin** role, sees findings across every application in the workspace — see [Owners and roles](owners-and-roles.md).
