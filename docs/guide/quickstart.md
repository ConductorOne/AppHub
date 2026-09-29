# Quickstart

Deploy an existing GitHub repository to AppHub through the web portal, from a fresh sign-in to a running application.

## Before you start

You need:

- Access to an AppHub portal URL from your administrator, and an identity your organization's sign-in provider admits.
- A GitHub repository with a `Dockerfile` at (or under) its root. The repository's owner must have the AppHub GitHub App installed, or the deployment target must list it explicitly.
- `applications:write` permission, which every signed-in identity gets unless your administrator has restricted it. If the **New application** button is missing from Home, ask your administrator.

## Deploy an application

1. Sign in at `/login` with your organization's identity provider. Different providers (or different accounts on the same provider) are always separate AppHub identities, even if their email addresses match.
2. From Home, click **New application**.
3. **Repository.** Pick a deployment target (if more than one is offered) and enter the repository URL, either by selecting one from the list of approved or synced repositories or by pasting a `https://github.com/<owner>/<repo>` URL.
4. AppHub scans the repository for a Dockerfile and configuration hints. This is advisory only: it can prefill the Dockerfile path, the container port (from an `EXPOSE` line), and suggest a database kind, but nothing is applied automatically — review every field on the next screen. Detection failing or finding nothing just means the form falls back to plain defaults.
5. **Review and deploy.** Fill in the rest of the specification:
   - Application name, and an optional category to group it on Home.
   - Source ref (branch, tag, or commit; empty resolves the default branch at deploy time) and the Dockerfile path.
   - Execution mode (continuous service or scheduled job), container port, CPU/memory size, and replica count — all constrained to what the target allows.
   - A database and/or object storage bucket, if the application needs one (see [Databases and storage](databases-and-storage.md)).
   - Network exposure: private (internal network only) or public (over HTTPS, with a hostname label you choose). Publishing publicly requires checking an acknowledgement that anyone your identity provider admits can open the address.
6. Click **Deploy application**. This creates the application as a draft, then immediately submits a deployment of it — nothing is deployed until this step.
7. You land on the deployment's page, which polls the durable operation status until it reaches a terminal state: `succeeded`, `failed`, or `interrupted`. A build (Kaniko, no cache, no build arguments, 45-minute limit) runs first; once the image is ready, the service starts or the schedule installs.
8. On success, the application's URL (if it has one) appears on this page and on the application's **Overview** tab. Scheduled jobs have no URL — a successful deployment there means the schedule was installed, not that a job has run.

> [!TIP]
> The same action is available from the CLI: `apphub apps create --file application.json --json` followed by `apphub deploy <application-id> --revision <revision> --wait --json`. An MCP-connected agent uses the equivalent `applications_create` and `deployments_create` tools — see [Connect an agent over MCP](connect-an-agent-mcp.md).

## After the first deploy

- **Applications** lists everything you own (and, for administrators, every application in the workspace), with status, target, and revision.
- Opening an application shows its **Overview**, **Settings**, **Secrets**, **Resources**, **Domains**, and (if enabled) **Vulnerabilities** tabs.
- Editing the specification in **Settings** and saving creates a new revision; it takes effect on the next deployment, not automatically. See [Deployments](deployments.md).

## Next steps

- [Concepts](concepts.md) for the vocabulary used throughout the portal.
- [Access and exposure](access-and-exposure.md) for what "public" and "private" actually mean.
- [Owners and roles](owners-and-roles.md) to add teammates to the application.
