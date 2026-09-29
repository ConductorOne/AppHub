# Concepts

The vocabulary AppHub uses across the portal, the CLI, the API, and MCP tools.

## How it fits together

![AppHub architecture](images/architecture.svg)

You reach AppHub itself (the portal, the REST API, and its MCP endpoint) through the API service. Submitting a deployment records it as queued; the worker picks it up, fetches the source from GitHub through the AppHub GitHub App, builds the image in an isolated build task, pushes it to the application's own image repository, and then creates or updates the application's service and everything attached to it.

Visitors reach a deployed application at its own hostname. Every request passes the platform sign-in first, so the application only ever sees signed-in users. See [Access and exposure](access-and-exposure.md) for how that sign-in works, and the sections below for what an application, target, and deployment are.

## Application

An application is one deployable unit: a container built from a GitHub repository, plus the resources attached to it (database, bucket, secrets) and how it's exposed. It has a stable ID, a name, one or more owners, and a current **specification** (everything above) at a given **revision**.

Editing an application's settings creates a new revision; it does not deploy anything by itself. A revision only takes effect once a deployment submits it.

## Target

A target is an operator-configured deployment destination: a region, an ECS cluster, approved resource sizes, execution modes, database/bucket kinds, and whether public exposure is allowed. Every application is deployed to exactly one target, chosen at creation and fixed afterward. `/api/v1/targets` (or the `targets_list` MCP tool) lists the targets available to you, each marked `ready` only when its worker's descriptor matches the API's configuration.

Workspace administrators can see every target's full configuration on **Workspace → Infrastructure**.

## Deployment (operation)

A deployment is a durable, asynchronous operation that takes one exact application revision and converges it: resolve the source ref to a commit, build the image, provision or update attached resources, and run the workload. Submitting a deployment returns immediately with a `queued` operation; the portal, CLI, and MCP tools all poll it until it reaches a terminal state.

Deployment states: `queued`, `running`, `succeeded`, `failed`, `interrupted`. Only the first two are nonterminal. See [Deployments](deployments.md) for what each terminal state means and why there is no automatic rollback.

Deleting an application is also a deployment-like operation (a **teardown**) rather than an instant action — it runs the same durable-operation machinery in reverse, removing every resource the application owns.

## Execution mode

- **Service** — a long-running container. It gets 1 to the target's `maxReplicas` replicas, and (depending on exposure) a route.
- **Scheduled** — a run-to-completion job installed on a schedule (a rate expression or five-field cron, with a timezone). A successful deployment here means the schedule was installed, not that a run has succeeded — see [Deployments](deployments.md).

## Exposure

Every application is **private** (reachable only inside the organization's network, on targets that offer an internal route) or **public** (reachable over HTTPS at an operator-managed hostname). Both sit behind the platform's own sign-in; neither exposure lets an application skip authentication. See [Access and exposure](access-and-exposure.md).

## Database and object storage

An application may attach at most one database (relational PostgreSQL, or a DynamoDB-style key-value table) and one S3-backed bucket. AppHub creates and names these resources; the application never supplies or references a raw resource name. See [Databases and storage](databases-and-storage.md).

## Owners

Owners are the users and directory groups who can edit, deploy, and delete an application, and manage its other owners. Every owner has equal control; a group owner makes everyone in that group an owner. See [Owners and roles](owners-and-roles.md) for owners versus workspace-wide roles.

## Category

An optional label (from a fixed, operator-defined list) used only to group applications on the Home page. It has no effect on infrastructure or behavior.
