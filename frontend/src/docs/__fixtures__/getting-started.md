# Getting Started

This page walks through installing the CLI, deploying your first application, and where to go
next for configuration.

## Installation

Install the CLI with your package manager of choice, then confirm it works with `apphub --version`.

### Prerequisites

You will need a **GitHub account** with access to the *conductorone/apphub* repository, and Docker
installed locally.

- Node.js 24 or newer
- Docker Desktop or an equivalent container runtime
- A GitHub personal access token with `repo` scope

## Deploying your first app

Follow these steps in order.

1. Create a new application from the [Applications](getting-started.md) page.
2. Configure your build settings, then read the [Configuration](configuration.md#build-settings) guide.
3. Trigger a deployment and watch its status in the workspace.

## Installation

A second "Installation" heading, to confirm heading id deduplication works.

> [!NOTE]
> AppHub polls GitHub for new commits every 60 seconds by default.

> [!TIP]
> **Skip the wait**
> Trigger an immediate sync from the application's overview page.

> [!IMPORTANT]
> Deployments require an owner or admin role on the application.

> [!WARNING]
> Rotating a deploy key invalidates all outstanding builds using the old key.

> [!CAUTION]
> **Danger zone**
> Deleting an application also deletes its build history and cannot be undone.

## Reference table

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | string | yes | Must be unique within the workspace |
| `region` | string | no | Defaults to `us-east-1` |

See the full [CLI reference](cli-reference.md) for command-line flags, the
[Terraform README](../../terraform/README.md) for infrastructure setup, and the
[AppHub GitHub repository](https://github.com/conductorone/apphub) for source code.

```bash
apphub apps create --name my-app --region us-east-1
```
