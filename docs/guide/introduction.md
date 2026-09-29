# Introduction

AppHub takes a GitHub repository and runs it: it builds the repository's Dockerfile, deploys the image to AWS ECS Fargate, and gives you a URL behind your organization's sign-in.

> [!IMPORTANT]
> AppHub is pre-alpha. There is no release or supported upgrade path, and the deployment shown in this guide may be an operator's own trial environment. Confirm with your administrator before relying on it for anything important.

## What it does

- Builds a container image from a Dockerfile in an approved GitHub repository. There is no build-time configuration file (no `apphub.yaml`) and no build arguments — the Dockerfile is the whole contract.
- Runs the image as a long-running service or a scheduled job on AWS ECS Fargate.
- Optionally attaches one managed database or table (a PostgreSQL database or a DynamoDB-style key-value table) and one S3-backed object storage bucket, and injects the connection details as environment variables.
- Publishes the application privately (inside your organization's network) or publicly (over HTTPS), always behind sign-in.
- Lets you manage applications from the web portal, the `apphub` CLI, or an MCP-connected agent such as Claude Code.

## What it does not do

- It does not run your database migrations, manage custom domains, or let you set arbitrary infrastructure — see [Concepts](concepts.md) and [Databases and storage](databases-and-storage.md) for what is actually configurable.
- It has no built-in vulnerability scanner yet — see [Vulnerabilities](vulnerabilities.md).
- It does not roll a failed or interrupted deployment back automatically — see [Deployments](deployments.md).

## Where to go next

- New to AppHub: [Quickstart](quickstart.md) walks through deploying an application in the portal.
- Want the vocabulary first: [Concepts](concepts.md) explains applications, targets, revisions, and deployments.
- Deploying with an agent instead of the UI: [Connect an agent over MCP](connect-an-agent-mcp.md).
- Running your own AppHub instance: [Self-hosting](self-hosting.md).
