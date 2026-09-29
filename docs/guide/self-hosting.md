# Self-hosting

This page is a map, not a manual — the manuals already exist and this guide doesn't duplicate them.

> [!IMPORTANT]
> AppHub is pre-alpha with no supported upgrade path. Treat any instance, including one you stand up yourself, accordingly.

## What you're standing up

An AppHub deployment is three processes plus your own infrastructure: the `apphub serve` API (the control plane and the portal's backend), a dedicated `apphub worker` that does the actual cloud work (builds, provisioning, teardown), and isolated per-build ECS tasks the worker launches. The diagram in [Concepts](concepts.md#how-it-fits-together) shows how these pieces connect; the rest of that page covers how they map onto applications, targets, and deployments.

## Running it on AWS with Terraform

The reference deployment is Terraform: one API service, one worker service, isolated build tasks with no task role, and Traefik plus oauth2-proxy in front of published applications. Start with [`terraform/README.md`](../../terraform/README.md), which covers bringing an environment up, how builds are isolated, secrets handling, and what the Terraform module deliberately does not do (autoscaling, custom domains, more than one worker's worth of build concurrency, and so on).

## Configuring the server and worker

Both processes read one shared, strictly-validated YAML configuration (auth providers, storage, targets, source repositories, and more). The full schema and every section's meaning is documented in the root [`README.md`](../../README.md#operator-configuration), including local development setup (`make infra-up`, `make config-init`, `make dev`) if you'd rather run everything on your own machine first.

## Becoming the first administrator

Nobody is an administrator on a fresh deployment — email is never used to identify one. Sign in once with any admitted identity, copy the "Subject" value shown at **Settings → Signed-in identity**, and add it as an explicit `(providerId, subject)` pair to the server configuration (`auth_admins` in Terraform, or `auth.admins` in `server.yaml`), then restart the API. From there, see [Owners and roles](owners-and-roles.md) for assigning roles to everyone else, ideally through a synced identity-directory group rather than one entry per person.

## Reference

- [`terraform/README.md`](../../terraform/README.md) — infrastructure shape, bringing an environment up, build isolation, secrets, and what it doesn't do.
- [`README.md`](../../README.md) — operator configuration schema, local development, and the CLI/MCP verification checklist.
- [API reference](api-reference.md) — the external HTTP contract this instance serves.
