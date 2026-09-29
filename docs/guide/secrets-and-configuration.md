# Secrets and configuration

Configuration reaches your application only through environment variables — there is no other config channel, and no `apphub.yaml` or similar file in your repository.

## Variables AppHub sets for you

Set automatically, only when the matching resource is attached (see [Databases and storage](databases-and-storage.md) for what each holds): `TABLE_NAME`; `BUCKET_NAME` and `BUCKET_URI`; `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`.

Read these at startup and fail with a clear message if one your code needs is missing, rather than silently falling back to an anonymous or local default in production.

## Owner-managed secrets

From an application's **Secrets** tab, an owner can add, replace, or delete extra environment variables:

- Names must match `^[A-Z_][A-Z0-9_]*$` (uppercase letters, digits, underscore; starting with a letter or underscore), at most 100 characters.
- A name cannot be `PORT`, `TABLE_NAME`, `BUCKET_NAME`, or `BUCKET_URI`, and cannot start with `DATABASE_`, `APPHUB_`, `AWS_`, or `ECS_` — those are reserved for AppHub's own injected variables.
- Values are at most 4096 bytes each; an application can hold at most 50 secrets; one save can total at most 48 KiB across all its changes (save the rest in a second pass if you hit that).
- Secrets are encrypted at rest and decrypted only inside the running container. Once saved, a value cannot be viewed again through the portal, CLI, or MCP — only replaced or deleted.

Saving secret changes deploys them immediately: it rolls out a new task definition reusing the image from the last successful deployment (no rebuild), unless the current revision has never deployed successfully, in which case it's built first. Editing secrets requires both `applications:write` and `deployments:write` permission, and is locked while a deployment is already active.

> [!NOTE]
> If an operator hasn't configured AppHub's secret handoff key, the Secrets tab is read-only: you can see the names of any existing secrets but cannot add, replace, or delete them.

## What you cannot configure this way

There is no general-purpose "add a custom environment variable that isn't a secret" field yet — every operator-supplied value that isn't a resource variable goes through Secrets, whether or not it's actually sensitive.
