# Owners and roles

AppHub separates two things that are easy to conflate: **owners**, who control one specific application, and **roles**, which govern what an identity can do workspace-wide.

## Owners

An application's owners — listed on its **Settings** tab — are the users and directory groups who can open, edit, deploy, and delete it, and manage who else owns it. Every owner has equal control; there's no separate "read-only owner." Adding a directory group as an owner makes everyone in that group an owner.

Rules:

- An application always needs at least one owner; the last owner cannot be removed.
- An application can have at most 20 owners.
- Owner changes are blocked while a deployment is active, and while the application is being deleted.
- Removing your own ownership ends your access to the application unless a group or your workspace role still grants it.

There is no invite flow for AppHub itself — an account is created the first time an identity your organization's provider admits signs in.

## Workspace roles

| Role | Can | Cannot |
| --- | --- | --- |
| Member | View applications and their status; view their own activity | Create or edit applications; request repository detection; see vulnerability findings; change workspace settings |
| App owner | Everything a member can; create applications, request repository detection, edit and redeploy applications they own; see vulnerability findings for applications they own | See findings for applications they don't own; change workspace settings |
| Workspace admin | Everything an app owner can, for every application; manage the GitHub App and deploy targets; view platform system logs | — |

**Vulnerability admin** is a separate grant, not a rank in the table above: it adds cross-application vulnerability finding visibility on top of whichever of the three roles an identity already has, without granting the broader `admin` role. See [Vulnerabilities](vulnerabilities.md).

## Assigning roles

Email is never used to identify an administrator or to merge identities — roles are assigned to verified `(issuer, subject)` identities or, more practically, to synced identity-directory groups.

If your operator has configured directory sync (`APPHUB_C1_DIRECTORY_*`), a workspace administrator can map a directory group to a role from **Workspace → Role assignment**, granting it to every member of that group without editing anyone individually. A group maps to exactly one role at a time; reassigning it moves it. Group membership is refreshed at sign-in and cached for a few minutes, so a change can take a little time to take effect.

Without directory sync configured, an administrator adds individual `(providerId, subject)` pairs directly to the server configuration — see [Self-hosting](self-hosting.md) for how the very first administrator is established on a new deployment.
