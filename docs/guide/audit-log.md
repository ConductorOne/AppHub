# Audit log

Workspace administrators can review recent mutations across the workspace from **Workspace → Audit log**.

## What's recorded

Each entry carries safe metadata: the actor, the action, the target, and allowlisted details such as deployment state, role, or feature flag mode. Entries never include request bodies, credential values, or application secret payloads. Audited changes and their audit entry are written together, in one transaction; if the audit table is unavailable, the change itself is blocked rather than going unrecorded.

Directory group sync writes one `directory.sync` entry per successful run (with group, written, and removed counts), not one entry per group — a recent entry is a sign the sync loop is running. Ephemeral login challenges, membership-cache refreshes, and unchanged worker heartbeats are excluded. Worker cloud effects show up as the durable deployment checkpoints they already produce, not as a separate event stream.

Entries are stored in a separate table from application state and are not exposed to non-administrators through any surface. They're eligible for removal after 400 days; because the underlying deletion is asynchronous, that's an eligibility window, not an exact retention boundary.

> [!NOTE]
> This is a workspace-wide administrative log, distinct from an individual application's **Activity** tab, which does not record anything yet — deployment history for one application is on its **Overview** tab instead.
