# Deployments

A deployment is a durable, asynchronous operation that takes one exact application revision and converges it: resolve the source ref to a commit, build the container image, provision or update attached resources, and run the workload.

## Submitting one

From an application's page, **Deploy** (or **Redeploy**, once a deployment has succeeded before) submits a deployment of the application's current revision. You land on the operation's page, which polls its status every two seconds and shows an operation log built from real step/progress transitions — never fabricated. Closing the page does not cancel the deployment.

Only one deployment (or teardown) can be active on an application at a time; editing the specification or submitting another deployment is blocked until it settles.

## States

| State | Terminal? | Meaning |
| --- | --- | --- |
| `queued` | No | Accepted, waiting for a worker to claim it. |
| `running` | No | A worker is actively converging the application. |
| `succeeded` | Yes | For a service, the requested replicas became ready and old replicas finished draining. For a scheduled job, the schedule was installed — this does **not** mean a run of the job has succeeded. |
| `failed` | Yes | The operation did not complete. Review the reported step, error code, and message; a new deployment is a new operation, not a resume from the failed step. |
| `interrupted` | Yes | The outcome is uncertain (typically a lost worker). Resources may have changed; there is **no automatic retry and no rollback**. |

## There is no rollback

A failed or interrupted deployment does not revert the application to its previous state. Partial resources from that attempt are retained, not cleaned up automatically. To recover, fix the issue (in the repository, the specification, or infrastructure) and submit a new deployment — which is a new operation from the start, not a resume.

An `interrupted` deployment additionally keeps its execution lock and will never rerun on its own. It requires an administrator to independently confirm the old worker and its build container have stopped, then run:

```sh
apphub deployments resolve-interrupted <operation-id> --worker-stopped --reason "<explanation>"
```

This records the acknowledgement and releases the lock — it does not mark the deployment successful, and it does not delete or recover anything by itself.

## Deleting an application (teardown)

Deleting an application is the same durable-operation machinery run in reverse. It runs these steps, in order, for whatever the application actually has:

1. Stop the workload (service replicas, or the scheduled job's future runs).
2. Delete the relational database or key-value table.
3. Empty and delete the object storage bucket.
4. Remove secrets.
5. Remove the workload's identity.
6. Remove container images.
7. Remove AppHub's own records for the application.

Data is destroyed with no snapshot, and the confirmation dialog requires typing the application's exact name. Deletion is safe to retry: steps already completed are skipped. A deletion that fails can be retried from the application's page; a deployment in progress blocks starting a deletion until it finishes.

## Scheduled jobs

A scheduled execution mode installs a schedule (a rate expression or five-field cron, in a chosen timezone) rather than running a workload continuously. A successful deployment means the schedule was installed, not that any particular run has completed — there is no per-run status in the portal.
