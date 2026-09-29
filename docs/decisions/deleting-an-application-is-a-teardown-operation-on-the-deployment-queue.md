## Deleting an application is a teardown operation on the deployment queue

An owner or administrator deletes an application with
`POST /api/v1/applications/{id}/deletion`, confirming by its exact name. Every
resource it owns is destroyed: the workload, the database (no final snapshot),
the key-value table, the bucket and every object version in it, its secrets,
its workload identity and its image repository. After them go its hostname
reservations, deployment history, usage and the application record.

### How it runs

* The request queues a `DeploymentRecord` whose `operation` is `teardown`. It
  uses the same queue, claim, lease, heartbeat and attempt fence as a
  deployment. Nothing new was built for durability, and the portal observes it
  through `GET /api/v1/deployments/{id}` like any operation.
* `deploy.Teardown` runs ordered, idempotent steps. An absent resource counts
  as success, so any attempt can be run again from the start.
* Cloud deletes are asynchronous, so a step retries `compute.ErrTransient` with
  capped backoff until the attempt's `teardownTimeout` (default 60m). The RDS
  instance, cluster and subnet-group state faults and EC2 `DependencyViolation`
  are classified as transient for this reason. Any other failure stops the
  teardown at that step immediately.
* A teardown whose worker stops, or whose deadline expires, is requeued rather
  than interrupted, up to `controlplane.MaxTeardownAttempts`. A deployment in
  the same situation needs an operator, because its outcome is uncertain. A
  teardown's outcome is not uncertain: it is only ever "less deleted".
* A failed teardown keeps the application's lock (`activeDeploymentId`). A
  part-deleted application must never be edited or deployed, and every write
  path already refuses a locked application. Calling the endpoint again with a
  new idempotency key replaces it with a new teardown; that is the retry.
* A never-deployed draft owns nothing outside the control plane. It is deleted
  in the request, which returns 204.

### Alternatives refused

* **A separate record kind for teardowns.** It would need its own queue index,
  query shape, claim and reaper, all restating the deployment's fencing.
* **Emptying buckets inside `DeleteBucket`.** That port deliberately refuses to
  delete data as a side effect. `EmptyBucket` is its own explicit, destructive
  operation, which a teardown calls on purpose.
* **Idempotency records deleted with the application.** They are filed per
  principal and cannot be enumerated by application. A replay resolves to an
  application that no longer exists and returns 404.
