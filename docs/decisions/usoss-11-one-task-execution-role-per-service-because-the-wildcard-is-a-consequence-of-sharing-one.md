## USOSS-11 — one task execution role per service, because the wildcard is a consequence of sharing one

The source system gives every application the same ECS task execution role
(`container.go:742` reads `clusterConfig.TaskExecutionRoleARN`), and Terraform
grants that one role `ssm:GetParameter` and `ssm:GetParameters` on
`…:parameter{ssm_prefix}/apps/*` — the statement is labelled `ReadAppSecrets`
(`terraform/modules/ecs/iam.tf:30-49`). Every deployed application's ECS agent
can therefore read every other application's secrets.

The wildcard is not an independent mistake, and that is the whole point of this
entry: **with one role shared by every service, a grant scoped to one service's
parameters would break every other service.** The wildcard is the only thing
that works under that design, so narrowing it is not a fix — it is a change that
would be reverted the first time a deploy failed. Per-service roles are what
make least privilege *expressible*.

So this port creates one execution role per service, carrying only what starting
that service requires: the read grant for exactly the parameter ARNs the service
binds, pull access to exactly the repository its image lives in, and log-write
scoped to its own log group. The read grant is produced by the secret store
rather than by this port, because only the store knows what reading one of its
parameters requires — and this port checks the document it is handed for a
wildcard resource before attaching it, because that property is the difference
between the two designs and is not one to take on trust across a seam.

The cost is real and is not hidden: one IAM role per service consumes an
account-level quota, and an operator with thousands of services will feel it. A
shared role that can read every tenant's secrets is not an acceptable way to
save quota.
