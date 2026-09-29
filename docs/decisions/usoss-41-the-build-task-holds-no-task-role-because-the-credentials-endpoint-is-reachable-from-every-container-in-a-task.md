## USOSS-41 — the build task holds no task role, because the credentials endpoint is reachable from every container in a task

Binding on `compute/aws`'s hosted build path, and on any later runner that
executes a recipe in a container the platform launched.

USOSS-41 said the build phase gets no credential and the push is a different
process, and shipped that as two ports and a `BuildCommand` with nowhere to put
credential material. `BuildTaskRunner` moves the build off a local container
runtime and into its own ECS task, and that move introduces a way to reopen the
hole that has nothing to do with `BuildCommand` at all.

On Fargate every container in a task shares one network namespace. The task
metadata credentials endpoint — `169.254.170.2`, whose path arrives in
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` — is therefore reachable from **every**
container in the task, including the one running the Dockerfile. So:

> A task role attached for any container's benefit is a credential every
> container can read. There is no arrangement of containers within one task that
> takes it back.

The obvious design this forecloses is the tempting one. A sidecar holding a
small, scoped credential — write this one S3 object, read that one — looks like
it isolates the credential from the builder, and it does not: a `RUN` line
curls the metadata endpoint and has it. The sidecar's separate PID namespace is
irrelevant, because the credential is served over the network the two share.

So the rule is the absence, not an arrangement:

* `BuildTaskRunner.Validate` refuses a task definition whose `taskRoleArn` is
  non-empty, and says why. It runs on every worker start, so a definition
  changed out from under the deployment fails at the next start rather than at
  the next build.
* Nothing the build needs may require a credential. That is what decides the
  transport, below.

### The transport follows from it

The context has to reach the task and the artefact has to come back, and
`compute.BuildSource.ContextDir` already obliges a provider whose builder does
not share the caller's filesystem to transport the context itself and to
document the size at which it refuses.

A presigned S3 URL is the cheapest transport and was rejected. It needs no EFS,
no mount targets and no access points — and it is credential material, in argv
or the environment, of the process executing the Dockerfile. It is a smaller
credential than a registry push token and it is the same shape, which is the
shape this ticket exists to remove. The rule USOSS-41 left behind applies
directly: *prefer a construction that cannot express the violation over a check
that notices one.*

An EFS mount is performed by the Fargate agent before the container starts. The
container is handed a directory. There is no token in it, nothing to read out of
`/proc`, and nothing for a later edit to widen.

### What it costs, stated rather than buried

**One task definition per concurrent build.** A volume is declared on a task
definition, not on a `RunTask` override, so the access point that confines a
build to its own directory cannot be chosen per call. Concurrency is therefore a
fixed set of slots an operator provisions, and the runner blocks for a free one
rather than failing.

**The share is a real filesystem with real failure modes.** A slot is emptied
before a build and confirmed empty after, because a slot is reused and a
leftover file is the next build's input.

**No layer cache, still.** Unchanged from USOSS-41: the cache is a registry
repository and the build phase has no credential for one. The task changed where
the build runs, not what it is allowed to hold.
