## USOSS-17 — v1 ships direct invocation, and no dispatcher at all

`agent_scan.go:28-36` documents two dispatch modes: an in-process goroutine when
`JOB_MODE=local`, and a Fargate one-shot through `cmd/job-runner` when
`JOB_MODE=sqs`. The ticket asked what the open-source repository ships.

**It ships neither. It ships a module, and the host decides how to call it.**

### The premise checks out

The ticket said the queue coupling lives in the runner rather than the module,
and it does. `grep -rn JOB_MODE backend/internal/modules/` in the source tree at
`b626d3497057955d222da805be5be81ba6109876` returns **three** lines, and all
three are comments: `security/agent_scan.go:31,32` and
`deploy/container.go:705`. No module reads the variable. The port is therefore
free of the question, and this decision is about what to add rather than about
what to remove.

### Why nothing is added

`Execute(ctx, userID, params)` is already the whole dispatch contract. Anything
that can call a function can dispatch this module: a request handler calling it
inline, a goroutine, a queue consumer, a one-shot container. Progress reaches an
asynchronous caller through `modules.WithProgress` without the module knowing
one is there, and the record the module writes to is what a caller polls. A
dispatcher shipped here would be a fourth opinion about queues in a repository
whose adopters have their own.

The Fargate path specifically is out of v1. Its shape — run this module once, in
a container, somewhere else — is a compute concern, and `compute/` is where a
capability like that belongs if it returns. It is not designed here, and no
part of this port assumes it.

### The rule this makes explicit

**No library code in this repository reads an environment variable.** The
modules take their configuration as constructor arguments and their parameters
as an argument to `Execute`; there is no third channel. That is not a
restatement of the source's behaviour, it is a correction of it — three of the
files ruled out of scope below read four environment variables between them
(`deepsec_sandbox.go:55`, `deepsec_scan.go:296,300,319`) — and it is what lets a
host configure two differently-bounded instances of the same module in one
process, which reading a process-wide variable cannot express.
