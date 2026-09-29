## USOSS-41 — the build phase gets no credential, and the push is a different process

Binding on `compute/aws`, and on any provider that later implements
`compute.ImageBuilder` by running a builder that executes the recipe in a process
it controls.

The obligation in `compute/image.go` says a provider must not expose ambient
platform credentials to a build, and must scope and time-bound whatever it does
expose. PR #18 met it and demonstrated the residue: kaniko unpacks the image into
the container it runs in and shares a PID namespace with the commands it runs, so
a `RUN` line — authored by whoever owns the repository being built — read the
executor's own environment, which held the scoped ECR push credential, and printed
it into a log the caller persists. The answer shipped then was redaction where the
provider consumes builder output. That is a filter over the channels this provider
knows about.

> The credential is not made unreadable to repository-authored code. It is not
> present. A build runs with no registry credential of any kind, and no credential
> for the build exists anywhere until the builder has returned; the push is
> performed afterwards by a process that never executed a line of the Dockerfile.

Concretely, and each of these is load-bearing rather than incidental:

* `BuildCommand` has **no field that can carry credential material**. The
  separation is a property of the type, not of the code that fills it in: there is
  no call site to review, because there is nowhere for a credential to go.
  `PushCommand` and `ImagePusher` are where material and an executable meet.
* The credential is minted **after** the builder returns, not before it. So the
  fifteen-minute lifetime is spent on the push rather than on an
  arbitrarily-long repository-authored build, and during that build there is
  nothing minted for anything to steal.
* The two phases get **separate registry configurations**. The push phase's maps
  each destination registry onto the `ecr-login` helper; the build phase's maps
  nothing, because it has no credential for a helper to find.
* A build that exits zero having written **no artefact mints no credential**. A
  credential exists only when there is something to publish with it.

### What this costs, stated rather than buried

**The registry layer cache is gone.** kaniko's cache is a repository in the
registry; reading and writing it needs a credential, and the build phase has none.
`compute.BuildRequest.Cache` anticipates exactly this — "a provider that cannot
cache should log and proceed rather than fail" — so a cache repository a caller
names is still resolved, still refused if it belongs to somebody else, then logged
and not used. `BuildConfig.CacheTTL` is inert and kept, because the constraint it
encodes is the one any restored caching must satisfy.

The obvious way to keep it was rejected: a second credential scoped to the cache
repository only, handed to the build. Write access to a shared cache repository is
a cache-poisoning primitive — a poisoned layer is code execution inside another
application's image — and read access hands out every cached layer of everything
sharing that repository. The class this decision closes would reopen one notch
smaller. Restoring caching means staging it onto local disk from a phase that holds
the credential, which needs a real kaniko to validate, or BuildKit's
externally-driven cache import/export (USOSS-80).

**A private base image in the operator's own registry no longer pulls.** A
credential-free build can use public base images. This follows from the same fact
and has the same remedies.

**The push binary is operator configuration with an argv contract.**
`BuildConfig.PusherPath` is required, and this provider composes
`push <tarball> <destination>` — crane's grammar. An operator with a different tool,
or with somewhere better to run a push, implements `ImagePusher`.

### What is still open

**Same-user process separation is not isolation.** `ExecRunner` and `ExecPusher`
are subprocesses of one apphub process, one user, one PID namespace. Same-user
processes can read each other's `/proc/<pid>/environ`, so a build that overlaps in
time with a *different* build's push can still observe that push's credential. It
is a large reduction on an unconditional, direct read of the build's own
environment, and it is not zero. Closing it needs the push to run as another user,
in another namespace, or in another container — a property of the deployment, which
is why `ImagePusher` is an interface and why the redaction stays.

**No end-to-end run against a real kaniko.** Kaniko's flags were verified against
its flag registration at v1.28.4 (`--no-push`, `--no-push-cache`, `--tar-path`,
and the validation that makes `--destination` optional only under `--no-push`);
no build was executed. This ticket said so in advance — it is one of the few
items on this project that genuinely needs credentials and infrastructure — and
it remains the outstanding acceptance criterion.

### The rule this leaves behind

> Prefer a construction that cannot express the violation over a check that
> notices one. When the construction lands, the check stays: a mitigation deleted
> because its stated reason was removed is how a closed hole reopens.

`redactingWriter` and `redactCredentials` were kept and re-aimed at the push phase
for exactly that reason, and because the residue above means their reason is not
fully gone.
