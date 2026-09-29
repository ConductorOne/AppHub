## USOSS-6 — a module's `Result` and its `error` are independent

Recorded because review found the opposite asserted in a doc comment, and
because this binds every module USOSS-15 and USOSS-17 port.

`Execute` returns `(*Result, error)`. **Neither implies anything about the
other.** A module that got part of the way and then failed returns both: the
error reports the failure, and the `Result` carries what actually exists. The
ported Lambda deploy module does exactly this when the function is created but
its load balancer cannot be attached (`deploy/lambda.go:328-332`) — the result
carries the function and role identifiers alongside a non-nil error, because
that state is real and a caller needs it to clean up or resume.

`Success` is likewise the module's own statement about the outcome and is not a
restatement of `err == nil`. Neither may be derived from the other.

### Where the wrong version came from, stated precisely

The first version of `modules/module.go` documented the reverse — a non-nil
error paired with a nil `Result`, and `Success: false` as a "handled" failure —
and an earlier version of *this entry* called that invented and said nothing in
the source obeys it. Both of those statements are wrong, and they contradicted
the evidence assembled further down this entry, which is worse than being simply
wrong: a record that argues against its own evidence gives a reader no way to
tell which half to believe.

What is actually true, out of the nine `Execute` implementations:

| | Count |
| --- | --- |
| Return a populated `Result` **with** a non-nil error | 1 of 9 (`deploy/lambda.go:328-332`) |
| Can return `Success: false` **with** a nil error | 1 of 9 (`announce/delivery.go:222-232`, computed from a rolled-up status) |
| Ever return a `Success` that is not the literal `true` | 2 of 9 (the two above) |

So most ordinary failure paths *do* return `(nil, err)`, which is why the
convention looked right. It is simply not universal, and both diagonals it
forbids occur.

And the convention was not invented. `cmd/job-runner/main.go:568-575` states it
almost word for word — "Modules conventionally return a non-nil \*Result on
success and (nil, err) on failure" — immediately adding that "the contract isn't
enforced by the types.Module interface". So the mistake was not fabrication. It
was **treating one entrypoint's comment as stronger evidence than the nine
implementations**, and promoting an explicitly unenforced convention into a
binding interface contract that one module already broke.

That is the more dangerous error of the two, because it reads as sourced and so
does not invite re-checking. It is also the exact failure the procedural rule
below was rewritten to catch: a citation existed, and a citation was not enough.
`modules/module_test.go` pins both diagonals, so enforcing the narrow convention
now breaks a test.

### The related source finding

The source has **five** non-test call sites that invoke a module, and **all
five** lose a partial `Result`:

| Call site | userID passed | How the `Result` is lost |
| --- | --- | --- |
| `internal/services/modules.go:187` | `user.ID` | branches on `err` first, returns HTTP 500 without reading it |
| `internal/jobs/runner.go:88` | `job.CreatedBy` | reads `result.Data` only on the success branch |
| `internal/services/repo_audit.go:1262` | `audit.RequesterID` | assigned to `_` — discarded unconditionally |
| `internal/services/repo_fix.go:660` | `fix.RequesterID` | assigned to `_` — discarded unconditionally |
| `cmd/job-runner/main.go:540` | `""` | branches on `execErr`, reports a sanitised failure, exits |

So the partial state the deploy module deliberately assembles is lost on every
path, and none of the five inspects the *kind* of error it got. That is a bug in
the source rather than in this port, it is reported rather than fixed here, and
it is why the caller obligation is written into the interface doc instead of
left to be inferred.

One more thing from the same enumeration: `cmd/job-runner/main.go:540` passes an
**empty** userID, so a module cannot assume it has a requester at all.
