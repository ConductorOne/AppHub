## USOSS-40 — the taxonomy has a permission sentinel, `compute.ErrNotPermitted`

*Amendment to the Compute interface, the sixth. Raised by USOSS-13 while porting
S3, ruled on by the supervisor, and implemented here.*

A substrate authorization failure — an IAM `AccessDenied`, a Kubernetes RBAC
rejection, an organization guardrail, a resource policy — now maps to
**`compute.ErrNotPermitted`** rather than to `compute.ErrFailed`.

### Why the old position was untenable

`ErrFailed` says the resource "reached a terminal failed phase" and is "not
retryable without changing the spec". Both halves are false for a denial: no
resource reached any phase, and no spec change helps. What has to change is a
policy the *platform itself* runs under, which is an operator's job and a
different person from the one who owns a failing application. So a surface above
this interface could not route a permission failure to the operator and a resource
failure to the application owner without parsing prose.

And prose is per-port. USOSS-13 found this while writing the fourth AWS provider,
with USOSS-11, 12, 14 and 26 each about to write denial handling of their own —
six spellings of one idea, which is the specific thing a shared taxonomy exists to
prevent. That timing is why this landed as an amendment rather than as a note.

### The name

`ErrNotPermitted`, following `ErrNotOwned`'s convention: it describes the
situation from apphub's own point of view — *we* are not permitted — rather than
naming a substrate status code. That convention is not cosmetic here. `ErrConflict`
was renamed to `ErrNotOwned` because "the name was the trap", and the trap
available to this sentinel is direction: a name like `ErrDenied` or
`ErrPlatformDenied` can be read as "apphub denied *you*", which is the opposite
of what it means and would waste the distinction the amendment exists to make.

### What enforces it

* **A conformance check**, `provider/an-authorization-failure-is-ErrNotPermitted`,
  which asserts not only that a denial matches the new sentinel but that it does
  *not* also match `ErrFailed`, `ErrInvalidSpec` or `ErrTransient` — the three
  that send a reader to the wrong place.
* **An injected defect**, `fake.DefectDenialIsTerminal`, and an entry in the
  suite's own defects table. A check nobody has shown to fail is an assertion, and
  USOSS-32 found this hour that the `ErrTransient` gate has no such entry — so the
  new gate ships with one, verified in both directions: neutering the defect fails
  the table, and neutering the check fails the table.
* **A derived sentinel set.** `compute/contract_test.go` used to assert
  distinctness over six sentinels somebody had written out, which would have
  silently excluded this one. It now type-checks the package and enumerates the
  package scope for exported variables assignable to `error`, then cross-checks
  that against the map the properties run over, so a sentinel added later cannot
  sit outside every property. Both directions of that cross-check have a fixture.
  The file set is read from the directory rather than named, so a sentinel is
  found wherever it is declared; an earlier version walked the syntax of
  `compute/errors.go` alone and review defeated it twice, once with an alias and
  once with a sentinel in a sibling file.

### The new hook takes a kind, and that is deliberate

`Options.InduceDenial` takes the `compute.Kind` the suite is about to drive, so the
check can exercise whichever port the provider actually has. `Options.InduceTransient`
cannot, which is why its check is pinned to a secret `Put` — "the cheapest write on
any provider", true of a provider that has one, and five of the six AWS providers do
not, so the only gate on their transient mapping does not run (reported by USOSS-10).
Giving `InduceTransient` the same treatment would touch every provider's options and
is left as its own change.

### Known gap this does not close

> **Closed since.** Both halves of the gap below are now shut: `compute/aws` in
> USOSS-55, and `compute/k8s` in
> [USOSS-70](usoss-70-each-substrate-names-its-own-denial-and-the-hook-arms-exactly-one.md),
> which found that the skip had been hiding a wrong mapping on all three of that
> provider's substrates rather than an unverified correct one. The paragraph
> stands as what was true when this record landed; a Kubernetes 403 no longer
> lands on `ErrFailed`.

No provider maps denials to the new sentinel yet. `compute/k8s` supplies no
`InduceDenial` hook, so the check skips there and is recorded as unverified rather
than passing — a Kubernetes 403 still lands on `ErrFailed`, and closing that
belongs to USOSS-19. `compute/aws` adopts it in USOSS-13's rebase. The sentinel and
its gate land first on purpose: a provider cannot map to a sentinel that does not
exist, and every day it does not exist is another port writing prose.
