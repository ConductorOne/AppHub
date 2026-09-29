## USOSS-52 — The error-content invariant is driven by the package it constrains, not by a central list

*Recorded from USOSS-8 declining to widen the c1-optional allowlist for a test
fixture, and restating the whole invariant inside `credentials/c1` instead. That
was the right call and it left two packages holding the same machinery. This is
the fix it named in its own report.*

### The rule

**`internal/errhygiene` is an importable helper, and a package states the
error-content invariant over itself.** A package that returns errors declares an
`errhygiene.Subject` in its own external test and calls `errhygiene.Assert`.
Nothing imports the package under test.

### Why the previous shape could not hold

The invariant is:

> No error a package returns contains any text that did not come from a constant
> in this repository, a numeric count, or a Go type name.

Driving an entry point means calling it, and calling into a package means
importing it. So a central fixture's package list was also a list of imports, and
that failed twice over.

**It failed on the boundary.** `credentials/c1` is the one package nothing may
import — the `c1-optional` rule deliberately covers first-party *test* imports so
that a test cannot be the wedge that widens it — and it is also the package most
in need of the check. Stating the invariant over it from outside needed a second
allowlist entry. USOSS-8 declined to spend one on a fixture: the allowlist derives
its value from being narrow, and spending an entry on tooling is the cheapest
possible way to make it less so.

**It failed as a list.** Every package with an error surface needs this check, so
a central list of packages is a hand-maintained restatement of *which packages
have errors*. It grows, and it goes stale like any other hand-maintained list.

Reversing the direction fixes both at once. `credentials/c1` importing a test
helper is not the thing `c1-optional` denies; `c1-optional` denies importing
`credentials/c1`. The allowlist is unchanged, which
`TestC1AllowlistPermitsOnlyTheNamedCompositionRoot` and `go run
./hack/boundarycheck` both still say.

### What is kept, because it was learned the hard way

* **Both population derivations.** USOSS-7 landed two, obtained different ways.
  The `go/types` surface guards against the derivation narrowing; a `go/parser`
  sweep applying no build constraints guards against the population being wrong,
  and review proved the point by adding a `//go:build windows` file with an
  exported input that every `go/types` check passed. A cross-check that shares the
  derivation's blind spot is not a cross-check.
* **The accounting check is a second traversal, not a counter.** A count kept
  inside the derivation drops in step with any narrowing of the derivation, so it
  would agree with itself. Two traversals cannot.
* **Exemptions are per driver, never per type.** An exemption that propagates
  through composition is not the exemption that was documented — a real defect
  found on the PR that introduced this fixture, where a `Metadata` exempted by
  type was walked out of an error it had been nested inside.
* **Two equal-length sentinels sharing no byte at any position.** Containment
  alone is below the resolution the failure lives at: the leak that defeated the
  first version quoted exactly one byte of its input.

### What a package now has to say out loud

A derived set that is empty passes every check made over it, so a subject names
the populations it claims are empty (`Subject.EmptyPopulations`) and the claim is
checked in both directions. `credentials/c1` declaring that it has no type with a
rendering method used to be a bespoke test in that package; it is now one line
that fails the moment a type there grows an `Error`, `String`, `Format` or
`LogValue` method.

### What did not move, and why

`internal/errhygiene` keeps its own reflective walk rather than calling
`internal/reachable`, which USOSS-59 made the single walk for leak and
recombination checks. The two answer different questions. `internal/reachable`
asks "what bytes are reachable", in any order, for a recombination attack on one
value. This one compares two runs of the same driver **slot for slot**, and the
pairing is what buys the one-byte resolution — which needs a deterministic slot
order, so it sorts map keys, which `internal/reachable` deliberately does not do
because ordering buys its question nothing. Unifying them means changing a
security-critical shared walk to serve this one. That is a larger change than the
ticket that produced this entry, and it is named here rather than done quietly.
