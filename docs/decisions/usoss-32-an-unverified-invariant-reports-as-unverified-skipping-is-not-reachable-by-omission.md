## USOSS-32 — An unverified invariant reports as unverified; skipping is not reachable by omission

*Recorded from the USOSS-32 fix to `compute/conformance`. Two checks reported
success on providers they had not tested, which is the defect class this project
has paid for most often: a gate reporting success on exactly the input it was
built to reject.*

### The rule

**A check may legitimately have nothing to drive. When that happens it says so,
by name, in the place every other unverified invariant is counted — and it never
produces the same observable outcome as a check that drove something and found
nothing wrong.**

Three consequences, in the order they bite:

1. **Non-emptiness is asserted, not assumed.** A check that planted no sentinel,
   exercised no port, or induced no failure fails. `checkTransientIsNotTerminal`
   used to accept a nil error as "the provider absorbed a retryable failure,
   which the contract allows" — true, and it means a hook that induces nothing is
   indistinguishable from a mapping that is right. It now fails unless at least
   one of the methods it drove surfaced `compute.ErrTransient`.
2. **What a check can drive is derived, never restated.** The old gate tested
   `CapSecretStore`, "because a secret Put is the cheapest write on any
   provider". That condition is a hand-maintained restatement of *what can I
   write with*, and it drifted: five of the six AWS ports have no secret store,
   so the only check guarding the substrate-error → `ErrTransient` mapping did
   not run for them at all. The drivable set now comes from the port interfaces
   in `compute` — themselves derived from `compute.Provider`'s accessors — and
   the residue that cannot be derived is named with a reason and pinned
   generatively, in both directions, by `TestEveryPortMethodIsDrivenOrNamed`.
3. **Where a skip is genuine, it is a named skip and not a pass.** A provider
   with no port that can be handed secret material cannot leak any; what it
   cannot do is stand as evidence that the invariant holds.
   `checkSecretsNotInRendered` used to scan for a sentinel nobody had stored and
   report a pass — counted as coverage of a security invariant. It now reports
   `NOT VERIFIED`, naming the ports it looked for and why none qualified.

### A per-service mapping cannot be checked at one call site

The retry gate drove one `SecretStore.Put`. A provider that reached
`ErrTransient` from its registry and `ErrFailed` from its identity service passed
it, and six AWS providers are writing that mapping independently. The gate now
drives every method of every port the provider has — 39 methods across 10 ports
for the reference provider, 20 across 6 for one shaped like the Kubernetes
falsification exercise, 10 across 3 for a provider with no secret store, against
1 and 1 and 0 before. Whatever a provider's hook cannot reach is recorded as a
contract observation naming the methods, so a hook that only arms writes is
visible in a green run instead of looking like coverage.

### The derivation itself has two outcomes, not three

Lesson 9 applies to the recogniser as much as to the gate it feeds. The walk that
decides whether a port can be handed material is structural, so an interface
argument is opaque to it — and returning "no secret material here" for a type it
cannot see through would put the check straight back to scanning for a sentinel
nobody planted. So every kind is handled explicitly and anything else is an
error the check reports as a failure. The two interfaces that do appear,
`context.Context` and `io.Writer`, each have their decision written down where
the walk stops. A third would fail the derivation rather than quietly widen it.

That exercise found something: `compute.BuildRequest.Logs` is an `io.Writer`, and
the decision recorded for it is about *ingress* only. A build log is exactly
where the source system leaks a credential, `compute.ImageBuilder` carries a
documented obligation not to put builder output in an error because of it, and
**nothing in this suite observes what a provider writes there** —
`ImageBuilder.Build` is not driven by any check at all. That is named in
`undrivenPortMethods` rather than left implicit, and it is a bigger gap than this
change closes.

### What this does not claim

`checkSecretsNotInRendered` was **not** vacuous for every provider, and the
ticket's premise that it was is corrected here. USOSS-26 falsified it by breaking
the check rather than by arguing about it: the secret port's own lifecycle checks
store secrets whose value *is* the sentinel, and the substrate is shared across a
run, so the scan has teeth as soon as the provider has a secret store — with or
without a container runtime. That behaviour is now pinned by a fixture so the fix
for the vacuous case could not quietly remove it. What the check no longer does
is depend on a *different* check having run first for its teeth: it plants
deliberately, through every port the interface says can carry material.
