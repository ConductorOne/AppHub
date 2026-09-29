## USOSS-60 — A population inferred from an outcome is not a derived population

*Recorded from the USOSS-60 fix to `compute/aws`'s failure injector. The fix is
four lines; the near-miss beside it is the reason this entry exists.*

### The defect

`Harness.FailNext` armed exactly one call, because `take()` cleared the injected
error on the way out. The conformance suite's retry gate drives every method of
every port inside **one** armed window, so the first intercepted call consumed
the arming — whichever verb it happened to be — and every method after it saw a
healthy substrate and was scored as unexercised. Measured on `compute/aws`: **2
of 6 driven methods surfaced the induced failure; with the fix, 6 of 6.**

The one-shot semantics are not a bug and are kept. A single induced failure whose
retry succeeds is exactly what `conformance.Options.InduceTransient` documents,
and a caller that arms one failure to assert its retry works would, under sticky
semantics, be asserting nothing. So `FailUntilStopped` is a **second** method
rather than a change to the first: adding a capability, not mutating a contract.
`TestFailNextIsStillOneShot` pins that.

### The near-miss, which is the point

The first diagnosis was *the injector is consulted by writes and not by reads*.
It came from the shape of the results across three providers — every port showing
only its first method verified — and the convergence across three independent
implementations made it feel derived rather than guessed.

It was false. With an arming in place, a `DescribeRepository` **alone** surfaces
the induced failure, and the one immediately after it does not. Reads consult the
injector; the arming was simply gone.

Both hypotheses predict the identical symptom. Only a measurement separates them,
and **widening the hooks to reads would have changed nothing while shipping as a
fix that reported coverage which had not improved** — a green diff, a plausible
story, and the same 2 of 6.

So, as a rule distinct from the ones already recorded here:

> **A population inferred from an outcome is not a derived population.** Deriving
> a set from the code is one thing; inferring the shape of a set from the results
> of a check over it is guessing with a denominator attached. Convergent evidence
> across several implementations raises confidence in the *symptom*, never in the
> *mechanism*.

### Two corollaries this ticket paid for

**A test can pass for the wrong reason and look like the fix.** The first
acceptance test here gave each method a fresh provider and its own arming, and
passed **6 of 6 with the one-shot injector still in place** — verifying six
mappings while saying nothing about the ticket, because one arming is enough for
one call. Only driving every method under a *single* arming distinguishes the fix
from the defect. A test written against a defect has to be run against the defect.

**An injection that never fired is not evidence.** "No induced failure surfaced"
and "this method handles it correctly" are the same silence from outside, so
every case asserts the arming was *observed* to be consumed. Without that, the
whole construction passes against a harness whose arming does nothing.
