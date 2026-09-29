## USOSS-54 — the taxonomy map is a decided population, not every exported error

*Recorded from USOSS-54, which was a red `main`: two PRs that were each green in
isolation and incompatible together. Both artifacts were the same author's, which
is why the taxonomy call and the fix are in one place.*

`compute/contract_test.go` derives the error-sentinel population from the package
with `go/types` — every exported package-scope variable assignable to `error` —
so that a sentinel added later cannot sit outside every property asserted over
the taxonomy. It used to require `sentinels()` to match that population exactly.
It now requires every derived name to be in **exactly one** of `sentinels()` and
`nonTaxonomy()`, which is the change this record is about.

`compute.ErrSecretSerialize` is the first exported error in the package that is
**not** part of the taxonomy. The derivation reported that as a defect, because
until then "exported error variable" and "taxonomy member" had the same answer,
and the derivation can only ask the first question.

### Why this was not fixable by adding a map entry

Adding `ErrSecretSerialize` to `sentinels()` makes every test pass. That was
measured, not assumed — exactly-one-says-try-again, mutual distinguishability, the
wrapped-sentinel property and the denial property are all satisfied by it.

**Which is the argument against doing it.** Those properties are satisfied by any
distinct `errors.New` that does not claim to mean "try again", so passing them is
not evidence of belonging. The map's meaning is carried entirely by its name and
its doc comment, and a member the properties cannot distinguish from an unrelated
error would make the map mean "the exported errors" rather than "the taxonomy". A
green derivation test bought at that price stops describing anything.

### The criterion

A taxonomy sentinel is **a provider port-operation outcome intended for caller
action** — retry, choose another provider, fix the spec, give up. Of a candidate:
is it returned from a port operation, and is it *meant* to be the thing a caller
branches on?

The rule is about intent, and an earlier draft made it evidential — "does a caller
`errors.Is` it to choose an action". Review withdrew that, correctly, because **it
is false of every member**: an exact search outside providers and the conformance
suite finds no business caller branching on any of the nine. That is what a
pre-1.0 library looks like. And the repair that suggests itself — widening
"caller" until the claim is true — swallows the conformance suite, which also
exercises the one error this map excludes, so it would erase the distinction the
criterion exists to draw. Intent survives the first real caller appearing; a usage
census does not.

`ErrSecretSerialize` is not one. It is not returned from a port operation at all —
it is what a value type's encoding paths return instead of writing a secret out —
and it is meant to be matched to assert that the refusal happened, never to decide
what to do about a resource.

### Why an exception list is not a bypass

The distinction is semantic and nothing in the package expresses it, so it cannot
be derived — it has to be decided and written down. What makes that safe is the
shape of the check rather than the goodwill of whoever edits the map. Four ways to
get it wrong, each fatal, each verified by a mutation that was confirmed to
compile before its result was read:

| mutation | outcome |
|---|---|
| a new exported error in neither map | fatal, and the message says deciding is the point |
| a name in both maps | fatal — it cannot carry the properties and be excused from them |
| an exception naming an error the package no longer declares | fatal — a stale exception is a standing permission |
| an exception with an empty reason | fatal — an exception nobody can review |

So the next new error stops the build until somebody classifies it, which is the
only property that matters here.

**Exclusion is from the taxonomy's properties, not from scrutiny.** The population
is still derived from the package, so the hierarchy test still sees an excused
error that wraps a real sentinel. Verified by mutation: declaring
`ErrSecretSerialize` as `fmt.Errorf("%w: ...", ErrInvalidSpec)` fails
`TestTheSentinelHierarchyMatchesTheImplementation` with "hierarchy() does not say
so", exception or not. That is the case that would matter, because an excused
error wrapping `ErrInvalidSpec` is indistinguishable from `ErrInvalidSpec` to a
caller.

### One thing the exception made necessary

`nonTaxonomy()` excuses `ErrSecretSerialize` on the stated grounds that a caller
matches it to assert the refusal happened — and **nothing matched it**, which
would have made the reason special pleading and the export unjustified.
`TestTheSerializationRefusalIsIdentifiable` now asserts that both gob paths, and
an encoder over a struct holding one, fail with that sentinel.
`credentials.ErrSecretMarshal` is matched the same way and for the same reason: a
type that fails closed is only demonstrably failing closed if the failure is
identifiable.

### How it happened

Neither PR was wrong. The one that added the derivation could not see a sentinel
that did not exist yet; the one that added the sentinel had no reason to know
about a map in a test file for a different concern. The test did its job — it did
it after the merge rather than before, because nothing previewed the two together.
That is a merge-order gap rather than an authoring defect, and it is the reason
the standing rule became "nothing merges without an adversarial verdict".
