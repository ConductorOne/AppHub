## USOSS-6 — a registered module's identity is snapshotted, not trusted

Recorded because the fix is a construction where the obvious remedy was a
documented obligation, and because eleven rounds of review missed the defect
while a twelfth found it in one pass.

`Registry` is documented as keyed by module ID, it rejects a duplicate ID so that
two modules cannot answer to one key, and it orders by ID on the assumption that
IDs are unique. All three were claims about a value the caller could change after
registration: `BaseModule` exported its metadata, so

```go
r.Register(m)   // ID "before"
m.ModuleID = "after"
```

left `Get("before")` returning a module reporting `after`, and — with two modules
— produced a listing containing two entries reporting the same ID, past a
duplicate check that had already passed. No race, no malformed implementation: a
legal, sequential state transition through the delivered API.

### Two halves, and the first does not cover the second

**`BaseModule`'s metadata is now private and constructor-only.** That closes both
reproductions for the type this package ships.

**`Registry` snapshots what it uses at `Register` time and never re-reads the
module's accessors.** The key, the sort order and the category filter all come
from that snapshot. This is the half that matters, because the first one only
governs implementations this package wrote, and `Module` is an interface that
anybody can implement.

The alternative was to state on the interface that identity does not change after
registration. That is a documented requirement with nothing enforcing it — an
unobservable contract is an unasserted contract — and it puts the obligation on
every future implementor to be correct rather than making incorrectness harmless.
**Prefer a construction that cannot express the violation over a rule that
forbids it**, which is the same conclusion the import boundary checker and the
source auditor each reached the long way round.

### The residual, named rather than implied

A custom module can still *report* an identity that disagrees with the one it was
registered under. Nothing can stop an arbitrary implementation returning whatever
it likes from `ID()`.

What is guaranteed is that **the registry does not believe it**. The
disagreement is visible to a caller that asks the module, and it cannot corrupt
the registry. That is pinned by a test which mutates a registered module's
accessors and asserts the registry keeps its snapshot — so the limit is a
checked property rather than a sentence someone has to keep true.

### Only what the registry uses is snapshotted

`Name`, `Description` and `Icon` are not copied, because the registry never reads
them. Storing them would imply a guarantee about values nothing here depends on,
and a guarantee nothing depends on is one nobody notices breaking.
