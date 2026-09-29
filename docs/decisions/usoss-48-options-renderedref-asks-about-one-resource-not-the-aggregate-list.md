## USOSS-48 — Options.RenderedRef asks about one resource, not the aggregate list

`Options.Rendered` gains a companion:

```go
RenderedRef func(ctx context.Context, p compute.Provider, ref compute.Ref) (artefact string, found bool, err error)
```

and `compute/conformance` gains a check that uses it,
`security/every-planted-resource-has-a-rendered-artefact`, alongside the
existing `security/secret-material-does-not-appear-in-rendered-artefacts`
rather than in place of it.

### The ticket's first premise was wrong, and measuring it said so

The ticket as filed described a provider whose `Rendered` hook returns nothing.
`checkSecretsNotInRendered` already has `if len(rendered) == 0 { fail }` ahead
of the sentinel scan, and `TestTheRenderedGateFailsWhenTheSubstrateShowsNothing`
already pins it. Injecting that fixture again would have shipped a passing test
that proved nothing new.

The real gap, measured against `fake.DefectSecretValueInStoreListing` (material
in the secret listing) combined with a new fixture that drops exactly that
listing from the enumeration: **the check still passes.** `Options.Rendered`
stays non-empty and grows — a service planted through the same check still
renders fresh — so both of `checkSecretsNotInRendered`'s emptiness arguments
hold, and the sentinel is in none of what it searches because the one artefact
that carried it was never a member of the list. This reproduces PR #25 exactly:
`ListBuckets` found a bucket, its tag read returned 500, the bucket was dropped
from the list, and the rest of the substrate reported normally.

`TestThePartialArtefactDropDefeatsTheAggregateCheckButNotCorrespondence` pins
both halves in one run: `security/secret-material-does-not-appear-in-
rendered-artefacts` passes against the fixture, and
`security/every-planted-resource-has-a-rendered-artefact` fails against it.
Deleting `Options.RenderedRef` from the wiring and re-running the same fixture
(kept only as a manual check during development, not shipped as a test)
reproduces zero failures at all — the exact vacuous pass the ticket is about.

### Why a check change could not close it

`checkSecretsNotInRendered`'s non-emptiness argument is entirely aggregate:
size, and membership grown since a snapshot taken before planting. Neither
question can distinguish "the provider rendered everything" from "the provider
rendered everything except the one thing that would have failed this check" —
both look identical to a scan that only knows the list's size and freshness.
Making the scan cleverer does not help: whatever pattern it searches for, a
provider can omit the one artefact matching it and satisfy the same two
aggregate conditions. The suite would be adding heuristics to a class of gap
that is not about pattern-matching, it is about not being able to name which
enumerated member corresponds to which created resource.

Only the provider can name that correspondence. The suite already tracks the
`compute.Ref` a plant's `Ensure` returns; what it lacked was a way to ask the
provider "what did you render for this one" rather than "what did you render,
in total". `hostile.go`'s marker mechanism (USOSS-61) does not reach this
either, and says so in its own package comment: a marker can be carried into an
artefact, and nothing stops the provider omitting that artefact from the
enumeration regardless — the marker's arrival would prove the list non-empty,
not complete.

### The hook is scoped to the same resources the check already plants

`checkEveryPlantedResourceIsRendered` reuses `materialPorts(e)` —
`checkSecretsNotInRendered`'s own derivation of which ports can be handed
secret material — rather than asking about every resource the whole suite run
has ever created. Two reasons, not one:

* The invariant this ticket is about is specifically the rendered-material
  scan's completeness, not a general "every resource must render" property
  applied suite-wide. Widening the scope to every check's fixtures would be
  solving a bigger problem than the one measured, with a bigger surface for a
  provider author to wire.
* `materialPorts` already carries the legitimate-empty case:
  `skipBecause` when a provider has no port that can be handed material. The
  correspondence check inherits it for free rather than re-deriving it.

`fake.Harness.RenderedRef` is implemented for every kind the store holds, not
only the three `materialPorts` can return (secret, container-service,
relational-database) — narrowing it to those three would have been a second
restatement of `materialPorts` inside the reference provider, and the two would
drift the way every hand-maintained pair in this codebase has.

### What it cost, and what it deliberately did not touch

One new `Options` hook, one new check, six extraction-only helper methods on
`fake.Harness` (`renderRelational`, `renderRepository`, `renderBucket`,
`renderKeyValue`, `renderSecret`, `renderIdentity`) so `Rendered` and
`RenderedRef` share one rendering per kind instead of two copies that could
disagree, and one new defect, `fake.DefectDropsRenderedArtefact`, deliberately
partial rather than total.

`checkSecretsNotInRendered` itself is untouched. It still cannot be settled by
a hostile marker on its own, and `hostile.go`'s `unverifiableByMarker` table
said so for it and eleven siblings that also read `Options.Rendered`. This
ticket closes that entry for the rendered-material check specifically — the
pairing with the correspondence check is what closes the invariant, not a
change to the marker mechanism — and leaves the other eleven, including
`security/tls-listener-requires-a-resolvable-certificate` and the ten
per-port `ensure-converges-rather-than-accumulating` checks, exactly as open as
they were. Nothing here claims otherwise: PR #21's rendered check is not PR
#29's build checks, and this ticket is scoped to the one gap it measured, not
to every check sharing the same limiting mechanism.
