## USOSS-39 — An ambiguous expiry condition has no truth value

*Recorded from a one-line correction to `compute/conformance`'s undriven-method
table. The fix is a sentence; the class it belongs to is the reason for the entry.*

### The finding

Every entry in `undrivenPortMethods` carries a required `Expires` — the condition
under which the exclusion stops being justified. `SecretStore.DeleteScope` read:

> `Expires: "a per-check secret scope, or USOSS-26's lifecycle checks growing an error-mapping case"`

USOSS-26's checks **already** have an error-mapping case:
`checkDeleteScopeRefusesEmpty` asserts `errors.Is(err, compute.ErrInvalidSpec)` on
`DeleteScope("")`. So the condition was met. But the mapping the exclusion is
*about* — the method's behaviour under an induced substrate failure — is still
undriven, so the condition was also unmet. **The same two sentences supported both
conclusions.**

That is worse than a stale entry, and worse than a forward reference:

> A stale condition resolves. A forward reference is at least decidable. An
> ambiguous one can never retire and can never be shown not to have retired.

A required field whose value cannot be evaluated is a field that has been filled
in rather than answered — the same shape as a check that runs without observing,
which is what USOSS-32 and USOSS-39 were both about. The audit machinery enforced
that `Expires` was **present**. Nothing enforced that it was **decidable**.

### The cause: one term doing two jobs

"Error mapping" covered two different obligations on the same method:

| obligation | driven? | by what |
|---|---|---|
| a caller bug maps to `ErrInvalidSpec` | yes | `port/secret/delete-scope-refuses-an-empty-scope` |
| an induced substrate failure maps to `ErrTransient`/`ErrFailed` | no | nothing in the suite |

The exclusion's `Reason` is about the second. Its `Expires` said the first. Naming
the mechanism — *induced-failure case* — makes the condition testable against a
list of check names, which is what the field is for.

The `CoveredBy` had a second, smaller problem in the same sentence: it claimed in
the present tense that checks on an unmerged branch "exercise" the method. It now
says "not yet on main", and says which mapping they do and do not cover.

### Why the correction came from elsewhere

USOSS-26 found it while verifying a claim this table made **about their own
checks**, reported the correction, and did not edit the sentence — the same
jurisdiction line they drew on the manifests, held when crossing it would have
been cheaper. That is worth recording because the alternative failure mode is
common and silent: an agent who fixes a neighbour's wording ships a claim about
work they own, in a file whose owner never sees the change.

### The remedy was in the same register as the defect

The diagnosis above is right and the first fix was not enough. Making the sentence
unambiguous left it a sentence:

> **Replacing `Expires` with `banana` left every audit in this file green.**

So the field went from ambiguous prose to unambiguous prose, and the gate still
could not distinguish either from a fruit. Requiring a field to be **present** is
not requiring it to be **evaluable** — which is the finding restated one level in,
against its own remedy.

What closes it is a second field, `RetiredWhen`: a fragment of a check name, which
`TestNoExclusionOutlivesItsRetirementCondition` fails on once any registered check
name contains it. The entry deletes itself by turning red the moment it stops being
necessary, so the merge order of two unrelated pull requests stops mattering. Note
the direction, which is the unusual part: **it fires when something succeeds.** A
tripwire that fires on breakage gets watched; one that fires on an obligation being
met does not, and that is how a "not yet" becomes permanent.

`Expires` stays, and stays prose — nothing evaluates it, and the struct now says
so. The reviewer's exact mutation therefore still passes, on a field documented as
unread rather than one claiming to be the condition. That is a different claim, not
a closed one, and #35 legitimately edits `Expires` to describe an event that cites
no ticket and no check, so a validator over it would break honest values.

Two details of the shape are borrowed from PR #35 / USOSS-37, whose exemption table
reached it first for a different subject, and both are load-bearing: a **fragment**
rather than a whole name, because port check names are computed (`"port/" +
portName + suffix`) so no literal of the whole name exists to match; and a
**floor**, because a collector that finds nothing retires nothing and reports the
same green as one that found everything.

One judgement the audit deliberately does not enforce: a fragment can be **too
coarse** for its entry. `delete-scope` is valid by every rule and is the wrong
fragment here, because USOSS-26's two checks contain it and neither drives the
method under an induced failure — it would retire the entry on the wrong event.
Retiring early and never retiring are the same defect in different clothes, but
which fragment distinguishes the awaited check is per-entry judgement, so it is
recorded at the entry rather than pretended to be a law.

### The mechanical reader named in the first draft was the wrong one

That draft said `TestEveryCoveredByClaimIsBoundToACall` would come to read this
field. Three corrections, and they matter because a commit message has no amendment
path after merge:

| claimed | actual |
|---|---|
| USOSS-35 | **PR #35 / USOSS-37** |
| it will read `Expires` | it reads **`CoveredBy` only**, never `Expires` |
| its wildcard exemption binds automatically once the checks land | it **turns red** rather than binding |

The third is not a defect in #35 — turning red is the self-retiring behaviour, and
it is the shape adopted above. It simply is not what was attributed to it.
