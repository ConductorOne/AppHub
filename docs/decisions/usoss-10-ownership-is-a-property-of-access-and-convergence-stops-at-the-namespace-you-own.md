## USOSS-10 — ownership is a property of access, and convergence stops at the namespace you own

Binding on USOSS-11 through USOSS-14 and USOSS-26. Two rules that look unrelated
and are the same rule seen from two sides: **what may this platform touch, and how
much of it.**

### Ownership is established at use, by resolution, not by a check each method remembers

The ownership tags were read inside `EnsureRepository`. Review found `Build` and
both `Delete` methods walking straight past it: a build minted a scoped push
credential against a repository somebody else owned and pushed to it, and both
deletes destroyed unowned resources. The check was right about its own entry
point and silent about the other three.

Adding the check to three more call sites is the case, not the class — the fourth
method added later forgets it again. So:

> A port method obtains the coordinates it needs to act — a physical name, an
> ARN — only by going through a resolve step that reads the ownership marker
> first and returns [compute.ErrNotOwned] instead of a value.

A method that forgets has nothing to pass. In `compute/aws` that step is
`imageRegistry.owned` / `ownedByName` and `identityService.owned` / `ownedByName`,
and the value they return is the only way to reach a mutating call.

The second half is the one worth carrying furthest:

> A `compute.Ref` this provider issued is **not a capability**. The resource
> behind it can be deleted and somebody else's can take the same physical name,
> so ownership is re-established on every call rather than inherited from
> issuance.

A test derives the method set from the interfaces by reflection and fails if a
method has neither an ownership case nor a recorded exemption, because a
hand-maintained list of methods drifts from the interface.

### Converge the sub-namespace you own; never touch what you do not

`Ensure` is declarative: what the spec does not ask for is removed. Applied
without a boundary that rule destroys other people's configuration, and applied
without nerve it leaves privilege behind. The boundary is **ownership, not data
type**:

* **Tags** — converge the `apphub:` namespace exactly, leave every other tag
  alone. An operator's `CostCenter` tag is their deliberate configuration.
  USOSS-13 found the sharp edge: S3's `PutBucketTagging` **replaces** the whole
  set and succeeds, so reconcile-to-exactly-the-spec silently deletes cost and
  compliance tags on every deploy. ECR's `TagResource`/`UntagResource` are
  additive and subtractive, so the same rule needs different code per service.
* **An IAM trust policy** — converge the **whole document**. Every statement in
  it is one this provider authored, and a principal nobody asked for is a
  finding rather than configuration. Review found an owned role keeping a
  wildcard `AWS:"*"` principal — "anyone in this partition may assume this" —
  because reconciliation compared only the runtime it could read back.
* **An ECR lifecycle policy** — converge the rules this provider marked and copy
  the rest through. `PutLifecyclePolicy` also replaces the whole document, so
  this is the tag trap in a second place; it was found in this package's own
  spine by looking for the shape rather than by review.

The general form, for the next port:

> **If a substrate call replaces a whole collection, "the call succeeded" is not
> evidence it did what you meant.** Find the sub-namespace you own, mark what you
> write so you can recognise it later, and read-merge-write.

### Where the merge was tried and withdrawn

The first attempt at the ECR lifecycle policy did read-merge-write, splitting the
document by a rule-description marker and a reserved priority band. It was added
mid-review to close one finding and produced two more: an operator rule whose
description happened to start with the marker was classified as this platform's
and deleted, and the merged document could violate ECR's own unique-priority
invariant so the service rejected it outright.

Both are failures of *arithmetic over a document format this platform does not
own*. So for that call the rule is now:

> Where a replace-only call carries a document with no namespace this platform
> can safely claim, **do not merge — refuse.** Record the claim outside the
> document, in a namespace already owned, and refuse when the claim is absent.

For ECR that is a repository tag. The construction cannot express either failure:
there is no ownership classification to get wrong, and no priorities to compute.
It is also the safer default, because a refusal is visible and a mis-parsed merge
is silent.

The cost is accepted and stated: an operator whose repository already carries a
lifecycle policy cannot use this provider's retention on it until they remove it
or hand it over. What the tag does *not* detect is an operator editing a policy
this provider wrote; the guarantee is "apphub will not silently take over a
policy it did not create", not "apphub detects edits".

Deliberately not a digest of the document: AWS normalises policy text, no port
here has an account to verify how, and a digest that disagreed after
normalisation would refuse every deploy rather than the one that deserved it.

A preserving merge is worth building properly, with the format's invariants
stated up front — that is what this one was missing. It is a ticket, not a
patch.

### The rule is applied per substrate *operation*, not per port

USOSS-13's refinement, from hitting the trap: whether a call is **diff-capable**
or **replace-only** decides the code, so one port needs both implementations and
a test per *shape* rather than per port. A port that got the diff path right and
the replace path wrong passes every test written against the diff path.

Sort your calls before you write them. In `compute/aws` as of USOSS-10:

| Substrate call | Shape | How the rule is met |
|---|---|---|
| ECR `TagResource` / `UntagResource` | diff-capable | `tagDelta` emits only `apphub:`-namespaced removals |
| IAM `TagRole` / `UntagRole` | diff-capable | same |
| ECR `PutLifecyclePolicy` | **replace-only** | written whole; see below — the merge was deleted |
| IAM `UpdateAssumeRolePolicy` | **replace-only** | whole document is ours; converge it entirely |
| ECR `PutImageScanningConfiguration`, `PutImageTagMutability` | scalar | no collection to lose |

Known replace-only calls in the ports that follow, so nobody has to rediscover
them: S3 `PutBucketTagging`, and ECS `RegisterTaskDefinition`.

And copy USOSS-13's third test, which is the one most likely to be omitted: assert
that **the call site actually goes through the merge**. A correct merge function
that `Ensure` does not call is a defect sitting between two verified things, and
their first two tests both passed while it was live.

Two ports have now hit this on two different AWS services. Audit every
replace-shaped call in a port before it ships.

### Amended: the merge came out, and ownership moved to every write

Two later corrections to this record, both from review, both worth more than the
positions they replaced.

**The ECR lifecycle merge was deleted.** The table above once sent you to a
read-split-merge-write for `PutLifecyclePolicy`. Three versions of it produced
five findings between them — an operator rule deleted for starting with the
marker, merged documents violating ECR's unique-priority invariant, a refusal
contradicting its own remedy text, a check-then-write race, and a stale claim
authorising an overwrite. The premise did not hold: **nothing in AWS applies a
lifecycle policy to a repository on your behalf**, so the account-wide tagging
that makes `PutBucketTagging` dangerous has no ECR analogue. The policy of a
repository this provider owns is written whole.

Take the general form rather than the instance: *replace-only is dangerous when
something other than you writes to the collection.* Check that before building the
machinery. For S3 tags it is true; for ECR lifecycle policies it is not.

**Ownership is re-established at every write, not once per call.** The rule at the
top of this record is about a caller's `Ref`. Inside a converging `Ensure` there
is a second version of the same mistake, and this package shipped both halves of
it in consecutive rounds:

1. The ownership decision was taken once at the top of `Ensure` and inherited by
   four writes several round trips later.
2. The fix moved the check next to the *last* write. Review then removed
   ownership after the first read and watched `Ensure` change the repository's
   scanning configuration on a repository it no longer owned, and only then
   refuse at the lifecycle step. **The mutation stood, and it needed no
   interleaving to reach.**

> Moving a check leaves it wherever the next write is not. A write should not be
> *reachable* without a fresh proof.

The construction is the one this record already prescribes for ports, applied
inside: a helper does the ownership read and hands the write its coordinates, so
a write that forgets has nothing to call. Two API calls means two proofs — the
tag convergence does one for the removal and one for the addition rather than
sharing.

A stale read may still cause the provider to do *less* — skip a convergence now
and perform it next call, which an eventually-convergent contract permits. It may
never authorise a write.

None of this closes the window: ECR has no conditional write, so a person
revoking ownership between the proof and the write still has one write land. Say
so where you implement it rather than implying atomicity you do not have.

Test it in two places, because neither is sufficient alone. A structural
assertion over the call sequence — every mutating call immediately preceded by
the read that authorised it — cannot see the *first* write, because a stale proof
and a fresh one look identical when nothing ran between them. A behavioural test
that changes the answer between the read and the write catches that one and says
nothing about the others.
