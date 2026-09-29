## USOSS-45 — The ticket's premise was a mid-review snapshot of PR #18, superseded before merge

*Recorded from the USOSS-45 audit. The ticket states the current behaviour as
"the port now declines RetentionPolicy with a typed compute.UnsupportedError,"
cut from PR #18 by supervisor ruling after five findings across three review
rounds. `compute/aws/registry.go` on `main` at commit `a3f6380` (unchanged
since PR #18 itself merged at `6e9cef9`) does not decline `RetentionPolicy`.
It implements it, and the doc comments on `applyLifecycle` and
`parseLifecyclePolicy` narrate the same five findings the ticket lists,
resolved before that PR closed rather than after. USOSS-45 was filed from a
state that existed during review and did not survive to the merge.*

### What actually shipped, and why the machinery the ticket asks for is absent

The design `main` carries is not "retention, done properly" layered on top of
a decline — it is a fourth attempt that discharges the ticket's own list of
required properties by construction rather than by mechanism:

* **Ownership lives on a repository tag, never in the document.** `checkOwned`
  reads `tagManagedBy`/`tagComponent`, set once by `CreateRepository`'s own
  `Tags` parameter (`awssdk.go`) in the same call that creates the resource.
  There is no free-standing "claim" tag with a lifecycle of its own to forget
  to clear.
* **The lifecycle document is written whole, never merged.** `applyLifecycle`
  (`registry.go:363-372`) is six lines: empty retention deletes the policy,
  non-empty retention `PutLifecyclePolicy`s the rendered document. No read, no
  rule classification, no priority arithmetic.
* **The renderer refuses what ECR cannot express**, rather than emitting an
  invalid document: `KeepLast` and `MaxAge` together are refused at the spec
  (`compute.ErrInvalidSpec`) because both shapes are `tagStatus: "any"` and ECR
  permits exactly one such rule, last.

The full reasoning — including the general rule ("replace-only is dangerous
only when something *other than this provider* writes to the collection, and
nothing else writes ECR lifecycle policies") — is already recorded in
[`usoss-10-ownership-is-a-property-of-access-and-convergence-stops-at-the-namespace-you-own.md`](usoss-10-ownership-is-a-property-of-access-and-convergence-stops-at-the-namespace-you-own.md).
This entry does not restate it; it exists to answer USOSS-45's specific
acceptance bar, which that record does not: **which test drives which of the
five named failure modes, by name.**

### The five failure modes, closed and where each is pinned

1. **Render-only-and-Put deletes an operator's rule.** Structurally
   impossible for a repository this provider does not own — `owned`/
   `ownedByName` refuse before any write is reachable — and
   `TestARepositoryThisProviderDoesNotOwnIsNeverReached`
   (`blockers_test.go`) plants an operator's own lifecycle policy on a
   same-named unowned repository and asserts it is byte-identical after
   `EnsureRepository` is called with both an empty and a non-empty retention.
   For a repository this provider *does* own, the document is scoped to this
   provider entirely by declared design (same record as scan-on-push, tag
   mutability, and labels) — an operator hand-edit to an owned repository's
   policy is documented as replaced on the next deploy, which is a stated
   scope decision, not the ticket's failure mode.

2. **Marker-by-description-prefix misclassification.** `parseLifecyclePolicy`
   (`registry.go:547-581`) performs no ownership classification of any kind —
   it recovers `KeepLast`/`MaxAge` from `countType`/`countUnit` and ignores
   everything else, including `description`. There is no marker to collide
   with an operator's own rule text. The round-trip is exercised across every
   retention transition, including from-and-back-to empty, by
   `TestTheLifecyclePolicyOfAnOwnedRepositoryConvergesToTheSpec`.

3. **Priority arithmetic producing AWS-invalid documents.**
   `TestEveryLifecyclePolicyThisProviderRendersIsValidForECR` asserts every
   rendered document against ECR's own invariants directly — positive, unique
   `rulePriority`, and at most one `tagStatus: "any"` rule, last — across both
   shapes this provider renders. `TestRetentionShapesECRCannotCombineAreRefused`
   covers the shape the invariant check found and review had not: a spec
   asking for both `KeepLast` and `MaxAge` would need two `tagStatus: "any"`
   rules, which ECR rejects however they are numbered, so it is refused at the
   spec with `compute.ErrInvalidSpec` naming both fields.

4. **Hash-based refusal breaking on AWS policy normalisation.** No hash or
   digest of the policy document exists anywhere in `compute/aws`. Ownership
   is exclusively the repository tag (finding 1's mechanism); nothing compares
   document bytes, so there is nothing for AWS's normalisation to break.

5. **Tag-claim TOCTOU, three ways:**
   - *Empty retention returned `ErrNotOwned` instead of leaving a foreign
     policy alone.* `TestARepositoryThisProviderDoesNotOwnIsNeverReached`
     drives both `compute.RetentionPolicy{}` and a non-empty policy through
     the same unowned repository in the same loop — empty retention gets the
     same refusal and the same untouched foreign document as any other
     request, because ownership is checked once, uniformly, before the
     retention value is even inspected.
   - *A policy created between the Get-not-found and the Put is overwritten.*
     `applyLifecycle` contains no Get before its Put or Delete — there is no
     read-then-write of the lifecycle document for a race to land in. The
     TOCTOU that remains is the ownership tag read a round trip before the
     write, which is a different and smaller window: bounded to one round
     trip, and stated rather than implied in `writeOwned`'s doc comment
     ("ECR has no conditional write... a person revoking ownership inside
     that window still has one write land"). It is exercised by
     `TestOwnershipIsReEstablishedAtTheWriteNotInheritedFromTheRead`
     (`registry_internal_test.go`),
     `TestARevokedOwnershipStopsTheFirstWriteAndNotJustTheLast`, and
     `TestEveryMutatingCallIsPrecededByItsOwnProof`.
   - *A failed claim-tag clear leaves stale authority.* There is no
     claim-tag clear operation to fail. The managed-by tag is set once, in
     the same `CreateRepository` call that creates the repository
     (`awssdk.go:484-496`, `Tags` parameter), and torn down only by deleting
     the repository itself — there is no independent tag lifecycle that can
     survive the resource it authorises, or vice versa.

### Disposition

No code change. `go build ./...`, `go vet ./...`, and
`go test ./compute/... -race` are green on `main` as received. This entry is
the requested written record: the ticket's five failure modes map to five
already-passing fixtures, named above, and the ticket is closed without a
functional change.
