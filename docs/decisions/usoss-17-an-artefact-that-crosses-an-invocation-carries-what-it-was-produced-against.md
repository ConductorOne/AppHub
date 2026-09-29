## USOSS-17 — an artefact that crosses an invocation carries what it was produced against

Two security-relevant defects in this port turned out to be one property with
two instances, and stating the property is what found the second.

**A completed scan could be redirected at another repository.** `fix.Scan`
carried findings, a revision, and nothing else. `Execute` took owner, repository
and installation from the *invocation* and copied only the scan's revision over
them, so a caller holding one scan identifier could open a draft pull request
against any repository they could otherwise reach. The finding came from one
repository and the change landed in another, and nothing in the flow could
notice, because the artefact did not say what it was about. Possession of the
artefact was authority over the target.

**A snapshot could be written over a branch that had moved on.** The tree is
fetched before the agent runs; the branch head is read again after. The patch is
a set of *whole-file* replacements computed from the older tree, so committing
it on top of a newer head silently reverts whatever landed in between. Every
call in the sequence happens in its expected order, which is why the exact
call-order assertion stayed green: **it is the transition that is wrong, not any
call.**

### The property

> An artefact that crosses from one invocation to another must carry the
> identity of what it was produced against, and the consumer must check it at
> the point of use.

Everything else these two packages pass between a producer and a consumer — a
scan result, a verdict, a patch, an opened pull request — is produced and
consumed inside a single `Execute`, against coordinates the module supplied in
that same call, so the call binds it. Enumerating the crossings gives exactly
two: the completed scan, read back by a later invocation, and the snapshot,
whose contents a later *step* writes against a branch that can move underneath
it. Both were unbound. That the enumeration is complete is the reason this is
an entry rather than two patches.

### What binding looks like here

`review.Completion` records owner, repository, requested revision and the
**resolved commit**; `fix.Scan` records owner and repository; `review.Snapshot`
carries the immutable commit its contents came from. Three consequences are
deliberate:

- **Checked at the point of use, not at creation.** The redirect happens after
  the scan exists, by invoking the fix with different coordinates, so a check
  where the scan was written could not see it.
- **An unrecorded identity is refused, not treated as "any".** A scan that does
  not say what it is about cannot authorise anything.
- **The comparison is exact, and installation is deliberately excluded.**
  Hosting platforms fold case in ways this repository does not know, and
  guessing a folding rule is a widening path on an authorisation check. But
  installation must *not* be compared: a public scan legitimately has none and
  a fix for it legitimately needs one, so requiring equality would break a real
  flow while protecting nothing that owner and repository do not already.

### Refusal, not reconciliation

When the branch has moved, the fix stops and says so. Merging a model's
whole-file output against a concurrent change is a three-way merge this module
has no business attempting, and getting it subtly wrong produces a pull request
that looks reviewed and is not. Re-running is cheap; a silently reverted commit
inside an approved-looking change is not.
