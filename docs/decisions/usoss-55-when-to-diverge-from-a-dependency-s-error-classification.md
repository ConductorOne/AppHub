## USOSS-55 — when to diverge from a dependency's error classification

*Recorded from USOSS-55, after a review round spent reverting a change that
diverged from the AWS SDK in the wrong direction. The criterion below was
operating in `compute/aws` already and was written down nowhere, which is why the
divergence looked like an inconsistency to be tidied up.*

`compute/aws` classifies substrate errors onto the `compute` taxonomy. It has to
decide, per error, whether to take the SDK's own retryability judgement or to
override it. It does both, and the rule is not "prefer the SDK" or "prefer our
own":

> **The SDK's judgement is authoritative for a fact about the service, and not
> authoritative for a fact about the caller.**

### The two worked cases

**A quota exhaustion is a fact about the service.** `LimitExceededException`
means the account has as many of something as it is allowed. Whether waiting
helps is a property of the service's own semantics, which the SDK models and this
package does not. So `isThrottleCode` carries the SDK's list and does not
second-guess it — including where the result looks odd, which it does: the SDK
treats ECR's `LimitExceededException` as a throttle even though a quota is not
one. That is inherited deliberately, and changing it is a judgement about
somebody's account rather than a defect fix.

**A consistency race is a fact about the caller.** `isConsistencyRace` classifies
IAM's `ConcurrentModificationException` and `EntityTemporarilyUnmodifiableException`
as `compute.ErrTransient`, and the SDK's standard retryer classifies both as not
retryable. Overriding it is correct because **the SDK cannot know that this
package's own reconcile loop is the other writer.** From the SDK's position a
concurrent modification is an unexplained conflict; from here it is two Ensures
racing on one role, and waiting is the remedy. The information that decides it is
not available to the dependency.

### Why the rule needed writing down

Without it, the two look like an inconsistency, and an inconsistency invites
harmonisation in whichever direction the reader notices first. Both directions are
wrong: harmonising toward the SDK makes a self-inflicted race terminal, and
harmonising away from it makes a quota retryable.

The second is not hypothetical. It happened in this ticket. A comment stated that
IAM spells a quota exhaustion `LimitExceededException` — which is the Go **type**
name, not the error code; IAM's code is `LimitExceeded`. Reading the type name as
the code made the map entry look like it was meant for IAM and mis-spelled, so a
"fix" added typed matching for the IAM type and made an IAM quota retryable. The
classifier was correct and the comment beside it was not.

**A correct classifier beside a comment giving the wrong reason is how the next
reader re-derives the bug**, and here the next reader was the same author, one
round later. The comment now names which service the entry is for and records the
regression it caused.

### What this does not license

The rule is about *whose fact it is*, not about confidence. "This package knows
better" is not the test — the test is whether the deciding information is
structurally unavailable to the dependency. For a consistency race it is: the
other writer is us. For a quota it is not: the account's limits are the service's
own state.

Every future divergence names which side of that line it is on, in the comment
that makes it.
