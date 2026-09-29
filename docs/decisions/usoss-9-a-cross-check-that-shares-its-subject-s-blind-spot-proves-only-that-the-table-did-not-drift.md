## USOSS-9 — a cross-check that shares its subject's blind spot proves only that the table did not drift

*Recorded from USOSS-9, after the cross-check described below passed while the
thing it was guarding was wrong. It generalises past this package, which is why it
is here rather than in a comment.*

`credentials/aws` classifies an AWS failure as transient or terminal, and the
transient set began as a copy of the SDK's own `retry.DefaultThrottleErrorCodes`
plus `retry.DefaultRetryableErrorCodes`. A copy is a restatement, so it was
cross-checked generatively: `TestRetryableCodesMatchTheSDK` derives the expected
set from those two maps and fails on any difference in either direction.

That test passed. The classification was still incomplete, and the sentence that
says why is the decision:

> `TestRetryableCodesMatchTheSDK` **cannot ever see it: both sides are the SDK's
> map.** The population that catches it is the types IAM and STS declare.

Comparing a copy with its source proves the copy did not **drift**. It can never
prove the copy was the **right set**, because the question "did we copy this
correctly" and the question "is this the set our clients can return" have different
answers and only the first one is being asked.

### What was missing

`ConcurrentModification` and `EntityTemporarilyUnmodifiable` — IAM's two
"somebody else is changing this right now" errors — are in neither SDK map and are
both `FaultClient`, so neither the code set nor the fault check saw them. Two
concurrent lifecycle reconciles on one IAM user therefore reported **terminal**
when waiting was the entire remedy. Probed directly, with a throttling error as the
control so a probe answering false to everything would have been visible.

`compute/aws` had already found and closed exactly this (`awssdk.go:280-292`). This
package had read that file and copied only the part that looked relevant — so it is
not two packages disagreeing by accident, it is one package having the answer and
the other taking half of it. Convergence is tracked separately; the local lesson is
that **knowledge which is written down and does not cross a package boundary fails
the same way a comment fails.**

### The second population, and why it is a different mechanism

`TestEveryDeclaredSDKErrorIsClassified` reads every error type the `iam` and `sts`
packages **declare**, out of the SDK's own generated `types/errors.go`: **45 of 45
`ErrorCode` methods parsed, an unrecognised form fatal rather than absent.** Each
declared code carries a decision — transient with a recorded reason, or terminal —
and an undecided code fails, as does a decision for a code the SDK no longer
declares. That is the same shape USOSS-54 settled for the compute taxonomy: a
decided population, not a derived one.

It found a second gap immediately: `sts` `IDPCommunicationError` is also
`FaultClient` and in neither map, and it is on the web identity path this provider
uses. And it corrected one of my own decisions — `iam` `PolicyEvaluation` is
`FaultServer`, so the classifier was already right about it and the table was
wrong.

### A related trap the same reading exposed

**An AWS error's wire code is not its Go type name.** IAM's
`ConcurrentModificationException` reports `ConcurrentModification`;
`LimitExceededException` reports `LimitExceeded`; 33 of IAM's 33 and 12 of STS's 12
were checked and most differ. So:

- The new predicates match with `errors.As` on the typed error, never on the code
  string. A code-string match would be a second spelling of one grammar, which is
  how a code accepted at one call site is rejected at another.
- The comment justifying one entry in the copied set claimed
  `LimitExceededException` was "how IAM spells a quota exhaustion". That is the Go
  type name and the claim is false. It was inherited verbatim from
  `compute/aws/awssdk.go:184-190`, which is wrong the same way; that is routed
  separately. What replaced it says plainly what the set is: the SDK's codes, several
  of which no IAM or STS client can return, kept because matching the SDK's own
  classification is checkable and drift-resistant — and **not** a list of what these
  services return.

### Overriding the dependency needs a reason, and it is not "we know better"

Review then found the table wrong in the *other* direction: two codes classified
terminal here that the SDK also treats as terminal, and which are nonetheless
retryable **for this provider**. `InvalidIdentityToken` and `IDPRejectedClaim`.

The test that licenses the override is not that this package has a better opinion.
It is:

> **the deciding information is not available to the dependency.**

`Provider.assume` mints a **new** web identity token from the token source on every
attempt. The SDK cannot know that. The caller it has to assume is one holding a
single token and presenting it repeatedly, and for that caller a retry changes
nothing — so the SDK's classification is right about its caller and wrong about
this one. The classification differs because the callers differ.

Two consequences, and both belong in the record rather than only in the code:

- **A caller that reuses a token must not inherit this.** If this provider ever
  stops re-minting per attempt, these two go back to terminal, and the reason is
  the mint and not the error.
- **`IDPRejectedClaim` is ambiguous and is resolved toward transient.** The SDK
  documents it as possibly meaning the claim expired — a fresh mint fixes that —
  and possibly meaning it was revoked, which it does not. This provider cannot tell
  which. Transient is the safe side, because bounded retry ends and the lifecycle
  layer finalizes the record, whereas a terminal misclassification of an expiry
  fails a vend that would have worked on the next attempt, every time.

The cost is stated rather than implied: a genuinely wrong trust policy or an
unusable signing key now reports transient and is retried until
`credentials/lifecycle` gives up. A misconfiguration surfacing late is a worse
diagnostic and a better outcome than a retryable failure surfacing never.

### Why this criterion is trustworthy rather than convenient

Because the same test decides cases in opposite directions. Applied to a sibling
port's question — should an IAM quota exhaustion be retryable — it says **no**: an
account's user limit is information the SDK has as fully as we do, so there is
nothing the dependency cannot see and no grounds to override. Applied here it says
**yes**. A rule that only ever licensed overriding would be a rationalisation
wearing a rule's clothes.

### The rule

If you guard a restatement, obtain the guard's population **a different way**. Two
mechanisms that agree are weak evidence; two that disagree are the finding. And
state which question each one answers, because a cross-check that answers the wrong
question reads exactly like one that answers the right one.
