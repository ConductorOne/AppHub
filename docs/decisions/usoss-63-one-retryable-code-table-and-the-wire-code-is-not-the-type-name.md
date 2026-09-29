## USOSS-63 — one retryable-code table, and the wire code is not the type name

Two AWS providers each held a copy of the SDK's retryable-and-throttling code set:
`throttleCodes` in `compute/aws/awssdk.go` and `retryableCodes` in
`credentials/aws/fault.go`. The entries were identical. There is now one
declaration, in `internal/awscode`, and both providers read it.

### The duplication was not symmetric, which is what made it urgent

"Two identical maps" makes this sound like tidying. It was not, because only one
of the two was checked.

`credentials/aws` cross-checked its copy against `retry.DefaultThrottleErrorCodes`
and `retry.DefaultRetryableErrorCodes` at test time, in both directions.
`compute/aws` cross-checked its copy against nothing at all. So the two could only
ever have drifted one way: a code AWS adds turns `credentials/aws`'s test red and
goes **silently missing in `compute/aws`**, where a throttle then classifies as
`compute.ErrFailed` and a caller is told its spec has to change while waiting was
the entire remedy. That is the exact failure USOSS-10's classification ruling was
written to prevent, sitting in the provider that runs deploys.

`credentials/aws`'s own comment said converging the two was the right end state and
was not that pull request's to make, and raised it as a follow-up. This is it.

### The shared package imports nothing, deliberately

`internal/awscode` has no dependency, not even the AWS SDK. `internal/boundary`'s
`aws-sdk-confined` rule names the packages permitted to reach `github.com/aws`, and
it counts test imports as well as build imports, so a shared table whose tests
reached for the SDK would have required widening an import fence in order to land a
deduplication. That is a bad trade, and it is avoidable: a wire code is a string.

The SDK cross-check therefore stays in `credentials/aws`, which is already on that
allowlist and already had it, and now runs over the shared set. One gate over one
declaration, covering both providers — where before there was one gate over one of
two declarations.

### The set is a predicate, not an exported map

Both copies carried a comment explaining that the SDK's sets were *copied rather
than referenced* because a package-level map is something any dependency can mutate
in place. Exporting the converged set as a map would have rebuilt that hazard inside
this repository, one import closer to the classifiers than the SDK's version of it.
So the table is unexported, the surface is `awscode.IsRetryable(code)`, and
`awscode.RetryableCodes()` hands out a fresh sorted slice per call.

### The ticket's premise, corrected

USOSS-63 was raised reporting a live misclassification: that an IAM throttle reaches
these packages as `ErrorCode() == "LimitExceeded"`, misses a set carrying only ECR's
longer spelling, and is reported terminal. **The first half is a true fact about a
real type. The second half does not follow from it, and no such misclassification
existed.** Separating them is the whole content of this class of bug, so both halves
are now pinned rather than argued:

* `iamtypes.LimitExceededException` does report `"LimitExceeded"`, and
  `ecrtypes.LimitExceededException` — identical Go name — reports
  `"LimitExceededException"`. Keyed by code, as both copies already were and as the
  shared table is, each service gets its own answer with no per-service table.
* That IAM type is a **quota exhaustion**, not a throttle. The account is at its IAM
  limit; retrying does not create head-room. Terminal is the SDK's answer and this
  repository's, and `compute/aws` had already pinned it with the SDK's own type after
  spending a review round on the opposite "fix".
* IAM's **throttle** is a different error with no Go type at all. IAM is a
  query-protocol service, so a rate refusal arrives as the common wire code
  `"Throttling"` — which is in the shared set, and was in both of the sets it
  replaced. An IAM throttle has been transient in both packages throughout.

Making the IAM type retryable, which is what the ticket asked for, has now been
written and reverted twice: once in `compute/aws` and once in `credentials/aws`,
each time by a reader who read the Go type name as the wire code. It is not done
here either.

### What is done instead: the confusion is a test rather than a paragraph

`awscode.TestATypeNameIsNotAWireCode` parses the generated `types/errors.go` of
every AWS service module this repository requires — 617 declared error types across
16 services, derived from `go.mod` rather than listed — and enumerates every type
whose **Go name** and **wire code** give different answers to `IsRetryable`. Each
one needs a recorded decision; a new one is a test failure rather than an ambush in
review, and a service that ships no `types/errors.go` (EC2, which models no errors
as types) must be named with its reason rather than silently dropping out.

There are two, and they run in **opposite directions**:

| Service | Go type | Wire code | Retryable by name | Retryable by code |
|---|---|---|---|---|
| `iam` | `LimitExceededException` | `LimitExceeded` | yes | no |
| `elasticloadbalancingv2` | `PriorRequestNotCompleteException` | `PriorRequestNotComplete` | no | yes |

The second was found by the test, not by a reviewer, and it matters more than the
first. Every argument this repository has had about this bug has been about IAM, so
the IAM row alone reads as a fact about IAM's spelling habits. The ELBv2 row says it
is a fact about generated code — and it is the direction that costs a deploy:
matching the type would classify a retryable ELBv2 condition terminal, telling a
caller its spec has to change while the previous request finishes. `compute/aws`
holds an ELBv2 client, so it was live. It is pinned in the taxonomy table with the
SDK's own type.

### A shared declaration nothing local checks is worse than the duplicate

Both providers gained a test asserting that every code in `awscode.RetryableCodes()`
actually reaches `compute.ErrTransient` through their own classifier, each with a
control in the other direction. The cross-check proves the set equals the SDK's; it
says nothing about whether a package still reads it, and the declaration is now two
packages away from the behaviour it decides. Delete the arm, or narrow it, and the
cross-check stays green over a set nothing consults.
