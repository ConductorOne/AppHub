## USOSS-10 — classification belongs in the adapter that holds the client

Supervisor ruling, binding on all six ports, recorded here because this package
holds the spine and two ports had already solved it locally and differently.

> The **SDK adapter** maps AWS errors onto the substrate vocabulary. The **port**
> maps substrate vocabulary onto the [compute] taxonomy. A port that reaches for a
> classifier at all is a layering violation: it should be receiving an
> already-classified substrate error.

**The layering above stands. The mechanism under it has been reversed, and this
record is the amended version.** The ruling used to say the adapter classifies
*using the retryer of the client it holds*. It does not any more: it classifies
from signals this package owns, and a caller who needs to widen the result says
so through `Config.IsRetryable`.

The next two sections are kept as the history that produced the reversal, and
they are **not** current: read "Reversed" and "What this costs you" for what
binds you. In particular the ruling that this needs "neither a hook nor a widened
seam" is exactly what was overturned — it is a hook, and it is USOSS-13's.

### What went wrong before the rule existed

`classify` consulted a separately constructed default retryer. So the decision to
retry was made by the client's retryer and the decision to call the exhausted
result retryable was made by another one, and the two disagreed the moment an
operator extended a client with `retry.AddWithErrorCodes` — which is exactly what
this record tells USOSS-11 to do for the EC2 teardown path. The client retries a
`DependencyViolation`, exhausts, and the provider reports a terminal error, so a
caller abandons a deploy that would have worked. Silent, and in the dangerous
direction.

USOSS-13 found the same shape in its own port and reported it could not reach the
client's retryer, because the `Substrate` seam is deliberately narrow
per-operation interfaces holding no client options — and that narrowness is worth
keeping, because the short interfaces are what let a reviewer audit what this
package can do to an account. Their workaround was a configuration hook. The
ruling is neither a hook nor a widened seam: the adapter already receives the
client, so the fix is entirely inside it, and the seam stays narrow.

### The composition property, which survives the mechanism

Preserved from USOSS-13's design even though its hook goes away:

> Every signal is consulted **in addition to** the others and never instead of
> one, so any of them can only ever widen. A wrong extra signal cannot make a
> retryable failure terminal.

The safe failure is over-retrying; under-classifying costs a deploy. This is the
one part of USOSS-13's design that was never in doubt, it outlived two mechanisms
that were, and it is what makes the caller hook safe to expose at all.

### Reversed: the client's retryer is not consulted at all

Two positions preceded this one, and the second failed for a reason worth
carrying into every port.

A separately constructed default retryer disagreed with the client the error came
from. So the adapter was given *that client's* retryer, which made the retry
decision and the classification decision the same function. That looked exempt
from the lesson that had just deleted this package's retry ownership, because it
*read* the caller's configuration rather than trying to own it.

It was not exempt, and there are two independent reasons. The second is the one
that makes this a soundness result rather than a preference, so take it first:

> **`aws.Retryer` does not require wrapper-insensitive classification, so a
> caller's implementation may classify by concrete type without doing anything
> wrong.** There is no correct way to hand a foreign classifier an error when the
> interface never promised the classifier ignores wrapping.

Review demonstrated it with a custom retryer whose `IsErrorRetryable` type-asserts
to `*awshttp.ResponseError` at the top level and uses `errors.As` only inside it.
It retried a `DependencyViolation` twice during the operation and answered
terminal when the adapter handed it the `*smithy.OperationError` the SDK actually
returns. Same function, same underlying error, different wrapper, different
answer — and the retryer is not at fault, because `aws.Retryer` never said
otherwise. Note what does *not* rescue this: the SDK's own classifiers do use
`errors.As`, so checking them tells you nothing about the caller's.

**So "consult the client's retryer" is unrecoverable, not inconvenient.** Handing
it exactly what the SDK hands it would mean enumerating the SDK's wrapping, which
is the same open set one layer along.

The second reason needs no claim about wrapping at all:

> `IsErrorRetryable` is a caller-supplied function, so a client's configuration
> silently became this provider's error taxonomy.

A retryer that classifies nothing retryable is a real construction — an earlier
round built one, to defeat a guard that had asked a retryer for its attempt
budget and not its opinion. Against a client configured that way, every throttle
this package saw became `compute.ErrFailed`: a caller told its spec had to change
when waiting was the whole remedy. **The operator who turned retry down asked for
fewer attempts. They did not ask for a different error vocabulary.**

That makes it the third instance on this branch of one shape, and the shape is
the thing to remember:

> **A construction built on a surface we do not own.** Not the number of ways a
> behaviour can be disabled — that was the retry lesson one level up — but the
> fact that somebody else's function was answering a question this package's
> callers ask it.

So classification is now a fixed function of the error. Every signal is reached
with `errors.As` through whatever chain the error arrives in, and each is an
`OR`, so the composition property above still holds:

* **A named throttle code set.** The hand-maintained list the two retryer
  positions existed to avoid, back because what it was traded for turned out to
  depend on somebody else's classifier. The drift risk is real and in the
  dangerous direction; three things bound it — most throttles are also a 429 or a
  5xx, the set is copied from the SDK's own so it is checkable rather than
  invented, and `Config.IsRetryable` closes a new one without waiting for this
  package. Copied rather than referenced: `retry.DefaultThrottleErrorCodes` is a
  package-level map an operator can mutate in place.
* **A server fault.** A typed exception arriving without its transport wrapper
  carries the fault and not the HTTP status. A bare `ecrtypes.ServerException` —
  and, in another port, `s3tablestypes.InternalServerErrorException` — classified
  terminal without it.
* **IAM's two consistency exceptions.** `ConcurrentModificationException` and
  `EntityTemporarilyUnmodifiableException` are `FaultClient` and are in none of
  the SDK's code lists. Two concurrent reconciles touching one role were telling
  the caller its spec had to change — the race the source system handles at
  `bucket.go:799-816`, inherited by every port that creates a role through the
  shared identity service, which is all of them.
* **An HTTP 429 under a code nobody enumerated**, and **a connection that failed
  rather than a service that answered**. The second took over from the retryer: a
  reset connection or a read timeout that the SDK gave up on says nothing about
  the caller's spec, and terminal is the wrong answer for a deploy.

Cancellation is answered before any of them, because a context deadline reports
`Timeout() true` and would otherwise be told to try again.

### What this costs you, USOSS-11 especially

**Extending an SDK client's retryable codes no longer tells this provider
anything.** This record used to send you to `retry.AddWithErrorCodes` for the EC2
teardown path. Keep doing that so the *client* retries, and then say the same
thing again on this package's surface, or the exhaustion is classified terminal:

```go
cfg.IsRetryable = func(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) &&
		(api.ErrorCode() == "DependencyViolation" || api.ErrorCode() == "ResourceInUse")
}
```

It is consulted **in addition** and never instead, so it can only move an error
from terminal to `compute.ErrTransient`. It cannot narrow anything, cannot reach
a denial or a missing resource, and cannot answer "try again" to a cancelled
context. Widening costs a caller a wasted retry; narrowing costs it a deploy, and
a configuration field must not be able to do the second.

This is USOSS-13's hook, adopted after their design was overruled in favour of
the client's retryer and the client's retryer failed. The hook is on our surface
and does not depend on how anyone wraps an error.

### Testing it

Three things, all learned the expensive way.

**Assert the premise**: that the two clients in the fixture really do disagree
about the error — otherwise the test passes against a provider where the
configuration does nothing. That premise is what now proves the *cost* as well:
the extended client is asserted to retry, and the provider is asserted to
classify it terminal anyway. A documented consequence no test touches is a
documented consequence that quietly stops being true.

**Carry a control in both directions.** A table proving two exceptions are now
retryable is indistinguishable from a classifier that calls everything retryable,
so it carries a throttle that must stay retryable *and* a genuine spec error that
must stay terminal. The probe that found the IAM exceptions used a throttle as a
control for the same reason.

**Check the behaviour, not the label.** A retryer's `MaxAttempts()` is a name for
a budget: a standard retryer with its `Retryables` emptied reports 3 while making
one attempt. A guard that read the number passed a client that never retried. The
generalisation is worth more than the instance — *when you choose an observable,
check whether it is the value or the name of the value.*
