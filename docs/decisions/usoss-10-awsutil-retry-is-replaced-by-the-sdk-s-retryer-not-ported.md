## USOSS-10 — `awsutil.Retry` is replaced by the SDK's retryer, not ported

> **Amended.** The division below — the SDK retries, this package classifies,
> the caller decides whether to try again — still holds. The *mechanism* for
> classification does not: "classification through the client's own retryer",
> below, was reversed, and the corrected version, with the reasons the client's
> retryer had to go, lives in
> [the record that amended it](usoss-10-classification-belongs-in-the-adapter-that-holds-the-client.md).
> The two passages marked below are the specific claims that reversal made
> false; the rest of this record still describes what shipped.

Binding on USOSS-11 through USOSS-14 and USOSS-26. Recorded because an
undocumented replacement is indistinguishable from an oversight, and because the
brief for every AWS ticket says to port `awsutil.Retry` **or** to replace it and
say which. This says which.

**`compute/aws` contains no retry loop.** The source system wraps most of its
AWS calls in `awsutil.Retry` (`backend/internal/awsutil/retry.go`), which is a
hand-rolled loop over a list of retryable error codes. It is not ported. What
replaces it is the AWS SDK's own standard retryer, which is on by default on
every client and which the hand-rolled loop was reimplementing badly: the SDK
has exponential backoff, a client-side rate limiter, and a token bucket that
stops a throttled service being hammered by every concurrent caller at once, and
`awsutil.Retry` has none of those.

Porting it *as well* would have been worse than either: two nested loops
multiply, so five attempts around a client already making three is fifteen
requests against a service that is asking for fewer.

So the division is:

* **The SDK retries.** Backoff, jitter, and the attempt budget are its business.
* **This package classifies.** `classify` (`compute/aws/awssdk.go`) classifies
  from the error itself — a named throttle code, an HTTP status, a server fault,
  and a short further list of signals, each reached with `errors.As` — **not**
  by asking any client's retryer whether the error was retryable. [Amended: see
  the note at the top of this record.] `Provider.substrateError` maps a
  throttle onto [`compute.ErrTransient`]. By the time an error reaches a caller
  the SDK has already given up, so `ErrTransient` means "the provider tried and
  you may try again", which is what the sentinel promises.
* **The caller decides whether to try again.** `compute.ErrTransient` is explicit
  that nothing in the compute package retries on a caller's behalf, and that a
  provider must not retry past the caller's context deadline. The SDK honours the
  context, so that obligation is met by construction rather than by a budget this
  package would have to keep in step with one it does not own.

### Four attempts to guarantee it, and why there are none now

This package tried to make retry non-optional, and the attempt is recorded
because the failure is structural rather than a run of bad luck.

First as a **guard**, in four versions, each defeated by a different part of the
retryer: an attempt budget, which is a name for a budget and reports 3 while the
retryable classifiers are empty; correct classification, with a token bucket
behind it that never issues a token; counting real attempts through a fake
transport, which **spent the certified client's retry quota** — after fifty
probes a client could make one attempt instead of three, so the guard
manufactured the condition it existed to detect; and overriding the delay to
make that probe fast, which changed the object being measured.

Then as **ownership**: install this package's own retryer and there is nothing
left to guard. That lasted one round. `Options.RetryMaxAttempts` is re-applied
*over* an installed retryer, so owning the retryer was not owning the behaviour.
And `APIOptions` survives a client rebuild and runs *after* the SDK installs its
retry middleware, so a caller can remove that middleware by ID and reduce every
client to one attempt. Three disable paths, and the fourth is whatever the SDK
adds next.

> **Owning a behaviour inside somebody else's extensible object is enumerating
> its disable paths.** The set is not closed, and it is not ours to close.

That is the same failure the guards taught, one level up — and it is why the
answer is neither a guard nor ownership.

### So retry configuration belongs to the composition root

Stated as a consequence rather than defended, **and this is the first of the
two claims the later reversal made false** — see the amendment note at the top:

	A caller who disables retry on these clients gets a provider that does not
	retry, and throttling errors are classified terminal rather than
	compute.ErrTransient.

That is not what shipped. Disabling a client's retry changes only how many
attempts the SDK makes on the caller's behalf — one instead of three — and
nothing about how the single attempt's result is classified: a throttle is
still `compute.ErrTransient` however the client is configured, because
classification does not consult the client. What the consequence *should* have
said, and does after the reversal, is that a caller who disables retry simply
does more of the retrying itself.

Visible and diagnosable, and strictly better than what the ownership machinery
produced — which was this package causing the same outcome by its own means,
through a shared rate limiter, a removable middleware, and a classifier invoked
after the retry loop had already finished.

**This is the second claim the reversal made false.** What was kept at the time
of this record was classification through the client's own retryer, on the
theory that it was never the problem: it made the decision to retry and the
decision to report the exhaustion retryable one function, whatever the client
was configured to do. That theory did not survive contact with a caller-supplied
`IsErrorRetryable` — see the amended record for why a client's retry
configuration silently became this provider's error taxonomy, and why
classification was moved onto signals this package owns instead.

### One divergence to carry forward

`awsutil.Retry` retries **five** times and treats `DependencyViolation` and
`ResourceInUse` as retryable. The SDK's standard retryer makes **three**
attempts and treats neither as retryable.

That difference is harmless in USOSS-10 only by accident of scope: both codes
belong to the EC2 teardown path (`build.go:785-954`), which this ticket did not
port. **It stops being harmless the moment USOSS-11 ports that path.** A security
group cannot be deleted while a network interface still references it, and the
`DependencyViolation` that reports this really does clear on its own once the
interface is released — so a teardown that does not retry it fails where the
source succeeds.

USOSS-11 should add those codes through a `retry.AddWithErrorCodes` option on the
EC2 client it builds, not by reintroducing a loop above the SDK, and not by
adding them to `classify` — where they would make an EC2-shaped exception a
property of every service this package talks to.
