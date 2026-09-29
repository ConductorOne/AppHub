## USOSS-10 — a spec the substrate cannot express is refused at the spec

Binding on all six ports. Three instances in one ticket, which is what makes it a
rule rather than three judgement calls.

> When a substrate cannot express something the interface permits, refuse it as
> [compute.ErrInvalidSpec] naming the limit — do not round it, do not
> approximate it, and do not emit a request the service will reject.

The three:

* **`RetentionPolicy.MaxAge` that is not a whole number of days.** ECR expresses
  age in days. Rounding down can reach zero and expire every image; rounding up
  retains longer than the caller asked, and the caller set a staleness bound for
  a reason.
* **`RetentionPolicy` with both `KeepLast` and `MaxAge`.** ECR permits one
  lifecycle rule that applies to every image in a repository and requires it
  last, and both shapes this provider renders are that. The combination renders a
  document the service rejects outright. It costs nothing real — the source
  system prunes application images by count and cache layers by age, on two
  different repositories, never both on one — but it is an interface concession
  and is reported as one.
* **`Build.SessionDuration` below fifteen minutes.** The security token service
  will not issue it. Rounding up would silently give a credential handed to
  repository-authored code a longer life than the operator asked for.

The shared reasoning is about *where the failure lands*. Emitting the request
moves the failure from the spec, where the caller can act on it, to the middle of
a deploy, as a validation error about a document format the caller never wrote.
And every approximation is a decision about somebody else's bound, taken
silently.

The test for whether this applies: *could a caller write this spec from the
interface's documentation alone?* If yes and the substrate cannot serve it, that
is a refusal plus a reported concession, not a rounding.
