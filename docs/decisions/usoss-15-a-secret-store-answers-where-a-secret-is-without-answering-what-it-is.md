## USOSS-15 — a secret store answers where a secret is without answering what it is

`compute.SecretStore` gains one method:

```go
Describe(ctx context.Context, ref Ref) (*SecretInfo, error)
```

`SecretInfo` carries the reference and the placement. Nothing else.

### Why an interface change, when the ruling was that a read-back is not this PR's

The ruling stands and this is not the thing it deferred. What was deferred is a
**read-back** — an operation that returns state a caller wrote, which on a
secret store means the material. This returns a locator and a location, and the
distinction is the whole justification: existence and placement are not the
secret.

The reason it is needed is that two ordinary operator transitions make a binding
invalid and nothing could see either before creating infrastructure:

* somebody deletes or rotates the secret the record still references;
* somebody moves the application to another placement and keeps its bindings.

Review reproduced both. Each was refused by the provider when the *workload* was
created — `saves=2 rendered=2` and `saves=2 rendered=3` — so a rejected deploy
had already built an image repository, an identity and, in the second case, a
secret. Everything before that point is a resource nobody asked for.

`Get` cannot serve: it returns the value, so using it to establish existence
means pulling every application's secrets through the deploy module on every
deploy, which is exactly the traffic the interface is careful to avoid.

### What keeps "non-material" true

Not the comment. Three things that fail a build:

* **`SecretInfo` has no field that can hold a value**, and a conformance check
  asserts that structurally — a `SecretValue` field would make the operation a
  read-back whatever any provider chose to put in it;
* **`security/secret-metadata-read-returns-no-material`** stores a sentinel,
  describes it, and searches every field of what comes back. It also asserts
  that describing a deleted secret is `ErrNotFound`, because a store that says a
  missing secret is fine cannot be preflighted against;
* **`fake.DefectSecretValueInDescribe`** returns the material through a field
  named for something else, and the suite's self-test asserts the check catches
  it. Verified by mutation: with the content assertion disabled the defective
  provider passes the whole suite.

### What it cost, and what it bought

Two implementations (`compute/fake`, `compute/k8s`; the AWS store is not ported
yet — USOSS-26), one conformance check, one injected defect, and a small
correction in the suite: the secret port's liveness op now asks `Describe`
rather than `Get`, so the conformance suite stops reading secret values to find
out whether a secret exists.

`Get` moves to the suite's undriven-methods table with a reason, an expiry and
the check that does exercise it — because a method nothing drives and nothing
names is the defect USOSS-32 closed.

### The one it does not close

A secret deleted *between* the preflight and the workload's creation. The
provider's refusal remains the backstop for that, and it always will be: no
preflight can close a race. The two stable-state cases are closed — for every
reference the deploy will bind, which is `Plan.Secrets` and `Artifacts.Secrets`
both, and not only the ones the application record declares. Review found the
first version of the preflight walking only `Plan.Secrets`, so the one binding
this module issues for itself was the one nothing asked about; see the entry on
partial application.
