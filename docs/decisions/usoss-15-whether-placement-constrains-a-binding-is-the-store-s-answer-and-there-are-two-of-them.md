## USOSS-15 — whether placement constrains a binding is the store's answer, and there are two of them

`compute.SecretInfo` carries a `PlacementScope` alongside its `Placement`, with
two values: `SecretPlacementScoped` and `SecretPlacementGlobal`. A caller asks
the scope first and compares placements only when there is something to compare.

### Why one field was not enough

The first version reported a placement and nothing else, and the AWS store had
to report *something*. It resolved the provider's **default** placement and
returned that — while `Put` accepted any configured placement and stored the
parameter regardless, because an SSM parameter is account-global and
`compute.SecretSpec` says in as many words that an AWS provider ignores the
field.

So a secret stored at `secondary` was described as living in `default`, and the
deploy module — comparing the two exactly as designed — would have refused a
correct deployment as cross-placement. Review reproduced it.

**An invariant that is too strong manufactures findings, and a caller that trusts
one acts on it.** The placement was not wrong by accident: there was no true
answer available in the vocabulary the field offered, so the implementation
returned a plausible one.

### The two answers are genuinely different

* A Kubernetes `secretKeyRef` resolves only within the pod's own namespace. A
  secret there **is somewhere**, and a workload elsewhere cannot bind it.
* An SSM parameter is account-global. A secret there is **nowhere in
  particular**, and every workload the provider runs can bind it.

Collapsing those into one field forces the second to lie. Naming the third state
is the same move this project made for `SupportPartial` and for a bucket policy
it could not fully evaluate: **when a check's answer is not one of two poles, add
the state rather than folding it into the nearest one.**

### What it buys the caller

The deploy module's requirement that an application binding provider-held secrets
must name its placement now applies **only to a scoped store**. Requiring it
unconditionally would have imposed a configuration on AWS deployments in order to
satisfy a check that can never fire on them — a false requirement to serve a
comparison with nothing on the other side.

A scope outside the two defined values is **fatal** in the preflight, not
ignored. A provider answering with something unrecognised would otherwise have
its placement silently unchecked, which is the one outcome the preflight exists
to prevent.

### What keeps it true

`security/secret-metadata-read-returns-no-material` asserts the coupling — scoped
implies a placement, global implies none, anything else fails — and then, for a
scoped store, **puts a secret into every placement the provider was configured
with and requires `Describe` to report the one `Put` was given.** A single-
placement check would have passed the defect: the store always answered its
default, and its default was the only placement anybody tested.
