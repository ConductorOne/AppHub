## USOSS-35 — the deploy layer's interim refusal of a pinned SecretRef is deleted, and the pin travels through

This reverses the last section of *USOSS-15 — the SecretRef adapter is a lookup
in a table this layer built, and a pinned version is refused until USOSS-35*.
That entry said the refusal was interim, that it would go when USOSS-35 landed,
and that it would be deleted there rather than there and then. This is that
deletion, recorded as a new entry rather than an edit, per this directory's rule.

### What changed

`compute.SecretBinding` now carries a version, so the two outcomes that forced
the refusal — refuse the pin, or bind the current revision and hand the workload
material the credential layer did not authorise — are no longer the only two.
`modules/deploy` passes `credentials.SecretRef.Version` straight into
`compute.SecretBinding.Version` and the provider decides.

### The conversion does not validate the revision, deliberately

A revision is provider-issued and opaque above the interface. Checking one in the
deploy layer would be this module guessing at another package's vocabulary —
precisely the mistake the USOSS-15 entry rejected when it refused to compose a
`Ref` from a provider's path convention. The provider refuses a revision it
cannot honour (`compute.ErrVersionPinningUnsupported`) or does not have
(`compute.ErrNotFound`), and neither refusal falls back to the current value.

### The revision a deploy's own Put reported is not remembered

`secretBinder.put` discards `StoredSecret.Version`. A pin is the credential
layer's decision, and a version this module remembered from its own write would
pin every later deploy to the revision *this* one happened to create — a pin
nobody asked for, and one that would freeze out the next rotation. The database
password this module mints for itself is bound unpinned for the same reason.

### What replaced the tests that pinned the refusal

The refusal had two tests and both are now assertions about the pin travelling,
because deleting them would have left the field's most important property — that
it is not silently dropped between the credential layer and the provider —
covered by nothing:

* the field-derived refusal table over `credentials.SecretRef` keeps its
  both-directions population check, with `Version` exempted **by name** and
  pointing at the two tests that do cover it, so removing them fails the count;
* the end-to-end test through `Execute` now drives both halves: a pin to a
  revision that exists deploys *and is visible in the rendered specification*,
  and a pin to one that does not fails the deploy with `compute.ErrNotFound`.
  Either half alone passes against the wrong provider — the first against one
  that refuses every pin, the second against one that ignores the field.
