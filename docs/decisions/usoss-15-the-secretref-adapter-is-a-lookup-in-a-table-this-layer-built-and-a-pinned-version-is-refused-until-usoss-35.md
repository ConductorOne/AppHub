## USOSS-15 — the SecretRef adapter is a lookup in a table this layer built, and a pinned version is refused until USOSS-35

The workload-identity contract assigns exactly one conversion to the deploy
layer and to nobody else: `credentials.SecretRef` to `compute.SecretBinding`. It
requires the conversion to validate that the named store belongs to the selected
compute provider and to fail loudly otherwise.

### The conversion cannot be a pure function, and that turns out to be the point

A `credentials.SecretRef` names a store and a store-scoped name. A
`compute.SecretBinding` needs a provider-issued `compute.Ref`. `compute.SecretStore`
has `Put`, `Get`, `Delete` and `DeleteScope`, and no operation that turns a name
into a `Ref` — `Get` already needs one.

So the only sound conversion is a lookup in a table this layer built itself, one
entry per secret it wrote through this provider on this deploy, plus the
references an earlier deploy recorded on the application. A reference the table
does not contain is refused.

That is not a consolation. It is the contract's requirement obtained by
construction rather than by comparing two strings that were never guaranteed to
be drawn from one vocabulary. The alternative — composing a `Ref` from the
provider name and the secret's path — is a restatement of provider-internal
naming: `compute/fake` keys a secret by `placement/scope/name` and `compute/aws`
by an SSM path, and getting that right for two providers is getting it wrong for
the third.

### An unset store name is fail-closed, not permissive

`Config.SecretStoreName` binds the credential layer's vocabulary for this
provider's store to the provider. It is optional, and unset means a reference
that *names* a store is refused — because nothing then establishes that the
store it names is the one this provider backs. A reference naming no store is
the deployment's default store and is accepted either way.

### A version-pinned reference is refused, and the refusal is scheduled for deletion

`compute.SecretBinding` has no version field. A version-pinned reference
therefore has two possible outcomes here: refuse it, or bind the current
revision and hand the workload material the credential layer did not authorise.
The second is a silent downgrade of a pin somebody set deliberately.

**This refusal is interim.** USOSS-35 adds the version to the binding; when it
lands, this branch goes and the version travels through instead. It is deleted
there, not here, and the refusal names USOSS-35 in its own message and in its
comment so that whoever lands it finds this.

### The population the tests quantify over

`credentials.SecretRef` has four fields and each one is a way of asking for
something this conversion might silently drop, so the test derives its
population from the type: a field added there with no case in the table fails.
Both directions are asserted, because a table of four refusals is satisfied by a
conversion that refuses everything.

And the refusal is verified through `Execute`, not only against the adapter. A
conversion tested in isolation can be correct while nothing calls it.
