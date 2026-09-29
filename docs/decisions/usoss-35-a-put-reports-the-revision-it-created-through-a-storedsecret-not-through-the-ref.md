## USOSS-35 — a Put reports the revision it created through a StoredSecret, not through the Ref

`compute.SecretStore.Put` returns `StoredSecret{Ref, Version}` rather than a bare
`compute.Ref`.

### Why Put has to report a revision at all

`compute.SecretBinding.Version` is only fillable by somebody who knows which
revision exists. The write is the only place that knows: it is the operation that
created the revision. Without this, the field could be filled only by a caller
that obtained a version from outside the interface — and a field nobody inside
the interface can fill correctly is a worse artefact than the gap it replaced,
because it reads as a capability while being a dead end.

### Why the version is not part of the Ref

Encoding the revision into `Ref` was the obvious design and it is wrong.

A `Ref` is the *identity* of a resource. Folding a mutable revision into it makes
`Ref` equality stop meaning "the same resource" and start meaning "the same
resource at the same revision" — a semantic overload inherited by every future
reader who compares two Refs, in a type whose entire job is to be comparable. It
also breaks the conformance suite's "the same spec yields the same Ref"
invariant, which is asserted across all three Puts of the idempotence check: a
provider that minted a new Ref per write would look correct against a
version-bearing Ref and would have silently stopped being idempotent.

So identity and revision are two fields of one result. `StoredSecret.Ref` does
not change when the value does; `StoredSecret.Version` does.

### What an empty Version means, and why it is not an error

Empty means the store has no revisions. That is a fact about the substrate, not a
failure, and it is reported at the write rather than at the bind for a reason: a
caller that needs a pin learns it cannot have one *before* it builds a workload
specification, instead of finding out from a refused `EnsureService` after an
image repository and an identity already exist.

### The version is opaque, and the AWS provider is the reason to say so

`compute/aws` renders SSM's parameter version as a decimal string, and SSM
honours a `name:version` selector natively. That is a coincidence of one
substrate. A caller passes the string back through `SecretBinding.Version` and
never parses it; `compute/aws` parses its own, and refuses a version it did not
issue the shape of (`compute.ErrInvalidSpec`) rather than composing a selector
from a caller's arithmetic.
