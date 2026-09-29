## USOSS-35 — pinning is a typed refusal, not a capability

A provider whose secret store has no revisions refuses a non-empty
`compute.SecretBinding.Version` with `compute.ErrVersionPinningUnsupported`. It
is not gated by a `compute.Capability`.

### Why a refusal rather than a best effort

Ignoring a version a provider cannot honour reproduces the exact defect the field
was added to close, one layer further in and now with a field in the interface
implying otherwise: the workload is bound to the latest value while its caller
believes it is pinned. A pin exists to bound what a leaked credential is worth,
so "the latest value, silently" is the one outcome that is worse than having no
field at all. Refusing is the only answer that leaves the caller knowing what it
got.

`compute/k8s` is the concrete decliner, and it is worth naming why it cannot
fake one. A Kubernetes Secret carries no content version anywhere in the object.
Its `resourceVersion` is an optimistic-concurrency token that changes on writes
the caller never made, so mapping one onto the other would look like honouring
the pin while following the latest value — the failure mode dressed as the fix.

### Why not a capability

A `compute.Capability` is a whole port, or a class of behaviour a substrate may
structurally lack; a provider advertises it and a caller asks before it builds
anything. This is one field on one spec.

Gating it would put the answer in the wrong place twice. A caller would have to
consult the capability set to decide whether a field on a struct is legal, and a
provider that advertised the capability would still have to refuse an individual
revision that does not exist — so the refusal is needed regardless and the
capability adds a second, coarser way to ask the same question. What a caller
acts on is the refusal, and it arrives from the call that could not be satisfied.

`StoredSecret.Version` already answers the "can this substrate pin at all"
question earlier and more cheaply, at the write, without a capability bit.

### Why the sentinel wraps ErrUnsupported

`ErrVersionPinningUnsupported` wraps `compute.ErrUnsupported`, so a caller that
already branches on that sentinel sees it with no change, while a caller that
wants to tell "this provider cannot pin" from "this provider has no such port"
can. The wrapping is asserted structurally rather than by hand: `compute`'s
contract test derives the sentinel population with `go/types` and checks each
one's declared parent, so a sentinel declared with `errors.New` — or wrapping the
wrong parent — fails without anybody remembering to add it to a list.

### An unknown revision is refused too, and it is the same rule

A provider that *does* pin must also refuse a revision that does not exist rather
than falling back to the current value. Falling back is the same silent
degradation as ignoring the field, and the conformance suite drives both halves —
a decliner refusing, and an honourer refusing an unknown revision — because a
check that drove only one would pass against a provider that refuses everything.
