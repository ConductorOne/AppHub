## USOSS-19 — the capability matrix is generated from the providers, not written

USOSS-20 needs a published answer to "which capabilities does each provider
support". That is a factual claim about code, and five separate defect classes on
this project have been a document that stopped agreeing with the thing it described.

So `docs/design/capability-matrix.md` is generated. `compute/matrix` derives a
provider's matrix from three things it does not restate: the capability-gated
accessors read out of `compute.Provider`'s reflected method set, the capability
population from `compute.AllCapabilities`, and what the provider's own accessors
actually return. A test renders the document and compares it byte for byte with
what is committed, so a provider whose capabilities change turns the build red.

Three properties are worth recording because each closes a way the artifact could
be confidently wrong.

**A derivation that returns nothing passes every check written over it.** `Derive`
therefore fails rather than returning an empty matrix — no accessors, no capability
constants, or no rows is an error — and the document's test additionally requires
the rendered table to contain both a supported and an unsupported answer, which
catches the two ways it could be uniformly wrong.

**A restatement of a set drifts from the set.** `compute.AllCapabilities` is a
hand-written slice claiming to be the whole population of a const block a few lines
above it — the same shape as the `Granter` port list that a port carrying `Granter`
once walked straight past. It is cross-checked generatively: a test parses this
package with `go/ast`, collects every constant declared with type `Capability`, and
requires the two sets to be equal. Both mutations — dropping a constant from the
list, and adding a constant without listing it — were reproduced and caught.

**A port that exists but is unimplemented can hide.** `compute.Provider` is designed
so a refusal happens at acquisition: the accessor returns `ErrUnsupported` and the
caller never receives a port. Nothing in the type system forbids the opposite — a
provider that advertises the capability, hands out a port, and refuses every call —
and a capability set can agree with the accessors while the port behind one of them
is a shell. With probing enabled, `Derive` calls every method of every port it
obtained and reports a port whose every method refuses as a stub rather than as
available. The fixture is a real provider with one accessor replaced by exactly such
a shell, and the control half matters as much: a working port must not be swept up by
the same probe. Probing is opt-in because it calls methods with zero-valued
arguments, and "that is inert" is a property of an implementation rather than of the
interface.
