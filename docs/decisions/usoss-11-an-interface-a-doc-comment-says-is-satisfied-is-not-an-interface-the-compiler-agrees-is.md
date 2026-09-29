## USOSS-11 — an interface a doc comment says is satisfied is not an interface the compiler agrees is

*Recorded from USOSS-11's review, which found the port's headline capability —
secret injection by reference from this provider's own SSM store — composed
nowhere but in a test stub, while the interface's own doc comment said otherwise.*

`SecretResolver` said, of the SSM-backed store:

> It is satisfied by the SSM-backed secret store (USOSS-26).

It was not. Both methods differed, in both directions:

    seam    SecretParameterARNs(ctx, []SecretBindingRef)     SecretReadPolicy(...) (string, error)
    store   SecretParameterARNs(ctx, []compute.SecretBinding) SecretReadPolicy(...) (PolicyDocument, error)

`var _ SecretResolver = (*Provider)(nil)` does not compile. No adapter existed
anywhere in the repository, so an operator could not wire this provider's
container port to this provider's secret store without writing glue that was
neither present nor specified — and every test and every conformance run
resolved secrets through `stubSecrets`. The claim was false on arrival rather
than drifted: the placeholder declaration and the real store landed in one
package, and reconciling the *type* collision did not reconcile the *method*
one.

### The signatures are not converged, and that is deliberate

Each spelling is right for its own side, so picking one would trade one side's
correctness for the other's convenience:

- The seam takes `SecretBindingRef` — a flattened mirror of
  `compute.SecretBinding` — so a secret store implementing it carries no
  dependency in the direction that would let it reach back into the compute
  types it is called from. The store, in this package and already holding
  `compute.SecretStore`, has no such constraint.
- The seam returns a rendered document rather than a `PolicyDocument` for the
  same reason: a policy document is this package's type, and a resolver an
  operator writes must not need it.

So both are kept and one small adapter — `providerSecretResolver`, reached
through `Provider.SecretResolver` — is the only thing required to know both.
Beside it is the `var _ SecretResolver` assertion whose absence is what let the
two drift unnoticed for a release.

### Self-composition is the default, because the alternative shipped uncomposed

`ContainerConfig.Secrets` is an interface so an operator *can* bind one
provider's container port to another provider's store. That is a real need and
the reason the seam is not a direct call. It is not the common case. The common
case is one provider with both ports, and requiring hand-written glue to connect
a provider to **itself** is how the capability shipped with no path through it.

Nil now means "this provider's own store, if it has one". Nil with no
`Config.Secrets` still refuses a spec that binds secrets, which is the direction
that field documents.

Two consequences worth stating, because both were found by making the change:

- **The conformance fixture stopped using the stub.** With a stub resolver in
  `fullConfig`, `security/secrets-do-not-cross-placements` could not pass for the
  right reason — a stub does not know where a secret is stored. The tests that
  need an adversarial or a broken resolver now set the field explicitly, and
  everything else exercises the real store.
- **A fail-closed test went green for a second reason.**
  `TestSecretsAreRefusedWithoutAResolver` cleared only
  `ContainerConfig.Secrets`, which was sufficient while nil ended the search.
  Once nil began composing, the test still passed — against a provider that had
  a store, on an unrelated refusal of a hand-composed reference outside the
  configured path prefix. It now clears `Config.Secrets` too and asserts what
  the refusal *says*. A fail-closed assertion that has two ways to pass is not
  evidence for either.

### The rule

A satisfaction claim in prose is a comment about the type system, and the type
system will state it for free. Write `var _ Iface = (*T)(nil)` or do not write
the sentence — and if a seam's only implementation is a test stub, the seam has
not been composed, whatever the comment says.
