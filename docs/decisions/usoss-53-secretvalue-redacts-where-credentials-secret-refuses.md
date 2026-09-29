## USOSS-53 — `SecretValue` redacts where `credentials.Secret` refuses

*Recorded from USOSS-53, which was filed to resolve an apparent inconsistency
between the two credential-material wrappers. Most of the asymmetry was a real
gap and is now closed. One part of it is deliberate, and this record exists
because the obvious "fix" for that part panics the fake.*

`compute.SecretValue` and `credentials.Secret` both exist to stop credential
material escaping by accident. `credentials.Secret` was hardened first, and its
doc comment names three leaks it closed. `SecretValue` still had two of them.

### What was leaking, measured

The existing `TestSecretValueDoesNotLeak` checked `%v`, `%s`, `%+v` and `%#v`.
Those are four of the five verbs `fmt` routes through `fmt.Stringer` — every
verb it tested was one that could not leak, and the leaking verbs were exactly
the ones absent. The test passed for the whole life of the leaking type.

Enumerating the single-letter verb space instead of choosing from it, against
the old implementation: **462 leaking paths.** 230 bare and 230 struct-embedded
verb-and-flag combinations rendering `{%!d(string=correct-horse-battery-staple)}`,
plus two reflection paths. A hand-written probe found five of them; the derived
enumeration found all of them. That ratio is the argument against hand-picked
populations, and it is the same shape as the transition-versus-call lesson in
the contract: a list verifies what someone thought of, never the complement.

`slog`, `encoding/json` and `encoding/gob` did not leak. The first two route
through `Stringer`, and gob refused because the type has no exported fields —
safe by accident, which would end the moment somebody added one.

### Two defences, neither redundant

- `Format` for every verb closes the non-`Stringer` verbs.
- Masking the material closes `reflect.ValueOf(s).Field(0).String()`, which does
  not panic on an unexported field and returned the material in one call.

Masking is also the only thing that closes `%p`: `fmt` handles `%p` *before* it
consults `fmt.Formatter`, so no method can redact it, and the fallback prints
the struct's fields. Verified directly, with a control — a type whose only
defence is `Format` still renders `%!p(compute.formatOnly={MATERIAL})`, and this
type does not. So each defence closes something the other cannot, which is why
both are present rather than one being belt-and-braces, and why neither may be
dropped on the grounds that the other exists.

**Amended by USOSS-43: `%p` is a property of where the material lives, not of
any particular masking.** This section originally described the masking as *the
material XOR'd across two byte slices*, and that shape does not survive
USOSS-46: the mask sat beside the material, so eleven lines of ordinary
reflection — no `unsafe`, no build tags — recovered it by XORing the field pair.
The keystream is now derived from a package-level key that no `SecretValue`
references, so a reflective walk reaches masked bytes and a nonce and
recombining them yields nothing.

What carries over unchanged is the `%p` reasoning above, and it is the half most
easily lost in a rewrite because it is not about method dispatch: whatever
construction this type has, `%p` prints its fields, so the fields must not hold
the material. `TestFormatCannotCoverThePointerVerb` pins that against the
construction actually shipped, with a `Format`-only control that must leak.

`LogValue`, `MarshalText` and an explicit `GobEncode`/`GobDecode` refusal are
added for a different reason: those paths were already safe, but by consequence
of a handler's verb choice or of the current field set. They are now properties
of the type.

### The divergence that is deliberate

`credentials.Secret.MarshalJSON` returns an error. Aligning `SecretValue` with
it is wrong, and the reason is mechanical rather than aesthetic.

A `SecretValue` lives inside specs that are legitimately serialized for reasons
unrelated to reading the secret. `compute/fake`'s `revisionOf` marshals the
whole effective spec to hash it, so a caller can tell a real rollout from a
no-op `Ensure`, and it panics if the spec will not marshal. Making `MarshalJSON`
fail closed was tried: it panics `revisionOf`, and takes `compute/fake` and the
k8s conformance run down with it.

    panic: fake: spec is not marshalable: json: error calling MarshalJSON
    for type compute.SecretValue: compute: refusing to serialize credential
    material

The redaction is also load-bearing rather than incidental. Because it is a
constant, an admin password change does not alter the computed revision — which
is correct twice over: the password is not part of the effective configuration,
and a provider must not rotate it.

So the requirement is that material must not appear *and* marshalling must
succeed, and a constant redaction is the only thing that satisfies both. `gob`
is the exception because it has no redacted form to emit, so it refuses.

The two types differ because their jobs differ: a vended credential is seen once
by one caller and every serialization of it is a bug, while a spec is hashed as
a matter of course. Anyone aligning these should read `revisionOf` first.

### Not closed here — closed by USOSS-43

`Reveal` was still a method when this was written, so `text/template` reached the
material by name with `{{.Password.Reveal}}`, and
`TestSecretValueRevealIsReachableFromATemplate` asserted that leak so it appeared
in a test run rather than only in a review comment.

USOSS-43 closed it. `RevealSecret` is a package function, which no template can
name; the tripwire is inverted rather than deleted, as its own comment asked, and
the general template walk is folded into `leakPaths`. The rule that replaced it
is not a prohibition on the `Reveal` shape — two reviewers defeated shape rules
here in succession — but an allowlist: over the method sets of `SecretValue` and
`*SecretValue`, promotions included, only the methods `secretValueSurface` names
may exist. `MarshalText`, `GobEncode` and `GobDecode` from this record are on
that list, each with the reason it cannot carry material out.
