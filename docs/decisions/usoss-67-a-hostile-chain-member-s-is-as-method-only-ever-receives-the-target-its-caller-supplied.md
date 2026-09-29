## USOSS-67 — a hostile chain member's Is/As method only ever receives the target its caller supplied

USOSS-67 was filed as a note-only residual from PR #27's review of
`postgres.sealed`: `errors.Is` runs an `Is(error) bool` method on every error in
the chain it walks, including one this repository did not write, so a chain
containing a caller- or dependency-supplied cause executes foreign code. The
ticket asked for a repo-wide population, a per-site judgment of what is in
reach, and a pin on every site judged acceptable.

### The population, counted rather than estimated

A `go/ast` walk (not a text search — a comment reading `// errors.Is(err,
ErrUnsupported)` is not a call) over every non-test `.go` file under
`credentials/`, `compute/`, `store/`, and `postgres/` finds **262** calls to
`errors.Is` or `errors.As`. `postgres/conn.go` contributes one: `sealed.Is`
itself.

Judging 262 sites individually, or commenting each with the same three-word
verdict, is the restated-invariant failure `CONTRIBUTING.md`'s decision-record
rule already warns about, and it is exactly what `secret_hygiene_test.go` and
`errhygiene_test.go` reject in favour of deriving a class from the type system.
So the question this record answers is not "site by site, is material in
reach", but "what is the one fact that decides it everywhere at once".

### What a hostile `Is`/`As` method can actually receive

`errors.Is(err, target)` walks `err`'s chain. For a chain member `e` that is not
`==` to `target`, the standard library calls `e.Is(target)` if `e` defines that
method — code this repository may not have written. The **only** argument that
call receives is `target`. It is not handed `err`, any sibling branch of a
multi-`%w` wrap, the calling function's other locals, or a receiver's fields —
Go's method dispatch gives a receiver its own fields and exactly the arguments
its caller passed, nothing else. `errors.As(err, dst)` is the same shape: a
member's `As(any) bool`, where defined, receives only `dst`, the pointer the
call site declared immediately beforehand — always the zero value going in, so
there is nothing to read back out through it, only something to (mis)write.

So "is a credential, a Secret, or a SecretValue reachable from an attacker's
`Is`/`As`" reduces to one question with no per-site component: **can the
`target`/`dst` a call site supplies ever itself be, or carry, one of those
types?** `errors.Is`'s `target` parameter is statically typed `error`.
`errors.As`'s `dst`, at the point a custom `As` method would be invoked, must
satisfy `error` or be an interface, or the standard library panics before any
user code runs. Neither `credentials.Secret`, `credentials.Foreign`, nor
`compute.SecretValue` implements `error` — inspecting every method on each
(`IsZero`, `Format`, `String`/`GoString` on `Foreign`, `LogValue`,
`MarshalJSON`/`MarshalText`/`UnmarshalJSON`, `GobEncode`/`GobDecode`) turns up
none named `Error`, by design: they hold material, not failures. The same fact
closes the other direction too — none of the three can appear as a chain member
at all, wrapped or bare, because `fmt.Errorf`'s `%w` and every wrapping
constructor in this codebase require the wrapped value to satisfy `error`.

That single fact — pinned below — clears all 262 sites at once. A future change
that gives one of these types an `Error() string` method (to make a marshal
failure `%w`-friendly, say) reopens exactly the question this ticket asked, and
the pin fails loudly instead of the population silently growing unnoticed.

### The three sites where a credential-shaped value is merely nearby

The reduction above does not depend on lexical proximity, but the ticket asked
for the receiver/captured-variable question answered directly, and grepping for
it surfaces three sites where a `Secret`/`Foreign`/`SecretValue`-shaped value
sits in the same function as an `errors.Is`/`errors.As` call:

* `compute/aws/secret.go`'s `(*secretStore).Put` holds `spec.Value
  compute.SecretValue` while calling `errors.Is(err, ErrParameterExists)` and
  `errors.Is(mErr, ErrParameterNotFound)`. Both targets are package sentinels;
  `spec.Value` is never passed to anything in `err`'s chain. **Acceptable,
  nothing in reach** — pinned by `TestSecretValueIsNotAnError`
  (`compute/errreach_test.go`), since that is the fact that would have to break
  first.
* `credentials/lifecycle/issuance.go`'s `ExpiryDisposition` takes `rec
  *Record` and calls `errors.Is(revokeErr, ...)` against two of this package's
  own sentinels. `Record` is documented ("There is no field on this type
  capable of holding credential material, and that is a load-bearing property
  rather than an accident") and already pinned by
  `testNoMaterialSurvivesARoundTrip`
  (`credentials/lifecycle/lifecycletest/conformance.go`). **Acceptable** —
  reaffirmed, not re-pinned: pinning the same claim twice is the drift
  `CONTRIBUTING.md` warns about for decisions, and it applies equally to tests.
* `store/credentials.go`'s `(*CredentialRecords).Update` takes `rec
  *lifecycle.Record` and calls `errors.As(err, &cfe)` against
  `*types.ConditionalCheckFailedException`. Same `Record`, same existing pin.
  **Acceptable.**

`ensureExecutionRole` (`compute/aws/execrole.go`) also matched a naive
"signature mentions Secret" grep through its `secretRefs
[]SecretParameterRef` parameter; `SecretParameterRef` is a locator (env var
name, ARN, version) with no material field, so it is not actually one of the
three types this record is about — named here only so the grep hit does not
look silently dropped.

### `postgres.sealed`: the one site with a different shape, and why it still holds

`sealed.Is` is not "material nearby a target"; it is the ticket's original
finding, and it is different in kind: `s.is(target) = errors.Is(err, target)`
re-walks the **actual driver cause**, so a hostile driver error's own `Is`
method genuinely executes, with the caller's `target` — same as every other
site above. What makes it worth a named judgment rather than falling out of the
general rule is that `err`'s text may itself contain the DSN's password; the
type-based reduction only says the hostile method cannot be handed a
`compute.SecretValue`, and here the concern was ever about the driver's own
error text, not a typed value.

Restating PR #27's review finding with the general rule now available: the
hostile method receives exactly `target` (a plain sentinel — `context.Canceled`,
`compute.ErrFailed`, and so on, in every call site in this repository) and its
own receiver, which it already had. There is nothing new to copy out. The
residual capability a hostile driver keeps is to make its `Is` **lie** — claim a
match it should not — but that grants nothing beyond what the same driver could
already do by returning a different `err` outright; both are "this driver's
classification of its own failure cannot be trusted further than the driver is
trusted", which is the premise of calling an external driver at all, not a new
hole `sealed` opened. `TestASealedErrorsIsDelegationCannotExfiltrateThroughAHostileCause`
(`postgres/postgres_test.go`) exercises a driver cause with an adversarial `Is`
method against the existing `assertNoMaterial` machinery and pins that
observation.

### What was rejected

Per-site inline comments on all 262 calls: rejected as the enumeration this
repository's own hygiene tests exist to replace, and as 259 near-duplicate
sentences that would drift the moment one of them stopped being renewed by
hand.

A `go/types`-driven analyzer that checks every call site's argument type
against a denylist automatically: considered, and rejected for this ticket's
size. It would re-derive, at build-graph cost, exactly the fact this record
states once — that `errors.Is`'s `target` is statically `error`-typed and none
of the three redacting types implements it — and that fact is what is pinned
directly, at the three types, rather than re-checked at every call site that
depends on it.
