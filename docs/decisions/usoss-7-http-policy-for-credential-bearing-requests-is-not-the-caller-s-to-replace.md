## USOSS-7 — HTTP policy for credential-bearing requests is not the caller's to replace

Every provider in `credentials/` sends an administrative credential in an HTTP
header. Two properties of that request are load-bearing:

* a redirect must not be followed, because Go's client strips `Authorization`,
  `Cookie` and `WWW-Authenticate` across hosts and knows nothing about
  `DD-API-KEY` or any other vendor header, so a followed redirect hands the
  credential to whatever the `Location` header named; and
* an error from the transport must not be returned, because the transport has
  already seen the authenticated request, and an instrumentation layer that
  annotates failures with request detail is an ordinary thing to write.

The first port stated both as documentation. Each provider accepted an
`*http.Client` and its option comment said the caller taking that option was
"responsible for" preserving the properties. Review defeated both in one
sitting: an ordinary replacement client followed a synthetic 302 and the second
request carried the Datadog administrative key, and a request-dumping
`RoundTripper` produced provider errors containing a full `DD-API-KEY` and a full
app JWT.

**Decision: `internal/credhttp` owns both properties, and the type that carries
them exposes no way to change either.** `credhttp.Client` wraps an unexported
`*http.Client` with no accessor, so `CheckRedirect` is unreachable; its only
method classifies before returning, so no foreign error text escapes. Providers
accept a `http.RoundTripper` — which is what a caller wanting tracing, a proxy or
a test double actually needs, and which cannot express a redirect policy.

Two things follow, and both are the reason to write this down.

**The delegation was a shape, not three bugs.** The same "the caller is
responsible for" comment existed in `credentials/datadog`, `credentials/github`,
`internal/githubapp`, and `credentials/c1`. Review found the first two. The
fourth had no implementation yet, so it was changed to `Transport` in the same
change rather than left to be implemented against by USOSS-8 — a defect found
twice does not need to be shipped a third time. If a fifth provider appears, it
takes a `http.RoundTripper` too; a review comment asking for redirect refusal is
not the mechanism.

**The cost is real and is the point.** A caller cannot set a timeout, cannot
follow a redirect it knows is safe, and gets an operation label and a
classification instead of an upstream diagnostic string. Those are exactly the
three affordances whose absence cannot leak a credential. An operator who needs
transport detail has the transport: their instrumentation may log whatever it
likes, because the leak was never the logging — it was this repository handing
that text back as a return value.

The general form of the lesson is the one already recorded above under USOSS-1:
prefer a construction that cannot express the violation over a check that
notices it. This is the same lesson bought a second time, at the cost of four
verified fail-open paths in a package whose entire job is handling credentials.

### The error-content invariant is held by types, not by comments

The port went on to state a stronger property across five packages:

> No error returned by `credentials`, `credentials/datadog`,
> `credentials/github`, `internal/githubapp` or `internal/credhttp` contains any
> text that did not come from a constant in this repository, a numeric count, or
> a Go type name.

That claim was false at the head that made it, in four exported inputs, and the
mechanism was identical in the first three: a field held a caller-supplied
string, a rendering path formatted it, and the only thing between the two was a
comment asserting the value was repository-owned. The registry's duplicate-ID
error named `CredentialProvider.ID()`; `CreateNotDeliveredError` named the
provider ID its own field comment called "ours, a constant, and safe to render";
`credhttp.Client.Do` took an `op string` a comment said "must never be built from
a response". All three comments described conventions, and all three APIs
accepted arbitrary text. The fourth, `Secret.UnmarshalJSON`, forwarded
`encoding/json`'s input-derived diagnostic, which quotes a byte of the input.

**Decision: the caller-supplied string stops being a `string`.** Three
constructions, because the four sites want three different things:

* **Text that must be kept and must never render** is a `credentials.Foreign`.
  Every verb, `String`, `GoString` and `LogValue` answer with a placeholder and
  the encoders refuse, so `fmt.Errorf("%q", e.providerID)` renders the
  placeholder instead of leaking. Getting the value back is `RevealForeign`, a
  package function and a deliberate, greppable act — the standard `Secret`
  already set for material. `DuplicateProviderError` and
  `CreateNotDeliveredError` hold their IDs and handles this way, and expose them
  through accessors, which is where an operator's real need is met.
* **Text that must render and must be ours** is a `credhttp.Op`: an opaque struct
  whose only values are a closed set of functions in that package. `Do` cannot be
  handed a label from outside, and the set being closed is why. The cost is that
  adding a provider adds a constant there rather than a string at the call site.
* **A diagnostic derived from foreign input** is dropped for a repository
  constant: `ErrSecretUnmarshal`, not `encoding/json`'s error.

The fixture is `internal/errhygiene`, and it names the class rather than the four
cases. Committing the four reproductions as four tests is what the previous round
did one level up, and the next review found a fifth path through the same shape.
It instead derives the surface from source with `go/ast` — every exported
function and method in the five packages that takes an argument — and requires
each to be driven with a sentinel or carry a named exemption, in both directions,
so a renamed function cannot leave a driver covering nothing. It asserts the
derivation is non-empty per package, because a derivation that returns nothing
passes every check over it. And it checks generatively that every exported type
with a rendering method was actually driven, because a zero-argument `Error()` is
not an entry point and would otherwise be tested by nothing.

Two sentinels are driven, of equal length and sharing no byte, and the two
renderings must be identical as well as sentinel-free. The equal length is so a
permitted count does not read as a difference. The disjointness is the part worth
copying: the first version of the fixture used a shared readable prefix, and it
passed against the `Secret.UnmarshalJSON` defect, because that error quotes
exactly one byte of the input and the shared prefix was the byte it quoted. The
defect was below the check's resolution — the same failure recorded under USOSS-7
for a merge separator, in a different medium.

### Refusing to render is not enough: the readers that leak do not ask

Review of the above found two live holes, and both were outside everything it
tested. `Foreign` held one unexported `string`, so
`reflect.ValueOf(f).Field(0).String()` returned the whole value — unexported
closes `Value.Interface` and field setting and closes nothing else — and so did a
custom `slog.Handler` that forgot `Value.Resolve` and reflected into the
`slog.Any` it was handed. Neither needs `unsafe`.

The lesson generalises past this type. Every rendering method was correct; the
type still leaked, because **a reflection walk and a struct-dumping logger never
ask a value to render itself.** A construction that answers "what do I look like"
does not answer "what do you contain", and the reader that actually leaks in
practice — a logging handler, a debug dump — is the second kind.

**Decision: for a type whose job is not to render its contents, the property is
stated over the representation, not over the rendering.**

> No field reachable from the value contains the plaintext bytes.

`Foreign` therefore holds its text XOR a keystream derived from a per-process key
and a per-value random nonce. A walk sees ciphertext and a nonce; the key is a
package-level variable that no `Foreign` value references, so recombining
everything a walk *can* see does not reverse it. Two consequences are worth
naming:

* **This is obfuscation and is documented as obfuscation.** The key is in the same
  address space. `unsafe`, a memory dump, or simply calling `RevealForeign` all
  recover the value, and nothing here pretends otherwise. What it buys is that no
  *generic* reader recovers it — not a verb, an encoder, a logger, a template, or
  a reflection walk — and generic readers are what has actually leaked here.
* **It is one step stronger than `Secret`, which stores its mask beside its masked
  bytes.** A walk that recombines two reachable fields recovers `Secret`'s
  material, as `Secret`'s own comment says. That asymmetry is deliberate for now
  and is a ticket rather than a silent divergence: changing `Secret` is a decision
  about credential material and belongs with the other redacting types, not
  smuggled into this one's commit. `compute.SecretValue` is worse than either and
  is tracked separately at USOSS-43, Urgent.

That last property — the reversing key is not reachable from the value — is the
kind a later refactor removes without noticing, so it is enforced rather than
noted. Two refactors would remove it and **neither is visible to any general
check**, which is why both have a dedicated test named in the source:

* **Moving the key into the struct**, which is what `Secret` does. The obvious test
  does not see this: the keystream is a hash of the key rather than the key itself,
  so XORing two reachable fields still recovers nothing. It took an adversary that
  knows the construction — every window of a value's reachable bytes tried as a
  candidate key and nonce, through the real derivation.
* **Replacing the random draw with a constant**, to drop a `crypto/rand`
  dependency or to make something deterministic. In a public repository a
  compiled-in key is not a key, and every claim in the type's comment would be
  false with every other test still green. The zero and low-entropy cases are
  caught; a high-entropy compiled-in constant is not, because freshness is a
  property across processes, and the test says so rather than implying coverage it
  does not have.

Both were found by mutating the finished change rather than by review, and neither
was caught by the checks that were already there — which is the argument for
mutating a construction *after* it looks correct, not only the checks around it.

### A cross-check that shares the derivation's blind spot is not a cross-check

The accounting assertion above — the type checker's total against what the
derivation filed — caught a narrowed derivation and could never have caught a
derivation that was never the whole set, because **both sides asked the same
question of the same package view.** Review proved it by adding a
`//go:build windows` file with an exported input: every check passed, still
reporting "91 exported callables". It proves the derivation did not shrink; it
cannot prove the derivation ever looked everywhere. That is the same distinction as
non-emptiness proving a derivation found something but never that it looked
everywhere — one level up, inside the guard against exactly that.

**Decision: a population check must obtain its population by a different mechanism
from the one it audits.** So `go/types` for one configuration is joined by a
`go/parser` sweep that applies no build constraints at all — the same answer
USOSS-28 reached for the boundary graph, reused rather than reinvented — and every
exported declaration the sweep finds must be known to the derivation or named as
platform-excluded with its tags.

The general form, which is the fourth instance of a too-narrow population on this
project: **go/types is necessary and not sufficient, because the configuration you
type-check in is itself a population choice.** Two mechanisms are needed because
neither is complete: syntax cannot see a promoted method, and one type-check
configuration cannot see a constrained file.

### Refusing to render is not enough either: a zero-argument method is called by name

The invariant was enforced over *rendering paths* and then over the
*representation*. Review escaped both with a third thing: a zero-argument
`Foreign.Reveal` method, which `text/template` calls **by name**, needing no
reflection and no mistake by the caller. The derivation had filed it under
"parameterless" and congratulated itself; the renderer-coverage test recognised
eight hard-coded method names and `Reveal` was not one of them.

This is the same defect as USOSS-43 in `compute.SecretValue`, reproduced against
the type designed to avoid it — and `credentials/secret.go` had already documented
it as the reason `credentials.Reveal` is a package function. The knowledge existed
in the repository and did not travel.

**Decision: an exported zero-argument method that returns caller text is part of
the leak surface, and the fixture derives that class rather than naming it.** Every
exported zero-argument method whose results can carry text is invoked, directly and
through a template, on values built from the sentinel; the derived set is
cross-checked against what was actually invoked.

Two consequences in production code:

* `DuplicateProviderError.ProviderID` and `CreateNotDeliveredError.PlatformKeyID`
  and `.ProviderID` now return a `Foreign` rather than a `string`. A template that
  reaches them by name gets a placeholder, and a deliberate caller writes
  `credentials.RevealForeign(err.ProviderID())` — two greppable acts instead of one
  method that renders.
* An exemption must be scoped to the driver that earns it, not to a type. The
  `credentials.Metadata` exclusion was applied by type at any depth, so review put
  a `Metadata` inside `CreateNotDeliveredError` and walked the map out through a
  returned error while every test passed. **An exemption that propagates through
  composition is not the exemption that was documented.**

And a containment check needs its resolution to be a property of the comparison
rather than a constant somebody picked: a five-byte plaintext field walked straight
past a six-byte window. Two byte-disjoint sentinels, compared slot by slot, get to
one byte for a whole-field leak, because a real leak appears in both runs at the
same offset and a coincidence appears in one.

The alternative considered was an opaque integer handle into package-private
storage, which is a stronger construction — reflection yields an `int`. It was
rejected because it buys that with process-global storage of foreign text and a
lifetime question, and the failure mode of getting the lifetime wrong is
unbounded retention of credential-shaped text. Values also stop being
self-contained: a copied `Foreign` whose entry has been reaped renders something
wrong or panics, in error-handling code, which runs when things are already going
badly. A per-process key has no registry, so the garbage collector is the lifetime
manager and there is nothing to get wrong.

The fixture grew the two missing readers — a deep reflection walk over everything
a returned value reaches, and a hostile `slog.Handler` — and both are containment
checks at six-byte resolution rather than differential ones, because the stored
representation is randomised per value and two runs differ by construction.

### A derivation is only as good as its idea of "exported"

The same review defeated the fixture's population twice. It derived
`*ast.FuncDecl` only, so it reported 33 exported callables with arguments where
the real number was 37: it missed every method of an exported interface, and two
shapes that are exported API and are not function declarations — a package-level
`var` of func type, and a method promoted into an exported type from an unexported
embedded one. Both returned the sentinel while all four class checks stayed green.
This is the fourth time on this project that a recogniser has been defeated by
input it was built to reject, and the third time the recogniser was reconstructing
something the toolchain already knows.

**Decision: ask the type checker, do not reconstruct the API from syntax.**
`go/types` via `go/importer`'s source compiler — no new module dependency.
`types.Package.Scope` answers "what is exported"; `types.NewMethodSet` answers
"what methods does this type have", with promotion resolved by the type checker
rather than by the fixture. Interface methods, exported func-typed vars and
exported func-typed struct fields are each their own category.

There is deliberately no second count to reconcile, because the population is not
reconstructed. What is asserted instead is that every exported callable the type
checker reports is filed as either an entry point or as parameterless, so a future
narrowing of the derivation fails a test rather than printing a smaller number
nobody reads. "33 of 37, with nothing comparing the two" is what the absence of
that assertion looked like.
