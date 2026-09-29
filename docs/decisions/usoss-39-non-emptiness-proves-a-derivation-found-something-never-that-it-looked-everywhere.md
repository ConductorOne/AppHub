## USOSS-39 — Non-emptiness proves a derivation found something, never that it looked everywhere

*Recorded from the USOSS-39 audit and fix. The ticket was filed as "drive
`ImageBuilder.Build`, which no check exercises". The audit that preceded the fix
found the missing check was one instance of a systematic hole, and the hole was
in the machinery USOSS-32 had shipped an hour earlier to close this very class.*

### The rule

**A derivation is only as good as its population. Assert non-emptiness *and*
demonstrate the denominator.**

USOSS-32 replaced two hand-maintained conditions with derivations, and asserted
that each derivation returned something — which is the rule this project already
had. It did not ask whether the set it derived over was the whole set. It was not:
`portInterfaces()` derives the port interfaces from `compute.Provider`'s
accessors, and four ports are reached through a *lookup helper* instead. Twelve
methods across `compute.ImagePullGranter` and the three `compute/ext` ports were
outside the population every "driven or named" assertion was made against, so
they were neither driven nor named and nothing said so. **39 of 54.** The
exclusion list looked complete because everything in its population was
accounted for.

### Two outcomes for an exclusion, and one of them expires

The USOSS-39 audit asked two questions of every named exclusion that a bare
reason cannot answer, and both changed a disposition:

* **Is it legitimate?** "No provider implements this" is true today and stops
  being true on a named event. "Nobody got to it" is a hole. The two look
  identical in a list of reasons. All three of USOSS-32's entries turned out to
  be the second kind, every one implemented by at least the reference provider
  and therefore testable that day.
* **When does it expire?** An exclusion with no expiry is where an obligation
  goes to be forgotten. `exclusion.Expires` is now required, so an eternal
  exclusion is not a thing the table can express — a construction rather than a
  rule.

### A syntax walk that shrugs is the same defect one level down

The first fix for the population was a `go/ast` walk over both packages. It was
rejected, and the reasoning is the fourth instance of one shape on this project:
**a syntax walk recognises a hardcoded set of forms, and the next form is always
available.** That draft followed an embedded interface only when it was a bare
identifier — a same-package embed — and silently ignored a selector, so an `ext`
port embedding `compute.Granter` would have had two methods vanish from its
method set with no complaint. It also saw only `type X interface{...}` and would
have missed an alias. Two shrugs, in the audit written to stop things being
silently missed.

So the population comes from the type checker. `types.Scope` is the compiler's
own answer to what a package exports, and `*types.Interface.NumMethods` has
already resolved promotion through embedding whatever syntax produced it. There
is no set of recognised forms left to forget and no second count to reconcile.
The cost is a few seconds of type-checking in a package whose own tests take
milliseconds, and it is worth it.

### Three obligations were sitting behind one undriven method

The audit's other half. `ImageBuilder.Build` was driven by no check at all — not
a lenient gate but **a gate with no input**, so there was no tolerant path to
tighten and the check had to be built. Behind it:

* *A provider MUST NOT expose ambient platform credentials to the build.
  Credentials made available to a build MUST be scoped to no more than push
  access to Destinations and Cache, and MUST be short-lived.* Stated in capitals
  in `compute/image.go` precisely because it could not be expressed as a method.
* `BuildRequest.BuildArgs` — "non-secret is a contract, not a hint: build
  arguments are recorded in image metadata and readable by anyone who can pull
  the image".
* `BuildCache.MaxAge` — the provider's default "must not be 'forever'".

And `BuildRequest.Logs` documents where a leak lands: the caller "keeps a capped
tail so a build failure's diagnostic can be persisted onto a 400 KB DynamoDB
item ... which is a caller policy, not a provider one". **So the interface
documents that build output reaches durable storage, documents that the provider
must not put credentials near the build, and checked neither half.** PR #18's
review found the same class live in the first provider to implement the port, at
the same time, with a benign recorder that could not exercise it.

Checking the credential half requires the provider to report what its build is
given, because the obligation exists so that a minted credential is *never*
visible to a caller. Hence `Options.BuildCredentials`: a hook, reporting to a
test, whose absence is an unverified invariant and whose empty result is a
failure rather than a pass.

### The fake's builders are adversarial on purpose

The threat model is a build context authored by whoever owns the repository being
built. A cooperative fake is what made the provider-side test in PR #18 useless,
so the reference provider now emits its own credential into `Logs`, puts what it
read from the context into a failing build's error, writes nothing at all, and
accepts a build with no destination — each behind its own `fake.Defect`, each
with a table entry proving the matching check can fail.
