## USOSS-64 — credentials/aws stays outside the shared error-hygiene invariant

*Follow-up from USOSS-9 / PR #41, which named the limitation in
`hygiene_test.go`'s doc comment but never a decision record. USOSS-64 asks
whether the limitation still holds and whether it is worth the cost it names.
It does, and it is.*

### The limitation, restated precisely

`internal/errhygiene.Assert`'s documented contract is a subject's **own external
test package** driving only its **exported** entry points — that is what lets
nothing import the package under test and needs no boundary allowlist entry
(USOSS-52). `credentials/aws` cannot meet that contract: `stsAPI` and `iamAPI`
(`api.go`) are unexported by the same rule `store/dynamo.go` states for
DynamoDB — "an exported interface over IAM would be an IAM abstraction with a
different name, and the SDK types in its signatures would be back in whatever
package accepted one" — and `NewProvider` takes concrete `*sts.Client` /
`*iam.Client`, not an interface. An external `aws_test` package therefore has no
way to inject a fake response and drive `CreateCredential` without attempting a
real STS or IAM call. `hygiene_test.go` is the in-package fixture that exists
because of this, and it keeps errhygiene's two disciplines (a derived
population; an input the fixture cannot classify is a failure, not an absence)
even though it cannot be the shared package's own test.

### Why the in-package version is not equivalent, and the record says so plainly

USOSS-59 measured the actual cost of this: `internal/errhygiene`'s differential
check failed on a mutation in `credentials` — a package that **does** join the
shared invariant — while `go test ./credentials` stayed green. The property
that made the shared check catch it is exactly what an in-package fixture
cannot have: it is written by someone other than the person with the local
model of the code, checking an implementation it was not built alongside. A
package's own fixture, however disciplined, is written against its own
author's understanding of its own vend paths, and a systematic gap in that
understanding is invisible to a test built from the same understanding.
`hygiene_test.go`'s doc comment now says this directly, rather than reading as
"the same check, just located differently".

### Considered: exporting or refactoring the client seam

Rejected. `stsAPI`/`iamAPI` are unexported by the identical, already-standing
rule `store/dynamo.go` applies to `dynamoAPI` — the interface is the
load-bearing half of the fence, not an implementation detail, because an
exported interface over an AWS API is an invitation for other code to accept
one and pull SDK request/response types back into business logic. Widening it
here, for one package's test to reach a shared harness, buys back exactly the
class of coupling the fence exists to refuse, in exchange for closing a gap
that is real but bounded: the derivation half of `errhygiene.Assert` (every
exported input must be driven or named as exempt, checked from both `go/ast`
and `go/types`) is not the half this package is missing — `hygiene_test.go`
already does that work itself, by hand, in-package. What it cannot have is the
independent author. Trading the fence for that is not a trade this ticket
makes; `store` accepts the same limitation for the same reason and has not
widened its own fence to get it back either.

### Decision

`credentials/aws` stays outside `internal/errhygiene`. `hygiene_test.go` remains
the in-package fixture, its doc comment now states the blind-spot cost rather
than only the structural reason, and `stsAPI`/`iamAPI` stay unexported. Revisit
only if this package's client construction is ever refactored for an unrelated
reason that removes the concrete-client constructor — not by exporting the
interfaces to serve this test alone.
