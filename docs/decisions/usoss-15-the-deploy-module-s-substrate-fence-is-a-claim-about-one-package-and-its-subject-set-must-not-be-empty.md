## USOSS-15 — the deploy module's substrate fence is a claim about one package, and its subject set must not be empty

The objectively verifiable success criterion for the whole abstraction is that
`modules/deploy` compiles with no cloud SDK import. This entry records three
decisions about how that is enforced.

### It is stated over substrates, not over AWS

The ticket says "zero AWS SDK imports". The rule denies `github.com/aws`,
`k8s.io` and `sigs.k8s.io`, because a deploy module that had swapped one
substrate SDK for another would have failed the ticket just as thoroughly, and a
rule naming only AWS would have said so a release too late.

The denied set is **organisation prefixes, not module paths**. A list of module
paths is a restatement of somebody else's release history and goes stale the
first time they publish a new one; `github.com/aws` cannot. It is deliberately
wider than "the SDK" — `smithy-go`, the Lambda runtime library and the
Kubernetes API machinery are all substrate detail this package must not carry.

### It is scoped to one package, which is a new capability in the checker

`boundary.Rule` grew a `SubjectPrefixes` field. The two original fences are
claims about the whole tree — *nobody* may reach ConductorOne except the c1
provider — and are stated as a denial with an allowlist. This one is the
opposite shape: *this package* may not reach that dependency.

Stated tree-wide it would have needed an allowlist naming `compute/aws`,
`compute/k8s`, `credentials/aws` and everything added later. The list, not the
claim, would then have been the thing under review, and the claim would have
widened silently every time somebody added an entry. Subject scoping keeps the
reviewable artefact the same shape as the decision.

### A subject set that comes out empty fails the run

A subject set is the population the rule quantifies over, and a population that
comes out empty satisfies every property stated over it. The way that happens is
mundane — the package is renamed, moved or deleted — and the symptom is a rule
that goes on passing while guarding nothing.

`Findings.Validate` therefore fails a run in which a subject-scoped rule judged
no first-party package at all. Verified by mutation: renaming the subject prefix
to a package that does not exist turns the run red with `inert`, and it is the
only thing that does — the violation list is empty, every root is judged, and
the summary reports success.

### The planted-import control

`internal/boundary/testdata/union/deployfence` is a real module directory judged
with the **shipped** `DefaultConfig`, not with a rule the test spells itself. It
plants a denied import eight ways — direct, blank, aliased, dotted, in-package
test, external test, transitively through the AWS provider package, and in a
`*_windows.go` file no compatibility pass on a Linux host compiles — plus a
Kubernetes import, and asserts the fence's whole output by **equality**.

Equality is what makes the two controls in the other direction bind: a sibling
module that is not a subject imports the same denied package and must produce no
finding, and a package inside the subject set that names no substrate must
produce none either. A table proving eight things are caught is otherwise
indistinguishable from a rule that fires on everything.

The `*_windows.go` case is the reason the proof is the union import graph rather
than `go list -deps`: the union ignores build constraints entirely, so an import
behind a selector no supported configuration selects is still judged. That is
also the one mutation whose compile check is vacuous on this host, and it is
recorded here rather than left to be rediscovered.
