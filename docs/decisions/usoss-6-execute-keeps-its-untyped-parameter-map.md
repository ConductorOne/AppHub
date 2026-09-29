## USOSS-6 — `Execute` keeps its untyped parameter map

`Execute(ctx, userID string, params map[string]any)` is ported unchanged, and so
is `Result.Data map[string]any`. No type parameters, no per-module request type.

The map is what makes a module invocable without the caller knowing which module
it is: a request names a module ID and carries a parameter object, and the
registry resolves one to the other. A typed parameter would push that resolution
into the type system, where the set of modules has to be closed at compile time
— the opposite of an extension point. The published `Schema()` plus
`ValidateDeclaredParams` is how the shape recovers its safety: a module's schema
is its enforced contract, not merely its documented one, and an undeclared key
is rejected at the boundary.

This is also what keeps the interface general in the direction USOSS-21 asked
for, though it is worth not overstating what that buys. Nesting a structured
value under a single key is *an* answer for a capability whose inputs do not fit
a flat map, and `modules/module_test.go` pins that the framework carries such a
value through untouched with a deliberately paved-shaped input, so a future
narrowing of the signature fails a test rather than a review. It is not a proven
answer: no module in the source does it, and the one capability there with
genuinely rich inputs was left outside this interface instead — see the
correction below.

### A correction to the USOSS-21 entry above

USOSS-21 records that "`paved` (1,547 lines) uses the same `Module` interface as
deploy and security". **It does not.** `paved` does not implement `Module` at
all, is not in `RegisterDefaultModules`, and says so in its own package doc
(`paved/agent_deploy.go:1-7`): it is "intentionally NOT wired into
modules.Registry's Module interface" because "paved deployments have rich,
kind-specific inputs (catalog spec, T-shirt size, hibernation policy, BYO
tokens) that don't fit the generic params-map shape", and the REST handlers call
it directly.

The decision itself is unaffected — `paved` is still out of v1 — but the
reassurance attached to it is weaker than it reads. Keeping this interface
general is **necessary** for a v2 `paved` port and is not **sufficient**: the
thing standing between `paved` and this interface is the params-map shape, which
the entry above deliberately keeps. So a v2 port has a real design question to
answer — shape those inputs into a parameter object, or let `paved` stay a
direct-call capability outside the registry — and "USOSS-6 ports the interface
unchanged, so paved ports cleanly later" should not be read as having settled
it. Nothing in this port narrows the interface, which is the part USOSS-6 was
actually able to guarantee.
