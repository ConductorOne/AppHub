## USOSS-15 — an application that binds provider-held secrets must name its placement

A deployment whose `Config.Placement` is empty takes the provider's default. An
application deployed there may not bind secrets the provider already holds: the
plan refuses it, naming the field to set.

### Why

A workload may only bind a secret in its own placement — the interface says so,
and a provider must not copy material between placements to satisfy a binding.
Checking that means comparing two placements, and an empty `Config.Placement`
gives this module one it cannot name: the provider's default is a name the
provider knows.

There was a working alternative and it was implemented first. `Status.Spec`
carries the effective desired state, so the workload identity — the first and
cheapest resource a deploy creates — reports its resolved placement, and the
comparison could happen immediately after it. That refuses a cross-placement
binding with one idempotent identity in existence instead of three resources.

It was replaced because one resource is not none, and because the alternative is
better on every axis that matters: the check moves from mid-deploy to
plan-time, a code path disappears rather than being added, and what an operator
has to do about it is a configuration they set once rather than a failure they
meet on a deploy.

### It is a real restriction, and that is the point of writing it down

An operator who binds provider-held secrets must name a placement they could
previously leave to the provider. That is a narrower deployment surface in
exchange for a check that happens before anything exists, and it is stated here
so the restriction is visible rather than discovered.

Applications that bind no such secrets are unaffected, and a test asserts that:
the requirement is about bindings, not about placement.

### The shape this is an instance of

The remedy for *a check that runs too late* is not always an earlier check. It
is sometimes an input that cannot express the case — the same move as deleting
`Route.TargetPort` rather than validating it, one round earlier.
