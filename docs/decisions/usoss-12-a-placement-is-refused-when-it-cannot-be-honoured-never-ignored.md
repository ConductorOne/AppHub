## USOSS-12 — a placement is refused when it cannot be honoured, never ignored

Binding on every AWS port. The interface's own text says an AWS provider "can
ignore" placement, because an IAM role is account-global. That reading is wrong
for anything regional and this record supersedes it for this package.

`PlacementConfig.Region` exists precisely so a placement can differ in region, so
the mismatch is reachable through ordinary configuration rather than being
hypothetical. A caller that named a placement and silently got a resource in
whichever region the provider's clients happen to address has been handed
something it did not ask for, and has no way to find out — which is the fail-open
shape the standing contract forbids.

So `Provider.regionalPlacement` refuses a placement whose region differs from
`Config.Region`, with `compute.ErrInvalidSpec` naming both. A second region is a
second provider instance, which is what `compute.Placement`'s own documentation
proposes one level down: "the answer is more named placements, not network fields
here".

An unconfigured placement name was already refused by `Config.placement`; this
adds the case where the name *is* configured and the provider still cannot serve
it.

### The conformance suite cannot see this, and that is worth a ticket

`conformance`'s `abstraction/placement-is-an-operator-configured-name` check
skips with "Options do not supply a port that takes a Placement". It drives the
container, bucket, relational and secret ports, and a provider that has none of
them — this one, today — gets a skip even though **both** of its ports take a
placement. The invariant is reachable and simply is not reached.
`TestAnUnconfiguredPlacementIsRefusedRatherThanDefaulted` and
`TestAPlacementInAnotherRegionIsRefused` are the local replacements. The suite
should drive whichever placement-taking port a provider has.
