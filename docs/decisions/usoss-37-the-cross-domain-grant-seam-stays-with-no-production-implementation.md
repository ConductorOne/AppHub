## USOSS-37 — the cross-domain grant seam stays, with no production implementation

*Recorded from USOSS-37, which was opened to implement
`ext.ExternalAccessGranter` for the AWS provider and resolved instead as a
decision about whether the port should exist at all. Supervisor ruling, adopted
on the reasoning below.*

`compute/ext.ExternalAccessGranter` has no *production* implementation —
`compute/fake` implements it, asserts so at compile time, and drives it. The
question USOSS-37 answers is whether that is a gap to fill, a port to delete, or
a state to keep on purpose. **It is kept on purpose, and given no production
implementation.**

### The prospective consumer is not the one the port named

The port's own documentation said it existed for "the ConductorOne credential
provider, USOSS-8". That is false, and it was disproved by the person who built
that provider: `credentials/c1` has **zero dependency on package `compute`**,
tests included, derived with `go list -test -deps ./credentials/c1`. Credential
vending is an outbound HTTPS call to a tenant API — mint, get, revoke a
service-principal credential. It touches no object store and has nothing to
grant anyone access to. There is no version of it that reaches this port.

The real prospective consumer is a *different* ConductorOne integration: the
source system's datasource binding, `EnsureC1DatasourceRole`
(`bucket.go:668-767`), which creates a cross-account IAM trust so that vendor's
product can read an application's bucket. That feature is excluded from v1 — see
`usoss-13-cross-domain-object-access-is-not-ported.md` — and one of the four
reasons for excluding it was that it deserves its own ticket and its own review.

Two integrations with the same vendor's name, only one of which needs the seam.
The port's comment is corrected, because a seam whose stated justification is
false gets deleted by the next reader who checks it — which is the right instinct
applied to the wrong sentence.

### Why not delete it

The tempting argument is that a port with no implementation and no consumer is
dead surface whose conformance check every provider satisfies by refusing. **That
argument is wrong twice over on the facts.**

It is wrong about the implementations, as above: `compute/fake` has one. And it
is wrong about the check. `conformance/checks_negative.go` is
bidirectional: a provider that documents the port must have the lookup succeed,
and a provider that does *not* must have it **refuse, legibly**. The second half
is a live assertion, enforced today against every provider in the suite, and its
failure message states the stake — a lookup that succeeds on an undocumented port
means "a caller would use a non-portable port the provider never promised, and an
operator would learn the resource is substrate-specific only when something else
broke".

So the seam, with no production implementation, still pins a contract. Worth
recording as
its own small lesson, because the wrong argument above was reached for first and
by reflex: **"a check nobody implements is vacuous" is itself a hand-picked
population.** It covers checks whose assertion is about the implementation, and
misses checks whose assertion is about the refusal.

The second reason not to delete it: `ExternalPrincipal` exists to replace the
source's three hardcoded cross-account role ARNs, and says so. Deleting the port
means re-deciding that vocabulary later, when the excluded feature is being
ported, under whatever pressure that ticket carries.

### Why not implement it

Because nothing would use it. Building a *production* implementation behind a
port with no consumer is work that cannot be wrong, since nothing depends on it
being right, and it would be reviewed against no production call site.

`compute/fake` already implements the port and `compute/fake/fake_test.go`
drives grant and revoke against it, so the contract is not untested — it is
tested where a fake is the right place to test a contract nobody consumes yet.
Checking that implementation is also what corrected the requirement in (1)
below: the fake refuses an empty constraint list and leaves existing state
alone, which is right, and an earlier draft of this decision asked the *grant*
call to tear down instead of naming the reconciling caller as the owner. A
reference implementation earns its keep by contradicting the specification.

### Requirements recorded for whoever does implement it

These were derived while USOSS-13 built and then removed an implementation, and
are written into `compute/ext/ext.go` next to the methods they constrain rather
than left here alone.

1. **A grant with no constraints is refused, and the refusal does not mutate
   anything.** An error return that also deletes a grant is a worse contract
   than either half.

   The refusal is necessary and not sufficient. A configuration edit is how a
   constraint list becomes empty, so the realistic path to an unpinned grant is
   not a call with an empty list — it is a grant correctly pinned yesterday that
   the configuration no longer names, and no creation-time check sits on that
   path. **Closing that is the reconciling caller's obligation, not
   `GrantExternal`'s:** a per-principal call cannot observe that a principal has
   vanished from a set it was never given. The source closes it because its
   equivalent *is* a reconciler over the whole set (`bucket.go:681-698`).

   USOSS-13's removed implementation had the refusal and not the reconcile, and
   reported the refusal as strictly safer than the source.

   This is the reference instance of a general failure: a per-call control that
   is exhaustive over calls and blind to transitions. USOSS-13's ownership matrix
   covered 15 of 15 call sites and could not see this, because the hole is a
   sequence. See `/shared/apphub/POPULATION-FAILURES.md`.

2. **Constraints are plural per grant and singular per tenant.** ConductorOne
   issues one external ID per tenant; the source's list is plural because it
   allowlists several *tenants* on one application's role. A ten-element list
   means ten tenants share the resource. Do not collapse it to a scalar.

   Enforced against `compute/fake` on both the creation and the replacement of a
   grant, and the second of those needed its own test. The existing pair read the
   stored set element by element for a principal's *first* grant, and asserted
   only that two snapshots either side of a re-grant *differed* — which the access
   level alone changing satisfies. So a re-grant that applied the new level and
   kept every old constraint passed both, which for this requirement is the
   failure that matters: it leaves tenants allowlisted that the last call did not
   name. An inequality is not an equality, the same way a length is not a content.

3. **Constraints are not secret material**, corroborated by the producing system
   rather than by AWS's documentation alone: the value is served from an API
   requiring only a viewer role and rendered in plaintext in an admin UI with a
   copy-to-clipboard control.

4. **A flow with no correlation value is not a grant with an empty list; it is
   not a grant.** ConductorOne has AWS-shaped integrations that authenticate with
   static access keys rather than role assumption. Those never reach this port —
   the credential is the identity, so there is no external principal to name.
   Anyone routing one through `GrantExternal` will meet the refusal in (1), and
   the correct response is to keep refusing.

5. The guarantee in (1) is **apphub's, not inherited.** ConductorOne always has
   a correlation value available and nothing in ConductorOne forces its use: its
   own configuration schema permits a role ARN with an empty external ID. "The
   caller would not send that" is not an argument available here.

### Not settled by this

`credentials/c1`'s entry in the `ext-is-optional` allowlist carries the same false
justification the port's comment did — "the ConductorOne integration needs the
cross-domain grant port". Nothing in USOSS-37 can make that entry necessary,
because the necessity is a property of what `credentials/c1` imports, and it
imports nothing from `compute`. It is ticketed separately against that package,
whose owner is the only one who can settle it. Removing an allowlist entry from a
decision about a different package would be tuning someone else's security
control.
