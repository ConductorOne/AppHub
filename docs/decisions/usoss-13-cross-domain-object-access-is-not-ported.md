## USOSS-13 — cross-domain object access is not ported

*Supervisor ruling, recorded from `/shared/apphub/usoss-10/SUPERVISOR-ADDENDUM.md`
§3, which accepts USOSS-11's recommendation in full. The file it concerns is
USOSS-13's, so it is recorded here.*

`EnsureC1DatasourceRole` (`bucket.go:668-767`, gated on
`bucketType == BucketTypeGeneral` at `:683`) is **not ported**. It creates a
cross-account IAM trust to a named vendor's tenant accounts, with external IDs,
so that vendor's product can read an S3 bucket as an external datasource.

The ruling's four reasons: it is not a compute concept; it is a bucket concern
rather than a container one; the security consequence is high and caller-fed and
deserves its own ticket and its own review rather than arriving as a side effect
of another port; and locked decision 3 (c1 is optional). It notes that the
import-boundary checker cannot enforce the last of these — c1-optional is an
import-prefix rule, and a port of this function imports nothing c1-related — so
**this record is the only thing holding the line** (tracked as USOSS-34).

The consequence in `compute/aws`: `objectStore` does **not** implement
`ext.ExternalAccessGranter`. `ext.ExternalAccess` returns a typed
`*ext.ErrNotImplemented` wrapping `compute.ErrUnsupported`, and
`conformance.Options.ImplementsExt` records that, so the suite checks the
refusal rather than skipping the port. `policyPrincipal` has no `AWS` field and
`policyStatement` has no `Condition`, so a cross-account trust statement is not
representable in this package rather than merely not written.

**One correction to the ruling's first reason, recorded because it changes what a
future revisit has to decide, not to relitigate the outcome.** The reason states
that "neither `ContainerRuntime` nor `ObjectStore` has vocabulary for 'grant a
third party cross-account read', and inventing one to hold a single vendor's
integration puts that vendor into the portable interface." Neither of those two
ports does — but `compute/ext.ExternalAccessGranter` on `main` already does, and
it was added deliberately for this case: its own documentation says it "exists so
that an optional integration which needs cross-domain sharing (in this
repository, the ConductorOne credential provider, USOSS-8) has a seam to reach a
provider through without importing one, and without that integration's
requirements leaking into the core object-store contract", and
`ext.ExternalPrincipal` says the source's three hardcoded role ARNs are
"precisely the pattern this type exists to replace". `compute/ext` is also
already the shape §3 prescribes for a revisit — "an optional package behind a
narrow interface, so the import graph makes the optionality real rather than
conventional" — because the `ext-is-optional` rule in `internal/boundary` is an
allowlist over importers, and it is enforced.

So the choice available was not "invent vocabulary or exclude it" but "implement
the seam that exists or exclude it", and reasons 2, 3 and 4 stand either way.
Reason 3 is sufficient on its own.

**The question this paragraph used to leave open has since been answered**, and
the answer is recorded under USOSS-37: the seam stays, with no production
implementation. Two of the things this paragraph assumed turned out to be false —
`compute/fake` does implement the port, and the conformance check for a provider
that does *not* is a real bidirectional assertion rather than something every
provider satisfies by refusing. Neither changes this ruling; both change what a
revisit has to decide, which is why the pointer is here rather than only there.
