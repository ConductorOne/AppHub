## USOSS-42 — the transient gate arms a port and drives it, not the whole provider

`Options.InduceTransient` used to be `func(ctx, p compute.Provider) (stop func(),
err error)` — no kind, unlike its sibling `Options.InduceDenial`
([USOSS-70](usoss-70-each-substrate-names-its-own-denial-and-the-hook-arms-exactly-one.md)).
This gives it the same signature and the same per-port arm/drive/report loop
`checkDenialIsNotAResourceFailure` already has.

### The premise that turned out to be stale

The ticket's own text, carried from `Options.InduceDenial`'s doc comment,
attributes the gap to `compute/aws`: "a secret Put is the cheapest write on any
provider" — true of a provider that has one, and five of the six AWS providers
do not, so the gate did not run at all (USOSS-10). **That defect was already
fixed, by USOSS-60** ("A population inferred from an outcome is not a derived
population"): `Harness.InduceTransient` now arms every substrate field it can
reach, not a single secret-store fixture, which is why `TestConformanceFullAccount`
measured `38 of 38` methods verified across every port of `compute/aws` *before*
this change. Retrofitting the kind parameter for the coverage number described
in the ticket would have been fixing something already fixed — the check here is
what this repository's own culture asks for before treating a ticket's numbers
as ground truth.

What the kind parameter is actually for, and still worth doing on its own
merits:

* **Symmetry.** `Options.InduceDenial`'s own doc says as much: "The same
  treatment would fix `InduceTransient` and is not done here: changing its
  signature touches every provider's options, and it is not this amendment's to
  make." This is that amendment.
* **Per-port attribution instead of a single fatal.** The old check armed the
  whole provider once and drove every port inside that one window; a hook that
  could not arrange a failure at all made the whole check `fatal`. The new loop
  arms one port's kind at a time, so a hook that cannot reach ONE port names
  that port as undrivable (mirroring `checkDenialIsNotAResourceFailure`'s
  `undrivable` list) and still drives, tallies and verifies the rest.
* **A real, if narrower, correctness fix.** See below.

### The measurement, in both directions

* Before: `checks_provider.go:466: … verified for 38 of 38 method(s) driven
  across 10 port(s) of provider "aws"` (`TestConformanceFullAccount`).
* After: `… verified for 37 of 38 method(s) driven across 10 port(s) of
  provider "aws"`, with a note: `key-value-table … Revoke did not surface the
  induced failure`.
* `compute/fake` and `compute/k8s` are unaffected — `38→38`, `43→43`, `37→37` —
  because their hooks already arm every substrate regardless of kind and had no
  narrower option to take.

### Why the AWS number went down, and why that is the fix working

`compute/aws`'s key-value-table port routes `Grant` through
`DynamoDB.DescribeTable` (its own substrate) but routes `Revoke` through
`IAM.DeleteRolePolicy` — a different substrate entirely
(`keyvalue.go:308`). The old provider-wide arm happened to also arm IAM, so
`Revoke`'s induced failure was real, but it was never evidence about the
key-value-table port's own mapping — it was IAM's mapping, already established
by the workload-identity port's own drive, credited to the wrong tally. Arming
only the kind's own substrate — the same restriction `InduceDenial` already
applies — stops crediting a port for a call it does not make. `37 of 38` is a
more honest number than `38 of 38` was, for the same reason
`checkDenialIsNotAResourceFailure` already reports per port rather than per
provider.

### The AWS harness gets a new method, not a changed one

`Harness.InduceTransient(ctx, err)` (arm-everything) stays exactly as it was:
several of this package's own unit tests pin that exact behaviour by name —
`objectstore_test.go`'s "InduceTransient arms every service it reports" and the
armable/observable-set pin next to it — and they are not about the conformance
suite. `Harness.InduceTransientKind(ctx, kind, err)` is new, mirrors
`Harness.InduceDenial`'s switch over `compute.Kind`, and is what the
conformance wiring in `aws_test.go` and `defects_test.go` now calls. `compute/k8s`
and `compute/fake` accept the new parameter and ignore it: both already arm
every substrate they have regardless of which port is being driven, so there is
nothing narrower to scope to.

### A hook that refuses one kind is reported, not fatal

`TestTheRetryGateNamesAPortItCannotDrive` (`compute/fake/vacuity_test.go`) pins
the new failure mode: a hook that returns an error for `compute.KindBucket`
alone leaves the retry gate passing, with a note naming the bucket port as
undrivable, while the other ten ports still verify. Before this change there was
no way to express "not this one port" — a hook either worked for the whole
provider or the whole check went `fatal`.
