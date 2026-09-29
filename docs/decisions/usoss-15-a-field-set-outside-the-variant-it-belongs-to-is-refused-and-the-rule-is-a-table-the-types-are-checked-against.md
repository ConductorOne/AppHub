## USOSS-15 — a field set outside the variant it belongs to is refused, and the rule is a table the types are checked against

An application record has variants — container or function, service or
scheduled, relational or key-value or neither, standard or zonal bucket — and
most of its fields belong to one of them. A field set on the wrong variant used
to be **ignored**.

Ignoring is wrong twice over. It discards what the operator asked for without
telling them; and, as review found, some of those fields are not ignored all the
way down. A zone on a standard bucket travelled into `compute.BucketSpec` and
was refused by the provider *after* three resources existed.

### The rule, stated once

> Every exported field of every input type is classified with the condition
> under which it carries meaning, and a field whose condition does not hold must
> be zero.

`modules/deploy/applicability.go` holds the classification; `checkApplicability`
is the walk, and it derives the fields it must classify **from the types** rather
than from a list. Two consequences:

* **an unclassified field is fatal, not absent.** A field added to
  `Application`, `Source`, `Database`, `Bucket`, `SecretBinding` or `Route`
  without a decision about when it applies stops the walk with a message naming
  it. A walk that shrugs at an input it cannot classify is a gate with a bypass,
  and this is the gate that decides whether a record is deployable at all;
* **the behavioural test quantifies over the table.** For every conditional
  field it builds a record where the condition is false, sets the field, and
  requires a refusal naming the field — before anything is created. A field added
  to the table gets that treatment without anybody writing a case.

Measured at the tip of `agent/usoss-15/deploy-on-compute`: 43 exported fields
classified across six input types, 13 of them conditional and driven from both
sides.

### Why the condition carries a name

The refusal says which circumstance the field belongs to, so an operator is told
what to change rather than that something is wrong. It also distinguishes the
two conditions that are the same predicate and different facts: `always`, an
input that applies to every application, and `output`, a field this module
writes and never reads — which a redeploy legitimately carries, and which is
therefore unconstrained on purpose rather than by omission.
