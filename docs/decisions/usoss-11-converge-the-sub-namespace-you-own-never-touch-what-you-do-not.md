## USOSS-11 — converge the sub-namespace you own; never touch what you do not

Every `Ensure` in this package reconciles some collection, and the rule is *not*
"the actual set equals the spec". That rule is right for some collections and is
data loss for others, so each collection is sorted deliberately:

**Converge fully** — security-group ingress rules on a group this provider
created, inline role policies carrying this provider's prefix, and the container
definition and secrets array inside a task-definition revision this provider
authors. The test is ownership, not data type: a rule on a group created for one
service, or a policy under `apphub-`, is either something apphub put there or
something nobody asked for, and the second is a security finding rather than an
operator's configuration.

**Converge by namespace** — tags. `apphub:*` keys converge exactly; everything
else survives untouched. An operator's `CostCenter` tag is deliberate
configuration, and a reconcile that deleted it would be a data-loss bug dressed
as correctness.

**Never touch** — an inline policy an operator attached out of band, and any tag
outside this provider's namespace.

The general shape to watch for: this bites wherever a substrate API **replaces**
rather than merges. `RegisterTaskDefinition` replaces a whole document, so
anything omitted from a revision is dropped rather than left alone; ECS tagging
applies only on create, so a changed label is invisible until converged
separately. When the API replaces, "the call succeeded" is not evidence it did
what you meant.
