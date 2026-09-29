## USOSS-15 — a resource name is derived from the application identifier, and an identifier that would have to be folded is refused

Every resource an application gets is created under one logical name, and that
name is the configured prefix plus the application's identifier, used verbatim.

### Why not the display name, which is what the source used

`deployResourceName` returned the application's display name and `sanitizeName`
folded every character outside `[A-Za-z0-9_-]` to a hyphen (`lambda.go:844-858`).
Two consequences, both delivered behaviour rather than theory:

* **The fold is many-to-one.** Applications called `my app` and `my-app` were
  handed the same ECS service, the same IAM role, the same security group and
  the same bucket. Reported as a source defect; not reproduced here.
* **The display name is mutable.** Renaming an application moved every resource
  name, so the next deploy created a second set and the first became invisible
  to teardown.

Deriving from the identifier fixes both: it is stable across a rename, and the
mapping is the identity function, so it is injective without a digest to
reconcile. The display name still travels — as a label, which is where a mutable
human-readable string belongs and where nothing's identity depends on it.

### Why the identifier is checked rather than sanitised

A sanitiser is what made the fold many-to-one. `resourceName` refuses an
identifier it cannot use verbatim instead of repairing it, so injectivity is a
property of the construction rather than a property somebody has to keep
checking. An operator learns about a bad identifier when the application is
created rather than when two applications quietly share a bucket.

The physical-name mapping stays where USOSS-10 put it: a provider maps a logical
name onto its substrate's grammar injectively or refuses. This module produces a
logical name and does not know any substrate's rules — except one length ceiling,
checked here so that "too long" is a refusal an operator gets once, at the top,
naming the application, rather than a provider refusal partway through a deploy
that has already created three resources.
