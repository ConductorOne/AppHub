## USOSS-12 — an ownership marker goes on a tag, never on caller-influenceable free text

**Binding on every AWS port.** Recorded because this is the third instance in one
day of the same mistake in three different components, which makes it a class
rather than three bugs: USOSS-10 marked ECR lifecycle rules by description
prefix, USOSS-13 established the general form while analysing marker-objects
versus tags, and this port marked security group rules by description substring.

### The rule

> **An ownership signal is only as trustworthy as the permission needed to forge
> it.**

Free text needs none. A tag needs `ec2:CreateTags`, `iam:TagRole`,
`ecr:TagResource` — a permission an account policy can grant, withhold and audit.
So the claim "apphub created this" lives *outside* the thing being claimed, in a
field the caller cannot write, and it is matched **exactly** rather than searched
for.

The corollary about closing witnesses matters as much as the rule. A longer
substring, or a prefix test instead of a `Contains`, closes the reproduction in
front of you and leaves the next spelling available. That is not a fix; it is a
narrower version of the same defect.

### How it failed here, in both directions at once

`compute.IngressRule.Description` is caller-supplied and is carried through to
the EC2 rule. An earlier revision of `isOwnRule` treated a rule as
provider-owned when its description contained `"apphub"`, on the argument — in
a code comment admitting the weakness and taking it anyway — that a security
group rule had nowhere else to put a marker.

* **Fail-open.** A rule this provider created with an ordinary caller
  description (`"public HTTPS for customers"`) was **never revoked**, because the
  caller's text replaced the default marker. A listener removed from a
  declarative spec disappeared and its security-group permission stayed open.
  Triggered by the most ordinary input there is: a caller who described their own
  rule.
* **Fail-destructive.** An operator's own rule whose text merely mentioned the
  project (`"operator: not managed by apphub"`) was **deleted**, by an
  *unchanged* Ensure.

The argument was also simply wrong on the facts. An EC2 security group **rule**
is a first-class taggable object with its own identifier: `security-group-rule`
is a tagging resource type, `AuthorizeSecurityGroupIngress` takes a
`TagSpecification`, `DescribeSecurityGroupRules` returns identifiers and tags, and
`RevokeSecurityGroupIngress` accepts rule identifiers. Nothing had to be invented.

### The construction

* Rules are read through `DescribeSecurityGroupRules`, not off the permissions on
  `DescribeSecurityGroups` — the group-level read carries neither identifiers nor
  tags, and **that** is what made an earlier revision reach for the description
  in the first place. A seam that cannot carry the ownership signal forces the
  layer above it to invent one.
* Rules are tagged in the authorise call, not afterwards, so there is no window
  in which a rule exists with no marker. A reconcile landing in such a window
  would decline to revoke a rule this provider had just created — the fail-open
  direction.
* Both tags are checked, `apphub:managed-by` and `apphub:component`, for the
  same reason `checkOwned` checks both: this port creates four objects and its
  siblings create more, so "apphub made this" is not specific enough to act on.
  A sibling port's rule in the same security group is distinguishable only by
  component, and no description test could ever have told them apart.
* Revocation is **by rule identifier**, not by reconstructed permission. An
  identifier names exactly one rule; a reconstructed permission asks EC2 to
  match, and a match has more than two outcomes — it can miss the rule that was
  meant and catch one that was not.

### The obligation on the other ports

If a resource your port reconciles has tags, the marker goes there. If it does
not, that is a finding to report rather than a licence to use free text — and
check the assumption first, because it was false here.

Test the **conjunction**, not the witnesses. The description is a loop variable
in `TestARuleRemovedFromASpecIsRevokedWhateverItsDescription`, covering empty,
ordinary prose, text mentioning the project, and text spelling the old marker
exactly; and `TestARuleThisProviderDidNotCreateSurvivesConvergence` covers an
operator rule on both sides of that boundary plus one carrying apphub's owner tag
under another component. Both were mutation-verified against the old mechanism:
restoring the substring test fails the first for two descriptions and the second
for all three.
