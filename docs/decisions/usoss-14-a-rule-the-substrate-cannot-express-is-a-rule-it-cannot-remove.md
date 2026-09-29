## USOSS-14 — a rule the substrate cannot express is a rule it cannot remove

`SecurityGroupRule` carries `FromPort` and `ToPort`, and a rendering refusal
returns a plain error rather than a substrate sentinel.

### What it replaced

The first version carried a single `Port` and reported a port range read off a
group as `Port: -1`. The reasoning was deliberate and it was half right: a range
is not a rule this provider ever asks for, `-1` is not a legal port, so a range
could never compare equal to a desired rule and therefore always landed in the
removal set. Reconciliation would revoke it.

It could not. To revoke, a rule has to be rendered back into an EC2 permission,
and there is no permission for port `-1`. So the sentinel made the range
*visible* and simultaneously made it *unremovable* — and the comment beside it
described the behaviour that the code prevented.

The consequence is a security one, and it depends on something this package
cannot know. Given a revoke of `FromPort: -1`, AWS answers either
`InvalidParameterValue` — which this package maps to `ErrMalformed` and the
reconcile fails — or `InvalidPermission.NotFound`, which is `ErrNoSuchResource`,
which `reconcileIngress` **tolerates** as a benign concurrent teardown. In the
second case the reconcile returns `nil` while the wide rule is still authorised:
a caller is told a rule was removed that is still in force. On USOSS-11's
container port, where their reviewer reproduced it, the surviving rule was
`1024-65535` from `0.0.0.0/0`.

A design whose safety turns on which of two undocumented error codes a service
returns is not safe, and this repository has already written down that it will
not claim to know EC2's answers.

### The two halves, because either alone leaves it

**Representation.** A representation that cannot express a rule cannot remove
it, so anything the substrate can hold has to be expressible — or **explicitly
refused**. Those two are both acceptable and silent omission is not:

```
expressible          reconcilable, revocable, correct
explicitly refused   loud, safe, incomplete but honest
silently omitted     the rule stays authorised and nothing knows
```

`Port` was **renamed** rather than joined by a second field, so the compiler
found every site; a new field would have left the sites that forgot it compiling
and wrong. `singlePort(protocol, port, description)` constructs the single-port
rules this provider writes, so a half-built rule is not constructible by
accident. The property the sentinel existed for is kept without a magic value: a
rule this provider did not write is not equal to one that came from `singlePort`.

### The first attempt fixed the reported witness and not the class

This entry originally concluded that the representation now satisfied
"anything the substrate can hold has to be expressible". It did not, and review
found three more shapes before the change merged. The first version gave the rule
two port numbers, which closed exactly one axis of a seven-field type.

The axes must come from `types.IpPermission`, not from the shapes this provider
has met:

| field | what the first fix did |
|---|---|
| `IpProtocol` | kept, but its effect on the ports' *meaning* was missed |
| `FromPort`, `ToPort` | modelled as required `int`, though the SDK's are `*int32` |
| `IpRanges`, `Ipv6Ranges` | kept |
| `UserIdGroupPairs` | kept the group, **dropped the owner** |
| `PrefixListIds` | **no field at all** |

Three consequences, and the first is worse than the defect this entry is about:

1. a permission whose only source was a prefix list produced **zero rules**. It
   could never enter the removal set, and stayed authorised with nothing pointing
   at it. A strange value in a read-back is an anomaly somebody may notice; zero
   rules is indistinguishable from an empty group. **Silent omission is the
   fail-open with the evidence removed.**
2. an all-protocol permission omits both ports, and a nil became a non-nil zero
   on the way back — so again the revoke was not built from the permission EC2
   returned.
3. ICMP's documented `-1/-1` wildcard was **refused**, because the bound written
   for TCP ports rejected every negative value. That is a **false refusal
   introduced by the fix for a silent one**, and both come from the same missing
   axis: `-1` was a sentinel in this package and a real value in the SDK at the
   same time.

So the ports are `OptionalPort` (comparable, absence with one representation),
`-1` is carried rather than minted or refused, the owner of a cross-account pair
is kept because a revoke that drops it revokes nothing, and prefix lists have a
field. The remaining unexpressible shape — a permission with no source arm at all
— is an **error at the read**, which is the tripwire that keeps the honest answer
available without pretending the grammar is closed by luck.

`TestEveryEC2IngressShapeStaysRepresentable` asserts the closure by round-tripping
each shape through the production path and comparing **field for field, including
the nil-ness of the ports**. Each of the three consequences above reproduces when
its axis is removed.

**Classification.** `ipPermissions` can now refuse, and its refusal carries no
substrate sentinel. *Malformed, invalid and absent are three answers*, and
collapsing "I cannot describe your rule" into "that rule is already gone" turns
a failure into evidence of the desired state, which is the fail-open direction.
The tolerance itself is unchanged and still right: a rule the **service** says is
absent really is a benign race.

Fixing the first half made a second instance of the same class visible. A rule
with neither a source group nor a source CIDR used to fall through to the IPv4
branch and render `CidrIp: ""` — a permission describing no source at all, sent
to EC2 to be rejected with a code nobody here chose. It is refused in the same
place, for the same reason.

### Where `-1` still appears, and why that is not the same thing

`compute.IngressRule` carries one port, so a range read off a group cannot be
reported faithfully through the interface. `observedIngress` reports it as its
low port with the span appended to the description: a shape no caller can have
asked for, so the next `Ensure` revokes it. The lossiness is confined to that
read-back, and revocation is built from the substrate record, which keeps both
numbers — so the approximation can never feed a revoke. That separation is the
correction. What was wrong before was that the **substrate** representation was
the lossy one.

### The fake accepted what the real adapter refuses

USOSS-11 could not reproduce any of this against their in-memory EC2:
`MemoryEC2.RevokeIngress` matches rules by equality on the record, so it removed
a rule the SDK adapter could not describe, and end to end everything looked
correct. A green against the in-memory substrate alone would have meant nothing.

So the tests share the step where the loss happens. The unit assertion is a round
trip through `securityGroupRecord` and `ipPermissions`, both production code; the
end-to-end one drives `reconcileIngress` through a `renderingEC2` that renders
through `ipPermissions` before mutating, the way the adapter does. Both halves
were red-checked independently: restoring the sentinel fails the round trip and
the not-asked-for property, and re-classifying a rendering refusal as
`ErrNoSuchResource` fails the refusal-is-not-absence test.

### A false suppression that became unnecessary

The old `int32` conversion carried `//nolint:gosec // bounded to 1..65535 by the
compiler`. It was provably false: `securityGroupRecord` set the value to `-1` by
construction, in the same file, eighty lines above. The fix is not a corrected
justification — the explicit range check makes the bound visible to the linter,
so `gosec` no longer warns and there is nothing left to suppress. A suppression
is a statement to the next reader that somebody checked; the honest version of
that statement is a check.
