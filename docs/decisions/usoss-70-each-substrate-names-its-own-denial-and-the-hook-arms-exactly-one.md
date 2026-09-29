## USOSS-70 — each substrate names its own denial, and the hook arms exactly one

Closes the gap [USOSS-40](usoss-40-the-taxonomy-has-a-permission-sentinel-compute-errnotpermitted.md)
recorded against `compute/k8s`: `Options.InduceDenial` was nil there, so
`provider/an-authorization-failure-is-ErrNotPermitted` reported a clean skip on
both configurations of the provider — and behind the skip, a Kubernetes 403
reached a caller as `compute.ErrFailed`.

That pairing is the point. The skip was not "this provider is unverified"; it was
"this provider is wrong, and nothing was in a position to say so". An inert gate
and a correct mapping look identical from outside, which is why the check counts
ports by name — and why closing a skip has to be a mapping change and a hook
change together, not a hook change that turns a green tick on.

### The measurement, in both directions

* Before: `NOT VERIFIED — ... This provider's Options do not supply
  Options.InduceDenial`, on `TestConformanceFullCluster` and
  `TestConformancePlainCluster`.
* After: `induced a denial through 9 of 9 port(s)` on the full cluster and
  `4 of 4` on the plain one, with no port reported undrivable.
* With the mapping arms removed and the hook left in place, all nine ports fail
  with `an authorization failure surfaced as compute.ErrFailed`. That is the
  provider's behaviour before this change, stated by the gate that could not
  previously reach it.

### Three substrates, three denial sentinels

`compute/k8s` talks to three substrates with three unrelated failure vocabularies,
and two of them already had a denial sentinel: `ErrRegistryDenied` and
`ErrObjectStoreDenied`. The cluster had none, so this adds **`ErrClusterDenied`**
— the API server's 403 and its 401 — rather than mapping a `k8s.io` error onto
the compute taxonomy at the point it is caught. `ClientCluster.apiError` stops at
this package's own vocabulary on purpose (the two unrelated 409s are why), and
`Provider.substrateError` is the single place that vocabulary becomes a compute
sentinel.

**The two backing sentinels were already live and already unmapped.** Neither
`ErrRegistryDenied` nor `ErrObjectStoreDenied` had an arm in
`Provider.backingError`; both fell to its default and became `compute.ErrFailed`.
`S3ObjectStore` produces `ErrObjectStoreDenied` from a real HTTP 403 with nothing
injected, so this half is a fix to a path in production, not only to one a test
can reach. That is what the missing hook was hiding: not a gap in coverage of a
correct mapping, but a wrong mapping on three substrates, one of which nothing
had to arrange.

A 401 lands on the same sentinel as a 403, following `compute.ErrNotPermitted`'s
own reasoning: the taxonomy discriminates on who can fix it and whether the same
request could ever succeed, and a refused credential and a refused verb answer
both questions the same way.

### The hook arms one substrate, and it arms it stickily

`Harness.FailNextApply` arms all three substrates because it is not told which
port the suite is about to drive. `InduceDenial` **is** told, so it arms exactly
the substrate behind that kind. Arming all three would let the check report nine
ports driven while establishing only that whichever substrate answered first is
mapped — three mappings collapsed into one measurement, which is the same vacuity
one level along.

Each substrate is armed in its own vocabulary for the reason `FailNextApply`
already translates: handing the object store a cluster error exercises the
default arm of a mapping rather than its denial arm, and passes while proving the
opposite.

It is sticky (`FailEvery`) rather than one-shot. A one-shot arm has to guess how
many calls into an `Ensure` the interesting one is, and guessing wrong is quiet in
the worst direction — the shot is spent on a call the port converges rather than
propagates, the `Ensure` succeeds, and the suite reports "this provider does not
surface denials at all". The message would name the wrong defect.

**Which substrate stands behind a kind is asked once.** The cluster's answer is
`Provider.clusterGVK`, split out of `Provider.locate` so the hook and the waiter
share one switch. A second switch over the same kinds is the restatement
`locate`'s own note warns about, and the drift it invites is a port silently
reported as undrivable.

A kind with no substrate behind it — a key-value table on this provider — is an
error rather than a no-op stop, so the suite records that port as undrivable by
name instead of counting it as verified.

### The AWS secret port, found by the same count

`compute/aws` had the hook already, and the check reported `8 of 9` and `7 of 8`
on its configurations, naming `secret` as undrivable. The port whose subject *is*
authorization was the one port whose denial mapping nothing exercised. The mapping
was in fact correct — `secret.go` reaches `ErrNotPermitted` and a unit test pins
it — but "correct by inheritance" is the claim this hook exists to drive rather
than accept. Arming SSM Parameter Store takes those runs to `9 of 9` and `8 of 8`.

Finding it took no investigation: the check prints the ports it drove and the
ports it could not. That is the argument for counting by name rather than
reporting a pass.
