## USOSS-12 — readiness is the whole construction, not its first object

`compute.PhaseReady` means serving, and `WaitForEndpoint` promises to block until
the endpoint is serving.

`WaitForEndpoint` polled only `DescribeLoadBalancer` and mapped an active load
balancer straight to ready. One of the endpoint's six objects was active and the
whole construction was called serving — a correctly-counted wrong population. A
load balancer whose only target is unhealthy answers every request with a 502.

The distinction was being destroyed **below the substrate seam**, which is the
part worth remembering: the SDK adapter already called `DescribeTargetHealth` and
discarded every state, keeping only the identifiers. The question had been asked
of the service and thrown away, so the layer above could only treat registration
as health. **Registration is not health.**

`DescribeTargets` now returns `[]TargetHealth` and `endpointPhase` takes the
conjunction. The three-way split matters as much as including health at all:

* **no targets** is pending, not failed — that is what an endpoint looks like
  between its create and its registration;
* **`initial`** is pending, because ELBv2 has not finished checking and a Wait
  should keep waiting;
* anything else that is not `healthy` is **failed**, carrying ELBv2's own reason,
  because a caller that cannot distinguish "not yet" from "never" has to choose
  between waiting forever and abandoning early.

Both directions are tested. A one-directional check cannot tell "includes health"
from "never ready", and the in-memory substrate models a target settling from
`initial` to `healthy` on observation so the ready direction is reachable at all.

One consequence worth stating: the stall hook now has to hold **both**
conditions. Stalling only the load balancer would still satisfy today's deadline
checks and would silently stop stalling the moment the readiness rule changed —
and the per-group stall exists because a substrate-wide flag, set by a one-way
hook the conformance suite never releases, held every later check's endpoint
pending forever. The suite caught that.
