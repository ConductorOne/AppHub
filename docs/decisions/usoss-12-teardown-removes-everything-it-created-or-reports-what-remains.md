## USOSS-12 — teardown removes everything it created, or reports what remains

**Binding on every AWS port.** There is no third outcome, and in particular no
path that returns success having left a resource behind.

The worst finding on this project is a teardown that reported success while
leaving a live cross-account trust relationship in place. This is the same class,
found in this port by review.

### What happened

`DeleteEndpoint` is documented as ordinarily taking **two** calls on a real
account: deleting a load balancer is asynchronous and ELBv2 releases its network
interfaces minutes later, so the first call deletes the load balancer, fails to
delete the security group with `DependencyViolation`, and returns
`compute.ErrTransient` telling the caller to retry.

On that retry there is no load balancer. The implementation read the placement off
the load balancer's tag, found no load balancer, and **returned nil** — reporting
a successful teardown with the security group still in place. Its own comment
claimed the case was "reported rather than passed over silently"; the code did the
opposite. Worse, the surviving group carries this platform's ownership tags, so
the next `Ensure` of the same logical name would *adopt* it, with the old rule
set, instead of creating a fresh one.

The retry is the documented normal path, not an edge case, so this was reachable
by every teardown that ever ran against AWS.

### Two changes, and the first is structural

**One physical name for all three objects.** A `compute.Ref` carries the physical
ELBv2 name and `sanitizeWith` is not invertible — a digested name cannot be
turned back into the logical name it came from. So a security group named by a
second mapping at a second ceiling was **unlocatable from a reference alone**,
and it had to be located exactly when the load balancer that recorded the
placement was already gone. Sharing one name makes it computable. The three
objects live in three namespaces so one name cannot collide with itself, and
`checkOwned` over distinct components is what keeps them from being mistaken for
each other.

**A bounded search when there is no load balancer to name the placement.** Every
configured placement is inspected, by exact name, with the ownership check applied
inside each — so the widest thing the search can do is delete groups this platform
created as this component under the name the reference names. A placement that
cannot be inspected is reported as `compute.ErrTransient` rather than skipped,
because a teardown that could not look everywhere has not established that
nothing remains.

### The test shape this needs

Drive the **completed two-call construction**, not a one-call synchronous
deletion. `TestTheDeleteRetryRemovesTheSecurityGroup` injects the failure at
`DeleteSecurityGroup` only — the one call AWS refuses, so the describes keep
working and the call order under test is the real one — and then observes the
substrate directly. Observing the return value is exactly what the defective
version satisfied.
