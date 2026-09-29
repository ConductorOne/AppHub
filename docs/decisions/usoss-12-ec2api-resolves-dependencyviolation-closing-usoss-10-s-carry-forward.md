## USOSS-12 — `EC2API` resolves `DependencyViolation`, closing USOSS-10's carry-forward

USOSS-10's retry record names one divergence to carry forward: `awsutil.Retry`
treats `DependencyViolation` and `ResourceInUse` as retryable and the SDK's
standard retryer does not, and it says the difference "stops being harmless the
moment USOSS-11 ports that path".

**USOSS-12 reached the path first.** The EC2 layer is this ticket's — the split
approved by the supervisor gives `EC2API`, its implementations and the placement
resolver to USOSS-12 and the `compute.IngressRule` compiler's service-side call
sites to USOSS-11 — and `DeleteEndpoint` deletes the security group in front of a
load balancer, which is exactly where the code arises.

Resolved by **classification, not by a loop**, which is the division the retry
record draws. `ec2Error` maps both codes onto `ErrConflict`, and
`Provider.substrateError` maps that onto `compute.ErrTransient`. The codes live
in `ec2Error` and not in `classify`, because they are an EC2-shaped fact and the
shared classifier would make them a property of every service this package talks
to — which the retry record asks the port that needs them not to do.

`ErrConflict` rather than `ErrThrottled`: a dependency is not a rate. Both reach
the same sentinel, and the error a caller reads should say which thing happened.

An operator who wants the SDK itself to absorb it adds the codes through a
`retry.AddWithErrorCodes` option on the EC2 client they build. Nothing in this
package changes for that, and the two compose rather than multiply.

**The consequence a caller has to know**, and it is why swallowing the error was
rejected: deleting a load balancer is asynchronous and its network interfaces are
released minutes later, so the first `DeleteEndpoint` on a real account reports
`ErrTransient` and the security group survives. Swallowing it would leave a
security group behind with nothing recording that it exists — and its ownership
tag means the next `Ensure` of the same logical name would adopt it, with the old
rule set, instead of creating a fresh one. Idempotency is the mechanism, and the
sentinel is how the caller is told to use it.
