## USOSS-62 — ownership by tag is AWS account scoped

Binding on the AWS provider and on publication readiness. This amends USOSS-10's
ownership rule and USOSS-12's tag-marker rule by naming the boundary those rules
actually prove.

### Decision

Ownership tags prove that a resource is inside the AWS account or equivalent
trust boundary that controls writes to the reserved `apphub:` tag namespace.
They do not prove which process wrote the tags.

The AWS provider may accept a resource as its own when the physical name it was
resolving carries the exact reserved ownership markers for the expected
component. That remains the right construction inside one operator-controlled
account: AWS tags are auditable and permissioned, unlike caller-supplied free
text, and they let the provider refuse rather than adopt unmarked resources.

The accepted limitation is the other side of the same construction:

> Anything in the same AWS account that can set the reserved ownership and
> component tags can present a matching resource as this platform's.

For object storage specifically, a bucket under the configured physical name
prefix that carries `apphub:managed-by=apphub` and
`apphub:component=object-bucket` is inside the provider's ownership set. If a
tenant or workload can write those tags, it can make its bucket look
AppHub-managed to this provider.

### Consequence for tenant boundaries

Cross-tenant deployment on a shared AWS account is not supported unless those
tenants intentionally share the same trust boundary. A deployment that needs
separate tenant ownership must give each tenant an isolated AWS account or an
equivalent boundary that prevents tenants from writing the reserved `apphub:`
tag namespace on resources the platform will later resolve.

A naming prefix is not that boundary. It reduces global S3 name collisions and
operator confusion; it does not stop a principal with tag-write permission from
forging the claim.

### Publication and disclosure handling

This is an accepted trust-boundary limitation, not a provider bug. Operator-facing
documentation must state it where AWS object storage and provider configuration
are described. USOSS-47's publication-disclosure audit carries it as an accepted
boundary rather than as a scrubbed disclosure class.
