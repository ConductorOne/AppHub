## USOSS-12 — function exposure and container exposure are two shapes, and neither contains the other

The design question this ticket was opened to answer: is
`compute.FunctionRuntime.EnsureEndpoint` provider-neutral, or is the ALB leaking
through it?

**Two shapes is correct.** Established from the source with a denominator, by
USOSS-11: of twenty-one Go files on the deploy path, exactly **one** uses
`elbv2`, and it is `lambda.go`. `container.go` has no ELBv2 reference at all and
`CreateService`'s `LoadBalancers` field is never set; its only `loadbalancer`
strings are Traefik's own label vocabulary at `:1333` and `:1375`. So a container
is exposed by *registering with a reverse proxy that already exists* and a
function by *provisioning a load balancer of its own*. Those are different
operations on different objects, and `compute.Route` and `compute.EndpointSpec`
are right to be two types.

**The finding is that neither shape contains the other.** Reported rather than
worked around, and concurred in by USOSS-11 from its own call sites:

* `Route` expresses path-prefix routing and platform authentication —
  `PathPrefixes`, `RequireAuth`, `PublicPaths`. `EndpointSpec` cannot, so a
  caller wanting an authenticated function endpoint has nowhere to say so.
* `EndpointSpec` expresses several listeners with per-listener port, protocol and
  certificate. `Route` cannot — one `TargetPort`, one `TLS` — so a caller wanting
  a service on two ports with two certificates has nowhere to say so.
* `EndpointSpec.Target` is already a bare `compute.Ref` with nothing
  function-specific about it, which is what makes the asymmetry look accidental
  rather than designed.

The auth half carries a security semantic that makes it more than a feature gap.
`Route.PublicPaths` is the **auth-exemption** set: the base router carries the
platform's auth middleware and each public path gets its own router at a higher
priority *without* it. A port implementing one without the other silently either
authenticates nothing or exempts nothing, so the two must be implemented
together or neither. This port implements neither, and does not advertise
`compute.CapIngressAuth`.

Not raised as an amendment because nothing above the interface asks for an
authenticated function endpoint today. It is the shape to fix if anything does,
and the fix is likely a common exposure type rather than a third one.
