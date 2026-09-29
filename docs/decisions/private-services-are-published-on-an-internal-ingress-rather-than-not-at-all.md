## Private services are published on an internal ingress rather than not at all

A private application used to get no route and a security group with no
inbound rule, so nothing could connect to it — not other services, not staff
on the network — and none of its requests reached the proxy whose access log
counts traffic. The form described it as reachable from the private network,
which it was not.

On a target with an internal ingress configured (`deployConfig.internalRouteDomain`
and `internalRouteCertificate`, and the provider's
`container.internalEntrypoint`), a private *service* is now published at
`<hostname>.<internalRouteDomain>`:

* **An internal load balancer forwards only to a dedicated proxy entrypoint.**
  The router for an internal route (`compute.Route.Internal`) is bound to that
  entrypoint alone, and the public load balancer never forwards to it, so a
  request from the internet carrying an internal `Host` header matches nothing.
  A provider with no internal entrypoint refuses an internal route rather than
  placing it on a public one.
* **The same sign-in applies.** Internal routes carry the platform's
  authenticating middleware, like public ones.
* **The hostname is reserved like a public one.** A private service that names
  none gets a label derived from its application ID (`app-<12 hex>`), stable
  across edits, and reserved in the same per-target namespace, so a private and
  a public application cannot hold the same label.

Scheduled jobs, and every private application on a target without an internal
ingress, keep having no route.

### Alternatives refused

* **Proxy entrypoint published through service discovery, no load balancer.**
  No per-application name and no TLS; every caller would have to address the
  proxy and pick the application with a header.
* **A private DNS zone.** Chosen against by the operator: a record in the public
  zone resolves from peered networks and VPN clients without forwarding rules,
  at the cost of disclosing private addresses to anyone who looks the name up.
