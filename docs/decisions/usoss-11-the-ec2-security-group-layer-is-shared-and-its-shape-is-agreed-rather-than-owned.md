## USOSS-11 — the EC2 security-group layer is shared, and its shape is agreed rather than owned

The supervisor's addendum assigns the EC2 primitive layer to USOSS-12 and the
`compute.IngressRule` compiler to USOSS-11. This port carries both, because the
conformance suite drives `ServiceSpec.Ingress` on every container-service check
(`conformance/ports.go:515-518`), so the container port cannot pass the contract
without the primitives and cannot wait for them.

The type and method names are USOSS-14's published shape, adopted verbatim rather
than re-derived, so that whoever rebases second resolves the collision by
**deleting one copy** instead of reconciling two designs. `SecurityGroupRule` is
deliberately comparable — no slices, no maps — because reconciling ingress is set
arithmetic, and a rule type that could not be a map key pushes every
implementation into a hand-written comparison whose bugs are silent.

Two behaviours are load-bearing rather than incidental. **Revoke happens before
authorise**, so an `Ensure` that narrows a rule set and fails halfway leaves the
narrower set in force rather than the wider one. And **`PeerInternet` opens both
address families**: a rule that opened only `0.0.0.0/0` would leave an
IPv6-reachable workload unreachable on an address it actually has, an operator
would add `::/0` by hand, and that hand-added rule would then be revoked by the
next convergence — so naming both is the honest reading of what the peer means.
