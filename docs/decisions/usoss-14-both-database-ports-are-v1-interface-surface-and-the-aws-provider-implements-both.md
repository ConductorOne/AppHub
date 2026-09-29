## USOSS-14 — both database ports are v1 interface surface, and the AWS provider implements both

The ticket asked whether relational (Aurora/Postgres) and key-value (DynamoDB)
provisioning are both v1 interface surface, or whether v1 covers only Postgres,
"which has the cleanest cross-provider story". The answer is both, and the
question was already settled by the interface rather than open.

`compute` declares `RelationalProvisioner` **and** `KeyValueProvisioner`, gated
on `CapRelationalDatabase` and `CapKeyValueTable`, with `Provider.Relational()`
and `Provider.KeyValues()` as separate accessors and a written argument for why
they are separate — the two have separate access-control models, and a single
accessor gated on "either" would hand a relational-only provider an interface it
can only half implement. Deciding to drop one now would be an interface
amendment, not a scoping choice inside a port.

`compute/k8s` declines `CapKeyValueTable` unconditionally with no backing stub,
and that remains a good precedent for declining a port cleanly. This provider
does not follow it, for three reasons that are about this substrate:

* DynamoDB is the substrate `KeyValueProvisioner` was **derived from**
  (`database.go:50-107`), so declining here leaves a capability the interface
  declares with no implementation anywhere outside `compute/fake`.
* It is the substrate `Granter`'s presence on that port was argued from — the
  source grants the application's task role eight DynamoDB actions on the table
  and its indexes (`database.go:111-149`), with no notion of a database-internal
  principal. The grant half of the port is portable exactly here and nowhere
  else, so declining would leave that argument untested.
* The source's own deploy path offers it as one of two database types
  (`container.go:243-259`), so an application configured for it has no other
  answer.

### What the relational port does not cover, and who owns it

`compute.Peer{Kind: PeerWorkload}` on a relational spec is the source's
`addRDSIngress(rdsSG, appSG)` (`database.go:196-198`) — the application's
security group reaching Aurora. Resolving a workload `Ref` to a security group is
the container port's knowledge, and inventing a naming convention for another
port's resources is the coupling `Substrate` exists to prevent. So this port
**refuses** such a rule with a typed `*compute.UnsupportedError` naming
`CapContainerService`, rather than widening it or dropping it silently.

The consequence, stated plainly: **an application cannot reach its own database
until USOSS-11 lands and the two are wired together.** The seam is agreed and
shipped on USOSS-11's branch (PR #23), so the follow-up is named rather than
folklore:

```go
func (p *Provider) WorkloadSecurityGroupID(ctx context.Context, ref compute.Ref) (string, error)
```

It resolves the `Ref` through USOSS-11's service target, requires the service to
exist and to be owned — `ErrNotFound` when absent, `ErrNotOwned` when the
resource behind the reference was replaced, because ownership is re-established
at *use* rather than inherited from issuance — then looks the group up by name
and requires both the owner tag and `apphub:component == "service-security-group"`.
It composes no identifier. When USOSS-11 lands, this port's `PeerWorkload` branch
calls it and the refusal goes away.
