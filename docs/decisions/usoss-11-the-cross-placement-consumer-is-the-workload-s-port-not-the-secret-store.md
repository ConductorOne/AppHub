## USOSS-11 — the cross-placement consumer is the workload's port, not the secret store

*Recorded from USOSS-11, which turned `security/secrets-do-not-cross-placements`
red the day it landed the first provider with both a container service and a
secret store. USOSS-26's #49 supplied the datum; this settles which side reads
it, because "needs #49 on main" was necessary and not sufficient and nothing in
either change consumed what the other recorded.*

The invariant is that a workload in one placement may not bind a secret from
another. It had never run: `checkSecretsDoNotCrossPlacements` needs
`CapContainerService` **and** `CapSecretStore`, and until this port arrived no
provider advertised both.

The reason it could not simply be satisfied is a real gap in the interface. A
`compute.SecretBinding` carries a `compute.Ref`, and a `Ref` is
`{Provider, Kind, ID}` — no placement. So the container port, handed a binding
and a workload placement, had nothing to compare. The store knew the answer at
`Put` and discarded it: it validated `spec.Placement` for the error and returned
a ref built from scope and name.

#49 fixed the recording half — an `apphub:placement` tag and
`Provider.SecretPlacement` — and touched no consumer. Two candidate consumers
existed and they are not equivalent.

### Why the store cannot carry it

Handing the workload's placement *down* to the store, and letting the store
refuse, is the shorter diff. It is the wrong side, for the reason this port
already sealed the foreign-provider and wrong-kind checks in
`resolveSecrets` rather than delegating them: **`SecretResolver` is a
caller-supplied interface.** A resolver that answered the placement question
permissively — or not at all — would make the port's fail-closed behaviour a
property of whichever resolver it was handed, and a fail-open at the port is
exactly what that seam exists to prevent. USOSS-26's own review arrived at the
same conclusion from the other direction.

There is a second reason, narrower and decisive. The store is not the only thing
a placement mismatch breaks. The execution role's SSM read grant, the task
definition's `valueFrom`, and the region the task resolves the parameter in are
all this port's, and all three are wrong together. A refusal that lives in the
store fires after the port has already decided what to grant.

### So the seam reports a fact and the port makes the decision

`SecretResolver` grows `SecretPlacement(ctx, SecretBindingRef) (string, error)`.
It reports where the secret is stored. It does not compare, and it does not
refuse. `containerRuntime.EnsureService` compares against the resolved placement
and returns `compute.ErrInvalidSpec`.

Three properties this shape has and the delegating one does not:

- **The seam still cannot carry material.** A placement is a name an operator
  chose. `TestTheSecretSeamCannotCarryAValue` reflects over the interface's
  return types and still holds, which is the check that licenses adding a method
  here at all.
- **The comparison is on the resolved name from both sides.** `Config.placement`
  fills a caller's empty "use the default" in before the comparison, and the
  store records the resolved name at `Put` for the same reason. Two placements
  spelled differently would make the check a comparison of formatting.
- **"Not recorded" is an error, not an empty string.** #49 chose that and this
  consumer depends on it: a secret stored before the store recorded placements
  and a secret stored for the default placement are different facts, and a
  consumer comparing them would silently read the first as the second.

### The cost, stated

An existing parameter with no `apphub:placement` tag now fails an `Ensure` that
binds it, rather than being bound and resolving to nothing at launch. That is a
deliberate trade: the second outcome is a container that never starts, reported
minutes later as a deploy failure. There is no migration path in this change
because there is no deployed store to migrate.

### The rule

When one change records a datum and the invariant needs it read, the change that
records it is half the fix. Name the consumer in the same breath, and put the
refusal on the side that owns the grants the mismatch would otherwise produce.
