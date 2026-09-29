## USOSS-15 — the database is opened to its own workload by a second Ensure, and to nothing else

An application's relational database accepts inbound connections from exactly
one peer: the workload deployed for that application. Reaching that state takes
two `EnsureRelational` calls, and the ordering is the decision.

### Why two calls

The two resources depend on each other in opposite directions. The workload
needs the database's endpoint in its environment, so the database has to exist
first. The database's only permitted peer is the workload, which does not exist
yet on a first deploy — `compute.Peer` identifies a workload peer by its `Ref`.

Ingress is declarative: the set attached to a spec is the desired state and a
provider reconciles to exactly it on every `Ensure`. So the resolution is to
create the database with **no** ingress at all, create the workload, and then
re-`Ensure` the database with the one rule naming it. Between the two calls the
database accepts no inbound connections from anything, which is the right state
for a database nothing is using yet.

The second call passes the same administrative password the first did, because a
provider must not rotate on a re-`Ensure` and passing a different one would be
asking it to.

### Why the control plane is not on the list

The source authorised every control-plane security group onto the database
(`container.go:349`, calling `database.go:206`) so that deploy-time SQL could
run: `CREATE EXTENSION` and `CREATE ROLE`, issued from the job runner.

No port here issues SQL — see the entry on what this module does not port — so
that rule would be an opening with nothing behind it. `compute.PeerControlPlane`
exists and is documented for exactly this, and it is deliberately unused by this
module. If deploy-time SQL is ever ported, the rule comes back with it, in the
same change.

### The engine's port is a constant, and an unknown engine is refused

The default port of a protocol is not a cloud identifier; every Postgres in the
world is on 5432. What it must not be is a guess: an engine `enginePort` does not
recognise is refused rather than given a plausible default, because an ingress
rule on the wrong port is a database the application cannot reach and an operator
debugging the application instead of the rule.

The refusal happens when the plan is built, not when the rule is, so an engine
with no known port fails before the database, the image and the workload exist.
