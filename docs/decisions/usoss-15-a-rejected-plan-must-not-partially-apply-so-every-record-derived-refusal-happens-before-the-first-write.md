## USOSS-15 — a rejected plan must not partially apply, so every record-derived refusal happens before the first write

Adversarial review of PR #42 found four defects and they were one shape:
**validation happened after mutation began.** Each invalid application record
was saved as deploying, four or five resources were created, and only then did a
provider refuse it — returning an error that said nothing about what had been
made.

The reviewer measured it: `saves=2 rendered=4` and `saves=2 rendered=5`.

### The contract this establishes

> `newPlan` performs every refusal an application record can provoke.
> `Execute` calls it, and checks the provider's capabilities, **before its first
> save and before its first provider call.**

So a record that cannot be deployed leaves the record byte-identical and the
substrate untouched. What remains after the first save is a genuine
infrastructure failure, which is a different thing and is reported as one.

### Why the remedy is not three more checks

Review reproduced three invalid combinations: a zone on a standard bucket, an
undefined access level, and a route targeting a port the workload does not
declare. Three checks would have closed those three. They would not have closed
the fourth field somebody adds next month — and the actual defect is that the
input types can express a combination the module cannot honour with nothing
systematically saying so.

Each of the three is closed by a construction instead:

* the zone, and every other variant-scoped field, by the applicability table and
  its derived walk — see the separate entry;
* the access level, by a decided closed set cross-checked against
  `compute.AccessLevel` with `go/types`, so a level added upstream stops this
  build until somebody rules on it;
* the route target, **by deleting the field.** This module declares exactly one
  workload port, so a settable route target offered a choice the model could not
  honour. There is now no value anybody can set, so there is nothing to validate
  and nothing to get wrong later.

### What is left after the first save, stated rather than hidden

Two things can still fail mid-deploy, and neither is closable from here:

1. **Workload-identity materials.** The credential layer's references are not
   derivable from the record: they arrive from `Provisioner.Materials`, which
   the workload-identity contract requires be called after `Rotate`. Rotating
   earlier so the binding could be checked earlier would break a *running*
   application on any input error, which is worse than the failure it prevents.
   So the call stays as late as possible and a failure there is a mid-deploy
   failure.
2. **A secret deleted between the preflight and the workload's creation.** No
   preflight can close a race, and the provider's refusal is the backstop.

Both are pinned by tests asserting the *current* behaviour, so a later interface
change turns them red rather than letting a better guarantee be inherited
silently.

### The instance that keeps coming back, and what it says about the shape

Later rounds of review found the same shape twice more, both times in a secret
reference the refusal-before-mutation pass did not ask about. The first was that
there was no operation to ask with, closed by `SecretStore.Describe` — see the
separate entry. The second was that the preflight, having the operation, walked
only the bindings the *application* declares.

The one binding it therefore skipped is the one this module issues for itself:
the database's administrative password, which lives on `Artifacts.Secrets` and is
adopted into the binder before anything is created. Deleting it produced a
refusal at the relational step and a changed `Config.Placement` produced one from
`EnsureService`, both at `saves=2` — after an image was built and pushed, and in
the placement case after a new identity, repository and database existed.

> The preflight's subject is **every reference this deploy will bind**, not the
> ones the record declares: `Plan.Secrets` and `Artifacts.Secrets` both.

Stated that way because "check the application's bindings" is the formulation
that admitted the defect, and the module issuing a binding of its own is not a
special case — it is the ordinary consequence of a module that provisions
anything with a credential.
