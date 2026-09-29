## USOSS-15 — a failed deploy records a classification, never the provider's error text

The source stored `err.Error()` on the application row when a deploy failed
(`container.go:999`). This module stores the step it was on and a
classification derived by asking the error which of the compute taxonomy's
sentinels it is. The full error still reaches the caller as `Execute`'s return
value; it does not become a durable artefact.

### Why

A provider is free to put anything in an error string, and an application record
is read by a user interface, exported, and kept. The two facts together make the
record a credential-egress channel that nothing else in the design treats as one.

This is not hypothetical: `compute/fake` ships a deliberate defect that
interpolates a database's administrative password into a provisioning error,
because a provider doing that is a thing the conformance suite has to be able to
catch. A deploy module that persisted the error text would turn one provider bug
into a stored credential.

It is a deliberate departure from the source, and it is fail-closed in the sense
this repository uses: where the source's behaviour depends on every provider
being careful, the port does not depend on it.

### What is kept instead, and why that is enough

`FailedStep` is a phase name this module chooses from a closed set, and
`FailureClass` is one of a closed set of classifications. Between them a reader
is told what failed and whose problem it is — which is what the record is for —
without carrying a string this module did not compose.

`classify` has a third answer, `unclassified`, and that is deliberate rather than
a gap: it says the failure was not one of the classes this module can describe,
which is what somebody needs to know before going to the logs. Folding it into
the nearest class would record a guess as a fact.

### The controls

The assertion has a control that establishes the material was there to be found,
because a scan of a channel that could never have carried it is a scan that
reports success honestly and means nothing. `TestTheHostileProviderReallyLeaks`
asserts the hostile provider's error **does** contain the password, and that a
conformant one does not. The record is then searched with a reflective walk over
the whole `Application`, normalised for nothing, so a field added later is
covered by construction rather than by somebody remembering.
