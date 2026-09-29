# `cmd/`

Executable entrypoints.

* **`apphub`** — the composition root for credential vending. It builds the
  provider registry from the environment and reports what it registered. That is
  deliberately all it does: the applications that will consume the registry are
  other tickets, and a composition root with nothing to compose into yet is more
  useful as an honest one than as a placeholder.

This directory is also the wiring point: it is where a binary chooses which
providers to register. That matters for one specific reason — the ConductorOne
credential provider (`credentials/c1`) must never be pulled in by a library
package, so a binary that wants it imports it *here* and registers it
explicitly. A binary that does not import it has no ConductorOne dependency in
its build graph at all.

`make boundary` enforces that rule; `internal/boundary` holds the allowlist, and
**`cmd/apphub` is the single allowlisted importer of `credentials/c1`**. A second
entry needs supervisor approval — see `docs/design/credential-vending.md` §11.3,
which exists so a later reader does not delete the entry as cleanup.

`cmd/apphub/main_test.go` is the binary-level evidence for the
ConductorOne-optional guarantee: it compiles the binary and runs it in a separate
process with an empty environment. That is the claim an adopter actually cares
about, and package-level tests cannot make it.
