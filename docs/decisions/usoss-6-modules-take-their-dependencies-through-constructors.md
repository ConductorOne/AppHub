## USOSS-6 — modules take their dependencies through constructors

The source has **two** dependency-wiring conventions in `internal/modules`, not
one. AppHub adopts one of them and does so deliberately, because the ticket
that ported the framework described the other as if it were universal.

What is actually there, verified against the source repository's
`backend/internal/modules` (paths below are relative to it):

- `security` and `announce` are constructed **empty** and mutated afterwards
  through 16 exported setters — `agent_fix.go:232,237,241,244,247,250,257`,
  `agent_scan.go:153,158,163,176,184`, `deepsec_scan.go:45,49,53`, and
  `announce/delivery.go:82`. `RegisterDefaultModules` registers them unwired
  (`registry.go:110-125`) and `services.New` / `cmd/job-runner` push the
  dependencies in later.
- `deploy` takes its dependencies as **constructor arguments**
  (`container.go:44`, `lambda.go:38`), fed from a `DeployDeps` struct
  (`registry.go:16-22`).
- `paved`, which is out of v1 scope anyway, also uses a constructor
  (`agent_deploy.go:51`).

**AppHub uses constructor injection everywhere, and no module in this
repository exposes a `Set*` method for a dependency.**

### Why

The setters solve a problem this repository does not have. They exist because
the source builds its registry *before* it builds the collaborators the modules
need: `cmd/server/main.go` calls `RegisterDefaultModules` and then hands the
populated registry to `services.New`, which is where the concrete AI clients,
token minters, and repositories first exist. Given that order, a module cannot
receive them at construction, so it receives them afterwards. AppHub has no
`services` god-package to be on the far side of, so a caller can build a
collaborator before the module that uses it, and the ordering constraint that
motivated the setters is absent.

What the setters cost, once the ordering constraint is gone:

- **Fail-closed becomes a per-module obligation.** With a setter, an unwired
  module is registered and invocable, so every module has to remember to check
  each dependency and produce its own "not configured" error at execution time.
  **Four** concrete modules use setters — `AgentScanModule`, `AgentFixModule`,
  `DeepsecScanModule`, `DeliveryModule` — with **16** setters between them, 12 of
  those on AgentScan and AgentFix.

  Counting the resulting guards needs a definition, because an earlier version of
  this entry gave a total that mixed nil checks, resolver failures, disabled
  collaborators and optional dependencies together. Define a guard as *a nil
  check on a setter-injected field, in an `Execute` path, that returns instead of
  proceeding*. The population is every nil comparison against a field one of the
  16 setters assigns — the field set derived from the setter bodies rather than
  hand-listed — which is **13**, of which **12 return and 1 does not**:

  | Module | Guards that return | Lines |
  | --- | --- | --- |
  | `AgentScanModule` | 4 | `security/agent_scan.go:216,237,241,255` |
  | `AgentFixModule` | 5 | `security/agent_fix.go:271,364,368,372,376` |
  | `DeepsecScanModule` | 2 | `security/deepsec_scan.go:71,81` |
  | `DeliveryModule` | 1 | `announce/delivery.go:130` |

  **The thirteenth is the interesting one**, and a lexical search for
  `m.<field> == nil` missed it because the field is read into a local first:
  `agent_fix.go:459-461` does `fixer := m.fixer; if fixer == nil { fixer =
  ai.NewSecurityFixer(m.scanner) }`. That is the one place an absent
  setter-injected dependency does **not** fail closed — the module builds a
  default and carries on. So of the 16 late-bound dependencies, one silently
  substitutes rather than refusing, which is an argument for the constructor
  rather than against it: a constructor cannot express "absent, so invent one"
  without saying so in its signature.

  Deliberately *not* counted, though they are adjacent and an earlier version
  conflated them: branches on a resolver *returning* an error or nil
  (`agent_scan.go:245-252`, `agent_fix.go:427-431`), and checks on a collaborator
  that is present but switched off (`m.scanner.IsEnabled()`). Those are runtime
  failures of a dependency that was supplied, not absence of one.

  Twelve guards that refuse and one that improvises, hand-written across four
  modules, each with its own message — and "GitHub App is not configured" appears
  five times across two files. With a constructor, refusing to build is one
  branch in one place, and there is no state in which a registered module is not
  ready.
- **It publishes a mutable-after-registration surface.** A registered module is
  reachable by every holder of the registry, and a setter writes a field with no
  synchronisation at all — the `sync.RWMutex` on `Registry` guards the map, not
  the modules in it. In the source both the registration and the wiring happen
  on the start-up goroutine before anything serves, so this is not an observed
  race; it is a race that nothing in the type system prevents, and preserving
  the shape in a public library invites it in a way the internal call order
  currently does not. AppHub's `Registry` therefore has no mutation path other
  than `Register`, which is what lets its documentation say a registry read is
  safe without qualifying it.
- **It is not what makes the modules portable**, which is the part of the
  ticket's description worth keeping. The mechanism that keeps `internal/modules`
  free of `internal/services` is that each module declares the *interface* it
  needs — `ScanResultPersister`, `MintTokenFunc`, `AppResolver`, `HitsRecorder` —
  and the caller supplies something satisfying it. That is orthogonal to whether
  the value arrives through a setter or a parameter, and it is carried over
  verbatim as the first of the two rules in `modules/doc.go`.

The fail-closed *behaviour* survives the change of mechanism. `modules.Missing`
and `modules.ErrNotConfigured` give the whole tree one recognisable error for a
dependency that was not supplied, so a caller can tell an operator's wiring
mistake from a caller's bad parameters — a distinction the nine bespoke strings
did not support.

### What this obliges of USOSS-15 and USOSS-17

The security and announce modules are the ones that used setters, and
`modules/review` and `modules/fix` are ports of `security/agent_scan.go` and
`security/agent_fix.go`. They convert: dependencies become constructor
parameters, the "not configured" checks in `Execute` become one guard in
`New...`, and the narrow interfaces they declare come across unchanged. This is
a mechanical change to seven setters on `AgentFixModule` and five on
`AgentScanModule`, not a redesign of either module.
