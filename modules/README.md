# `modules/`

The `Module` framework and the modules built on it.

| Path              | Role                                                | Ticket   |
| ----------------- | --------------------------------------------------- | -------- |
| `modules/`        | The `Module` interface, schema, result, progress, DI.| USOSS-6  |
| `modules/deploy/` | Deploy an application onto a compute provider.       | USOSS-15 |
| `modules/review/` | Agent-driven scan; produces findings.                | USOSS-17 |
| `modules/fix/`    | Agent-driven remediation of those findings.          | USOSS-17 |

`modules/review` and `modules/fix` are ported; `modules/deploy` is a skeleton.
`modules/fix` imports `modules/review` — it acts on the findings that package
defines, and the repository coordinates, snapshot and cost vocabulary are shared
rather than restated. Neither ships an AI provider: each declares the interface
it needs and an adopter supplies it ([`docs/decisions/`](../docs/decisions/),
USOSS-17).

The framework sits at the root of this tree and the implementations sit
underneath it, so implementations import the framework and never the reverse.
That is what keeps the registry (which must know every module) out of the
import path of any single module.

Keep the interface **general** — do not narrow it to fit only the three modules
in the table, because that closes options a later capability will need.

What generality does *not* settle is `paved`, which is out of v1 scope
([`docs/decisions/`](../docs/decisions/)). It is worth being precise, because
an earlier version of this line said `paved` "must port later through this same
machinery", and that reads as a promise the code does not support: `paved`
implements no part of `Module` — none of its production methods matches any of
the eight — is not in the source's registry, and its own package comment says it
was deliberately left out because its rich, kind-specific inputs do not fit the
generic parameter map. Its eventual relationship to
`Module` is **undecided** — an adapter, a richer interface, or continued direct
invocation are all still open. Keeping this interface general is necessary to
leave those options open; it is not sufficient to make a `paved` port
mechanical.

## The deploy module's dependency fence

`modules/deploy` is the abstraction's acceptance test, so the claim it makes is
machine-checked rather than reviewed: **no package under `modules/deploy` may
have a dependency path — direct, transitive, in a test, or behind a build
constraint no supported configuration selects — to anything outside the
compute interface, the credential vocabulary, the module framework, and the
standard library.**

`make boundary` enforces it, as two rules in
[`internal/boundary`](../internal/boundary/boundary.go):

| rule | claim |
| ---- | ----- |
| `deploy-imports-are-an-allowlist` | everything not named is forbidden |
| `deploy-is-substrate-free`        | `github.com/aws`, `k8s.io`, `sigs.k8s.io` are forbidden **by name** |

They are different claims, not two spellings of one. The allowlist is the fence;
the denylist exists so that the most likely violation gets a message saying what
it is and why the interface is there.

Three things are worth knowing before you touch either side:

* **the allowlist came from a defeat, and its membership test came from a
  second one.** Review planted a compileable import of a cloud SDK from a fourth
  vendor and the denylist stayed green, because a denylist is blind to a
  population that does not exist yet. Then it planted a locally replaced module
  named `cloud` and the allowlist stayed green, because "is this the standard
  library" was a question about spelling. It is now `go list std` over the
  supported platforms;
* the denylist is stated over **substrates**, not over AWS, because a deploy
  module that swapped one SDK for another would have failed the ticket just as
  thoroughly;
* both are **subject-scoped**, and a subject set that comes out empty fails the
  run. Renaming or moving `modules/deploy` without updating them turns the build
  red rather than quietly disarming the fence.

If the allowlist ever needs widening, that is an edit somebody makes on purpose
and a reviewer sees — which is the point. If it needs widening to a *substrate*,
the interface is wrong and gets fixed rather than exempted.
[`internal/boundary/deployfence_test.go`](../internal/boundary/deployfence_test.go)
is the planted-import control for both rules, including the cases in the other
direction.

## How a module gets its dependencies

Two rules, and the first is the one that matters:

1. **A module declares the interface it needs and never imports its supplier.**
   The narrow interface or func type belongs to the module's package; whatever
   satisfies it belongs to the caller.
2. **Dependencies arrive through the constructor.** `NewXModule` returns an
   error — built with `modules.Missing` — naming anything absent, so a
   registered module is always a wired module.

Rule 1 is what keeps this tree portable, and it is the first thing to look for
in a new module. Here it is the wide version — no store, no service layer, no
cloud SDK. The source achieved the service-layer half and only that half. Out of
the **28** production files in its module tree: **0 of 28** import the service
layer — the dependency runs the other way, with **7 of 87** service-layer files
importing the framework package and **25 of 87** importing somewhere under the
module tree — but **16 of 28** import the persistence package directly (**6 of
the 8** packages under the tree; the exceptions are `types` and `vendor`) and
**10 of 28** import a cloud SDK directly
(8 in `deploy`, 2 in `paved`). Rule 2 replaces the `Set*` setters that **4 of its
9** modules used.

[`docs/decisions/`](../docs/decisions/) records why, with the evidence, and
the package doc ([`doc.go`](doc.go)) is the contributor-facing statement of
both — including which parts are machine-checked and which are held in review.
