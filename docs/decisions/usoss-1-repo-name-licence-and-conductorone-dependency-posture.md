## USOSS-1 — Repo name, licence, and ConductorOne dependency posture

*Recorded from the USOSS-1 decision record, verbatim, except that the name of
the deciding individual has been replaced with the project. What the project
decided is public; who was in the room is not.*

> ## Decision record — USOSS-1 resolved
>
> All three gating choices are decided. These are now binding on every downstream porting ticket.
>
> ### 1. Repo name + location
>
> **`github.com/conductorone/apphub`** — repo already exists, currently **private and empty**.
>
> Go module path for every ported file: `github.com/conductorone/apphub`. Replaces `the source repository module path` (`backend/go.mod:1`).
>
> The repo stays **private until USOSS-18 (pre-publication audit) passes**. Publication is a one-way door — git history cannot be un-published — so the flip to public is a gated, human-approved step, not a side effect of a merge.

### A correction to "git history cannot be un-published"

Recorded here because it widens what USOSS-18 has to check, and because it was
only in a worker report until now.

Squash-merging a branch removes its intermediate commits from `main`'s
**ancestry**. It does not remove them from GitHub. Pull-request refs and the
commit objects behind them are retained independently of any branch, so a
commit that is no longer an ancestor of `main` can still be reachable through
the pull request that carried it — and when a private repository is later made
public, that material can become visible with it.

Two commits on the USOSS-4 branch matter for this: `b28b48c` and `ad1b17b`
carried an individual's name and handle that were deliberately removed from the
tree afterwards.

**Before this repository's visibility is ever changed**, USOSS-18 must either
verify that the old pull-request commits are not exposed, or publish from a
clean-history repository or mirror. "We squashed" is not by itself an erasure
mechanism.
>
> ### 2. License
>
> **Apache-2.0.**
>
> Rationale: explicit patent grant and trademark clause, which matters for a credential-vending project; compatible with every direct dependency in scope (AWS SDK is Apache-2.0, `anthropics/anthropic-sdk-go`, `jackc/pgx/v5`, `coreos/go-oidc`). Contribution flow is **DCO sign-off, not a CLA**.
>
> USOSS-4 lands `LICENSE`, `NOTICE`, and the DCO note in `CONTRIBUTING.md`. The full dependency-license sweep is part of the survey feeding USOSS-18; anything non-permissive gets flagged before publication rather than after.
>
> ### 3. c1 dependency posture — **c1 optional, AWS-native path first-class**
>
> * c1 is the **flagship** credential-vending backend and the reason the project exists in this shape.
> * AWS-native STS/IAM vending (`credentials/claude.go` and friends) remains a **fully supported, CI-tested provider** — not a reference example.
> * **An outside adopter can run apphub without a c1 account.** This is a hard requirement, not an aspiration: CI must prove it by exercising the AWS-native path with no c1 credentials present.
>
> Consequences now locked in:
>
> * **USOSS-9 is first-class scope**, not optional. Its providers ship tested.
> * **USOSS-20's README** answers "what do I need to run this?" with: a cloud account (AWS today), and *optionally* c1 for c1-backed vending.
> * CI runs the provider conformance suite (USOSS-16) against **both** credential paths.
> * No import cycle or build-time dependency on c1 may exist in any package outside the c1 provider itself. Reviewers enforce this.
>
> ### Acceptance criteria
>
> * [x] Repo name, org, full Go module path written down
> * [x] License chosen; `LICENSE` content decided (Apache-2.0 + NOTICE + DCO)
> * [x] Written statement of what is required to run this — c1 optional, replaceable
> * [x] AWS-native credential vending confirmed as a supported provider

### How this is enforced here

"Reviewers enforce this" is the part that decays. The c1 rule is therefore also
a build failure: [`internal/boundary`](../internal/boundary) rejects a
dependency on ConductorOne — the SDKs, or AppHub's own `credentials/c1` — from
any package outside `credentials/c1` itself. `make boundary` runs it, and CI
runs `make boundary`. Relaxing the rule means widening the allowlist in
`internal/boundary/boundary.go`, which is a diff a reviewer sees.

**What the check proves, exactly.** It builds one *union import graph*: every
import declared by every Go file in every reachable package, with build
constraints ignored entirely, plus test imports for first-party packages. Since
any build configuration can only *select* edges from that union, every concrete
build graph is a subgraph of it — so a union with no forbidden path proves that
no supported or unsupported configuration has one. That is the property this
repository claims, and the reasoning behind it is recorded below under USOSS-28,
including the four rounds of review that showed why the earlier design could not
claim it.

The **concrete build targets are still run** — Linux, macOS, and Windows on amd64
and arm64 — but as **compatibility checks, not the proof**: they catch code that
does not compile on a supported platform, invalid `//go:build` combinations, and
any disagreement between the union parser and the real toolchain. Along the same
lines, a build constraint no configured target selects is still rejected, because
such a file is one no *compatibility* pass compiles. The union graph reads it
regardless, so that rule is hygiene rather than fence.
