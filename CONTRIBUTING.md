# Contributing to AppHub

AppHub is being extracted from a working internal codebase, one capability at
a time. That shapes what a good contribution looks like right now: the ports
have to land faithfully and the seams have to stay clean. Small, honest,
well-argued changes are far more useful than large ones.

## Before you start

The repository is **pre-alpha**. Interfaces are still being designed, and a
change that depends on an interface that has not landed yet will need to wait.
If you are planning anything larger than a fix, open an issue first so we can
tell you whether it collides with work already in flight.

Read [`docs/decisions/`](docs/decisions/). It records the decisions that are
already settled — the module path, the licence, and in particular the rule that
ConductorOne is optional. Those are not open for relitigation in a pull request;
if you think one is wrong, open an issue and argue it there.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/),
**not** a CLA. You keep the copyright in your contribution; you are certifying
that you have the right to submit it under Apache-2.0.

Sign off every commit:

```sh
git commit -s -m "your message"
```

That appends a trailer:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and an address you read. If you forget on the last commit,
`git commit --amend -s` fixes it; for a branch, `git rebase --signoff main`.

CI checks this on every commit in a pull request, and the sign-off has to match
the commit's author — that is the point of the DCO. Run `make dco` to check
before you push.

## The development loop

```sh
make tools     # install pinned linters and scanners into .tools/ (once)
make check     # build, vet, lint, headers, boundary, hermetic, decisions, citations, test
make check-all # the above plus gitleaks, govulncheck, and the licence check
```

**CI runs exactly these targets.** If `make check` is green locally and CI is
red, that is a bug in the Makefile or the workflow, not something to work
around — please report it.

Useful individually:

| Command          | What it does                                                 |
| ---------------- | ------------------------------------------------------------ |
| `make test`      | `go test -race -cover ./...`                                   |
| `make lint`      | golangci-lint at the pinned version                            |
| `make boundary`  | the import-boundary rules (see below)                          |
| `make headers`   | every `.go` file carries the SPDX header                       |
| `make secrets`   | gitleaks over the working tree **and full git history**        |
| `make hermetic`  | parses every workflow; fails if CI could obtain a credential   |
| `make decisions` | asserts the decision record's structure (see below)            |
| `make citations` | file:line citations in comments/docs resolve (see below)       |
| `make dco`       | every commit on your branch is signed off by its author         |
| `make cover`     | writes `coverage.html`                                         |

## What every change has to satisfy

**Tests are hermetic.** No test may require network access, real cloud
credentials, a real ConductorOne account, or a fixed TCP port. A test that only
passes with live credentials is a test we cannot ship, and CI has no
credentials to give it. Use the fake compute provider (`compute/fake`) or an
interface stub.

**ConductorOne stays optional.** No package may *depend* on ConductorOne except
`credentials/c1` — not directly, not through a wrapper, and not from a file
behind a build tag. `make boundary` proves that over a **union import graph**:
every import declared by every Go file in every reachable package, build
constraints ignored entirely, plus test imports for first-party packages. Any
build configuration can only select edges from that union, so it does not matter
which platform, tag, or architecture the import is hidden behind — the union
contains it either way. The only way to relax the rule is to widen an allowlist in
[`internal/boundary/boundary.go`](internal/boundary/boundary.go) — which is a
diff, on purpose, so it gets discussed.

**So a build constraint will not hide an import.** If `make boundary` reports an
import that "is not even compiled on our platforms", that is the check working as
designed: it judges every declared import, because code behind an unused selector
is exactly the code that becomes reachable later without anyone revisiting the
boundary. Delete the import, or move it behind the allowed package. There is no
constraint that exempts it.

**A build constraint must still name a configuration the compatibility builds
run.** Those are Linux, macOS, and Windows on amd64 and arm64, so `//go:build
linux`, `arm64`, `unix`, `gc`, and `go1.N` up to the toolchain's release tags are
all fine. Anything else fails — including real-but-uncovered selectors like
`freebsd`, `riscv64`, `race`, and `cgo`, and future ones like `go1.99`. This one
is hygiene rather than fence: a file no configured build compiles is a file the
*compatibility* checks never type-check, though the union graph read it all the
same. Widen the matrix in `internal/boundary` (`Config.GOOS`, `Config.GOARCH`,
`Config.CgoEnabled`, or `Config.AllowedBuildTags`) to use one; acceptance is
derived from the matrix, so widening what is allowed also adds the build that
checks it.

**It refuses to run inside a Go workspace.** A go.work file redirects module
resolution, so what a build compiles is no longer what `go.mod` selects and the
check would be describing a tree nobody builds. Run it outside the workspace.
Same reasoning as the tracked-`vendor/` refusal, and go.work is gitignored, so
this only ever fires locally.

**A directory named `vendor` or `node_modules` is not a hiding place.** Which
directories count as packages is answered in one place
([`PackageDirs`](internal/boundary/packages.go)), deliberately over-inclusive, and
checked against the real `go list` by a generative test. If you need that question
answered anywhere else, import it rather than restating it — the restatement has
been wrong twice.

**What the check will not tell you.** It covers committed Go import
declarations. Native linker flags, runtime plugin loading, reflection-driven
network calls, and source generated after the check are different policies —
[`docs/decisions/`](docs/decisions/) records them as out of scope rather than
leaving them implied. If you are about to write one of those, say so in the pull
request.

**DynamoDB stays fenced.** Same mechanism: only `store/` may import a DynamoDB
client. v1 is not cloud-agnostic about persistence and does not claim to be.

**One decision, one file, and `make decisions` checks it.**
[`docs/decisions/`](docs/decisions/) holds one file per decision. To record a
decision, add a file. Do not append to an existing entry, and do not add an
index: the directory listing is the index, and a committed index would be a file
every decision-adding pull request has to touch.

The file name is derived from the entry's own heading — lowercased, with every
run of characters outside `[a-z0-9]` folded to a single hyphen — so nobody
chooses it. `make decisions` recomputes it from the heading and compares. The
heading is a `##` on line 1; sub-headings are `###`.

That layout replaced a single append-only `docs/DECISIONS.md`, which relied on
the `merge=union` attribute to keep concurrent appends from conflicting. The
attribute works locally and GitHub does not honour it, so every open branch went
`CONFLICTING` whenever the record merged — and a `CONFLICTING` pull request gets
no CI at all while still displaying its last green tick. Separate files cannot
conflict either way. `.gitattributes` keeps the full reasoning.

What this does *not* remove: two pull requests that edit the *same* decision
still conflict, which is correct. Reversals are recorded as new entries rather
than edited in, so that should not arise.

**A `file:line` citation in a comment or a doc names a real file at a real
line, or it does not go in.** `make citations` (see
[`internal/citations`](internal/citations)) resolves every such citation it
recognises against the tree: a citation naming a file this repository does
not carry (most of them — this repository cites the source system it was ported from, by that system's own paths) is fine and is left
alone; a citation naming a file this repository *does* carry, at a line
range outside it, fails the build. It cannot tell you a citation lands on
real, in-range code that says something other than what the comment claims —
that comparison is a reading, not a lexical check — so it does not report
success over that class and neither should you read a green run as covering
it.

A bare file name with no directory (`database.go`, not
`compute/database.go`) is resolved against a same-named file in the citing
comment's own directory, because that is the reading that turns a source
system's file name into a silent wrong-file citation when this repository
happens to carry a file by the same name. When several citations share one
parenthetical or comma-joined list and one of them names a file absent from
this repository entirely, the whole list is treated as a reference to that
other system — one provably-external member is cheaper than reading the
sentence, and just as decisive. Prefer citing another tree by repository and
path (and the enclosing function, when you know it) over a line range
nothing here can check: `source system @
backend/internal/modules/deploy/build.go, func buildImage`, not
`build.go:100-200`.

**Nothing internal, ever.** No account ID, ARN containing an account ID, access
key, token, password, private key, internal hostname or domain, VPC, subnet, or
security-group ID. This repository is heading for public release and git
history does not forget. Anything that looks like site-specific configuration
becomes a configuration value with no default, or a clearly-marked placeholder.
`make secrets` is a backstop, not a substitute for reading your own diff — and
note what it looks for beyond ordinary secrets:

- **any standalone twelve-digit number**, which is the shape of an AWS account
  ID and has no entropy for a generic scanner to find;
- ARN account components, ECR registry hosts, and VPC/subnet/security-group
  identifiers;
- **any hostname not on the allowlist** in `.gitleaks.toml` — three-or-more
  labels anywhere, two labels in a URL or email address, and two labels
  assigned as a value (quoted, or after an `=` or `:`). AWS *service* endpoints
  are allowlisted; a deployment-specific one such as an RDS or ELB endpoint is
  not, because that is the disclosure. Source file names are shaped like
  two-label hostnames, so an extension exception keeps `boundary.go` out of it;
- the same patterns in **file names**, via `hack/check-paths.sh`, because
  gitleaks reads contents and a path is published just as surely.

If you add a legitimate new URL you will need to allowlist the host,
deliberately, in `.gitleaks.toml`. `make secrets-selftest` proves the rules
still fire and that legitimate AWS endpoints still pass.

The hostname rules are fail-closed, and that has a predictable cost: a quoted
dotted identifier — a metric name or a subtest name, say — looks exactly like a
two-label hostname and will be reported. Spelling cannot separate those, so the
answer is an **exact** allowlist entry for the specific string, not a broader
suffix pattern. It is a maintenance cost we chose over the alternative, which is
a rule that misses an internal hostname sitting in a config value.

(You will notice this file names no example of either. A literal one would be a
disclosure-shaped string in a public repository, and the rules would flag the
document explaining them — which they did, on the first draft.)

`.gitleaksignore` accepts a finding in *history* that cannot be edited away, by
fingerprint. It is not for the working tree: fix those, or allowlist the pattern
where the exception sits next to the rule it weakens.

**Every `.go` file starts with the licence header**, followed by a blank line so
it does not become the package doc comment:

```go
// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package thing
```

**Gates come with fixtures.** If you add or change a check, add an input that
fails before your change and passes after. A gate that has never been defeated
has an unknown detection rate; three of this repository's original gates
reported success on inputs they were supposed to reject, and fixtures are how
that stops being possible.

**No dead code.** Land it working or leave it out and say why.

**Match the surrounding idiom.** Much of this repository is a port. Where the
original design is right, keep it; a rewrite disguised as a port is very hard to
review.

## Testing against the compute interface

Nothing in the test suite talks to a cloud. Anything that needs compute
behaviour uses the in-memory provider in
[`compute/fake`](compute/fake), which is a working implementation of every port
— image build and registry, container service, scheduled job, function and
endpoint, object storage, relational, key-value, secret store — backed by state
in a `fake.Store`:

```go
store := fake.NewStore()
p := fake.New(store, fake.Config{})
```

`fake.Config` is where an operator's configuration would go for a real
provider: which placement names exist, which function runtimes are legal, which
certificates resolve, whether there is a platform ingress proxy, and which
capabilities the provider advertises. Configure a subset of
`fake.AllCapabilities()` when you want to exercise what happens on a substrate
that cannot do something — that path is usually the one with the bug in it.

`p.Harness()` exposes the substrate operations the interface deliberately does
not have: perform a read as a workload identity, attempt an anonymous read,
authenticate against a relational endpoint, dump what the provider rendered.
Use it to assert on behaviour rather than on which methods your code called.

`Harness.FailNext(op, kind, err)` queues a failure. Nothing across this
interface is transactional — a deploy that provisions a bucket, a database, and
a service can fail in the middle and leave two of the three — so use it to test
the partial-failure and retry paths rather than assuming they work.

### Making a new provider pass conformance

The contract is executable. [`compute/conformance`](compute/conformance) is a
shared suite that every provider runs against itself, so "implements
`compute.Provider`" — which is only a statement about method sets — becomes a
statement about behaviour:

```go
func TestConformance(t *testing.T) {
    store := fake.NewStore()
    conformance.Run(t, func(conformance.TB) compute.Provider {
        return fake.New(store, fake.Config{})
    }, conformance.Options{
        Placement:       "default",
        FunctionRuntime: "nodejs20.x",
        // ... plus the hooks below
    })
}
```

What a new provider has to supply:

1. **A factory.** It is called more than once and every call must return a
   provider addressing the *same* substrate: one invariant is that a second
   instance finds what the first one created, because teardown reconstructs a
   reference from a logical name that may never have been persisted.
2. **Substrate facts the suite cannot invent** — a placement name the provider
   was configured with, a legal function runtime, a resolvable certificate
   reference, an engine version on offer. If the provider advertises a
   capability and the matching option is missing, the run fails immediately
   rather than skipping: a suite that quietly tested less than it claimed would
   be worse than one that tested nothing.
3. **Hooks for the invariants the interface cannot express** — perform a read or
   a write as a workload identity, attempt an anonymous read, authenticate with
   the original admin password, make a resource stop converging, create a
   resource without the ownership marker, dump rendered artefacts. A nil hook
   skips its checks *loudly*, naming the invariant that went unverified.

Scope is **per port class**, and this is the part to understand before writing
an implementation. Asynchronous ports — container services, scheduled jobs,
functions, endpoints, relational endpoints, key-value tables — return a
`compute.Status` promptly, report `PhaseGone` after a delete, and have a `Wait`
with a caller-chosen deadline. Synchronous ports — image repositories, buckets,
secrets, workload identities — have no phase and no `Wait`: their `Ensure`
returns a usable resource or an error, and a read-back after a delete is
`ErrNotFound`. Grant invariants run only against the ports that implement
`compute.Granter`. Applying the phase rules to every port would assert a phase
on types that have none, so the classification lives in one table in
`compute/conformance/ports.go` and is pinned by a test.

Read
[`docs/design/compute-provider.md`](docs/design/compute-provider.md) §5 —
"What this abstraction does not make portable" — before you start. Where the
interface deliberately says nothing (permission granularity, key-value
consistency semantics, capacity equivalence, egress, log delivery), the suite
says nothing either, and inventing a semantic there is worse than the gap.

If you cannot make an invariant pass because your substrate genuinely cannot do
the thing, the answer is usually to *not advertise the capability* and let the
refusal be explicit. `compute.ErrUnsupported` at deploy time is a better outcome
than a resource that silently does not work.

## Commit and pull request style

- Branch from `main`.
- Conventional-ish subject lines (`feat:`, `fix:`, `docs:`, `chore:`) — a short
  imperative summary, then a body explaining *why*.
- Sign off every commit (`git commit -s`).
- Fill in the pull request template. The section that matters most is **what you
  deliberately did not do, and why**; a reviewer can check code, but only you
  know what you decided to leave out.
- Do not merge your own pull request.

## How a pull request lands

AppHub is developed in a private repository and published here. Each publish
is one commit whose tree is exactly the private `main`, so this repository's
`main` only ever moves by those commits, and a pull request is never merged
here directly.

A maintainer applies an accepted pull request to the private repository with
you as the commit author and your sign-off kept, and closes the pull request
here with a note. Your change then appears in the next publish.

For maintainers:

```sh
git fetch git@github.com:ConductorOne/AppHub.git pull/<N>/head:oss-pr-<N> main:oss-main
git switch -c oss-pr-<N> origin/main
git diff oss-main oss-pr-<N> | git apply -3
git commit -s --author="<contributor name> <email>"  # keep their Signed-off-by
```

To publish, run `make oss-sync` from an up-to-date checkout of the private
repository. It builds the snapshot commit, runs the disclosure and secret scans
against exactly that tree, and prints the file list and commit message; nothing
is pushed. Review both, since every line becomes public, then run
`make oss-sync PUSH=1`. Only admins of the public repository can update its
`main`.

## Reporting security problems

Not through an issue or a pull request. See [`SECURITY.md`](SECURITY.md).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Contributions are licensed under Apache-2.0 (see [`LICENSE`](LICENSE)). Your DCO
sign-off is your statement that you have the right to submit them under it.
