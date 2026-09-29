## USOSS-28 — the boundary proof is a union import graph, not a list of builds

The c1-optional rule and the DynamoDB fence are universal claims:

> No supported build configuration may give a disallowed first-party package a
> dependency path to a denied package.

Until this ticket, the checker tried to establish that by running `go list` over
a matrix of concrete configurations. `go list` answers an existentially narrower
question — *what did this one configuration select?* — and no finite enumeration
proves a universal property. GOOS and GOARCH are two dimensions; custom tags,
cgo, compiler and release tags, experiment and architecture feature tags,
mutually exclusive expressions, and constraints inside replaced or vendored
dependencies keep the space open.

Review defeated the enumeration four times, and the pattern is the point:

1. a transitive import through a third-party wrapper;
2. a `*_windows.go` blank import, invisible to the Linux graph;
3. an `arm64`-only import — an accepted selector no executed pass covered;
4. coverage blessing a success line from evidence for a subset of targets.

Each fix was correct about its instance. Each time the property reappeared one
level up, because the primitive could not express the claim being made.

### The construction

Let `G(c)` be the import graph any supported configuration `c` selects, and `U`
the graph of every syntactically declared production import edge from every Go
file in every reachable package, **build constraints ignored entirely**, plus
test imports for first-party packages because the rule covers tests.

```
for every supported configuration c:   G(c) ⊆ U
therefore: if U contains no forbidden path, no G(c) contains one.
```

Adding a platform, a custom tag, a nested negation, a release tag, or a whole new
supported target **cannot open a hole**: those things only select edges, and every
edge they could select is already in `U`, where it has already been judged. The
checker stops needing to know which configurations exist.

### What is now proven, and what is not

**Proven** — for the committed Go source in this repository, with the module
versions in `go.mod`: no package outside `credentials/c1` has a declared import
path, direct or transitive, to ConductorOne, and none outside `store/` has one to
a DynamoDB client — *under every build configuration, supported or not*, and in
tests as well as production code. The proof does not depend on the target matrix,
so widening the matrix cannot weaken it.

**Not proven**, and deliberately out of scope, because these are different
policies rather than gaps in this one:

- **native linker flags** and anything else outside the Go import graph;
- **runtime plugin loading** (`plugin.Open`) and other dynamic loading;
- **reflection- or configuration-driven network calls** to a ConductorOne
  endpoint from a package that imports nothing of the kind;
- **source generated after the check runs.** Generated Go that ships must be
  committed, and is then scanned like any other file; if CI ever generates
  source, generation has to precede the scan and the scan has to reject an
  unexpected output state. A `//go:generate` directive is not an import edge;
- **dependency behaviour**: that a permitted dependency does not itself reach
  ConductorOne at runtime by some means other than an import.

**Over-approximation is intended.** `U` can flag an import that no supported
configuration selects. For an architectural fence that is the right trade: code
behind an unsupported selector is exactly the code that becomes reachable later
without anyone revisiting the boundary. The fix for such a finding is to delete
the import or move it behind the allowed provider package — not to teach a
security gate a configuration exception. SAT over constraint-labelled edges would
reduce over-approximation and is explicitly **not** built: it is a far larger
correctness surface, and it is warranted only by *observed* false positives.

### Fail closed, everywhere

An unresolvable import, an unparseable Go file, a malformed build constraint, a
tracked `vendor/` tree, a Go workspace in effect, a main-module directory that
cannot be resolved, a `-module` that is not the tree's own main module, a build
configuration that will not load, a dependency graph loaded from some other
directory, a judgement of some other tree, a rule set other than the one being
reported, or a first-party package that went unjudged — each one fails the run. A graph with a hole in it has not been
checked, and a gate that says otherwise is worse than no gate.

The concrete targets stay, demoted to compatibility checks, and earn their keep
through a **differential invariant**: every edge a real build graph reports must
already exist in `U`. If one does not, the union resolver missed a toolchain
behaviour, the proof does not hold for the tree in front of it, and the gate
fails rather than trusting the union's silence.

### The evidence types, and the seam this closed

The fifth round of review recorded honestly that `Coverage` could not tell a real
completion from a fabricated one: `Complete` took a target and a package count as
*arguments*, so a caller could record a configuration that was never loaded. The
ordering in the command was the only thing keeping that straight, and an ordering
is not a type.

That seam is now closed by construction rather than by validation:

- `LoadGraph` returns a sealed `*Graph`; `Coverage.Complete` takes the graph and
  reads the target and the package count off it, so there is no number to supply.
  It also runs the differential itself instead of accepting a caller's word.
- `Union` is produced only by `LoadUnion`, which reads real directories, and has
  no exported way to add a node or an edge.
- `Findings` is produced only by `Union.Judge` and validates on exact first-party
  root accounting: every package that existed must have been judged.

### Round six: provenance

Sealing the graph proved that *a* graph had been loaded. It did not prove it had
been loaded **from here**. Review built a temporary module that **declared the
same module path** as this repository, containing one empty package, loaded a
real graph from it, and offered that to a `Coverage` for the real checkout —
which accepted it, and validated. Success over a tree the checker had never
looked at. The foreign graph's node carried a matching import path and an empty
edge set, so even the differential found nothing missing.

That is the same shape a sixth time, and it was closed the same way — by removing
the input rather than adding a check:

- A dependency graph is now loaded by `Union.LoadGraph`, a **method**. There is no
  exported way to load a graph for a directory of the caller's choosing, so a
  foreign graph cannot be obtained without first loading a whole union of that
  other tree — whose coverage then judges that tree, consistently.
- Every graph is stamped with the **canonical resolved directory** it came from —
  absolute, symlinks expanded — and `Coverage.Complete` and `Union.Differential`
  refuse one that does not match the union's. Identity is the resolved path and
  never the declared module path, because the declared path is exactly what the
  attack made match.
- A `Coverage` is created by `Union.NewCoverage`, so it is bound to a union at
  construction and cannot be paired with another union's evidence.
- The success sentence is produced by one method, `Coverage.Endorse`, which
  requires both pieces of evidence to be real, to come from the **same** resolved
  directory, and to have been produced under **exactly the rules being reported** —
  closing the adjacent gap where a run could judge a permissive rule set and print
  a strict one. The command layer no longer combines anything.

So the general lesson from the fourth round now applies to itself — *prefer a type
that cannot express a violation over a check that notices one* — and the claim it
protects is the smaller, truer one.

### Which directories are packages: two wrongs, and a construction instead

This one predicate has now been wrong twice, in opposite directions, and both were
**full silent bypasses** — a first-party package with its import behind a
constraint no compatibility target selects, invisible to the union, to the file
scan, and to every concrete build at once:

- **Round one** excluded `node_modules`, which the go command has no rule for.
  `go build ./...` compiles `apphub/node_modules/foo` like any other package.
- **Round two** excluded every directory *named* `vendor`, when the go command
  excludes only what is **beneath** a vendor element — `cmd/vendor` is an ordinary
  package, as `go help packages` says outright.

Two wrongs in opposite directions is a statement about the *shape* of the answer,
not about two names. Both came from the same root cause: a hand-written
restatement of the toolchain's behaviour, with any divergence silent.

**Deriving the set from the toolchain was tried first and is unsound.** Two
measurements, now asserted by tests rather than remembered:

1. `go list -e -json ./...` does **not** report a directory whose files are all
   excluded by build constraints. That is not a corner case here — it is the
   central case, the reason the union graph exists — so deriving the package set
   from a concrete `go list` would reintroduce exactly the configuration
   dependence this ticket removes, in the silent direction.
2. The toolchain's package set is **pattern-root dependent**: `go list ./...` from
   the module root omits `cmd/vendor/sub`, while `go list ./cmd/vendor/...`
   reports it. There is no single set to copy; asking replaces a restatement with
   a choice of which question to ask, and the narrower answer is a hole.

So the rule is restated exactly once, in `PackageDirs`, and deliberately
**maximal**: skip a subtree only for `testdata`, a name beginning with `.` or `_`,
or a nested `go.mod`; enumerate everything else, including `vendor`, everything
beneath it, and `node_modules`. Under-approximating has cost two bypasses;
over-approximating costs a possible false positive. Both walkers call it, so there
are not two lists to drift apart.

And the restatement is **checked against the thing it restates, on every run**. A
generative test builds a module containing every combination of directory-name
shape up to depth three, with plain unconstrained files so file selection cannot be
a factor, asks the real `go list` from the module root *and* from each first-level
directory, and requires every package it reports to be enumerated. **Containment,
not equality** — the toolchain gaining a package can never open a hole, and the
walker losing one fails CI. Both historical mistakes were verified to fail it.

Note what none of this affects: import resolution. A package inside an excluded
directory that something actually imports is still resolved, parsed, and judged.
The rule decides what is enumerated as a first-party *root*, not what is reachable.

The general lesson, which is the same one this file has been recording all along:
*prefer a construction that cannot diverge over a rule that must be kept in sync* —
and where a rule is genuinely unavoidable, make its divergence a red build rather
than a review round.

### A workspace is refused, for the vendor-tree reason

A go.work file redirects module resolution wholesale, so the dependency directories
a build would compile are not the ones `go.mod` selects. Both loaders here set
`GOWORK=off`, which means they agree with each other and would silently disagree
with the developer's build — the differential cannot see this, because it is on
the wrong side of it. So the checker asks the toolchain whether a workspace is in
effect and refuses to run inside one. go.work is gitignored, so this cannot fire
in CI.

Every attack listed above is committed as a fixture under
`internal/boundary/testdata/union`, together with a mutation test that pins the
finding as **identical behind nine different build expressions**. If that test
ever starts caring which expression was used, the checker has gone back to
enumerating configurations.
