## USOSS-34 — the c1-optional rule proves an import, and behavioural coupling is not an import

USOSS-28 turned the c1-optional rule into a proof. The argument is in
`docs/decisions/usoss-28-the-boundary-proof-is-a-union-import-graph-not-a-list-of-builds.md`
and it is sound: every concrete build graph is a subgraph of the union graph, so
a union with no forbidden path proves that no supported configuration has one.

A proof is exactly as wide as its subject, and the subject there is imports.
`internal/boundary/boundary.go:195-235` states the c1-optional rule as two denied
import prefixes — `github.com/conductorone` and
`github.com/conductorone/apphub/credentials/c1` — and one allowed composition root.
Nothing in that construction can see a package that behaves differently for
ConductorOne without importing anything.

### The gap was measured, not argued

The USOSS-11 worker was told in a brief that the boundary checker would reject a
c1-specific port, and tested it instead. A faithful stand-in for the source
system's `EnsureC1DatasourceRole` — an IAM role trusting a named vendor's tenant
accounts, keyed by external IDs that vendor issues — was placed in `compute/aws`,
and `make boundary` **passed**. It takes strings and an IAM client, so it imports
nothing c1-related. That is recorded in
`docs/decisions/usoss-11-ensurec1datasourcerole-is-not-ported-and-the-import-graph-does-not-enforce-that.md`,
which ends by observing that nothing enforces this boundary by construction and a
decision record is the only thing holding it.

The measurement was repeated on this ticket's branch before anything was written,
against the post-USOSS-28 checker, on the tree at `5504b18`. A 38-line file in
`compute/aws` building a ConductorOne cross-account trust policy — no import
under `github.com/conductorone`, none under `credentials/c1` — produced:

```
boundarycheck: the dynamodb-idiom-fenced rule held over 373 Go file(s)
boundarycheck: 6 rule(s) (c1-optional, …) held over the union import graph …
```

Exit 0, with the c1-optional rule reporting that it held. The union graph is not
weak here; it is looking at the wrong thing. Strengthening the import half — more
targets, more constraint handling, SAT over constraint-labelled edges — could not
close this at any price, because there is no edge.

### The mechanism: a second idiom rule, not a longer denylist

This repository already had the answer to this shape of problem, one fence over.
`internal/boundary/idiom.go` exists because the DynamoDB fence has the same two
halves: an import is a dependency, an idiom is a shape, and the first does not
imply the second. A `dynamodbav` tag needs no SDK import and is still DynamoDB
leaking into business logic.

So USOSS-34 adds `DefaultC1IdiomRule` beside `DefaultDynamoDBIdiomRule`, running
over the same AST scan, with the same constant folding, escape resolution and
comment exclusion the DynamoDB rule already had. Three needles, each answering a
spelling of the coupling seen in real code:

| needle | match | what it catches |
| --- | --- | --- |
| `conductorone` | substring, case-folded | the vendor's name in an identifier or a string — the `EnsureC1DatasourceRole` stand-in, a resource tag, an error message, an API path |
| `APPHUB_C1_` | substring, case-folded | `os.Getenv` of the provider's own configuration namespace |
| `c1` | delimited token, string values only | the provider's registry id — `if providerID == "c1"`, `id=c1` — and a host label, which is delimited by dots and slashes like anything else |

There were four, and the fourth was wrong. It was a needle for the vendor's
public domain, invented rather than looked up, and `.gitleaks.toml` settled it:
the two apexes this repository may name are recorded in that file's hostname
allowlist, and neither is the one that was guessed. The `conductorone` needle
already matches one of them and the `c1` needle matches the other in any URL, so
the entry had no coverage of its own. It also could not have been written down —
the disclosure gate forbids spelling a vendor hostname anywhere here, which is
what it is for, so the needle literal would itself have been a finding. The same
constraint is why the endpoint fixture in `c1idiom_test.go` names the vendor
through the path rather than the host.

The third needle is two characters, and the two restrictions on it are what make
it a check rather than a random number generator:

- **Delimited, not camel-case.** A camel-case boundary would make
  `OpC1FetchToken` a finding, and also `doc1`, `svc1` and `rec1`. A gate that
  fires on ordinary Go is a gate somebody deletes.
- **String values, not identifiers.** `c1, c2 := clientA, clientB` is an
  abbreviation, not a coupling, and it is everywhere in test code. As a string,
  `"c1"` is the provider's registry id and means exactly that.

Both bounds are stated on `MatchToken` and `Needle.StringsOnly` and pinned by
`TestTokenNeedleIsDelimitedNotCamelCase` and `TestC1IdiomRuleCleanFilesAreClean`.
What they give up is named rather than implied: `internal/credhttp`'s
`OpC1FetchToken` is not matched. Its label string `"c1: fetch access token"` is,
which is how that package was found.

### What this is, and what it is emphatically not

It is a lexical net over what the compiler computes. It inherits every bound
already stated at the top of `idiom.go`: a value built from runtime input,
assembled a rune at a time, or read from a file is invisible to it, and no
lexical rule can see one. It is **not** a second proof beside USOSS-28's. The
import half proves a universal property over every build configuration; this half
stops a fence eroding by ordinary convenience — which is how it actually erodes,
and how the source system reached 1,456 `dynamodbav` tags.

USOSS-28 lists reflection- and configuration-driven calls to a ConductorOne
endpoint as deliberately out of scope for the import proof. They are in scope
here whenever they are spelled in the source, which is the common case and the
only one a checker gets to have an opinion about.

Import declarations are the one place these rules deliberately do not look
(`*ast.ImportSpec` returns `false` from the walk). An import path is the import
rules' subject; reporting it here as well would describe one coupling twice and
misname the second report, and "idiom leak" is a lie about an import. It closes
nothing — a blank import of `credentials/c1` is still a c1-optional violation over
the union graph, and the same path written as a string anywhere other than an
import declaration is still matched here.
`TestImportPathsAreNotIdiomLeaks` pins both halves.

### What the rule found on the first run, and what was done about each

Three things, and the disposition of each is the interesting part.

**Nine sample provider ids in tests of provider-agnostic machinery.**
`credentials/capabilities_test.go` and `credentials/lifecycle/policy_test.go`
used `"c1"` as the sample id when testing `CapabilitiesOf` and `CheckScope` —
functions that have no idea which providers exist. **Fixed, not exempted.** Using
a real provider's registry id in a test of generic machinery is exactly the
ambiguity this rule exists to remove: a reader cannot tell from the fixture
whether the machinery special-cases c1. They now use `"example"`, and the
assertions never depended on the value.

**Rule names and credential variable names in the gates.** `internal/astaudit`
derives its evidence table from the target repository's boundary `Rules` literal
and checks the rule set by name, of which `c1-optional` is one
(`internal/astaudit/evidence.go:202`). `internal/hermetic` asserts that CI carries
no vendor credentials and names ConductorOne's environment variables alongside
AWS's, GitHub's and Anthropic's (`internal/hermetic/hermetic.go:94-96`).
**Allowlisted, as one category**: a checker that may not name the thing it checks
cannot be written, which is why `internal/boundary` and `hack/boundarycheck` were
already exempt from the DynamoDB rule for the same reason. It is not a loophole —
every one of them is still bound by the import half, so none may reach
ConductorOne; what they are permitted is to hold its name as data.

**Four operation labels in `internal/credhttp`.** `OpC1FetchToken`,
`OpC1MintCredential`, `OpC1RevokeCredential` and `OpC1GetCredential`
(`internal/credhttp/credhttp.go:139-148`) name ConductorOne in a package every
credential provider shares. **Allowlisted, one file, with the reason attached.**
That package's whole construction is a closed `Op` set — `Op` cannot be built from
outside the package, which is what stops response-controlled text reaching a log
line or an error, and the package comment argues that closure at length. So this
is a *decided* coupling rather than drift, and the fix for a decided coupling is
an allowlist entry a reviewer sees, not a redesign of the construction that
decided it: opening the `Op` set to satisfy a lint would sell back the exact
property `credhttp` exists to buy. The entry is the file and not the package, so
`credhttp_test.go` and `opset_test.go` are still checked —
`TestTheC1IdiomExemptionIsOneCredhttpFileNotThePackage` keeps it that way.

After those three, the rule holds over all 373 Go files in the tree with no
suppressions and no false positives.

### The allowlist has exactly two kinds of entry

Worth stating, because a list of five paths read as five ad-hoc holes is a list
nobody reviews:

1. **Packages allowed to be, or to compose, the ConductorOne integration** —
   `credentials/c1` and `cmd/apphub`. The second is the same single entry the
   import half already carries, for the same reason (USOSS-8): a composition root
   that registers the provider has to be able to name it. The two halves share one
   exception rather than growing two differently-shaped ones, and a second entry
   in either half requires supervisor approval.
2. **Gates and shared plumbing whose subject is the boundary itself** —
   `internal/boundary`, `hack/boundarycheck`, `internal/astaudit`,
   `internal/hermetic`, and the one `credhttp` file.

Nothing else. The property an adopter with no ConductorOne account actually
relies on survives intact: no library package depends on ConductorOne, and now
none of them recognises one either.
