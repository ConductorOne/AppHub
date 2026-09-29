## USOSS-6 — what "ported near-verbatim" is allowed to claim

A general lesson, recorded because it has now cost this pull request four rounds
of review, and because the rule it produced had to be rewritten once when the
version below turned out not to prevent the thing it was written for.

Review of the module framework found a contributor-facing comment asserting a
convention the source does not follow. Re-reading the *rest* of that
documentation against the source — prompted by the finding rather than by any
failing test — turned up four more claims of the same kind, none of them visible
to CI:

- Rule 1 of the dependency convention said a module "never imports its
  supplier", generalising from the source keeping its **service layer** out.
  Out of the 28 production files in its module tree and the 87 in its service
  layer: **0 of 28** module files import the service layer, and the dependency
  runs the other way — **7 of 87** service-layer files import the framework
  package and **25 of 87** import somewhere under the module tree — so the
  reverse would be a cycle. It does not hold one layer down: **16 of 28** module
  files import the persistence package directly (**6 of the 8** packages under the
  tree; the exceptions are `types` and `vendor`) and **10 of 28** import a cloud
  SDK directly, 8 in `deploy` and 2 in `paved`. The wide rule is this repository's; only the
  service-layer half was inherited.

  The 7-and-25 figures are a round-3 correction. This bullet previously said
  three, which was three real citations mistaken for the population — the same
  defect the bullet is describing, committed inside the description of it.
- `Validate` was documented as beginning with the declared-parameter check in
  every implementation. In the source **2 of 9** call it
  (`deploy/lambda.go:795`, `deploy/container.go:1060`).
- `userID` was documented as available for authorisation decisions a module
  makes itself. **0 of 9** do.
- `ProgressFunc` was documented as requiring concurrency safety. Reasonable, and
  now stated as a requirement added here — but there is **no `go` statement
  anywhere** under the source module tree, so nothing there established it.

A first draft of the *fix* then claimed `internal/boundary` enforces that cloud
calls go through a compute provider. It does not. That one was caught before it
was committed, which is the only reason it is a footnote rather than a fifth
item — but the number it was corrected to went stale within two rounds, which is
its own lesson. It had two rules then; rebasing onto a `main` that had taken
USOSS-2 and USOSS-3 gave it three (`c1-optional`, `ext-is-optional`,
`dynamodb-fenced`). **A count against a moving base has to be re-derived at the
rebase, not carried across it** — the rebase is a change to the population.

And then the *mechanism* moved too, not just the count. The corrected sentence
said the rules are enforced "over the build configurations it enumerates, which
is a guard rather than a proof" — accurate when written, and made wrong by the
rebase that took USOSS-28, which replaced the enumeration with a union import
graph that does carry the universal claim. Twice stale, on the same borrowed
sentence. The lesson is narrower than the one above and worth stating on its own:
**describing a neighbouring subsystem's internals in this tree's documentation
buys a maintenance obligation nobody is watching.** The reference now says what
it needs for this tree and defers to that package's own comment for how it works,
which is the only version that cannot go stale under someone else's merge.

### Then it happened again, inside the fix

The next round found the *corrected* `userID` sentence doing the same thing in
the other direction. Having removed the false authorisation claim, it asserted
that a module "records it on whatever it writes" — attribution, universally.
Two of nine do. The authorisation half was now right and the attribution half
was the original defect in a new coat, written while fixing the original defect,
in the same sentence.

That is the fact worth recording, because it is not the same as the four above.
Those were claims written without counting. This one was written *by someone who
had just been told to count*, and it still generalised — because the correction
was aimed at the wrong thing. The instinct being corrected was "do not say
something false about the source". The instinct that actually needs correcting is
**"do not write the general form before you have the number"**. Removing a false
universal and replacing it with a true-sounding universal satisfies the first and
violates the second, which is exactly what happened.

So the rule below is not "be accurate". It is procedural, and the order matters:
**enumerate, then write.** If the number is not in front of you, the sentence is
not ready, however plausible it sounds.

The pattern is consistent, and it is not carelessness about the code — the code
was faithful in every one of these cases. It is that prose generalises for free.
A comment saying "every module does X" costs nothing to write and is not checked
by anything, so it drifts toward the tidiest version of the truth. In a port
whose entire value is faithfulness, and a repository going public where an
outside contributor will read these comments as the specification, that drift is
a defect of the same kind as a wrong line of code.

So, for anything written here about the code this was ported from:

- **Any population claim needs the denominator, not just the numerator.** A
  claim shaped `all`, `none`, `only`, `most`, a fraction, a total, or "the
  convention is X" is a claim about a whole population, and it is not made by
  citing members of it. State the population, state the search that defines it,
  then give `count / denominator`. "Three files import X" is not a claim about
  anything; "three of eighty-seven files import X" is. A citation is
  **supplementary** — it shows one instance exists, which settles an existential
  claim and settles nothing else.
- **Derive the sentence from the enumeration, in that order.** Not the reverse,
  and not in parallel. If the denominator is not in front of you, the sentence is
  not ready, however plausible it sounds.
- **The search must be shown to define the population it claims to count.** A
  count is only as good as the boundary of its search, and a text search almost
  never has the boundary of a semantic category. Where a regex stands in for one,
  either *demonstrate* the boundary — run the candidate forms and show the delta,
  which is how "0 of 64 literal arguments" was caught being 62 int literals, 2
  expressions and 5 identifiers out of 69 — or **count semantically instead.**
  For Go that means `go/ast`: it can tell an integer literal from an expression
  that merely begins with digits, an import from a commented-out one, a
  discarded call result from a checked one, and a `go` statement from the word
  "go" in a string. A regex can tell none of those.
- **Say which side of the port a rule is on.** "Ported" and "adopted here" are
  different statements, and a reader deciding whether they may deviate needs to
  know which one they are reading.
- **Never document a convention the implementations do not follow** — including
  one the source itself documents. If the convention is worth having, change the
  implementations and record the decision. A comment is not a migration, and
  somebody else's comment is not evidence about their implementations.

### Why the earlier version of this rule did not work

It said: quantify it **or** cite it. That `or` was the hole, and all three rounds
walked through it:

| Round | The claim | Why a citation let it pass |
| --- | --- | --- |
| 1 | `Execute` pairs a non-nil error with a nil `Result` | `cmd/job-runner/main.go:568-575` is a real, exact citation for it. It is one entrypoint's comment, and it says in the next clause that nothing enforces it. |
| 2 | Every module records `userID` for attribution | Two modules really do. Citing either is honest and proves nothing about the other seven. |
| 3 | Three service-layer files import the modules | All three cited files really do import them. The population is 7 by one definition and 25 by another, out of 87. |
| 4 | 0 of 64 `ReportProgress` literal arguments are outside 0–100 | Nothing was cited and nothing was truncated: the count was complete for the set the *regex* defined, which was not the set the *sentence* named. 62 of 69 arguments are integer literals. |

Rounds 1 to 3 were each a true citation supporting a false population claim, so
a rule satisfied by citation could not catch any of them. Requiring the
denominator catches all three, because in each case producing the denominator is
the step that exposes the error: counting the 87 finds the other four importers,
counting the nine finds the six non-users, and counting the implementations finds
the one that breaks the convention.

Round 4 is a different failure and is the reason for the third bullet. It had a
population, a search, a count and a denominator — everything the amended rule
asked for — and was still wrong, because the rule never required the *search* and
the *population* to be checked against each other. The sentence said "literal int
arguments" and the search matched "argument beginning with a digit". Both halves
were stated; nothing compared them.

Two of the failures were mechanical rather than conceptual, and both are worth
naming because both fixes are mechanical too.

The round-3 count ended in `head -3`: a truncated output read as a complete one.
**A population count may not come from a command that can truncate** — no
`head`, no `-m`, no first-page-of-output — and the count and the denominator must
come from the same search.

The round-4 sweep found one more of the same kind that nobody flagged, and it is
worth recording because the search was not even a regex — it was a hand-drawn
population. "Five of the six module packages import the persistence package"
silently excluded two of the eight packages under the tree: the root package,
whose one such import is in the registration helper this port leaves out, and
`types`, the framework itself. Counted properly it is **6 of 8**, exceptions
`types` and `vendor`. An implicit denominator is still a denominator, and it is
the easiest one to get wrong because it is never written down.

The round-4 count had no truncation and was still wrong, which is what produced
the clause above. `ReportProgress\([^,]+,\s*[0-9]+` returns 64 and
`ReportProgress\([^,]+,\s*[0-9]+\s*,` returns 62; the missing trailing comma is
the entire difference between *the argument is an integer literal* and *the
argument starts with digits*. The regex was reproducible, complete, and about the
wrong set — a failure the "no truncation" rule cannot see, because nothing was
truncated. That is why the fix is to count semantically rather than to write a
better regex: every row of the evidence table is now derived from `go/ast` by
`hack/astaudit`, and doing so also found a thirteenth dependency guard that a
`m.<field> == nil` search could not see because the field was read into a local
first.

The table has **thirty** rows, not the twenty-eight this entry claimed for four
revisions. Twenty-eight is the highest row *number* (E28); four rows are split
into an `a` and a `b` half and are two rows each. Nobody counted them — the
number was read off the last identifier. It is the same defect the entry above
it describes, committed inside the correction for it, which is why the row set is
now derived from the document rather than stated: see the entry below.
