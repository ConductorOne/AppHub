## USOSS-6 — five bypasses in one parser, so the parser was deleted

Recorded because the count is the argument, and because the conclusion applies to
every gate here that reads a set out of a document a human also edits.

The audit's row set lived in a Markdown table that the tool read back, so the
document and the program could be checked against each other. Five rounds were
spent making that check cleverer. Each round a reader found another way for a row
to be **visible in the rendered document and invisible to the parser**:

| # | The bypass | Where the fix for it lived |
| --- | --- | --- |
| 1 | the row set was not pinned at all | — |
| 2 | `_E99_`: emphasis stripped by a known-decoration list; unrecognised cells skipped | the fix for 1 |
| 3 | backticks in the `Derived by` column | the fix for 2, ninety seconds later |
| 4 | a four-space-indented fence marker opens no fence in Markdown, but opened one in the scanner | the fix for 3 |
| 5 | an info string containing a backtick is not a valid fence opener; the scanner skipped the line rather than failing | the fix for 4, same change |

Four of the five were in the Markdown scanner. Two were inside the fix for the
previous one. The fifth was in a function written specifically to remove silent
third outcomes and was itself a silent third outcome.

**The answer was not a better scanner, and not a Markdown parser either.** A
parser is the same bet one level up: that someone else's CommonMark agrees with
the renderer a human is actually reading. So the table is now **generated** from
a declaration in the program, and nothing parses Markdown at all. There is one
artefact, so there is no drift to detect.

### The distinction that makes this legal under rule 7

Rule 7 says a hand-maintained restatement of a set drifts from the set, and the
row set is now a hand-written list in the program. That is not a violation, and
the difference is worth stating because "derive, never restate" read without it
would forbid the thing that saves this design:

> **Rule 7 is about two artefacts drifting apart. A list that nothing else
> restates cannot drift from anything — it is a definition, not a claim about
> another file.**

### And generating a document does not, by itself, preserve what checking it
### bought

This nearly went wrong. If the table is simply whatever the tool prints, then
"every row was derived" becomes vacuous and deleting an emit call quietly
produces a smaller table — the original blocker, returning through the front
door. Generation removes the drift; it does not remove the need for the
emissions to be held to a declaration. Both are required, and only together.

### What replaced five rounds of parsing

One byte comparison. `-check` regenerates the table and compares it to the
committed file exactly, which catches a stale artefact and cannot have the
failure above: there is nothing to parse, so there is no grammar to disagree with
a renderer about.

Two smaller things fell out of generating rather than transcribing:

* **Reported paths are relative to the repository root**, so the output is the
  same on any machine. Earlier artefacts had absolute paths edited out by hand
  before publication — a hand-maintained transformation of a tool's output, which
  is precisely the kind of step that goes wrong quietly.
* **The target repository's own revision is deliberately not recorded** in a
  document that lives in it. Committing the file changes the commit, so any value
  written down is always the previous one. The attribution that is always true --
  "this repository, at the commit containing this file" -- needs no maintenance.
  Its dirtiness *is* recorded, because not naming a commit must not mean
  concealing that there wasn't one.

### The measurement

Five self-found or reviewer-found defects of one class in one file, over five
rounds, two of them introduced by the fix for the previous one. Every fix was
correct about the instance it was aimed at, and the audit's figures never moved.
The lesson is not that the fixes were careless:

> **A fix for a class is itself new code, and new code is where the next instance
> of that class will be.** The defence is not more care. It is removing the
> surface — and where that is impossible, arranging for the next one to fail
> loudly, because a bypass that fails loudly is a bug report and one that fails
> quietly is what you spend five rounds chasing.
