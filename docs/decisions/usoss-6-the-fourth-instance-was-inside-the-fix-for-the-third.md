## USOSS-6 — the fourth instance was inside the fix for the third

Recorded because it is the measurement, not the anecdote. One class of defect --
a skip path in a checked reader -- was reproduced **four times in one file**, and
the last two were in code written specifically to close the previous one.

| # | The bypass | Where the fix for it lived |
| --- | --- | --- |
| 1 | The row set was not pinned at all | — |
| 2 | `_E99_`: emphasis stripped by a known-decoration list, unrecognised cells skipped | the fix for 1 |
| 3 | Backticks in the `Derived by` column, refused | the fix for 2, ninety seconds after writing it |
| 4 | A four-space-indented ` ``` ` opens no fence in Markdown, but opened one in the scanner | the fix for 3 |

The fourth is the sharpest. CommonMark allows a code-fence opener at most three
spaces of indent; at four it is an indented code block containing backticks and
opens nothing. So a renderer showed the table below it and the scanner skipped
every table after it — one line, and the "every table must be classified" check
silently stopped applying to the rest of the document. An unterminated fence did
the same thing more quietly still.

**The direction of a divergence is the whole property.** When a scanner and a
renderer disagree, exactly one direction is dangerous: the scanner believing it
is inside a fence while the renderer is not, because then a human sees a table
the tool ignored. The opposite — leaving a fence early — makes the scanner see
*more* tables and fail loudly. So the rules are written to err that way: openers
at indent ≤ 3, a closer matching the opener's character and length, and an
unterminated fence fatal because a scan that cannot reach the end of a document
establishes nothing about the tables in it.

**A bounded scanner, stated as such.** A real Markdown parser is the construction
that cannot express this class, and it was rejected: a new dependency in a
repository going public under a strict licence allowlist, for a tool that reads
one document this project writes. The honest claim replaces it —

> a bounded Markdown scanner whose known divergences fail closed

— and that sentence is worth more than the dependency, because it tells the next
reader exactly what they may rely on.

### The other hand-rolled grammar, audited rather than waited for

Predicting where the fifth instance lives is cheaper than finding it. The two
places this tool hand-rolls a grammar over someone else's format are the fence
scanner and the table-cell splitter; the first was confirmed, so the second was
audited in the same change rather than left for a reviewer.

Result, stated with the cases: **cell splitting was correct in all ten**,
including a pipe inside a code span (GFM is explicit that backticks do not
protect a delimiter), an escaped backslash immediately before a real delimiter,
and a trailing lone backslash. One **content** defect was found and fixed: `\\`
came back as two backslashes rather than one, so a cell's content was not what a
reader saw. It could not change a row's shape — the escape was consumed
correctly — but "the content is what is rendered" is the claim the value
comparison rests on, and it should be true rather than nearly true.

A negative result you can name is worth having. "I audited the splitter and here
are the ten cases" is a different statement from "I did not find anything there".

### The measurement, and what to do with it

Four self-found defects introduced by fixes, in one file, over four rounds. The
lesson is not that the fixes were wrong — each was correct about the instance it
was aimed at, and the audit's figures never moved. It is that **a fix for a class
is itself new code, and new code is where the next instance of that class will
be.** The defence is not more care. It is arranging for the next one to fail
loudly:

> A bypass that fails loudly is a bug report. One that fails quietly is what you
> spend four rounds chasing.
