## USOSS-6 — a parser with a skip path is a gate with a bypass

Recorded because it is the fifth time on this project that the fix for a class
contained an instance of it, and because the fix here generalises to every gate
that reads a set out of a document.

The previous entry pinned the audit's row set by deriving it from the report's
evidence table rather than restating it in the tool. That was the right shape and
it was defeated in one line. The extraction searched every line of the document
for a first cell that *looked like* a row identifier -- stripping `*` and
backticks before matching -- and silently continued past everything else. Review
added an ordinary Markdown row:

```markdown
| _E99_ | ... | ... | ... |
```

`_E99_` is emphasis, renders as E99, and does not survive a strip that only knows
about asterisks. The table rendered thirty-one rows, the audit reported that all
thirty of them had been derived, and the command exited 0.

**The defect was not the missing underscore.** Stripping a known set of
decorations is a hand-maintained restatement of "Markdown emphasis", and there is
always another syntax: `<em>`, a link, a trailing comment. The defect was that a
**third outcome existed at all**, between "this is row E99" and "this document is
wrong". A skip path in a parser is a bypass in every gate built on it, because
the thing skipped is by definition the thing nobody sees.

The rule, for the next one:

> When a gate reads a set out of a document, identify the set's extent
> **structurally**, then treat every member of it as an assertion. Anything
> inside the boundary that does not parse is a hard failure, never a pass.

Concretely: the evidence table is marked with an anchor comment and delimited by
its own Markdown structure, so its extent comes from the document rather than
from what its contents look like; nothing inside it is normalised; and a first
cell that is not exactly a canonical identifier ends the run naming the row. That
the identifier column carries no emphasis is not a convention anyone has to
remember, because it is enforced.

### And the other half: presence is not correctness

The same review found the second half, which is older and worse. The bijection
proved every row was **derived** and nothing about whether it was **right**. The
report stated SL = 88 and named no source revision; the same command over the
checkout a reader would reasonably reach for produced 87 and exited 0 just as
happily. Two runs, both correct about the tree they saw, one report, and nothing
in the output saying which tree it was about.

This project has already paid for that once -- a count went stale and survived a
re-audit -- and the previous entry's own finding, that "28 rows" had been read
off the last identifier rather than counted since revision 5, is the same defect:
it survived three reviews because presence was checked and values were not.

So two things, and the second is the one that generalises:

* **A figure without its tree is not a claim.** Both inputs are resolved to a
  commit before anything is counted, printed above the figures, and reported as
  dirty when the working tree has edits on top of the commit -- because a hash
  describes a commit, not a commit plus somebody's uncommitted changes.
* **Compare the values, not the labels.** The document's figures are written in a
  canonical machine-readable form and checked against what was derived, figure by
  figure and label by label. A tool that reads as though it validates the numbers
  while validating only their names is worse than no tool, because it converts
  "nobody checked" into "something checked and it was fine".

The label grammar is deliberately narrow for the same reason the identifier
grammar is: a permissive label swallows whatever follows the first number, so the
old prose form `62 int literals, 2 binary exprs, 5 identifiers, of 69` would read
as *a population of 62 carrying a long label* -- a figure silently reinterpreted
rather than rejected. That is the identifier bypass one column across, and it was
found by writing the fixture rather than by reasoning about the regex.
