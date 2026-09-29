## USOSS-6 — a tool that walks a tree must report whether it walked all of it

Recorded because this repository's gates all walk file trees — the import
boundary checker, the hermeticity check, the licence-header check, the decision
lint — and because the same defect appeared three times in one auditor while
each fix for it was being written.

The auditor behind USOSS-6's source claims counted correctly from the start.
What it lacked, three times over, was any assurance that it had counted a
population that existed:

1. Pointed at a path that did not exist, it printed a full table of `0 / 0` rows
   and exited 0, with one row silently absent because it printed only inside an
   `if err == nil`.
2. Given one production file that would not parse, it logged the error, dropped
   that file from every denominator, and exited 0 with a table that looked
   exactly like a correct one.
3. Given a **symlinked** subtree containing a malformed file, it exited 0 and
   omitted the subtree — while its own summary line asserted that every
   population had been parsed in full.

The third is the instructive one, because the first two had already been fixed
and the fix was aimed at *the ways a walk reports failure*. `filepath.Walk` uses
`Lstat` and does not follow symlinks, so a symlinked directory is not an error;
it simply is not there. **Absence that does not announce itself** is the class,
and enumerating the ways a walk *errors* does not cover it.

So the contract to hold a tree-walking tool to is **"I traversed everything, or I
failed"**, and the useful question is which states make a traversal incomplete
*without* erroring. The list, for anyone writing the next one:

| State | Silent? | What to do |
| --- | --- | --- |
| symlinked directory | yes — never descended into | refuse, or follow with cycle detection |
| symlinked file | counted, but from outside the population | refuse |
| non-regular entry (FIFO, socket, device) | parser blocks or fails oddly | refuse |
| file created after its parent was read | yes | traverse twice, require identical sets |
| `filepath.SkipDir` returned by the callback | yes | never return it |
| permission or stat error | no — errors | fatal, never logged-and-skipped |
| empty population | no, but yields `0 / 0` | assert non-emptiness per population |
| crossing a mount boundary | traversed normally | nothing; not an omission |
| directories Go's build rules ignore (`_x`, `.x`) | included here | state the definition; it can only enlarge a denominator |

Refusing beats following for the symlink cases. Following needs cycle detection,
which is another place to be wrong, and a symlink inside a Go source tree in this
repository is unusual enough that a human should look at it.

The general lesson, which is the one worth carrying past this ticket: **every
mechanism that reports a result must also report whether it ran.** Prefer a shape
that cannot express the incomplete state over a check that notices one — the same
standard the import boundary checker arrived at after four rounds, reached here
by four more. And a summary line that asserts completeness is worse than none at
all if nothing establishes it: this tool printed "every population parsed in
full" over a tree it had not finished reading.
