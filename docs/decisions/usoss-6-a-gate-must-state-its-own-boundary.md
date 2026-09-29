## USOSS-6 — a gate must state its own boundary

Recorded because the last three entries are all about a mechanism claiming more
than it established, and the final state of this one is a gate that is
deliberately **bounded** rather than complete.

Three residual holes were closed by making the default fail closed, and two were
accepted permanently with reasons rather than apologies.

**Closed — a dirty tree is refused, not reported.** The rule is that a figure
without its tree is not a claim, and a tree with uncommitted changes is not
attributable to any commit: the hash names a commit, the count is of that commit
plus somebody's working copy. Printing a warning and carrying on was a *third
outcome* between attributable and fatal, which is the shape that has holed this
tool three times. The default now fails; `-allow-dirty` is an override a human
types and thereby owns.

**Closed — every table in the document is classified.** Anchoring the evidence
table proved the other tables were not rows. It did not stop a reader treating
one as evidence, and a table nobody checks beside a table everybody trusts is
where an unverified figure ends up. So an unclassified table is now fatal. The
alternative — banning every other table — was rejected: this record and the
reports carry legitimate prose tables, and forcing those into paragraphs would
make the documents worse in order to make a check easier to write. Marking costs
one line and is enforced, which is the property that matters.

**Narrowed — prose that points somewhere checkable.** The claim columns of an
evidence table cannot be verified; nothing can confirm that a sentence describes
what a function computes. But the *pointer* can be: the table names the function
that derives each row, and the tool compares it against the function that
actually emitted the row, captured from the running program rather than restated.
A row whose derivation moves fails until the table is corrected. This does not
make the prose true. It makes the prose point somewhere, checkably, and that is
all it claims.

**Accepted permanently, and this is the important one.** The audit does not run
in CI and never will. Twenty-nine of its thirty rows are claims about the source
repository this code was extracted from, and wiring CI to check them would
require CI to clone that repository — putting an internal repository's name into
a **public** one, disclosing its existence and the fact of the extraction, in a
file every visitor can read. That is the same disclosure the security bar forbids
for an internal hostname or an account ID.

So the division is deliberate: **CI gates the hermetic test suite; a human runs
the audit over a source tree CI cannot have.** It is written here so that nobody
later reads "the audit isn't in `make check`" as an oversight and closes it by
adding the clone.

The general form, which is the last thing this ticket has to teach: **a gate must
state its own boundary.** Every previous round here was a mechanism that reported
success over ground it had not covered — a population it had not traversed, a row
it had not derived, a figure it had not compared. The final defence is not
another check. It is the gate saying, in its own documentation, exactly what it
does not cover, so the next reader extends it deliberately instead of trusting it
accidentally.
