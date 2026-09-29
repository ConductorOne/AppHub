## USOSS-6 — a count of rows is not a check on the row set

Recorded because it is the fourth time on this project that an artifact built to
end a class contained an instance of it, and because the shape generalises to
every gate here that reports a total.

The auditor above was held to *"I traversed everything, or I failed"* and it
holds. Its populations are established, its denominators are non-zero, and its
figures were confirmed by an independent reviewer running it. It still reported
success on a table that was missing five of its rows.

The summary line said `audit complete: 29 rows`. Nothing asserted **which** rows,
so:

* five rows of the table — E7, E8, E9, E23, E28 — had never been derived by any
  run, while the report said every row was derived from `go/ast`;
* deleting a single `emit` call printed `28 rows` and still exited 0;
* the twenty-nine printed lines were not the table's rows in any case: one row
  was printed as four lines, one line was not a row at all, and the totals agreed
  by coincidence.

**A total is not a set.** `29` is consistent with every 29-element set, including
the one that omits the row you needed. This is the same failure as a count that
runs without error not being a count of the right population, one level further
out: the population is established, and now the *set of claims about it* is not.

The fix is not a `[]string` of row IDs in the tool. That is a hand-maintained
restatement of the table, which is the defect one level out again — the exact
shape that defeated the `Granter` port list and the go-command directory rules.
The row set is **read out of the report's evidence table** and the tool requires
a bijection with it: every row in the document derived exactly once, every row
derived present in the document, both sides asserted non-empty. A missing row, a
duplicated row and a row the document does not state are each fatal and named.

Two consequences worth copying:

* **Emit one row per row.** A claim carrying several figures (files *and*
  packages; a four-way partition) emits one row with several figures rather than
  several rows. Then the mapping between what is printed and what is claimed
  needs no table to state it, and so has no table to drift.
* **Derive it, or take the input.** One row counts this repository's own
  import-boundary rules and cannot be derived from the source tree at all. The
  tool takes the target repository as a second required input rather than
  exempting the row. An exemption is an omission with a note attached, and the
  failure being fixed here is precisely a row that is absent while the table says
  it is present.

The general form: **a mechanism that reports how much it did must also report
what it was supposed to do.** "I traversed everything or I failed" covers the
population; "I produced every claim the artifact makes, or I failed" covers the
claims. A gate that reports a total and nothing else is one deleted line away
from reporting a smaller total just as cheerfully.
