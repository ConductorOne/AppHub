## USOSS-6 — the union merge driver drops this file's separators, silently

> **Superseded, and the mechanism is retired.** This entry describes
> `docs/DECISIONS.md`, a single file merged with the `union` driver. That file no
> longer exists: the record is one file per decision, so the failure below cannot
> occur — separate files cannot glue together. Kept because it is the evidence
> for that change, and because the defect recurred **nine times** before the
> storage was fixed rather than the merge. See
> [the decision that split the record](decision-record-one-file-per-decision-because-github-does-not-honour-merge-union.md).

Recorded because it has now happened on two branches, the same way, and because
a reader of `.gitattributes` would not predict it from what is written there.

`docs/DECISIONS.md merge=union` was added to stop the conflict cascade on this
file, and it does. Its own comment names the hazard it knew about: union turns an
in-place edit into silent duplication rather than a conflict. **It has a second
one.** Union concatenates at *line* level with no notion of what a line is, so
when a branch appends an entry and `main` has also grown, the last line of one
side and the first line of the other end up adjacent with the `---` between them
gone. PR #4 and PR #5 both landed a heading directly against the previous
entry's closing sentence, at exactly the boundary where their first entry began.

**Git reported no conflict in either case**, and no gate saw it: the file still
parses as Markdown, the headings are all present, and nothing counts them. The
damage is only that two decisions render as one.

So: **after any rebase or merge that touches this file, check it by content, not
by exit status.** The check is one line —

```sh
[ "$(grep -c '^## ' docs/DECISIONS.md)" = "$(grep -c '^---$' docs/DECISIONS.md)" ]
```

— and the stronger form is to assert that every entry heading is preceded by a
blank line and a `---`, which is what caught this one. (`make decisions` now does
both, and more: it also catches a heading *spliced into* the middle of a line,
which is the other thing a line-level merge does and which the count above cannot
see.)

The general shape is worth keeping, because it is the same one five rounds of
review on USOSS-6 were about. A mechanism introduced to prevent a problem
created a smaller one that no check could see, and the absence of a complaint was
read as evidence of correctness. **A clean merge is not evidence of a correct
merge**, exactly as a count that runs without error is not evidence of a count of
the right population. In both cases the missing step is looking at the thing
itself.

If this recurs a third time, the answer is the migration `.gitattributes`
already names — one file per decision under `docs/decisions/`, where separate
files cannot be concatenated into each other — or a gate that fails the build on
a heading without its separator. Either is a change to how the record is stored,
not to how it is merged, which is why neither is being made in this pull request.

**It recurred a third time**, on the rebase onto `main` at `3ac3b04`, at the same
boundary, in the same way, with no conflict reported. Three for three: every
rebase of this branch across a `main` that had grown has dropped this separator.
So the sentence above has come due, and the recommendation is no longer
conditional — **the storage should change.** Sequencing it into a pull request
that is otherwise finished would mean moving sixteen entries and rewriting every
cross-reference to them in the same change as a module framework, so it is filed
as its own ticket rather than done here. Until it lands, the content check above
is the only thing standing between this file and a silent merge defect, and it
has to be run by hand after every rebase.
