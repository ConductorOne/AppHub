## USOSS-18 — two commits on `main` carry no DCO sign-off, and the gate cannot see them

**This is a recorded defect in `main`'s provenance, not a settled design choice.**
It is written down because a DCO repository whose own trunk is unsigned has a gap
that no green check will ever mention.

### What is missing

Two of `main`'s four commits carry no `Signed-off-by` trailer:

| Commit | Subject | Sign-off | Source PR | Commits squashed |
|---|---|---|---|---|
| `f74450b` | seed: license, notice, gitignore | present | — | — |
| `eebc1ac` | USOSS-4: repository skeleton, build, and hermetic CI | **missing** | #1 | 11 |
| `ee03261` | chore: remove the now-inert gitleaksignore entry | present | #10 | 1 |
| `81555d8` | USOSS-3: c1-backed credential vending contract | **missing** | #2 | 5 |

Both unsigned commits carry a GitHub-generated `Co-authored-by:` trailer, so the
absence is specifically of the DCO certification, not of attribution.

### Why

The trailers were lost when the squash commit message was composed by hand at
merge time. Both unsigned bodies are curated prose summaries of their branch;
neither reproduces the squashed commits' messages, and the trailers went with the
text that was replaced. The single-commit PR (#10) kept its sign-off because its
default squash body *was* the original commit message, trailers included.

This was a procedural error in how the merges were performed, not a
misconfiguration: the repository's `squash_merge_commit_message` is already
`COMMIT_MESSAGES`, so the untouched default would have carried the trailers
through. Editing the body is what dropped them.

**Corrected going forward:** a hand-written squash body must re-append the
`Signed-off-by` trailers of the commits it replaces, or the default body must be
left alone. This is now checkable after the fact — `hack/check-dco.sh` accepts an
explicit range, so `./hack/check-dco.sh <old-main> main` audits what a merge
actually landed.

### Why the gate did not catch it, and still would not

The DCO job runs `if: github.event_name == 'pull_request'` and checks
`base..head`. A pull request's base commit is excluded from that range by
construction, so an unsigned commit that is *already on `main`* is outside every
future pull request's range. Nothing re-examines trunk. The gate is not broken —
it is scoped to incoming contributions, and these commits are no longer incoming.

The consequence is asymmetric and worth stating plainly: the two unsigned commits
will never fail a check, and no amount of CI on subsequent pull requests will
surface them. Only an explicit audit of `main` will.

### Not fixed by rewriting history — deliberately

The obvious remedy, `git rebase --signoff` over `main`, is refused. Rewriting
merged history was done once already for the squash-merges and invalidated every
open branch in the process; repeating it to add four trailers would break the
open stack a second time for a strictly documentary gain. The commits are
authored by the same person who would sign them, and that person's certification
is recorded here instead.

### What actually moots this

USOSS-18 already recommends, for an unrelated reason (pull-request refs surviving
a squash — see "A correction to 'git history cannot be un-published'" under
USOSS-1), that publication happen **from a clean-history repository or mirror**
rather than from this history. If that recommendation is adopted, the published
trunk is a fresh commit — or a fresh set of commits — created by the publisher,
which can be signed correctly at that point, and this gap never reaches an
outside adopter.

That is the intended resolution. The two recommendations are independent findings
that happen to share one remedy, which is a reason to weight it more heavily, not
less.

**USOSS-18 must therefore either** publish from clean, correctly-signed history,
**or** record an explicit, human-approved exception stating that two trunk
commits in the published history carry no DCO certification and why that was
accepted.
