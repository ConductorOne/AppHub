## Decision record — one file per decision, because GitHub does not honour merge=union

This entry has no USOSS ticket. It is recorded here rather than given a number
because inventing an identifier would be a claim about a tracker this repository
cannot see.

It is also the first entry written in the layout it describes, which is the only
live test the migration gets before someone else needs it.

### What was decided

The decision record is a directory, `docs/decisions/`, holding one file per
decision. `docs/DECISIONS.md` is deleted. There is **no index file**, generated
or otherwise: the directory listing is the index, and GitHub renders
`docs/decisions/README.md` — which holds the record's preamble and nothing else
— underneath it.

An entry's file name is derived from its own heading: lowercased, with every run
of characters outside `[a-z0-9]` folded to a single hyphen. Nobody chooses it.
`make decisions` recomputes it from the heading and compares, so a name cannot
drift from the entry it holds, and two entries cannot collide on one file
because equal headings are equal names.

### Why, given that the merge attribute was supposed to have solved this

`.gitattributes` set `docs/DECISIONS.md merge=union` so that concurrent appends
would merge without conflict. It works. It is simply not consulted by the thing
that was causing the damage.

A merge driver is a property of local git configuration. **GitHub's mergeability
computation does not honour `.gitattributes` merge drivers.** Measured against
`main` at `8e8afcd`:

* `git merge-tree --write-tree origin/main origin/<branch>` exits **0, with no
  conflicts**, for pull requests **#5, #19, #26 and #27**;
* GitHub reports all four **CONFLICTING**;
* the only file `main` had touched since those four branches diverged is
  `docs/DECISIONS.md`, via #21.

Four of four disagree, in the same direction, over one file. The local merge and
the hosted merge were computing different things, and only one of them gates
anything.

The consequence is worse than a conflict marker. **A `CONFLICTING` pull request
gets no CI at all** — `pull_request` workflows need a `refs/pull/N/merge` that
cannot be built, so no run is created: not queued, not cancelled, absent. The
pull request keeps displaying its last green tick, describing a tree nobody will
build again. One worker lost four consecutive pushes to this and reported it as
an infrastructure fault. With thirteen pull requests open, one merge of the
record was conflicting seven or more of them and silently removing their checks.

`.gitattributes` had already named this migration as the remedy, for a different
trigger — it predicted entries being edited in place, which never happened. The
reasoning it recorded is kept in that file rather than deleted.

### What this changes about `make decisions`

The old check was a bijection between entries and the blank/`---`/blank
separator blocks that introduced them. That invariant existed because `union`
merges a line at a time and could drop a separator, or splice a heading onto the
previous line, without reporting a conflict — a defect that sat between two
verified things and below the resolution of every content check applied to it.

With one entry per file there are no separators, and no line-level merge of two
entries into one file. Those checks are not weakened, they are unreachable, and
they are gone rather than kept as a gate over an empty room. What replaces them
is stated in `internal/decisions`: every member of the directory is classified
or the check fails, each entry file holds exactly one entry, and the file name
equals the slug of its heading. One migration guard is added — the reappearance
of `docs/DECISIONS.md` is fatal, because twelve branches were open across this
change and every one of them carries an append to that path.

### What this does not claim

Not that conflicts are impossible. Two pull requests that edit the *same*
decision still conflict, which is correct: that is a disagreement, and the
record's own preamble says reversals are appended as new entries rather than
edited in.

Not that GitHub's behaviour is a bug being worked around. It is not documented as
supporting merge drivers, and a hosted merge that ran repository-supplied
configuration would be a different design with its own problems. The error was
relying on a mechanism whose reach had never been measured at the place the
failure occurred.

And not that the split preserved the record's *order*. It preserves every byte
of every entry — the concatenation of the entry files, in the original order,
after the preamble, is byte-identical to `docs/DECISIONS.md` at `8e8afcd`
(`d5553cd06f2367aabe07b7b6f16a2e71cd9917d68addaaa271d15e6090733193`). What it
does not preserve is the append sequence as a readable property of the record;
that now lives in git history, and the directory sorts by name instead. Buying
that back would take a committed ordering file, which is a file every
decision-adding pull request has to touch — the thing this migration exists to
remove.
