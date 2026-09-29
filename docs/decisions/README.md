# Decision record

Decisions that are settled. Each one is binding on subsequent work and is not
relitigated in a pull request; if you think one is wrong, open an issue.

Entries are recorded verbatim from where the decision was made, with the source
named. Later reversals are appended as new entries rather than edited in, so the
record shows what was believed when.

### How this directory is laid out

One decision per file. The file name is derived from the entry's own heading —
lowercased, with every run of non-alphanumeric characters folded to a single
hyphen — so it cannot be chosen, cannot be hand-numbered, and cannot collide:
two entries with the same heading would be the same file.

There is deliberately **no index**. This directory listing is the index, and
GitHub renders it above this file. A committed index would be a file that every
decision-adding pull request has to touch, which is the merge conflict this
layout exists to remove.

`make decisions` checks the layout. It is the only place the invariants are
stated; `internal/decisions` holds them and the fixtures that prove they fire.
