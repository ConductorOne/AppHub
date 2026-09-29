## USOSS-17 — a claim about a whole tree is a gate, not a sentence

The decision to abstract the AI provider rests on a construction argument: the
detection heuristics cannot be published because there is no file here for them
to be in. That argument was written down, reviewed, and **false at the moment it
was written**. Three identifier literals from the source scanner's system prompt
had been reproduced verbatim in these packages — one in a doc comment, two in a
test fixture — and an adversarial review found them.

### What the population actually was

Derived rather than eyeballed, because the point of this entry is that the eye
had already passed over it. The source's prompt builder contains **4** quoted
example literals and **12** in-scope category phrases, 16 strings in total.
Of those, **3 of 16** appeared in the two ported packages, in **2** files: two
classifier identifiers in a test fixture, one check identifier in a doc comment.
None of the 12 category phrases appeared.

Three of sixteen is small and entirely beside the point. A construction argument
is not weakened by a small violation, it is **falsified** by any violation: if
the claim is "there is no file for them to be in", one line in one file settles
it. And a test fixture is a publication surface exactly as a source file is —
the tarball does not distinguish them, and neither does the git history, which
is why the remedy was removal rather than relocation.

### The general form

**A claim about a whole tree cannot be maintained by anybody reading the diff.**
This project has now paid for that in five separate documentation defects, and
the pattern is always the same: the claim is true when written, and stays
written after it stops being true. The two answers are to make the violation
inexpressible, or to make a machine check the claim. Here the first is only
partly available — abstracting the provider removes the *file*, not the ability
to type a string — so the second has to cover the rest.

`internal/disclosure` is that check. It walks every package under `modules/`,
comments and test files included, and refuses anything matching the shape of a
ranked risk-category identifier, a weakness-catalogue entry, or a dotted check
identifier.

### Three things about the gate that are the actual decision

**It names shapes, never terms.** The patterns describe the *form* each kind of
identifier takes and contain no real classifier, catalogue number, or check
name. Writing the terms into the guard would publish them in the guard. That is
the rule this project already settled for detection rules generally, applied to
a detection rule about detection rules.

**It lives outside the tree it inspects.** The first version put the patterns in
a test file inside `modules/review` and skipped that file by name while
scanning — a gate with a documented bypass, which is the shape this project has
now found in four separate gates. `internal/disclosure` is a different package,
so the scanned set and the set holding the patterns are disjoint and there is
nothing to skip. **A gate that has to exempt itself is a gate with an exemption
in it.**

**It says what it cannot see.** It cannot catch a heuristic expressed in prose,
a paraphrase, or an identifier whose shape it does not model. Neither can any
check that runs inside this repository: the comparison that would settle it
needs the source tree, and a public repository must not name or clone that —
the same constraint that keeps USOSS-6's audit out of CI. So the complete check
is a human comparison run before publication, USOSS-18, and this gate is the
part that can be automated. That boundary is written into the package comment,
because a gate that does not state its limits is read as covering everything.
