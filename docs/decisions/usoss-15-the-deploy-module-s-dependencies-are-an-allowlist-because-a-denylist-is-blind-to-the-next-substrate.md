## USOSS-15 — the deploy module's dependencies are an allowlist, because a denylist is blind to the next substrate

The first version of this fence denied three prefixes: `github.com/aws`,
`k8s.io`, `sigs.k8s.io`. Review defeated it in the way that matters — by
planting a **compileable** import of a cloud SDK from a fourth vendor into the
real union fixture and watching `internal/boundary` stay green.

That was graded non-blocking, correctly: no such SDK is in the tree today. It is
also the exact purpose of USOSS-15, and it is *a test immune to a change is also
blind to it* sitting inside the gate built to prevent that class.

### Why a fourth prefix is not the fix

Adding the vendor would close that spelling and leave the population defect
exactly where it was. The next vendor is not enumerable, and there is no
semantic authority for "is this module a substrate SDK" — that is a judgement,
not a fact anything can derive.

### The construction: invert the question

A denylist asks "is this one of the things we know about", which has no
authority. An allowlist asks "is this one of the things this package needs",
which does: the answer is short, it is knowable, and it is already written down
in the imports.

`boundary.Rule` grew `PermittedImportPrefixes`. A rule that names them forbids
everything it does not name. The deploy module's list is three first-party
prefixes — the compute interface, the credential vocabulary, the module
framework — plus the standard library, which is permitted without being named.

The standard library is permitted without being named, and **which paths are
standard is the toolchain's answer, from `go list std` over the supported
platform matrix**, not an inference from how the path is spelled.

### That sentence used to say something else, and it was false

The first version of this entry said the standard library was not an exemption
anybody could hide behind, because "the go command's own rule is that a module
path's first element contains a dot and a standard-library path's does not, so
no third-party or first-party import — including one reached through a local
`replace`, whose module still declares a dotted path — can be mistaken for
standard."

**A module reached through a `replace` directive may declare any path it likes,
including one with no dot.** Review demonstrated it rather than argued it: a
local module named `cloud`, providing `cloud/sdk/azidentity`, compiled, imported
cleanly from the deploy module, and was waved through the allowlist as standard
library. `internal/boundary/testdata/union/deployfence/nodotstub` is that module,
kept as the control.

The inference was **sound while every rule was a denylist**, and that is the part
worth carrying: calling something standard by mistake could only stop the walk
early on a package no denied prefix covered, so it could not hide a violation.
The moment one rule became an allowlist, the same classification decided
*admission*. The implication reversed and the argument for the heuristic did not
come with it.

Two lessons, and the second is the one this record is for:

* **the membership test of an allowlist is part of the allowlist.** The
  structural move was right and its predicate was a list of spellings, which is
  the same defect one level down;
* **when a rule's polarity changes, every justification written for the old
  polarity has to be re-derived rather than carried.** The sentence above was
  true when it was written and false when it was moved.

The standard-library set is also a **union over the supported platform matrix**,
not one `go list std`: the set differs per platform, and a Linux-only answer
made the union graph try to resolve `crypto/x509/internal/macos` as a
third-party import when it judged a darwin build. The graph's own differential
invariant caught that within a minute, which is the second time that invariant
has caught a resolver mistake.

### Both rules stay, and they are different claims

`deploy-is-substrate-free` is kept alongside. It is strictly narrower than the
allowlist and cannot disagree with it, so it is not a restatement that can
drift: it exists so that the most likely violation gets a diagnostic naming what
it is and why the interface is there, instead of the allowlist's generic "not on
the list". A test asserts the denylist stays silent about the fourth vendor, so
nobody closes the population defect by adding a prefix and believing it fixed.

### The failure lands on whoever adds the dependency

That is the property worth having. A dependency nobody anticipated fails the
build of the person adding it, which is the only place it is cheap — rather than
passing silently and being discovered by an audit, or not at all.

A rule that states both kinds of claim, or an allowlist with no subject set, is
refused by `Config.Validate`: the first cannot be read off its own declaration,
and the second would forbid every dependency this repository has.
