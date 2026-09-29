## USOSS-10 — a logical name maps to a physical one injectively, or the provider refuses

Binding on USOSS-11 through USOSS-14 and USOSS-26. Recorded because the rule was
got wrong three times in one function inside a single ticket, twice in revisions
written to fix the previous one, and because every AWS port derives physical
names from caller-supplied application names the same way.

> Two distinct logical names must never produce one physical name.

### Why this is a security property and not a naming convention

Because the ownership check cannot catch a violation of it. That check exists to
stop apphub mutating somebody else's infrastructure, and it works by reading a
tag. When two logical names collide, both resources are genuinely
apphub-owned and carry the same component tag, so every check passes and the
second `Ensure` adopts the first's resource and reports success.

For an image repository that is two applications sharing a registry namespace.
For an IAM role it is worse: `EnsureWorkloadIdentity` resolves two applications
to one role, so application B's workload assumes the identity provisioned for
application A. A privilege boundary between two tenants collapses, and nothing
in the system reports anything.

### The three ways it was got wrong

Listed because each is a shape rather than an incident, and the third is the one
that matters most.

1. **Truncation dropped the tail with nothing appended.** Two long names
   agreeing on their first N characters became one. This is what the source
   system does (`bucket.go:124-130`); USOSS-13 found it there.
2. **Truncation appended `"-"` plus an eight-hex digest.** That separates two
   truncated names from each other and not from an untruncated one: a short name
   spelled `foo-a1b2c3d4` is what a long name beginning `foo` produces when its
   digest starts `a1b2c3d4`. Around 2^32 work against a chosen prefix.
3. **The untruncated path — the common one — collapsed runs of
   non-alphanumerics and stopped there.** Six spellings of one two-word name —
   differing only in the punctuation between the words (hyphen, underscore, full
   stop, spaces, other punctuation) or in case — all produced the same physical
   name. No work factor at all: two application names differing in a single
   character of punctuation.

The third was live while a test named `TestTruncationIsInjective` was passing.
The test named three cases and never quantified over pairs of distinct names,
and it never exercised the untruncated path — the gap sat one generalisation
away from a test that had already been written.

### The construction

Stated in one sentence, by the USOSS-26 worker who arrived at it independently:

> The fix is not a better slug. It is a digest of the **original input** on every
> derived path, plus a marker a verbatim form cannot contain.

Both halves are load-bearing. Digesting the *slug* rather than the input would
make two names that slug identically digest identically, which is the punctuation
collision again one layer down. And a marker some paths omit proves nothing:
disjointness has to be a decidable property of the string, not a convention.

Concretely, it is a rule about sets rather than a check about strings. A name is
used **verbatim** only when sanitization changed nothing at all — byte-for-byte,
so a difference in case or punctuation cannot land there — and it fits. Such a
name is drawn from `[a-z0-9-]`, so it contains no full stop. Every other name is
rendered as `head + "." + digest-of-the-whole-logical-name`.

The three clauses are then independent:

* two verbatim names differ because the names differ;
* two digested names differ because their digests differ;
* a verbatim name and a digested one differ because exactly one contains a full
  stop after the configured prefix.

The third is a property of the alphabet rather than of a digest length, which is
why it needs no argument about work factors. The digest is 16 hex digits because
the number that matters is the *second-preimage* bound — choosing a name that
collides with a specific existing one — not the birthday bound.

A prefix that leaves no room for a head, a marker and a digest is
`compute.ErrInvalidSpec` naming the configuration field. An earlier revision
returned the bare digest there, which is an ordinary verbatim-shaped name and
reintroduced the very collision the marker exists to prevent — a new instance of
the defect living inside the branch added to close the previous one.

### Three independent arrivals

Worth recording, because it is as much corroboration as this shape ever gets.
USOSS-13 found the truncation half in the source's own bucket naming. USOSS-26
found it in its own port before any warning reached it, by the identical route —
its first scheme put a hyphen between slug and digest, so the derived form of a
long name was itself a legal short name a caller could simply use — and reserved
a marker a verbatim segment cannot contain. This ticket got there third, and only
after review supplied the reproductions.

Three ports reached the same construction from three directions. That is why it
is in the decision record rather than in one package's comments.

### The invariant is injectivity; the construction below is one means to it

Stated separately because the distinction matters to the ports that follow.
**The property a port must hold is injectivity.** Lossless-or-digest is a
sufficient construction and it is the one used here and in USOSS-13; it is not
the only legal answer, and a port that reaches injectivity another way and can
demonstrate it has satisfied this entry. What is *not* acceptable is a port that
argues its slug is good enough, because that is the argument all three defects
above survived.

### The marker is per-grammar by necessity, not by taste

Established across three grammars rather than argued:

* `.` is legal in an ECR repository name and an IAM role name; **illegal** in an
  ELBv2 or Lambda name; and legal-but-hostile in an S3 bucket name, where a dot
  breaks virtual-hosted-style wildcard certificates.
* `--` is legal in S3 and IAM; **illegal** in ECR, whose grammar admits single
  separators between alphanumeric runs.
* An RDS identifier admits letters, digits and single hyphens and nothing else,
  so it has **no spare character at all**.

No single character works everywhere. `sanitize` therefore takes the marker as a
parameter, and a port picks the one its grammar permits. Where the marker is
drawn from the name's own alphabet, disjointness is recovered by excluding from
the verbatim set any candidate that already ends in marker-plus-digest — which
keeps disjointness a decidable property of the string rather than an argument
about digest length.

### A note on the marker, for a substrate whose alphabet has no spare character

The full stop is legal in ECR repository names and IAM role names. It is **not**
legal in an RDS identifier, whose grammar admits letters, digits and single
hyphens and nothing else — there is no spare character to reserve. USOSS-14 is
parameterising the marker rather than writing a second sanitizer, and recovering
disjointness for a marker drawn from the name's own alphabet by excluding, from
the verbatim set, any candidate that already ends in marker-plus-digest. That
keeps disjointness a decidable property of the string, which is the standard
here; it leaves this ticket's behaviour unchanged, provably, because the lossless
form of a name contains no full stop and so the new clause can never fire for it.

### The obligation on the other ports

Do not re-derive this. `sanitize` in `compute/aws/names.go` is shared, returns an
error, and is covered by `TestSanitizeIsInjective`, which quantifies over pairs
drawn from a corpus of every shape known to have broken it. A port that needs a
different physical grammar should extend that function and add its shapes to the
corpus, rather than writing a second sanitizer whose injectivity is argued
separately.
