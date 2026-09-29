## USOSS-12 — the digest marker is per-grammar, because no one character is legal everywhere

Binding on USOSS-11 through USOSS-14, USOSS-26 and USOSS-33. An amendment to the
construction in
`usoss-10-a-logical-name-maps-to-a-physical-one-injectively-or-the-provider-refuses.md`,
not a replacement for it: that construction is right, and this is about the
character it appends.

`sanitize` appends a full stop before the digest, and argues — correctly — that a
full stop cannot survive `notAllowed`, so the digested and undigested forms are
disjoint sets of strings. That argument holds. The **character** does not
generalise. A full stop is legal in an ECR repository name and an IAM role name,
which is all USOSS-10 needed, and it is illegal in:

* an ELBv2 load balancer name and target group name — `[a-zA-Z0-9-]`, max 32;
* a Lambda function name — `[a-zA-Z0-9_-]`, max 64.

So calling `sanitize` for any of those returns a name the AWS API rejects, **and
only for a name that gets digested** — which is to say only for a name carrying
punctuation, mixed case, or length. Every plain lowercase name works and the
break arrives from a live API on the first name that does not. That is the same
failure distribution as the collision the marker was introduced to close, and it
is the reason this is a decision record rather than a one-line fix.

### The fix, and the one wrong answer

`sanitizeWith(prefix, name, limit, marker)` takes the marker; `sanitize` is a
wrapper passing the full stop, so nothing of USOSS-10's changes behaviour. The
function port passes `markerDoubleDash`.

An underscore is the obvious wrong answer and worth naming so nobody reaches for
it: legal in a Lambda function name, **illegal in an ELBv2 name**.

Two hyphens works, on exactly the argument the full stop works on. A *single*
hyphen cannot be a marker — `notAllowed` produces hyphens, so `foo-a1b2` is
reachable both as a name spelled that way and as a digested rendering of
something beginning `foo`, which is the collision USOSS-13 found. A *run* of two
cannot appear: `sanitize` emits a name verbatim only when `clean == name` byte
for byte, and `clean` has every run of non-alphanumerics replaced by a single
hyphen, so a name that survives that comparison provably contains no two
adjacent hyphens.

The prefix is the only other component of a physical name and the only part that
does not pass through `notAllowed`, so `namePrefixGrammar` forbids `--` there and
`New` refuses a prefix that does not match. That is deliberately a construction
at the point the input enters rather than a check further out: a prefix admitting
`--` would put the marker's own separator into the undigested form and collapse
the two sets back together — the same shape as the bare-digest branch that
USOSS-10 record describes.

The single occurrence also makes the split unique, so a digested name determines
its own head and digest and two digested names can only collide on a 64-bit
digest of the whole logical name.

The convention comes from USOSS-13, which reached it independently for S3 bucket
names — a third grammar where a full stop is legal but unwanted, because a dot in
a bucket name breaks virtual-hosted-style TLS.

### The obligation on the other ports

An **ECS service name and an ECS task-definition family are `[a-zA-Z0-9_-]`**, so
USOSS-11 has this wherever it derives either from a caller-supplied name.
Check the finished name against the substrate's grammar, not the pieces that
built it: the marker mistake is invisible to any check on a step and visible to a
check on the artefact. `TestTheFunctionPortsNamesAreLegalOnTheirSubstrate` does it
that way, over the shared corpus, and asserts that the digested path was actually
taken so it cannot pass vacuously.
