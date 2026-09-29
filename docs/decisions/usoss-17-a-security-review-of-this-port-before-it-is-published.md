## USOSS-17 — a security review of this port, before it is published

This is security tooling and it writes to other people's repositories, so the
diff was read as a disclosure surface and as an attack surface separately. Both
readings changed the code.

### Disclosure: what a published detection rule tells an attacker

The rule this project already applies is that a published detection mechanism is
a published evasion, which is why honeytoken providers are not ported. Applied
here, it splits into three answers rather than one.

**The scan heuristics do not ship, because there is no file for them to be in** —
and that sentence was **false when this entry first made it**, which is the most
useful thing in the entry. The decision to abstract the AI provider does keep
every prompt, budget and tool-loop policy in the source repository, and
`modules/review` does orchestrate a scan without describing one. But three
identifier literals from the source scanner's system prompt had been reproduced
verbatim in these packages — one in a doc comment, two in a test fixture — so
the construction argument was already untrue for those three at the moment it
was written, and a review found them rather than this section did. They are
removed, and `internal/disclosure` now checks the property instead of asserting
it. What that gate covers, what it deliberately cannot, and why it names shapes
and never terms are in its own entry.

**The input validators do ship, deliberately, and publication does not help
anyone.** `review.SanitisePath`, `review.IsSafeRef` and `review.ValidateOwnerRepo`
are enforcement rather than detection. Knowing exactly which characters a path
may contain does not help an attacker construct one that gets through, because
the check is total: there is no third outcome and no repair path. The same goes
for `fix.writeFencedBlock` and `fix.pickFence` — an injection *mitigation* whose
whole security property is that it holds against an adversary who has read it.

**The fix guardrails ship, and this one needed an argument.** `modules/fix`
publishes the paths a proposed patch may not touch and the finding categories
that unlock them (`caps.go`). That is closer to a detection rule: it tells a
reader that claiming a supply-chain category is the way to reach `.github/workflows/`.
It ships anyway, for a reason that is about the threat model rather than about
convenience. The category is emitted by a model reading the repository under
scan, so in the scenario where secrecy would matter the attacker already
controls the input and would reach the same list by trying the obvious words.
What actually protects the workflow directory is not that the list is secret; it
is that the patch is bounded, that new files cannot be created, and that the
result is a **draft** pull request a person has to approve. Secrecy was never
doing the work, and pretending it was would leave the real defences
unexamined.

**Security correction (2026-09-28).** The draft-PR review rationale above does
not hold for executable CI definitions: a workflow or composite action can run
on the bot's branch push before a reviewer sees the draft. The fix guardrail
now refuses `.github/workflows/` and `.github/actions/` edits in every finding
category. Category-gated supply-chain changes remain possible for lockfiles
and Dockerfiles; those still require ordinary review.

### Attack surface: four places this port fails closed where the source did not

Each is a deliberate behaviour change, and each is tested.

**The supply-chain category is matched whole.** The source normalised the
category and then split it on separators, admitting it if *any* fragment was in
the allow-list, so `artificial-intelligence/ci` unlocked the workflow directory
(`agent_fix.go:159-186`). Its own comment records that an earlier version used
`strings.Contains` and was worse. Splitting is the same mistake one level in: a
widening path driven by attacker-reachable text, made more lenient in the
direction that grants permission. `fix.IsSupplyChainCategory` matches the whole
normalised category against a closed set and refuses a compound it might have
been able to interpret. The cost is that a legitimate `supply-chain/dependency`
is refused with a message a person can read; the alternative is a bypass.

**A ref must be a sequence of non-empty components.** The source's ref check
tested a character set, refused `..`, and refused a leading dash
(`agent_scan.go:743-756`), which accepts `/x`, `x/` and `a//b` — each of which
produces an empty path component when spliced into a request path, and none of
which any implementation would resolve. `review.IsSafeRef` adds the structural
rule. It was found by testing the shape rather than the examples: the property
test generates every placement of every unsafe fragment, and these three fell
out of it.

**The storage ceiling is checked against the thing that is stored.** The source
bounded the sum of the raw file contents at 350 KiB and explained in a comment
that the bound exists because a DynamoDB item may not exceed 400 KiB
(`agent_fix.go:88-104`). The sum of the contents is not what is stored — the
JSON encoding is, and escaping can multiply a byte by six. `modules/fix`
marshals the patch and checks the encoded length, which is the resolution the
failure lives at. The provenance of the number is recorded on
`SuggestedMaxEncodedPatchBytes`, where a reader raising it will see that it is a
storage decision before it is a review one.

**No credential crosses a module boundary.** The source minted an installation
token in the module and passed it to the downloader and to nine Git Data calls
(`agent_scan.go:539-547`, `agent_fix.go:934`). Here `SourceFetcher` and
`GitClient` authenticate themselves from the `Coordinates` they are given, so
there is no token, header or key in either package. The security bar's rule
about credential material — never logged, never in an error, never on disk — is
met by there being nothing to hold rather than by holding it carefully.

### Identifiers: the automation has to be named by whoever runs it

The source stamps its own product name onto everything it creates in a customer
repository: the branch namespace, the commit title prefix, the pull request
label, and a link to an internal repository URL in the pull request body
(`agent_fix.go:1077`, `:1108`, `:1123`, `:1178`). All four are ConductorOne
identifiers, and one is an internal repository address, so none can appear in a
public repository. They are replaced by `fix.Identity`, which is **required and
has no default**: `fix.New` refuses to build without it. The URL is not
replaced by a configurable one — it is dropped, because a caller-supplied URL
rendered into markup is an injection surface added for no capability.

### What this review did not cover

The two ported packages, and only those. The three files ruled out of scope were
read for the ruling above and not audited; `deepsec_sandbox.go`'s accepted
residual is reported for USOSS-18 and is not this ticket's to close. And this is
a reading of a diff, not a proof about it: what is machine-checked is stated in
`modules/review/portability_test.go`, and what that test does *not* cover — every
claim in the paragraphs above about intent, disclosure and threat model — is
prose, and should be read as prose.
