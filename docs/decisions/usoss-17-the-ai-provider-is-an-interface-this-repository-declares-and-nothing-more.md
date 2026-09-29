## USOSS-17 — the AI provider is an interface this repository declares, and nothing more

`security/agent_scan.go` and `security/agent_fix.go` both depend on the source's
`internal/ai` package: `SecurityScanner`, `SecurityFixer`, `ScanRequest`,
`PriceUsageMicrosTier`, and the request and result types around them. The ticket
asked for a written decision between porting that package, abstracting it, or
vendoring it. **It is abstracted.** `modules/review` declares [`Scanner`] and
`modules/fix` declares [`Fixer`], each with the narrow shape its own module
needs, and neither package contains a line of provider code.

### Why not port it

Three reasons, in increasing order of how much they matter.

The smallest is size and dependency weight. `internal/ai` is **4,846 lines
across 12 files** (`wc -l backend/internal/ai/*.go` in the source tree at
`b626d3497057955d222da805be5be81ba6109876`), of which the two modules use two
types and a pricing function. Porting it would add a direct dependency on one
model vendor's SDK to a repository that has none today — **the ticket's premise
that "the repo already depends on `anthropics/anthropic-sdk-go v1.44.1`" is
about the source repository's `go.mod:6`, not this one; `grep anthropic go.mod`
here returns nothing.** For a public repository a direct dependency is a
constraint on every adopter, so acquiring one is a decision rather than a
consequence.

The middle reason is that the seam is where an adopter differs from us. A
capability whose whole content is "ask a model to look at this code" is the one
place a different organisation will have a different answer, and an interface
costs nothing to leave open.

**The largest reason is disclosure, and it is the one that would decide this on
its own.** `internal/ai` is where the detection strategy lives: the system
prompts that say what counts as a finding, the tool loop that decides what to
read, the iteration and byte budgets that bound how hard it looks. Published,
those describe the shape of what this scanner does and does not notice. The
project has already ruled that way once, for the same reason — honeytoken
providers are not ported because publishing a detection mechanism publishes its
evasion — and the same reasoning applies here. Abstracting the provider is not
merely the tidiest of the three options; it is the one that keeps the heuristics
out of a public repository **by construction**, because there is no file for
them to be in.

That last clause is the load-bearing one, and it was not true on the first
attempt: three identifier literals from the source scanner's prompt had been
reproduced in a doc comment and a test fixture. The remedy is not to soften the
claim but to check it — `internal/disclosure` walks the module tree for the
shapes such an identifier takes. Removing the file the heuristics could live in
removes the easy way to publish them; it does not remove every way, and the
difference between those two is now a gate rather than a hope.

### What moved with the interface

Pricing did. The source computes a per-scan cost inside the module, from a rate
card resolved out of an administrative record (`agent_scan.go:448`,
`agent_fix.go:325`). Here the provider reports its own cost, as
[`review.Cost`], and the module only records what it is told. A module that
carries a price table cannot be pointed at a different provider without lying
about what it costs, and a rate card in a public repository is stale the week it
is written.

### What this does not settle

An adopter still has to write a scanner. This decision does not claim that is
small; it claims it is theirs. `modules/review` and `modules/fix` declare what a
provider must do, in `scanner.go` and `fixer.go` respectively, and this
repository ships no implementation of either. That is a real gap in what an
adopter can run out of the box, and it should become a ticket rather than be
discovered.
