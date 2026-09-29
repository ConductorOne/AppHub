## USOSS-4 — the Go toolchain floor is go1.26.6, and it is pinned everywhere

For a public repository the Go floor is a constraint on every adopter, so it is
recorded as a decision rather than left as a version tick.

**What is pinned, and why it cannot drift.** `go.mod` names the toolchain, the
Makefile exports `GOTOOLCHAIN` read from that same line, and CI's `setup-go`
reads the same file. A local `make vuln` and the CI job therefore analyse the
same standard library. They did not before, and the divergence was not
cosmetic: with `GOTOOLCHAIN` at its default, a developer whose Go is newer than
the floor saw eight standard-library advisories that CI never reported,
attributed to the module's declared toolchain rather than the one doing the
work. A security check that disagrees with CI is a security check people stop
reading.

**Why 1.26.6 rather than staying at 1.25.13.** Honestly, and this matters
because the record should not carry a justification that does not hold:

- The reason offered was that introducing the first HTTP-calling dependency
  turns five standard-library advisories from "not called" into "called". **I
  could not reproduce that.** A synthetic module using the real AWS SDK v2
  DynamoDB client and `config.LoadDefaultConfig` reports no called
  vulnerabilities at go1.25.13, with `GOTOOLCHAIN` verified to be taking effect.
  The originating pull request's own CI job also passes at the 1.25.13 floor.
  The eight-advisory symptom appears to have been the local/CI drift described
  above, which is now fixed.
- What the bump is actually for: **every stacked branch runs one toolchain.**
  Several pull requests are in flight against this base, one of them already
  pinning 1.26.6. Branches disagreeing about the Go floor is a worse problem
  than the floor being one minor version higher than strictly necessary, and it
  is a problem the base is the right place to solve.
- Secondarily, staying on a current patch line is cheap defence in depth for a
  repository that vends credentials.

So: the coordination reason is the real one, and it is sufficient. If the
originating pull request has reachability evidence I could not reproduce, that
strengthens the case rather than changing the decision.

**The originating pull request's measurement, added on request (USOSS-5).** It
does not change the decision, and it confirms the correction above rather than
disputing it:

- At go1.25.13, `govulncheck` on the DynamoDB branch reports **no**
  vulnerabilities. USOSS-4 is right, and the claim that the SDK made the bump
  necessary was wrong. `make vuln` was never red at the old floor.
- Forced onto go1.26.5 — the Go that environment had installed, newer than the
  old floor — the same branch reports **five**, with traces through
  `store/credentials.go` and `credentials/secret.go`.
- Forced onto go1.26.5, this base with no DynamoDB anywhere reports **one**,
  GO-2026-5972, reached by `internal/boundary` calling `exec.Command`.

So the SDK does widen the reachable standard library — one advisory becomes five
on an identical toolchain — but that is a statement about surface area, not about
the floor. Whether any of it surfaces depends entirely on which Go is doing the
work, which is exactly the drift this entry closes. The 1→5 figure only explains
why the symptom appeared on that branch first: it is the branch that made
`net/http`, `crypto/tls`, `encoding/xml` and `net/url` reachable at all.

**Contributors with an existing `.tools/` must run `make clean tools`.**
`go-licenses` classifies the standard library by the GOROOT it was itself built
against, so a tool binary built by a different toolchain than the module reports
every standard-library package as missing module info. Pinning `GOTOOLCHAIN`
across all Make targets means freshly built tools match the module from now on;
already-built ones do not.

go1.26.7 was published while this was being written. Moving to it is a
follow-up, not a blocker — the point of this entry is that the floor is a
decision and that one value governs the Makefile, CI, and `go.mod` together.
