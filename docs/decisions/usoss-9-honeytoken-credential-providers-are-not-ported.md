## USOSS-9 — honeytoken credential providers are not ported

*Recorded from USOSS-9, which the ticket asked for explicitly: "Written decision
on whether honeytoken providers ship publicly." The standing project decision
already excluded them; this is the reasoning, plus a correction to the ticket's
premise.*

`backend/internal/credentials/honeytoken_aws.go` and `honeytoken_github.go` are
**not ported**, and the interface is nevertheless required to accommodate their
shape — which it does: a honeytoken provider is a `CredentialProvider` that vends
short-lived STS credentials against a trap role, reports
`ErrRevokeNotSupported`, and answers `CredentialStatusUnknown`. Nothing in
`credentials` or `credentials/aws` would have to change to add one.

### Why not

A published honeytoken implementation is a published detection strategy. The value
of a trap credential is entirely in an adversary not recognising it as one, and the
source's own design says where the recognisable parts are: the session name is
prefixed so the trap origin is "self-evident in the audit trail"
(`honeytoken_aws.go:132-136`), and the subject claim format "mirrors the Claude
provider so a single trust policy can author both audiences"
(`honeytoken_aws.go:146-148`). Both are deliberate and both are exactly what a
reader of a public repository would use to tell a trap credential from a real one.

That is a different kind of harm from the rest of this extraction. Publishing a
deploy path tells an adversary how the system works; publishing a deception path
tells them how not to be caught by it.

### A correction to the ticket

The ticket says: "Any sentinel account ID or trap-role ARN in
`honeytoken_aws.go` — **must not** be published under any circumstances."

There is no sentinel account ID or trap-role ARN in that file. The trap role
arrives as operator configuration (`role_arn`, read from the provider config at
`honeytoken_aws.go:105-112`), the region defaults to a public AWS region name, and
the session prefix is two letters. So the disclosure this instruction guards
against is not present, and the decision not to port rests on the strategy
disclosure above rather than on an identifier.

The instruction is still worth keeping as a standing rule for anyone who later
reads that file: it is right about the class even though this instance is clean.

### What was carried across instead

Two things from the honeytoken provider are reused in the ported code, because
they are good and not secret:

- Its statement of the caller's obligation — that the requester identity flowing
  into a subject claim comes from the authenticated handler and "NOT the untrusted
  vend request body" (`honeytoken_aws.go:41-45`) — is now the documented obligation
  on `credentials/aws`'s web identity path, asserted by
  `TestTheWebIdentitySubjectIsWhateverTheCallerSaid` rather than left in a comment.
- Its refusal to fall back to long-lived credentials when federation is not
  configured. The Bedrock path expresses that at construction instead of at run
  time: whether web identity federation is used is decided by which option was
  passed, so there is no fallback in either direction.
