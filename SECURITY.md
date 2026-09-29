# Security policy

AppHub vends credentials and provisions cloud infrastructure. A bug here can
be a production incident in somebody else's account, so we would much rather
hear about a suspected problem that turns out to be nothing than not hear about
a real one.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Two private channels, either is fine:

1. **GitHub private vulnerability reporting** — the *Report a vulnerability*
   button under this repository's **Security** tab. This keeps the report,
   the discussion, and the eventual advisory in one place.
2. **Email** — <security@c1.ai>. This is ConductorOne's published security
   contact; see <https://www.c1.ai/.well-known/security.txt>.

Please include, as far as you can determine it:

- what the issue is and which package or file it is in;
- how to reproduce it, ideally as a failing test or a minimal program;
- what an attacker gets out of it, and what they need to start with;
- any version, commit, or configuration that matters.

## What to expect

- We aim to acknowledge a report within **three business days**.
- We will tell you our assessment of severity and our intended fix, and we will
  tell you if we disagree that it is a vulnerability, rather than going quiet.
- We will credit you in the advisory unless you would rather we did not.

Please give us a reasonable window to ship a fix before disclosing publicly.
We are not going to threaten anyone with lawyers for good-faith research.

## Scope

This repository is **pre-release and not yet published**. There are no
supported versions and no security updates for tagged releases, because there
are no tagged releases. Reports against `main` are in scope.

Out of scope: findings in the internal ConductorOne services AppHub was
extracted from — report those through <https://www.c1.ai/security> instead.

## What we consider a vulnerability here

Beyond the obvious, these are specifically in scope because of what this
codebase does:

- credential material appearing in a log line, an error message, a panic, or a
  file outside a documented secret store;
- a generated IAM policy, role trust policy, or bucket policy that is broader
  than the operation needs;
- an SSRF in anything that fetches a caller-supplied URL, command injection in
  anything that shells out, or path traversal in anything that takes a filename;
- a provider that fails open — proceeding when it cannot verify something it
  claims to verify.

## Accepted trust-boundary limitations

These are documented limitations rather than provider vulnerabilities:

- **AWS ownership by tag is account-scoped.** The AWS provider's ownership
  checks read exact reserved tags such as `apphub:managed-by=apphub` and a
  component tag. That proves the resource is inside the AWS account/trust
  boundary that controls tag writes; it does not prove which process wrote the
  tags. Anything in the same AWS account that can tag a bucket with the reserved
  marker can present that bucket as AppHub-managed. Cross-tenant deployment on
  one shared AWS account is not supported unless the tenants share that trust
  boundary; otherwise isolate tenants by AWS account or by an equivalent
  tag-write boundary.

## Secrets in this repository

CI runs `gitleaks` over the working tree **and the full git history** on every
pull request, and no workflow is permitted to reference the secrets context
(`make hermetic` enforces this). If you believe a secret was nevertheless
committed, report it through the private channels above rather than opening an
issue: history is public once the repository is, and the correct response is to
rotate the credential first.
