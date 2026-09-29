## USOSS-64 — IAM user names stay derived from the credential name, not the idempotency key

*Follow-up from USOSS-9 / PR #41. Proposed by the USOSS-9 author: derive the IAM
user name from `credentials.CreateRequest.IdempotencyKey` instead of from the
request's name, so a retried vend converges on the same IAM principal instead of
creating a second one. `provider.go`'s `Capabilities` comment already names this
as the reason `RecoverCreate` is false and defers it to "its own ticket". This
entry is that evaluation, and the answer is: not yet, and not as a small change.*

### What the proposal actually requires

Converging on one principal is not just a different input to `sanitize` — three
things have to hold together, and USOSS-64 is a follow-ups ticket, not a
redesign:

1. **The naming function would have to become injective.** `names.go`'s
   `sanitize` is deliberately the opposite today:

   > "It is not injective, and that is safe here for one specific reason [...]
   > the mapping cannot be inverted and must never be used to *find* a resource
   > — and it is not: the IAM user name travels in the platform key ID."

   `ResolveCreate(ctx, idempotencyKey, metadata)` is exactly "find a resource by
   re-deriving its name", so it needs the opposite property from what `sanitize`
   was built to guarantee. `compute/aws` already carries the machinery for that
   — `sanitizeWith` plus a per-grammar digest marker, argued sound in
   USOSS-12/USOSS-13/USOSS-14 — but porting it here is porting a second naming
   discipline into a package that took the simpler one on purpose, not a
   two-line change to what a name is derived from.

2. **A recovered user is not a recovered secret.** Even with a deterministic
   name, `ResolveCreate` can find that a user exists; it cannot recover an
   access-key secret or a Bedrock static password, because IAM returns each
   exactly once at creation and never again. Every other provider in this
   package family declines `CreateRecoverer` for precisely this shape —
   `credentials/datadog`, `credentials/github`, and `credentials/c1` each say,
   in their own words, that `CreateRequest.IdempotencyKey` "has nothing to be
   forwarded as". Making AWS's `CreateUser` idempotent by name does not change
   that for `CreateAccessKey` or `CreateServiceSpecificCredential`. A real
   `ResolveCreate` would have to decide what "recovered" means when the material
   is gone — rotate the key and hand back a new one, most plausibly — and that
   is a new capability decision, not a naming tweak.

3. **The name an operator sees would change**, as the existing comment already
   states, which is a compatibility question of its own.

### Decision

Declined for this ticket. `Capabilities.RecoverCreate` stays `false`, `Provider`
implements no `credentials.CreateRecoverer`, and `lifecycle.CheckIssuable`
continues to require `ProviderPolicy.AllowUnrecoverableIssuance` before issuing
through this provider — the same interim answer every sibling provider in this
repository gives for the same reason. If this is picked up, the ticket for it
inherits three obligations from this record, not one: an injective naming
scheme argued sound the way `compute/aws`'s is, a stated answer for what
`ResolveCreate` returns when the secret itself is unrecoverable, and a note on
the operator-visible name change.
