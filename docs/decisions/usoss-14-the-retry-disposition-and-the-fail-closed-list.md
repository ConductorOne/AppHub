## USOSS-14 — the retry disposition, and the fail-closed list

### Retry

`awsutil.Retry` is **not ported**, and this ticket adopts USOSS-10's disposition
without amending it: classification into `compute.ErrTransient` happens in this
package, and the actual retrying is delegated to the AWS SDK's standard retryer
on the caller-supplied client, which `NewSDKSubstrateFrom` refuses to accept
without. `Provider.substrateError` and `classify` are reused rather than
duplicated — `ErrAlreadyExists` maps to `ErrTransient`, not `ErrNotOwned`,
because a create that raced another create is not a collision with somebody
else's infrastructure.

Two things this ticket adds to that disposition:

* The source's polling loops are gone rather than ported.
  `ensureAuroraCluster` blocks for up to ten minutes in one loop and
  `ensureAuroraInstance` for another ten (`database.go:323-346, :380-401`); the
  interface makes readiness a separate `Wait` with a caller-chosen deadline, so
  the provider returns `PhasePending` and the caller decides how long to wait.
* The poll interval is `Config.PollInterval`, defaulting to
  `DefaultPollInterval` (five seconds). An earlier version of this entry said the
  interval was one millisecond, right for the in-memory substrate and wrong for a
  real account, and that "if one needs it, it belongs in `Config`" — review round
  one made that a blocker rather than a note, correctly: the old comment claimed
  the SDK's retryer made a millisecond loop polite, and a retryer bounds failures
  rather than throughput. It is in `Config` now, floored at `MinPollInterval` and
  still bounded by the caller's remaining deadline, and the hermetic suite sets a
  millisecond in the test's own configuration rather than in the default.

### Where this port fails closed, deliberately

Each of these is a behaviour change from the source, and each is a place the
source either widens or continues:

* A `PeerInternet` or `PeerPlatformIngress` rule on a database endpoint is
  refused. There is no code path in this port that produces a security-group rule
  with a CIDR source at all.
* A `PeerControlPlane` rule on a placement configured with no control-plane
  security groups is refused. The source skips an empty entry silently
  (`database.go:207-210`); the two ways to not satisfy the rule are a connection
  that times out with no diagnosis — which the source documents having hit
  (`database.go:200-205`) — and a port open to everything.
* Ingress is reconciled, including revocation. The source has no revoke on this
  path, so a rule it wrote outlives the spec that asked for it: "I removed that
  rule" silently means "I stopped asking for it", which is a security control
  failing open.
* Storage encryption is unconditional and there is no configuration for it.
* A capacity range that does not land on an Aurora Serverless v2 half-ACU step is
  refused rather than rounded. Fourth port in this package to refuse rather than
  round, after ECR retention (USOSS-10) and SSM parameter tiers (USOSS-26).
* TLS to the database defaults to `verify-full` and a verifying mode with no root
  certificate is refused rather than downgraded. The source uses
  `sslmode=require` (`postgres_roles.go:40`), which encrypts and verifies
  nothing: it stops a passive observer and does nothing at all against an active
  one, while carrying the database's master password.
* A password containing a NUL byte is refused rather than stripped, and a role
  type the package does not define is refused rather than defaulted.
* A failure to enable row-level security is fatal. The source logs a warning and
  continues (`postgres_roles.go:96-100`), so a role that asked for it and did not
  get it reads rows a policy was written to hide, on a deploy that reported
  success.

### The physical-name grammars, collected

Every AWS port needs a digest marker legal in its own substrate's grammar, and
there is no single character that works everywhere. Collected here so the next
port does not re-derive it:

| Substrate | Forbids | Marker |
|---|---|---|
| ECR repository | `--` | `.` |
| IAM role | — | `.` |
| DynamoDB table | — | `.` |
| DB subnet group | — | `.` |
| EC2 security group | a leading `sg-` | `.` |
| RDS cluster / instance | `.` **and** `--` | `-`, with the verbatim set excluding a digest tail |
| ECS service / task family | `.` | `_` or `-` (USOSS-11) |
| ELBv2 / Lambda | `.` | (USOSS-12) |

RDS additionally requires an identifier to **begin with a letter**, which
`sanitizeWith` cannot supply without breaking injectivity — prepending a letter
when the head starts with a digit makes an application named `d9lives` collide
with one named `9lives`. It is supplied instead by requiring a letter-led
`Config.Relational.NamePrefix`, validated in `New`, so the property holds for
every name by construction. `TestRDSIdentifiersAreInjectiveAndLegal` asserts the
**conjunction** over the shared corpus, because a name that is injective and
illegal is a deploy-time failure and one that is legal and not injective is two
applications sharing a database.
