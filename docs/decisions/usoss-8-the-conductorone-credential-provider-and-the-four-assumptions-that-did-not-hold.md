## USOSS-8: the ConductorOne credential provider, and the four assumptions that did not hold

The design in `docs/design/credential-vending.md` was drawn without access to a
ConductorOne vending API: the source repository this project ports from calls
ConductorOne only for directory and entitlement data and contains no vending calls
at all, so §9 listed ten consumer-declared assumptions and made verifying them
this ticket's first job. Six hold, two hold with a condition, one does not apply,
and **one is false**. §9 now records a verdict and its evidence for each.

The false one is A4 — idempotent creation, resolvable afterwards by the caller's
key — and it is the one with a consequence rather than a caveat. ConductorOne's
create request has no idempotency key, and there is no operation that resolves a
creation by one. Compounding it: the credential's secret half is returned exactly
once and is documented as not retrievable afterwards. Those two together mean a
vend whose response is lost leaves a live credential that **cannot be found
again** — unrecoverable by construction, not merely unsupported.

### The provider declares that rather than working around it

`credentials.Capabilities{RecoverCreate: false}`, and no
`credentials.CreateRecoverer` implementation. `lifecycle.CheckIssuable` then
refuses managed issuance through this provider unless an operator sets
`ProviderPolicy.AllowUnrecoverableIssuance`, which is the visible form of the risk
rather than the hidden one.

The alternative was a `ResolveCreate` that guesses — list the service principal's
credentials, match on the display name AppHub chose. It was rejected because a
guess that is usually right is worse here than an admitted gap: the lifecycle
layer admits issuance on the strength of that interface, and a wrong match would
hand the platform a handle for somebody else's credential to revoke.
`TestProviderDoesNotClaimToRecoverAnAmbiguousVend` asserts the absence as a
compile-time fact, so adding such a method is a test failure rather than a quiet
change of posture.

### Three shapes the design described that the API does not have

Each deletion from `credentials/c1.Client` is a capability the design assumed and
the API does not offer. Keeping the shape would have meant a provider whose
declared capabilities were claims rather than facts.

* **`ResolveVend` is gone.** See A4 above.
* **`Subject` and `Target` are gone.** A ConductorOne credential belongs to a
  *service principal* — a non-human identity — and the create request carries no
  separate requester, no application id and no entitlement id. So
  `CreateRequest.RequesterID` and `RequesterType` are not expressible on this
  surface at all, and the design's claim that the subject "is the anchor for every
  access decision on the ConductorOne side" does not hold for vending. Which
  service principal to mint against arrives in
  `credentials.Metadata["c1_service_principal_id"]`, required and with no default.
* **`GrantStatus` is gone.** The credential has no status field. Liveness is an
  expiry timestamp plus whether the credential is still returned at all.

### Status can report three of four states, and that is the API's limit

`GetCredentialStatus` returns active (returned, expiry in the future), expired
(returned, expiry passed) and unknown (not returned, or returned with no expiry).
**Revoked is not reachable**, because a revoke deletes the credential rather than
tombstoning it and an absent credential cannot be told apart from one that lapsed
and was cleaned up.

Reporting revoked for an absent credential was rejected: it is the platform
concluding a credential is dead on the strength of a 404, which is the rule the
design already states for an unrecognised grant. Nothing depends on deriving it —
`lifecycle`'s own rule is that only a successful upstream revoke finalises a
record as revoked. `TestStatusIsTheDocumentedFunctionOfWhatTheUpstreamSaid`
asserts all three reachable states occur *and* that revoked never does, so if
ConductorOne grows a revoked-but-present state the mapping has to be revisited
rather than silently continuing to under-report.

### Revoke is real, and the handle is why

A1 and A3 both hold: the credential has a stable identifier and `DELETE` destroys
it, and unlike the GitHub App path the caller does not need the material to
authenticate the call. So this provider never returns
`credentials.ErrRevokeNotSupported`, and `TestRevokeNeverReportsThatItIsUnsupported`
drives every failure mode of the revoke path to keep it that way — a provider that
quietly acquired that sentinel would be telling the lifecycle layer that a leaked
credential can only be left to expire.

**The handle carries both halves of the upstream reference, and that is a security
decision rather than a convenience.** ConductorOne addresses a credential by
`(service principal, credential)`, and `credentials.CredentialProvider` hands
revoke a single opaque `platformKeyID`. The rejected alternative was to take the
service principal from per-call `credentials.Metadata` — under which a caller
supplying the wrong principal would revoke against the wrong one, and because
revoking something absent succeeds, it would report a **successful revoke having
revoked nothing at all**. A credential system that lies about revocation is worse
than one that admits it cannot revoke, so `RevokeCredential` ignores metadata
entirely and `TestRevokeIgnoresMetadataEntirely` pins that.

The handle's grammar is this package's own and deliberately not a restatement of
ConductorOne's identifier formats, which are both narrower. Pinning theirs would
make an upstream identifier change a parse failure in AppHub — a hand-maintained
restatement of somebody else's grammar, which this project has already paid for.
What the grammar asserts is only what path construction needs, it has exactly two
outcomes on every input, and there is no tolerant path that strips or normalises.

### Least privilege is checked, not trusted

The granted scope is documented as the intersection of the request with the
service principal's own roles, so it cannot introduce a role. It is compared
anyway, because "may narrow, never widen" is the one direction of the rule that
cannot be recovered from after the fact and the check costs a set comparison. A
credential wider than the request is **revoked here** rather than returned — the
only place in this provider where it compensates on its own, and the reason is that
handing the credential over is the harm, so there is nothing honest to give the
lifecycle layer to decide about. If the compensating revoke fails, the handle
travels in a `credentials.CreateNotDeliveredError` so the live over-privileged
credential can still be destroyed.

An empty requested scope is not compared: it means "do not narrow", and comparing
the principal's own roles against an empty request would report every one as a
widening and make the check fire on every ordinary vend. Both halves are tested,
because a check that fires on everything is indistinguishable from one that works.

### Missing material is not compensated here, which diverges from the design

`docs/design/credential-vending.md` §3 told this provider to attempt a best-effort
revoke of a partial grant. It does not. It returns
`credentials.CreateNotDeliveredError` carrying the handle, matching
`credentials/datadog`, whose reasoning is better and predates nothing: a provider
that quietly revoked on its way out of an error would be making the lifecycle
layer's decision where nobody can see it. The design's instruction predates
`CreateNotDeliveredError` existing. The divergence is deliberate and is called out
rather than left as a silent inconsistency between two providers.

A response missing *either* half is undelivered, not just one missing the secret: a
consumer needs the client id and the client secret to authenticate, so a response
with a secret and no client id is equally unusable.

### `Client` is sealed

`credentials/c1.Client` carries an unexported method, so only this package can
implement it. USOSS-3 declared it as "the surface a fake will implement in tests",
and this is a deliberate departure.

`Provider` forwards a `Client`'s error to its own caller. An implementation from
outside the package is therefore an API that accepts arbitrary text and renders it
back out — exactly the defect the USOSS-7 review found four times, and which
`credentials.Foreign` and `credhttp.Op` were built to make inexpressible. The
error-hygiene fixture found it by driving `Provider` with a nonconforming
`Client`, and a fifth comment saying "an implementer must not put foreign text in
an error" would have been the fifth iteration of the mistake. Closing it by
removing the input is what the boundary checker needed after being defeated inside
the abstraction built to stop it.

Nothing is lost. Fakes live at `Deps.Transport`, which is where
`credentials/datadog` and `credentials/github` put theirs, and every provider test
now exercises the real request construction, path escaping and response decoding on
its way to the behaviour it is about. An adopter who wants to vend from somewhere
other than ConductorOne implements `credentials.CredentialProvider`.

### `Config.Timeout` is honoured through the context, and that is the whole mechanism

`internal/credhttp`'s thirty-second timeout is a fixed backstop a caller cannot
change, because a timeout is a field on `http.Client` and the fields of
`http.Client` are what the USOSS-7 review defeated twice. So every request wraps
its context with `Config.Timeout()`, the shorter of the two deadlines wins, and a
configured timeout above thirty seconds does not take effect.
`TestTheConfiguredTimeoutReachesEveryRequestContext` asserts the deadline the
transport observes, over a population of timeouts, rather than asserting that a
call eventually failed.

### Four refusals in `credentials/c1/config.go` were rendering operator-supplied text

Found by stating the standing error-content invariant over this package, on code
that has been on `main` since USOSS-3 and had passed two reviews: `Validate`
rendered the rejected URL scheme and the rejected auth mode, and `ConfigFromEnv`
rendered the rejected duration string and `time.ParseDuration`'s own message.
Each is now a sentinel plus the name of the environment variable, which is a
constant in this repository and is the half that actually locates the mistake. An
operator who pasted the OAuth client secret into `APPHUB_C1_REQUEST_TIMEOUT`
would have had the front of it printed.

### The invariant is stated locally, and that is a boundary decision

`internal/errhygiene` holds this invariant for five packages, and adding a sixth
is a two-line change to its package list. It is not that change: driving an entry
point means calling it, calling into `credentials/c1` means importing it, and the
`c1-optional` rule deliberately covers first-party *test* imports so that a test
cannot be the wedge that widens it. The one allowlist entry this ticket adds is the
composition root; a second requires supervisor approval, and a test fixture is not
a good enough reason to spend it.

So `credentials/c1/errhygiene_test.go` states the same invariant by the same
method — a surface derived from `go/types`, a driver or an explicit exemption for
every entry point, cross-checked in both directions, and two equal-length sentinels
sharing no byte at any position. The duplication is real. Unifying the two by
making `internal/errhygiene` an importable helper that a package's own test drives
itself with — which reverses the import direction and needs no allowlist entry — is
the follow-up, and is USOSS-7's own candidate ticket made concrete.

### Sixteen mutations, and three of them were the fixture's fault

Every mutation below fails before the fix and passes after. Three are recorded
separately because they were **not** caught on the first run, and each was a
population that contained only shapes the implementation already handled:

* no transport returned a 200 whose body would not decode, so a forwarded
  `encoding/json` diagnostic — which quotes one byte of its input — passed
  everything;
* the bare sentinel is *inside* the handle grammar, so the driver never reached the
  refusal that rendered a rejected service-principal id;
* no request exceeded the upstream's 32-role scope limit, so a refusal that listed
  the roles instead of counting them passed.

That is the shape this project has now paid for repeatedly, and it is worth
recording that it appeared again here, in a fixture written specifically to avoid
it. Stating the property is necessary and is not sufficient: the population has to
straddle the boundary the property is about.

### The binary-level claim, and the half of it that is still owed

`docs/design/credential-vending.md` §11.2 lists three package-level mechanisms
behind the ConductorOne-optional guarantee and says a fourth is owed at the binary
level, because package-level evidence would not catch a binary that refuses to
start without ConductorOne configuration. `cmd/apphub` is the one allowlisted
composition root and `cmd/apphub/main_test.go` compiles it and runs it in a
separate process with an **empty** environment, asserting that it starts, registers
the providers that need no configuration, and reports ConductorOne as unconfigured
— with the control in the other direction, so the test is not satisfied by a binary
in which ConductorOne support does not exist.

§11.2's obligation is "starts **and vends** through the AWS-native path". The
vending half is not delivered and is not counted as delivered: `credentials/aws` is
a stub until USOSS-9, and vending needs credentials no CI environment has. It stays
open.
