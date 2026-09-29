# Credential vending contract

Status: design, revised after independent review of PR #2, and revised again by
USOSS-8 after its assumptions were checked against ConductorOne's own API. The
neutral interface and the lifecycle contract are settled. `credentials/c1.Client`
is **no longer provisional**: §9 records a verdict and its evidence for each of
the ten assumptions, and the four that did not hold as stated changed the client's
shape rather than being worked around. See `docs/DECISIONS.md`.
Ticket: USOSS-3
Normative dependency: `/shared/apphub/contracts/workload-identity.md` — supervisor-owned, authoritative over §5
Depends on: USOSS-1 (ConductorOne optional, AWS-native path first-class)
Implemented by: USOSS-7 (providers, issuer, reconciler), USOSS-8 (ConductorOne provider), USOSS-5 (persistence)

This document specifies the whole credential contract: the neutral interface, the
persistence and lifecycle half that the ticket's scope did not originally include,
the ConductorOne wire contract, the authentication model, failure semantics, the
security properties, and what an adopter has to configure.

Everything here was derived by reading the source checkout at `49b7628`. File and
line references point into that repository unless they name a path in this one.
**Every claim about ConductorOne's vending API began as an
assumption** — the source repository calls ConductorOne only for directory and
entitlement data and contains no credential-vending calls at all — and §9 now
records how each one turned out. Where this document and the code disagree about
ConductorOne, the code is the one that was checked against the API.

---

## 1. Does `CredentialProvider` survive?

Yes. The interface is genuinely cloud-neutral and its six methods are unchanged:

```go
type CredentialProvider interface {
	ID() string
	Name() string
	CreateCredential(ctx context.Context, req CreateRequest) (*CreateResult, error)
	RevokeCredential(ctx context.Context, platformKeyID string, metadata Metadata) error
	GetCredentialStatus(ctx context.Context, platformKeyID string, metadata Metadata) (CredentialStatus, error)
	SupportsDynamic() bool
}
```

Verified before accepting the claim: four of the six providers in the source have
no AWS import at all — including `datadog.go` and `github.go`, the two non-AWS
providers in v1 scope — the interface signature names no cloud type, and
`registry.go` is a `map[string]CredentialProvider` that imports no provider.
ConductorOne fits it as one implementation among several. Nothing outside
`credentials/c1` needs to know ConductorOne exists.

On scope: three of the source's six providers are in v1 (`claude.go`,
`datadog.go`, `github.go`). The other three are excluded by project decisions
recorded outside this repository. Those exclusions constrain what gets *ported*;
they must not constrain the interface, and §10 says why.

Six deltas, all additive, none of which changes a method signature's shape or adds
a method only one provider can implement.

### D1 — `Secret` and `Metadata` types for credential material

`credentials.Secret` replaces `string` for material (`CreateResult.APIKey`,
`CreateResult.Credentials`); `credentials.Metadata` replaces `map[string]string`
for the provider-configuration bag. Both redact under every `fmt` verb and under
`log/slog`, and both refuse to marshal to JSON or text.

The reason is that this repository is going public and its entire job is handling
credentials, so "do not log material" needs a mechanism and not just a rule. The
source system's `CreateResult.APIKey` is a `string`, `CreateRequest.Metadata` is a
`map[string]string` holding `admin_api_key` and RSA private keys, and one `%+v`
anywhere in a call chain prints them. The types make the accidental cases — a
struct dump, a wrapped error, a response type that grew a field, an
`slog.Any` — fail safe.

Cost, stated honestly: `Metadata` is free, because it is a `map[string]string`
underneath and ported code that does `req.Metadata["region"]` or ranges over it
needs no change at all. `Secret` costs one `NewSecret` per provider at the point
material is produced and one `Reveal` at each of the few points material is
delivered. Those `Reveal` call sites are the audit list for "where does material
cross a boundary", which is worth having as a grep.

#### `Secret` is an opaque struct, not a defined string

The first version was `type Secret string` with redacting methods. A review
fixture broke it three ways; each was reproduced before being fixed:

| Vector | Result against the defined string type |
| --- | --- |
| `gob.NewEncoder(&buf).Encode(secret)` | wrote the raw material, no error |
| `reflect.ValueOf(secret).String()` | returned the raw material |
| `text/template` `{{.Reveal}}` | invoked the exported method, returned the raw material |

One cause, three symptoms: a defined string type hands its underlying value to
anything that inspects *kind* rather than methods. So `Secret` is now a struct
with unexported fields, `GobEncode`/`GobDecode` fail closed, and `Reveal` is a
**package-level function** — a template can call any exported method by name, and
cannot call a function.

A fourth vector appeared while fixing the first three: `reflect.Value.Bytes` does
**not** panic on an unexported field, so a single accessor on a plain `[]byte`
field still returned the material. The material is therefore held XOR-masked
across two unexported slices with a per-`Secret` random mask. That is not
encryption — the mask sits next to the value — and is not presented as such. It
buys one thing: no single generic accessor returns anything usable, so recovering
the value takes a deliberate combination of two fields.

`Secret` implements `fmt.Formatter` rather than only `String()` because `fmt`
formats `%q` against the underlying kind and never consults `fmt.Stringer`.

**What this defends against:** accidental exposure — generic serializers, log and
error formatting, reflection-based dumpers, template rendering. Each fails closed.
**What it does not:** code in the same process that is trying to read the
material. `reflect` can combine the two fields, `unsafe` reads them directly, a
memory dump contains both, and a provider that writes `Reveal(s)` into an error
message defeats the type entirely. It is a guardrail, not a vault, and
`credentials/secret_test.go` asserts both halves — including a test that
*documents* the residual reach rather than pretending it is closed.

`Metadata` keeps its map shape, because that shape is what makes it free for
ported providers, and gains the same `GobEncode` refusal. Its residual exposure is
stated on the type: a map's values are reachable by reflection, so `Metadata`
stops the formatting, logging and serialization leaks but cannot stop code that
walks it deliberately. Material needing more than that belongs in a `Secret`.

### D2 — `Capabilities`, as an optional interface

`SupportsDynamic()` answers one of six questions. The others — can this provider
revoke, report status, rotate, recover an ambiguous create, or vend static at
all — are otherwise answered by trying and inspecting the error. That works for
the reconciler and not for a user interface, an operator, or a conformance suite.

`credentials.Capabilities` plus `CapabilityReporter` (discovered by type
assertion) declares them. Widening `CredentialProvider` itself would have broken
every provider for the benefit of one — including providers outside this
repository, which is the case that makes the optional-interface form not merely
convenient but required (§10).

**The inference for an undeclared provider is not uniformly conservative**, because
"conservative" points in opposite directions depending on the cost of being wrong:

| Inferred | Value | Why |
| --- | --- | --- |
| `Revoke`, `Status` | true | Attempting an unsupported revoke costs one call and an error the lifecycle already handles. Skipping a revoke that would have worked leaves a live credential. |
| `Static` | **false** | A static credential is one the platform must tear down itself. Issuing one through a provider of unknown capability risks a credential that nothing can revoke and nothing expires. |
| `Rotate`, `RecoverCreate` | false | Claiming either wrongly means claiming an action happened that did not. |

The first version of this inference returned `Static` and `Revoke` both true, which
is the most dangerous combination available — the review was right to call that
the wrong direction to fail.

**Consequence for USOSS-7:** `datadog` is a static-only provider, so it must
implement `CapabilityReporter` (`Static: true, Revoke: true`) as part of the port.
It does support revoke — `datadog.go:115-139` — so this is a declaration of
existing behavior, not a change to it. The dynamic providers port untouched.

### D3 — Scope and idempotency fields

**Read the ConductorOne outcome first if you are implementing against this**: §9's
A4 is false, so `IdempotencyKey` reaches ConductorOne nowhere and the interface's
own note about the consequence — that such a provider cannot implement
`CreateRecoverer` — is the operative one for `credentials/c1`. `RequesterID` and
`RequesterType` are likewise unrepresentable there: a ConductorOne credential
belongs to a *service principal*, and the create request has no field for who
asked for it. Both fields remain in the interface, because a provider that can
honour them is the ordinary case and dropping them would narrow the contract
around the one provider that cannot (§10).

`CreateRequest` gains `RequestedScope []string` and `IdempotencyKey string`;
`CreateResult` gains `GrantedScope []string`. Least privilege needs a way to ask
for less and a way to record what was actually granted; a provider that can mint
needs a way to not mint twice when a caller retries a timed-out request. Both are
ignorable by providers whose upstream has no such notion.

### D4 — `ErrTransient`, `ErrStatusNotSupported`, `ErrCreateNotFound`

`ErrRevokeNotSupported` already exists and is load-bearing. Its siblings were
missing: the reconciler's retry decision currently rests on "any error that is not
`ErrRevokeNotSupported` is worth retrying", which retries permanent failures
forever, and an ambiguous vend needs a way to be told "nothing was created".
Providers now mark retryable failures explicitly.

### D6 — `CreateRecoverer`, as an optional interface

```go
type CreateRecoverer interface {
	ResolveCreate(ctx context.Context, idempotencyKey string, metadata Metadata) (*CreateResult, error)
}
```

What became of the vend identified by an idempotency key? Without an answer to
that question, a vend whose response is lost leaves the platform holding a key and
nothing else — `GetCredentialStatus` cannot help, because it takes a
`platformKeyID` the caller never received. This is the difference between seeing
an unmanaged credential and being able to retire it; §2.4 is the full argument.

**The capability is coupled to the interface, not trusted from a declaration.**
`CapabilitiesOf` clears `RecoverCreate` for any provider that does not implement
`CreateRecoverer`, and `CheckIssuable` and `DispositionForFailure` take the
provider rather than a `Capabilities` value so a caller cannot hand them a
fabricated bit. The first version trusted the declaration, which meant a provider
could claim recoverability, be admitted on that basis, and then be unable to
recover — the exact state §2.4 exists to prevent, reachable by writing one
`true`. A capability a provider can claim without being able to honor is not a
safety mechanism.

`RecoverCreate` is the only capability with a corresponding interface, so it is the
only one a declaration cannot lie about. Every provider has a `RevokeCredential`
method whether or not it works, so `Revoke` can only ever be a claim — which is why
the fallbacks in D2 are chosen so that being lied to is survivable.

### D5 — `SecretRef`

A locator (store, name, version, target env var) that identifies material without
containing it. Records, audit entries and container definitions carry a
`SecretRef`; only the secret store and the workload see the value. The source
system had this concept as a bare `SecretName string` field on the DynamoDB
record (`internal/database/credential.go:40`); making it a type is what lets the
compute layer inject secrets by reference (§5).

---

## 2. The persistence and lifecycle half

**The ticket's scope was wrong about where this lives, and the survey was right.**
Verified independently: `grep -rn "CredentialRepository\|internal/database" backend/internal/credentials/`
returns nothing. `backend/internal/credentials/` has no persistence at all.

The state actually lives in four places that had never been named as one thing:

| What | Where in the source | Lines |
| --- | --- | --- |
| The stored record + queries | `internal/database/credential.go` | 321 |
| Vend / revoke / refresh policy, audit, secret injection | `internal/services/credential.go` | 1,311 |
| The expiry and pending-revoke drive | `internal/jobs/credential_scheduler.go` | 163 |
| Per-provider operator policy | `internal/database/admin.go:919-962` | ~45 |
| Admin-key resolution from the secret store | `internal/services/ssm_cache.go:105-140` | ~40 |

A credential provider that can mint but whose rotation, expiry, revocation and
scheduling live somewhere unspecified is a half-designed contract. So the contract
is three layers, and the middle one is new:

```
credentials/            vending. stateless. a provider mints material and forgets it.
credentials/lifecycle/  the state: what is remembered, and who drives it to gone.
store/                  the DynamoDB implementation of lifecycle.Records (USOSS-5).
```

### 2.1 What `credentials/lifecycle` defines

- **`Record`** — what is stored. Metadata and a `SecretRef`; *no field capable of
  holding material*. That is a load-bearing property, not an accident.
- **`Records`** — the persistence port. Declared by the consumer so that the fence
  around persistence is a fence: this package knows there is somewhere to put a
  record and nothing about tables or partition keys.
- **`SecretWriter`** — storing material for a workload to read. Separate from
  `Records` because the blast radii differ: a leaked `Records` tells an attacker
  who has credentials; a leaked `SecretWriter` hands over the credentials.
- **`Issuer`** — the policy layer: clamp TTL, check scope, write intent, vend,
  record the outcome.
- **`Reconciler`** — the drive. This is what makes a TTL real. A credential whose
  expiry is a timestamp in a database and nothing else is a credential that never
  expires, and the source system's four static providers are exactly that case.
- **`ProviderPolicy` / `CallerScope`** — the two narrowing layers of §7.

### 2.2 What this means for the `store/` fence (USOSS-5)

USOSS-5's scope grows by one file's worth of surface, and gains a precise
specification instead of a porting exercise:

1. `store/` must implement `lifecycle.Records` — nine methods, listed in
   `credentials/lifecycle/records.go`. That is the entire required surface. The
   source's `CredentialRepository` is the starting point; the mapping is
   mechanical except for the three changes below.
2. **`ErrNotFound` replaces `(nil, nil)`.** The source returns `(nil, nil)` for a
   missing credential (`internal/database/credential.go:98`), so every caller has
   to remember a nil check the compiler does not require. A caller that forgets
   dereferences nil in the revoke path.
3. **`Revision` adds optimistic concurrency.** The source's `Update` is a full-item
   `PutItem` with `attribute_exists(PK)` — last write wins. The reconciler
   (`credential_scheduler.go:105-112`) and the revoke handler
   (`services/credential.go:1054-1058`) both write the whole record, so a
   scheduler pass can silently overwrite an operator's revoke with an expiry a
   moment later. `Update` now takes a revision and returns `ErrConflict`.
4. **`Annotations` is allowlisted, not free-form.** The source's record has a
   `Metadata map[string]string` field. The vend path never populates it — verified,
   `services/credential.go:813-823` sets no `Metadata` — but the field is a latent
   hazard: assigning the resolved provider metadata bag (with `admin_api_key` and
   `private_key` in it) onto the record compiles, because both sides are
   `map[string]string`.

   The first fix here was a denylist of secret-looking key names. A review fixture
   defeated it in one line by storing an admin key under `value`, which is the
   failure mode every denylist has — it enumerates what is forbidden, and the
   interesting cases are the ones nobody enumerated. So it is inverted:
   `lifecycle.AnnotationRegistry` holds a per-provider allowlist, a provider may
   persist only keys it declared **in code**, and a provider that declared nothing
   persists nothing. `Records` implementations are constructed with the registry
   and call `Validate` before persisting.

   The denylist survives as a lint applied when a *schema* is registered, which is
   where it belongs: catching a developer about to declare `api_key` as a
   legitimate annotation, once, in a reviewable diff. What this still cannot do is
   inspect values — a provider that declares `region` and stores an access key in
   it defeats any key-based scheme. The property established is narrower and real:
   **every key persisted on a record was named by a human in a reviewed change.**

5. **`ExpiryAuthoritative` is a new field**, recording whether `ExpiresAt` came
   from the provider or from the platform applying a TTL locally. §6.2 explains why
   the reconciler cannot be correct without it.
6. **Query shapes are unchanged**, including the three that are DynamoDB `Scan`s
   with filter expressions (`ListAll`, `ListPendingRevoke`, `ListExpired`). Those
   scans are a scaling problem at volume, not a correctness one; the interface does
   not encode them, so fixing them later is one package's work. Flagged, not fixed
   here.

### 2.3 The lifecycle, and who drives each transition

```
                    ┌──────────────────────────────────────────┐
   Issue()          │                                          │
     ├─ policy reject ──────────────────────────────► (nothing written)
     │                                                │
     ├─ write intent ──► pending ─── provider ok ───► active
     │                     │                            │
     │                     ├── permanent failure ──► revoked (untracked)
     │                     │                            │
     │                     ├── ambiguous, recoverable ─► (reconciler resolves)
     │                     │                            │
     │                     └── ambiguous, otherwise ──► orphaned (ALERT)
     │                                                  │
   Revoke() ──────────────────────────────────────────► │
     ├─ upstream ok ────────────────────────────────► revoked (upstream)
     ├─ ErrRevokeNotSupported ──────────► pending_revoke (ALERT) ─┐
     └─ transient ──────────────────────► pending_revoke ─────────┤
                                                                  │
   Reconciler, every pass:                                        │
     expired records        ─► revoke, then ExpiryDisposition ◄───┘
     pending_revoke records ─► retry, then ExpiryDisposition
                              (the ONLY finalizer for unrevoked material:
                               expired only once the material has lapsed,
                               otherwise it stays pending_revoke, alerting)
     pending > 1h           ─► ResolveCreate, else orphaned (alert)
```

| Stage | Driver | Mechanism |
| --- | --- | --- |
| Issuance | requester, via `Issuer.Issue` | write-ahead record, then provider call |
| Rotation | nobody, today | see §6.4 — this is a real gap, named rather than papered over |
| TTL extension | operator, via `Issuer.ExtendTTL` | static credentials only; changes no material |
| Expiry | `Reconciler`, unattended | `Records.ListExpiring(now)`, revoke, then `ExpiryDisposition` — which finalizes only when something other than the platform's clock says the material is dead |
| Revocation | operator, via `Issuer.Revoke` | upstream call, then `RevokeDisposition`. Finalizes **only** on a successful upstream revoke; anything else parks the record in `StatusPendingRevoke` |
| Finalizing what revoke could not | `Reconciler`, via `ExpiryDisposition` | the single rule about when unrevoked material may be called dead |
| Resolving an ambiguous vend | `Reconciler` | `StatusPending` → `CreateRecoverer.ResolveCreate` → adopt the handle, or close out on `ErrCreateNotFound` |

### 2.4 The write-ahead ordering: what it fixes, and what it only makes visible

The source calls the provider first (`services/credential.go:794`) and writes the
record second (`:826`). If the write fails, an upstream credential exists that the
platform has no record of, will never revoke, and cannot report. A database error
becomes a permanent credential leak.

`Issuer` reverses the order: write a `StatusPending` record whose ID is the
idempotency key, then vend, then finalize.

**An earlier draft of this document claimed that closes the window. It does not,
and the review was right to reject the claim.** What the pending record holds is
an idempotency key — not a handle, because the handle only ever existed in the
response that was lost. `GetCredentialStatus` takes a `platformKeyID`, so it
cannot resolve the record, and providers are free to ignore the idempotency key
entirely. The rewritten ordering makes an unmanaged credential *observable*, which
is a real improvement over a silent leak, and observability is not retirement.

The window closes only where the provider can answer "what became of this key?".
So the contract now distinguishes three failures, in `DispositionForFailure`:

| Failure | Disposition | Window |
| --- | --- | --- |
| Provider refused; nothing minted | `revoked` / `untracked` | nothing to close |
| Ambiguous, provider implements `CreateRecoverer` | stays `pending`, `Recoverable` | **closed** — the reconciler resolves the key to a handle or to `ErrCreateNotFound` |
| Ambiguous, no `CreateRecoverer` | `orphaned` immediately, alerting | **observed, not closed** — nothing will ever resolve it, so leaving it `pending` would be pretending a later pass might |
| Provider answered, finalizing write failed | `pending`, `CompensateRevoke`, alerting | best case: the handle is in hand, so retry the write and revoke what was just created rather than losing it |

And because "observed, not closed" is a real risk rather than a footnote,
`CheckIssuable` **refuses to issue at all** through a provider without
`CreateRecoverer` unless `ProviderPolicy.AllowUnrecoverableIssuance` says an
operator has accepted it. Defaulting that to false means the normal case is a
platform that can always answer, after a timeout, either "nothing was created" or
"here is the handle that revokes it".

#### Which side ConductorOne landed on: "observed, not closed"

This section was written before anyone knew, and USOSS-3's report said the answer
would decide which of the three rows above the ConductorOne provider occupies.
USOSS-8 checked, and it is **the third row**: assumption A4 is false. There is no
idempotency key on ConductorOne's create request and no operation that resolves a
creation by one, so `CreateRequest.IdempotencyKey` cannot be forwarded and
`CreateRecoverer` cannot be implemented.

A2 makes it worse than merely unsupported. The client secret is returned exactly
once and is documented as not retrievable afterwards, so even an operator holding
the credential id cannot recover the material. **A vend whose response is lost is
unrecoverable by construction**, not by omission, and no later version of this
provider can close that window without ConductorOne growing the operation.

So `credentials/c1` declares `Capabilities{RecoverCreate: false}`, implements no
`CreateRecoverer`, and an adopter must set
`ProviderPolicy.AllowUnrecoverableIssuance` before the lifecycle layer will issue
through it at all. That is the mechanism working as designed rather than a
concession: the operator accepts a stated risk instead of discovering it. It also
means **the flagship provider is, today, the one provider in v1 that needs that
opt-in** — worth saying plainly, because "ConductorOne is the credential-vending
backend" and "ConductorOne requires an explicit acceptance of unrecoverable
issuance" are both true and only the first one is usually said.

**This is a pre-existing gap in the internal repository, reported per the
contract's "found a security problem in the source" rule.** It is not fixed there
by this ticket. Two smaller ones alongside it: a failed secret-store write during
vend only logs a warning and still reports success
(`services/credential.go:832-844`), so the application never receives the secret it
was promised; and the record-versus-scheduler write race in §2.2(3).

---

## 3. The ConductorOne wire contract

`credentials/c1.Client` is what the provider needs from ConductorOne. It was
declared by the consumer as four methods and is **three** after USOSS-8 checked it
against the API: it is mapped onto ConductorOne's service-principal credential
API, which is a credential-issuance surface distinct from entitlement granting.
The neutral `CredentialProvider` interface did not depend on the outcome, and did
not change.

| AppHub sends | AppHub expects back |
| --- | --- |
| `Mint`: service principal, display name, requested role scope, clamped TTL | credential id, client id, the client secret (once only), expiry, granted scope |
| `Revoke`: service principal + credential id | success, or "not found", which is also success — there is nothing to destroy |
| `Get`: service principal + credential id | the credential's expiry and granted scope, with no secret |

Three things the four-method version had are gone, each because the API does not
have them. `ResolveVend` (resolve a vend by idempotency key) — there is no
idempotency key, which is A4 and is the one assumption that was false. `Subject`
and `Target` — a credential belongs to a service principal and carries no separate
requester, application or entitlement. `GrantStatus` — the credential has no
status field. `docs/DECISIONS.md` records what each deletion cost.

Method-by-method against `CredentialProvider`:

| Interface method | ConductorOne mapping |
| --- | --- |
| `ID()` | `"c1"`. Constant. |
| `Name()` | `"ConductorOne"`. Constant, and deliberately not a tenant name — a display string that varies per adopter is configuration, not code. |
| `CreateCredential` | `Client.Mint`. The target service principal arrives in `Metadata["c1_service_principal_id"]`, required with no default, because the API has no requester or application field. `(service principal, credential id)` → `PlatformKeyID` as one opaque handle carrying both halves. Both halves of the material go in `Credentials` under `client_id` and `client_secret`: a consumer needs the pair, so a response missing either is a `CreateNotDeliveredError`. `GrantedScope` is the upstream's list. A grant wider than the request is revoked rather than returned. |
| `RevokeCredential` | `Client.Revoke` with the stored `PlatformKeyID`, and **`metadata` is ignored entirely**. Real: the credential has a stable id, `DELETE` destroys it, and unlike the GitHub App path the platform does not need the material to authenticate the call. This provider therefore never returns `ErrRevokeNotSupported`. Taking the service principal from metadata was rejected — a caller supplying the wrong one would revoke against the wrong principal, and because revoking something absent succeeds it would report success having revoked nothing. |
| `GetCredentialStatus` | `Client.Get`. Active (returned, expiry in the future), expired (returned, expiry passed), unknown (not returned, or returned with no expiry). **Revoked is not reachable**: a revoke deletes rather than tombstones, so an absent credential cannot be told apart from one that lapsed and was cleaned up. The platform must not conclude a credential is dead because the system that issued it has forgotten it, and `lifecycle` finalises a revoked record from the revoke path rather than from a status read. |
| `SupportsDynamic` | `true`. Short-lived, role-scoped credentials are the point of the integration. |
| `Capabilities` | `{Dynamic: true, Static: false, Revoke: true, Status: true, Rotate: false, RecoverCreate: false}`, and every value is a fact about the API rather than a choice. `Static: false` because the create request's lifetime must be strictly positive, so a non-expiring credential cannot be asked for. `RecoverCreate: false` because A4 is false. |

### 3.1 Relationship to the existing `conductorone/` client: independent

`internal/conductorone/client.go` (1,070 lines) talks to ConductorOne for
directory and entitlement data, consumed by `auth/c1_sync.go` and ~10
`services/*.go` files. **None of that is being ported**, and the vending client
shares no code with it.

Reasons, in order of weight: the entitlements integration is out of scope, so
sharing would mean porting it to get a dependency; it is a different trust
relationship (reading an organization's directory versus minting credentials) and
should be able to hold different credentials with different privileges; and it
lives outside `credentials/c1`, so sharing code with it would put ConductorOne in a
second package and break the import boundary. The authentication *pattern* is
reused (§4); the code is not.

If entitlements are ported later they get their own package, and the boundary
allowlist gains one reviewable entry.

### 3.2 Approval-gated vending is refused in v1

ConductorOne is an access-management system, so a vend may legitimately require a
human approval. An earlier draft modelled that as a pending outcome the lifecycle
would hold open — which does not work, and the review caught why: `lifecycle`
cannot import a ConductorOne-specific sentinel, and `credentials.CreateResult` has
no provider-neutral channel for "created, but no material yet". Reaching for one
would put a ConductorOne concept into the neutral interface, which is the single
thing this design may not do.

So v1 refuses instead — and USOSS-8 found that there is nothing on this surface
to refuse. Creating a service-principal credential is an administrative operation
on a machine identity and has no approval gate; approval lives on the entitlement
and access-request surfaces, which `credentials/c1` does not touch. `c1` therefore
has no approval sentinel at all: the design's decision stands, and the reason
changed from "v1 declines to model it" to "this API has none to model" (A9).

If a later ticket ports the entitlement surface, this decision is the one to
re-open, and it needs a provider-neutral pending outcome before it can be.

Neither a synchronous vend endpoint nor a deploy waiting on a secret can express
"come back later" to its own caller anyway. Adding a provider-neutral pending
outcome later is additive; guessing at its shape now is not.

---

## 4. How AppHub authenticates to ConductorOne

Two modes. The first is verified to work against ConductorOne today; the second is
better and is an assumption.

### 4.1 `client_secret` — OAuth 2.0 client credentials (verified pattern)

Exactly the flow `internal/conductorone/client.go` uses today
(`:100-155`, `:307-321`), which is why it is the default:

1. `POST {TenantURL}/auth/v1/token`, form-encoded, `grant_type=client_credentials`
   with `client_id` and `client_secret`.
2. Cache the returned bearer token in memory until shortly before expiry. Never on
   disk.
3. `Authorization: Bearer <token>` on API calls; on a `401`, invalidate once and
   retry once.

The client secret is held as a `SecretRef`, never as a value: it is resolved from
the deployment's secret store at use, so it is not in a config file, not in the
process environment, and rotating it needs no redeploy.

Cost, stated plainly: a long-lived shared secret exists, and whoever holds it can
act as AppHub against the tenant. That is the reason for mode two.

### 4.2 `federated_jwt` — no shared secret (assumption)

AppHub already runs an OIDC issuer with a KMS-backed signing key and a public
JWKS endpoint (`internal/oidc/provider.go:94`, `:317`, `:348`) — the same one that
mints workload identity tokens. In this mode AppHub signs an assertion with that
key and exchanges it for a ConductorOne access token; ConductorOne trusts a public
key it fetches from the JWKS endpoint. There is then no shared secret to leak, and
compromising the signing identity means compromising the KMS.

**Whether a ConductorOne tenant accepts this is unverified** (§9). It is designed
in now because designing it in later would change `Config`, and it costs one enum
value to leave the door open.

### 4.3 AppHub's own privilege at the tenant

Whatever AppHub authenticates as should be able to vend the credentials it is
meant to vend and nothing else — not read the directory, not grant entitlements,
not administer the tenant. A vending client that also holds directory-write
privilege makes a compromise of AppHub a compromise of the access-management
system. This is a deployment instruction rather than something code can enforce,
so it is in the adopter documentation (§8) as a requirement, not a suggestion.

---

## 5. Workload identity — implementing the normative shared contract

**This section is subordinate to `/shared/apphub/contracts/workload-identity.md`,
which is supervisor-owned and binding.** Where this document and that one differ,
that one wins; the shapes below are its shapes, and a disagreement with it is
raised there rather than resolved here.

### 5.1 Why there is a separate owner for this boundary

USOSS-2 and USOSS-3 designed the two halves of workload identity in parallel,
without being able to see each other's output, and produced designs that did not
compose. The independent reviewer verified four concrete incompatibilities: the
name `Attestation` meant "the expected identity policy" on the compute side and
"the submitted runtime evidence" on the credentials side; the AWS scheme was
spelled `aws-sts-caller-identity` on one side and `aws-sts` on the other; the
`Verify` signature had no parameter for the expected value it was supposed to
check against; and `credentials.SecretRef` could not be passed where a
`compute.SecretBinding` was wanted, with no adapter specified anywhere.

None of those is a judgment error by either side. They are what happens when a
shared boundary has no single owner, and the contract document is that owner.

### 5.2 The problem in the source system, restated

The survey's landmine 3, verified: `modules/deploy/container.go:696-712` makes the
compute layer inject a rotating deploy signature and a token endpoint URL into
every container, and the deployed application then calls AWS STS
`GetCallerIdentity` at runtime, presigns it, and exchanges the presigned request
plus that signature for a platform OIDC JWT (`services/workload.go:246-340`,
verified via `auth/sts_verify.go`). A credential concern is wired into compute, and
an AWS API call is a runtime dependency of every deployed application — including
applications that have nothing to do with AWS.

**The line, in one sentence: compute moves opaque bytes into a workload's
environment; credentials decides what those bytes are and what they are worth.**

### 5.3 The two concepts, permanently distinguished

This is the change that makes the two sides compose. One name meant two things, so
there are now two names, and neither can drift into the other's job:

| Type | Meaning | Carries material? |
| --- | --- | --- |
| `ExpectedAttestation` | The **stored policy**: what identity a valid workload must prove. `Method`, `Subject`, `Issuer`, `Audience`. | Never. It is persisted and safe to log — and `credentials/workload/workload_test.go` asserts structurally that it cannot hold a `Secret`. |
| `AttestationProof` | The **runtime evidence** a workload submits. `Method` plus an opaque `map[string]credentials.Secret`. | Yes. Never persisted, never logged. |

`Method` is a defined type whose values live in exactly one file,
`credentials/workload/attestation.go`. A test enforces that: it parses **every Go
file in the repository** with `go/ast` and unquotes each string literal, failing if
a scheme value appears anywhere but its declaration. A second spelling of the same
scheme is invisible in review — both look correct — and a registry keyed by one
silently fails to select the other.

The first version of that guard scanned file text within one directory, and a
review fixture walked through it twice: a raw Go string literal in the owning
package passed, and an ordinary quoted literal in `compute` passed. Both now fail,
verified with fixtures. The remaining limit is stated in the test: a literal
assembled by concatenation is not detected, which is not something anyone does by
accident, and accidents are what this guard is for. It matters because it is what
protects the vocabulary after the duplicate declaration on the compute branch is
deleted.

### 5.4 The verification boundary

```go
type Verifier interface {
	Verify(ctx context.Context, expected ExpectedAttestation, proof AttestationProof) (Identity, error)
}
```

**One method, because the contract specifies one.** An earlier version of this
interface also required `Method() Method`, which was useful and wrong: a verifier
written against the frozen contract has only `Verify`, so the extra requirement
meant a conforming outside implementation would not satisfy the Go interface —
defeating the point of freezing it. Dispatch metadata moved to `VerifierRegistry`,
where a scheme is named at registration; the mapping is then visible in one place
as a property of the wiring rather than recoverable only by asking each verifier.
`TestVerifierIsExactlyTheContractInterface` pins the method count, name and
signature, because the reviewer removed `Method()` and the whole test package
stayed green — the property was documented and unenforced.

`VerifierRegistry.Verify` dispatches on `expected.Method`, never on the proof's:
letting a submitter choose its verifier is letting it choose the weakest one a
deployment happens to accept. A scheme mismatch and an unregistered scheme both
return `ErrAttestationRejected`, so the error does not enumerate which schemes are
accepted.

The expected value is an explicit parameter, not a lookup inside the
implementation. A verifier that fetches its own expectations cannot be tested in
isolation and cannot be reasoned about: what it checks against becomes a property
of whatever database it happens to be pointed at. Implementations confirm the
proof resolves exactly to `expected.Subject` and satisfies the issuer and audience
obligations, and never trust a subject carried inside the proof — a proof
asserting who it is proves nothing.

`ErrAttestationRejected` remains one error for every failure mode. The source's
handler distinguishes "invalid IAM identity" from "no application bound to caller"
from "invalid deploy signature" (`services/workload.go:274-312`), which tells an
unauthenticated caller which half of its proof was right. That is an oracle.
Detail goes to the platform's own logs.

### 5.5 Split of obligations

| Obligation | Owner |
| --- | --- |
| Create the workload identity; report what it is | `compute` |
| Persist the `ExpectedAttestation` for a workload | deploy layer |
| Rotate the deploy secret each deployment | `credentials` (`Provisioner.Rotate`) |
| Deliver opaque materials into the workload environment | `compute` |
| Convert `credentials.SecretRef` → `compute.SecretBinding` | deploy layer |
| Verify an `AttestationProof` against an `ExpectedAttestation` | `credentials` (`workload.Verifier`) |
| Mint the workload token after successful verification | `credentials` (`workload.TokenIssuer`) |

The secret-reference conversion is the piece neither design had. It belongs to the
deploy layer because only the deploy layer knows which compute provider is in
play, and it must fail loudly when a named store does not belong to that provider.
Putting it in either package would force that package to know about a provider
selection it has no business seeing.

### 5.6 Consequences

- **Two methods, not three.** `Provisioner.Rotate` then `Provisioner.Materials`,
  with the returned revision passed into `Materials`. Both reviews concluded
  independently that this suffices; a compute provider needing a third has taken on
  a credential responsibility that belongs on this side of the line. A test asserts
  the interface has exactly two methods.
- **The AWS STS call stops being universal.** `Method` is a value and `Proof` is an
  opaque map, so a Kubernetes provider attests with a projected service-account
  token and never links the AWS SDK. If any part of the implementation makes the
  AWS scheme structurally privileged, that is a bug against the contract.
- **Rotation on deploy is kept.** It bounds the value of a leaked attestation
  secret to the time until the next deploy, and is nearly free because the workload
  is being replaced anyway.

---
## 6. Credential lifecycle: issuance, rotation, expiry, revocation

### 6.1 Issuance

`Issuer.Issue`, per §2.4: admission (`CheckIssuable`), write-ahead record, vend,
finalize. TTL reaching the provider is already clamped, so a provider may honor it
directly and must never extend it.

### 6.2 Expiry, and the difference between a fact and a belief

Driven by `Reconciler`, unattended. The rule that makes this more than bookkeeping,
and that an earlier draft got wrong:

> A record may be marked `expired` only when something other than the platform's
> own clock says the material is dead.

For a dynamic credential whose provider stated an expiry, the provider's expiry is
a fact: the material stops working whether or not anyone acts. For a static
credential, `ExpiresAt` is a row in a database. Marking that record expired does
not stop the credential working — it stops the platform *watching* a credential
that still works, which is strictly worse than leaving it alone.

So `ExpiryDisposition` finalizes on exactly two grounds — the upstream revoke
succeeded, or the material is provider-expiring with an authoritative expiry
(`Record.ExpiryAuthoritative`, set only when `CreateResult.ExpiresAt` was
populated). Everything else stays non-terminal and alerting, and is counted in
`Report.Unrevocable`:

| Situation | Status | Why |
| --- | --- | --- |
| Revoke succeeded | `expired` / `upstream` | The credential is dead. |
| `ErrRevokeNotSupported`, provider-expiring, authoritative expiry, **and that expiry has passed** | `expired` / `expiry_only` | It died on its own, later than the operator asked. Audit shows partial. |
| `ErrRevokeNotSupported`, provider-expiring, but the expiry has **not** passed | **`pending_revoke`, alerting** | The material is still working. Come back when it is not. |
| `ErrRevokeNotSupported`, anything else | **`pending_revoke`, alerting** | Nothing expires this material and nothing can revoke it. It is live and will stay live. |
| Provider no longer registered, authoritative expiry | `expired` / `untracked` | It dies on its own. |
| Provider no longer registered, otherwise | **`pending_revoke`, alerting** | Nothing can revoke it and nothing can confirm it. |
| Transient failure | `pending_revoke` | Come back next pass. |

A reconciler that is not running is therefore a security incident and not a
degraded feature, which is why `Report` exists to make "it is running, and here is
what it could not finish" observable.

### 6.3 Revocation

Driven by an operator through `Issuer.Revoke`; retried by the reconciler.

**Only a successful upstream revoke finalizes a record on this path.** Everything
else — including `ErrRevokeNotSupported` — leaves it `pending_revoke`, and it
finalizes later through `ExpiryDisposition`, once its material has actually lapsed.
There is one rule about when a credential may be called finished, and the request
path does not get its own copy of it.

That is a correction. The first version applied the fail-closed rule to the expiry
path and left `Issuer.Revoke` turning `ErrRevokeNotSupported` straight into a
terminal `revoked` / `expiry_only` — a second, more permissive finalizer that closed
out records whose material was still working: authoritative dynamic material until
its future `ExpiresAt`, and static material potentially forever. An operator asking
for a credential to be gone is not evidence that it is gone, and a record marked
revoked while its material still works is worse than one honestly marked pending,
because it stops anyone looking.

`ExpiryDisposition` is now the only function that can produce `expiry_only`, and it
will only do so once the expiry has actually passed — both halves matter, since the
outcome is a claim that the material has lapsed. The outcome is recorded because
`revoked` covers two very different situations:

| `RevokeOutcome` | Meaning | Blast radius after |
| --- | --- | --- |
| `upstream` | The provider confirmed it is dead. | None. |
| `expiry_only` | `ErrRevokeNotSupported`, but the provider expires the material itself, said when, and that time has passed. | Nothing further: the material is dead. Audit says "partial", because the operator's request was not what killed it. Reachable only from `ExpiryDisposition` — see §6.2. |
| `untracked` | Provider no longer registered; nothing can revoke or confirm. | Unknown. Worth an alert. |

The source system already distinguishes the first two in its audit output
(`services/credential.go:1063-1076`) — this makes it a field rather than a log
string.

### 6.4 Rotation — a named gap

**No provider rotates today, and this design does not add rotation.** What the
source system calls "refresh" (`services/credential.go:1084-1157`) extends the
record's `ExpiresAt` and touches no material at all; it is a bookkeeping
operation, and calling it rotation would be wrong. It is `Issuer.ExtendTTL` here,
named for what it does, and restricted to static credentials because a dynamic
credential's expiry is the provider's fact and not the platform's choice.

Real rotation — replacing material behind a stable identity — is
`Capabilities.Rotate`, declared by nothing. Until a provider implements it, the
platform's answer to "rotate this credential" is revoke and vend again, which
means a brief gap where the old material is dead and the new material has not
reached the workload. Adopters should know that; it belongs in a follow-up ticket
rather than in a doc comment claiming a capability that does not exist.

---

## 7. Least privilege: what a vended credential carries, and who decides

Four layers. **Every layer may only narrow.** AppHub never widens a request, and
the narrowest answer wins.

| Layer | Decided by | Mechanism |
| --- | --- | --- |
| 1. Deployment ceiling | operator | `lifecycle.ProviderPolicy`: enabled, allowed types, default and max TTL per type, and whether unrecoverable issuance is accepted. Ported from `CredentialProviderConfig` (`database/admin.go:919-962`), with hours replaced by durations. |
| 1a. Provider capability | the provider, in code | `credentials.Capabilities`. A policy cannot permit what a provider cannot do, and two combinations are refused outright — see below. |
| 2. Caller authorization | operator, per service account | `lifecycle.CallerScope`: allowed providers, types, max TTL. Ported from `checkScope` (`services/credential.go:1290`). |
| 3. Request | requester | `IssueRequest.RequestedScope` and `RequestedTTL`. May only narrow layers 1 and 2. |
| 4. Provider policy | ConductorOne | May grant less than requested. `GrantedScope` records what was actually granted. |

`CheckIssuable` applies all of this in one place, in a fixed order, and refuses two
combinations outright:

- **Static without revoke** (`ErrStaticRequiresRevoke`). Static material is
  material the upstream never expires, so a static credential from a provider that
  cannot revoke is a credential that lives forever — and issuance is the only
  moment at which the platform has any control over it. The review found this
  reachable in the first draft, which allowed `Capabilities{Static: true, Revoke:
  false}` and then let the reconciler quietly relabel such a record `expired`.
- **Unrecoverable issuance** (`ErrUnrecoverableIssuance`), unless the operator has
  set `AllowUnrecoverableIssuance`. §2.4 is the argument.

Three properties worth calling out. **There is no uncapped credential**: a policy
with nothing configured still yields `FallbackMaxTTL` (12 hours, adopted from the
Bedrock ceiling at `credentials/claude.go:31` rather than invented), and
`ClampTTL` is tested for it. **An unconfigured policy permits nothing**: an empty
`AllowedTypes` means no types, where the source system read it as "static only"
(`services/credential.go:584-586`) — the unconfigured state should not issue the
kind of credential that needs manual teardown. And **the record stores what was
granted, not what was asked for**, so the audit trail describes reality; storing
the request would make an audit that overstates privilege look identical to one
that does not.

`CheckScope` distinguishes a nil scope slice (not scope-limited; an interactive
user authorized elsewhere) from an empty non-nil one (a caller with no permissions,
which gets nothing). Conflating them is how a service account with an empty scope
list inherits an administrator's reach.

For ConductorOne specifically, the recommended defaults are: **dynamic only,
default TTL 1 hour, max 12 hours, static disabled.** Static is a credential the
platform must remember to tear down; dynamic is one that cleans up after itself.
Static becomes available only if USOSS-8 verifies that ConductorOne revocation
works (assumption A3), because without it `CheckIssuable` refuses static anyway.

---

## 8. Security properties

### 8.1 Material never lands anywhere it was not sent

- **Never logged.** `Secret` and `Metadata` redact under every `fmt` verb and under
  `log/slog`, in text and JSON, grouped and ungrouped; `credentials/secret_test.go`
  asserts the nested-struct and `%q` cases, which a `String()`-only approach misses.
- **Never in an error.** No error in this design carries material. A provider that
  writes `Reveal(s)` into an error defeats this, which is why `Reveal` is the
  grep-able boundary and why reviewers check its call sites.
- **Never marshalled by accident.** `MarshalJSON`, `MarshalText` and `GobEncode`
  fail with `ErrSecretMarshal`. A response that must carry material builds a wire
  type from `Reveal`, deliberately and visibly.
- **Not reachable by one reflective accessor.** `reflect.Value.String` reports a
  placeholder; `Interface` panics on the unexported fields; `Bytes` — which does
  *not* panic — returns masked noise. See §1/D1 for the mechanism.
- **Never on disk outside the secret store.** The only sanctioned destination is a
  `SecretWriter` implementation, and what comes back is a `SecretRef`.

**And the limit, stated as plainly as the properties.** None of this stops code in
the same process that is trying to read material: reflection can combine the two
fields of a `Secret`, `unsafe` reads them directly, a memory dump contains both,
and `Metadata`'s map values are reachable by any deliberate walk. What is
established is narrower — *material does not escape by accident* — and claiming
more would make the guarantee less useful, not more, because someone would rely on
it.

### 8.2 Stored versus in memory

| Data | Where | For how long |
| --- | --- | --- |
| Credential material | process memory only | the single request that vends it |
| Material, when vended for an application | the deployment's secret store, via `SecretWriter` | until the credential is revoked, when `SecretWriter.Delete` removes it |
| Record metadata (`lifecycle.Record`) | `store/` (DynamoDB in v1) | indefinitely — it is the audit trail |
| Provider admin keys | the deployment's secret store; resolved on use | cached in memory for a bounded TTL (5 minutes in the source, `ssm_cache.go:14`) |
| AppHub's ConductorOne client secret | the secret store, as a `SecretRef` | resolved per token fetch |
| ConductorOne bearer token | process memory | until shortly before expiry |

The record has no field capable of holding material, and `Annotations` is no longer
free-form at all: a provider may persist only keys it declared in code
(§2.2). That is a weaker claim than "no material can be persisted" — a declared
`region` key can still be filled with an access key — and it is the strongest claim
a key-based scheme can support. It is stated as such rather than as an invariant it
cannot establish.

### 8.3 Blast radius when a vended credential leaks

| Bound | What provides it | When it fails |
| --- | --- | --- |
| Time | TTL, capped by policy and `FallbackMaxTTL` | a policy with a long max; a provider that ignores TTL |
| Scope | requested scope narrowed by the provider; `GrantedScope` recorded | a provider that grants coarsely — `AmazonBedrockLimitedAccess` in the source is account-wide Bedrock, not one model |
| Revocability | `RevokeCredential` | `ErrRevokeNotSupported`, where TTL is the only bound left |
| Blast surface | one provider, one subject, one application | a credential vended to a shared identity |
| Detection | the record, plus audit entries naming requester, provider, scope and outcome | a credential that was never recorded — which is the leak §2.4 exists to prevent |

The honest summary: for a dynamic, narrowly scoped, revocable credential the
radius is small and time-bounded. For a static credential from a provider that
cannot revoke, a leak lasts until the TTL expires and nothing can shorten it — so
the design makes that combination a deliberate opt-in (static disabled by default)
rather than a default, and makes `expiry_only` a recorded outcome rather than a log
line.

### 8.4 Nothing ConductorOne-internal in the repository

Verified: no hostname, account identifier, tenant name, client id, or internal URL
appears anywhere in this change. `credentials/c1` has **no default tenant URL** —
`Config.Validate` requires one and there is nothing to fall back to. A default
would either be wrong for an adopter or would be somebody else's tenant.

`Validate` also refuses plain HTTP (the client-credentials grant puts the secret in
a request body), embedded userinfo (a common way to smuggle a different host past
a naive parse), and any query or fragment on a base URL that gets paths appended
to it. Documentation uses `https://tenant.example.com`.

---

## 9. Assumptions, and how each one turned out

This section listed ten unverified assumptions when the design was written: the
source repository calls ConductorOne only for directory and entitlement data and
contains **no credential-vending calls**, so nothing here could be checked from
it. USOSS-8 verified each one against ConductorOne's own API definitions before
implementing, which the ticket made its first task and which
`credentials/c1.Client` was marked PROVISIONAL for.

**Six hold, two hold with a condition, one does not apply, and one is false.**
Verdicts below; `docs/DECISIONS.md` records what each one changed.

| # | Assumption | Verdict | What was found |
| --- | --- | --- | --- |
| A1 | ConductorOne exposes a credential-vending API at all, distinct from entitlement grants. | **HOLDS** | The service-principal credential API — create, read and delete a client credential belonging to a non-human identity — is a distinct set of routes from the entitlement-grant and access-request surfaces, which this package touches none of. A second, narrower vending surface also exists for gateway keys; it was rejected as the mapping because it carries no TTL, no scope and no read-by-id. |
| A2 | A vend returns credential material directly in the response. | **HOLDS**, and is stronger than assumed | The secret half is in the create response and is documented as shown exactly once and not retrievable afterwards. No create-then-fetch split is needed. The second half of that is what makes A4 consequential: a lost response is a lost credential. |
| A3 | A grant has a stable server-side identifier usable for later revoke and status. | **HOLDS** | The credential carries an identifier, and read and delete are both addressed by it. Revoke is real and this provider never returns `ErrRevokeNotSupported`. The identifier is scoped to its service principal, so both halves travel in `PlatformKeyID` — see `credentials/c1.Ref`. |
| A4 | Vending is idempotent on a caller-supplied key **and a vend can be resolved by that key afterwards**. | **FALSE** | The create request has no idempotency key, and no operation resolves a creation by one. With A2, a vend whose response is lost leaves a live credential that cannot be found again — unrecoverable by construction. The provider declares `Capabilities{RecoverCreate: false}` and implements no `CreateRecoverer`; `lifecycle.CheckIssuable` then refuses managed issuance unless an operator opts in. |
| A5 | A requested TTL is honorable, and the response states an expiry. | **HOLDS, with a ceiling** | The create request takes a duration that must be strictly positive and is capped at **180 days**, and the response states an expiry. Two consequences: a non-positive TTL is refused rather than defaulted, and a static credential cannot be asked for at all — so `Capabilities{Static: false}` is a fact, not a policy. The provider clamps down to the ceiling, which is narrowing and always permitted. |
| A6 | Requested scope can be expressed per-request and the response reports what was granted. | **HOLDS** | The request takes a list of role identifiers (at most 32) and the response reports what was granted, documented as the *intersection* with the service principal's own roles. The intersection is the "may narrow, never widen" property enforced upstream; the provider compares the two anyway. A second scope axis exists (source-address restriction) and is deliberately not exposed — AppHub does not know the consumer's egress address, so it could not set it correctly. |
| A7 | The token endpoint is `{TenantURL}/auth/v1/token` with a client-credentials grant. | **HOLDS** | Verified twice over: the source system's ConductorOne client posts a form-encoded client-credentials grant to exactly that path and reads `access_token` / `expires_in`, and the credential API is on the same tenant host behind the same gateway. |
| A8 | `federated_jwt` (§4.2) is supported. | **UNVERIFIED** — no evidence either way | Nothing in the available surface says whether a client assertion is accepted. The mode is implemented to RFC 7523 §2.2 rather than invented, it is not the default, and it has never been run against ConductorOne. An adopter enabling it against a tenant that does not support it gets a refusal from the token endpoint on the first call. |
| A9 | Whether a target is approval-gated can be determined **before** creating a grant. | **DOES NOT APPLY** | Creating a service-principal credential is an administrative operation on a machine identity; there is no approval gate on this path at all. Approval lives on the entitlement and access-request surfaces, which this package does not touch. §3.2's refusal of approval-gated vending stands, but the reason changes: not "v1 declines to model it" but "this API has none to model". |
| A10 | AppHub can authenticate with a vending-only privilege at the tenant. | **HOLDS PARTIALLY** | The credential operations require an editor role on the service-principal service, and reads require a viewer role. Privilege is therefore per *service*, not per operation: an editor on that service can also create, update and delete service principals themselves. Least privilege is coarser than §4.3 assumes, and an adopter should be told so. |

The evidence for each verdict is a route or a field definition in ConductorOne's
own API. Specific paths and field names are quoted in `credentials/c1/client.go`
and `credentials/c1/contract.go`, where the mapping lives; they are not restated
here, because a restatement of a mapping in prose is the thing that drifts.

There is no longer an open assumption about which providers are in scope: the
exclusions in §10 are decided, and the reasons are recorded outside this
repository.

---
## 10. Provider scope, and why the interface is wider than it

Three of the source system's six credential providers are in v1 scope:

| Provider | Shape | Ticket |
| --- | --- | --- |
| `claude` | AWS Bedrock, via STS and IAM. Dynamic and static. | USOSS-9 |
| `datadog` | Vendor REST API. Static only. | USOSS-7 |
| `github` | GitHub App installation tokens. Dynamic only. | USOSS-7 |

Plus `c1`, which is new (USOSS-8).

The other three source providers are **excluded by project decisions recorded
outside this repository**. The reasons are not technical and are not relitigated
here; what matters for this document is the constraint they place on the design,
which is the opposite of the obvious one:

**Excluding a provider must not narrow the interface.** It would be easy, having
dropped the providers that do unusual things with the contract, to tighten the
contract around the three that remain — and doing so would quietly make a whole
category of provider unimplementable by anyone else. Two specific shapes the
interface therefore continues to accommodate, though nothing in this repository
uses them:

- **A provider whose credentials are not meant to be used.** Some legitimate uses
  of a credential-vending system issue material whose value is in what happens
  next rather than in the access it grants. Such a provider needs the full
  contract — issuance, TTL, scope, status — while `GetCredentialStatus` may
  reasonably always answer `unknown`, since the platform's own record is the only
  liveness signal. Nothing in the contract requires a provider to be able to
  report on what it vended, and nothing should be added that does.
- **A provider that forcibly overrides requested scope.** `CreateRequest.RequestedScope`
  is a request, and `CreateResult.GrantedScope` is the answer; a provider that
  ignores the former entirely and returns something much narrower is behaving
  correctly. That asymmetry is deliberate, and it is what lets scope be enforced
  provider-side rather than trusted from the caller.

Both fall out of decisions already made for other reasons — §7's "every layer may
only narrow", and `CredentialStatusUnknown` meaning "the provider does not track
this" rather than "the credential is gone". Recording them here is what stops a
later change from removing them as unused generality.

---
## 11. What an adopter configures

### 11.1 To use ConductorOne-backed vending

| Variable | Required | Meaning |
| --- | --- | --- |
| `APPHUB_C1_TENANT_URL` | yes | Their tenant base URL, `https://` only. No default. |
| `APPHUB_C1_CLIENT_ID` | yes | OAuth client id. Not a secret. |
| `APPHUB_C1_CLIENT_SECRET_REF` | in `client_secret` mode | A secret-store *reference* to the client secret, not the secret. |
| `APPHUB_C1_AUTH_MODE` | no | `client_secret` (default) or `federated_jwt`. |
| `APPHUB_C1_AUDIENCE` | no | Audience asserted in `federated_jwt` mode. Defaults to the tenant URL. |
| `APPHUB_C1_REQUEST_TIMEOUT` | no | Per-call timeout. Defaults to 15s. |

Plus, outside the environment: an OAuth client at their tenant with **vending
privilege only** (§4.3), that client's secret in their secret store, and a
`ProviderPolicy` for `"c1"` with `Enabled: true` and the types they want.

Half-configured is rejected at startup. Setting a tenant URL and no client id is
an error, not a silent fallback to "ConductorOne is off": a deployment that
believes it has ConductorOne vending and does not is worse than one that fails to
start.

### 11.2 To use none of it

**Set none of the above and everything still works.** That is not a claim about
intent — it is a structural property with three independent mechanisms behind it:

1. `ConfigFromEnv` returns `ErrNotConfigured` when nothing is set, which the caller
   reads as "this deployment does not use ConductorOne" and continues. Tested:
   `credentials/c1/config_test.go`.
2. Nothing registers the provider, so `ProviderRegistry` contains only what the
   deployment asked for. `credentials/` imports no provider. Tested:
   `TestRegistryIsEmptyWithoutRegistration`.
3. `make boundary` fails the build if any package outside `credentials/c1` imports
   ConductorOne or `credentials/c1` itself. **Today that is absolute: no package in
   this repository imports it.** One composition root will be allowlisted when
   USOSS-8 has a binary to wire, for the reason recorded in §11.3 — and even then no
   *library* package may, which is the property an adopter's build graph actually
   depends on.

A fourth mechanism was owed at the **binary** level, because the three above are
package-level and package-level evidence would not catch a binary that refuses to
start without ConductorOne configuration — which is where an adopter would actually
meet the problem. USOSS-8 built it: `cmd/apphub/main_test.go` compiles
`cmd/apphub` and runs it in a separate process with an **empty** environment,
asserting that it starts, registers the providers that need no configuration, and
reports ConductorOne as unconfigured. The control in the other direction is
asserted too, so the test is not satisfied by a binary in which ConductorOne
support does not exist, and the build runs with the module proxy disabled so a pass
is also evidence the binary needs no network to be built.

**Half of this obligation is still open.** It said "starts *and vends* through the
AWS-native path". The vending half is not delivered: `credentials/aws` is a stub
until USOSS-9, and vending needs real credentials no CI environment has. The
starting half, and the whole of the ConductorOne-optional half, are.

An adopter with an AWS account and no ConductorOne account gets the AWS-native
providers, the same lifecycle, the same reconciler, the same store, and no degraded
functionality anywhere except the c1 provider they did not want.

### 11.3 Why exactly one composition root is allowlisted to import `credentials/c1`

**This section exists so that a later reader does not delete the allowlist entry
as cleanup.** An entry in a security boundary's allowlist with no recorded reason
looks like drift, and removing it silently unwires ConductorOne support.

#### The problem

The boundary rule allows only `credentials/c1` to import `credentials/c1`. Read
strictly, that means **no binary in this repository can register the ConductorOne
provider**, because any composition root that imports the package to register it
is itself a violation.

#### The decision

**One composition root is allowlisted.** The alternative — adopters wire
ConductorOne in their own downstream `main` — was rejected: it means AppHub ships
no runnable binary capable of its own flagship capability, so "ConductorOne is the
credential-vending backend" becomes a claim an adopter can only realize by writing
Go. One reviewed allowlist entry is a smaller cost than that, and concentrating
dependency wiring in a composition root is what composition roots are for.

**The constraint being protected survives intact:** no *library* package depends
on ConductorOne. That is the property that matters for an adopter who does not
want it — their build graph is unchanged, because they do not build that binary —
and it is the property `make boundary` still enforces everywhere else.

#### The conditions attached to it

1. **`credentials/c1` exposes a single entry point**, so exactly one import site
   ever exists. Its signature is pinned in code by `c1.RegisterFunc`:

   ```go
   func Register(reg *credentials.ProviderRegistry, cfg Config, deps Deps) error
   ```

   `Deps` carries the three collaborators a test must be able to replace: a secret
   resolver, an assertion signer, and an HTTP client. `Register` returns
   `ErrNotConfigured` having registered nothing when the configuration is empty,
   refuses a half-configured one, and does not dial ConductorOne — startup is not
   where you want to discover a tenant is unreachable, and a provider that cannot
   be registered without a network cannot be registered in a hermetic test either.

2. **The allowlist entry landed with USOSS-8**, naming one path:
   `github.com/conductorone/apphub/cmd/apphub`. Note what the rule does and does not
   enforce, because it is a path-*prefix* match and not an exact one: it names one
   leaf main package, and any package created beneath that path would be allowed
   too. Nothing beneath it exists, and
   `TestC1AllowlistPermitsOnlyTheNamedCompositionRoot` pins both halves so the true
   extent of the widening is visible rather than inferred.

3. **The binary-level test landed with USOSS-8**, in the form described in §11.2 —
   with the vending half of it still open on USOSS-9, which is stated there rather
   than counted as done here.

4. **A second allowlist entry requires supervisor approval.** One entry is a
   composition root; two is a pattern, and a pattern is how a boundary erodes.

#### What this rests on

The boundary checker has to actually work. It has been defeated twice by the
independent reviewer — most recently through a build tag — and this decision
assumes a hardened checker rather than excusing a weak one. If the checker cannot
be trusted, the correct response is to fix the checker, not to widen the rule
further or to abandon it.
