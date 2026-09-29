# Credential provider authoring guide

A credential provider mints credential material for one external system and hands
that material to the caller exactly once. Everything after the vend request —
policy, lifecycle records, reconciliation, expiry, and revoke retry — belongs to
`credentials/lifecycle` and `store/`.

## 1. Implement `credentials.CredentialProvider`

A provider must implement:

- `ID() string`: stable registry key. It must not change between releases.
- `Name() string`: human-readable display name.
- `CreateCredential(ctx, req)`: mint a credential and return its handle and
  material in `credentials.Secret` fields.
- `RevokeCredential(ctx, platformKeyID, metadata)`: revoke when the upstream can;
  return `credentials.ErrRevokeNotSupported` when it cannot.
- `GetCredentialStatus(ctx, platformKeyID, metadata)`: report upstream status;
  return `credentials.ErrStatusNotSupported` or `CredentialStatusUnknown` when
  the upstream cannot answer.
- `SupportsDynamic() bool`: legacy dynamic-support signal used by providers that
  do not implement the richer capability reporter.

`CreateRequest` carries the effective TTL, requester identity, provider metadata,
optional requested scope, and an idempotency key. A provider may narrow requested
scope and must never widen it. If it cannot honor caller-supplied scope at all,
return `credentials.ErrScopeNotSupported` rather than vending a broader
credential.

`CreateResult.PlatformKeyID` is the provider handle needed for status and revoke;
it is persisted. `CreateResult.APIKey` or `CreateResult.Credentials` carries the
material; those fields are `credentials.Secret` and are not persisted.

## 2. Redaction rules

Credential material must enter `credentials.Secret` immediately and leave it only
at the boundary that delivers the credential to the requester or writes it to the
upstream system that consumes it. Never put material in:

- errors;
- logs or structured log attributes;
- metadata or annotations;
- lifecycle records;
- provider IDs, names, or duplicate-registration errors;
- test failure messages outside purpose-built redaction tests.

`credentials.Secret` redacts formatting and refuses ordinary serialization.
`credentials.Metadata`, `SecretRef`, and `Foreign` exist so provider configuration,
secret locators, and caller-controlled text do not get rendered by accident. If a
provider must expose a value for debugging, expose a count, status enum, or
repository-authored constant instead of the value itself.

## 3. Declare capabilities

Implement `credentials.CapabilityReporter` when the provider can state its shape:

```go
func (p *Provider) Capabilities() credentials.Capabilities {
    return credentials.Capabilities{
        Dynamic:       true,
        Static:        false,
        Revoke:        true,
        Status:        true,
        Rotate:        false,
        RecoverCreate: true,
    }
}
```

`CapabilitiesOf` falls back for older providers, but explicit declarations are
better because static credentials, rotation, and ambiguous-create recovery have
safety consequences. `RecoverCreate` is checked: if the provider claims it but
does not implement `credentials.CreateRecoverer`, `CapabilitiesOf` clears the bit.

Implement `CreateRecoverer` only when the upstream lets you resolve a create by
idempotency key without creating anything new:

```go
func (p *Provider) ResolveCreate(ctx context.Context, key string, md credentials.Metadata) (*credentials.CreateResult, error) {
    // Lookup only. Return credentials.ErrCreateNotFound if no credential was made.
}
```

A resolve method must never mint on a miss. Its job is to close the window where a
create may have succeeded upstream but the caller did not receive the response.

## 4. Register explicitly

Use `credentials.ProviderRegistry` at the composition root:

```go
reg := credentials.NewProviderRegistry()
if err := reg.Register(myprovider.New()); err != nil {
    return err
}
```

The registry imports no providers. That is the optional-provider mechanism: a
binary carries only the implementations it imports and registers. Duplicate IDs
are refused instead of overwritten so wiring order cannot decide which provider a
request reaches.

For optional implementations, follow the pattern used by `credentials/c1`: parse
configuration, report a not-configured sentinel when the provider is intentionally
off, and make partial configuration a startup error.

## 5. Lifecycle policy and reconciler path

`credentials/lifecycle` is the stateful half of credential vending:

1. `ProviderPolicy` decides whether a provider may issue the requested credential
   type, clamps TTL, and records whether static credentials or ambiguous creates
   are allowed for that provider.
2. The issuer writes intent before calling the provider, so a timeout or delivery
   failure leaves a record the reconciler can inspect.
3. The provider mints and returns a `CreateResult`.
4. The lifecycle layer stores the provider handle, expiry, granted scope,
   metadata, and secret-store locators, never the material.
5. The reconciler drives expiry, revoke, status checks, and create recovery.

Provider authors should design for that path. Return `credentials.ErrTransient`
for retryable upstream failures. Return permanent typed errors when an operation
cannot be retried into success. If a create result was not delivered, use
`credentials.ErrCreateNotDelivered` through the provided error type so the
lifecycle layer can keep the upstream handle without rendering material.

## 6. Metadata and annotations

`credentials.Metadata` is the provider-specific configuration bag on requests.
Use it for operator-supplied, per-call configuration such as workspace, project,
repository, or policy identifiers. Treat it as sensitive deployment topology even
when it is not credential material:

- validate required keys before calling upstream;
- do not echo raw values in errors;
- do not copy raw metadata into annotations unless the annotation contract says it
  is safe and useful;
- prefer stable provider-authored labels or redacted references for durable
  records.

If a provider returns annotations or metadata for a UI, keep them descriptive but
non-secret: capability names, expiry times, granted-scope descriptors, and counts
are safer than raw locators or administrative identifiers.

## 7. ConductorOne is optional

`credentials/c1` is an optional implementation of the same interface, not a
special case in the registry or lifecycle layer. It is enabled only by explicit
composition-root wiring and complete environment configuration. A deployment that
uses only AWS-native or other providers should not import it and should not carry
it in its build graph.

## 8. Provider checklist

Before opening a provider PR:

- `ID` is stable and unique.
- `CreateCredential` returns material only in `credentials.Secret` fields.
- Revoke and status unsupported paths use the documented sentinels.
- Scope requests are honored, narrowed, or refused; never widened.
- `CapabilityReporter` is implemented when the provider supports static,
  rotation, status, revoke, or recovery semantics worth declaring.
- `CreateRecoverer` is implemented only for true lookup-by-idempotency-key
  upstreams.
- Registration happens in a composition root, not inside `credentials/`.
- Lifecycle policy admits only the credential types and recovery posture the
  provider can honestly support.
- Errors and logs carry no material, raw provider response bodies, raw metadata,
  or private locators.
