// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package c1 vends credentials through ConductorOne.
//
// This is the only package in the repository permitted to depend on
// ConductorOne. Every other package reaches it through the CredentialProvider
// interface in github.com/conductorone/apphub/credentials, so a build that never
// imports this package has no ConductorOne dependency at all.
//
// `make boundary` proves that over the union of every build configuration --
// every build constraint ignored, so a dependency behind a tag nobody selects is
// still a finding -- and widening the allowlist in internal/boundary is the only
// way to change what it permits.
//
// Exactly one composition root is allowlisted to import this package, so that a
// binary in this repository can register the provider: github.com/conductorone/apphub/cmd/apphub.
// It reaches this package through Register, the single entry point, whose
// signature is pinned by RegisterFunc. Every library package -- without
// exception -- still may not import it, and that is the property an adopter's
// build graph depends on. See docs/design/credential-vending.md §11.3 for why
// that entry exists, which matters because an allowlist entry with no recorded
// reason is one a later reader deletes as cleanup.
//
// # What it vends
//
// A credential belonging to a ConductorOne *service principal* -- a non-human
// identity -- consisting of a client id and a client secret, scoped to a subset of
// that principal's roles and expiring after a bounded lifetime.
//
// Dynamic only. ConductorOne's create request requires a strictly positive
// lifetime, so a credential that never expires cannot be asked for, and
// CreateCredential refuses credentials.CredentialTypeStatic rather than vending a
// long one and calling it static. The upstream ceiling is 180 days; a longer
// requested TTL is clamped down to it and CreateResult.ExpiresAt reports what was
// actually granted.
//
// # How an adopter configures it
//
// Seven environment variables, three of them required (exactly one of the two
// secret forms). None has a default and none has a fallback: with none of them
// set, Config.Enabled is false, nothing registers a provider, and no request
// can reach ConductorOne even by accident.
// There is no default tenant URL, no default audience, and no hostname of any kind
// compiled into this package.
//
//	APPHUB_C1_TENANT_URL         required   the adopter's tenant base URL, https only
//	APPHUB_C1_CLIENT_ID          required   the OAuth client id; not a secret
//	APPHUB_C1_CLIENT_SECRET_REF  required*  a secret-store *reference* to the client secret
//	APPHUB_C1_CLIENT_SECRET      required*  the client secret itself (ECS Parameter Store injection)
//	APPHUB_C1_AUTH_MODE          optional   "client_secret" (default) or "federated_jwt"
//	APPHUB_C1_AUDIENCE           optional   audience asserted in federated_jwt mode
//	APPHUB_C1_REQUEST_TIMEOUT    optional   per-call timeout, a Go duration; default 15s
//
// *exactly one of CLIENT_SECRET_REF or CLIENT_SECRET in client_secret mode.
//
// Half-configured is refused at startup. Setting a tenant URL and no client id is
// an error and not a silent fallback to "ConductorOne is off": a deployment that
// believes it has ConductorOne vending and does not is worse than one that fails
// to start.
//
// Outside the environment an adopter needs an OAuth client at their tenant, that
// client's secret in their secret store, and a lifecycle ProviderPolicy for "c1".
// Because ConductorOne cannot resolve a vend whose response was lost -- see
// "What it cannot do" below -- that policy must set AllowUnrecoverableIssuance
// before the lifecycle layer will issue through this provider. That is deliberate:
// the operator is accepting a stated risk rather than discovering it.
//
// Per-request, credentials.Metadata must carry MetadataServicePrincipalID naming
// the identity to mint for. Required, no default: which identity a credential
// belongs to is a deployment's decision, and a fallback would mint against
// whichever principal this package happened to name. Nothing authenticating to
// ConductorOne is ever read from metadata.
//
// Wiring, in a composition root:
//
//	cfg, err := c1.ConfigFromEnv(os.Getenv)
//	switch {
//	case errors.Is(err, c1.ErrNotConfigured):
//		// This deployment does not use ConductorOne. Carry on.
//	case err != nil:
//		return err // half-configured; do not start
//	default:
//		if err := c1.Register(registry, cfg, c1.Deps{Secrets: mySecretStore}); err != nil {
//			return err
//		}
//	}
//
// Deps carries the collaborators this package will not implement itself: a secret
// resolver, an assertion signer, and an HTTP transport. Each is an interface
// because each is a thing a test must be able to replace, and because a package
// that reached a secret store or a signing key directly would be untestable
// without one. cmd/apphub ships a process-backed resolver, which reads an
// absolute file path or an environment variable ECS injected from Parameter
// Store; an adopter whose secrets live in
// a cloud secret manager implements SecretResolver and wires that instead.
//
// Register does not dial ConductorOne. Startup is not the place to discover that a
// tenant is unreachable, and a provider that cannot be registered without a
// working network cannot be registered in a hermetic test either.
//
// # What it cannot do, stated rather than discovered
//
// Every limit below is a property of ConductorOne's API, checked against it rather
// than assumed. docs/design/credential-vending.md §9 records the evidence.
//
//   - **An ambiguous vend cannot be recovered.** The create request has no
//     idempotency key, and the client secret is returned exactly once and is not
//     retrievable afterwards. A vend whose response is lost therefore leaves a
//     live credential that cannot be found again. The provider declares
//     Capabilities{RecoverCreate: false} and implements no
//     credentials.CreateRecoverer, so lifecycle.CheckIssuable refuses managed
//     issuance unless an operator has explicitly accepted it.
//   - **Status cannot report revoked.** A revoke deletes the credential rather than
//     tombstoning it, so an absent credential cannot be told apart from one that
//     lapsed and was cleaned up. GetCredentialStatus reports active, expired or
//     unknown, and unknown is a real answer rather than a synonym for either.
//   - **A requester is not expressible.** A ConductorOne credential belongs to a
//     service principal; the create request has no field for who asked for it, so
//     CreateRequest.RequesterID and RequesterType do not reach ConductorOne.
//   - **federated_jwt is unverified.** Whether a tenant accepts a client assertion
//     is assumption A8 and is unknown. The mode is implemented to RFC 7523 §2.2,
//     is not the default, and has never been run against ConductorOne.
//
// What it can do, equally deliberately: revoke. The credential has a stable
// identifier and DELETE destroys it, so this provider never returns
// credentials.ErrRevokeNotSupported -- a credential system that lies about
// revocation is worse than one that admits it cannot revoke, and the converse is
// worth stating too.
package c1
