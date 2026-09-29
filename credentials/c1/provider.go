// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/credentials"
)

// ProviderID is the registry key.
const ProviderID = "c1"

// providerName is what an operator sees. It is a constant and deliberately not a
// tenant name: a display string that varies per adopter is configuration, not
// code, and a tenant name in a public repository would be somebody's.
const providerName = "ConductorOne"

// MetadataServicePrincipalID names the ConductorOne service principal a
// credential is minted for.
//
// It is required and has no default. A ConductorOne credential belongs to a
// non-human identity, and which identity is a deployment's decision -- there is
// no sensible fallback, and a fallback would mint against whichever principal
// this package happened to name.
const MetadataServicePrincipalID = "c1_service_principal_id"

// The refusals this provider makes.
var (
	// ErrStaticNotSupported means a static credential was requested.
	//
	// ConductorOne cannot vend one. Its create request requires a strictly
	// positive lifetime, so there is no way to ask for a credential that does not
	// expire, and vending a 180-day credential in answer to a request for a
	// static one would be reporting a lifetime the caller did not ask for as
	// though it were none.
	ErrStaticNotSupported = errors.New("c1: only dynamic credentials are supported")

	// ErrServicePrincipalRequired means the metadata did not name one.
	ErrServicePrincipalRequired = errors.New("c1: metadata " + MetadataServicePrincipalID + " is required")

	// ErrMalformedServicePrincipalID means the metadata named something this
	// package will not put in a URL.
	//
	// It carries nothing from the value. A metadata value is caller-supplied, and
	// credentials.Metadata already establishes that metadata values do not
	// render: a misconfiguration that put a credential in this field would
	// otherwise print it.
	ErrMalformedServicePrincipalID = errors.New("c1: metadata " + MetadataServicePrincipalID + " is not a usable identifier")

	// ErrTTLRequired means a non-positive TTL was requested. ConductorOne
	// refuses one, and defaulting it would invent a lifetime.
	ErrTTLRequired = errors.New("c1: a positive TTL is required")

	// ErrClientSecretUnresolved means the deployment's secret store did not
	// return AppHub's OAuth client secret. It carries nothing from the
	// resolver's own error, which is text this package did not write.
	ErrClientSecretUnresolved = errors.New("c1: the OAuth client secret could not be resolved from the secret store")

	// ErrAssertionUnavailable means the assertion signer did not produce one.
	ErrAssertionUnavailable = errors.New("c1: the signed assertion could not be produced")

	// ErrUnknownAuthMode means an authentication mode reached the token fetch
	// that Config.Validate should have refused.
	ErrUnknownAuthMode = errors.New("c1: unknown authentication mode")
)

// Provider vends ConductorOne service-principal credentials.
//
// # What it can and cannot do, and why each is a fact rather than a policy
//
// Every line of Capabilities below is derived from the API this package was
// verified against rather than chosen:
//
//   - Dynamic only. The create request's lifetime must be positive, so a
//     credential that never expires cannot be asked for.
//   - Revoke is real. A credential has a stable identifier and DELETE destroys
//     it, and unlike the GitHub App path the caller does not need the material to
//     authenticate the call. This provider therefore never returns
//     credentials.ErrRevokeNotSupported, and that is worth stating positively:
//     the sentinel exists for providers that cannot revoke, and returning it here
//     would be admitting to a limitation that does not exist.
//   - Status is real, but cannot report revoked. ConductorOne deletes a revoked
//     credential rather than tombstoning it, and it may also stop returning one
//     that has lapsed, so an absent credential is ambiguous between the two and
//     is reported as credentials.CredentialStatusUnknown. Unknown is the honest
//     answer and is not a synonym for either; see GetCredentialStatus.
//   - RecoverCreate is false. The create request has no idempotency key and the
//     secret is returned exactly once, so a vend whose response is lost leaves a
//     live credential that cannot be found again. That is not a gap this package
//     can close, so it is declared rather than hidden, and
//     lifecycle.CheckIssuable refuses managed issuance through this provider
//     unless an operator explicitly accepts it.
//
// # What arrives per call and what is configured
//
// Unlike credentials/datadog, this provider holds its own authentication: an
// adopter configures a tenant and an OAuth client once, and the collaborators
// that reach a secret store or a signing key arrive through Deps. Nothing
// authenticating to ConductorOne is ever read from credentials.Metadata, and
// nothing is compiled in. Metadata carries one value, the service principal, and
// that is a target rather than a credential.
//
// A Provider is safe for concurrent use.
type Provider struct {
	client Client
}

// NewProvider returns a provider over client.
//
// It exists separately from Register so that a test can supply a stub Client. The
// composition root uses Register.
func NewProvider(client Client) (*Provider, error) {
	if client == nil {
		return nil, errors.New("c1: a client is required")
	}
	return &Provider{client: client}, nil
}

// Compile-time proof that the provider satisfies the contract, and that its
// capability declaration is not the only thing asserting what it can do.
var (
	_ credentials.CredentialProvider = (*Provider)(nil)
	_ credentials.CapabilityReporter = (*Provider)(nil)
)

// ID returns the registry key.
func (p *Provider) ID() string { return ProviderID }

// Name returns the human-readable provider name.
func (p *Provider) Name() string { return providerName }

// SupportsDynamic reports true: short-lived, role-scoped credentials are the
// whole point of the integration.
func (p *Provider) SupportsDynamic() bool { return true }

// Capabilities declares what this provider can do. See the type comment for why
// each value is a fact about the API rather than a choice.
func (p *Provider) Capabilities() credentials.Capabilities {
	return credentials.Capabilities{
		Dynamic:       true,
		Static:        false,
		Revoke:        true,
		Status:        true,
		Rotate:        false,
		RecoverCreate: false,
	}
}

// CreateCredential mints a ConductorOne credential.
//
// The result's PlatformKeyID is a handle carrying both halves of the upstream
// reference, because ConductorOne addresses a credential by a pair and the
// neutral contract carries one string. See Ref for why the handle is
// self-contained rather than reassembled from metadata at revoke time.
func (p *Provider) CreateCredential(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	if req.CredentialType != credentials.CredentialTypeDynamic {
		return nil, fmt.Errorf("%w, got %s", ErrStaticNotSupported, credentials.DescribeType(req.CredentialType))
	}
	spID, err := servicePrincipalID(req.Metadata)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Mint(ctx, MintRequest{
		ServicePrincipalID: spID,
		DisplayName:        req.Name,
		ScopedRoleIDs:      req.RequestedScope,
		TTL:                req.TTL,
	})
	if err != nil {
		return nil, err
	}

	handle, err := FormatHandle(resp.Credential.Ref)
	if err != nil {
		// The client already refused a reference it could not format, so reaching
		// here means a Client implementation returned one it should not have.
		return nil, err
	}

	// Least privilege has one direction that cannot be recovered from after the
	// fact, so it is checked rather than trusted. A credential wider than what was
	// asked for is revoked here rather than returned: unlike missing material,
	// there is no honest way to hand this to the caller and let the lifecycle layer
	// decide, because handing it over is the harm.
	if widened := widenedScope(req.RequestedScope, resp.Credential.ScopedRoleIDs); widened > 0 {
		if revokeErr := p.client.Revoke(ctx, resp.Credential.Ref); revokeErr != nil {
			// The over-privileged credential is live and nothing else knows its
			// handle. Both facts have to survive: the handle travels in a
			// CreateNotDeliveredError, which is the neutral contract's channel for
			// exactly this, and the reason travels alongside it.
			return nil, fmt.Errorf("%w (%d role(s)): %w",
				ErrScopeWidened, widened, credentials.NewCreateNotDelivered(ProviderID, handle))
		}
		return nil, fmt.Errorf("%w (%d role(s)); the credential was revoked", ErrScopeWidened, widened)
	}

	// A consumer needs both halves to authenticate, so a response missing either
	// is an undelivered credential rather than a partial one.
	//
	// The provider does not revoke it. Compensating for a half-completed vend is
	// the lifecycle layer's decision, and a provider that quietly revoked on its
	// way out of an error would be making that decision where nobody can see it.
	// The handle has to survive -- it is the only record anyone will have of a
	// credential that needs destroying -- and it must not be rendered, because it
	// is built from a value the response chose. Both hold at once only through a
	// type. This is a deliberate divergence from docs/design/credential-vending.md
	// §3, which predates credentials.CreateNotDeliveredError and told this
	// provider to revoke; see the USOSS-8 report.
	if resp.ClientSecret.IsZero() || resp.Credential.ClientID == "" {
		return nil, credentials.NewCreateNotDelivered(ProviderID, handle)
	}

	// ExpiresAt is whatever ConductorOne said and is never computed locally. The
	// contract reads a non-nil value as an expiry the provider stated, and
	// lifecycle.Record.ExpiryAuthoritative is derived from it -- so a locally
	// computed now+TTL here would let the reconciler retire the record of a
	// credential that still works.
	//
	// GrantedScope is the upstream's list rather than the request's, per the
	// contract's preference for what was granted over what was asked for. It is
	// nil when ConductorOne described no scope, which the contract reads as "the
	// provider does not describe scope" and not as "unscoped".
	return &credentials.CreateResult{
		PlatformKeyID: handle,
		Credentials: map[string]credentials.Secret{
			// Both halves are carried as Secret. The client id is not itself
			// secret, but the map is Secret-typed and a consumer needs the pair;
			// splitting them across a rendering type and a bare string would be
			// one %v away from the question of which was which.
			CredentialKeyClientID:     credentials.NewSecret(resp.Credential.ClientID),
			CredentialKeyClientSecret: resp.ClientSecret,
		},
		ExpiresAt:    resp.Credential.ExpiresAt,
		GrantedScope: resp.Credential.ScopedRoleIDs,
	}, nil
}

// The names a consumer knows the two halves of a ConductorOne credential by.
const (
	// CredentialKeyClientID is the public half.
	CredentialKeyClientID = "client_id"
	// CredentialKeyClientSecret is the secret half.
	// The value is the name a consumer knows the secret half by, not a secret.
	CredentialKeyClientSecret = "client_secret"
)

// RevokeCredential destroys a credential.
//
// It never returns credentials.ErrRevokeNotSupported: ConductorOne can revoke by
// identifier, so claiming otherwise would be a provider admitting to a limit it
// does not have. metadata is unused, and that is the point -- everything needed
// to name the credential is in the handle, so a caller cannot change what gets
// revoked by changing what it passes here.
func (p *Provider) RevokeCredential(ctx context.Context, platformKeyID string, _ credentials.Metadata) error {
	ref, err := ParseHandle(platformKeyID)
	if err != nil {
		return err
	}
	return p.client.Revoke(ctx, ref)
}

// GetCredentialStatus asks ConductorOne what became of a credential.
//
// Three of the four statuses are reachable, and the missing one is a fact about
// the API rather than an omission here:
//
//   - Active: ConductorOne returns the credential and its expiry has not passed.
//   - Expired: it returns the credential and the expiry has passed.
//   - Unknown: it does not recognise the credential, or returns one with no
//     expiry at all. The first is ambiguous between revoked and expired-and-gone,
//     because a revoke deletes rather than tombstones; the second does not match
//     the API this package was written against, and "the response was not what I
//     expect" is not knowledge about a credential.
//   - Revoked is not reachable. There is no revoked-but-present state to observe.
//     A revoked record is finalised by the revoke path, which is where
//     lifecycle's own rule puts it -- only a successful upstream revoke finalises
//     -- so nothing depends on deriving it from a status read.
//
// Reporting Unknown for an absent credential rather than Revoked is the same rule
// the design states for an unrecognised grant: the platform must not conclude a
// credential is dead because the system that issued it has forgotten it.
func (p *Provider) GetCredentialStatus(ctx context.Context, platformKeyID string, _ credentials.Metadata) (credentials.CredentialStatus, error) {
	ref, err := ParseHandle(platformKeyID)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}

	cred, err := p.client.Get(ctx, ref)
	switch {
	case errors.Is(err, ErrCredentialNotFound):
		// A real answer, not a failure: the caller asked what ConductorOne knows
		// and the answer is nothing.
		return credentials.CredentialStatusUnknown, nil
	case err != nil:
		return credentials.CredentialStatusUnknown, err
	case cred == nil:
		return credentials.CredentialStatusUnknown, errors.New("c1: the client returned neither a credential nor an error")
	case cred.ExpiresAt == nil:
		return credentials.CredentialStatusUnknown, nil
	case cred.ExpiresAt.After(now()):
		return credentials.CredentialStatusActive, nil
	default:
		return credentials.CredentialStatusExpired, nil
	}
}

// servicePrincipalID pulls the target service principal out of metadata and
// refuses anything this package will not put in a URL.
func servicePrincipalID(metadata credentials.Metadata) (string, error) {
	id := strings.TrimSpace(metadata[MetadataServicePrincipalID])
	if id == "" {
		return "", ErrServicePrincipalRequired
	}
	if !handleSegment.MatchString(id) || isDotSegment(id) {
		return "", ErrMalformedServicePrincipalID
	}
	return id, nil
}

// widenedScope returns how many granted roles were not requested.
//
// An empty request is not a request for nothing: ConductorOne intersects the
// request with the service principal's own roles, so an empty list means "do not
// narrow" and whatever comes back is the principal's own scope. Comparing against
// an empty request would report every granted role as a widening, which would
// make the check fire on every unscoped vend and be turned off within a week.
func widenedScope(requested, granted []string) int {
	if len(requested) == 0 {
		return 0
	}
	want := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		want[r] = struct{}{}
	}
	extra := 0
	for _, g := range granted {
		if _, ok := want[g]; !ok {
			extra++
		}
	}
	return extra
}
