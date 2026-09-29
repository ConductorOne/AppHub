// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/conductorone/apphub/credentials"
)

// WebIdentityTokenSource mints the OIDC token presented to
// AssumeRoleWithWebIdentity.
//
// It is an interface so that this package never holds a signing key: the
// implementation is the platform's own OIDC issuer, whose key lives in a KMS or
// an HSM. That is the same reasoning as credentials/c1's AssertionSigner
// (credentials/c1/register.go:92-102), and the two are deliberately separate
// interfaces -- an assertion exchanged for a ConductorOne token and a web
// identity presented to STS have different audiences and different lifetimes, and
// one interface serving both would make a change for either a change for both.
//
// The returned token is a bearer credential for as long as it is valid, which is
// why it is a credentials.Secret. The source passed it as a bare string
// (claude.go:112-119), one %v away from a log line.
type WebIdentityTokenSource interface {
	// WebIdentityToken returns a signed token asserting subject, for audience,
	// valid for ttl.
	WebIdentityToken(ctx context.Context, subject, audience string, ttl time.Duration) (credentials.Secret, error)
}

// Provider vends AWS-native credentials for Bedrock model invocation.
//
// # Differences from the internal implementation
//
// Every one of them fails closed, and each names the source line it changes.
//
//   - A role is required for the dynamic path. The source presigned with the
//     platform's own ambient credentials when role_arn was absent
//     (claude.go:96-152 skips the assume-role block entirely), so the requester
//     received a Bedrock token authenticating as the platform. This is the
//     consequential one.
//   - The role, the region, the IAM path, the attached policy and the
//     permissions boundary are operator configuration, not request metadata. The
//     source read all but the first two out of the per-request metadata bag
//     (claude.go:66, claude.go:96, claude.go:236), so a caller chose the role it
//     was given and could omit the boundary. This provider reads no metadata at
//     all -- see the note on RevokeCredential.
//   - A permissions boundary is required. The source treated it as optional
//     (claude.go:236-238), so the common path created an unbounded IAM user.
//   - TTL is required and is never substituted. The source defaulted a dynamic
//     TTL to an hour (claude.go:80-83) and, for a static credential, omitted
//     CredentialAgeDays when no TTL was given (claude.go:255-261) -- which AWS
//     documents as "the credential will not expire".
//   - A static TTL must be a whole number of days. The source computed
//     int32(TTL.Hours()/24) and forced a floor of 1 (claude.go:256-259), so a
//     twelve-hour request became a twenty-four-hour credential: an extension, not
//     a rounding. Refusing and naming the limit is docs/decisions/'s rule for a
//     substrate that cannot express what the interface permits.
//   - A dynamic TTL outside STS's 15-minute-to-12-hour window is refused rather
//     than clamped (the source clamped, claude.go:84-86).
//   - Created IAM users carry an ownership marker that teardown reads before it
//     deletes anything. The source deleted whatever user the handle named
//     (claude.go:354-409). An IAM user name is account-global and derived from a
//     mutable application name, so a name that was ours once can be somebody
//     else's later -- compute/aws/names.go:19-23 records the same finding.
//   - Teardown paginates. The source read one page of each of
//     ListAttachedUserPolicies, ListUserPolicies and ListAccessKeys
//     (claude.go:355-401), so a user with more entities than one page left them
//     behind and DeleteUser then failed with a conflict.
//   - Teardown reports its failures. The source discarded the error from every
//     detach and delete on the way (claude.go:360, 372, 384, 396) and returned
//     only DeleteUser's.
//   - An unrecognised platform key ID is an error. The source returned nil from
//     RevokeCredential for anything that did not start with "{"
//     (claude.go:288-290), so a revoke of a dynamic credential reported success
//     having done nothing, and the record was finalized as revoked.
//   - A non-empty CreateRequest.RequestedScope is refused with
//     credentials.ErrScopeNotSupported. What a vended credential may do is the
//     operator's configuration here, so a caller's narrowing cannot be honored --
//     and ignoring one would return something wider than was asked for.
//   - Errors carry an operation constant and an HTTP status code, and nothing
//     from the AWS response. See fault.go.
//   - Sanitizing a name never falls back to a compiled-in identifier and never
//     truncates. See names.go.
//
// # Not ported
//
// The honeytoken provider (honeytoken_aws.go) is deliberately absent, per the
// standing decision that honeytoken providers are out of scope for the public
// repository. See docs/decisions/.
//
// A Provider is safe for concurrent use: it holds configuration and two AWS
// clients, all of which are read-only after construction.
type Provider struct {
	cfg     Config
	sts     stsAPI
	iam     iamAPI
	tokens  WebIdentityTokenSource
	presign presignerFor
	now     func() time.Time
}

// Option configures a Provider.
type Option func(*Provider)

// WithWebIdentity makes the dynamic path use AssumeRoleWithWebIdentity, with src
// minting the token.
//
// Whether web identity federation is used is settled at construction and not per
// request. The source preferred it and fell back to a plain AssumeRole when no
// OIDC provider was wired (claude.go:110-139), which reads as a preference chain
// and is not one: the fallback was reachable only when the provider was nil, so
// the decision was already a wiring decision -- it was just spelled as a runtime
// branch that a later reader could make reachable for a different reason. Here
// there is no fallback in either direction, so a deployment cannot silently stop
// federating.
//
// A nil src is ignored rather than accepted, because accepting one would produce
// exactly the fallback this option exists to remove.
func WithWebIdentity(src WebIdentityTokenSource) Option {
	return func(p *Provider) {
		if src != nil {
			p.tokens = src
		}
	}
}

// NewProvider builds a provider from a validated configuration and the clients
// it will use.
//
// The clients are supplied rather than constructed here, and nil is meaningful:
// a nil client says the corresponding capability is not available, and this
// function reports the mismatch if cfg says otherwise. Both halves are
// compute/aws/awssdk.go:32-40's contract rather than a new one -- where
// credentials come from and how retry is configured are the composition root's
// decisions, and four rounds of trying to own retry from inside a provider are
// recorded there.
//
// stsClient is needed by the dynamic path, iamClient by the static path. Passing
// a client for a credential type that is not configured is legal and ignored: a
// composition root that builds both clients unconditionally should not have to
// know which types an operator enabled.
func NewProvider(cfg Config, stsClient *sts.Client, iamClient *iam.Client, opts ...Option) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, now: time.Now, presign: newPresigner}
	if stsClient != nil {
		p.sts = stsClient
	}
	if iamClient != nil {
		p.iam = iamClient
	}
	for _, opt := range opts {
		opt(p)
	}
	if err := p.checkClients(); err != nil {
		return nil, err
	}
	return p, nil
}

// checkClients refuses a provider that would fail on its first vend.
//
// Registering a provider whose configured credential type has no client to reach
// AWS with defers a configuration error to whenever somebody first asks for a
// credential, which is the least useful moment for it to arrive.
func (p *Provider) checkClients() error {
	if p.cfg.Dynamic != nil && p.sts == nil {
		return fmt.Errorf("%w: dynamic credentials need an STS client", ErrMissingClient)
	}
	if p.cfg.Static != nil && p.iam == nil {
		return fmt.Errorf("%w: static credentials need an IAM client", ErrMissingClient)
	}
	return nil
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
func (p *Provider) Name() string { return "AWS Bedrock (STS and IAM)" }

// SupportsDynamic reports whether this deployment configured dynamic
// credentials.
func (p *Provider) SupportsDynamic() bool { return p.cfg.Dynamic != nil }

// Capabilities declares what this provider can do, which depends on what the
// operator configured.
//
// Dynamic and Static come straight from the configuration, because a credential
// type nobody configured cannot be vended and claiming otherwise would have
// lifecycle.CheckIssuable admit a request this provider then refuses.
//
// Revoke is true exactly when static credentials are configured, and that is not
// an approximation. A Bedrock bearer token is a presigned request: AWS holds no
// record of it and offers nothing to revoke, so RevokeCredential returns
// credentials.ErrRevokeNotSupported for a dynamic handle. lifecycle.CheckIssuable
// consults Revoke only to refuse a *static* vend through a provider that cannot
// revoke, which is the question this answers.
//
// Status is true exactly when static credentials are configured, for the same
// reason: a static credential's liveness is a question IAM can answer, and a
// dynamic one's is derived locally from the expiry in the handle. That is
// credentials/github's reading of this bit (github.go:262-266) -- Status means
// "the provider is consulted", not "an answer exists".
//
// Rotate and RecoverCreate are false, and RecoverCreate is the one worth
// explaining. IAM accepts no idempotency token on CreateUser or
// CreateServiceSpecificCredential, and the handle this package returns is derived
// from the request's name rather than from CreateRequest.IdempotencyKey -- so a
// ResolveCreate given only the key has nothing to look the user up by. Making it
// implementable means deriving the IAM user name from the idempotency key, which
// changes what an operator sees in their console and belongs in its own ticket.
// The consequence is deliberate and visible rather than papered over:
// lifecycle.CheckIssuable refuses to issue through this provider unless the
// operator sets ProviderPolicy.AllowUnrecoverableIssuance.
func (p *Provider) Capabilities() credentials.Capabilities {
	return credentials.Capabilities{
		Dynamic:       p.cfg.Dynamic != nil,
		Static:        p.cfg.Static != nil,
		Revoke:        p.cfg.Static != nil,
		Status:        p.cfg.Static != nil,
		Rotate:        false,
		RecoverCreate: false,
	}
}

// CreateCredential vends a credential of the requested type.
func (p *Provider) CreateCredential(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	if len(req.RequestedScope) > 0 {
		return nil, fmt.Errorf("%w: what an AWS credential from this provider may do is "+
			"operator configuration, not a request parameter", credentials.ErrScopeNotSupported)
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("aws: a positive TTL is required for %s credentials and has no default",
			credentials.DescribeType(req.CredentialType))
	}
	switch req.CredentialType {
	case credentials.CredentialTypeDynamic:
		if p.cfg.Dynamic == nil {
			return nil, fmt.Errorf("%w: %s", ErrTypeNotConfigured, credentials.DescribeType(req.CredentialType))
		}
		return p.createDynamic(ctx, req)
	case credentials.CredentialTypeStatic:
		if p.cfg.Static == nil {
			return nil, fmt.Errorf("%w: %s", ErrTypeNotConfigured, credentials.DescribeType(req.CredentialType))
		}
		return p.createStatic(ctx, req)
	default:
		// Neither of the two constants. The source dispatched with an if/else on
		// dynamic and treated everything else as static (claude.go:71-74), so an
		// empty or unrecognised type vended a long-lived IAM user.
		return nil, fmt.Errorf("aws: cannot vend %s", credentials.DescribeType(req.CredentialType))
	}
}

// RevokeCredential revokes a credential this provider minted.
//
// The metadata argument is unused, and that is a property worth stating rather
// than an omission. Every identifier this provider acts on is operator
// configuration fixed at construction, so a revoke cannot be pointed at a
// different region or a different account by whatever metadata a record happens
// to carry. The source read the region out of metadata at revoke time
// (claude.go:297-300), so a revoke whose metadata disagreed with the create's
// looked in the wrong account and reported a failure that was not one.
func (p *Provider) RevokeCredential(ctx context.Context, platformKeyID string, _ credentials.Metadata) error {
	kind, err := handleKind(platformKeyID)
	if err != nil {
		return err
	}
	switch kind {
	case handleDynamic:
		// A presigned request is not registered anywhere in AWS. Nothing can be
		// deleted and nothing can be told to stop honoring it; it stops working
		// when the signature expires and not before. credentials/github's
		// RevokeCredential (github.go:245-259) documents the same shape: the
		// lifecycle layer moves such a record to pending_revoke and finalizes it
		// only once the stated expiry has passed, so the leak is bounded by the
		// TTL and the audit trail says so.
		if _, err := parseDynamicHandle(platformKeyID); err != nil {
			return err
		}
		return fmt.Errorf("%w: a Bedrock bearer token is a presigned request and AWS holds no "+
			"record of it", credentials.ErrRevokeNotSupported)
	case handleStatic:
		if p.cfg.Static == nil {
			// The handle is one this package mints, but this deployment no longer
			// configures the path that mints it -- so there is no IAM client to
			// revoke with. Saying so is better than returning nil, which would
			// finalize the record as revoked while the credential still works.
			return fmt.Errorf("%w: this deployment no longer configures static credentials",
				ErrTypeNotConfigured)
		}
		userName, credentialID, err := parseStaticHandle(platformKeyID)
		if err != nil {
			return err
		}
		return p.revokeStatic(ctx, userName, credentialID)
	default:
		return ErrUnrecognizedHandle
	}
}

// GetCredentialStatus reports what became of a credential this provider minted.
func (p *Provider) GetCredentialStatus(ctx context.Context, platformKeyID string, _ credentials.Metadata) (credentials.CredentialStatus, error) {
	kind, err := handleKind(platformKeyID)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}
	switch kind {
	case handleDynamic:
		expiry, err := parseDynamicHandle(platformKeyID)
		if err != nil {
			return credentials.CredentialStatusUnknown, err
		}
		if !p.now().Before(expiry) {
			return credentials.CredentialStatusExpired, nil
		}
		// Active, and the word is doing less work than it looks. Nothing was
		// asked: the expiry came from this package at mint time, and a presigned
		// request cannot be invalidated early, so "not yet expired" is the whole
		// of what is knowable. Capabilities reports Status false when static
		// credentials are not configured, which is how a caller learns that.
		return credentials.CredentialStatusActive, nil
	case handleStatic:
		if p.cfg.Static == nil {
			return credentials.CredentialStatusUnknown, fmt.Errorf(
				"%w: this deployment no longer configures static credentials", ErrTypeNotConfigured)
		}
		userName, credentialID, err := parseStaticHandle(platformKeyID)
		if err != nil {
			return credentials.CredentialStatusUnknown, err
		}
		return p.statusStatic(ctx, userName, credentialID)
	default:
		return credentials.CredentialStatusUnknown, ErrUnrecognizedHandle
	}
}

// errNoCredentials is returned when AWS answers successfully with nothing in it.
//
// It is a distinct sentinel because the alternative is a nil dereference on a
// field the SDK models as a pointer, and because "STS said yes and returned no
// credentials" is a real answer that deserves its own diagnosis.
var errNoCredentials = errors.New("aws: AWS returned success and no credentials")
