// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

// ProviderID is the registry key for this provider.
const ProviderID = "github"

// Metadata keys this provider reads.
const (
	// MetadataAppID is the numeric GitHub App ID.
	MetadataAppID = "app_id"
	// MetadataPrivateKey is the app's PEM-encoded RSA private key. Material.
	MetadataPrivateKey = "private_key"
	// MetadataInstallationID names the installation to mint a token from.
	MetadataInstallationID = "installation_id"
	// MetadataAPIBaseURL overrides the API root for GitHub Enterprise Server.
	MetadataAPIBaseURL = "api_base_url"
	// MetadataRepositories restricts the token to these repository names.
	MetadataRepositories = "repositories"
	// MetadataRepositoryIDs restricts the token to these repository IDs.
	MetadataRepositoryIDs = "repository_ids"
	// MetadataPermissions restricts the token's permissions, as a JSON object.
	MetadataPermissions = "permissions"
)

// platformKeyPrefix is the first segment of the synthetic handle this provider
// returns. GitHub gives no identifier for a minted token, so the handle is built
// from what is known: the installation, and the expiry GitHub stated.
const platformKeyPrefix = "inst"

// maxScopeEntries bounds each scoping list. An installation token request is
// operator configuration, not a bulk API, and an unbounded list is an unbounded
// request body.
const maxScopeEntries = 128

// ErrScopeResolvesToNothing means a scoping metadata key was present but yielded
// no entries.
//
// It is refused because of what GitHub does with an absent scoping field: it
// grants the whole installation. So a "repositories" value of ", ," would, if
// ignored, turn an operator's attempt to restrict a token into a token for every
// repository the app is installed on -- a widening produced by a typo.
var ErrScopeResolvesToNothing = errors.New("github: scoping metadata is present but resolves to no entries")

// Provider vends GitHub App installation access tokens.
//
// # Differences from the internal implementation
//
// Every one of them fails closed:
//
//   - A non-empty CreateRequest.RequestedScope is refused with
//     credentials.ErrScopeNotSupported. This provider's scope comes from operator
//     metadata, not from the request, so it cannot honor a caller's narrowing --
//     and ignoring one would hand back a token wider than was asked for.
//   - A scoping key that resolves to nothing is refused. See
//     ErrScopeResolvesToNothing; the source silently fell back to the full
//     installation grant.
//   - CreateResult.GrantedScope reports what GitHub actually granted -- the
//     permissions, the repository selection, and the repositories in the response.
//     The source discarded all of it, so a record said what was asked for and
//     never what was given.
//   - api_base_url must be an absolute https URL. The source accepted any string
//     and sent an app JWT to it; see internal/githubapp.
//   - Errors carry a status code and nothing from the response at all, and
//     redirects are refused. githubapp.statusError drains the body and discards
//     it; a transport failure is reported as a classification rather than as the
//     transport's own text. See internal/githubapp and internal/credhttp.
//   - Capabilities are declared rather than inferred, because two of the inferred
//     answers would be wrong. See Capabilities.
//
// A Provider is safe for concurrent use: it holds only a caller-supplied
// http.RoundTripper, and the app credentials arrive per call in
// credentials.Metadata. It holds no *http.Client -- the opaque client that owns
// redirect refusal is constructed per githubapp.App, from that transport, inside
// internal/credhttp.
type Provider struct {
	transport http.RoundTripper
}

// Option configures a Provider.
type Option func(*Provider)

// WithTransport replaces the HTTP transport, for a caller that needs its own
// dialing, proxying, instrumentation or test double.
//
// It takes a http.RoundTripper and not an *http.Client on purpose, and that is a
// deliberate narrowing of an earlier API. Redirect refusal is a field on
// http.Client, so accepting a client let a caller replace this provider's central
// security invariant by supplying one for an unrelated reason. Every request here
// carries an app JWT, which is higher privilege than the installation token it
// buys. A RoundTripper cannot express a redirect policy, so this signature cannot
// be used to remove one. See internal/credhttp.
func WithTransport(rt http.RoundTripper) Option {
	return func(p *Provider) {
		if rt != nil {
			p.transport = rt
		}
	}
}

// NewProvider returns a GitHub provider. It performs no network I/O and needs no
// configuration: the app credentials arrive per request.
//
// The transport is held here rather than built per vend. Each CreateCredential
// constructs a githubapp.App around one installation's credentials, and
// connection pooling lives in the transport, so sharing one keeps a client per
// App cheap.
func NewProvider(opts ...Option) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Compile-time proof that the provider satisfies the contract.
var (
	_ credentials.CredentialProvider = (*Provider)(nil)
	_ credentials.CapabilityReporter = (*Provider)(nil)
)

// ID returns the registry key.
func (p *Provider) ID() string { return ProviderID }

// Name returns the human-readable provider name.
func (p *Provider) Name() string { return "GitHub" }

// SupportsDynamic reports true: an installation token always expires.
func (p *Provider) SupportsDynamic() bool { return true }

// Capabilities declares what this provider can do.
//
// Two of these would be inferred wrongly, which is the reason to declare them at
// all. credentials.CapabilitiesOf infers Revoke and Status true for an
// undeclared provider -- a safe default in general, because attempting an
// unsupported revoke costs one call and an error the lifecycle already handles.
// Here both are known to be false, and a declaration of a known fact is better
// than a default chosen for the unknown case:
//
//   - Revoke is false. GitHub does expose DELETE /installation/token, but it is
//     authenticated with the installation token itself, and this platform
//     deliberately does not retain the token after handing it to the requester.
//     The record holds a synthetic handle and nothing that can authenticate that
//     call. RevokeCredential returns credentials.ErrRevokeNotSupported.
//   - Status is false, in the precise sense the field documents: whether
//     GetCredentialStatus consults the provider. It does not -- it reads the
//     expiry GitHub stated at create time, which the handle carries. That answer
//     is worth having and GetCredentialStatus returns it, but it comes from the
//     platform's own record and this declaration says so rather than implying a
//     live check that never happens.
//
// Neither costs anything at admission: lifecycle.CheckIssuable consults Revoke
// only for a static vend, and this provider vends nothing static.
//
// RecoverCreate is false and cannot be otherwise. Minting an installation token
// has no idempotency notion at all -- CreateRequest.IdempotencyKey has nothing to
// be forwarded as, and there is no lookup that would say whether a lost response
// had minted one -- so this provider does not implement
// credentials.CreateRecoverer, and lifecycle.CheckIssuable refuses to issue
// through it unless the operator sets
// ProviderPolicy.AllowUnrecoverableIssuance. The mitigating fact, which is a
// property of the provider rather than of the contract, is that an unresolvable
// token is bounded by GitHub's one-hour cap.
func (p *Provider) Capabilities() credentials.Capabilities {
	return credentials.Capabilities{
		Dynamic:       true,
		Static:        false,
		Revoke:        false,
		Status:        false,
		Rotate:        false,
		RecoverCreate: false,
	}
}

// CreateCredential mints an installation access token.
func (p *Provider) CreateCredential(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	if req.CredentialType != credentials.CredentialTypeDynamic {
		return nil, fmt.Errorf("github: only dynamic credentials are supported, got %s", credentials.DescribeType(req.CredentialType))
	}
	if len(req.RequestedScope) > 0 {
		return nil, fmt.Errorf("%w: this provider takes its scope from operator metadata (%s, %s, %s)",
			credentials.ErrScopeNotSupported, MetadataRepositories, MetadataRepositoryIDs, MetadataPermissions)
	}

	appID, err := positiveInt(req.Metadata[MetadataAppID], MetadataAppID)
	if err != nil {
		return nil, err
	}
	installationID, err := positiveInt(req.Metadata[MetadataInstallationID], MetadataInstallationID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Metadata[MetadataPrivateKey]) == "" {
		return nil, fmt.Errorf("github: metadata %q is required", MetadataPrivateKey)
	}

	app, err := githubapp.NewApp(githubapp.AppConfig{
		AppID:         appID,
		PrivateKeyPEM: credentials.NewSecret(req.Metadata[MetadataPrivateKey]),
		BaseURL:       req.Metadata[MetadataAPIBaseURL],
		Transport:     p.transport,
	})
	if err != nil {
		return nil, err
	}

	tokenReq, err := scoping(req.Metadata)
	if err != nil {
		return nil, err
	}

	tok, err := app.MintInstallationToken(ctx, installationID, tokenReq)
	if err != nil {
		return nil, err
	}

	// The TTL is GitHub's, not ours: it caps an installation token at one hour and
	// this provider does not ask for anything else. CreateRequest.TTL is therefore
	// ignored, and ExpiresAt reports what GitHub chose -- which is a fact about the
	// material, so lifecycle records it as authoritative and may finalize on it.
	expiresAt := tok.ExpiresAt.UTC()
	return &credentials.CreateResult{
		PlatformKeyID: platformKeyID(installationID, expiresAt),
		APIKey:        tok.Token,
		ExpiresAt:     &expiresAt,
		GrantedScope:  grantedScope(tok),
	}, nil
}

// RevokeCredential cannot revoke, and says so.
//
// GitHub's DELETE /installation/token is authenticated with the installation
// token itself, and the platform does not keep the token after handing it to the
// requester -- only the synthetic handle survives on the record. So there is
// nothing to authenticate the call with, and reporting
// credentials.ErrRevokeNotSupported is the honest answer.
//
// What the lifecycle layer does with that is the interesting half: the record
// goes to pending_revoke rather than revoked, and is only finalized once the
// expiry GitHub stated has actually passed. The leak is therefore bounded by
// GitHub's one-hour cap and by nothing else, and the audit trail says so.
func (p *Provider) RevokeCredential(_ context.Context, _ string, _ credentials.Metadata) error {
	return credentials.ErrRevokeNotSupported
}

// GetCredentialStatus reports liveness from the expiry embedded in the handle.
//
// It makes no call to GitHub, and Capabilities reports Status false to say so.
// There is nothing to call: GitHub returns no identifier for a minted token and
// exposes no endpoint that describes one. The expiry in the handle came from
// GitHub at create time, so the answer is derived from a provider fact even
// though nothing is asked at read time.
//
// A handle in any other shape reports unknown, which the contract defines as
// "the provider does not track this" -- true here, and not a claim that the
// credential is gone.
func (p *Provider) GetCredentialStatus(_ context.Context, platformKeyID string, _ credentials.Metadata) (credentials.CredentialStatus, error) {
	expiry, ok := parsePlatformKeyID(platformKeyID)
	if !ok {
		return credentials.CredentialStatusUnknown, nil
	}
	if !time.Now().Before(expiry) {
		return credentials.CredentialStatusExpired, nil
	}
	return credentials.CredentialStatusActive, nil
}

// platformKeyID builds the synthetic handle: the installation and the expiry
// GitHub stated, which together are everything known about a token that GitHub
// itself will not identify.
func platformKeyID(installationID int64, expiresAt time.Time) string {
	return fmt.Sprintf("%s-%d-%d", platformKeyPrefix, installationID, expiresAt.Unix())
}

// parsePlatformKeyID recovers the expiry from a handle this provider minted.
func parsePlatformKeyID(id string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(id, platformKeyPrefix+"-")
	if !ok {
		return time.Time{}, false
	}
	_, expiry, ok := strings.Cut(rest, "-")
	if !ok {
		return time.Time{}, false
	}
	unix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(unix, 0).UTC(), true
}

// positiveInt parses a required numeric metadata value.
func positiveInt(raw, key string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("github: metadata %q is required", key)
	}
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("github: metadata %q must be a positive integer", key)
	}
	return n, nil
}

// scoping builds the token request from the optional metadata keys.
//
// The rule throughout: a key that is present must produce entries, because in
// GitHub's API the absence of a scoping field is the full installation grant.
func scoping(metadata credentials.Metadata) (githubapp.InstallationTokenRequest, error) {
	var out githubapp.InstallationTokenRequest

	if raw, present := present(metadata, MetadataRepositoryIDs); present {
		parts, err := splitList(raw, MetadataRepositoryIDs)
		if err != nil {
			return out, err
		}
		for i, part := range parts {
			id, err := strconv.ParseInt(part, 10, 64)
			if err != nil || id <= 0 {
				// The offending entry is deliberately not in the message: it is a
				// metadata value, and credentials.Metadata already establishes that
				// metadata values do not render. The position is enough to find it.
				return out, fmt.Errorf("github: metadata %q entry %d is not a positive integer", MetadataRepositoryIDs, i+1)
			}
			out.RepositoryIDs = append(out.RepositoryIDs, id)
		}
	}

	if raw, present := present(metadata, MetadataRepositories); present {
		parts, err := splitList(raw, MetadataRepositories)
		if err != nil {
			return out, err
		}
		out.Repositories = parts
	}

	if raw, present := present(metadata, MetadataPermissions); present {
		if raw == "" {
			// Present and blank. Refused here rather than left to json.Unmarshal so
			// the error names the real problem, and so a blank value can never be
			// mistaken for an absent key.
			return out, fmt.Errorf("%w: %q", ErrScopeResolvesToNothing, MetadataPermissions)
		}
		perms := map[string]string{}
		if err := json.Unmarshal([]byte(raw), &perms); err != nil {
			return out, fmt.Errorf("github: metadata %q must be a JSON object of permission names to levels", MetadataPermissions)
		}
		if len(perms) == 0 {
			return out, fmt.Errorf("%w: %q", ErrScopeResolvesToNothing, MetadataPermissions)
		}
		if len(perms) > maxScopeEntries {
			return out, fmt.Errorf("github: metadata %q declares %d permissions (max %d)", MetadataPermissions, len(perms), maxScopeEntries)
		}
		for name, level := range perms {
			if strings.TrimSpace(name) == "" || strings.TrimSpace(level) == "" {
				return out, fmt.Errorf("github: metadata %q contains an empty permission name or level", MetadataPermissions)
			}
		}
		out.Permissions = perms
	}

	// No scoping metadata at all is the ordinary "vend me a token for this
	// installation" request, and it is still allowed -- but it is now stated rather
	// than arrived at. githubapp refuses a request that restricts nothing unless
	// this is set, so the widest token this provider can produce takes a
	// deliberate line of code here instead of falling out of an empty map.
	if len(out.RepositoryIDs) == 0 && len(out.Repositories) == 0 && len(out.Permissions) == 0 {
		out.FullInstallationGrant = true
	}
	return out, nil
}

// present reports whether a metadata key exists at all, and returns its trimmed
// value.
//
// Membership, not emptiness. This distinction is the whole function: "the
// operator did not scope this token" and "the operator tried to and it came to
// nothing" must not be the same answer, because GitHub reads an omitted scoping
// field as the full installation grant. An earlier version tested
// strings.TrimSpace(metadata[key]) != "", which made `repositories = ""` and
// `repositories = " \t\n"` indistinguishable from an absent key -- and review
// verified all four such values reaching MintInstallationToken with the field
// omitted, escalating a restricted token to every repository the installation can
// reach. A map read cannot tell you which of those you have; only a two-value map
// read can.
func present(metadata credentials.Metadata, key string) (string, bool) {
	raw, ok := metadata[key]
	if !ok {
		return "", false
	}
	return strings.TrimSpace(raw), true
}

// splitList parses a comma-separated metadata list, refusing one that resolves to
// nothing.
func splitList(raw, key string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrScopeResolvesToNothing, key)
	}
	if len(out) > maxScopeEntries {
		return nil, fmt.Errorf("github: metadata %q has %d entries (max %d)", key, len(out), maxScopeEntries)
	}
	return out, nil
}

// grantedScope describes what GitHub actually granted, in this provider's own
// terms.
//
// Recording the answer rather than the request is the point: an installation
// token can come back narrower than asked for -- a permission the installation
// does not hold is simply not granted -- and a record that only remembers the
// request describes an intention instead of a credential. Sorted so the value is
// stable enough to compare across two vends.
func grantedScope(tok *githubapp.InstallationToken) []string {
	var out []string
	if sel := strings.TrimSpace(tok.RepositorySelection); sel != "" {
		out = append(out, "repository_selection:"+sel)
	}
	repos := make([]string, 0, len(tok.Repositories))
	for _, repo := range tok.Repositories {
		if name := strings.TrimSpace(repo.FullName); name != "" {
			repos = append(repos, "repository:"+name)
		}
	}
	sort.Strings(repos)
	out = append(out, repos...)

	perms := make([]string, 0, len(tok.Permissions))
	for name, level := range tok.Permissions {
		perms = append(perms, "permission:"+name+"="+level)
	}
	sort.Strings(perms)
	return append(out, perms...)
}
