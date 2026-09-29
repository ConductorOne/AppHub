// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

// Wire limits. Both are this package's own bounds on what it will read or send,
// not restatements of the upstream's.
const (
	// maxResponseBodyBytes caps a decoded response. A credential response is a
	// few hundred bytes; anything approaching this is not one.
	maxResponseBodyBytes = 1 << 20
	// maxDrainBytes caps how much of a failed response is read and discarded so
	// the connection can be reused. The content is never looked at.
	maxDrainBytes = 1 << 16
	// maxDisplayNameBytes is the upstream's own limit on a credential name. A
	// name over it is refused here rather than upstream, so the failure names the
	// field instead of arriving as an opaque 400.
	maxDisplayNameBytes = 512
	// maxScopedRoles is the upstream's own limit on the scope list.
	maxScopedRoles = 32
)

// API paths. Relative to Config.BaseURL, which Config.Validate has already
// constrained to an https URL with no query, fragment or userinfo.
const (
	// tokenPath is the OAuth token endpoint. It is a path, not a credential: the
	// secret is resolved from the deployment's secret store at each fetch and is
	// never in this repository. Verified against the source system's own
	// ConductorOne client, which posts a client-credentials grant to exactly this
	// path on the tenant host.
	//
	//nolint:gosec // G101: the name of an endpoint, not a credential.
	tokenPath          = "/auth/v1/token"
	servicePrincipalsP = "/api/v1/service_principals/"
	credentialsP       = "/credentials"
)

// assertionTTL is how long a signed assertion presented to the token endpoint is
// valid for. Short: it is presented once, immediately, and a longer window is
// only a longer window in which a captured assertion is replayable.
const assertionTTL = 5 * time.Minute

// tokenRefreshSkew is how far before a token's stated expiry it is refreshed, so
// that a token is never presented in the last moments of its life to a server
// whose clock differs from ours.
//
// It is capped at half the token's own lifetime. Subtracting a fixed skew from a
// short-lived token yields an already-expired token and a refresh on every single
// call, which is a self-inflicted denial of service against the token endpoint.
const tokenRefreshSkew = 5 * time.Minute

// clientAssertionType is the RFC 7523 §2.2 assertion type for a JWT presented as
// a client credential.
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// httpClient is the Client implementation over ConductorOne's HTTP API.
//
// It holds no credential material of its own beyond a cached access token: the
// OAuth client secret is resolved from the deployment's secret store on each
// token fetch, so rotating it takes effect without a redeploy and it is not
// sitting in a field for the lifetime of the process.
type httpClient struct {
	cfg   Config
	deps  Deps
	http  *credhttp.Client
	token *tokenCache
}

// NewClient returns a Client that talks to the ConductorOne tenant in cfg.
//
// It performs no network I/O. A provider that could not be constructed without a
// reachable tenant could not be constructed in a hermetic test either, and
// startup is not where an operator wants to discover that a tenant is down.
//
// The HTTP client is built by internal/credhttp, which owns redirect refusal and
// error classification. deps.Transport is the whole of what a caller may
// supply -- see Deps.Transport for why it is a http.RoundTripper and not an
// *http.Client.
func NewClient(cfg Config, deps Deps) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := deps.validate(cfg); err != nil {
		return nil, err
	}
	return &httpClient{
		cfg:   cfg,
		deps:  deps,
		http:  credhttp.New(deps.Transport),
		token: &tokenCache{},
	}, nil
}

// Compile-time proof that the HTTP implementation satisfies the contract.
var _ Client = (*httpClient)(nil)

// sealed implements Client's marker method. See Client.
func (c *httpClient) sealed() {}

// mintBody is the POST .../credentials request body.
//
// The field names are the tenant API's lowerCamelCase, and expires is a protobuf
// Duration, whose JSON form is a decimal number of seconds with an "s" suffix.
type mintBody struct {
	DisplayName string   `json:"displayName"`
	ScopedRoles []string `json:"scopedRoles,omitempty"`
	Expires     string   `json:"expires"`
	// RequireDPoP is sent explicitly rather than omitted.
	//
	// It is false, and it is stated rather than left to the upstream's default
	// because turning it on changes the protocol the *consumer* of the vended
	// credential has to speak: a DPoP-bound credential requires a
	// proof-of-possession key at token exchange, and credentials.CreateResult has
	// no way to hand a consumer one. A default that flipped upstream would
	// therefore vend credentials nothing in this repository can use.
	RequireDPoP bool `json:"requireDpop"`
}

// credentialBody is the credential object the API returns.
type credentialBody struct {
	ID                 string     `json:"id"`
	ServicePrincipalID string     `json:"servicePrincipalId"`
	ClientID           string     `json:"clientId"`
	ExpiresAt          *time.Time `json:"expiresAt"`
	ScopedRoleIDs      []string   `json:"scopedRoleIds"`
}

// mintResponseBody is the POST .../credentials response.
type mintResponseBody struct {
	Credential   credentialBody     `json:"credential"`
	ClientSecret credentials.Secret `json:"clientSecret"`
}

// getResponseBody is the GET .../credentials/{id} response.
type getResponseBody struct {
	Credential credentialBody `json:"credential"`
}

// Mint creates a credential.
func (c *httpClient) Mint(ctx context.Context, req MintRequest) (*MintResponse, error) {
	if !handleSegment.MatchString(req.ServicePrincipalID) || isDotSegment(req.ServicePrincipalID) {
		return nil, fmt.Errorf("c1: %w", ErrMalformedServicePrincipalID)
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		return nil, errors.New("c1: a credential display name is required")
	}
	if len(name) > maxDisplayNameBytes {
		return nil, fmt.Errorf("c1: credential display name is %d bytes (max %d)", len(name), maxDisplayNameBytes)
	}
	ttl := req.TTL
	if ttl <= 0 {
		return nil, ErrTTLRequired
	}
	if ttl > maxCredentialTTL {
		ttl = maxCredentialTTL
	}
	if len(req.ScopedRoleIDs) > maxScopedRoles {
		return nil, fmt.Errorf("c1: %d scoped roles requested (max %d)", len(req.ScopedRoleIDs), maxScopedRoles)
	}

	body, err := json.Marshal(mintBody{
		DisplayName: name,
		ScopedRoles: req.ScopedRoleIDs,
		Expires:     strconv.FormatInt(int64(ttl/time.Second), 10) + "s",
		RequireDPoP: false,
	})
	if err != nil {
		// Nothing here can fail to encode, and if it ever does the error is
		// derived from the values being encoded -- one of which is a
		// caller-supplied name.
		return nil, errors.New("c1: encoding the mint request failed")
	}

	op := credhttp.OpC1MintCredential()
	resp, err := c.do(ctx, http.MethodPost, collectionPath(req.ServicePrincipalID), op, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return nil, statusError(op, resp)
	}

	var decoded mintResponseBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&decoded); err != nil {
		// The decoder's own message quotes bytes of the response body, and a
		// credential response body is where material arrives.
		return nil, errors.New("c1: the mint response was not the expected JSON")
	}

	cred, err := decoded.Credential.toCredential(req.ServicePrincipalID)
	if err != nil {
		return nil, err
	}
	return &MintResponse{Credential: cred, ClientSecret: decoded.ClientSecret}, nil
}

// Get reads a credential's metadata.
func (c *httpClient) Get(ctx context.Context, ref Ref) (*Credential, error) {
	path, err := itemPath(ref)
	if err != nil {
		return nil, err
	}
	op := credhttp.OpC1GetCredential()
	resp, err := c.do(ctx, http.MethodGet, path, op, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, ErrCredentialNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, statusError(op, resp)
	}

	var decoded getResponseBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&decoded); err != nil {
		return nil, errors.New("c1: the credential response was not the expected JSON")
	}
	cred, err := decoded.Credential.toCredential(ref.ServicePrincipalID)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// Revoke destroys a credential.
//
// A credential that is already gone is a successful revoke. The point of the
// call is that the material no longer works, and a 404 says so; returning an
// error would leave the reconciler retrying against something nobody can find.
//
// The residual is worth naming rather than leaving implied: a 404 is also what a
// reference to somebody else's credential returns, so this cannot distinguish
// "already revoked" from "the handle names nothing". What makes the first the
// only realistic reading is that the handle is not caller-supplied context -- it
// is the platform's own record of a credential this provider minted, and
// ParseHandle has already refused anything that does not parse.
func (c *httpClient) Revoke(ctx context.Context, ref Ref) error {
	path, err := itemPath(ref)
	if err != nil {
		return err
	}
	op := credhttp.OpC1RevokeCredential()
	resp, err := c.do(ctx, http.MethodDelete, path, op, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil
	}
	if resp.StatusCode >= 400 {
		return statusError(op, resp)
	}
	drain(resp)
	return nil
}

// toCredential validates a decoded credential object and converts it.
//
// It cross-checks the service principal the response names against the one that
// was asked for. The response is the upstream's, the request's is ours, and a
// mismatch means a later revoke would be built from a handle addressing a
// credential this call did not create.
func (b credentialBody) toCredential(wantServicePrincipalID string) (Credential, error) {
	if b.ID == "" {
		return Credential{}, errors.New("c1: the response carried no credential ID")
	}
	if b.ServicePrincipalID != "" && b.ServicePrincipalID != wantServicePrincipalID {
		// Neither value is rendered: one is a response field and one is a
		// metadata value.
		return Credential{}, errors.New("c1: the response named a different service principal than the request")
	}
	ref := Ref{ServicePrincipalID: wantServicePrincipalID, CredentialID: b.ID}
	if _, err := FormatHandle(ref); err != nil {
		// The credential exists upstream and cannot be addressed. Reported as
		// malformed rather than as a delivery failure: the caller has no handle
		// to compensate with, which is a different and worse situation than
		// having one and no material.
		return Credential{}, fmt.Errorf("%w: the response's credential ID cannot be used as a handle", ErrMalformedHandle)
	}
	return Credential{
		Ref:           ref,
		ClientID:      b.ClientID,
		ExpiresAt:     b.ExpiresAt,
		ScopedRoleIDs: b.ScopedRoleIDs,
	}, nil
}

// collectionPath is the credentials collection for a service principal.
func collectionPath(servicePrincipalID string) string {
	return servicePrincipalsP + url.PathEscape(servicePrincipalID) + credentialsP
}

// itemPath is one credential.
//
// The Ref is re-validated here rather than trusted from the caller. Every path
// this package builds goes through this function or collectionPath, and both
// escape every segment: the identifiers arrive from a persisted record and from
// an upstream response, and neither is a source to build a URL from unchecked.
func itemPath(ref Ref) (string, error) {
	if _, err := FormatHandle(ref); err != nil {
		return "", err
	}
	return collectionPath(ref.ServicePrincipalID) + "/" + url.PathEscape(ref.CredentialID), nil
}

// do issues one authenticated request, bounded by Config.Timeout.
//
// The timeout is applied to the context and not to the HTTP client. That is the
// whole mechanism: internal/credhttp's own thirty-second timeout is a fixed
// backstop that a caller cannot change, so the shorter of the two deadlines wins
// and a Config.RequestTimeout above it will not take effect. Doing it any other
// way would mean reaching for a field on http.Client, which is the surface the
// USOSS-7 review defeated twice.
func (c *httpClient) do(ctx context.Context, method, path string, op credhttp.Op, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout())
	defer cancel()

	token, err := c.token.get(ctx, c.cfg, c.deps, c.http)
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL()+path, reader)
	if err != nil {
		return nil, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+credentials.Reveal(token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.http.Do(req, op)
}

// tokenCache holds one access token and serialises fetches of it.
type tokenCache struct {
	mu      sync.Mutex
	token   credentials.Secret
	expires time.Time
}

// now is the clock, so a test can pin one without sleeping. It is a package
// variable rather than a field because every construction path would otherwise
// have to thread it, and nothing outside this package can reach it.
var now = time.Now

// get returns a live access token, fetching one if the cached token is missing or
// close to expiry.
//
// The whole fetch happens under the mutex. A read-then-fetch-then-write would let
// a burst of concurrent calls each fetch their own token, which is not incorrect
// but is a stampede against the token endpoint at exactly the moment a
// deployment is busiest.
func (t *tokenCache) get(ctx context.Context, cfg Config, deps Deps, hc *credhttp.Client) (credentials.Secret, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.token.IsZero() && now().Before(t.expires) {
		return t.token, nil
	}

	token, lifetime, err := fetchToken(ctx, cfg, deps, hc)
	if err != nil {
		return credentials.Secret{}, err
	}

	skew := tokenRefreshSkew
	if half := lifetime / 2; half < skew {
		skew = half
	}
	t.token = token
	t.expires = now().Add(lifetime - skew)
	return token, nil
}

// tokenResponse is the OAuth token endpoint's response. Its field names are
// RFC 6749's snake_case, not the tenant API's lowerCamelCase.
type tokenResponse struct {
	AccessToken credentials.Secret `json:"access_token"`
	ExpiresIn   int64              `json:"expires_in"`
}

// fetchToken exchanges AppHub's own credentials for an access token.
//
// Two modes, and the difference between them is what is sent rather than where:
//
//   - AuthModeClientSecret posts the OAuth client secret, resolved from the
//     deployment's secret store on every fetch. This is the mode the source
//     system's ConductorOne client uses and is the one known to work.
//   - AuthModeFederatedJWT posts a signed assertion instead, in the RFC 7523
//     §2.2 form. Whether a ConductorOne tenant accepts one is assumption A8 in
//     docs/design/credential-vending.md and is the one assumption USOSS-8 could
//     neither confirm nor refute: the API surface available carries no evidence
//     either way. The mode is implemented to the standard rather than invented,
//     it is not the default, and an adopter enabling it against a tenant that
//     does not support it gets a refusal from the token endpoint on the first
//     call. It has never been run against ConductorOne.
func fetchToken(ctx context.Context, cfg Config, deps Deps, hc *credhttp.Client) (credentials.Secret, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)

	switch cfg.Mode() {
	case AuthModeClientSecret:
		secret, err := deps.Secrets.Resolve(ctx, cfg.ClientSecret)
		if err != nil {
			// The resolver's error is the deployment's own, not an upstream's,
			// but it is still text this package did not write.
			return credentials.Secret{}, 0, ErrClientSecretUnresolved
		}
		if secret.IsZero() {
			return credentials.Secret{}, 0, ErrClientSecretUnresolved
		}
		form.Set("client_secret", credentials.Reveal(secret))
	case AuthModeFederatedJWT:
		assertion, err := deps.Assertions.SignAssertion(ctx, cfg.EffectiveAudience(), assertionTTL)
		if err != nil {
			return credentials.Secret{}, 0, ErrAssertionUnavailable
		}
		if assertion.IsZero() {
			return credentials.Secret{}, 0, ErrAssertionUnavailable
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", credentials.Reveal(assertion))
	default:
		// Unreachable: Config.Validate refuses an unknown mode, and NewClient
		// validates before returning. Stated as a refusal rather than a
		// fallthrough to one of the modes, because a fallthrough would pick an
		// authentication scheme on an operator's behalf.
		return credentials.Secret{}, 0, ErrUnknownAuthMode
	}

	op := credhttp.OpC1FetchToken()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL()+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return credentials.Secret{}, 0, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req, op)
	if err != nil {
		return credentials.Secret{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return credentials.Secret{}, 0, statusError(op, resp)
	}

	var decoded tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&decoded); err != nil {
		return credentials.Secret{}, 0, errors.New("c1: the token response was not the expected JSON")
	}
	if decoded.AccessToken.IsZero() {
		return credentials.Secret{}, 0, errors.New("c1: the token response carried no access token")
	}
	if decoded.ExpiresIn <= 0 {
		// A token with no stated lifetime would be cached forever or refetched on
		// every call depending on which way the arithmetic fell. Refusing is the
		// only answer that does neither.
		return credentials.Secret{}, 0, errors.New("c1: the token response stated no positive lifetime")
	}
	return decoded.AccessToken, time.Duration(decoded.ExpiresIn) * time.Second, nil
}

// statusError turns a non-2xx response into an error built only from constants in
// this repository and the status code.
//
// The body is drained and discarded. An upstream error body is text this process
// did not write, and a ConductorOne error body describing a rejected credential
// is exactly where a credential would appear -- the same reasoning, and the same
// deliberate loss of diagnostics, as credentials/datadog.statusError. An operator
// who needs the body reads it from ConductorOne's side.
func statusError(op credhttp.Op, resp *http.Response) error {
	drain(resp)

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// AppHub's own credentials were rejected. Not transient, and not the
		// requester's problem: retrying will fail the same way until an operator
		// fixes the tenant configuration.
		return fmt.Errorf("%s failed (%d): %w", op, resp.StatusCode, ErrUnauthenticated)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%s failed (%d): %w", op, resp.StatusCode, credentials.ErrTransient)
	default:
		return fmt.Errorf("%s failed (%d)", op, resp.StatusCode)
	}
}

// drain reads and discards a bounded prefix of a response body so the connection
// can be reused.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
}
