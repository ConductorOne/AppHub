// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package datadog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

// ProviderID is the registry key for this provider.
const ProviderID = "datadog"

// defaultSite is the Datadog API host used when metadata names none.
const defaultSite = "api.datadoghq.com"

// Metadata keys this provider reads.
const (
	// MetadataAdminAPIKey is the Datadog API key used to authenticate key
	// management. Material.
	MetadataAdminAPIKey = "admin_api_key"
	// MetadataAdminAppKey is the matching Datadog application key. Material.
	MetadataAdminAppKey = "admin_app_key"
	// MetadataSite is the Datadog API host. Optional; see allowedSites.
	MetadataSite = "dd_site"
)

// allowedSites is the set of Datadog API hosts this provider will send an admin
// key to.
//
// It is exactly the set the internal implementation carried. Datadog has since
// added regions, and adding one here is a one-line reviewable change -- but
// guessing at a hostname that has never been verified is how a typo becomes a
// host somebody else controls, so nothing was added on the way out.
var allowedSites = map[string]struct{}{
	"api.datadoghq.com":     {},
	"api.us3.datadoghq.com": {},
	"api.us5.datadoghq.com": {},
	"api.datadoghq.eu":      {},
	"api.ap1.datadoghq.com": {},
	"api.ddog-gov.com":      {},
}

// allowedSiteNames returns the allowlist, sorted, for an error message. These are
// our own constants, so unlike the value being rejected they are safe to render.
func allowedSiteNames() []string {
	out := make([]string, 0, len(allowedSites))
	for site := range allowedSites {
		out = append(out, site)
	}
	sort.Strings(out)
	return out
}

// Bounds on what this provider will send or read.
const (
	// maxKeyNameLen bounds the key name forwarded to Datadog. The name is
	// caller-supplied and ends up in a request body; nothing needs it to be long.
	maxKeyNameLen = 256
	// maxDrainBytes bounds how much of a discarded error body is read to let the
	// connection be reused.
	maxDrainBytes = 4 << 10
	// maxResponseBodyBytes bounds how much of a success response is decoded.
	maxResponseBodyBytes = 1 << 20
)

// ErrSiteNotAllowed means dd_site named a host that is not a known Datadog API
// host. See allowedSites for why that is refused rather than trusted.
var ErrSiteNotAllowed = errors.New("datadog: dd_site is not a recognized Datadog API host")

// Provider vends Datadog API keys.
//
// # Differences from the internal implementation
//
// Each one is a case where the source's behavior would be wrong under the
// contract in docs/design/credential-vending.md, and all of them fail closed:
//
//   - CreateCredential refuses anything but a static credential. The source
//     reported SupportsDynamic() == false and then vended whatever it was asked
//     for.
//   - CreateResult.ExpiresAt is always nil. The source set it to now+TTL, which
//     reads as a provider-stated expiry: lifecycle.Record.ExpiryAuthoritative is
//     derived from whether this field was set, and a true there lets the
//     reconciler finalize a record as expired. A Datadog API key does not expire,
//     so that would have retired the record of a key that still works.
//   - A non-empty CreateRequest.RequestedScope is refused with
//     credentials.ErrScopeNotSupported. A Datadog API key is org-wide, so
//     honoring a narrowing request is not possible and ignoring one would grant
//     more than was asked for.
//   - Revoking a key that is already gone succeeds. The source treated the 404 as
//     a failure, which would have left the reconciler retrying a revoke that had
//     nothing left to revoke.
//   - Errors carry the status code and nothing from the response at all. The
//     source interpolated the whole response body; an earlier version of this port
//     kept Datadog's own bounded "errors" array, and the leak test rejected that
//     too, so statusError now drains the body and discards every byte of it. See
//     statusError for why the diagnostic loss is deliberate.
//   - Redirects are refused, and a caller cannot re-enable them. See
//     WithTransport and internal/credhttp.
//   - A transport failure is reported as a classification, never as the
//     transport's own error text. See internal/credhttp.
//
// A Provider is safe for concurrent use: it holds only an HTTP client, and every
// credential it needs arrives per call in credentials.Metadata.
type Provider struct {
	http *credhttp.Client
}

// Option configures a Provider.
type Option func(*Provider)

// WithTransport replaces the HTTP transport, for a caller that needs its own
// dialing, proxying, instrumentation or test double.
//
// It takes a http.RoundTripper and not an *http.Client on purpose, and that is a
// deliberate narrowing of an earlier API. Redirect refusal is a field on
// http.Client, so accepting a client let a caller replace this provider's central
// security invariant by supplying one for an unrelated reason -- review verified
// exactly that, following a synthetic 302 and sending DD-API-KEY to the second
// host. A RoundTripper cannot express a redirect policy, so this signature cannot
// be used to remove one.
//
// A supplied transport still sees the authenticated request, so its own errors
// are classified rather than returned: see internal/credhttp.
func WithTransport(rt http.RoundTripper) Option {
	return func(p *Provider) {
		if rt != nil {
			p.http = credhttp.New(rt)
		}
	}
}

// NewProvider returns a Datadog provider. It performs no network I/O and needs
// no configuration: the operator's Datadog credentials arrive per request.
func NewProvider(opts ...Option) *Provider {
	p := &Provider{http: credhttp.New(nil)}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Compile-time proof that the provider satisfies the contract, and that its
// capability declaration is not the only thing asserting it can revoke.
var (
	_ credentials.CredentialProvider = (*Provider)(nil)
	_ credentials.CapabilityReporter = (*Provider)(nil)
)

// ID returns the registry key.
func (p *Provider) ID() string { return ProviderID }

// Name returns the human-readable provider name.
func (p *Provider) Name() string { return "Datadog" }

// SupportsDynamic reports false: a Datadog API key has no expiry.
func (p *Provider) SupportsDynamic() bool { return false }

// Capabilities declares what this provider can do.
//
// Static and Revoke are the two that have to be declared. Without a declaration,
// credentials.CapabilitiesOf infers Static false -- the safe default for a
// provider of unknown shape -- and lifecycle.CheckIssuable would then refuse
// every credential this provider is capable of vending. Revoke is declared true
// because RevokeCredential really does delete the key upstream, which is also
// what lifecycle.CheckIssuable requires before it will admit a static vend at
// all.
//
// Rotate and RecoverCreate are false because neither is implementable here.
// Datadog has no endpoint that replaces the material behind an existing key, and
// no idempotent create: CreateRequest.IdempotencyKey has nothing to be forwarded
// as, so an ambiguous vend cannot be resolved afterwards and this provider does
// not implement credentials.CreateRecoverer. The consequence is deliberate and
// visible rather than papered over -- lifecycle.CheckIssuable refuses to issue
// through it unless the operator sets ProviderPolicy.AllowUnrecoverableIssuance.
func (p *Provider) Capabilities() credentials.Capabilities {
	return credentials.Capabilities{
		Dynamic:       false,
		Static:        true,
		Revoke:        true,
		Status:        true,
		Rotate:        false,
		RecoverCreate: false,
	}
}

// createKeyRequest is the POST /api/v2/api_keys body.
type createKeyRequest struct {
	Data createKeyData `json:"data"`
}

type createKeyData struct {
	Type       string              `json:"type"`
	Attributes createKeyAttributes `json:"attributes"`
}

type createKeyAttributes struct {
	Name string `json:"name"`
}

// apiKeyResponse is the api_keys response envelope.
type apiKeyResponse struct {
	Data apiKeyData `json:"data"`
}

type apiKeyData struct {
	ID         string           `json:"id"`
	Attributes apiKeyAttributes `json:"attributes"`
}

type apiKeyAttributes struct {
	// Key is the material, present only on create. It decodes straight into a
	// credentials.Secret so that it never exists as a string in this package.
	Key  credentials.Secret `json:"key"`
	Name string             `json:"name"`
}

// CreateCredential creates a Datadog API key.
func (p *Provider) CreateCredential(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	if req.CredentialType != credentials.CredentialTypeStatic {
		return nil, fmt.Errorf("datadog: only static credentials are supported, got %s", credentials.DescribeType(req.CredentialType))
	}
	if len(req.RequestedScope) > 0 {
		return nil, fmt.Errorf("%w: a Datadog API key is org-wide", credentials.ErrScopeNotSupported)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("datadog: a key name is required")
	}
	if len(name) > maxKeyNameLen {
		return nil, fmt.Errorf("datadog: key name is %d bytes (max %d)", len(name), maxKeyNameLen)
	}

	auth, err := extractAuth(req.Metadata)
	if err != nil {
		return nil, err
	}

	bodyJSON, err := json.Marshal(createKeyRequest{
		Data: createKeyData{Type: "api_keys", Attributes: createKeyAttributes{Name: name}},
	})
	if err != nil {
		return nil, errors.New("datadog: encoding the create request failed")
	}

	resp, err := p.do(ctx, http.MethodPost, auth, "/api/v2/api_keys", credhttp.OpDatadogCreateAPIKey(), bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return nil, statusError(credhttp.OpDatadogCreateAPIKey(), resp)
	}

	var keyResp apiKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&keyResp); err != nil {
		return nil, errors.New("datadog: create response was not the expected JSON")
	}
	if keyResp.Data.ID == "" {
		return nil, errors.New("datadog: create response carried no key ID")
	}
	if keyResp.Data.Attributes.Key.IsZero() {
		// The key exists upstream and cannot be handed over. The handle has to
		// survive -- it is the only record anyone will have of a key that needs
		// deleting -- and it must not be rendered, because it is a value the
		// response chose: review returned an administrative key in data.id and
		// watched the previous version of this line print it. Both hold at once
		// only through a type, so the handle travels in one and a caller asks for
		// it deliberately. See credentials.CreateNotDeliveredError.
		//
		// The provider does not delete the key itself. Compensating for a
		// half-completed vend is the lifecycle layer's decision, and a provider
		// that quietly revoked on its way out of an error would be making that
		// decision where nobody can see it.
		return nil, credentials.NewCreateNotDelivered(ProviderID, keyResp.Data.ID)
	}

	// ExpiresAt is deliberately nil: Datadog does not expire API keys, and
	// reporting a locally computed time here would be recorded as an expiry the
	// provider stated. The caller applies its own TTL, which is what
	// credentials.CreateResult.ExpiresAt documents as the fallback.
	//
	// GrantedScope is nil for the same kind of reason: Datadog does not describe
	// the scope of a key, so there is nothing truthful to put here. Note that the
	// contract reads an empty GrantedScope as "the provider does not describe
	// scope" and not as "unscoped" -- for this provider the honest reading is both,
	// and the interface has no way to say the second. That gap is recorded in the
	// USOSS-7 report rather than papered over with an invented value.
	return &credentials.CreateResult{
		PlatformKeyID: keyResp.Data.ID,
		APIKey:        keyResp.Data.Attributes.Key,
	}, nil
}

// RevokeCredential deletes a Datadog API key.
//
// A key that is already gone is a successful revoke. The point of the call is
// that the material no longer works, and a 404 says so; returning an error would
// leave the reconciler retrying forever against a key nobody can find.
func (p *Provider) RevokeCredential(ctx context.Context, platformKeyID string, metadata credentials.Metadata) error {
	keyID, err := keyPath(platformKeyID)
	if err != nil {
		return err
	}
	auth, err := extractAuth(metadata)
	if err != nil {
		return err
	}

	resp, err := p.do(ctx, http.MethodDelete, auth, keyID, credhttp.OpDatadogDeleteAPIKey(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		return statusError(credhttp.OpDatadogDeleteAPIKey(), resp)
	}
	return nil
}

// GetCredentialStatus asks Datadog whether a key still exists.
//
// Datadog has no notion of a revoked-but-present key, so "exists" is the whole
// answer: a key that is gone reports revoked, and a key that is present reports
// active. Neither can report expired, because Datadog API keys do not expire.
func (p *Provider) GetCredentialStatus(ctx context.Context, platformKeyID string, metadata credentials.Metadata) (credentials.CredentialStatus, error) {
	keyID, err := keyPath(platformKeyID)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}
	auth, err := extractAuth(metadata)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}

	resp, err := p.do(ctx, http.MethodGet, auth, keyID, credhttp.OpDatadogStatusCheck(), nil)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return credentials.CredentialStatusRevoked, nil
	case resp.StatusCode >= 400:
		return credentials.CredentialStatusUnknown, statusError(credhttp.OpDatadogStatusCheck(), resp)
	default:
		return credentials.CredentialStatusActive, nil
	}
}

// keyPath validates a platform key ID and returns the request path for it.
//
// url.PathEscape rather than interpolation: the ID comes back out of the
// platform's own record, and a record is not a thing to trust with path
// construction.
func keyPath(platformKeyID string) (string, error) {
	id := strings.TrimSpace(platformKeyID)
	if id == "" {
		return "", errors.New("datadog: a platform key ID is required")
	}
	return "/api/v2/api_keys/" + url.PathEscape(id), nil
}

// auth is the operator's Datadog credentials plus the host to send them to.
type auth struct {
	apiKey credentials.Secret
	appKey credentials.Secret
	site   string
}

// extractAuth pulls the operator's Datadog credentials out of metadata.
//
// The two keys become credentials.Secret immediately. They are material, and a
// bare string here would be one %v away from a log line.
func extractAuth(metadata credentials.Metadata) (auth, error) {
	apiKey := strings.TrimSpace(metadata[MetadataAdminAPIKey])
	if apiKey == "" {
		return auth{}, fmt.Errorf("datadog: metadata %q is required", MetadataAdminAPIKey)
	}
	appKey := strings.TrimSpace(metadata[MetadataAdminAppKey])
	if appKey == "" {
		return auth{}, fmt.Errorf("datadog: metadata %q is required", MetadataAdminAppKey)
	}
	site := strings.ToLower(strings.TrimSpace(metadata[MetadataSite]))
	if site == "" {
		site = defaultSite
	}
	if _, ok := allowedSites[site]; !ok {
		// The rejected value is deliberately not in the message. It is a metadata
		// value, and credentials.Metadata already establishes that metadata values
		// do not render -- a misconfiguration that put the admin key in dd_site
		// would otherwise print it. Naming the allowed set is more useful anyway.
		return auth{}, fmt.Errorf("%w; allowed: %s", ErrSiteNotAllowed, strings.Join(allowedSiteNames(), ", "))
	}
	return auth{apiKey: credentials.NewSecret(apiKey), appKey: credentials.NewSecret(appKey), site: site}, nil
}

// do issues one authenticated request against the allowlisted site.
//
// op is the only detail that reaches a transport-failure error. It is a
// credhttp.Op and not a string, so "nothing built from metadata or from a
// response is passed here" is a property of the type rather than a rule this
// comment asks the next author to remember -- which is what the previous version
// of it did, and what review defeated.
func (p *Provider) do(ctx context.Context, method string, a auth, path string, op credhttp.Op, body io.Reader) (*http.Response, error) {
	endpoint := "https://" + a.site + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("DD-API-KEY", credentials.Reveal(a.apiKey))
	req.Header.Set("DD-APPLICATION-KEY", credentials.Reveal(a.appKey))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// credhttp.Client.Do refuses redirects and classifies its own errors; there is
	// no path here that returns a transport's error text. See internal/credhttp.
	resp, err := p.http.Do(req, op)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// statusError turns a non-2xx response into an error.
//
// It carries the status code and the operation, and nothing from the response
// body. That is a deliberate loss of diagnostics, and the reason is that an
// upstream error body is text this process did not write: the internal
// implementation interpolated the whole body, and a body that quotes back the key
// it just rejected -- or the admin key it was authenticated with -- turns every
// error into a credential in a log aggregator. The test that pins this
// (TestErrorsCarryNoCredentialMaterial) failed against an earlier version of this
// function that included only Datadog's own documented "errors" array, which is
// how the tradeoff got settled: an operator who needs the body reads it from
// Datadog's side, and no error from this package can carry one.
//
// Retryable statuses are marked with credentials.ErrTransient so the reconciler
// can tell "come back later" from "this will never work".
func statusError(op credhttp.Op, resp *http.Response) error {
	// The body is drained rather than read so the connection can be reused; its
	// content is deliberately discarded.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return fmt.Errorf("%s failed (%d): %w", op, resp.StatusCode, credentials.ErrTransient)
	}
	return fmt.Errorf("%s failed (%d)", op, resp.StatusCode)
}
