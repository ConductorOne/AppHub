// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// GoogleIssuerURL is Google's canonical OIDC issuer; only its documented alias is normalized.
const GoogleIssuerURL = "https://accounts.google.com"

func canonicalIssuer(s string) string {
	if s == "accounts.google.com" {
		return GoogleIssuerURL
	}
	return s
}

// Config binds an upstream issuer and client credentials to one fixed callback.
type Config struct{ IssuerURL, ClientID, ClientSecret, RedirectURL string }

// OIDCClient verifies upstream identities; it does not issue AppHub credentials.
type OIDCClient struct {
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	client       *http.Client
	jwksURL      string
}

// UserInfo is a verified issuer/subject profile. EmailVerified applies to Email,
// not a different address from another claim or identity.
type UserInfo struct {
	Issuer, ID, Email string
	EmailVerified     bool
	Name, AvatarURL   string
}

// NewOIDCClient discovers the issuer and installs bounded, nonredirecting upstream
// transport and signature verification. Callers must first validate issuer trust.
func NewOIDCClient(ctx context.Context, cfg Config) (*OIDCClient, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, cp.Problem(503, "auth_unavailable", "Identity provider configuration is incomplete.")
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if supplied, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		configuredClient := *supplied
		configuredClient.Timeout = 15 * time.Second
		configuredClient.CheckRedirect = client.CheckRedirect
		client = &configuredClient
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = upstreamTransport{base: transport}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	provider, err := oidc.NewProvider(ctx, canonicalIssuer(cfg.IssuerURL))
	if err != nil {
		return nil, unavailable()
	}
	var discovery struct {
		JWKSURL     string   `json:"jwks_uri"`
		Algorithms  []string `json:"id_token_signing_alg_values_supported"`
		AuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	}
	if provider.Claims(&discovery) != nil || discovery.JWKSURL == "" || provider.Endpoint().AuthURL == "" || provider.Endpoint().TokenURL == "" {
		return nil, unavailable()
	}
	endpoint := provider.Endpoint()
	for _, address := range []string{discovery.JWKSURL, endpoint.AuthURL, endpoint.TokenURL, provider.UserInfoEndpoint()} {
		if address != "" && !secureEndpoint(address, cfg.IssuerURL) {
			return nil, unavailable()
		}
	}
	// OAuth2 auto-detection retries a consumed authorization code after transport
	// failure. Select the discovered client-auth method before sending credentials.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if len(discovery.AuthMethods) > 0 && !slices.Contains(discovery.AuthMethods, "client_secret_basic") {
		if !slices.Contains(discovery.AuthMethods, "client_secret_post") {
			return nil, unavailable()
		}
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	algorithms := []string{}
	for _, alg := range discovery.Algorithms {
		switch alg {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA":
			algorithms = append(algorithms, alg)
		}
	}
	keys := observedKeySet{delegate: oidc.NewRemoteKeySet(ctx, discovery.JWKSURL)}
	verified := oidc.NewVerifier(canonicalIssuer(cfg.IssuerURL), keys, &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: algorithms})
	return &OIDCClient{provider: provider, client: client, jwksURL: discovery.JWKSURL, verifier: verified, oauth2Config: &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}}, nil
}

func secureEndpoint(address, issuer string) bool {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	base, err := url.Parse(issuer)
	if err != nil || base.Scheme != "http" || u.Scheme != "http" {
		return false
	}
	host, baseHost := net.ParseIP(u.Hostname()), net.ParseIP(base.Hostname())
	return host != nil && baseHost != nil && host.IsLoopback() && baseHost.IsLoopback()
}

// GetAuthURL binds caller-generated state, nonce and verifier using S256 PKCE.
func (c *OIDCClient) GetAuthURL(state, nonce, verifier string) string {
	return c.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

// Exchange verifies signature, issuer, audience, expiry, nonce and subject, then
// reconciles subject-matched UserInfo. It returns no upstream bearer tokens.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, expectedNonce string) (*UserInfo, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	token, err := c.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var response *oauth2.RetrieveError
		if errors.As(err, &response) && response.Response != nil && response.Response.StatusCode < 500 {
			return nil, invalidLogin()
		}
		return nil, unavailable()
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, invalidLogin()
	}
	var failure verificationFailure
	ctx = context.WithValue(ctx, verificationFailureKey{}, &failure)
	id, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		var dependency upstreamFailure
		if errors.As(failure.err, &dependency) {
			return nil, unavailable()
		}
		return nil, invalidLogin()
	}
	if expectedNonce == "" || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(expectedNonce)) != 1 || id.Subject == "" {
		return nil, invalidLogin()
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		Name     string `json:"name"`
		Picture  string `json:"picture"`
	}
	if id.Claims(&claims) != nil {
		return nil, invalidLogin()
	}
	result := &UserInfo{Issuer: canonicalIssuer(id.Issuer), ID: id.Subject, Email: claims.Email, EmailVerified: claims.Verified, Name: claims.Name, AvatarURL: claims.Picture}
	if c.provider.UserInfoEndpoint() != "" {
		info, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, unavailable()
		}
		if info.Subject != id.Subject {
			return nil, invalidLogin()
		}
		if info.Email != "" {
			result.Email = info.Email
			result.EmailVerified = info.EmailVerified || (info.Email == claims.Email && claims.Verified)
		}
		var profile struct {
			Name    string `json:"name"`
			Picture string `json:"picture"`
		}
		if info.Claims(&profile) != nil {
			return nil, invalidLogin()
		}
		if profile.Name != "" {
			result.Name = profile.Name
		}
		if profile.Picture != "" {
			result.AvatarURL = profile.Picture
		}
	}
	return result, nil
}
func unavailable() *cp.Error {
	return cp.Problem(503, "auth_unavailable", "Authentication is temporarily unavailable.")
}
func invalidLogin() *cp.Error {
	return cp.Problem(401, "invalid_callback", "The sign-in attempt is invalid or expired. Start sign-in again.")
}
func unauthorized() *cp.Error { return cp.Problem(401, "unauthenticated", "Sign in is required.") }

// The OIDC verifier formats key-set errors instead of wrapping them. Retain the
// typed transport failure per verification, without retaining provider bodies,
// so a JWKS outage is not presented as invalid credentials. The key cache remains
// shared; the observation belongs only to this request.
type verificationFailureKey struct{}
type verificationFailure struct{ err error }
type observedKeySet struct{ delegate oidc.KeySet }

func (k observedKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	payload, err := k.delegate.VerifySignature(ctx, token)
	if result, ok := ctx.Value(verificationFailureKey{}).(*verificationFailure); ok {
		result.err = err
	}
	return payload, err
}

type upstreamFailure struct{}

func (upstreamFailure) Error() string { return "identity provider unavailable" }

type upstreamTransport struct{ base http.RoundTripper }

func (t upstreamTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, upstreamFailure{}
	}
	if response.StatusCode >= 500 {
		_ = response.Body.Close() // Upstream failure is already determined; discard its body.
		return nil, upstreamFailure{}
	}
	return response, nil
}
