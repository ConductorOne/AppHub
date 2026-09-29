// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// OIDCIdentity is a test-only signed upstream profile. It never bypasses the
// relying party: every login traverses discovery, PKCE, signed JWT and UserInfo.
type OIDCIdentity struct {
	Subject, Email, Name, Avatar string
	EmailVerified                bool
}
type fixtureCode struct {
	Challenge, Nonce string
	Identity         OIDCIdentity
	Fault            string
	Redirect         string
}

// OIDCFixture is a signed, loopback-only test issuer with synthetic identities.
// It exercises the relying party's real verification path, not an auth bypass.
type OIDCFixture struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string
	mu           sync.Mutex
	key          *rsa.PrivateKey
	identity     OIDCIdentity
	fault        string
	codes        map[string]fixtureCode
	tokens       map[string]fixtureCode
}

// NewOIDC starts an isolated issuer with a fresh signing key and test-owned cleanup.
func NewOIDC(t testing.TB) *OIDCFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &OIDCFixture{ClientID: "apphub-test", ClientSecret: "test-only-secret", key: key, identity: OIDCIdentity{Subject: "subject-a", Email: "member@example.com", Name: "Test Member", EmailVerified: true}, codes: map[string]fixtureCode{}, tokens: map[string]fixtureCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("GET /userinfo", f.userinfo)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Issuer returns the running fixture's exact discovery issuer URL.
func (f *OIDCFixture) Issuer() string { return f.Server.URL }

// SetIdentity changes the synthetic profile captured by subsequent authorizations.
func (f *OIDCFixture) SetIdentity(identity OIDCIdentity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity = identity
}

// SetFault changes subsequent authorizations. Supported faults: signature,
// issuer, audience, expiry, nonce, subject, userinfo-subject, userinfo-unverified,
// userinfo-outage, token-outage, jwks-outage, and discovery-outage. Empty restores normal flow.
func (f *OIDCFixture) SetFault(fault string) { f.mu.Lock(); defer f.mu.Unlock(); f.fault = fault }
func fixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (f *OIDCFixture) discovery(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	fault := f.fault
	f.mu.Unlock()
	if fault == "discovery-outage" {
		http.Error(w, "test upstream outage", http.StatusServiceUnavailable)
		return
	}
	fixtureJSON(w, map[string]any{"issuer": f.Issuer(), "authorization_endpoint": f.Issuer() + "/authorize", "token_endpoint": f.Issuer() + "/token", "userinfo_endpoint": f.Issuer() + "/userinfo", "jwks_uri": f.Issuer() + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
}
func (f *OIDCFixture) jwks(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	fault := f.fault
	f.mu.Unlock()
	if fault == "jwks-outage" {
		http.Error(w, "test JWKS secret-canary", http.StatusServiceUnavailable)
		return
	}
	fixtureJSON(w, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
}
func (f *OIDCFixture) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	challenge, e := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || redirect.Host == "" || (redirect.Scheme != "http" && redirect.Scheme != "https") || q.Get("client_id") != f.ClientID || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || e != nil || len(challenge) != 32 {
		http.Error(w, "invalid authorization", http.StatusBadRequest)
		return
	}
	code := fixtureSecret()
	f.mu.Lock()
	f.codes[code] = fixtureCode{Challenge: q.Get("code_challenge"), Nonce: q.Get("nonce"), Identity: f.identity, Fault: f.fault, Redirect: q.Get("redirect_uri")}
	f.mu.Unlock()
	query := redirect.Query()
	query.Set("code", code)
	query.Set("state", q.Get("state"))
	query.Set("iss", f.Issuer())
	redirect.RawQuery = query.Encode()
	// #nosec G710 -- This test-only httptest issuer intentionally accepts dynamic
	// HTTP(S) callbacks after the client/protocol checks above; it issues only fake
	// fixture identities, and the token endpoint binds each code to this redirect.
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
func (f *OIDCFixture) token(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	if id != f.ClientID || secret != f.ClientSecret {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	code, found := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	f.mu.Unlock()
	verifier := r.Form.Get("code_verifier")
	digest := sha256.Sum256([]byte(verifier))
	validGrammar := len(verifier) >= 43 && len(verifier) <= 128
	for _, ch := range verifier {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && !strings.ContainsRune("-._~", ch) {
			validGrammar = false
		}
	}
	if !found || r.Form.Get("grant_type") != "authorization_code" || !validGrammar || base64.RawURLEncoding.EncodeToString(digest[:]) != code.Challenge || r.Form.Get("redirect_uri") != code.Redirect {
		fixtureJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	if code.Fault == "token-outage" {
		http.Error(w, "test token secret-canary", http.StatusServiceUnavailable)
		return
	}
	claims := map[string]any{"iss": f.Issuer(), "aud": f.ClientID, "sub": code.Identity.Subject, "nonce": code.Nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "email": code.Identity.Email, "email_verified": code.Identity.EmailVerified, "name": code.Identity.Name, "picture": code.Identity.Avatar}
	switch code.Fault {
	case "issuer":
		claims["iss"] = "https://wrong.example"
	case "audience":
		claims["aud"] = "wrong-client"
	case "expiry":
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
	case "nonce":
		claims["nonce"] = "wrong-nonce"
	case "subject":
		claims["sub"] = ""
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	body, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	hashed := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hashed[:])
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	if code.Fault == "signature" {
		signature[0] ^= 1
	}
	access := fixtureSecret()
	f.mu.Lock()
	f.tokens[access] = code
	f.mu.Unlock()
	fixtureJSON(w, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600, "id_token": signed + "." + base64.RawURLEncoding.EncodeToString(signature)})
}
func (f *OIDCFixture) userinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	code, ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if code.Fault == "userinfo-outage" {
		http.Error(w, "test userinfo secret-canary", http.StatusServiceUnavailable)
		return
	}
	sub, email, verified := code.Identity.Subject, code.Identity.Email, code.Identity.EmailVerified
	if code.Fault == "userinfo-subject" {
		sub = "other-subject"
	}
	if code.Fault == "userinfo-unverified" {
		email = "other@example.com"
		verified = false
	}
	fixtureJSON(w, map[string]any{"sub": sub, "email": email, "email_verified": verified, "name": code.Identity.Name, "picture": code.Identity.Avatar})
}
func fixtureSecret() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}
