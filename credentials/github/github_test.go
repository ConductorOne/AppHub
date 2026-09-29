// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package github_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	ghprovider "github.com/conductorone/apphub/credentials/github"
	"github.com/conductorone/apphub/credentials/lifecycle"
	"github.com/conductorone/apphub/internal/githubapp"
)

// Fixture values. The RSA key is generated in-process rather than committed:
// a PEM private key in a public repository is a finding whether or not it is real,
// and generating one also exercises the parse path this provider depends on.
const (
	fixtureAppID          = "1234"
	fixtureInstallationID = "42"
	fixtureToken          = "fixture-installation-token-material"
)

// testKey returns a PKCS#1 PEM key, generated once for the whole package.
var testKey = sync.OnceValues(func() (string, *rsa.PrivateKey) {
	// 2048 is the smallest size GitHub issues and keeps the suite fast.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block)), key
})

func privateKeyPEM(t *testing.T) string {
	t.Helper()
	material, _ := testKey()
	return material
}

// roundTripFunc is the whole test transport: no httptest server, no listening
// socket, no network. Every test asserts on the request it captured and answers
// from a literal.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type recorder struct {
	requests []*http.Request
	bodies   []string
	reply    reply
	err      error
}

// The exported field names are a leftover, kept because renaming them back is
// churn and not because they are needed. An all-lowercase three-segment field
// chain (r.reply.body) used to be reported by the repository's
// hostname-disclosure scan, which could not tell a Go selector chain from a
// hostname; a leading capital ended the match. That rule was rebuilt to decide by
// position rather than by suffix, and the false positive is gone -- verified
// against the current ruleset, which now carries a self-test case for exactly
// this shape.
type reply struct {
	Status int
	Body   string
	Header http.Header
}

func (r *recorder) provider(rep reply) *ghprovider.Provider {
	if rep.Status == 0 {
		rep.Status = 201
	}
	r.reply = rep
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := ""
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			body = string(b)
		}
		r.requests = append(r.requests, req)
		r.bodies = append(r.bodies, body)
		if r.err != nil {
			return nil, r.err
		}
		header := r.reply.Header
		if header == nil {
			header = http.Header{}
		}
		return &http.Response{
			StatusCode: r.reply.Status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(r.reply.Body)),
			Request:    req,
		}, nil
	})
	return ghprovider.NewProvider(ghprovider.WithTransport(rt))
}

func metadata(t *testing.T) credentials.Metadata {
	t.Helper()
	return credentials.Metadata{
		ghprovider.MetadataAppID:          fixtureAppID,
		ghprovider.MetadataPrivateKey:     privateKeyPEM(t),
		ghprovider.MetadataInstallationID: fixtureInstallationID,
	}
}

func dynamicRequest(t *testing.T) credentials.CreateRequest {
	t.Helper()
	return credentials.CreateRequest{
		Name:           "apphub-vended",
		CredentialType: credentials.CredentialTypeDynamic,
		Metadata:       metadata(t),
		IdempotencyKey: "record-1",
	}
}

// tokenBody is a realistic access_tokens response.
func tokenBody(expiresAt time.Time) string {
	body, err := json.Marshal(map[string]any{
		"token":                fixtureToken,
		"expires_at":           expiresAt.UTC().Format(time.RFC3339),
		"permissions":          map[string]string{"contents": "read", "checks": "write"},
		"repository_selection": "selected",
		"repositories": []map[string]any{
			{"id": 7, "name": "zebra", "full_name": "acme/zebra", "private": true},
			{"id": 3, "name": "apple", "full_name": "acme/apple", "private": false},
		},
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

// TestCreateCredentialMintsAnInstallationToken pins the wire contract and the
// shape of what comes back.
func TestCreateCredentialMintsAnInstallationToken(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(expiry)})

	md := metadata(t)
	md[ghprovider.MetadataRepositories] = "apple, zebra"
	md[ghprovider.MetadataPermissions] = `{"contents":"read"}`
	req := dynamicRequest(t)
	req.Metadata = md

	got, err := p.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests, want 1", len(rec.requests))
	}
	hreq := rec.requests[0]
	if hreq.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", hreq.Method)
	}
	if want := "https://api.github.com/app/installations/42/access_tokens"; hreq.URL.String() != want {
		t.Errorf("URL = %q, want %q", hreq.URL, want)
	}
	if got := hreq.Header.Get("Accept"); got != "application/vnd.github+json" {
		t.Errorf("Accept = %q", got)
	}
	if got := hreq.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q", got)
	}

	var sent struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(rec.bodies[0]), &sent); err != nil {
		t.Fatalf("request body was not JSON: %v", err)
	}
	if len(sent.Repositories) != 2 || sent.Repositories[0] != "apple" {
		t.Errorf("repositories = %v", sent.Repositories)
	}
	if sent.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v", sent.Permissions)
	}

	if want := fmt.Sprintf("inst-42-%d", expiry.UTC().Unix()); got.PlatformKeyID != want {
		t.Errorf("PlatformKeyID = %q, want %q", got.PlatformKeyID, want)
	}
	if credentials.Reveal(got.APIKey) != fixtureToken {
		t.Error("APIKey did not carry the token")
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiry.UTC()) {
		t.Errorf("ExpiresAt = %v, want %v: GitHub's expiry is authoritative and must be reported", got.ExpiresAt, expiry.UTC())
	}
}

// TestAuthorizationHeaderCarriesAValidAppJWT checks the one piece of crypto in
// this port: the header GitHub authenticates, decoded and inspected.
func TestAuthorizationHeaderCarriesAValidAppJWT(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})
	if _, err := p.CreateCredential(context.Background(), dynamicRequest(t)); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	header := rec.requests[0].Header.Get("Authorization")
	jwt, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		t.Fatalf("Authorization = %q, want a Bearer token", header)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d segments, want 3", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	if got := string(headerJSON); got != `{"alg":"RS256","typ":"JWT"}` {
		t.Errorf("JWT header = %s", got)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != fixtureAppID {
		t.Errorf("iss = %q, want the app ID %q as a string", claims.Iss, fixtureAppID)
	}
	if span := claims.Exp - claims.Iat; span > 600 {
		t.Errorf("iat..exp spans %ds; GitHub refuses anything over 600", span)
	}
	if claims.Iat > time.Now().Unix() {
		t.Error("iat is in the future; it must be back-dated to tolerate clock drift")
	}
}

// TestGrantedScopeReportsWhatGitHubGranted: an installation token can come back
// narrower than asked for, and a record that only remembers the request describes
// an intention rather than a credential.
func TestGrantedScopeReportsWhatGitHubGranted(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})

	got, err := p.CreateCredential(context.Background(), dynamicRequest(t))
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	want := []string{
		"repository_selection:selected",
		"repository:acme/apple",
		"repository:acme/zebra",
		"permission:checks=write",
		"permission:contents=read",
	}
	if len(got.GrantedScope) != len(want) {
		t.Fatalf("GrantedScope = %v, want %v", got.GrantedScope, want)
	}
	for i := range want {
		if got.GrantedScope[i] != want[i] {
			t.Fatalf("GrantedScope = %v, want %v (stable order matters for comparing two vends)", got.GrantedScope, want)
		}
	}
}

// TestCreateCredentialRefusesEverythingButDynamic: an installation token always
// expires, so nothing static can be vended here.
func TestCreateCredentialRefusesEverythingButDynamic(t *testing.T) {
	for _, typ := range []credentials.CredentialType{credentials.CredentialTypeStatic, ""} {
		rec := &recorder{}
		p := rec.provider(reply{})
		req := dynamicRequest(t)
		req.CredentialType = typ
		if _, err := p.CreateCredential(context.Background(), req); err == nil {
			t.Errorf("CreateCredential(type=%q) succeeded", typ)
		}
		if len(rec.requests) != 0 {
			t.Errorf("type=%q: GitHub was called before the refusal", typ)
		}
	}
}

// TestCreateCredentialRefusesARequestedScope: this provider's scope comes from
// operator metadata, so it cannot honor a caller's narrowing -- and ignoring one
// would hand back a token wider than was asked for.
func TestCreateCredentialRefusesARequestedScope(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{})
	req := dynamicRequest(t)
	req.RequestedScope = []string{"repository:acme/apple"}

	_, err := p.CreateCredential(context.Background(), req)
	if !errors.Is(err, credentials.ErrScopeNotSupported) {
		t.Fatalf("CreateCredential(scoped) = %v, want ErrScopeNotSupported", err)
	}
	if len(rec.requests) != 0 {
		t.Error("a token was minted before the scope was refused")
	}
}

// TestScopingThatResolvesToNothingIsRefused is the regression test for the
// source's silent widening: in GitHub's API an absent scoping field means the full
// installation grant, so dropping an unparseable one turns a request for two
// repositories into a token for all of them.
func TestScopingThatResolvesToNothingIsRefused(t *testing.T) {
	for _, tc := range []struct{ Key, Value string }{
		{ghprovider.MetadataRepositories, ", ,"},
		{ghprovider.MetadataRepositories, ","},
		{ghprovider.MetadataRepositoryIDs, ", ,"},
		{ghprovider.MetadataPermissions, "{}"},
	} {
		t.Run(tc.Key+"="+tc.Value, func(t *testing.T) {
			md := metadata(t)
			md[tc.Key] = tc.Value
			req := dynamicRequest(t)
			req.Metadata = md

			rec := &recorder{}
			p := rec.provider(reply{})
			_, err := p.CreateCredential(context.Background(), req)
			if !errors.Is(err, ghprovider.ErrScopeResolvesToNothing) {
				t.Fatalf("err = %v, want ErrScopeResolvesToNothing", err)
			}
			if len(rec.requests) != 0 {
				t.Error("a full-installation token was minted instead of refusing")
			}
		})
	}
}

// TestScopingRejectsMalformedEntries keeps a typo out of the request body.
func TestScopingRejectsMalformedEntries(t *testing.T) {
	for _, tc := range []struct{ Name, Key, Value string }{
		{"non-numeric repository ID", ghprovider.MetadataRepositoryIDs, "7,abc"},
		{"zero repository ID", ghprovider.MetadataRepositoryIDs, "0"},
		{"negative repository ID", ghprovider.MetadataRepositoryIDs, "-7"},
		{"permissions is an array", ghprovider.MetadataPermissions, `["contents"]`},
		{"permissions is not JSON", ghprovider.MetadataPermissions, `contents=read`},
		{"empty permission level", ghprovider.MetadataPermissions, `{"contents":""}`},
		{"empty permission name", ghprovider.MetadataPermissions, `{"":"read"}`},
		{"too many repositories", ghprovider.MetadataRepositories, strings.Repeat("r,", 129)},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			md := metadata(t)
			md[tc.Key] = tc.Value
			req := dynamicRequest(t)
			req.Metadata = md

			rec := &recorder{}
			p := rec.provider(reply{})
			if _, err := p.CreateCredential(context.Background(), req); err == nil {
				t.Error("malformed scoping was accepted")
			}
			if len(rec.requests) != 0 {
				t.Error("GitHub was called with malformed scoping")
			}
		})
	}
}

// TestRequiredMetadata refuses an incomplete app configuration before any call.
func TestRequiredMetadata(t *testing.T) {
	for _, tc := range []struct{ Name, Key, Value string }{
		{"missing app ID", ghprovider.MetadataAppID, ""},
		{"non-numeric app ID", ghprovider.MetadataAppID, "not-a-number"},
		{"zero app ID", ghprovider.MetadataAppID, "0"},
		{"negative app ID", ghprovider.MetadataAppID, "-1"},
		{"missing installation ID", ghprovider.MetadataInstallationID, ""},
		{"zero installation ID", ghprovider.MetadataInstallationID, "0"},
		{"missing private key", ghprovider.MetadataPrivateKey, ""},
		{"private key is not PEM", ghprovider.MetadataPrivateKey, "not a pem block"},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			md := metadata(t)
			md[tc.Key] = tc.Value
			req := dynamicRequest(t)
			req.Metadata = md

			rec := &recorder{}
			p := rec.provider(reply{})
			if _, err := p.CreateCredential(context.Background(), req); err == nil {
				t.Error("an incomplete app configuration was accepted")
			}
			if len(rec.requests) != 0 {
				t.Error("GitHub was called with an incomplete configuration")
			}
		})
	}
}

// TestPKCS8PrivateKeyIsAccepted: GitHub has emitted both block types over the
// years, and the source accepted both.
func TestPKCS8PrivateKeyIsAccepted(t *testing.T) {
	_, key := testKey()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	md := metadata(t)
	md[ghprovider.MetadataPrivateKey] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	req := dynamicRequest(t)
	req.Metadata = md

	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})
	if _, err := p.CreateCredential(context.Background(), req); err != nil {
		t.Fatalf("CreateCredential with a PKCS#8 key: %v", err)
	}
}

// TestAPIBaseURLMustBeAnHTTPSURL is the SSRF test. api_base_url decides where an
// app JWT is sent, and the source accepted any string.
func TestAPIBaseURLMustBeAnHTTPSURL(t *testing.T) {
	for _, base := range []string{
		"http://api.github.com",
		"ftp://api.github.com",
		"//api.github.com",
		"https://",
		"https://user:pass@api.github.com",
		"https://api.github.com?x=1",
		"https://api.github.com#frag",
		"mailto:someone@example.test",
		"not a url at all",
		"http://169.254.169.254/latest/meta-data",
	} {
		md := metadata(t)
		md[ghprovider.MetadataAPIBaseURL] = base
		req := dynamicRequest(t)
		req.Metadata = md

		rec := &recorder{}
		p := rec.provider(reply{})
		_, err := p.CreateCredential(context.Background(), req)
		if !errors.Is(err, githubapp.ErrBaseURL) {
			t.Errorf("api_base_url=%q gave %v, want ErrBaseURL", base, err)
		}
		if len(rec.requests) != 0 {
			t.Errorf("api_base_url=%q: an app JWT was sent there", base)
		}
	}
}

// TestGitHubEnterpriseBaseURL: a GHES root has a path, which is why a path is the
// one thing the base URL check allows.
func TestGitHubEnterpriseBaseURL(t *testing.T) {
	md := metadata(t)
	md[ghprovider.MetadataAPIBaseURL] = "https://ghe.example.test/api/v3/"
	req := dynamicRequest(t)
	req.Metadata = md

	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})
	if _, err := p.CreateCredential(context.Background(), req); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if want := "https://ghe.example.test/api/v3/app/installations/42/access_tokens"; rec.requests[0].URL.String() != want {
		t.Errorf("URL = %q, want %q", rec.requests[0].URL, want)
	}
}

// TestTokenResponseMustCarryMaterialAndAnExpiry: returning an empty Secret as if a
// vend had succeeded would hand the caller a credential that is not one.
func TestTokenResponseMustCarryMaterialAndAnExpiry(t *testing.T) {
	for _, tc := range []struct{ Name, Body string }{
		{"no token", `{"expires_at":"2030-01-01T00:00:00Z"}`},
		{"empty token", `{"token":"","expires_at":"2030-01-01T00:00:00Z"}`},
		{"no expiry", `{"token":"t"}`},
		{"not JSON", `<html>gateway error</html>`},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{Status: 201, Body: tc.Body})
			if _, err := p.CreateCredential(context.Background(), dynamicRequest(t)); err == nil {
				t.Error("an unusable token response was accepted")
			}
		})
	}
}

// TestRevokeIsNotSupported, and says so with the sentinel the lifecycle layer
// keys on: the record goes to pending_revoke rather than revoked, so nobody stops
// looking at a credential that still works.
func TestRevokeIsNotSupported(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{})
	err := p.RevokeCredential(context.Background(), "inst-42-9999999999", metadata(t))
	if !errors.Is(err, credentials.ErrRevokeNotSupported) {
		t.Fatalf("RevokeCredential = %v, want ErrRevokeNotSupported", err)
	}
	if len(rec.requests) != 0 {
		t.Error("RevokeCredential called GitHub; there is nothing to authenticate that call with")
	}
}

// TestGetCredentialStatusReadsTheHandle: the answer comes from the expiry GitHub
// stated at create time, which the handle carries.
func TestGetCredentialStatusReadsTheHandle(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()

	for _, tc := range []struct {
		Name  string
		KeyID string
		Want  credentials.CredentialStatus
	}{
		{"live", fmt.Sprintf("inst-42-%d", future), credentials.CredentialStatusActive},
		{"lapsed", fmt.Sprintf("inst-42-%d", past), credentials.CredentialStatusExpired},
		{"wrong prefix", fmt.Sprintf("token-42-%d", future), credentials.CredentialStatusUnknown},
		{"no expiry segment", "inst-42", credentials.CredentialStatusUnknown},
		{"expiry is not a number", "inst-42-soon", credentials.CredentialStatusUnknown},
		{"empty", "", credentials.CredentialStatusUnknown},
		{"someone else's handle", "aws-role-session-1", credentials.CredentialStatusUnknown},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{})
			got, err := p.GetCredentialStatus(context.Background(), tc.KeyID, metadata(t))
			if err != nil {
				t.Fatalf("GetCredentialStatus: %v", err)
			}
			if got != tc.Want {
				t.Errorf("status = %q, want %q", got, tc.Want)
			}
			if len(rec.requests) != 0 {
				t.Error("GetCredentialStatus called GitHub; Capabilities reports Status false because it does not")
			}
		})
	}
}

// TestHandleRoundTrips: the handle is the only thing that survives a vend, so the
// two halves have to agree.
func TestHandleRoundTrips(t *testing.T) {
	expiry := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(expiry)})

	got, err := p.CreateCredential(context.Background(), dynamicRequest(t))
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	status, err := p.GetCredentialStatus(context.Background(), got.PlatformKeyID, metadata(t))
	if err != nil {
		t.Fatalf("GetCredentialStatus: %v", err)
	}
	if status != credentials.CredentialStatusActive {
		t.Errorf("a handle minted moments ago reports %q", status)
	}
}

// TestTransientClassification is what lets the reconciler tell "come back later"
// from "this will never work".
func TestTransientClassification(t *testing.T) {
	for _, tc := range []struct {
		Status    int
		Transient bool
	}{
		{401, false}, {403, false}, {404, false}, {422, false},
		{429, true}, {500, true}, {502, true}, {503, true},
	} {
		rec := &recorder{}
		p := rec.provider(reply{Status: tc.Status, Body: `{"message":"nope"}`})
		_, err := p.CreateCredential(context.Background(), dynamicRequest(t))
		if err == nil {
			t.Fatalf("status %d succeeded", tc.Status)
		}
		if errors.Is(err, credentials.ErrTransient) != tc.Transient {
			t.Errorf("status %d: ErrTransient = %v, want %v", tc.Status, !tc.Transient, tc.Transient)
		}
	}

	t.Run("transport failure", func(t *testing.T) {
		rec := &recorder{err: errors.New("connection reset")}
		p := rec.provider(reply{})
		if _, err := p.CreateCredential(context.Background(), dynamicRequest(t)); !errors.Is(err, credentials.ErrTransient) {
			t.Errorf("transport failure = %v, want ErrTransient", err)
		}
	})
}

// TestErrorsCarryNoCredentialMaterial walks the failing paths with material in the
// metadata and in the response body. A provider that interpolates a response body
// defeats the Secret type on its own.
func TestErrorsCarryNoCredentialMaterial(t *testing.T) {
	keyPEM := privateKeyPEM(t)
	leaky := fmt.Sprintf(`{"message":"rejected token %s","token":%q,"key":%q}`,
		fixtureToken, fixtureToken, keyPEM)

	// Two PEM fragments as well as the whole key: a leak often shows up as a
	// fragment rather than the entire block.
	fragments := []string{fixtureToken, keyPEM, "BEGIN RSA PRIVATE KEY", "rejected token"}

	for _, status := range []int{401, 403, 422, 429, 500} {
		rec := &recorder{}
		p := rec.provider(reply{Status: status, Body: leaky})
		_, err := p.CreateCredential(context.Background(), dynamicRequest(t))
		if err == nil {
			t.Fatalf("status %d succeeded", status)
		}
		for _, fragment := range fragments {
			if strings.Contains(err.Error(), fragment) {
				t.Errorf("status %d: error leaks %q: %v", status, fragment, err)
			}
		}
		if !strings.Contains(err.Error(), fmt.Sprint(status)) {
			t.Errorf("error %q does not report the status code", err)
		}
	}

	t.Run("a bad key does not appear in the parse error", func(t *testing.T) {
		md := metadata(t)
		md[ghprovider.MetadataPrivateKey] = "-----BEGIN RSA PRIVATE KEY-----\nZGVmaW5pdGVseS1ub3QtYS1rZXk=\n-----END RSA PRIVATE KEY-----\n"
		req := dynamicRequest(t)
		req.Metadata = md

		rec := &recorder{}
		p := rec.provider(reply{})
		_, err := p.CreateCredential(context.Background(), req)
		if err == nil {
			t.Fatal("a malformed key was accepted")
		}
		if strings.Contains(err.Error(), "ZGVmaW5pdGVseS1ub3QtYS1rZXk") {
			t.Errorf("the parse error carries the key material: %v", err)
		}
	})

	t.Run("a successful result does not render its material", func(t *testing.T) {
		rec := &recorder{}
		p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})
		got, err := p.CreateCredential(context.Background(), dynamicRequest(t))
		if err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "%v|%+v|%#v|%s|%q", got, got, got, got.APIKey, got.APIKey)
		if strings.Contains(buf.String(), fixtureToken) {
			t.Errorf("formatting the result rendered the token: %s", buf.String())
		}
		if credentials.Reveal(got.APIKey) != fixtureToken {
			t.Error("Reveal did not return the token")
		}
	})
}

// TestRedirectIsRefused: every request carries an app JWT, and a redirect off the
// configured host is never something this client should follow silently.
func TestRedirectIsRefused(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{
		Status: http.StatusFound,
		Header: http.Header{"Location": []string{"https://attacker.example.com/collect"}},
	})

	_, err := p.CreateCredential(context.Background(), dynamicRequest(t))
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Fatalf("CreateCredential against a redirect = %v, want ErrRedirectRefused", err)
	}
	for _, req := range rec.requests {
		if req.URL.Host == "attacker.example.com" {
			t.Fatal("an app JWT was sent to the redirect target")
		}
	}
	if errors.Is(err, credentials.ErrTransient) {
		t.Error("a refused redirect is marked transient; the reconciler would retry a misconfiguration forever")
	}
}

// TestCapabilitiesAreDeclaredAndAdmitDynamic pins the two declarations that
// contradict the safe defaults, and shows neither costs anything at admission.
func TestCapabilitiesAreDeclaredAndAdmitDynamic(t *testing.T) {
	p := ghprovider.NewProvider()
	got := credentials.CapabilitiesOf(p)
	want := credentials.Capabilities{
		Dynamic: true, Static: false, Revoke: false, Status: false, Rotate: false, RecoverCreate: false,
	}
	if got != want {
		t.Fatalf("CapabilitiesOf() = %+v, want %+v", got, want)
	}
	if !p.SupportsDynamic() {
		t.Error("SupportsDynamic() = false")
	}

	policy := lifecycle.ProviderPolicy{
		Enabled:                    true,
		AllowedTypes:               []credentials.CredentialType{credentials.CredentialTypeDynamic},
		MaxTTL:                     map[credentials.CredentialType]time.Duration{credentials.CredentialTypeDynamic: time.Hour},
		AllowUnrecoverableIssuance: true,
	}
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeDynamic); err != nil {
		t.Errorf("CheckIssuable(dynamic) = %v, want nil: Revoke false must not block a dynamic vend", err)
	}
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeStatic); err == nil {
		t.Error("CheckIssuable(static) succeeded against a dynamic-only provider")
	}

	// GitHub has no idempotent create, so an operator has to accept explicitly
	// that an ambiguous vend cannot be resolved. The mitigating fact is a property
	// of the provider, not of the contract: such a token dies within an hour.
	policy.AllowUnrecoverableIssuance = false
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeDynamic); !errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
		t.Errorf("CheckIssuable without the opt-in = %v, want ErrUnrecoverableIssuance", err)
	}
	if _, ok := any(p).(credentials.CreateRecoverer); ok {
		t.Error("provider implements CreateRecoverer; minting an installation token has no idempotency notion")
	}
}

// TestRegistersUnderItsOwnID checks the provider is usable through the registry,
// which is how every caller reaches it.
func TestRegistersUnderItsOwnID(t *testing.T) {
	reg := credentials.NewProviderRegistry()
	if err := reg.Register(ghprovider.NewProvider()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(ghprovider.NewProvider()); err == nil {
		t.Error("a second GitHub provider was registered under the same ID")
	}
	got, ok := reg.Get(ghprovider.ProviderID)
	if !ok {
		t.Fatalf("Get(%q) missed", ghprovider.ProviderID)
	}
	if got.Name() != "GitHub" {
		t.Errorf("Name() = %q", got.Name())
	}
}

// TestPresentButBlankScopingIsRefused is review's reproduction, with the four
// values it planted.
//
// The bypass: presence was tested with strings.TrimSpace(metadata[key]) != "", so
// a key that was present and blank was indistinguishable from a key that was
// absent -- and GitHub reads an absent scoping field as the full installation
// grant. All four of these reached MintInstallationToken with the field omitted,
// which is the same privilege escalation the guard was written to stop, arrived at
// by a different route.
func TestPresentButBlankScopingIsRefused(t *testing.T) {
	for _, tc := range []struct{ Name, Key, Value string }{
		{"repositories empty", ghprovider.MetadataRepositories, ""},
		{"repositories whitespace", ghprovider.MetadataRepositories, " \t\n"},
		{"repository_ids empty", ghprovider.MetadataRepositoryIDs, ""},
		{"permissions whitespace", ghprovider.MetadataPermissions, " \t"},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			md := metadata(t)
			md[tc.Key] = tc.Value
			req := dynamicRequest(t)
			req.Metadata = md

			rec := &recorder{}
			p := rec.provider(reply{})
			_, err := p.CreateCredential(context.Background(), req)
			if !errors.Is(err, ghprovider.ErrScopeResolvesToNothing) {
				t.Fatalf("err = %v, want ErrScopeResolvesToNothing", err)
			}
			if len(rec.requests) != 0 {
				t.Fatal("a full-installation token was minted from a blank scoping value")
			}
		})
	}
}

// TestAbsentScopingStillVendsAndSaysSo is the other half of the fix. An operator
// who supplies no scoping metadata at all is making the ordinary request -- vend a
// token for this installation -- and that must keep working. What changed is that
// the provider now states it, so the widest token it can produce is a line of code
// rather than the value an empty map falls into.
func TestAbsentScopingStillVendsAndSaysSo(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: tokenBody(time.Now().Add(time.Hour))})

	if _, err := p.CreateCredential(context.Background(), dynamicRequest(t)); err != nil {
		t.Fatalf("CreateCredential with no scoping metadata: %v", err)
	}
	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests, want 1", len(rec.requests))
	}
	// The request body carries no scoping field, which is what asks GitHub for the
	// full grant. That is intended here and refused everywhere it is not stated.
	if body := rec.bodies[0]; body != "" {
		t.Errorf("request body = %q, want empty for a full-installation grant", body)
	}
}

// dumpingTransport is the accidental-instrumentation failure review reproduced: a
// transport that has seen the authenticated request and includes it in its own
// diagnostic error.
func dumpingTransport() http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var dump bytes.Buffer
		dump.WriteString("dial failed for " + req.URL.String() + " with headers: ")
		for name, values := range req.Header {
			dump.WriteString(name + "=" + strings.Join(values, ",") + " ")
		}
		return nil, errors.New(dump.String())
	})
}

// TestTransportErrorsCarryNoAppJWT is review's reproduction. The previous
// implementation wrapped the error from http.Client.Do, so a transport that
// dumped its request returned the full freshly minted `Bearer eyJ...` app JWT --
// which is higher privilege than the installation token the request was buying.
func TestTransportErrorsCarryNoAppJWT(t *testing.T) {
	p := ghprovider.NewProvider(ghprovider.WithTransport(dumpingTransport()))

	_, err := p.CreateCredential(context.Background(), dynamicRequest(t))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, forbidden := range []string{
		"Bearer", "eyJ", "Authorization", "headers:", "dial failed",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("error carries %q: %v", forbidden, err)
		}
	}
	if !errors.Is(err, credentials.ErrTransient) {
		t.Errorf("a transport failure must still classify as transient: %v", err)
	}
}

// TestASuppliedTransportCannotReEnableRedirects is review's first reproduction
// against the narrowed API. See the same test in credentials/datadog for why the
// old signature was the bug.
func TestASuppliedTransportCannotReEnableRedirects(t *testing.T) {
	var seen []*http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req)
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.example.com/collect"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	p := ghprovider.NewProvider(ghprovider.WithTransport(rt))

	_, err := p.CreateCredential(context.Background(), dynamicRequest(t))
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Fatalf("CreateCredential = %v, want ErrRedirectRefused", err)
	}
	if errors.Is(err, credentials.ErrTransient) {
		t.Error("a refused redirect must not be transient")
	}
	if len(seen) != 1 {
		t.Fatalf("the transport saw %d requests; the redirect was followed", len(seen))
	}
	if seen[0].URL.Host != "api.github.com" {
		t.Errorf("first request went to %q", seen[0].URL.Host)
	}
	if strings.Contains(err.Error(), "attacker.example.com") {
		t.Errorf("the refusal reflected the redirect target: %v", err)
	}
}

// TestNoMetadataValueReachesAnError is the class-level invariant: no error from
// this package contains text that arrived from outside it. Every metadata value
// below is a unique sentinel, including the private key, so an error that echoes
// any of them fails whichever path produced it.
func TestNoMetadataValueReachesAnError(t *testing.T) {
	const (
		sentinelAppID   = "SENTINEL-metadata-app-id"
		sentinelKey     = "SENTINEL-metadata-private-key"
		sentinelInstall = "SENTINEL-metadata-installation-id"
		sentinelBase    = "sentinel-scheme://SENTINEL-metadata-api-base-url"
		sentinelRepos   = "SENTINEL-metadata-repositories"
		sentinelIDs     = "SENTINEL-metadata-repository-ids"
		sentinelPerms   = "SENTINEL-metadata-permissions"
	)
	sentinels := []string{
		sentinelAppID, sentinelKey, sentinelInstall, sentinelBase,
		sentinelRepos, sentinelIDs, sentinelPerms, "sentinel-scheme",
	}

	cases := map[string]credentials.Metadata{
		"every value is junk": {
			ghprovider.MetadataAppID:          sentinelAppID,
			ghprovider.MetadataPrivateKey:     sentinelKey,
			ghprovider.MetadataInstallationID: sentinelInstall,
			ghprovider.MetadataAPIBaseURL:     sentinelBase,
			ghprovider.MetadataRepositories:   sentinelRepos,
			ghprovider.MetadataRepositoryIDs:  sentinelIDs,
			ghprovider.MetadataPermissions:    sentinelPerms,
		},
		"valid app, junk scoping": {
			ghprovider.MetadataAppID:          fixtureAppID,
			ghprovider.MetadataPrivateKey:     privateKeyPEM(t),
			ghprovider.MetadataInstallationID: fixtureInstallationID,
			ghprovider.MetadataRepositoryIDs:  sentinelIDs,
		},
		"valid app, junk permissions": {
			ghprovider.MetadataAppID:          fixtureAppID,
			ghprovider.MetadataPrivateKey:     privateKeyPEM(t),
			ghprovider.MetadataInstallationID: fixtureInstallationID,
			ghprovider.MetadataPermissions:    sentinelPerms,
		},
		"valid app, junk base URL": {
			ghprovider.MetadataAppID:          fixtureAppID,
			ghprovider.MetadataPrivateKey:     privateKeyPEM(t),
			ghprovider.MetadataInstallationID: fixtureInstallationID,
			ghprovider.MetadataAPIBaseURL:     sentinelBase,
		},
		"unparseable private key": {
			ghprovider.MetadataAppID:          fixtureAppID,
			ghprovider.MetadataPrivateKey:     "-----BEGIN RSA PRIVATE KEY-----\n" + sentinelKey + "\n-----END RSA PRIVATE KEY-----\n",
			ghprovider.MetadataInstallationID: fixtureInstallationID,
		},
	}

	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{Status: 403, Body: `{"message":"denied"}`})

			req := dynamicRequest(t)
			req.Metadata = md

			var errs []error
			_, err := p.CreateCredential(context.Background(), req)
			errs = append(errs, err)
			errs = append(errs, p.RevokeCredential(context.Background(), "inst-42-1", md))
			_, err = p.GetCredentialStatus(context.Background(), "inst-42-1", md)
			errs = append(errs, err)

			scoped := req
			scoped.RequestedScope = []string{"repository:acme/apple"}
			_, err = p.CreateCredential(context.Background(), scoped)
			errs = append(errs, err)
			wrongType := req
			wrongType.CredentialType = credentials.CredentialTypeStatic
			_, err = p.CreateCredential(context.Background(), wrongType)
			errs = append(errs, err)

			for _, err := range errs {
				if err == nil {
					continue
				}
				for _, sentinel := range sentinels {
					// Case-insensitive: a path that normalizes a metadata value before
					// rendering it is still a path that renders it.
					if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(sentinel)) {
						t.Errorf("error echoed a metadata value: %v", err)
					}
				}
			}
		})
	}
}
