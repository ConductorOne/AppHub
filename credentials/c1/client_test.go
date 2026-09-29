// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1"
)

// Everything below runs against a http.RoundTripper. No listener, no port, no
// network: the transport is the seam c1.Deps offers, and it is the seam every
// test here uses, so nothing in this file can reach a tenant even if
// misconfigured.

const (
	testTenant   = "https://tenant.example.invalid"
	testClientID = "apphub-client"
)

// recordedRequest is what the fake transport saw.
type recordedRequest struct {
	Method      string
	Path        string
	Query       string
	Header      http.Header
	Body        string
	Deadline    time.Time
	HasDeadline bool
}

// fakeTransport answers the token endpoint and the credential API from
// caller-supplied handlers, recording every request.
type fakeTransport struct {
	token func(*http.Request) (*http.Response, error)
	api   func(*http.Request) (*http.Response, error)

	seen []recordedRequest
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := recordedRequest{
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.RawQuery,
		Header: req.Header.Clone(),
	}
	rec.Deadline, rec.HasDeadline = req.Context().Deadline()
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		rec.Body = string(b)
	}
	f.seen = append(f.seen, rec)

	if strings.HasSuffix(req.URL.Path, "/auth/v1/token") {
		if f.token != nil {
			return f.token(req)
		}
		return jsonResponse(http.StatusOK, `{"access_token":"tenant-access-token","expires_in":3600}`, req), nil
	}
	if f.api != nil {
		return f.api(req)
	}
	return jsonResponse(http.StatusOK, `{}`, req), nil
}

// tokenRequests and apiRequests split the recording, so an assertion about one
// does not have to count the other.
func (f *fakeTransport) tokenRequests() []recordedRequest {
	var out []recordedRequest
	for _, r := range f.seen {
		if strings.HasSuffix(r.Path, "/auth/v1/token") {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeTransport) apiRequests() []recordedRequest {
	var out []recordedRequest
	for _, r := range f.seen {
		if !strings.HasSuffix(r.Path, "/auth/v1/token") {
			out = append(out, r)
		}
	}
	return out
}

func jsonResponse(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d upstream", status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// stubSecrets and stubSigner are the two host collaborators.
type stubSecrets struct {
	secret credentials.Secret
	err    error
	calls  int
}

func (s *stubSecrets) Resolve(context.Context, credentials.SecretRef) (credentials.Secret, error) {
	s.calls++
	return s.secret, s.err
}

type stubSigner struct {
	assertion credentials.Secret
	err       error
	audiences []string
	ttls      []time.Duration
}

func (s *stubSigner) SignAssertion(_ context.Context, audience string, ttl time.Duration) (credentials.Secret, error) {
	s.audiences = append(s.audiences, audience)
	s.ttls = append(s.ttls, ttl)
	return s.assertion, s.err
}

func secretModeConfig() c1.Config {
	return c1.Config{
		TenantURL:    testTenant,
		ClientID:     testClientID,
		ClientSecret: credentials.SecretRef{Name: "/run/secrets/c1-client-secret"},
	}
}

func newTestClient(t *testing.T, cfg c1.Config, ft *fakeTransport, deps c1.Deps) c1.Client {
	t.Helper()
	deps.Transport = ft
	if deps.Secrets == nil && deps.Assertions == nil {
		deps.Secrets = &stubSecrets{secret: credentials.NewSecret("apphub-client-secret")}
	}
	client, err := c1.NewClient(cfg, deps)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func testRef() c1.Ref {
	return c1.Ref{ServicePrincipalID: testPrincipal, CredentialID: testCredential}
}

func mintRequest() c1.MintRequest {
	return c1.MintRequest{
		ServicePrincipalID: testPrincipal,
		DisplayName:        "apphub-vended",
		TTL:                time.Hour,
	}
}

// mintBody is a complete, well-formed upstream mint response.
func mintBodyJSON() string {
	return `{"credential":{"id":"` + testCredential + `","servicePrincipalId":"` + testPrincipal +
		`","clientId":"client-id-value","expiresAt":"2030-01-01T00:00:00Z","scopedRoleIds":["roleA"]},` +
		`"clientSecret":"client-secret-value"}`
}

// -- authentication ---------------------------------------------------------

func TestTokenExchangeSendsTheClientCredentialsGrant(t *testing.T) {
	secrets := &stubSecrets{secret: credentials.NewSecret("apphub-client-secret")}
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{Secrets: secrets})

	if _, err := client.Mint(context.Background(), mintRequest()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	tokens := ft.tokenRequests()
	if len(tokens) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", len(tokens))
	}
	tok := tokens[0]
	if tok.Method != http.MethodPost {
		t.Errorf("token request method = %s, want POST", tok.Method)
	}
	if got := tok.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("token request Content-Type = %q", got)
	}
	form, err := url.ParseQuery(tok.Body)
	if err != nil {
		t.Fatalf("token request body did not parse as a form: %v", err)
	}
	if form.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("client_id") != testClientID {
		t.Errorf("client_id = %q", form.Get("client_id"))
	}
	if form.Get("client_secret") != "apphub-client-secret" {
		t.Error("client_secret was not the value the resolver returned")
	}
	if form.Get("client_assertion") != "" {
		t.Error("an assertion was sent in client_secret mode")
	}
	if secrets.calls != 1 {
		t.Errorf("the secret store was consulted %d times, want 1 per token fetch", secrets.calls)
	}
}

func TestTokenExchangeSendsAnAssertionInFederatedMode(t *testing.T) {
	// AuthModeFederatedJWT is assumption A8 and is unverified against
	// ConductorOne. What this test pins is that the request AppHub sends is the
	// RFC 7523 §2.2 shape rather than something invented -- so if a tenant does
	// support it, this is the request it will see, and if it does not, the failure
	// is a refusal from the token endpoint and not a malformed request.
	signer := &stubSigner{assertion: credentials.NewSecret("signed.jwt.value")}
	cfg := c1.Config{TenantURL: testTenant, ClientID: testClientID, AuthMode: c1.AuthModeFederatedJWT}
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, cfg, ft, c1.Deps{Assertions: signer})

	if _, err := client.Mint(context.Background(), mintRequest()); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	form, err := url.ParseQuery(ft.tokenRequests()[0].Body)
	if err != nil {
		t.Fatalf("token request body: %v", err)
	}
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %q", form.Get("client_assertion_type"))
	}
	if form.Get("client_assertion") != "signed.jwt.value" {
		t.Error("client_assertion was not the signer's output")
	}
	if form.Get("client_secret") != "" {
		t.Error("a client secret was sent in federated_jwt mode; the mode exists so there is no shared secret")
	}
	// The audience defaults to the tenant, which is what a token endpoint expects
	// when nothing else is agreed.
	if len(signer.audiences) != 1 || signer.audiences[0] != testTenant {
		t.Errorf("assertion audiences = %v, want [%s]", signer.audiences, testTenant)
	}
	if len(signer.ttls) != 1 || signer.ttls[0] <= 0 || signer.ttls[0] > time.Hour {
		t.Errorf("assertion ttls = %v, want one short positive lifetime", signer.ttls)
	}
}

func TestAConfiguredAudienceOverridesTheTenantURL(t *testing.T) {
	signer := &stubSigner{assertion: credentials.NewSecret("signed.jwt.value")}
	cfg := c1.Config{
		TenantURL: testTenant + "/",
		ClientID:  testClientID,
		AuthMode:  c1.AuthModeFederatedJWT,
		Audience:  "https://audience.example.invalid",
	}
	if got := cfg.EffectiveAudience(); got != "https://audience.example.invalid" {
		t.Fatalf("EffectiveAudience() = %q", got)
	}
	// And with no Audience, the trailing slash must not change what is asserted.
	cfg.Audience = ""
	if got := cfg.EffectiveAudience(); got != testTenant {
		t.Fatalf("EffectiveAudience() = %q, want the tenant URL without its trailing slash", got)
	}
	_ = signer
}

func TestTheAccessTokenIsFetchedOnceAndReused(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodDelete {
			return jsonResponse(http.StatusOK, `{}`, req), nil
		}
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})

	if _, err := client.Mint(context.Background(), mintRequest()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := client.Revoke(context.Background(), testRef()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := client.Get(context.Background(), testRef()); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if n := len(ft.tokenRequests()); n != 1 {
		t.Errorf("token endpoint called %d times across three API calls, want 1", n)
	}
	if n := len(ft.apiRequests()); n != 3 {
		t.Errorf("%d API requests, want 3", n)
	}
	for _, r := range ft.apiRequests() {
		if got := r.Header.Get("Authorization"); got != "Bearer tenant-access-token" {
			t.Errorf("%s %s Authorization = %q", r.Method, r.Path, got)
		}
	}
}

func TestATokenResponseWithoutAUsableTokenIsRefused(t *testing.T) {
	// Both halves matter. A missing token would otherwise be sent as an empty
	// bearer, and a missing or non-positive lifetime would be cached forever or
	// refetched on every call depending on which way the arithmetic fell.
	for _, body := range []string{
		`{}`,
		`{"expires_in":3600}`,
		`{"access_token":"","expires_in":3600}`,
		`{"access_token":"t"}`,
		`{"access_token":"t","expires_in":0}`,
		`{"access_token":"t","expires_in":-1}`,
		`not json at all`,
	} {
		ft := &fakeTransport{token: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, body, req), nil
		}}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		if _, err := client.Mint(context.Background(), mintRequest()); err == nil {
			t.Errorf("a token response of %d bytes was accepted", len(body))
		}
		if n := len(ft.apiRequests()); n != 0 {
			t.Errorf("a bad token response still produced %d API requests", n)
		}
	}
}

func TestAnUnresolvableClientSecretIsRefusedWithoutTheResolversOwnError(t *testing.T) {
	const sentinel = "Kp4Kp4Kp4Kp4Kp4Kp4Kp4Kp4Kp4Kp4Kp4"
	for _, secrets := range []*stubSecrets{
		{err: errors.New(sentinel)},
		{secret: credentials.Secret{}},
	} {
		ft := &fakeTransport{}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{Secrets: secrets})
		_, err := client.Mint(context.Background(), mintRequest())
		if !errors.Is(err, c1.ErrClientSecretUnresolved) {
			t.Errorf("err = %v, want ErrClientSecretUnresolved", err)
		}
		if err != nil && strings.Contains(err.Error(), sentinel) {
			t.Error("the resolver's own error text was rendered")
		}
		if len(ft.seen) != 0 {
			t.Error("a request went out without a resolvable client secret")
		}
	}
}

func TestNewClientRefusesWiringThatCannotAuthenticate(t *testing.T) {
	// Checked at construction rather than at first vend: a deployment whose wiring
	// forgot the resolver would otherwise start cleanly and fail at the moment a
	// person or a deploy is waiting on a credential.
	if _, err := c1.NewClient(secretModeConfig(), c1.Deps{}); !errors.Is(err, c1.ErrSecretResolverRequired) {
		t.Errorf("err = %v, want ErrSecretResolverRequired", err)
	}
	cfg := c1.Config{TenantURL: testTenant, ClientID: testClientID, AuthMode: c1.AuthModeFederatedJWT}
	if _, err := c1.NewClient(cfg, c1.Deps{}); !errors.Is(err, c1.ErrAssertionSignerRequired) {
		t.Errorf("err = %v, want ErrAssertionSignerRequired", err)
	}
	// And the other direction, so this is not a test that passes against a
	// constructor that refuses everything.
	if _, err := c1.NewClient(secretModeConfig(), c1.Deps{Secrets: &stubSecrets{}}); err != nil {
		t.Errorf("NewClient refused a complete wiring: %v", err)
	}
	if _, err := c1.NewClient(cfg, c1.Deps{Assertions: &stubSigner{}}); err != nil {
		t.Errorf("NewClient refused a complete federated wiring: %v", err)
	}
}

func TestDepsExposesNoHTTPClient(t *testing.T) {
	// Redirect refusal and error classification are fields and behaviours of
	// *http.Client, so a Deps field of that type would hand a caller the ability
	// to remove both -- which is the defect review verified in two other
	// providers. The field is a http.RoundTripper, and this asserts that
	// structurally rather than by reading the doc comment.
	dt := reflect.TypeOf(c1.Deps{})
	clientType := reflect.TypeOf((*http.Client)(nil))
	found := 0
	for i := range dt.NumField() {
		f := dt.Field(i)
		if f.Type == clientType || f.Type == clientType.Elem() {
			t.Errorf("Deps.%s is an http.Client; a caller could replace the redirect policy", f.Name)
		}
		if f.Type == reflect.TypeOf((*http.RoundTripper)(nil)).Elem() {
			found++
		}
	}
	if found != 1 {
		t.Errorf("Deps declares %d http.RoundTripper fields, want exactly 1", found)
	}
}

// -- Config.Timeout reaches the request ------------------------------------

func TestTheConfiguredTimeoutReachesEveryRequestContext(t *testing.T) {
	// The property, over a generated population rather than one case: for every
	// configured timeout, the deadline the transport observes is that timeout from
	// now -- not internal/credhttp's fixed thirty-second backstop, and not no
	// deadline at all.
	//
	// This is the defect the c1 config comment was written to prevent being
	// rebuilt a third time: a timeout is a field on http.Client, and the fields of
	// http.Client are what the USOSS-7 review defeated. The only way to honour a
	// configurable timeout is through the context.
	timeouts := []time.Duration{
		time.Millisecond,
		100 * time.Millisecond,
		time.Second,
		5 * time.Second,
		29 * time.Second,
	}
	if len(timeouts) == 0 {
		t.Fatal("empty population")
	}
	for _, timeout := range timeouts {
		cfg := secretModeConfig()
		cfg.RequestTimeout = timeout
		ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
		}}
		client := newTestClient(t, cfg, ft, c1.Deps{})

		before := time.Now()
		_, _ = client.Mint(context.Background(), mintRequest())
		after := time.Now()

		if len(ft.seen) == 0 {
			t.Fatalf("timeout %v: no request was issued", timeout)
		}
		for _, r := range ft.seen {
			if !r.HasDeadline {
				t.Fatalf("timeout %v: %s %s carried no deadline at all", timeout, r.Method, r.Path)
			}
			// The deadline must lie inside [before+timeout, after+timeout]. That
			// brackets it without depending on how long the test took.
			if r.Deadline.Before(before.Add(timeout)) || r.Deadline.After(after.Add(timeout)) {
				t.Errorf("timeout %v: %s %s deadline is %v from the call, want %v",
					timeout, r.Method, r.Path, r.Deadline.Sub(before), timeout)
			}
		}
	}
}

func TestAShorterCallerDeadlineWinsOverTheConfiguredOne(t *testing.T) {
	cfg := secretModeConfig()
	cfg.RequestTimeout = 20 * time.Second
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, cfg, ft, c1.Deps{})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	before := time.Now()
	_, _ = client.Mint(ctx, mintRequest())

	for _, r := range ft.seen {
		if !r.HasDeadline {
			t.Fatalf("%s %s carried no deadline", r.Method, r.Path)
		}
		if d := r.Deadline.Sub(before); d > time.Second {
			t.Errorf("%s %s deadline is %v from the call; the caller's shorter deadline did not win", r.Method, r.Path, d)
		}
	}
}

func TestARequestThatHangsFailsAtTheConfiguredTimeout(t *testing.T) {
	// The observable consequence of the property above: a hung upstream fails in
	// tens of milliseconds because that is what was configured, and not in thirty
	// seconds because that is what internal/credhttp's backstop says.
	cfg := secretModeConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	ft := &fakeTransport{token: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	client := newTestClient(t, cfg, ft, c1.Deps{})

	start := time.Now()
	_, err := client.Mint(context.Background(), mintRequest())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a hung upstream produced no error")
	}
	if !errors.Is(err, credentials.ErrTransient) {
		t.Errorf("err = %v, want it to wrap credentials.ErrTransient so the reconciler retries", err)
	}
	// Generous, because a loaded CI machine is not a stopwatch. The point is that
	// it is nowhere near thirty seconds.
	if elapsed > 5*time.Second {
		t.Errorf("a hung upstream took %v to fail with a %v timeout configured", elapsed, cfg.Timeout())
	}
}

// -- routes and paths ------------------------------------------------------

func TestEachCallUsesItsVerifiedRoute(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodDelete {
			return jsonResponse(http.StatusOK, `{}`, req), nil
		}
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})

	collection := "/api/v1/service_principals/" + testPrincipal + "/credentials"
	item := collection + "/" + testCredential

	if _, err := client.Mint(context.Background(), mintRequest()); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := client.Get(context.Background(), testRef()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := client.Revoke(context.Background(), testRef()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	want := []struct{ method, path string }{
		{http.MethodPost, collection},
		{http.MethodGet, item},
		{http.MethodDelete, item},
	}
	got := ft.apiRequests()
	if len(got) != len(want) {
		t.Fatalf("%d API requests, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Method != w.method || got[i].Path != w.path {
			t.Errorf("request %d = %s %s, want %s %s", i, got[i].Method, got[i].Path, w.method, w.path)
		}
		if got[i].Query != "" {
			t.Errorf("request %d carried a query string %q; a base URL with a query would put it on every call", i, got[i].Query)
		}
	}
}

func TestNoAcceptedHandleCanReachOutsideItsCollection(t *testing.T) {
	// The security property behind the handle grammar, asserted over the whole
	// accepted population rather than over one identifier: for every reference the
	// grammar admits, the URL that gets built stays inside
	// /api/v1/service_principals/, survives path.Clean unchanged, and contains no
	// dot segment. A grammar that let one escape would let a persisted record
	// address an arbitrary tenant endpoint with AppHub's own bearer token.
	valid := validSegments()
	if len(valid) < 2 {
		t.Fatalf("the valid population is %d segments", len(valid))
	}
	checked := 0
	for _, sp := range valid {
		for _, cred := range valid {
			ref := c1.Ref{ServicePrincipalID: sp, CredentialID: cred}
			ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{}`, req), nil
			}}
			client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
			if err := client.Revoke(context.Background(), ref); err != nil {
				t.Fatalf("Revoke refused a reference inside the grammar: %v", err)
			}
			api := ft.apiRequests()
			if len(api) != 1 {
				t.Fatalf("%d API requests, want 1", len(api))
			}
			p := api[0].Path
			if !strings.HasPrefix(p, "/api/v1/service_principals/") {
				t.Errorf("path %q left the service principals collection", p)
			}
			if cleaned := path.Clean(p); cleaned != p {
				t.Errorf("path %q is not already clean (cleans to %q)", p, cleaned)
			}
			if strings.Contains(p, "/../") || strings.Contains(p, "/./") {
				t.Errorf("path %q contains a dot segment", p)
			}
			if n := strings.Count(p, "/"); n != 6 {
				t.Errorf("path %q has %d separators, want 6", p, n)
			}
			checked++
		}
	}
	if checked != len(valid)*len(valid) {
		t.Fatalf("checked %d references, expected %d", checked, len(valid)*len(valid))
	}
	t.Logf("checked %d accepted references", checked)
}

// -- the mint request body -------------------------------------------------

func TestTTLIsClampedDownToTheUpstreamCeilingAndNeverExtended(t *testing.T) {
	// The upstream's own hard limit is 180 days. Narrowing a lifetime is always
	// permitted; extending one never is. The population spans both sides of the
	// ceiling so a clamp that ran the wrong way, or not at all, is visible.
	const ceiling = 180 * 24 * time.Hour
	population := []time.Duration{
		time.Second,
		time.Hour,
		24 * time.Hour,
		ceiling - time.Second,
		ceiling,
		ceiling + time.Second,
		2 * ceiling,
		10000 * 24 * time.Hour,
	}
	sawClamped, sawHonoured := 0, 0
	for _, ttl := range population {
		ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
		}}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		req := mintRequest()
		req.TTL = ttl
		if _, err := client.Mint(context.Background(), req); err != nil {
			t.Fatalf("ttl %v: Mint: %v", ttl, err)
		}
		body := ft.apiRequests()[0].Body
		want := ttl
		if want > ceiling {
			want = ceiling
			sawClamped++
		} else {
			sawHonoured++
		}
		wantField := fmt.Sprintf(`"expires":"%ds"`, int64(want/time.Second))
		if !strings.Contains(body, wantField) {
			t.Errorf("ttl %v: body %q does not carry %s", ttl, body, wantField)
		}
	}
	if sawClamped == 0 || sawHonoured == 0 {
		t.Fatalf("the population exercised %d clamped and %d honoured TTLs; both must occur", sawClamped, sawHonoured)
	}
}

func TestANonPositiveTTLIsRefusedRatherThanDefaulted(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, -time.Hour} {
		ft := &fakeTransport{}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		req := mintRequest()
		req.TTL = ttl
		if _, err := client.Mint(context.Background(), req); !errors.Is(err, c1.ErrTTLRequired) {
			t.Errorf("ttl %v: err = %v, want ErrTTLRequired", ttl, err)
		}
		if len(ft.seen) != 0 {
			t.Errorf("ttl %v reached the upstream", ttl)
		}
	}
}

func TestTheMintBodyStatesEverythingItRelieOn(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, mintBodyJSON(), req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
	req := mintRequest()
	req.ScopedRoleIDs = []string{"roleA", "roleB"}
	if _, err := client.Mint(context.Background(), req); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	body := ft.apiRequests()[0].Body
	for _, want := range []string{
		`"displayName":"apphub-vended"`,
		`"scopedRoles":["roleA","roleB"]`,
		`"expires":"3600s"`,
		// Stated rather than omitted: a DPoP-bound credential needs a
		// proof-of-possession key the neutral contract cannot hand a consumer, so
		// an upstream default that flipped would vend unusable credentials.
		`"requireDpop":false`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("mint body %q does not carry %s", body, want)
		}
	}
	if got := ft.apiRequests()[0].Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("mint Content-Type = %q", got)
	}
}

func TestMintRefusesInputTheUpstreamWouldRejectAnyway(t *testing.T) {
	cases := map[string]func(*c1.MintRequest){
		"no display name":    func(r *c1.MintRequest) { r.DisplayName = "" },
		"blank display name": func(r *c1.MintRequest) { r.DisplayName = "   " },
		"oversize name":      func(r *c1.MintRequest) { r.DisplayName = strings.Repeat("n", 513) },
		"too many roles": func(r *c1.MintRequest) {
			r.ScopedRoleIDs = make([]string, 33)
			for i := range r.ScopedRoleIDs {
				r.ScopedRoleIDs[i] = fmt.Sprintf("role%02d", i)
			}
		},
		"unusable principal": func(r *c1.MintRequest) { r.ServicePrincipalID = "../elsewhere" },
	}
	for name, mutate := range cases {
		ft := &fakeTransport{}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		req := mintRequest()
		mutate(&req)
		if _, err := client.Mint(context.Background(), req); err == nil {
			t.Errorf("%s: Mint accepted it", name)
		}
		if len(ft.seen) != 0 {
			t.Errorf("%s: reached the upstream", name)
		}
	}
}

// -- responses -------------------------------------------------------------

func TestMintRefusesAResponseThatNamesADifferentServicePrincipal(t *testing.T) {
	// The request's principal is ours; the response's is the upstream's. A
	// mismatch means the handle a later revoke would be built from addresses a
	// credential this call did not create.
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		body := `{"credential":{"id":"` + testCredential + `","servicePrincipalId":"` + otherPrincipal +
			`","clientId":"c"},"clientSecret":"s"}`
		return jsonResponse(http.StatusOK, body, req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
	if _, err := client.Mint(context.Background(), mintRequest()); err == nil {
		t.Fatal("Mint accepted a response naming a different service principal")
	}
}

func TestMintRefusesAResponseWithNoCredentialID(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"credential":{}}`,
		`{"credential":{"clientId":"c"},"clientSecret":"s"}`,
		`{"credential":{"id":"has/slash"},"clientSecret":"s"}`,
		`{"credential":{"id":"../.."},"clientSecret":"s"}`,
	} {
		ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, body, req), nil
		}}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		if _, err := client.Mint(context.Background(), mintRequest()); err == nil {
			t.Errorf("Mint accepted a response of %d bytes with no usable credential ID", len(body))
		}
	}
}

func TestGetReportsAnAbsentCredentialAsSuch(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, `{"message":"nope"}`, req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
	if _, err := client.Get(context.Background(), testRef()); !errors.Is(err, c1.ErrCredentialNotFound) {
		t.Errorf("err = %v, want ErrCredentialNotFound", err)
	}
}

func TestRevokingSomethingAlreadyGoneSucceeds(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, `{"message":"nope"}`, req), nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
	if err := client.Revoke(context.Background(), testRef()); err != nil {
		t.Errorf("Revoke of an absent credential returned %v; the reconciler would retry forever", err)
	}
}

func TestStatusCodesAreClassifiedForTheReconciler(t *testing.T) {
	// Both directions. A classifier that called everything transient would let the
	// reconciler retry a 400 until someone noticed; one that called everything
	// terminal would give up on a 503.
	type want struct {
		transient bool
		unauth    bool
	}
	population := map[int]want{
		http.StatusBadRequest:          {},
		http.StatusNotFound:            {}, // on a mint, where absence is not a success
		http.StatusConflict:            {},
		http.StatusUnprocessableEntity: {},
		http.StatusUnauthorized:        {unauth: true},
		http.StatusForbidden:           {unauth: true},
		http.StatusTooManyRequests:     {transient: true},
		http.StatusInternalServerError: {transient: true},
		http.StatusBadGateway:          {transient: true},
		http.StatusServiceUnavailable:  {transient: true},
		http.StatusGatewayTimeout:      {transient: true},
	}
	seenTransient, seenTerminal, seenUnauth := 0, 0, 0
	for code, w := range population {
		ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(code, `{"message":"upstream detail"}`, req), nil
		}}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		_, err := client.Mint(context.Background(), mintRequest())
		if err == nil {
			t.Errorf("%d: Mint reported success", code)
			continue
		}
		if got := errors.Is(err, credentials.ErrTransient); got != w.transient {
			t.Errorf("%d: transient = %t, want %t (%v)", code, got, w.transient, err)
		}
		if got := errors.Is(err, c1.ErrUnauthenticated); got != w.unauth {
			t.Errorf("%d: unauthenticated = %t, want %t (%v)", code, got, w.unauth, err)
		}
		switch {
		case w.unauth:
			seenUnauth++
		case w.transient:
			seenTransient++
		default:
			seenTerminal++
		}
		if !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Errorf("%d: the error does not name the status code: %v", code, err)
		}
	}
	if seenTransient == 0 || seenTerminal == 0 || seenUnauth == 0 {
		t.Fatalf("the population produced %d transient, %d terminal and %d unauthenticated outcomes; all three must occur",
			seenTransient, seenTerminal, seenUnauth)
	}
}

func TestErrorsCarryNothingFromAResponse(t *testing.T) {
	// A ConductorOne error body describing a rejected credential is exactly where a
	// credential would appear, so the body is drained and discarded. The sentinel
	// is placed in the status line, every header, and the body.
	const sentinel = "Hv8Hv8Hv8Hv8Hv8Hv8Hv8Hv8Hv8Hv8Hv8"
	for _, code := range []int{400, 401, 429, 500} {
		ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: code,
				Status:     fmt.Sprintf("%d %s", code, sentinel),
				Header:     http.Header{"X-Upstream-Note": []string{sentinel}},
				Body:       io.NopCloser(strings.NewReader(`{"message":"` + sentinel + `","clientSecret":"` + sentinel + `"}`)),
				Request:    req,
			}, nil
		}}
		client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
		_, err := client.Mint(context.Background(), mintRequest())
		if err == nil {
			t.Fatalf("%d produced no error", code)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("%d: the error rendered text from the response", code)
		}
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	// The provider cannot re-enable them: refusal is installed by
	// internal/credhttp.New and is not a field anything here can reach. Following
	// one would hand AppHub's bearer token to whatever the Location header named.
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Status:     "302 Found",
			Header:     http.Header{"Location": []string{"https://elsewhere.example.invalid/collect"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}}
	client := newTestClient(t, secretModeConfig(), ft, c1.Deps{})
	_, err := client.Mint(context.Background(), mintRequest())
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Errorf("err = %v, want credentials.ErrRedirectRefused", err)
	}
	if err != nil && strings.Contains(err.Error(), "elsewhere.example.invalid") {
		t.Error("the refusal named the redirect target, which is a value out of an upstream header")
	}
}

func TestNewClientRefusesAnInvalidConfig(t *testing.T) {
	for name, cfg := range map[string]c1.Config{
		"empty":         {},
		"no client id":  {TenantURL: testTenant},
		"plain http":    {TenantURL: "http://tenant.example.invalid", ClientID: testClientID, ClientSecret: credentials.SecretRef{Name: "x"}},
		"embedded auth": {TenantURL: "https://user:pass@tenant.example.invalid", ClientID: testClientID, ClientSecret: credentials.SecretRef{Name: "x"}},
		"with query":    {TenantURL: testTenant + "?a=b", ClientID: testClientID, ClientSecret: credentials.SecretRef{Name: "x"}},
		"unknown mode":  {TenantURL: testTenant, ClientID: testClientID, AuthMode: "something-else"},
	} {
		if _, err := c1.NewClient(cfg, c1.Deps{Secrets: &stubSecrets{}, Assertions: &stubSigner{}}); err == nil {
			t.Errorf("%s: NewClient accepted it", name)
		}
	}
}
