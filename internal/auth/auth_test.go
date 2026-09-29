// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
)

type authHarness struct {
	manager   *Manager
	mux       *http.ServeMux
	repo      *testutil.Repository
	config    serverconfig.Config
	providers []*testutil.OIDCFixture
}

func newHarness(t *testing.T, count int) *authHarness {
	t.Helper()
	cfg := serverconfig.Config{PublicOrigin: "http://127.0.0.1:5173", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(strings.Repeat("K", 32))}}
	h := &authHarness{repo: testutil.NewRepository(), mux: http.NewServeMux()}
	for i := range count {
		f := testutil.NewOIDC(t)
		h.providers = append(h.providers, f)
		id := []string{"primary", "secondary"}[i]
		cfg.Auth.Providers = append(cfg.Auth.Providers, serverconfig.ProviderConfig{ID: id, Label: id, Kind: "oidc", Issuer: f.Issuer(), ClientID: f.ClientID, ClientSecret: credentials.NewSecret(f.ClientSecret), AllowedDomains: []string{"example.com"}})
	}
	cfg.Auth.Admins = []serverconfig.AdminConfig{{ProviderID: "primary", Subject: "subject-a"}}
	m, err := New(context.Background(), cfg, h.repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.manager = m
	h.config = cfg
	m.Register(h.mux)
	return h
}
func (h *authHarness) begin(t *testing.T, provider, returnTo string) (string, *http.Cookie) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/"+provider+"/login?return_to="+url.QueryEscape(returnTo), nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected transaction cookie")
	}
	return w.Header().Get("Location"), cookies[0]
}
func upstreamCallback(t *testing.T, authorizationURL string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorization status %d", res.StatusCode)
	}
	return res.Header.Get("Location")
}
func (h *authHarness) callback(raw string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, raw, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	return w
}
func (h *authHarness) login(t *testing.T, provider string) (*http.Cookie, cp.Principal, cp.Session) {
	t.Helper()
	raw, binding := h.begin(t, provider, "/applications")
	result := h.callback(upstreamCallback(t, raw), binding)
	if result.Code != 303 {
		t.Fatalf("callback %d: %s", result.Code, result.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range result.Result().Cookies() {
		if c.Name == h.manager.sessionCookieName() {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.AddCookie(cookie)
	p, s, err := h.manager.Browser(req)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, p, s
}
func assertStatus(t *testing.T, err error, status int) {
	t.Helper()
	var p *cp.Error
	if !errors.As(err, &p) || p.Status != status {
		t.Fatalf("expected status %d, got %v", status, err)
	}
}

func TestSignedOIDCFailuresCannotCreateSessions(t *testing.T) {
	for _, fault := range []string{"signature", "issuer", "audience", "expiry", "nonce", "subject", "userinfo-subject", "userinfo-unverified", "token-outage", "userinfo-outage", "jwks-outage"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t, 1)
			h.providers[0].SetFault(fault)
			raw, cookie := h.begin(t, "primary", "/applications")
			result := h.callback(upstreamCallback(t, raw), cookie)
			want := 401
			if fault == "userinfo-unverified" {
				want = 403
			}
			if strings.HasSuffix(fault, "outage") {
				want = 503
			}
			if result.Code != want {
				t.Fatalf("callback %d, expected %d: %s", result.Code, want, result.Body.String())
			}
			if strings.Contains(result.Body.String(), "secret-canary") {
				t.Fatal("upstream response leaked")
			}
			for _, rec := range h.repo.Snapshot() {
				if rec.Kind == cp.SessionKind || rec.Kind == cp.UserKind {
					t.Fatal("rejected upstream identity created account/session")
				}
			}
		})
	}
}
func TestConcurrentTabsBindProviderBrowserAndReturnTarget(t *testing.T) {
	h := newHarness(t, 2)
	a, ac := h.begin(t, "primary", "/applications?tab=one")
	b, bc := h.begin(t, "secondary", "/settings/sessions")
	if ac.Name == bc.Name {
		t.Fatal("tabs overwrite transaction cookie")
	}
	callbackA, callbackB := upstreamCallback(t, a), upstreamCallback(t, b)
	wrong := h.callback(strings.Replace(callbackA, "/auth/primary/", "/auth/secondary/", 1), ac)
	if wrong.Code != 401 {
		t.Fatal("mixed-provider callback accepted")
	}
	wrong = h.callback(callbackA, bc)
	if wrong.Code != 401 {
		t.Fatal("wrong browser binding accepted")
	}
	successB := h.callback(callbackB, bc)
	if successB.Code != 303 || successB.Header().Get("Location") != "/settings/sessions" {
		t.Fatalf("second tab lost target: %s", successB.Body.String())
	}
	successA := h.callback(callbackA, ac)
	if successA.Code != 303 || successA.Header().Get("Location") != "/applications?tab=one" {
		t.Fatalf("first tab lost target: %s", successA.Body.String())
	}
	if h.callback(callbackA, ac).Code != 401 {
		t.Fatal("consumed login replay accepted")
	}
	for _, c := range successA.Result().Cookies() {
		if c.Name == bc.Name {
			t.Fatal("callback cleared another tab")
		}
	}
}
func TestSessionIdentityIsolationAndCurrentEligibility(t *testing.T) {
	h := newHarness(t, 2)
	cookie, a, session := h.login(t, "primary")
	_, b, _ := h.login(t, "secondary")
	if a.UserID == b.UserID || !a.Admin || b.Admin {
		t.Fatal("equal email merged identity or granted admin")
	}
	view, err := h.manager.Me(context.Background(), a, session.CSRF)
	if err != nil {
		t.Fatal(err)
	}
	if view.ID != a.UserID || view.CSRFToken != session.CSRF || view.Role != "admin" {
		t.Fatalf("incorrect verified user view: %+v", view)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	request.AddCookie(cookie)
	request.Header["Authorization"] = []string{""}
	_, _, err = h.manager.Browser(request)
	assertStatus(t, err, 401)
	cfg := h.config.Auth
	cfg.Providers = append([]serverconfig.ProviderConfig{}, cfg.Providers...)
	cfg.Providers[0].AllowedDomains = []string{"elsewhere.example"}
	_, err = NewEligibility(cfg, h.repo, nil).CheckPrincipal(context.Background(), a)
	assertStatus(t, err, 401)
	cfg = h.config.Auth
	cfg.Admins = nil
	checked, err := NewEligibility(cfg, h.repo, nil).CheckPrincipal(context.Background(), a)
	if err != nil || checked.Admin {
		t.Fatal("stale principal admin remained authoritative")
	}
	rec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.UserKind, ID: a.UserID})
	if err != nil {
		t.Fatal(err)
	}
	user, _ := cp.Decode[cp.User](rec)
	user.Disabled = true
	updated, _ := cp.Encode(rec.RecordID, rec.Version, user)
	if err = h.repo.Commit(context.Background(), []cp.Mutation{{Record: updated, ExpectedVersion: rec.Version}}); err != nil {
		t.Fatal(err)
	}
	request.Header.Del("Authorization")
	_, _, err = h.manager.Browser(request)
	assertStatus(t, err, 401)
}
func TestCSRFAndLogoutFailureRemainRetryable(t *testing.T) {
	h := newHarness(t, 1)
	cookie, p, s := h.login(t, "primary")
	for _, origin := range []string{"", "https://foreign.example", h.config.PublicOrigin} {
		r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("X-CSRF-Token", s.CSRF)
		err := h.manager.RequireCSRF(r, s)
		if origin == h.config.PublicOrigin {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertStatus(t, err, 403)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", h.config.PublicOrigin)
	r.Header.Set("X-CSRF-Token", "wrong")
	assertStatus(t, h.manager.RequireCSRF(r, s), 403)
	r.Header.Set("X-CSRF-Token", s.CSRF)
	h.repo.SetError(cp.ErrUnavailable)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 503 || len(w.Result().Cookies()) != 0 {
		t.Fatal("outage falsely logged out browser")
	}
	h.repo.SetError(nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("logout retry failed: %s", w.Body.String())
	}
	read := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	read.AddCookie(cookie)
	_, _, err := h.manager.Browser(read)
	assertStatus(t, err, 401)
	rec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.SessionKind, ID: p.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := cp.Decode[cp.Session](rec)
	if !saved.Revoked {
		t.Fatal("logout did not persist revocation")
	}
}
func TestExpiredTransactionsAndUnverifiedAdmission(t *testing.T) {
	h := newHarness(t, 1)
	raw, cookie := h.begin(t, "primary", "/applications")
	callback := upstreamCallback(t, raw)
	u, _ := url.Parse(raw)
	stateHash := hash(u.Query().Get("state"))
	rec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.LoginKind, ID: stateHash})
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := cp.Decode[loginTransaction](rec)
	tx.ExpiresAt = time.Now().Add(-time.Second)
	updated, _ := cp.Encode(rec.RecordID, rec.Version, tx)
	if err = h.repo.Commit(context.Background(), []cp.Mutation{{Record: updated, ExpectedVersion: rec.Version}}); err != nil {
		t.Fatal(err)
	}
	result := h.callback(callback, cookie)
	if result.Code != 401 {
		t.Fatal("expired transaction accepted")
	}
	h.providers[0].SetIdentity(testutil.OIDCIdentity{Subject: "unverified", Email: "member@example.com", EmailVerified: false})
	raw, cookie = h.begin(t, "primary", "/applications")
	if h.callback(upstreamCallback(t, raw), cookie).Code != 403 {
		t.Fatal("unverified admitted email accepted")
	}
}
func TestSessionListingUsesDisplayIDsAndRevokesFamilies(t *testing.T) {
	h := newHarness(t, 1)
	_, p, _ := h.login(t, "primary")
	_, other, _ := h.login(t, "primary")
	family := cp.OAuthFamily{ID: uuid(), UserID: p.UserID, ProviderID: p.ProviderID, Issuer: p.Issuer, Subject: p.Subject, ClientID: "apphub-cli", Resource: h.config.PublicOrigin + "/api", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	rec, _ := cp.Encode(cp.RecordID{Kind: cp.FamilyKind, ID: family.ID}, 0, family)
	if err := h.repo.Commit(context.Background(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
	var views []cp.SessionView
	cursor := ""
	for {
		page, err := h.manager.ListSessions(context.Background(), p, cp.ListOptions{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, page.Items...)
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
	foundFamily, current := false, false
	for _, v := range views {
		if v.ID == p.SessionID || v.ID == other.SessionID {
			t.Fatal("session bearer hash leaked as display id")
		}
		if v.ID == family.ID {
			foundFamily = true
		}
		current = current || v.Current
	}
	if !foundFamily || !current {
		t.Fatal("owned browser/family inventory missing")
	}
	if err := h.manager.RevokeSession(context.Background(), p, family.ID); err != nil {
		t.Fatal(err)
	}
	saved, err := h.repo.Read(context.Background(), rec.RecordID)
	if err != nil {
		t.Fatal("family tombstone deleted")
	}
	f, _ := cp.Decode[cp.OAuthFamily](saved)
	if !f.Revoked {
		t.Fatal("family revocation not durable")
	}
}
func TestReturnTargetsRejectEncodedAuthorityAndControls(t *testing.T) {
	for _, raw := range []string{"https://evil.example", "//evil.example", "/%2fevil.example", "/%252fevil.example", "/\\evil.example", "/%5cevil.example", "/%0d%0aLocation:evil", "javascript:alert(1)", "/%zz"} {
		if safeReturn(raw) != "/applications" {
			t.Fatalf("accepted unsafe target %q", raw)
		}
	}
	if safeReturn("/authorize?transactionId=abc") != "/authorize?transactionId=abc" {
		t.Fatal("valid local consent target rejected")
	}
}
func TestLoginSecretsAreEncryptedAndCookieIsHostOnly(t *testing.T) {
	h := newHarness(t, 1)
	raw, cookie := h.begin(t, "primary", "/applications")
	u, _ := url.Parse(raw)
	for _, rec := range h.repo.Snapshot() {
		var generic map[string]any
		if json.Unmarshal(rec.Value, &generic) != nil {
			t.Fatal("invalid transaction record")
		}
		if strings.Contains(string(rec.Value), u.Query().Get("nonce")) || strings.Contains(string(rec.Value), cookie.Value) || strings.Contains(string(rec.Value), u.Query().Get("state")) {
			t.Fatal("raw login credential persisted")
		}
	}
	if cookie.Domain != "" || cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("transaction cookie scope unsafe")
	}
	h.manager.secure = true
	w := httptest.NewRecorder()
	h.manager.setCookie(w, h.manager.sessionCookieName(), "test", time.Now().Add(time.Hour))
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-apphub_session" || !c.Secure || c.Domain != "" {
		t.Fatal("production cookie lacks host security")
	}
}
func TestRegistryDiscoveryFailsClosed(t *testing.T) {
	h := newHarness(t, 1)
	h.providers[0].SetFault("discovery-outage")
	_, err := New(context.Background(), h.config, h.repo, nil)
	assertStatus(t, err, 503)
}

type failedCommits struct{ cp.Repository }

func (r failedCommits) Commit(context.Context, []cp.Mutation) error { return cp.ErrUnavailable }
func TestLogoutCommitFailureDoesNotClearCookie(t *testing.T) {
	h := newHarness(t, 1)
	cookie, _, s := h.login(t, "primary")
	h.manager.repo = failedCommits{h.repo}
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", h.config.PublicOrigin)
	r.Header.Set("X-CSRF-Token", s.CSRF)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 503 || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed durable revoke falsely cleared browser cookie")
	}
	h.manager.repo = h.repo
	read := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	read.AddCookie(cookie)
	if _, _, err := h.manager.Browser(read); err != nil {
		t.Fatal("failed revocation destroyed session")
	}
}
func TestParallelFirstLoginsResolveOneIdentity(t *testing.T) {
	h := newHarness(t, 1)
	a, ac := h.begin(t, "primary", "/applications")
	b, bc := h.begin(t, "primary", "/applications")
	callbackA, callbackB := upstreamCallback(t, a), upstreamCallback(t, b)
	results := make(chan *httptest.ResponseRecorder, 2)
	go func() { results <- h.callback(callbackA, ac) }()
	go func() { results <- h.callback(callbackB, bc) }()
	for range 2 {
		result := <-results
		if result.Code != 303 {
			t.Fatalf("concurrent login failed: %s", result.Body.String())
		}
	}
	users, identities, sessions := 0, 0, 0
	for _, rec := range h.repo.Snapshot() {
		switch rec.Kind {
		case cp.UserKind:
			users++
		case cp.IdentityKind:
			identities++
		case cp.SessionKind:
			sessions++
		}
	}
	if users != 1 || identities != 1 || sessions != 2 {
		t.Fatalf("nonunique identity transaction: users=%d identities=%d sessions=%d", users, identities, sessions)
	}
}
func TestSessionRevocationCannotCrossOwners(t *testing.T) {
	h := newHarness(t, 1)
	_, a, _ := h.login(t, "primary")
	h.providers[0].SetIdentity(testutil.OIDCIdentity{Subject: "another-user", Email: "member@example.com", EmailVerified: true})
	cookie, b, s := h.login(t, "primary")
	if a.UserID == b.UserID || b.Admin {
		t.Fatal("same email granted another subject's authority")
	}
	assertStatus(t, h.manager.RevokeSession(context.Background(), a, s.ID), 404)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.AddCookie(cookie)
	if _, _, err := h.manager.Browser(req); err != nil {
		t.Fatal("cross-owner revoke affected session")
	}
}
func TestPKCEAndHTMLCallbackFailure(t *testing.T) {
	h := newHarness(t, 1)
	client := h.manager.providers["primary"]
	nonce, verifier := randomSecret(), randomSecret()
	callback := upstreamCallback(t, client.GetAuthURL(randomSecret(), nonce, verifier))
	parsed, _ := url.Parse(callback)
	_, err := client.Exchange(context.Background(), parsed.Query().Get("code"), randomSecret(), nonce)
	assertStatus(t, err, 401)
	r := httptest.NewRequest(http.MethodGet, "/auth/primary/callback?state=invalid", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/login?error=invalid_callback" {
		t.Fatal("browser did not reach actionable sign-in error screen")
	}
}

func TestAdminBootstrapHintLogsOnlyForNonAdminLogins(t *testing.T) {
	h := newHarness(t, 2)
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(previous)

	h.login(t, "primary") // subject-a via "primary" is the harness's configured admin.
	if strings.Contains(buf.String(), "admin authority") {
		t.Fatalf("bootstrap hint logged for an already-admin login: %s", buf.String())
	}

	buf.Reset()
	h.login(t, "secondary") // same default subject, unlisted provider: not an admin.
	out := buf.String()
	if !strings.Contains(out, "admin authority") || !strings.Contains(out, "providerId=secondary") || !strings.Contains(out, "subject=subject-a") {
		t.Fatalf("missing actionable admin bootstrap hint: %s", out)
	}
}

func TestDelegatedScopesCannotRevokeSettingsSessions(t *testing.T) {
	h := newHarness(t, 1)
	cookie, p, session := h.login(t, "primary")
	family := cp.OAuthFamily{ID: uuid(), UserID: p.UserID, ProviderID: p.ProviderID, Issuer: p.Issuer, Subject: p.Subject, ClientID: "other-client", Resource: h.config.PublicOrigin + "/api", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	record, _ := cp.Encode(cp.RecordID{Kind: cp.FamilyKind, ID: family.ID}, 0, family)
	if err := h.repo.Commit(context.Background(), []cp.Mutation{{Record: record, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
	for _, scopes := range [][]string{{cp.ApplicationsRead, cp.DeploymentsRead}, {cp.ApplicationsRead, cp.ApplicationsWrite, cp.DeploymentsRead, cp.DeploymentsWrite}} {
		delegated := p
		delegated.Bearer = true
		delegated.Scopes = scopes
		assertStatus(t, h.manager.RevokeSession(context.Background(), delegated, session.ID), 403)
		assertStatus(t, h.manager.RevokeSession(context.Background(), delegated, family.ID), 403)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.AddCookie(cookie)
	if _, _, err := h.manager.Browser(req); err != nil {
		t.Fatal("delegated settings mutation revoked browser")
	}
	saved, err := h.repo.Read(context.Background(), record.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	persisted, _ := cp.Decode[cp.OAuthFamily](saved)
	if persisted.Revoked {
		t.Fatal("delegated settings mutation revoked another family")
	}
	if err := h.manager.RevokeSession(context.Background(), p, family.ID); err != nil {
		t.Fatal("browser settings revocation refused:", err)
	}
	saved, err = h.repo.Read(context.Background(), record.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	persisted, _ = cp.Decode[cp.OAuthFamily](saved)
	if !persisted.Revoked {
		t.Fatal("browser settings revocation not durable")
	}
}

func TestTwoClientsAtOneIssuerPreserveBoundSessions(t *testing.T) {
	h := newHarness(t, 1)
	fixture := h.providers[0]
	// Reuse the signed fixture's real endpoints with two registered clients.
	// Serialize client selection with every fixture request so signatures contain
	// the requesting client's audience, without racing its single-client fields.
	upstream := fixture.Server.Config.Handler
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		clientID := ""
		switch r.URL.Path {
		case "/authorize":
			clientID = r.URL.Query().Get("client_id")
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			clientID, _, _ = r.BasicAuth()
			if clientID == "" {
				clientID = r.Form.Get("client_id")
			}
		}
		if r.URL.Path == "/authorize" || r.URL.Path == "/token" {
			if clientID != "client-a" && clientID != "client-b" {
				http.Error(w, "unregistered test client", http.StatusUnauthorized)
				return
			}
			fixture.ClientID = clientID
		}
		upstream.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	fixture.Server = server
	primary := h.config.Auth.Providers[0]
	primary.Issuer = server.URL
	primary.ClientID = "client-a"
	secondary := primary
	secondary.ID = "secondary"
	secondary.ClientID = "client-b"
	h.config.Auth.Providers = []serverconfig.ProviderConfig{primary, secondary}
	var err error
	h.manager, err = New(context.Background(), h.config, h.repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.mux = http.NewServeMux()
	h.manager.Register(h.mux)
	aCookie, a, _ := h.login(t, "primary")
	bCookie, b, _ := h.login(t, "secondary")
	if a.UserID != b.UserID || !a.Admin || b.Admin {
		t.Fatal("same issuer/subject lost stable identity or provider-specific authority")
	}
	for _, cookie := range []*http.Cookie{aCookie, bCookie} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.AddCookie(cookie)
		principal, _, err := h.manager.Browser(req)
		if err != nil {
			t.Fatal("second client login invalidated bound session:", err)
		}
		if principal.UserID != a.UserID {
			t.Fatal("session moved to another user")
		}
	}
	changed := h.config.Auth
	changed.Providers = []serverconfig.ProviderConfig{secondary}
	eligibility := NewEligibility(changed, h.repo, nil)
	_, err = eligibility.CheckPrincipal(context.Background(), a)
	assertStatus(t, err, 401)
	if _, err = eligibility.CheckPrincipal(context.Background(), b); err != nil {
		t.Fatal("removing another configured client revoked the enabled provider")
	}
	changed.Providers = []serverconfig.ProviderConfig{primary, secondary}
	changed.Providers[0].AllowedDomains = []string{"elsewhere.example"}
	eligibility = NewEligibility(changed, h.repo, nil)
	_, err = eligibility.CheckPrincipal(context.Background(), a)
	assertStatus(t, err, 401)
	if _, err = eligibility.CheckPrincipal(context.Background(), b); err != nil {
		t.Fatal("one provider's admission policy leaked into another")
	}
}
