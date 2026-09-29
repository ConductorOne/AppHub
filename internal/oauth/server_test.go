// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
)

type oauthHarness struct {
	server    *Server
	browser   *auth.Manager
	repo      *testutil.Repository
	mux       *http.ServeMux
	cookie    *http.Cookie
	principal cp.Principal
	session   cp.Session
	origin    string
}

func newOAuthHarness(t *testing.T) *oauthHarness {
	t.Helper()
	issuer := testutil.NewOIDC(t)
	cfg := serverconfig.Config{PublicOrigin: "http://127.0.0.1:5173", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(strings.Repeat("K", 32)), Providers: []serverconfig.ProviderConfig{{ID: "test", Kind: "oidc", Issuer: issuer.Issuer(), ClientID: issuer.ClientID, ClientSecret: credentials.NewSecret(issuer.ClientSecret), AllowedDomains: []string{"example.com"}}}, Clients: []serverconfig.ClientConfig{{ID: "remote", RedirectURIs: []string{"https://client.example/callback"}}}}}
	repo := testutil.NewRepository()
	browser, err := auth.New(context.Background(), cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(cfg, repo, browser)
	if err != nil {
		t.Fatal(err)
	}
	h := &oauthHarness{server: server, browser: browser, repo: repo, mux: http.NewServeMux(), origin: cfg.PublicOrigin}
	browser.Register(h.mux)
	server.Register(h.mux)
	// Exercise the signed local relying-party flow, not a production bypass.
	begin := httptest.NewRecorder()
	h.mux.ServeHTTP(begin, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	if begin.Code != 302 {
		t.Fatalf("login: %d %s", begin.Code, begin.Body.String())
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(begin.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("issuer: %d", res.StatusCode)
	}
	callback := httptest.NewRequest(http.MethodGet, res.Header.Get("Location"), nil)
	for _, cookie := range begin.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	h.mux.ServeHTTP(result, callback)
	if result.Code != 303 {
		t.Fatalf("callback: %d %s", result.Code, result.Body.String())
	}
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == "apphub_session" {
			h.cookie = cookie
		}
	}
	if h.cookie == nil {
		t.Fatal("signed login did not establish a session")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	request.AddCookie(h.cookie)
	h.principal, h.session, err = browser.Browser(request)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (h *oauthHarness) request(method, path, body string, cookie bool, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie {
		r.AddCookie(h.cookie)
	}
	if csrf {
		r.Header.Set("Origin", h.origin)
		r.Header.Set("X-CSRF-Token", h.session.CSRF)
	}
	if method == "POST" {
		if strings.HasPrefix(body, "{") {
			r.Header.Set("Content-Type", "application/json")
		} else {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	return w
}
func (h *oauthHarness) authorizationQuery(resource string) (url.Values, string) {
	verifier := secret()
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {"apphub-cli"}, "redirect_uri": {"http://127.0.0.1:43210/callback"}, "response_type": {"code"}, "state": {secret()}, "resource": {h.origin + resource}, "scope": {cp.ApplicationsRead + " " + cp.DeploymentsRead}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}, verifier
}
func (h *oauthHarness) consent(t *testing.T, query url.Values) string {
	t.Helper()
	w := h.request("GET", "/oauth/authorize?"+query.Encode(), "", true, false)
	if w.Code != 302 {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/authorize" {
		t.Fatalf("unexpected consent location: %s", location)
	}
	return location.Query().Get("transactionId")
}

func TestAuthorizationResponsesDenyFraming(t *testing.T) {
	h := newOAuthHarness(t)
	q, _ := h.authorizationQuery("/api")
	id := h.consent(t, q)
	for _, tc := range []struct {
		name, method, path, body string
		cookie, csrf             bool
		status                   int
	}{
		{name: "login redirect", method: "GET", path: "/oauth/authorize?" + q.Encode(), status: http.StatusFound},
		{name: "consent redirect", method: "GET", path: "/oauth/authorize?" + q.Encode(), cookie: true, status: http.StatusFound},
		{name: "invalid request", method: "GET", path: "/oauth/authorize?client_id=unknown", cookie: true, status: http.StatusBadRequest},
		{name: "invalid hosted target", method: "GET", path: "/mcp/apps/nonexistent/assistant.apps.example.test/oauth/authorize", status: http.StatusBadRequest},
		{name: "rejected consent decision", method: "POST", path: "/oauth/authorize", body: `{}`, cookie: true, csrf: true, status: http.StatusBadRequest},
		{name: "approved consent decision", method: "POST", path: "/oauth/authorize", body: `{"transactionId":"` + id + `","action":"approve"}`, cookie: true, csrf: true, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.request(tc.method, tc.path, tc.body, tc.cookie, tc.csrf)
			if response.Code != tc.status {
				t.Fatalf("authorization response = %d %s, want %d", response.Code, response.Body.String(), tc.status)
			}
			if got := response.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
				t.Fatalf("authorization CSP = %q", got)
			}
			if got := response.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("authorization X-Frame-Options = %q", got)
			}
			if tc.name == "consent redirect" && !strings.HasPrefix(response.Header().Get("Location"), "/authorize?transactionId=") {
				t.Fatalf("valid top-level authorization did not reach consent: %s", response.Header().Get("Location"))
			}
		})
	}
}

func (h *oauthHarness) approve(t *testing.T, id, action string) *url.URL {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"transactionId": id, "action": action})
	w := h.request("POST", "/oauth/authorize", string(body), true, true)
	if w.Code != 200 {
		t.Fatalf("consent: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		RedirectURL string `json:"redirectUrl"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal("invalid consent response")
	}
	u, err := url.Parse(out.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func (h *oauthHarness) exchangeValues(t *testing.T, resource string) url.Values {
	t.Helper()
	q, verifier := h.authorizationQuery(resource)
	id := h.consent(t, q)
	redirect := h.approve(t, id, "approve")
	if redirect.Query().Get("state") != q.Get("state") || redirect.Query().Get("iss") != h.origin || redirect.Query().Get("code") == "" {
		t.Fatal("uncorrelated authorization response")
	}
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {q.Get("client_id")}, "redirect_uri": {q.Get("redirect_uri")}, "resource": {q.Get("resource")}, "code_verifier": {verifier}, "code": {redirect.Query().Get("code")}}
}
func (h *oauthHarness) issue(t *testing.T, resource string) tokenResponse {
	t.Helper()
	w := h.request("POST", "/oauth/token", h.exchangeValues(t, resource).Encode(), false, false)
	return decodeTokens(t, w)
}
func decodeTokens(t *testing.T, w *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var out tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !validSecret(out.AccessToken) || !validSecret(out.RefreshToken) {
		t.Fatal("missing bearer credentials")
	}
	return out
}
func refreshValues(h *oauthHarness, token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"apphub-cli"}, "resource": {h.origin + "/api"}, "refresh_token": {token}}
}
func assertProblem(t *testing.T, err error, status int) {
	t.Helper()
	var p *cp.Error
	if !errors.As(err, &p) || p.Status != status {
		t.Fatalf("expected %d, got %v", status, err)
	}
}

func TestAuthorizationCodeBindingAndResourceIsolation(t *testing.T) {
	h := newOAuthHarness(t)
	values := h.exchangeValues(t, "/api")
	for _, field := range []string{"code_verifier", "client_id", "redirect_uri", "resource"} {
		t.Run(field, func(t *testing.T) {
			bad := maps.Clone(values)
			switch field {
			case "code_verifier":
				bad.Set(field, secret())
			case "resource":
				bad.Set(field, h.origin+"/mcp")
			case "client_id":
				bad.Set(field, "remote")
			default:
				bad.Set(field, "http://127.0.0.1:43211/callback")
			}
			w := h.request("POST", "/oauth/token", bad.Encode(), false, false)
			if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
				t.Fatalf("binding accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
	tokens := decodeTokens(t, h.request("POST", "/oauth/token", values.Encode(), false, false))
	if w := h.request("POST", "/oauth/token", values.Encode(), false, false); w.Code != 400 {
		t.Fatal("authorization code replay accepted")
	}
	principal, err := h.server.AuthenticateBearer(context.Background(), "Bearer "+tokens.AccessToken, h.origin+"/api")
	if err != nil || principal.UserID != h.principal.UserID || !principal.Bearer {
		t.Fatalf("API token rejected: %v", err)
	}
	_, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+tokens.AccessToken, h.origin+"/mcp")
	assertProblem(t, err, 401)
	for _, raw := range []string{h.cookie.Value, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.signature", tokens.RefreshToken} {
		_, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+raw, h.origin+"/api")
		assertProblem(t, err, 401)
	}
	mcp := h.issue(t, "/mcp")
	if _, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+mcp.AccessToken, h.origin+"/mcp"); err != nil {
		t.Fatal(err)
	}
}

func TestConsentBindingTamperCSRFAndSingleUse(t *testing.T) {
	h := newOAuthHarness(t)
	q, _ := h.authorizationQuery("/api")
	id := h.consent(t, q)
	view, err := h.server.Consent(context.Background(), h.principal, id)
	if err != nil || view.Resource != q.Get("resource") || view.Identity.Subject != h.principal.Subject {
		t.Fatalf("consent view: %v", err)
	}
	other := h.principal
	other.SessionID = hash(secret())
	if _, err = h.server.Consent(context.Background(), other, id); err == nil {
		t.Fatal("consent exposed to another session")
	}
	bearer := h.principal
	bearer.Bearer = true
	if _, err = h.server.Consent(context.Background(), bearer, id); err == nil {
		t.Fatal("consent exposed to bearer")
	}
	for _, body := range []string{`{"transactionId":"` + id + `","action":"anything"}`, `{"transactionId":"` + id + `","action":"deny","action":"approve"}`, `{"transactionId":"` + id + `","action":"approve","scope":"applications:write"}`, `{"transactionId":"` + id + `","action":"approve","redirectUri":"https://attacker.example/"}`} {
		if w := h.request("POST", "/oauth/authorize", body, true, true); w.Code != 400 {
			t.Fatalf("consent tamper accepted: %s", w.Body.String())
		}
	}
	body := `{"transactionId":"` + id + `","action":"approve"}`
	if w := h.request("POST", "/oauth/authorize", body, true, false); w.Code != 403 {
		t.Fatal("consent accepted without origin and CSRF")
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(body))
	r.AddCookie(h.cookie)
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("X-CSRF-Token", h.session.CSRF)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	denied := h.approve(t, id, "deny")
	if denied.Query().Get("error") != "access_denied" || denied.Query().Get("code") != "" || denied.Query().Get("state") != q.Get("state") || denied.Query().Get("iss") != h.origin {
		t.Fatal("denial was not correlated")
	}
	if w = h.request("POST", "/oauth/authorize", body, true, true); w.Code != 400 {
		t.Fatal("denied consent reused")
	}
}

func TestRefreshRotationReplayAndAbsoluteExpiry(t *testing.T) {
	h := newOAuthHarness(t)
	tokens := h.issue(t, "/api")
	accessRec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.AccessKind, ID: hash(tokens.AccessToken)})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := cp.Decode[cp.OAuthToken](accessRec)
	familyRec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.FamilyKind, ID: access.FamilyID})
	if err != nil {
		t.Fatal(err)
	}
	family, _ := cp.Decode[cp.OAuthFamily](familyRec)
	// A family near its absolute deadline must not get a fresh 30 days or a
	// fifteen-minute access token that outlives the family.
	family.ExpiresAt = time.Now().Add(2 * time.Minute)
	if err = h.repo.Commit(context.Background(), []cp.Mutation{mutation(cp.FamilyKind, family.ID, familyRec.Version, family)}); err != nil {
		t.Fatal(err)
	}
	rotated := decodeTokens(t, h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false))
	if rotated.ExpiresIn > 120 {
		t.Fatal("refresh extended absolute expiry")
	}
	if _, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+rotated.AccessToken, h.origin+"/api"); err != nil {
		t.Fatal(err)
	}
	replay := h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false)
	if replay.Code != 400 {
		t.Fatal("refresh replay accepted")
	}
	_, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+rotated.AccessToken, h.origin+"/api")
	assertProblem(t, err, 401)
	if w := h.request("POST", "/oauth/token", refreshValues(h, rotated.RefreshToken).Encode(), false, false); w.Code != 400 {
		t.Fatal("revoked family resurrected")
	}
}

func TestConcurrentRefreshAndRevocationCannotResurrectFamily(t *testing.T) {
	h := newOAuthHarness(t)
	tokens := h.issue(t, "/api")
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		results <- h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false)
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- h.request("POST", "/oauth/revoke", url.Values{"client_id": {"apphub-cli"}, "token": {tokens.RefreshToken}}.Encode(), false, false)
	}()
	close(start)
	wg.Wait()
	close(results)
	for result := range results {
		if result.Code != 200 && result.Code != 400 {
			t.Fatalf("unexpected race result: %d %s", result.Code, result.Body.String())
		}
		if result.Body.Len() > 0 && result.Code == 200 {
			rotated := decodeTokens(t, result)
			_, err := h.server.AuthenticateBearer(context.Background(), "Bearer "+rotated.AccessToken, h.origin+"/api")
			assertProblem(t, err, 401)
		}
	}
	_, err := h.server.AuthenticateBearer(context.Background(), "Bearer "+tokens.AccessToken, h.origin+"/api")
	assertProblem(t, err, 401)
	for range 2 {
		if w := h.request("POST", "/oauth/revoke", url.Values{"client_id": {"apphub-cli"}, "token": {tokens.RefreshToken}}.Encode(), false, false); w.Code != 200 {
			t.Fatal("revocation is not idempotent")
		}
	}
}

func TestEligibilityAndStorageFailuresRemainDistinct(t *testing.T) {
	h := newOAuthHarness(t)
	tokens := h.issue(t, "/api")
	h.repo.SetError(cp.ErrUnavailable)
	_, err := h.server.AuthenticateBearer(context.Background(), "Bearer "+tokens.AccessToken, h.origin+"/api")
	assertProblem(t, err, 503)
	if w := h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false); w.Code != 503 {
		t.Fatal("storage outage misclassified as invalid credential")
	}
	h.repo.SetError(nil)
	rec, err := h.repo.Read(context.Background(), cp.RecordID{Kind: cp.UserKind, ID: h.principal.UserID})
	if err != nil {
		t.Fatal(err)
	}
	user, _ := cp.Decode[cp.User](rec)
	user.Disabled = true
	if err = h.repo.Commit(context.Background(), []cp.Mutation{mutation(cp.UserKind, user.ID, rec.Version, user)}); err != nil {
		t.Fatal(err)
	}
	_, err = h.server.AuthenticateBearer(context.Background(), "Bearer "+tokens.AccessToken, h.origin+"/api")
	assertProblem(t, err, 401)
	if w := h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false); w.Code != 400 {
		t.Fatal("disabled user refreshed")
	}
}

func TestAuthorizeValidationAndUnauthenticatedResume(t *testing.T) {
	h := newOAuthHarness(t)
	q, _ := h.authorizationQuery("/api")
	w := h.request("GET", "/oauth/authorize?"+q.Encode(), "", false, false)
	location, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || location.Path != "/login" || location.Query().Get("return_to") != "/oauth/authorize?"+q.Encode() {
		t.Fatal("login did not preserve validated authorization")
	}
	for _, change := range []struct{ key, value string }{{"scope", ""}, {"scope", "applications:read-more"}, {"scope", "applications:read\tdeployments:write"}, {"code_challenge_method", "plain"}, {"code_challenge", strings.Repeat("a", 42)}, {"resource", "https://other.example/api"}, {"redirect_uri", "http://localhost:43210/callback"}, {"redirect_uri", "http://127.0.0.1:43210/callback?extra=1"}} {
		bad := maps.Clone(q)
		bad.Set(change.key, change.value)
		result := h.request("GET", "/oauth/authorize?"+bad.Encode(), "", true, false)
		if result.Code == 302 {
			u, _ := url.Parse(result.Header().Get("Location"))
			if u.Path == "/authorize" {
				t.Fatalf("invalid %s accepted", change.key)
			}
		} else if result.Code != 400 {
			t.Fatalf("unexpected invalid request status %d", result.Code)
		}
	}
	for _, path := range []string{"/.well-known/oauth-authorization-server/extra", "/.well-known/oauth-protected-resource/unknown"} {
		if w = h.request("GET", path, "", false, false); w.Code != 404 {
			t.Fatal("unknown discovery suffix accepted")
		}
	}
}

func TestExpiryIsEnforcedWithoutTTLDeletion(t *testing.T) {
	h := newOAuthHarness(t)
	ctx := context.Background()
	q, _ := h.authorizationQuery("/api")
	id := h.consent(t, q)
	rec, err := h.repo.Read(ctx, cp.RecordID{Kind: cp.ConsentKind, ID: hash(id)})
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := cp.Decode[consentTransaction](rec)
	tx.ExpiresAt = time.Now().Add(-time.Second)
	if err = h.repo.Commit(ctx, []cp.Mutation{mutation(cp.ConsentKind, rec.ID, rec.Version, tx)}); err != nil {
		t.Fatal(err)
	}
	if w := h.request("POST", "/oauth/authorize", `{"transactionId":"`+id+`","action":"approve"}`, true, true); w.Code != 400 {
		t.Fatal("expired consent issued a code")
	}
	values := h.exchangeValues(t, "/api")
	rec, err = h.repo.Read(ctx, cp.RecordID{Kind: cp.CodeKind, ID: hash(values.Get("code"))})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := cp.Decode[authorizationCode](rec)
	code.ExpiresAt = time.Now().Add(-time.Second)
	if err = h.repo.Commit(ctx, []cp.Mutation{mutation(cp.CodeKind, rec.ID, rec.Version, code)}); err != nil {
		t.Fatal(err)
	}
	if w := h.request("POST", "/oauth/token", values.Encode(), false, false); w.Code != 400 {
		t.Fatal("expired code exchanged")
	}
	tokens := h.issue(t, "/api")
	rec, err = h.repo.Read(ctx, cp.RecordID{Kind: cp.AccessKind, ID: hash(tokens.AccessToken)})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := cp.Decode[cp.OAuthToken](rec)
	token.ExpiresAt = time.Now().Add(-time.Second)
	if err = h.repo.Commit(ctx, []cp.Mutation{mutation(cp.AccessKind, rec.ID, rec.Version, token)}); err != nil {
		t.Fatal(err)
	}
	_, err = h.server.AuthenticateBearer(ctx, "Bearer "+tokens.AccessToken, h.origin+"/api")
	assertProblem(t, err, 401)
	fr, err := h.repo.Read(ctx, cp.RecordID{Kind: cp.FamilyKind, ID: token.FamilyID})
	if err != nil {
		t.Fatal(err)
	}
	family, _ := cp.Decode[cp.OAuthFamily](fr)
	family.ExpiresAt = time.Now().Add(-time.Second)
	if err = h.repo.Commit(ctx, []cp.Mutation{mutation(cp.FamilyKind, fr.ID, fr.Version, family)}); err != nil {
		t.Fatal(err)
	}
	if w := h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false); w.Code != 400 {
		t.Fatal("expired family refreshed")
	}
}

func TestConcurrentRefreshReplayRevokesWinningTokens(t *testing.T) {
	h := newOAuthHarness(t)
	tokens := h.issue(t, "/api")
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			<-start
			results <- h.request("POST", "/oauth/token", refreshValues(h, tokens.RefreshToken).Encode(), false, false)
		}()
	}
	close(start)
	var winner tokenResponse
	successes := 0
	for range 2 {
		result := <-results
		if result.Code == 200 {
			winner = decodeTokens(t, result)
			successes++
		} else if result.Code != 400 {
			t.Fatalf("refresh race: %d %s", result.Code, result.Body.String())
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one refresh before replay revocation, got %d", successes)
	}
	_, err := h.server.AuthenticateBearer(context.Background(), "Bearer "+winner.AccessToken, h.origin+"/api")
	assertProblem(t, err, 401)
	if w := h.request("POST", "/oauth/token", refreshValues(h, winner.RefreshToken).Encode(), false, false); w.Code != 400 {
		t.Fatal("replayed family replacement refreshed")
	}
}

func TestHostedMCPAuthorizationBindsAppAudienceAndForwardAuth(t *testing.T) {
	h := newOAuthHarness(t)
	applicationID := cp.NewID()
	host := "assistant.apps.example.test"
	application := cp.ApplicationRecord{
		ID:     applicationID,
		Owners: []cp.ApplicationOwner{{Kind: cp.OwnerUser, ID: h.principal.UserID}},
		Input: cp.ApplicationInput{
			Exposure: cp.ExposureInput{Mode: "public", Hostname: "assistant", MCPAuthEnabled: true},
		},
		Addresses: []string{"https://" + host},
	}
	record, err := cp.Encode(cp.RecordID{Kind: cp.ApplicationKind, ID: applicationID}, 1, application)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.repo.Commit(t.Context(), []cp.Mutation{{Record: record, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}

	issuerPath := "/mcp/apps/" + applicationID + "/" + host
	issuer := h.origin + issuerPath
	resource := "https://" + host + "/mcp"
	metadata := h.request("GET", "/.well-known/oauth-protected-resource/mcp/apps/"+applicationID+"/"+host, "", false, false)
	if metadata.Code != http.StatusOK || !strings.Contains(metadata.Body.String(), resource) || !strings.Contains(metadata.Body.String(), issuer) || !strings.Contains(metadata.Body.String(), cp.AppAccess) {
		t.Fatalf("hosted resource metadata: %d %s", metadata.Code, metadata.Body.String())
	}

	verifier := secret()
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {"apphub-cli"},
		"redirect_uri":          {"http://127.0.0.1:43210/callback"},
		"response_type":         {"code"},
		"state":                 {secret()},
		"resource":              {resource},
		"scope":                 {cp.AppAccess},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
	}
	authorization := h.request("GET", issuerPath+"/oauth/authorize?"+query.Encode(), "", true, false)
	if authorization.Code != http.StatusFound {
		t.Fatalf("hosted authorize: %d %s", authorization.Code, authorization.Body.String())
	}
	if authorization.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" || authorization.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("hosted authorization redirect can be framed")
	}
	consentURL, err := url.Parse(authorization.Header().Get("Location"))
	if err != nil || consentURL.Path != "/authorize" {
		t.Fatalf("hosted consent redirect: %s", authorization.Header().Get("Location"))
	}
	redirect := h.approve(t, consentURL.Query().Get("transactionId"), "approve")
	if redirect.Query().Get("iss") != issuer {
		t.Fatalf("authorization issuer = %q, want %q", redirect.Query().Get("iss"), issuer)
	}
	exchange := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {query.Get("client_id")},
		"redirect_uri":  {query.Get("redirect_uri")},
		"resource":      {resource},
		"code_verifier": {verifier},
		"code":          {redirect.Query().Get("code")},
	}
	tokens := decodeTokens(t, h.request("POST", issuerPath+"/oauth/token", exchange.Encode(), false, false))
	principal, err := h.server.AuthenticateApplicationBearer(t.Context(), "Bearer "+tokens.AccessToken, applicationID, host)
	if err != nil || principal.UserID != h.principal.UserID || !slices.Equal(principal.Scopes, []string{cp.AppAccess}) {
		t.Fatalf("hosted token rejected: principal=%+v err=%v", principal, err)
	}
	if _, err = h.server.AuthenticateBearer(t.Context(), "Bearer "+tokens.AccessToken, h.origin+"/mcp"); err == nil {
		t.Fatal("app-scoped token authenticated to the AppHub management MCP")
	}

	forwardRequest := httptest.NewRequest(http.MethodPost, "/authz/app-mcp", nil)
	forwardRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	forwardRequest.Header.Set(hostedApplicationHeader, applicationID)
	forwardRequest.Header.Set(hostedHostHeader, host)
	forward := httptest.NewRecorder()
	h.mux.ServeHTTP(forward, forwardRequest)
	if forward.Code != http.StatusNoContent || forward.Header().Get(hostedUserHeader) != h.principal.UserID || forward.Header().Get(hostedEmailHeader) == "" {
		t.Fatalf("ForwardAuth response: %d headers=%v body=%s", forward.Code, forward.Header(), forward.Body.String())
	}

	application.Input.Exposure.MCPAuthEnabled = false
	updated, err := cp.Encode(record.RecordID, record.Version+1, application)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.repo.Commit(t.Context(), []cp.Mutation{{Record: updated, ExpectedVersion: record.Version}}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.server.AuthenticateApplicationBearer(t.Context(), "Bearer "+tokens.AccessToken, applicationID, host); err == nil {
		t.Fatal("disabling hosted MCP auth left its access token usable")
	}
	disabledRefresh := h.request("POST", issuerPath+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"apphub-cli"},
		"resource":      {resource},
		"refresh_token": {tokens.RefreshToken},
	}.Encode(), false, false)
	if disabledRefresh.Code != http.StatusBadRequest || !strings.Contains(disabledRefresh.Body.String(), "invalid_grant") {
		t.Fatalf("disabled hosted refresh: %d %s", disabledRefresh.Code, disabledRefresh.Body.String())
	}
	if disabled := h.request("GET", "/.well-known/oauth-protected-resource/mcp/apps/"+applicationID+"/"+host, "", false, false); disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled hosted metadata returned %d", disabled.Code)
	}
}
