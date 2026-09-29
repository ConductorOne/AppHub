// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/oauth"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
)

const apiTestOrigin = "http://127.0.0.1:5173"

// appOwnerByDefaultEligibility wraps the real *auth.Manager's admission
// recheck but resolves every non-admin identity to RoleAppOwner rather than
// the directory-driven default (RoleMember) -- this fixture configures no
// ConductorOne directory at all, and its many application-lifecycle tests
// exercise an ordinary application owner (alice, bob), not a fresh member
// with nothing assigned. The real, directory-driven default is covered by
// internal/auth/eligibility_test.go and TestAPIMembersAdminEndpoint.
type appOwnerByDefaultEligibility struct{ inner *auth.Manager }

func (e appOwnerByDefaultEligibility) CheckPrincipal(ctx context.Context, p cp.Principal) (cp.Principal, error) {
	out, err := e.inner.CheckPrincipal(ctx, p)
	if err == nil && !out.Admin {
		out.Role = cp.RoleAppOwner
	}
	return out, err
}
func (e appOwnerByDefaultEligibility) ResolveRole(ctx context.Context, email string) (string, bool) {
	return e.inner.ResolveRole(ctx, email)
}

type apiFixture struct {
	mux     *http.ServeMux
	repo    *testutil.Repository
	issuer  string
	input   cp.ApplicationInput
	cookies map[string]string
	csrf    map[string]string
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	// Only discovery is exercised here; sessions below represent already verified
	// identities. Signed login/token verification belongs to the auth integration.
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "userinfo_endpoint": issuer.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	t.Cleanup(issuer.Close)
	repo := testutil.NewRepository()
	cfg := serverconfig.Config{PublicOrigin: apiTestOrigin, Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(strings.Repeat("k", 32)), Providers: []serverconfig.ProviderConfig{{ID: "test", Kind: "oidc", Issuer: issuer.URL, ClientID: "portal", ClientSecret: credentials.NewSecret("test-secret"), AllowedDomains: []string{"example.com"}}}}}
	browser, err := auth.New(context.Background(), cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.New(cfg, repo, browser)
	if err != nil {
		t.Fatal(err)
	}
	policy := cp.TargetPolicy{ID: "test", Label: "Test", ConfigHash: "test-policy", DeployConfig: deploy.Config{WorkloadIdentityMode: "native", ResourcePrefix: "test", AllowedSourceHosts: []string{"github.com"}}, ResourceSizes: []cp.ResourceInput{{CPU: 1000, Memory: 2048}}, MaxReplicas: 3, ExecutionModes: []string{"service"}, Repositories: []string{"https://github.com/example/app.git"}}
	service, err := cp.NewService(repo, appOwnerByDefaultEligibility{browser}, map[string]cp.TargetPolicy{"test": policy})
	if err != nil {
		t.Fatal(err)
	}
	f := &apiFixture{mux: http.NewServeMux(), repo: repo, issuer: issuer.URL, cookies: map[string]string{}, csrf: map[string]string{}, input: cp.ApplicationInput{Name: "Example", TargetID: "test", Source: cp.SourceInput{URL: policy.Repositories[0], Dockerfile: "Dockerfile"}, Execution: deploy.ExecutionService, Port: 8080, Resources: policy.ResourceSizes[0], Replicas: 1, Exposure: cp.ExposureInput{Mode: "private"}}}
	f.put(t, cp.RecordID{Kind: cp.TargetKind, ID: "test"}, cp.TargetDescriptor{ID: "test", ProviderName: "aws", ConfigHash: policy.ConfigHash, Capabilities: compute.NewCapabilitySet(compute.AllCapabilities()...), HeartbeatAt: time.Now().Add(-time.Second)})
	for i, user := range []string{"alice", "bob"} {
		now := time.Now().UTC()
		raw := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))
		csrf := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 11)}, 32))
		f.cookies[user], f.csrf[user] = raw, csrf
		f.put(t, cp.RecordID{Kind: cp.UserKind, ID: user}, cp.User{ID: user, Email: user + "@example.com", Name: user, CreatedAt: now, UpdatedAt: now})
		f.put(t, cp.RecordID{Kind: cp.IdentityKind, ID: user, ParentID: issuer.URL}, cp.ExternalIdentity{UserID: user, ProviderID: "test", Issuer: issuer.URL, Subject: user, Email: user + "@example.com", EmailVerified: true, UpdatedAt: now})
		f.put(t, cp.RecordID{Kind: cp.SessionKind, ID: cp.Hash(raw)}, cp.Session{ID: cp.NewID(), UserID: user, ProviderID: "test", Issuer: issuer.URL, Subject: user, CSRF: csrf, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	}
	Register(f.mux, service, browser, authority, apiTestOrigin)
	return f
}

func (f *apiFixture) put(t *testing.T, id cp.RecordID, value any) {
	t.Helper()
	record, err := cp.Encode(id, 1, value)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: record, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}

func (f *apiFixture) token(t *testing.T, user, resource string, scopes ...string) string {
	t.Helper()
	id := cp.NewID()
	raw := base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(cp.NewID(), "-", "")))
	now := time.Now()
	f.put(t, cp.RecordID{Kind: cp.FamilyKind, ID: id}, cp.OAuthFamily{ID: id, UserID: user, ProviderID: "test", Issuer: f.issuer, Subject: user, ClientID: "apphub-cli", Resource: apiTestOrigin + resource, Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	f.put(t, cp.RecordID{Kind: cp.AccessKind, ID: cp.Hash(raw)}, cp.OAuthToken{FamilyID: id, ExpiresAt: now.Add(time.Minute)})
	return raw
}

func (f *apiFixture) request(t *testing.T, method, path, user string, body any, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	switch value := body.(type) {
	case nil:
	case string:
		encoded = []byte(value)
	default:
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	if user != "" {
		request.AddCookie(&http.Cookie{Name: "apphub_session", Value: f.cookies[user]})
	}
	for key, values := range headers {
		request.Header[key] = values
	}
	response := httptest.NewRecorder()
	f.mux.ServeHTTP(response, request)
	return response
}

func (f *apiFixture) mutationHeaders(user, key string) http.Header {
	h := http.Header{"Origin": {apiTestOrigin}, "X-Csrf-Token": {f.csrf[user]}}
	if key != "" {
		h.Set("Idempotency-Key", key)
	}
	return h
}

func apiStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status %d, want %d: %s", response.Code, status, response.Body.String())
	}
	if status >= 400 {
		var problem cp.ErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
			t.Fatal(err)
		}
		if problem.Error == nil || problem.Error.Code == "" || problem.RequestID == "" || problem.RequestID != response.Header().Get("X-Request-ID") {
			t.Fatalf("missing structured problem/correlation: %s", response.Body.String())
		}
	}
}

func TestAPICookieCSRFAndBearerPrecedence(t *testing.T) {
	f := newAPIFixture(t)
	anonymous := f.request(t, "GET", "/api/v1/users/me", "", nil, nil)
	apiStatus(t, anonymous, 401)
	if anonymous.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="`+apiTestOrigin+`/.well-known/oauth-protected-resource/api"` {
		t.Fatal("missing resource-specific challenge")
	}
	valid := f.request(t, "GET", "/api/v1/users/me", "alice", nil, nil)
	apiStatus(t, valid, 200)
	var me cp.UserView
	if err := json.Unmarshal(valid.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.ID != "alice" || me.CSRFToken != f.csrf["alice"] || valid.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cookie identity/CSRF was not returned privately")
	}
	for _, authorization := range []string{"", "Bearer invalid"} {
		apiStatus(t, f.request(t, "GET", "/api/v1/users/me", "alice", nil, http.Header{"Authorization": {authorization}}), 401)
	}
	for name, headers := range map[string]http.Header{
		"missing origin": {"X-Csrf-Token": {f.csrf["alice"]}, "Idempotency-Key": {"csrf"}},
		"foreign origin": {"Origin": {"https://attacker.example"}, "X-Csrf-Token": {f.csrf["alice"]}, "Idempotency-Key": {"csrf"}},
		"missing token":  {"Origin": {apiTestOrigin}, "Idempotency-Key": {"csrf"}},
	} {
		t.Run(name, func(t *testing.T) {
			apiStatus(t, f.request(t, "POST", "/api/v1/applications", "alice", f.input, headers), 403)
		})
	}
	token := f.token(t, "bob", "/api", cp.ApplicationsWrite)
	response := f.request(t, "POST", "/api/v1/applications", "alice", f.input, http.Header{"Authorization": {"Bearer " + token}, "Idempotency-Key": {"bearer-create"}})
	apiStatus(t, response, 201)
	var app cp.ApplicationView
	if err := json.Unmarshal(response.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	if len(app.Owners) != 1 || app.Owners[0].ID != "bob" {
		t.Fatal("cookie overrode bearer identity")
	}
	wrongAudience := f.token(t, "alice", "/mcp", cp.ApplicationsRead)
	apiStatus(t, f.request(t, "GET", "/api/v1/targets", "alice", nil, http.Header{"Authorization": {"Bearer " + wrongAudience}}), 401)
	readOnly := f.token(t, "alice", "/api", cp.ApplicationsRead)
	apiStatus(t, f.request(t, "POST", "/api/v1/applications", "", f.input, http.Header{"Authorization": {"Bearer " + readOnly}, "Idempotency-Key": {"read-only"}}), 403)
}

func TestAPIOwnershipIdempotencyAndDeploymentLocation(t *testing.T) {
	f := newAPIFixture(t)
	create := func(input cp.ApplicationInput) cp.ApplicationView {
		response := f.request(t, "POST", "/api/v1/applications", "alice", input, f.mutationHeaders("alice", "create"))
		apiStatus(t, response, 201)
		var view cp.ApplicationView
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if response.Header().Get("Location") != "/api/v1/applications/"+view.ID || response.Header().Get("ETag") != `"1"` {
			t.Fatal("missing creation location/revision")
		}
		return view
	}
	app := create(f.input)
	if repeated := create(f.input); repeated.ID != app.ID {
		t.Fatal("idempotency replay created another application")
	}
	changed := f.input
	changed.Name = "Other"
	apiStatus(t, f.request(t, "POST", "/api/v1/applications", "alice", changed, f.mutationHeaders("alice", "create")), 409)
	path := "/api/v1/applications/" + app.ID
	for _, route := range []string{path, path + "/deployments"} {
		apiStatus(t, f.request(t, "GET", route, "bob", nil, nil), 404)
	}
	apiStatus(t, f.request(t, "POST", path+"/deployments", "bob", cp.SubmitDeploymentInput{ApplicationRevision: 1}, f.mutationHeaders("bob", "foreign")), 404)
	headers := f.mutationHeaders("bob", "")
	headers.Set("If-Match", `"1"`)
	apiStatus(t, f.request(t, "PUT", path, "bob", changed, headers), 404)
	inventory := f.request(t, "GET", "/api/v1/applications", "bob", nil, nil)
	apiStatus(t, inventory, 200)
	var page cp.Page[cp.ApplicationView]
	if err := json.Unmarshal(inventory.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatal("cross-owner inventory disclosed")
	}
	headers = f.mutationHeaders("alice", "")
	headers.Set("If-Match", `"2"`)
	apiStatus(t, f.request(t, "PUT", path, "alice", changed, headers), 409)
	var accepted cp.DeploymentAccepted
	for range 2 {
		response := f.request(t, "POST", path+"/deployments", "alice", cp.SubmitDeploymentInput{ApplicationRevision: 1}, f.mutationHeaders("alice", "deploy"))
		apiStatus(t, response, 202)
		var value cp.DeploymentAccepted
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if accepted.DeploymentID != "" && value.DeploymentID != accepted.DeploymentID {
			t.Fatal("submission replay created another operation")
		}
		if value.State != cp.Queued || value.PollAfterMs != 2000 || response.Header().Get("Location") != value.StatusURL || value.StatusURL != "/api/v1/deployments/"+value.DeploymentID {
			t.Fatal("acceptance does not identify durable queued operation")
		}
		accepted = value
	}
	apiStatus(t, f.request(t, "GET", accepted.StatusURL, "bob", nil, nil), 404)
	apiStatus(t, f.request(t, "POST", path+"/deployments", "alice", cp.SubmitDeploymentInput{ApplicationRevision: 1}, f.mutationHeaders("alice", "second")), 409)
	headers.Set("If-Match", `"1"`)
	apiStatus(t, f.request(t, "PUT", path, "alice", changed, headers), 409)
}

func TestAPIStrictBodiesAndPagination(t *testing.T) {
	f := newAPIFixture(t)
	for _, body := range []string{`null`, `{`, `{} {}`, `{"ownerUserId":"bob"}`, `{"source":{"awsSecretAccessKey":"canary"}}`} {
		apiStatus(t, f.request(t, "POST", "/api/v1/applications", "alice", body, f.mutationHeaders("alice", "malformed")), 400)
	}
	apiStatus(t, f.request(t, "POST", "/api/v1/applications", "alice", f.input, f.mutationHeaders("alice", "")), 400)
	huge := `{"name":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}`
	apiStatus(t, f.request(t, "POST", "/api/v1/applications", "alice", huge, f.mutationHeaders("alice", "oversized")), 413)
	// Unknown Content-Length must still enforce the streaming limit.
	request := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(huge))
	request.ContentLength = -1
	request.Header = f.mutationHeaders("alice", "chunked")
	request.AddCookie(&http.Cookie{Name: "apphub_session", Value: f.cookies["alice"]})
	response := httptest.NewRecorder()
	f.mux.ServeHTTP(response, request)
	apiStatus(t, response, 413)
	for _, query := range []string{"limit=0", "limit=101", "limit=1&limit=2", "all=1", "cursor=not-a-cursor"} {
		apiStatus(t, f.request(t, "GET", "/api/v1/applications?"+query, "alice", nil, nil), 400)
	}
	apiStatus(t, f.request(t, "GET", "/api/v1/applications?all=true", "alice", nil, nil), 403)
	f.repo.SetError(errors.New("storage secret-canary"))
	unavailable := f.request(t, "GET", "/api/v1/applications", "alice", nil, nil)
	apiStatus(t, unavailable, 503)
	if strings.Contains(unavailable.Body.String(), "secret-canary") {
		t.Fatal("dependency error leaked")
	}
}

func TestAPISessionRevocationIncludesDelegation(t *testing.T) {
	f := newAPIFixture(t)
	token := f.token(t, "alice", "/api", cp.ApplicationsRead)
	response := f.request(t, "GET", "/api/v1/sessions", "alice", nil, nil)
	apiStatus(t, response, 200)
	var page cp.Page[cp.SessionView]
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	var delegated string
	for _, session := range page.Items {
		if session.ClientID == "apphub-cli" {
			delegated = session.ID
		}
	}
	if delegated == "" {
		t.Fatal("delegated session missing from own session list")
	}
	apiStatus(t, f.request(t, "DELETE", "/api/v1/sessions/"+delegated, "bob", nil, f.mutationHeaders("bob", "")), 404)
	apiStatus(t, f.request(t, "DELETE", "/api/v1/sessions/"+delegated, "alice", nil, f.mutationHeaders("alice", "")), 204)
	apiStatus(t, f.request(t, "GET", "/api/v1/users/me", "", nil, http.Header{"Authorization": {"Bearer " + token}}), 401)
	f.repo.SetError(cp.ErrUnavailable)
	apiStatus(t, f.request(t, "DELETE", "/api/v1/sessions/"+delegated, "alice", nil, f.mutationHeaders("alice", "")), 503)
}

// fakeAdminKeyStore and fakeAdminLogReader are minimal stand-ins for
// internal/ghappkey.Store and internal/logs.Reader, satisfying
// controlplane's narrow interfaces so an admin fixture never needs the AWS
// SDK.
type fakeAdminKeyStore struct{ stored string }

func (f *fakeAdminKeyStore) Put(_ context.Context, key credentials.Secret) error {
	f.stored = credentials.Reveal(key)
	return nil
}
func (f *fakeAdminKeyStore) Delete(context.Context) error { f.stored = ""; return nil }

type fakeAdminLogReader struct {
	sawGroup string
	result   cp.LogResult
}

func (f *fakeAdminLogReader) Filter(_ context.Context, group string, _ cp.LogQuery) (cp.LogResult, error) {
	f.sawGroup = group
	return f.result, nil
}

// newAdminAPIFixture is a separate, smaller fixture rather than a
// modification of newAPIFixture's shared Admins config: several other tests
// in this file assert on "alice"/"bob" behaving as ordinary, non-admin
// users, and widening that shared fixture's admin set would be a silent
// coupling between unrelated tests.
func newAdminAPIFixture(t *testing.T, opts ...cp.ServiceOption) (*apiFixture, *fakeAdminKeyStore, *fakeAdminLogReader) {
	t.Helper()
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "userinfo_endpoint": issuer.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	t.Cleanup(issuer.Close)
	repo := testutil.NewRepository()
	cfg := serverconfig.Config{PublicOrigin: apiTestOrigin, Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(strings.Repeat("k", 32)), Providers: []serverconfig.ProviderConfig{{ID: "test", Kind: "oidc", Issuer: issuer.URL, ClientID: "portal", ClientSecret: credentials.NewSecret("test-secret"), AllowedDomains: []string{"example.com"}}}, Admins: []serverconfig.AdminConfig{{ProviderID: "test", Subject: "root"}}}}
	browser, err := auth.New(context.Background(), cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.New(cfg, repo, browser)
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeAdminKeyStore{}
	logs := &fakeAdminLogReader{}
	policy := cp.TargetPolicy{ID: "test", Label: "Test", ConfigHash: "test-policy", DeployConfig: deploy.Config{WorkloadIdentityMode: "native", ResourcePrefix: "test", AllowedSourceHosts: []string{"github.com"}}, ResourceSizes: []cp.ResourceInput{{CPU: 1000, Memory: 2048}}, MaxReplicas: 3, ExecutionModes: []string{"service"}, Repositories: []string{"https://github.com/example/app.git"}}
	service, err := cp.NewService(repo, browser, map[string]cp.TargetPolicy{"test": policy}, append([]cp.ServiceOption{cp.WithGitHubAppAdmin(keys), cp.WithLogs(logs, []cp.LogGroup{{Name: "serve", LogGroup: "/ecs/apphub/serve"}})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	f := &apiFixture{mux: http.NewServeMux(), repo: repo, issuer: issuer.URL, cookies: map[string]string{}, csrf: map[string]string{}}
	for _, user := range []string{"root", "regular"} {
		now := time.Now().UTC()
		raw := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(len(user))}, 32))
		csrf := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(len(user) + 10)}, 32))
		f.cookies[user], f.csrf[user] = raw, csrf
		f.put(t, cp.RecordID{Kind: cp.UserKind, ID: user}, cp.User{ID: user, Email: user + "@example.com", Name: user, CreatedAt: now, UpdatedAt: now})
		f.put(t, cp.RecordID{Kind: cp.IdentityKind, ID: user, ParentID: issuer.URL}, cp.ExternalIdentity{UserID: user, ProviderID: "test", Issuer: issuer.URL, Subject: user, Email: user + "@example.com", EmailVerified: true, UpdatedAt: now})
		f.put(t, cp.RecordID{Kind: cp.SessionKind, ID: cp.Hash(raw)}, cp.Session{ID: cp.NewID(), UserID: user, ProviderID: "test", Issuer: issuer.URL, Subject: user, CSRF: csrf, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	}
	Register(f.mux, service, browser, authority, apiTestOrigin)
	return f, keys, logs
}

func TestAPIGitHubAppAdminEndpoints(t *testing.T) {
	f, keys, _ := newAdminAPIFixture(t)

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/github-app", "regular", nil, nil), 403)
	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/github-app", "regular", cp.GitHubAppConfigInput{AppID: 1, PrivateKey: "x"}, f.mutationHeaders("regular", "")), 403)

	response := f.request(t, "GET", "/api/v1/admin/github-app", "root", nil, nil)
	apiStatus(t, response, 200)
	var status cp.GitHubAppStatusView
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Available || status.Configured {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	setResponse := f.request(t, "PUT", "/api/v1/admin/github-app", "root", cp.GitHubAppConfigInput{AppID: 555, PrivateKey: pemKey}, f.mutationHeaders("root", ""))
	apiStatus(t, setResponse, 200)
	var updated cp.GitHubAppStatusView
	if err := json.Unmarshal(setResponse.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.Configured || updated.AppID != 555 || keys.stored == "" {
		t.Fatalf("config did not take effect: %+v (stored key present: %v)", updated, keys.stored != "")
	}
}

// fakeManifestConverter stands in for a real call to GitHub's manifest
// conversion endpoint, so this test never reaches the network.
type fakeManifestConverter struct {
	calls    int
	lastCode string
	result   githubapp.ManifestConversion
}

func (f *fakeManifestConverter) convert(_ context.Context, code, _ string) (githubapp.ManifestConversion, error) {
	f.calls++
	f.lastCode = code
	return f.result, nil
}

func TestAPIGitHubAppManifestFlow(t *testing.T) {
	converter := &fakeManifestConverter{result: githubapp.ManifestConversion{AppID: 555, PrivateKeyPEM: credentials.NewSecret("-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n")}}
	f, keys, _ := newAdminAPIFixture(t, cp.WithPublicOrigin(apiTestOrigin), cp.WithManifestConverter(converter.convert))

	apiStatus(t, f.request(t, "POST", "/api/v1/admin/github-app/manifest", "regular", cp.GitHubAppManifestInput{}, f.mutationHeaders("regular", "")), 403)

	response := f.request(t, "POST", "/api/v1/admin/github-app/manifest", "root", cp.GitHubAppManifestInput{}, f.mutationHeaders("root", ""))
	apiStatus(t, response, 200)
	var start cp.GitHubAppManifestStart
	if err := json.Unmarshal(response.Body.Bytes(), &start); err != nil {
		t.Fatal(err)
	}
	if start.State == "" || start.CreateURL != "https://github.com/settings/apps/new" {
		t.Fatalf("unexpected start response: %+v", start)
	}

	// The callback is a plain browser GET navigation from github.com, not a
	// fetch this origin issued: no CSRF header, no Idempotency-Key, just the
	// session cookie and GitHub's own query parameters.
	callbackPath := "/api/v1/admin/github-app/manifest/callback?code=one-time-code&state=" + url.QueryEscape(start.State)
	callback := f.request(t, "GET", callbackPath, "root", nil, nil)
	if callback.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body=%s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != apiTestOrigin+"/workspace?tab=github-app&manifest=success" {
		t.Fatalf("unexpected redirect location: %q", location)
	}
	if converter.calls != 1 || converter.lastCode != "one-time-code" {
		t.Fatalf("converter calls=%d lastCode=%q, want 1 and the given code", converter.calls, converter.lastCode)
	}
	if keys.stored == "" {
		t.Fatal("the private key was never stored")
	}

	statusResp := f.request(t, "GET", "/api/v1/admin/github-app", "root", nil, nil)
	apiStatus(t, statusResp, 200)
	var view cp.GitHubAppStatusView
	if err := json.Unmarshal(statusResp.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.AppID != 555 || !view.PrivateKeyConfigured {
		t.Fatalf("stored app did not reflect the manifest exchange: %+v", view)
	}

	// Replaying the same callback URL (a resubmitted request, a shared link)
	// must not re-exchange the code: the state token is already consumed.
	replay := f.request(t, "GET", callbackPath, "root", nil, nil)
	if replay.Code != http.StatusFound || !strings.Contains(replay.Header().Get("Location"), "manifest=error") {
		t.Fatalf("replayed callback = %d %q, want a redirect reporting an error", replay.Code, replay.Header().Get("Location"))
	}
	if converter.calls != 1 {
		t.Fatal("GitHub was called again on a replayed callback")
	}
}

func TestAPILogsAdminEndpoints(t *testing.T) {
	f, _, logs := newAdminAPIFixture(t)
	logs.result = cp.LogResult{Events: []cp.LogEvent{{Message: "boot ok"}}}

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/log-groups", "regular", nil, nil), 403)

	groupsResp := f.request(t, "GET", "/api/v1/admin/log-groups", "root", nil, nil)
	apiStatus(t, groupsResp, 200)
	var names []string
	if err := json.Unmarshal(groupsResp.Body.Bytes(), &names); err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "serve" {
		t.Fatalf("log groups = %v", names)
	}

	logsResp := f.request(t, "GET", "/api/v1/admin/logs/serve", "root", nil, nil)
	apiStatus(t, logsResp, 200)
	var result cp.LogResult
	if err := json.Unmarshal(logsResp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Message != "boot ok" || logs.sawGroup != "/ecs/apphub/serve" {
		t.Fatalf("unexpected log result: %+v (sawGroup=%q)", result, logs.sawGroup)
	}

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/logs/serve?start=not-a-time", "root", nil, nil), 400)
	apiStatus(t, f.request(t, "GET", "/api/v1/admin/logs/unknown-group", "root", nil, nil), 422)
}

// TestAPIFreshMemberCannotCreateApplications guards the default-role policy
// change directly at the HTTP layer: an identity with no directory-driven
// role mapping and no legacy auth.admins grant resolves to RoleMember, and
// CreateApplication refuses a member regardless of how far its request would
// otherwise get -- this fixture configures no target descriptor at all, so a
// role check that ran after target validation would fail for the wrong
// reason instead of the 403 asserted here.
func TestAPIFreshMemberCannotCreateApplications(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)
	response := f.request(t, "POST", "/api/v1/applications", "regular", cp.ApplicationInput{Name: "x", TargetID: "test"}, f.mutationHeaders("regular", "fresh-member"))
	apiStatus(t, response, 403)
	var body cp.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error == nil || body.Error.Code != "forbidden" {
		t.Fatalf("expected a forbidden problem, got %+v", body.Error)
	}
}

func TestAPIFreshMemberCannotRequestDetectionWithWriteScope(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)
	token := f.token(t, "regular", "/api", cp.ApplicationsWrite)
	response := f.request(t, "POST", "/api/v1/targets/test/detect", "", cp.DetectionInput{URL: "https://github.com/example/app.git"}, http.Header{"Authorization": {"Bearer " + token}})
	apiStatus(t, response, 403)
	var body cp.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error == nil || body.Error.Code != "forbidden" {
		t.Fatalf("expected a forbidden problem, got %+v", body.Error)
	}
	queued, err := f.repo.Query(t.Context(), cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if err != nil || len(queued.Records) != 0 {
		t.Fatalf("member detection reached worker queue: %+v %v", queued, err)
	}
}

func TestAPIMembersAdminEndpoint(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/members", "regular", nil, nil), 403)

	response := f.request(t, "GET", "/api/v1/admin/members", "root", nil, nil)
	apiStatus(t, response, 200)
	var members []cp.MemberView
	if err := json.Unmarshal(response.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("expected both seeded users to be listed, got %+v", members)
	}
	byEmail := make(map[string]cp.MemberView, len(members))
	for _, m := range members {
		byEmail[m.Email] = m
	}
	if _, ok := byEmail["root@example.com"]; !ok {
		t.Fatalf("root did not appear in the roster: %+v", members)
	}
	if regular, ok := byEmail["regular@example.com"]; !ok || regular.Role != cp.RoleMember {
		t.Fatalf("regular did not resolve the unmapped default role: %+v", members)
	}
}

func TestAPIDirectoryEntitlementsAdminEndpoint(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/directory/entitlements", "regular", nil, nil), 403)

	empty := f.request(t, "GET", "/api/v1/admin/directory/entitlements", "root", nil, nil)
	apiStatus(t, empty, 200)
	var none []cp.DirectoryEntitlementView
	if err := json.Unmarshal(empty.Body.Bytes(), &none); err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected an empty list with nothing synced, got %+v", none)
	}

	rec, err := cp.Encode(cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: "ent-1"}, 0, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Engineering", Bindable: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: rec}}); err != nil {
		t.Fatal(err)
	}

	synced := f.request(t, "GET", "/api/v1/admin/directory/entitlements", "root", nil, nil)
	apiStatus(t, synced, 200)
	var views []cp.DirectoryEntitlementView
	if err := json.Unmarshal(synced.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ID != "ent-1" || !views[0].Bindable {
		t.Fatalf("unexpected entitlements: %+v", views)
	}
}

func TestAPIRoleMappingsAdminEndpoints(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/role-mappings", "regular", nil, nil), 403)
	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/role-mappings/ent-1", "regular", cp.RoleMappingInput{Role: cp.RoleAdmin}, f.mutationHeaders("regular", "")), 403)

	// Setting a mapping before the entitlement is synced is refused.
	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/role-mappings/ent-1", "root", cp.RoleMappingInput{Role: cp.RoleAdmin}, f.mutationHeaders("root", "")), 422)

	rec, err := cp.Encode(cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: "ent-1"}, 0, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Engineering", Bindable: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: rec}}); err != nil {
		t.Fatal(err)
	}

	setResponse := f.request(t, "PUT", "/api/v1/admin/role-mappings/ent-1", "root", cp.RoleMappingInput{Role: cp.RoleAdmin}, f.mutationHeaders("root", ""))
	apiStatus(t, setResponse, 200)
	var view cp.RoleMappingView
	if err := json.Unmarshal(setResponse.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.EntitlementID != "ent-1" || view.DisplayName != "Engineering" || view.Role != cp.RoleAdmin {
		t.Fatalf("unexpected mapping view: %+v", view)
	}

	list := f.request(t, "GET", "/api/v1/admin/role-mappings", "root", nil, nil)
	apiStatus(t, list, 200)
	var views []cp.RoleMappingView
	if err := json.Unmarshal(list.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].EntitlementID != "ent-1" {
		t.Fatalf("unexpected mapping list: %+v", views)
	}

	apiStatus(t, f.request(t, "DELETE", "/api/v1/admin/role-mappings/ent-1", "regular", nil, f.mutationHeaders("regular", "")), 403)
	apiStatus(t, f.request(t, "DELETE", "/api/v1/admin/role-mappings/ent-1", "root", nil, f.mutationHeaders("root", "")), 204)

	afterDelete := f.request(t, "GET", "/api/v1/admin/role-mappings", "root", nil, nil)
	apiStatus(t, afterDelete, 200)
	var none []cp.RoleMappingView
	if err := json.Unmarshal(afterDelete.Body.Bytes(), &none); err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no mappings after delete, got %+v", none)
	}
}

func TestAPIFeatureFlagsAdminEndpoints(t *testing.T) {
	f, _, _ := newAdminAPIFixture(t)

	apiStatus(t, f.request(t, "GET", "/api/v1/admin/feature-flags", "regular", nil, nil), 403)
	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/feature-flags/"+cp.FeatureVulnerabilities, "regular", cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}, f.mutationHeaders("regular", "")), 403)

	defaultList := f.request(t, "GET", "/api/v1/admin/feature-flags", "root", nil, nil)
	apiStatus(t, defaultList, 200)
	var defaults []cp.FeatureFlagView
	if err := json.Unmarshal(defaultList.Body.Bytes(), &defaults); err != nil {
		t.Fatal(err)
	}
	if len(defaults) != len(cp.KnownFeatureFlags) || defaults[0].Mode != cp.FeatureFlagOff {
		t.Fatalf("unexpected default flags: %+v", defaults)
	}

	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/feature-flags/not-a-real-flag", "root", cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}, f.mutationHeaders("root", "")), 404)

	setResponse := f.request(t, "PUT", "/api/v1/admin/feature-flags/"+cp.FeatureVulnerabilities, "root", cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}, f.mutationHeaders("root", ""))
	apiStatus(t, setResponse, 200)
	var view cp.FeatureFlagView
	if err := json.Unmarshal(setResponse.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Key != cp.FeatureVulnerabilities || view.Mode != cp.FeatureFlagOn {
		t.Fatalf("unexpected flag view: %+v", view)
	}

	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/feature-flags/"+cp.FeatureProvisionShortLink, "root", cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}, f.mutationHeaders("root", "")), 200)
	apiStatus(t, f.request(t, "PUT", "/api/v1/admin/feature-flags/"+cp.FeatureProvisionAppCatalog, "root", cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup}, f.mutationHeaders("root", "")), 422)
	afterList := f.request(t, "GET", "/api/v1/admin/feature-flags", "root", nil, nil)
	apiStatus(t, afterList, 200)
	var after []cp.FeatureFlagView
	if err := json.Unmarshal(afterList.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	modes := make(map[string]string, len(after))
	for _, flag := range after {
		modes[flag.Key] = flag.Mode
	}
	if modes[cp.FeatureVulnerabilities] != cp.FeatureFlagOn || modes[cp.FeatureProvisionShortLink] != cp.FeatureFlagOn || modes[cp.FeatureProvisionAppCatalog] != cp.FeatureFlagOff {
		t.Fatalf("workspace flags did not persist independently: %+v", after)
	}
}

func TestAPIDetectRepositoryQueuesAndScopesAccess(t *testing.T) {
	f := newAPIFixture(t)
	body := cp.DetectionInput{URL: "https://github.com/example/app.git", Ref: "main"}

	// Only an approved repository may be queued.
	apiStatus(t, f.request(t, "POST", "/api/v1/targets/test/detect", "alice", cp.DetectionInput{URL: "https://github.com/example/other.git"}, f.mutationHeaders("alice", "")), 422)

	response := f.request(t, "POST", "/api/v1/targets/test/detect", "alice", body, f.mutationHeaders("alice", ""))
	apiStatus(t, response, 202)
	var accepted cp.DetectionAccepted
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.DetectionID == "" || accepted.State != cp.DetectionQueued || accepted.StatusURL != "/api/v1/detections/"+accepted.DetectionID {
		t.Fatalf("unexpected accepted body: %+v", accepted)
	}
	if got := response.Header().Get("Location"); got != accepted.StatusURL {
		t.Fatalf("Location = %q, want %q", got, accepted.StatusURL)
	}

	// The requester can poll it, and sees it queued (the fixture runs no worker).
	poll := f.request(t, "GET", "/api/v1/detections/"+accepted.DetectionID, "alice", nil, nil)
	apiStatus(t, poll, 200)
	var view cp.DetectionView
	if err := json.Unmarshal(poll.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ID != accepted.DetectionID || view.State != cp.DetectionQueued || view.Terminal || view.Result != nil {
		t.Fatalf("unexpected detection view: %+v", view)
	}

	// A different requester cannot see it: ownership, not mere possession of the ID.
	apiStatus(t, f.request(t, "GET", "/api/v1/detections/"+accepted.DetectionID, "bob", nil, nil), 404)

	// An unapproved target is refused outright.
	apiStatus(t, f.request(t, "POST", "/api/v1/targets/does-not-exist/detect", "alice", body, f.mutationHeaders("alice", "")), 422)
}

func TestAPIListCategories(t *testing.T) {
	f := newAPIFixture(t)
	response := f.request(t, "GET", "/api/v1/categories", "alice", nil, nil)
	apiStatus(t, response, 200)
	var categories []cp.CategoryView
	if err := json.Unmarshal(response.Body.Bytes(), &categories); err != nil {
		t.Fatal(err)
	}
	if len(categories) != len(cp.KnownCategories) || categories[0].Key != cp.KnownCategories[0].Key {
		t.Fatalf("got %+v; want %+v", categories, cp.KnownCategories)
	}
	apiStatus(t, f.request(t, "GET", "/api/v1/categories", "", nil, nil), 401)
}

func TestAPISecretRoutesAreOwnerScopedAndStrict(t *testing.T) {
	f := newAPIFixture(t)
	response := f.request(t, "POST", "/api/v1/applications", "alice", f.input, f.mutationHeaders("alice", "create"))
	apiStatus(t, response, 201)
	var app cp.ApplicationView
	if err := json.Unmarshal(response.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/applications/" + app.ID + "/secrets"
	list := f.request(t, "GET", path, "alice", nil, nil)
	apiStatus(t, list, 200)
	var secrets cp.SecretList
	if err := json.Unmarshal(list.Body.Bytes(), &secrets); err != nil || secrets.Items == nil || secrets.Available {
		t.Fatalf("list = %s; want an empty, unavailable list", list.Body.String())
	}
	apiStatus(t, f.request(t, "GET", path, "bob", nil, nil), 404)

	changes := cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{{Name: "API_KEY", Action: cp.SecretSet, Value: "v"}}}
	apiStatus(t, f.request(t, "POST", path+"/deployments", "alice", changes, f.mutationHeaders("alice", "")), 400)
	apiStatus(t, f.request(t, "POST", path+"/deployments", "alice", map[string]any{"applicationRevision": 1, "changes": changes.Changes, "extra": true}, f.mutationHeaders("alice", "k")), 400)
	unavailable := f.request(t, "POST", path+"/deployments", "alice", changes, f.mutationHeaders("alice", "k"))
	apiStatus(t, unavailable, 503)
	if strings.Contains(unavailable.Body.String(), `"v"`) {
		t.Fatal("the response echoed a value")
	}
}

func TestAPINonOwnersCannotReadAnyApplicationDetail(t *testing.T) {
	f := newAPIFixture(t)
	response := f.request(t, "POST", "/api/v1/applications", "alice", f.input, f.mutationHeaders("alice", "create"))
	apiStatus(t, response, 201)
	var app cp.ApplicationView
	if err := json.Unmarshal(response.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	submitted := f.request(t, "POST", "/api/v1/applications/"+app.ID+"/deployments", "alice", cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, f.mutationHeaders("alice", "deploy"))
	apiStatus(t, submitted, 202)
	var accepted cp.DeploymentAccepted
	if err := json.Unmarshal(submitted.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/applications/" + app.ID
	for _, route := range []string{base, base + "/deployments", base + "/secrets", base + "/usage", "/api/v1/deployments/" + accepted.DeploymentID} {
		apiStatus(t, f.request(t, "GET", route, "alice", nil, nil), 200)
		// Not 403: a non-owner cannot even learn the application exists.
		apiStatus(t, f.request(t, "GET", route, "bob", nil, nil), 404)
	}
	listing := f.request(t, "GET", "/api/v1/applications", "bob", nil, nil)
	apiStatus(t, listing, 200)
	if strings.Contains(listing.Body.String(), app.ID) {
		t.Fatal("a non-owner's application list includes another user's application")
	}
	directory := f.request(t, "GET", "/api/v1/directory/applications", "bob", nil, nil)
	apiStatus(t, directory, 200)
	if !strings.Contains(directory.Body.String(), app.ID) || strings.Contains(directory.Body.String(), f.input.Source.URL) {
		t.Fatalf("directory = %s; want the application discoverable without its specification", directory.Body.String())
	}
	apiStatus(t, f.request(t, "GET", "/api/v1/directory/applications/"+app.ID, "bob", nil, nil), 200)
}

func TestAPIDeleteApplication(t *testing.T) {
	f := newAPIFixture(t)
	create := func(key string) cp.ApplicationView {
		response := f.request(t, "POST", "/api/v1/applications", "alice", f.input, f.mutationHeaders("alice", key))
		apiStatus(t, response, 201)
		var view cp.ApplicationView
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	confirm := cp.DeleteApplicationInput{ConfirmName: f.input.Name}

	draft := create("draft")
	path := "/api/v1/applications/" + draft.ID
	apiStatus(t, f.request(t, "POST", path+"/deletion", "alice", confirm, f.mutationHeaders("alice", "")), 400)
	apiStatus(t, f.request(t, "POST", path+"/deletion", "bob", confirm, f.mutationHeaders("bob", "foreign")), 404)
	apiStatus(t, f.request(t, "POST", path+"/deletion", "alice", cp.DeleteApplicationInput{ConfirmName: "wrong"}, f.mutationHeaders("alice", "mismatch")), 422)
	apiStatus(t, f.request(t, "POST", path+"/deletion", "alice", confirm, f.mutationHeaders("alice", "delete-draft")), 204)
	apiStatus(t, f.request(t, "GET", path, "alice", nil, nil), 404)

	app := create("deployed")
	path = "/api/v1/applications/" + app.ID
	apiStatus(t, f.request(t, "POST", path+"/deployments", "alice", cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, f.mutationHeaders("alice", "deploy")), 202)
	response := f.request(t, "POST", path+"/deletion", "alice", confirm, f.mutationHeaders("alice", "delete"))
	apiStatus(t, response, 202)
	var accepted cp.DeploymentAccepted
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.State != cp.Queued || response.Header().Get("Location") != accepted.StatusURL {
		t.Fatalf("deletion acceptance does not identify the queued teardown: %+v", accepted)
	}
	observed := f.request(t, "GET", accepted.StatusURL, "alice", nil, nil)
	apiStatus(t, observed, 200)
	var teardown cp.DeploymentView
	if err := json.Unmarshal(observed.Body.Bytes(), &teardown); err != nil {
		t.Fatal(err)
	}
	if teardown.Operation != "teardown" || teardown.Terminal {
		t.Fatalf("teardown view = %+v", teardown)
	}
}
