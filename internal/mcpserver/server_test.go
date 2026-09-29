// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/httpapi"
	"github.com/conductorone/apphub/internal/oauth"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
	sdk "github.com/conductorone/apphub/sdk/go"
)

// These tests use the official MCP client and production service, HTTP API,
// browser eligibility and bearer authority. Only persistence and upstream OIDC
// discovery use the shared hermetic fixtures; no JSON-RPC server is mocked.
type fixture struct {
	repo   *testutil.Repository
	server *httptest.Server
	issuer string
	input  cp.ApplicationInput
}

// appOwnerByDefaultEligibility wraps the real *auth.Manager's admission
// recheck but resolves every non-admin identity to RoleAppOwner rather than
// the directory-driven default (RoleMember) -- this fixture configures no
// ConductorOne directory at all, and its "owner"/"other" identities exercise
// ordinary application ownership, not a fresh member with nothing assigned.
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

func newFixture(t *testing.T) *fixture {
	t.Helper()
	upstream := testutil.NewOIDC(t)
	repo := testutil.NewRepository()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "http://" + server.Listener.Addr().String()
	cfg := serverconfig.Config{PublicOrigin: origin, Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(strings.Repeat("k", 32)), Providers: []serverconfig.ProviderConfig{{ID: "oidc", Label: "Test identity", Kind: "oidc", Issuer: upstream.Issuer(), ClientID: upstream.ClientID, ClientSecret: credentials.NewSecret(upstream.ClientSecret), AllowedDomains: []string{"example.com"}}}}}
	manager, err := auth.New(t.Context(), cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.New(cfg, repo, manager)
	if err != nil {
		t.Fatal(err)
	}
	target := cp.TargetPolicy{ID: "org", Label: "Organization", ConfigHash: "policy-hash", DeployConfig: deploy.Config{ResourcePrefix: "test", AllowedSourceHosts: []string{"github.com"}}, ResourceSizes: []cp.ResourceInput{{CPU: 500, Memory: 1024}}, MaxReplicas: 4, ExecutionModes: []string{"service", "scheduled"}, Repositories: []string{"https://github.com/example/app"}}
	service, err := cp.NewService(repo, appOwnerByDefaultEligibility{manager}, map[string]cp.TargetPolicy{target.ID: target})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(service, authority, origin)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	httpapi.Register(mux, service, manager, authority, origin)
	server.Config.Handler = mux
	server.Start()
	f := &fixture{repo: repo, server: server, issuer: upstream.Issuer(), input: cp.ApplicationInput{Name: "Example", TargetID: "org", Source: cp.SourceInput{URL: "https://github.com/example/app", Ref: "main", Dockerfile: "Dockerfile"}, Execution: deploy.ExecutionService, Port: 8080, Resources: cp.ResourceInput{CPU: 500, Memory: 1024}, Replicas: 2, Exposure: cp.ExposureInput{Mode: "private"}}}
	f.put(t, cp.RecordID{Kind: cp.TargetKind, ID: target.ID}, cp.TargetDescriptor{ID: target.ID, ProviderName: "test", ConfigHash: target.ConfigHash, HeartbeatAt: time.Now(), Capabilities: compute.NewCapabilitySet(compute.CapImageBuild, compute.CapImageRegistry, compute.CapContainerService, compute.CapScheduledJob)})
	for _, id := range []string{"owner", "other"} {
		f.put(t, cp.RecordID{Kind: cp.UserKind, ID: id}, cp.User{ID: id, Email: id + "@example.com"})
		f.put(t, cp.RecordID{Kind: cp.IdentityKind, ParentID: f.issuer, ID: id}, cp.ExternalIdentity{UserID: id, ProviderID: "oidc", Issuer: f.issuer, Subject: id, Email: id + "@example.com", EmailVerified: true})
	}
	return f
}
func (f *fixture) put(t *testing.T, id cp.RecordID, value any) {
	t.Helper()
	previous, err := f.repo.Read(t.Context(), id)
	if err != nil && !errors.Is(err, cp.ErrNotFound) {
		t.Fatal(err)
	}
	record, err := cp.Encode(id, previous.Version+1, value)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(t.Context(), []cp.Mutation{{Record: record, ExpectedVersion: previous.Version}}); err != nil {
		t.Fatal(err)
	}
}
func newSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func secretHash(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func (f *fixture) token(t *testing.T, user, resource string, scopes ...string) (string, cp.OAuthFamily) {
	t.Helper()
	token := newSecret()
	family := cp.OAuthFamily{ID: newSecret(), UserID: user, ProviderID: "oidc", Issuer: f.issuer, Subject: user, ClientID: "apphub-cli", Resource: f.server.URL + resource, Scopes: scopes, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	f.put(t, cp.RecordID{Kind: cp.FamilyKind, ID: family.ID}, family)
	f.put(t, cp.RecordID{Kind: cp.AccessKind, ID: secretHash(token)}, cp.OAuthToken{FamilyID: family.ID, ExpiresAt: time.Now().Add(15 * time.Minute)})
	return token, family
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	request := r.Clone(r.Context())
	request.Header = r.Header.Clone()
	request.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(request)
}
func remoteSession(t *testing.T, f *fixture, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "regression-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: f.server.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}
func callTool(t *testing.T, s *mcp.ClientSession, name string, input any, output any) {
	t.Helper()
	result, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("%s: %+v", name, result)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, output); err != nil {
		t.Fatal(err)
	}
}
func requireToolError(t *testing.T, s *mcp.ClientSession, name string, input any, code string) {
	t.Helper()
	result, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("%s unexpectedly succeeded", name)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var problem cp.ErrorResponse
	if err := json.Unmarshal(data, &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Error == nil || problem.Error.Code != code {
		t.Fatalf("unexpected error: %s", data)
	}
}

func exerciseDurableTools(t *testing.T, f *fixture, s *mcp.ClientSession) cp.ApplicationView {
	t.Helper()
	var targets []cp.TargetView
	callTool(t, s, "targets_list", emptyInput{}, &targets)
	var categories []cp.CategoryView
	callTool(t, s, "categories_list", emptyInput{}, &categories)
	if len(categories) != len(cp.KnownCategories) {
		t.Fatalf("categories_list returned %d categories; want %d", len(categories), len(cp.KnownCategories))
	}
	resource, err := s.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: deploymentOptionsURI})
	if err != nil {
		t.Fatal(err)
	}
	if len(resource.Contents) != 1 {
		t.Fatalf("unexpected resource response: %+v", resource)
	}
	var options []cp.TargetView
	if err := json.Unmarshal([]byte(resource.Contents[0].Text), &options); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(targets, options) || len(options) != 1 || !options[0].Ready {
		t.Fatalf("resource differs from ready target options: %+v", options)
	}
	var created, replayed cp.ApplicationView
	input := createInput{Application: f.input, IdempotencyKey: "draft-key"}
	callTool(t, s, "applications_create", input, &created)
	callTool(t, s, "applications_create", input, &replayed)
	if created.ID == "" || replayed.ID != created.ID || created.Status != "draft" {
		t.Fatalf("draft creation was not durable/idempotent: %+v / %+v", created, replayed)
	}
	var secrets cp.SecretList
	callTool(t, s, "secrets_list", applicationIDInput{ApplicationID: created.ID}, &secrets)
	if secrets.Available || secrets.Items == nil || len(secrets.Items) != 0 {
		t.Fatalf("secrets_list without a sealer = %+v; want an empty, unavailable list", secrets)
	}
	changed := f.input
	changed.Name = "Updated"
	callTool(t, s, "applications_update", updateInput{ApplicationID: created.ID, Application: changed, Revision: created.Revision}, &created)
	if created.Revision != 2 || created.Specification.Name != "Updated" {
		t.Fatalf("revisioned edit failed: %+v", created)
	}
	requireToolError(t, s, "applications_update", updateInput{ApplicationID: created.ID, Application: changed, Revision: 1}, "revision_conflict")
	var got cp.ApplicationView
	callTool(t, s, "applications_get", applicationIDInput{created.ID}, &got)
	if got.ID != created.ID || got.Revision != 2 {
		t.Fatalf("read lost updated revision: %+v", got)
	}
	var apps cp.Page[cp.ApplicationView]
	callTool(t, s, "applications_list", listInput{Limit: 1}, &apps)
	if len(apps.Items) != 1 || apps.Items[0].ID != created.ID {
		t.Fatalf("application inventory lost draft: %+v", apps)
	}
	submission := submitInput{ApplicationID: created.ID, Deployment: cp.SubmitDeploymentInput{ApplicationRevision: created.Revision}, IdempotencyKey: "deploy-key"}
	var accepted, again cp.DeploymentAccepted
	callTool(t, s, "deployments_create", submission, &accepted)
	callTool(t, s, "deployments_create", submission, &again)
	if accepted.DeploymentID == "" || accepted.DeploymentID != again.DeploymentID || accepted.State != cp.Queued || accepted.PollAfterMs != 2000 || accepted.StatusURL != "/api/v1/deployments/"+accepted.DeploymentID {
		t.Fatalf("submission was not durable queued acceptance: %+v / %+v", accepted, again)
	}
	var operation cp.DeploymentView
	callTool(t, s, "deployments_get", deploymentIDInput{accepted.DeploymentID}, &operation)
	if operation.Terminal || operation.State != cp.Queued || operation.ApplicationID != created.ID {
		t.Fatalf("acceptance falsely claimed completion: %+v", operation)
	}
	var history cp.Page[cp.DeploymentView]
	callTool(t, s, "deployments_list", historyInput{ApplicationID: created.ID}, &history)
	if len(history.Items) != 1 || history.Items[0].ID != accepted.DeploymentID {
		t.Fatalf("attempt history differs from durable operation: %+v", history)
	}
	return created
}

func TestRemoteOfficialClientDurableToolsOwnershipAndRevocation(t *testing.T) {
	f := newFixture(t)
	token, family := f.token(t, "owner", "/mcp", cp.ApplicationsRead, cp.ApplicationsWrite, cp.DeploymentsRead, cp.DeploymentsWrite)
	session := remoteSession(t, f, token)
	app := exerciseDurableTools(t, f, session)
	other, _ := f.token(t, "other", "/mcp", cp.ApplicationsRead)
	requireToolError(t, remoteSession(t, f, other), "applications_get", applicationIDInput{app.ID}, "not_found")
	readOnly, _ := f.token(t, "owner", "/mcp", cp.ApplicationsRead, cp.DeploymentsRead)
	restricted := remoteSession(t, f, readOnly)
	// An inaccessible ID still yields scope denial here: the adapter must not
	// dispatch this mutation to the service's ownership/existence lookup first.
	requireToolError(t, restricted, "deployments_create", submitInput{ApplicationID: "does-not-exist", Deployment: cp.SubmitDeploymentInput{ApplicationRevision: 1}, IdempotencyKey: "blocked"}, "insufficient_scope")
	deploymentOnly, _ := f.token(t, "owner", "/mcp", cp.DeploymentsRead)
	if _, err := remoteSession(t, f, deploymentOnly).ReadResource(t.Context(), &mcp.ReadResourceParams{URI: deploymentOptionsURI}); err == nil {
		t.Fatal("deployment scope read application target resource")
	}
	// Stateless transport must not preserve eligibility after initialization.
	family.Revoked = true
	f.put(t, cp.RecordID{Kind: cp.FamilyKind, ID: family.ID}, family)
	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "targets_list", Arguments: emptyInput{}}); err == nil {
		t.Fatal("revoked family retained an initialized MCP session")
	}
}

func TestRemoteHTTPBoundary(t *testing.T) {
	f := newFixture(t)
	mcpToken, _ := f.token(t, "owner", "/mcp", cp.ApplicationsRead)
	apiToken, _ := f.token(t, "owner", "/api", cp.ApplicationsRead)
	cookie := newSecret()
	f.put(t, cp.RecordID{Kind: cp.SessionKind, ID: secretHash(cookie)}, cp.Session{ID: "browser", UserID: "owner", ProviderID: "oidc", Issuer: f.issuer, Subject: "owner", CSRF: newSecret(), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	for _, test := range []struct {
		name, token, origin, path, body string
		status                          int
	}{
		{name: "browser cookie is not MCP authentication", path: "/mcp", status: 401},
		{name: "invalid bearer cannot fall back", path: "/mcp", token: "invalid", status: 401},
		{name: "API audience is not MCP", path: "/mcp", token: apiToken, status: 401},
		{name: "foreign origin", path: "/mcp", token: mcpToken, origin: "https://foreign.example", status: 403},
		{name: "null origin", path: "/mcp", token: mcpToken, origin: "null", status: 403},
		{name: "origin path is not origin", path: "/mcp", token: mcpToken, origin: f.server.URL + "/", status: 403},
		{name: "bounded request", path: "/mcp", token: mcpToken, body: strings.Repeat(" ", maxRequestBodyBytes+1), status: 413},
		{name: "exact route", path: "/mcp/", token: mcpToken, status: 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+test.path, strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(&http.Cookie{Name: "apphub_session", Value: cookie})
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != test.status {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status=%d want %d: %s", response.StatusCode, test.status, body)
			}
			if test.status == 401 && !strings.Contains(response.Header.Get("WWW-Authenticate"), f.server.URL+"/.well-known/oauth-protected-resource/mcp") {
				t.Fatal("missing resource-specific discovery challenge")
			}
		})
	}
}

func TestStdioOfficialClientUsesAuthenticatedAPI(t *testing.T) {
	f := newFixture(t)
	token, _ := f.token(t, "owner", "/api", cp.ApplicationsRead, cp.ApplicationsWrite, cp.DeploymentsRead, cp.DeploymentsWrite)
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("APPDATA", base)
	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "apphub"), 0700); err != nil {
		t.Fatal(err)
	}
	key := f.server.URL + "\n" + f.server.URL + "/api\napphub-cli"
	data, err := json.Marshal(map[string]any{"current": key, "entries": map[string]any{key: map[string]any{"server": f.server.URL, "resource": f.server.URL + "/api", "clientId": "apphub-cli", "accessToken": token, "refreshToken": newSecret(), "expiresAt": time.Now().Add(10 * time.Minute)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "apphub", "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestStdioHelperProcess$")
	command.Env = append(os.Environ(), "APPHUB_MCP_TEST_HELPER=1")
	command.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-regression", Version: "1.0.0"}, nil)
	session, err := client.Connect(t.Context(), &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	}()
	exerciseDurableTools(t, f, session)
}

func TestStdioHelperProcess(_ *testing.T) {
	if os.Getenv("APPHUB_MCP_TEST_HELPER") != "1" {
		return
	}
	client, err := sdk.FromContext()
	if err == nil {
		err = RunStdio(context.Background(), client)
	}
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "stdio helper failed\n")
		os.Exit(1)
	}
	// The testing framework must never write its PASS banner into MCP stdout.
	os.Exit(0)
}
