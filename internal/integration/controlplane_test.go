// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/httpapi"
	"github.com/conductorone/apphub/internal/mcpserver"
	"github.com/conductorone/apphub/internal/oauth"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/internal/worker"
	"github.com/conductorone/apphub/modules/deploy"
	"github.com/conductorone/apphub/store"
)

type portal struct {
	origin string
	server *httptest.Server
	repo   cp.Repository
	issuer *testutil.OIDCFixture
}

type preparedSource struct {
	dir    string
	source deploy.Source
}

func (s *preparedSource) Prepare(_ context.Context, source deploy.Source) (string, error) {
	s.source = source
	return strings.Repeat("a", 40), nil
}
func (s *preparedSource) Fetch(_ context.Context, source deploy.Source) (string, error) {
	if source.URL != s.source.URL || source.Ref != strings.Repeat("a", 40) {
		return "", fmt.Errorf("test source binding mismatch")
	}
	return s.dir, nil
}
func (s *preparedSource) Close() error { return os.RemoveAll(s.dir) }

// This fixture runs the real login/OAuth/service/HTTP/MCP/module/dispatcher paths.
// Only cloud compute and prepared repository contents are test doubles. It is
// compiled exclusively into tests and cannot enable a production authentication
// bypass or replace the real worker's isolation preflight.
func newPortal(t *testing.T, browserMode bool, repo cp.Repository) *portal {
	t.Helper()
	issuer := testutil.NewOIDC(t)
	second := testutil.NewOIDC(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if browserMode {
		_ = listener.Close()
		listener, err = net.Listen("tcp", "127.0.0.1:8081")
		if err != nil {
			t.Fatal(err)
		}
	}
	origin := "http://" + listener.Addr().String()
	if browserMode {
		origin = "http://127.0.0.1:5173"
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.Config{PublicOrigin: origin, Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true, TransactionKey: credentials.NewSecret(string(key)), Providers: []serverconfig.ProviderConfig{
		{ID: "local", Label: "Local signed OIDC", Kind: "oidc", Issuer: issuer.Issuer(), ClientID: issuer.ClientID, ClientSecret: credentials.NewSecret(issuer.ClientSecret), AllowedDomains: []string{"example.com"}},
		{ID: "second", Label: "Second signed OIDC", Kind: "oidc", Issuer: second.Issuer(), ClientID: second.ClientID, ClientSecret: credentials.NewSecret(second.ClientSecret), AllowedDomains: []string{"example.com"}},
	},
		// Role now defaults to member absent a directory-driven grant (see
		// internal/controlplane's HighestRole), so exerciseDeployment's
		// application-owning identity (the fixture OIDC issuer's default
		// subject "subject-a") needs the same legacy auth.admins bootstrap a
		// real fresh deployment would use to grant its first operator
		// anything above member. The second browserLogin in that test signs
		// in as "different-subject" instead and stays an ordinary member.
		Admins: []serverconfig.AdminConfig{{ProviderID: "local", Subject: "subject-a"}},
	}, Worker: serverconfig.WorkerConfig{WorkDir: t.TempDir(), MaxConcurrentDeployments: 2, DeploymentTimeout: 30 * time.Second, HeartbeatInterval: 100 * time.Millisecond, StaleAfter: 3 * time.Second}}
	config := deploy.Config{ResourcePrefix: "integration", AllowedSourceHosts: []string{"code.example.test"}, Placement: compute.Placement{Name: "default"}, WorkloadIdentityMode: "native", WaitTimeout: 5 * time.Second, RouteDomain: "example.test", RouteCertificate: "cert-default"}
	targets := map[string]cp.TargetPolicy{"test": {ID: "test", Label: "Hermetic test compute (not AWS)", ConfigHash: "hermetic-target", DeployConfig: config, ResourceSizes: []cp.ResourceInput{{CPU: 256, Memory: 512}, {CPU: 512, Memory: 1024}}, MaxReplicas: 3, ExecutionModes: []string{"service", "scheduled"}, Repositories: []string{"https://code.example.test/team/application"}, PublicExposure: true}}
	identity, err := auth.New(context.Background(), cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.New(cfg, repo, identity)
	if err != nil {
		t.Fatal(err)
	}
	options := []cp.ServiceOption{}
	if reader, ok := repo.(cp.AuditReader); ok {
		options = append(options, cp.WithAuditReader(reader))
	}
	if writer, ok := repo.(cp.AuditWriter); ok {
		options = append(options, cp.WithAuditWriter(writer))
	}
	service, err := cp.NewService(repo, identity, targets, options...)
	if err != nil {
		t.Fatal(err)
	}
	provider := fake.New(fake.NewStore(), fake.Config{})
	dispatcher, err := worker.NewWithSourceFactory(cfg, repo, identity, map[string]compute.Provider{"test": provider}, targets, func() (worker.PreparedSource, error) {
		dir, err := os.MkdirTemp(cfg.Worker.WorkDir, "source-")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
			return nil, err
		}
		return &preparedSource{dir: dir}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := httpapi.NewMux("", repo.Ready)
	identity.Register(mux)
	authority.Register(mux)
	httpapi.Register(mux, service, identity, authority, origin)
	remote, err := mcpserver.New(service, authority, origin)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/mcp", remote)
	if browserMode {
		if memory, ok := repo.(*testutil.Repository); ok {
			mux.HandleFunc("POST /__fixture/outage", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("enabled") == "true" {
					memory.SetError(cp.ErrUnavailable)
				} else {
					memory.SetError(nil)
				}
				w.WriteHeader(http.StatusNoContent)
			})
		}
		mux.HandleFunc("POST /__fixture/fail-next-build", func(w http.ResponseWriter, _ *http.Request) {
			provider.Harness().FailNext(fake.OpBuild, compute.KindImageRepository, fmt.Errorf("test-only build denial: %w", compute.ErrNotPermitted))
			w.WriteHeader(http.StatusNoContent)
		})
	}
	server := httptest.NewUnstartedServer(httpapi.NewServer("", mux).Handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("dispatcher: %v", err)
			}
		case <-time.After(35 * time.Second):
			t.Error("dispatcher did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.TargetKind, ID: "test"}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not publish readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &portal{origin: origin, server: server, repo: repo, issuer: issuer}
}

func browserLogin(t *testing.T, p *portal) (*http.Client, cp.UserView) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	response, err := client.Get(p.origin + "/auth/local/login?return_to=/applications")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	var me cp.UserView
	requestJSON(t, client, http.MethodGet, p.origin+"/api/v1/users/me", nil, nil, 200, &me)
	if me.ID == "" || me.CSRFToken == "" {
		t.Fatal("signed callback did not establish a browser session")
	}
	return client, me
}

func requestJSON(t *testing.T, client *http.Client, method, address string, input any, headers http.Header, status int, output any) {
	t.Helper()
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, address, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s %s: got%d want%d: %s", method, address, response.StatusCode, status, data)
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			t.Fatalf("invalid response: %v %s", err, data)
		}
	}
}

func applicationInput() cp.ApplicationInput {
	return cp.ApplicationInput{Name: "Integration service", TargetID: "test", Source: cp.SourceInput{URL: "https://code.example.test/team/application", Dockerfile: "Dockerfile"}, Execution: deploy.ExecutionService, Port: 8080, Resources: cp.ResourceInput{CPU: 256, Memory: 512}, Replicas: 2, Exposure: cp.ExposureInput{Mode: "private"}}
}

func exerciseDeployment(t *testing.T, repo cp.Repository) {
	t.Helper()
	p := newPortal(t, false, repo)
	client, me := browserLogin(t, p)
	headers := http.Header{"Origin": {p.origin}, "X-Csrf-Token": {me.CSRFToken}, "Idempotency-Key": {cp.NewID()}}
	var app, replayed cp.ApplicationView
	requestJSON(t, client, "POST", p.origin+"/api/v1/applications", applicationInput(), headers, 201, &app)
	requestJSON(t, client, "POST", p.origin+"/api/v1/applications", applicationInput(), headers, 201, &replayed)
	if app.ID != replayed.ID || app.Status != "draft" {
		t.Fatal("idempotent draft contract failed")
	}
	headers.Set("Idempotency-Key", cp.NewID())
	var accepted cp.DeploymentAccepted
	requestJSON(t, client, "POST", p.origin+"/api/v1/applications/"+app.ID+"/deployments", cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, headers, 202, &accepted)
	var result cp.DeploymentView
	deadline := time.Now().Add(15 * time.Second)
	for {
		requestJSON(t, client, "GET", p.origin+accepted.StatusURL, nil, nil, 200, &result)
		if result.Terminal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable operation did not finish: %+v", result)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if result.State != cp.Succeeded || result.ResolvedCommit != strings.Repeat("a", 40) {
		t.Fatalf("worker deployment failed: %+v", result)
	}
	requestJSON(t, client, "GET", p.origin+"/api/v1/applications/"+app.ID, nil, nil, 200, &app)
	if app.LastSuccessfulDeploymentID != accepted.DeploymentID || app.ActiveDeploymentID != "" {
		t.Fatalf("durable application state differs from deployment: %+v", app)
	}
	if _, ok := repo.(cp.AuditReader); ok {
		var audit cp.AuditPage
		requestJSON(t, client, "GET", p.origin+"/api/v1/admin/audit-logs?limit=100", nil, nil, 200, &audit)
		created := 0
		for _, event := range audit.Items {
			if event.Action == "application.create" && event.Target == "application:"+app.ID && event.Actor == me.ID {
				created++
			}
		}
		if created != 1 {
			t.Fatalf("idempotent create must have one attributable audit entry, got %d in %+v", created, audit)
		}
	}
	p.issuer.SetIdentity(testutil.OIDCIdentity{Subject: "different-subject", Email: me.Email, Name: "Same email, different identity", EmailVerified: true})
	other, otherMe := browserLogin(t, p)
	if otherMe.ID == me.ID {
		t.Fatal("email merged distinct subjects")
	}
	requestJSON(t, other, "GET", p.origin+"/api/v1/applications/"+app.ID, nil, nil, 404, nil)
	requestJSON(t, other, "GET", p.origin+accepted.StatusURL, nil, nil, 404, nil)
	if _, ok := repo.(cp.AuditReader); ok {
		requestJSON(t, other, "GET", p.origin+"/api/v1/admin/audit-logs", nil, nil, 403, nil)
	}
	// Disconnecting the submitting request did not own the worker; observation is
	// a separate request and follows only the durable accepted operation ID.
}

func TestSignedLoginOwnedDurableDeployment(t *testing.T) {
	exerciseDeployment(t, testutil.NewRepository())
}

func TestDynamoDBDurableDeployment(t *testing.T) {
	endpoint := os.Getenv("APPHUB_INTEGRATION_DYNAMO_ENDPOINT")
	if endpoint == "" {
		t.Skip("explicit isolated DynamoDB integration endpoint not configured")
	}
	table := os.Getenv("APPHUB_INTEGRATION_DYNAMO_TABLE")
	if table == "" {
		t.Fatal("isolated integration table required")
	}
	client, err := store.New(context.Background(), store.Config{Region: "us-west-2", TableName: table, AuditTableName: table + "-audit", Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.NewControlPlaneRecords(client)
	if err != nil {
		t.Fatal(err)
	}
	exerciseDeployment(t, repo)
}

func TestBrowserHarness(t *testing.T) {
	if os.Getenv("APPHUB_BROWSER_FIXTURE") != "1" {
		t.Skip("manual browser fixture is explicitly opt-in and test-only")
	}
	var repo cp.Repository = testutil.NewRepository()
	if endpoint, table := os.Getenv("APPHUB_INTEGRATION_DYNAMO_ENDPOINT"), os.Getenv("APPHUB_INTEGRATION_DYNAMO_TABLE"); endpoint != "" && table != "" {
		client, err := store.New(context.Background(), store.Config{Region: "us-west-2", TableName: table, AuditTableName: table + "-audit", Endpoint: endpoint})
		if err != nil {
			t.Fatal(err)
		}
		repo, err = store.NewControlPlaneRecords(client)
		if err != nil {
			t.Fatal(err)
		}
	}
	p := newPortal(t, true, repo)
	fmt.Printf("AppHub test-only browser fixture ready at %s (backend %s); no AWS deployment proof\n", p.origin, p.server.URL)
	<-time.After(30 * time.Minute)
}

// authorizeToken drives the real consent and code-exchange endpoints using an
// established signed browser identity; tokens are scoped to exactly one resource.
func authorizeToken(t *testing.T, p *portal, client *http.Client, me cp.UserView, resource, scope string) string {
	t.Helper()
	verifier := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("v", 32)))
	digest := sha256.Sum256([]byte(verifier))
	redirect := "http://127.0.0.1:45678/callback"
	q := url.Values{"client_id": {"apphub-cli"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {scope}, "resource": {resource}, "state": {"correlated-state"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
	response, err := client.Get(p.origin + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	transaction := response.Request.URL.Query().Get("transactionId")
	_ = response.Body.Close()
	if transaction == "" {
		t.Fatal("authorization did not create consent transaction")
	}
	headers := http.Header{"Origin": {p.origin}, "X-Csrf-Token": {me.CSRFToken}}
	var decision struct {
		RedirectURL string `json:"redirectUrl"`
	}
	requestJSON(t, client, "POST", p.origin+"/oauth/authorize", map[string]string{"transactionId": transaction, "action": "approve"}, headers, 200, &decision)
	callback, err := url.Parse(decision.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != "correlated-state" || callback.Query().Get("iss") != p.origin {
		t.Fatal("authorization response lost issuer/state binding")
	}
	response, err = client.PostForm(p.origin+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"apphub-cli"}, "redirect_uri": {redirect}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}, "resource": {resource}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || token.AccessToken == "" {
		t.Fatal("code exchange did not return resource token")
	}
	return token.AccessToken
}
