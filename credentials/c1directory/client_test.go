// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1directory"
)

// Everything below runs against a http.RoundTripper -- the seam c1directory.Deps
// offers -- so nothing here can reach a real tenant even if misconfigured.

const (
	testTenant   = "https://tenant.example.invalid"
	testClientID = "directory-client"
)

type recordedRequest struct {
	Method string
	Path   string
	Body   string
}

type fakeTransport struct {
	token func(*http.Request) (*http.Response, error)
	api   func(*http.Request) (*http.Response, error)
	seen  []recordedRequest
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := recordedRequest{Method: req.Method, Path: req.URL.Path}
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
	return jsonResponse(http.StatusOK, `{"list":[]}`, req), nil
}

func (f *fakeTransport) tokenRequests() int {
	n := 0
	for _, r := range f.seen {
		if strings.HasSuffix(r.Path, "/auth/v1/token") {
			n++
		}
	}
	return n
}

// apiRequests returns every recorded request that was not the token endpoint.
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
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d upstream", status), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

type stubSecrets struct {
	secret credentials.Secret
	err    error
}

func (s *stubSecrets) Resolve(context.Context, credentials.SecretRef) (credentials.Secret, error) {
	return s.secret, s.err
}

func testConfig() c1directory.Config {
	return c1directory.Config{TenantURL: testTenant, ClientID: testClientID, ClientSecret: credentials.SecretRef{Name: "/run/secrets/c1directory-client-secret"}}
}

func newTestClient(t *testing.T, ft *fakeTransport) c1directory.Client {
	t.Helper()
	client, err := c1directory.NewClient(testConfig(), c1directory.Deps{
		Secrets:   &stubSecrets{secret: credentials.NewSecret("directory-client-secret")},
		Transport: ft,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestListEntitlementsRejectsNonJSON(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `<!doctype html><html></html>`, req), nil
	}}
	_, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err == nil {
		t.Fatal("ListEntitlements accepted an HTML catalog response")
	}
	if !strings.Contains(err.Error(), "html") || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("error = %v, want html body kind and byte count", err)
	}
	if strings.Contains(err.Error(), "doctype") || strings.Contains(err.Error(), "<html") {
		t.Fatalf("error leaked the upstream body: %v", err)
	}
}

func TestListEntitlementsRejectsTruncatedJSON(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"list":[{"appEntitlement":{"id":"ent-1"`, req), nil
	}}
	_, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err == nil {
		t.Fatal("ListEntitlements accepted a truncated catalog response")
	}
	if !strings.Contains(err.Error(), "json-object") || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("error = %v, want json-object body kind and byte count", err)
	}
}

func TestListEntitlementsHappyPath(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"list":[{"appEntitlement":{"id":"ent-1","displayName":"Engineering","description":"eng team","appId":"app-1"}}]}`, req), nil
	}}
	got, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	want := []c1directory.Entitlement{{ID: "ent-1", DisplayName: "Engineering", Description: "eng team", AppID: "app-1"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("ListEntitlements = %+v, want %+v", got, want)
	}
	requests := ft.apiRequests()
	if len(requests) != 1 {
		t.Fatalf("ListEntitlements sent %d API requests, want 1: %+v", len(requests), requests)
	}
	if strings.Contains(requests[0].Body, "isAutomated") {
		t.Errorf("ListEntitlements sent isAutomated, want the unfiltered catalog: %s", requests[0].Body)
	}
	if !strings.Contains(requests[0].Body, `"pageSize":100`) {
		t.Errorf("ListEntitlements pageSize = %s, want 100 (Union Station searchGroups)", requests[0].Body)
	}
}

func TestListGroupsSetsIsAutomated(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"list":[]}`, req), nil
	}}
	if _, err := newTestClient(t, ft).ListGroups(context.Background()); err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	requests := ft.apiRequests()
	if len(requests) != 1 || !strings.Contains(requests[0].Body, `"isAutomated":true`) {
		t.Errorf("ListGroups did not request isAutomated:true: %+v", requests)
	}
}

func TestListEntitlementsPaginatesAndDeduplicates(t *testing.T) {
	var call int32
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		n := atomic.AddInt32(&call, 1)
		switch n {
		case 1:
			return jsonResponse(http.StatusOK, `{"list":[{"appEntitlement":{"id":"ent-1","displayName":"One"}}],"nextPageToken":"page-2"}`, req), nil
		case 2:
			// A repeated ID across pages is deduplicated rather than doubled.
			return jsonResponse(http.StatusOK, `{"list":[{"appEntitlement":{"id":"ent-1","displayName":"One"}},{"appEntitlement":{"id":"ent-2","displayName":"Two"}}]}`, req), nil
		default:
			t.Fatalf("unexpected page request %d", n)
			return nil, nil
		}
	}}
	got, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListEntitlements = %+v, want 2 deduplicated entitlements", got)
	}
}

func TestSearchStopsAtTheHardPageCap(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		// Always claims another page, so the client's own bound is what stops this,
		// not the fixture running out of pages.
		return jsonResponse(http.StatusOK, `{"list":[{"appEntitlement":{"id":"ent-1","displayName":"One"}}],"nextPageToken":"more"}`, req), nil
	}}
	got, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ent-1" {
		t.Fatalf("ListEntitlements = %+v, want the truncated page of unique entitlements", got)
	}
}

func TestSearchStopsWhenPageTokenDoesNotAdvance(t *testing.T) {
	var calls int32
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		n := atomic.AddInt32(&calls, 1)
		return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"appEntitlement":{"id":"ent-%d"}}],"nextPageToken":"stuck"}`, n), req), nil
	}}
	got, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if calls != 2 {
		t.Fatalf("search issued %d requests, want 2 (first page, then a repeated cursor)", calls)
	}
	if len(got) != 2 {
		t.Fatalf("ListEntitlements = %+v, want the two pages collected before the cursor stuck", got)
	}
}

func TestTokenIsCachedAcrossCalls(t *testing.T) {
	ft := &fakeTransport{}
	client := newTestClient(t, ft)
	if _, err := client.ListEntitlements(context.Background()); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if _, err := client.ListGroups(context.Background()); err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if n := ft.tokenRequests(); n != 1 {
		t.Fatalf("token requests = %d, want 1 (cached across calls)", n)
	}
}

func TestUnauthorizedIsReportedAsUnauthenticated(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, `{"error":"invalid_token"}`, req), nil
	}}
	_, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if !errors.Is(err, c1directory.ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if strings.Contains(err.Error(), "invalid_token") {
		t.Fatalf("error leaked the upstream response body: %v", err)
	}
}

func TestForbiddenErrorNamesStatusCodeAndPathNotBody(t *testing.T) {
	body := `{"error":"insufficient_scope","token":"leak-me"}`
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, body, req), nil
	}}
	_, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if !errors.Is(err, c1directory.ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want the status code named", err)
	}
	if !strings.Contains(err.Error(), "/api/v1/search/entitlements") {
		t.Fatalf("error = %v, want the request path named", err)
	}
	if !strings.Contains(err.Error(), http.MethodPost) {
		t.Fatalf("error = %v, want the request method named", err)
	}
	if strings.Contains(err.Error(), "leak-me") ||
		strings.Contains(err.Error(), "insufficient_scope") {
		t.Fatalf("error leaked the upstream response body: %v", err)
	}
}

func TestServerErrorIsReportedAsTransient(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusServiceUnavailable, `internal details`, req), nil
	}}
	_, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if !errors.Is(err, credentials.ErrTransient) {
		t.Fatalf("error = %v, want credentials.ErrTransient", err)
	}
	if strings.Contains(err.Error(), "internal details") {
		t.Fatalf("error leaked the upstream response body: %v", err)
	}
}

func TestListUserGroupIDsHappyPath(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/search/users"):
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana@acme.dev"}}]}`, req), nil
		case strings.HasSuffix(req.URL.Path, "/search/grants"):
			return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-1"}}},{"entitlement":{"appEntitlement":{"id":"ent-2"}}}]}`, req), nil
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
			return nil, nil
		}
	}}
	got, err := newTestClient(t, ft).ListUserGroupIDs(context.Background(), "Dana@Acme.dev")
	if err != nil {
		t.Fatalf("ListUserGroupIDs: %v", err)
	}
	if len(got) != 2 || got[0] != "ent-1" || got[1] != "ent-2" {
		t.Fatalf("ListUserGroupIDs = %+v, want [ent-1 ent-2]", got)
	}
	requests := ft.apiRequests()
	if len(requests) != 2 || !strings.Contains(requests[0].Body, "Dana@Acme.dev") {
		t.Fatalf("unexpected requests: %+v", requests)
	}
}

func TestListUserHeldEntitlementIDsFiltersTheGrantsSearch(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/search/users"):
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana@acme.dev"}}]}`, req), nil
		case strings.HasSuffix(req.URL.Path, "/search/grants"):
			return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-security"}}},{"entitlement":{"appEntitlement":{"id":"ent-other"}}}]}`, req), nil
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
			return nil, nil
		}
	}}
	got, err := newTestClient(t, ft).ListUserHeldEntitlementIDs(context.Background(), "dana@acme.dev", []c1directory.EntitlementRef{
		{ID: "ent-security", AppID: "app-1"},
		{ID: "ent-security", AppID: "app-1"},
		{ID: "ent-missing-app"},
	})
	if err != nil {
		t.Fatalf("ListUserHeldEntitlementIDs: %v", err)
	}
	if len(got) != 1 || got[0] != "ent-security" {
		t.Fatalf("ListUserHeldEntitlementIDs = %+v, want [ent-security]", got)
	}
	var grantsBody string
	for _, r := range ft.apiRequests() {
		if strings.HasSuffix(r.Path, "/search/grants") {
			grantsBody = r.Body
		}
	}
	if !strings.Contains(grantsBody, `"entitlementRefs":[{"appId":"app-1","id":"ent-security"}]`) {
		t.Fatalf("grants search missing filtered entitlementRefs: %s", grantsBody)
	}
}

func TestListUserHeldEntitlementIDsSkipsGrantsWhenNothingToCheck(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected path %s", req.URL.Path)
		return nil, nil
	}}
	got, err := newTestClient(t, ft).ListUserHeldEntitlementIDs(context.Background(), "dana@acme.dev", []c1directory.EntitlementRef{{ID: "ent-security"}})
	if err != nil {
		t.Fatalf("ListUserHeldEntitlementIDs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListUserHeldEntitlementIDs = %+v, want empty", got)
	}
}

func TestListUserGroupIDsRequiresExactEmailMatch(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/search/users") {
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana-not-quite@acme.dev"}}]}`, req), nil
		}
		t.Fatalf("grants search should not run when no user matched")
		return nil, nil
	}}
	got, err := newTestClient(t, ft).ListUserGroupIDs(context.Background(), "dana@acme.dev")
	if err != nil {
		t.Fatalf("ListUserGroupIDs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListUserGroupIDs = %+v, want empty for an unresolved user", got)
	}
}

func TestListUserGroupIDsDeduplicatesAcrossPages(t *testing.T) {
	var call int32
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/search/users") {
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana@acme.dev"}}]}`, req), nil
		}
		n := atomic.AddInt32(&call, 1)
		switch n {
		case 1:
			return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-1"}}}],"nextPageToken":"page-2"}`, req), nil
		case 2:
			return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-1"}}},{"entitlement":{"appEntitlement":{"id":"ent-2"}}}]}`, req), nil
		default:
			t.Fatalf("unexpected grants page %d", n)
			return nil, nil
		}
	}}
	got, err := newTestClient(t, ft).ListUserGroupIDs(context.Background(), "dana@acme.dev")
	if err != nil {
		t.Fatalf("ListUserGroupIDs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListUserGroupIDs = %+v, want 2 deduplicated IDs", got)
	}
}

func TestListUserGroupIDsGrantsSearchStopsAtTheHardPageCap(t *testing.T) {
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/search/users") {
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana@acme.dev"}}]}`, req), nil
		}
		return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-1"}}}],"nextPageToken":"more"}`, req), nil
	}}
	got, err := newTestClient(t, ft).ListUserGroupIDs(context.Background(), "dana@acme.dev")
	if err != nil {
		t.Fatalf("ListUserGroupIDs: %v", err)
	}
	if len(got) != 1 || got[0] != "ent-1" {
		t.Fatalf("ListUserGroupIDs = %+v, want the truncated page of unique IDs", got)
	}
}

func TestListUserGroupIDsCanceledContextDoesNotReturnPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var grants int32
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/search/users") {
			return jsonResponse(http.StatusOK, `{"list":[{"user":{"id":"usr-1","email":"dana@acme.dev"}}]}`, req), nil
		}
		if atomic.AddInt32(&grants, 1) == 1 {
			cancel()
			return jsonResponse(http.StatusOK, `{"list":[{"entitlement":{"appEntitlement":{"id":"ent-1"}}}],"nextPageToken":"more"}`, req), nil
		}
		t.Fatal("grants search continued after cancel")
		return nil, nil
	}}
	_, err := newTestClient(t, ft).ListUserGroupIDs(ctx, "dana@acme.dev")
	if err == nil {
		t.Fatal("ListUserGroupIDs returned success for a cancelled crawl")
	}
}

func TestTokenGrantPostsClientSecret(t *testing.T) {
	ft := &fakeTransport{}
	if _, err := newTestClient(t, ft).ListEntitlements(context.Background()); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	var tokenBody string
	for _, r := range ft.seen {
		if strings.HasSuffix(r.Path, "/auth/v1/token") {
			tokenBody = r.Body
			break
		}
	}
	if tokenBody == "" {
		t.Fatal("no token request was sent")
	}
	if !strings.Contains(tokenBody, "grant_type=client_credentials") {
		t.Errorf("token grant missing client_credentials: %s", tokenBody)
	}
	if !strings.Contains(tokenBody, "client_id="+testClientID) {
		t.Errorf("token grant missing client_id: %s", tokenBody)
	}
	if !strings.Contains(tokenBody, "client_secret=directory-client-secret") {
		t.Errorf("token grant missing client_secret: %s", tokenBody)
	}
	if strings.Contains(tokenBody, "client_assertion") {
		t.Errorf("token grant used a JWT assertion, want Union Station's client_secret: %s", tokenBody)
	}
}

func TestTokenGrantPostsSecretTokenAsClientSecret(t *testing.T) {
	const secret = "secret-token:conductorone.com:v1:not-a-real-jwk"
	ft := &fakeTransport{}
	client, err := c1directory.NewClient(testConfig(), c1directory.Deps{
		Secrets:   &stubSecrets{secret: credentials.NewSecret(secret)},
		Transport: ft,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.ListEntitlements(context.Background()); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	var tokenBody string
	for _, r := range ft.seen {
		if strings.HasSuffix(r.Path, "/auth/v1/token") {
			tokenBody = r.Body
			break
		}
	}
	if !strings.Contains(tokenBody, "client_secret=secret-token") {
		t.Fatalf("secret-token was not posted as client_secret: %s", tokenBody)
	}
	if strings.Contains(tokenBody, "client_assertion") {
		t.Fatalf("secret-token was sent as a JWT assertion: %s", tokenBody)
	}
}

func TestSearchReadsTheBodyAfterDoReturns(t *testing.T) {
	payload := `{"list":[{"appEntitlement":{"id":"ent-1","displayName":"One"}}]}`
	ft := &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       &ctxAwareBody{ctx: req.Context(), r: strings.NewReader(payload)},
			Request:    req,
		}, nil
	}}
	got, err := newTestClient(t, ft).ListEntitlements(context.Background())
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ent-1" {
		t.Fatalf("ListEntitlements = %+v, want [{ID:ent-1}]", got)
	}
}

type ctxAwareBody struct {
	ctx context.Context
	r   *strings.Reader
}

func (b *ctxAwareBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	return b.r.Read(p)
}

func (b *ctxAwareBody) Close() error { return nil }

func TestUnresolvableClientSecretIsRefused(t *testing.T) {
	client, err := c1directory.NewClient(testConfig(), c1directory.Deps{
		Secrets:   &stubSecrets{err: errors.New("vault is on fire, credentials leaked: sk_live_abc123")},
		Transport: &fakeTransport{},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ListEntitlements(context.Background())
	if !errors.Is(err, c1directory.ErrClientSecretUnresolved) {
		t.Fatalf("error = %v, want ErrClientSecretUnresolved", err)
	}
	if strings.Contains(err.Error(), "sk_live_abc123") {
		t.Fatalf("error leaked the resolver's own error text: %v", err)
	}
}
