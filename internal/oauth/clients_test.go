// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func metadataResponse(body string, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func TestCIMDValidationAndExactRedirect(t *testing.T) {
	h := newOAuthHarness(t)
	id := "https://client.example/metadata.json"
	doc := clientMetadata{ClientID: id, ClientName: "Remote MCP", RedirectURIs: []string{"https://remote.example/callback"}, TokenEndpointAuthMethod: "none"}
	var calls atomic.Int64
	h.server.metadataClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		data, _ := json.Marshal(doc)
		return metadataResponse(string(data), 200), nil
	})}
	if err := h.server.validateClient(context.Background(), id, "https://remote.example/callback"); err != nil {
		t.Fatal(err)
	}
	if err := h.server.validateClient(context.Background(), id, "https://remote.example/callback?different=1"); err == nil {
		t.Fatal("CIMD redirect prefix match accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("validated client metadata was not cached")
	}
	// Configured registrations are authoritative even if a public document would
	// claim a broader redirect list.
	h.server.clients[id] = []string{"https://configured.example/callback"}
	if err := h.server.validateClient(context.Background(), id, "https://remote.example/callback"); err == nil {
		t.Fatal("metadata overrode operator registration")
	}
	if err := h.server.validateClient(context.Background(), id, "https://configured.example/callback"); err != nil {
		t.Fatal(err)
	}
}
func TestCIMDLoopbackRedirectAcceptsEphemeralPort(t *testing.T) {
	h := newOAuthHarness(t)
	id := "https://claude.ai/oauth/claude-code-client-metadata"
	doc := clientMetadata{ClientID: id, ClientName: "Claude Code", RedirectURIs: []string{"http://localhost/callback"}, TokenEndpointAuthMethod: "none"}
	h.server.metadataClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(doc)
		return metadataResponse(string(data), 200), nil
	})}
	if err := h.server.validateClient(context.Background(), id, "http://localhost:53682/callback"); err != nil {
		t.Fatalf("ephemeral loopback port rejected: %v", err)
	}
	for _, redirect := range []string{
		"http://localhost:53682/other",
		"http://127.0.0.1:53682/callback",
		"https://localhost/callback",
		"http://localhost.evil.com/callback",
		"http://user@localhost:1/callback",
	} {
		if err := h.server.validateClient(context.Background(), id, redirect); err == nil {
			t.Fatalf("unsafe loopback redirect accepted: %s", redirect)
		}
	}
}
func TestCIMDLoopbackAuthorizeAccepts(t *testing.T) {
	h := newOAuthHarness(t)
	id := "https://claude.ai/oauth/claude-code-client-metadata"
	doc := clientMetadata{ClientID: id, ClientName: "Claude Code", RedirectURIs: []string{"http://localhost/callback"}, TokenEndpointAuthMethod: "none"}
	h.server.metadataClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(doc)
		return metadataResponse(string(data), 200), nil
	})}
	verifier := secret()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {id}, "redirect_uri": {"http://localhost:53682/callback"}, "response_type": {"code"}, "state": {secret()}, "resource": {h.origin + "/api"}, "scope": {cp.ApplicationsRead}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	w := h.request("GET", "/oauth/authorize?"+q.Encode(), "", false, false)
	if w.Code != 302 {
		t.Fatalf("expected redirect to login, got %d %s", w.Code, w.Body.String())
	}
	if location, err := url.Parse(w.Header().Get("Location")); err != nil || location.Path != "/login" {
		t.Fatalf("unexpected redirect: %s", w.Header().Get("Location"))
	}
}
func TestCIMDRejectsUnsafeDocumentsBeforeAuthorization(t *testing.T) {
	id := "https://client.example/metadata.json"
	valid := clientMetadata{ClientID: id, ClientName: "Remote", RedirectURIs: []string{"https://remote.example/callback"}, TokenEndpointAuthMethod: "none"}
	for _, test := range []struct {
		name   string
		change func(*clientMetadata)
	}{
		{"mismatched ID", func(m *clientMetadata) { m.ClientID = "https://other.example/metadata.json" }},
		{"confidential client", func(m *clientMetadata) { m.TokenEndpointAuthMethod = "client_secret_basic" }},
		{"implicit confidential default", func(m *clientMetadata) { m.TokenEndpointAuthMethod = "" }},
		{"non-loopback HTTP redirect", func(m *clientMetadata) { m.RedirectURIs = []string{"http://remote.example/callback"} }},
		{"private HTTP redirect", func(m *clientMetadata) { m.RedirectURIs = []string{"http://10.0.0.1/callback"} }},
		{"userinfo redirect", func(m *clientMetadata) { m.RedirectURIs = []string{"https://user@remote.example/callback"} }},
		{"fragment redirect", func(m *clientMetadata) { m.RedirectURIs = []string{"https://remote.example/callback#fragment"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := valid
			test.change(&doc)
			data, _ := json.Marshal(doc)
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return metadataResponse(string(data), 200), nil })}
			if _, err := fetchMetadata(context.Background(), client, id); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(valid)
		return metadataResponse(string(data)+strings.Repeat(" ", 16<<10), 200), nil
	})}
	if _, err := fetchMetadata(context.Background(), client, id); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}
func TestCIMDNetworkCannotReachLoopbackOrFollowRedirect(t *testing.T) {
	var reached atomic.Int64
	trap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(http.StatusOK) }))
	defer trap.Close()
	client := newMetadataHTTPClient()
	if _, err := fetchMetadata(context.Background(), client, trap.URL+"/metadata.json"); err == nil {
		t.Fatal("loopback metadata allowed")
	}
	if reached.Load() != 0 {
		t.Fatal("metadata request reached private host")
	}
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		reached.Add(1)
		response := metadataResponse("", 302)
		response.Header.Set("Location", "https://other.example/metadata.json")
		return response, nil
	})
	if _, err := fetchMetadata(context.Background(), client, "https://client.example/metadata.json"); err == nil {
		t.Fatal("metadata redirect accepted")
	}
	if reached.Load() != 1 {
		t.Fatal("metadata followed redirect")
	}
}
func TestCIMDRejectsPrivateAndTranslationAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "198.18.0.1", "192.0.2.1", "224.0.0.1", "::1", "::ffff:169.254.169.254", "fe80::1", "fc00::1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:db8::1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("unsafe metadata address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("public address refused: %s", raw)
		}
	}
}
