// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCallbackIgnoresUncorrelatedErrorsAndCodes(t *testing.T) {
	const issuer = "https://apphub.example"
	const host = "127.0.0.1:32001"
	results := make(chan callbackResult, 1)
	handler := callbackHandler("expected-state", issuer, host, results)
	for _, query := range []url.Values{
		{"state": {"stale-state"}, "iss": {issuer}, "error": {"access_denied"}},
		{"state": {"expected-state"}, "iss": {"https://attacker.example"}, "code": {"code"}},
		{"state": {"expected-state"}, "error": {"access_denied"}},
		{"state": {"expected-state"}, "iss": {issuer}, "resource": {issuer + "/mcp"}, "code": {"code"}},
		{"state": {"expected-state", "extra"}, "iss": {issuer}, "code": {"code"}},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/callback?"+query.Encode(), nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("uncorrelated callback status = %d", response.Code)
		}
		select {
		case <-results:
			t.Fatal("uncorrelated callback terminated login")
		default:
		}
	}
	good := url.Values{"state": {"expected-state"}, "iss": {issuer}, "code": {"bound-code"}}
	request := httptest.NewRequest(http.MethodGet, "http://"+host+"/callback?"+good.Encode(), nil)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if result := <-results; result.err != nil || result.code != "bound-code" {
		t.Fatalf("valid correlated response rejected: %+v", result)
	}
	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, request)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate callback status = %d", duplicate.Code)
	}
}

func TestDiscoveryRejectsIssuerResourceAndCredentialEndpointSubstitution(t *testing.T) {
	for _, scenario := range []string{"issuer", "resource", "token", "redirect", "missing-iss-support"} {
		t.Run(scenario, func(t *testing.T) {
			contactedUntrusted := false
			untrusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { contactedUntrusted = true; w.WriteHeader(http.StatusOK) }))
			defer untrusted.Close()
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "redirect" {
					http.Redirect(w, r, untrusted.URL, http.StatusFound)
					return
				}
				if r.URL.Path == "/.well-known/oauth-protected-resource/api" {
					resource := server.URL + "/api"
					if scenario == "resource" {
						resource = server.URL + "/mcp"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{server.URL}})
					return
				}
				issuer, token := server.URL, server.URL+"/oauth/token"
				if scenario == "issuer" {
					issuer = untrusted.URL
				}
				if scenario == "token" {
					token = untrusted.URL + "/oauth/token"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer": issuer, "authorization_endpoint": server.URL + "/oauth/authorize", "token_endpoint": token, "revocation_endpoint": server.URL + "/oauth/revoke",
					"authorization_response_iss_parameter_supported": scenario != "missing-iss-support", "code_challenge_methods_supported": []string{"S256"},
					"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none"},
				})
			}))
			defer server.Close()
			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.discover(context.Background()); err == nil {
				t.Fatal("accepted substituted or weakened OAuth discovery")
			}
			if contactedUntrusted {
				t.Fatal("followed discovery to an untrusted endpoint")
			}
		})
	}
}

func TestServerAndAPIPathCannotRetargetCredentials(t *testing.T) {
	for _, origin := range []string{"http://example.com", "http://localhost:8000", "https://user:secret@example.com", "https://example.com/api", "https://example.com?x=y", "https://example.com/#fragment"} {
		if _, err := NewClient(origin); err == nil {
			t.Fatalf("accepted non-origin or insecure server %q", origin)
		}
	}
	client, err := NewClient("https://APPHUB.example:443/")
	if err != nil || client.Server != "https://apphub.example" {
		t.Fatalf("canonical origin: %v, %v", client, err)
	}
	for _, path := range []string{"https://attacker.example/api/v1/users/me", "//attacker.example/api/v1/users/me", "/api/v1/../../oauth/token", "/api/v1/%2e%2e/token", "/oauth/token", "/api/v1/users/me#fragment"} {
		if _, err := apiPath(path); err == nil {
			t.Fatalf("accepted escaping API path %q", path)
		}
	}
	client.Server = "https://attacker.example"
	if err := client.Do(context.Background(), http.MethodGet, "/api/v1/users/me", nil, nil, nil); err == nil {
		t.Fatal("retargeted client accepted")
	}
}
