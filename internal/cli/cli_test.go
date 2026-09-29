// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/conductorone/apphub/sdk/go"
)

type loginPrompt struct{ urls chan string }

func (p loginPrompt) Write(b []byte) (int, error) {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "/oauth/authorize?") {
			p.urls <- line
		}
	}
	return len(b), nil
}

// This fixture exercises the real loopback Login and credential persistence,
// rather than teaching CLI tests the credential-file format or adding auth seams.
func authenticatedCLI(t *testing.T, api http.HandlerFunc) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	var server *httptest.Server
	challenges := make(chan string, 1)
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/api":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": server.URL + "/api", "authorization_servers": []string{server.URL}})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth/authorize", "token_endpoint": server.URL + "/oauth/token", "revocation_endpoint": server.URL + "/oauth/revoke",
				"authorization_response_iss_parameter_supported": true, "code_challenge_methods_supported": []string{"S256"},
				"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none"},
			})
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(hash[:]) != <-challenges || r.Form.Get("resource") != server.URL+"/api" || r.Form.Get("code") != "bound-code" || r.Form.Get("client_id") != "apphub-cli" {
				t.Error("login did not preserve PKCE/client/resource/code binding")
			}
			_ = json.NewEncoder(w).Encode(sdk.TokenResponse{AccessToken: "fixture-access", RefreshToken: "fixture-refresh", TokenType: "Bearer", ExpiresIn: 900, Scope: "applications:read applications:write deployments:read deployments:write"})
		default:
			if r.Header.Get("Authorization") != "Bearer fixture-access" {
				t.Error("CLI API request not authenticated")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			api(w, r)
		}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prompts := loginPrompt{urls: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { _, err := sdk.Login(ctx, server.URL, true, prompts); done <- err }()
	var raw string
	select {
	case raw = <-prompts.urls:
	case err := <-done:
		t.Fatalf("login failed before prompt: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	authorization, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	query := authorization.Query()
	challenges <- query.Get("code_challenge")
	callback, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	callback.RawQuery = url.Values{"state": {query.Get("state")}, "iss": {server.URL}, "code": {"bound-code"}}.Encode()
	response, err := http.Get(callback.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", response.StatusCode)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func decodeOne(t *testing.T, output []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("stdout is not JSON: %v: %s", err, output)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("stdout contains more than one JSON value: %v: %s", err, output)
	}
	return value
}

func TestDeployWaitJSONTerminalExit(t *testing.T) {
	const appID = "1278122c-f3f2-479f-8c04-e924b92e7815"
	const deploymentID = "37e9d738-3d8c-42a3-80b7-b227ee5f8531"
	for _, state := range []string{"succeeded", "failed", "interrupted"} {
		t.Run(state, func(t *testing.T) {
			authenticatedCLI(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "POST /api/v1/applications/" + appID + "/deployments":
					if r.Header.Get("Idempotency-Key") != "retained-key" {
						t.Error("submission key not preserved")
					}
					var input sdk.SubmitDeploymentInput
					if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ApplicationRevision != 6 {
						t.Errorf("submission revision: %+v, %v", input, err)
					}
					w.WriteHeader(http.StatusAccepted)
					_, _ = fmt.Fprintf(w, `{"deploymentId":%q,"applicationId":%q,"state":"queued","statusUrl":%q,"pollAfterMs":2000}`, deploymentID, appID, "/api/v1/deployments/"+deploymentID)
				case "GET /api/v1/deployments/" + deploymentID:
					_, _ = fmt.Fprintf(w, `{"id":%q,"applicationId":%q,"state":%q,"terminal":true,"execution":"service","message":"Safe outcome"}`, deploymentID, appID, state)
				default:
					t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			var stdout, stderr bytes.Buffer
			exit := Run(context.Background(), []string{"deploy", appID, "--revision", "6", "--idempotency-key", "retained-key", "--wait", "--json"}, &stdout, &stderr)
			value := decodeOne(t, stdout.Bytes())
			if value["id"] != deploymentID || value["state"] != state || value["terminal"] != true {
				t.Fatalf("incorrect terminal JSON: %v", value)
			}
			if (state == "succeeded" && exit != 0) || (state != "succeeded" && exit == 0) {
				t.Fatalf("state %s exit %d", state, exit)
			}
			if !strings.Contains(stderr.String(), deploymentID) || !strings.Contains(stderr.String(), "retained-key") {
				t.Fatal("durable ID/key missing from recovery output")
			}
			if strings.Contains(stdout.String()+stderr.String(), "fixture-access") || strings.Contains(stdout.String()+stderr.String(), "fixture-refresh") {
				t.Fatal("credential leaked to command output")
			}
		})
	}
}

func TestWaitTimeoutRetainsAcceptedOperationInOneJSONValue(t *testing.T) {
	const appID = "1278122c-f3f2-479f-8c04-e924b92e7815"
	const deploymentID = "37e9d738-3d8c-42a3-80b7-b227ee5f8531"
	authenticatedCLI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprintf(w, `{"deploymentId":%q,"applicationId":%q,"state":"queued","statusUrl":%q,"pollAfterMs":2000}`, deploymentID, appID, "/api/v1/deployments/"+deploymentID)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%q,"state":"running","terminal":false,"pollAfterMs":2000}`, deploymentID)
	})
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"deploy", appID, "--revision", "1", "--wait", "--timeout", "20ms", "--json"}, &stdout, &stderr)
	value := decodeOne(t, stdout.Bytes())
	recovery, ok := value["recovery"].(map[string]any)
	if exit == 0 || !ok || recovery["deploymentId"] != deploymentID || value["error"] == nil {
		t.Fatalf("timeout lost accepted operation: exit=%d, value=%v", exit, value)
	}
	if !strings.Contains(stderr.String(), deploymentID) {
		t.Fatal("timeout omitted recovery ID")
	}
}

func TestJSONUsageFailureIsOneValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"deploy", "app", "--revision", "0", "--json"}, &stdout, &stderr)
	value := decodeOne(t, stdout.Bytes())
	if exit != 2 || value["error"] == nil {
		t.Fatalf("usage failure: exit %d, %v", exit, value)
	}
}
