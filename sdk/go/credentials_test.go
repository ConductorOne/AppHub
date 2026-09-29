// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func isolatedCredentials(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	// macOS derives UserConfigDir from HOME rather than XDG_CONFIG_HOME.
	t.Setenv("HOME", dir)
}

func seedCredential(t *testing.T, server, access, refresh string, expiry time.Time) {
	t.Helper()
	store, err := openCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	key := credentialKey(server)
	store.data.Entries[key] = credential{Server: server, Resource: server + "/api", ClientID: clientID, AccessToken: access, RefreshToken: refresh, ExpiresAt: expiry}
	store.data.Current = key
	if err := store.save(); err != nil {
		t.Fatal(err)
	}
}

func TestUnauthorizedForcesOneRefreshAndRetainsMutationKey(t *testing.T) {
	isolatedCredentials(t)
	var calls, refreshes atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshes.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("resource") != server.URL+"/api" || r.Form.Get("client_id") != clientID || r.Form.Get("refresh_token") != "refresh-1" {
				t.Error("refresh lost its binding")
			}
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-2", RefreshToken: "refresh-2", TokenType: "Bearer", ExpiresIn: 900, Scope: requestedScopes})
		case "/api/v1/applications":
			call := calls.Add(1)
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"name":"demo"}` || r.Header.Get("Idempotency-Key") != "stable-command-key" {
				t.Error("retry changed the mutation")
			}
			if call == 1 {
				if r.Header.Get("Authorization") != "Bearer access-1" {
					t.Error("missing original access token")
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer access-2" {
				t.Error("retry did not use rotated access token")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"created":true}`)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	seedCredential(t, server.URL, "access-1", "refresh-1", time.Now().Add(10*time.Minute))
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Created bool `json:"created"`
	}
	err = client.Do(context.Background(), http.MethodPost, "/api/v1/applications", map[string]string{"name": "demo"}, &response, http.Header{"Idempotency-Key": {"stable-command-key"}})
	if err != nil || !response.Created || calls.Load() != 2 || refreshes.Load() != 1 {
		t.Fatalf("refresh retry outcome: %v, %+v, calls %d refreshes %d", err, response, calls.Load(), refreshes.Load())
	}
	store, err := openCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	saved := store.data.Entries[credentialKey(server.URL)]
	if saved.RefreshToken != "refresh-2" || saved.RefreshPending {
		t.Fatal("rotated credential was not committed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("credential permissions: %v, %v", info, err)
		}
		info, err = os.Stat(filepath.Dir(store.path))
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("credential directory permissions: %v, %v", info, err)
		}
	}
}

func TestRefreshUncertaintyCannotReplayConsumedToken(t *testing.T) {
	isolatedCredentials(t)
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Error("API request made despite uncertain refresh")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		refreshes.Add(1)
		// Observe the write-ahead intent without taking the lock held by the client.
		base, _ := os.UserConfigDir()
		b, err := os.ReadFile(filepath.Join(base, "apphub", "credentials.json"))
		if err != nil {
			t.Error(err)
		}
		var file credentialFile
		if err := json.Unmarshal(b, &file); err != nil {
			t.Error(err)
		}
		for _, entry := range file.Entries {
			if !entry.RefreshPending {
				t.Error("refresh sent before durable uncertainty marker")
			}
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// Server consumed the refresh, but the response was lost.
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	seedCredential(t, server.URL, "expired-access", "single-use-refresh", time.Now().Add(-time.Minute))
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err := client.Do(context.Background(), http.MethodGet, "/api/v1/users/me", nil, new(UserView), nil)
		if !errors.Is(err, ErrReauthenticationRequired) {
			t.Fatalf("uncertain refresh did not require login: %v", err)
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("consumed refresh replayed %d times", refreshes.Load())
	}
	if _, err := FromContext(); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("uncertain record remained current: %v", err)
	}
}

func TestCredentialsStayBoundToServerAndResource(t *testing.T) {
	isolatedCredentials(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	seedCredential(t, "https://other.example", "other-access", "other-refresh", time.Now().Add(time.Hour))
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Do(context.Background(), http.MethodGet, "/api/v1/users/me", nil, nil, nil); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("cross-server credential reuse: %v", err)
	}
	seedCredential(t, server.URL, "access", "refresh", time.Now().Add(time.Hour))
	store, err := openCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key := credentialKey(server.URL)
	entry := store.data.Entries[key]
	entry.Resource = server.URL + "/mcp"
	store.data.Entries[key] = entry
	if err := store.save(); err != nil {
		t.Fatal(err)
	}
	store.close()
	if err := client.Do(context.Background(), http.MethodGet, "/api/v1/users/me", nil, nil, nil); !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("cross-resource credential reuse: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("transmitted another server/resource's credentials")
	}
}

func TestCredentialLockCrossProcess(t *testing.T) {
	isolatedCredentials(t)
	store, err := openCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialLockChild$")
	child.Env = append(os.Environ(), "APPHUB_SDK_LOCK_CHILD=blocked")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child lock exclusion: %v: %s", err, output)
	}
	store.close()
	child = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialLockChild$")
	child.Env = append(os.Environ(), "APPHUB_SDK_LOCK_CHILD=write")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child persistence: %v: %s", err, output)
	}
	store, err = openCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if store.data.Entries[credentialKey("https://child.example")].RefreshToken != "child-refresh" {
		t.Fatal("child atomic write not visible after lock release")
	}
}

func TestCredentialLockChild(t *testing.T) {
	mode := os.Getenv("APPHUB_SDK_LOCK_CHILD")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	store, err := openCredentials(ctx)
	if mode == "blocked" {
		if !errors.Is(err, context.DeadlineExceeded) {
			if store != nil {
				store.close()
			}
			t.Fatalf("cross-process lock was not exclusive: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	key := credentialKey("https://child.example")
	store.data.Entries[key] = credential{Server: "https://child.example", Resource: "https://child.example/api", ClientID: clientID, RefreshToken: "child-refresh"}
	if err := store.save(); err != nil {
		t.Fatal(err)
	}
}

func TestWaitDeploymentReturnsTerminalFailureAndStopsPolling(t *testing.T) {
	isolatedCredentials(t)
	const id = "ef248f53-cfa8-47b9-81b9-6aaeff46f603"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if _, err := fmt.Fprintf(w, `{"id":%q,"state":"interrupted","terminal":true,"message":"Operator resolution required"}`, id); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	seedCredential(t, server.URL, "access", "refresh", time.Now().Add(time.Hour))
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	view, err := client.WaitDeployment(context.Background(), id, nil)
	var outcome *DeploymentOutcomeError
	if !errors.As(err, &outcome) || view == nil || view.State != "interrupted" || !strings.Contains(err.Error(), id) || calls.Load() != 1 {
		t.Fatalf("terminal failure observation: %v, %+v, calls=%d", err, view, calls.Load())
	}
}
