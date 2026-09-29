// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conductorone/apphub/internal/httpapi"
)

func TestHealthAndReadiness(t *testing.T) {
	type contextKey struct{}
	dependencyFailure := errors.New("secret-provider-configuration")
	var receivedContext bool
	mux := httpapi.NewMux("", func(ctx context.Context) error {
		receivedContext = ctx.Value(contextKey{}) == "request"
		return dependencyFailure
	})
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	request = request.WithContext(context.WithValue(request.Context(), contextKey{}, "request"))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !receivedContext {
		t.Fatalf("readiness = %d, request context propagated = %v", response.Code, receivedContext)
	}
	if strings.Contains(response.Body.String(), dependencyFailure.Error()) {
		t.Fatal("readiness exposed dependency error")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("readiness can be cached")
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(method, "/healthz", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("liveness with failed dependency = %d", response.Code)
		}
		if method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatal("HEAD liveness returned a body")
		}
	}

	dependencyFailure = nil
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("recovered readiness = %d", response.Code)
	}
	response = httptest.NewRecorder()
	httpapi.NewMux("", nil).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured readiness = %d", response.Code)
	}
}

func staticFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"index.html":    "<!doctype html><title>AppHub</title>",
		"assets/app.js": "console.log('AppHub');",
		"assets/opaque": "opaque asset",
		".env":          "private-config-canary",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestStaticNavigationAndAssetMisses(t *testing.T) {
	mux := httpapi.NewMux(staticFixture(t), nil)
	for _, tc := range []struct {
		name, method, target, accept, mode, dest string
		status                                   int
		body                                     string
	}{
		{name: "root navigation", target: "/", accept: "text/html", status: 200, body: "<!doctype html>"},
		{name: "deep navigation", target: "/applications/app/deployments/job", accept: "text/html,application/xhtml+xml;q=0.9", mode: "navigate", dest: "document", status: 200, body: "<!doctype html>"},
		{name: "head navigation", method: "HEAD", target: "/applications/app", accept: "text/html", status: 200},
		{name: "existing script", target: "/assets/app.js", status: 200, body: "console.log"},
		{name: "existing extensionless asset", target: "/assets/opaque", status: 200, body: "opaque asset"},
		{name: "missing script", target: "/assets/missing.js", accept: "text/html", status: 404},
		{name: "missing extensionless asset", target: "/assets/missing", accept: "text/html", status: 404},
		{name: "missing root asset", target: "/favicon.ico", accept: "text/html", status: 404},
		{name: "directory listing", target: "/assets", accept: "text/html", status: 404},
		{name: "no accept", target: "/applications/app", status: 404},
		{name: "wildcard accept", target: "/applications/app", accept: "*/*", status: 404},
		{name: "excluded html", target: "/applications/app", accept: "text/html;q=0,*/*", status: 404},
		{name: "fetch not navigation", target: "/applications/app", accept: "text/html", mode: "cors", status: 404},
		{name: "script not navigation", target: "/applications/app", accept: "text/html", dest: "script", status: 404},
		{name: "mutation", method: "POST", target: "/applications/app", accept: "text/html", status: 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			request := httptest.NewRequest(method, tc.target, nil)
			request.Header.Set("Accept", tc.accept)
			request.Header.Set("Sec-Fetch-Mode", tc.mode)
			request.Header.Set("Sec-Fetch-Dest", tc.dest)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if tc.body != "" && !strings.Contains(response.Body.String(), tc.body) {
				t.Fatalf("body = %q, want %q", response.Body.String(), tc.body)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatal("HEAD returned frontend body")
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing MIME sniffing protection")
			}
			if tc.status == 200 {
				mediaType := response.Header().Get("Content-Type")
				if tc.target == "/assets/app.js" && !strings.Contains(mediaType, "javascript") {
					t.Fatalf("script content type = %q", mediaType)
				}
				if tc.target == "/assets/opaque" && mediaType != "application/octet-stream" {
					t.Fatalf("unknown asset content type = %q", mediaType)
				}
			}
		})
	}
}

func TestFrontendDocumentsDenyFraming(t *testing.T) {
	mux := httpapi.NewMux(staticFixture(t), nil)
	for _, target := range []string{"/", "/login", "/authorize?transactionId=example", "/applications/app"} {
		t.Run(target, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.Header.Set("Accept", "text/html")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Dest", "iframe")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<!doctype html>") {
				t.Fatalf("iframe navigation %s: %d %s", target, response.Code, response.Body.String())
			}
			if got := response.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
				t.Fatalf("iframe navigation %s CSP = %q", target, got)
			}
			if got := response.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("iframe navigation %s X-Frame-Options = %q", target, got)
			}
		})
	}
}

func TestReservedBackendPathsNeverServeFrontend(t *testing.T) {
	root := staticFixture(t)
	// An accidentally packaged file under a backend prefix must not be served.
	if err := os.Mkdir(filepath.Join(root, "api"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "api", "secret.json"), []byte("backend-file-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	mux := httpapi.NewMux(root, nil)
	for _, prefix := range []string{"/api", "/auth", "/oauth", "/mcp", "/.well-known", "/healthz", "/readyz"} {
		for _, suffix := range []string{"/", "/unknown", "/secret.json"} {
			request := httptest.NewRequest(http.MethodGet, prefix+suffix, nil)
			request.Header.Set("Accept", "text/html")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", prefix+suffix, response.Code)
			}
		}
	}
	mux.HandleFunc("GET /api/v1/example", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/example", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("registered API route = %d", response.Code)
	}
}

func TestStaticFilesystemConfinement(t *testing.T) {
	root := staticFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside-secret-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	mux := httpapi.NewMux(root, nil)
	for _, target := range []string{"/escape/secret.txt", "/secret.txt", "/%2e%2e/secret.txt", "/assets/%2e%2e/.env", "/assets%5c..%5c.env", "/.env", "/%00"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, response.Code)
		}
		if strings.Contains(response.Body.String(), "canary") {
			t.Errorf("GET %s exposed private file", target)
		}
	}
	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/applications/app", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("escaped SPA entrypoint = %d", response.Code)
	}
}

func TestServerBoundsKnownAndStreamedBodies(t *testing.T) {
	server := httpapi.NewServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			if len(body) > 128<<10 {
				t.Error("handler received body beyond cap")
			}
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			t.Errorf("reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, length := range []int{128 << 10, (128 << 10) + 1} {
		for _, streamed := range []bool{false, true} {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/example", strings.NewReader(strings.Repeat("x", length)))
			if streamed {
				request.ContentLength = -1
			}
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			want := http.StatusNoContent
			if length > 128<<10 {
				want = http.StatusRequestEntityTooLarge
			}
			if response.Code != want {
				t.Errorf("body length %d, streamed %v: status = %d, want %d", length, streamed, response.Code, want)
			}
		}
	}
}
