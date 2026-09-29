// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

// rsaPEM generates a key in-process. Nothing key-shaped is committed to a
// repository that is going public, and generating one exercises the parse path.
func rsaPEM(t *testing.T) credentials.Secret {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return credentials.NewSecret(string(pem.EncodeToMemory(block)))
}

// These are the package's own guards, behind the provider's validation rather
// than in front of it. They are tested here because they are what makes this
// package safe to call from a second consumer, which is the whole reason it is a
// package.
func TestNewAppRejectsAnUnusableConfiguration(t *testing.T) {
	t.Run("app ID is required", func(t *testing.T) {
		for _, id := range []int64{0, -1} {
			if _, err := githubapp.NewApp(githubapp.AppConfig{AppID: id, PrivateKeyPEM: rsaPEM(t)}); err == nil {
				t.Errorf("NewApp(appID=%d) succeeded", id)
			}
		}
	})

	t.Run("private key is required", func(t *testing.T) {
		if _, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1}); err == nil {
			t.Error("NewApp with no private key succeeded")
		}
		blank := credentials.NewSecret("   \n ")
		if _, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: blank}); err == nil {
			t.Error("NewApp with a blank private key succeeded")
		}
	})

	t.Run("a PKCS8 key that is not RSA is refused", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		material := credentials.NewSecret(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))

		_, err = githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: material})
		if err == nil {
			t.Fatal("an ECDSA key was accepted; GitHub app JWTs are RS256")
		}
		if strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("the error carries key material: %v", err)
		}
	})

	t.Run("the base URL is checked", func(t *testing.T) {
		// ForceQuery: "https://host/path?" parses with an empty RawQuery, so a check
		// on RawQuery alone would let it through.
		for _, base := range []string{"https://api.github.test/?", "http://api.github.test", "https://"} {
			_, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), BaseURL: base})
			if !errors.Is(err, githubapp.ErrBaseURL) {
				t.Errorf("NewApp(baseURL=%q) = %v, want ErrBaseURL", base, err)
			}
		}
		if _, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t)}); err != nil {
			t.Errorf("NewApp with no base URL = %v, want the github.com default", err)
		}
	})
}

// TestMintInstallationTokenRequiresAnInstallation: a zero installation ID would
// otherwise be interpolated into a path and asked of GitHub.
func TestMintInstallationTokenRequiresAnInstallation(t *testing.T) {
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t)})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	for _, id := range []int64{0, -1} {
		if _, err := app.MintInstallationToken(context.Background(), id, githubapp.InstallationTokenRequest{}); err == nil {
			t.Errorf("MintInstallationToken(installation=%d) succeeded", id)
		}
	}
}

func TestListInstallationRepositories(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body string
		switch r.URL.Path {
		case "/app/installations/7/access_tokens":
			body = `{"token":"ghs_test","expires_at":"2099-01-01T00:00:00Z"}`
		case "/installation/repositories":
			if r.Header.Get("Authorization") != "Bearer ghs_test" {
				t.Errorf("repository list authorization = %q", r.Header.Get("Authorization"))
			}
			body = `{"repositories":[{"full_name":"Example-Org/app"},{"full_name":"Example-Org/app"},{"full_name":"not a repo"},{"full_name":"Example-Org/other"}]}`
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			body = `{}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), BaseURL: "https://api.github.test", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	urls, err := app.ListInstallationRepositories(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 || urls[0] != "https://github.com/Example-Org/app" || urls[1] != "https://github.com/Example-Org/other" {
		t.Fatalf("urls = %#v", urls)
	}
}

// TestTheFullInstallationGrantMustBeAskedForByName is the fundamental half of the
// scope fix.
//
// Review found a provider-level parsing bug that produced a full-installation
// token from a blank metadata value. Fixing the parsing was necessary and is not
// sufficient: the shape of that bug is that the widest possible grant was the
// value any parsing mistake fell into, because GitHub reads an omitted scoping
// field as "everything". This layer now refuses a request that restricts nothing
// unless the caller says so, which is what makes a future parsing bug in any
// caller unable to widen a token by omission.
func TestTheFullInstallationGrantMustBeAskedForByName(t *testing.T) {
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t)})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}

	t.Run("a request restricting nothing is refused", func(t *testing.T) {
		_, err := app.MintInstallationToken(context.Background(), 42, githubapp.InstallationTokenRequest{})
		if !errors.Is(err, githubapp.ErrFullInstallationGrant) {
			t.Fatalf("err = %v, want ErrFullInstallationGrant", err)
		}
	})

	t.Run("an empty-but-present restriction is still nothing", func(t *testing.T) {
		// A caller that built empty slices from a blank configuration value looks
		// exactly like a caller that built none. Both are refused.
		for _, req := range []githubapp.InstallationTokenRequest{
			{Repositories: []string{}},
			{RepositoryIDs: []int64{}},
			{Permissions: map[string]string{}},
			{Repositories: []string{}, RepositoryIDs: []int64{}, Permissions: map[string]string{}},
		} {
			if _, err := app.MintInstallationToken(context.Background(), 42, req); !errors.Is(err, githubapp.ErrFullInstallationGrant) {
				t.Errorf("MintInstallationToken(%+v) = %v, want ErrFullInstallationGrant", req, err)
			}
		}
	})

	t.Run("asking for both is refused", func(t *testing.T) {
		req := githubapp.InstallationTokenRequest{
			Repositories:          []string{"apple"},
			FullInstallationGrant: true,
		}
		if _, err := app.MintInstallationToken(context.Background(), 42, req); !errors.Is(err, githubapp.ErrFullInstallationGrant) {
			t.Errorf("a request that both restricts and asks for everything = %v, want ErrFullInstallationGrant", err)
		}
	})

	t.Run("a restricted request and a named full grant both pass validation", func(t *testing.T) {
		// Both reach the transport, which is as far as this test needs them to get:
		// the point is that validation admitted them.
		for _, req := range []githubapp.InstallationTokenRequest{
			{Repositories: []string{"apple"}},
			{FullInstallationGrant: true},
		} {
			var reached bool
			rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
				reached = true
				return nil, errors.New("stop here")
			})
			scoped, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), Transport: rt})
			if err != nil {
				t.Fatalf("NewApp: %v", err)
			}
			if _, err := scoped.MintInstallationToken(context.Background(), 42, req); errors.Is(err, githubapp.ErrFullInstallationGrant) {
				t.Errorf("MintInstallationToken(%+v) was refused as an unnamed full grant", req)
			}
			if !reached {
				t.Errorf("MintInstallationToken(%+v) never reached the transport", req)
			}
		}
	})
}

// roundTripFunc is a transport stub. Supplying a transport is the only HTTP seam
// this package exposes; it deliberately cannot carry a redirect policy.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body any) *http.Response {
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(status)
	_, _ = recorder.Write(data)
	return recorder.Result()
}

func TestListInstallationsPaginatesToCompletion(t *testing.T) {
	page1 := make([]githubapp.Installation, 100)
	for i := range page1 {
		page1[i] = githubapp.Installation{ID: int64(i + 1), Account: githubapp.InstallationAccount{Login: fmt.Sprintf("org-%d", i)}}
	}
	page2 := []githubapp.Installation{{ID: 101, Account: githubapp.InstallationAccount{Login: "org-101"}}}
	var calls []string
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.RawQuery)
		if strings.Contains(r.URL.RawQuery, "page=2") {
			return jsonResponse(http.StatusOK, page2), nil
		}
		return jsonResponse(http.StatusOK, page1), nil
	})})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	got, err := app.ListInstallations(context.Background())
	if err != nil {
		t.Fatalf("ListInstallations: %v", err)
	}
	if len(got) != 101 {
		t.Fatalf("got %d installations, want 101", len(got))
	}
	if got[100].ID != 101 {
		t.Fatalf("last installation = %+v, want ID 101", got[100])
	}
	if len(calls) != 2 {
		t.Fatalf("expected exactly two pages fetched, got %d: %v", len(calls), calls)
	}
}

func TestListInstallationsPropagatesAFailedPage(t *testing.T) {
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, map[string]string{"message": "nope"}), nil
	})})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	if _, err := app.ListInstallations(context.Background()); err == nil {
		t.Fatal("ListInstallations succeeded against a 403")
	}
}

func TestGetInstallationByOwnerTriesOrgThenUser(t *testing.T) {
	var paths []string
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/orgs/") {
			return jsonResponse(http.StatusNotFound, map[string]string{}), nil
		}
		return jsonResponse(http.StatusOK, githubapp.Installation{ID: 7, Account: githubapp.InstallationAccount{Login: "someuser", Type: "User"}}), nil
	})})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	inst, err := app.GetInstallationByOwner(context.Background(), "someuser")
	if err != nil {
		t.Fatalf("GetInstallationByOwner: %v", err)
	}
	if inst == nil || inst.ID != 7 {
		t.Fatalf("inst = %+v", inst)
	}
	if len(paths) != 2 || !strings.HasPrefix(paths[0], "/orgs/") || !strings.HasPrefix(paths[1], "/users/") {
		t.Fatalf("unexpected request path order: %v", paths)
	}
}

func TestGetInstallationByOwnerNotFoundAnywhereReturnsNil(t *testing.T) {
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t), Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, map[string]string{}), nil
	})})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	inst, err := app.GetInstallationByOwner(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("GetInstallationByOwner: %v", err)
	}
	if inst != nil {
		t.Fatalf("inst = %+v, want nil", inst)
	}
}

func TestGetInstallationByOwnerRequiresAnOwner(t *testing.T) {
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: rsaPEM(t)})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	if _, err := app.GetInstallationByOwner(context.Background(), "   "); err == nil {
		t.Fatal("GetInstallationByOwner('   ') succeeded")
	}
}
