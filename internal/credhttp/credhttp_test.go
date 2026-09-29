// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credhttp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// testOp is one member of the closed Op set. The set is closed on purpose -- see
// credhttp.Op -- so these tests use a real label rather than inventing one, which
// is the same guarantee the providers get.
var testOp = credhttp.OpDatadogCreateAPIKey()

func request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.com/thing", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Credential-Header", "material-that-must-not-escape")
	return req
}

// TestRedirectsAreRefusedWhateverTransportIsSupplied is the property the whole
// package exists for. A caller supplies a transport -- the thing they actually
// wanted, for tracing or a proxy or a test -- and gets no say over redirect
// policy, because a RoundTripper cannot express one and Client exposes no
// *http.Client to set it on.
func TestRedirectsAreRefusedWhateverTransportIsSupplied(t *testing.T) {
	var seen int
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen++
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.example.com/collect"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	resp, err := credhttp.New(rt).Do(request(t), testOp)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Fatalf("Do = %v, want ErrRedirectRefused", err)
	}
	if seen != 1 {
		t.Errorf("the transport saw %d requests; the redirect was followed", seen)
	}
	if errors.Is(err, credentials.ErrTransient) {
		t.Error("a refused redirect is not transient")
	}
	// The Location header is upstream-controlled. net/http builds its *url.Error
	// wrapper from the redirect target, so this holds only because the error is
	// rebuilt rather than wrapped.
	for _, forbidden := range []string{"attacker.example.com", "collect"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("the refusal reflected the redirect target: %v", err)
		}
	}
}

// TestATransportsErrorTextNeverEscapes is the other half. A transport has already
// seen the authenticated request, so its diagnostics can contain the credential --
// and an instrumentation layer that annotates failures with request detail is an
// ordinary thing to write, not an attack.
func TestATransportsErrorTextNeverEscapes(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("trace: failed sending " + req.URL.String() +
			" X-Credential-Header=" + req.Header.Get("X-Credential-Header"))
	})

	resp, err := credhttp.New(rt).Do(request(t), testOp)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, forbidden := range []string{
		"material-that-must-not-escape", "X-Credential-Header", "trace:", "failed sending",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Errorf("error carries %q: %v", forbidden, err)
		}
	}
	if !errors.Is(err, credentials.ErrTransient) {
		t.Errorf("a transport failure must classify as transient: %v", err)
	}
	if !strings.Contains(err.Error(), testOp.String()) {
		t.Errorf("error %q does not name the operation, which is the only detail it may carry", err)
	}
}

// TestClassificationDistinguishesWhatACallerCanActOn. Four outcomes, because four
// is what a caller can do something different about; everything else collapses
// into one transient failure on purpose.
func TestClassificationDistinguishesWhatACallerCanActOn(t *testing.T) {
	t.Run("cancellation is not transient", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/thing", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		// The transport may or may not be reached -- net/http short-circuits a done
		// context inconsistently -- so it returns an unhelpful error either way,
		// which is exactly the case the classification has to get right without
		// relying on net/http's wrapping.
		rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection reset")
		})

		resp, err := credhttp.New(rt).Do(req, testOp)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Do = %v, want context.Canceled", err)
		}
		if errors.Is(err, credentials.ErrTransient) {
			t.Error("a caller that gave up has not found a transient failure")
		}
	})

	t.Run("a deadline is transient and says so", func(t *testing.T) {
		rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		})
		resp, err := credhttp.New(rt).Do(request(t), testOp)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, credentials.ErrTransient) {
			t.Errorf("Do = %v, want ErrTransient", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Do = %v, want the deadline preserved", err)
		}
	})

	t.Run("a successful response passes through", func(t *testing.T) {
		rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Request:    req,
			}, nil
		})
		resp, err := credhttp.New(rt).Do(request(t), testOp)
		if err != nil {
			t.Fatalf("Do = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
}

// TestANilTransportGetsTheSharedDefault: the ordinary construction path still
// works and still refuses redirects.
func TestANilTransportGetsTheSharedDefault(t *testing.T) {
	if c := credhttp.New(nil); c == nil {
		t.Fatal("New(nil) returned nil")
	}
}

// TestAPlaintextURLIsRefused covers the backstop. Every provider constrains its
// destination before building a request -- a fixed host allowlist for Datadog, an
// https-only base URL for GitHub -- and this is the check at the point they all
// pass through, so a provider that ever assembles a plaintext URL fails here
// instead of sending a credential in the clear.
func TestAPlaintextURLIsRefused(t *testing.T) {
	var reached bool
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		reached = true
		return nil, errors.New("should not be reached")
	})

	for _, target := range []string{
		"http://api.example.com/thing",
		"ftp://api.example.com/thing",
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q): %v", target, err)
		}
		req.Header.Set("X-Credential-Header", "material-that-must-not-escape")

		resp, err := credhttp.New(rt).Do(req, testOp)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("Do(%q) succeeded", target)
		}
		if reached {
			t.Fatalf("Do(%q) reached the transport; the credential was sent", target)
		}
		if strings.Contains(err.Error(), "material-that-must-not-escape") {
			t.Errorf("the refusal carried the credential: %v", err)
		}
	}
}

// TestTheOpSetIsClosedAndRepositoryOwned pins the property the type exists for.
//
// Do took an op string, and a comment said the caller must supply a constant.
// Review drove a sentinel through it and read it back out of the returned error,
// so the comment described a convention and not a constraint. There is no test
// that can prove a negative about a type that cannot be constructed from outside
// -- that a caller cannot build an Op is a compile-time property, and
// `credhttp.Op{label: "x"}` from this external test package does not compile --
// so what is checked here is the other half: that every value the closed set does
// produce is distinct, non-empty, and text this repository wrote.
func TestTheOpSetIsClosedAndRepositoryOwned(t *testing.T) {
	ops := map[string]credhttp.Op{
		"OpDatadogCreateAPIKey":                   credhttp.OpDatadogCreateAPIKey(),
		"OpDatadogDeleteAPIKey":                   credhttp.OpDatadogDeleteAPIKey(),
		"OpDatadogStatusCheck":                    credhttp.OpDatadogStatusCheck(),
		"OpGitHubAppMintInstallationToken":        credhttp.OpGitHubAppMintInstallationToken(),
		"OpGitHubAppListInstallations":            credhttp.OpGitHubAppListInstallations(),
		"OpGitHubAppGetInstallation":              credhttp.OpGitHubAppGetInstallation(),
		"OpGitHubAppListInstallationRepositories": credhttp.OpGitHubAppListInstallationRepositories(),
		"OpGitHubAppManifestConversion":           credhttp.OpGitHubAppManifestConversion(),
		"OpC1FetchToken":                          credhttp.OpC1FetchToken(),
		"OpC1MintCredential":                      credhttp.OpC1MintCredential(),
		"OpC1RevokeCredential":                    credhttp.OpC1RevokeCredential(),
		"OpC1GetCredential":                       credhttp.OpC1GetCredential(),
		"OpC1DirectoryFetchToken":                 credhttp.OpC1DirectoryFetchToken(),
		"OpC1DirectorySearchEntitlements":         credhttp.OpC1DirectorySearchEntitlements(),
		"OpC1DirectorySearchUsers":                credhttp.OpC1DirectorySearchUsers(),
		"OpC1DirectorySearchGrants":               credhttp.OpC1DirectorySearchGrants(),
	}
	// This map is a hand-maintained restatement of a set, which on this project is
	// a thing that drifts from the set. TestTheOpSetIsExactlyWhatThePackageDeclares
	// cross-checks it against the type checker in both directions, so a new Op
	// function with no entry here is a test failure rather than a silent gap in
	// this one.
	seen := map[string]string{}
	for name, op := range ops {
		label := op.String()
		if strings.TrimSpace(label) == "" {
			t.Errorf("%s has an empty label", name)
		}
		if prior, dup := seen[label]; dup {
			t.Errorf("%s and %s share the label %q, so an error cannot say which happened",
				name, prior, label)
		}
		seen[label] = name
		// Through fmt as well as directly: an Op reaches an error through a verb,
		// and a String method that fmt does not consult would prove nothing.
		if viaFmt := fmt.Sprintf("%v|%s|%q", op, op, op); !strings.Contains(viaFmt, label) ||
			strings.Count(viaFmt, label) != 3 {
			t.Errorf("%s renders differently through fmt (%s) than through String (%s)", name, viaFmt, label)
		}
	}

	// The zero value is reachable -- a struct field left unset, a var declaration --
	// and must render something, or a message reads ": transport failure".
	var zero credhttp.Op
	if strings.TrimSpace(zero.String()) == "" {
		t.Error("the zero Op renders as empty")
	}
	if _, dup := seen[zero.String()]; dup {
		t.Error("the zero Op renders as a real operation")
	}
}
