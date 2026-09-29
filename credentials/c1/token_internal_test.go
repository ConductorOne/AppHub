// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

// The token cache's behaviour is a function of time, so these tests are inside
// the package: they pin the clock rather than sleeping. Everything else about the
// client is tested from outside, against the exported surface.
//
// They deliberately do not call t.Parallel: they replace a package-level clock.

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// countingTransport answers every token request from a fixed lifetime and counts
// how many it saw.
type countingTransport struct {
	expiresIn int64
	tokens    int
	apiCalls  int
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := `{}`
	if strings.HasSuffix(req.URL.Path, tokenPath) {
		c.tokens++
		body = `{"access_token":"token-` + strconv.Itoa(c.tokens) + `","expires_in":` +
			strconv.FormatInt(c.expiresIn, 10) + `}`
	} else {
		c.apiCalls++
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 upstream",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

type fixedSecrets struct{}

func (fixedSecrets) Resolve(context.Context, credentials.SecretRef) (credentials.Secret, error) {
	return credentials.NewSecret("apphub-client-secret"), nil
}

func internalTestConfig() Config {
	return Config{
		TenantURL:    "https://tenant.example.invalid",
		ClientID:     "apphub-client",
		ClientSecret: credentials.SecretRef{Name: "/run/secrets/c1"},
	}
}

// pinClock replaces the package clock for the duration of a test.
func pinClock(t *testing.T, at *time.Time) {
	t.Helper()
	original := now
	now = func() time.Time { return *at }
	t.Cleanup(func() { now = original })
}

func TestTheTokenIsRefreshedOnceItsCachedLifetimeHasPassed(t *testing.T) {
	clock := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pinClock(t, &clock)

	rt := &countingTransport{expiresIn: 3600}
	client, err := NewClient(internalTestConfig(), Deps{Secrets: fixedSecrets{}, Transport: rt})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ref := Ref{ServicePrincipalID: "sp1111111111111111111111111", CredentialID: "fixture-fixture-11111"}

	// First call fetches.
	if err := client.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rt.tokens != 1 {
		t.Fatalf("token fetches = %d, want 1", rt.tokens)
	}

	// Still inside the cached window: no second fetch. A cache that refetched
	// every call would pass a test that only checked the last call worked.
	clock = clock.Add(time.Hour - tokenRefreshSkew - time.Second)
	if err := client.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rt.tokens != 1 {
		t.Fatalf("token fetches = %d after a call inside the cached window, want 1", rt.tokens)
	}

	// Past the refresh point: exactly one more fetch.
	clock = clock.Add(2 * time.Second)
	if err := client.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rt.tokens != 2 {
		t.Fatalf("token fetches = %d after the cached window lapsed, want 2", rt.tokens)
	}
	if rt.apiCalls != 3 {
		t.Fatalf("api calls = %d, want 3", rt.apiCalls)
	}
}

func TestTheRefreshSkewNeverExceedsHalfTheTokensOwnLifetime(t *testing.T) {
	// Subtracting a fixed five-minute skew from a token that lives for one minute
	// yields an already-expired token and a fresh fetch on every single call --
	// a self-inflicted denial of service against the token endpoint, and one that
	// only shows up against a tenant issuing short-lived tokens.
	//
	// The property, over a population that straddles the fixed skew: a token is
	// always reused for at least a third of its stated lifetime.
	for _, lifetime := range []int64{1, 5, 30, 60, 299, 300, 301, 600, 3600} {
		clock := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		pinClock(t, &clock)

		rt := &countingTransport{expiresIn: lifetime}
		client, err := NewClient(internalTestConfig(), Deps{Secrets: fixedSecrets{}, Transport: rt})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		ref := Ref{ServicePrincipalID: "sp1111111111111111111111111", CredentialID: "fixture-fixture-11111"}

		if err := client.Revoke(context.Background(), ref); err != nil {
			t.Fatalf("lifetime %ds: Revoke: %v", lifetime, err)
		}
		if rt.tokens != 1 {
			t.Fatalf("lifetime %ds: token fetches = %d, want 1", lifetime, rt.tokens)
		}

		// A third of the way through the token's own life, it must still be cached.
		clock = clock.Add(time.Duration(lifetime) * time.Second / 3)
		if err := client.Revoke(context.Background(), ref); err != nil {
			t.Fatalf("lifetime %ds: Revoke: %v", lifetime, err)
		}
		if rt.tokens != 1 {
			t.Errorf("lifetime %ds: refetched after a third of the lifetime (fetches = %d)", lifetime, rt.tokens)
		}

		// And past the whole lifetime it must have been refreshed, so the cap does
		// not turn into "cache forever".
		clock = clock.Add(time.Duration(lifetime) * time.Second)
		if err := client.Revoke(context.Background(), ref); err != nil {
			t.Fatalf("lifetime %ds: Revoke: %v", lifetime, err)
		}
		if rt.tokens != 2 {
			t.Errorf("lifetime %ds: did not refresh after the stated lifetime elapsed (fetches = %d)", lifetime, rt.tokens)
		}
	}
}
