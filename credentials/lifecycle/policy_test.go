// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle_test

import (
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

func TestClampTTLNeverWidens(t *testing.T) {
	policy := lifecycle.ProviderPolicy{
		Enabled:      true,
		AllowedTypes: []credentials.CredentialType{credentials.CredentialTypeDynamic},
		DefaultTTL:   map[credentials.CredentialType]time.Duration{credentials.CredentialTypeDynamic: time.Hour},
		MaxTTL:       map[credentials.CredentialType]time.Duration{credentials.CredentialTypeDynamic: 4 * time.Hour},
	}

	tests := []struct {
		name      string
		requested time.Duration
		want      time.Duration
	}{
		{"unset takes the policy default", 0, time.Hour},
		{"negative takes the policy default", -time.Hour, time.Hour},
		{"within the cap is honored", 2 * time.Hour, 2 * time.Hour},
		{"above the cap is clamped", 72 * time.Hour, 4 * time.Hour},
		{"exactly the cap is honored", 4 * time.Hour, 4 * time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.ClampTTL(credentials.CredentialTypeDynamic, tc.requested); got != tc.want {
				t.Errorf("ClampTTL(%s) = %s, want %s", tc.requested, got, tc.want)
			}
		})
	}
}

// TestClampTTLBoundsAnUnconfiguredPolicy is the property that matters most: an
// operator who configures nothing still gets a credential that dies on its own.
func TestClampTTLBoundsAnUnconfiguredPolicy(t *testing.T) {
	var empty lifecycle.ProviderPolicy

	if got := empty.ClampTTL(credentials.CredentialTypeStatic, 0); got != lifecycle.FallbackDefaultTTL {
		t.Errorf("ClampTTL(unset) = %s, want FallbackDefaultTTL %s", got, lifecycle.FallbackDefaultTTL)
	}
	if got := empty.ClampTTL(credentials.CredentialTypeStatic, 30*24*time.Hour); got != lifecycle.FallbackMaxTTL {
		t.Errorf("ClampTTL(30d) = %s, want FallbackMaxTTL %s", got, lifecycle.FallbackMaxTTL)
	}
}

// TestPolicyAllowsNothingByDefault is a regression test: an empty AllowedTypes
// used to mean "static only", so the unconfigured state issued exactly the kind
// of credential the platform then has to remember to tear down.
func TestPolicyAllowsNothingByDefault(t *testing.T) {
	var empty lifecycle.ProviderPolicy
	if empty.Allows(credentials.CredentialTypeStatic) {
		t.Error("an unconfigured policy must not allow static")
	}
	if empty.Allows(credentials.CredentialTypeDynamic) {
		t.Error("an unconfigured policy must not allow dynamic")
	}

	dynamicOnly := lifecycle.ProviderPolicy{AllowedTypes: []credentials.CredentialType{credentials.CredentialTypeDynamic}}
	if dynamicOnly.Allows(credentials.CredentialTypeStatic) {
		t.Error("a dynamic-only policy should not allow static")
	}
	if !dynamicOnly.Allows(credentials.CredentialTypeDynamic) {
		t.Error("a dynamic policy should allow dynamic")
	}
}

func TestCheckScopeDistinguishesUnscopedFromEmptyScope(t *testing.T) {
	// nil: not scope-limited, authorized elsewhere.
	if err := lifecycle.CheckScope(nil, "example", credentials.CredentialTypeDynamic, time.Hour); err != nil {
		t.Errorf("CheckScope(nil) = %v, want nil", err)
	}
	// empty non-nil: a caller with no permissions at all gets nothing.
	if err := lifecycle.CheckScope([]lifecycle.CallerScope{}, "example", credentials.CredentialTypeDynamic, time.Hour); !errors.Is(err, lifecycle.ErrOutOfScope) {
		t.Errorf("CheckScope(empty) = %v, want ErrOutOfScope", err)
	}
}

func TestCheckScopeNarrows(t *testing.T) {
	scopes := []lifecycle.CallerScope{{
		ProviderID: "example",
		Types:      []credentials.CredentialType{credentials.CredentialTypeDynamic},
		MaxTTL:     2 * time.Hour,
	}}

	tests := []struct {
		name     string
		provider string
		credType credentials.CredentialType
		ttl      time.Duration
		wantErr  bool
	}{
		{"in scope", "example", credentials.CredentialTypeDynamic, time.Hour, false},
		{"at the scope's TTL ceiling", "example", credentials.CredentialTypeDynamic, 2 * time.Hour, false},
		{"another provider", "datadog", credentials.CredentialTypeDynamic, time.Hour, true},
		{"another type", "example", credentials.CredentialTypeStatic, time.Hour, true},
		{"longer than the scope allows", "example", credentials.CredentialTypeDynamic, 8 * time.Hour, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := lifecycle.CheckScope(scopes, tc.provider, tc.credType, tc.ttl)
			if tc.wantErr != (err != nil) {
				t.Fatalf("CheckScope() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, lifecycle.ErrOutOfScope) {
				t.Errorf("CheckScope() error = %v, want ErrOutOfScope", err)
			}
		})
	}
}

func TestStatusTerminalAndExpiry(t *testing.T) {
	for _, s := range []lifecycle.Status{lifecycle.StatusRevoked, lifecycle.StatusExpired, lifecycle.StatusOrphaned} {
		if !s.Terminal() {
			t.Errorf("%s should be terminal", s)
		}
	}
	for _, s := range []lifecycle.Status{lifecycle.StatusPending, lifecycle.StatusActive, lifecycle.StatusPendingRevoke} {
		if s.Terminal() {
			t.Errorf("%s should not be terminal", s)
		}
	}

	now := time.Now().UTC()
	rec := &lifecycle.Record{ExpiresAt: now.Add(-time.Minute)}
	if !rec.Expired(now) {
		t.Error("a record whose ExpiresAt has passed should report expired")
	}
	if (&lifecycle.Record{ExpiresAt: now.Add(time.Hour)}).Expired(now) {
		t.Error("a record expiring later should not report expired")
	}
	if (&lifecycle.Record{}).Expired(now) {
		t.Error("a record with no expiry should not report expired")
	}
}

func TestStatusFromProviderKeepsRecordStateOnUnknown(t *testing.T) {
	// A provider outage must not tear down working credentials.
	if got := lifecycle.StatusFromProvider(lifecycle.StatusActive, credentials.CredentialStatusUnknown); got != lifecycle.StatusActive {
		t.Errorf("StatusFromProvider(active, unknown) = %s, want active", got)
	}
	if got := lifecycle.StatusFromProvider(lifecycle.StatusActive, credentials.CredentialStatusRevoked); got != lifecycle.StatusRevoked {
		t.Errorf("StatusFromProvider(active, revoked) = %s, want revoked", got)
	}
	if got := lifecycle.StatusFromProvider(lifecycle.StatusPending, credentials.CredentialStatusActive); got != lifecycle.StatusActive {
		t.Errorf("StatusFromProvider(pending, active) = %s, want active", got)
	}
}
