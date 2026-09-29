// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials/c1"
)

// env builds a getenv function from a map, which is what keeps these tests
// hermetic: no process environment, no ordering between parallel tests.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// TestConfigFromEnvUnsetMeansNotConfigured is the c1-optional requirement stated
// as a test: an adopter who sets none of these variables gets ErrNotConfigured,
// which the caller reads as "this deployment does not use ConductorOne" and
// carries on with the AWS-native path.
func TestConfigFromEnvUnsetMeansNotConfigured(t *testing.T) {
	cfg, err := c1.ConfigFromEnv(env(nil))
	if !errors.Is(err, c1.ErrNotConfigured) {
		t.Fatalf("ConfigFromEnv(empty) error = %v, want ErrNotConfigured", err)
	}
	if cfg.Enabled() {
		t.Error("the zero Config reports Enabled")
	}
}

func TestConfigFromEnvHappyPath(t *testing.T) {
	cfg, err := c1.ConfigFromEnv(env(map[string]string{
		c1.EnvTenantURL:       "https://tenant.example.com/",
		c1.EnvClientID:        "client-id",
		c1.EnvClientSecretRef: "/apphub/c1/client-secret",
		c1.EnvRequestTimeout:  "5s",
	}))
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if !cfg.Enabled() {
		t.Error("Enabled() = false for a fully configured Config")
	}
	if cfg.Mode() != c1.AuthModeClientSecret {
		t.Errorf("Mode() = %q, want the client_secret default", cfg.Mode())
	}
	if cfg.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %s, want 5s", cfg.Timeout())
	}
	if got := cfg.BaseURL(); got != "https://tenant.example.com" {
		t.Errorf("BaseURL() = %q, want the trailing slash trimmed", got)
	}
	// The secret is a reference. Nothing in the configuration path ever holds the
	// value, so nothing in the configuration path can leak it.
	if cfg.ClientSecret.Name != "/apphub/c1/client-secret" {
		t.Errorf("ClientSecret.Name = %q, want the reference", cfg.ClientSecret.Name)
	}
}

func TestConfigFromEnvAcceptsTheSecretFromTheEnvironment(t *testing.T) {
	const material = "c1-client-secret-canary"
	cfg, err := c1.ConfigFromEnv(env(map[string]string{
		c1.EnvTenantURL:    "https://tenant.example.com",
		c1.EnvClientID:     "client-id",
		c1.EnvClientSecret: material,
	}))
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.ClientSecret.EnvVar != c1.EnvClientSecret || cfg.ClientSecret.Name != "" {
		t.Errorf("ClientSecret = %+v, want an EnvVar locator and no Name", cfg.ClientSecret)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), material) {
		t.Error("Config held the secret material")
	}
}

func TestConfigFromEnvRejectsSecretAndSecretRefTogether(t *testing.T) {
	_, err := c1.ConfigFromEnv(env(map[string]string{
		c1.EnvTenantURL:       "https://tenant.example.com",
		c1.EnvClientID:        "client-id",
		c1.EnvClientSecret:    "material",
		c1.EnvClientSecretRef: "/apphub/c1/client-secret",
	}))
	if err == nil {
		t.Fatal("ConfigFromEnv accepted both the secret and a reference")
	}
}

func TestConfigFromEnvRejectsPartialConfiguration(t *testing.T) {
	// Half-configured is the dangerous state: it looks intentional and does not
	// work, so it must stop startup rather than silently disable vending.
	tests := []struct {
		name string
		kv   map[string]string
	}{
		{"tenant only", map[string]string{c1.EnvTenantURL: "https://tenant.example.com"}},
		{"client id only", map[string]string{c1.EnvClientID: "client-id"}},
		{"no client secret in client_secret mode", map[string]string{
			c1.EnvTenantURL: "https://tenant.example.com",
			c1.EnvClientID:  "client-id",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c1.ConfigFromEnv(env(tc.kv))
			if err == nil {
				t.Fatal("ConfigFromEnv accepted a partial configuration")
			}
			if errors.Is(err, c1.ErrNotConfigured) {
				t.Fatalf("ConfigFromEnv reported not-configured for a partial configuration: %v", err)
			}
		})
	}
}

func TestValidateRejectsUnsafeTenantURLs(t *testing.T) {
	base := map[string]string{
		c1.EnvClientID:        "client-id",
		c1.EnvClientSecretRef: "/apphub/c1/client-secret",
	}
	for _, tenant := range []string{
		"http://tenant.example.com",            // client_credentials puts the secret in the body
		"https://user:pass@tenant.example.com", // userinfo smuggles a different host
		"https://tenant.example.com?x=1",       // a base URL's query string rides on every request
		"https://tenant.example.com#f",         // likewise a fragment
		"https:///no-host",                     // no host at all
		"tenant.example.com",                   // no scheme
		"://",                                  // unparseable
	} {
		kv := map[string]string{c1.EnvTenantURL: tenant}
		for k, v := range base {
			kv[k] = v
		}
		if _, err := c1.ConfigFromEnv(env(kv)); err == nil {
			t.Errorf("ConfigFromEnv accepted tenant URL %q", tenant)
		}
	}
}

func TestValidateRejectsUnknownAuthMode(t *testing.T) {
	_, err := c1.ConfigFromEnv(env(map[string]string{
		c1.EnvTenantURL:       "https://tenant.example.com",
		c1.EnvClientID:        "client-id",
		c1.EnvClientSecretRef: "/apphub/c1/client-secret",
		c1.EnvAuthMode:        "trust-me",
	}))
	if err == nil {
		t.Fatal("ConfigFromEnv accepted an unknown auth mode")
	}
}

func TestFederatedJWTModeNeedsNoSharedSecret(t *testing.T) {
	cfg, err := c1.ConfigFromEnv(env(map[string]string{
		c1.EnvTenantURL: "https://tenant.example.com",
		c1.EnvClientID:  "client-id",
		c1.EnvAuthMode:  string(c1.AuthModeFederatedJWT),
	}))
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if !cfg.ClientSecret.IsZero() {
		t.Error("federated_jwt mode should not require a client secret reference")
	}
}

func TestConfigFromEnvRejectsBadTimeout(t *testing.T) {
	base := map[string]string{
		c1.EnvTenantURL:       "https://tenant.example.com",
		c1.EnvClientID:        "client-id",
		c1.EnvClientSecretRef: "/apphub/c1/client-secret",
	}
	for _, raw := range []string{"soon", "-5s", "0"} {
		kv := map[string]string{c1.EnvRequestTimeout: raw}
		for k, v := range base {
			kv[k] = v
		}
		if _, err := c1.ConfigFromEnv(env(kv)); err == nil {
			t.Errorf("ConfigFromEnv accepted %s=%q", c1.EnvRequestTimeout, raw)
		}
	}
}
