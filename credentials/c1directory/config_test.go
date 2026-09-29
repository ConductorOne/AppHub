// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials/c1directory"
)

// env builds a getenv function from a map, which is what keeps these tests
// hermetic: no process environment, no ordering between parallel tests.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestConfigFromEnvUnsetMeansNotConfigured(t *testing.T) {
	cfg, err := c1directory.ConfigFromEnv(env(nil))
	if !errors.Is(err, c1directory.ErrNotConfigured) {
		t.Fatalf("ConfigFromEnv(empty) error = %v, want ErrNotConfigured", err)
	}
	if cfg.Enabled() {
		t.Error("the zero Config reports Enabled")
	}
}

func TestConfigFromEnvHappyPath(t *testing.T) {
	cfg, err := c1directory.ConfigFromEnv(env(map[string]string{
		c1directory.EnvTenantURL:       "https://tenant.example.com/",
		c1directory.EnvClientID:        "directory-client-id",
		c1directory.EnvClientSecretRef: "/apphub/c1directory/client-secret",
		c1directory.EnvRequestTimeout:  "5s",
	}))
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if !cfg.Enabled() {
		t.Error("Enabled() = false for a fully configured Config")
	}
	if cfg.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %s, want 5s", cfg.Timeout())
	}
	if got := cfg.BaseURL(); got != "https://tenant.example.com" {
		t.Errorf("BaseURL() = %q, want the trailing slash trimmed", got)
	}
	if cfg.ClientSecret.Name != "/apphub/c1directory/client-secret" {
		t.Errorf("ClientSecret.Name = %q, want the reference", cfg.ClientSecret.Name)
	}
}

func TestConfigFromEnvAcceptsTheSecretFromTheEnvironment(t *testing.T) {
	const material = "directory-client-secret-canary"
	cfg, err := c1directory.ConfigFromEnv(env(map[string]string{
		c1directory.EnvTenantURL:    "https://tenant.example.com",
		c1directory.EnvClientID:     "directory-client-id",
		c1directory.EnvClientSecret: material,
	}))
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.ClientSecret.EnvVar != c1directory.EnvClientSecret || cfg.ClientSecret.Name != "" {
		t.Errorf("ClientSecret = %+v, want an EnvVar locator and no Name", cfg.ClientSecret)
	}
	if strings.Contains(fmt.Sprintf("%+v", cfg), material) {
		t.Error("Config held the secret material")
	}
}

func TestConfigFromEnvRejectsSecretAndSecretRefTogether(t *testing.T) {
	_, err := c1directory.ConfigFromEnv(env(map[string]string{
		c1directory.EnvTenantURL:       "https://tenant.example.com",
		c1directory.EnvClientID:        "directory-client-id",
		c1directory.EnvClientSecret:    "material",
		c1directory.EnvClientSecretRef: "/apphub/c1directory/client-secret",
	}))
	if err == nil {
		t.Fatal("ConfigFromEnv accepted both the secret and a reference")
	}
}

func TestConfigFromEnvIsIndependentOfVendingConfig(t *testing.T) {
	// APPHUB_C1_TENANT_URL (no DIRECTORY segment) is the vending provider's
	// variable. It must not satisfy this package's configuration -- the whole
	// point of a separate namespace is that the two credentials are configured,
	// rotated, and scoped independently.
	_, err := c1directory.ConfigFromEnv(env(map[string]string{
		"APPHUB_C1_TENANT_URL":        "https://tenant.example.com",
		"APPHUB_C1_CLIENT_ID":         "vending-client-id",
		"APPHUB_C1_CLIENT_SECRET_REF": "/apphub/c1/client-secret",
	}))
	if !errors.Is(err, c1directory.ErrNotConfigured) {
		t.Fatalf("ConfigFromEnv read the vending provider's variables: error = %v", err)
	}
}

func TestConfigFromEnvRejectsPartialConfiguration(t *testing.T) {
	tests := []struct {
		name string
		kv   map[string]string
	}{
		{"tenant only", map[string]string{c1directory.EnvTenantURL: "https://tenant.example.com"}},
		{"client id only", map[string]string{c1directory.EnvClientID: "directory-client-id"}},
		{"no client secret", map[string]string{
			c1directory.EnvTenantURL: "https://tenant.example.com",
			c1directory.EnvClientID:  "directory-client-id",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c1directory.ConfigFromEnv(env(tc.kv))
			if err == nil {
				t.Fatal("ConfigFromEnv accepted a partial configuration")
			}
			if errors.Is(err, c1directory.ErrNotConfigured) {
				t.Fatalf("ConfigFromEnv reported not-configured for a partial configuration: %v", err)
			}
		})
	}
}

func TestValidateRejectsUnsafeTenantURLs(t *testing.T) {
	base := map[string]string{
		c1directory.EnvClientID:        "directory-client-id",
		c1directory.EnvClientSecretRef: "/apphub/c1directory/client-secret",
	}
	for _, tenant := range []string{
		"http://tenant.example.com",
		"https://user:pass@tenant.example.com",
		"https://tenant.example.com?x=1",
		"https://tenant.example.com#f",
		"https:///no-host",
		"tenant.example.com",
		"://",
	} {
		kv := map[string]string{c1directory.EnvTenantURL: tenant}
		for k, v := range base {
			kv[k] = v
		}
		if _, err := c1directory.ConfigFromEnv(env(kv)); err == nil {
			t.Errorf("ConfigFromEnv accepted tenant URL %q", tenant)
		}
	}
}

func TestConfigFromEnvRejectsBadTimeout(t *testing.T) {
	base := map[string]string{
		c1directory.EnvTenantURL:       "https://tenant.example.com",
		c1directory.EnvClientID:        "directory-client-id",
		c1directory.EnvClientSecretRef: "/apphub/c1directory/client-secret",
	}
	for _, raw := range []string{"soon", "-5s", "0"} {
		kv := map[string]string{c1directory.EnvRequestTimeout: raw}
		for k, v := range base {
			kv[k] = v
		}
		if _, err := c1directory.ConfigFromEnv(env(kv)); err == nil {
			t.Errorf("ConfigFromEnv accepted %s=%q", c1directory.EnvRequestTimeout, raw)
		}
	}
}
