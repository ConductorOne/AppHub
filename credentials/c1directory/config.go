// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Environment variables an adopter sets to turn on ConductorOne directory
// reads or optional deployment provisioning. None has a default and none has a
// fallback: with none of these set, Enabled is false, nothing constructs a
// client, and no request can reach ConductorOne even by accident. This
// namespace is deliberately separate from credentials/c1's APPHUB_C1_*
// vending variables -- see doc.go.
const (
	// EnvTenantURL is the adopter's ConductorOne tenant base URL. Required.
	EnvTenantURL = "APPHUB_C1_DIRECTORY_TENANT_URL"
	// EnvClientID is the OAuth client identifier. Required.
	EnvClientID = "APPHUB_C1_DIRECTORY_CLIENT_ID"
	// EnvClientSecretRef is a secret-store reference to the OAuth client
	// secret -- a reference, not the secret. Required unless EnvClientSecret
	// is set instead.
	//
	//nolint:gosec // G101: the name of an environment variable that holds a
	// locator, not a credential.
	EnvClientSecretRef = "APPHUB_C1_DIRECTORY_CLIENT_SECRET_REF"
	// EnvClientSecret is the OAuth client secret itself, for ECS secrets
	// injection from Parameter Store. Required unless EnvClientSecretRef is
	// set instead. ConfigFromEnv stores a locator to this variable, never
	// the value.
	//
	//nolint:gosec // G101: the name of an environment variable, not a credential.
	EnvClientSecret = "APPHUB_C1_DIRECTORY_CLIENT_SECRET"
	// EnvRequestTimeout bounds a single API call, as a Go duration. Optional.
	EnvRequestTimeout = "APPHUB_C1_DIRECTORY_REQUEST_TIMEOUT"
)

// DefaultRequestTimeout bounds one ConductorOne API call. Union Station's
// own client uses a 30s http.Client timeout for the same calls.
const DefaultRequestTimeout = 30 * time.Second

// Config is everything an adopter configures to use ConductorOne directory
// reads and optional deployment provisioning.
//
// The zero value is "ConductorOne directory and provisioning are not
// configured", which is a supported and fully functional way to run AppHub.
type Config struct {
	// TenantURL is the adopter's tenant base URL. No default.
	TenantURL string
	// ClientID is the OAuth client identifier. Not a secret.
	ClientID string
	// ClientSecret locates the OAuth client secret. A reference, resolved at
	// use, never stored in Config: either a file path or the name of an
	// environment variable ECS injected from Parameter Store.
	ClientSecret credentials.SecretRef
	// RequestTimeout bounds one API call. Zero means DefaultRequestTimeout.
	RequestTimeout time.Duration
}

// ErrNotConfigured means no directory configuration is present. Not a
// failure: it is how a deployment says it does not use optional ConductorOne
// directory or provisioning features.
var ErrNotConfigured = errors.New("c1directory: not configured")

// The configuration refusals. Sentinels rather than formatted messages for the
// same reason credentials/c1's are: the environment variable's name locates
// the mistake without rendering an operator-supplied value.
var (
	ErrTenantURLNotHTTPS   = errors.New("c1directory: the tenant URL must use https")
	ErrTimeoutNotADuration = errors.New("c1directory: the request timeout is not a valid duration")
	ErrTimeoutNotPositive  = errors.New("c1directory: the request timeout must be positive")
)

// Enabled reports whether enough is configured to attempt a ConductorOne call.
func (c Config) Enabled() bool {
	return c.TenantURL != "" || c.ClientID != "" || !c.ClientSecret.IsZero()
}

// Validate checks the configuration, refusing anything that would send an
// adopter's OAuth secret somewhere unintended. Mirrors credentials/c1
// Config.Validate's URL rules exactly; see that package for the reasoning.
func (c Config) Validate() error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	if c.TenantURL == "" {
		return fmt.Errorf("c1directory: %s is required", EnvTenantURL)
	}
	if c.ClientID == "" {
		return fmt.Errorf("c1directory: %s is required", EnvClientID)
	}
	if c.ClientSecret.IsZero() {
		return fmt.Errorf("c1directory: %s or %s is required", EnvClientSecret, EnvClientSecretRef)
	}

	u, err := url.Parse(c.TenantURL)
	if err != nil {
		return fmt.Errorf("c1directory: %s is not a valid URL", EnvTenantURL)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %s", ErrTenantURLNotHTTPS, EnvTenantURL)
	}
	if u.Host == "" {
		return fmt.Errorf("c1directory: %s must include a host", EnvTenantURL)
	}
	if u.User != nil {
		return fmt.Errorf("c1directory: %s must not embed credentials", EnvTenantURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("c1directory: %s must not include a query or fragment", EnvTenantURL)
	}
	return nil
}

// Timeout returns the effective per-call timeout.
func (c Config) Timeout() time.Duration {
	if c.RequestTimeout <= 0 {
		return DefaultRequestTimeout
	}
	return c.RequestTimeout
}

// BaseURL returns the tenant URL with any trailing slash removed, so that
// paths can be appended without producing a double slash.
func (c Config) BaseURL() string {
	return strings.TrimSuffix(c.TenantURL, "/")
}

// ConfigFromEnv builds a Config from a lookup function -- os.Getenv in
// production, a map in a test.
//
// It returns ErrNotConfigured when nothing is set. A caller treats that as
// "this deployment does not use optional ConductorOne features" and carries
// on; any other error is a misconfiguration and should stop startup.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		TenantURL: strings.TrimSpace(getenv(EnvTenantURL)),
		ClientID:  strings.TrimSpace(getenv(EnvClientID)),
	}
	secretEnv := strings.TrimSpace(getenv(EnvClientSecret))
	secretRef := strings.TrimSpace(getenv(EnvClientSecretRef))
	if secretEnv != "" && secretRef != "" {
		return Config{}, fmt.Errorf("c1directory: set %s or %s, not both", EnvClientSecret, EnvClientSecretRef)
	}
	if secretEnv != "" {
		cfg.ClientSecret = credentials.SecretRef{EnvVar: EnvClientSecret}
	} else if secretRef != "" {
		cfg.ClientSecret = credentials.SecretRef{Name: secretRef}
	}
	if raw := strings.TrimSpace(getenv(EnvRequestTimeout)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("%w: %s", ErrTimeoutNotADuration, EnvRequestTimeout)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("%w: %s", ErrTimeoutNotPositive, EnvRequestTimeout)
		}
		cfg.RequestTimeout = d
	}
	if !cfg.Enabled() {
		return Config{}, ErrNotConfigured
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
