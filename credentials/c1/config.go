// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Environment variables an adopter sets to turn ConductorOne vending on. Every
// one of them is empty by default and none has a fallback, which is the
// mechanism that keeps ConductorOne optional: with none of these set, Enabled is
// false, nothing registers a provider, and no request can reach ConductorOne
// even by accident.
//
// There is no default tenant URL, no default audience, and no hostname of any
// kind compiled into this package. An adopter's tenant URL is theirs; a default
// would either be wrong for them or would be somebody else's tenant.
const (
	// EnvTenantURL is the adopter's ConductorOne tenant base URL, e.g.
	// https://tenant.example.com. Required.
	EnvTenantURL = "APPHUB_C1_TENANT_URL"
	// EnvClientID is the OAuth client identifier. Required.
	EnvClientID = "APPHUB_C1_CLIENT_ID"
	// EnvClientSecretRef is a secret-store reference to the OAuth client secret --
	// a reference, not the secret. Required for AuthModeClientSecret unless
	// EnvClientSecret is set instead.
	//
	//nolint:gosec // G101: this is the name of an environment variable that holds
	// a locator, not a credential.
	EnvClientSecretRef = "APPHUB_C1_CLIENT_SECRET_REF"
	// EnvClientSecret is the OAuth client secret itself, for ECS secrets
	// injection from Parameter Store. Required for AuthModeClientSecret unless
	// EnvClientSecretRef is set instead. ConfigFromEnv stores a locator to this
	// variable, never the value.
	//
	//nolint:gosec // G101: the name of an environment variable, not a credential.
	EnvClientSecret = "APPHUB_C1_CLIENT_SECRET"
	// EnvAuthMode selects how AppHub authenticates: "client_secret" or
	// "federated_jwt". Optional; defaults to client_secret.
	EnvAuthMode = "APPHUB_C1_AUTH_MODE"
	// EnvAudience overrides the audience asserted in federated_jwt mode. Optional.
	EnvAudience = "APPHUB_C1_AUDIENCE"
	// EnvRequestTimeout bounds a single API call, as a Go duration. Optional.
	EnvRequestTimeout = "APPHUB_C1_REQUEST_TIMEOUT"
)

// AuthMode is how AppHub proves to ConductorOne that it is AppHub.
type AuthMode string

const (
	// AuthModeClientSecret is the OAuth 2.0 client-credentials grant: AppHub
	// posts a client ID and secret to the tenant's token endpoint and gets a
	// bearer token back. This is the mode the source system's ConductorOne client
	// uses today (backend/internal/conductorone/client.go:100-155), so it is the
	// one that is known to work.
	//
	// Its cost is a long-lived shared secret. AppHub never writes it down -- it
	// holds a reference and resolves it from the secret store on use -- but the
	// secret exists, and whoever holds it can act as AppHub.
	AuthModeClientSecret AuthMode = "client_secret"

	// AuthModeFederatedJWT exchanges a token AppHub signs itself, with its own
	// key, for a ConductorOne access token. There is then no shared secret to
	// leak: ConductorOne trusts a public key it fetches from AppHub's JWKS
	// endpoint, and compromising the signing key requires compromising the KMS or
	// HSM holding it.
	//
	// This is the mode to prefer where it is available. Whether a given
	// ConductorOne tenant supports it is an assumption this design cannot verify
	// from the source repository -- see docs/design/credential-vending.md, which
	// lists it as unverified.
	AuthModeFederatedJWT AuthMode = "federated_jwt"
)

// DefaultRequestTimeout bounds one ConductorOne API call.
//
// It is short on purpose. A vend request has a person or a deploy waiting on it,
// and a call that hangs is worse than a call that fails: the credential may have
// been created upstream, which is the ambiguous case the lifecycle layer has to
// clean up. Failing fast means fewer records in that state.
const DefaultRequestTimeout = 15 * time.Second

// Config is everything an adopter configures to use ConductorOne-backed vending.
//
// The zero value is "ConductorOne is not configured", which is a supported and
// fully functional way to run AppHub.
type Config struct {
	// TenantURL is the adopter's tenant base URL. No default.
	TenantURL string

	// ClientID is the OAuth client identifier. Not a secret.
	ClientID string

	// ClientSecret locates the OAuth client secret. It is a reference so that
	// Config never holds the material: either a file path (EnvClientSecretRef)
	// or the name of an environment variable ECS injected from Parameter Store
	// (EnvClientSecret). The secret is resolved at use.
	ClientSecret credentials.SecretRef

	// AuthMode selects the authentication scheme. Empty means
	// AuthModeClientSecret.
	AuthMode AuthMode

	// Audience is the audience AppHub asserts in AuthModeFederatedJWT. Empty
	// means the tenant URL.
	Audience string

	// RequestTimeout bounds one API call. Zero means DefaultRequestTimeout.
	RequestTimeout time.Duration
}

// ErrNotConfigured means no ConductorOne configuration is present. It is not a
// failure: it is how a deployment says it does not use ConductorOne.
var ErrNotConfigured = errors.New("c1: not configured")

// The configuration refusals.
//
// Each is a sentinel rather than a formatted message because each replaced one
// that rendered part of an operator-supplied value. The value is gone from all
// four; the environment variable's name, which is a constant in this repository,
// is what a caller gets and is what actually locates the mistake.
var (
	// ErrTenantURLNotHTTPS means the tenant URL was not https. Plain HTTP is
	// refused because the client-credentials grant puts the OAuth secret in a
	// request body.
	ErrTenantURLNotHTTPS = errors.New("c1: the tenant URL must use https")

	// ErrTimeoutNotADuration means the per-call timeout was not a Go duration.
	ErrTimeoutNotADuration = errors.New("c1: the request timeout is not a valid duration")

	// ErrTimeoutNotPositive means the per-call timeout was zero or negative.
	ErrTimeoutNotPositive = errors.New("c1: the request timeout must be positive")
)

// Enabled reports whether enough is configured to attempt to use ConductorOne.
func (c Config) Enabled() bool {
	return c.TenantURL != "" || c.ClientID != "" || !c.ClientSecret.IsZero()
}

// Validate checks the configuration, refusing anything that would make AppHub
// send an adopter's OAuth secret somewhere unintended.
//
// The URL rules are the interesting ones. Plain HTTP is refused because the
// client-credentials grant puts the secret in a request body. Embedded
// credentials are refused because a userinfo section is a common way to smuggle a
// different host past a naive parse. Query strings and fragments are refused
// because this is a base URL that gets paths appended to it, and a query string
// on a base URL means every request carries an attacker's parameter.
func (c Config) Validate() error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	if c.TenantURL == "" {
		return fmt.Errorf("c1: %s is required", EnvTenantURL)
	}
	if c.ClientID == "" {
		return fmt.Errorf("c1: %s is required", EnvClientID)
	}

	u, err := url.Parse(c.TenantURL)
	if err != nil {
		return fmt.Errorf("c1: %s is not a valid URL", EnvTenantURL)
	}
	if u.Scheme != "https" {
		// The rejected scheme is deliberately not in the message. It is a
		// substring of an operator-supplied value, and this repository's standing
		// invariant is that no error it returns contains text it did not author --
		// an operator who pasted the OAuth client secret into this variable would
		// otherwise have the front of it printed. The variable's name is the
		// useful half anyway.
		return fmt.Errorf("%w: %s", ErrTenantURLNotHTTPS, EnvTenantURL)
	}
	if u.Host == "" {
		return fmt.Errorf("c1: %s must include a host", EnvTenantURL)
	}
	if u.User != nil {
		return fmt.Errorf("c1: %s must not embed credentials", EnvTenantURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("c1: %s must not include a query or fragment", EnvTenantURL)
	}

	switch c.Mode() {
	case AuthModeClientSecret:
		if c.ClientSecret.IsZero() {
			return fmt.Errorf("c1: %s or %s is required in %s mode", EnvClientSecret, EnvClientSecretRef, AuthModeClientSecret)
		}
	case AuthModeFederatedJWT:
		// Nothing further: the signing key is the platform's OIDC issuer, wired in
		// as a dependency rather than configured here.
	default:
		// Not rendered, for the same reason as the scheme above.
		return fmt.Errorf("%w: %s", ErrUnknownAuthMode, EnvAuthMode)
	}
	return nil
}

// Mode returns the effective authentication mode.
func (c Config) Mode() AuthMode {
	if c.AuthMode == "" {
		return AuthModeClientSecret
	}
	return c.AuthMode
}

// Timeout returns the effective per-call timeout.
//
// USOSS-8 must honor this through the request context -- ctx, WithTimeout, the
// context handed to http.NewRequestWithContext -- and not by expecting the HTTP
// client to carry it. Every credential-bearing request in this repository goes
// through internal/credhttp, whose thirty-second timeout is a fixed backstop and
// deliberately not configurable: a timeout is a field on http.Client, and the
// fields of http.Client are what the USOSS-7 review defeated. The shorter of the
// two deadlines wins, so a context built from this value is the whole mechanism,
// and a Config.Timeout above thirty seconds will not take effect.
func (c Config) Timeout() time.Duration {
	if c.RequestTimeout <= 0 {
		return DefaultRequestTimeout
	}
	return c.RequestTimeout
}

// BaseURL returns the tenant URL with any trailing slash removed, so that paths
// can be appended without producing a double slash.
func (c Config) BaseURL() string {
	return strings.TrimSuffix(c.TenantURL, "/")
}

// EffectiveAudience returns the audience asserted in AuthModeFederatedJWT.
//
// Empty Audience means the tenant URL, which is the RFC 7523 default a token
// endpoint expects when nothing else is agreed. It is BaseURL rather than the raw
// TenantURL so that a trailing slash in configuration does not silently change
// the asserted audience.
func (c Config) EffectiveAudience() string {
	if c.Audience != "" {
		return c.Audience
	}
	return c.BaseURL()
}

// ConfigFromEnv builds a Config from a lookup function -- os.Getenv in
// production, a map in a test, which is what keeps the tests hermetic.
//
// It returns ErrNotConfigured when nothing is set. A caller treats that as "this
// deployment does not use ConductorOne" and carries on; any other error is a
// misconfiguration and should stop startup, because the alternative is a
// deployment that believes it has ConductorOne vending and does not.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		TenantURL: strings.TrimSpace(getenv(EnvTenantURL)),
		ClientID:  strings.TrimSpace(getenv(EnvClientID)),
		AuthMode:  AuthMode(strings.TrimSpace(getenv(EnvAuthMode))),
		Audience:  strings.TrimSpace(getenv(EnvAudience)),
	}
	secretEnv := strings.TrimSpace(getenv(EnvClientSecret))
	secretRef := strings.TrimSpace(getenv(EnvClientSecretRef))
	if secretEnv != "" && secretRef != "" {
		return Config{}, fmt.Errorf("c1: set %s or %s, not both", EnvClientSecret, EnvClientSecretRef)
	}
	if secretEnv != "" {
		cfg.ClientSecret = credentials.SecretRef{EnvVar: EnvClientSecret}
	} else if secretRef != "" {
		cfg.ClientSecret = credentials.SecretRef{Name: secretRef}
	}
	if raw := strings.TrimSpace(getenv(EnvRequestTimeout)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			// Neither the value nor time.ParseDuration's own message, which quotes
			// it back. Same reason as the two refusals in Validate.
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
