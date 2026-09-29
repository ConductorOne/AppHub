// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// RegisterFunc is the signature of this package's single entry point.
//
//	func Register(reg *credentials.ProviderRegistry, cfg Config, deps Deps) error
//
// There is exactly one, and that is the point. Registering the ConductorOne
// provider is the only reason any code outside this package ever imports it, and
// the repository's import boundary permits exactly one composition root to do so
// (docs/design/credential-vending.md §11.3). A package with two entry points
// would invite a second import site, and a second import site is a second place
// for the boundary to be widened.
//
// Register must:
//
//   - return ErrNotConfigured, having registered nothing, when cfg is empty. A
//     deployment that does not use ConductorOne calls this and carries on.
//   - validate cfg and return an error without registering anything if it is
//     half-configured. A deployment that believes it has ConductorOne vending and
//     does not is worse than one that fails to start.
//   - build the provider and register it, returning whatever
//     ProviderRegistry.Register returns.
//
// It must not dial ConductorOne. Startup is not the place to discover that a
// tenant is unreachable, and a provider that cannot be registered without a
// working network cannot be registered in an air-gapped test either.
type RegisterFunc func(reg *credentials.ProviderRegistry, cfg Config, deps Deps) error

// Register is the pinned entry point. See RegisterFunc.
//
// The order of the checks is the contract: nothing is constructed and nothing is
// registered until the configuration is known good, so a half-configured
// deployment fails with an empty registry rather than a partly populated one.
func Register(reg *credentials.ProviderRegistry, cfg Config, deps Deps) error {
	if reg == nil {
		return errors.New("c1: a provider registry is required")
	}
	if !cfg.Enabled() {
		return ErrNotConfigured
	}
	client, err := NewClient(cfg, deps)
	if err != nil {
		return err
	}
	provider, err := NewProvider(client)
	if err != nil {
		return err
	}
	return reg.Register(provider)
}

// The signature is pinned in code and not only in the doc comment above, so that
// changing it is a build failure in this package rather than a discrepancy a
// reader has to notice.
var _ RegisterFunc = Register

// Deps are the collaborators the ConductorOne provider needs from its host.
//
// They are interfaces rather than concrete types because every one of them is a
// thing a test must be able to replace: a secret store, a signing key, and a
// network client are exactly the three dependencies that make a package
// untestable when they are wired in directly.
type Deps struct {
	// Secrets resolves cfg.ClientSecret at use. Required in AuthModeClientSecret.
	//
	// Resolution happens per token fetch rather than once at startup, so rotating
	// the client secret in the store takes effect without a redeploy -- and so the
	// secret is not sitting in a long-lived field for the lifetime of the process.
	Secrets SecretResolver

	// Assertions signs the JWT presented in AuthModeFederatedJWT. Required in that
	// mode, ignored otherwise.
	//
	// The implementation is the platform's existing OIDC issuer, whose signing key
	// lives in a KMS or HSM. Keeping it behind an interface means this package
	// never holds key material of any kind.
	Assertions AssertionSigner

	// Transport is the HTTP transport used for every call. Optional: nil means the
	// shared default in internal/credhttp.
	//
	// It is a http.RoundTripper and not an *http.Client, and that is the whole
	// point of the field's shape. Redirect refusal is a field on http.Client, so an
	// earlier version of this field -- which took a client and documented that the
	// caller was "responsible for" not following redirects -- delegated a security
	// invariant to a caller who had supplied a client for an unrelated reason.
	// Review of USOSS-7 verified that exact delegation being defeated in two other
	// providers: an ordinary replacement client followed a synthetic 302 and the
	// second request carried the administrative credential. This field was changed
	// before USOSS-8 implemented against it, so the defect could not be written a
	// third time.
	//
	// A RoundTripper cannot express a redirect policy. Every client here is built
	// with credhttp.New, which owns redirect refusal and error classification; see
	// internal/credhttp for why both belong there rather than here.
	Transport http.RoundTripper
}

// validate refuses a Deps that is missing the collaborator cfg's mode needs.
//
// It is checked at construction rather than at first use. A deployment whose
// wiring forgot the secret resolver would otherwise start cleanly, register a
// provider, and fail on the first vend -- which is the moment a person or a
// deploy is waiting on it.
func (d Deps) validate(cfg Config) error {
	switch cfg.Mode() {
	case AuthModeClientSecret:
		if d.Secrets == nil {
			return ErrSecretResolverRequired
		}
	case AuthModeFederatedJWT:
		if d.Assertions == nil {
			return ErrAssertionSignerRequired
		}
	default:
		return ErrUnknownAuthMode
	}
	return nil
}

// The wiring refusals.
var (
	// ErrSecretResolverRequired means Deps.Secrets was nil in a mode that needs
	// it.
	ErrSecretResolverRequired = errors.New("c1: Deps.Secrets is required in " + string(AuthModeClientSecret) + " mode")

	// ErrAssertionSignerRequired means Deps.Assertions was nil in a mode that
	// needs it.
	ErrAssertionSignerRequired = errors.New("c1: Deps.Assertions is required in " + string(AuthModeFederatedJWT) + " mode")
)

// SecretResolver reads a secret from the deployment's secret store.
type SecretResolver interface {
	Resolve(ctx context.Context, ref credentials.SecretRef) (credentials.Secret, error)
}

// AssertionSigner mints the signed assertion exchanged for a ConductorOne access
// token in AuthModeFederatedJWT.
//
// Whether ConductorOne accepts such an assertion is assumption A8 in
// docs/design/credential-vending.md. USOSS-8 could neither confirm nor refute it
// from the API surface available, so the mode is implemented to RFC 7523 §2.2 and
// has never been run against ConductorOne. The interface exists so that the
// answer changes one implementation rather than the shape of Config.
type AssertionSigner interface {
	// SignAssertion returns a signed assertion for the given audience, valid for
	// ttl. The returned value is credential material.
	SignAssertion(ctx context.Context, audience string, ttl time.Duration) (credentials.Secret, error)
}
