// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package credhttp owns the HTTP policy for every request in this repository
// that carries credential material.
//
// # Why it exists
//
// Two of the four fail-open paths found in review of the first credentials port
// were the same mistake in two places, and the mistake was where the policy
// lived rather than what the policy said:
//
//   - Each provider took an *http.Client from its caller. Redirect refusal is a
//     field on http.Client, so supplying a client -- an advertised option, for
//     tracing or proxying or tests -- silently replaced the refusal with Go's
//     default of following redirects. A synthetic 302 was followed and the second
//     request carried the Datadog administrative key.
//   - Each provider wrapped the error from http.Client.Do with %w. A transport
//     has already seen the authenticated request, so an instrumentation layer
//     that includes request detail in its diagnostics puts the credential in the
//     error. A request-dumping RoundTripper produced errors containing a full
//     DD-API-KEY and a full app JWT.
//
// Both were reachable through the same seam: a caller-supplied HTTP layer meeting
// a credential-bearing request. docs/DECISIONS.md records the general form of the
// lesson -- prefer a construction that cannot express the violation over a check
// that notices it -- so this package is that construction rather than two more
// review comments.
//
// # What the construction is
//
// Client is opaque. It holds an *http.Client and does not expose it, so:
//
//   - There is no way to set CheckRedirect. Refusal is installed by New and is
//     not a field anybody can reach. A caller supplies a http.RoundTripper --
//     which is the part they actually wanted for tracing, proxying or a test --
//     and gets no say over redirect policy at all.
//   - There is no way to obtain a raw error from http.Client.Do. Client.Do is the
//     only method, and it classifies before returning, so no text this process
//     did not write can escape. That covers the transport's own error and the
//     *url.Error wrapper around it, which is itself response-controlled: on a
//     refused redirect, net/http builds the wrapper from the *redirect target*,
//     so even the refusal's own error would have carried a URL out of a Location
//     header.
//   - There is no way to put arbitrary text in the operation label. Do took an
//     op string and a comment said the caller must supply a constant; review
//     drove a sentinel through it and read it back out of the returned error, so
//     the comment described a convention and not a constraint. The label is now an
//     Op, whose values are the closed set of functions below, and Op{} cannot be
//     built with a label from outside this package.
//
// The cost is real and is the point: a caller cannot set a timeout, cannot follow
// a redirect it knows is safe, and gets a status code and a classification
// instead of an upstream diagnostic string. Those are the three things whose
// absence cannot leak a credential.
package credhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// timeout bounds every request. Not configurable: see the package comment. A
// credential-vending call that has not completed in thirty seconds is not going
// to.
//
// It is a backstop and not a policy knob. A caller with its own deadline expresses
// it through the request's context, which every provider here threads from its
// own ctx argument, and the shorter of the two wins. USOSS-8 must honor
// ConductorOne's configurable Config.Timeout that way -- through the context it
// passes -- rather than expecting this value to change.
const timeout = 30 * time.Second

// unnamedOp is what the zero Op renders as.
//
// The zero value is reachable -- var op Op, a struct field left unset -- and it
// must render something rather than an empty string, so a message never reads
// ": transport failure". It is a constant in this repository, like every other
// label here.
const unnamedOp = "an unnamed credential operation"

// Op names the operation a credential-bearing request is attempting.
//
// It is the only detail besides a classification that reaches an error returned by
// Do, which is why it is a type and not a string. The label lives in an
// unexported field, so the set of labels that can exist is exactly the set of
// functions below: no code outside this package can construct an Op carrying text
// of its own, and the invariant that no error here renders foreign text holds by
// construction rather than by every caller remembering to pass a constant.
//
// The cost is that the set is closed and lives here rather than with each
// provider, so adding a provider adds a function below. That is deliberate: a
// closed set is the property being bought, and an open constructor -- NewOp(string)
// -- would sell it back. The provider prefix is part of the label because these
// labels are also what an operator reads in a log.
type Op struct {
	label string
}

// String renders the label. It is safe by construction: every value came from one
// of the functions below.
func (o Op) String() string {
	if o.label == "" {
		return unnamedOp
	}
	return o.label
}

// The closed set of credential-bearing operations in this repository.
//
// These are functions rather than exported variables so that they are immutable:
// an exported var of type Op could be reassigned by any package in the build,
// which could not leak foreign text but could make a log line name the wrong
// operation.

// OpDatadogCreateAPIKey labels a Datadog API key creation.
func OpDatadogCreateAPIKey() Op { return Op{label: "datadog: create API key"} }

// OpDatadogDeleteAPIKey labels a Datadog key deletion.
func OpDatadogDeleteAPIKey() Op { return Op{label: "datadog: delete API key"} }

// OpDatadogStatusCheck labels a Datadog key status read.
func OpDatadogStatusCheck() Op { return Op{label: "datadog: status check"} }

// OpGitHubAppMintInstallationToken labels a GitHub App installation-token mint.
func OpGitHubAppMintInstallationToken() Op {
	return Op{label: "githubapp: mint installation token"}
}

// OpGitHubAppListInstallations labels a GitHub App installation listing. The
// request is authenticated with an app JWT, which is credential material.
func OpGitHubAppListInstallations() Op {
	return Op{label: "githubapp: list installations"}
}

// OpGitHubAppGetInstallation labels a GitHub App single-installation lookup
// by account. Also app-JWT authenticated.
func OpGitHubAppGetInstallation() Op {
	return Op{label: "githubapp: get installation"}
}

// OpGitHubAppListInstallationRepositories labels a listing of the
// repositories one installation can access. The request carries an
// installation access token.
func OpGitHubAppListInstallationRepositories() Op {
	return Op{label: "githubapp: list installation repositories"}
}

// OpGitHubAppManifestConversion labels the one-time exchange of a GitHub App
// Manifest flow's code for the created App's credentials. Unlike every other
// GitHub App operation here, this request carries no credential of AppHub's
// own on the way out -- GitHub's manifest-conversion endpoint requires no
// authentication -- but the response is exactly as sensitive as any other
// app credential (it carries the new App's private key), so it still goes
// through this client rather than a bare http.Client.
func OpGitHubAppManifestConversion() Op {
	return Op{label: "githubapp: manifest conversion"}
}

// OpC1FetchToken labels the ConductorOne access-token exchange. The request
// carries AppHub's own client secret or a signed assertion, so it is
// credential-bearing in both directions.
func OpC1FetchToken() Op { return Op{label: "c1: fetch access token"} }

// OpC1MintCredential labels a ConductorOne credential mint.
func OpC1MintCredential() Op { return Op{label: "c1: mint credential"} }

// OpC1RevokeCredential labels a ConductorOne credential revoke.
func OpC1RevokeCredential() Op { return Op{label: "c1: revoke credential"} }

// OpC1GetCredential labels a ConductorOne credential status read.
func OpC1GetCredential() Op { return Op{label: "c1: get credential"} }

// OpC1DirectoryFetchToken labels the ConductorOne access-token exchange made
// by the read-only directory client (credentials/c1directory), which holds a
// separate credential from the vending provider above and so gets its own
// label rather than reusing OpC1FetchToken.
func OpC1DirectoryFetchToken() Op { return Op{label: "c1: directory fetch access token"} }

// OpC1DirectorySearchUsers labels a ConductorOne user-search request, used to
// resolve an email to the ConductorOne user ID that ListUserGroupIDs then
// looks up grants for.
func OpC1DirectorySearchUsers() Op { return Op{label: "c1: directory search users"} }

// OpC1DirectorySearchGrants labels a ConductorOne grants-search request,
// used to read the entitlements one user currently holds.
func OpC1DirectorySearchGrants() Op { return Op{label: "c1: directory search grants"} }

// OpC1DirectorySearchEntitlements labels a ConductorOne entitlement-catalog
// search made by the directory client.
func OpC1DirectorySearchEntitlements() Op { return Op{label: "c1: directory search entitlements"} }

// sharedTransport is the default transport, built once.
//
// It is a clone of http.DefaultTransport rather than http.DefaultTransport
// itself, because that value is process-global and reachable by any dependency
// in an adopter's binary. Connection pooling lives in the transport, so sharing
// one across every Client in the process is what keeps a client-per-App cheap.
var sharedTransport = sync.OnceValue(func() http.RoundTripper {
	return http.DefaultTransport.(*http.Transport).Clone()
})

// Client issues credential-bearing HTTP requests under a policy its caller
// cannot change.
//
// The embedded *http.Client is unexported and there is no accessor. That is the
// enforcement: see the package comment for what it prevents.
type Client struct {
	c *http.Client
}

// New returns a Client using rt as its transport, or a shared default when rt is
// nil.
//
// rt is the whole of what a caller may supply. It is enough for the reasons
// callers actually give -- instrumentation, a proxy, a test double -- and it
// carries no policy: a RoundTripper cannot express a redirect rule, and its
// errors are classified on the way out.
func New(rt http.RoundTripper) *Client {
	if rt == nil {
		rt = sharedTransport()
	}
	return &Client{c: &http.Client{
		Transport:     rt,
		Timeout:       timeout,
		CheckRedirect: refuse,
	}}
}

// Do issues req and returns the response, or an error that carries no text this
// process did not write.
//
// op names what was being attempted and is the only detail in the returned error
// besides the classification. It is an Op rather than a string so that "never
// built from a response, a metadata value, or anything else that arrived from
// outside" is a property of the type instead of a rule at each call site.
func (c *Client) Do(req *http.Request, op Op) (*http.Response, error) {
	// Every request that reaches here carries a credential, and every provider
	// that builds one has already constrained where it may go: credentials/datadog
	// against a fixed host allowlist, internal/githubapp against an https-only
	// base URL. This is the backstop for that, at the one point all of them pass
	// through -- a provider that ever builds a plaintext URL by accident fails
	// here rather than sending the credential in the clear.
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%s: refusing to send a credential over a non-https URL", op)
	}

	// G704 flags this as SSRF-by-taint because the request URL reaches here from a
	// caller. That is true of every HTTP client, and this is the one place in the
	// repository where the constraints on it are all satisfied at once: the https
	// check above, credentials/datadog's fixed host allowlist
	// (TestSiteAllowlist), and internal/githubapp's base-URL validation
	// (TestAPIBaseURLMustBeAnHTTPSURL) are each a committed test that fails if the
	// constraint is removed. Suppressing it here rather than at four call sites is
	// what keeps this function the only place a credential-bearing request is
	// issued.
	resp, err := c.c.Do(req) //nolint:gosec // G704: destination is constrained by the caller's allowlist plus the https check above; both are covered by mutation-tested fixtures
	if err != nil {
		// The request's own context is consulted as well as the returned error.
		// net/http does not reliably unwrap to context.Canceled when it
		// short-circuits a request whose context is already done, and "the caller
		// gave up" is the one classification worth getting right for a reason other
		// than disclosure: it is the only failure here that must not be retried.
		return nil, classify(op, err, req.Context().Err())
	}
	return resp, nil
}

// refuse is the CheckRedirect for every Client.
//
// It returns the bare sentinel. An earlier version named the redirect target,
// which is a value out of an upstream Location header -- the same class of
// mistake as formatting a response body into an error, and found by applying that
// lesson rather than by a second review.
func refuse(*http.Request, []*http.Request) error {
	return credentials.ErrRedirectRefused
}

// classify converts an error from http.Client.Do into one built only from
// constants in this repository.
//
// The four outcomes are the distinctions a caller can act on. Everything else
// collapses into one transient failure, deliberately: a DNS error, a TLS
// verification failure and a connection reset differ in ways worth knowing and in
// no way worth a credential, and there is no subset of a foreign error's text
// that is safe by construction. An operator who needs the detail has the
// transport itself, which is where it belongs -- their instrumentation may log
// what it likes, because the leak here was this package handing that text back as
// a return value.
func classify(op Op, err, ctxErr error) error {
	canceled := errors.Is(err, context.Canceled) || errors.Is(ctxErr, context.Canceled)
	expired := errors.Is(err, context.DeadlineExceeded) || errors.Is(ctxErr, context.DeadlineExceeded)
	switch {
	case errors.Is(err, credentials.ErrRedirectRefused):
		// Not transient: retrying a misconfiguration is not a retry policy.
		return fmt.Errorf("%s: %w", op, credentials.ErrRedirectRefused)
	case canceled:
		// The caller gave up. Nothing upstream is wrong, so nothing should retry.
		return fmt.Errorf("%s: %w", op, context.Canceled)
	case expired:
		return fmt.Errorf("%s: %w: %w", op, credentials.ErrTransient, context.DeadlineExceeded)
	default:
		return fmt.Errorf("%s: transport failure: %w", op, credentials.ErrTransient)
	}
}
