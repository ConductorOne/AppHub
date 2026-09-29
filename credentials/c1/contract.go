// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// The ConductorOne surface this package is written against.
//
// USOSS-3 declared this interface from the consumer side and marked it
// PROVISIONAL, because the source repository this project ports from calls
// ConductorOne only for directory and entitlement data and contains no vending
// calls at all. USOSS-8's first job was to verify the ten assumptions in
// docs/design/credential-vending.md §9 against the real API before building on
// them. Six held, two are conditional, one is false and one does not apply, and
// the false one changed this file: see the "Verified against" section below and
// §9 of the design document, which now records a verdict and its evidence for
// each.
//
// The interface that came out of that is narrower than the one that went in.
// Three methods, not four: ResolveVend is gone because the operation it named
// does not exist, and a provider cannot implement credentials.CreateRecoverer
// against an API with no idempotency key. Subject and Target are gone because a
// ConductorOne credential belongs to a service principal and carries no separate
// requester; GrantStatus is gone because the credential has no status field.
// Every deletion is a place the design described a capability the API does not
// have, and keeping the shape would have meant a provider whose declared
// capabilities were claims rather than facts.

// maxCredentialTTL is the longest lifetime ConductorOne will issue.
//
// It is the API's own hard limit rather than a policy of this package: the
// request field is validated `lte: {seconds: 15552000}`, which is 180 days
// exactly. A request above it is rejected upstream, so this package clamps down
// to it -- narrowing a lifetime is always permitted, and
// credentials.CreateResult.ExpiresAt then reports what was actually granted
// rather than what was asked for.
//
// An explicit ceiling in the provider is the shape credentials/claude.go uses
// for Bedrock (maxBedrockTokenExpiry) and is what stops a caller's TTL policy
// from silently disagreeing with the upstream's.
const maxCredentialTTL = 180 * 24 * time.Hour

// Client is what the ConductorOne credential provider needs from ConductorOne.
//
// # Verified against
//
// ConductorOne's service-principal credential API, which is a credential
// issuance surface distinct from entitlement granting:
//
//	POST   /api/v1/service_principals/{service_principal_id}/credentials
//	GET    /api/v1/service_principals/{service_principal_id}/credentials/{id}
//	DELETE /api/v1/service_principals/{service_principal_id}/credentials/{id}
//
// The entitlement-grant surface is a different set of routes entirely, and this
// package touches none of them. That distinction is what assumption A1 was
// about, and it is the reason the provider can be a credential vendor rather
// than an entitlement client.
//
// # What it deliberately does not have
//
// No listing, no search, no bulk operations, and no resolve-by-idempotency-key.
// The first three are surface nobody asked for. The fourth is the one that was
// asked for and cannot be had: the create request has no idempotency key, so a
// vend whose response is lost cannot be found again, and the material is
// returned exactly once and is not retrievable afterwards. Those two facts
// compound -- a lost response is unrecoverable by construction and not merely
// unsupported -- so Provider declares credentials.Capabilities{RecoverCreate:
// false} and implements no credentials.CreateRecoverer. lifecycle.CheckIssuable
// then refuses managed issuance through this provider unless an operator has
// explicitly accepted that, which is the visible form of the risk rather than
// the hidden one.
//
// Implementations must be safe for concurrent use.
type Client interface {
	// Mint creates a credential for a service principal and returns it together
	// with its secret. The secret is returned once and cannot be retrieved
	// afterwards, so a caller that loses this response has lost the credential
	// while leaving it live upstream.
	Mint(ctx context.Context, req MintRequest) (*MintResponse, error)

	// Get reports what ConductorOne knows about a credential, without its
	// secret. It returns ErrCredentialNotFound when ConductorOne does not
	// recognise the reference.
	Get(ctx context.Context, ref Ref) (*Credential, error)

	// Revoke destroys a credential. Revoking one that is already gone succeeds:
	// the caller's intent is satisfied either way, and an error would send the
	// reconciler into a retry loop over a credential that no longer exists.
	Revoke(ctx context.Context, ref Ref) error

	// sealed makes this interface implementable only inside this package.
	//
	// USOSS-3 declared it as "the surface a fake will implement in tests", and
	// this is a deliberate departure from that. Provider forwards a Client's
	// error to its own caller, so an implementation from outside this package is
	// an API that accepts arbitrary text and renders it back out -- which is,
	// exactly, the defect the USOSS-7 review found four times and which
	// credentials.Foreign and credhttp.Op were built to make inexpressible. A
	// fourth comment saying "an implementer must not put foreign text in an
	// error" would have been the fifth iteration of it.
	//
	// The fixture in errhygiene_test.go found this by driving Provider with a
	// nonconforming Client, and closing it by removing the input is the same
	// remedy the boundary checker needed after being defeated inside the
	// abstraction built to stop it.
	//
	// Nothing is lost. Fakes live at Deps.Transport instead, which is where
	// credentials/datadog and credentials/github put theirs, so a test still
	// controls every response and every transport failure -- and it exercises the
	// real request construction on the way, which a Client fake skipped. An
	// adopter who wants to vend from somewhere other than ConductorOne implements
	// credentials.CredentialProvider, which is the interface that exists for it.
	sealed()
}

// Ref identifies one credential.
//
// Both halves are required, and that is the point: ConductorOne addresses a
// credential by the pair, so a reference carrying only the credential id cannot
// name it. credentials.CredentialProvider hands revoke and status a single
// opaque platformKeyID, so the pair travels inside it -- see FormatHandle. A
// provider that instead took the service principal id from per-call metadata
// would revoke against whichever principal the caller happened to supply, and
// because a revoke of something absent succeeds, supplying the wrong one would
// report a successful revoke having revoked nothing at all. A credential system
// that lies about revocation is worse than one that admits it cannot revoke, so
// the handle is self-contained.
type Ref struct {
	// ServicePrincipalID is the non-human identity the credential belongs to.
	ServicePrincipalID string
	// CredentialID is ConductorOne's identifier for the credential.
	CredentialID string
}

// IsZero reports whether either half is missing.
func (r Ref) IsZero() bool {
	return r.ServicePrincipalID == "" || r.CredentialID == ""
}

// MintRequest asks ConductorOne for a credential.
type MintRequest struct {
	// ServicePrincipalID is the identity the credential authenticates as.
	ServicePrincipalID string

	// DisplayName is what an operator sees in ConductorOne. Required upstream.
	DisplayName string

	// ScopedRoleIDs restricts the credential to a subset of the service
	// principal's roles. Empty asks for no restriction, which is not the same as
	// asking for none: ConductorOne intersects this list with the roles the
	// service principal actually holds, so an empty list grants the principal's
	// own roles and a non-empty one can only ever grant less.
	ScopedRoleIDs []string

	// TTL is the requested lifetime, already clamped by AppHub's policy and
	// clamped again here to maxCredentialTTL. It must be positive: ConductorOne
	// rejects a non-positive duration, and defaulting one would be this package
	// inventing a lifetime nobody asked for.
	TTL time.Duration
}

// MintResponse is what ConductorOne returns from a mint.
type MintResponse struct {
	// Credential is the metadata, including the handle used for every later
	// call.
	Credential Credential

	// ClientSecret is the credential's secret half. ConductorOne shows it
	// exactly once.
	ClientSecret credentials.Secret
}

// Credential is ConductorOne's record of a credential. It holds no secret.
type Credential struct {
	// Ref addresses it.
	Ref Ref

	// ClientID is the public half of the credential. It is not a secret, and it
	// is not optional either: a consumer needs both halves to authenticate, so a
	// response missing it is an undelivered credential rather than a partial
	// one.
	ClientID string

	// ExpiresAt is when the credential stops working. Nil means ConductorOne did
	// not say, which for this API is a condition worth surfacing rather than
	// papering over with the requested TTL: every credential it issues has a
	// positive lifetime, so a missing expiry is a response that does not match
	// the API this package was written against.
	ExpiresAt *time.Time

	// ScopedRoleIDs is what was actually granted -- the intersection of the
	// request with the service principal's own roles. Recorded in preference to
	// what was requested.
	ScopedRoleIDs []string
}

// ErrCredentialNotFound means ConductorOne does not recognise a reference.
//
// On a revoke this is success: there is nothing to destroy. On a status check it
// is credentials.CredentialStatusUnknown and specifically not expired or
// revoked -- ConductorOne deletes a revoked credential rather than tombstoning
// it, and it may also stop returning one that has lapsed, so absence cannot
// distinguish the two. Guessing either would let the platform close out a record
// on the strength of a 404.
var ErrCredentialNotFound = errors.New("c1: credential not found")

// ErrUnauthenticated means AppHub's own credentials for ConductorOne were
// rejected. It is an operator problem, not a requester problem, and must never
// be reported to a requester as a refusal of their request.
var ErrUnauthenticated = errors.New("c1: apphub is not authenticated to conductorone")

// ErrScopeWidened means ConductorOne granted a role the request did not ask
// for.
//
// It should be impossible: the granted scope is documented as the intersection
// of the request with the service principal's roles, and an intersection cannot
// introduce a member. It is checked anyway because "may narrow, never widen" is
// the one direction of the least-privilege rule that cannot be recovered from
// after the fact, and because the check costs a set comparison. A credential
// that trips it is revoked rather than returned.
var ErrScopeWidened = errors.New("c1: the granted scope is wider than the requested scope")

// ErrMalformedHandle means a platformKeyID did not parse.
//
// It carries nothing from the value that failed. A platformKeyID arrives from
// the platform's own persisted record, and a record is not a thing to trust with
// either path construction or an error message.
var ErrMalformedHandle = errors.New("c1: platform key ID is not a c1 credential handle")

// handleSeparator joins the two halves of a Ref into one platformKeyID.
const handleSeparator = "/"

// handleSegment is the grammar each half of a handle must match.
//
// It is deliberately this package's own grammar and not a restatement of
// ConductorOne's identifier formats. Both of those are narrower than this --
// one is 27 alphanumerics, the other three dash-separated fields -- and pinning
// them here would make an upstream identifier change a parse failure in AppHub,
// which is a hand-maintained restatement of somebody else's grammar and the
// class of mistake this repository has already paid for. What this asserts is
// only what path construction needs: the segment cannot contain a separator, a
// dot segment, an escape, or anything a URL would have to encode.
//
// A recogniser here has exactly two outcomes, recognised or fatal. There is no
// tolerant path that strips or normalises: stripping a known set of decorations
// is enumerating the ways a value can be spelled, and the next spelling is
// always available.
var handleSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// FormatHandle renders a Ref as the opaque platformKeyID the neutral contract
// carries.
//
// It refuses to build a handle it could not parse back, so a Ref that would
// produce an unusable handle fails at mint time -- where the credential can
// still be compensated for -- rather than at revoke time, where it would be a
// live credential with no way to name it.
func FormatHandle(ref Ref) (string, error) {
	if !handleSegment.MatchString(ref.ServicePrincipalID) || !handleSegment.MatchString(ref.CredentialID) {
		return "", ErrMalformedHandle
	}
	if isDotSegment(ref.ServicePrincipalID) || isDotSegment(ref.CredentialID) {
		return "", ErrMalformedHandle
	}
	return ref.ServicePrincipalID + handleSeparator + ref.CredentialID, nil
}

// ParseHandle recovers a Ref from a platformKeyID.
func ParseHandle(platformKeyID string) (Ref, error) {
	if strings.Count(platformKeyID, handleSeparator) != 1 {
		return Ref{}, ErrMalformedHandle
	}
	spID, credID, _ := strings.Cut(platformKeyID, handleSeparator)
	ref := Ref{ServicePrincipalID: spID, CredentialID: credID}
	if _, err := FormatHandle(ref); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// isDotSegment reports whether s is a path segment a URL resolver would treat as
// navigation. handleSegment already forbids a leading dot, so this is the second
// of two independent mechanisms rather than the only one.
func isDotSegment(s string) bool {
	return s == "." || s == ".."
}
