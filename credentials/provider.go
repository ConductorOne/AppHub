// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"time"
)

// ErrRevokeNotSupported indicates that a provider cannot revoke a previously
// vended credential -- typically because the credential material is not
// retained server-side after vending and the upstream API requires that
// material to authenticate the revoke call. Callers should treat this as a
// non-retryable failure (the credential will still expire naturally), not as
// a transient error eligible for the pending-revoke retry loop.
var ErrRevokeNotSupported = errors.New("provider does not support revoke")

// ErrStatusNotSupported indicates that a provider cannot report on a credential
// it vended, so liveness is whatever the local record says. A provider may
// return this instead of CredentialStatusUnknown when the distinction matters;
// callers that only care about liveness may treat the two identically.
var ErrStatusNotSupported = errors.New("provider does not support status checks")

// ErrScopeNotSupported indicates that a provider cannot honor a
// CreateRequest.RequestedScope at all, so it refuses the request rather than
// vending something broader than was asked for.
//
// Refusing is the only compliant answer. CreateRequest.RequestedScope documents
// that a provider "may narrow it and must never widen it", and a provider with
// no scope model that quietly ignored the field would be doing exactly the
// forbidden thing: returning a credential wider than the caller asked for, while
// the empty CreateResult.GrantedScope made the result look merely undescribed.
// A caller that gets this error knows its narrowing did not happen, which is the
// one thing it must not be wrong about.
//
// It says nothing about whether the provider has a scope model at all: a
// provider whose scope comes from operator configuration rather than from the
// request returns this too, because such a provider still cannot honor a
// caller-supplied scope.
var ErrScopeNotSupported = errors.New("provider cannot honor a requested scope")

// ErrRedirectRefused indicates that a provider refused to follow an HTTP
// redirect because the request it was answering carried credential material.
//
// It is not transient. A redirect off the host an operator configured is a
// misconfiguration or an attack, and neither improves by being retried.
//
// Following such a redirect is a credential disclosure rather than a policy
// nicety. Go's HTTP client strips Authorization, Cookie and WWW-Authenticate
// when a redirect crosses hosts, and knows nothing about vendor-specific
// credential headers -- DD-API-KEY among them -- so a provider that follows one
// hands its administrative credential to whatever the Location header named.
var ErrRedirectRefused = errors.New("provider refused to follow a redirect")

// ErrCreateNotDelivered indicates that a provider created a credential upstream
// and could not hand the material back. See CreateNotDeliveredError, which
// carries the handle.
var ErrCreateNotDelivered = errors.New("credential was created but its material could not be delivered")

// ErrCreateNotFound is returned by CreateRecoverer.ResolveCreate when no
// credential was ever created for an idempotency key. It is the answer that
// closes an ambiguous vend: nothing was minted, so nothing is leaking.
var ErrCreateNotFound = errors.New("no credential was created for this idempotency key")

// ErrTransient marks a failure that is worth retrying: an upstream 5xx, a rate
// limit, a dropped connection. Wrapping with it is how a provider tells the
// reconciler "come back later" instead of "give up". Anything not wrapped is
// treated as permanent.
var ErrTransient = errors.New("transient provider failure")

// CredentialType distinguishes between auto-expiring and manually-tracked credentials.
type CredentialType string

// The two credential types. Dynamic credentials expire on their own; static
// credentials expire only because the platform tears them down, which is why the
// lifecycle layer exists.
const (
	CredentialTypeDynamic CredentialType = "dynamic"
	CredentialTypeStatic  CredentialType = "static"
)

// CredentialStatus represents the lifecycle state of a vended credential as the
// upstream provider sees it. It is deliberately narrower than the platform's own
// record status: a provider knows whether the thing it minted still works, and
// nothing about whether an operator has asked for it to be torn down. The
// mapping between the two lives in credentials/lifecycle.
type CredentialStatus string

// The statuses a provider can report. Unknown means the provider does not track
// this credential, which says nothing about whether it works -- see
// lifecycle.StatusFromProvider.
const (
	CredentialStatusActive  CredentialStatus = "active"
	CredentialStatusExpired CredentialStatus = "expired"
	CredentialStatusRevoked CredentialStatus = "revoked"
	CredentialStatusUnknown CredentialStatus = "unknown"
)

// CreateRequest carries the parameters for creating a credential on a provider.
//
// TTL is the already-clamped, effective lifetime: the caller resolved the
// request against the operator's per-provider policy before getting here, so a
// provider may honor TTL directly and must not extend it. A provider that
// cannot honor a TTL at all vends the shortest lifetime it can and reports the
// truth in CreateResult.ExpiresAt.
type CreateRequest struct {
	Name           string
	CredentialType CredentialType
	TTL            time.Duration
	Metadata       Metadata
	RequesterID    string // user email or service account ID
	RequesterType  string // "user" or "service-account"

	// RequestedScope is the least privilege the caller believes it needs, in
	// provider-defined terms (an entitlement reference, a repository, a model
	// family). A provider may narrow it and must never widen it: what was
	// actually granted comes back in CreateResult.GrantedScope.
	RequestedScope []string

	// IdempotencyKey is stable across retries of one logical request. A provider
	// whose upstream supports idempotent creation must forward it, so that a
	// client that times out and retries ends up with one credential rather than
	// two -- one of which nothing is tracking.
	//
	// A provider whose upstream has no such notion may ignore it, but ignoring it
	// has a consequence rather than being free: such a provider cannot implement
	// CreateRecoverer, so a vend whose outcome is unknown can never be resolved,
	// and the lifecycle layer refuses to manage it unless an operator has
	// explicitly accepted that (see lifecycle.ProviderPolicy).
	IdempotencyKey string
}

// CreateResult holds the provider's response after creating a credential.
//
// Material lives in the Secret-typed fields and nowhere else. A provider fills
// in exactly one of APIKey (single-value credentials) or Credentials
// (multi-value credentials, where the map keys are the names the consumer knows
// them by). Neither field is ever persisted; see credentials/lifecycle.
type CreateResult struct {
	// PlatformKeyID identifies the credential on the provider well enough to
	// revoke it and to ask after its status later. It is not material and is
	// persisted.
	PlatformKeyID string

	// APIKey is the material for a single-value credential.
	APIKey Secret

	// Credentials is the material for a multi-value credential, keyed by the
	// name the consumer expects (the specific names are the provider's
	// business, not this package's).
	Credentials map[string]Secret

	// ExpiresAt is when the material stops working, as the provider reports it.
	// Nil means the provider did not say, in which case the caller falls back to
	// the requested TTL -- and, because that is a guess, a nil here on a dynamic
	// credential is worth a second look.
	ExpiresAt *time.Time

	// GrantedScope is what the provider actually granted, which may be narrower
	// than CreateRequest.RequestedScope. Empty means "the provider does not
	// describe scope"; it does not mean unscoped.
	GrantedScope []string
}

// CredentialProvider is the interface that every external platform must implement.
// All methods receive metadata containing provider-specific config (e.g. admin_api_key, workspace_id).
//
// The interface says nothing about clouds, and nothing in it is specific to any
// one provider: that is the property that lets ConductorOne be one
// implementation among several rather than a special case the rest of the system
// knows about. Adding a method that only one provider can implement breaks it --
// use the optional interfaces in capabilities.go instead.
//
// Implementations must be safe for concurrent use, must not log or embed
// credential material in returned errors, and must not retain material after
// returning.
type CredentialProvider interface {
	ID() string
	Name() string
	CreateCredential(ctx context.Context, req CreateRequest) (*CreateResult, error)
	RevokeCredential(ctx context.Context, platformKeyID string, metadata Metadata) error
	GetCredentialStatus(ctx context.Context, platformKeyID string, metadata Metadata) (CredentialStatus, error)
	SupportsDynamic() bool
}

// DescribeType renders a credential type for an error message, and renders
// nothing recognizable for a value that is not one of this package's constants.
//
// It exists so that the invariant these providers hold can be stated without
// exceptions: no error they return contains any text that did not come from a
// constant in this repository, a count, or a Go type name. CredentialType is a
// string type, so an unexpected value in it is caller-supplied text -- and while
// a caller putting a credential in a type field would be strange, "strange" is
// not the standard a public credential vendor gets to work to. Review found three
// disclosure paths in code that had already been read for exactly this, so the
// remaining judgement calls were removed rather than re-argued.
func DescribeType(t CredentialType) string {
	switch t {
	case CredentialTypeDynamic:
		return `"dynamic"`
	case CredentialTypeStatic:
		return `"static"`
	case "":
		return "no credential type"
	default:
		return "an unrecognized credential type"
	}
}
