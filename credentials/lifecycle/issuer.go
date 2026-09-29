// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// IssueRequest is a request to vend a credential, as it arrives at the lifecycle
// layer: already authenticated, not yet authorized, and with a TTL that is still
// only a wish.
type IssueRequest struct {
	ProviderID     string
	Name           string
	Type           credentials.CredentialType
	Requester      Requester
	RequestedTTL   time.Duration
	RequestedScope []string

	// ApplicationID, when set, means the credential is for a deployed
	// application: the material goes to the secret store rather than back to a
	// human, and the record is bound to the application so that tearing the
	// application down tears its credentials down too.
	ApplicationID string

	// ProviderMetadata is provider configuration resolved by a
	// ProviderMetadataSource. It routinely contains admin API keys, which is why
	// it is credentials.Metadata and not a plain map.
	ProviderMetadata credentials.Metadata

	// Annotations is non-secret context to keep on the record. Every key must be
	// declared in the provider's schema; see AnnotationRegistry.
	Annotations Annotations
}

// IssueResult is what a successful vend produces.
//
// Material is in Result and is in memory only. The caller delivers it -- once, to
// the requester, or to the secret store -- and then drops it. Nothing here is
// cached, and Record deliberately has nowhere to put it.
type IssueResult struct {
	// Record is the persisted state, already written.
	Record *Record
	// Result is the provider's response, including material.
	Result *credentials.CreateResult
	// EffectiveTTL is what the policy allowed, which may be shorter than what was
	// requested.
	EffectiveTTL time.Duration
}

// Issuer vends credentials and keeps the record straight.
//
// The ordering it must implement is the interesting part, and it is not the
// ordering the source system used. The source called the provider first and
// wrote the record second (backend/internal/services/credential.go:794 then
// :826), so a failure in between left a live upstream credential that the
// platform had no record of, would never revoke, and could not even report -- a
// credential leak caused by a database error. Issue therefore writes first:
//
//  1. Admission: CheckIssuable against the operator's policy and the provider's
//     declared capabilities, then clamp the TTL and check the caller's scope.
//     Reject before touching the provider.
//  2. Create a StatusPending record with a fresh ID, using the record's ID as the
//     idempotency key.
//  3. Call the provider with the clamped TTL and that key.
//  4. On success, update the record to StatusActive with the provider's handle,
//     granted scope and expiry, setting ExpiryAuthoritative from whether the
//     provider stated an expiry.
//  5. On failure, take the disposition from DispositionForFailure and apply it.
//
// # What write-ahead ordering does and does not buy
//
// It removes the source system's silent leak: a persistence failure can no longer
// produce a live credential that nothing has ever heard of. What the pending
// record holds, though, is an idempotency key -- not a handle, because the handle
// only exists in the response that was lost. GetCredentialStatus takes a
// platformKeyID, so it cannot help.
//
// So the window closes only for a provider implementing
// credentials.CreateRecoverer, which can answer "what became of this key?".
// Without that the vend is observable-but-unresolvable, and CheckIssuable refuses
// it unless ProviderPolicy.AllowUnrecoverableIssuance says an operator accepted
// the risk. DispositionForFailure encodes both paths.
//
// The one case that is strictly better than either: the provider answered and the
// finalizing write failed. The handle is in hand, so an implementation must retry
// the write and, if it still fails, revoke the credential it just created --
// while it still can.
//
// Implementations must not log credential material, must not put it in an error,
// and must not retain it after returning.
type Issuer interface {
	// Issue vends a credential, or explains why not.
	Issue(ctx context.Context, req IssueRequest) (*IssueResult, error)

	// Revoke requests revocation and applies RevokeDisposition to the outcome. It
	// returns the updated record.
	//
	// Only a successful upstream revoke finalizes the record. A provider returning
	// credentials.ErrRevokeNotSupported is not an error, but it is also not
	// completion: the record goes to StatusPendingRevoke and stays there until its
	// material actually lapses, which ExpiryDisposition decides later. An operator
	// asking for a credential to be gone does not make it gone, and a record
	// marked revoked while its material still works is worse than one honestly
	// marked pending -- it stops anyone looking.
	Revoke(ctx context.Context, id string) (*Record, error)

	// ExtendTTL moves a static credential's expiry out, subject to the same
	// policy clamp as issuance. It changes no material: the platform is
	// re-deciding how long it will keep tracking something that never expires on
	// its own, which is why it is refused for dynamic credentials -- their expiry
	// is the provider's fact, not the platform's choice.
	ExtendTTL(ctx context.Context, id string, ttl time.Duration) (*Record, error)
}

// ProviderMetadataSource resolves the operator-configured metadata for a
// provider, including admin keys pulled from a secret store.
//
// It exists as an interface because resolving metadata is where the secret store
// gets touched, and the reconciler needs it just as much as the request path
// does: a revoke that runs an hour after the vend has to re-resolve the admin key
// to authenticate the revoke call.
type ProviderMetadataSource interface {
	ResolveMetadata(ctx context.Context, providerID string) (credentials.Metadata, error)
}

// ProviderPolicy is the operator's per-provider ceiling: whether it may be used
// at all, which credential types it may vend, and for how long.
//
// TTLs are durations here rather than the source system's hours, because "1"
// meaning an hour in one field and a count in another is how a 24-hour
// credential becomes a 24-day one.
type ProviderPolicy struct {
	// Enabled gates the provider entirely. A registered provider whose policy is
	// disabled cannot vend, which is what makes registering a provider a safe,
	// reversible act -- and why a provider that ships registered-but-disabled is
	// not dead code.
	Enabled bool

	// AllowedTypes lists the credential types this provider may vend.
	//
	// Empty means none. The source system read an empty list as "static only"
	// (backend/internal/services/credential.go:584-586), which makes the
	// unconfigured state issue exactly the kind of credential the platform then has
	// to remember to tear down. An operator who wants a type says so.
	AllowedTypes []credentials.CredentialType

	// AllowUnrecoverableIssuance permits vending through a provider that cannot
	// resolve an ambiguous create (no credentials.CreateRecoverer).
	//
	// It defaults to false, which means a timed-out vend can always be traced to
	// either "nothing was created" or a handle that can revoke it. Setting it true
	// is an operator accepting that some vends may leave a live credential this
	// platform can name but not retire; the records land as StatusOrphaned and
	// alert. It exists because refusing those providers outright would be the
	// wrong default for a deployment that has weighed it, not because the risk is
	// small.
	AllowUnrecoverableIssuance bool

	// DefaultTTL applies when a request names no TTL, per type.
	DefaultTTL map[credentials.CredentialType]time.Duration

	// MaxTTL caps the request, per type. A zero or missing entry means
	// FallbackMaxTTL applies; there is no such thing as an uncapped credential,
	// because TTL is the only bound on a leak that no provider can revoke.
	MaxTTL map[credentials.CredentialType]time.Duration
}

// FallbackDefaultTTL is used when neither the request nor the policy names a TTL.
const FallbackDefaultTTL = time.Hour

// FallbackMaxTTL caps any credential whose policy names no maximum.
//
// Twelve hours is not arbitrary: it is the ceiling the source system's AWS
// Bedrock token path already enforced (maxBedrockTokenExpiry,
// backend/internal/credentials/claude.go:31), and adopting it as the global
// fallback means an unconfigured provider inherits a bound rather than the
// source system's 24-hour default that nobody chose.
const FallbackMaxTTL = 12 * time.Hour

// ErrTypeNotAllowed is returned when a policy forbids the requested credential
// type.
var ErrTypeNotAllowed = errors.New("credential type is not allowed for this provider")

// ErrProviderDisabled is returned when a policy has the provider switched off.
var ErrProviderDisabled = errors.New("credential provider is not enabled")

// Allows reports whether the policy permits the given type. An empty AllowedTypes
// permits nothing.
func (p ProviderPolicy) Allows(t credentials.CredentialType) bool {
	for _, allowed := range p.AllowedTypes {
		if allowed == t {
			return true
		}
	}
	return false
}

// ClampTTL resolves a requested TTL against the policy.
//
// Requests may only narrow: a request for longer than the maximum gets the
// maximum, not an error, matching the source system's behavior -- but a request
// for no TTL at all gets the policy default rather than the largest thing on
// offer. Every path returns something bounded, so a policy with nothing filled in
// still produces a credential that dies on its own.
func (p ProviderPolicy) ClampTTL(t credentials.CredentialType, requested time.Duration) time.Duration {
	maxTTL := p.MaxTTL[t]
	if maxTTL <= 0 {
		maxTTL = FallbackMaxTTL
	}

	ttl := requested
	if ttl <= 0 {
		ttl = p.DefaultTTL[t]
	}
	if ttl <= 0 {
		ttl = FallbackDefaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

// PolicySource returns the operator's policy for a provider. Implemented over
// whatever holds administrative configuration (store/, in this repository).
type PolicySource interface {
	PolicyFor(ctx context.Context, providerID string) (ProviderPolicy, error)
}

// CallerScope is the authorization a caller carries: which providers and types it
// may ask for, and the longest TTL it may ask for.
//
// It is separate from ProviderPolicy because the two answer different questions.
// The policy is what the deployment permits; the scope is what this caller
// permits. Both may only narrow, and the narrower of the two wins -- which is the
// whole of the least-privilege rule, stated once, in one place.
type CallerScope struct {
	ProviderID string
	Types      []credentials.CredentialType
	MaxTTL     time.Duration
}

// ErrOutOfScope is returned when a caller asks for something its scopes do not
// cover.
var ErrOutOfScope = errors.New("request is outside the caller's allowed scope")

// CheckScope reports whether any of the caller's scopes permits this request.
//
// A nil scopes slice means the caller is not scope-limited (an interactive user,
// authorized elsewhere); an empty non-nil slice means a caller with no
// permissions at all, and gets nothing. The distinction is deliberate: the
// failure mode of conflating them is a service account with an empty scope list
// inheriting an administrator's reach.
func CheckScope(scopes []CallerScope, providerID string, t credentials.CredentialType, ttl time.Duration) error {
	if scopes == nil {
		return nil
	}
	for _, s := range scopes {
		if s.ProviderID != providerID {
			continue
		}
		if len(s.Types) > 0 {
			ok := false
			for _, allowed := range s.Types {
				if allowed == t {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if s.MaxTTL > 0 && ttl > s.MaxTTL {
			continue
		}
		return nil
	}
	// The TTL is a duration and stays: a quantity is permitted by the invariant, it
	// cannot carry text, and it is the one part of the request that tells an operator
	// which limit was exceeded. The provider ID and the credential type are both
	// caller-chosen strings and are not.
	return fmt.Errorf("%w: provider %s, type %s, ttl %s",
		ErrOutOfScope, credentials.NewForeign(providerID), credentials.NewForeign(string(t)), ttl)
}
