// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Status is the platform's view of a vended credential, which is a superset of
// the provider's view (credentials.CredentialStatus). The provider knows whether
// the material still works; only the platform knows that a vend was started and
// never confirmed, or that an operator asked for a revoke that the upstream has
// not accepted yet.
type Status string

const (
	// StatusPending means the platform wrote down its intent to vend and has not
	// yet confirmed the outcome. A record in this state may or may not have a
	// live credential behind it upstream -- resolving that ambiguity is the
	// reconciler's job, and the reason the state exists at all.
	StatusPending Status = "pending"

	// StatusActive means the credential was vended and is believed usable.
	StatusActive Status = "active"

	// StatusPendingRevoke means a revoke was requested and the upstream call
	// failed in a way worth retrying. The material may still work; the
	// reconciler keeps trying.
	StatusPendingRevoke Status = "pending_revoke"

	// StatusRevoked means the credential is gone as far as the platform is
	// concerned: either the upstream revoke succeeded, or the provider cannot
	// revoke and the material will lapse at ExpiresAt. Those two are materially
	// different and the audit record must say which -- see Record.RevokeOutcome.
	StatusRevoked Status = "revoked"

	// StatusExpired means the credential passed ExpiresAt and was finalized.
	//
	// It is a claim that the material no longer works, so it may only be set when
	// something other than a row in a database makes that true: the provider
	// expires the material itself and stated the expiry (Record.ExpiryAuthoritative),
	// or an upstream revoke succeeded. Marking a static credential expired because
	// a locally computed timestamp passed would be the platform lying to itself --
	// and then, worse, no longer tracking a credential that still works. See
	// ExpiryDisposition.
	StatusExpired Status = "expired"

	// StatusOrphaned means the platform believes an upstream credential exists
	// that it cannot manage: a pending vend that could not be resolved before
	// its deadline. It is a terminal state that exists to be alerted on, because
	// the alternative to naming it is a credential nobody knows about.
	StatusOrphaned Status = "orphaned"
)

// Terminal reports whether the status is final. A terminal record needs no
// further reconciliation.
func (s Status) Terminal() bool {
	switch s {
	case StatusRevoked, StatusExpired, StatusOrphaned:
		return true
	default:
		return false
	}
}

// RevokeOutcome records how a revocation actually ended, because "revoked"
// covers two situations with very different blast radii.
type RevokeOutcome string

const (
	// RevokeOutcomeNone means no revocation has been attempted.
	RevokeOutcomeNone RevokeOutcome = ""
	// RevokeOutcomeUpstream means the provider confirmed the credential is dead.
	RevokeOutcomeUpstream RevokeOutcome = "upstream"
	// RevokeOutcomeExpiryOnly means the provider cannot revoke
	// (credentials.ErrRevokeNotSupported) but the material expires on its own at a
	// time the provider stated, so the credential does die -- just later than the
	// operator asked. Audit shows this as a partial success, and TTL is the only
	// thing bounding the leak.
	//
	// This outcome is valid only for provider-expiring material with an
	// authoritative expiry. For anything else, an unrevocable credential is a
	// credential that never dies, and the record stays non-terminal and alerting
	// rather than being relabeled as finished.
	RevokeOutcomeExpiryOnly RevokeOutcome = "expiry_only"
	// RevokeOutcomeUntracked means the record's provider is no longer registered,
	// so nothing can be revoked upstream and nothing can confirm it either.
	RevokeOutcomeUntracked RevokeOutcome = "untracked"
)

// Requester identifies who asked for a credential. It is what makes the audit
// trail worth having.
type Requester struct {
	// ID is the stable identifier: a user ID or a service-account ID.
	ID string
	// Type is "user" or "service-account".
	Type string
	// Email is the human-readable identity, when there is one.
	Email string
}

// Record is what the platform stores about a credential it vended.
//
// There is no field on this type capable of holding credential material, and
// that is a load-bearing property rather than an accident: material reaches a
// requester or a secret store, and the record keeps a locator (SecretRef) so
// that later revocation can clean up without the platform ever having kept a
// copy. Annotations was the one free-form field, and is now an allowlist keyed by
// what each provider declared -- see AnnotationRegistry -- because a free-form
// string map on a persisted type is exactly where an admin API key ends up six
// months later.
type Record struct {
	// ID is the platform's identifier for this credential. Assigned by the
	// issuer before the provider is called, so a vend that fails halfway still
	// has something to reconcile.
	ID string

	// Revision is a monotonic counter for optimistic concurrency. Records
	// implementations reject an Update whose Revision does not match the stored
	// one with ErrConflict. Without it, the reconciler and an operator revoking
	// by hand race, and the loser's write disappears silently.
	Revision uint64

	// ProviderID is the credentials.CredentialProvider that vended it.
	ProviderID string

	// Type is dynamic or static.
	Type credentials.CredentialType

	// Name is the operator-supplied label.
	Name string

	// PlatformKeyID is the provider's handle, needed to revoke or ask after
	// status. Not material.
	PlatformKeyID string

	// IdempotencyKey is what was sent to the provider so a retried vend does not
	// mint twice. Stable for the life of the record.
	IdempotencyKey string

	// Requester is who asked.
	Requester Requester

	// Status is the platform's lifecycle state.
	Status Status

	// RevokeOutcome says how a revocation ended, when one has been attempted.
	RevokeOutcome RevokeOutcome

	// GrantedScope is what the provider said it granted, which may be narrower
	// than what was asked for. Recording the granted scope rather than the
	// requested one is what makes the audit trail describe reality.
	GrantedScope []string

	// RequestedScope is what was asked for, kept so that a granted-narrower-than-
	// requested case is visible after the fact.
	RequestedScope []string

	// ApplicationID binds the credential to a deployed application, when it was
	// vended for one rather than for a person.
	ApplicationID string

	// SecretRef locates the material in a secret store, when it was written to
	// one. Zero means the material was handed to the requester and never stored.
	SecretRef credentials.SecretRef

	// Annotations holds non-secret provider context worth keeping: a region, an
	// installation ID, a device identifier.
	//
	// The keys are not free-form. Each provider declares the keys it may persist,
	// in code, and persistence rejects anything undeclared -- see
	// AnnotationRegistry, which also explains why this is an allowlist and what it
	// still cannot promise.
	Annotations Annotations

	// ExpiresAt is when the material stops working, or when the platform intends to
	// stop tracking it. Which of those it means is ExpiryAuthoritative's job to
	// say.
	ExpiresAt time.Time

	// ExpiryAuthoritative reports whether ExpiresAt came from the provider
	// (credentials.CreateResult.ExpiresAt was set) rather than from the platform
	// applying a requested TTL locally.
	//
	// The distinction decides whether expiry is a fact or a belief, and therefore
	// whether the reconciler may finalize a record on expiry alone. A locally
	// computed timestamp passing tells you nothing about whether an API key still
	// works.
	ExpiryAuthoritative bool

	// CreatedAt is when the record was written, before the provider was called.
	CreatedAt time.Time

	// UpdatedAt is the last write.
	UpdatedAt time.Time

	// LastRefreshedAt is the last time the record's TTL was extended.
	LastRefreshedAt time.Time

	// RevokedAt is when revocation was requested, not when it succeeded.
	RevokedAt *time.Time
}

// Expired reports whether the record's believed expiry has passed.
func (r *Record) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !r.ExpiresAt.After(now)
}
