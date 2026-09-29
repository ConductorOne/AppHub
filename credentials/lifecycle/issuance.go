// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"errors"
	"fmt"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Errors from the issuance admission rules.
var (
	// ErrProviderCannotVendType means the provider does not claim the requested
	// credential type. A provider that declares nothing is assumed not to support
	// static (see credentials.CapabilitiesOf).
	ErrProviderCannotVendType = errors.New("provider does not support this credential type")

	// ErrStaticRequiresRevoke means a static credential was requested from a
	// provider that cannot revoke.
	//
	// Static material is material the upstream never expires. The platform's
	// ExpiresAt is then a row in a database and nothing more, so a static
	// credential from a provider that cannot revoke is a credential that lives
	// forever, and the only thing the platform can do at expiry is stop watching
	// it. Refusing to issue it is the only point in its life at which the platform
	// has any control.
	ErrStaticRequiresRevoke = errors.New("static credentials require a provider that supports revoke")

	// ErrUnrecoverableIssuance means the provider cannot resolve an ambiguous vend
	// (no credentials.CreateRecoverer) and the operator has not accepted that.
	ErrUnrecoverableIssuance = errors.New("provider cannot resolve an ambiguous vend; set ProviderPolicy.AllowUnrecoverableIssuance to accept this")

	// ErrProviderNotRegistered means a record names a provider that is no longer
	// wired in. Passed to ExpiryDisposition so that case is decided in one place
	// rather than at each call site.
	ErrProviderNotRegistered = errors.New("credential provider is not registered")
)

// CheckIssuable is the admission decision for a vend, in one function so that
// every caller applies the same rules in the same order.
//
// It takes the provider rather than a Capabilities value on purpose. The bits it
// consults decide whether a credential can ever be retired, so they must come from
// credentials.CapabilitiesOf -- which clears RecoverCreate for a provider that does
// not implement credentials.CreateRecoverer -- and not from a value a caller
// assembled. An earlier signature accepted Capabilities directly, which let a
// provider claiming RecoverCreate without implementing it be admitted as
// recoverable and then be unable to recover.
//
// The order matters for the error a requester sees: operator configuration first
// (this provider is off, this type is not allowed here), then provider capability
// (this provider cannot do that), then the two safety rules that exist because
// getting them wrong produces a credential nobody can retire.
func CheckIssuable(p credentials.CredentialProvider, policy ProviderPolicy, t credentials.CredentialType) error {
	caps := credentials.CapabilitiesOf(p)
	if !policy.Enabled {
		return ErrProviderDisabled
	}
	if !policy.Allows(t) {
		return fmt.Errorf("%w: %s", ErrTypeNotAllowed, credentials.NewForeign(string(t)))
	}
	if !caps.Supports(t) {
		return fmt.Errorf("%w: %s", ErrProviderCannotVendType, credentials.NewForeign(string(t)))
	}
	if t == credentials.CredentialTypeStatic && !caps.Revoke {
		return ErrStaticRequiresRevoke
	}
	if !caps.RecoverCreate && !policy.AllowUnrecoverableIssuance {
		return ErrUnrecoverableIssuance
	}
	return nil
}

// IssuePhase names where in Issue a failure happened. The disposition of a failed
// vend depends entirely on this: the same error means "nothing was created" in
// one phase and "something may exist that we cannot name" in another.
type IssuePhase string

const (
	// PhaseIntent is before the pending record was persisted. Nothing exists
	// anywhere.
	PhaseIntent IssuePhase = "intent"
	// PhaseVend is the provider call itself.
	PhaseVend IssuePhase = "vend"
	// PhaseFinalize is after the provider returned successfully, while writing
	// the result down. The handle is in hand and the credential is live.
	PhaseFinalize IssuePhase = "finalize"
)

// Disposition is what to do with a record after a failed vend.
type Disposition struct {
	// Status is the record's new status. Empty means there is no record to write.
	Status Status
	// RevokeOutcome to record alongside it.
	RevokeOutcome RevokeOutcome
	// CompensateRevoke says the caller should attempt an upstream revoke now,
	// while it still holds the handle. This is the only chance it will get.
	CompensateRevoke bool
	// Recoverable says the reconciler can resolve this record later through
	// credentials.CreateRecoverer.
	Recoverable bool
	// Alert says an operator should be told. Every disposition that leaves a
	// credential possibly live and unmanaged sets it.
	Alert bool
}

// DispositionForFailure decides what a failed vend leaves behind.
//
// The honest summary of the ambiguous case, which an earlier version of this
// design overstated: writing the intent down before vending makes an unresolvable
// vend *visible*, and visibility is worth having, but it does not make the
// credential go away. Whether the window closes or merely becomes observable
// depends on one capability:
//
//   - The provider implements credentials.CreateRecoverer: the record stays
//     pending, the reconciler asks what became of the idempotency key, and the
//     credential is either adopted (handle recorded, now revocable) or confirmed
//     never to have existed. The window closes.
//   - It does not: nothing will ever resolve the record, so it is finalized as
//     orphaned immediately and an operator is told. Leaving it pending would be
//     pretending a reconciler pass might fix it. The window is observed, not
//     closed -- which is why CheckIssuable refuses this combination unless an
//     operator has explicitly accepted it.
//
// handleKnown distinguishes the failure that happens after the provider answered.
// There the handle exists and a compensating revoke is possible, which is a
// strictly better outcome than either of the above.
//
// Like CheckIssuable, this takes the provider so that the recoverability decision
// comes from an interface check rather than from a bit a caller could set.
func DispositionForFailure(phase IssuePhase, p credentials.CredentialProvider, ambiguous bool) Disposition {
	caps := credentials.CapabilitiesOf(p)
	switch phase {
	case PhaseIntent:
		// Nothing was written and nothing was vended.
		return Disposition{}

	case PhaseVend:
		if !ambiguous {
			// The provider said no. Nothing was minted, so the record closes out
			// with nothing upstream to clean up.
			return Disposition{Status: StatusRevoked, RevokeOutcome: RevokeOutcomeUntracked}
		}
		if caps.RecoverCreate {
			return Disposition{Status: StatusPending, Recoverable: true}
		}
		return Disposition{Status: StatusOrphaned, RevokeOutcome: RevokeOutcomeUntracked, Alert: true}

	case PhaseFinalize:
		// The credential is live and the handle is in hand. Retry the write; if it
		// keeps failing, revoke what was just created rather than leaving it.
		return Disposition{
			Status:           StatusPending,
			CompensateRevoke: true,
			Recoverable:      caps.RecoverCreate,
			Alert:            true,
		}

	default:
		return Disposition{Status: StatusOrphaned, Alert: true}
	}
}

// expiresOnItsOwn reports whether the record's material dies without anyone
// acting: the provider expires it, and the provider said when.
//
// This predicate is the single place the question is answered. Both finalizers
// below consult it, so there is one rule about when a credential may be called
// finished rather than one rule per code path -- which is how the revoke path came
// to disagree with the expiry path in the first place.
func expiresOnItsOwn(rec *Record) bool {
	return rec.ExpiryAuthoritative && rec.Type == credentials.CredentialTypeDynamic
}

// RevokeDisposition decides what an operator-requested revoke leaves behind.
//
// A successful upstream revoke is the only thing that finalizes a record here.
// Everything else -- including credentials.ErrRevokeNotSupported -- leaves it in
// StatusPendingRevoke, non-terminal and alerting.
//
// That is a change from the first draft, which turned ErrRevokeNotSupported
// straight into a terminal StatusRevoked with RevokeOutcomeExpiryOnly. The fix on
// the expiry path had not been applied here, so revoke was a second, more
// permissive finalizer: it closed out records whose material was still working --
// for authoritative dynamic material until its future ExpiresAt, and for static
// material potentially forever. "The operator asked for this to be gone" is not
// evidence that it is gone.
//
// A record left in StatusPendingRevoke by an unrevocable provider finalizes later,
// through ExpiryDisposition, once its expiry has actually passed and only if the
// material expires on its own. If it does not, the record stays non-terminal
// forever, which is the honest representation of a credential that cannot be
// retired.
//
// It takes no Record, and that absence is the point: every judgment that depends on
// what the record says about its material -- the type, whether the expiry is
// authoritative, whether it has passed -- belongs to the one finalizer, and this
// function has nothing to decide with them.
func RevokeDisposition(revokeErr error) Disposition {
	switch {
	case revokeErr == nil:
		return Disposition{Status: StatusRevoked, RevokeOutcome: RevokeOutcomeUpstream}

	case errors.Is(revokeErr, credentials.ErrRevokeNotSupported):
		// The material is still live. Whether it will ever die is
		// ExpiryDisposition's question, asked at expiry time, not now.
		return Disposition{Status: StatusPendingRevoke, Alert: true}

	case errors.Is(revokeErr, ErrProviderNotRegistered):
		return Disposition{Status: StatusPendingRevoke, RevokeOutcome: RevokeOutcomeUntracked, Alert: true}

	default:
		// Transient or unknown: the reconciler retries.
		return Disposition{Status: StatusPendingRevoke}
	}
}

// ExpiryDisposition decides how the reconciler finalizes a record whose expiry has
// passed, given the result of the upstream revoke it attempted.
//
// It is the only function that can produce RevokeOutcomeExpiryOnly, and it will
// only do so once now is at or past the record's expiry. Both halves of that
// matter: an outcome meaning "the material lapses on its own" is a claim that it
// has lapsed, so no other code path may assert it, and it cannot be asserted
// early. The reconciler also calls this on StatusPendingRevoke records, which is
// how a record parked there by an unrevocable provider eventually finalizes -- and
// why the expiry check has to be here rather than assumed by the caller.
//
// The rule: a record may be marked expired only when something other than the
// platform's own clock says the material is dead. That means either the revoke
// succeeded, or the material expires on its own (expiresOnItsOwn) and that time has
// come. Anything else -- static material from a provider that cannot revoke, a
// provider no longer wired in, a locally computed expiry on material nothing
// expires -- stays non-terminal and alerting, because the credential is still out
// there and "expired" would mean the platform stopped watching a live credential.
func ExpiryDisposition(rec *Record, now time.Time, revokeErr error) Disposition {
	lapsed := expiresOnItsOwn(rec) && rec.Expired(now)

	switch {
	case revokeErr == nil:
		return Disposition{Status: StatusExpired, RevokeOutcome: RevokeOutcomeUpstream}

	case errors.Is(revokeErr, credentials.ErrRevokeNotSupported):
		if lapsed {
			// The provider will not revoke it, but it does expire it, it said when,
			// and that time has passed. The credential is dead.
			return Disposition{Status: StatusExpired, RevokeOutcome: RevokeOutcomeExpiryOnly}
		}
		// Either nothing expires this material, or it has not expired yet. Live
		// either way.
		return Disposition{Status: StatusPendingRevoke, Alert: true}

	case errors.Is(revokeErr, ErrProviderNotRegistered):
		if lapsed {
			return Disposition{Status: StatusExpired, RevokeOutcome: RevokeOutcomeUntracked}
		}
		return Disposition{Status: StatusPendingRevoke, RevokeOutcome: RevokeOutcomeUntracked, Alert: true}

	default:
		// Transient or unknown: leave it alone and come back.
		return Disposition{Status: StatusPendingRevoke}
	}
}
