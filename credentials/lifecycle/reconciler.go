// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// PendingResolutionGrace is how long a StatusPending record is given to resolve
// before it is finalized as StatusOrphaned.
//
// It has to exceed the longest plausible provider round trip and stay far short
// of a credential's lifetime, because the whole value of the state is to notice
// an unmanaged credential while there is still time to do something about it. An
// hour clears any provider that is going to answer at all.
const PendingResolutionGrace = time.Hour

// Report summarizes one reconciliation pass, so an operator can see the loop
// working without reading its logs.
type Report struct {
	// Finalized is the number of records driven to a terminal state this pass.
	Finalized int
	// RevokedUpstream is how many upstream credentials were actually killed.
	RevokedUpstream int
	// ExpiryOnly is how many were finalized without an upstream revoke because the
	// provider does not support one but does expire the material itself. Each of
	// these is a credential that stays usable until its stated expiry, which is
	// worth counting rather than burying.
	ExpiryOnly int

	// Unrevocable is how many records could not be revoked and whose material
	// nothing expires -- a static credential from a provider that cannot revoke, or
	// one whose provider is no longer wired in. These stay non-terminal on purpose:
	// the credential is live and will remain live, and marking it expired would
	// mean the platform stopped watching it. Any value above zero is an alert.
	Unrevocable int
	// Deferred is how many failed transiently and will be retried.
	Deferred int
	// Orphaned is how many pending records could not be resolved within
	// PendingResolutionGrace. Any value above zero deserves an alert: it means a
	// credential may exist that this platform cannot manage.
	Orphaned int
	// Failed is how many records could not be processed for a reason that is not
	// the provider's fault -- a persistence error, unresolvable metadata.
	Failed int
}

// Reconciler drives credentials to their terminal state without anyone watching.
//
// It is also the only thing that finalizes a credential the platform could not
// revoke, because ExpiryDisposition is the only function permitted to conclude
// that unrevoked material has lapsed -- the request path deliberately cannot.
//
// It is the half of the lifecycle that makes TTLs real. A credential whose expiry
// is only ever enforced by the provider is fine; a credential whose expiry is a
// timestamp in a database and nothing else is a credential that never expires,
// and the source system's four static providers are exactly that case -- their
// material works until something calls revoke.
//
// One pass does three things, in this order:
//
//  1. Expired records (ListExpiring at now): attempt the upstream revoke and
//     apply ExpiryDisposition to the result. A record is only finalized as expired
//     when the revoke succeeded, or the provider expires the material itself, said
//     when, and that time has passed; otherwise it stays non-terminal and alerting,
//     because the credential is still live.
//  2. StatusPendingRevoke records: retry the upstream revoke and apply
//     ExpiryDisposition again. This is where a record parked by an unrevocable
//     provider finalizes, once its material has actually lapsed -- and where one
//     whose material never lapses stays forever, counted in Report.Unrevocable. That
//     is a standing alert rather than a queue entry, so implementations back off
//     instead of retrying it every pass.
//  3. StatusPending records older than PendingResolutionGrace: resolve them
//     through credentials.CreateRecoverer, which is the only operation that can
//     turn an idempotency key back into a handle. ErrCreateNotFound means nothing
//     was ever created and the record closes out; a returned CreateResult means
//     the credential exists and is now revocable, so record the handle. A provider
//     that does not implement CreateRecoverer cannot resolve anything, so those
//     records finalize as StatusOrphaned and alert -- see DispositionForFailure,
//     which decides this at vend time so the reconciler is not left guessing.
//
// Implementations must be safe to run concurrently with the request path: both
// write records, so both use Records.Update's revision check and treat
// ErrConflict as "someone else decided, re-read next pass" rather than an error.
// The source system had no such check and its scheduler could overwrite an
// operator's revoke with an expiry a moment later.
type Reconciler interface {
	// Reconcile runs one pass and reports what it did. It returns an error only
	// for a failure that stops the pass; per-record failures are counted in the
	// report so one bad record cannot stall the loop.
	Reconcile(ctx context.Context, now time.Time) (Report, error)
}

// StatusFromProvider maps a provider's view of a credential onto the platform's
// record status, for a record that is currently believed active.
//
// The mapping is not symmetric and cannot be: "unknown" is the provider saying it
// does not track this, which says nothing about the record, so the record's own
// state stands. Turning unknown into revoked would tear down working credentials
// every time a provider had an outage.
func StatusFromProvider(current Status, reported credentials.CredentialStatus) Status {
	switch reported {
	case credentials.CredentialStatusActive:
		return StatusActive
	case credentials.CredentialStatusExpired:
		return StatusExpired
	case credentials.CredentialStatusRevoked:
		return StatusRevoked
	default:
		return current
	}
}
