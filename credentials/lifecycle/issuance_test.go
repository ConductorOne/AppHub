// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

// provider is a CredentialProvider whose declared capabilities are configurable.
// CheckIssuable and DispositionForFailure take a provider rather than a
// Capabilities value, so tests have to build one that really does or does not
// implement credentials.CreateRecoverer -- which is the point: a fabricated
// capability set is exactly what those functions no longer accept.
type provider struct {
	id   string
	caps credentials.Capabilities
}

func (p provider) ID() string                             { return p.id }
func (p provider) Name() string                           { return p.id }
func (p provider) SupportsDynamic() bool                  { return p.caps.Dynamic }
func (p provider) Capabilities() credentials.Capabilities { return p.caps }
func (p provider) RevokeCredential(context.Context, string, credentials.Metadata) error {
	return nil
}
func (p provider) GetCredentialStatus(context.Context, string, credentials.Metadata) (credentials.CredentialStatus, error) {
	return credentials.CredentialStatusActive, nil
}
func (p provider) CreateCredential(context.Context, credentials.CreateRequest) (*credentials.CreateResult, error) {
	return &credentials.CreateResult{PlatformKeyID: "key-1"}, nil
}

// recovering additionally implements CreateRecoverer, so a RecoverCreate
// declaration on it is backed by something.
type recovering struct{ provider }

func (r recovering) ResolveCreate(context.Context, string, credentials.Metadata) (*credentials.CreateResult, error) {
	return nil, credentials.ErrCreateNotFound
}

// fullyCapable can vend both types, revoke, report status, and resolve an
// ambiguous create.
func fullyCapable() recovering {
	return recovering{provider{id: "full", caps: credentials.Capabilities{
		Dynamic: true, Static: true, Revoke: true, Status: true, RecoverCreate: true,
	}}}
}

// withCaps builds a recovery-capable provider with an otherwise custom shape.
func withCaps(caps credentials.Capabilities) recovering {
	return recovering{provider{id: "custom", caps: caps}}
}

func policyFor(types ...credentials.CredentialType) lifecycle.ProviderPolicy {
	return lifecycle.ProviderPolicy{Enabled: true, AllowedTypes: types}
}

// TestStaticIssuanceRequiresRevoke is the regression test for the defect where a
// static credential could be issued through a provider that cannot revoke, then
// be marked expired on a locally computed timestamp while continuing to work
// forever.
func TestStaticIssuanceRequiresRevoke(t *testing.T) {
	noRevoke := withCaps(credentials.Capabilities{
		Dynamic: true, Static: true, Revoke: false, Status: true, RecoverCreate: true,
	})

	err := lifecycle.CheckIssuable(noRevoke, policyFor(credentials.CredentialTypeStatic), credentials.CredentialTypeStatic)
	if !errors.Is(err, lifecycle.ErrStaticRequiresRevoke) {
		t.Fatalf("CheckIssuable(static, no revoke) = %v, want ErrStaticRequiresRevoke", err)
	}

	// The same provider may still vend dynamic credentials: those expire whether
	// or not anyone revokes them.
	if err := lifecycle.CheckIssuable(noRevoke, policyFor(credentials.CredentialTypeDynamic), credentials.CredentialTypeDynamic); err != nil {
		t.Errorf("CheckIssuable(dynamic, no revoke) = %v, want nil", err)
	}
	// And with revoke, static is fine.
	if err := lifecycle.CheckIssuable(fullyCapable(), policyFor(credentials.CredentialTypeStatic), credentials.CredentialTypeStatic); err != nil {
		t.Errorf("CheckIssuable(static, revoke) = %v, want nil", err)
	}
}

// TestCheckIssuableRefusesAnUnbackedRecoverClaim is the other half of the
// capability-coupling fix: the admission decision must not be satisfiable by a
// declaration alone.
func TestCheckIssuableRefusesAnUnbackedRecoverClaim(t *testing.T) {
	// Declares RecoverCreate, does not implement CreateRecoverer.
	claimant := provider{id: "liar", caps: credentials.Capabilities{
		Dynamic: true, Revoke: true, RecoverCreate: true,
	}}
	err := lifecycle.CheckIssuable(claimant, policyFor(credentials.CredentialTypeDynamic), credentials.CredentialTypeDynamic)
	if !errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
		t.Fatalf("CheckIssuable(unbacked RecoverCreate) = %v, want ErrUnrecoverableIssuance", err)
	}

	// Backed by the interface, the same declaration is accepted.
	honest := recovering{claimant}
	if err := lifecycle.CheckIssuable(honest, policyFor(credentials.CredentialTypeDynamic), credentials.CredentialTypeDynamic); err != nil {
		t.Errorf("CheckIssuable(backed RecoverCreate) = %v, want nil", err)
	}
}

// TestDispositionRefusesAnUnbackedRecoverClaim: the same coupling on the failure
// path, where believing the claim would leave a record marked recoverable that
// nothing can resolve.
func TestDispositionRefusesAnUnbackedRecoverClaim(t *testing.T) {
	claimant := provider{id: "liar", caps: credentials.Capabilities{
		Dynamic: true, Revoke: true, RecoverCreate: true,
	}}
	got := lifecycle.DispositionForFailure(lifecycle.PhaseVend, claimant, true)
	if got.Recoverable {
		t.Error("an unbacked RecoverCreate declaration produced a recoverable disposition")
	}
	if got.Status != lifecycle.StatusOrphaned || !got.Alert {
		t.Errorf("disposition = %+v, want orphaned and alerting", got)
	}
}

func TestCheckIssuableOrdersItsRefusals(t *testing.T) {
	tests := []struct {
		name     string
		provider credentials.CredentialProvider
		policy   lifecycle.ProviderPolicy
		typ      credentials.CredentialType
		want     error
	}{
		{
			name:     "disabled provider",
			provider: fullyCapable(),
			policy:   lifecycle.ProviderPolicy{Enabled: false, AllowedTypes: []credentials.CredentialType{credentials.CredentialTypeDynamic}},
			typ:      credentials.CredentialTypeDynamic,
			want:     lifecycle.ErrProviderDisabled,
		},
		{
			name:     "type not permitted by policy",
			provider: fullyCapable(),
			policy:   policyFor(credentials.CredentialTypeDynamic),
			typ:      credentials.CredentialTypeStatic,
			want:     lifecycle.ErrTypeNotAllowed,
		},
		{
			name:     "provider cannot vend the type",
			provider: withCaps(credentials.Capabilities{Dynamic: false, Static: true, Revoke: true, RecoverCreate: true}),
			policy:   policyFor(credentials.CredentialTypeDynamic),
			typ:      credentials.CredentialTypeDynamic,
			want:     lifecycle.ErrProviderCannotVendType,
		},
		{
			name:     "unrecoverable issuance is refused by default",
			provider: provider{id: "no-recovery", caps: credentials.Capabilities{Dynamic: true, Revoke: true}},
			policy:   policyFor(credentials.CredentialTypeDynamic),
			typ:      credentials.CredentialTypeDynamic,
			want:     lifecycle.ErrUnrecoverableIssuance,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := lifecycle.CheckIssuable(tc.provider, tc.policy, tc.typ); !errors.Is(err, tc.want) {
				t.Errorf("CheckIssuable() = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUnrecoverableIssuanceIsAnExplicitOptIn(t *testing.T) {
	p := provider{id: "no-recovery", caps: credentials.Capabilities{Dynamic: true, Revoke: true}}
	policy := policyFor(credentials.CredentialTypeDynamic)
	policy.AllowUnrecoverableIssuance = true

	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeDynamic); err != nil {
		t.Errorf("CheckIssuable(opted in) = %v, want nil", err)
	}
}

// TestDispositionForAmbiguousVend is the regression test for the overstated
// claim that write-ahead intent closes the untracked-credential window. It closes
// only when the provider can resolve the create; otherwise the record is
// finalized as orphaned and alerts, rather than sitting pending as though a
// reconciler pass might fix it.
func TestDispositionForAmbiguousVend(t *testing.T) {
	recoverable := lifecycle.DispositionForFailure(lifecycle.PhaseVend, fullyCapable(), true)
	if recoverable.Status != lifecycle.StatusPending {
		t.Errorf("recoverable ambiguous vend Status = %q, want pending", recoverable.Status)
	}
	if !recoverable.Recoverable {
		t.Error("a provider implementing CreateRecoverer should give a recoverable disposition")
	}

	noRecovery := provider{id: "no-recovery", caps: credentials.Capabilities{
		Dynamic: true, Static: true, Revoke: true, Status: true,
	}}
	unrecoverable := lifecycle.DispositionForFailure(lifecycle.PhaseVend, noRecovery, true)
	if unrecoverable.Status != lifecycle.StatusOrphaned {
		t.Errorf("unrecoverable ambiguous vend Status = %q, want orphaned", unrecoverable.Status)
	}
	if unrecoverable.Recoverable {
		t.Error("nothing can resolve this record; it must not claim to be recoverable")
	}
	if !unrecoverable.Alert {
		t.Error("a credential that may be live and cannot be named must alert")
	}
}

func TestDispositionForOtherPhases(t *testing.T) {
	if got := lifecycle.DispositionForFailure(lifecycle.PhaseIntent, fullyCapable(), false); got.Status != "" {
		t.Errorf("PhaseIntent Status = %q, want empty: nothing was written and nothing vended", got.Status)
	}

	definite := lifecycle.DispositionForFailure(lifecycle.PhaseVend, fullyCapable(), false)
	if definite.Status != lifecycle.StatusRevoked || definite.RevokeOutcome != lifecycle.RevokeOutcomeUntracked {
		t.Errorf("definite vend failure = %+v, want revoked/untracked", definite)
	}
	if definite.Alert {
		t.Error("a provider saying no is not an alert; nothing was minted")
	}

	// The handle is in hand: revoke what was just created rather than losing it.
	finalize := lifecycle.DispositionForFailure(lifecycle.PhaseFinalize, fullyCapable(), true)
	if !finalize.CompensateRevoke {
		t.Error("a finalize failure must compensate: this is the last moment the handle exists")
	}
	if !finalize.Alert || finalize.Status != lifecycle.StatusPending {
		t.Errorf("finalize disposition = %+v, want pending and alerting", finalize)
	}
}

// TestExpiryDispositionNeverMarksLiveMaterialExpired is the regression test for
// the fourth blocker: a static credential whose upstream never expires it must
// not be relabeled "expired" because a database timestamp passed.
func TestExpiryDispositionNeverMarksLiveMaterialExpired(t *testing.T) {
	now := time.Now().UTC()
	staticRec := &lifecycle.Record{
		Type:                credentials.CredentialTypeStatic,
		ExpiryAuthoritative: false,
		ExpiresAt:           now.Add(-time.Hour),
	}
	got := lifecycle.ExpiryDisposition(staticRec, now, credentials.ErrRevokeNotSupported)
	if got.Status != lifecycle.StatusPendingRevoke {
		t.Errorf("unrevocable static Status = %q, want pending_revoke (non-terminal)", got.Status)
	}
	if got.Status.Terminal() {
		t.Error("an unrevocable static credential must not reach a terminal status")
	}
	if got.RevokeOutcome == lifecycle.RevokeOutcomeExpiryOnly {
		t.Error("expiry_only claims the material lapses on its own; nothing expires this")
	}
	if !got.Alert {
		t.Error("a credential that is live and cannot be revoked must alert")
	}
}

func TestExpiryDispositionTable(t *testing.T) {
	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	rec := func(t credentials.CredentialType, authoritative bool, expires time.Time) *lifecycle.Record {
		return &lifecycle.Record{Type: t, ExpiryAuthoritative: authoritative, ExpiresAt: expires}
	}

	tests := []struct {
		name          string
		rec           *lifecycle.Record
		revokeErr     error
		wantStatus    lifecycle.Status
		wantOutcome   lifecycle.RevokeOutcome
		wantAlerting  bool
		wantsTerminal bool
	}{
		{"revoke succeeded", rec(credentials.CredentialTypeStatic, false, past), nil, lifecycle.StatusExpired, lifecycle.RevokeOutcomeUpstream, false, true},
		{"provider expires it, said when, and it has passed", rec(credentials.CredentialTypeDynamic, true, past), credentials.ErrRevokeNotSupported, lifecycle.StatusExpired, lifecycle.RevokeOutcomeExpiryOnly, false, true},
		{"provider expires it but that time has not come", rec(credentials.CredentialTypeDynamic, true, future), credentials.ErrRevokeNotSupported, lifecycle.StatusPendingRevoke, lifecycle.RevokeOutcomeNone, true, false},
		{"expiry is only our belief", rec(credentials.CredentialTypeDynamic, false, past), credentials.ErrRevokeNotSupported, lifecycle.StatusPendingRevoke, lifecycle.RevokeOutcomeNone, true, false},
		{"static material never expires itself", rec(credentials.CredentialTypeStatic, true, past), credentials.ErrRevokeNotSupported, lifecycle.StatusPendingRevoke, lifecycle.RevokeOutcomeNone, true, false},
		{"provider gone, authoritative and lapsed", rec(credentials.CredentialTypeDynamic, true, past), lifecycle.ErrProviderNotRegistered, lifecycle.StatusExpired, lifecycle.RevokeOutcomeUntracked, false, true},
		{"provider gone, static", rec(credentials.CredentialTypeStatic, false, past), lifecycle.ErrProviderNotRegistered, lifecycle.StatusPendingRevoke, lifecycle.RevokeOutcomeUntracked, true, false},
		{"transient", rec(credentials.CredentialTypeStatic, false, past), credentials.ErrTransient, lifecycle.StatusPendingRevoke, lifecycle.RevokeOutcomeNone, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lifecycle.ExpiryDisposition(tc.rec, now, tc.revokeErr)
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tc.wantStatus)
			}
			if got.RevokeOutcome != tc.wantOutcome {
				t.Errorf("RevokeOutcome = %q, want %q", got.RevokeOutcome, tc.wantOutcome)
			}
			if got.Alert != tc.wantAlerting {
				t.Errorf("Alert = %v, want %v", got.Alert, tc.wantAlerting)
			}
			if got.Status.Terminal() != tc.wantsTerminal {
				t.Errorf("Terminal() = %v, want %v", got.Status.Terminal(), tc.wantsTerminal)
			}
		})
	}
}

// TestRevokeDispositionOnlyFinalizesOnASuccessfulRevoke is the regression test for
// the second finalizer. Direct revoke used to turn ErrRevokeNotSupported straight
// into terminal StatusRevoked with RevokeOutcomeExpiryOnly, closing out records
// whose material was still working -- for authoritative dynamic material until its
// future expiry, and for static material indefinitely.
func TestRevokeDispositionOnlyFinalizesOnASuccessfulRevoke(t *testing.T) {
	now := time.Now().UTC()

	// Even the most favorable case -- dynamic material with an authoritative expiry
	// still in the future -- is live, so revoke may not finalize it. RevokeDisposition
	// takes no record at all now: every judgment that depends on one belongs to the
	// single finalizer below.
	got := lifecycle.RevokeDisposition(credentials.ErrRevokeNotSupported)
	if got.Status.Terminal() {
		t.Errorf("Status = %q; revoke must not finalize material that is still live", got.Status)
	}
	if got.RevokeOutcome == lifecycle.RevokeOutcomeExpiryOnly {
		t.Error("revoke asserted expiry_only; only ExpiryDisposition may conclude material has lapsed")
	}
	if !got.Alert {
		t.Error("an unrevocable revoke request should alert")
	}

	// Once that expiry passes, the centralized rule finalizes it -- one finalizer,
	// reached from the reconciler rather than from the request path.
	lapsed := &lifecycle.Record{Type: credentials.CredentialTypeDynamic, ExpiryAuthoritative: true, ExpiresAt: now.Add(-time.Minute)}
	final := lifecycle.ExpiryDisposition(lapsed, now, credentials.ErrRevokeNotSupported)
	if final.Status != lifecycle.StatusExpired || final.RevokeOutcome != lifecycle.RevokeOutcomeExpiryOnly {
		t.Errorf("expiry disposition after lapse = %+v, want expired/expiry_only", final)
	}

	// A successful upstream revoke is the one thing that finalizes here.
	if got := lifecycle.RevokeDisposition(nil); got.Status != lifecycle.StatusRevoked || got.RevokeOutcome != lifecycle.RevokeOutcomeUpstream {
		t.Errorf("RevokeDisposition(nil) = %+v, want revoked/upstream", got)
	}

	// Transient and unregistered-provider failures also stay non-terminal.
	for _, err := range []error{credentials.ErrTransient, lifecycle.ErrProviderNotRegistered} {
		if got := lifecycle.RevokeDisposition(err); got.Status.Terminal() {
			t.Errorf("RevokeDisposition(%v) finalized the record", err)
		}
	}
}

// TestStaticCredentialCannotBeIssuedThenAbandoned walks the two rules together,
// which is the property that actually matters: there is no path from a legal
// issuance to a live credential the platform has stopped tracking.
func TestStaticCredentialCannotBeIssuedThenAbandoned(t *testing.T) {
	unrevocable := withCaps(credentials.Capabilities{Static: true, Revoke: false, RecoverCreate: true})
	policy := policyFor(credentials.CredentialTypeStatic)
	policy.MaxTTL = map[credentials.CredentialType]time.Duration{credentials.CredentialTypeStatic: time.Hour}

	if err := lifecycle.CheckIssuable(unrevocable, policy, credentials.CredentialTypeStatic); err == nil {
		t.Fatal("issuance was permitted for static material nothing can revoke")
	}

	// And if such a record exists anyway -- ported from an older system, or issued
	// before a provider regressed -- neither finalizer closes it out.
	now := time.Now().UTC()
	rec := &lifecycle.Record{Type: credentials.CredentialTypeStatic, Status: lifecycle.StatusActive, ExpiresAt: now.Add(-time.Hour)}
	if lifecycle.ExpiryDisposition(rec, now, credentials.ErrRevokeNotSupported).Status.Terminal() {
		t.Error("expiry finalized a live static credential")
	}
	if lifecycle.RevokeDisposition(credentials.ErrRevokeNotSupported).Status.Terminal() {
		t.Error("revoke finalized a live static credential")
	}
}
