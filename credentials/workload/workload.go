// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// Ref names the workload an identity belongs to.
type Ref struct {
	// ApplicationID is the platform's identifier for the deployed application.
	ApplicationID string
	// Revision is the attestation revision, as returned by Provisioner.Rotate.
	Revision int
}

// Materials is everything a workload needs in order to obtain its own identity
// token, in the two shapes a compute provider can actually deliver.
//
// The division is the security property. Env holds values the compute layer may
// read, log and put in a workload specification, because none of them are secret:
// an endpoint URL, an audience, an application ID. Secrets holds *references*
// only, so the compute layer wires up "read this, expose it as that" without the
// value ever entering the compute code path — which is what lets the attestation
// secret rotate on every deploy without the deploy code ever holding it.
type Materials struct {
	// Env is non-secret environment variables to set on the workload.
	Env map[string]string

	// Secrets are secret-store references to inject. The target variable name is
	// on the reference (credentials.SecretRef.EnvVar).
	//
	// Converting these into whatever the selected compute provider binds is the
	// deploy layer's job. Neither this package nor compute performs that
	// conversion: only the deploy layer knows which provider is in play, and it
	// must fail loudly if the named store does not belong to that provider.
	Secrets []credentials.SecretRef
}

// Provisioner is what the deploy path calls on the credential side. It is the
// entire credential-facing surface of provisioning a workload.
//
// The sequence is fixed: Rotate, then Materials with the returned revision. Two
// methods suffice, and both reviews of the parallel designs confirmed it
// independently — a compute provider that needs a third has taken on a credential
// responsibility that belongs on this side of the line.
type Provisioner interface {
	// Rotate invalidates the current attestation material and issues new material,
	// returning the new revision.
	//
	// Rotating on every deploy bounds the value of a leaked attestation secret to
	// the time until the next deployment, and it is nearly free because the
	// workload is being replaced anyway.
	Rotate(ctx context.Context, ref Ref) (revision int, err error)

	// Materials returns what to inject for this workload. The caller passes the
	// revision returned by Rotate in ref.
	Materials(ctx context.Context, ref Ref) (Materials, error)
}

// ErrAttestationRejected is returned for any failed verification.
//
// One error for every failure mode is deliberate. Distinguishing "the identity
// did not verify" from "no workload is bound to it" from "the deploy secret was
// wrong" tells an unauthenticated caller which half of its proof was right, which
// is an oracle. Detail goes to the platform's own logs.
var ErrAttestationRejected = errors.New("workload attestation rejected")

// Verifier turns a proof into a verified identity, or rejects it.
//
// It has exactly one method, and that is a property of the normative contract
// rather than a stylistic choice: the contract froze this interface so that a
// verifier written against the document satisfies it, and any method added here —
// however useful — makes an outside implementation of the frozen contract fail to
// compile. An earlier version of this interface also required Method(), which had
// exactly that effect. Dispatch metadata belongs next to the verifier, in
// VerifierRegistry, not inside the contract.
//
// The expected value is an explicit parameter rather than something the
// implementation looks up. A verifier that fetches its own expectations cannot be
// tested in isolation and cannot be reasoned about: what it checks against
// becomes a property of whatever database it happens to be pointed at.
//
// Implementations must confirm the proof resolves exactly to expected.Subject and
// satisfies the issuer and audience obligations, and must never trust a subject
// carried inside the proof — a proof asserting who it is proves nothing.
type Verifier interface {
	// Verify checks proof against expected. Every failure returns
	// ErrAttestationRejected.
	Verify(ctx context.Context, expected ExpectedAttestation, proof AttestationProof) (Identity, error)
}

// VerifierRegistry selects a Verifier by attestation scheme.
//
// The scheme a verifier handles is named at registration rather than by the
// verifier itself, which is what keeps Verifier at the one method the contract
// specifies. It also puts the mapping somewhere a reader can see all of it at
// once: which schemes a deployment accepts is a property of its wiring, not
// something to be recovered by asking each verifier in turn.
type VerifierRegistry struct {
	mu       sync.RWMutex
	byMethod map[Method]Verifier
}

// NewVerifierRegistry returns an empty registry. Empty means no attestation scheme
// is accepted, which is the right starting point: a deployment accepts the schemes
// it wired up and no others.
func NewVerifierRegistry() *VerifierRegistry {
	return &VerifierRegistry{byMethod: make(map[Method]Verifier)}
}

// Register binds a verifier to a scheme, refusing to replace an existing binding.
//
// Refusing rather than overwriting matters more here than in most registries: two
// verifiers for one scheme means two different opinions about what proves an
// identity, and letting the last registration win would make which opinion applies
// depend on wiring order.
func (r *VerifierRegistry) Register(m Method, v Verifier) error {
	if m == "" {
		return errors.New("workload: attestation method is required")
	}
	if v == nil {
		return fmt.Errorf("workload: verifier for method %s is nil", credentials.NewForeign(string(m)))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byMethod[m]; exists {
		return fmt.Errorf("workload: verifier for method %s already registered", credentials.NewForeign(string(m)))
	}
	r.byMethod[m] = v
	return nil
}

// For returns the verifier registered for a scheme.
func (r *VerifierRegistry) For(m Method) (Verifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.byMethod[m]
	return v, ok
}

// Methods returns the schemes this registry accepts, for diagnostics.
func (r *VerifierRegistry) Methods() []Method {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Method, 0, len(r.byMethod))
	for m := range r.byMethod {
		out = append(out, m)
	}
	return out
}

// Verify dispatches on the expected scheme and checks the proof against it.
//
// The proof does not choose the scheme: expected does. A proof claiming a
// different Method than the workload's stored policy is rejected rather than
// routed, because letting a submitter pick its verifier is letting it pick the
// weakest one available.
//
// An unregistered scheme also returns ErrAttestationRejected rather than a
// distinguishable "no such verifier". The caller is unauthenticated at this point,
// and an error enumerating which schemes a deployment accepts is an oracle for the
// same reason the failure modes are not distinguished. Operators get the detail
// from the platform's own logs.
func (r *VerifierRegistry) Verify(ctx context.Context, expected ExpectedAttestation, proof AttestationProof) (Identity, error) {
	if expected.Method == "" || proof.Method != expected.Method {
		return Identity{}, ErrAttestationRejected
	}
	v, ok := r.For(expected.Method)
	if !ok {
		return Identity{}, ErrAttestationRejected
	}
	return v.Verify(ctx, expected, proof)
}

// Identity is a verified workload identity. Everything on it was proved, not
// asserted.
type Identity struct {
	// Subject is the resolved identity, equal to the ExpectedAttestation.Subject
	// it was checked against. It is the canonical name of the workload and what
	// the minted token is issued for.
	Subject string
	// Method is the scheme that proved it.
	Method Method
	// Attributes is verified, non-secret, scheme-specific detail. Kept as a map so
	// that a second scheme does not widen this struct and so that nothing outside
	// the verifier has to understand it.
	//
	// Values can name internal topology (an account, a cluster), so they belong in
	// the platform's own logs and not in third-party sinks.
	Attributes map[string]string
}

// TokenIssuer mints the short-lived token a verified workload uses to call the
// platform.
//
// The token is a credential, which is why it is minted here and not in compute:
// its audience, lifetime and claims are credential-policy decisions, and its
// signing key is one the compute layer has no business holding.
type TokenIssuer interface {
	// IssueToken mints a token for a verified identity. TTL is a request; the
	// implementation may shorten it and reports what it did.
	IssueToken(ctx context.Context, id Identity, ttl time.Duration) (Token, error)
}

// Token is a minted workload identity token.
type Token struct {
	// Value is the token. It is material.
	Value credentials.Secret
	// Audience is who the token is for. A workload token must never be accepted by
	// anything other than its audience.
	Audience string
	// ExpiresAt is when it stops working.
	ExpiresAt time.Time
}

// DefaultTokenTTL is the lifetime of a workload identity token.
//
// One hour matches the source system (WorkloadTokenTTL,
// backend/internal/services/workload.go:23). It is short because a workload can
// always attest again — its attestation material does not expire — so there is
// nothing to gain from a longer-lived token and a leaked one is worth an hour.
const DefaultTokenTTL = time.Hour
