// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import "time"

// Phase is where a resource is in its convergence toward the desired state.
type Phase string

const (
	// PhasePending means the provider has accepted the spec and the resource is
	// converging. Not an error.
	PhasePending Phase = "pending"
	// PhaseReady means the resource is serving.
	PhaseReady Phase = "ready"
	// PhaseFailed means convergence stopped and will not resume without a
	// change to the spec.
	PhaseFailed Phase = "failed"
	// PhaseDeleting means teardown is in progress.
	PhaseDeleting Phase = "deleting"
	// PhaseGone means the resource does not exist. Returned by a Describe on a
	// resource that was deleted, so teardown can be re-run without treating a
	// second pass as an error.
	PhaseGone Phase = "gone"
)

// Status is the part of every asynchronous resource's status that is the same
// across ports.
//
// # Two classes of port
//
// It would be tidier to claim that every Ensure is asynchronous. It would also
// be false: of the seven provisioning paths in the source system, four poll for
// readiness and three do not. Overclaiming here would be worse than a small
// inconsistency, because the conformance suite encodes whatever this says, and
// an invariant applied to a port that cannot satisfy it is a broken test rather
// than a caught bug.
//
// Asynchronous ports — container services, functions, function endpoints,
// relational endpoints, key-value tables. Ensure returns a status-bearing type
// promptly, possibly [PhasePending]; Describe reports current state including
// [PhaseGone]; a Wait method blocks with a caller-chosen deadline. These are the
// ports the rules below apply to, and the ones the conformance suite exercises
// for prompt return, [PhaseGone] after delete, and deadline behaviour.
//
// Synchronous ports — image repositories, buckets, secrets, workload
// identities, scheduled jobs. Ensure returns the resource itself, there is no
// phase and no Wait, and the resource is usable when the call returns. The
// source system creates all of them with no polling loop (build.go:282-348,
// bucket.go:217-288, container.go:1138-1154, container.go:1382-1490), which is
// the evidence this class exists at all.
//
// Scheduled jobs moved here rather than gaining a Wait. They were in the
// asynchronous class — a phase-bearing status — with no Wait method, which left
// three conformance invariants unverifiable and gave a caller no supported way
// to block. The resolution went the other way because there is nothing to wait
// for: a cron entry is live on acceptance on every substrate named so far.
//
// A provider whose substrate makes a synchronous-class resource asynchronous
// must still return only once the resource is usable, or return [ErrTimeout].
// It must not return a half-created resource and leave the caller to find out.
// If that ever becomes untenable for a real substrate, the fix is to promote
// that port to the asynchronous class here — a visible, reviewable interface
// change — not to relax the rule inside an implementation.
//
// # Why Ensure and Wait are separate
//
// This is a deliberate departure from the source system. There, provisioning
// blocks inline: up to ten minutes for an Aurora cluster and ten more for its
// instance (source system @ backend/internal/modules/deploy/database.go, funcs
// ensureAuroraCluster and ensureAuroraInstance), two minutes for an ECS service
// (source system @ backend/internal/modules/deploy/container.go), two for a
// DynamoDB table (source system @ backend/internal/modules/deploy/database.go),
// and a half for an ALB (source system @ backend/internal/modules/deploy/lambda.go).
// Those loops run inside a
// synchronous deploy request, they hardcode their own timeouts, and a caller
// cannot shorten one or run two in parallel.
//
// Here, an asynchronous port's Ensure returns promptly with a Status that may
// be [PhasePending], and waiting is a separate call with a caller-chosen
// deadline. A provider that blocks inside such an Ensure is non-conformant.
// This is portable — every substrate's create API is asynchronous underneath —
// and it is what lets a deploy provision a bucket and a database concurrently
// instead of adding their worst cases together.
// # Every read-back carries its effective spec
//
// Each port's status or descriptor has a Spec field holding the desired state
// the provider is converging to, as it understood it. A provider MUST populate
// it.
//
// It is **provider-reported desired state, not an observation of the
// substrate**, and the distinction is load-bearing. A caller can see from it
// that the provider *believes* the environment variable it removed is gone,
// which catches the common failure — an Ensure implemented as create-or-add
// accumulates and then reports the accumulation. It cannot catch a provider
// that reports the new spec while leaving the old object in place, because
// nothing a provider says about itself can establish what it did.
//
// An earlier revision of this comment claimed the field removed the need for an
// independent substrate observation. It does not, and a reviewer demonstrated
// it: a wrapper reporting the new spec from Describe and Wait while the
// underlying object kept the old one satisfied every interface-level check.
// Convergence is verified by looking at the substrate, and the conformance suite
// records it as unverified when nothing does.
//
// It is also nearly free. The substrate is already holding the desired state —
// a Kubernetes object literally stores it, and even on AWS a provider assembling
// a status has the spec it just wrote in hand. Throwing it away was the
// interface losing information it had.
//
// A read-back must not share storage with what the provider holds. Returning the
// map a provider stored lets a caller rewrite the provider's own state by
// editing a label it was shown, and a caller has no way to know it happened. The
// conformance suite checks it on every port.
//
// [SecretStore] is the one port with no Spec, and deliberately: a secret's
// declarative state *is* its value, [SecretStore.Get] already returns it, and a
// descriptor echoing the rest would add a second place material could leak from
// for no information a caller does not already have. Where a spec is carried and
// contains material — [RelationalSpec.AdminPassword] — the provider zeroes it.
type Status struct {
	// Ref addresses the resource.
	Ref Ref
	// Phase is where it is.
	Phase Phase
	// Message is human-readable detail for the operator, especially the reason
	// for [PhaseFailed]. It must never contain credential material.
	//
	// It may be empty in any phase. A provider SHOULD explain a [PhaseFailed],
	// and SHOULD say so here when it has adjusted a spec it could not honour
	// exactly — rounding an allocation up, or narrowing a capacity range — since
	// that is the caller's only notice of it.
	Message string
	// UpdatedAt is when the provider observed this state, on the provider's own
	// clock.
	//
	// "Observed" means the read, not the substrate's own timestamp for the
	// transition. The two differ and the difference is not small: a Kubernetes
	// condition's lastTransitionTime is when a controller wrote it, which may be
	// minutes earlier than a read from a watch cache, and a provider reporting
	// that would look stale to a caller polling for progress. Callers may
	// compare it across successive reads from one provider and must not compare
	// it across providers or treat it as substrate truth.
	UpdatedAt time.Time
}

// WaitOptions controls a Wait* call.
type WaitOptions struct {
	// Timeout bounds the wait. Zero means "use the context deadline"; if the
	// context has none either, the provider must return [ErrInvalidSpec] rather
	// than wait forever.
	Timeout time.Duration

	// OnUpdate, when set, is called each time the provider observes a state
	// change, including the first observation. It exists so the deploy module
	// can drive its progress reporting from real state instead of guessing —
	// the source system interpolates a percentage from the loop counter
	// (source system @ backend/internal/modules/deploy/container.go), which
	// reports progress for a service that is
	// making none.
	//
	// It is called synchronously from the waiting goroutine. It must not block,
	// and it must not be relied on for correctness: a provider may coalesce
	// updates.
	OnUpdate func(Status)
}
