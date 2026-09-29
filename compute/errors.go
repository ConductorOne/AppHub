// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"errors"
	"fmt"
)

// The error taxonomy every provider must map its native errors onto.
//
// Business logic above this boundary branches on these and nothing else. The
// source system branched on AWS error shapes directly — string matching for
// "RepositoryNotFoundException" (build.go:434-441), errors.As against
// *s3types.BucketAlreadyOwnedByYou (bucket.go:232), a smithy APIError code for
// "InvalidPermission.Duplicate" (build.go:872-878) — and every one of those
// checks is a provider dependency hiding in a conditional.
//
// Providers wrap, they do not replace: an implementation should return an error
// that satisfies errors.Is against the sentinel here while still carrying the
// underlying cause for logs.
var (
	// ErrUnsupported reports that the provider structurally cannot do what was
	// asked. Returned by the [Provider] port accessors for a capability the
	// provider lacks, and by any method whose spec requests a capability the
	// provider lacks. It is never transient: retrying cannot help, and a caller
	// that retries it has misread the error.
	ErrUnsupported = errors.New("compute: capability not supported by provider")

	// ErrNotFound reports that a named or referenced resource does not exist.
	ErrNotFound = errors.New("compute: resource not found")

	// ErrNotOwned reports that the desired name is taken by a resource this
	// platform does not own, so proceeding would mutate somebody else's
	// infrastructure. This is the generalisation of the ownership-tag refusal in
	// bucket.go:776-800 (ErrNotC1DatasourceRole), which exists because resource
	// names are derived from mutable application names and can collide. Every
	// provider must implement an ownership check; adopting an untagged resource
	// is not permitted.
	//
	// A substrate's optimistic-concurrency conflict is NOT this error. It is
	// [ErrTransient]. The distinction matters enough that this sentinel was
	// renamed from ErrConflict to say what it means: Kubernetes returns HTTP 409
	// both for "that name is taken" and for "your copy is stale, read and try
	// again", and an implementer who maps 409 to a sentinel called "conflict"
	// makes every routine reconcile race look to the caller like a collision
	// with somebody else's infrastructure. The name was the trap; the name is
	// gone.
	ErrNotOwned = errors.New("compute: resource exists and is not managed by this platform")

	// ErrTransient reports a failure that may succeed if the same call is
	// retried unchanged: a throttled API, a stale-read conflict on an
	// optimistic-concurrency update, a reset connection. It is the only
	// sentinel here that says "try again"; every other one is terminal for the
	// call that produced it.
	//
	// A provider MAY retry internally — most substrates need to, and a caller
	// should not have to know that an update is read-modify-write underneath.
	// Two obligations bound that discretion:
	//
	//   - A provider MUST NOT retry past its caller's context deadline. The
	//     caller chose the deadline; an internal budget that outlives it takes
	//     back the control [Status] and [WaitOptions] exist to give.
	//   - A provider MUST return this, not [ErrFailed], when it gives up on
	//     something that could still succeed. [ErrFailed] tells the caller the
	//     spec has to change, and a caller that believes that about a
	//     throttling error stops a deploy that would have worked.
	//
	// Retrying is the caller's decision because only the caller knows what else
	// is in flight and how long the operator will wait. Nothing in this package
	// retries on a caller's behalf.
	ErrTransient = errors.New("compute: transient failure, may succeed if retried")

	// ErrInvalidSpec reports that the spec cannot be satisfied as written — a
	// name too long for the substrate, a CPU/memory pair with no legal
	// equivalent, an HTTPS listener with no certificate. It is a caller bug, not
	// an infrastructure failure.
	ErrInvalidSpec = errors.New("compute: invalid specification")

	// ErrTimeout reports that a Wait* call's deadline elapsed before the
	// resource reached the requested phase. The resource may still converge; the
	// caller decides whether to wait again or fail the deploy. Distinguishing
	// this from [ErrFailed] matters: the source system's polling loops returned
	// a bare "timed out" that callers could not tell from a hard failure
	// (source system @ backend/internal/modules/deploy/database.go and
	// container.go).
	ErrTimeout = errors.New("compute: timed out waiting for resource")

	// ErrNotPermitted reports that the substrate refused the operation because of
	// the platform's own credentials: they were not allowed to do what apphub
	// asked, or they were not accepted at all.
	//
	// # Authorization and authentication are both here, deliberately
	//
	// A 403 and a 401 land on the same sentinel -- "you may not" and "I do not
	// accept you" -- and that is a decision rather than an oversight. The
	// discriminator this taxonomy uses is not what went wrong but who can fix it
	// and whether the same request could ever succeed, and on both counts they are
	// the same answer: an operator, and not without changing something outside the
	// request.
	//
	// The objection worth answering is that a rejected credential might be a
	// rotation race, which a retry would survive -- and if so, a terminal sentinel
	// would suppress a retry that would have worked, which is the mistake
	// [ErrTransient] exists to prevent. It does not apply, because credential
	// refresh happens *below* this layer in both substrates surveyed: the AWS SDK
	// refreshes in the credential provider rather than by retrying the call, and
	// its standard retryer classifies ExpiredToken as not retryable; client-go
	// refreshes a projected ServiceAccount token and retries once inside its own
	// transport. So a rejection that reaches a provider's error mapping has
	// already outlived the refresh, and calling it terminal is accurate rather
	// than pessimistic.
	//
	// A provider should still say *which* in the wrapped message. "Add a
	// permission" and "the token was rejected" send the same person to different
	// places.
	//
	// # The one thing it does not mean
	//
	// "Not permitted" has three readings and only the first is this:
	//
	//   - the credentials *apphub* runs with lack a permission -- this sentinel;
	//   - the caller asked for something a policy forbids -- not this sentinel;
	//   - a deployed *workload* was refused access to something -- not this
	//     sentinel, and not anything in this package.
	//
	// The third is the one to return this sentinel for by mistake. A workload's
	// access is decided when the runtime hands it an identity and a [Granter]
	// authorises that identity; whether the workload is then allowed to read its
	// own bucket is settled between the workload and the substrate at runtime, on
	// a path apphub is not on. Nothing in this interface can observe it and no
	// error here reports it. Two providers wrote that sentence independently
	// before this comment existed, which is how likely the confusion is.
	//
	// The second reading is the one to be careful about, because the interesting
	// cases look like it. A guardrail that refuses a bucket outside an approved
	// region, or a resource policy that refuses a particular action, reads like
	// "the request was disallowed" -- and it is still this sentinel, because the
	// thing that has to change is the guardrail or the platform's grant under it,
	// not the caller's spec. A provider maps a substrate denial here whatever
	// provoked it.
	//
	// [ErrInvalidSpec] is for a spec the *substrate's own rules* cannot express at
	// all -- a name too long, a CPU and memory pair with no legal equivalent. The
	// test between them is not who is at fault but who can fix it: if granting a
	// permission or relaxing a policy would make the identical request succeed,
	// it is this one.
	//
	// # Whose problem it is, which is the whole reason it exists
	//
	// The name follows [ErrNotOwned]'s convention and describes the situation from
	// apphub's own point of view -- *we* are not permitted -- rather than
	// naming a substrate's status code. A caller's spec has nothing to do with it
	// and changing the spec cannot fix it; what has to change is an IAM policy, a
	// Kubernetes RBAC binding, an organization-level guardrail, or a resource
	// policy. That is an operator's job, and it is a different person from the
	// one who owns a failing application.
	//
	// Before this sentinel existed there was nowhere for it to go but [ErrFailed],
	// whose documentation says the resource "reached a terminal failed phase" and
	// is "not retryable without changing the spec". Both halves are false for a
	// denial: no resource reached any phase, and no spec change helps. So a
	// surface above this interface could not route a permission failure to the
	// operator and a resource failure to the application owner without parsing
	// prose -- and six AWS providers were about to write six different prose
	// spellings of it (USOSS-13, USOSS-40).
	//
	// # It is terminal, and it is not [ErrInvalidSpec]
	//
	// Terminal for the call: retrying the same request with the same permissions
	// cannot succeed, so a caller must not treat it as [ErrTransient]. It is not
	// [ErrInvalidSpec] either, and the distinction is the point -- ErrInvalidSpec
	// sends a reader to the request they made, which is the wrong place to look
	// and the wrong person to ask.
	ErrNotPermitted = errors.New("compute: the platform's own credentials are not permitted to do this")

	// ErrFailed reports that the resource reached a terminal failed phase. Not
	// retryable without changing the spec.
	//
	// It is the last resort of the taxonomy, so it is worth saying what it is
	// *not*. An authorization failure is [ErrNotPermitted], not this: neither
	// half of the sentence above is true of a denial, because no resource reached
	// a phase and no spec change helps. A provider author who reads this doc,
	// correctly concludes a denial does not belong here, and then finds nowhere
	// else to put it is how a taxonomy grows six local spellings of one idea --
	// which is why the qualification is here and not only on the other sentinel.
	ErrFailed = errors.New("compute: resource entered a failed state")

	// ErrForeignRef reports that a [Ref] was issued by a different provider. See
	// [Ref] for why this is a hard error rather than a best-effort attempt.
	ErrForeignRef = errors.New("compute: reference was issued by a different provider")
)

// ErrVersionPinningUnsupported reports that a [SecretBinding.Version] was
// supplied to a provider whose store has no revisions.
//
// It wraps [ErrUnsupported], so a caller that already branches on that sentinel
// sees it without changing, and it is distinguishable for a caller that wants to
// tell "this provider cannot pin" from "this provider has no such port".
//
// It exists because the alternative is the defect the field was added to close.
// A provider that ignored a version it could not honour would hand back a
// workload bound to the latest value while its caller believed it was pinned —
// the same silent degradation, one layer further in, and now with a field in the
// interface implying otherwise. Refusing is the only answer that leaves the
// caller knowing what it got.
var ErrVersionPinningUnsupported = fmt.Errorf(
	"%w: this provider's secret store has no versions to pin to", ErrUnsupported)

// UnsupportedError is the concrete error a [Provider] returns when asked for a
// capability it does not have. It names the provider and the capability so the
// operator can see which of the two to change, and satisfies errors.Is against
// [ErrUnsupported].
type UnsupportedError struct {
	// Provider is the [Provider.Name] that refused.
	Provider string
	// Capability is what was asked for.
	Capability Capability
	// Detail optionally explains why, for capabilities a provider could
	// plausibly have but does not in this configuration.
	Detail string
}

func (e *UnsupportedError) Error() string {
	msg := fmt.Sprintf("compute: provider %q does not support capability %q", e.Provider, e.Capability)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Unwrap makes errors.Is(err, ErrUnsupported) true.
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

// Unsupported builds an [UnsupportedError]. Providers use it in their port
// accessors so that the refusal is uniform across implementations.
func Unsupported(provider string, capability Capability) error {
	return &UnsupportedError{Provider: provider, Capability: capability}
}
