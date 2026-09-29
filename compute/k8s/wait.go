// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/conductorone/apphub/compute"
)

// pollInterval is how often a wait re-reads **when the substrate cannot report
// changes**.
//
// It is the fallback, not the mechanism. A [Cluster] that implements [Watcher] —
// [ClientCluster] does — makes [Provider.waitFor] block on a change instead, so
// a production wait against a real API server never runs this timer. Two
// substrates still do:
//
//   - [MemoryCluster], whose clock *is* the read: convergence advances on
//     observation, so a watch on it would wait forever for a write that only a
//     reader can cause. Deliberately not a [Watcher], and the reason the interval
//     is a millisecond rather than a second — nothing is actually being waited
//     for, the loop is only stepping the controllers along.
//   - a [ClientCluster] whose watch has died and could not be re-established.
//     Falling back to polling turns that into a slower wait rather than a hang.
//
// USOSS-27's report claimed there were "no sleeps anywhere in the package". That
// was not true when it was written — this timer was, and still is, on a live path.
//
// The first correction to that claim was itself too strong. It said the *watched*
// path "contains no timer", and it does contain one: [awaitChange] arms
// time.NewTimer for the caller's remaining deadline on both paths, because a wait
// has to be able to give up. What the read-count comparison in
// [TestAWatchedWaitDoesNotPoll] actually establishes is the property that matters,
// and it is narrower: **the watched path runs no periodic poll timer.** One
// deadline timer that fires at most once is not polling; a millisecond ticker that
// re-reads is. The test measures reads, not timers, which is why it was right while
// the sentence over it was wrong.
const pollInterval = time.Millisecond

// waitFor is the shared body of every Wait* method.
//
// The contract it implements is the one [compute.Status] states: the caller
// chooses the deadline, a Wait with neither a timeout nor a context deadline is
// refused rather than waiting forever, and OnUpdate is called synchronously
// from this goroutine so that a caller may tear down whatever the callback
// touches the moment the call returns.
//
// # Watch, then poll
//
// Between observations it blocks on whichever of three things happens first: the
// substrate reporting that the object changed, the deadline elapsing, or the
// caller's context being cancelled. When the substrate cannot report changes it
// blocks on a short timer instead, which is the same loop with a worse clock.
//
// A tick carries no payload deliberately: every observation goes through the
// same read every other code path uses, so there is exactly one source of truth
// for the object's state. A watch that delivered the object would give this loop
// two, and they can disagree.
func (p *Provider) waitFor(
	ctx context.Context,
	opts compute.WaitOptions,
	ref compute.Ref,
	observe func() (compute.Status, bool, error),
) (compute.Status, error) {
	deadline, ok := waitDeadline(ctx, opts)
	if !ok {
		return compute.Status{}, fmt.Errorf("%w: a wait needs either WaitOptions.Timeout or a "+
			"context deadline; no path may wait forever", compute.ErrInvalidSpec)
	}

	changes, stop := p.watchChanges(ctx, ref)
	defer stop()

	type observed struct {
		ref     compute.Ref
		phase   compute.Phase
		message string
	}
	var last observed
	var reported bool
	for {
		st, done, err := observe()
		if err != nil {
			return st, err
		}
		// UpdatedAt deliberately does not take part: it changes on every read,
		// and a callback that fired for it would report progress a resource is
		// not making — the defect OnUpdate exists to fix.
		now := observed{st.Ref, st.Phase, st.Message}
		if !reported || now != last {
			last, reported = now, true
			if opts.OnUpdate != nil {
				opts.OnUpdate(st)
			}
		}
		switch {
		case done:
			return st, nil
		case st.Phase == compute.PhaseFailed:
			return st, fmt.Errorf("%w: %s", compute.ErrFailed, st.Message)
		case st.Phase == compute.PhaseGone:
			return st, fmt.Errorf("%w: the resource was deleted while waiting for it",
				compute.ErrNotFound)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return st, fmt.Errorf("%w: %s is still %s", compute.ErrTimeout, st.Ref, st.Phase)
		}
		switch outcome := awaitChange(ctx, changes, remaining); outcome {
		case changeObserved:
		case changeDeadline:
			return st, fmt.Errorf("%w: %s is still %s", compute.ErrTimeout, st.Ref, st.Phase)
		case changeCancelled:
			return st, fmt.Errorf("%w: %w", compute.ErrTimeout, ctx.Err())
		case changeSourceGone:
			// The watch died and could not be re-established. Drop to the poll
			// path for the rest of this wait: a slower wait is a far better
			// failure than a wait that never returns.
			changes = nil
		}
	}
}

// changeOutcome is why [awaitChange] returned.
type changeOutcome int

const (
	// changeObserved means the object may have changed, or the poll interval
	// elapsed. Either way: read it again.
	changeObserved changeOutcome = iota
	// changeDeadline means the caller's deadline elapsed first.
	changeDeadline
	// changeCancelled means the caller's context was cancelled first.
	changeCancelled
	// changeSourceGone means the change channel closed, so change notification
	// has stopped working.
	changeSourceGone
)

// awaitChange blocks until something worth re-reading for happens, or until
// remaining elapses.
//
// With no change channel it sleeps for the poll interval, capped at the time
// left, which is what keeps the fallback from overshooting a deadline it was
// given a millisecond before.
func awaitChange(ctx context.Context, changes <-chan struct{}, remaining time.Duration) changeOutcome {
	if changes == nil {
		wait := pollInterval
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return changeCancelled
		case <-timer.C:
			return changeObserved
		}
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return changeCancelled
	case <-timer.C:
		return changeDeadline
	case _, ok := <-changes:
		if !ok {
			return changeSourceGone
		}
		return changeObserved
	}
}

// watchChanges opens a change notification for the object behind ref, when the
// substrate can supply one.
//
// It returns a nil channel and a no-op stop whenever it cannot: the substrate is
// not a [Watcher], the ref names something with no cluster object behind it (a
// bucket, an image repository), or establishing the watch failed. Every one of
// those is a reason to poll rather than an error to report — the caller asked to
// wait for a resource, not to be told how the provider is watching it — so the
// only observable consequence is that the wait re-reads on a timer.
func (p *Provider) watchChanges(ctx context.Context, ref compute.Ref) (<-chan struct{}, func()) {
	noop := func() {}
	watcher, ok := p.sub.Cluster.(Watcher)
	if !ok {
		return nil, noop
	}
	gvk, namespace, name, err := p.locate(ref)
	if err != nil {
		return nil, noop
	}
	changes, stop, err := watcher.Watch(ctx, gvk, namespace, name)
	if err != nil {
		return nil, noop
	}
	return changes, stop
}

// waitDeadline resolves the deadline a wait must honour.
func waitDeadline(ctx context.Context, opts compute.WaitOptions) (time.Time, bool) {
	if opts.Timeout > 0 {
		return time.Now().Add(opts.Timeout), true
	}
	return ctx.Deadline()
}

// status builds the common half of every status the provider reports.
func (p *Provider) status(ref compute.Ref, phase compute.Phase, message string) compute.Status {
	return compute.Status{Ref: ref, Phase: phase, Message: message, UpdatedAt: p.clock.now()}
}

// gone is the status of a resource that does not exist.
func (p *Provider) gone(ref compute.Ref) compute.Status {
	return p.status(ref, compute.PhaseGone, "")
}
