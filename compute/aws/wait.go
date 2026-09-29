// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/conductorone/apphub/compute"
)

// DefaultPollInterval is how often a Wait re-reads, unless an operator says
// otherwise.
//
// # Why this is seconds and why it is configuration
//
// The first version was one millisecond, with a comment admitting it was wrong
// for a real account and asserting that the SDK's retryer and token bucket made
// it polite anyway. That assertion was false and review measured it: **a 40ms
// wait made 38 successful provider reads.** The retry machinery bounds
// *failures* — it decides whether to try again and how long to back off — and
// does nothing at all to a successful DescribeDBClusters. A multi-minute Aurora
// creation would therefore have issued roughly a thousand successful reads a
// second until AWS throttled it, at which point the port would have returned
// ErrTransient immediately rather than continuing the caller's Wait: the polling
// would have converted its own impoliteness into a spurious failure.
//
// Five seconds is the production default, which for a cluster that takes minutes
// costs a handful of reads and at most one interval of latency after readiness.
// It is [Config.PollInterval] rather than a constant because a hermetic suite
// needs a fast one — test speed is not a substrate contract, so the fast value
// belongs in the test's configuration and not in the provider's default.
const DefaultPollInterval = 5 * time.Second

// MinPollInterval is the floor a configured interval is raised to.
//
// Zero or negative means "use the default", and anything positive is honoured
// down to this floor, so a test can ask for something fast without a provider
// being configurable into the hammering the default is written against. A floor
// rather than a refusal because a value below it is a plausible thing to want in
// a test and an implausible thing to want in production.
const MinPollInterval = time.Millisecond

// pollInterval resolves the interval a Wait re-reads at.
func (c *Config) pollInterval() time.Duration {
	switch {
	case c.PollInterval <= 0:
		return DefaultPollInterval
	case c.PollInterval < MinPollInterval:
		return MinPollInterval
	default:
		return c.PollInterval
	}
}

// waitFor is the shared body of every Wait* method on this provider.
//
// It is the same contract [compute.Status] states and the same shape
// compute/k8s uses, and it is a separate implementation rather than a shared
// helper because the two providers share no package that could hold one. The
// contract, restated because it is the part that gets broken:
//
//   - the caller chooses the deadline;
//   - a Wait with neither a timeout nor a context deadline is refused rather
//     than waiting forever;
//   - OnUpdate is called synchronously from this goroutine, so a caller may tear
//     down whatever the callback touches the moment the call returns;
//   - OnUpdate fires on a *change*, not on every read.
//
// waiter is [waitFor]'s two substitutable pieces, so a test can assert on what
// the loop *asks for* rather than on what a machine under load happens to do.
//
// # Why this seam exists, and why it is not a clock in Config
//
// The first test for the poll interval counted successful reads inside a
// wall-clock window and asserted the count was small. Review demonstrated that
// this is a **scheduler measurement, not a code measurement**: with
// GOMAXPROCS(1) and 64 runnable goroutines the *correct* implementation failed
// five times out of five, while the idle control passed a hundred out of a
// hundred. A threshold tuned to a quiet machine is a flake with a plausible
// justification, and lowering the threshold only makes it a luckier one.
//
// So the property is observed through the sleep the loop **requests**. That is
// exact, deterministic, and load cannot perturb it: a loop asking for 5s and a
// loop asking for 1ms are distinguishable with no reference to elapsed time at
// all.
//
// It is a parameter on an unexported helper rather than a clock threaded through
// [Config] deliberately. Config is production surface an operator reads; this is
// two function values on an internal call, and nothing outside this package can
// see it.
type waiter struct {
	// sleep waits. Nil means [time.Sleep].
	sleep func(time.Duration)
	// now reports the current time. Nil means [time.Now].
	now func() time.Time
}

func (w waiter) doSleep(d time.Duration) {
	if w.sleep == nil {
		time.Sleep(d)
		return
	}
	w.sleep(d)
}

func (w waiter) timeNow() time.Time {
	if w.now == nil {
		return time.Now()
	}
	return w.now()
}

func waitFor(
	ctx context.Context,
	interval time.Duration,
	opts compute.WaitOptions,
	observe func() (compute.Status, bool, error),
) (compute.Status, error) {
	return waiter{}.waitFor(ctx, interval, opts, observe)
}

func (w waiter) waitFor(
	ctx context.Context,
	interval time.Duration,
	opts compute.WaitOptions,
	observe func() (compute.Status, bool, error),
) (compute.Status, error) {
	deadline, ok := w.waitDeadline(ctx, opts)
	if !ok {
		return compute.Status{}, fmt.Errorf("%w: a wait needs either WaitOptions.Timeout or a "+
			"context deadline; no path may wait forever", compute.ErrInvalidSpec)
	}

	// UpdatedAt deliberately does not take part in the comparison: it changes on
	// every read, and a callback that fired for it would report progress a
	// resource is not making — the defect OnUpdate exists to fix.
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
		// Never longer than the caller's remaining deadline, so a production
		// interval does not overshoot a short Wait — the caller chose the
		// deadline and the interval is this provider's business.
		if remaining := deadline.Sub(w.timeNow()); remaining <= 0 {
			return st, fmt.Errorf("%w: %s is still %s", compute.ErrTimeout, st.Ref, st.Phase)
		} else if remaining < interval {
			w.doSleep(remaining)
		} else {
			w.doSleep(interval)
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("%w: %w", compute.ErrTimeout, ctx.Err())
		default:
		}
	}
}

// waitDeadline resolves the deadline a wait must honour.
func (w waiter) waitDeadline(ctx context.Context, opts compute.WaitOptions) (time.Time, bool) {
	if opts.Timeout > 0 {
		return w.timeNow().Add(opts.Timeout), true
	}
	return ctx.Deadline()
}

// status builds the common half of every status this provider reports.
//
// UpdatedAt is always set, and the conformance suite is right to insist: a
// status with a zero timestamp gives an operator no way to tell a current
// observation from a stale one, and every asynchronous port's whole value is
// telling them where a resource is *now*.
//
// It reads the wall clock rather than taking one from configuration. There is no
// hermeticity cost — nothing asserts on the value, only that it is present and
// moves — and a clock threaded through [Config] would be a test seam in a
// production type, which is the shape this package has avoided elsewhere.
func (p *Provider) status(ref compute.Ref, phase compute.Phase, message string) compute.Status {
	return compute.Status{Ref: ref, Phase: phase, Message: message, UpdatedAt: time.Now().UTC()}
}

// --- the function/endpoint poller ---------------------------------------------

// The polling schedule.
//
// It starts fast and backs off, because the two things it is used for have very
// different timescales: a Lambda configuration update settles in seconds and a
// load balancer takes minutes. A fixed interval has to choose which of those to
// serve, and both choices are bad — a slow one adds latency to every function
// deploy, a fast one issues hundreds of DescribeLoadBalancers calls against a
// rate-limited API and becomes the throttle it then reports.
//
// The source system polls both on a fixed interval it hardcodes at each call
// site: two seconds thirty times for a function (lambda.go:990-1013), five
// seconds thirty times for a load balancer (lambda.go:715-734). Those are also
// its *deadlines*, so a caller cannot choose one — which is the thing
// [compute.WaitOptions] exists to fix.
const (
	pollInitial = 50 * time.Millisecond
	pollMax     = 2 * time.Second
	pollFactor  = 2
)

// observe reports one observation: where the resource is, and whether that is a
// terminal answer.
type observe func(ctx context.Context) (compute.Status, bool, error)

// await runs the polling loop every Wait method on this provider shares.
//
// One implementation, because the invariants the conformance suite checks about
// waiting are per-port and the mistakes are not: a deadline honoured on one port
// and overrun on another is one defect written twice. What it guarantees:
//
//   - **A wait with no deadline is refused.** Neither
//     [compute.WaitOptions.Timeout] nor a context deadline means
//     [compute.ErrInvalidSpec], because no path may wait forever.
//   - **OnUpdate fires on the first observation and on every change, and never
//     after this function returns.** It is called synchronously from this
//     goroutine, which is what the interface promises and what lets a caller
//     tear down whatever the callback touches as soon as Wait returns.
//   - **The deadline is honoured.** [compute.ErrTimeout] on expiry, and
//     distinct from [compute.ErrFailed] — the caller's decision about whether
//     to wait again depends on which it was.
//   - **Cancellation is reported as itself**, not as a timeout: the caller
//     asked to stop, and telling it that time ran out invites a retry it did not
//     ask for.
func (p *Provider) await(ctx context.Context, opts compute.WaitOptions, fn observe) error {
	deadline, ok := ctx.Deadline()
	switch {
	case opts.Timeout > 0:
		if !ok || time.Now().Add(opts.Timeout).Before(deadline) {
			deadline = time.Now().Add(opts.Timeout)
		}
	case !ok:
		return fmt.Errorf("%w: this wait has neither WaitOptions.Timeout nor a context deadline, "+
			"and no path here may wait forever", compute.ErrInvalidSpec)
	}
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var (
		last  compute.Status
		first = true
		delay = pollInitial
	)
	for {
		st, done, err := fn(waitCtx)
		if err != nil {
			return err
		}
		if opts.OnUpdate != nil && (first || changed(last, st)) {
			opts.OnUpdate(st)
		}
		last, first = st, false
		if done {
			return nil
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-waitCtx.Done():
			timer.Stop()
			// The distinction the caller acts on. A cancelled parent context is
			// an instruction, and a deadline this loop imposed is a timeout.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w: the resource was still %s when the deadline elapsed",
				compute.ErrTimeout, last.Phase)
		}
		if delay = delay * pollFactor; delay > pollMax {
			delay = pollMax
		}
	}
}

// changed reports whether an observation differs from the previous one in
// anything a caller watching progress would want to hear about.
//
// [compute.Status.UpdatedAt] is deliberately excluded: it is the time of the
// read, so including it would make every poll a change and turn OnUpdate into a
// tick.
func changed(a, b compute.Status) bool {
	return a.Phase != b.Phase || a.Message != b.Message || a.Ref != b.Ref
}

// settled reports whether a phase is one waiting can stop on.
//
// [compute.PhaseGone] counts. A resource deleted from underneath a wait is a
// terminal answer, and blocking until the deadline on something that no longer
// exists would report a timeout for a question that has an answer.
func settled(p compute.Phase) bool {
	switch p {
	case compute.PhaseReady, compute.PhaseFailed, compute.PhaseGone:
		return true
	default:
		return false
	}
}
