// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/conductorone/apphub/compute"
)

// pollInterval is how often a Wait re-observes. The fake converges on
// observations rather than on elapsed time, so this only bounds how quickly a
// Wait notices; it is small so that no test pays for it.
const pollInterval = time.Millisecond

// defectOvershoot is how far past its deadline a [DefectWaitIgnoresDeadline]
// provider runs. It is a bounded overshoot rather than an infinite one so the
// suite's self-test observes the violation instead of hanging on it.
const defectOvershoot = 3 * time.Second

// waitFor is the shared Wait body.
//
// The rule it enforces, from [compute.WaitOptions], is that no path may wait
// forever: with neither a timeout nor a context deadline the call is a caller
// bug and returns [compute.ErrInvalidSpec] instead of blocking.
func waitFor(
	ctx context.Context,
	p *Provider,
	what string,
	ref compute.Ref,
	opts compute.WaitOptions,
	observe func() (compute.Status, error),
	ready func(compute.Status) bool,
) (compute.Status, error) {
	var deadline time.Time
	switch {
	case opts.Timeout > 0:
		deadline = time.Now().Add(opts.Timeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	default:
		ctxDeadline, ok := ctx.Deadline()
		if !ok {
			if p.broken(DefectWaitWithoutDeadline) {
				// Waits anyway. The resource converges, so this returns a
				// success where the contract requires a refusal.
				deadline = time.Now().Add(defectOvershoot)
				break
			}
			return compute.Status{}, fmt.Errorf(
				"fake: waiting for %s %s with neither WaitOptions.Timeout nor a context deadline "+
					"would wait forever: %w", what, ref, compute.ErrInvalidSpec)
		}
		deadline = ctxDeadline
	}

	hardStop := deadline
	if p.broken(DefectWaitIgnoresDeadline) {
		hardStop = deadline.Add(defectOvershoot)
	}

	var last compute.Status
	reported := false
	for {
		st, err := observe()
		if err != nil {
			return compute.Status{}, err
		}
		if !reported || st.Phase != last.Phase || st.Message != last.Message {
			if opts.OnUpdate != nil && !p.broken(DefectNoProgress) {
				opts.OnUpdate(st)
			}
			last = st
			reported = true
		}

		switch {
		case ready(st):
			return st, nil
		case st.Phase == compute.PhaseFailed:
			return st, fmt.Errorf("fake: %s %s failed: %s: %w", what, ref, st.Message, compute.ErrFailed)
		case st.Phase == compute.PhaseGone:
			return st, fmt.Errorf("fake: %s %s does not exist: %w", what, ref, compute.ErrNotFound)
		}

		if !time.Now().Before(hardStop) {
			return last, fmt.Errorf("fake: %s %s was still %q after waiting: %w",
				what, ref, last.Phase, compute.ErrTimeout)
		}

		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return last, fmt.Errorf("fake: %s %s was still %q when the context deadline elapsed: %w",
					what, ref, last.Phase, compute.ErrTimeout)
			}
			return last, fmt.Errorf("fake: waiting for %s %s: %w", what, ref, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}
