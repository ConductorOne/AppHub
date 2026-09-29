// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/compute"
)

// codeError is an AWS API error with a chosen code and fault.
type codeError struct {
	code  string
	fault smithy.ErrorFault
}

func (e codeError) Error() string                 { return "api error " + e.code }
func (e codeError) ErrorCode() string             { return e.code }
func (e codeError) ErrorMessage() string          { return e.code }
func (e codeError) ErrorFault() smithy.ErrorFault { return e.fault }

// TestTheRetryableHookCanOnlyWiden is the property this port depends on, and it
// replaces a test whose premise the design has since reversed.
//
// # What changed and why the old test had to go
//
// This port used to assert that extending a client's retryer with
// retry.AddWithErrorCodes changed the provider's classification too, so that the
// two could not disagree. USOSS-10 removed that coupling on its fifth review
// round for a reason that is stronger than the one it replaced: IsErrorRetryable
// is caller-supplied, so a client's retry configuration had silently become this
// provider's error taxonomy, and against a retryer with its Retryables emptied
// every throttle classified terminal. An operator who turns retry down asked for
// fewer attempts, not for a different error vocabulary.
//
// So classification is now a fixed function of the error plus
// [Config.IsRetryable], and the property worth pinning is the DIRECTION of that
// hook: it may only move an error from terminal to [compute.ErrTransient]. This
// port cares more than most, because EC2's teardown path is the live case —
// DependencyViolation is retryable there and is in no default set.
func TestTheRetryableHookCanOnlyWiden(t *testing.T) {
	t.Parallel()

	dependency := codeError{code: "DependencyViolation", fault: smithy.FaultClient}
	widen := func(err error) bool {
		var api smithy.APIError
		return errors.As(err, &api) && api.ErrorCode() == "DependencyViolation"
	}
	// A hook that says "no" to everything. It must change nothing at all: the
	// interesting failure is not a hook that fails to widen but one that
	// narrows, and only a false-returning hook can demonstrate the difference.
	deny := func(error) bool { return false }

	t.Run("the documented consequence: without the hook, it is terminal", func(t *testing.T) {
		t.Parallel()
		p := &Provider{name: "test"}
		got := p.substrateError(dependency)
		if !errors.Is(got, compute.ErrFailed) {
			t.Errorf("got %v, want ErrFailed. USOSS-10's decision record says extending an SDK "+
				"client no longer tells this provider anything, so the un-hooked answer has to be "+
				"the terminal one or the record is wrong about its own cost", got)
		}
	})

	t.Run("with the hook, it widens to ErrTransient", func(t *testing.T) {
		t.Parallel()
		p := &Provider{name: "test", cfg: Config{IsRetryable: widen}}
		got := p.substrateError(dependency)
		if !errors.Is(got, compute.ErrTransient) {
			t.Errorf("got %v, want ErrTransient", got)
		}
		if errors.Is(got, compute.ErrFailed) {
			t.Error("the error matches BOTH ErrTransient and ErrFailed, so a caller branching on " +
				"either gets a different answer")
		}
	})

	t.Run("it cannot narrow anything", func(t *testing.T) {
		t.Parallel()
		// Every classification the hook is consulted AFTER. A hook returning
		// false must leave each of them exactly as it was — this is the half
		// that makes the direction one-way, and it is enumerated rather than
		// sampled because "the hook did not break the case I thought of" is not
		// the property.
		for _, tc := range []struct {
			name string
			err  error
			want error
		}{
			{"a throttle stays transient", ErrThrottled, compute.ErrTransient},
			{"a missing resource stays not-found", ErrNoSuchResource, compute.ErrNotFound},
			{"an existing resource stays transient", ErrAlreadyExists, compute.ErrTransient},
			// ErrNotPermitted rather than ErrFailed since #39. The property is
			// unchanged — the hook must not move a denial — but the baseline
			// assertion caught the change rather than letting the subtest pass
			// against a taxonomy that had moved underneath it.
			{"a denial stays not-permitted", ErrDenied, compute.ErrNotPermitted},
		} {
			t.Run(tc.name, func(t *testing.T) {
				plain := (&Provider{name: "test"}).substrateError(tc.err)
				hooked := (&Provider{name: "test", cfg: Config{IsRetryable: deny}}).substrateError(tc.err)
				if !errors.Is(plain, tc.want) {
					t.Fatalf("without a hook: got %v, want %v — this test's baseline is wrong", plain, tc.want)
				}
				if !errors.Is(hooked, tc.want) {
					t.Errorf("with a false-returning hook: got %v, want %v; a hook that answers "+
						"\"not retryable\" must not be able to change a classification",
						hooked, tc.want)
				}
			})
		}
	})

	t.Run("it cannot make a cancelled context retryable", func(t *testing.T) {
		t.Parallel()
		// The sharpest case, because a hook COULD match it: "try again" inverts
		// the instruction the caller just gave, so cancellation is classified
		// before the hook is consulted and a hook that says yes to everything
		// must not reach it.
		yes := func(error) bool { return true }
		p := &Provider{name: "test", cfg: Config{IsRetryable: yes}}
		for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
			got := p.substrateError(err)
			if errors.Is(got, compute.ErrTransient) {
				t.Errorf("%v was classified transient by a yes-to-everything hook; a caller that "+
					"cancelled is being told to try again", err)
			}
			if !errors.Is(got, err) {
				t.Errorf("%v was not returned as itself, got %v", err, got)
			}
		}
	})
}
