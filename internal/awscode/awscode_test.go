// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package awscode

import (
	"sort"
	"testing"
)

// TestTheSetCannotBeMutatedThroughItsExportedSurface is the property that made
// this package a predicate rather than an exported map.
//
// The two copies this package replaces both carried a comment saying the SDK's
// sets were copied rather than referenced BECAUSE a package-level map is
// something any dependency can mutate in place. Converging them into an exported
// map would have rebuilt that hazard inside this repository, one import closer to
// the classifiers, and no test would have noticed.
func TestTheSetCannotBeMutatedThroughItsExportedSurface(t *testing.T) {
	t.Parallel()

	const throttle = "ThrottlingException"
	if !IsRetryable(throttle) {
		t.Fatalf("%s is not retryable; this test's premise is gone", throttle)
	}

	first := RetryableCodes()
	if len(first) == 0 {
		t.Fatal("the set is empty")
	}
	for i := range first {
		first[i] = "clobbered"
	}
	if !IsRetryable(throttle) {
		t.Errorf("writing through the slice from RetryableCodes changed what IsRetryable answers")
	}
	second := RetryableCodes()
	for _, code := range second {
		if code == "clobbered" {
			t.Fatal("RetryableCodes returned the same backing array twice; a caller's write " +
				"reaches every later caller")
		}
	}
	if len(second) != len(first) {
		t.Errorf("RetryableCodes returned %d codes and then %d", len(first), len(second))
	}
}

// TestTheTwoSurfacesDescribeOneSet stops [RetryableCodes] and [IsRetryable] from
// answering about different things -- which is the shape of the bug this package
// exists to remove, at a smaller scale.
func TestTheTwoSurfacesDescribeOneSet(t *testing.T) {
	t.Parallel()

	codes := RetryableCodes()
	for _, code := range codes {
		if !IsRetryable(code) {
			t.Errorf("RetryableCodes lists %q and IsRetryable says it is not retryable", code)
		}
	}
	if !sort.StringsAreSorted(codes) {
		t.Errorf("RetryableCodes is documented sorted and is not: %v", codes)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			t.Errorf("RetryableCodes repeats %q", code)
		}
		seen[code] = true
	}
	if len(seen) != len(retryableCodes) {
		t.Errorf("RetryableCodes yielded %d distinct codes and the table holds %d",
			len(seen), len(retryableCodes))
	}
	if IsRetryable("") {
		t.Error("the empty code is retryable; an error with no code would be retried forever")
	}
	// The witness the package comment is about, both spellings, asserted here so
	// the claim in the comment is a checked one.
	if !IsRetryable("LimitExceededException") {
		t.Error(`"LimitExceededException" -- ECR's code -- is not retryable; the SDK's own ` +
			"throttle list carries it and this set is derived from that list")
	}
	if IsRetryable("LimitExceeded") {
		t.Error(`"LimitExceeded" -- IAM's code for a quota exhaustion -- is retryable. That ` +
			"is the reverted 'fix' growing back: a quota is not a throttle, and the SDK " +
			"classifies it terminal")
	}
}
