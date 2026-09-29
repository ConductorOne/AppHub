// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package awscode holds the one declaration of the AWS wire codes this
// repository classifies as retryable.
//
// There were two. compute/aws called its copy throttleCodes and credentials/aws
// called its copy retryableCodes; the entries were identical and neither package
// could see the other, so the invariant that they stayed identical was a
// coincidence maintained by whoever last read both files. One of them was
// cross-checked against the SDK and the other was not, which means the two could
// only have diverged in one direction: compute/aws's copy could silently fall
// behind a code the SDK added, and a throttle classified terminal tells a caller
// to change a spec when waiting was the whole remedy. USOSS-63.
//
// # This package is deliberately not an AWS package
//
// It imports nothing. That is what lets both providers share it without touching
// the aws-sdk-confined rule in internal/boundary, which names the packages
// permitted to reach github.com/aws — and test imports count against that rule
// too, so a shared package whose tests reached for the SDK would have needed the
// fence widened. Nothing here needs the SDK: a wire code is a string, and the
// question this package answers is a question about strings.
//
// The cross-check against the SDK's own maps therefore stays in credentials/aws,
// which is already allowlisted and already had it. There is now one table under
// it instead of one of two.
//
// # The set is a predicate, not a map
//
// Both copies were package-level maps, and both carried a comment explaining that
// the SDK's own retry.DefaultThrottleErrorCodes and retry.DefaultRetryableErrorCodes
// were copied rather than referenced *because a package-level map is something any
// dependency can mutate in place*. Exporting the converged set as a map would have
// reproduced, at the top of this repository's own import graph, precisely the
// hazard both packages copied the SDK to escape. So the surface is
// [IsRetryable], the table is unexported, and [RetryableCodes] hands out a fresh
// slice.
//
// # What this set is, precisely
//
// It is the SDK's set of retryable and throttling **wire codes**, minus two
// entries belonging to DynamoDB, which this repository fences into store/. One of
// the two is refused outright by the idiom fence in internal/boundary, so it
// cannot be named here at all; the other is TransactionInProgressException, which
// belongs to TransactWriteItems. compute/aws recovers the DynamoDB throttle it can
// actually receive with a typed check in its own database adapter, where the fence
// exempts the file — see isDynamoThrottle in compute/aws/awssdkdb.go.
//
// It is **not** a list of what any particular service returns. Several entries are
// dead for any given client: neither IAM nor STS declares an error reporting
// BandwidthLimitExceeded, EC2ThrottledException, SlowDown or PriorRequestNotComplete.
// Keeping the SDK's set anyway is deliberate — it is checkable against the SDK, so
// it cannot drift from it, and matching the SDK's classification means a caller
// gets the same answer from these providers that the client would have given
// itself.
//
// # The key is the wire code, and the Go type name is not the wire code
//
// This is the whole reason the two copies were worth converging rather than
// leaving alone, because the confusion behind them is not a duplication problem
// and would have survived deduplication done carelessly.
//
// A generated SDK error type's Go name and the string its ErrorCode method
// returns are different values, and for some types they differ. Two services can
// declare types with the *same* Go name reporting *different* codes:
//
//	iamtypes.LimitExceededException   ErrorCode() == "LimitExceeded"
//	ecrtypes.LimitExceededException   ErrorCode() == "LimitExceededException"
//
// So there is no consistent answer to "is LimitExceededException retryable" and
// the question is malformed. Keyed by code, as it is here and as both copies
// already were, each service gets its own answer with no per-service table: IAM's
// quota exhaustion is terminal, which is what a quota should be and what the SDK
// says, and ECR's is retryable, which is inherited from the SDK's own throttle
// list carrying that exact string.
//
// Reading the type name as the code has cost this repository two review rounds in
// two packages. Both times the reader concluded that IAM's quota exhaustion was
// being misclassified and "fixed" it by adding typed matching for
// *iamtypes.LimitExceededException, which made a quota error retryable and
// diverged from the SDK in the dangerous direction. Both times it was reverted.
//
// TestATypeNameIsNotAWireCode is what stops it being re-derived a third time. It
// parses every AWS service this module depends on and enumerates every declared
// error type whose type name and wire code disagree about membership of this set,
// in both directions, and requires a recorded decision for each. There are
// currently two, and the second was found by that test rather than by a reviewer:
// elbv2's PriorRequestNotCompleteException reports "PriorRequestNotComplete",
// which IS in this set. That trap runs the other way — a reader matching on the
// type would classify a retryable ELBv2 condition terminal — and nobody had
// noticed it, because every argument about this class of bug so far has been
// about IAM.
package awscode

import "sort"

// retryableCodes is the SDK's retryable-and-throttling set, copied rather than
// referenced, minus the DynamoDB entries described in the package comment.
//
// Copied because retry.DefaultThrottleErrorCodes and retry.DefaultRetryableErrorCodes
// are package-level maps any dependency or operator can mutate in place, and a
// classification these providers cannot reason about is the thing this whole
// mechanism exists to avoid.
//
// A copy is a restatement, so it is cross-checked generatively rather than by eye:
// TestRetryableCodesMatchTheSDK in credentials/aws derives the expected set from
// those two maps at test time and fails on any difference in either direction, so
// a code AWS adds is a test failure rather than a throttle silently reported
// terminal.
var retryableCodes = map[string]struct{}{
	"BandwidthLimitExceeded":    {},
	"EC2ThrottledException":     {},
	"LimitExceededException":    {},
	"PriorRequestNotComplete":   {},
	"RequestLimitExceeded":      {},
	"RequestThrottled":          {},
	"RequestThrottledException": {},
	"RequestTimeout":            {},
	"RequestTimeoutException":   {},
	"SlowDown":                  {},
	"Throttling":                {},
	"ThrottlingException":       {},
	"ThrottledException":        {},
	"TooManyRequestsException":  {},
}

// IsRetryable reports whether an AWS wire code is one this repository treats as
// retryable.
//
// The argument is the string an error's ErrorCode method returns. It is NOT a Go
// type name, and passing one is the defect the package comment is about: the two
// differ for some SDK error types, and for at least one type they differ in a way
// that inverts the answer.
func IsRetryable(code string) bool {
	_, ok := retryableCodes[code]
	return ok
}

// RetryableCodes returns the set, sorted, as a fresh slice.
//
// A slice rather than the map, and a fresh one per call, so that a caller
// enumerating the set for a cross-check or a table-driven test cannot mutate what
// every classification in this repository reads.
func RetryableCodes() []string {
	out := make([]string, 0, len(retryableCodes))
	for code := range retryableCodes {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}
