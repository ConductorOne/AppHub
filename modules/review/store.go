// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
)

// ErrRecordNotFound reports that the record a write was aimed at is gone --
// deleted by whoever asked for the scan, between the request and the write.
//
// It is a distinct outcome rather than an error because it is not a failure:
// nobody is waiting for the result any more, so there is nothing to repair and
// nothing to report. A [ResultStore] returns something wrapping this and
// [Module.Execute] stops, successfully. Wrap with %w.
var ErrRecordNotFound = errors.New("review: scan record not found")

// Completion is the terminal state of a scan that produced findings.
//
// It names the repository and revision the findings were produced against, and
// that is a requirement rather than provenance decoration. Findings are read
// back by a later, separate invocation -- modules/fix -- which decides what to
// write into a repository on the strength of them. An artefact that crosses
// between one invocation and another must carry the identity of what it was
// produced against, or possession of it becomes authority over anything: a
// scan of one repository could be redirected at another. A store must persist
// these four fields and return them, or the consumer cannot check the binding.
type Completion struct {
	// Owner and Repo name the repository the findings are about.
	Owner string
	Repo  string
	// Ref is the revision that was asked for, which may be a moving branch.
	Ref string
	// Commit is the immutable revision the snapshot actually resolved to.
	Commit string
	// Findings is what the scan reported, sanitised.
	Findings []Finding
	// HighestSeverity is the most severe severity present, or "info" when
	// there are no findings. Derived by [HighestSeverity] from Findings, so it
	// cannot disagree with them.
	HighestSeverity Severity
	// Cost is what the scan consumed.
	Cost Cost
	// Iterations and BytesRead are the provider's diagnostics.
	Iterations int
	BytesRead  int64
}

// ResultStore is the slim view onto the record a scan reports into.
//
// It is deliberately a lifecycle rather than a setter: every method moves the
// record between states a reader can distinguish, so a caller polling the
// record always sees either a state that is going somewhere or a terminal one.
// A scan that dies without reaching Complete or Fail leaves the record in
// running, which is the one state the module never leaves behind on purpose.
//
// Implementations must treat the context they are given as the whole of their
// deadline; [Module.Execute] gives terminal writes a fresh one so a cancelled
// scan can still land its outcome.
type ResultStore interface {
	// MarkRunning moves the record out of pending.
	MarkRunning(ctx context.Context, scanID string) error
	// Complete writes the terminal success state.
	Complete(ctx context.Context, scanID string, c Completion) error
	// RecordPartialCost books spend for a scan that is going to fail. Called
	// before Fail, and only when there was spend.
	RecordPartialCost(ctx context.Context, scanID string, cost Cost) error
	// Fail writes the terminal failure state with a message intended for the
	// person who asked for the scan. The message must not carry anything from
	// an upstream response body.
	Fail(ctx context.Context, scanID string, userMessage string) error
}
