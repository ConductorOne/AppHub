// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"context"
	"errors"

	"github.com/conductorone/apphub/modules/review"
)

// ErrRecordNotFound reports that the record a write was aimed at is gone. As
// in modules/review it is an outcome rather than a failure: nobody is waiting
// for the result, so the run stops successfully. Wrap with %w.
var ErrRecordNotFound = errors.New("fix: record not found")

// Status is where a fix has got to.
type Status string

const (
	// StatusValidating means the agent is deciding whether the finding is real.
	StatusValidating Status = "validating"
	// StatusPatching means the agent is drafting a change.
	StatusPatching Status = "patching"
	// StatusPushing means the change is being written to the repository.
	StatusPushing Status = "pushing"
)

// Scan is the completed scan a fix draws its finding from.
//
// # Why it names its own repository
//
// A scan is read back by an invocation that is not the one that produced it,
// and the finding it yields decides what this module writes into a repository.
// So the scan has to say which repository it is about, and [Module.Execute]
// has to refuse when the invocation names a different one. Without that,
// possession of a scan identifier is authority over any repository the caller
// can reach: a finding produced against one repository can be redirected at
// another, and the pull request opens against coordinates the scan never
// named. That was reproduced against the first version of this package.
//
// The general rule, and the reason this is stated here rather than fixed
// quietly: **an artefact that crosses from one invocation to another must
// carry the identity of what it was produced against.** Everything else these
// two packages pass between a producer and a consumer -- a snapshot, a scan
// result, a verdict, a patch, an opened pull request -- is produced and
// consumed inside a single Execute, against coordinates this module supplied
// in the same call, so it is bound by the call itself. Exactly two artefacts
// cross an invocation boundary: this one, and the snapshot, which
// [review.Snapshot] binds with its resolved commit for the same reason.
type Scan struct {
	// Complete reports whether the scan finished successfully. A fix refuses
	// to run against anything else: a finding from an incomplete scan has not
	// been through the sanitising Complete does.
	Complete bool
	// Owner and Repo name the repository the scan was produced against. Both
	// are required: a scan that does not say what it is about cannot authorise
	// anything, so an empty one is refused rather than treated as a wildcard.
	Owner string
	Repo  string
	// Ref is the revision the scan ran against. The fix operates on the same
	// one, so the agent validates against the tree the finding came from.
	Ref string
	// Findings are what the scan reported, in the order it reported them. The
	// requested index is into this slice.
	Findings []review.Finding
}

// ScanReader reads the completed scan a fix acts on.
type ScanReader interface {
	// Scan returns the scan with this identifier, or something wrapping
	// [ErrRecordNotFound].
	Scan(ctx context.Context, scanID string) (*Scan, error)
}

// Outcome is the terminal success state of a fix that opened a pull request.
type Outcome struct {
	// Branch carries the change.
	Branch string
	// CommitSHA identifies the commit.
	CommitSHA string
	// PullRequestURL is where a person reads it.
	PullRequestURL string
	// PullRequestNumber is its number in the repository.
	PullRequestNumber int
}

// ResultStore is the slim view onto the record a fix reports into.
type ResultStore interface {
	// MarkRunning moves the record out of pending.
	MarkRunning(ctx context.Context, fixID string) error
	// MarkStatus reports intermediate progress.
	MarkStatus(ctx context.Context, fixID string, status Status) error
	// RecordVerdict stores the agent's decision and its reasoning, whatever
	// the decision was.
	RecordVerdict(ctx context.Context, fixID string, v VerdictResult) error
	// RecordPatch stores the proposed change before it is pushed, so a failure
	// on the far side still leaves the proposal readable.
	RecordPatch(ctx context.Context, fixID string, files []FileChange, summary string, lines int) error
	// RecordCost books what the run consumed. Called once per run.
	RecordCost(ctx context.Context, fixID string, cost review.Cost) error
	// FinalizeRejected writes the terminal state for a finding the agent did
	// not accept. No pull request was opened and none will be.
	FinalizeRejected(ctx context.Context, fixID string) error
	// Complete writes the terminal success state.
	Complete(ctx context.Context, fixID string, o Outcome) error
	// Fail writes the terminal failure state with a message intended for the
	// person who asked for the fix. The message must not carry anything from
	// an upstream response body.
	Fail(ctx context.Context, fixID string, userMessage string) error
}
