// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"context"
	"fmt"

	"github.com/conductorone/apphub/modules/review"
)

// Verdict is the agent's answer to "is this finding real?".
type Verdict string

const (
	// VerdictReal means the agent reproduced the issue from the tree. It is
	// the only verdict that leads to a pull request.
	VerdictReal Verdict = "real"
	// VerdictFalsePositive means the agent believes the finding is wrong.
	VerdictFalsePositive Verdict = "false_positive"
	// VerdictUncertain means the agent could not decide. It is treated as
	// [VerdictFalsePositive] is: a change pushed on a hunch is worse than no
	// change, so uncertainty stops the run rather than proceeding carefully.
	VerdictUncertain Verdict = "uncertain"
)

// Verdicts returns the three verdicts.
func Verdicts() []Verdict { return []Verdict{VerdictReal, VerdictFalsePositive, VerdictUncertain} }

// Opens reports whether this verdict permits opening a pull request. Exactly
// one does, and asking here rather than comparing at each call site is what
// stops a later verdict being admitted by an inequality that was written when
// there were three.
func (v Verdict) Opens() bool { return v == VerdictReal }

// VerdictResult is what [Fixer.Validate] concluded.
type VerdictResult struct {
	// Verdict is the decision.
	Verdict Verdict
	// Reasoning is the agent's explanation, shown to a reviewer.
	Reasoning string
	// Evidence is what the agent read to reach the verdict. Optional.
	Evidence string
	// Cost is what the step consumed.
	Cost review.Cost
}

// FileChange is one whole-file replacement.
//
// Contents replaces the file entirely. This package does not apply diffs: a
// partial patch has to be reconciled against a tree, and getting that subtly
// wrong produces a commit that looks reviewed and is not.
type FileChange struct {
	// Path is repository-relative. Checked with [review.SanitisePath].
	Path string `json:"path"`
	// Contents is the file's new content in full.
	Contents string `json:"contents"`
	// Lines is the line count of Contents. Derived by [CountLines] when the
	// change is accepted, so a caller cannot state one thing and store another.
	Lines int `json:"lines"`
}

// Patch is what [Fixer.Propose] produced.
type Patch struct {
	// Summary is a one-line description of the change.
	Summary string
	// Files are the whole-file replacements.
	Files []FileChange
	// Cost is what the step consumed.
	Cost review.Cost
}

// NoPatchError reports that the agent declined to produce a patch.
//
// It is distinct from a transport failure because it is an answer rather than
// an error: the agent looked and concluded it could not fix this safely.
// Explanation is the agent's own words and is shown to the requester, capped
// and flattened by formatExplanation. Cost carries whatever the attempt spent,
// which is booked like any other spend.
type NoPatchError struct {
	Explanation string
	Cost        review.Cost
}

func (e *NoPatchError) Error() string {
	if e == nil || e.Explanation == "" {
		return "fix: the agent produced no patch"
	}
	return fmt.Sprintf("fix: the agent produced no patch: %s", e.Explanation)
}

// Request is what a [Fixer] step is given.
//
// Tree is the whole of what it may read. Owner, Repo and Ref are context for
// the agent's prompt, and a [Fixer] must not perform I/O against them.
type Request struct {
	Tree    review.Tree
	Owner   string
	Repo    string
	Ref     string
	Finding review.Finding
}

// Fixer is the AI-provider seam for remediation.
//
// As with [review.Scanner], nothing in this package implements it and nothing
// in this package says how a fix should be reasoned about. The two steps are
// separate because they are separately terminal: a validation that says
// "false positive" ends the run without a patch ever being proposed.
//
// Both methods may return a non-nil cost alongside an error, through
// [NoPatchError] for Propose; a step that spent before it failed still has to
// be paid for.
type Fixer interface {
	// Validate decides whether the finding is real.
	Validate(ctx context.Context, req Request) (*VerdictResult, error)
	// Propose drafts a patch. It returns a *[NoPatchError] when the agent
	// declined rather than failed.
	Propose(ctx context.Context, req Request) (*Patch, error)
}
