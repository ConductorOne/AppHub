// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules/fix"
)

// The two tests here state one property in its two instances.
//
// **An artefact that crosses from one invocation to another must carry the
// identity of what it was produced against.** Everything these packages pass
// between a producer and a consumer inside a single Execute -- a scan result,
// a verdict, a patch, an opened pull request -- is bound by the call, because
// this module supplied the coordinates in that same call. Exactly two
// artefacts cross an invocation boundary: the completed scan, which a later
// Execute reads by identifier, and the snapshot, whose contents a later step
// of the same run writes against a branch that may have moved. Both were
// unbound, and both were reproduced by a review.

// TestAScanCannotBeRedirectedToAnotherRepository is the first instance. Without
// the binding, possession of a scan identifier is authority over any
// repository the caller can reach: the finding is fetched from, and the pull
// request opened against, coordinates the scan never named.
//
// It quantifies over each coordinate independently and over both together, so
// a check that compared only one of them fails here.
func TestAScanCannotBeRedirectedToAnotherRepository(t *testing.T) {
	redirects := map[string]func(*fix.Scan){
		"a different owner":      func(s *fix.Scan) { s.Owner = "someone-else" },
		"a different repository": func(s *fix.Scan) { s.Repo = "another-repository" },
		"a different owner and repo": func(s *fix.Scan) {
			s.Owner, s.Repo = "someone-else", "another-repository"
		},
		"an owner differing only by case": func(s *fix.Scan) { s.Owner = strings.ToUpper(s.Owner) },
		"a repo differing only by case":   func(s *fix.Scan) { s.Repo = strings.ToUpper(s.Repo) },
		"no owner recorded":               func(s *fix.Scan) { s.Owner = "" },
		"no repository recorded":          func(s *fix.Scan) { s.Repo = "" },
		"neither recorded":                func(s *fix.Scan) { s.Owner, s.Repo = "", "" },
	}
	for name, redirect := range redirects {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(h *harness) { redirect(h.scans.scan) })
			_, err := h.module.Execute(context.Background(), "u", validParams())
			if err == nil {
				t.Fatal("Execute ran a fix against a scan produced for another repository")
			}
			if !errors.Is(err, fix.ErrScanNotBound) {
				t.Fatalf("the error was %v, which does not match ErrScanNotBound", err)
			}
			// Nothing may be read from or written to the repository, so the
			// refusal has to come before the fetch as well as before the push.
			if h.fetcher.calls != 0 {
				t.Errorf("the snapshot was fetched anyway (%d call(s))", h.fetcher.calls)
			}
			if h.fixer.validateN != 0 {
				t.Errorf("the agent was asked to validate anyway")
			}
			if len(h.git.seq) != 0 {
				t.Errorf("the repository was written to anyway: %v", h.git.seq)
			}
			if h.store.failCalls != 1 {
				t.Errorf("Fail was called %d times, want once", h.store.failCalls)
			}
			// A scan that records nothing and a scan that records something
			// else are both refused, but for different reasons, and the
			// requester needs to be told which. Without this the two branches
			// are indistinguishable from one: the inequality alone refuses an
			// empty owner too, so only the message makes the first branch do
			// anything.
			if strings.Contains(name, "no owner") || strings.Contains(name, "no repository") || strings.Contains(name, "neither") {
				if !strings.Contains(h.store.failMessage, "does not record") {
					t.Errorf("an unrecorded repository was reported as %q, which reads as a comparison "+
						"against nothing rather than as a scan that says nothing", h.store.failMessage)
				}
			} else if !strings.Contains(h.store.failMessage, "produced against") {
				t.Errorf("a redirected scan was reported as %q, which does not say what it was "+
					"produced against", h.store.failMessage)
			}
		})
	}

	// Both directions. A module that refused every scan would satisfy all of
	// the above, so the matching scan must still run -- and an installation
	// that differs must NOT be refused, because a public scan legitimately has
	// none and a fix for it legitimately needs one.
	if _, err := newHarness(t).module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("a scan bound to this repository was refused: %v", err)
	}
	other := newHarness(t)
	if _, err := other.module.Execute(context.Background(), "u", with(validParams(), "installationId", 999)); err != nil {
		t.Fatalf("a differing installation was refused, which would block fixing a public scan: %v", err)
	}
	t.Logf("refused %d redirects and accepted the bound scan under two installations", len(redirects))
}

// TestABranchThatMovedAfterTheSnapshotIsRefused is the second instance, and the
// shape is a transition rather than a call: every step is correct on its own
// and the move between two of them is not.
//
// The patch is a set of whole-file replacements computed from the snapshot. If
// the branch advances while the agent is thinking, committing that patch on
// top of the newer head silently reverts whatever landed in between -- and the
// call-order assertion stays green, because every expected call still happens
// in its expected position. That is why this is its own test and not an extra
// assertion on the sequence.
func TestABranchThatMovedAfterTheSnapshotIsRefused(t *testing.T) {
	moves := map[string]string{
		"the branch advanced":                "newer-commit",
		"the branch advanced then came back": "another-commit",
		"the branch head is unknown to us":   "0000000",
	}
	for name, head := range moves {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(h *harness) {
				// The snapshot is read at one commit and the branch points at
				// another by the time the push resolves it.
				h.fetcher.commit = "snapshot-commit"
				h.git.branchHeads["main"] = head
			})
			_, err := h.module.Execute(context.Background(), "u", validParams())
			if err == nil {
				t.Fatal("Execute pushed a patch computed against a snapshot the branch had left behind")
			}
			if !errors.Is(err, fix.ErrBaseMoved) {
				t.Fatalf("the error was %v, which does not match ErrBaseMoved", err)
			}
			// Refusal, not reconciliation, and refusal before the first write.
			for _, e := range h.git.seq {
				if strings.HasPrefix(e, "CreateBlob") || strings.HasPrefix(e, "CreateTree") ||
					strings.HasPrefix(e, "CreateCommit") || strings.HasPrefix(e, "CreateBranch") ||
					e == "OpenPullRequest" {
					t.Fatalf("the repository was written to before the movement was noticed: %v", h.git.seq)
				}
			}
			if h.store.failCalls != 1 {
				t.Errorf("Fail was called %d times, want once", h.store.failCalls)
			}
			if !strings.Contains(strings.ToLower(h.store.failMessage), "moved") {
				t.Errorf("the requester was told %q, which does not say what happened", h.store.failMessage)
			}
			// The message must not carry the commit identifiers from the
			// upstream error, which is where they belong.
			if strings.Contains(h.store.failMessage, head) {
				t.Errorf("the requester message quoted an upstream identifier: %q", h.store.failMessage)
			}
		})
	}

	// Both directions: a branch that did not move is pushed to.
	still := newHarness(t)
	if _, err := still.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("a branch that had not moved was refused: %v", err)
	}
	if still.store.outcome == nil {
		t.Fatal("a branch that had not moved produced no pull request")
	}
	t.Logf("refused %d branch movements and pushed to the one that had not moved", len(moves))
}

// TestASnapshotThatNamesNoRevisionIsRefused closes the way the movement check
// could be defeated: a fetcher that returns contents without saying which
// commit they came from leaves nothing to compare against.
//
// Both modules refuse it, because both depend on the answer -- modules/review
// records it, and modules/fix checks it.
func TestASnapshotThatNamesNoRevisionIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*harness){
		"no commit":   func(h *harness) { h.fetcher.commit = "" },
		"no contents": func(h *harness) { h.fetcher.tree = nil },
		"no snapshot": func(h *harness) { h.fetcher.noSnap = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			if _, err := h.module.Execute(context.Background(), "u", validParams()); err == nil {
				t.Fatal("Execute accepted a snapshot it could not check")
			}
			if len(h.git.seq) != 0 {
				t.Fatalf("the repository was written to anyway: %v", h.git.seq)
			}
			if h.store.failCalls != 1 {
				t.Errorf("Fail was called %d times, want once", h.store.failCalls)
			}
		})
	}
}
