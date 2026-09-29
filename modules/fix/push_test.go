// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules/fix"
	"github.com/conductorone/apphub/modules/review"
)

// TestABaseThatIsNotABranchIsNamedAsSuch covers the whole classification, in
// both directions. A pull request merges into a branch; a scan may have run
// against something else, and the requester can act on that only if they are
// told which.
func TestABaseThatIsNotABranchIsNamedAsSuch(t *testing.T) {
	notBranches := map[string]func(*harness){
		"a tag reached through refs/tags": func(h *harness) { h.scans.scan.Ref = "refs/tags/v1" },
		"a tag that looks like a branch":  func(h *harness) { h.scans.scan.Ref = "v1"; h.git.tags["v1"] = true },
		"a full commit name":              func(h *harness) { h.scans.scan.Ref = "0123456789abcdef0123456789abcdef01234567" },
		"an abbreviated commit name":      func(h *harness) { h.scans.scan.Ref = "abc1234" },
		"a ref in some other namespace":   func(h *harness) { h.scans.scan.Ref = "refs/notes/commits" },
		"a pull request head":             func(h *harness) { h.scans.scan.Ref = "refs/pull/1/head" },
	}
	for name, mutate := range notBranches {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			_, err := h.module.Execute(context.Background(), "u", validParams())
			if err == nil {
				t.Fatal("Execute opened a pull request against something that is not a branch")
			}
			if !errors.Is(err, fix.ErrBaseNotBranch) {
				t.Fatalf("the error was %v, which does not match ErrBaseNotBranch", err)
			}
			if !strings.Contains(strings.ToLower(h.store.failMessage), "branch") {
				t.Errorf("the requester was told %q, which does not name the remedy", h.store.failMessage)
			}
			for _, e := range h.git.seq {
				if strings.HasPrefix(e, "CreateBlob") || strings.HasPrefix(e, "CreateBranch") {
					t.Fatalf("something was written before the base was classified: %v", h.git.seq)
				}
			}
		})
	}

	// Both directions: the branch shapes are accepted, including the fully
	// qualified one and the empty revision that falls back to the default.
	branches := map[string]func(*harness){
		"a plain branch name": func(h *harness) { h.scans.scan.Ref = "main" },
		"a branch with a slash": func(h *harness) {
			h.scans.scan.Ref = "release/2026-q2"
			h.git.branchHeads["release/2026-q2"] = "basesha"
		},
		"a fully qualified head":  func(h *harness) { h.scans.scan.Ref = "refs/heads/main" },
		"no revision at all":      func(h *harness) { h.scans.scan.Ref = "" },
		"the literal HEAD":        func(h *harness) { h.scans.scan.Ref = "HEAD" },
		"a hex branch of 6 chars": func(h *harness) { h.scans.scan.Ref = "abc12"; h.git.branchHeads["abc12"] = "basesha" },
	}
	for name, mutate := range branches {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
				t.Fatalf("Execute refused a branch base: %v", err)
			}
			if h.git.opened.Base == "" {
				t.Fatal("the pull request was opened with no base")
			}
			if strings.HasPrefix(h.git.opened.Base, "refs/") {
				t.Errorf("the pull request base was %q; the refs/heads/ prefix should be stripped", h.git.opened.Base)
			}
		})
	}
	t.Logf("refused %d non-branch bases and accepted %d branch bases", len(notBranches), len(branches))
}

// TestADefaultBranchFromTheHostIsRevalidated closes the one gap the parameter
// validation cannot: the default branch is the only revision that arrives from
// outside without having been through Validate.
func TestADefaultBranchFromTheHostIsRevalidated(t *testing.T) {
	hostile := []string{"a b", "a\nb", "../x", "/x", "x/", "a//b", "-x", "a?b", "a#b", "a%2f", ""}
	for _, name := range hostile {
		h := newHarness(t, func(h *harness) {
			h.scans.scan.Ref = ""
			h.git.defaultBranch = name
		})
		_, err := h.module.Execute(context.Background(), "u", validParams())
		if err == nil {
			t.Errorf("a default branch of %q was accepted", name)
		}
		// The refusal has to happen before the name is used, not merely
		// somewhere downstream: the whole point is that it is about to be
		// spliced into a request path that does not escape slashes. An
		// earlier version of this test asserted only that the run failed,
		// and it failed for the wrong reason -- the lookup 404ed -- so
		// removing the check entirely left the test green.
		for _, e := range h.git.seq {
			if e == "CreateBlob" {
				t.Errorf("a default branch of %q reached a write", name)
			}
			if name != "" && strings.Contains(e, name) {
				t.Errorf("a default branch of %q was sent to the git client as %q", name, e)
			}
		}
	}
	t.Logf("refused %d hostile default-branch answers", len(hostile))
}

// TestBranchNamesChangeOnCollision walks the whole retry range plus the case
// beyond it, so the bound is a bound rather than an unbounded loop.
func TestBranchNamesChangeOnCollision(t *testing.T) {
	for taken := 0; taken < 5; taken++ {
		h := newHarness(t, func(h *harness) { h.git.createRefFails = taken })
		if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
			t.Fatalf("with %d names taken: %v", taken, err)
		}
		if len(h.git.branches) != taken+1 {
			t.Fatalf("with %d names taken, %d names were tried", taken, len(h.git.branches))
		}
		want := "apphub/fix-scan-1-0"
		if taken > 0 {
			want = fmt.Sprintf("%s-r%d", want, taken)
		}
		if got := h.git.branches[len(h.git.branches)-1]; got != want {
			t.Fatalf("with %d names taken, the branch was %q, want %q", taken, got, want)
		}
		// Every attempt is a distinct name; retrying the same one would loop
		// against the same collision.
		seen := map[string]bool{}
		for _, b := range h.git.branches {
			if seen[b] {
				t.Fatalf("the branch name %q was tried twice", b)
			}
			seen[b] = true
		}
	}
	// Beyond the bound the run gives up rather than looping.
	h := newHarness(t, func(h *harness) { h.git.createRefFails = 99 })
	if _, err := h.module.Execute(context.Background(), "u", validParams()); err == nil {
		t.Fatal("Execute succeeded with every branch name taken")
	}
	if len(h.git.branches) != 5 {
		t.Fatalf("%d branch names were tried, want the bound of 5", len(h.git.branches))
	}
	t.Logf("checked collision retry across the whole bound")
}

// TestTreeEntryModesComeFromTheSnapshotAndNowhereElse states what a fix may do
// to a file's mode: preserve an executable bit that was already there, and
// otherwise write a regular file. A mode the snapshot reports that this module
// does not write is not carried through.
func TestTreeEntryModesComeFromTheSnapshotAndNowhereElse(t *testing.T) {
	sourceModes := []string{"", fix.ModeFile, fix.ModeExecutable, "120000", "160000", "040000", "100644 ", "rwxr-xr-x", "100755\n"}
	for _, mode := range sourceModes {
		h := newHarness(t, func(h *harness) {
			tree := newTree(map[string]string{"a.go": "x", "b.sh": "y"})
			if mode != "" {
				tree.modes["a.go"] = mode
			}
			h.fetcher.tree = tree
			h.fixer.patch.Files = []fix.FileChange{{Path: "a.go", Contents: "z\n"}}
		})
		if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
			t.Fatalf("with a source mode of %q: %v", mode, err)
		}
		if len(h.git.entries) != 1 {
			t.Fatalf("with a source mode of %q: %d tree entries", mode, len(h.git.entries))
		}
		got := h.git.entries[0].Mode
		want := fix.ModeFile
		if mode == fix.ModeExecutable {
			want = fix.ModeExecutable
		}
		if got != want {
			t.Errorf("a source mode of %q produced the entry mode %q, want %q", mode, got, want)
		}
	}
	t.Logf("checked %d source modes", len(sourceModes))
}

// TestBlobsAreCreatedForEveryFileAndOnlyThose is arithmetic that has to hold
// for the commit to be the patch: one blob per accepted change, one entry per
// blob, and the entries name the accepted paths.
func TestBlobsAreCreatedForEveryFileAndOnlyThose(t *testing.T) {
	for n := 1; n <= fix.SuggestedMaxFiles; n++ {
		files := make([]fix.FileChange, 0, n)
		contents := map[string]string{}
		for i := 0; i < n; i++ {
			path := fmt.Sprintf("f%d.go", i)
			files = append(files, fix.FileChange{Path: path, Contents: fmt.Sprintf("body %d\n", i)})
			contents[path] = "old\n"
		}
		h := newHarness(t, func(h *harness) {
			h.fetcher.tree = newTree(contents)
			h.fixer.patch.Files = files
		})
		if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
			t.Fatalf("with %d files: %v", n, err)
		}
		if len(h.git.blobs) != n || len(h.git.entries) != n {
			t.Fatalf("with %d files: %d blobs and %d entries", n, len(h.git.blobs), len(h.git.entries))
		}
		for i, entry := range h.git.entries {
			if entry.Path != files[i].Path {
				t.Errorf("entry %d names %q, want %q", i, entry.Path, files[i].Path)
			}
			if string(h.git.blobs[i]) != files[i].Contents {
				t.Errorf("blob %d carries %q, want %q", i, h.git.blobs[i], files[i].Contents)
			}
			if entry.BlobSHA == "" {
				t.Errorf("entry %d has no blob", i)
			}
		}
		if h.store.patchLines != n {
			t.Errorf("with %d one-line files the recorded line count was %d", n, h.store.patchLines)
		}
	}
	t.Logf("checked patches of 1 to %d files", fix.SuggestedMaxFiles)
}

// TestALabelFailureDoesNotFailTheRun states which of the write steps are
// load-bearing. A missing label makes the pull request no less useful, and
// failing a run that already opened one would be worse than the label.
func TestALabelFailureDoesNotFailTheRun(t *testing.T) {
	h := newHarness(t, func(h *harness) { h.git.addLabelsErr = errors.New("no permission to label") })
	res, err := h.module.Execute(context.Background(), "u", validParams())
	if err != nil {
		t.Fatalf("a label failure failed the run: %v", err)
	}
	if !res.Success || h.store.outcome == nil {
		t.Fatalf("a label failure lost the outcome: %+v", res)
	}
}

// TestTheCommitCarriesTheFindingAndTheIdentity checks the message the reviewer
// reads first.
func TestTheCommitCarriesTheFindingAndTheIdentity(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.scans.scan.Findings = []review.Finding{{
			Severity: review.SeverityCritical, Title: "unchecked input",
			CheckID: "check-9", Path: "a.go", Line: 12,
		}}
	})
	if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	message := h.git.message
	first, rest, _ := strings.Cut(message, "\n")
	if !strings.HasPrefix(first, "[apphub] ") {
		t.Errorf("the commit title is %q", first)
	}
	for _, want := range []string{"check-9", "critical", "a.go:12", "scan-1"} {
		if !strings.Contains(rest, want) {
			t.Errorf("the commit body does not mention %q:\n%s", want, rest)
		}
	}
}
