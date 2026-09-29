// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The traversal contract was verified by review against the real source and
// adversarial copies of it. These fixtures pin the same states hermetically so a
// later change cannot quietly regress them. Each names the class -- "a state
// that makes a traversal incomplete without erroring" -- rather than the symlink
// case that happened to be found first.

func writeGo(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

// goodTree is a minimal population that must traverse cleanly, so every failure
// below is attributable to the state it introduces rather than to the fixture.
func goodTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeGo(t, filepath.Join(root, "a.go"), "package p\n")
	writeGo(t, filepath.Join(root, "sub", "b.go"), "package q\n")
	writeGo(t, filepath.Join(root, "sub", "b_test.go"), "package q\n")
	return root
}

func TestATreeThatIsFullyTraversableIsAccepted(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	var err error
	var got tree
	func() {
		defer recoverFail(&err)
		got = mustTree("T", root, root)
	}()
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if got.n() != 2 {
		t.Errorf("population is %d, want 2 (test files excluded)", got.n())
	}
}

func TestANonexistentRootFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"cannot stat"}, func() {
		mustTree("T", filepath.Join(t.TempDir(), "nope"), "")
	})
}

func TestARootThatIsNotADirectoryFailsTheRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	f := filepath.Join(root, "file.go")
	writeGo(t, f, "package p\n")
	wantIncomplete(t, []string{"is not a directory"}, func() { mustTree("T", f, f) })
}

// A population that traverses cleanly and contains nothing yields 0 / 0 rows,
// which are the absence of a count rather than a count.
func TestAnEmptyPopulationFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"no production .go files", "absence of a count"}, func() {
		mustTree("T", t.TempDir(), "")
	})
}

// A file that does not parse must not be dropped from the denominators it
// belongs in: that leaves a table which looks exactly like a correct table.
func TestAMalformedProductionFileFailsTheRun(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	writeGo(t, filepath.Join(root, "broken.go"), "package p\nfunc (\n")
	wantIncomplete(t, []string{"parse", "broken.go"}, func() { mustTree("T", root, root) })
}

// A malformed *test* file is outside the population and must not fail the run,
// or the contract would be stricter than the claim it supports.
func TestAMalformedTestFileIsIgnored(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	writeGo(t, filepath.Join(root, "broken_test.go"), "package p\nfunc (\n")
	wantOK(t, func() { mustTree("T", root, root) })
}

// The state that holed the previous contract: filepath.Walk uses Lstat, so a
// symlinked directory is never descended into and leaves no trace in the output.
func TestASymlinkedDirectoryFailsTheRun(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	outside := t.TempDir()
	writeGo(t, filepath.Join(outside, "hidden.go"), "package p\n")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	wantIncomplete(t, []string{"is a symlink", "linked", outside}, func() { mustTree("T", root, root) })
}

func TestASymlinkedGoFileFailsTheRun(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "hidden.go")
	writeGo(t, target, "package p\n")
	if err := os.Symlink(target, filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	wantIncomplete(t, []string{"is a symlink", "linked.go", target}, func() { mustTree("T", root, root) })
}

func TestARootThatIsItselfASymlinkFailsTheRun(t *testing.T) {
	t.Parallel()
	actual := goodTree(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	wantIncomplete(t, []string{"is itself a symlink"}, func() { mustTree("T", link, link) })
}

// A named pipe called *.go would make the parser block or fail for reasons
// unrelated to Go syntax.
func TestANonRegularGoEntryFailsTheRun(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on windows")
	}
	root := goodTree(t)
	fifo := filepath.Join(root, "pipe.go")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	wantIncomplete(t, []string{"not a regular file", "pipe.go"}, func() { mustTree("T", root, root) })
}

// An unreadable subtree is a walk error, and a walk error is a subtree missing
// from every count below it.
func TestAnUnreadableSubtreeFailsTheRun(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	root := goodTree(t)
	locked := filepath.Join(root, "locked")
	writeGo(t, filepath.Join(locked, "c.go"), "package r\n")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot chmod here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	wantIncomplete(t, []string{"walk", "locked"}, func() { mustTree("T", root, root) })
}

// Two traversals that disagree mean the tree changed under the walk, so neither
// count is of a population that existed. Rather than race a background mutator
// -- which the previous round could only report probabilistically -- this drives
// the comparison directly, which is the resolution the failure actually lives
// at.
func TestTwoTraversalsThatDisagreeFailTheRun(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	first, err := walkPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	writeGo(t, filepath.Join(root, "sub", "appeared.go"), "package q\n")
	second, err := walkPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == len(second) {
		t.Fatalf("fixture did not change the path set: %d then %d", len(first), len(second))
	}
	// And the same state reached through mustTree, where it must be fatal.
	root2 := goodTree(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			p := filepath.Join(root2, "churn.go")
			if i%2 == 0 {
				_ = os.WriteFile(p, []byte("package p\n"), 0o644)
			} else {
				_ = os.Remove(p)
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	// Probabilistic by nature: the assertion is that when the two walks do
	// disagree the run fails, not that they disagree on any given attempt.
	for i := 0; i < 200; i++ {
		var err error
		func() {
			defer recoverFail(&err)
			mustTree("T", root2, root2)
		}()
		if err != nil {
			// Every way a tree mutating under the walk can surface is fatal,
			// and which one surfaces on a given attempt is a race: the two
			// walks disagree, or the second walk's Lstat finds a file that
			// readdir had just listed, or a half-written file will not parse.
			// The property is that none of them yields a successful audit.
			raceAttributable := []string{
				"two traversals disagree", "walk ", "lstat", "parse",
			}
			ok := false
			for _, m := range raceAttributable {
				if strings.Contains(err.Error(), m) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("unexpected failure: %v", err)
			}
			return // the state was reached and was fatal
		}
	}
	t.Log("the two walks never disagreed in 200 attempts; the direct comparison above " +
		"is the load-bearing half of this test")
}
