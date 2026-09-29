// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// revision identifies the tree a figure came from.
//
// A figure without its tree is not a claim. Revision 9 reported SL = 88 and
// INT = 247 and named no source revision; the same command over the checkout a
// reader would reasonably reach for produced 87 and 246 and exited 0 just as
// happily. Both runs were correct about the tree they saw and the report was
// only correct about one of them, and nothing in the output said which.
type revision struct {
	sha   string
	dirty bool
}

func (r revision) String() string {
	if r.dirty {
		// A dirty tree is not the commit. Saying so is the whole point: the SHA
		// would otherwise describe a tree that is not the one that was counted.
		return r.sha + " (WITH UNCOMMITTED CHANGES -- the figures below are not of this commit)"
	}
	return r.sha
}

// requireAttributable ends the run on a tree whose figures cannot be attributed
// to a commit.
//
// A dirty tree is exactly that: the hash names a commit and the count is of that
// commit plus somebody's working copy. Reporting it and carrying on would be a
// third outcome between "attributable" and "fatal", which is the shape this tool
// has now been holed by three times -- so the default fails closed and the
// escape hatch is typed by a human who then owns it.
func (r revision) requireAttributable(what string, allowDirty bool) {
	if !r.dirty {
		return
	}
	if allowDirty {
		return
	}
	fail("%s tree is at %s but has uncommitted changes, so no figure derived from it "+
		"is a claim about that commit -- or about any commit. Commit or stash them, or "+
		"pass -allow-dirty to say deliberately that these figures are of a working copy "+
		"rather than of a revision anyone else can check out", what, r.sha)
}

// gitRevision resolves the commit of the repository containing dir, and whether
// its working tree is clean.
//
// It shells out to git rather than reading .git by hand. Both inputs here are
// real checkouts and one of them is a linked worktree, whose .git is a file
// pointing elsewhere; re-implementing that resolution would be a hand-maintained
// restatement of git's own layout, which is the shape of defect this package
// exists to avoid.
//
// Failure to resolve is fatal. A run that cannot say which tree it counted
// produces figures nobody can reproduce, which is the state being fixed.
func gitRevision(what, dir string) revision {
	abs, err := filepath.Abs(dir)
	if err != nil {
		fail("%s: cannot resolve %s: %v", what, dir, err)
	}
	run := func(args ...string) string {
		// #nosec G204 -- abs is a filesystem path this process was given as an
		// input and has already stat'd as a directory; the subcommand and every
		// other argument are constants.
		out, cerr := exec.Command("git", append([]string{"-C", abs}, args...)...).Output()
		if cerr != nil {
			fail("%s: cannot read the git revision of %s (%v). Every figure derived from "+
				"this tree is a claim about a specific commit, so a run that cannot name "+
				"the commit must not report figures", what, abs, cerr)
		}
		return strings.TrimSpace(string(out))
	}
	sha := run("rev-parse", "HEAD")
	if len(sha) != 40 {
		fail("%s: git reported %q as the revision of %s, which is not a commit hash",
			what, sha, abs)
	}
	return revision{sha: sha, dirty: run("status", "--porcelain") != ""}
}
