// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/conductorone/apphub/modules/review"
)

// ErrBaseNotBranch reports that the revision the scan ran against cannot be
// the base of a pull request.
//
// A pull request merges into a branch. A scan may run against a tag or a
// commit, and there is no branch to target when it did. It is a named error
// rather than a message because it is the one push failure whose remedy the
// requester can carry out: re-run the scan against a branch.
var ErrBaseNotBranch = errors.New("fix: the base revision is not a branch")

// ErrBaseMoved reports that the branch advanced between the snapshot being
// read and the patch being pushed.
//
// This is the transition, not the call. Every step of the push is correct on
// its own: the snapshot is read at one commit, the branch head is read again
// later, and the new tree is derived from whatever the branch points at then.
// What is wrong is the move between them -- the patch is a set of *whole-file*
// replacements computed from the older contents, so committing it on top of a
// newer head silently reverts whatever landed in between, and every call in
// the sequence still happens in its expected order.
//
// The remedy is refusal rather than reconciliation. Merging a model's
// whole-file output against a concurrent change is a three-way merge this
// module has no business attempting, and getting it subtly wrong produces a
// pull request that looks reviewed and is not. Re-running the fix is cheap.
var ErrBaseMoved = errors.New("fix: the branch moved after the snapshot was read")

// push builds the commit and opens the pull request.
//
// The sequence is: resolve the base branch, read its head commit's tree,
// create a blob per file, create a tree derived from the base tree, create a
// commit, create a branch, open the pull request, label it.
//
// Deriving the new tree from the base tree is what makes this a patch rather
// than a replacement: every path the change did not mention keeps the entry it
// had.
func (m *Module) push(ctx context.Context, p pushRequest) (*Outcome, error) {
	base, err := m.resolveBaseBranch(ctx, p.At)
	if err != nil {
		return nil, err
	}

	baseSHA, err := m.git.BranchHead(ctx, p.At, base)
	if err != nil {
		return nil, fmt.Errorf("read the head of %q: %w", base, err)
	}
	if baseSHA == "" {
		// The branch is not there. Before reporting that, ask whether the name
		// is a tag: a tag reaches here looking exactly like a branch that does
		// not exist, and the two have different remedies.
		if isTag, terr := m.git.TagExists(ctx, p.At, base); terr == nil && isTag {
			return nil, fmt.Errorf("%w: %q is a tag", ErrBaseNotBranch, base)
		}
		return nil, fmt.Errorf("the base branch %q does not exist on %s/%s", base, p.At.Owner, p.At.Repo)
	}

	// The ref that was read has to be the ref that is written against. This is
	// the check ErrBaseMoved exists for, and it is here rather than anywhere
	// later because the next call creates a blob.
	// An empty p.Snapshot needs no branch of its own: Execute refuses a
	// snapshot that names no revision before it gets here, and if one ever
	// did, an empty string does not equal a real commit and this refuses it.
	// A branch that cannot fire is worse than no branch, because it reads as
	// coverage.
	if baseSHA != p.Snapshot {
		return nil, fmt.Errorf("%w: the snapshot was read at %s and %q now points at %s",
			ErrBaseMoved, p.Snapshot, base, baseSHA)
	}

	baseTreeSHA, err := m.git.CommitTree(ctx, p.At, baseSHA)
	if err != nil {
		return nil, fmt.Errorf("read the tree of commit %s: %w", baseSHA, err)
	}

	entries := make([]TreeEntry, 0, len(p.Files))
	for _, f := range p.Files {
		blobSHA, err := m.git.CreateBlob(ctx, p.At, []byte(f.Contents))
		if err != nil {
			return nil, fmt.Errorf("create a blob for %s: %w", f.Path, err)
		}
		entries = append(entries, TreeEntry{Path: f.Path, Mode: entryMode(p.Tree, f.Path), BlobSHA: blobSHA})
	}
	treeSHA, err := m.git.CreateTree(ctx, p.At, baseTreeSHA, entries)
	if err != nil {
		return nil, fmt.Errorf("create the tree: %w", err)
	}

	commitSHA, err := m.git.CreateCommit(ctx, p.At, buildCommitMessage(m.identity, p), treeSHA, baseSHA)
	if err != nil {
		return nil, fmt.Errorf("create the commit: %w", err)
	}

	branch, err := m.createBranch(ctx, p, commitSHA)
	if err != nil {
		return nil, err
	}

	pr, err := m.git.OpenPullRequest(ctx, p.At, PullRequest{
		Title: buildTitle(m.identity, p),
		Body:  buildBody(m.identity, p, branch, commitSHA),
		Head:  branch,
		Base:  base,
		// Always a draft. A person is the last step of this pipeline, and a
		// draft is what makes that structural rather than customary.
		Draft: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open the pull request: %w", err)
	}
	if pr == nil {
		return nil, fmt.Errorf("the git client opened no pull request and reported no error")
	}

	if err := m.git.AddLabels(ctx, p.At, pr.Number, []string{m.identity.Name}); err != nil {
		// Best effort. A label makes the pull request easier to find and its
		// absence makes nothing wrong.
		m.log.WarnContext(ctx, "could not label the pull request",
			slog.Int("pullRequest", pr.Number), slog.Any("error", err))
	}

	return &Outcome{
		Branch:            branch,
		CommitSHA:         commitSHA,
		PullRequestURL:    pr.URL,
		PullRequestNumber: pr.Number,
	}, nil
}

// resolveBaseBranch turns the scan's revision into a branch name, or explains
// why it is not one.
//
// The revision reached this module either from the scan record or, when that
// was empty, from the host's own answer about the default branch. The second
// is the one revision neither module validated on the way in, so it is checked
// here: it is about to be spliced into a request path that deliberately does
// not escape slashes.
func (m *Module) resolveBaseBranch(ctx context.Context, at Coordinates) (string, error) {
	base := strings.TrimSpace(at.Ref)
	if base == "" || base == "HEAD" {
		resolved, err := m.git.DefaultBranch(ctx, at)
		if err != nil {
			return "", fmt.Errorf("resolve the default branch: %w", err)
		}
		base = strings.TrimSpace(resolved)
		if base == "" {
			return "", fmt.Errorf("could not determine the default branch of %s/%s", at.Owner, at.Repo)
		}
	}
	if !review.IsSafeRef(base) {
		return "", fmt.Errorf("the base revision %q contains characters that are not permitted in a ref", base)
	}
	switch {
	case strings.HasPrefix(base, "refs/heads/"):
		return strings.TrimPrefix(base, "refs/heads/"), nil
	case strings.HasPrefix(base, "refs/tags/"):
		return "", fmt.Errorf("%w: %q is a tag", ErrBaseNotBranch, base)
	case strings.HasPrefix(base, "refs/"):
		// Some other ref namespace: notes, pull request heads, replaces. None
		// of them is a branch, and guessing which is which is a grammar this
		// module does not need to know.
		return "", fmt.Errorf("%w: %q is not a branch", ErrBaseNotBranch, base)
	case looksLikeCommitSHA(base):
		return "", fmt.Errorf("%w: %q is a commit", ErrBaseNotBranch, base)
	default:
		return base, nil
	}
}

// createBranch creates the branch, changing the name on collision.
//
// The name is "<identity>/fix-<scanID>-<index>", then the same with "-r1",
// "-r2" and so on. Both variable parts were validated on the way in: the
// identity by [Identity.Validate] and the scan identifier by [Module.Validate],
// which is what makes it safe to build a ref out of them.
func (m *Module) createBranch(ctx context.Context, p pushRequest, commitSHA string) (string, error) {
	for attempt := 0; attempt < maxBranchAttempts; attempt++ {
		name := fmt.Sprintf("%s/fix-%s-%d", m.identity.Name, p.ScanID, p.Index)
		if attempt > 0 {
			name = fmt.Sprintf("%s-r%d", name, attempt)
		}
		err := m.git.CreateBranch(ctx, p.At, name, commitSHA)
		switch {
		case err == nil:
			return name, nil
		case errors.Is(err, ErrRefExists):
			continue
		default:
			return "", fmt.Errorf("create the branch: %w", err)
		}
	}
	return "", fmt.Errorf("could not find an unused branch name after %d attempts", maxBranchAttempts)
}

// entryMode returns the tree-entry mode for a path.
//
// The source's mode is carried through only when it is one this module writes,
// so a snapshot reporting a symlink, a submodule or a directory cannot turn
// into a blob entry claiming to be one. Everything else is a regular file:
// executability is not inferred from the name or from a shebang, because a
// person reviewing the draft can set the bit and a wrong guess is a permission
// change nobody asked for.
func entryMode(tree review.Tree, path string) string {
	if tree == nil {
		return ModeFile
	}
	if mode, ok := tree.Mode(path); ok && mode == ModeExecutable {
		return ModeExecutable
	}
	return ModeFile
}

// looksLikeCommitSHA reports whether ref is shaped like an object name: 7 to
// 40 lowercase hex digits, the short form upwards.
//
// A branch could in principle be named "abc1234". Refusing such a branch costs
// its owner a clear message; admitting every commit costs a failed push at the
// last step with nothing to say about why.
func looksLikeCommitSHA(ref string) bool {
	if len(ref) < 7 || len(ref) > 40 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
