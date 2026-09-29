// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"context"
	"errors"

	"github.com/conductorone/apphub/modules/review"
)

// Coordinates name the repository being written to. It is [review.Coordinates]
// under another name: the fix acts on the repository the scan read, so naming a
// second type for the same three fields plus an installation would create two
// things to keep in step.
type Coordinates = review.Coordinates

// ErrRefExists reports that a ref already exists, so the name has to change.
// [GitClient.CreateRef] returns something wrapping this and the module retries
// under a new name. Wrap with %w.
var ErrRefExists = errors.New("fix: ref already exists")

// TreeEntry is one file in a tree being created.
type TreeEntry struct {
	// Path is repository-relative.
	Path string
	// Mode is the octal string a Git tree entry carries: "100644" for a
	// regular file, "100755" for an executable one.
	Mode string
	// BlobSHA identifies the content, from [GitClient.CreateBlob].
	BlobSHA string
}

// The two file modes this package writes. A mode outside the pair is never
// produced: the source mode is carried through only when it is one of these,
// so a snapshot reporting something else -- a symlink, a submodule, a
// directory -- cannot become a blob entry claiming to be that thing.
const (
	// ModeFile is a regular file.
	ModeFile = "100644"
	// ModeExecutable is a regular file with the executable bit set.
	ModeExecutable = "100755"
)

// PullRequest is the pull request to open.
type PullRequest struct {
	// Title is plain text. It is not rendered as markup by the host, so it is
	// the one place untrusted text is not fenced -- see pr.go.
	Title string
	// Body is markup and is assembled by buildBody, which fences every piece
	// of untrusted text it includes.
	Body string
	// Head is the branch carrying the change.
	Head string
	// Base is the branch to merge into.
	Base string
	// Draft asks for a draft pull request. This module always sets it.
	Draft bool
}

// PullRequestResult identifies the pull request that was opened.
type PullRequestResult struct {
	// Number is the pull request's number in the repository.
	Number int
	// URL is where a person can read it.
	URL string
}

// GitClient is the write side of the hosting platform, as this module needs
// it: the object-level API a commit is built out of, plus the two calls that
// turn a branch into something a person reviews.
//
// It is one interface rather than several because the six object calls are one
// sequence with one failure story, and splitting them would let a caller wire
// half of it.
//
// Every method takes [review.Coordinates] and none takes a credential: an
// implementation authenticates itself from the installation named there. That
// is why no token appears anywhere in this package.
type GitClient interface {
	// DefaultBranch returns the repository's default branch name.
	DefaultBranch(ctx context.Context, at Coordinates) (string, error)
	// BranchHead returns the commit a branch points at, or ("", nil) when the
	// branch does not exist. A missing branch is not an error here because the
	// module has to be able to tell "no such branch" from "the lookup failed",
	// and it acts differently on each.
	BranchHead(ctx context.Context, at Coordinates, branch string) (string, error)
	// TagExists reports whether a tag of this name exists. It is asked only to
	// turn "that branch does not exist" into a message that says why.
	TagExists(ctx context.Context, at Coordinates, tag string) (bool, error)
	// CommitTree returns the tree a commit points at.
	CommitTree(ctx context.Context, at Coordinates, commitSHA string) (string, error)
	// CreateBlob stores file content and returns its identifier.
	CreateBlob(ctx context.Context, at Coordinates, content []byte) (string, error)
	// CreateTree stores a tree derived from baseTreeSHA with entries applied,
	// and returns its identifier. Deriving from the base tree is what leaves
	// every file the patch did not mention exactly as it was.
	CreateTree(ctx context.Context, at Coordinates, baseTreeSHA string, entries []TreeEntry) (string, error)
	// CreateCommit stores a commit and returns its identifier.
	CreateCommit(ctx context.Context, at Coordinates, message, treeSHA, parentSHA string) (string, error)
	// CreateBranch points a new branch at a commit. It returns something
	// wrapping [ErrRefExists] when the name is taken.
	CreateBranch(ctx context.Context, at Coordinates, branch, commitSHA string) error
	// OpenPullRequest opens the pull request.
	OpenPullRequest(ctx context.Context, at Coordinates, pr PullRequest) (*PullRequestResult, error)
	// AddLabels labels it. Best effort: the module logs a failure and carries
	// on, because a missing label does not make the pull request less useful.
	AddLabels(ctx context.Context, at Coordinates, number int, labels []string) error
}
