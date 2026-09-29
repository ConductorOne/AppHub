// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Tree is a read-only snapshot of a repository, held in memory.
//
// It is the whole of what a [Scanner] is given: an implementation must not
// touch the disk or the network to answer either method, so a scan cannot
// reach anything the snapshot does not contain.
type Tree interface {
	// List returns every path in the snapshot, sorted.
	List() []string
	// Read returns the bytes at one path, or (nil, false) when the snapshot
	// has no such path.
	Read(path string) ([]byte, bool)
	// Mode returns the file mode the source recorded for one path, in the
	// octal string form a Git tree entry uses ("100644", "100755"), or
	// ("", false) when the source recorded none. modules/fix uses it so a fix
	// preserves the executable bit rather than silently clearing it.
	Mode(path string) (string, bool)
}

// Coordinates name one repository at one revision, together with the
// installation whose authorisation reaches it.
//
// InstallationID is how authentication is expressed here, and it is the only
// way it is expressed: this package never sees a token. A [SourceFetcher]
// resolves credentials for itself, so there is nothing here to redact.
type Coordinates struct {
	// Owner is the repository owner. Validated by [ValidateOwnerRepo].
	Owner string
	// Repo is the repository name, without the owner.
	Repo string
	// Ref is the revision to read: a branch, tag or commit. Empty means the
	// repository's default branch.
	Ref string
	// InstallationID identifies the installation to authenticate as. Zero
	// means no installation: the fetch is unauthenticated, which is what
	// "public" mode is.
	InstallationID int64
}

// Authenticated reports whether these coordinates name an installation.
func (c Coordinates) Authenticated() bool { return c.InstallationID > 0 }

// Snapshot is a repository's contents at one revision, together with the name
// of the revision it actually is.
//
// Commit is not decoration. [Coordinates.Ref] may name a branch, and a branch
// is a moving pointer: the contents that come back are the contents of one
// commit, and which commit that was is the only thing that makes the snapshot
// an artefact rather than a reading. Anything that later writes against the
// same branch has to be able to ask whether it is still the same commit --
// see modules/fix, where not being able to ask it silently overwrote a
// concurrent change.
type Snapshot struct {
	// Tree is the contents.
	Tree Tree
	// Commit identifies the revision the contents came from. It must be
	// immutable: a branch name here would defeat the point. A fetcher that
	// returns an empty Commit is refused, because a snapshot that cannot say
	// what it is cannot be checked against anything.
	Commit string
}

// SourceFetcher produces the snapshot a scan runs against.
//
// The three sentinels below are the vocabulary an implementation reports
// failures in. They exist because [Module.Execute] has to turn a failure into
// a message a person reads, and it cannot do that from an opaque error: an
// implementation that wraps none of them gets the general message, which is
// correct but unhelpful. Wrap with %w.
type SourceFetcher interface {
	// Fetch returns a snapshot of the repository at the given coordinates,
	// refusing anything whose decompressed size would exceed maxBytes. It must
	// populate [Snapshot.Commit] with the immutable revision it resolved.
	Fetch(ctx context.Context, at Coordinates, maxBytes int64) (*Snapshot, error)
}

var (
	// ErrSourceNotFound reports that the repository or the revision does not
	// exist, or is not visible to the installation.
	ErrSourceNotFound = errors.New("review: repository or ref not found")
	// ErrSourceTooLarge reports that the snapshot exceeded the byte cap.
	ErrSourceTooLarge = errors.New("review: repository snapshot exceeds the configured cap")
	// ErrSourceForbidden reports that the host refused the request: a missing
	// grant on an authenticated fetch, or a rate limit on an unauthenticated
	// one.
	ErrSourceForbidden = errors.New("review: source host denied the request")
)

// Repository-name shape. Both bounds and the pattern come from what a hosting
// platform itself accepts, so nothing here rejects a name that could exist.
const (
	// MaxOwnerLen bounds an owner login.
	MaxOwnerLen = 39
	// MaxRepoLen bounds a repository name.
	MaxRepoLen = 100
	// MaxRefLen bounds a revision.
	MaxRefLen = 250
)

// segmentRE bounds an owner or repository name. Requiring the first character
// to be alphanumeric is what excludes ".", "..", ".hidden" and "-rf" without
// naming any of them: none of those can exist as a repository, so nothing real
// is refused by the requirement.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateOwnerRepo checks an owner and repository name.
//
// It is exported because modules/fix names the same repositories and must
// apply the same rule; restating it there would be a second copy to keep in
// step with this one.
func ValidateOwnerRepo(owner, repo string) error {
	if owner == "" {
		return fmt.Errorf("owner is required and must be a non-empty string")
	}
	if len(owner) > MaxOwnerLen || !segmentRE.MatchString(owner) {
		return fmt.Errorf("owner contains invalid characters or exceeds %d characters", MaxOwnerLen)
	}
	if repo == "" {
		return fmt.Errorf("repo is required and must be a non-empty string")
	}
	if len(repo) > MaxRepoLen || !segmentRE.MatchString(repo) {
		return fmt.Errorf("repo contains invalid characters or exceeds %d characters", MaxRepoLen)
	}
	return nil
}

// refRE bounds a revision to the characters a ref can contain here.
var refRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// IsSafeRef reports whether ref may be spliced into a request path.
//
// A ref reaches a hosting API inside a URL path that is deliberately not
// escaped, because slashes in a ref are meaningful. That makes this check the
// whole of the defence, so it is an allowlist of characters plus a structural
// rule: a ref is a sequence of non-empty components separated by slashes.
//
// The structural half is not inherited. The source checked the character set,
// refused ".." anywhere, and refused a leading "-", which accepts "/x", "x/"
// and "a//b" -- every one of which produces an empty path component when it is
// spliced into a URL, and none of which is a ref any implementation would
// resolve. It was found here by testing the shape rather than the examples.
//
// Each component must therefore be non-empty, must not be "." or "..", and
// must not begin with "-": the last because a ref read by anything that shells
// out becomes an option. ".." is additionally refused anywhere, because it
// traverses even inside a component.
//
// Exported for the same reason as [ValidateOwnerRepo]: modules/fix re-checks
// the default branch it learns from the host, which is the one ref neither
// module validated on the way in.
func IsSafeRef(ref string) bool {
	if ref == "" || len(ref) > MaxRefLen {
		return false
	}
	if !refRE.MatchString(ref) {
		return false
	}
	if strings.Contains(ref, "..") {
		return false
	}
	for _, component := range strings.Split(ref, "/") {
		if component == "" || component == "." || component[0] == '-' {
			return false
		}
	}
	return true
}
