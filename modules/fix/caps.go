// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/modules/review"
)

// Suggested values for [Limits]. They are suggestions, not defaults: [New]
// refuses a zero in every field, so a caller states each bound deliberately.
const (
	// SuggestedMaxFiles bounds how many files one fix may touch. It is small
	// on purpose. A fix for one finding that rewrites a dozen files is not a
	// fix, and the cost of the bound is a refusal a person can read.
	SuggestedMaxFiles = 5
	// SuggestedMaxLines bounds the total lines across the replacement files.
	SuggestedMaxLines = 1000
	// SuggestedMaxBytesPerFile bounds one replacement file. The line bound
	// alone does not: a handful of megabyte-long lines satisfies it.
	SuggestedMaxBytesPerFile = 256 << 10
	// SuggestedMaxEncodedPatchBytes bounds the encoded patch -- the bytes that
	// are actually stored, not the sum of the file contents.
	//
	// The value is inherited from the storage fence rather than chosen here.
	// v1 persistence is DynamoDB behind store/ (docs/decisions/, USOSS-5),
	// and a DynamoDB item may not exceed 400 KiB in total, so a patch that has
	// to fit inside one alongside the rest of the record needs headroom for
	// JSON escaping, attribute names and every other field. 350 KiB is that
	// headroom.
	//
	// The source carried this reasoning as a comment beside a constant that
	// bounded something else -- the sum of the raw file contents, which is not
	// what is stored and is smaller than what is stored. [EnforceLimits]
	// checks the encoded form, so the bound is on the artefact the ceiling
	// applies to. Raising it is a storage decision before it is a review one.
	SuggestedMaxEncodedPatchBytes = 350 << 10
)

// Limits are the bounds a proposed patch must satisfy before anything is
// written to a repository.
//
// They are values on the constructor for the same reason as [review.Limits]:
// a bound that is re-read at execution time and falls back when the read fails
// is not a bound.
type Limits struct {
	// MaxFiles bounds the number of files one patch may replace.
	MaxFiles int
	// MaxLines bounds the total lines across the replacements.
	MaxLines int
	// MaxBytesPerFile bounds one replacement.
	MaxBytesPerFile int
	// MaxEncodedPatchBytes bounds the encoded patch as stored.
	MaxEncodedPatchBytes int
	// TerminalWriteTimeout bounds each write that moves the record to a
	// terminal state, on a context of its own.
	TerminalWriteTimeout time.Duration
}

// executedPrefixes are repository automation definitions. A patch to one of
// these may run on push, before the draft pull request can be reviewed, so no
// finding category may authorize it.
var executedPrefixes = []string{
	".github/workflows/",
	".github/actions/",
}

// protectedNames are file names -- matched on the basename, case-insensitively
// -- that only a supply-chain finding may change.
var protectedNames = map[string]struct{}{
	"package-lock.json": {},
	"yarn.lock":         {},
	"pnpm-lock.yaml":    {},
	"go.sum":            {},
	"poetry.lock":       {},
	"composer.lock":     {},
	"gemfile.lock":      {},
	"cargo.lock":        {},
	"dockerfile":        {},
}

// protectedSuffixes are basename suffixes under the same rule, so a lock file
// this list has never heard of is still protected.
var protectedSuffixes = []string{".lock"}

// supplyChainCategories are the finding categories that unlock dependency and
// build files, never repository automation. A finding about a dependency has
// to be able to change the file that pins it, or it cannot be fixed at all.
//
// The match is exact against the whole normalised category. The source split
// the category on separators and admitted it if any fragment was in this set,
// so "artificial-intelligence/ci" unlocked protected paths. That is a widening
// path driven by a string a model wrote while reading a repository this process
// does not control, which is the wrong direction for a check to be lenient in:
// this one refuses a category it does not recognise, including a compound one.
// See docs/decisions/.
var supplyChainCategories = map[string]struct{}{
	"build":                   {},
	"build-system":            {},
	"cd":                      {},
	"ci":                      {},
	"ci-cd":                   {},
	"cicd":                    {},
	"continuous-integration":  {},
	"dependencies":            {},
	"dependency":              {},
	"lockfile":                {},
	"package":                 {},
	"package-manager":         {},
	"supply-chain":            {},
	"supplychain":             {},
	"vulnerable-dependencies": {},
	"vulnerable-dependency":   {},
}

// SupplyChainCategories returns the categories that unlock dependency and
// build files, sorted. Derived from the same map [IsSupplyChainCategory] reads,
// so a test quantifying over the set covers exactly what the check admits.
func SupplyChainCategories() []string {
	out := make([]string, 0, len(supplyChainCategories))
	for c := range supplyChainCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// IsSupplyChainCategory reports whether cat unlocks dependency and build files.
//
// Normalisation is lowercasing, trimming surrounding space, and treating "_"
// as "-" -- three spelling variations of one token, and nothing that turns one
// token into several. A category that is not in the set after that is refused.
func IsSupplyChainCategory(cat string) bool {
	normalised := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(cat)), "_", "-")
	if normalised == "" {
		return false
	}
	_, ok := supplyChainCategories[normalised]
	return ok
}

// IsProtectedPath reports whether p is a platform-executed CI definition or a
// dependency/build file gated by the finding category.
func IsProtectedPath(p string) bool {
	lower := strings.ToLower(p)
	return isExecutedPath(lower) || isCategoryProtectedPath(lower)
}

// Both helpers take an already lowercased path so EnforceLimits classifies each
// proposed path without lowercasing it twice.
func isExecutedPath(lower string) bool {
	for _, prefix := range executedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isCategoryProtectedPath(lower string) bool {
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if _, ok := protectedNames[base]; ok {
		return true
	}
	// Dockerfile, and the whole suffixed family of it: a build stage
	// variant is still the file that decides what the image contains.
	if strings.HasPrefix(base, "dockerfile") {
		return true
	}
	for _, suffix := range protectedSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// CountLines returns the number of lines in s, counting a final unterminated
// line. An empty string is zero lines.
func CountLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// EnforceLimits checks a proposed patch and returns the accepted changes with
// their line counts filled in.
//
// Every failure is returned as an error whose text is shown to the requester,
// so each says which file and which bound. The checks are performed here,
// before [Module.Execute] writes anything, because after the first blob is
// created there is no longer a decision to make.
//
// tree is the snapshot the fix was reasoned against. A path not in it is
// refused: this module edits files that exist and does not create them, which
// is what stops an agent that has been talked into it from dropping a new file
// somewhere in the repository.
func EnforceLimits(files []FileChange, category string, tree review.Tree, limits Limits) ([]FileChange, int, error) {
	if len(files) > limits.MaxFiles {
		return nil, 0, fmt.Errorf("the patch touches %d files; the limit is %d", len(files), limits.MaxFiles)
	}
	allowProtected := IsSupplyChainCategory(category)
	out := make([]FileChange, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	totalLines := 0
	for _, f := range files {
		path := strings.TrimSpace(f.Path)
		if path == "" {
			// An entry with no path names nothing. Refusing rather than
			// skipping is the difference between a patch that was checked and
			// one that was partly checked.
			return nil, 0, fmt.Errorf("the patch contains a change with no file path")
		}
		if review.SanitisePath(path) == "" {
			return nil, 0, fmt.Errorf("the patch contains an invalid file path %q", path)
		}
		if _, dup := seen[path]; dup {
			return nil, 0, fmt.Errorf("the patch changes %q twice", path)
		}
		seen[path] = struct{}{}
		lower := strings.ToLower(path)
		if isExecutedPath(lower) {
			return nil, 0, fmt.Errorf("the patch changes the platform-executed CI path %q, which cannot be edited by a fix", path)
		}
		if isCategoryProtectedPath(lower) && !allowProtected {
			return nil, 0, fmt.Errorf("the patch changes the protected path %q, which is only permitted for a supply-chain finding", path)
		}
		if _, ok := tree.Read(path); !ok {
			return nil, 0, fmt.Errorf("the patch changes %q, which is not in the repository; creating files is not permitted", path)
		}
		if n := len(f.Contents); n > limits.MaxBytesPerFile {
			return nil, 0, fmt.Errorf("the patch's %q is %d bytes; the per-file limit is %d", path, n, limits.MaxBytesPerFile)
		}
		lines := CountLines(f.Contents)
		totalLines += lines
		if totalLines > limits.MaxLines {
			return nil, 0, fmt.Errorf("the patch exceeds the %d-line limit", limits.MaxLines)
		}
		out = append(out, FileChange{Path: path, Contents: f.Contents, Lines: lines})
	}
	return out, totalLines, nil
}
