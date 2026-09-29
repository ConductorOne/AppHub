// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/conductorone/apphub/internal/detect"
	"github.com/conductorone/apphub/modules/deploy"
)

// maxDiscoverFiles, maxDiscoverFileBytes and maxDiscoverTreeBytes bound what
// Discover loads into memory. Detection only ever reads a Dockerfile, a
// compose file, or a small dependency manifest, so these are far smaller than
// [maxSourceBytes]: unlike Prepare, which hands a whole checkout to an image
// build, Discover's caller only ever looks at a handful of small files, and
// bounding what is read keeps a repository with a huge unrelated tree from
// costing more than a normal one to scan.
const (
	maxDiscoverFiles     = 500
	maxDiscoverFileBytes = 256 << 10
	maxDiscoverTreeBytes = 8 << 20
)

// Discover shallow-clones one approved repository revision and returns its
// file tree in memory, for advisory repository introspection (Dockerfile
// discovery, compose preview, database guess) ahead of a deploy that names a
// Dockerfile explicitly. Unlike Prepare, no Dockerfile path is required or
// validated, and no build directory is exposed.
//
// Discover always spends this Checkout, successful or not: nothing calls Fetch
// after a scan, so its temporary directory is removed before Discover returns
// rather than left for a caller that will never claim it. Construct a fresh
// Checkout per call, exactly as Prepare's callers do per deploy.
//
// This exists in the worker, not the authenticated API process, for the same
// reason Prepare does: acquiring source means running a version-control client
// with credentials for a code host (see [NewCheckout]'s "githubApp" auth), and
// the process that serves requester HTTP traffic never holds those
// credentials (serverconfig.Load skips loading them in "serve" mode). A
// repository's Dockerfile is discovered by the same isolated worker that will
// eventually build it, not by the process an unauthenticated caller can reach.
func (c *Checkout) Discover(ctx context.Context, src deploy.Source) (commit string, tree detect.Tree, resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.attempted {
		return "", detect.Tree{}, ErrNotPrepared
	}
	c.attempted, c.closed = true, true
	defer func() {
		if err := os.RemoveAll(c.root); err != nil {
			resultErr = errors.Join(resultErr, ErrUnavailable)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()

	canonical, err := canonicalURL(src.URL)
	if err != nil {
		return "", detect.Tree{}, err
	}
	repo, err := c.resolve(ctx, canonical)
	if err != nil {
		return "", detect.Tree{}, err
	}
	if err := c.validateRef(ctx, src.Ref); err != nil {
		return "", detect.Tree{}, err
	}
	if _, err := c.run(ctx, nil, "init", "--quiet", "--template=", c.dir); err != nil {
		return "", detect.Tree{}, err
	}

	var auth *askpass
	if repo.app != nil {
		auth, err = c.authentication(ctx, repo)
		if err != nil {
			return "", detect.Tree{}, err
		}
		defer func() {
			if cleanupErr := auth.close(); cleanupErr != nil {
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}()
	}
	remote := canonical
	if c.transport != nil {
		remote = c.transport(canonical)
	}
	ref := src.Ref
	if ref == "" {
		ref = "HEAD"
	}
	_, err = c.run(ctx, auth, "-C", c.dir, "fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", remote, ref)
	if auth != nil {
		if cleanupErr := auth.close(); cleanupErr != nil {
			return "", detect.Tree{}, errors.Join(err, cleanupErr)
		}
	}
	if err != nil {
		return "", detect.Tree{}, err
	}
	out, err := c.run(ctx, nil, "-C", c.dir, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", detect.Tree{}, err
	}
	commit = strings.TrimSpace(out)
	if !commitPattern.MatchString(commit) {
		return "", detect.Tree{}, ErrRefused
	}
	if _, err := c.run(ctx, nil, "-C", c.dir, "checkout", "--quiet", "--detach", commit, "--"); err != nil {
		return "", detect.Tree{}, err
	}
	if err := os.RemoveAll(filepath.Join(c.dir, ".git")); err != nil {
		return "", detect.Tree{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return "", detect.Tree{}, ErrCanceled
	}

	scanned, err := scanTree(c.dir)
	if err != nil {
		return "", detect.Tree{}, err
	}
	return commit, scanned, nil
}

// scanTree walks a checked-out directory and loads the small set of files
// [detect.FromTree] can use into memory, skipping everything else. It is
// best-effort and permissive by design, unlike validateTree: an unreadable or
// oversized file is skipped rather than refused, because a scan is advisory
// and never reaches a builder, and a broken symlink or an unusual repository
// layout should degrade the suggestion, not fail it.
//
// Traversal goes through [os.Root], the same symlink-safe mechanism
// exposeContext uses, so a symlink cannot walk this scan outside the checkout.
func scanTree(dir string) (detect.Tree, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return detect.Tree{}, ErrUnavailable
	}
	defer func() { _ = root.Close() }() // Read-only directory handle; no pending writes.

	files := make(map[string][]byte)
	var total int64
	walkErr := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrUnavailable
		}
		if name == "." || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		if !interestingName(entry.Name()) || len(files) >= maxDiscoverFiles {
			return nil
		}
		f, err := root.Open(name)
		if err != nil {
			return nil // Best-effort: skip a file this scan cannot read.
		}
		data, err := io.ReadAll(io.LimitReader(f, maxDiscoverFileBytes))
		_ = f.Close()
		if err != nil || total+int64(len(data)) > maxDiscoverTreeBytes {
			return nil
		}
		total += int64(len(data))
		files[filepath.ToSlash(name)] = data
		return nil
	})
	if walkErr != nil {
		return detect.Tree{}, ErrUnavailable
	}
	return detect.Tree{Files: files}, nil
}

// interestingName reports whether base is a filename [detect.FromTree] reads:
// a Dockerfile, a compose file, or one of the dependency-manifest/env files it
// scans for a database hint. The match is case-insensitive to be a safe
// superset -- detect.FromTree applies its own, more precise matching against
// the paths this produces, so over-inclusion here only wastes a few bytes of
// memory, never a wrong answer.
func interestingName(base string) bool {
	lower := strings.ToLower(base)
	switch {
	case lower == "dockerfile", strings.HasPrefix(lower, "dockerfile."):
		return true
	case lower == "compose.yaml", lower == "compose.yml", lower == "docker-compose.yaml", lower == "docker-compose.yml":
		return true
	case lower == "package.json", lower == "go.mod", lower == "requirements.txt",
		lower == "pyproject.toml", lower == "pipfile", lower == "gemfile", lower == "schema.prisma":
		return true
	case lower == ".env", strings.HasPrefix(lower, ".env."):
		return true
	}
	return false
}
