// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// This file is the part of a hosted build that is not about ECS: what the
// provider's argument list is allowed to say, what a build context is allowed to
// contain, and how bytes cross between the worker's filesystem and a slot.
//
// It is the container-backed runner's validation, moved rather than rewritten.
// None of it was ever about Docker: a flag allowlist, a containment check and a
// bounded tree walk are the same controls whoever executes the builder.

const (
	// buildTaskDiskBytes bounds the artefact that crosses back. Eight GiB is
	// the same ceiling the container-backed runner set on a build's disk.
	buildTaskDiskBytes int64 = 8 << 30

	// buildTaskContextBytes bounds the tree that crosses out.
	//
	// [compute.BuildSource.ContextDir] obliges a provider whose builder does not
	// share the caller's filesystem to "document the size limit at which it
	// refuses", precisely so that shipping an unbounded tree across a network is
	// not an available reading of that field. This is that limit.
	buildTaskContextBytes int64 = 512 << 20

	// buildTaskDigestBytes bounds the digest file. A digest is 71 bytes.
	buildTaskDigestBytes int64 = 128

	// minBuildEphemeralGiB is the smallest task scratch space worth accepting.
	// kaniko unpacks every layer of the image it is building into it, and
	// Fargate's own floor is 21.
	minBuildEphemeralGiB = 21

	// buildTaskStartedBy marks tasks this provider launched, so an operator
	// reading a cluster can tell them apart. It names the project, never a
	// deployment.
	buildTaskStartedBy = "apphub-build"

	// buildValidationDestination names the image inside the validation build's
	// tarball. It is never contacted: the build runs with --no-push, and the
	// builder only refuses a --tar-path build that names no destination at all.
	// The .invalid suffix is reserved by RFC 2606 and resolves nowhere.
	buildValidationDestination = "apphub.invalid/validation:v0"

	// buildTaskStopTimeout bounds stopping and observing a build task after
	// the build context has expired. Failure leaves the slot unavailable.
	buildTaskStopTimeout = 30 * time.Second
)

// builderImagePinned is the digest-pinned image grammar, applied to a build task
// definition's builder container.
var builderImagePinned = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)

// buildTaskLayout is one validated build invocation.
type buildTaskLayout struct {
	// context is the caller's build context directory, on the worker.
	context string
	// dockerfileRel is the recipe's path relative to context, which is how the
	// builder names it once the context is somewhere else.
	dockerfileRel string
	// tar and digest are where the caller expects the outputs, on the worker.
	tar    string
	digest string
	// output is the private provider directory holding both.
	output string
	// passthrough are the arguments forwarded verbatim: the destinations, the
	// build arguments, and the three flags that make this a build and not a
	// publish.
	passthrough []string
}

// layout validates one [BuildCommand] and returns what running it needs.
//
// Everything here happens before any substrate call, so a command that escapes
// its context costs nothing and leaves nothing behind.
func (r *BuildTaskRunner) layout(cmd BuildCommand) (buildTaskLayout, error) {
	var result buildTaskLayout
	if cmd.Executable != r.cfg.Build.ExecutorPath {
		return result, errors.New("aws: a build must invoke the configured builder")
	}
	if !cleanAbsolutePath(cmd.Dir) || !insidePath(r.contextRoot, cmd.Dir) {
		return result, errors.New("aws: a build context must be inside the configured context root")
	}
	flags := make(map[string]string)
	var passthrough []string
	for _, arg := range cmd.Args {
		key, value, hasValue := strings.Cut(arg, "=")
		switch key {
		case "--destination", "--build-arg":
			if !hasValue || value == "" || strings.ContainsRune(value, 0) {
				return result, errors.New("aws: invalid build argument")
			}
			passthrough = append(passthrough, arg)
			continue
		case "--context", "--dockerfile", "--tar-path", "--digest-file":
			if !hasValue || value == "" {
				return result, errors.New("aws: invalid build path argument")
			}
		case "--cache":
			if value != "false" {
				return result, errors.New("aws: a hosted build has no credential for a layer cache")
			}
			passthrough = append(passthrough, arg)
		case "--no-push", "--no-push-cache":
			if hasValue {
				return result, errors.New("aws: a build must not push")
			}
			value = "true"
			passthrough = append(passthrough, arg)
		default:
			return result, errors.New("aws: unsupported build argument")
		}
		if _, duplicate := flags[key]; duplicate {
			return result, errors.New("aws: duplicate build argument")
		}
		flags[key] = value
	}
	result = buildTaskLayout{
		context:     flags["--context"],
		tar:         flags["--tar-path"],
		digest:      flags["--digest-file"],
		passthrough: passthrough,
	}
	result.output = filepath.Dir(result.tar)
	if result.context != cmd.Dir || flags["--no-push"] != "true" || flags["--no-push-cache"] != "true" || flags["--cache"] != "false" {
		return result, errors.New("aws: a build must use a local context without publishing or cache")
	}
	for _, path := range []string{result.context, result.output, result.tar, result.digest} {
		if !cleanAbsolutePath(path) || strings.ContainsAny(path, ",:\r\n") {
			return result, errors.New("aws: invalid build path")
		}
	}
	// The outputs belong to a private directory this provider created for this
	// build, and nowhere else. Anything looser is a build writing into a
	// directory somebody else owns.
	if filepath.Base(result.tar) != buildArtefactName || filepath.Base(result.digest) != "digest" ||
		filepath.Dir(result.digest) != result.output ||
		insidePath(result.context, result.output) || insidePath(result.output, result.context) ||
		!strings.HasPrefix(filepath.Base(result.output), "apphub-build-") ||
		filepath.Dir(result.output) != os.TempDir() {
		return result, errors.New("aws: build outputs must use a separate private provider directory")
	}
	if err := realPath(result.context, true); err != nil {
		return result, errors.New("aws: invalid source context directory")
	}
	if err := realPath(result.output, true); err != nil {
		return result, errors.New("aws: invalid build output directory")
	}
	st, err := os.Stat(result.output)
	if err != nil || st.Mode().Perm() != 0o700 {
		return result, errors.New("aws: the build output directory must be private")
	}
	for _, path := range []string{result.tar, result.digest} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return result, errors.New("aws: build output already exists")
		}
	}
	dockerfile := flags["--dockerfile"]
	if !filepath.IsAbs(dockerfile) {
		dockerfile = filepath.Join(result.context, dockerfile)
	}
	if !insidePath(result.context, dockerfile) {
		return result, errors.New("aws: the dockerfile escapes the source context")
	}
	if err := realPath(dockerfile, false); err != nil {
		return result, errors.New("aws: the dockerfile must be a regular non-symlink file")
	}
	rel, err := filepath.Rel(result.context, dockerfile)
	if err != nil {
		return result, errors.New("aws: the dockerfile escapes the source context")
	}
	result.dockerfileRel = rel
	if err := walkBuildContext(result.context); err != nil {
		return result, err
	}
	return result, nil
}

// walkBuildContext enforces what a context may contain and how large it may be.
//
// The permission checks are not tidiness. The builder runs in its own task,
// through an access point forcing the worker's EFS identity; unreadable
// input would fail partway through a build.
func walkBuildContext(root string) error {
	var size int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		st, err := entry.Info()
		if err != nil {
			return err
		}
		if st.IsDir() {
			if st.Mode().Perm()&0o005 != 0o005 {
				return errors.New("source directory is unreadable to the builder")
			}
			return nil
		}
		if st.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || !insidePath(root, resolved) {
				return errors.New("source symlink escapes the context")
			}
			return nil
		}
		if !st.Mode().IsRegular() || hasMultipleLinks(st) {
			return errors.New("source contains special files or hard links")
		}
		if st.Mode().Perm()&0o004 == 0 {
			return errors.New("source file is unreadable to the builder")
		}
		size += st.Size()
		if size > buildTaskContextBytes {
			return errors.New("source exceeds the build context limit")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("aws: the source context violates this provider's build bounds (at most %d bytes)",
			buildTaskContextBytes)
	}
	return nil
}

// --- slots ---------------------------------------------------------------------

// slotPaths are one slot's directories on the worker's side of the share.
type slotPaths struct {
	root    string
	context string
	output  string
}

func (r *BuildTaskRunner) slotPaths(slot int) slotPaths {
	root := filepath.Join(r.cfg.Build.Task.SharePath, fmt.Sprintf("%d", slot))
	return slotPaths{
		root:    root,
		context: filepath.Join(root, "context"),
		output:  filepath.Join(root, buildSlotOutputDir),
	}
}

// prepareSlot empties a mounted slot and recreates its two directories.
//
// Emptying first rather than trusting the previous build's cleanup: a slot is
// reused, and a leftover file is an input to whatever runs next. The root is
// a per-slot EFS mountpoint and must never be removed or fabricated locally.
func (r *BuildTaskRunner) prepareSlot(slot int) (slotPaths, error) {
	dir := r.slotPaths(slot)
	if err := r.clearSlot(slot); err != nil {
		return dir, err
	}
	for _, path := range []string{dir.context, dir.output} {
		// The access points force both builder and worker to the same POSIX
		// owner. The task may revoke traversal with chmod 000, but cannot
		// create an inaccessible directory owned by a different user.
		//
		//nolint:gosec // G301: the task's separate EFS filesystem confines it to this slot.
		if err := os.Mkdir(path, 0o755); err != nil {
			return dir, err
		}
	}
	return dir, nil
}

// clearSlot restores traversal on directories the task's POSIX owner made
// inaccessible, then removes only the mountpoint's children. Root confines
// every nested chmod beneath the opened slot, never following a symlink out.
func (r *BuildTaskRunner) clearSlot(slot int) error {
	dir := r.slotPaths(slot)
	info, err := os.Lstat(dir.root)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("aws: a build slot mount is missing")
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("aws: a build slot is not a directory")
	}
	//nolint:gosec // G302: a directory needs execute permission for its owner to traverse and clear it.
	if err := os.Chmod(dir.root, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir.root)
	if err != nil {
		return err
	}
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && name != "." {
			return root.Chmod(name, 0o700)
		}
		return nil
	})
	closeErr := root.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	entries, err := os.ReadDir(dir.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir.root, entry.Name())); err != nil {
			return err
		}
	}
	entries, err = os.ReadDir(dir.root)
	if err != nil || len(entries) != 0 {
		return errors.New("aws: a build slot could not be emptied")
	}
	return nil
}

// copyContext moves a validated context onto the share.
//
// A tree copy rather than a tarball, deliberately. A tar would be one sequential
// write instead of many small ones, which on a network filesystem is the faster
// shape -- but it makes the builder's context argument depend on the builder's
// tar handling, and a directory is the one context form every builder has always
// accepted. If the copy ever shows up in build latency, packing is the change to
// make, and the argument list is the only thing that moves.
//
// Both ends are root-scoped handles rather than composed paths. The tree was
// validated by [walkBuildContext] a moment earlier, and a check followed by a
// path-based walk is exactly the window a symlink swapped in between the two
// would escape through; a [os.Root] resolves every name beneath its own
// directory or fails.
func (r *BuildTaskRunner) copyContext(from, to string) error {
	if err := copyTree(from, to); err != nil {
		return errors.New("aws: the build context could not be placed on the build share")
	}
	return nil
}

func copyTree(from, to string) error {
	source, err := os.OpenRoot(from)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	destination, err := os.OpenRoot(to)
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()

	return fs.WalkDir(source.FS(), ".", func(name string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		info, err := source.Lstat(name)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			// This slot has its own EFS filesystem. The worker and task
			// access points force the same POSIX identity so either can
			// traverse and restore its ownership bits for cleanup.
			return destination.Mkdir(name, 0o755)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := source.Readlink(name)
			if err != nil {
				return err
			}
			return destination.Symlink(link, name)
		default:
			mode := os.FileMode(0o644)
			if info.Mode().Perm()&0o100 != 0 {
				mode = 0o755
			}
			return copyRegular(source, destination, name, mode)
		}
	})
}

func copyRegular(source, destination *os.Root, name string, mode os.FileMode) error {
	src, err := source.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := destination.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

// openSlotOutput pins the task's output directory beneath its leased slot.
// Lstat rejects a symlink at out; comparing the opened directory with that
// entry also rejects a replacement between the check and OpenRoot. Once open,
// renaming out cannot redirect subsequent reads to another directory.
func openSlotOutput(slot *os.Root) (*os.Root, error) {
	info, err := slot.Lstat(buildSlotOutputDir)
	if err != nil || !info.IsDir() {
		return nil, errors.New("aws: the build output directory is not a directory")
	}
	output, err := slot.OpenRoot(buildSlotOutputDir)
	if err != nil {
		return nil, errors.New("aws: the build output directory could not be opened")
	}
	opened, err := output.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = output.Close()
		return nil, errors.New("aws: the build output directory changed while opening")
	}
	return output, nil
}

// copyBounded moves one build output from the pinned output directory back
// into the private provider directory. OpenFile refuses leaf symlinks, and the
// opened file is checked before copying so a replaced file cannot bypass the
// regular-file and size checks. The destination is created exclusively through
// a root handle pinned to its private directory.
func copyBounded(source *os.Root, name, to string, maxBytes int64) error {
	// Only leaf names are accepted: no task-controlled intermediate directory
	// (including a nested symlink) is ever traversed during read-back.
	if name != filepath.Base(name) || name == "." || name == ".." {
		return errors.New("aws: an invalid build output name")
	}
	dir, base := filepath.Dir(to), filepath.Base(to)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("aws: the build output directory is unavailable")
	}
	defer func() { _ = root.Close() }()

	src, err := source.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("aws: the builder wrote no readable regular output")
	}
	defer func() { _ = src.Close() }()
	info, err := src.Stat()
	switch {
	case err != nil || !info.Mode().IsRegular():
		return errors.New("aws: a build output is not a regular file")
	case info.Size() <= 0 || info.Size() > maxBytes:
		return fmt.Errorf("aws: a build output is empty or exceeds this provider's limit of %d bytes", maxBytes)
	}

	dst, err := root.OpenFile(base, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("aws: a build output could not be created")
	}
	written, err := io.Copy(dst, io.LimitReader(src, maxBytes+1))
	if err != nil || written == 0 || written > maxBytes {
		_ = dst.Close()
		_ = root.Remove(base)
		return errors.New("aws: a build output could not be copied within its limit")
	}
	if err := dst.Close(); err != nil {
		_ = root.Remove(base)
		return errors.New("aws: a build output could not be written")
	}
	return nil
}

// --- paths ---------------------------------------------------------------------

func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" &&
		!strings.ContainsRune(path, 0)
}

func insidePath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func realPath(path string, directory bool) error {
	if !cleanAbsolutePath(path) {
		return errors.New("invalid path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("path contains symlinks")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory && !st.IsDir() || !directory && (!st.Mode().IsRegular() || hasMultipleLinks(st)) {
		return errors.New("invalid path type")
	}
	return nil
}
