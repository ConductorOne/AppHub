// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package source acquires one approved repository revision per deployment.
package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/modules/deploy"
)

// Errors deliberately exclude URLs, Git output, filesystem paths and credentials.
var (
	ErrConfiguration = errors.New("source: invalid source configuration")
	ErrRefused       = errors.New("source: repository, ref or context refused")
	ErrUnavailable   = errors.New("source: acquisition unavailable")
	ErrLimit         = errors.New("source: context size limit exceeded")
	ErrCanceled      = errors.New("source: acquisition canceled or timed out")
	ErrNotPrepared   = errors.New("source: exact revision has not been prepared")
)

const maxSourceBytes int64 = 512 << 20
const maxSourceEntries = 100000
const cloneTimeout = 5 * time.Minute

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type repository struct {
	app          *githubapp.App
	installation int64
	fullName     string
}

// Checkout owns all source files until Close. Prepare is single-use, including
// failed attempts. Fetch never performs network I/O or resolves a mutable ref.
// Methods are serialized; cancellation belongs to the Prepare context.
type Checkout struct {
	mu                sync.Mutex
	repositories      map[string]repository
	root, dir, git    string
	canonical, commit string
	attempted, closed bool
	admin             *githubapp.App
	// Private seams allow real local-Git fixtures without a production file://
	// transport or an operator-configurable executable/credential environment.
	transport func(string) string
	limit     int64
}

var _ deploy.SourceFetcher = (*Checkout)(nil)

// CheckoutOption configures an optional capability on a Checkout.
type CheckoutOption func(*Checkout)

// WithAdminApp lets Prepare and Discover clone repositories covered by the
// Workspace GitHub App when they are not in the operator source.repositories
// map. app may be nil, which leaves unlisted URLs refused.
func WithAdminApp(app *githubapp.App) CheckoutOption {
	return func(c *Checkout) { c.admin = app }
}

// NewCheckout validates operator-approved repositories and creates a private
// operation directory without fetching source. The caller must close it.
// An empty operator list is valid when clones will be authorized by the
// Workspace GitHub App at Prepare/Discover time.
func NewCheckout(cfg serverconfig.SourceConfig, workDir string, opts ...CheckoutOption) (*Checkout, error) {
	if !processGroupsSupported() || workDir == "" {
		return nil, ErrConfiguration
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, ErrConfiguration
	}
	git, err = filepath.Abs(git)
	if err != nil {
		return nil, ErrConfiguration
	}
	c := &Checkout{repositories: make(map[string]repository), git: git, limit: maxSourceBytes}
	for _, r := range cfg.Repositories {
		canonical, err := canonicalURL(r.URL)
		if err != nil {
			return nil, ErrConfiguration
		}
		if _, exists := c.repositories[canonical]; exists {
			return nil, ErrConfiguration
		}
		var repo repository
		switch r.Auth {
		case "public":
			if r.GitHubApp != nil {
				return nil, ErrConfiguration
			}
		case "githubApp":
			u, _ := url.Parse(canonical)
			parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
			g := r.GitHubApp
			if u.Hostname() != "github.com" || len(parts) != 2 || g == nil || g.InstallationID <= 0 {
				return nil, ErrConfiguration
			}
			fullName := parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
			if parts[0] == "" || strings.TrimSuffix(parts[1], ".git") == "" {
				return nil, ErrConfiguration
			}
			app, err := githubapp.NewApp(githubapp.AppConfig{AppID: g.AppID, PrivateKeyPEM: g.PrivateKey})
			if err != nil {
				return nil, ErrConfiguration
			}
			repo = repository{app: app, installation: g.InstallationID, fullName: fullName}
		default:
			return nil, ErrConfiguration
		}
		c.repositories[canonical] = repo
	}
	base, err := filepath.Abs(workDir)
	if err != nil {
		return nil, ErrConfiguration
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, ErrUnavailable
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return nil, ErrUnavailable
	}
	c.root, err = os.MkdirTemp(base, "apphub-source-")
	if err != nil {
		return nil, ErrUnavailable
	}
	c.dir = filepath.Join(c.root, "context")
	for _, dir := range []string{c.dir, filepath.Join(c.root, "home"), filepath.Join(c.root, "tmp"), filepath.Join(c.root, "hooks")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			_ = os.RemoveAll(c.root)
			return nil, ErrUnavailable
		}
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func canonicalURL(raw string) (string, error) {
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 || strings.Contains(raw, "\\") {
		return "", ErrRefused
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.RawPath != "" || u.Path == "" || u.Path == "/" || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") {
		return "", ErrRefused
	}
	canonical, err := deploy.ValidateSourceURL(raw, []string{u.Hostname()})
	if err != nil {
		return "", ErrRefused
	}
	return canonical, nil
}

func githubOwnerRepo(raw string) (owner, name string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	owner, name = parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || name == "" || owner == "." || name == "." {
		return "", "", false
	}
	return owner, name, true
}

func (c *Checkout) resolve(ctx context.Context, canonical string) (repository, error) {
	if repo, ok := c.repositories[canonical]; ok {
		return repo, nil
	}
	if c.admin == nil {
		return repository{}, ErrRefused
	}
	owner, name, ok := githubOwnerRepo(canonical)
	if !ok {
		return repository{}, ErrRefused
	}
	inst, err := c.admin.GetInstallationByOwner(ctx, owner)
	if err != nil {
		if ctx.Err() != nil {
			return repository{}, ErrCanceled
		}
		return repository{}, ErrUnavailable
	}
	if inst == nil || inst.ID <= 0 || inst.SuspendedAt != nil {
		return repository{}, ErrRefused
	}
	fullName := owner + "/" + name
	if login := strings.TrimSpace(inst.Account.Login); login != "" {
		fullName = login + "/" + name
	}
	return repository{app: c.admin, installation: inst.ID, fullName: fullName}, nil
}

// Prepare acquires one approved source revision within time and size bounds,
// returning its exact commit only after credentials and Git metadata are removed.
// Any attempt consumes the checkout; failures disable it and attempt directory cleanup.
func (c *Checkout) Prepare(ctx context.Context, src deploy.Source) (commit string, resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.attempted {
		return "", ErrNotPrepared
	}
	c.attempted = true
	defer func() {
		if resultErr != nil {
			commit = ""
			c.closed = true
			if err := os.RemoveAll(c.root); err != nil {
				resultErr = errors.Join(resultErr, ErrUnavailable)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()
	canonical, err := canonicalURL(src.URL)
	if err != nil {
		return "", err
	}
	repo, err := c.resolve(ctx, canonical)
	if err != nil {
		return "", err
	}
	if err := c.validateRef(ctx, src.Ref); err != nil {
		return "", err
	}
	if !validRelativePath(src.Dockerfile) {
		return "", ErrRefused
	}
	if _, err := c.run(ctx, nil, "init", "--quiet", "--template=", c.dir); err != nil {
		return "", err
	}

	var auth *askpass
	if repo.app != nil {
		auth, err = c.authentication(ctx, repo)
		if err != nil {
			return "", err
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
			return "", errors.Join(err, cleanupErr)
		}
	}
	if err != nil {
		return "", err
	}
	out, err := c.run(ctx, nil, "-C", c.dir, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}
	commit = strings.TrimSpace(out)
	if !commitPattern.MatchString(commit) {
		return "", ErrRefused
	}
	if _, err := c.run(ctx, nil, "-C", c.dir, "checkout", "--quiet", "--detach", commit, "--"); err != nil {
		return "", err
	}
	if err := os.RemoveAll(filepath.Join(c.dir, ".git")); err != nil {
		return "", ErrUnavailable
	}
	if err := c.validateTree(src.Dockerfile); err != nil {
		return "", err
	}
	if err := c.exposeContext(); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	c.canonical, c.commit = canonical, commit
	return commit, nil
}

// Fetch returns the borrowed build directory only for the prepared URL and exact
// commit. It rechecks containment without resolving refs or accessing the network.
func (c *Checkout) Fetch(ctx context.Context, src deploy.Source) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	canonical, err := canonicalURL(src.URL)
	if err != nil {
		return "", err
	}
	if c.closed || c.commit == "" || canonical != c.canonical || src.Ref != c.commit {
		return "", ErrNotPrepared
	}
	if err := c.validateTree(src.Dockerfile); err != nil {
		return "", err
	}
	return c.dir, nil
}

// Close permanently disables this checkout and removes its owned directory.
// Removal errors are safe to expose and may be retried by calling Close again.
func (c *Checkout) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if err := os.RemoveAll(c.root); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Checkout) validateRef(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if len(ref) > 1024 || strings.HasPrefix(ref, "-") || strings.IndexFunc(ref, unicode.IsControl) >= 0 || strings.ContainsAny(ref, "~^:?*[\\ ") {
		return ErrRefused
	}
	_, err := c.run(ctx, nil, "check-ref-format", "--allow-onelevel", ref)
	if errors.Is(err, ErrUnavailable) {
		return ErrRefused
	}
	return err
}

func validRelativePath(p string) bool {
	return p != "" && p != "." && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, ".."+string(filepath.Separator)) && !strings.Contains(p, "\\") && strings.IndexFunc(p, unicode.IsControl) < 0
}

func within(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (c *Checkout) validateTree(dockerfile string) error {
	if !validRelativePath(dockerfile) {
		return ErrRefused
	}
	if err := directoryBound(c.dir, c.limit); err != nil {
		return err
	}
	err := filepath.WalkDir(c.dir, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrUnavailable
		}
		if entry.Name() == ".git" {
			return ErrRefused
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(name)
			if err != nil || filepath.IsAbs(target) {
				return ErrRefused
			}
			resolved, err := filepath.EvalSymlinks(name)
			if err != nil || !within(c.dir, resolved) {
				return ErrRefused
			}
			return nil
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return ErrRefused
		}
		return nil
	})
	if err != nil {
		return err
	}
	name := filepath.Join(c.dir, dockerfile)
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || !within(c.dir, resolved) {
		return ErrRefused
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return ErrRefused
	}
	return nil
}

// Only the validated build tree becomes readable by the runtime's remapped
// user. Its enclosing private operation directory remains 0700; the builder
// receives a bind mount of this subtree, never its parent or credential files.
func (c *Checkout) exposeContext() error {
	root, err := os.OpenRoot(c.dir)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = root.Close() }() // Read-only directory handle; no pending writes.
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrUnavailable
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		// Resolve through the held root, then chmod the opened object, not a
		// path that could be replaced by an escaping symlink during traversal.
		file, err := root.Open(name)
		if err != nil {
			return ErrUnavailable
		}
		defer func() { _ = file.Close() }() // No file content is written.
		info, err := file.Stat()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			return ErrUnavailable
		}
		mode := fs.FileMode(0755)
		if !info.IsDir() {
			mode = 0644 | (info.Mode().Perm() & 0111)
		}
		// #nosec G122 -- file was opened through os.Root and chmod operates on
		// that held descriptor, not the replaceable WalkDir path.
		if err := file.Chmod(mode); err != nil {
			return ErrUnavailable
		}
		return nil
	})
}

// Count logical sizes, including sparse files, and cap inode-heavy trees. This
// is also sampled while Git is transferring/checking out, not only afterwards.
func directoryBound(root string, limit int64) error {
	var total int64
	entries := 0
	return filepath.WalkDir(root, func(_ string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, fs.ErrNotExist) {
			return nil
		} // Git renames temporary packs.
		if walkErr != nil {
			return ErrUnavailable
		}
		entries++
		if entries > maxSourceEntries {
			return ErrLimit
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return ErrUnavailable
		}
		if info.Size() > limit-total {
			return ErrLimit
		}
		total += info.Size()
		return nil
	})
}

// gitConfigArgs is the fixed configuration for every Git command this checkout
// runs.
//
// credential.interactive is left unset on purpose. Git treats false as "do not
// call GIT_ASKPASS", and GIT_ASKPASS is the only path an installation token
// has into fetch: it lives in a pipe, not in argv, the environment, or the
// helper file. Setting the option false makes every private fetch fail at
// once with "unable to get password from user" and the token unread.
// GIT_TERMINAL_PROMPT=0 still refuses a terminal prompt, and credential.helper
// is empty so a stored helper cannot supply a different secret.
func gitConfigArgs(root string, fileProtocol bool) []string {
	args := []string{"-c", "credential.helper=", "-c", "core.hooksPath=" + filepath.Join(root, "hooks"),
		"-c", "http.followRedirects=false", "-c", "http.sslVerify=true", "-c", "http.proxy=", "-c", "http.maxRequests=1", "-c", "fetch.recurseSubmodules=false",
		"-c", "submodule.recurse=false", "-c", "filter.lfs.required=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"}
	if fileProtocol {
		args = append(args, "-c", "protocol.file.allow=always")
	}
	return args
}

func (c *Checkout) environment() []string {
	return []string{
		"PATH=" + filepath.Dir(c.git) + ":/usr/bin:/bin", "HOME=" + filepath.Join(c.root, "home"),
		"XDG_CONFIG_HOME=" + filepath.Join(c.root, "home"), "TMPDIR=" + filepath.Join(c.root, "tmp"),
		"LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0",
	}
}

// Only rev-parse's tiny stdout is needed. Untrusted output is neither retained
// unboundedly nor included in an error, including Git's credential failures.
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 4096 {
		_, _ = b.Buffer.Write(p[:min(n, 4096-b.Len())])
	}
	return n, nil
}

func (c *Checkout) run(ctx context.Context, auth *askpass, args ...string) (string, error) {
	protocol := "https"
	if c.transport != nil {
		protocol = "https:file"
	} // package-private test seam only
	base := gitConfigArgs(c.root, c.transport != nil)
	// #nosec G204 -- git is resolved from the worker PATH at construction, not
	// request input. Callers use fixed Git subcommands and separate argv with
	// option terminators; repository URLs are allowlisted and refs validated.
	cmd := exec.Command(c.git, append(base, args...)...)
	cmd.Dir = c.root
	cmd.WaitDelay = time.Second
	cmd.Env = append(c.environment(), "GIT_ALLOW_PROTOCOL="+protocol)
	if auth != nil {
		// Replace rather than duplicate GIT_ASKPASS (exec implementations differ
		// in their handling of duplicate environment keys).
		for i, value := range cmd.Env {
			if strings.HasPrefix(value, "GIT_ASKPASS=") {
				cmd.Env[i] = "GIT_ASKPASS=" + auth.helper
			}
		}
		cmd.ExtraFiles = []*os.File{auth.reader}
	}
	configureProcessGroup(cmd)
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	if err := cmd.Start(); err != nil {
		return "", ErrUnavailable
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			killProcessGroup(cmd) // No helper/transport child survives successful Git.
			if ctx.Err() != nil {
				return "", ErrCanceled
			}
			if boundErr := directoryBound(c.root, c.limit); boundErr != nil {
				return "", boundErr
			}
			if err != nil {
				return "", ErrUnavailable
			}
			return out.String(), nil
		case <-ctx.Done():
			killProcessGroup(cmd)
			<-done
			return "", ErrCanceled
		case <-ticker.C:
			if err := directoryBound(c.root, c.limit); err != nil {
				killProcessGroup(cmd)
				<-done
				return "", err
			}
		}
	}
}

// The token crosses only an anonymous inherited pipe. It is never an argv,
// environment value, Git remote, source file, or on-disk credential helper value.
type askpass struct {
	helper string
	reader *os.File
}

func (a *askpass) close() error {
	var result error
	if a.reader != nil {
		if err := a.reader.Close(); err != nil {
			result = ErrUnavailable
		}
		a.reader = nil
	}
	if err := os.Remove(a.helper); err != nil && !errors.Is(err, fs.ErrNotExist) {
		result = ErrUnavailable
	}
	return result
}

func (c *Checkout) authentication(ctx context.Context, repo repository) (*askpass, error) {
	name := strings.Split(repo.fullName, "/")[1]
	token, err := repo.app.MintInstallationToken(ctx, repo.installation, githubapp.InstallationTokenRequest{
		Repositories: []string{name}, Permissions: map[string]string{"contents": "read"},
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		return nil, ErrUnavailable
	}
	if token.RepositorySelection != "selected" || len(token.Repositories) != 1 || !strings.EqualFold(token.Repositories[0].FullName, repo.fullName) || token.Permissions["contents"] != "read" || !token.ExpiresAt.After(time.Now()) {
		return nil, ErrRefused
	}
	for permission, value := range token.Permissions {
		if permission != "contents" && (permission != "metadata" || value != "read") {
			return nil, ErrRefused
		}
	}
	secret := credentials.Reveal(token.Token)
	if secret == "" || len(secret) > 4096 || strings.IndexFunc(secret, unicode.IsControl) >= 0 {
		return nil, ErrRefused
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := io.WriteString(w, secret+"\n"); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, ErrUnavailable
	}
	if err := w.Close(); err != nil {
		_ = r.Close() // Already failing; discard the remaining credential pipe.
		return nil, ErrUnavailable
	}
	a := &askpass{helper: filepath.Join(c.root, "askpass"), reader: r}
	// Git is always launched with argv. This fixed helper interprets no input as
	// shell code; its only executable operation is the shell's builtin read.
	const helper = "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s\\n' x-access-token ;;\n  Password*) IFS= read -r token <&3 || exit 1; printf '%s\\n' \"$token\" ;;\n  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(a.helper, []byte(helper), 0600); err != nil {
		_ = a.close() // Preparation already fails; its owner removes the whole tree.
		return nil, ErrUnavailable
	}
	// #nosec G302 -- Git must execute this fixed, credential-free helper. Only
	// its owner can read/execute it in the private 0700 operation directory;
	// the token remains exclusively in the inherited pipe, not this file.
	if err := os.Chmod(a.helper, 0700); err != nil {
		_ = a.close() // Preparation already fails; its owner removes the whole tree.
		return nil, ErrUnavailable
	}
	return a, nil
}
