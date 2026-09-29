// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/modules/deploy"
)

const approvedURL = "https://github.com/example/approved.git"

func fixture(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("local Git is required")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.com", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.com"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git failed: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet", "--initial-branch=main", "--template=")
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "--", ".")
	run("commit", "--quiet", "-m", "fixture")
	run("tag", "release")
	return dir, run("rev-parse", "HEAD")
}

func checkout(t *testing.T, local string) *Checkout {
	t.Helper()
	if !processGroupsSupported() {
		t.Skip("source runner requires Linux")
	}
	c, err := NewCheckout(serverconfig.SourceConfig{Repositories: []serverconfig.RepositoryConfig{{URL: approvedURL, Auth: "public"}}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.transport = func(raw string) string {
		if raw != approvedURL {
			t.Fatal("unapproved repository reached transport")
		}
		return "file://" + local
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func TestPreparedCommitIsExactAndContextHasNoCredentials(t *testing.T) {
	local, wantCommit := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n", "payload": "source"})
	// Inherited Git configuration may contain credentials, hooks, transport
	// rewrites, and filters. None may affect acquisition or enter its context.
	malicious := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(malicious, []byte("[url \"https://evil.invalid/\"]\n insteadOf = file://\n[credential]\n helper = !exit 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", malicious)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_0", "never")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "source-credential-canary")
	for _, ref := range []string{"", "main", "release", wantCommit} {
		t.Run("ref="+ref, func(t *testing.T) {
			c := checkout(t, local)
			src := deploy.Source{URL: approvedURL, Ref: ref, Dockerfile: "Dockerfile"}
			got, err := c.Prepare(context.Background(), src)
			if err != nil || got != wantCommit {
				t.Fatalf("Prepare = %q, %v", got, err)
			}
			src.Ref = got
			dir, err := c.Fetch(context.Background(), src)
			if err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(filepath.Join(dir, "payload")); err != nil || string(data) != "source" {
				t.Fatalf("source bytes: %q, %v", data, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, ".git")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Git metadata exposed to builder")
			}
			if strings.Contains(strings.Join(c.environment(), "\n"), "source-credential-canary") {
				t.Fatal("worker credentials inherited")
			}
			src.Ref = "main"
			if _, err := c.Fetch(context.Background(), src); !errors.Is(err, ErrNotPrepared) {
				t.Fatal("mutable ref exposed as prepared source")
			}
			src.Ref, src.URL = got, "https://github.com/example/other.git"
			if _, err := c.Fetch(context.Background(), src); !errors.Is(err, ErrNotPrepared) {
				t.Fatal("cross-repository prepared source exposed")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Close retained source")
			}
		})
	}
}

func TestRefAndURLRefusalsRemoveOperationDirectory(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	for _, ref := range []string{"--upload-pack=evil", "main:refs/heads/injected", "HEAD~1", "main\nsecret", "refs/heads/../main", "@{1}", "main^{tree}"} {
		t.Run(ref, func(t *testing.T) {
			c := checkout(t, local)
			if _, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Ref: ref, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrRefused) {
				t.Fatalf("hostile ref: %v", err)
			}
			if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed preparation retained files")
			}
		})
	}
	for _, raw := range []string{approvedURL + "?token=secret", approvedURL + "?", approvedURL + "#fragment", approvedURL + "#", "https://github.com/example/%61pproved.git", "https://github.com/example/other.git", "file://" + local, "https://token@github.com/example/approved.git"} {
		c := checkout(t, local)
		if _, err := c.Prepare(context.Background(), deploy.Source{URL: raw, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrRefused) {
			t.Fatalf("hostile URL accepted: %v", err)
		}
	}
}

func TestContextBoundsAndContainment(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n", "large": strings.Repeat("A", 256<<10)})
	c := checkout(t, local)
	c.limit = 128 << 10
	if _, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversize checkout: %v", err)
	}
	if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversize checkout retained")
	}

	c = checkout(t, local)
	if err := os.WriteFile(filepath.Join(c.dir, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(outside, []byte("worker secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(c.dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := c.validateTree("Dockerfile"); !errors.Is(err, ErrRefused) {
		t.Fatal("out-of-context symlink accepted")
	}
	if err := os.Remove(filepath.Join(c.dir, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Dockerfile", filepath.Join(c.dir, "SafeDockerfile")); err != nil {
		t.Fatal(err)
	}
	if err := c.validateTree("SafeDockerfile"); err != nil {
		t.Fatalf("contained symlink refused: %v", err)
	}
	for _, name := range []string{"../canary", "/etc/passwd", "dir/../../Dockerfile", "dir\\Dockerfile"} {
		if err := c.validateTree(name); !errors.Is(err, ErrRefused) {
			t.Fatal("escaping Dockerfile accepted")
		}
	}
}

func TestSizeMonitorStopsAnActiveTransfer(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	c := checkout(t, local)
	c.limit = 32 << 10
	program := filepath.Join(t.TempDir(), "git")
	// The child does not exit after writing: only the live disk monitor can
	// produce ErrLimit before the context deadline.
	body := "#!/bin/sh\nprintf '%040000d' 0 > transfer-pack\nsleep 10\n"
	if err := os.WriteFile(program, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	c.git = program
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Prepare(ctx, deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("active transfer escaped size monitor: %v", err)
	}
	if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversize transfer retained")
	}
}

func TestCancellationKillsDescendantsAndDiscardsOutput(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	c := checkout(t, local)
	marker := filepath.Join(t.TempDir(), "child-survived")
	program := filepath.Join(t.TempDir(), "git")
	// This test-only executable models a transport child that outlives Git.
	body := "#!/bin/sh\n(sleep 0.4; printf survived > '" + marker + "') &\nprintf credential-canary >&2\nwait\n"
	if err := os.WriteFile(program, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	c.git = program
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Prepare(ctx, deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrCanceled) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("cancellation not classified: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("transport descendant survived cancellation")
	}
	if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled source files retained")
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubAppCredentialsAreScopedAndPipeOnly(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	c := checkout(t, local)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	material := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	calls := 0
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: credentials.NewSecret(string(material)), Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.github.com/app/installations/2/access_tokens" {
			t.Fatal("unexpected credential destination")
		}
		var request struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Repositories) != 1 || request.Repositories[0] != "approved" || len(request.Permissions) != 1 || request.Permissions["contents"] != "read" {
			t.Fatal("installation token request was widened")
		}
		body := `{"token":"github-source-canary","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","repository_selection":"selected","repositories":[{"name":"approved","full_name":"example/approved"}],"permissions":{"contents":"read","metadata":"read"}}`
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	repo := repository{app: app, installation: 2, fullName: "example/approved"}
	auth, err := c.authentication(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	helper := auth.helper
	data, err := os.ReadFile(helper)
	if err != nil || strings.Contains(string(data), "github-source-canary") {
		t.Fatal("helper persisted credentials")
	}
	cmd := exec.Command(helper, "Password for https://github.com:")
	cmd.Env = c.environment()
	cmd.ExtraFiles = []*os.File{auth.reader}
	out, err := cmd.Output()
	if err != nil || string(out) != "github-source-canary\n" {
		t.Fatalf("pipe credential helper failed: %v", err)
	}
	if err := auth.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(helper); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("askpass helper retained")
	}
	c.repositories[approvedURL] = repo
	commit, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := c.Fetch(context.Background(), deploy.Source{URL: approvedURL, Ref: commit, Dockerfile: "Dockerfile"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private repository metadata retained")
	}
	if _, err := os.Stat(helper); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private prepare retained helper")
	}
	if calls != 2 {
		t.Fatal("private source did not mint per-operation credentials")
	}
	repo.fullName = "wrong-owner/approved"
	if _, err := c.authentication(context.Background(), repo); !errors.Is(err, ErrRefused) {
		t.Fatal("installation belonging to another owner accepted")
	}
}

func TestNewCheckoutAllowsEmptyOperatorList(t *testing.T) {
	if !processGroupsSupported() {
		t.Skip("source runner requires Linux")
	}
	c, err := NewCheckout(serverconfig.SourceConfig{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = NewCheckout(serverconfig.SourceConfig{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("unlisted URL without admin app: %v", err)
	}
}

func TestAdminGitHubAppClonesUnlistedRepository(t *testing.T) {
	if !processGroupsSupported() {
		t.Skip("source runner requires Linux")
	}
	local, wantCommit := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	material := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: 1, PrivateKeyPEM: credentials.NewSecret(string(material)), Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Path == "/orgs/example/installation":
			body := `{"id":2,"account":{"login":"example","type":"Organization"},"repository_selection":"all"}`
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			body := `{"token":"github-source-canary","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","repository_selection":"selected","repositories":[{"name":"approved","full_name":"example/approved"}],"permissions":{"contents":"read","metadata":"read"}}`
			return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
			return nil, errors.New("unexpected request")
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCheckout(serverconfig.SourceConfig{}, t.TempDir(), WithAdminApp(app))
	if err != nil {
		t.Fatal(err)
	}
	c.transport = func(raw string) string {
		if raw != approvedURL {
			t.Fatal("unapproved repository reached transport")
		}
		return "file://" + local
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	got, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"})
	if err != nil || got != wantCommit {
		t.Fatalf("Prepare = %q, %v", got, err)
	}
}

// TestAskpassSuppliesTheFetchCredential is the production credential path.
// credential.interactive=false makes Git skip GIT_ASKPASS entirely, so a
// private fetch dies in one round trip and the installation token stays in
// the pipe. This uses the same configuration Checkout.run passes to Git.
func TestAskpassSuppliesTheFetchCredential(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("local Git is required")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "asked")
	helper := filepath.Join(dir, "askpass")
	const script = "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$MARKER\"\ncase \"$1\" in\n  Username*) printf '%s\\n' x-access-token ;;\n  Password*) printf '%s\\n' askpass-canary ;;\n  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, append(gitConfigArgs(dir, false), "credential", "fill")...)
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	cmd.Env = []string{
		"PATH=" + filepath.Dir(git) + ":/usr/bin:/bin",
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=" + helper, "SSH_ASKPASS=/bin/false",
		"MARKER=" + marker, "LANG=C", "LC_ALL=C",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git credential fill: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "username=x-access-token") || !strings.Contains(string(out), "password=askpass-canary") {
		t.Fatalf("installation token did not come from GIT_ASKPASS:\n%s", out)
	}
}
