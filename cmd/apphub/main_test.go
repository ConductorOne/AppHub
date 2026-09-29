// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// The ConductorOne-optional guarantee, proved at the binary level.
//
// docs/design/credential-vending.md §11.2 lists three package-level mechanisms
// behind that guarantee and then says a fourth is owed: package-level evidence
// would not catch a binary that refuses to start without ConductorOne
// configuration, "which is where an adopter would actually meet the problem".
// This file is that fourth mechanism.
//
// It compiles the real binary and runs it in a separate process with an empty
// environment. Not a call to run() in the test process -- that would share this
// process's environment, its already-initialised packages and its linked test-only
// dependencies, and "the binary starts" is a claim about a process. The build runs
// with GOPROXY=off so a pass is also evidence that nothing about this binary needs
// the network to be built.
//
// What it does not prove, stated rather than implied: the binary does not *vend*
// anything, because the AWS-native provider is USOSS-9 and does not exist yet, and
// because vending needs credentials this environment does not have. §11.2's
// obligation is "starts and vends through the AWS-native path"; this delivers the
// first half and the whole of the ConductorOne-optional half, and the second half
// is recorded as outstanding in the USOSS-8 report rather than quietly counted as
// done.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
)

// buildBinary compiles cmd/apphub and returns the path to it.
//
// It fails rather than skipping when the toolchain is missing. A skip in a gate is
// a bypass: this test is the only evidence for a claim the design document makes,
// and a silently skipped run would report success for a claim nothing checked.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "apphub")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	// GOPROXY=off: a pass is evidence the build needs nothing from the network.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build ./cmd/apphub: %v\n%s", err, stderr.String())
	}
	return bin
}

// runBinary runs the built binary with exactly the environment given -- nothing
// inherited -- and returns its output and exit code.
func runBinary(t *testing.T, bin string, env []string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "providers")
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running the binary: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func TestTheBinaryStartsWithNoConductorOneEnvironmentAtAll(t *testing.T) {
	bin := buildBinary(t)

	// An empty environment, which is stronger than "no APPHUB_C1_* variables":
	// there is nothing at all for a fallback to find.
	stdout, stderr, code := runBinary(t, bin, []string{})
	if code != 0 {
		t.Fatalf("the binary exited %d with no environment\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Errorf("the binary wrote to stderr on a clean start:\n%s", stderr)
	}
	if !strings.Contains(stdout, "conductorone: not configured") {
		t.Errorf("the binary did not report ConductorOne as unconfigured:\n%s", stdout)
	}
	if strings.Contains(stdout, "id=c1") {
		t.Errorf("a ConductorOne provider was registered with no configuration:\n%s", stdout)
	}

	// It has to have registered something, or "the binary starts and can vend
	// without ConductorOne" would be satisfied by a binary that registers nothing
	// and vends nothing.
	if !strings.Contains(stdout, "id=datadog") || !strings.Contains(stdout, "id=github") {
		t.Errorf("no non-ConductorOne providers were registered, so nothing could be vended:\n%s", stdout)
	}
	if !strings.Contains(stdout, "credential providers registered: 2") {
		t.Errorf("unexpected provider count:\n%s", stdout)
	}
}

func TestTheBinaryRegistersConductorOneWhenItIsConfigured(t *testing.T) {
	// The control in the other direction. Without it, the test above is
	// indistinguishable from one that passes against a binary in which ConductorOne
	// support does not exist -- which would make the whole claim vacuous.
	bin := buildBinary(t)

	stdout, stderr, code := runBinary(t, bin, []string{
		"APPHUB_C1_TENANT_URL=https://tenant.example.invalid",
		"APPHUB_C1_CLIENT_ID=apphub-client",
		"APPHUB_C1_CLIENT_SECRET_REF=/nonexistent/secret",
	})
	if code != 0 {
		t.Fatalf("the binary exited %d with a complete configuration\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "conductorone: configured") {
		t.Errorf("ConductorOne was configured and the binary did not say so:\n%s", stdout)
	}
	if !strings.Contains(stdout, "id=c1 name=ConductorOne") {
		t.Errorf("the ConductorOne provider was not registered:\n%s", stdout)
	}
	// The declared capabilities reach the report, which is how an operator can see
	// that recovery of an ambiguous vend is unsupported without reading the source.
	if !strings.Contains(stdout, "id=c1 name=ConductorOne dynamic=true static=false revoke=true status=true recover=false") {
		t.Errorf("the ConductorOne provider's capabilities were not reported as declared:\n%s", stdout)
	}
	// Startup must not dial: the secret reference above names a file that does not
	// exist, and a binary that resolved it eagerly would have failed.
	if strings.Contains(stderr, "could not be read") {
		t.Errorf("startup resolved the client secret; it must be resolved per token fetch:\n%s", stderr)
	}
}

func TestTheBinaryRefusesToStartHalfConfigured(t *testing.T) {
	// A deployment that believes it has ConductorOne vending and does not is worse
	// than one that fails to start, so a partial configuration is a startup
	// failure and specifically not a silent fallback to "ConductorOne is off".
	bin := buildBinary(t)

	for name, env := range map[string][]string{
		"tenant only":       {"APPHUB_C1_TENANT_URL=https://tenant.example.invalid"},
		"client id only":    {"APPHUB_C1_CLIENT_ID=apphub-client"},
		"secret ref only":   {"APPHUB_C1_CLIENT_SECRET_REF=/nonexistent/secret"},
		"no secret ref":     {"APPHUB_C1_TENANT_URL=https://tenant.example.invalid", "APPHUB_C1_CLIENT_ID=apphub-client"},
		"plain http tenant": {"APPHUB_C1_TENANT_URL=http://tenant.example.invalid", "APPHUB_C1_CLIENT_ID=c", "APPHUB_C1_CLIENT_SECRET_REF=/s"},
		"bad timeout":       {"APPHUB_C1_TENANT_URL=https://tenant.example.invalid", "APPHUB_C1_CLIENT_ID=c", "APPHUB_C1_CLIENT_SECRET_REF=/s", "APPHUB_C1_REQUEST_TIMEOUT=soon"},
	} {
		stdout, stderr, code := runBinary(t, bin, env)
		if code == 0 {
			t.Errorf("%s: the binary started anyway\nstdout:\n%s", name, stdout)
		}
		if strings.Contains(stdout, "conductorone: not configured") {
			t.Errorf("%s: a half-configured deployment was reported as unconfigured", name)
		}
		if stderr == "" {
			t.Errorf("%s: the binary failed without saying why", name)
		}
	}
}

func TestTheBinaryNeverPrintsAnEnvironmentValue(t *testing.T) {
	// The report names provider ids, provider names and capability booleans. It
	// must not name a tenant URL, a client id or a secret locator: this binary's
	// stdout is a place an operator's log shipper reads, and a locator is
	// deployment topology even when it is not material.
	bin := buildBinary(t)
	const (
		tenant   = "https://TENANTSENTINEL.example.invalid"
		clientID = "CLIENTIDSENTINEL"
		ref      = "/nonexistent/SECRETREFSENTINEL"
	)
	stdout, stderr, code := runBinary(t, bin, []string{
		"APPHUB_C1_TENANT_URL=" + tenant,
		"APPHUB_C1_CLIENT_ID=" + clientID,
		"APPHUB_C1_CLIENT_SECRET_REF=" + ref,
		"APPHUB_C1_AUDIENCE=AUDIENCESENTINEL",
	})
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, secret := range []string{"TENANTSENTINEL", clientID, "SECRETREFSENTINEL", "AUDIENCESENTINEL"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the binary printed a configured value (%s)", secret)
		}
	}
}

func TestTheBinaryFailsLoudlyWhenAMisconfigurationNamesTheValue(t *testing.T) {
	// The other half of the test above: a failure path must not print the value
	// either. A malformed tenant URL is the failure most likely to be reported by
	// quoting what was given.
	bin := buildBinary(t)
	stdout, stderr, code := runBinary(t, bin, []string{
		"APPHUB_C1_TENANT_URL=BADSCHEMESENTINEL://host.example.invalid",
		"APPHUB_C1_CLIENT_ID=CLIENTIDSENTINEL",
		"APPHUB_C1_CLIENT_SECRET_REF=/s",
	})
	if code == 0 {
		t.Fatalf("the binary accepted a non-https tenant URL\nstdout:\n%s", stdout)
	}
	for _, secret := range []string{"BADSCHEMESENTINEL", "CLIENTIDSENTINEL"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the failure printed a configured value (%s):\nstdout:\n%s\nstderr:\n%s", secret, stdout, stderr)
		}
	}
}

// -- the file-backed secret resolver ---------------------------------------

func TestFileSecretsRefusesAnythingButAnAbsoluteLocalPath(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "secret")
	if err := os.WriteFile(good, []byte("  apphub-client-secret\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	// The one accepted shape, first, so this is not a test that passes against a
	// resolver that refuses everything.
	secret, err := fileSecrets{}.Resolve(t.Context(), credentials.SecretRef{Name: good})
	if err != nil {
		t.Fatalf("Resolve refused a readable absolute path: %v", err)
	}
	if got := credentials.Reveal(secret); got != "apphub-client-secret" {
		t.Errorf("the resolved secret was not the file's trimmed contents")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	refused := map[string]credentials.SecretRef{
		"a relative path":         {Name: "secret"},
		"a bare name":             {Name: "apphub/c1"},
		"a traversal":             {Name: "../secret"},
		"nothing":                 {},
		"another store's locator": {Store: "aws-ssm", Name: good},
		"a missing file":          {Name: filepath.Join(dir, "absent")},
		"a directory":             {Name: dir},
		"an empty file":           {Name: empty},
		"file and env together":   {Name: good, EnvVar: "APPHUB_C1_CLIENT_SECRET"},
	}
	for name, ref := range refused {
		got, err := fileSecrets{}.Resolve(t.Context(), ref)
		if err == nil {
			t.Errorf("%s: Resolve accepted it", name)
		}
		if !got.IsZero() {
			t.Errorf("%s: Resolve returned material alongside a failure", name)
		}
	}
}

func TestFileSecretsErrorsNameNoPath(t *testing.T) {
	// A locator is not material, but it is deployment topology, and os.ReadFile's
	// own error contains the path it was given.
	const sentinel = "PATHSENTINEL"
	dir := t.TempDir()
	for name, ref := range map[string]credentials.SecretRef{
		"missing file": {Name: filepath.Join(dir, sentinel)},
		"relative":     {Name: sentinel},
		"other store":  {Store: sentinel, Name: filepath.Join(dir, sentinel)},
	} {
		_, err := fileSecrets{}.Resolve(t.Context(), ref)
		if err == nil {
			t.Fatalf("%s: Resolve accepted it", name)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("%s: the error rendered the locator: %v", name, err)
		}
	}
}

func TestFileSecretsReadsAnEnvironmentVariable(t *testing.T) {
	const material = "env-secret-canary"
	secret, err := fileSecrets{getenv: func(string) string { return "  " + material + "\n" }}.
		Resolve(t.Context(), credentials.SecretRef{EnvVar: "APPHUB_C1_CLIENT_SECRET"})
	if err != nil {
		t.Fatalf("Resolve refused an environment locator: %v", err)
	}
	if got := credentials.Reveal(secret); got != material {
		t.Errorf("the resolved secret was not the environment value")
	}

	_, err = fileSecrets{getenv: func(string) string { return "   \n" }}.
		Resolve(t.Context(), credentials.SecretRef{EnvVar: "APPHUB_C1_CLIENT_SECRET"})
	if err == nil {
		t.Fatal("Resolve accepted an empty environment value")
	}
}
