// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// The properties in this file are the ones the conformance suite cannot reach.
//
// That is not a complaint about the suite: its secret invariants are driven
// through a secret store and a container service, and this provider has
// neither, so every one of them passes here by scanning artefacts for a
// sentinel nobody planted. A vacuous pass is the failure mode the whole project
// has been bitten by, so the material this port actually handles — the minted
// ECR push credential — is checked here instead, and checked as a class rather
// than a case: every test below enumerates all three components of the
// credential rather than picking the one that looks most secret.

// credentialMaterial is every string the in-memory token service mints. Tests
// assert about the whole set, so a leak of the access key ID is caught by the
// same test that would catch a leak of the session token.
func credentialMaterial() []string {
	return []string{
		"apphub-test-access-key-id",
		"apphub-test-secret-access-key",
		"apphub-test-session-token",
	}
}

// contextDir writes a minimal build context and returns its path.
func contextDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["Dockerfile"]; !ok {
		files["Dockerfile"] = "FROM scratch\n"
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("preparing the build context: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// ensureRepo provisions a repository and returns its prefix.
func ensureRepo(t *testing.T, p *aws.Provider, name string) string {
	t.Helper()
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	repo, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{
		Name:      name,
		Retention: compute.RetentionPolicy{KeepLast: 20},
	})
	if err != nil {
		t.Fatalf("EnsureRepository(%q): %v", name, err)
	}
	return repo.Prefix
}

// TestPushCredentialReachesNothingObservable is the central property of this
// port.
//
// It is stated as one sentence — no component of the minted credential appears
// in anything a person or another system can read — and then checked against
// every surface this provider has: the rendered artefacts, the recorded
// command's arguments and environment, the log stream the caller supplied, the
// build result, and every file the provider wrote to disk.
//
// Enumerating the surfaces is the point. A test that checked only the rendered
// artefacts would have passed against an implementation that put the credential
// on the command line.
func TestPushCredentialReachesNothingObservable(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	cachePrefix := ensureRepo(t, p, "app-cache")

	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	var logs strings.Builder
	result, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		Cache:        &compute.BuildCache{Repository: cachePrefix},
		BuildArgs:    map[string]string{"VERSION": "1.2.3"},
		Logs:         &logs,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	surfaces := map[string]string{}
	rendered, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	surfaces["rendered artefacts"] = strings.Join(rendered, "\n")
	surfaces["the caller's log stream"] = logs.String()
	surfaces["the build result"] = fmt.Sprintf("%#v", result)

	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	runs := runner.Runs()
	if len(runs) != 1 {
		t.Fatalf("the builder ran %d times, want 1", len(runs))
	}
	surfaces["the command line"] = strings.Join(runs[0].Args, " ")
	surfaces["the build environment"] = strings.Join(runs[0].Env, " ")
	surfaces["the whole command, formatted"] = fmt.Sprintf("%#v", runs[0])

	// And the push phase, which is the one that holds the credential: its
	// arguments and its environment must be as clean as the build's, because the
	// credential travels in PushCommand.Credentials and is turned into a variable
	// only by the pusher that is about to exec.
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	pushes := pusher.Runs()
	if len(pushes) != 1 {
		t.Fatalf("the pusher ran %d times, want 1", len(pushes))
	}
	surfaces["the push command line"] = strings.Join(pushes[0].Args, " ")
	surfaces["the push environment"] = strings.Join(pushes[0].Env, " ")
	surfaces["the whole push command, formatted"] = fmt.Sprintf("%#v", pushes[0])

	for surface, text := range surfaces {
		for _, material := range credentialMaterial() {
			if strings.Contains(text, material) {
				t.Errorf("the push credential appears in %s; it must reach the pusher's process "+
					"environment and nothing else -- and since USOSS-41 the builder's process is "+
					"not one of the places it may reach", surface)
			}
		}
	}
}

// TestPushCredentialIsRedactedByEveryFormattingVerb pins the type rather than a
// call site.
//
// A call site that formats a credential is a bug somebody adds later; a type
// that cannot be formatted is a bug that does not compile into existence. The
// verbs enumerated here are the ones a developer reaches for while debugging,
// which is the situation where the leak actually happens.
func TestPushCredentialIsRedactedByEveryFormattingVerb(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	creds := pusher.Runs()[0].Credentials
	if creds.IsZero() {
		t.Fatal("the push ran with no credential at all, so this test proves nothing")
	}

	for _, verb := range []string{"%v", "%s", "%q", "%x", "%#v", "%+v"} {
		rendered := fmt.Sprintf(verb, creds)
		for _, material := range credentialMaterial() {
			if strings.Contains(rendered, material) {
				t.Errorf("formatting a PushCredentials with %s revealed material", verb)
			}
		}
	}
	// Serialisation is the other route, and the one a struct reaches by
	// accident when it is embedded in something an API handler returns.
	if _, err := json.Marshal(creds); err == nil {
		t.Error("a PushCredentials marshalled to JSON without error; credential material must " +
			"refuse to serialise rather than travel in a response body")
	}
}

// TestNoErrorFromTheBuildPathCarriesCredentialMaterial names the class the
// source system's build failure belongs to.
//
// The source appends a tail of the builder's output to the error it returns
// (build.go:566-572), and that error is persisted onto a job record. This
// provider returns no builder output in an error at all, and this test drives
// every failure the build path can produce to check that nothing else does
// either.
func TestNoErrorFromTheBuildPathCarriesCredentialMaterial(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	good := compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}

	cases := map[string]func() error{
		"no destinations": func() error {
			req := good
			req.Destinations = nil
			_, err := builder.Build(context.Background(), req)
			return err
		},
		"a destination in another registry": func() error {
			req := good
			req.Destinations = []compute.ImageRef{"somewhere-else.invalid/app:latest"}
			_, err := builder.Build(context.Background(), req)
			return err
		},
		"a Dockerfile outside the context": func() error {
			req := good
			req.Source.Dockerfile = "../Dockerfile"
			_, err := builder.Build(context.Background(), req)
			return err
		},
		"the token service refusing": func() error {
			defer sts.FailNext(aws.ErrDenied)()
			_, err := builder.Build(context.Background(), good)
			return err
		},
		"the builder failing": func() error {
			// No material planted in this one, and the reason is worth reading
			// rather than inferring from the diff. Since USOSS-41 the build
			// phase runs before any credential for the build exists, so an
			// error from it has nothing to redact and redactCredentials is not
			// applied to it. Planting a material-shaped string here would
			// therefore assert something about a redactor that is deliberately
			// not on this path.
			//
			// The hostile case moved to the pusher, below, and the stronger
			// property that replaced it -- no credential has been minted while
			// the builder runs -- is asserted in
			// TestNoCredentialExistsWhileTheDockerfileIsRunning.
			defer runner.FailNext(errors.New("boom"))()
			_, err := builder.Build(context.Background(), good)
			return err
		},
		"the pusher failing": func() error {
			// The failure carries the material in its own text, which is the
			// hostile case: a pusher that leaked would be indistinguishable
			// from one that did not unless the error is checked.
			leak := errors.New("boom: apphub-test-session-token")
			defer pusher.FailNext(leak)()
			_, err := builder.Build(context.Background(), good)
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("the call succeeded, so this case checks nothing")
			}
			for _, material := range credentialMaterial() {
				if strings.Contains(err.Error(), material) {
					t.Errorf("the error from %s carries credential material", name)
				}
			}
		})
	}
}

// TestTheBuilderConfigurationIsRemovedWhateverHappens.
//
// The source system writes /kaniko/.docker/config.json and never removes it
// (build.go:584-616). This provider writes into a directory private to the
// build and removes it unconditionally, so the removal has to hold on the paths
// nobody exercises: a failed mint, a failed build, a cancelled context.
func TestTheBuilderConfigurationIsRemovedWhateverHappens(t *testing.T) {
	// Not parallel, and it owns its own temporary root. Counting directories
	// under the shared one would be a test whose answer depends on what else is
	// running, which is the kind of check that goes green for the wrong reason.
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	req := compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}

	// The successful build first, which is what tells the test where the
	// directory was: the provider never names it to a caller, so the recorded
	// command's DOCKER_CONFIG is the only handle on it.
	if _, err := builder.Build(context.Background(), req); err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, run := range runner.Runs() {
		dir := dockerConfigDirOf(t, run.Env)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("the builder's configuration directory %s still exists after a successful "+
				"build (stat err: %v)", dir, err)
		}
	}

	if left := buildDirs(t, root); len(left) != 0 {
		t.Errorf("a successful build left %v behind", left)
	}

	// And the failure paths, each checked on its own so a leak names the path
	// it came from rather than a total.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, run := range map[string]func(){
		"the token service refusing": func() {
			defer sts.FailNext(aws.ErrDenied)()
			_, _ = builder.Build(context.Background(), req)
		},
		"the builder failing": func() {
			defer runner.FailNext(errors.New("the build failed"))()
			_, _ = builder.Build(context.Background(), req)
		},
		"a cancelled context": func() {
			_, _ = builder.Build(cancelled, req)
		},
	} {
		run()
		if left := buildDirs(t, root); len(left) != 0 {
			t.Errorf("%s left %v behind; the removal is deferred rather than on the happy path "+
				"precisely so that it survives this", name, left)
		}
	}
}

func dockerConfigDirOf(t *testing.T, env []string) string {
	t.Helper()
	for _, kv := range env {
		if dir, ok := strings.CutPrefix(kv, "DOCKER_CONFIG="); ok {
			return dir
		}
	}
	t.Fatal("the phase's environment carries no DOCKER_CONFIG, so the tool would read whatever " +
		"is at its compiled-in default path")
	return ""
}

func buildDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(root, "apphub-build-*"))
	if err != nil {
		t.Fatalf("listing builder configuration directories: %v", err)
	}
	return entries
}

// TestTheBuilderConfigurationHoldsNoCredentialAndIsOwnerOnly.
//
// Three properties in one test because they are three parts of the same claim.
// The file's contents are a mapping onto a credential helper and nothing else —
// the ticket for this port assumed otherwise, and the source is worth reading on
// the point — its permissions are tight anyway, because it is provider state in a
// directory a repository-authored build can read, and since USOSS-41 there are
// two of these files and only one of them names a helper.
//
// The asymmetry is the interesting part. The push phase's configuration maps each
// destination registry onto "ecr-login", because that is the phase with a
// credential for the helper to find. The build phase's maps nothing: a helper
// mapping there would turn a build's pull of a private base image from a clear
// authorization failure into a confusing helper failure, and would be the only
// part of the build phase that even names the registry.
func TestTheBuilderConfigurationHoldsNoCredentialAndIsOwnerOnly(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")

	// The configurations are removed when the build returns, so they are
	// inspected from inside the phases: the runner and the pusher are the only
	// things that see them alive.
	inspector := &configInspector{RecordingBuilder: aws.NewRecordingBuilder(), t: t}
	sub.Builder = inspector
	pushInspector := &pushConfigInspector{RecordingPusher: aws.NewRecordingPusher(), t: t}
	sub.Pusher = pushInspector
	p, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !inspector.saw {
		t.Fatal("the build inspector never ran, so this test checks nothing")
	}
	if !pushInspector.saw {
		t.Fatal("the push inspector never ran, so half of this test checks nothing")
	}
}

// readPhaseConfig checks the permissions and the credential-freedom every phase's
// configuration has to have, and returns its parsed contents.
func readPhaseConfig(t *testing.T, phase string, env []string) phaseConfig {
	t.Helper()
	dir := dockerConfigDirOf(t, env)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the %s phase's configuration directory is not readable: %v", phase, err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("the %s phase's configuration directory is %o, want 700", phase, perm)
	}
	path := filepath.Join(dir, "config.json")
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the %s phase's configuration is not readable: %v", phase, err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("the %s phase's configuration is %o, want 600", phase, perm)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the %s phase's configuration: %v", phase, err)
	}
	for _, material := range credentialMaterial() {
		if strings.Contains(string(body), material) {
			t.Errorf("the %s phase's configuration contains credential material", phase)
		}
	}
	var parsed phaseConfig
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("the %s phase's configuration is not JSON: %v", phase, err)
	}
	if len(parsed.Auths) != 0 {
		t.Errorf("the %s phase's configuration has an auths section; this provider maps "+
			"registries onto a credential helper and stores no credential on disk", phase)
	}
	return parsed
}

type phaseConfig struct {
	CredHelpers map[string]string `json:"credHelpers"`
	Auths       map[string]any    `json:"auths"`
}

// configInspector reads the build phase's configuration while the build is
// running.
type configInspector struct {
	*aws.RecordingBuilder
	t   *testing.T
	saw bool
}

func (c *configInspector) Run(ctx context.Context, cmd aws.BuildCommand) error {
	c.t.Helper()
	c.saw = true
	parsed := readPhaseConfig(c.t, "build", cmd.Env)
	if len(parsed.CredHelpers) != 0 {
		c.t.Errorf("the build phase's configuration maps %v onto a credential helper. It has no "+
			"credential for a helper to resolve, so the mapping can only turn a clear failure "+
			"into a confusing one — and it is the only thing that would tell a "+
			"repository-authored build where this deployment's registry is", parsed.CredHelpers)
	}
	return c.RecordingBuilder.Run(ctx, cmd)
}

// pushConfigInspector reads the push phase's configuration while the push is
// running.
type pushConfigInspector struct {
	*aws.RecordingPusher
	t   *testing.T
	saw bool
}

func (c *pushConfigInspector) Push(ctx context.Context, cmd aws.PushCommand) error {
	c.t.Helper()
	c.saw = true
	parsed := readPhaseConfig(c.t, "push", cmd.Env)
	if len(parsed.CredHelpers) == 0 {
		c.t.Error("the push phase's configuration maps no registry onto a credential helper, so " +
			"the pusher has no way to turn its AWS credential into a registry token")
	}
	for host := range parsed.CredHelpers {
		if host != aws.MemoryRegistryHost {
			c.t.Errorf("the push phase's configuration names registry %q, which is not a "+
				"registry this build pushes to", host)
		}
	}
	return c.RecordingPusher.Push(ctx, cmd)
}

// TestTheBuildEnvironmentIsAnAllowlist.
//
// The property is stated the way the source system states it (kaniko_creds.go:120-131)
// and checked the way it is not: rather than asserting that the known-dangerous
// variable is absent, the test plants a variable of its own and requires it to
// be absent too. A denylist passes the first check and fails the second, which
// is the difference the comment there is about.
func TestTheBuildEnvironmentIsAnAllowlist(t *testing.T) {
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	planted := map[string]string{
		// The ambient container-credential source, which is the vulnerability.
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/apphub",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     "http://169.254.170.2/creds",
		// An arbitrary variable a deployment might add later. A denylist would
		// carry this through, which is the whole argument for an allowlist.
		"APPHUB_DATABASE_PASSWORD": "not-a-real-password-but-it-would-be",
		"GITHUB_TOKEN":             "not-a-real-token-but-it-would-be",
	}
	for k, v := range planted {
		t.Setenv(k, v)
	}

	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	env := strings.Join(runner.Runs()[0].Env, "\n")
	for k, v := range planted {
		if strings.Contains(env, k) || strings.Contains(env, v) {
			t.Errorf("%s reached the build environment; a Dockerfile RUN instruction executes "+
				"repository-authored code in it", k)
		}
	}
}

// TestNoCredentialIsMintedForADestinationThisProviderDidNotIssue.
//
// The ordering is the property. Refusing the destination after minting would
// still refuse the build, and would still have created a credential for a
// registry the operator never configured — and the source system does write its
// registry configuration before it mints (build.go:481-535), so the ordering is
// not automatic.
func TestNoCredentialIsMintedForADestinationThisProviderDidNotIssue(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}

	refused := []compute.ImageRef{
		// Another registry entirely.
		"somewhere-else.invalid/apphub/app:latest",
		// The right registry, a repository that does not exist.
		compute.ImageRef(aws.MemoryRegistryHost + "/apphub/not-provisioned:latest"),
		// The right repository name reached through somebody else's host, which
		// is the case a host-blind lookup would accept.
		"attacker.invalid/apphub/app:latest",
		// Not registry-qualified at all.
		"apphub/app:latest",
	}
	for _, dest := range refused {
		t.Run(string(dest), func(t *testing.T) {
			_, err := builder.Build(context.Background(), compute.BuildRequest{
				Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
				Destinations: []compute.ImageRef{dest},
			})
			if err == nil {
				t.Fatalf("Build accepted destination %q", dest)
			}
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Errorf("Build refused %q with %v, want compute.ErrInvalidSpec", dest, err)
			}
		})
	}
	if got := sts.Requests(); len(got) != 0 {
		t.Errorf("%d credential(s) were minted for destinations the provider then refused; the "+
			"refusal must come first", len(got))
	}

	// And the cache repository is bounded by the same rule, which is the half a
	// fix for the destination alone would leave open.
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		Cache:        &compute.BuildCache{Repository: "somewhere-else.invalid/apphub/cache"},
	})
	if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a cache repository in another registry was accepted or refused wrongly: %v", err)
	}
	if got := sts.Requests(); len(got) != 0 {
		t.Errorf("%d credential(s) were minted for a cache repository the provider then refused",
			len(got))
	}
}

// TestTheSessionPolicyIsScopedToExactlyThisBuild.
//
// The least-privilege machinery the source system built (kaniko_creds.go:66-104)
// is preserved, so this test is written to fail if it is ever widened: it checks
// the resource list is exactly the destination repositories, that the only
// unscoped statement is the one AWS requires to be unscoped, and that the
// credential's life is the fifteen minutes the source chose.
//
// "Exactly the destinations" is narrower than it was, and the change is checked
// in both directions below: the cache repository this build names has to be
// absent, because nothing in the build touches it any more.
func TestTheSessionPolicyIsScopedToExactlyThisBuild(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	appPrefix := ensureRepo(t, p, "app")
	cachePrefix := ensureRepo(t, p, "app-cache")
	otherPrefix := ensureRepo(t, p, "unrelated")

	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source: compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{
			compute.ImageRef(appPrefix + ":latest"),
			compute.ImageRef(appPrefix + ":v1"),
		},
		Cache: &compute.BuildCache{Repository: cachePrefix},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}
	reqs := sts.Requests()
	if len(reqs) != 1 {
		t.Fatalf("the build minted %d credentials, want 1", len(reqs))
	}
	req := reqs[0]

	if req.Duration != 15*time.Minute {
		t.Errorf("the push credential was requested for %s, want 15m; a short life is what "+
			"bounds a credential that can write to the operator's registry, and since USOSS-41 "+
			"it is spent on the push rather than on the build", req.Duration)
	}

	var doc struct {
		Statement []struct {
			Effect   string          `json:"Effect"`
			Action   []string        `json:"Action"`
			Resource json.RawMessage `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(req.Policy), &doc); err != nil {
		t.Fatalf("the session policy is not JSON: %v", err)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("the session policy has %d statements, want 2", len(doc.Statement))
	}

	wildcards, scoped := 0, []string(nil)
	for _, st := range doc.Statement {
		var one string
		if err := json.Unmarshal(st.Resource, &one); err == nil {
			if one != "*" {
				t.Errorf("a statement scopes to the single resource %q, which the policy renders "+
					"as a string rather than a list", one)
			}
			wildcards++
			if len(st.Action) != 1 || st.Action[0] != "ecr:GetAuthorizationToken" {
				t.Errorf("the unscoped statement allows %v; ecr:GetAuthorizationToken is the only "+
					"action AWS requires Resource \"*\" for, and every action that can write an "+
					"image must be scoped", st.Action)
			}
			continue
		}
		var many []string
		if err := json.Unmarshal(st.Resource, &many); err != nil {
			t.Fatalf("a statement's Resource is neither a string nor a list: %s", st.Resource)
		}
		scoped = append(scoped, many...)
	}
	if wildcards != 1 {
		t.Errorf("the session policy has %d unscoped statements, want exactly 1", wildcards)
	}

	got := strings.Join(scoped, "\n")
	if !strings.Contains(got, "repository/apphub/app") {
		t.Error("the session policy does not cover repository/apphub/app, so the push it " +
			"authorises would fail and the natural fix would be a wildcard")
	}
	if strings.Contains(got, "unrelated") {
		t.Errorf("the session policy covers a repository this build does not touch (%s)", otherPrefix)
	}
	// The cache repository is named by this build and deliberately NOT in the
	// policy (USOSS-41). It used to be, and the reason it was is gone: the build
	// phase has no credential, so it neither reads nor writes a registry layer
	// cache, and a scope covering the cache repository would authorise a write
	// nothing performs. This is a narrowing rather than a widening, and it is
	// asserted rather than merely allowed so that restoring the cache has to
	// restore the scope in the same change.
	if strings.Contains(got, "app-cache") {
		t.Errorf("the session policy covers the cache repository %s. Nothing in this build "+
			"touches it: the build phase runs with no credential and the push phase pushes only "+
			"to the destinations. Adding it back needs the caching to come back with it",
			cachePrefix)
	}
	if len(scoped) != 1 {
		t.Errorf("the session policy scopes to %d repositories, want 1 (two tags of one "+
			"destination repository, and no cache): %v", len(scoped), scoped)
	}
	if strings.Contains(got, "*") {
		t.Errorf("a scoped resource contains a wildcard: %v", scoped)
	}
}

// TestABuilderCannotBeConfiguredWithoutAPushRole is the source system's
// fail-closed refusal (kaniko_creds.go:160-166), moved to construction.
//
// Moving it is a behaviour change worth checking rather than assuming: the
// source refuses at build time, so a deployment with the variable unset looks
// healthy until somebody deploys. Here it cannot start.
func TestABuilderCannotBeConfiguredWithoutAPushRole(t *testing.T) {
	t.Parallel()
	cfg := fullConfig()
	cfg.Build.PushRoleARN = ""
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Fatal("a provider was constructed with a builder and no push role; the build would " +
			"then have to fall back to apphub's own credentials, which is the vulnerability " +
			"the scoped credential exists to close")
	}
	cfg.Build.PushRoleARN = "   "
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Fatal("whitespace was accepted as a push role ARN")
	}
}

// TestTheRecipeCannotEscapeTheBuildContext.
//
// The source system's check is a prefix comparison on the cleaned join
// (build.go:462-467), which stops "../" and does not stop a symbolic link. Both
// are checked here, and the symlink case is the one that would have passed
// before.
func TestTheRecipeCannotEscapeTheBuildContext(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "Secret"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("preparing the file outside the context: %v", err)
	}
	dir := contextDir(t, map[string]string{"nested/Dockerfile": "FROM scratch\n"})
	if err := os.Symlink(filepath.Join(outside, "Secret"), filepath.Join(dir, "Escape")); err != nil {
		t.Skipf("this platform does not support symbolic links: %v", err)
	}

	for _, name := range []string{
		"../Dockerfile",
		"nested/../../Dockerfile",
		"Escape",
		"/etc/hostname",
		"nested",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := builder.Build(context.Background(), compute.BuildRequest{
				Source:       compute.BuildSource{ContextDir: dir, Dockerfile: name},
				Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
			})
			if err == nil {
				t.Fatalf("the Dockerfile path %q was accepted", name)
			}
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Errorf("%q was refused with %v, want compute.ErrInvalidSpec", name, err)
			}
		})
	}

	// And the legitimate case still works, so the confinement is not just a
	// refusal of everything.
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir, Dockerfile: "nested/Dockerfile"},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Errorf("a Dockerfile inside the context was refused: %v", err)
	}
}

// TestEveryBuildArgumentIsOneArgument.
//
// The --flag=value form is what makes argument injection structurally
// impossible, so the test is written against the structure: whatever a caller
// puts in a tag or a build argument, the number of arguments the builder
// receives does not change and no element of the slice starts a new flag.
func TestEveryBuildArgumentIsOneArgument(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}

	hostile := map[string]string{
		"VERSION":  "1.0 --destination=attacker.invalid/x:latest",
		"SNEAKY":   "--force",
		"NEWLINES": "a b\tc",
	}
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		BuildArgs:    hostile,
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	args := runner.Runs()[0].Args
	destinations := 0
	for _, arg := range args {
		if strings.HasPrefix(arg, "--destination=") {
			destinations++
			if !strings.HasPrefix(arg, "--destination="+aws.MemoryRegistryHost+"/") {
				t.Errorf("the builder was given destination %q", arg)
			}
		}
		if arg != "" && !strings.HasPrefix(arg, "--") {
			t.Errorf("argument %q is not a --flag=value element, so a value could be read as a "+
				"flag", arg)
		}
	}
	if destinations != 1 {
		t.Errorf("the builder was given %d destinations, want 1", destinations)
	}

	// A build argument whose *name* is not an identifier is refused rather than
	// passed on, because a name is the one part of the pair that has to mean
	// something to the builder.
	for _, name := range []string{"--force", "", "A B", "9lives"} {
		_, err := builder.Build(context.Background(), compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
			BuildArgs:    map[string]string{name: "x"},
		})
		if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("build argument name %q was accepted or refused wrongly: %v", name, err)
		}
	}
	// So is a value carrying a NUL or a newline, which nothing downstream can
	// represent unambiguously.
	for _, value := range []string{"a\nb", "a\x00b"} {
		_, err := builder.Build(context.Background(), compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
			BuildArgs:    map[string]string{"V": value},
		})
		if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("build argument value %q was accepted or refused wrongly: %v", value, err)
		}
	}
}

// TestAHostileTagIsRefused pins the other half of the caller-composed
// destination: the repository half is checked by lookup, and the tag is the
// part a caller writes freely.
func TestAHostileTagIsRefused(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	for _, tag := range []string{
		"latest --destination=attacker.invalid/x",
		"latest\nv2",
		"-latest",
		"",
		strings.Repeat("v", 200),
	} {
		_, err := builder.Build(context.Background(), compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":" + tag)},
		})
		if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("tag %q was accepted or refused wrongly: %v", tag, err)
		}
	}
}

// --- two ordering invariants that have no other test ---------------------------
//
// Both of these are facts about the order two correct operations happen in.
// Nothing in the code reads wrong if the order is swapped, and the compiler is
// happy either way, so an edit that swapped one would break a real property
// with nothing red. This project's most expensive lesson is exactly that shape:
// the defect sat between two things that had been verified but not edited.

// TestRedactionHappensInsideTheErrorMapping.
//
// builder.go calls substrateError(redactCredentials(err, creds)) on the push
// phase's error — the phase that has a credential to leak. The nesting is
// load-bearing in both directions:
//
//   - redactCredentials deliberately does NOT wrap the error it redacts, because
//     wrapping keeps the original reachable through errors.Unwrap and its Error
//     method would hand the material straight back. So it breaks the chain.
//   - substrateError is what puts a compute sentinel on. Applied first, its
//     sentinel is inside the thing redactCredentials discards.
//
// Swapping them therefore produces an error that is redacted and matches no
// sentinel at all — a caller branching on compute.ErrFailed silently stops
// seeing build failures. This asserts both halves of the outcome at once,
// because either half alone passes against the swap.
func TestRedactionHappensInsideTheErrorMapping(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}

	// A pusher that violates its own obligation and puts the credential in its
	// error. That is the only way to make the redaction fire at all — and it has
	// to be the pusher: an error from the build phase cannot mention this build's
	// credential, because when it is produced no credential has been minted.
	defer pusher.FailNext(errors.New("push failed: AWS_SESSION_TOKEN=apphub-test-session-token"))()
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if err == nil {
		t.Fatal("the build succeeded, so this test checks nothing")
	}

	for _, material := range credentialMaterial() {
		if strings.Contains(err.Error(), material) {
			t.Errorf("the error carries credential material; redaction did not run")
		}
	}
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("the redacted error matches no compute sentinel (%v). Redaction discards the "+
			"error it redacts rather than wrapping it, so it has to run INSIDE substrateError; "+
			"applied outside, it throws the sentinel away and every caller branching on "+
			"compute.ErrFailed stops seeing build failures", err)
	}
}

// TestTheDigestIsReadBeforeTheConfigurationDirectoryIsRemoved.
//
// The builder writes its digest to a file inside the same per-build directory
// that carries the registry configuration, and that directory is removed by a
// deferred cleanup. The digest is read in the return expression, which Go
// evaluates before running deferred functions — so it works, and it works for a
// reason a reader has to know about Go rather than about this package.
//
// Turning the deferred cleanup into an explicit call before the return, which is
// the tidier-looking edit, deletes the file before it is read and yields an
// empty digest. compute.BuildResult.Digest is documented as optional and callers
// must not require it, so nothing else would notice.
func TestTheDigestIsReadBeforeTheConfigurationDirectoryIsRemoved(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}

	result, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Digest == "" {
		t.Fatal("the build reported no digest. The registry digest is read after the push and " +
			"before the deferred cleanup removes the builder's digest file; removing that " +
			"directory first is how a build used to report the builder's digest, which ECR " +
			"never stored")
	}
	if result.Digest != aws.MemoryPushedImageDigest {
		t.Errorf("the build reported digest %q, want the registry digest %q", result.Digest, aws.MemoryPushedImageDigest)
	}
	if result.Digest == runner.Digest {
		t.Errorf("the build reported the builder's digest %q. crane re-encodes the tarball, so "+
			"that digest is not the manifest ECS can pull", runner.Digest)
	}

	// And the directory really is gone afterwards, so the test is not passing
	// because the cleanup silently stopped running.
	for _, run := range runner.Runs() {
		dir := dockerConfigDirOf(t, run.Env)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("the builder's configuration directory %s survived the build (stat err: "+
				"%v), so this test would pass even with the read and the cleanup in the wrong "+
				"order", dir, err)
		}
	}
}

// TestTheWorkloadDigestIsTheOneTheRegistryStored.
//
// Kaniko's digest file and the manifest crane uploads are not the same digest.
// A task pinned to the file fails with CannotPullContainerError while the
// tagged image is in the repository. The build result has to be the digest
// the registry reports for the tag that was pushed.
func TestTheWorkloadDigestIsTheOneTheRegistryStored(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "pinned")
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	stored := "sha256:" + strings.Repeat("ee", 32)
	if err := mem.PutImage("apphub/pinned", "latest", stored); err != nil {
		t.Fatalf("PutImage: %v", err)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	result, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Digest != stored {
		t.Errorf("digest = %q, want the registry digest %q", result.Digest, stored)
	}
	if result.Digest == runner.Digest {
		t.Errorf("digest fell back to the builder's %q", runner.Digest)
	}
}

// TestAPushTheRegistryDoesNotShowFailsTheBuild.
//
// Falling back to the builder's digest is how a task gets pinned to a manifest
// that was never uploaded. A push the registry cannot find is a failed build.
func TestAPushTheRegistryDoesNotShowFailsTheBuild(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "missing")
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	// Seeding a different tag switches the repository to "only seeded tags
	// exist", so the tag this build pushes is absent.
	if err := mem.PutImage("apphub/missing", "other", "sha256:"+strings.Repeat("ee", 32)); err != nil {
		t.Fatalf("PutImage: %v", err)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if !errors.Is(err, compute.ErrFailed) {
		t.Fatalf("Build error = %v, want compute.ErrFailed", err)
	}
}

// TestTheRecipeCannotEscapeThroughASymlinkedDirectory.
//
// The confinement test above covers a Dockerfile that *is* a symlink. This is
// the natural next attack and a different code path: the Dockerfile is an
// ordinary file inside a directory that is a symlink out of the context. A
// check that resolved only the final component would accept it.
//
// The second half matters as much: a context directory that is itself a symlink
// has to keep working. Symlinked checkout roots are ordinary, and a confinement
// that refused them would be a confinement people route around.
func TestTheRecipeCannotEscapeThroughASymlinkedDirectory(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("preparing the directory outside the context: %v", err)
	}
	dir := contextDir(t, map[string]string{})
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("this platform does not support symbolic links: %v", err)
	}

	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir, Dockerfile: "escape/Dockerfile"},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if err == nil {
		t.Error("a Dockerfile reached through a symlinked directory was accepted; the platform " +
			"would build a file from outside the repository it was asked to build")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}

	// A context directory that is itself a symlink is legitimate and must work.
	link := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("this platform does not support symbolic links: %v", err)
	}
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: link},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Errorf("a context directory that is itself a symlink was refused: %v", err)
	}
}

// TestNothingInheritedCanShadowWhatTheBuildEnvironmentSets.
//
// Two variables in the build environment are set by this provider for a reason:
// DOCKER_CONFIG points the builder at the per-build registry configuration, and
// the three AWS credential variables carry the scoped push credential.
//
// Both are appended to a list, and a duplicate in an exec environment is
// resolved by *position* — later wins on Linux, which is an implementation
// detail rather than a guarantee. So the property worth asserting is that there
// is no duplicate to resolve: nothing inherited reaches the child under either
// name.
//
// DOCKER_CONFIG is the sharper case, because it is on the allowlist's shape —
// a plausible thing to inherit — and pointing the builder at an attacker's
// registry configuration would redirect where it authenticates.
func TestNothingInheritedCanShadowWhatTheBuildEnvironmentSets(t *testing.T) {
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	t.Setenv("DOCKER_CONFIG", "/somewhere/an/attacker/controls")
	t.Setenv("AWS_ACCESS_KEY_ID", "inherited-and-wrong")
	t.Setenv("AWS_SESSION_TOKEN", "inherited-and-wrong")

	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}

	counts := map[string]int{}
	for _, kv := range runner.Runs()[0].Env {
		name, value, _ := strings.Cut(kv, "=")
		counts[name]++
		if strings.Contains(value, "attacker") || strings.Contains(value, "inherited-and-wrong") {
			t.Errorf("%s reached the build environment with an inherited value", name)
		}
	}
	for _, name := range []string{"DOCKER_CONFIG", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"} {
		if counts[name] > 1 {
			t.Errorf("%s appears %d times in the build environment, so which one the child sees "+
				"depends on how the platform resolves duplicates", name, counts[name])
		}
	}
	// DOCKER_CONFIG is set by the provider and must point at the directory it
	// wrote, not at whatever was inherited.
	dir := dockerConfigDirOf(t, runner.Runs()[0].Env)
	if strings.Contains(dir, "attacker") {
		t.Errorf("the builder was pointed at %q", dir)
	}
}
