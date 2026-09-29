// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/credentials"
)

// USOSS-41: the process that runs the Dockerfile has no push credential.
//
// # What was shipped before this, and why it was not enough
//
// PR #18 closed a demonstrated leak — a session token arriving in
// [compute.BuildRequest.Logs] — by redacting where the provider consumes runner
// output. That is the right mitigation and it stays; see redact.go for the
// boundary of what a redactor can promise.
//
// What it could not do is stop the credential being *reachable*. kaniko unpacks
// the image into the container it runs in and shares a PID namespace with the
// commands it runs, so a Dockerfile RUN instruction executes attacker-authored
// code in a process whose environment held live registry credentials. Redaction
// filters the exfiltration channels this provider knows about; it does not
// enumerate them.
//
// So the credential is not there any more, and this file is where that is
// measured rather than asserted. Four separate claims, because a single "no
// credential in the build" test would pass for whichever reason happened to hold:
//
//   - the *type* cannot carry material (TestABuildCommandCannotCarryCredentialMaterial)
//   - the *environment* handed to the build carries none (TestTheBuildPhaseHasNoCredentialInItsEnvironment)
//   - no credential *exists* while the Dockerfile runs (TestNoCredentialExistsWhileTheDockerfileIsRunning)
//   - the push happens anyway, from somewhere else, with the credential
//     (TestTheArtefactIsPushedByTheOtherPhase)

// TestABuildCommandCannotCarryCredentialMaterial is the construction, checked.
//
// A test that scanned a build's environment for material would pass against an
// implementation that put the credential in a field beside it. This walks the
// type: no field of [aws.BuildCommand], however deeply nested, is or contains a
// [credentials.Secret].
//
// The second half is the anti-vacuity half and it is not decoration. A walk with
// a bug — a case that returns false for a struct, a visited set that swallows the
// answer — reports "no material" for everything, and this file's headline claim
// would then rest on a function that cannot say yes. [aws.PushCommand] does carry
// material, so the same walk has to find it there.
func TestABuildCommandCannotCarryCredentialMaterial(t *testing.T) {
	t.Parallel()

	if carries(reflect.TypeOf(aws.BuildCommand{}), map[reflect.Type]bool{}) {
		t.Error("aws.BuildCommand reaches a credentials.Secret. The whole of USOSS-41 is that " +
			"the phase executing repository-authored code cannot be handed one: a field that " +
			"can carry material is a field a later change puts material in, and the runner " +
			"holding it is the process a Dockerfile RUN instruction runs inside")
	}
	if !carries(reflect.TypeOf(aws.PushCommand{}), map[reflect.Type]bool{}) {
		t.Error("aws.PushCommand does not reach a credentials.Secret, so the walk above found " +
			"nothing because it cannot find anything. Either the push phase stopped carrying " +
			"the credential -- in which case nothing pushes -- or this derivation is broken")
	}
}

// carries reports whether t is, or contains, a [credentials.Secret].
//
// Every kind is decided explicitly and the default is "no", which is safe here
// only because the scalar kinds genuinely cannot contain a struct. An interface
// is opaque to a structural walk, so it is reported as carrying nothing and the
// test above is what keeps that from becoming a silent hole: both command types
// are concrete structs of concrete fields.
func carries(t reflect.Type, visited map[reflect.Type]bool) bool {
	if t == nil || visited[t] {
		return false
	}
	visited[t] = true
	if t == reflect.TypeOf(credentials.Secret{}) {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := range t.NumField() {
			if carries(t.Field(i).Type, visited) {
				return true
			}
		}
		return false
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
		return carries(t.Elem(), visited)
	case reflect.Map:
		return carries(t.Key(), visited) || carries(t.Elem(), visited)
	default:
		return false
	}
}

// TestTheBuildPhaseHasNoCredentialInItsEnvironment inspects what the provider
// passes, which is what this ticket's acceptance criteria ask for.
//
// Two readings of the same environment, because they fail differently. The
// recorded [aws.BuildCommand.Env] is what the provider composed; the log line is
// what a hostile RUN instruction would print out of it, through the writer the
// caller persists. An implementation that composed a clean environment and then
// added to it before exec passes the first and fails the second.
func TestTheBuildPhaseHasNoCredentialInItsEnvironment(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")

	runner := aws.NewRecordingBuilder()
	runner.LeakEnvironment = true
	sub.Builder = runner
	p = newProviderOver(t, sub, nil)

	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	var logs strings.Builder
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		Logs:         &logs,
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	runs := runner.Runs()
	if len(runs) != 1 {
		t.Fatalf("the builder ran %d times, want 1", len(runs))
	}
	env := strings.Join(runs[0].Env, "\n")
	for _, material := range credentialMaterial() {
		if strings.Contains(env, material) {
			t.Error("the build phase's environment carries credential material. A Dockerfile " +
				"RUN instruction executes repository-authored code in it, and kaniko shares a " +
				"PID namespace with what it runs")
		}
	}
	// Nothing AWS-credential-shaped at all, not merely none of this fixture's
	// three strings: a variable name is enough to find, and the point of the
	// split is that there is no credential here of any kind.
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if strings.Contains(env, name) {
			t.Errorf("the build phase's environment names %s", name)
		}
	}

	// The leak really ran, or the scan above read a log that never held the
	// environment.
	if !strings.Contains(logs.String(), "recording builder: env ") {
		t.Fatalf("the builder printed no environment, so scanning its output proves nothing: %q",
			logs.String())
	}
	for _, material := range credentialMaterial() {
		if strings.Contains(logs.String(), material) {
			t.Error("credential material reached the caller's log through the build phase's " +
				"printed environment")
		}
	}

	// And the material exists: a build whose push held no credential would pass
	// every assertion above by pushing nothing.
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	pushes := pusher.Runs()
	if len(pushes) != 1 {
		t.Fatalf("the pusher ran %d times, want 1", len(pushes))
	}
	if pushes[0].Credentials.IsZero() {
		t.Error("the push ran with no credential, so the build environment being clean says " +
			"nothing: there was no material anywhere to find")
	}
}

// TestNoCredentialExistsWhileTheDockerfileIsRunning is the ordering claim.
//
// The environment being clean is one property; a credential existing in this
// process, in another build's push, or in an expiring fifteen-minute window while
// attacker-authored code runs is another. Minting after the builder returns means
// that during the whole of the repository-authored part of a build there is
// nothing minted to steal.
//
// It is asserted from inside the build phase, which is the only place that can
// see the ordering: from outside, "minted before" and "minted after" produce
// identical results.
func TestNoCredentialExistsWhileTheDockerfileIsRunning(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}

	watcher := &mintWatcher{RecordingBuilder: aws.NewRecordingBuilder(), t: t, sts: sts}
	sub.Builder = watcher
	p = newProviderOver(t, sub, nil)

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
	if !watcher.saw {
		t.Fatal("the watcher never ran, so this test checks nothing")
	}
	// And one was minted eventually, or the ordering held for the wrong reason.
	if got := len(sts.Requests()); got != 1 {
		t.Errorf("the build minted %d credentials, want 1; zero would satisfy the assertion "+
			"inside the build phase without anything having been pushed", got)
	}
}

// mintWatcher asserts, from inside the build phase, that nothing has been minted.
type mintWatcher struct {
	*aws.RecordingBuilder
	t   *testing.T
	sts *aws.MemorySTS
	saw bool
}

func (m *mintWatcher) Run(ctx context.Context, cmd aws.BuildCommand) error {
	m.t.Helper()
	m.saw = true
	if got := len(m.sts.Requests()); got != 0 {
		m.t.Errorf("%d credential(s) had already been minted when the builder started. A "+
			"credential that exists while repository-authored code runs is a credential that "+
			"can be read out of a sibling process, and it is also one whose fifteen minutes "+
			"are being spent on the build", got)
	}
	return m.RecordingBuilder.Run(ctx, cmd)
}

// TestTheArtefactIsPushedByTheOtherPhase pins the command lines of both phases.
//
// The flags are the load-bearing part: --no-push is what makes the build a build,
// and --no-push-cache is not implied by it — kaniko treats them as separate
// decisions and with --no-push alone it still writes cache layers to a registry.
// A build phase that pushed anything would need a credential, which is the thing
// removed.
func TestTheArtefactIsPushedByTheOtherPhase(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	cachePrefix := ensureRepo(t, p, "app-cache")

	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	inspector := &artefactInspector{RecordingPusher: pusher, t: t}
	sub.Pusher = inspector
	p = newProviderOver(t, sub, nil)

	runner, ok := sub.Builder.(*aws.RecordingBuilder)
	if !ok {
		t.Fatalf("the substrate's builder is a %T", sub.Builder)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	// A cache is configured on purpose: it is legal, it is resolved, and it is
	// then not used. See imageBuilder.cacheArgs.
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source: compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{
			compute.ImageRef(prefix + ":latest"),
			compute.ImageRef(prefix + ":v1"),
		},
		Cache: &compute.BuildCache{Repository: cachePrefix},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	args := runner.Runs()[0].Args
	joined := strings.Join(args, " ")
	for _, want := range []string{"--no-push", "--no-push-cache", "--tar-path="} {
		if !strings.Contains(joined, want) {
			t.Errorf("the builder was not given %s: %v", want, args)
		}
	}
	if strings.Contains(joined, "--cache=true") {
		t.Errorf("the builder was told to use a registry layer cache, which it has no credential "+
			"to reach: %v", args)
	}
	if !strings.Contains(joined, "--cache=false") {
		t.Errorf("the builder was not told whether to cache, so it applies its own default: %v", args)
	}

	artefact := ""
	for _, arg := range args {
		if path, ok := strings.CutPrefix(arg, "--tar-path="); ok {
			artefact = path
		}
	}

	// One push per destination, each naming the artefact the build wrote.
	pushes := inspector.Runs()
	if len(pushes) != 2 {
		t.Fatalf("the pusher ran %d times for 2 destinations", len(pushes))
	}
	for i, push := range pushes {
		if len(push.Args) != 3 || push.Args[0] != "push" || push.Args[1] != artefact {
			t.Errorf("push %d ran %v, want [push %s <destination>]", i+1, push.Args, artefact)
			continue
		}
		if !strings.HasPrefix(push.Args[2], prefix+":") {
			t.Errorf("push %d publishes %q, which is not a destination of this build",
				i+1, push.Args[2])
		}
		if push.Credentials.IsZero() {
			t.Errorf("push %d ran with no credential, so it could not have pushed", i+1)
		}
	}
	if !inspector.sawArtefact {
		t.Error("the artefact inspector never confirmed the file, so the sequencing is unchecked")
	}
}

// artefactInspector checks, from inside the push, that the artefact the build
// wrote is on disk and readable.
//
// It is the sequencing assertion: the build phase's directory is removed by a
// deferred cleanup, so a provider that pushed before building, or that cleaned up
// before pushing, hands the pusher a path to nothing.
type artefactInspector struct {
	*aws.RecordingPusher
	t           *testing.T
	sawArtefact bool
}

func (a *artefactInspector) Push(ctx context.Context, cmd aws.PushCommand) error {
	a.t.Helper()
	if len(cmd.Args) < 2 {
		a.t.Fatalf("the push command has %d arguments: %v", len(cmd.Args), cmd.Args)
	}
	info, err := os.Stat(cmd.Args[1])
	switch {
	case err != nil:
		a.t.Errorf("the artefact the push names is not on disk: %v", err)
	case info.Size() == 0:
		a.t.Error("the artefact the push names is empty")
	default:
		a.sawArtefact = true
	}
	return a.RecordingPusher.Push(ctx, cmd)
}

// TestABuildThatProducedNothingMintsNoCredential.
//
// A builder that exits zero having written no image is a real failure mode — a
// misspelled flag on an operator-configured binary produces exactly it — and the
// two ways of getting it wrong are both worse than a refusal. Pushing a missing
// file diagnoses the problem as whatever the pusher says about a path; a
// forgiving pusher reports a successful build that published nothing, and the
// next deploy pulls an image nobody pushed.
//
// The credential is the reason it is checked here rather than left to the push:
// nothing should mint one for a build with nothing to publish.
func TestABuildThatProducedNothingMintsNoCredential(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	sts, ok := sub.STS.(*aws.MemorySTS)
	if !ok {
		t.Fatalf("the substrate's token service is a %T", sub.STS)
	}
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	sub.Builder = emptyHandedRunner{inner: aws.NewRecordingBuilder()}
	p = newProviderOver(t, sub, nil)

	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if err == nil {
		t.Fatal("a build that produced no image reported success")
	}
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("the refusal is %v, which does not match compute.ErrFailed", err)
	}
	if got := len(sts.Requests()); got != 0 {
		t.Errorf("%d credential(s) were minted for a build with nothing to push", got)
	}
	if got := len(pusher.Runs()); got != 0 {
		t.Errorf("the pusher ran %d times for a build that produced no artefact", got)
	}
}

// emptyHandedRunner succeeds and writes no artefact, by dropping the flag that
// tells it where to write one.
type emptyHandedRunner struct{ inner aws.BuildRunner }

func (e emptyHandedRunner) Run(ctx context.Context, cmd aws.BuildCommand) error {
	kept := make([]string, 0, len(cmd.Args))
	for _, arg := range cmd.Args {
		if !strings.HasPrefix(arg, "--tar-path=") {
			kept = append(kept, arg)
		}
	}
	cmd.Args = kept
	return e.inner.Run(ctx, cmd)
}

// TestARetryableSubstrateFailureFromThePusherIsErrTransient.
//
// The pusher is a substrate port like any other, and it is the one this ticket
// added — so it is also the one with no existing transient-classification cell.
// A push that fails because the registry throttled is retryable, and a provider
// that reports it as [compute.ErrFailed] tells its caller the spec has to change
// when the deploy would have succeeded.
//
// It doubles as the arming this package's coverage derivation requires for
// Substrate.Pusher: see TestTheInjectionObserverAndArmingCoverEveryService, which
// fails if a field can be observed for an injection and nothing stimulates one.
func TestARetryableSubstrateFailureFromThePusherIsErrTransient(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	pusher, ok := sub.Pusher.(*aws.RecordingPusher)
	if !ok {
		t.Fatalf("the substrate's pusher is a %T", sub.Pusher)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	defer pusher.FailUntilStopped(aws.ErrThrottled)()
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
	})
	if !errors.Is(err, compute.ErrTransient) {
		t.Errorf("a throttled push returned %v, want compute.ErrTransient", err)
	}
	if !p.Harness().InjectionFired() {
		t.Error("the injection did not fire, so the classification above was of something else")
	}
}
