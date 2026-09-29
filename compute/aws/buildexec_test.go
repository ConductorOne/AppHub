// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// USOSS-41's acceptance criterion, measured on real processes.
//
// Everything in buildsplit_test.go is measured against the in-memory runner and
// pusher, which is the right place for the provider's own decisions — what it puts
// in an environment, what it mints and when. It cannot answer the question the
// criterion actually asks, because the in-memory fixtures never exec: what does
// the *process* that runs the Dockerfile have in its environment?
//
// That question has been answered wrongly before by exactly this route. PR #18's
// review found a provider-side test that used a benign recorder while the provider
// really did put a session token in the log, and USOSS-39 found a conformance
// check scanning a log that could never have held the material. A fixture that
// cannot exec cannot see os/exec's own behaviour — and os/exec is where the
// mistake would live: a nil Cmd.Env inherits the parent's environment, and the
// line that used to append the credential is the line that used to make the slice
// non-nil.
//
// So this compiles a small program, hands it to the provider as both the builder
// and the pusher, and reads what each phase's process actually received. Compiling
// rather than depending on /usr/bin/env: cmd/apphub/main_test.go established the
// pattern, and it fails rather than skipping when the toolchain is missing,
// because a skip in a gate is a bypass.
//
// What it does not prove, stated rather than implied: it is not kaniko. It proves
// what this provider's real exec path hands a real subprocess; it does not prove
// that kaniko accepts these flags, which needs a real kaniko and is this ticket's
// one outstanding criterion.

// probeSource is a builder and a pusher that reports what it was given.
//
// It writes its argv and its whole environment to a file under TMPDIR rather than
// to stdout, and the reason is not incidental: the push phase's output passes
// through the provider's redacting writer, so a credential printed there arrives
// as a placeholder — which would make the anti-vacuity half of this test
// unfalsifiable. The file is outside the provider's redaction, which is what lets
// the test establish that the material really is in the push phase's environment
// and really is absent from the build's.
const probeSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var b strings.Builder
	fmt.Fprintf(&b, "argv %s\n", strings.Join(os.Args[1:], " "))
	for _, kv := range os.Environ() {
		fmt.Fprintf(&b, "env %s\n", kv)
	}
	dir := os.Getenv("TMPDIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "probe: no TMPDIR, so this process cannot report")
		os.Exit(1)
	}
	name := filepath.Join(dir, fmt.Sprintf("apphub-probe-%d.txt", os.Getpid()))
	if err := os.WriteFile(name, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
	for _, arg := range os.Args[1:] {
		if path, ok := strings.CutPrefix(arg, "--tar-path="); ok {
			if err := os.WriteFile(path, []byte("probe artefact\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "probe: %v\n", err)
				os.Exit(1)
			}
		}
		if path, ok := strings.CutPrefix(arg, "--digest-file="); ok {
			if err := os.WriteFile(path, []byte("sha256:"+strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "probe: %v\n", err)
				os.Exit(1)
			}
		}
	}
	fmt.Println("probe: ok")
}
`

// buildProbe compiles probeSource and returns the path to the binary.
func buildProbe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing the probe's %s: %v", name, err)
		}
	}
	write("main.go", probeSource)
	write("go.mod", "module apphubprobe\n\ngo 1.25.0\n")

	bin := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	// GOPROXY=off: the probe is standard library only, and a pass is evidence
	// that building it needs nothing from the network.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compiling the probe: %v\n%s", err, stderr.String())
	}
	return bin
}

// probeRun is one process the provider started, as that process saw itself.
type probeRun struct {
	argv string
	env  string
}

// readProbes collects every report written under dir.
func readProbes(t *testing.T, dir string) []probeRun {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "apphub-probe-*.txt"))
	if err != nil {
		t.Fatalf("listing the probe's reports: %v", err)
	}
	out := make([]probeRun, 0, len(names))
	for _, name := range names {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		run := probeRun{}
		for _, line := range strings.Split(string(body), "\n") {
			switch {
			case strings.HasPrefix(line, "argv "):
				run.argv = strings.TrimPrefix(line, "argv ")
			case strings.HasPrefix(line, "env "):
				run.env += strings.TrimPrefix(line, "env ") + "\n"
			}
		}
		out = append(out, run)
	}
	return out
}

// TestTheProcessThatRunsTheDockerfileHasNoCredentialInItsEnvironment.
//
// The two halves fail differently and both are needed. The build phase's process
// must hold no credential, which is the criterion. The push phase's process must
// hold one, which is what makes the first half a measurement rather than a
// property of a probe that cannot see environments.
func TestTheProcessThatRunsTheDockerfileHasNoCredentialInItsEnvironment(t *testing.T) {
	// Not parallel: TMPDIR is process-global, and it is how the probe reports.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// Planted before anything runs, because the assertion about it below is
	// otherwise satisfied by the variable not having existed yet. os/exec reads a
	// nil Cmd.Env as "inherit the parent's environment", so "the environment was
	// replaced" needs something in the parent that must not appear in the child.
	t.Setenv("APPHUB_PROBE_MUST_NOT_TRAVEL", "planted")
	probe := buildProbe(t)

	sub := aws.NewMemorySubstrate()
	// The real exec path, not the recording one. This is the whole point of the
	// file: ExecRunner and ExecPusher are where a command becomes a process.
	sub.Builder = aws.ExecRunner{}
	sub.Pusher = aws.ExecPusher{}
	cfg := fullConfig()
	cfg.Build.ExecutorPath = probe
	cfg.Build.PusherPath = probe
	p, err := aws.New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	prefix := ensureRepo(t, p, "app")
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	var logs bytes.Buffer
	if _, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		Logs:         &logs,
	}); err != nil {
		t.Fatalf("Build: %v\n%s", err, logs.String())
	}

	runs := readProbes(t, tmp)
	if len(runs) != 2 {
		t.Fatalf("the provider started %d processes, want 2 (one build, one push): %+v", len(runs), runs)
	}
	var build, push *probeRun
	for i := range runs {
		switch {
		case strings.Contains(runs[i].argv, "--context="):
			build = &runs[i]
		case strings.HasPrefix(runs[i].argv, "push "):
			push = &runs[i]
		}
	}
	if build == nil || push == nil {
		t.Fatalf("the two processes are not one build and one push: %+v", runs)
	}

	// The criterion.
	for _, material := range credentialMaterial() {
		if strings.Contains(build.env, material) {
			t.Error("the process that executes the Dockerfile has credential material in its " +
				"environment. kaniko unpacks the image into the container it runs in and shares " +
				"a PID namespace with the commands it runs, so a RUN instruction reads this")
		}
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if strings.Contains(build.env, name) {
			t.Errorf("the process that executes the Dockerfile has %s in its environment", name)
		}
	}
	// And the environment really was replaced rather than inherited.
	if strings.Contains(build.env, "APPHUB_PROBE") {
		t.Error("the build phase inherited an unallowlisted variable from this process, so its " +
			"environment was extended rather than replaced")
	}
	if strings.Contains(push.env, "APPHUB_PROBE") {
		t.Error("the push phase inherited an unallowlisted variable from this process")
	}
	if !strings.Contains(build.env, "TMPDIR=") {
		t.Fatalf("the build phase's environment has no TMPDIR, so the probe could not have "+
			"reported and this test is reading something else: %q", build.env)
	}

	// The anti-vacuity half: the push phase's process really does hold the
	// material, so a scan that found none in the build phase found none because
	// there was none.
	for _, material := range credentialMaterial() {
		if !strings.Contains(push.env, material) {
			t.Error("the push phase's process does not have the credential in its environment. " +
				"Either nothing can push, or this test cannot see an environment at all -- in " +
				"which case the assertions above hold for the wrong reason")
		}
	}

	// The build phase's own output reached the caller, unredacted and complete:
	// there is nothing to redact on that path, and a build's log is its only
	// progress signal.
	if !strings.Contains(logs.String(), "probe: ok") {
		t.Errorf("the caller's log did not receive the phases' output: %q", logs.String())
	}
}
