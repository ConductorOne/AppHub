// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/credentials"
)

// The credential-egress obligation, made observable.
//
// USOSS-39 added a conformance check that scans a build's log, error and result
// for the material the provider hands the build, and USOSS-39's ruling was to
// wire this provider's harness into it rather than ship a check that reports NOT
// VERIFIED against the one provider known to have had the bug. Wiring it made the
// check run and pass.
//
// **That pass was not evidence, and this file is why.** The in-memory fixtures
// are benign: they write their own arguments to the output and nothing else, so
// the scan searched a log that could never have contained the credential.
// Bypassing the provider's redacting writer entirely — the mutation that should
// have turned the check red — changed nothing, because there was never anything
// to redact.
//
// That is the same shape PR #18's review found on the provider side, where a
// "nothing observable" test used a recorder that could not exercise the path
// while the provider really did put a session token in the log. A benign fixture
// and a correct implementation are indistinguishable.
//
// # What changed with USOSS-41, and why these tests moved rather than went away
//
// The threat these tests were written against was the builder's own environment:
// kaniko unpacks the image into the container it runs in and shares a PID
// namespace with the commands it runs, so a Dockerfile RUN could read the push
// credential and print it. That is closed by construction now — [aws.BuildCommand]
// has no credential field and the mint happens after the builder returns — and
// buildsplit_test.go is where that construction is measured.
//
// So what is left here is the phase that does hold material. The pusher's
// environment is where the credential lives, and a tool that echoes its
// environment when a registry call fails is ordinary rather than hostile. With
// RecordingPusher.LeakCredentials on, the provider's redactingWriter is doing
// observable work, and these tests are the pin on it.

// TestTheRedactorStopsALeakingPusher is the check with an input.
//
// It is red-before-green by construction: TestALeakingPusherReallyLeaks below
// establishes that the pusher emits the material, so if the redaction were
// removed this would fail. Both halves are needed — one asserts the defence
// works, the other asserts there was something to defend against.
func TestTheRedactorStopsALeakingPusher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pusher := aws.NewRecordingPusher()
	pusher.LeakCredentials = true
	pusher.FailWithCredentialsInError = true
	p, sub := newProvider(t, nil)
	sub.Pusher = pusher

	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	repo := mustEnsureRepo(t, p, "leak")

	var logs bytes.Buffer
	_, buildErr := builder.Build(ctx, compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(repo.Prefix + ":v1")},
		Logs:         &logs,
	})

	material, err := p.Harness().BuildCredentials(ctx)
	if err != nil {
		t.Fatalf("BuildCredentials(): %v", err)
	}
	if len(material) == 0 {
		t.Fatal("the harness reports no build material, so this test would scan for nothing")
	}

	// Neither of these prints the material.
	for i, secret := range material {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("material %d of %d reached the caller's Logs writer. A build's output is "+
				"persisted by its caller, and the provider cannot assume the pusher honours any "+
				"obligation, which is what the redacting writer is for", i+1, len(material))
		}
		if buildErr != nil && strings.Contains(buildErr.Error(), secret) {
			t.Errorf("material %d of %d reached the build's error. An error is logged, returned "+
				"to an API caller, and persisted onto a job record", i+1, len(material))
		}
	}
	// The log has to contain *something*, or the redactor could be a truncator.
	if logs.Len() == 0 {
		t.Error("the redacted log is empty; a writer that drops everything passes the scan above " +
			"while depriving the caller of a build's only progress signal")
	}
}

// TestALeakingPusherReallyLeaks is the other half, and without it the test above
// is satisfied by a pusher that emits nothing.
//
// It asserts the adversarial pusher puts the material where the provider has to
// deal with it, by handing it a writer the provider does not wrap.
func TestALeakingPusherReallyLeaks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pusher := aws.NewRecordingPusher()
	pusher.LeakCredentials = true
	pusher.FailWithCredentialsInError = true

	const token = "probe-session-token-7f2e"
	var raw bytes.Buffer
	err := pusher.Push(ctx, aws.PushCommand{
		Executable: "/usr/bin/crane",
		Output:     &raw,
		Credentials: aws.PushCredentials{
			AccessKeyID:     credentials.NewSecret("probe-access-key"),
			SecretAccessKey: credentials.NewSecret("probe-secret-key"),
			SessionToken:    credentials.NewSecret(token),
		},
	})

	if !strings.Contains(raw.String(), token) {
		t.Errorf("the leaking pusher wrote no session token to its output, so every assertion "+
			"about redaction is vacuous: got %q", raw.String())
	}
	if err == nil || !strings.Contains(err.Error(), token) {
		t.Errorf("the leaking pusher returned %v, with no session token in it; the error channel "+
			"is the one that gets persisted onto a job record", err)
	}
}
