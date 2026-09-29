// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/conductorone/apphub/credentials"
)

// ExecRunner runs the build as a subprocess, which is what the source system
// does and what [compute.ImageBuilder] is shaped around.
//
// There is no shell anywhere on the path: [BuildCommand] carries an executable
// and a slice of arguments, so no amount of quoting in a caller-influenced value
// can become a second command.
type ExecRunner struct{}

var _ BuildRunner = ExecRunner{}

// Run implements [BuildRunner].
//
// # The two things this function is careful about
//
// **The environment is replaced, not extended, and nothing is added to it.**
// cmd.Env is the complete environment, already reduced to an allowlist by
// [buildEnv]. Go's exec passes the parent's environment when Cmd.Env is nil, so
// leaving it unset — the easy mistake — would hand a repository-authored build
// every variable apphub holds, including the ambient container-credential
// source. An empty allowlist is a legitimate answer and a nil slice is not, so
// the nil is replaced rather than passed on: before USOSS-41 the credential was
// appended here, and that append is what happened to make the slice non-nil,
// which is a safety property nobody chose.
//
// **The builder's output does not reach the error.** The source system appends
// a tail of kaniko's output to the failure it returns (build.go:566-572), which
// is then persisted onto a job record and shown in an interface. kaniko unpacks
// the image into the same container it runs in, so that tail is
// repository-authored content going into durable storage. This is reported as a
// finding against the source rather than reproduced here.
//
// The diagnostic is not lost, it is relocated: the full stream goes to
// [compute.BuildRequest.Logs], and the interface is explicit that bounding and
// persisting that stream is the caller's policy rather than the provider's.
func (ExecRunner) Run(ctx context.Context, cmd BuildCommand) error {
	if cmd.Executable == "" {
		return errors.New("aws: no builder executable was configured")
	}
	//nolint:gosec // The executable is operator configuration and the arguments are
	// validated and passed as separate argv elements; there is no shell.
	proc := exec.CommandContext(ctx, cmd.Executable, cmd.Args...)
	proc.Dir = cmd.Dir
	proc.Env = exactEnvironment(cmd.Env)
	proc.Stdout = cmd.Output
	proc.Stderr = cmd.Output

	if err := proc.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("aws: the image build failed with exit status %d; its output was "+
				"written to the caller's log writer", exitErr.ExitCode())
		}
		return fmt.Errorf("aws: running the image builder: %w", err)
	}
	return nil
}

// ExecPusher pushes the artefact a build produced, as a subprocess.
//
// It is the other half of USOSS-41's split and the reason [ImagePusher] exists:
// this process has the push credential in its environment and has never executed
// a line of the Dockerfile. Read [ImagePusher] for what that closes and for the
// same-user /proc residue it does not.
//
// No shell here either, and the same argument holds: [PushCommand] carries an
// executable and a slice.
type ExecPusher struct{}

var _ ImagePusher = ExecPusher{}

// Push implements [ImagePusher].
func (ExecPusher) Push(ctx context.Context, cmd PushCommand) error {
	if cmd.Executable == "" {
		return errors.New("aws: no pusher executable was configured")
	}
	//nolint:gosec // The executable is operator configuration and the arguments are
	// provider-composed and passed as separate argv elements; there is no shell.
	proc := exec.CommandContext(ctx, cmd.Executable, cmd.Args...)
	proc.Dir = cmd.Dir
	proc.Env = withCredentials(exactEnvironment(cmd.Env), cmd.Credentials)
	proc.Stdout = cmd.Output
	proc.Stderr = cmd.Output

	if err := proc.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("aws: the image push failed with exit status %d; its output was "+
				"written to the caller's log writer", exitErr.ExitCode())
		}
		return fmt.Errorf("aws: running the image pusher: %w", err)
	}
	return nil
}

// exactEnvironment is env, with a nil turned into an empty slice.
//
// os/exec reads nil as "inherit the parent's environment" and an empty non-nil
// slice as "an empty environment". Those are opposite answers to the question
// this package cares most about, and the difference is one allocation.
func exactEnvironment(env []string) []string {
	if env == nil {
		return []string{}
	}
	return env
}

// The two places in this package where credential material becomes a string are
// [withCredentials] and [redactCredentials], and they are together so a reviewer
// reads both at once. Both are on the push path, and nothing on the build path
// reaches either. [credentials.Reveal] is a package function precisely so
// that every crossing is greppable; one of these adds the material to something
// and the other removes it from something, and there are no others.

// withCredentials composes the pusher's process environment.
func withCredentials(env []string, creds PushCredentials) []string {
	if creds.IsZero() {
		return env
	}
	return append(append([]string(nil), env...),
		"AWS_ACCESS_KEY_ID="+credentials.Reveal(creds.AccessKeyID),
		"AWS_SECRET_ACCESS_KEY="+credentials.Reveal(creds.SecretAccessKey),
		"AWS_SESSION_TOKEN="+credentials.Reveal(creds.SessionToken),
	)
}

// redactCredentials removes the build's own credential from an error's text.
//
// # What this is, and what it is not
//
// It is defence in depth, and it is third in line now rather than second. What
// holds first is the construction: the credential is minted after the builder
// returns and is handed only to [ImagePusher], so no error a build phase can
// produce has ever been near it. What holds second is the obligation on
// [ImagePusher]: a pusher must not put its own output into the error it returns,
// and [ExecPusher] does not. This exists for the pusher that does anyway — a
// tool that dumps its environment on failure is common, and a failing build's
// error is persisted onto a job record and shown in an interface.
//
// Its limits are worth stating plainly, because a redaction that is trusted
// past them is worse than none. It matches the exact bytes of the material this
// build minted, so it does not catch material that has been re-encoded, split
// across lines, or derived. It cannot see material this package never held. A
// pusher that leaks in any of those ways is a pusher that leaks.
func redactCredentials(err error, creds PushCredentials) error {
	if err == nil || creds.IsZero() {
		return err
	}
	text := err.Error()
	replaced := text
	for _, material := range []string{
		credentials.Reveal(creds.AccessKeyID),
		credentials.Reveal(creds.SecretAccessKey),
		credentials.Reveal(creds.SessionToken),
	} {
		if material == "" {
			continue
		}
		replaced = strings.ReplaceAll(replaced, material, "[REDACTED]")
	}
	if replaced == text {
		return err
	}
	// The original error is deliberately not wrapped: wrapping keeps it
	// reachable through errors.Unwrap and its Error method would hand the
	// material straight back.
	return fmt.Errorf("%s (the failure mentioned this build's own credential, which has been "+
		"removed from this message; see ImagePusher for why a pusher must not put its own "+
		"output in an error)", replaced)
}
