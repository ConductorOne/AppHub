// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules"
)

func TestMissingMatchesErrNotConfigured(t *testing.T) {
	t.Parallel()

	err := modules.Missing("review", "findings store")

	if !errors.Is(err, modules.ErrNotConfigured) {
		t.Errorf("errors.Is(err, ErrNotConfigured) = false for %v", err)
	}

	// Recognisable through a wrap, because Execute and the boundary above it
	// will both add context on the way out.
	wrapped := fmt.Errorf("running module: %w", err)
	if !errors.Is(wrapped, modules.ErrNotConfigured) {
		t.Errorf("errors.Is(wrapped, ErrNotConfigured) = false for %v", wrapped)
	}

	var missing *modules.MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("errors.As(err, *MissingError) = false for %v", err)
	}
	if got, want := missing.Module, "review"; got != want {
		t.Errorf("Module = %q, want %q", got, want)
	}
	if got, want := missing.Dependency, "findings store"; got != want {
		t.Errorf("Dependency = %q, want %q", got, want)
	}
}

func TestMissingErrorMessageNamesBoth(t *testing.T) {
	t.Parallel()

	got := modules.Missing("deploy", "compute provider").Error()
	for _, want := range []string{"deploy", "compute provider", "not configured"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q does not mention %q", got, want)
		}
	}
}

// A validation failure must not be mistaken for a wiring failure: the boundary
// reports one as the caller's problem and the other as the operator's.
func TestValidationFailureIsNotNotConfigured(t *testing.T) {
	t.Parallel()

	err := modules.ValidateDeclaredParams(nil, map[string]any{"k": "v"})
	if err == nil {
		t.Fatal("no error; want a rejection")
	}
	if errors.Is(err, modules.ErrNotConfigured) {
		t.Errorf("a parameter rejection matched ErrNotConfigured: %v", err)
	}
}
