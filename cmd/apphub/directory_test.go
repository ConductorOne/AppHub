// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/conductorone/apphub/internal/testutil"
)

func clearDirectoryEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APPHUB_C1_DIRECTORY_TENANT_URL", "")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_ID", "")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_SECRET_REF", "")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_SECRET", "")
	t.Setenv("APPHUB_C1_DIRECTORY_REQUEST_TIMEOUT", "")
}

func TestNewDirectorySyncerIsNilWhenUnconfigured(t *testing.T) {
	clearDirectoryEnv(t)
	syncer, err := newDirectorySyncer(testutil.NewRepository())
	if err != nil {
		t.Fatalf("newDirectorySyncer: %v", err)
	}
	if syncer != nil {
		t.Fatal("a syncer was constructed with no directory configuration")
	}
}

func TestNewDirectorySyncerRefusesPartialConfiguration(t *testing.T) {
	clearDirectoryEnv(t)
	t.Setenv("APPHUB_C1_DIRECTORY_TENANT_URL", "https://tenant.example.invalid")
	// Client ID and secret ref deliberately left unset.
	if _, err := newDirectorySyncer(testutil.NewRepository()); err == nil {
		t.Fatal("newDirectorySyncer accepted a partial directory configuration")
	}
}

func TestNewDirectorySyncerBuildsWhenFullyConfigured(t *testing.T) {
	clearDirectoryEnv(t)
	t.Setenv("APPHUB_C1_DIRECTORY_TENANT_URL", "https://tenant.example.invalid")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_ID", "directory-client")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_SECRET_REF", "/nonexistent/secret")

	syncer, err := newDirectorySyncer(testutil.NewRepository())
	if err != nil {
		t.Fatalf("newDirectorySyncer: %v", err)
	}
	if syncer == nil {
		t.Fatal("a complete directory configuration produced no syncer")
	}
	// NewClient performs no network I/O (credentials/c1directory's own
	// doc/tests cover that), so reaching here without dialing anything is the
	// property this test checks.
}

func TestNewGroupLookupIsNilWhenUnconfigured(t *testing.T) {
	clearDirectoryEnv(t)
	lookup, err := newGroupLookup(testutil.NewRepository())
	if err != nil {
		t.Fatalf("newGroupLookup: %v", err)
	}
	if lookup != nil {
		t.Fatal("a lookup was constructed with no directory configuration")
	}
}

func TestNewGroupLookupRefusesPartialConfiguration(t *testing.T) {
	clearDirectoryEnv(t)
	t.Setenv("APPHUB_C1_DIRECTORY_TENANT_URL", "https://tenant.example.invalid")
	if _, err := newGroupLookup(testutil.NewRepository()); err == nil {
		t.Fatal("newGroupLookup accepted a partial directory configuration")
	}
}

func TestNewGroupLookupBuildsWhenFullyConfigured(t *testing.T) {
	clearDirectoryEnv(t)
	t.Setenv("APPHUB_C1_DIRECTORY_TENANT_URL", "https://tenant.example.invalid")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_ID", "directory-client")
	t.Setenv("APPHUB_C1_DIRECTORY_CLIENT_SECRET_REF", "/nonexistent/secret")

	lookup, err := newGroupLookup(testutil.NewRepository())
	if err != nil {
		t.Fatalf("newGroupLookup: %v", err)
	}
	if lookup == nil {
		t.Fatal("a complete directory configuration produced no lookup")
	}
}
