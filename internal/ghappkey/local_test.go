// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghappkey_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/ghappkey"
)

func TestLocalStoreRejectsMissingPath(t *testing.T) {
	if _, err := ghappkey.NewLocalStore(ghappkey.LocalConfig{}); !errors.Is(err, ghappkey.ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
	if _, err := ghappkey.NewLocalReader(ghappkey.LocalConfig{}); !errors.Is(err, ghappkey.ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestLocalStoreRejectsBlankKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	store, err := ghappkey.NewLocalStore(ghappkey.LocalConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), credentials.NewSecret("  ")); !errors.Is(err, ghappkey.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestLocalStoreAndReaderRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	store, err := ghappkey.NewLocalStore(ghappkey.LocalConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := ghappkey.NewLocalReader(ghappkey.LocalConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if exists, err := store.Exists(ctx); err != nil || exists {
		t.Fatalf("Exists before Put = (%v, %v), want (false, nil)", exists, err)
	}
	if _, err := reader.Get(ctx); !errors.Is(err, ghappkey.ErrNotFound) {
		t.Fatalf("Get before Put = %v, want ErrNotFound", err)
	}

	if err := store.Put(ctx, credentials.NewSecret("-----BEGIN RSA PRIVATE KEY-----\nfirst\n-----END RSA PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	if exists, err := store.Exists(ctx); err != nil || !exists {
		t.Fatalf("Exists after Put = (%v, %v), want (true, nil)", exists, err)
	}
	got, err := reader.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Reveal(got) != "-----BEGIN RSA PRIVATE KEY-----\nfirst\n-----END RSA PRIVATE KEY-----\n" {
		t.Fatalf("Get returned an unexpected key")
	}

	// A second Put overwrites, exactly like the SSM-backed Store.
	if err := store.Put(ctx, credentials.NewSecret("second")); err != nil {
		t.Fatal(err)
	}
	got, err = reader.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Reveal(got) != "second" {
		t.Fatalf("overwrite did not apply: got %q", credentials.Reveal(got))
	}

	if err := store.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if exists, err := store.Exists(ctx); err != nil || exists {
		t.Fatalf("Exists after Delete = (%v, %v), want (false, nil)", exists, err)
	}
	if _, err := reader.Get(ctx); !errors.Is(err, ghappkey.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Deleting an absent key is not an error, matching the SSM-backed Store.
	if err := store.Delete(ctx); err != nil {
		t.Fatalf("second Delete = %v, want nil", err)
	}
}
