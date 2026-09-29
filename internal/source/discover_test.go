// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules/deploy"
)

func TestDiscoverReturnsFilteredTreeAndCommit(t *testing.T) {
	local, wantCommit := fixture(t, map[string]string{
		"Dockerfile":                "FROM node:20\nEXPOSE 3000\n",
		"api/Dockerfile":            "FROM golang:1\nEXPOSE 9090\n",
		"package.json":              `{"dependencies": {"pg": "^8"}}`,
		"README.md":                 "not interesting",
		"vendor/big-unrelated-file": strings.Repeat("A", 64<<10),
	})
	c := checkout(t, local)
	commit, tree, err := c.Discover(context.Background(), deploy.Source{URL: approvedURL})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if commit != wantCommit {
		t.Fatalf("commit = %q, want %q", commit, wantCommit)
	}
	if _, ok := tree.Files["Dockerfile"]; !ok {
		t.Fatal("root Dockerfile missing from scanned tree")
	}
	if _, ok := tree.Files["api/Dockerfile"]; !ok {
		t.Fatal("nested Dockerfile missing from scanned tree")
	}
	if _, ok := tree.Files["package.json"]; !ok {
		t.Fatal("package.json missing from scanned tree")
	}
	if _, ok := tree.Files["README.md"]; ok {
		t.Fatal("uninteresting file leaked into scanned tree")
	}
	if _, ok := tree.Files["vendor/big-unrelated-file"]; ok {
		t.Fatal("large uninteresting file leaked into scanned tree")
	}
	// Discover always spends the Checkout, so its temporary directory must be
	// gone even though the scan succeeded.
	if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Discover retained its operation directory")
	}
}

func TestDiscoverIsSingleUse(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	c := checkout(t, local)
	if _, _, err := c.Discover(context.Background(), deploy.Source{URL: approvedURL}); err != nil {
		t.Fatalf("first Discover: %v", err)
	}
	if _, _, err := c.Discover(context.Background(), deploy.Source{URL: approvedURL}); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("second Discover: %v", err)
	}
	if _, err := c.Prepare(context.Background(), deploy.Source{URL: approvedURL, Dockerfile: "Dockerfile"}); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("Prepare after Discover: %v", err)
	}
}

func TestDiscoverRefusesUnapprovedRepository(t *testing.T) {
	local, _ := fixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	c := checkout(t, local)
	if _, _, err := c.Discover(context.Background(), deploy.Source{URL: "https://github.com/example/other.git"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("unapproved repository: %v", err)
	}
	if _, err := os.Stat(c.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused Discover retained its operation directory")
	}
}

func TestDiscoverWithoutDockerfileStillScans(t *testing.T) {
	local, _ := fixture(t, map[string]string{"compose.yaml": "services:\n  web:\n    build: .\n"})
	c := checkout(t, local)
	_, tree, err := c.Discover(context.Background(), deploy.Source{URL: approvedURL})
	if err != nil {
		t.Fatalf("Discover without a Dockerfile: %v", err)
	}
	if _, ok := tree.Files["compose.yaml"]; !ok {
		t.Fatal("compose file missing from scanned tree")
	}
}
