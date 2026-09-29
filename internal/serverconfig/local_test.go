// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package serverconfig_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/conductorone/apphub/internal/serverconfig"
)

// accountShaped matches any standalone twelve-digit run, the shape of an AWS
// account ID -- not just one specific example number.
var accountShaped = regexp.MustCompile(`\b[0-9]{12}\b`)

func TestWriteLocalCreatesALoadableServeSkeleton(t *testing.T) {
	dir := t.TempDir()
	staticDir := filepath.Join(dir, "frontend", "dist")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := serverconfig.WriteLocal(serverconfig.LocalOptions{
		Dir:       filepath.Join(dir, "local"),
		StaticDir: staticDir,
		Endpoint:  "http://127.0.0.1:18000",
		Region:    "us-east-1",
		TableName: "apphub-local",
	})
	if err != nil {
		t.Fatalf("WriteLocal: %v", err)
	}
	if len(result.Created) != 4 || len(result.Existing) != 0 {
		t.Fatalf("created=%d existing=%d, want 4 new files", len(result.Created), len(result.Existing))
	}

	cfg, err := serverconfig.Load(result.Config, serverconfig.ModeServe)
	if err != nil {
		t.Fatalf("Load generated server.yaml: %v", err)
	}
	if cfg.PublicOrigin != "http://127.0.0.1:5173" || cfg.ListenAddress != "127.0.0.1:8081" {
		t.Fatalf("loopback listen = %s %s", cfg.PublicOrigin, cfg.ListenAddress)
	}
	if cfg.Store.Endpoint != "http://127.0.0.1:18000" || cfg.Store.TableName != "apphub-local" {
		t.Fatalf("store = %+v", cfg.Store)
	}
	if cfg.Targets["local"].AWSConfigFile == "" {
		t.Fatal("local target has no AWS config file")
	}
	if len(cfg.Auth.Admins) != 1 || cfg.Auth.Admins[0].ProviderID != "google" || cfg.Auth.Admins[0].Subject == "" {
		t.Fatalf("admins = %+v, want one placeholder google admin", cfg.Auth.Admins)
	}
	// Parsing that file with the AWS provider's own loader belongs in
	// compute/aws, not here: this package must not reach the AWS SDK
	// (boundarycheck's aws-sdk-confined rule, USOSS-14). See
	// TestGeneratedLocalConfigParses in compute/aws for that round trip.
}

func TestWriteLocalLeavesExistingFilesAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "local")
	staticDir := t.TempDir()
	if _, err := serverconfig.WriteLocal(serverconfig.LocalOptions{Dir: dir, StaticDir: staticDir}); err != nil {
		t.Fatalf("first WriteLocal: %v", err)
	}
	secretPath := filepath.Join(dir, "client.secret")
	if err := os.WriteFile(secretPath, []byte("operator-replaced-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := serverconfig.WriteLocal(serverconfig.LocalOptions{Dir: dir, StaticDir: staticDir})
	if err != nil {
		t.Fatalf("second WriteLocal: %v", err)
	}
	if len(result.Created) != 0 || len(result.Existing) != 4 {
		t.Fatalf("created=%d existing=%d, want only existing files", len(result.Created), len(result.Existing))
	}
	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "operator-replaced-secret\n" {
		t.Fatal("WriteLocal replaced an existing client secret")
	}
}

func TestWriteLocalRefusesMissingPaths(t *testing.T) {
	if _, err := serverconfig.WriteLocal(serverconfig.LocalOptions{}); err == nil {
		t.Fatal("empty options accepted")
	}
}

func TestWriteLocalYAMLHasNoAccountShapedNumbers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "local")
	if _, err := serverconfig.WriteLocal(serverconfig.LocalOptions{Dir: dir, StaticDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.yaml", "aws.yaml"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if accountShaped.Match(data) {
			t.Fatalf("%s contains an account-shaped placeholder", name)
		}
	}
}
