// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteEnvironmentCreatesPrivateRandomCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", ".env.local")
	if err := writeEnvironment([]string{"-file", path}); err != nil {
		t.Fatalf("writeEnvironment: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat environment file: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("environment file permissions = %o, want %o", got, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read environment file: %v", err)
	}
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_ENDPOINT_URL=" + defaultEndpoint,
		"AWS_SESSION_TOKEN=",
		"AWS_SECURITY_TOKEN=",
	} {
		if !strings.Contains(string(content), key) {
			t.Errorf("environment file does not set %s", key)
		}
	}
	if err := writeEnvironment([]string{"-file", path}); err != nil {
		t.Fatalf("writeEnvironment on a valid file: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread environment file: %v", err)
	}
	if string(content) != string(second) {
		t.Error("writeEnvironment rewrote a valid environment file")
	}
}

func TestWriteEnvironmentReplacesNonAlphanumericAccessKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID=bad-key\nAWS_SECRET_ACCESS_KEY=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvironment([]string{"-file", path}); err != nil {
		t.Fatalf("writeEnvironment: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read environment file: %v", err)
	}
	if strings.Contains(string(content), "bad-key") {
		t.Fatal("invalid access key was kept")
	}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "AWS_ACCESS_KEY_ID" {
			continue
		}
		for _, r := range value {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Fatalf("replacement access key is not alphanumeric")
			}
		}
		return
	}
	t.Fatal("replacement file has no AWS_ACCESS_KEY_ID")
}

func TestParseDatabaseConfigRejectsMissingValues(t *testing.T) {
	for _, args := range [][]string{
		{"-endpoint", ""},
		{"-region", ""},
		{"-table", ""},
		{"unexpected"},
	} {
		if _, err := parseDatabaseConfig(args); err == nil {
			t.Errorf("parseDatabaseConfig(%q) succeeded, want refusal", args)
		}
	}
}
