// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/conductorone/apphub/internal/serverconfig"
)

func TestIsLoopbackDev(t *testing.T) {
	cases := []struct {
		name string
		cfg  serverconfig.Config
		want bool
	}{
		{"loopback with explicit allow", serverconfig.Config{PublicOrigin: "http://127.0.0.1:5173", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}, true},
		{"loopback without explicit allow", serverconfig.Config{PublicOrigin: "http://127.0.0.1:5173"}, false},
		{"https loopback is not the dev signal", serverconfig.Config{PublicOrigin: "https://127.0.0.1:5173", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}, false},
		{"https public origin", serverconfig.Config{PublicOrigin: "https://portal.example.com", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}, false},
		{"http non-loopback host, allowed anyway", serverconfig.Config{PublicOrigin: "http://portal.example.com", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}, false},
		{"malformed origin", serverconfig.Config{PublicOrigin: "://bad", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLoopbackDev(c.cfg); got != c.want {
				t.Fatalf("isLoopbackDev(%+v) = %v, want %v", c.cfg, got, c.want)
			}
		})
	}
}

func TestGitHubAppKeyLocationDerivesFromDeploymentCoordinates(t *testing.T) {
	loopback := serverconfig.Config{PublicOrigin: "http://127.0.0.1:5173", Auth: serverconfig.AuthConfig{AllowLoopbackHTTP: true}}
	ssm, local, useLocal := githubAppKeyLocation(loopback, "/home/dev/.local/server.yaml")
	if !useLocal || local.Path != "/home/dev/.local/github-app-key.json" || ssm.Region != "" {
		t.Fatalf("loopback deployment did not derive a local key file next to the config: ssm=%+v local=%+v useLocal=%v", ssm, local, useLocal)
	}

	cloud := serverconfig.Config{PublicOrigin: "https://portal.example.com", Store: serverconfig.StoreConfig{Region: "us-west-2", TableName: "apphub-prod"}}
	ssm, local, useLocal = githubAppKeyLocation(cloud, "/etc/apphub/server.yaml")
	if useLocal || local.Path != "" {
		t.Fatalf("a real deployment used the local backend: local=%+v useLocal=%v", local, useLocal)
	}
	if ssm.Region != "us-west-2" || ssm.ParameterName != "/apphub/apphub-prod/github-app/private-key" {
		t.Fatalf("unexpected derived SSM location: %+v", ssm)
	}

	// Two deployments sharing a region and account must never collide: the
	// parameter path is namespaced by each deployment's own table name.
	other := serverconfig.Config{PublicOrigin: "https://portal.example.com", Store: serverconfig.StoreConfig{Region: "us-west-2", TableName: "apphub-staging"}}
	otherSSM, _, _ := githubAppKeyLocation(other, "/etc/apphub/server.yaml")
	if otherSSM.ParameterName == ssm.ParameterName {
		t.Fatal("two deployments in the same region derived the same SSM parameter path")
	}
}
