// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const hostedConfigYAML = `region: us-west-2
placements:
  primary:
    clusterArn: arn:aws:ecs:us-west-2:` + MemoryAccount + `:cluster/test
    vpc: vpc-example
    subnets: [subnet-example]
    securityGroups: [sg-example]
identity:
  pathPrefix: /test/
  namePrefix: test-
  permissionsBoundary: arn:aws:iam::` + MemoryAccount + `:policy/test-boundary
registry:
  namePrefix: test/
  immutableTags: false
build:
  executorPath: /kaniko/executor
  pusherPath: /usr/local/bin/crane
  pushRoleArn: arn:aws:iam::` + MemoryAccount + `:role/test-push
  sessionDuration: 15m
  task:
    cluster: arn:aws:ecs:us-west-2:` + MemoryAccount + `:cluster/test
    taskDefinitions: [test-build-0, test-build-1]
    containerName: builder
    subnets: [subnet-example]
    securityGroups: [sg-build]
    sharePath: /var/lib/apphub/build
    slotPath: /build
    logGroup: /test/build
    logStreamPrefix: build
container:
  namePrefix: test-
  executionRolePathPrefix: /test/execution/
  executionRolePermissionsBoundary: arn:aws:iam::` + MemoryAccount + `:policy/test-boundary
`

func writeHostedConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRejectsUnknownNestedFieldsAndExtraDocuments(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string]string{
		"unknown nested field": strings.Replace(hostedConfigYAML, "  immutableTags: false", "  immutableTags: false\n  pushCredential: secret-canary", 1),
		"wrong key case":       strings.Replace(hostedConfigYAML, "pushRoleArn:", "PushRoleARN:", 1),
		"second document":      hostedConfigYAML + "---\nregion: us-east-1\n",
		"duplicate field":      hostedConfigYAML + "region: us-east-1\n",
		"runtime hook":         hostedConfigYAML + "isRetryable: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeHostedConfig(t, contents))
			if err == nil {
				t.Fatal("accepted ambiguous or unknown operator configuration")
			}
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("configuration error exposed a rejected value")
			}
		})
	}
}

func TestHostedConfigRefusesMovingTagConflictAndWrongRegion(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string]string{
		"immutable moving tag":          strings.Replace(hostedConfigYAML, "immutableTags: false", "immutableTags: true", 1),
		"different region":              strings.Replace(hostedConfigYAML, "  primary:\n", "  primary:\n    region: us-east-1\n", 1),
		"missing boundary":              strings.Replace(hostedConfigYAML, "  permissionsBoundary: arn:aws:iam::"+MemoryAccount+":policy/test-boundary\n", "", 1),
		"missing network":               strings.Replace(hostedConfigYAML, "    subnets: [subnet-example]\n", "", 1),
		"relative executable":           strings.Replace(hostedConfigYAML, "/usr/local/bin/crane", "crane", 1),
		"unpublished database password": hostedConfigYAML + "relational:\n  namePrefix: test-\n  engineVersions: {postgres: ['16']}\n",
		// The builder runs in its own task or it does not run. Each of these is
		// a configuration that names no place to run one, or names two builds
		// into one slot.
		"no build task":       strings.Replace(hostedConfigYAML, "  task:\n", "  ignored:\n", 1),
		"no task definitions": strings.Replace(hostedConfigYAML, "    taskDefinitions: [test-build-0, test-build-1]\n", "", 1),
		"repeated slot":       strings.Replace(hostedConfigYAML, "[test-build-0, test-build-1]", "[test-build-0, test-build-0]", 1),
		"no build network":    strings.Replace(hostedConfigYAML, "    securityGroups: [sg-build]\n", "", 1),
		"relative share":      strings.Replace(hostedConfigYAML, "    sharePath: /var/lib/apphub/build", "    sharePath: build", 1),
		"bad tlsTermination":  strings.Replace(hostedConfigYAML, "container:\n", "container:\n  tlsTermination: plaintext\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeHostedConfig(t, contents)); err == nil {
				t.Fatal("accepted a hosted configuration that cannot safely deploy")
			}
		})
	}
}

func TestHostedConstructorRefusesHostExecutionBeforeCredentialDiscovery(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(writeHostedConfig(t, hostedConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Build.SessionDuration != 15*time.Minute {
		t.Fatal("duration string was not interpreted as a bounded credential lifetime")
	}
	for _, runner := range []BuildRunner{nil, ExecRunner{}, (*ExecRunner)(nil), &ExecRunner{}} {
		_, err := NewFromConfig(context.Background(), cfg, runner)
		if err == nil || (!strings.Contains(err.Error(), "runner") && !strings.Contains(err.Error(), "ExecRunner")) {
			t.Fatalf("host execution was not refused before credential discovery: %v", err)
		}
	}
}

func TestLoadConfigAcceptsEdgeTLSTermination(t *testing.T) {
	t.Parallel()
	contents := strings.Replace(hostedConfigYAML, "container:\n", "container:\n  tlsTermination: edge\n", 1)
	cfg, err := LoadConfig(writeHostedConfig(t, contents))
	if err != nil {
		t.Fatalf("edge tlsTermination was refused: %v", err)
	}
	if cfg.Container.TLSTermination != TLSTerminationEdge {
		t.Fatalf("tlsTermination = %q, want %q", cfg.Container.TLSTermination, TLSTerminationEdge)
	}
}
