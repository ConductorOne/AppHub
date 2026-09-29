// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/internal/serverconfig"
)

// The AWS config file written by serverconfig.WriteLocal must parse with this
// package's own loader. This lives here, not in internal/serverconfig, because
// that package must not reach the AWS SDK (boundarycheck's aws-sdk-confined
// rule, USOSS-14); this package is the one place that's allowed to.
func TestGeneratedLocalConfigParses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "local")
	staticDir := t.TempDir()

	result, err := serverconfig.WriteLocal(serverconfig.LocalOptions{Dir: dir, StaticDir: staticDir})
	if err != nil {
		t.Fatalf("WriteLocal: %v", err)
	}

	cfg, err := serverconfig.Load(result.Config, serverconfig.ModeServe)
	if err != nil {
		t.Fatalf("Load generated server.yaml: %v", err)
	}
	target, ok := cfg.Targets["local"]
	if !ok {
		t.Fatal("generated server.yaml has no \"local\" target")
	}
	if _, err := os.Stat(target.AWSConfigFile); err != nil {
		t.Fatalf("AWS config file: %v", err)
	}
	if _, err := aws.LoadConfig(target.AWSConfigFile); err != nil {
		t.Fatalf("LoadConfig generated aws.yaml: %v", err)
	}
}
