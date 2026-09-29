// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command hermeticcheck asserts that this repository's CI needs no credentials.
//
// It is a thin adapter; internal/hermetic holds the rules and the fixtures that
// prove they work.
//
// Usage:
//
//	go run ./hack/hermeticcheck [-dir .github/workflows]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/conductorone/apphub/internal/hermetic"
)

func main() {
	dir := flag.String("dir", hermetic.WorkflowDir, "directory of GitHub Actions workflows")
	flag.Parse()

	findings, files, err := hermetic.CheckDir(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hermeticcheck: %v\n", err)
		os.Exit(1)
	}
	if len(findings) == 0 {
		fmt.Printf("hermetic ci: ok (%d workflow file(s) parsed, no credential access)\n", len(files))
		return
	}
	fmt.Fprintf(os.Stderr, "hermeticcheck: %d finding(s)\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s\n      at   %s\n      %s\n\n", f.File, f.Path, f.Detail)
	}
	fmt.Fprint(os.Stderr,
		"CI for this repository is credential-free by design. If a job genuinely needs\n"+
			"a secret, removing a rule from internal/hermetic is the deliberate act that\n"+
			"permits it -- and it should be argued for in the pull request that does it.\n")
	os.Exit(1)
}
