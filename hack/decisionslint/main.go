// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command decisionslint asserts that the decision record still has the shape its
// format requires.
//
// It is a thin adapter; internal/decisions holds the invariant and the fixtures
// that prove it catches the failures it exists for.
//
// Usage:
//
//	go run ./hack/decisionslint [-root .]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/conductorone/apphub/internal/decisions"
)

func main() {
	root := flag.String("root", ".", "repository root holding "+decisions.Dir)
	flag.Parse()

	findings, shape, err := decisions.Check(os.DirFS(*root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decisionslint: %v\n", err)
		os.Exit(1)
	}
	if len(findings) == 0 {
		fmt.Printf("decision record: ok (%d entries, %d files in %s)\n",
			len(shape.Entries), len(shape.Files), decisions.Dir)
		return
	}

	fmt.Fprintf(os.Stderr, "decisionslint: %d finding(s) over %d entries in %s\n\n",
		len(findings), len(shape.Entries), decisions.Dir)
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s\n\n", f)
	}
	fmt.Fprint(os.Stderr,
		"The decision record is one file per decision, so that two pull requests adding\n"+
			"entries cannot conflict and cannot lose their CI to a conflict. The file name is\n"+
			"derived from the entry's heading rather than chosen. Add a decision by adding a\n"+
			"file; do not append to an existing one, and do not add an index.\n")
	os.Exit(1)
}
