// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command citationlint asserts that every file:line citation this repository's
// comments and documents make points inside the file it names.
//
// It is a thin adapter; internal/citations holds the resolution rule, the
// group-membership signal, and the fixtures that prove both fire.
//
// # What this command cannot tell you
//
// It catches a citation pointing at nothing, at a file absent from this
// repository, or past a real file's last line. It cannot tell you a citation
// points at real, in-range code that says something other than what the
// citing comment claims -- that comparison is a reading, not a lexical check,
// and this command does not pretend otherwise. See the internal/citations
// package doc comment for the full argument.
//
// Usage:
//
//	go run ./hack/citationlint [-root .] [-v]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/conductorone/apphub/internal/citations"
)

func main() {
	root := flag.String("root", ".", "repository root to scan")
	verbose := flag.Bool("v", false, "list every citation found, not only the ones this check refuses")
	flag.Parse()

	findings, all, err := citations.Check(os.DirFS(*root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "citationlint: %v\n", err)
		os.Exit(1)
	}

	var local, external, dangling int
	for _, c := range all {
		switch c.Kind {
		case citations.Local:
			local++
		case citations.External:
			external++
		case citations.Dangling:
			dangling++
		}
	}

	if *verbose {
		for _, c := range all {
			fmt.Println(c)
		}
	}

	if len(findings) == 0 {
		fmt.Printf("citations: ok (%d found: %d local, %d external, 0 dangling)\n",
			len(all), local, external)
		return
	}

	fmt.Fprintf(os.Stderr, "citationlint: %d dangling citation(s) of %d found (%d local, %d external)\n\n",
		len(findings), len(all), local, external)
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s\n", f)
	}
	fmt.Fprint(os.Stderr,
		"\nA file:line citation is a premise a reader accepts without checking. Each one "+
			"above names a file this repository carries but a line range outside it -- fix the "+
			"range, or fix the file it names. This check cannot tell you a citation lands on "+
			"real, in-range code that says something other than what the comment claims; that "+
			"needs a reader, not this command.\n")
	os.Exit(1)
}
