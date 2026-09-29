// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command astaudit derives the USOSS-6 source-claim evidence table from the Go
// AST of the the source tree.
//
// It is a thin adapter; internal/astaudit holds the derivation, the traversal
// and row-set contracts, and the fixtures that prove they catch the failures
// they exist for.
//
// It is not part of `make check`: twenty-nine of its thirty rows are claims
// about a source repository that is not present in CI, so the gate CI can run is
// the package's own test suite, which is hermetic. This command is how a
// reviewer re-runs the arithmetic rather than re-deriving it.
//
// Usage:
//
//	go run ./hack/astaudit \
//	  -source /path/to/source/backend \
//	  -target /path/to/apphub \
//	  -report /path/to/usoss-6/report.md
//
// Every input is explicit. None defaults to the working directory: a root that
// quietly became "wherever this was run from" is how a count stops being about
// the thing it names. -target is required because exactly one row, E28, counts
// the import-boundary rules in the *target* repository and cannot be derived
// from the source at all.
//
// It exits nonzero, naming what was incomplete, if it could not traverse a
// population in full, if a figure has no denominator, if the set of rows it
// derived is not exactly the set the evidence table declares, or if it cannot
// attribute both input trees to a commit -- which a tree with uncommitted
// changes cannot be, unless -allow-dirty says so deliberately.
//
// # The table is generated, not parsed
//
// The evidence table used to live in a Markdown document that this program read
// back, so the two could be checked against each other. Five reproductions of one
// class later -- four of them in the Markdown scanner, two of them inside the fix
// for the previous one -- the table is instead **generated** from the declaration
// in internal/astaudit/evidence.go. There is one artefact, so there is no drift
// to detect, and nothing here parses Markdown at all.
//
//	go run ./hack/astaudit -source <us>/backend -target <apphub>            # print
//	go run ./hack/astaudit ... -artifact docs/x.md                            # write
//	go run ./hack/astaudit ... -artifact docs/x.md -check                     # verify
//
// -check regenerates the table and compares it to the committed file byte for
// byte, so a stale committed artefact is caught. It is a comparison rather than a
// parse, which is the point: there is no grammar in it to disagree with a
// renderer about.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/conductorone/apphub/internal/astaudit"
)

func main() {
	source := flag.String("source", "", "path to the source backend/ directory (required)")
	target := flag.String("target", "", "path to the AppHub repository root, for E28 (required)")
	artifact := flag.String("artifact", "",
		"path to the generated evidence table. Written unless -check is given")
	check := flag.Bool("check", false,
		"regenerate the table and byte-compare it against -artifact instead of writing it")
	allowDirty := flag.Bool("allow-dirty", false,
		"count trees that have uncommitted changes. Off by default: a figure counted over "+
			"a working copy is not a claim about the commit printed beside it")
	flag.Parse()

	missing := []string{}
	for _, f := range []struct {
		name string
		val  string
	}{{"-source", *source}, {"-target", *target}} {
		if f.val == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "astaudit: %v required and not given; neither defaults "+
			"to the working directory\n", missing)
		flag.Usage()
		os.Exit(2)
	}
	if *check && *artifact == "" {
		fmt.Fprintf(os.Stderr, "astaudit: -check needs -artifact: there is nothing to "+
			"compare against\n")
		os.Exit(2)
	}

	out := bufio.NewWriter(os.Stdout)
	err := astaudit.Run(out, astaudit.Options{
		SourceRoot: *source,
		TargetRoot: *target,
		Artifact:   *artifact,
		Check:      *check,
		AllowDirty: *allowDirty,
	})
	// Flushed before the error is reported, so the rows established up to the
	// failure are visible next to the reason the run stopped.
	if ferr := out.Flush(); ferr != nil {
		fmt.Fprintf(os.Stderr, "astaudit: writing output: %v\n", ferr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
