// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package disclosure checks that the module tree publishes no detection
// vocabulary: no classifier, weakness-catalogue entry, or check identifier
// naming something a scanner looks for.
//
// # Why this exists
//
// USOSS-17 abstracts the AI provider behind an interface, and the largest
// reason recorded for that is disclosure: what a scanner looks for is not this
// repository's to publish, so keeping every prompt on the far side of the
// interface keeps the heuristics out by construction. That is a claim about a
// whole tree, and it was false on the first attempt -- three identifier
// literals from the source scanner's system prompt were reproduced verbatim,
// one in a doc comment and two in a test fixture, while the decision entry
// said they were absent. **A test fixture is a publication surface exactly as
// a source file is.**
//
// # This package names shapes, never terms
//
// [Shapes] matches the *form* each kind of identifier takes and contains no
// real classifier, weakness number, or check name. Writing the terms into the
// guard would publish them in the guard, which is the rule the project already
// settled for detection rules generally: match the shape.
//
// # No skip path
//
// This package lives outside the tree it inspects. An earlier version put the
// patterns in a test file inside modules/review and skipped that file by name
// while scanning -- which is a gate with a documented bypass, and the project
// has now found that shape in four separate gates. Here the scanned set and
// the set holding the patterns are disjoint, so there is nothing to skip.
//
// # What this covers, and what no check in this repository can
//
// It covers literals of the modelled shapes in every package under the module
// tree, comments and test files included, and it derives that set by walking
// rather than by listing.
//
// It cannot see a heuristic expressed in prose, a paraphrase, or an identifier
// whose shape it does not model. Neither can any other check that runs here:
// the comparison that would settle it needs the source tree, and a public
// repository must not name or clone that. The complete check is a human
// comparison run before publication -- USOSS-18 -- and this is the part that
// can be automated. The gap is written down so it is visible rather than
// assumed closed.
package disclosure

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// Shape is one recognisable form of detection vocabulary.
type Shape struct {
	// Name says what kind of identifier this is, without being one.
	Name string
	// Pattern matches the form.
	Pattern *regexp.Regexp
	// Why says what publishing one would disclose.
	Why string
}

// Shapes are the forms this package refuses. Every pattern is a shape; none is
// a term.
var Shapes = []Shape{
	{
		Name:    "ranked web-application risk category",
		Pattern: regexp.MustCompile(`\b[A-Z][0-9]{2}:[A-Za-z]`),
		Why:     "a ranked risk-category identifier names a class a scanner is looking for",
	},
	{
		Name:    "software-weakness catalogue entry",
		Pattern: regexp.MustCompile(`\b[A-Z]{3}-[0-9]{2,}\b`),
		Why:     "a catalogue number names one specific weakness a scanner is looking for",
	},
	{
		Name:    "dotted check identifier",
		Pattern: regexp.MustCompile(`\b[a-z][a-z0-9]{2,}\.[a-z0-9]+-[a-z0-9-]+\b`),
		Why:     "a check identifier is the name of one rule a scanner runs",
	},
}

// Finding is one piece of detection vocabulary found in the tree.
type Finding struct {
	// File is the path, relative to the filesystem root.
	File string
	// Line is 1-based.
	Line int
	// Match is what was found.
	Match string
	// Shape is the form it took.
	Shape Shape
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %q is a %s. %s. Use an invented placeholder that does not take this form",
		f.File, f.Line, f.Match, f.Shape.Name, f.Shape.Why)
}

// Coverage records what a scan actually read, so a caller can tell an empty
// result from an empty traversal. A check over nothing reports the same
// success as a check over everything.
type Coverage struct {
	// Packages is the number of directories holding Go files that were read.
	Packages int
	// Files is the number of Go files read.
	Files int
	// Bytes is how much was read.
	Bytes int
}

// Scan reads every Go file under root in fsys, test files included, and
// reports every match of every shape.
//
// A directory it cannot read, or a file it cannot open, is an error rather
// than a skipped entry: a walk that steps silently over what it could not read
// reports the same success as one that covered everything.
func Scan(fsys fs.FS, root string) ([]Finding, Coverage, error) {
	var (
		findings []Finding
		coverage Coverage
	)
	seen := map[string]bool{}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		dir := path.Dir(p)
		if !seen[dir] {
			seen[dir] = true
			coverage.Packages++
		}
		b, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}
		coverage.Files++
		coverage.Bytes += len(b)
		for i, line := range strings.Split(string(b), "\n") {
			for _, shape := range Shapes {
				if m := shape.Pattern.FindString(line); m != "" {
					findings = append(findings, Finding{File: p, Line: i + 1, Match: m, Shape: shape})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, Coverage{}, fmt.Errorf("walking %s: %w", root, err)
	}
	return findings, coverage, nil
}
