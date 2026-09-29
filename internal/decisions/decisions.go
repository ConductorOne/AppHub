// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package decisions checks the structure of the decision record.
//
// # What changed, and why most of what this package used to check is gone
//
// The record used to be one append-only file, docs/DECISIONS.md, merged with the
// `union` driver so that two branches appending entries did not conflict. That
// worked locally and not on GitHub: GitHub's mergeability computation does not
// honour .gitattributes merge drivers, so every open branch went CONFLICTING the
// moment anything merged the file -- and a CONFLICTING pull request gets no CI at
// all, because `pull_request` workflows need a refs/pull/N/merge that cannot be
// built. Seven-plus branches at a time were being taken out by one file, and they
// kept displaying a stale green tick while it happened.
//
// The record is now one file per decision under docs/decisions/. Separate files
// cannot conflict, so the merge driver is gone and so is the whole class of
// failure it was papering over.
//
// That deletes most of the old invariant. It was a bijection between entries and
// the blank/---/blank separator blocks that introduced them, and it existed
// because `union` merges a line at a time and could drop a separator, or splice a
// heading onto the previous line, without reporting a conflict. With one entry per
// file there are no separators, nothing to be dropped, and no line-level merge of
// two entries into one file. Those checks are not weakened here, they are
// unreachable, and keeping them would be keeping a gate over an empty room.
//
// # What still exists
//
// Three things, and they are the ones the new layout depends on:
//
//  1. Every file in the directory is classified, or the check fails. A file it
//     cannot classify is not skipped -- rule: a skip path in a gate is a bypass.
//  2. Each entry file holds exactly one entry: one level-two heading at column
//     zero, on the first line, with a body under it. Two headings in one file is
//     the old append shape growing back, and it is the shape that reintroduces the
//     conflict.
//  3. The file name is the heading, slugged. Nobody chooses a name, so a name
//     cannot drift from the entry it holds, and two entries cannot collide on one:
//     equal headings would be equal file names, which the filesystem forbids.
//     Uniqueness is now a property of the layout rather than something checked.
//
// And one migration guard: docs/DECISIONS.md must not exist. Twelve branches were
// open across the migration, every one of them carrying an append to that file. A
// rebase that resurrects it would split the record silently across two schemes,
// and nothing else in the repository would notice.
package decisions

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// Dir is the decision record, relative to the repository root.
	Dir = "docs/decisions"
	// Preamble is the one file in Dir that is not an entry. It is named
	// explicitly rather than matched by a pattern: a pattern is a grammar, and a
	// grammar in a gate is something to be walked around.
	Preamble = "README.md"
	// LegacyPath is the single-file record this directory replaced. Its continued
	// absence is an invariant, not an accident.
	LegacyPath = "docs/DECISIONS.md"
	// entryPrefix marks an entry heading. A level-three heading is a sub-heading
	// within an entry; a heading inside a blockquote is part of a record quoted
	// verbatim and is not a heading of this file's at all.
	entryPrefix = "## "
	// suffix is the extension every file in Dir must have.
	suffix = ".md"
)

// fence opens or closes a code block, at any indent. A fenced block may
// legitimately contain a line that looks like a heading.
var fence = regexp.MustCompile("^[ \t]*(```|~~~)")

// separator matches the blank/---/blank block that used to introduce an entry
// in the single-file record. One entry per file means there is nothing left for
// it to separate; a line that is exactly "---" (optionally padded with
// horizontal whitespace) in an entry file is a fragment of that old shape, not
// legitimate Markdown the entry needs. It most concretely arises when a naive
// per-entry extraction during the docs/DECISIONS.md -> docs/decisions/ migration
// carries the separator that actually introduced the *next* entry along with
// the one before it.
var separator = regexp.MustCompile(`^[ \t]*---[ \t]*$`)

// Finding is one structural defect.
type Finding struct {
	// File is the path the defect is in, relative to the repository root, or ""
	// for a finding about the record as a whole.
	File string
	// Line is the 1-based line the defect is at, or 0 when it is about the file
	// or the record as a whole.
	Line int
	// Rule identifies the invariant that was violated.
	Rule string
	// Detail says what is wrong and what it should look like instead.
	Detail string
}

func (f Finding) String() string {
	switch {
	case f.File == "":
		return fmt.Sprintf("%s: %s", f.Rule, f.Detail)
	case f.Line == 0:
		return fmt.Sprintf("%s: %s: %s", f.File, f.Rule, f.Detail)
	default:
		return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Rule, f.Detail)
	}
}

// Entry is one decision, as read off disk.
type Entry struct {
	// Name is the file's base name within Dir.
	Name string
	// Heading is the entry's level-two heading, without the "## ".
	Heading string
	// Lines is the number of lines in the file, excluding the final newline.
	Lines int
}

// Shape is what the checker found. It is returned even when there are findings,
// so a caller can report over what population they were produced.
type Shape struct {
	// Entries are the entry files, in directory order.
	Entries []Entry
	// Files is every name the directory held, entries and preamble alike.
	Files []string
}

// Slug derives an entry's file name, without the extension, from its heading.
//
// It is a total function: every rune is either kept as a lowercase ASCII
// alphanumeric or folded into a separator, so there is no input it declines to
// name and no second spelling of any name. That is what lets the check be an
// equality rather than a pattern match -- the checker computes the name the
// heading demands and compares it, so a file cannot be named something the
// checker merely tolerates.
func Slug(heading string) string {
	var b strings.Builder
	dash := false
	for _, r := range heading {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r + ('a' - 'A'))
		default:
			dash = true
		}
	}
	return b.String()
}

// Check reads the decision record out of fsys, which is rooted at the repository
// root, and reports every way in which it departs from the invariant.
func Check(fsys fs.FS) ([]Finding, Shape, error) {
	var findings []Finding
	var shape Shape

	// The migration guard, first: if the old single-file record is back, the rest
	// of this check is reasoning over half a record.
	if _, err := fs.Stat(fsys, LegacyPath); err == nil {
		findings = append(findings, Finding{
			File: LegacyPath,
			Rule: "legacy-record-present",
			Detail: "the single-file decision record is back. It was split into " + Dir +
				" because GitHub does not honour the merge=union attribute it relied on. A rebase " +
				"that restores it splits the record across two schemes; move the entry into its own " +
				"file under " + Dir + " and delete this one",
		})
	}

	ents, err := fs.ReadDir(fsys, Dir)
	if err != nil {
		return nil, shape, fmt.Errorf("reading %s: %w", Dir, err)
	}

	var entryNames []string
	for _, de := range ents {
		name := de.Name()
		shape.Files = append(shape.Files, name)
		full := path.Join(Dir, name)
		switch {
		case de.IsDir():
			// Recognised or fatal: there is no rule for what a subdirectory of the
			// record would mean, so it is not quietly walked past.
			findings = append(findings, Finding{
				File: full,
				Rule: "unrecognised-member",
				Detail: "the decision record is a flat directory of entry files; there is no rule " +
					"for what a subdirectory of it holds, so it is reported rather than skipped",
			})
		case name == Preamble:
			findings = append(findings, checkPreamble(fsys, full)...)
		case strings.HasSuffix(name, suffix):
			entryNames = append(entryNames, name)
		default:
			findings = append(findings, Finding{
				File: full,
				Rule: "unrecognised-member",
				Detail: fmt.Sprintf("every file in the decision record is either %s or an entry "+
					"ending in %s; this one is neither, so nothing in this repository checks it",
					Preamble, suffix),
			})
		}
	}

	sort.Strings(entryNames)
	for _, name := range entryNames {
		entry, entryFindings := checkEntry(fsys, name)
		findings = append(findings, entryFindings...)
		shape.Entries = append(shape.Entries, entry)
	}

	// A derivation that finds nothing passes every property over it, so the empty
	// case is named rather than left to be inferred from a clean run.
	if len(shape.Entries) == 0 {
		findings = append(findings, Finding{
			Rule: "empty-record",
			Detail: fmt.Sprintf("%s holds no entry files, which means this check is passing "+
				"over nothing rather than that the project has decided nothing", Dir),
		})
	}

	return findings, shape, nil
}

// checkPreamble asserts the one non-entry file in the directory is not carrying
// an entry. If it were, the entry would sit outside every rule below: no file
// name derived from its heading, and no check that it has one.
func checkPreamble(fsys fs.FS, full string) []Finding {
	lines, findings := readLines(fsys, full)
	if lines == nil {
		return findings
	}
	for i, line := range lines {
		if line.fenced || !strings.HasPrefix(line.text, entryPrefix) {
			continue
		}
		findings = append(findings, Finding{
			File: full,
			Line: i + 1,
			Rule: "entry-in-preamble",
			Detail: "this is a level-two heading, which is how an entry is written. " + Preamble +
				" introduces the record and holds no decisions; an entry here would have no file " +
				"name derived from it and nothing would check it. Move it to its own file",
		})
	}
	return findings
}

// checkEntry asserts one file holds exactly one decision, and is named after it.
func checkEntry(fsys fs.FS, name string) (Entry, []Finding) {
	full := path.Join(Dir, name)
	entry := Entry{Name: name}

	lines, findings := readLines(fsys, full)
	if lines == nil {
		return entry, findings
	}
	entry.Lines = len(lines)

	var headings []int
	for i, line := range lines {
		if !line.fenced && strings.HasPrefix(line.text, entryPrefix) {
			headings = append(headings, i)
		}
	}

	switch {
	case len(headings) == 0:
		return entry, append(findings, Finding{
			File: full,
			Rule: "no-entry-heading",
			Detail: "this file has no level-two heading at column zero, so it holds no entry. " +
				"An entry begins `## <ticket> — <what was decided>` on its first line",
		})
	case len(headings) > 1:
		// The old append shape growing back inside one file. This is the invariant
		// that keeps the record splittable, and the one the layout depends on.
		findings = append(findings, Finding{
			File: full,
			Line: headings[1] + 1,
			Rule: "second-entry-heading",
			Detail: fmt.Sprintf("this file holds %d level-two headings, so it holds more than one "+
				"decision. One decision per file is what stops two pull requests conflicting; "+
				"appending here rebuilds the shared file the record was split up to remove",
				len(headings)),
		})
	}

	if headings[0] != 0 {
		findings = append(findings, Finding{
			File: full,
			Line: headings[0] + 1,
			Rule: "heading-not-first",
			Detail: fmt.Sprintf("the entry heading is on line %d; it must be line 1, so that "+
				"nothing in the file sits outside the entry", headings[0]+1),
		})
	}

	entry.Heading = strings.TrimPrefix(lines[headings[0]].text, entryPrefix)
	if want := Slug(entry.Heading) + suffix; want != name {
		findings = append(findings, Finding{
			File: full,
			Rule: "name-does-not-match-heading",
			Detail: fmt.Sprintf("the heading %q names this file %q. The name is derived from the "+
				"heading rather than chosen, so that it cannot drift from the entry and two "+
				"entries cannot collide on one file. Rename it, or change the heading",
				truncate(entry.Heading), want),
		})
	}

	if !hasBody(lines[headings[0]+1:]) {
		findings = append(findings, Finding{
			File:   full,
			Rule:   "no-body",
			Detail: "this entry is a heading with nothing under it",
		})
	}

	for i, l := range lines {
		if l.fenced || !separator.MatchString(l.text) {
			continue
		}
		findings = append(findings, Finding{
			File: full,
			Line: i + 1,
			Rule: "stray-separator",
			Detail: "this line is exactly \"---\", the blank/---/blank block that used to sit " +
				"between two entries in the single-file record. One entry per file means there is " +
				"nothing left for it to separate; it is legal Markdown but not a shape this entry " +
				"needs. It typically survives a per-entry extraction that carried the separator " +
				"introducing the next entry along with this one. Delete the line",
		})
	}

	return entry, findings
}

func hasBody(lines []line) bool {
	for _, l := range lines {
		if strings.TrimSpace(l.text) != "" {
			return true
		}
	}
	return false
}

// line is one line of a file plus whether it fell inside a code fence, so that
// every rule reasons over the same view and a fence cannot be read two ways.
type line struct {
	text   string
	fenced bool
}

// readLines reads and classifies a file. It returns nil lines when the file
// could not be used at all, in which case the findings say why.
func readLines(fsys fs.FS, full string) ([]line, []Finding) {
	src, err := fs.ReadFile(fsys, full)
	if err != nil {
		return nil, []Finding{{File: full, Rule: "unreadable", Detail: err.Error()}}
	}

	var findings []Finding
	text := string(src)
	switch {
	case text == "":
		return nil, []Finding{{File: full, Rule: "empty", Detail: "the file is empty"}}
	case !strings.HasSuffix(text, "\n"):
		findings = append(findings, Finding{
			File:   full,
			Rule:   "trailing-newline",
			Detail: "the file does not end in a newline",
		})
	case strings.HasSuffix(text, "\n\n"):
		findings = append(findings, Finding{
			File:   full,
			Rule:   "trailing-newline",
			Detail: "the file ends in more than one newline",
		})
	}

	raw := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	out := make([]line, len(raw))
	inFence := false
	for i, t := range raw {
		if fence.MatchString(t) {
			inFence = !inFence
			out[i] = line{text: t, fenced: true}
			continue
		}
		out[i] = line{text: t, fenced: inFence}
	}
	if inFence {
		// The rest of the file was classified under an assumption nobody checked,
		// so the classification is reported rather than trusted.
		findings = append(findings, Finding{
			File:   full,
			Rule:   "unclosed-fence",
			Detail: "a code fence is opened and never closed, so the rest of the file could not be classified",
		})
	}
	return out, findings
}

func truncate(s string) string {
	const limit = 48
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
