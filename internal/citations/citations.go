// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package citations resolves the file:line citations this repository's Go
// comments and Markdown documents make, and reports the one class of defect
// that can be decided mechanically.
//
// # Why this exists
//
// A file:line citation is a premise a reader accepts without checking. Three of
// them (USOSS-68) were wrong from the moment they were written -- not stale, the
// cited files had not changed -- because they were transcribed from a grep
// window's offsets rather than read off the file. One pointed thirteen lines
// past the end of a 138-line file.
//
// USOSS-71 found a second, more dangerous shape of the same defect while
// re-scoping the first: this repository's comments cite the source system it
// was ported from, by that system's bare file names
// (`database.go`, `container.go`, ...), because the citation format elides the
// source repository's name. Ten of those bare citations happen to name a file
// that also exists, under the same base name, in the local package the citing
// comment lives in. A reader follows the citation, lands on real code in a real
// local file, and gets no signal at all that it is the wrong file -- the
// out-of-range check that catches a dangling citation cannot fire, because
// nothing is out of range.
//
// # What this package can decide, and how
//
// Every citation resolves to exactly one of three [Kind]s:
//
//   - [Local]: the named path exists in this repository and the cited range is
//     inside it.
//   - [Dangling]: the named path exists in this repository and the cited range
//     is not -- past the end, before line one, or inverted. This is USOSS-68's
//     defect, and it is decidable: read the file, count its lines, compare.
//   - [External]: the named path does not exist in this repository. Most
//     citations are this kind, because most of this repository's comments are
//     citing the source system it was ported from, which this repository does
//     not carry.
//
// A citation with no directory component (`database.go`, not
// `compute/database.go`) is ambiguous by construction: it could name a sibling
// file in the citing comment's own package, or it could name a file in a
// repository this one does not carry. This package resolves it the way a
// careless reader would -- against a same-named file in the citing file's own
// directory, if one exists -- because that is the reading that produces
// USOSS-71's silent defect, and a checker that resolved it more cautiously
// would not catch what it exists to catch.
//
// # The group-membership signal
//
// A citation rarely stands alone; it is usually one of several sharing a
// parenthetical, e.g. "(container.go, lines 301-334, and lines 1138-1154,
// postgres_roles.go, line 230-248)". This package treats such a run as one
// [group]: citations joined by nothing but ", " or " and " between the end of
// one and the start of the next, including the bare `:1138-1154` form (with a
// leading colon rather than spelled "lines") that continues the previous
// citation's file name rather than naming its own.
//
// If any member of a group is [External] -- and `postgres_roles.go` in the
// example above never exists in this repository under any path, so it always
// is -- every member of that group is reported as [External], even a member
// whose bare name would otherwise resolve, in-range, against a local sibling.
// One provably-external citation in a run written by the same sentence about the
// same other system proves the run is about that system, cheaper than reading
// the sentence.
//
// # What this package cannot decide, on purpose
//
// A citation can name a real local file, at a real line range inside it, that
// says something other than what the citing comment claims. USOSS-68's second
// defect was exactly this: identity.go, lines 99 through 104, was a real,
// in-range citation to code that renders a trust policy, cited by a comment
// that claimed it was about ownership. Nothing that does not read English can
// tell the two apart, and this package does not try. It reports every citation
// it resolves, [Local] or not, and lets a review read the ones a change
// touches -- it is not a substitute for that reading, only the check that ran
// unread.
//
// This package also only sees a citation in the exact shapes [Check]
// recognises: a path followed by a colon and a line number, optionally a
// dashed range, and the bare colon-and-range continuation immediately after
// ", " or " and ". A citation written another way is a citation this package
// does not see -- the alternative, a pattern loose enough to catch every
// spelling, would also catch address literals, struct tags, and version
// strings that are not citations at all. And a citation with no line number at
// all (`see database.go`) is not tracked here: with nothing to compare a range
// against, there is nothing this package could decide about it that reading the
// sentence would not decide better.
package citations

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind classifies what a citation's target resolved to.
type Kind int

const (
	// Local is a citation whose target exists in this repository and whose
	// range, if it has one, is inside that file.
	Local Kind = iota
	// Dangling is a citation whose target exists in this repository but whose
	// range is not inside it. This is the defect USOSS-68 exists to catch.
	Dangling
	// External is a citation whose target does not exist in this repository,
	// under the resolution rule [Check] documents -- most commonly a bare file
	// name from the source system this repository was ported
	// from.
	External
)

// String names the kind the way findings and reports print it.
func (k Kind) String() string {
	switch k {
	case Local:
		return "local"
	case Dangling:
		return "dangling"
	case External:
		return "external"
	default:
		return fmt.Sprintf("citations.Kind(%d)", int(k))
	}
}

// Citation is one file:line reference found in a Go comment or a Markdown
// document.
type Citation struct {
	SourceFile string // repo-relative path of the file the citation appears in
	SourceLine int    // 1-based line within SourceFile the citation starts on
	Text       string // the exact citation text matched, e.g. "container.go:301-334"
	Target     string // the path as written, e.g. "container.go" or "compute/aws/identity.go"

	HasRange bool // false for a bare continuation with no digits -- never produced today, reserved
	From, To int  // 1-based, inclusive; meaningful only when HasRange

	Kind     Kind
	Resolved string // repo-relative path this checker read to decide Kind; "" for External
	Lines    int    // line count of Resolved; 0 for External
}

// String reports one citation the way a finding or a verbose listing prints it.
func (c Citation) String() string {
	loc := fmt.Sprintf("%s:%d", c.SourceFile, c.SourceLine)
	switch c.Kind {
	case Dangling:
		return fmt.Sprintf("%s: cites %s, but %s has %d lines", loc, c.Text, c.Resolved, c.Lines)
	case Local:
		return fmt.Sprintf("%s: cites %s, resolved against %s (%d lines)", loc, c.Text, c.Resolved, c.Lines)
	default:
		return fmt.Sprintf("%s: cites %s, treated as external", loc, c.Text)
	}
}

// Finding is one citation this checker refuses: always [Dangling].
type Finding struct {
	Citation Citation
}

func (f Finding) String() string { return f.Citation.String() }

// group is a run of citations sharing one parenthetical or comma-joined list,
// including bare `:123-456` continuations. Every member of a group is judged
// external together: see the package doc comment.
type group []Citation

// Check walks fsys, which is rooted at the repository root, and resolves every
// file:line citation it recognises in a `.go` file's comments or a `.md`
// file's prose. It returns every citation found -- Local, Dangling, or
// External -- so a caller can both gate on the [Dangling] ones and report the
// full count, and a non-nil error only for a failure to read or parse the
// tree itself.
func Check(fsys fs.FS) ([]Finding, []Citation, error) {
	cache := map[string][]byte{}

	var groups []group
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".go"):
			gs, err := scanGoFile(fsys, p)
			if err != nil {
				return fmt.Errorf("parsing %s: %w", p, err)
			}
			groups = append(groups, gs...)
		case strings.HasSuffix(p, ".md"):
			gs, err := scanMarkdownFile(fsys, p)
			if err != nil {
				return fmt.Errorf("reading %s: %w", p, err)
			}
			groups = append(groups, gs...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	for i := range groups {
		resolveGroup(fsys, cache, groups[i])
	}

	var all []Citation
	for _, g := range groups {
		all = append(all, g...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].SourceFile != all[j].SourceFile {
			return all[i].SourceFile < all[j].SourceFile
		}
		return all[i].SourceLine < all[j].SourceLine
	})

	var findings []Finding
	for _, c := range all {
		if c.Kind == Dangling {
			findings = append(findings, Finding{Citation: c})
		}
	}
	return findings, all, nil
}

// skipDir reports whether a directory and its subtree hold nothing this check
// needs to look at: fixtures that deliberately violate the rules, and
// directories no configuration or reader treats as this repository's own
// source -- the same shape [internal/boundary]'s walker uses, narrowed to what
// this check cares about.
func skipDir(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return true
	}
	return name == "testdata" || name == "node_modules"
}

// namedCitation matches a citation that carries its own path:
// "path/to/file.go:123" or "path/to/file.go:123-456".
var namedCitation = regexp.MustCompile(`\b([A-Za-z0-9_][\w./-]*\.go):(\d+)(?:-(\d+))?\b`)

// continuationCitation matches the bare-range continuation form this
// repository uses to cite a second range in the file the previous citation in
// the same list just named: ", :123-456". The comma is what tells this apart
// from an unrelated "12:30" or a struct tag; nothing in this repository writes
// a citation continuation without one.
var continuationCitation = regexp.MustCompile(`,[ \t]+(:(\d+)(?:-(\d+))?)\b`)

// sameGroupGap matches the text a group tolerates between two citations and
// still calls them one group: a comma, an optional "and", and nothing else.
var sameGroupGap = regexp.MustCompile(`^,\s*(?:and\s+)?$`)

// scanGoFile extracts citation groups from every comment in one Go source
// file, using go/parser rather than a line-oriented scan so that both `//` and
// `/*/` comments, and their exact source lines, come from the compiler's own
// idea of where a comment is -- not a second, hand-rolled one.
func scanGoFile(fsys fs.FS, p string) ([]group, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, p, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var groups []group
	for _, cg := range file.Comments {
		text, lineAt := flattenGoComment(fset, cg)
		groups = append(groups, extractGroups(text, lineAt, p)...)
	}
	return groups, nil
}

// flattenGoComment joins one comment group's lines into flowing prose -- so
// that a continuation citation written on the next `//` line, as several of
// this repository's are, reads as adjacent to the citation before it -- and
// returns a function recovering the original source line for any offset into
// that prose.
func flattenGoComment(fset *token.FileSet, cg *ast.CommentGroup) (string, func(int) int) {
	var b strings.Builder
	bounds := make([]int, 0, len(cg.List))
	lines := make([]int, 0, len(cg.List))
	for i, c := range cg.List {
		if i > 0 {
			b.WriteByte(' ')
		}
		txt := c.Text
		switch {
		case strings.HasPrefix(txt, "//"):
			txt = strings.TrimPrefix(txt, "//")
		case strings.HasPrefix(txt, "/*"):
			txt = strings.TrimSuffix(strings.TrimPrefix(txt, "/*"), "*/")
		}
		b.WriteString(strings.TrimPrefix(txt, " "))
		bounds = append(bounds, b.Len())
		lines = append(lines, fset.Position(c.Pos()).Line)
	}
	text := b.String()
	lineAt := func(off int) int {
		for i, end := range bounds {
			if off < end {
				return lines[i]
			}
		}
		if len(lines) > 0 {
			return lines[len(lines)-1]
		}
		return 0
	}
	return text, lineAt
}

// scanMarkdownFile extracts citation groups from one Markdown file's prose,
// paragraph by paragraph -- a blank line ends a paragraph and therefore ends any
// group, so that a citation opening one bullet is never joined to a citation
// opening the next by this package's own line-flattening rather than by
// anything the document wrote.
func scanMarkdownFile(fsys fs.FS, p string) ([]group, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	rawLines := strings.Split(string(src), "\n")

	var groups []group
	var para []string
	var paraLines []int
	flush := func() {
		if len(para) == 0 {
			return
		}
		var b strings.Builder
		bounds := make([]int, 0, len(para))
		for i, l := range para {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(l)
			bounds = append(bounds, b.Len())
		}
		text := b.String()
		lines := append([]int(nil), paraLines...)
		lineAt := func(off int) int {
			for i, end := range bounds {
				if off < end {
					return lines[i]
				}
			}
			if len(lines) > 0 {
				return lines[len(lines)-1]
			}
			return 0
		}
		groups = append(groups, extractGroups(text, lineAt, p)...)
		para = para[:0]
		paraLines = paraLines[:0]
	}
	for i, l := range rawLines {
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		para = append(para, l)
		paraLines = append(paraLines, i+1)
	}
	flush()
	return groups, nil
}

// atom is one citation token found in flowing text, before its file target is
// known for a bare continuation.
type atom struct {
	start, end int
	target     string // "" for a bare continuation; resolved from the group before Citation is built
	from, to   int
}

// extractGroups finds every citation in text and clusters the ones that share
// a parenthetical or comma-joined list into one [group], resolving the bare
// continuation form's inherited file name as it goes.
func extractGroups(text string, lineAt func(int) int, sourceFile string) []group {
	var atoms []atom
	for _, m := range namedCitation.FindAllStringSubmatchIndex(text, -1) {
		from, _ := strconv.Atoi(text[m[4]:m[5]])
		to := from
		if m[6] != -1 {
			to, _ = strconv.Atoi(text[m[6]:m[7]])
		}
		atoms = append(atoms, atom{start: m[0], end: m[1], target: text[m[2]:m[3]], from: from, to: to})
	}
	for _, m := range continuationCitation.FindAllStringSubmatchIndex(text, -1) {
		from, _ := strconv.Atoi(text[m[4]:m[5]])
		to := from
		if m[6] != -1 {
			to, _ = strconv.Atoi(text[m[6]:m[7]])
		}
		// m[0]:m[1] spans the leading ", "; the atom itself is only the
		// ":N-M" part (m[2]:m[3]), so the comma stays in the gap between this
		// atom and the one before it -- otherwise the two would never look
		// adjacent enough to share a group.
		atoms = append(atoms, atom{start: m[2], end: m[3], from: from, to: to})
	}
	sort.Slice(atoms, func(i, j int) bool { return atoms[i].start < atoms[j].start })

	var groups []group
	var cur group
	currentTarget := ""
	clusterEnd := -1

	flush := func() {
		if len(cur) > 0 {
			groups = append(groups, cur)
			cur = nil
		}
	}

	for _, a := range atoms {
		target := a.target
		if target == "" {
			if currentTarget == "" {
				// A bare continuation with nothing to inherit from -- not a shape
				// this repository writes; skip rather than guess a file.
				continue
			}
			target = currentTarget
		}
		if clusterEnd < 0 || !sameGroupGap.MatchString(text[clusterEnd:a.start]) {
			flush()
		}
		cur = append(cur, Citation{
			SourceFile: sourceFile,
			SourceLine: lineAt(a.start),
			Text:       text[a.start:a.end],
			Target:     target,
			HasRange:   true,
			From:       a.from,
			To:         a.to,
		})
		currentTarget = target
		clusterEnd = a.end
	}
	flush()
	return groups
}

// resolveGroup decides each member's [Kind] and then applies the
// group-membership signal: one External member makes every member External.
func resolveGroup(fsys fs.FS, cache map[string][]byte, g group) {
	anyExternal := false
	for i := range g {
		resolveOne(fsys, cache, &g[i])
		if g[i].Kind == External {
			anyExternal = true
		}
	}
	if !anyExternal {
		return
	}
	for i := range g {
		g[i].Kind = External
		g[i].Resolved = ""
		g[i].Lines = 0
	}
}

// resolveOne decides one citation's [Kind] in isolation, before any
// group-membership override: a directory-qualified target is read at that
// exact path; a bare target is read from the citing file's own directory, the
// resolution a careless reader would make (see the package doc comment).
func resolveOne(fsys fs.FS, cache map[string][]byte, c *Citation) {
	candidate := c.Target
	if !strings.Contains(candidate, "/") {
		if dir := path.Dir(c.SourceFile); dir != "." {
			candidate = path.Join(dir, candidate)
		}
	}

	data, ok := cache[candidate]
	if !ok {
		var err error
		data, err = fs.ReadFile(fsys, candidate)
		if err != nil {
			c.Kind = External
			return
		}
		cache[candidate] = data
	}

	lines := strings.Split(string(data), "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	c.Resolved = candidate
	c.Lines = len(lines)
	if c.From < 1 || c.To < c.From || c.To > len(lines) {
		c.Kind = Dangling
		return
	}
	c.Kind = Local
}
