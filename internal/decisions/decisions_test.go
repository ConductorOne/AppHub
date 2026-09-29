// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package decisions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// The fixtures are the specification, and each one is a shape that would put the
// record back into the state the migration removed: a shared file two branches
// both append to, a name that can be chosen and so can drift from its entry, or a
// member of the directory that nothing checks.

const entryOne = "## USOSS-1 — first\n\nBody of one.\n"

func canonical() fstest.MapFS {
	return fstest.MapFS{
		Dir + "/" + Preamble:                   {Data: []byte("# Decision record\n\nPreamble.\n")},
		Dir + "/usoss-1-first.md":              {Data: []byte(entryOne)},
		Dir + "/usoss-9-ninth.md":              {Data: []byte("## USOSS-9 — ninth\n\nBody of nine.\n")},
		"docs/design/unrelated.md":             {Data: []byte("## not in the record\n")},
		"internal/decisions/decisions_test.go": {Data: []byte("package decisions\n")},
	}
}

func rules(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestCanonicalRecordPasses(t *testing.T) {
	t.Parallel()
	findings, shape, err := Check(canonical())
	if err != nil {
		t.Fatalf("checking the canonical record: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("the canonical shape was rejected: %v", findings)
	}
	if len(shape.Entries) != 2 {
		t.Fatalf("counted %d entries, want 2: %+v", len(shape.Entries), shape.Entries)
	}
	if got, want := shape.Entries[0].Heading, "USOSS-1 — first"; got != want {
		t.Errorf("heading %q, want %q", got, want)
	}
}

func TestCheckCatchesTheShapesTheLayoutForbids(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// mutate turns the canonical record into the shape under test, so every
		// fixture is one edit away from a record that passes.
		mutate func(fstest.MapFS)
		// want is every rule that must fire.
		want []string
	}{
		{
			// The shape the whole migration exists to prevent: two decisions back
			// in one file, which is a file two pull requests both have to touch.
			name: "a second entry appended to an existing file",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{
					Data: []byte(entryOne + "\n---\n\n## USOSS-4 — fourth\n\nBody of four.\n"),
				}
			},
			want: []string{"second-entry-heading"},
		},
		{
			// A name that was chosen rather than derived. Nothing else in the
			// repository would notice, and the next entry with the real heading
			// would have nowhere to go.
			name: "a file name that does not match its heading",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/some-other-name.md"] = m[Dir+"/usoss-1-first.md"]
				delete(m, Dir+"/usoss-1-first.md")
			},
			want: []string{"name-does-not-match-heading"},
		},
		{
			name: "content above the entry heading",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte("Stray prose.\n\n" + entryOne)}
			},
			want: []string{"heading-not-first"},
		},
		{
			name: "a file with no entry heading at all",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte("### only a sub-heading\n\nBody.\n")}
			},
			want: []string{"no-entry-heading"},
		},
		{
			name: "an entry with no body",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte("## USOSS-1 — first\n")}
			},
			want: []string{"no-body"},
		},
		{
			// The migration artifact this check exists for: a naive per-entry
			// extraction out of the old single-file record can carry the
			// blank/---/blank block that actually introduced the *next* entry
			// along with the one before it. checkEntry's other rules all pass
			// over this shape -- there is still exactly one heading, one file,
			// one name -- and a bare "---" is legal Markdown, so nothing else
			// catches it.
			name: "a stray separator trailing the entry",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{
					Data: []byte(entryOne + "\n---\n"),
				}
			},
			want: []string{"stray-separator"},
		},
		{
			name: "a member of the directory that is not an entry",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/notes.txt"] = &fstest.MapFile{Data: []byte("nothing checks this\n")}
			},
			want: []string{"unrecognised-member"},
		},
		{
			// An entry hidden in the one file the entry rules do not apply to.
			name: "a decision written into the preamble",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/"+Preamble] = &fstest.MapFile{
					Data: []byte("# Decision record\n\nPreamble.\n\n## USOSS-7 — seventh\n\nBody.\n"),
				}
			},
			want: []string{"entry-in-preamble"},
		},
		{
			// The migration guard. Twelve branches were open carrying an append to
			// this path; a rebase that restores it splits the record in two.
			name: "the single-file record is resurrected by a rebase",
			mutate: func(m fstest.MapFS) {
				m[LegacyPath] = &fstest.MapFile{Data: []byte("# Decision record\n\n---\n\n## USOSS-4 — fourth\n\nBody.\n")}
			},
			want: []string{"legacy-record-present"},
		},
		{
			name: "no entries at all",
			mutate: func(m fstest.MapFS) {
				delete(m, Dir+"/usoss-1-first.md")
				delete(m, Dir+"/usoss-9-ninth.md")
			},
			want: []string{"empty-record"},
		},
		{
			name: "no trailing newline",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte(strings.TrimSuffix(entryOne, "\n"))}
			},
			want: []string{"trailing-newline"},
		},
		{
			name: "an unclosed code fence",
			mutate: func(m fstest.MapFS) {
				m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte(entryOne + "\n```\nunclosed\n")}
			},
			want: []string{"unclosed-fence"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Red before green: the unmutated record passes, so every finding
			// below is caused by the mutation and not by the fixture.
			base, _, err := Check(canonical())
			if err != nil {
				t.Fatalf("checking the unmutated record: %v", err)
			}
			if len(base) != 0 {
				t.Fatalf("the unmutated fixture already fails: %v", base)
			}

			m := canonical()
			tc.mutate(m)
			findings, _, err := Check(m)
			if err != nil {
				t.Fatalf("checking the mutated record: %v", err)
			}
			got := rules(findings)
			for _, want := range tc.want {
				var found bool
				for _, g := range got {
					if g == want {
						found = true
					}
				}
				if !found {
					t.Errorf("no %q finding; got %v", want, got)
				}
			}
			for _, f := range findings {
				if f.Detail == "" || f.Rule == "" {
					t.Errorf("finding %+v is missing its rule or detail", f)
				}
			}
		})
	}
}

// TestSubHeadingsAndQuotedHeadingsAreNotEntries pins the classification against
// the shapes the real record contains. Several entries reproduce a decision
// verbatim inside a blockquote, and that quote has its own level-two heading.
func TestSubHeadingsAndQuotedHeadingsAreNotEntries(t *testing.T) {
	t.Parallel()
	m := canonical()
	m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{Data: []byte(
		"## USOSS-1 — first\n\n### A sub-heading\n\nBody.\n\n" +
			"> ## A heading inside a record quoted verbatim\n>\n> Quoted body.\n\n" +
			"And a #1 pull-request reference that is not a heading.\n")}
	findings, shape, err := Check(m)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("legitimate sub-headings or quoted headings were reported: %v", findings)
	}
	if len(shape.Entries) != 2 {
		t.Errorf("counted %d entries, want 2", len(shape.Entries))
	}
}

// TestCodeFenceContentsAreIgnored covers the other way a classifier goes wrong:
// a fenced block may legitimately hold a line that looks like a heading, and
// reading it as structure would report a second entry that is not there.
func TestCodeFenceContentsAreIgnored(t *testing.T) {
	t.Parallel()
	m := canonical()
	m[Dir+"/usoss-1-first.md"] = &fstest.MapFile{
		Data: []byte("## USOSS-1 — first\n\n```\n## not a heading\n```\n\nBody.\n")}
	findings, _, err := Check(m)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("fenced content was read as structure: %v", findings)
	}
}

// TestSlugIsTotalAndCollisionFree drives the property the layout rests on: the
// name is a function of the heading, so equal headings are equal names -- which
// is why nothing has to check that two entries do not collide.
func TestSlugIsTotalAndCollisionFree(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"USOSS-1 — Repo name, licence, and posture": "usoss-1-repo-name-licence-and-posture",
		"USOSS-21 — `modules/paved` is out of v1":   "usoss-21-modules-paved-is-out-of-v1",
		"USOSS-4 — the floor is go1.26.6":           "usoss-4-the-floor-is-go1-26-6",
		"   — leading and trailing —   ":            "leading-and-trailing",
		"MiXeD CaSe":                                "mixed-case",
	}
	for heading, want := range cases {
		if got := Slug(heading); got != want {
			t.Errorf("Slug(%q) = %q, want %q", heading, got, want)
		}
	}
	// Total: nothing in the output is outside [a-z0-9-], for any input.
	for _, heading := range []string{"— — —", "日本語", "a\tb\nc", "!!!", "x"} {
		got := Slug(heading)
		for _, r := range got {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				t.Errorf("Slug(%q) = %q contains %q", heading, got, r)
			}
		}
		if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") || strings.Contains(got, "--") {
			t.Errorf("Slug(%q) = %q is not a canonical slug", heading, got)
		}
	}
	// A heading that slugs to nothing has no file name, so the entry cannot
	// exist -- and the name check reports it rather than accepting any name.
	if got := Slug("— —"); got != "" {
		t.Errorf(`Slug("— —") = %q, want ""`, got)
	}
}

// TestTheRealRecordIsWellFormed runs the check against the repository itself, so
// a malformed record fails `go test ./...` and not only `make decisions`. It also
// keeps this package and the record from drifting apart: a deliberate change to
// the layout has to change this package in the same commit.
func TestTheRealRecordIsWellFormed(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	findings, shape, err := Check(os.DirFS(root))
	if err != nil {
		t.Fatalf("reading the decision record: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
	if t.Failed() {
		t.FailNow()
	}
	if len(shape.Entries) == 0 {
		t.Fatal("the decision record has no entries, which means the classifier is broken " +
			"rather than that the record is empty")
	}
	t.Logf("decision record: %d entries, %d files", len(shape.Entries), len(shape.Files))
}
