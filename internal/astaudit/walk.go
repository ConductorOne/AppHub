// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type sourceFile struct {
	path string
	f    *ast.File
}

// tree is a parsed population. It cannot be constructed except by a walk that
// completed without error over a directory that exists, in which every
// production file parsed, and which contained at least one such file.
type tree struct {
	name  string
	root  string
	base  string // paths are reported relative to this
	fset  *token.FileSet
	files []sourceFile
}

// pos renders a node's file:line **relative to the repository root**, so a row
// that names a call site names one a reader can open -- and so the output does
// not carry the absolute path of whoever ran it.
//
// That second property is what makes the generated table byte-comparable on
// another machine, and it retires a manual redaction step: earlier artefacts had
// their absolute paths edited out by hand before publication, which is a
// hand-maintained transformation of the tool's output and therefore exactly the
// kind of thing that goes wrong quietly.
func (t tree) pos(n ast.Node) string {
	p := t.fset.Position(n.Pos())
	name := p.Filename
	if rel, err := filepath.Rel(t.base, name); err == nil && !strings.HasPrefix(rel, "..") {
		name = rel
	}
	return fmt.Sprintf("%s:%d", name, p.Line)
}

func (t tree) n() int { return len(t.files) }

// walkPaths returns the sorted production .go paths under root, refusing every
// state that would make the traversal incomplete without erroring. It does not
// parse: the caller parses, so that a parse failure and a traversal failure are
// reported as the different things they are.
func walkPaths(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			// Never ignored: a directory this cannot read is a subtree missing
			// from every count below.
			return fmt.Errorf("walk %s: %w", p, err)
		}
		mode := fi.Mode()

		// A symlink is the case that made this function necessary. Walk uses
		// Lstat, so a symlinked directory is reported here as a non-directory
		// and is never descended into -- no error, no files, no sign in the
		// output that a subtree existed at all.
		if mode&os.ModeSymlink != 0 {
			target, rerr := os.Readlink(p)
			if rerr != nil {
				target = "unreadable: " + rerr.Error()
			}
			return fmt.Errorf("%s is a symlink (-> %s). filepath.Walk does not follow "+
				"symlinks, so anything beneath it would be silently absent from every "+
				"count. Refused rather than followed: a symlink inside a Go source tree "+
				"is worth a human looking at", p, target)
		}
		if mode.IsDir() {
			return nil
		}
		if !mode.IsRegular() {
			return fmt.Errorf("%s is not a regular file (mode %s); a named pipe, socket "+
				"or device cannot be read as Go source and must not be counted as one",
				p, mode)
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// mustTree builds a population or ends the run.
func mustTree(name, root, base string) tree {
	fi, err := os.Lstat(root)
	if err != nil {
		fail("population %q: cannot stat %s: %v", name, root, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		fail("population %q: %s is itself a symlink; refused for the same reason a "+
			"symlink inside the tree is", name, root)
	}
	if !fi.IsDir() {
		fail("population %q: %s is not a directory", name, root)
	}

	paths, err := walkPaths(root)
	if err != nil {
		fail("population %q: %v", name, err)
	}

	// Traverse a second time and require the same set. A file created after its
	// parent directory was read is absent from the first walk with no error, so
	// without this a concurrent modification is another silent omission.
	again, err := walkPaths(root)
	if err != nil {
		fail("population %q: second traversal: %v", name, err)
	}
	if len(paths) != len(again) {
		fail("population %q: two traversals disagree (%d files then %d); the tree "+
			"changed under the walk, so neither count is of a population that existed",
			name, len(paths), len(again))
	}
	for i := range paths {
		if paths[i] != again[i] {
			fail("population %q: two traversals disagree at %d (%s vs %s); the tree "+
				"changed under the walk", name, i, paths[i], again[i])
		}
	}

	if len(paths) == 0 {
		fail("population %q: no production .go files under %s -- every row derived "+
			"from it would be a 0 / 0, which is the absence of a count rather than a count",
			name, root)
	}

	fset := token.NewFileSet()
	out := make([]sourceFile, 0, len(paths))
	for _, p := range paths {
		f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			// Fatal, not skipped. Skipping shrinks every denominator this file
			// belongs in and leaves the table looking correct.
			fail("population %q: parse %s: %v", name, p, perr)
		}
		out = append(out, sourceFile{p, f})
	}
	return tree{name, root, base, fset, out}
}
