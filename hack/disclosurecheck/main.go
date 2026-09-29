// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command disclosurecheck fails on publication-disclosure shapes.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type rule struct {
	id          string
	description string
	pattern     *regexp.Regexp
	group       int
	allow       func(file, match string) bool
}

type finding struct {
	file  string
	line  int
	rule  string
	match string
	why   string
}

type coverage struct {
	files int
	lines int
	bytes int
	paths int
}

func rules() []rule {
	return []rule{
		{
			id:          "private-source-system-name",
			description: "the private source-system repository name is not public documentation",
			pattern:     regexp.MustCompile(`(?i)\bunion[-_]station\b`),
		},
		{
			id:          "build-host-absolute-path",
			description: "build-host checkout paths are local machine state, not publication evidence",
			pattern: regexp.MustCompile(`/` + `data/` + `squire/` + `src` +
				`(?:/[A-Za-z0-9._-]+)*`),
		},
		{
			id:          "private-ductone-repository-url",
			description: "repository URLs under the private organization must be deliberately scrubbed or made public first",
			pattern:     regexp.MustCompile(`github\.com/ductone/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*`),
		},
		{
			id:          "private-squire-url",
			description: "private Squire URLs are operator-local links, not public documentation",
			pattern:     regexp.MustCompile(`https?://[^\s` + "`" + `"'<>)]*[sS][qQ][uU][iI][rR][eE][^\s` + "`" + `"'<>)]*`),
		},
		{
			id:          "aws-account-id",
			description: "a standalone twelve-digit number has the shape of an AWS account ID",
			pattern:     regexp.MustCompile(`\b[0-9]{12}\b`),
			// AWS's documented placeholder account, in the same two files the
			// .gitleaks.toml allowlist names for it: the devseed fixture that uses
			// it, and the allowlist that has to spell it. Assembled so this file
			// does not spell it too.
			allow: func(file string, match string) bool {
				return match == "1234"+"5678"+"9012" &&
					(file == "store/cmd/devseed/application.go" || file == ".gitleaks.toml")
			},
		},
		{
			id:          "aws-account-arn",
			description: "AWS ARNs embed account identity and should not be committed with real values",
			pattern:     regexp.MustCompile(`\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:[^\s` + "`" + `"'<>)]*`),
		},
		{
			id:          "internal-host-url",
			description: "URLs under private-use DNS suffixes disclose internal hostnames",
			pattern:     regexp.MustCompile(`https?://([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.(?:internal|corp|lan|intranet|local))(?::[0-9]+)?(?:[/\s` + "`" + `"'<>)]|$)`),
			group:       1,
			allow: func(_ string, match string) bool {
				return match == "localhost" || match == "svc.cluster.local"
			},
		},
	}
}

var allRules = rules()

// scan checks every regular file under root. When publishable is non-nil, a
// file it rejects is skipped: a gitignored file is local state that no commit
// can carry, such as an operator's tfvars or a build's output.
func scan(fsys fs.FS, root string, publishable func(rel string) bool) ([]finding, coverage, error) {
	var findings []finding
	var cov coverage
	root = path.Clean(root)
	if root == "." {
		root = ""
	}
	walkRoot := root
	if walkRoot == "" {
		walkRoot = "."
	}
	err := fs.WalkDir(fsys, walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(name) {
				return fs.SkipDir
			}
			return nil
		}
		if name == ".git" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel := p
		if root != "" {
			var ok bool
			rel, ok = strings.CutPrefix(p, root+"/")
			if !ok && p == root {
				rel = path.Base(p)
			}
		}
		if publishable != nil && !publishable(rel) {
			return nil
		}
		cov.paths++
		findings = append(findings, scanLine(rel, 0, rel)...)
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if bytes.IndexByte(b, 0) >= 0 {
			return nil
		}
		text := string(b)
		cov.files++
		cov.bytes += len(b)
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			if i == len(lines)-1 && line == "" {
				continue
			}
			cov.lines++
			findings = append(findings, scanLine(rel, i+1, line)...)
		}
		return nil
	})
	if err != nil {
		return nil, coverage{}, err
	}
	if cov.paths == 0 {
		return nil, coverage{}, errors.New("no repository files were scanned")
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		if findings[i].line != findings[j].line {
			return findings[i].line < findings[j].line
		}
		return findings[i].rule < findings[j].rule
	})
	return findings, cov, nil
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".tools", ".task-worktrees", ".dynamodb", ".local", "vendor", "node_modules":
		return true
	default:
		return false
	}
}

func scanLine(file string, line int, text string) []finding {
	var out []finding
	for _, r := range allRules {
		matches := r.pattern.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			match := m[0]
			if r.group > 0 && r.group < len(m) {
				match = m[r.group]
			}
			if r.allow != nil && r.allow(file, match) {
				continue
			}
			out = append(out, finding{file: file, line: line, rule: r.id, match: match, why: r.description})
		}
	}
	return out
}

// gitPublishable lists the files a commit in the repository at root could
// carry: tracked files, and untracked files git does not ignore.
func gitPublishable(root string) (func(rel string) bool, error) {
	// root is the -root flag of whoever runs the check, passed as a single
	// argument with no shell, so it can only name a directory.
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard") //nolint:gosec // see comment above
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing publishable files with git ls-files in %s: %w "+
			"(run from a git checkout with git on PATH)", root, err)
	}
	files := map[string]bool{}
	for name := range strings.SplitSeq(string(out), "\x00") {
		if name != "" {
			files[name] = true
		}
	}
	return func(rel string) bool { return files[rel] }, nil
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	flag.Parse()
	publishable, err := gitPublishable(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "disclosurecheck: %v\n", err)
		os.Exit(1)
	}
	findings, cov, err := scan(os.DirFS(*root), ".", publishable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "disclosurecheck: %v\n", err)
		os.Exit(1)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "disclosurecheck: %d disclosure-shaped finding(s)\n\n", len(findings))
		for _, f := range findings {
			where := f.file
			if f.line > 0 {
				where = f.file + ":" + strconv.Itoa(f.line)
			}
			fmt.Fprintf(os.Stderr, "  [%s] %s\n      %q\n      %s\n\n", f.rule, where, f.match, f.why)
		}
		os.Exit(1)
	}
	fmt.Printf("disclosurecheck: ok (%d path(s), %d text file(s), %d line(s), %d byte(s) checked against %d rule(s))\n",
		cov.paths, cov.files, cov.lines, cov.bytes, len(allRules))
}
