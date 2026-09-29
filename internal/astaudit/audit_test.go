// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The tests below drive the whole of [Run] over a miniature source tree written
// into a temp directory. They are hermetic: they never read the real Union
// Station checkout, which is not present in CI, and they assert the mechanism
// rather than the figures. The figures over the real source are re-derived by
// running ./hack/astaudit, which is the point of shipping it.
//
// The fixture tree is shaped to give every population a non-zero denominator,
// because a row that cannot be derived from it would make these tests pass for
// the wrong reason.

// initGitRepo makes dir a clean git repository, because Run refuses to report a
// figure it cannot attribute to a commit. No network is involved.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not available: %v", err)
	}
	gitRun(t, dir, "init", "-q")
	gitCommitAll(t, dir)
}

// gitCommitAll commits everything in dir, so the tree is attributable to a
// commit -- which Run requires unless AllowDirty says otherwise.
func gitCommitAll(t *testing.T, dir string) {
	t.Helper()
	id := []string{"-c", "user.email=fixture@example.invalid", "-c", "user.name=fixture"}
	gitRun(t, dir, append(append([]string(nil), id...), "add", "-A")...)
	gitRun(t, dir, append(append([]string(nil), id...), "commit", "-q", "-m", "fixture")...)
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
}

// writeFixtureSource builds a miniature stand-in for the source backend:
// one module tree with an implementation, setters, guards, progress reports and
// a registry; one service layer that imports it; and two commands, one of which
// builds a registry.
func writeFixtureSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	w := func(rel, src string) { writeGo(t, filepath.Join(root, rel), src) }

	w("internal/database/db.go", "package database\n\ntype DB struct{}\n")

	w("internal/modules/registry.go", `package modules

type Registry struct{}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(m any) error { return nil }

func RegisterDefaults(r *Registry) {
	r.Register(nil)
	r.Register(nil)
}
`)

	w("internal/modules/types/types.go", `package types

func NewBaseModule(id, name, description, icon, category string) BaseModule {
	return BaseModule{}
}

type BaseModule struct{}
`)

	// One Module implementation: three parameters, two results, a nil-guard on a
	// setter-assigned field that returns, a Validate call, a progress report,
	// and a Result returned alongside a non-nil error.
	w("internal/modules/deploy/lambda.go", `package deploy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"example.com/x/internal/database"
	"example.com/x/internal/modules/types"
)

var _ = aws.Config{}
var _ = database.DB{}

type Mod struct {
	scanner   any
	persister any
}

func New() *Mod {
	_ = types.NewBaseModule("deploy-lambda", "Deploy", "d", "auto_fix_high", "Deployments")
	return &Mod{}
}

func (m *Mod) SetScanner(s any)   { m.scanner = s }
func (m *Mod) SetPersister(p any) { m.persister = p }

func (m *Mod) Validate(params map[string]any) error {
	return types.ValidateDeclaredParams(params)
}

func (m *Mod) Execute(ctx context.Context, userID string, params map[string]any) (*types.Result, error) {
	if m.scanner == nil {
		return nil, errNotConfigured
	}
	if err := m.Validate(params); err != nil {
		return nil, err
	}
	types.ReportProgress(ctx, 10, "starting")
	types.ReportProgress(ctx, step, "computed")
	types.ReportProgress(ctx, 10+5, "arithmetic")
	rec := map[string]string{"user": userID}
	_ = rec
	return &types.Result{Success: false}, nil
}

var errNotConfigured error
var step int
`)

	// A second implementation, so the E1 population is not a single case and the
	// "zero references to userID" class has a member.
	w("internal/modules/vendor/review.go", `package vendor

import (
	"context"

	"example.com/x/internal/modules/types"
)

type Mod struct{}

func New() *Mod {
	_ = types.NewBaseModule("vendor-review", "Review", "d", "business", "Governance")
	return &Mod{}
}

func (m *Mod) Execute(ctx context.Context, userID string, params map[string]any) (*types.Result, error) {
	return &types.Result{Success: true}, nil
}
`)

	w("internal/modules/paved/paved.go", `package paved

type Paved struct{}

func (p *Paved) Deploy() error   { return nil }
func (p *Paved) Deps() []string  { return nil }
func (p *Paved) Teardown() error { return nil }
`)

	// The service layer: imports the module tree, and calls Execute with the
	// Module arity, losing the partial Result on the error path.
	w("internal/services/svc.go", `package services

import (
	"context"

	"example.com/x/internal/modules"
)

var _ = modules.Registry{}

func Run(ctx context.Context, m Executor, params map[string]any) {
	result, err := m.Execute(ctx, "someone", params)
	if err != nil {
		return
	}
	_ = result
}

type Executor interface {
	Execute(ctx context.Context, userID string, params map[string]any) (any, error)
}
`)

	w("internal/services/other.go", `package services

import "example.com/x/internal/modules/types"

var _ = types.BaseModule{}

// A two-argument Execute, so E6's denominator is larger than its numerator --
// the discrimination the row claims to make.
func RenderTemplate(tpl interface{ Execute(a, b any) error }) error {
	return tpl.Execute(nil, nil)
}
`)

	w("cmd/runner/main.go", `package main

import (
	"context"

	"example.com/x/internal/modules"
)

func main() {
	r := modules.NewRegistry()
	_ = r
}

func run(ctx context.Context, m executor, params map[string]any) {
	_, execErr := m.Execute(ctx, "", params)
	if execErr != nil {
		return
	}
}

type executor interface {
	Execute(ctx context.Context, userID string, params map[string]any) (any, error)
}
`)

	w("cmd/other/main.go", "package main\n\nfunc main() {}\n")
	initGitRepo(t, root)
	return root
}

// writeFixtureTarget builds a stand-in for the target repository, whose only
// audited fact is the import-boundary rule set.
func writeFixtureTarget(t *testing.T, names ...string) string {
	t.Helper()
	root := t.TempDir()
	var b strings.Builder
	b.WriteString("package boundary\n\ntype Rule struct{ Name string }\n\ntype Config struct{ Rules []Rule }\n\nfunc DefaultConfig() Config {\n\treturn Config{\n\t\tRules: []Rule{\n")
	for _, n := range names {
		b.WriteString("\t\t\t{Name: \"" + n + "\"},\n")
	}
	b.WriteString("\t\t},\n\t}\n}\n")
	writeGo(t, filepath.Join(root, "internal/boundary/boundary.go"), b.String())
	initGitRepo(t, root)
	return root
}

func runFixture(t *testing.T, opts Options) (string, error) {
	t.Helper()
	if opts.SourceRoot == "" {
		opts.SourceRoot = writeFixtureSource(t)
	}
	if opts.TargetRoot == "" {
		opts.TargetRoot = writeFixtureTarget(t, "c1-optional", "ext-is-optional", "dynamodb-fenced")
	}
	var buf bytes.Buffer
	err := Run(&buf, opts)
	return buf.String(), err
}

// TestRunDerivesEveryRowTheDeclarationStates is the end-to-end half of the
// row-set contract, and it runs against the **shipped** declaration rather than
// a fixture one -- so a row added to evidence.go without a derivation, or a
// derivation deleted from audit.go, fails here in CI.
//
// The miniature source tree gives every population a non-zero denominator; the
// figures over it are not the real ones and are not asserted, because the
// figures are now output rather than something to be checked against a document.
func TestRunDerivesEveryRowTheDeclarationStates(t *testing.T) {
	t.Parallel()
	out, err := runFixture(t, Options{})
	if err != nil {
		t.Fatalf("audit failed over the fixture tree: %v\n%s", err, out)
	}
	got := emittedRowIDs(out)
	want := requiredRows()
	sort.Strings(got)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if strings.Join(got, " ") != strings.Join(sortedWant, " ") {
		t.Errorf("emitted rows\n got: %v\nwant: %v", got, sortedWant)
	}
	if !strings.Contains(out, "Every one of the 30 rows") {
		t.Errorf("completion does not state the row count:\n%s", out)
	}
}

// TestTheGeneratedTableCarriesTheDeclaredProseVerbatim. Claim and How are
// hand-authored and are attached to their row by construction -- the ID and its
// prose are the same literal -- so this asserts they reach the table unaltered.
func TestTheGeneratedTableCarriesTheDeclaredProseVerbatim(t *testing.T) {
	t.Parallel()
	out, err := runFixture(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range evidenceTable {
		line := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "| "+row.ID+" | ") {
				line = l
			}
		}
		if line == "" {
			t.Errorf("row %s is not in the generated table", row.ID)
			continue
		}
		if !strings.Contains(line, "| "+row.Claim+" |") {
			t.Errorf("row %s: claim not carried through verbatim:\n%s", row.ID, line)
		}
		if !strings.HasSuffix(line, "| "+row.How+" |") {
			t.Errorf("row %s: how not carried through verbatim:\n%s", row.ID, line)
		}
	}
}

// TestWritingThenCheckingTheArtifactRoundTrips, and
// TestAStaleArtifactIsFatal below, are the only check left over the document.
// It is a byte comparison: there is nothing to parse, so there is no grammar to
// disagree with a renderer about, which is the whole reason the Markdown scanner
// was deleted rather than fixed a sixth time.
func TestWritingThenCheckingTheArtifactRoundTrips(t *testing.T) {
	t.Parallel()
	src, tgt := writeFixtureSource(t), writeFixtureTarget(t, "a", "b", "c")
	path := filepath.Join(t.TempDir(), "evidence.md")

	if _, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt, Artifact: path}); err != nil {
		t.Fatalf("write: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) == 0 {
		t.Fatal("wrote an empty artifact")
	}
	out, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt, Artifact: path, Check: true})
	if err != nil {
		t.Fatalf("check of a freshly written artifact failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "matches the generated evidence table exactly") {
		t.Errorf("check did not confirm the match:\n%s", out)
	}
}

func TestAStaleArtifactIsFatal(t *testing.T) {
	t.Parallel()
	src, tgt := writeFixtureSource(t), writeFixtureTarget(t, "a", "b", "c")
	path := filepath.Join(t.TempDir(), "evidence.md")
	if _, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt, Artifact: path}); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, body string }{
		{"a figure edited by hand", strings.Replace(string(good), "| 2 / 2 |", "| 1 / 2 |", 1)},
		{"a row deleted", strings.Replace(string(good), "| E23 |", "| xx |", 1)},
		{"a trailing newline added", string(good) + "\n"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt, Artifact: path, Check: true})
			if err == nil {
				t.Fatal("a stale artifact was accepted")
			}
			if !strings.Contains(err.Error(), "stale") && !strings.Contains(err.Error(), "length") {
				t.Errorf("failure does not say the artifact is stale: %v", err)
			}
		})
	}
}

func TestCheckingAnAbsentArtifactIsFatal(t *testing.T) {
	t.Parallel()
	_, err := runFixture(t, Options{
		Artifact: filepath.Join(t.TempDir(), "missing.md"),
		Check:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("wanted a failure reading the absent artifact, got %v", err)
	}
}

// TestTheGeneratedTableIsMachineIndependent: the artifact records commits rather
// than the absolute paths of whoever ran the tool, so -check can be run
// somewhere else. Earlier artefacts had their paths edited out by hand before
// publication, which is a hand-maintained transformation of output and exactly
// the kind of step that goes wrong quietly.
func TestTheGeneratedTableIsMachineIndependent(t *testing.T) {
	t.Parallel()
	src, tgt := writeFixtureSource(t), writeFixtureTarget(t, "a")
	out, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt})
	if err != nil {
		t.Fatal(err)
	}
	for _, abs := range []string{src, tgt, os.TempDir()} {
		if strings.Contains(out, abs) {
			t.Errorf("the generated table contains the absolute path %q:\n%s", abs, out)
		}
	}
}

// TestARequiredInputIsNotDefaulted: neither root may fall back to the working
// directory, because a root that quietly became "wherever this ran from" is how
// a count stops being about the thing it names.
func TestARequiredInputIsNotDefaulted(t *testing.T) {
	t.Parallel()
	src, tgt := writeFixtureSource(t), writeFixtureTarget(t, "only-rule")
	for _, tc := range []struct {
		name string
		o    Options
	}{
		{"no source", Options{TargetRoot: tgt}},
		{"no target", Options{SourceRoot: src}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := Run(&buf, tc.o); err == nil {
				t.Error("wanted a failure, got success")
			}
		})
	}
}

// TestE28IsDerivedFromTheTargetRepository pins the decision that E28 is a real
// derivation rather than an exemption. It is a claim about the target, so a
// different target must give a different figure.
func TestE28IsDerivedFromTheTargetRepository(t *testing.T) {
	t.Parallel()
	src := writeFixtureSource(t)
	for _, n := range []int{1, 3, 5} {
		names := make([]string, n)
		for i := range names {
			names[i] = "rule-" + string(rune('a'+i))
		}
		out, err := runFixture(t, Options{SourceRoot: src, TargetRoot: writeFixtureTarget(t, names...)})
		if err != nil {
			t.Fatalf("%d rules: %v", n, err)
		}
		want := regexp.MustCompile(`(?m)^\| E28 \|.*\| ` + strconv.Itoa(n) + ` \|`)
		if !want.MatchString(out) {
			t.Errorf("E28 did not report %d rules:\n%s", n, out)
		}
	}
}

// TestATargetWithNoRuleSetFailsTheRun: an empty or absent rule set would be a
// row reporting zero, which for E28 is the absence of the population rather than
// a finding about it.
func TestATargetWithNoRuleSetFailsTheRun(t *testing.T) {
	t.Parallel()
	src := writeFixtureSource(t)

	t.Run("no Rules literal", func(t *testing.T) {
		t.Parallel()
		tgt := t.TempDir()
		writeGo(t, filepath.Join(tgt, "internal/boundary/boundary.go"), "package boundary\n")
		initGitRepo(t, tgt)
		_, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt})
		if err == nil || !strings.Contains(err.Error(), "found 0 Rules composite literals") {
			t.Errorf("wanted a failure naming the missing rule set, got %v", err)
		}
	})

	t.Run("empty Rules literal", func(t *testing.T) {
		t.Parallel()
		_, err := runFixture(t, Options{SourceRoot: src, TargetRoot: writeFixtureTarget(t)})
		if err == nil || !strings.Contains(err.Error(), "population is 0") {
			t.Errorf("wanted a failure on the empty rule set, got %v", err)
		}
	})

	t.Run("two Rules literals", func(t *testing.T) {
		t.Parallel()
		tgt := writeFixtureTarget(t, "a", "b")
		writeGo(t, filepath.Join(tgt, "internal/boundary/extra.go"),
			"package boundary\n\nvar other = Config{Rules: []Rule{{Name: \"c\"}}}\n")
		gitCommitAll(t, tgt)
		_, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt})
		if err == nil || !strings.Contains(err.Error(), "found 2 Rules composite literals") {
			t.Errorf("wanted a failure on the ambiguous rule set, got %v", err)
		}
	})
}

// TestADirtyTreeIsRefused. A commit hash describes a commit, not a working tree
// with edits on top of it. Reporting the dirtiness and carrying on would be a
// third outcome between "attributable" and "fatal".
func TestADirtyTreeIsRefused(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"source", "target"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			src := writeFixtureSource(t)
			tgt := writeFixtureTarget(t, "c1-optional", "ext-is-optional", "dynamodb-fenced")
			dirty := src
			if which == "target" {
				dirty = tgt
			}
			if err := os.WriteFile(filepath.Join(dirty, "uncommitted.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt})
			if err == nil {
				t.Fatalf("a dirty %s tree produced figures:\n%s", which, out)
			}
			for _, want := range []string{which, "uncommitted changes", "-allow-dirty"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("failure does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// TestAllowDirtyIsAnExplicitOverride: the escape hatch exists for local
// iteration, and when it is used the output still says the figures are not of a
// commit -- for either tree, including the target, whose revision is otherwise
// not printed at all.
func TestAllowDirtyIsAnExplicitOverride(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"source", "target"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			src := writeFixtureSource(t)
			tgt := writeFixtureTarget(t, "c1-optional", "ext-is-optional", "dynamodb-fenced")
			dirty := src
			if which == "target" {
				dirty = tgt
			}
			if err := os.WriteFile(filepath.Join(dirty, "uncommitted.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := runFixture(t, Options{SourceRoot: src, TargetRoot: tgt, AllowDirty: true})
			if err != nil {
				t.Fatalf("-allow-dirty did not permit the run: %v", err)
			}
			if !strings.Contains(out, "UNCOMMITTED CHANGES") {
				t.Errorf("a dirty %s tree left no trace in the output:\n%s", which, out)
			}
		})
	}
}

// TestTheTreesAreNamedInTheOutput: a figure without its tree is not a claim.
func TestTheTreesAreNamedInTheOutput(t *testing.T) {
	t.Parallel()
	out, err := runFixture(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The source is named by commit. The target is named by construction -- it
	// is the repository the artifact lives in -- because recording its commit
	// inside it would be self-referential.
	shas := regexp.MustCompile("`[0-9a-f]{40}`").FindAllString(out, -1)
	if len(shas) != 1 {
		t.Errorf("wanted exactly one commit hash, for the source, got %d:\n%s", len(shas), out)
	}
	if !strings.Contains(out, "this repository, at the commit containing this file") {
		t.Errorf("the target tree is not identified:\n%s", out)
	}
}

// TestFixtureOutput prints the fixture audit so a reader can see that the
// miniature tree exercises every row with a real population rather than passing
// on degenerate figures. Run with -v.
func TestFixtureOutput(t *testing.T) {
	t.Parallel()
	out, err := runFixture(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
}

var rowLine = regexp.MustCompile(`(?m)^\| (E[0-9]+[a-z]?) \|`)

func emittedRowIDs(out string) []string {
	var ids []string
	for _, m := range rowLine.FindAllStringSubmatch(out, -1) {
		ids = append(ids, m[1])
	}
	return ids
}
