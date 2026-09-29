// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests run against real module directories under testdata/union, not
// against synthetic graph values. The thing being tested is the resolver as much
// as the traversal: four rounds of review defeated this checker by making a file
// invisible to it, so a test that hands the logic a hand-written node set would
// prove the least interesting half.

// unionConfig builds a rule set scoped to a fixture module. The fixtures use
// example.com paths so they need no ConductorOne-shaped names and no replace
// directive pointing back into this repository.
func unionConfig(modulePrefix, denied string, allowed ...string) Config {
	return Config{
		ModulePrefix: modulePrefix,
		Rules: []Rule{{
			Name:            "fixture",
			Reason:          "fixture rule",
			DeniedPrefixes:  []string{denied},
			AllowedPrefixes: allowed,
		}},
	}
}

const (
	basicFixture = "testdata/union/basic"
	basicModule  = "example.com/unionbasic"
	deniedPrefix = "example.com/unionwrapper/forbidden"
)

func judgeBasicFixture(t *testing.T) *Findings {
	t.Helper()
	u, err := LoadUnion(basicFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	cfg := unionConfig(basicModule, deniedPrefix, basicModule+"/provider")
	f, err := u.Judge(cfg)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the run judged every root, so Validate should pass: %v", err)
	}
	return f
}

// wantViolation is the shape a fixture case expects. Every field is asserted, so
// a finding that is right about the package and wrong about which line to delete
// still fails.
type wantViolation struct {
	imported   string
	kind       ImportKind
	via        []string
	rootFile   string
	introducer string
	// chainFiles is the declaring file of every hop, in order.
	chainFiles []string
}

// The acceptance cases that are about what the union graph contains, run against
// one load of one fixture module.
func TestUnionGraphFindings(t *testing.T) {
	t.Parallel()
	findings := judgeBasicFixture(t)

	byRoot := map[string][]Violation{}
	for _, v := range findings.Violations() {
		byRoot[v.Package] = append(byRoot[v.Package], v)
	}

	const wrapper = "example.com/unionwrapper"
	viaWrapper := func(rootFile string) []wantViolation {
		return []wantViolation{{
			imported: deniedPrefix, kind: KindBuild, via: []string{wrapper},
			rootFile: rootFile, introducer: wrapper,
			chainFiles: []string{rootFile, "wrapper/wrapper.go"},
		}}
	}

	cases := []struct {
		name string
		root string
		want []wantViolation
	}{
		{
			// (1) direct, aliased, blank, and dot imports. Rewriting the form of
			// an import must not change the answer.
			name: "every import form",
			root: basicModule + "/importstyles",
			want: []wantViolation{
				{imported: deniedPrefix + "/aliased", kind: KindBuild, rootFile: "importstyles/importstyles.go",
					introducer: basicModule + "/importstyles", chainFiles: []string{"importstyles/importstyles.go"}},
				{imported: deniedPrefix + "/blank", kind: KindBuild, rootFile: "importstyles/importstyles.go",
					introducer: basicModule + "/importstyles", chainFiles: []string{"importstyles/importstyles.go"}},
				{imported: deniedPrefix + "/direct", kind: KindBuild, rootFile: "importstyles/importstyles.go",
					introducer: basicModule + "/importstyles", chainFiles: []string{"importstyles/importstyles.go"}},
				{imported: deniedPrefix + "/dotted", kind: KindBuild, rootFile: "importstyles/importstyles.go",
					introducer: basicModule + "/importstyles", chainFiles: []string{"importstyles/importstyles.go"}},
			},
		},
		{
			// (2) in-package and external test imports of a first-party package,
			// reported against that package with the right kind.
			name: "test imports in the main module",
			root: basicModule + "/tested",
			want: []wantViolation{
				{imported: deniedPrefix + "/exttest", kind: KindExternalTest, rootFile: "tested/tested_ext_test.go",
					introducer: basicModule + "/tested", chainFiles: []string{"tested/tested_ext_test.go"}},
				{imported: deniedPrefix + "/intest", kind: KindTest, rootFile: "tested/tested_test.go",
					introducer: basicModule + "/tested", chainFiles: []string{"tested/tested_test.go"}},
			},
		},
		// (3) the denied import is carried by a third-party wrapper; nothing in
		// the main module names it.
		{"third-party wrapper carries it", basicModule + "/viawrapper", viaWrapper("viawrapper/viawrapper.go")},
		// (4) and (5): reached only from a *_windows.go or *_arm64.go file.
		{"windows-only file", basicModule + "/winonly", viaWrapper("winonly/winonly_windows.go")},
		{"arm64-only file", basicModule + "/armonly", viaWrapper("armonly/armonly_arm64.go")},
		// (6) an invented tag, a nested negation, a disjunction of unsupported
		// platforms, and //go:build ignore. None of them changes anything, which
		// is the whole point of the new primitive.
		{"custom tag", basicModule + "/tag_custom", viaWrapper("tag_custom/tagged.go")},
		{"nested negation", basicModule + "/tag_nested", viaWrapper("tag_nested/tagged.go")},
		{"disjunction of unsupported platforms", basicModule + "/tag_or", viaWrapper("tag_or/tagged.go")},
		{"build ignore", basicModule + "/tag_ignore", viaWrapper("tag_ignore/tagged.go")},
		{
			// (7) the chain crosses a module that exists only because of a local
			// replace directive, so its files are nowhere near the module cache.
			name: "local replace module",
			root: basicModule + "/vialocal",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild, via: []string{"example.com/unionlocal"},
				rootFile: "vialocal/vialocal.go", introducer: "example.com/unionlocal",
				chainFiles: []string{"vialocal/vialocal.go", "local/local.go"},
			}},
		},
		// (9), second half: a root that is not allowed reaches the same wrapper
		// the allowed provider does, and is reported.
		{"unallowed root through the provider's wrapper", basicModule + "/consumer", viaWrapper("consumer/consumer.go")},
		// (9), first half: the allowed root may reach the denied package both
		// directly and through the wrapper.
		{"allowed provider root", basicModule + "/provider", nil},
		// (10) a dependency's *test* file imports the denied package.
		// `go test ./...` never compiles it, so this is not a path.
		{"dependency test imports do not taint a consumer", basicModule + "/viaclean", nil},
		{
			// A module path with uppercase letters, which the module cache escapes
			// ("!union!mixed!case"). The resolver uses Go's reported Dir, so this
			// resolves; one that built cache paths by hand would see nothing.
			name: "module path the cache escapes",
			root: basicModule + "/viamixed",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild, via: []string{"example.com/UnionMixedCase"},
				rootFile: "viamixed/viamixed.go", introducer: "example.com/UnionMixedCase",
				chainFiles: []string{"viamixed/viamixed.go", "mixedcase/mixedcase.go"},
			}},
		},
		{
			// A cgo package. Every compatibility configuration sets CGO_ENABLED=0,
			// so a file importing "C" is excluded from all of them and no concrete
			// graph contains this package's imports at all. The union reads it
			// anyway -- which is the whole thesis, tested rather than asserted.
			name: "cgo package no concrete configuration compiles",
			root: basicModule + "/cgocall",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild, rootFile: "cgocall/cgocall.go",
				introducer: basicModule + "/cgocall",
				chainFiles: []string{"cgocall/cgocall.go"},
			}},
		},
		{
			// Bypass seventeen, the reviewer's fixture: a directory *named* vendor
			// is an ordinary package -- the go command excludes only what is
			// beneath a vendor element -- and the constraint hid it from every
			// concrete build as well.
			name: "package in a directory named vendor",
			root: basicModule + "/cmd/vendor",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild,
				rootFile: "cmd/vendor/hidden.go", introducer: basicModule + "/cmd/vendor",
				chainFiles: []string{"cmd/vendor/hidden.go"},
			}},
		},
		{
			// Beneath a vendor element: `go list ./...` from the root does not
			// reach it, `go list ./cmd/vendor/...` does. Enumerated either way --
			// over-approximating costs a false positive, under-approximating costs
			// a silent hole, and this checker has paid the second price twice.
			name: "package beneath a vendor element",
			root: basicModule + "/cmd/vendor/sub",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild,
				rootFile: "cmd/vendor/sub/sub.go", introducer: basicModule + "/cmd/vendor/sub",
				chainFiles: []string{"cmd/vendor/sub/sub.go"},
			}},
		},
		{
			// Bypass sixteen: a directory that resembles build output but that the
			// go command has no rule for, with the import also behind an uncovered
			// constraint. Every view missed this at once until the walkers were
			// aligned to the go command's actual ignore list.
			name: "package parked in a directory that only looks ignorable",
			root: basicModule + "/node_modules/parked",
			want: []wantViolation{{
				imported: deniedPrefix, kind: KindBuild,
				rootFile: "node_modules/parked/tagged.go", introducer: basicModule + "/node_modules/parked",
				chainFiles: []string{"node_modules/parked/tagged.go"},
			}},
		},
		{
			// A //go:generate directive naming the denied package. It does nothing
			// during a build, so it is not an import edge -- over-approximating to
			// *this* would be over-approximating into comments.
			name: "go:generate directive is not an import edge",
			root: basicModule + "/generated",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := byRoot[tc.root]
			if len(got) != len(tc.want) {
				t.Fatalf("got %d violation(s) for %s, want %d: %v", len(got), tc.root, len(tc.want), got)
			}
			for i, want := range tc.want {
				v := got[i]
				if v.Import != want.imported {
					t.Errorf("violation %d: import = %s, want %s", i, v.Import, want.imported)
				}
				if v.Kind != want.kind {
					t.Errorf("violation %d: kind = %s, want %s", i, v.Kind, want.kind)
				}
				if strings.Join(v.Via, ",") != strings.Join(want.via, ",") {
					t.Errorf("violation %d: via = %v, want %v", i, v.Via, want.via)
				}
				if v.File != want.rootFile {
					t.Errorf("violation %d: file = %s, want %s", i, v.File, want.rootFile)
				}
				if v.Line == 0 {
					t.Errorf("violation %d: no line to point at", i)
				}
				if v.Introducer != want.introducer {
					t.Errorf("violation %d: introducer = %s, want %s", i, v.Introducer, want.introducer)
				}
				var chainFiles []string
				for _, hop := range v.Chain {
					if hop.Line == 0 {
						t.Errorf("violation %d: hop %s -> %s has no line", i, hop.From, hop.To)
					}
					chainFiles = append(chainFiles, hop.File)
				}
				if strings.Join(chainFiles, ",") != strings.Join(want.chainFiles, ",") {
					t.Errorf("violation %d: chain files = %v, want %v", i, chainFiles, want.chainFiles)
				}
			}
		})
	}

	// Nothing outside the table: a fixture that grew a package nobody asserted
	// on would otherwise pass silently.
	counted := 0
	for _, tc := range cases {
		counted += len(tc.want)
	}
	if got := len(findings.Violations()); got != counted {
		t.Errorf("the fixture produced %d violation(s) and the table accounts for %d; "+
			"unaccounted findings: %v", got, counted, findings.Violations())
	}
}

// (8) An import the union cannot resolve is fatal, with the file and line that
// declared it. A graph with a hole in it has not been checked, and the whole
// class of defect this package keeps hitting is reporting success over something
// unexamined.
func TestUnresolvableImportFailsClosedWithPosition(t *testing.T) {
	t.Parallel()
	u, err := LoadUnion("testdata/union/unresolvable")
	if err != nil {
		t.Fatalf("LoadUnion should parse the tree; resolution happens during the walk: %v", err)
	}
	_, err = u.Judge(unionConfig("example.com/unionunresolvable", deniedPrefix))
	if err == nil {
		t.Fatal("an unresolvable import must fail the run, not be skipped")
	}
	var unresolved *UnresolvedImportError
	if !errors.As(err, &unresolved) {
		t.Fatalf("want *UnresolvedImportError, got %T: %v", err, err)
	}
	if unresolved.File != "pkg/pkg.go" || unresolved.Line == 0 {
		t.Errorf("the error must name the declaring file and line, got %s:%d", unresolved.File, unresolved.Line)
	}
	if unresolved.From != "example.com/unionunresolvable/pkg" {
		t.Errorf("from = %s", unresolved.From)
	}
	for _, want := range []string{"no-such-module-exists-anywhere", "pkg/pkg.go"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q should contain %q", err, want)
		}
	}
}

// (11) A tracked vendor tree is refused. The bypass it closes is real: with
// vendor/ present the toolchain compiles the vendored copy of a dependency while
// a module-cache resolver reads a different one, so the graph being proved about
// is not the graph being built.
func TestTrackedVendorTreeIsRejected(t *testing.T) {
	t.Parallel()
	_, err := LoadUnion("testdata/union/vendored")
	if err == nil {
		t.Fatal("a vendor tree must be refused until there is a vendoring mode")
	}
	for _, want := range []string{"vendor", "no vendoring mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q should contain %q", err, want)
		}
	}
	// And the refusal has to come before any judgement, or the check could
	// report that the rules held over the wrong tree.
	if strings.Contains(err.Error(), "held") {
		t.Errorf("nothing may be endorsed: %v", err)
	}
}

// A malformed build constraint is fatal. It must never resolve to "treat the
// file as absent", which is the shape of every bypass this checker has suffered.
func TestMalformedBuildConstraintIsFatal(t *testing.T) {
	t.Parallel()
	_, err := LoadUnion("testdata/union/malformed")
	if err == nil {
		t.Fatal("a constraint the checker cannot parse must fail the run")
	}
	for _, want := range []string{"malformed build constraint", "pkg/pkg.go"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q should contain %q", err, want)
		}
	}
}

// (12) The mutation test, and the point of the whole ticket: adding a forbidden
// edge behind *any* build expression produces the same finding. If this ever
// stops holding, the checker has gone back to caring which configurations exist.
func TestBuildExpressionCannotChangeTheUnionFinding(t *testing.T) {
	t.Parallel()
	expressions := []struct {
		name      string
		buildExpr string
	}{
		{"no constraint", ""},
		{"invented tag", "//go:build mutationtag"},
		{"nested negation", "//go:build !(linux || darwin) && !windows"},
		{"disjunction", "//go:build plan9 || js || wasip1"},
		{"never satisfied", "//go:build ignore"},
		{"impossible conjunction", "//go:build linux && !linux"},
		{"future release", "//go:build go1.99"},
		{"legacy plus-build", "// +build zos"},
		{"architecture feature", "//go:build arm64 && !amd64"},
	}

	var baseline string
	for _, tc := range expressions {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t, basicFixture)
			mutant := filepath.Join(dir, "mutant")
			if err := os.MkdirAll(mutant, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			source := "package mutant\n\nimport _ \"example.com/unionwrapper\"\n"
			if tc.buildExpr != "" {
				// Both constraint forms need the blank line the toolchain
				// requires before the package clause.
				source = tc.buildExpr + "\n\n" + source
			}
			if err := os.WriteFile(filepath.Join(mutant, "mutant.go"), []byte(source), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			u, err := LoadUnion(dir)
			if err != nil {
				t.Fatalf("LoadUnion: %v", err)
			}
			f, err := u.Judge(unionConfig(basicModule, deniedPrefix, basicModule+"/provider"))
			if err != nil {
				t.Fatalf("Judge: %v", err)
			}
			var found []Violation
			for _, v := range f.Violations() {
				if v.Package == basicModule+"/mutant" {
					found = append(found, v)
				}
			}
			if len(found) != 1 {
				t.Fatalf("got %d finding(s) for the mutated package, want 1: %v", len(found), found)
			}
			v := found[0]
			if v.Import != deniedPrefix || v.Kind != KindBuild ||
				len(v.Via) != 1 || v.Via[0] != "example.com/unionwrapper" {
				t.Errorf("the finding depends on the build expression: %+v", v)
			}
			// The position must be right, not merely stable: a constraint comment
			// moves the import down the file, and that is the only thing about
			// the finding any build expression is allowed to change.
			if want := importLine(source); v.Line != want {
				t.Errorf("line = %d, want the line the import is actually on (%d)", v.Line, want)
			}
			rendered := lineNumbers.ReplaceAllString(v.String(), ":L")
			if baseline == "" {
				baseline = rendered
			} else if rendered != baseline {
				t.Errorf("build expression changed the finding:\n  %s\nwant:\n  %s", rendered, baseline)
			}
		})
	}
}

// lineNumbers matches the ":123" of a file position.
var lineNumbers = regexp.MustCompile(`:\d+`)

// importLine reports which line of a generated fixture file declares the import,
// so the mutation test can check the position is right rather than merely stable.
func importLine(source string) int {
	for i, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, "import ") {
			return i + 1
		}
	}
	return 0
}

// copyFixture copies a fixture module tree, including its nested replace-target
// modules, into a temporary directory so a test can mutate it.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatalf("copying %s: %v", src, err)
	}
	return dst
}

// The differential invariant: every edge a real build graph reports must already
// be in the union. This is what makes the concrete targets worth keeping -- they
// are no longer the proof, they are the check on the proof's resolver.
func TestEveryConcreteGraphEdgeExistsInTheUnion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		dir  string
	}{
		{"the fixture with every hiding place in it", basicFixture},
		// A module whose forbidden import only exists on Windows: the interesting
		// direction, because the union has to contain an edge the Linux graph
		// never reports and the Windows graph does.
		{"a platform-specific module", "testdata/tagged"},
		// The repository itself.
		{"this repository", "../.."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := LoadUnion(tc.dir)
			if err != nil {
				t.Fatalf("LoadUnion(%s): %v", tc.dir, err)
			}
			for _, target := range []Target{
				{GOOS: "linux", GOARCH: "amd64"},
				{GOOS: "windows", GOARCH: "arm64"},
				{GOOS: "darwin", GOARCH: "arm64"},
			} {
				graph, loadErr := u.LoadGraph(target)
				if loadErr != nil {
					t.Fatalf("LoadGraph(%s): %v", target, loadErr)
				}
				missing, diffErr := u.Differential(graph)
				if diffErr != nil {
					t.Fatalf("Differential(%s): %v", target, diffErr)
				}
				if len(missing) > 0 {
					t.Errorf("%d edge(s) reported by %s are absent from the union graph, so the "+
						"resolver missed a toolchain behaviour: %v", len(missing), target, missing)
				}
			}
		})
	}
}

// The windows fixture, from the other direction: the union must contain the edge
// that only a Windows build selects, and the Linux graph must not -- otherwise
// the test above would pass vacuously.
func TestUnionContainsEdgesNoLinuxBuildSelects(t *testing.T) {
	t.Parallel()
	const dir = "testdata/tagged"
	cfg := unionConfig("example.com/tagged", "example.com/tagged/forbidden")

	linux, err := unionFor(t, dir).LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if got := cfg.CheckGraph(linux.Nodes(), "linux"); len(got) != 0 {
		t.Fatalf("precondition: a Linux build cannot see this import, got %v", got)
	}

	u, err := LoadUnion(dir)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	f, err := u.Judge(cfg)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	got := f.Violations()
	if len(got) != 1 {
		t.Fatalf("got %d violation(s), want 1: %v", len(got), got)
	}
	if got[0].File != "deploy/deploy_windows.go" || got[0].Line == 0 {
		t.Errorf("the finding must name the file and line, got %+v", got[0])
	}
}

// Evidence cannot be assembled by a caller. The previous design had this seam
// documented rather than closed -- Coverage.Complete took a package count on
// trust -- and closing it here is the lesson docs/decisions/ records: prefer a
// type that cannot express a violation over a check that notices one.
func TestUnionEvidenceCannotBeFabricated(t *testing.T) {
	t.Parallel()

	var zeroFindings Findings
	if err := zeroFindings.Validate(); err == nil {
		t.Error("a zero Findings must endorse nothing")
	}
	if got := zeroFindings.Violations(); got != nil {
		t.Errorf("a zero Findings has no violations to report, got %v", got)
	}

	var zeroUnion Union
	if _, err := zeroUnion.Judge(unionConfig(basicModule, deniedPrefix)); err == nil {
		t.Error("a zero Union must refuse to judge anything")
	}
	if _, err := zeroUnion.Differential(&Graph{}); err == nil {
		t.Error("a zero Union must refuse to run a differential")
	}

	u, err := LoadUnion(basicFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	// A Graph a caller assembled is not evidence about a build configuration.
	if _, err := u.Differential(&Graph{}); err == nil {
		t.Error("a Graph that LoadGraph did not produce must be refused")
	}
	if _, err := u.Differential(nil); err == nil {
		t.Error("a nil Graph must be refused")
	}
	cov := u.NewCoverage([]Target{{GOOS: "linux", GOARCH: "amd64"}})
	if err := cov.Complete(&Graph{}); err == nil {
		t.Error("Coverage must refuse a fabricated Graph")
	}
	if err := cov.Validate(); err == nil {
		t.Error("Coverage with no completions must not validate")
	}
	// A zero Union cannot mint a graph either, so the foreign-graph attack has no
	// starting point that does not name a real tree.
	if _, err := zeroUnion.LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"}); err == nil {
		t.Error("a zero Union must refuse to load a graph")
	}
}

// Provenance, at the level of the package's own types: a graph is stamped with
// the resolved directory it came from, and every evidence path checks it.
//
// This is the sixth appearance of "success reported over something not examined".
// The previous five were closed by making the *claim* unrepresentable; this one is
// closed by removing the *input*, because there is no exported way to load a
// dependency graph for a directory of the caller's choosing. What remains here is
// the guard for the one shape still expressible -- two unions of two trees -- and
// the assertion that the identity used is the resolved path, since the attack
// worked by making the declared module path match.
func TestGraphProvenanceIsBoundToTheUnionModuleRoot(t *testing.T) {
	t.Parallel()
	ours, err := LoadUnion(basicFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}

	// A separate module declaring the *same* module path, with a single empty
	// package. Everything a name can carry matches; only the directory differs.
	foreignDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreignDir, "go.mod"),
		[]byte("module "+basicModule+"\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(foreignDir, "importstyles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignDir, "importstyles", "importstyles.go"),
		[]byte("package importstyles\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	foreign, err := LoadUnion(foreignDir)
	if err != nil {
		t.Fatalf("LoadUnion(foreign): %v", err)
	}
	if foreign.MainModule().Path != ours.MainModule().Path {
		t.Fatalf("precondition: both modules must declare the same path, got %q and %q",
			foreign.MainModule().Path, ours.MainModule().Path)
	}
	if foreign.ModuleDir() == ours.ModuleDir() {
		t.Fatal("precondition: the two directories must differ")
	}

	target := Target{GOOS: "linux", GOARCH: "amd64"}
	foreignGraph, err := foreign.LoadGraph(target)
	if err != nil {
		t.Fatalf("LoadGraph(foreign): %v", err)
	}
	if foreignGraph.Root() != foreign.ModuleDir() {
		t.Errorf("graph root = %q, want the directory it was loaded from %q",
			foreignGraph.Root(), foreign.ModuleDir())
	}

	// The differential: refused, rather than passing because an empty edge set is
	// trivially a subgraph.
	if _, err := ours.Differential(foreignGraph); err == nil {
		t.Error("the differential must refuse a graph from another directory")
	}
	// The accounting: refused.
	cov := ours.NewCoverage([]Target{target})
	err = cov.Complete(foreignGraph)
	if err == nil {
		t.Fatal("a graph loaded from another directory must not count as coverage")
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("the refusal should name the reason, got %v", err)
	}
	if err := cov.Validate(); err == nil {
		t.Error("nothing was completed, so nothing may validate")
	}

	// The endorsement: refused for a judgement of the other tree, even when the
	// coverage itself is complete.
	realGraph, err := ours.LoadGraph(target)
	if err != nil {
		t.Fatalf("LoadGraph(ours): %v", err)
	}
	good := ours.NewCoverage([]Target{target})
	if err := good.Complete(realGraph); err != nil {
		t.Fatalf("the ours graph must be accepted: %v", err)
	}
	foreignCfg := unionConfig(foreign.MainModule().Path, deniedPrefix, basicModule+"/provider")
	foreignFindings, err := foreign.Judge(foreignCfg)
	if err != nil {
		t.Fatalf("Judge(foreign): %v", err)
	}
	if _, err := good.Endorse(foreignCfg, foreignFindings); err == nil {
		t.Error("a judgement of another tree must not endorse this run")
	}

	// And the honest pairing still passes, or the checks above would be satisfied
	// by something that never succeeds.
	realFindings, err := ours.Judge(unionConfig(basicModule, "example.com/nothing-imports-this"))
	if err != nil {
		t.Fatalf("Judge(ours): %v", err)
	}
	summary, err := good.Endorse(unionConfig(basicModule, "example.com/nothing-imports-this"), realFindings)
	if err != nil {
		t.Fatalf("matching evidence must be endorsable: %v", err)
	}
	for _, want := range []string{basicModule, "first-party package(s)", target.String()} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary should evidence %q, got %q", want, summary)
		}
	}
}

// A module prefix that is not the main module would silently judge nothing: no
// package matches it, so every rule holds vacuously. That is a false success, so
// it is an error instead.
func TestJudgeRejectsAModulePrefixThatIsNotTheMainModule(t *testing.T) {
	t.Parallel()
	u, err := LoadUnion(basicFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	for _, prefix := range []string{"", "example.com/somewhere-else", basicModule + "/importstyles"} {
		cfg := unionConfig(prefix, deniedPrefix)
		if _, err := u.Judge(cfg); err == nil {
			t.Errorf("module prefix %q is not the main module and must be refused", prefix)
		}
	}
	if _, err := u.Judge(Config{ModulePrefix: basicModule}); err == nil {
		t.Error("a run with no rules enforces nothing and must be refused")
	}
}

// The union graph must contain every first-party package as a root, including
// ones with no imports at all -- a package that is never judged is a package
// whose imports were never read.
func TestUnionRootsAreEveryFirstPartyPackage(t *testing.T) {
	t.Parallel()
	u, err := LoadUnion(basicFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	want := []string{
		basicModule,
		basicModule + "/armonly",
		basicModule + "/cgocall",
		basicModule + "/cmd/vendor",
		basicModule + "/cmd/vendor/sub",
		basicModule + "/consumer",
		basicModule + "/generated",
		basicModule + "/importstyles",
		basicModule + "/node_modules/parked",
		basicModule + "/provider",
		basicModule + "/tag_custom",
		basicModule + "/tag_ignore",
		basicModule + "/tag_nested",
		basicModule + "/tag_or",
		basicModule + "/tested",
		basicModule + "/viaclean",
		basicModule + "/vialocal",
		basicModule + "/viamixed",
		basicModule + "/viawrapper",
		basicModule + "/winonly",
	}
	got := u.Roots()
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("roots =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The nested replace-target modules are not first-party: they are governed
	// by their own go.mod and judged as dependencies.
	for _, root := range got {
		if strings.HasSuffix(root, "/wrapper") || strings.HasSuffix(root, "/local") ||
			strings.HasSuffix(root, "/mixedcase") {
			t.Errorf("a nested module must not be judged as a first-party root: %s", root)
		}
	}
}
