// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These are the two bypasses review used to defeat the previous version of this
// checker, reproduced end to end against real module trees under testdata and
// the real loaders. The unit tests above prove the logic; these prove the
// loaders actually hand that logic enough to work with.

// unionFor loads a fixture module's union graph, which is now the only route to a
// dependency graph: LoadGraph is a method on Union so that a graph's provenance
// is always the module directory the union was built from. Review defeated the
// earlier free function by loading a real graph from a *different* module that
// declared the same path, so there is deliberately no way to ask for a graph by
// directory any more.
func unionFor(t *testing.T, dir string) *Union {
	t.Helper()
	u, err := LoadUnion(dir)
	if err != nil {
		t.Fatalf("LoadUnion(%s): %v", dir, err)
	}
	return u
}

// matrixTargets is the fixture's build matrix: the real one, so a fixture that
// passes here would pass in the repository too.
func matrixTargets(cfg Config) []Target { return cfg.Targets() }

// fixtureConfig builds a rule set scoped to a fixture module, so the fixtures
// need no ConductorOne-shaped names and no replace directive pointing back into
// this repository.
func fixtureConfig(modulePrefix, denied string, allowed ...string) Config {
	return Config{
		ModulePrefix: modulePrefix,
		GOOS:         DefaultGOOS,
		GOARCH:       DefaultGOARCH,
		ReleaseTags:  DefaultReleaseTags(),
		Rules: []Rule{{
			Name:            "fixture",
			Reason:          "fixture rule",
			DeniedPrefixes:  []string{denied},
			AllowedPrefixes: allowed,
		}},
	}
}

// Bypass one: no file in the module declares the forbidden import. It arrives
// through a third-party package, so a check that reads declared imports sees a
// clean tree.
func TestEndToEndTransitiveDependencyThroughThirdPartyModule(t *testing.T) {
	t.Parallel()
	const dir = "testdata/transitive"
	cfg := fixtureConfig("example.com/fixture", "example.com/wrapper/forbidden", "example.com/fixture/allowed")

	// First, the shape of the bypass: reading declared imports finds nothing.
	files, err := ScanFiles(dir, "example.com/fixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if got := cfg.CheckFiles(files); len(got) != 0 {
		t.Fatalf("precondition: no file in this fixture declares the forbidden import, got %v", got)
	}

	// The closure sees it.
	nodes, err := unionFor(t, dir).LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	got := cfg.CheckGraph(nodes.Nodes(), "linux")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	v := got[0]
	if v.Package != "example.com/fixture/consumer" {
		t.Errorf("package = %s, want example.com/fixture/consumer", v.Package)
	}
	if v.Import != "example.com/wrapper/forbidden" {
		t.Errorf("import = %s", v.Import)
	}
	if len(v.Via) != 1 || v.Via[0] != "example.com/wrapper" {
		t.Errorf("via = %v, want the wrapper that carried it in", v.Via)
	}
}

// The same fixture proves the allowlist still works through a chain: the
// allowed package reaches the forbidden one directly and is not reported.
func TestEndToEndAllowedPackageMayReachForbidden(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig("example.com/fixture", "example.com/wrapper/forbidden", "example.com/fixture/allowed")
	nodes, err := unionFor(t, "testdata/transitive").LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	for _, v := range cfg.CheckGraph(nodes.Nodes(), "linux") {
		if v.Package == "example.com/fixture/allowed" {
			t.Fatalf("the allowed package must not be reported: %v", v)
		}
	}
}

// Bypass two: the forbidden import is in a file the Linux build never selects.
func TestEndToEndBuildTaggedImportIsInvisibleToOneTargetAndCaughtAnyway(t *testing.T) {
	t.Parallel()
	const dir = "testdata/tagged"
	cfg := fixtureConfig("example.com/tagged", "example.com/tagged/forbidden")

	// The shape of the bypass: on Linux, the dependency does not exist.
	linux, err := unionFor(t, dir).LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph(linux): %v", err)
	}
	if got := cfg.CheckGraph(linux.Nodes(), "linux"); len(got) != 0 {
		t.Fatalf("precondition: a Linux build target cannot see this import, got %v", got)
	}

	// Every Go file, build constraints ignored: caught, with a line to delete.
	files, err := ScanFiles(dir, "example.com/tagged")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	got := cfg.CheckFiles(files)
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if got[0].File != "deploy/deploy_windows.go" || got[0].Line == 0 {
		t.Errorf("finding should name the file and line, got %+v", got[0])
	}

	// And the closure catches it too, on the target that does compile it.
	windows, err := unionFor(t, dir).LoadGraph(Target{GOOS: "windows", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph(windows): %v", err)
	}
	if got := cfg.CheckGraph(windows.Nodes(), "windows"); len(got) != 1 {
		t.Fatalf("windows closure: got %d violations, want 1: %v", len(got), got)
	}
}

func TestScanFilesSkipsNestedModulesAndTestdata(t *testing.T) {
	t.Parallel()
	files, err := ScanFiles("testdata/transitive", "example.com/fixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	for _, f := range files {
		if f.File == "wrapper/wrapper.go" {
			t.Errorf("a nested module is governed by its own go.mod, not ours: %+v", f)
		}
	}
	if len(files) == 0 {
		t.Fatal("scanned nothing, which would make this check vacuous")
	}
}

func TestScanFilesClassifiesTestFiles(t *testing.T) {
	t.Parallel()
	// Scan this package's own directory: it contains source and in-package
	// tests, so the classifier has something real to get right.
	files, err := ScanFiles(".", DefaultModulePrefix+"/internal/boundary")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	var sawBuild, sawTest bool
	for _, f := range files {
		switch f.Kind {
		case KindBuild:
			sawBuild = true
		case KindTest:
			sawTest = true
		case KindExternalTest:
		}
		if f.Package != DefaultModulePrefix+"/internal/boundary" {
			t.Errorf("package path = %s", f.Package)
		}
	}
	if !sawBuild || !sawTest {
		t.Errorf("expected both source and test files, got build=%v test=%v", sawBuild, sawTest)
	}
}

// Bypass three, from the second review: a dependency behind a *custom* build
// tag evades both of the earlier fixes at once. The file view is shallow and
// sees only the wrapper; the closure is deep but enumerates GOOS values and
// cannot enumerate a tag somebody invented.
func TestEndToEndCustomBuildTagHidesATransitiveDependency(t *testing.T) {
	t.Parallel()
	const dir = "testdata/tagged-transitive"
	cfg := fixtureConfig("example.com/tagfixture", "example.com/tagwrapper/forbidden")

	files, err := ScanFiles(dir, "example.com/tagfixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}

	// The shape of the bypass, part one: nothing in the tree declares the
	// forbidden import, so the file view is clean.
	if got := cfg.CheckFiles(files); len(got) != 0 {
		t.Fatalf("precondition: the file view is shallow and should see nothing, got %v", got)
	}
	// Part two: with the tag off, the dependency is not in the graph either.
	for _, target := range matrixTargets(cfg) {
		nodes, loadErr := unionFor(t, dir).LoadGraph(target)
		if loadErr != nil {
			t.Fatalf("LoadGraph(%s): %v", target, loadErr)
		}
		if got := cfg.CheckGraph(nodes.Nodes(), target.GOOS); len(got) != 0 {
			t.Fatalf("precondition: %s cannot see a customtag file, got %v", target, got)
		}
	}

	// The fix: an undeclared tag is itself the violation.
	tagFindings := cfg.CheckBuildTags(files)
	if len(tagFindings) != 1 {
		t.Fatalf("got %d build-tag findings, want 1: %v", len(tagFindings), tagFindings)
	}
	if tagFindings[0].Tag != "customtag" {
		t.Errorf("tag = %q, want customtag", tagFindings[0].Tag)
	}
	if tagFindings[0].File != "consumer/consumer_tagged.go" || tagFindings[0].Line == 0 {
		t.Errorf("finding should name the file and line, got %+v", tagFindings[0])
	}
}

// Declaring a tag must not be a way to opt out of the check: a declared tag is
// one the closure then actually looks through. This is the other half of the
// fix, and the half that would rot silently if nothing tested it.
func TestDeclaringABuildTagMakesTheClosureLookThroughIt(t *testing.T) {
	t.Parallel()
	const dir = "testdata/tagged-transitive"
	cfg := fixtureConfig("example.com/tagfixture", "example.com/tagwrapper/forbidden")
	cfg.AllowedBuildTags = []string{"customtag"}

	files, err := ScanFiles(dir, "example.com/tagfixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if got := cfg.CheckBuildTags(files); len(got) != 0 {
		t.Fatalf("a declared tag is not a violation, got %v", got)
	}

	targets := matrixTargets(cfg)
	if len(targets) != 2*len(DefaultGOOS)*len(DefaultGOARCH) {
		t.Fatalf("declaring a tag should add a pass per platform, got %d targets", len(targets))
	}

	var found []Violation
	for _, target := range targets {
		nodes, loadErr := unionFor(t, dir).LoadGraph(target)
		if loadErr != nil {
			t.Fatalf("LoadGraph(%s): %v", target, loadErr)
		}
		found = append(found, cfg.CheckGraph(nodes.Nodes(), target.GOOS)...)
	}
	merged := Merge(found)
	if len(merged) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(merged), merged)
	}
	v := merged[0]
	if v.Package != "example.com/tagfixture/consumer" {
		t.Errorf("package = %s", v.Package)
	}
	if len(v.Via) != 1 || v.Via[0] != "example.com/tagwrapper" {
		t.Errorf("via = %v, want the wrapper that carried it in", v.Via)
	}
}

// Bypass four: `go list -e` keeps going past a package it cannot resolve, and
// the resulting graph is missing whatever that package depended on. Discarding
// the error meant reporting that a rule held over a graph that was never built.
func TestLoadGraphFailsOnAnUnloadablePackage(t *testing.T) {
	t.Parallel()
	_, err := unionFor(t, "testdata/loaderror").LoadGraph(Target{GOOS: "linux", GOARCH: "amd64"})
	if err == nil {
		t.Fatal("an incomplete graph must be an error, not a pass")
	}
	var loadErrs *LoadErrors
	if !errors.As(err, &loadErrs) {
		t.Fatalf("want *LoadErrors, got %T: %v", err, err)
	}
	if len(loadErrs.Errors) == 0 {
		t.Fatal("the error should carry what could not be loaded")
	}
	msg := err.Error()
	for _, want := range []string{"incomplete", "no-such-module-exists-anywhere"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q should contain %q", msg, want)
		}
	}
}

func TestScanFilesExtractsBuildConstraints(t *testing.T) {
	t.Parallel()
	files, err := ScanFiles("testdata/tagged-transitive", "example.com/tagfixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	var found bool
	for _, f := range files {
		if f.File != "consumer/consumer_tagged.go" {
			continue
		}
		found = true
		if len(f.BuildTags) != 1 || f.BuildTags[0].Name != "customtag" {
			t.Errorf("build tags = %+v, want customtag", f.BuildTags)
		}
		if f.BuildTags[0].Line == 0 {
			t.Error("a constraint finding needs a line to point at")
		}
	}
	if !found {
		t.Fatal("the constrained file was not scanned at all")
	}
}

func TestScanFilesRecordsTagsImpliedByTheFilename(t *testing.T) {
	t.Parallel()
	// deploy_windows.go constrains the build without saying so in a comment.
	files, err := ScanFiles("testdata/tagged", "example.com/tagged")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	for _, f := range files {
		if f.File != "deploy/deploy_windows.go" {
			continue
		}
		var names []string
		for _, tag := range f.BuildTags {
			names = append(names, tag.Name)
		}
		if len(names) == 0 {
			t.Fatalf("no constraints recorded for %s", f.File)
		}
		// The //go:build line and the filename both say windows; either route
		// is fine, both are understood, and neither is a finding.
		if got := DefaultConfig().CheckBuildTags([]FileImports{f}); len(got) != 0 {
			t.Errorf("windows is a known tag, got %v", got)
		}
	}
}

// Bypass five, from the third review: an arm64-only import of a third-party
// wrapper. Nothing custom, nothing exotic -- arm64 is Graviton and Apple
// Silicon -- and it walked past a checker that accepted the tag while running
// its closure on amd64 alone.
func TestEndToEndArchitectureOnlyTransitiveDependency(t *testing.T) {
	t.Parallel()
	const dir = "testdata/arch-transitive"
	cfg := fixtureConfig("example.com/archfixture", "example.com/archwrapper/forbidden")

	files, err := ScanFiles(dir, "example.com/archfixture")
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	// The shape of the bypass, part one: no file declares the forbidden import,
	// so the shallow view is clean.
	if got := cfg.CheckFiles(files); len(got) != 0 {
		t.Fatalf("precondition: the file view should see only the wrapper, got %v", got)
	}

	// Part two: on the old matrix -- every GOOS, one architecture -- the
	// dependency is not in any graph, and the tag check accepted arm64 anyway.
	old := cfg
	old.GOARCH = []string{"amd64"}
	for _, target := range old.Targets() {
		nodes, loadErr := unionFor(t, dir).LoadGraph(target)
		if loadErr != nil {
			t.Fatalf("LoadGraph(%s): %v", target, loadErr)
		}
		if got := old.CheckGraph(nodes.Nodes(), target.GOOS); len(got) != 0 {
			t.Fatalf("precondition: %s cannot see an arm64 file, got %v", target, got)
		}
	}
	// With coverage narrowed, acceptance narrows with it: the constraint is now
	// itself the finding, so the hole cannot exist silently even on that matrix.
	if got := old.CheckBuildTags(files); len(got) != 1 || got[0].Tag != "arm64" {
		t.Fatalf("an uncovered arm64 constraint must be reported, got %v", got)
	}

	// And on the real matrix the closure simply finds it, with the chain.
	var found []Violation
	for _, target := range cfg.Targets() {
		nodes, loadErr := unionFor(t, dir).LoadGraph(target)
		if loadErr != nil {
			t.Fatalf("LoadGraph(%s): %v", target, loadErr)
		}
		found = append(found, cfg.CheckGraph(nodes.Nodes(), target.GOOS)...)
	}
	merged := Merge(found)
	if len(merged) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(merged), merged)
	}
	if merged[0].Package != "example.com/archfixture/probe" {
		t.Errorf("package = %s", merged[0].Package)
	}
	if len(merged[0].Via) != 1 || merged[0].Via[0] != "example.com/archwrapper" {
		t.Errorf("via = %v, want the wrapper that carried it in", merged[0].Via)
	}
	// arm64 is covered now, so the constraint itself is fine.
	if got := cfg.CheckBuildTags(files); len(got) != 0 {
		t.Errorf("arm64 is in the matrix and should be accepted, got %v", got)
	}
}

// The invariant review asked for, proved against the toolchain rather than
// against our own bookkeeping: for every selector the checker accepts, there is
// a build configuration it runs that actually compiles a file behind it.
//
// It enumerates Config.Accepts over a candidate universe rather than iterating
// AcceptedSelectors. That distinction is the point. An earlier version iterated
// the enumeration, and review widened acceptance through the *other* route --
// a bespoke exception in the rejection path -- which the enumeration never saw.
// Asking the decision function directly means any acceptance route, present or
// future, has to produce a file some pass compiles.
func TestEveryAcceptedSelectorIsActuallySelected(t *testing.T) {
	t.Parallel()
	const dir = "testdata/selectors"
	cfg := fixtureConfig("example.com/selectors", "example.com/selectors/forbidden")

	reached := map[string]bool{}
	for _, target := range cfg.Targets() {
		nodes, err := unionFor(t, dir).LoadGraph(target)
		if err != nil {
			t.Fatalf("LoadGraph(%s): %v", target, err)
		}
		for _, v := range cfg.CheckGraph(nodes.Nodes(), target.GOOS) {
			reached[v.Package] = true
		}
	}

	var accepted int
	for _, candidate := range selectorUniverse() {
		if !cfg.Accepts(candidate) {
			continue
		}
		accepted++
		// The release tags are one family with one representative fixture: a
		// package per version would be thirty packages proving one mechanism.
		pkg := "example.com/selectors/sel_" + candidate
		if goVersionTag.MatchString(candidate) {
			pkg = "example.com/selectors/sel_golang"
		}
		if !reached[pkg] {
			t.Errorf("Accepts(%q) is true but no closure pass compiled a file behind it; "+
				"acceptance and coverage have drifted", candidate)
		}
	}
	if accepted == 0 {
		t.Fatal("nothing was accepted, so this test proved nothing")
	}
}

// selectorUniverse is a deliberately wide set of plausible build constraints.
// Anything the checker accepts from it must be backed by a fixture; anything it
// rejects costs nothing. Widening this list can only make the test stricter.
func selectorUniverse() []string {
	out := []string{
		"unix", "gc", "gccgo", "cgo", "race", "msan", "asan", "purego",
		"boringcrypto", "ignore", "integration", "reviewbypass",
	}
	for name := range platformFileSuffix {
		out = append(out, name)
	}
	for i := 1; i <= 40; i++ {
		out = append(out, "go1."+strconv.Itoa(i))
	}
	sort.Strings(out)
	return out
}

// A package whose files are all excluded on a target contributes nothing to it,
// which is an answer rather than a gap -- and must not be confused with the
// unresolvable-import case that made the gate lie.
func TestLoadGraphToleratesAPackageExcludedOnThisTarget(t *testing.T) {
	t.Parallel()
	// sel_windows has a Windows-only file and an unconstrained one, so it is
	// never empty; sel_gc's tagged file is always in. What this asserts is that
	// the selectors fixture -- full of constrained files -- loads cleanly on
	// every target rather than tripping the fatal-error path.
	cfg := fixtureConfig("example.com/selectors", "example.com/selectors/forbidden")
	for _, target := range cfg.Targets() {
		if _, err := unionFor(t, "testdata/selectors").LoadGraph(target); err != nil {
			t.Fatalf("LoadGraph(%s) should succeed: %v", target, err)
		}
	}
}
