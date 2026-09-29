// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/internal/boundary"
)

// These tests live at the command layer on purpose.
//
// The property under test is not "Targets() is non-empty" -- a unit test could
// assert that and the command could still print success after checking nothing,
// which is exactly what review found. What has to be pinned is that *this
// program*, run against a fixture whose forbidden dependency is only reachable
// through a third-party wrapper, cannot produce a success report without having
// judged the union graph and accounted for every compatibility configuration.

const transitiveFixture = "../../internal/boundary/testdata/transitive"

// fixtureConfig mirrors the rule the transitive fixture is built for: no file in
// the module names the denied package, because only the third-party wrapper does.
func fixtureConfig() boundary.Config {
	cfg := boundary.DefaultConfig()
	cfg.ModulePrefix = "example.com/fixture"
	cfg.Rules = []boundary.Rule{{
		Name:            "fixture",
		Reason:          "fixture rule",
		DeniedPrefixes:  []string{"example.com/wrapper/forbidden"},
		AllowedPrefixes: []string{"example.com/fixture/allowed"},
	}}
	return cfg
}

// fixtureGraphs loads one real dependency graph per configured target, once for
// the whole test binary. Graphs are immutable once loaded, so sharing them is
// safe; a Union is not, so each test builds its own.
//
// Sharing works because provenance is identity by *resolved module directory*,
// not by Union instance: a graph loaded through one union of the fixture is
// evidence about that directory, so a second union of the same directory accepts
// it. A graph from anywhere else is refused, which is the point.
var fixtureGraphs = sync.OnceValues(func() ([]*boundary.Graph, error) {
	union, err := boundary.LoadUnion(transitiveFixture)
	if err != nil {
		return nil, err
	}
	var out []*boundary.Graph
	for _, target := range fixtureConfig().Targets() {
		g, loadErr := union.LoadGraph(target)
		if loadErr != nil {
			return nil, loadErr
		}
		out = append(out, g)
	}
	return out, nil
})

func loadFixtureUnionAndGraphs(t *testing.T) (*boundary.Union, []*boundary.Graph) {
	t.Helper()
	graphs, err := fixtureGraphs()
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	union, err := boundary.LoadUnion(transitiveFixture)
	if err != nil {
		t.Fatalf("LoadUnion: %v", err)
	}
	return union, graphs
}

func TestEmptyMatrixCannotReportSuccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*boundary.Config)
	}{
		{"no GOOS", func(c *boundary.Config) { c.GOOS = nil }},
		{"no GOARCH", func(c *boundary.Config) { c.GOARCH = nil }},
		{"neither", func(c *boundary.Config) { c.GOOS, c.GOARCH = nil, nil }},
		// What `-goos ,` produces: splitList drops the empty fields.
		{"empty flag value", func(c *boundary.Config) { c.GOOS = splitList(",") }},
		{"no release tags", func(c *boundary.Config) { c.ReleaseTags = nil }},
		{"no rules", func(c *boundary.Config) { c.Rules = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := fixtureConfig()
			tc.mutate(&cfg)

			var out bytes.Buffer
			err := run(cfg, transitiveFixture, "example.com/fixture", &out)
			if err == nil {
				t.Fatalf("a configuration that checks nothing must fail; it printed: %q", out.String())
			}
			if strings.Contains(out.String(), "held") {
				t.Errorf("no success message may be printed: %q", out.String())
			}
		})
	}
}

// A module path that is not the tree's own would judge no first-party packages at
// all, so every rule would hold vacuously. That was previously a route to a
// success line; it is now an error.
func TestWrongModulePathCannotReportSuccess(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	cfg.ModulePrefix = "example.com/not-this-module"

	var out bytes.Buffer
	err := run(cfg, transitiveFixture, "example.com/not-this-module", &out)
	if err == nil {
		t.Fatalf("judging nothing must not pass; it printed: %q", out.String())
	}
	if !strings.Contains(err.Error(), "main module") {
		t.Errorf("the error should explain the mismatch, got %v", err)
	}
}

// The same fixture with a real configuration: the run must find the transitive
// dependency. Without this, the tests above could pass for the wrong reason -- a
// checker that fails on everything also never reports false success.
func TestRealRunFindsTheTransitiveDependency(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(fixtureConfig(), transitiveFixture, "example.com/fixture", &out)
	if err == nil {
		t.Fatalf("the fixture's forbidden dependency must be found; output: %q", out.String())
	}
	got := out.String()
	if !strings.Contains(got, "example.com/wrapper/forbidden") {
		t.Errorf("the finding should name what was reached: %q", got)
	}
	if !strings.Contains(got, "example.com/wrapper") {
		t.Errorf("the finding should name the chain: %q", got)
	}
	// The union view reports a file and line for every hop, including the hop
	// inside the third-party module. That is what makes a transitive finding
	// something a contributor can act on.
	for _, want := range []string{"consumer/consumer.go", "wrapper/wrapper.go", "reachability is created by"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report should locate every hop (%q missing): %q", want, got)
		}
	}
}

// And a clean tree must still be able to say so, with evidence attached --
// otherwise the guards above are just a checker that never passes.
func TestCleanTreeReportsSuccessWithEvidence(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	// Deny something the fixture does not contain, so the tree is clean.
	cfg.Rules[0].DeniedPrefixes = []string{"example.com/nothing-imports-this"}

	var out bytes.Buffer
	if err := run(cfg, transitiveFixture, "example.com/fixture", &out); err != nil {
		t.Fatalf("a clean tree should pass: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "held") {
		t.Fatalf("expected a success message, got %q", got)
	}
	// Both success lines are generated from evidence objects, so neither can
	// claim more than the run did: the union summary says what was judged, and
	// the coverage summary accounts for every compatibility configuration.
	for _, want := range []string{
		"union import graph", "first-party package(s)", "every build constraint ignored",
		"Go files", "packages on linux/amd64", "packages on windows/arm64",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("success message should evidence %q, got %q", want, got)
		}
	}
}

func TestSplitListDropsEmptyFields(t *testing.T) {
	t.Parallel()
	if got := splitList(","); len(got) != 0 {
		t.Errorf(`splitList(",") = %v, want empty -- and an empty matrix must then be rejected`, got)
	}
	if got := splitList("linux, darwin ,"); len(got) != 2 {
		t.Errorf("splitList = %v, want two entries", got)
	}
}

// Round five: Coverage proved that *some* graph completed, not that every
// configured one had, so evidence from one target could stand in for six.
//
// Round six -- this one -- closes the seam the fifth round documented and left
// open: Complete used to take a target and a package count as arguments, so a
// caller could record a completion for a graph that was never loaded. It now
// takes the sealed *Graph itself. These tests therefore load real graphs; there
// is no way to write the fabricated version any more, which is the point.
func TestPartialCoverageCannotReportSuccess(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)
	if len(graphs) < 6 {
		t.Fatalf("this test needs a real matrix, got %d configurations", len(graphs))
	}

	// The exact reproduction: six configured, one completed.
	cov := union.NewCoverage(cfg.Targets())
	if err := cov.Complete(graphs[0]); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	cleanCfg, findings := judgeCleanly(t, union, cfg)
	var out bytes.Buffer
	err := reportSuccess(&out, cleanCfg, findings, cov)
	if err == nil {
		t.Fatalf("evidence for 1 of %d configurations must not pass; it printed: %q", len(graphs), out.String())
	}
	if out.Len() != 0 {
		t.Errorf("nothing may be printed when the claim is refused, got %q", out.String())
	}
	// The message has to say what is missing, or a maintainer cannot act on it.
	for _, want := range []string{"incomplete", graphs[1].Target().String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestCoverageWithOneConfigurationMissingCannotReportSuccess(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)

	cov := union.NewCoverage(cfg.Targets())
	for _, g := range graphs[:len(graphs)-1] {
		if err := cov.Complete(g); err != nil {
			t.Fatalf("Complete(%s): %v", g.Target(), err)
		}
	}

	cleanCfg, findings := judgeCleanly(t, union, cfg)
	var out bytes.Buffer
	err := reportSuccess(&out, cleanCfg, findings, cov)
	if err == nil {
		t.Fatalf("one missing configuration must fail; it printed: %q", out.String())
	}
	missing := graphs[len(graphs)-1].Target().String()
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q should name the missing configuration %q", err, missing)
	}
}

func TestCoverageRejectsDuplicateUnexpectedAndFabricatedGraphs(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)

	cov := union.NewCoverage(cfg.Targets())
	if err := cov.Complete(graphs[0]); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// A duplicate cannot stand in for a configuration that has not run.
	if err := cov.Complete(graphs[0]); err == nil {
		t.Error("a second completion for the same configuration must be rejected")
	}
	// Nor can evidence for something nobody asked to check. freebsd is a real
	// platform the toolchain will happily list and this matrix does not contain.
	unexpected, err := union.LoadGraph(boundary.Target{GOOS: "freebsd", GOARCH: "amd64"})
	if err != nil {
		t.Fatalf("LoadGraph(freebsd): %v", err)
	}
	if err := cov.Complete(unexpected); err == nil {
		t.Error("coverage for an unconfigured build configuration must be rejected")
	}
	// Nor a graph nothing loaded. There is no exported way to put nodes into a
	// Graph, so this is the strongest a caller can fabricate -- and it is refused
	// rather than merely empty.
	if err := cov.Complete(&boundary.Graph{}); err == nil {
		t.Error("a Graph that LoadGraph did not produce must be rejected")
	}

	// And after all that, the run is still incomplete and still cannot pass.
	cleanCfg, findings := judgeCleanly(t, union, cfg)
	var out bytes.Buffer
	if err := reportSuccess(&out, cleanCfg, findings, cov); err == nil {
		t.Errorf("the run is incomplete and must not pass; it printed %q", out.String())
	}
}

// The zero values endorse nothing. A Coverage that expects no configurations has
// nothing to account for, and a Findings that judged nothing has nothing to say.
func TestZeroEvidenceCannotReportSuccess(t *testing.T) {
	t.Parallel()
	var cov boundary.Coverage
	var findings boundary.Findings
	var out bytes.Buffer
	if err := reportSuccess(&out, fixtureConfig(), &findings, &cov); err == nil {
		t.Fatalf("empty evidence must not endorse anything; it printed %q", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("nothing may be printed when the claim is refused, got %q", out.String())
	}
}

// A union that judged nothing cannot endorse the run either, even with complete
// target coverage. The two pieces of evidence are independent on purpose: the
// compatibility configurations say the tree builds, and only the union says the
// fence holds.
func TestCompleteCoverageWithoutUnionFindingsCannotReportSuccess(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)

	cov := union.NewCoverage(cfg.Targets())
	for _, g := range graphs {
		if err := cov.Complete(g); err != nil {
			t.Fatalf("Complete(%s): %v", g.Target(), err)
		}
	}
	var findings boundary.Findings
	var out bytes.Buffer
	if err := reportSuccess(&out, cfg, &findings, cov); err == nil {
		t.Fatalf("full coverage without a judged union must not pass; it printed %q", out.String())
	}
}

// The sixth round, and the reviewer's exact reproduction.
//
// A sealed *Graph proved that a graph had been loaded. It did not prove it had
// been loaded *from the tree being judged*. So: load the real union, then load a
// graph from a separate temporary module that DECLARES THE SAME MODULE PATH and
// contains only an empty package. Before the fix, Complete and Validate both
// returned nil and this command would have printed success over a tree it had
// never looked at -- the foreign graph's node had a matching import path and an
// empty edge set, so the differential found nothing missing.
//
// Note what the fix removes rather than detects: there is no longer any exported
// way to load a graph by directory at all. Obtaining the foreign graph below
// requires loading a whole union of the foreign tree first, and its provenance
// then names that tree.
func TestGraphFromAnotherModuleDeclaringTheSamePathIsRefused(t *testing.T) {
	t.Parallel()
	realUnion, err := boundary.LoadUnion(transitiveFixture)
	if err != nil {
		t.Fatalf("LoadUnion(real): %v", err)
	}

	foreignDir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(foreignDir, rel)
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(path, []byte(content), 0o600); wErr != nil {
			t.Fatal(wErr)
		}
	}
	// The same module path the real fixture declares. That is the whole attack:
	// everything a name can carry matches.
	write("go.mod", "module example.com/fixture\n\ngo 1.25.0\n")
	write("consumer/consumer.go", "package consumer\n")

	foreignUnion, err := boundary.LoadUnion(foreignDir)
	if err != nil {
		t.Fatalf("LoadUnion(foreign): %v", err)
	}
	if foreignUnion.MainModule().Path != realUnion.MainModule().Path {
		t.Fatalf("this test is only meaningful when both modules declare the same path: %q vs %q",
			foreignUnion.MainModule().Path, realUnion.MainModule().Path)
	}
	if foreignUnion.ModuleDir() == realUnion.ModuleDir() {
		t.Fatalf("the two module directories must differ, got %q", realUnion.ModuleDir())
	}

	cfg := fixtureConfig()
	target := cfg.Targets()[0]
	foreignGraph, err := foreignUnion.LoadGraph(target)
	if err != nil {
		t.Fatalf("LoadGraph(foreign): %v", err)
	}
	if foreignGraph.Root() != foreignUnion.ModuleDir() {
		t.Errorf("a graph must be stamped with the directory it was loaded from: %q, want %q",
			foreignGraph.Root(), foreignUnion.ModuleDir())
	}

	cov := realUnion.NewCoverage(cfg.Targets())
	err = cov.Complete(foreignGraph)
	if err == nil {
		t.Fatal("coverage for one tree must not accept a graph loaded from another, however " +
			"faithfully that graph was loaded and whatever module path it declares")
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("the refusal should name the reason, got %v", err)
	}
	// The differential is the other door into the same room.
	if _, diffErr := realUnion.Differential(foreignGraph); diffErr == nil {
		t.Error("the differential must refuse a graph from another tree")
	}
	// And with that completion refused, nothing can be endorsed.
	if err := cov.Validate(); err == nil {
		t.Error("coverage with no accepted completion must not validate")
	}
	cleanCfg, findings := judgeCleanly(t, realUnion, cfg)
	var out bytes.Buffer
	if err := reportSuccess(&out, cleanCfg, findings, cov); err == nil {
		t.Fatalf("no success may be printed; it printed %q", out.String())
	}
}

// The same shape one level up: a judgement of one tree must not endorse a run
// over another, even when the coverage itself is complete.
func TestFindingsFromAnotherTreeCannotEndorseThisRun(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)
	cov := union.NewCoverage(cfg.Targets())
	for _, g := range graphs {
		if err := cov.Complete(g); err != nil {
			t.Fatalf("Complete(%s): %v", g.Target(), err)
		}
	}

	// A judgement of a different module: the union-fixture tree, judged with the
	// same rule names so only provenance separates the two.
	other, err := boundary.LoadUnion("../../internal/boundary/testdata/union/basic")
	if err != nil {
		t.Fatalf("LoadUnion(other): %v", err)
	}
	otherCfg := cfg
	otherCfg.ModulePrefix = other.MainModule().Path
	otherFindings, err := other.Judge(otherCfg)
	if err != nil {
		t.Fatalf("Judge(other): %v", err)
	}

	var out bytes.Buffer
	if err := reportSuccess(&out, cfg, otherFindings, cov); err == nil {
		t.Fatalf("a judgement of %s must not endorse a run over %s; it printed %q",
			other.ModuleDir(), union.ModuleDir(), out.String())
	} else if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("the refusal should name the reason, got %v", err)
	}
}

// And the rules reported must be the rules judged: a run may not enforce a
// permissive rule set and print the strict one.
func TestReportingRulesThatWereNotJudgedIsRefused(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)
	cov := union.NewCoverage(cfg.Targets())
	for _, g := range graphs {
		if err := cov.Complete(g); err != nil {
			t.Fatalf("Complete(%s): %v", g.Target(), err)
		}
	}
	// judgeCleanly judges a rule named "fixture-clean"; cfg names "fixture".
	_, findings := judgeCleanly(t, union, cfg)

	var out bytes.Buffer
	if err := reportSuccess(&out, cfg, findings, cov); err == nil {
		t.Fatalf("the reported rules must be the judged rules; it printed %q", out.String())
	}
}

// The complete case still passes, and the message accounts for every
// configuration rather than a subset -- otherwise the tests above would be
// satisfied by a checker that never succeeds.
func TestCompleteEvidenceReportsEveryConfiguration(t *testing.T) {
	t.Parallel()
	cfg := fixtureConfig()
	union, graphs := loadFixtureUnionAndGraphs(t)

	cov := union.NewCoverage(cfg.Targets())
	for _, g := range graphs {
		if err := cov.Complete(g); err != nil {
			t.Fatalf("Complete(%s): %v", g.Target(), err)
		}
	}

	cleanCfg, findings := judgeCleanly(t, union, cfg)
	var out bytes.Buffer
	if err := reportSuccess(&out, cleanCfg, findings, cov); err != nil {
		t.Fatalf("a complete run must pass: %v", err)
	}
	got := out.String()
	for _, g := range graphs {
		if !strings.Contains(got, g.Target().String()) {
			t.Errorf("the success message must account for %s, got %q", g.Target(), got)
		}
	}
}

// judgeCleanly judges the fixture with a rule the fixture does not break, so a
// test about *evidence* is not also a test about violations.
//
// It returns the configuration it judged as well as the findings, because
// Endorse requires the rules reported to be the rules judged -- so a test cannot
// accidentally report a rule set nothing was checked against. That is the point
// of the check, and it applies to tests too.
func judgeCleanly(t *testing.T, union *boundary.Union, cfg boundary.Config) (boundary.Config, *boundary.Findings) {
	t.Helper()
	clean := cfg
	clean.Rules = []boundary.Rule{{
		Name:           "fixture-clean",
		Reason:         "fixture rule nothing breaks",
		DeniedPrefixes: []string{"example.com/nothing-imports-this"},
	}}
	findings, err := union.Judge(clean)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if len(findings.Violations()) != 0 {
		t.Fatalf("the clean rule should find nothing, got %v", findings.Violations())
	}
	return clean, findings
}
