// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command boundarycheck enforces the repository's import-boundary rules.
//
// It is a thin adapter. internal/boundary holds every judgement and is
// unit-tested against fixtures; this file only decides which views of the tree
// to take and how to print the result.
//
// The order below is the argument the check makes:
//
//  1. The **union import graph** is the proof. Every import declared by every Go
//     file in every reachable package, build constraints ignored, plus test
//     imports for first-party packages. Any concrete build graph is a subgraph
//     of it, so a union with no forbidden path proves no configuration has one.
//  2. Everything after it is a **compatibility check**: the file scan, the
//     build-constraint check, and the concrete build targets. They catch code
//     that does not compile, constraints no supported build selects, and -- most
//     usefully -- any disagreement between the union parser and the real
//     toolchain, which would mean the proof is resting on a resolver that missed
//     something.
//
// Two kinds of rule run here, because they catch different things. The import
// rules answer "what does this package depend on". The idiom rules answer "does
// this package betray something it is not supposed to know" -- a `dynamodbav`
// struct tag or a hand-written "PK = :pk" expression needs no import at all, so
// an import-only check would pass a file that has already broken the store fence
// (USOSS-5); and neither does an IAM trust policy naming ConductorOne's tenant
// accounts or an os.Getenv("APPHUB_C1_TENANT_URL"), which is the same hole in
// the c1-optional fence (USOSS-34).
//
// The idiom rules are a lexical net over what the compiler computes, not a second
// proof. The import half is the proof, and it is exactly as wide as its subject.
//
// Usage:
//
//	go run ./hack/boundarycheck [-dir .] [-goos linux,darwin,windows]
//
// Exits non-zero and prints every violation if any rule is broken, and also if
// anything could not be examined -- an unresolvable import, an unparseable file,
// a malformed build constraint, a tracked vendor tree, or a build configuration
// that could not be loaded. Saying the rules held over something unexamined is
// the one thing a gate must never do.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/conductorone/apphub/internal/boundary"
)

func main() {
	dir := flag.String("dir", ".", "module root to check")
	goosList := flag.String("goos", strings.Join(boundary.DefaultGOOS, ","),
		"comma-separated GOOS values in the compatibility matrix")
	goarchList := flag.String("goarch", strings.Join(boundary.DefaultGOARCH, ","),
		"comma-separated GOARCH values in the compatibility matrix")
	modulePath := flag.String("module", boundary.DefaultModulePrefix, "module path of the tree being checked")
	flag.Parse()

	cfg := boundary.DefaultConfig()
	cfg.ModulePrefix = *modulePath
	// Narrowing the matrix narrows the compatibility checks. It no longer
	// narrows the proof: the union graph does not depend on which configurations
	// exist, which is the entire point of USOSS-28. A wrong -module, on the other
	// hand, would mean judging nothing -- so Judge compares it against the module
	// the toolchain reports and fails on a mismatch rather than quietly finding
	// no first-party packages.
	cfg.GOOS = splitList(*goosList)
	cfg.GOARCH = splitList(*goarchList)

	// Which go1.N selectors are satisfiable is whatever the toolchain running
	// the compatibility passes reports, so ask it rather than infer it from
	// go.mod.
	tags, err := boundary.ToolchainReleaseTags(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarycheck: %v\n", err)
		os.Exit(1)
	}
	cfg.ReleaseTags = tags

	// The standard-library set, for the views that have no union to ask. The
	// union loads its own; this one is what the file scan and the concrete
	// graphs judge against, and Config.Validate refuses an import allowlist
	// without it rather than letting the allowlist deny every standard import.
	std, err := boundary.StandardPackages(*dir, cfg.GOOS, cfg.GOARCH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boundarycheck: %v\n", err)
		os.Exit(1)
	}
	cfg.StandardPackages = std

	if err := run(cfg, *dir, *modulePath, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "boundarycheck: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg boundary.Config, dir, modulePath string, out io.Writer) error {
	// Before anything else. A configuration that cannot check anything must not
	// get as far as producing output that looks like a result.
	if err := cfg.Validate(); err != nil {
		return err
	}

	// The proof. LoadUnion resolves modules hermetically, refuses a tracked
	// vendor tree, and parses every Go file in the main module; Judge walks the
	// graph from every first-party package. Anything it cannot resolve or parse
	// is an error rather than an omission.
	union, err := boundary.LoadUnion(dir)
	if err != nil {
		return err
	}
	findings, err := union.Judge(cfg)
	if err != nil {
		return err
	}
	if violations := findings.Violations(); len(violations) > 0 {
		// Report and stop. This is the answer; running the compatibility passes
		// now would only risk burying it under a load error.
		reportViolations(out, violations)
		return fmt.Errorf("import boundary violated by %d dependency/dependencies", len(violations))
	}

	// Compatibility check one: every Go file in the tree, build constraints
	// recorded but not obeyed. Its findings are a subset of the union's by
	// construction, so what it is really for is the cross-check below -- and for
	// the build-constraint rule, which is about whether the *concrete* passes can
	// see a file, not about the fence.
	files, err := boundary.ScanFiles(dir, modulePath)
	if err != nil {
		return err
	}
	if tagViolations := cfg.CheckBuildTags(files); len(tagViolations) > 0 {
		reportViolations(out, tagViolations)
		return fmt.Errorf("%d build constraint(s) that no compatibility configuration selects; "+
			"the union graph still covered those files, but no concrete build did", len(tagViolations))
	}
	if missed := boundary.FileScanCrossCheck(cfg.CheckFiles(files), findings); len(missed) > 0 {
		reportViolations(out, missed)
		return fmt.Errorf("the union import graph missed %d import(s) that the file scan declared; "+
			"the union is meant to be a superset of every other view, so this is a defect in it "+
			"and not a report about the tree", len(missed))
	}

	// Compatibility check three: file contents rather than imports. This is the
	// store fence's semantic half, and it is the only view that reads source
	// text, because what it looks for -- struct tags, expression strings, key
	// names -- is not an import and cannot appear in a dependency graph.
	//
	// The file list is the scan's, never this rule's own. Which directories hold
	// packages is boundary.PackageDirs and nothing else; a second opinion here is
	// how that rule got its first two bypasses.
	sources, err := boundary.SourcesFrom(dir, files)
	if err != nil {
		return err
	}
	// Same discipline as Coverage: having inspected nothing must not be able to
	// look like having found nothing.
	if len(sources) == 0 {
		return fmt.Errorf("no Go files found under %s; the idiom rule inspected nothing", dir)
	}
	rules := boundary.DefaultIdiomRules()
	// Before any of them run, for the reason Config.Validate runs first: a rule
	// with no needles inspects every file in the tree and reports that it held.
	if err := boundary.ValidateIdiomRules(rules); err != nil {
		return err
	}
	// Every rule runs, and every rule's findings are reported, rather than
	// stopping at the first. These are independent fences, and being told about
	// one of two broken ones is how a second round of the same fix gets started.
	var broken int
	for _, rule := range rules {
		leaks := rule.Check(sources)
		if len(leaks) == 0 {
			continue
		}
		broken += len(leaks)
		reportLeaks(out, rule, leaks)
	}
	if broken > 0 {
		return fmt.Errorf("%d idiom leak(s) across %d file(s)", broken, len(sources))
	}
	// Reported on their own lines rather than folded into reportSuccess. That
	// function deliberately assembles nothing -- Coverage.Endorse owns the
	// import rules' claim, after six rounds of review found every variation of a
	// claim built one level out from its facts. These rules' evidence is their own
	// file count from their own scan, so they state it themselves and leave that
	// accounting alone.
	for _, rule := range rules {
		if _, err := fmt.Fprintf(out, "boundarycheck: the %s rule held over %d Go file(s) (%s)\n",
			rule.Name, len(sources), rule.Subject); err != nil {
			return err
		}
	}

	// Compatibility check two: the concrete build configurations. Coverage takes
	// the loaded graph itself, derives the target and package count from it, and
	// runs the differential (every edge in the real graph must exist in the
	// union) before recording anything.
	cov := union.NewCoverage(cfg.Targets())
	var graphSets [][]boundary.Violation
	for _, target := range cfg.Targets() {
		// The graph is loaded *by the union*, from the module directory the union
		// was built from. There is no exported way to load one from anywhere else,
		// which is what stops evidence about a different tree from reaching the
		// accounting below.
		graph, loadErr := union.LoadGraph(target)
		if loadErr != nil {
			return loadErr
		}
		graphSets = append(graphSets, cfg.CheckGraph(graph.Nodes(), target.GOOS))
		if covErr := cov.Complete(graph); covErr != nil {
			return covErr
		}
	}
	if violations := boundary.Merge(graphSets...); len(violations) > 0 {
		reportViolations(out, violations)
		return fmt.Errorf("a concrete build graph reported %d violation(s) that the union graph "+
			"did not; the union is meant to subsume every build, so reconcile the two before "+
			"trusting either", len(violations))
	}

	// The only success path, and it cannot be taken without evidence.
	return reportSuccess(out, cfg, findings, cov)
}

// reportSuccess is the single place this command can say the rules held, and it
// no longer decides anything.
//
// Six rounds of review found this checker able to report success over something
// it had not examined: dropped load errors, unselected build constraints, a
// zero-target matrix, evidence from one target standing in for six, a Complete
// that took a package count on trust, and -- last -- a real dependency graph
// loaded from a *different module that declared the same path*, which a Coverage
// for this tree accepted.
//
// The pattern in all six is a claim assembled one level out from the facts. So
// this function does not assemble one: boundary.Coverage.Endorse holds every
// condition (both pieces of evidence real, both from the same resolved module
// directory, the rules judged being the rules reported, and each validating on
// its own terms) and returns the sentence. There is nothing here for a caller to
// get wrong, because there is nothing here for a caller to combine.
func reportSuccess(out io.Writer, cfg boundary.Config, findings *boundary.Findings, cov *boundary.Coverage) error {
	summary, err := cov.Endorse(cfg, findings)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(summary, "\n") {
		if _, err := fmt.Fprintf(out, "boundarycheck: %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

// reportLeaks prints one rule's idiom leaks. They are not import violations and
// are not printed as if they were: "imports X" would be a lie about a struct tag,
// and a gate that misdescribes its own finding teaches people to distrust it.
//
// The subject and the advice come off the rule rather than being written here.
// With one rule a hardcoded paragraph was merely redundant; with two it would be
// wrong for whichever rule it was not written for.
func reportLeaks(out io.Writer, rule boundary.IdiomRule, leaks []boundary.Leak) {
	var b strings.Builder
	fmt.Fprintf(&b, "boundarycheck: %d leak(s): %s\n\n", len(leaks), rule.Subject)
	for _, l := range leaks {
		fmt.Fprintf(&b, "  [%s] %s:%d\n      %s  in  %s\n      %s\n\n",
			l.Rule, l.Path, l.Line, l.Needle, l.Token, l.Reason)
	}
	b.WriteString(rule.Advice)
	b.WriteString("\nThe reported text is the value the compiler computes, not the spelling in the\n" +
		"file -- an escaped or assembled string is reported as what it resolves to.\n")
	_, _ = io.WriteString(out, b.String())
}

func reportViolations(out io.Writer, violations []boundary.Violation) {
	var b strings.Builder
	fmt.Fprintf(&b, "boundarycheck: %d violation(s)\n\n", len(violations))
	for _, v := range violations {
		if v.Tag != "" {
			fmt.Fprintf(&b, "  [%s] %s\n      declares build tag %q, which no compatibility build selects\n",
				v.RuleName, v.File, v.Tag)
			if v.Line > 0 {
				fmt.Fprintf(&b, "      at      %s:%d\n", v.File, v.Line)
			}
			fmt.Fprintf(&b, "      %s\n\n", v.Reason)
			continue
		}
		fmt.Fprintf(&b, "  [%s] %s\n", v.RuleName, v.Package)
		if len(v.Via) > 0 {
			fmt.Fprintf(&b, "      reaches %s\n      via     %s\n", v.Import, strings.Join(append(v.Via, v.Import), " -> "))
		} else {
			fmt.Fprintf(&b, "      imports %s\n", v.Import)
		}
		fmt.Fprintf(&b, "      as      %s import", v.Kind)
		if len(v.Chain) == 0 && v.File != "" {
			fmt.Fprintf(&b, ", at %s:%d", v.File, v.Line)
		}
		if v.GOOS != "" && v.File == "" {
			fmt.Fprintf(&b, ", on GOOS=%s", v.GOOS)
		}
		b.WriteString("\n")
		// The chain with a line per hop. This is what turns "something reaches
		// ConductorOne" into a diff somebody can make.
		for _, hop := range v.Chain {
			fmt.Fprintf(&b, "      %s:%d: %s imports %s\n", hop.File, hop.Line, hop.From, hop.To)
		}
		if v.Introducer != "" && v.Introducer != v.Package {
			fmt.Fprintf(&b, "      the reachability is created by %s\n", v.Introducer)
		}
		fmt.Fprintf(&b, "      %s\n\n", v.Reason)
	}
	b.WriteString("If a violation is intentional, the fix is to widen the allowlist in\n" +
		"internal/boundary/boundary.go -- deliberately, in a diff a reviewer will see --\n" +
		"not to add a suppression here.\n\n" +
		"If the import is behind a build constraint no supported configuration selects, that\n" +
		"is still a finding: the union graph judges every declared import, because code\n" +
		"behind an unselected constraint is exactly what becomes reachable later without\n" +
		"anyone revisiting the boundary. Delete the import or move it behind the allowed\n" +
		"package.\n")
	_, _ = io.WriteString(out, b.String())
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
