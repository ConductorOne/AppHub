// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"strings"
	"testing"
)

// The checker is the only thing standing between a decision and a reviewer's
// memory, so it is tested on synthetic graphs rather than on whatever the
// repository happens to contain today. These tests stay meaningful when the
// repository is empty, which is exactly when the checker is easiest to break
// without noticing.

func apphub(suffix string) string { return DefaultModulePrefix + suffix }

// onlyRule narrows a finding set to one rule.
//
// A case about one rule must assert over that rule's findings and not over
// "everything the configuration reported", because the shipped configuration
// has five rules and a package can break more than one. Two cases here used to
// count total violations and broke the moment a second rule was added that also
// judged their fixture package -- which is a test measuring the configuration's
// size rather than the property it names.
func onlyRule(tb testing.TB, all []Violation, rule string) []Violation {
	tb.Helper()
	var out []Violation
	var seen []string
	for _, v := range all {
		seen = append(seen, v.RuleName)
		if v.RuleName == rule {
			out = append(out, v)
		}
	}
	if len(all) > 0 && len(out) == 0 {
		tb.Fatalf("no finding from rule %q; the run reported %v", rule, seen)
	}
	return out
}

// graph is a small helper: each entry is a package and what it imports.
func graph(edges map[string][]string) []Node {
	out := make([]Node, 0, len(edges))
	for path, imports := range edges {
		out = append(out, Node{ImportPath: path, Imports: imports})
	}
	return out
}

func TestHasPathPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"example.com/a", "example.com/a", true},
		{"example.com/a/b", "example.com/a", true},
		{"example.com/a/b/c", "example.com/a", true},
		{"example.com/ab", "example.com/a", false},
		{"example.com/a-b", "example.com/a", false},
		{"example.com", "example.com/a", false},
		{"", "example.com/a", false},
	}
	for _, tc := range cases {
		if got := hasPathPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("hasPathPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestCheckGraphFlagsDirectImport(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/credentials"): {"context", "github.com/conductorone/conductorone-sdk-go/pkg/client"},
	}), "linux")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if got[0].Kind != KindBuild {
		t.Errorf("kind = %q, want %q", got[0].Kind, KindBuild)
	}
	if len(got[0].Via) != 0 {
		t.Errorf("a direct import should have no via chain, got %v", got[0].Via)
	}
	if !strings.Contains(got[0].Reason, "optional") {
		t.Errorf("violation should explain the rule, got %q", got[0].Reason)
	}
}

// AppHub is published under the same organization the c1-optional rule denies.
// Its own packages must pass, every other module under the organization --
// including one whose path merely starts with "apphub" -- must not, and the
// c1 provider inside the module must stay denied.
func TestC1OptionalExemptsOnlyThisModule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, imp string
		want      int
	}{
		{"own package", apphub("/store"), 0},
		{"own module root", apphub(""), 0},
		{"sibling module under the org", "github.com/conductorone/conductorone-sdk-go/pkg/client", 1},
		{"prefix-sharing sibling module", "github.com/conductorone/apphub-extras", 1},
		{"own c1 provider", apphub("/credentials/c1"), 1},
		{"own c1 directory client", apphub("/credentials/c1directory"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			all := DefaultConfig().CheckGraph(graph(map[string][]string{
				apphub("/modules/deploy"): {tc.imp},
				tc.imp:                    nil,
			}), "linux")
			var got []Violation
			for _, v := range all {
				if v.RuleName == "c1-optional" {
					got = append(got, v)
				}
			}
			if len(got) != tc.want {
				t.Fatalf("importing %s: got %d c1-optional violations, want %d: %v",
					tc.imp, len(got), tc.want, got)
			}
		})
	}
}

// The first bypass review found: nothing in the repository declares the
// forbidden import, and it is in the build graph anyway.
func TestCheckGraphFlagsTransitiveImportThroughThirdParty(t *testing.T) {
	t.Parallel()
	got := onlyRule(t, DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/modules/deploy"): {"example.com/c1wrapper"},
		"example.com/c1wrapper":   {"github.com/conductorone/conductorone-sdk-go/pkg/client"},
	}), "linux"), "c1-optional")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	v := got[0]
	if v.Package != apphub("/modules/deploy") {
		t.Errorf("wrong package blamed: %s", v.Package)
	}
	if want := []string{"example.com/c1wrapper"}; len(v.Via) != 1 || v.Via[0] != want[0] {
		t.Errorf("via = %v, want %v -- the chain is the whole value of this finding", v.Via, want)
	}
}

func TestCheckGraphReportsShortestChain(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/store"):   {"example.com/long", "example.com/short"},
		"example.com/long": {"example.com/longer"},
		// A longer route to the same place must not be the one reported.
		"example.com/longer": {"github.com/conductorone/sdk"},
		"example.com/short":  {"github.com/conductorone/sdk"},
	}), "linux")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if len(got[0].Via) != 1 {
		t.Errorf("via = %v, want the one-hop route", got[0].Via)
	}
}

func TestCheckGraphDoesNotWalkThroughTheForbiddenPackage(t *testing.T) {
	t.Parallel()
	// Reaching c1 is the finding. What c1 itself depends on is c1's business,
	// and walking on would bury the one line the reader needs.
	got := onlyRule(t, DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/modules/deploy"):     {apphub("/credentials/c1")},
		apphub("/credentials/c1"):     {"github.com/conductorone/sdk"},
		"github.com/conductorone/sdk": {},
	}), "linux"), "c1-optional")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if got[0].Import != apphub("/credentials/c1") {
		t.Errorf("import = %s, want the first denied package reached", got[0].Import)
	}
}

func TestCheckGraphAllowsTheC1ProviderItself(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/credentials/c1"):                 {"github.com/conductorone/conductorone-sdk-go/pkg/client"},
		apphub("/credentials/c1/internal/tokens"): {"github.com/conductorone/conductorone-sdk-go/pkg/oauth"},
	}), "linux")
	if len(got) != 0 {
		t.Fatalf("the c1 provider must be allowed to reach c1, got %v", got)
	}
}

func TestC1AllowlistPermitsOnlyTheNamedCompositionRoot(t *testing.T) {
	t.Parallel()
	// USOSS-8 added one entry to the c1-optional allowlist, for the composition
	// root that registers the ConductorOne provider. The reason is recorded in
	// docs/design/credential-vending.md §11.3, and condition 4 there says a second
	// entry needs supervisor approval.
	//
	// This pins the true extent of that widening rather than leaving a reader to
	// infer it, because the two halves point in opposite directions and only one of
	// them is obvious.

	// Permitted: the named composition root.
	if got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/cmd/apphub"): {apphub("/credentials/c1")},
	}), "linux"); len(got) != 0 {
		t.Errorf("the allowlisted composition root must be able to register the provider, got %v", got)
	}

	// Refused: any other binary, any other package under cmd/, and any library.
	// A sibling under cmd/ is the case worth having, because "cmd/ is the wiring
	// point" is exactly the shape a later reader would generalise the entry to.
	for _, importer := range []string{
		apphub("/cmd/other"),
		apphub("/cmd"),
		apphub("/cmd/apphub-extra"),
		apphub("/credentials"),
		apphub("/credentials/lifecycle"),
		apphub("/modules/deploy"),
		apphub("/internal/errhygiene"),
	} {
		got := DefaultConfig().CheckGraph(graph(map[string][]string{
			importer: {apphub("/credentials/c1")},
		}), "linux")
		if len(got) != 1 {
			t.Errorf("%s reaching credentials/c1 produced %d findings, want 1", importer, len(got))
		}
	}

	// And the half that is not obvious: the rule matches on whole path segments,
	// so a package created *beneath* the named root would be allowed too. Nothing
	// beneath it exists. This asserts the behaviour rather than a wish, so the
	// widening's real extent is visible in a test rather than only in a comment --
	// and so that a later ticket wanting an exact-match rule finds the statement of
	// what changes.
	if got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/cmd/apphub/wiring"): {apphub("/credentials/c1")},
	}), "linux"); len(got) != 0 {
		t.Errorf("the allowlist is a path-prefix rule; a package beneath the root is permitted, got %v", got)
	}
}

// TestC1DirectoryAllowlistIsIndependentOfTheVendingProviders pins the second,
// separately-added entry for credentials/c1directory (docs/design/
// credential-vending.md §3.1: "own package", so its own allowlist pair rather
// than a widening of credentials/c1's). It shares the same one composition
// root as credentials/c1 rather than gaining a second one of its own.
func TestC1DirectoryAllowlistIsIndependentOfTheVendingProviders(t *testing.T) {
	t.Parallel()

	// Permitted: the same named composition root, reaching the directory client.
	if got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/cmd/apphub"): {apphub("/credentials/c1directory")},
	}), "linux"); len(got) != 0 {
		t.Errorf("the allowlisted composition root must be able to construct the directory client, got %v", got)
	}

	// Refused: the same importer set the vending provider's test refuses.
	// credentials/c1 itself is not in this list: it is already one of the two
	// ConductorOne-aware packages, so the import rule's proof (no *library*
	// depends on ConductorOne) is unaffected either way. That the two do not
	// import each other in practice is a "no shared code" design decision
	// (doc.go), not a property this rule is asked to enforce.
	for _, importer := range []string{
		apphub("/cmd/other"),
		apphub("/cmd"),
		apphub("/credentials"),
		apphub("/credentials/lifecycle"),
		apphub("/internal/worker"),
	} {
		got := DefaultConfig().CheckGraph(graph(map[string][]string{
			importer: {apphub("/credentials/c1directory")},
		}), "linux")
		if len(got) != 1 {
			t.Errorf("%s reaching credentials/c1directory produced %d findings, want 1", importer, len(got))
		}
	}

	// And that credentials/c1directory's own denied prefix is truly a second,
	// segment-aware entry: reaching plain credentials/c1 is unaffected by it.
	if got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/cmd/apphub"): {apphub("/credentials/c1")},
	}), "linux"); len(got) != 0 {
		t.Errorf("adding the credentials/c1directory entry regressed the existing credentials/c1 entry, got %v", got)
	}
}

func TestCheckGraphResolvesTestVariantsToTheirPackage(t *testing.T) {
	t.Parallel()
	// `go list -test` invents "a_test [a.test]" for an external test package.
	// Judged literally, ".../credentials/c1_test" is not beneath the allowed
	// ".../credentials/c1" prefix, and the c1 provider's own external test
	// would be reported as a violation of the rule that exists to permit it.
	nodes := []Node{{
		ImportPath: apphub("/credentials/c1_test [" + apphub("/credentials/c1") + ".test]"),
		ForTest:    apphub("/credentials/c1"),
		Imports:    []string{"github.com/conductorone/sdk"},
	}}
	if got := DefaultConfig().CheckGraph(nodes, "linux"); len(got) != 0 {
		t.Fatalf("c1's own external test must be allowed, got %v", got)
	}
}

func TestCheckGraphFlagsTestOnlyDependency(t *testing.T) {
	t.Parallel()
	nodes := []Node{{
		ImportPath: apphub("/compute/fake [" + apphub("/compute/fake") + ".test]"),
		ForTest:    apphub("/compute/fake"),
		Imports:    []string{"github.com/conductorone/sdk"},
	}}
	got := DefaultConfig().CheckGraph(nodes, "linux")
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if got[0].Kind != KindTest {
		t.Errorf("kind = %q, want %q", got[0].Kind, KindTest)
	}
}

func TestCheckGraphIgnoresPackagesOutsideTheModule(t *testing.T) {
	t.Parallel()
	// A dependency of ours importing c1 is not our violation to report against
	// them; it becomes ours only when one of our packages can reach it.
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		"example.com/unrelated": {"github.com/conductorone/sdk"},
	}), "linux")
	if len(got) != 0 {
		t.Fatalf("third-party packages are not judged, got %v", got)
	}
}

func TestCheckGraphFencesDynamoDB(t *testing.T) {
	t.Parallel()
	// The offender is modules/review rather than modules/deploy, which this
	// case used to name: the deploy fence (USOSS-15) also denies the AWS SDK to
	// modules/deploy, so that package produces one finding per rule and this
	// case would be measuring both. modules/review is outside store/ and
	// outside the deploy fence's subject set, so what survives here is the
	// DynamoDB fence on its own.
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/store"):          {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
		apphub("/store/dynamo"):   {"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"},
		apphub("/modules/review"): {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
	}), "linux")
	// Filtered by rule, because more than one rule can legitimately fire on the
	// same edge: USOSS-14 added `aws-sdk-confined`, which denies the whole AWS
	// SDK to everything outside the provider and the fence, so a DynamoDB import
	// in business logic now breaks two rules rather than one. This test is about
	// the fence, so it counts the fence's findings.
	var fence []Violation
	for _, v := range got {
		if v.RuleName == "dynamodb-fenced" {
			fence = append(fence, v)
		}
	}
	if len(fence) != 1 {
		t.Fatalf("got %d dynamodb-fenced violations, want 1 (only the package outside store/): %v",
			len(fence), got)
	}
	if fence[0].Package != apphub("/modules/review") {
		t.Errorf("wrong package flagged: %s", fence[0].Package)
	}
	if fence[0].RuleName != "dynamodb-fenced" {
		t.Errorf("wrong rule fired: %s", fence[0].RuleName)
	}
}

// TestCheckGraphReportsEveryRuleAPackageBreaks pins what the case above
// deliberately steps around: two rules denying the same import both fire, and a
// reader is told about both. Collapsing them would hide the deploy fence behind
// the older one exactly where they overlap, which is the case that matters.
func TestCheckGraphReportsEveryRuleAPackageBreaks(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/modules/deploy"): {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
	}), "linux")
	rules := map[string]bool{}
	for _, v := range got {
		rules[v.RuleName] = true
	}
	for _, want := range []string{"dynamodb-fenced", "deploy-is-substrate-free"} {
		if !rules[want] {
			t.Errorf("rule %q did not fire on an import it denies; got %v", want, got)
		}
	}
}

func TestCheckGraphIsCleanOnAnEmptySkeleton(t *testing.T) {
	t.Parallel()
	// The state of the repository at bootstrap. A checker that cannot pass on
	// nothing is a checker nobody will keep.
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/compute"):     nil,
		apphub("/credentials"): {"context", "fmt"},
		apphub("/store"):       nil,
	}), "linux")
	if len(got) != 0 {
		t.Fatalf("empty skeleton should be clean, got %v", got)
	}
}

func TestCheckFilesFlagsImportRegardlessOfBuildTag(t *testing.T) {
	t.Parallel()
	// The second bypass review found. CheckFiles never asks whether a file
	// would compile here.
	got := DefaultConfig().CheckFiles([]FileImports{{
		File:    "modules/deploy/deploy_windows.go",
		Package: apphub("/modules/deploy"),
		Kind:    KindBuild,
		Imports: []Import{{Path: apphub("/credentials/c1"), Line: 7}},
	}})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(got), got)
	}
	if got[0].File == "" || got[0].Line != 7 {
		t.Errorf("a file finding must say where to look, got %+v", got[0])
	}
}

func TestCheckFilesAllowsTheFencedPackage(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckFiles([]FileImports{{
		File:    "store/dynamo_windows.go",
		Package: apphub("/store"),
		Imports: []Import{{Path: "github.com/aws/aws-sdk-go-v2/service/dynamodb", Line: 3}},
	}})
	if len(got) != 0 {
		t.Fatalf("store/ may import dynamodb on any platform, got %v", got)
	}
}

func TestMergePrefersTheLocatedFinding(t *testing.T) {
	t.Parallel()
	fromGraph := []Violation{{
		RuleName: "c1-optional", Package: apphub("/store"),
		Import: apphub("/credentials/c1"), Kind: KindBuild, GOOS: "linux",
	}}
	fromFiles := []Violation{{
		RuleName: "c1-optional", Package: apphub("/store"),
		Import: apphub("/credentials/c1"), Kind: KindBuild,
		File: "store/x.go", Line: 4,
	}}
	got := Merge(fromGraph, fromFiles)
	if len(got) != 1 {
		t.Fatalf("the same problem found twice should be reported once, got %v", got)
	}
	if got[0].File != "store/x.go" {
		t.Errorf("merge should keep the finding that names a line, got %+v", got[0])
	}
}

func TestViolationStringNamesEverythingNeededToFixIt(t *testing.T) {
	t.Parallel()
	v := Violation{
		RuleName: "c1-optional",
		Package:  apphub("/store"),
		Import:   "github.com/conductorone/x",
		Via:      []string{"example.com/wrapper"},
		Kind:     KindBuild,
		File:     "store/x.go",
		Line:     9,
		Reason:   "because",
	}
	s := v.String()
	for _, want := range []string{v.Package, v.Import, v.Via[0], string(v.Kind), v.File, v.Reason} {
		if !strings.Contains(s, want) {
			t.Errorf("Violation.String() = %q, missing %q", s, want)
		}
	}
}

func file(name string, tags ...BuildTag) FileImports {
	return FileImports{File: name, Package: apphub("/modules/deploy"), BuildTags: tags}
}

func TestCheckBuildTagsAcceptsOnlyWhatTheClosureRuns(t *testing.T) {
	t.Parallel()
	// Accepted, because a configuration the closure executes selects them.
	for _, tag := range []string{
		"linux", "darwin", "windows", "amd64", "arm64", "unix", "gc",
		// Release tags every toolchain this repository builds with reports.
		"go1.1", "go1.9", "go1.25",
	} {
		got := DefaultConfig().CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: tag, Line: 1})})
		if len(got) != 0 {
			t.Errorf("tag %q is selected by a closure pass and should be accepted, got %v", tag, got)
		}
	}
	// Rejected, because nothing runs them. Every one of these used to be waved
	// through by a hand-written list of "normal" tags, which is how an
	// arm64-only import walked past a checker that only ran amd64.
	for _, tag := range []string{
		"freebsd", "js", "wasip1", "riscv64", "386", "wasm",
		"cgo", "race", "msan", "asan", "gccgo", "purego", "boringcrypto",
		// go1.0 was never a release tag, and go1.99 is not one yet. Versions
		// near the current toolchain are deliberately absent from this table:
		// which of those are reported differs between a 1.25 and a 1.26
		// toolchain, and that is the point of asking the toolchain.
		"go1.0", "go1.99",
	} {
		got := DefaultConfig().CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: tag, Line: 1})})
		if len(got) != 1 {
			t.Errorf("tag %q is selected by no closure pass and must be rejected, got %v", tag, got)
		}
	}
}

// The structural half of the invariant: nothing may be accepted without a
// justification that points at something real.
//
// An earlier version checked that a free-form sentence mentioned a target,
// which a hand-written string satisfies as easily as a genuine one -- review
// walked straight through it. The justification is now the target value itself,
// so the test compares identities rather than prose.
func TestEveryAcceptedSelectorNamesATargetThatRunsIt(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	// Target has a slice field, so it is not comparable; String() encodes every
	// field and is a faithful identity for this purpose.
	targets := map[string]bool{}
	for _, target := range cfg.Targets() {
		targets[target.String()] = true
	}
	for _, sel := range cfg.AcceptedSelectors() {
		switch sel.Kind {
		case SelectedByTarget:
			if !targets[sel.Target.String()] {
				t.Errorf("selector %q claims target %s, which is not in the matrix", sel.Name, sel.Target)
			}
		case SelectedByToolchain:
			// gc, and the release tags the toolchain reports. Both are
			// properties of every pass rather than of one.
			if sel.Name != "gc" && !goVersionTag.MatchString(sel.Name) {
				t.Errorf("selector %q claims toolchain justification but is neither gc nor a release tag", sel.Name)
			}
		default:
			t.Errorf("selector %q has no justification kind", sel.Name)
		}
	}
}

func TestAcceptedSelectorsFollowTheMatrix(t *testing.T) {
	t.Parallel()
	// Narrowing the matrix narrows acceptance, in the same edit. This is the
	// property that stops the two lists from drifting, because there is one.
	cfg := DefaultConfig()
	cfg.GOOS = []string{"linux"}
	cfg.GOARCH = []string{"amd64"}

	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "arm64", Line: 1})}); len(got) != 1 {
		t.Errorf("arm64 is no longer covered and must no longer be accepted, got %v", got)
	}
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "windows", Line: 1})}); len(got) != 1 {
		t.Errorf("windows is no longer covered and must no longer be accepted, got %v", got)
	}
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "linux", Line: 1})}); len(got) != 0 {
		t.Errorf("linux is still covered, got %v", got)
	}

	// And widening coverage widens acceptance, without a second edit anywhere.
	cfg.GOARCH = append(cfg.GOARCH, "riscv64")
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "riscv64", Line: 1})}); len(got) != 0 {
		t.Errorf("riscv64 is now in the matrix and should be accepted, got %v", got)
	}
}

func TestCgoIsAcceptedOnlyWhenAPassEnablesIt(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "cgo", Line: 1})}); len(got) != 1 {
		t.Fatalf("no pass sets CGO_ENABLED=1, so cgo must be rejected, got %v", got)
	}
	cfg.CgoEnabled = true
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "cgo", Line: 1})}); len(got) != 0 {
		t.Fatalf("a cgo pass now exists, so cgo is accepted, got %v", got)
	}
	var sawCgo bool
	for _, target := range cfg.Targets() {
		if target.Cgo {
			sawCgo = true
		}
	}
	if !sawCgo {
		t.Error("accepting cgo must come with a pass that enables it")
	}
}

func TestGoVersionSelectorsFollowTheToolchainsReleaseTags(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.ReleaseTags = []string{"go1.1", "go1.20", "go1.21"}
	if got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "go1.21", Line: 1})}); len(got) != 0 {
		t.Errorf("go1.21 is reported by the toolchain and should be accepted, got %v", got)
	}
	got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "go1.22", Line: 1})})
	if len(got) != 1 {
		t.Fatalf("go1.22 is not reported by the toolchain and must be rejected, got %v", got)
	}
	if !strings.Contains(got[0].Reason, "go1.21") {
		t.Errorf("the message should name what the toolchain does report, got %q", got[0].Reason)
	}
}

func TestDefaultReleaseTagsMatchTheToolchainThatWillRunTheClosure(t *testing.T) {
	t.Parallel()
	// The default is derived from the toolchain that built this binary; the
	// command asks the `go` on PATH. If those ever disagree, a run that falls
	// back to the default judges release selectors against the wrong fact.
	fromToolchain, err := ToolchainReleaseTags("../..")
	if err != nil {
		t.Fatalf("ToolchainReleaseTags: %v", err)
	}
	got := DefaultReleaseTags()
	if len(got) == 0 {
		t.Fatal("DefaultReleaseTags returned nothing, so go1.N selectors would all be rejected")
	}
	if got[len(got)-1] != fromToolchain[len(fromToolchain)-1] {
		t.Errorf("newest release tag: default says %q, the toolchain says %q",
			got[len(got)-1], fromToolchain[len(fromToolchain)-1])
	}
}

func TestCheckBuildTagsRejectsAnUndeclaredTag(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckBuildTags([]FileImports{
		file("modules/deploy/sneaky.go", BuildTag{Name: "reviewbypass", Line: 1}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
	if got[0].Tag != "reviewbypass" || got[0].File != "modules/deploy/sneaky.go" || got[0].Line != 1 {
		t.Errorf("finding should name the tag, file, and line: %+v", got[0])
	}
	// The reason has to say what the finding now means -- no pass type-checks the
	// file -- and must not claim the import is hidden from the boundary rules,
	// because since USOSS-28 the union graph reads the file regardless.
	if !strings.Contains(got[0].Reason, "type-checks") {
		t.Errorf("the reason should say why an unselected tag matters, got %q", got[0].Reason)
	}
	if strings.Contains(got[0].Reason, "can hide") {
		t.Errorf("the reason must not claim a constraint hides an import from the union "+
			"graph, got %q", got[0].Reason)
	}
}

func TestCheckBuildTagsAcceptsADeclaredTag(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.AllowedBuildTags = []string{"integration"}
	got := cfg.CheckBuildTags([]FileImports{file("x.go", BuildTag{Name: "integration", Line: 1})})
	if len(got) != 0 {
		t.Fatalf("a declared tag is allowed, got %v", got)
	}
}

func TestCheckBuildTagsReportsEveryTagInAnExpression(t *testing.T) {
	t.Parallel()
	// `linux && (foo || !bar)` -- the known tag passes and both custom ones are
	// reported. Short-circuit evaluation would have missed at least one, which
	// is why the constraint expression is walked rather than evaluated.
	got := DefaultConfig().CheckBuildTags([]FileImports{file("x.go",
		BuildTag{Name: "linux", Line: 1},
		BuildTag{Name: "foo", Line: 1},
		BuildTag{Name: "bar", Line: 1},
	)})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (foo and bar): %v", len(got), got)
	}
}

func TestCheckBuildTagsIsCleanOnAFileWithNoConstraints(t *testing.T) {
	t.Parallel()
	if got := DefaultConfig().CheckBuildTags([]FileImports{file("x.go")}); len(got) != 0 {
		t.Fatalf("an unconstrained file has nothing to declare, got %v", got)
	}
}

func TestTargetsAddAPassOnlyWhenATagIsDeclared(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.GOOS = []string{"linux", "windows"}
	cfg.GOARCH = []string{"amd64"}
	if got := cfg.Targets(); len(got) != 2 {
		t.Errorf("no declared tags means one pass per platform, got %d", len(got))
	}
	cfg.AllowedBuildTags = []string{"integration"}
	got := cfg.Targets()
	if len(got) != 4 {
		t.Fatalf("a declared tag should add a pass per platform, got %d: %v", len(got), got)
	}
	var tagged int
	for _, target := range got {
		if len(target.Tags) == 1 && target.Tags[0] == "integration" {
			tagged++
		}
	}
	if tagged != 2 {
		t.Errorf("expected two passes with the tag enabled, got %d", tagged)
	}
}

func TestTargetsCoverTheWholeMatrix(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	want := len(cfg.GOOS) * len(cfg.GOARCH)
	if got := len(cfg.Targets()); got != want {
		t.Fatalf("got %d targets, want %d (every GOOS crossed with every GOARCH)", got, want)
	}
	// The specific regression: amd64-only coverage is what let an arm64 import
	// through.
	var sawArm64 bool
	for _, target := range cfg.Targets() {
		if target.GOARCH == "arm64" {
			sawArm64 = true
		}
	}
	if !sawArm64 {
		t.Error("the matrix must include arm64: Graviton and Apple Silicon are ordinary targets")
	}
}

// Ported to the CheckGraph API by the post-squash rebase; the packages,
// expectations and assertions are USOSS-2's, unchanged.
func TestCheckGraphFencesComputeExt(t *testing.T) {
	t.Parallel()
	extPkg := apphub("/compute/ext")
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		// A core package that has no business reaching a non-portable port.
		apphub("/modules/review"): {extPkg},
		// An allowed importer: the deploy module has to be able to ask for an
		// AWS-only bucket type when an application is configured for one.
		apphub("/modules/deploy"): {extPkg},
		// A provider implementing the ports.
		apphub("/compute/aws"): {extPkg},
		// The conformance suite, which checks that an ext lookup succeeds exactly
		// when a provider documents the port.
		apphub("/compute/conformance"): {extPkg},
		// A package whose name merely resembles an allowed one is still fenced:
		// the allowlist names exact paths, and widening it for the suite must not
		// widen it for anything else.
		apphub("/conformance"): {extPkg},
	}), "linux")
	if len(got) != 2 {
		t.Fatalf("want exactly two violations, got %d: %v", len(got), got)
	}
	want := map[string]bool{
		apphub("/modules/review"): true,
		apphub("/conformance"):    true,
	}
	for _, v := range got {
		if !want[v.Package] || v.Import != extPkg {
			t.Errorf("flagged the wrong import: %s", v)
		}
	}
	if !strings.Contains(got[0].Reason, "compute/ext") {
		t.Errorf("reason does not say what the rule protects: %q", got[0].Reason)
	}
}

// The package's own tests may import it, including the external test variant
// `go list -test` decorates.
func TestCheckGraphAllowsComputeExtsOwnTests(t *testing.T) {
	t.Parallel()
	extPkg := apphub("/compute/ext")
	nodes := []Node{{
		ImportPath: apphub("/compute/ext_test [" + extPkg + ".test]"),
		ForTest:    extPkg,
		Imports:    []string{extPkg},
	}}
	if got := DefaultConfig().CheckGraph(nodes, "linux"); len(got) != 0 {
		t.Fatalf("compute/ext's own external test must be allowed, got %v", got)
	}
}

func TestExtRuleDoesNotCatchANearMiss(t *testing.T) {
	t.Parallel()
	// A package whose path merely starts with the same characters must not be
	// fenced; prefix matching is by path segment for exactly this reason.
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/modules/review"): {apphub("/compute/extras")},
	}), "linux")
	if len(got) != 0 {
		t.Errorf("compute/extras was fenced by the compute/ext rule: %v", got)
	}
}
