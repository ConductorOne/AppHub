// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"fmt"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// USOSS-34. The c1-optional rule is an import-prefix rule, and USOSS-28 made it a
// proof -- but a proof about imports. A package can behave differently for
// ConductorOne without importing anything: it can name the vendor in a trust
// policy, read APPHUB_C1_* out of the environment, aim a request at the vendor's
// API, or branch on the provider's registry id. None of that is an edge in any import
// graph, under any build configuration, so no amount of strengthening the import
// half could ever see it.
//
// The fixtures below are that claim, made concrete. Each one compiles, each one
// declares no denied import, and TestC1CouplingIsInvisibleToTheImportRule proves
// the import rule finds nothing in any of them -- which is what makes the idiom
// rule's findings meaningful rather than redundant.

var c1CouplingFixtures = []struct {
	name    string
	needle  string
	content string
}{
	{
		// The historical instance. A faithful stand-in for the source system's
		// EnsureC1DatasourceRole was placed in compute/aws and `make boundary`
		// passed, reporting that the c1-optional rule held -- recorded in
		// docs/decisions/usoss-11-ensurec1datasourcerole-is-not-ported-and-the-import-graph-does-not-enforce-that.md.
		name:   "a cross-account trust policy naming the vendor's tenant accounts",
		needle: "conductorone",
		content: `package aws

const conductorOneTenantAccount = "arn:aws:iam::<tenant-account>:root"

func trust(externalID string) map[string]any {
	return map[string]any{
		"Effect":    "Allow",
		"Principal": map[string]any{"AWS": conductorOneTenantAccount},
		"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}},
	}
}
`,
	},
	{
		name:   "configuration read straight out of the environment",
		needle: "APPHUB_C1_",
		content: `package deploy

import "os"

func tenant() string { return os.Getenv("APPHUB_C1_TENANT_URL") }
`,
	},
	{
		name:   "a branch on the provider's registry id",
		needle: "c1",
		content: `package lifecycle

func ttlFor(providerID string) int {
	if providerID == "c1" {
		return 3600
	}
	return 900
}
`,
	},
	{
		// The vendor's endpoint, named through the path rather than the host. That
		// is not a softened fixture, it is the only one this repository can hold:
		// .gitleaks.toml forbids spelling a vendor hostname anywhere here, so a
		// fixture that named one would be a disclosure finding rather than a test.
		// The coupling is the same either way, and so is the needle that catches it.
		name:   "a request aimed at the vendor's API",
		needle: "conductorone",
		content: `package deploy

const datasourcePath = "/api/v1/conductorone/datasources"
`,
	},
	{
		name: "the vendor's name written with an escape",
		// The escape bypass that defeated the first version of the DynamoDB rule,
		// aimed at this one. "\x63onductorone" is "conductorone" to the compiler.
		needle: "conductorone",
		content: `package deploy

var tag = "\x63onductorone-datasource"
`,
	},
	{
		// This module is published under the vendor's organization, and the rule
		// masks exactly that path. A sibling module under the same organization is
		// not this module.
		name:   "a sibling module under the vendor's organization",
		needle: "conductorone",
		content: `package deploy

const sdk = "github.com/conductorone/conductorone-sdk-go/pkg/client"
`,
	},
	{
		name:   "this module's path spelled with the vendor's capitalisation",
		needle: "conductorone",
		content: `package deploy

const pkg = "github.com/ConductorOne/apphub/store"
`,
	},
	{
		name:   "this module's c1 provider named by path",
		needle: "c1",
		content: `package deploy

const provider = "github.com/conductorone/apphub/credentials/c1"
`,
	},
	{
		name:   "the vendor's name assembled from constant fragments",
		needle: "conductorone",
		content: `package deploy

import "fmt"

func role(app string) string { return fmt.Sprintf("%s-%s%s", app, "conductor", "one") }
`,
	},
	{
		name:   "an environment variable spelled in the vendor's own namespace",
		needle: "c1",
		content: `package deploy

import "os"

func secret() string { return os.Getenv("C1_CLIENT_SECRET") }
`,
	},
}

// TestC1IdiomRuleCatchesBehaviouralCoupling is the green half: every fixture is
// reported, with a line, a reason and the name of the rule that reported it.
func TestC1IdiomRuleCatchesBehaviouralCoupling(t *testing.T) {
	t.Parallel()
	rule := DefaultC1IdiomRule()

	for _, tc := range c1CouplingFixtures {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rule.Check([]SourceFile{{
				Path:    "compute/aws/datasource.go",
				Content: []byte(tc.content),
			}})
			if len(got) == 0 {
				t.Fatalf("no leak reported; this fixture imports nothing under a denied "+
					"prefix, so the import rule cannot catch it either (needle %q)", tc.needle)
			}
			var found bool
			for _, leak := range got {
				if leak.Needle != tc.needle {
					continue
				}
				found = true
				if leak.Line == 0 {
					t.Error("leak has no line number; a violation you cannot navigate to is a bug report")
				}
				if leak.Reason == "" {
					t.Error("leak has no reason; the message has to explain the rule, not just cite it")
				}
				if leak.Rule != rule.Name {
					t.Errorf("leak names rule %q, want %q; with two idiom rules a finding that "+
						"does not say which fence it broke makes the reader guess", leak.Rule, rule.Name)
				}
			}
			if !found {
				t.Errorf("leaks %v do not include the expected needle %q", got, tc.needle)
			}
		})
	}
}

// TestC1CouplingIsInvisibleToTheImportRule is the premise of this whole ticket,
// and it is established rather than asserted.
//
// Every fixture above is placed in the import graph as a first-party package
// importing exactly what it declares, and the c1-optional rule -- the shipped
// one, over the shipped configuration -- reports nothing. If this test ever
// starts failing because the import rule caught one, the fixture has stopped
// being a demonstration of the gap and the idiom rule below it is guarding
// something the import half already covers.
//
// The control at the end is what stops this being a test that cannot fail: the
// same construction, with one denied import added, produces exactly one finding.
func TestC1CouplingIsInvisibleToTheImportRule(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()

	for _, tc := range c1CouplingFixtures {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			imports := declaredImports(t, tc.content)

			// compute/aws: a first-party package the c1-optional rule judges, and
			// the package the historical stand-in was actually placed in.
			violations := c1Findings(cfg.CheckGraph(graph(map[string][]string{
				apphub("/compute/aws"): imports,
			}), "linux"))
			if len(violations) != 0 {
				t.Fatalf("the import rule reported %v for a fixture whose imports are %v; "+
					"the fixture is supposed to declare no denied import", violations, imports)
			}

			// And the idiom rule, over the same source, does report it.
			leaks := DefaultC1IdiomRule().Check([]SourceFile{{
				Path:    "compute/aws/datasource.go",
				Content: []byte(tc.content),
			}})
			if len(leaks) == 0 {
				t.Fatalf("neither half saw it: imports %v, and no idiom leak either", imports)
			}
		})
	}

	// The control.
	control := c1Findings(cfg.CheckGraph(graph(map[string][]string{
		apphub("/compute/aws"): {"os", apphub("/credentials/c1")},
	}), "linux"))
	if len(control) != 1 {
		t.Fatalf("the control produced %d c1-optional findings, want 1; if a real import "+
			"is not caught by this construction then the zero results above prove nothing", len(control))
	}
}

// c1Findings narrows a finding set to the c1-optional rule. It is deliberately
// not onlyRule: this test asserts an *empty* result, and onlyRule fails a
// non-empty run that produced nothing for the named rule.
func c1Findings(all []Violation) []Violation {
	var out []Violation
	for _, v := range all {
		if v.RuleName == "c1-optional" {
			out = append(out, v)
		}
	}
	return out
}

// declaredImports returns the import paths a fixture declares, which is exactly
// what the import graph would have to work with.
func declaredImports(tb testing.TB, src string) []string {
	tb.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		tb.Fatalf("fixture does not parse, so it is not a demonstration of anything: %v", err)
	}
	out := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		out = append(out, unquoteString(spec.Path.Value))
	}
	return out
}

// TestC1IdiomRuleIgnoresComments is the false-positive half, and it matters more
// for this rule than for the DynamoDB one: half the files in this repository
// explain why ConductorOne is optional, and a gate that fires on its own
// rationale gets suppressed within a week.
func TestC1IdiomRuleIgnoresComments(t *testing.T) {
	t.Parallel()
	content := `package ext

// CrossDomainGrant is the port. The prospective consumer is ConductorOne's
// datasource registration, which reads APPHUB_C1_TENANT_URL and posts to
// /api/v1/service_principals/ on the tenant -- none of which happens here, and
// the provider id "c1" is not this package's business.
/*
   A block comment about conductorone, c1, and APPHUB_C1_CLIENT_ID.
*/
type CrossDomainGrant interface{}
`
	if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: "compute/ext/ext.go", Content: []byte(content)}}); len(got) != 0 {
		t.Fatalf("comments were flagged as leaks: %v", got)
	}
}

// TestTokenNeedleIsDelimitedNotCamelCase pins the bound stated on [MatchToken].
//
// "c1" is two characters, so it is matched only as a delimited token. That is
// what makes it a check rather than noise -- and it is also why OpC1FetchToken is
// not a match. A camel-case boundary was tried and rejected: it makes doc1, svc1
// and rec1 into findings, and a gate that fires on ordinary Go is a gate somebody
// deletes.
func TestTokenNeedleIsDelimitedNotCamelCase(t *testing.T) {
	t.Parallel()
	needle := Needle{Text: "c1", Reason: "r", Match: MatchToken, Fold: true}

	caught := []string{
		"c1",
		"c1: mint credential",
		"id=c1 name=ConductorOne",
		"APPHUB_C1_TENANT_URL",
		"C1_CLIENT_SECRET",
		"provider-c1-dynamic",
		"the c1 provider",
		// A host label. This is why the rule needs no separate needle for the
		// vendor's domains: a label is delimited by dots and slashes like anything
		// else. The suffix here is the RFC 2606 reserved one, because .gitleaks.toml
		// forbids spelling a real vendor host anywhere in this repository.
		"https://tenant.c1.invalid/auth/v1/token",
	}
	for _, s := range caught {
		if !needle.Found(s) {
			t.Errorf("%q was not matched, and it names the provider", s)
		}
	}

	clean := []string{
		"OpC1FetchToken",
		"doc1",
		"svc1",
		"rec1",
		"c10",
		"abc123",
		"Func1Thing",
		"7c1f9e",
		"",
	}
	for _, s := range clean {
		if needle.Found(s) {
			t.Errorf("%q was matched; ordinary Go must not trip a two-character needle", s)
		}
	}
}

// TestC1NeedlesFoldCase: ConductorOne is spelled three ways in this repository --
// a display name, an error string, an environment variable -- and all three are
// the same coupling.
func TestC1NeedlesFoldCase(t *testing.T) {
	t.Parallel()
	rule := DefaultC1IdiomRule()
	for _, spelling := range []string{
		"ConductorOne", "conductorone", "CONDUCTORONE", "conductorOne",
		"CONDUCTORONE-DATASOURCE", "apphub_c1_tenant_url",
	} {
		if _, ok := rule.match(spelling); !ok {
			t.Errorf("%q was not matched", spelling)
		}
	}
}

// TestC1IdiomRuleAllowsTheProviderAndTheCompositionRoot: the provider is what the
// coupling is *for*, and cmd/apphub is the one allowlisted composition root --
// the same single entry the import half carries, for the same reason (USOSS-8).
func TestC1IdiomRuleAllowsTheProviderAndTheCompositionRoot(t *testing.T) {
	t.Parallel()
	content := `package c1

import "os"

const providerID = "c1"

func tenant() string { return os.Getenv("APPHUB_C1_TENANT_URL") }

var name = "ConductorOne"
`
	for _, path := range []string{
		"credentials/c1/config.go",
		"credentials/c1/config_test.go",
		"cmd/apphub/main.go",
		"cmd/apphub/main_test.go",
	} {
		if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: path, Content: []byte(content)}}); len(got) != 0 {
			t.Errorf("%s is allowed and was flagged anyway: %v", path, got)
		}
	}

	// And a near-miss, the same one the import rule guards against: a package
	// whose path merely begins with the allowed spelling is not the allowed
	// package. hasPathPrefix is segment-aware, and this is what proves it here.
	for _, path := range []string{"credentials/c1sync/sync.go", "cmd/apphubctl/main.go"} {
		if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: path, Content: []byte(content)}}); len(got) == 0 {
			t.Errorf("%s was treated as an allowed package", path)
		}
	}
}

// TestC1IdiomRuleAllowsTheDirectoryClient pins the second, independently
// added entry for credentials/c1directory. It is a real second entry and not
// an accidental match on the "credentials/c1" prefix above: the near-miss
// case in the table proves hasPathPrefix does not fold "c1directory" into
// "c1" either.
func TestC1IdiomRuleAllowsTheDirectoryClient(t *testing.T) {
	t.Parallel()
	content := `package c1directory

import "os"

func tenant() string { return os.Getenv("APPHUB_C1_DIRECTORY_TENANT_URL") }

var name = "ConductorOne"
`
	for _, path := range []string{
		"credentials/c1directory/config.go",
		"credentials/c1directory/config_test.go",
		"cmd/apphub/main.go",
	} {
		if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: path, Content: []byte(content)}}); len(got) != 0 {
			t.Errorf("%s is allowed and was flagged anyway: %v", path, got)
		}
	}

	// internal/worker never gets an idiom exemption: DirectorySyncer depends on
	// a narrow local interface, never on this package, so its source should
	// never need to name ConductorOne at all.
	for _, path := range []string{"internal/worker/directorysync.go", "credentials/c1directory2/x.go"} {
		if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: path, Content: []byte(content)}}); len(got) == 0 {
			t.Errorf("%s was treated as an allowed package", path)
		}
	}
}

// TestTheC1IdiomExemptionIsOneCredhttpFileNotThePackage.
//
// internal/credhttp owns the HTTP policy for every credential-bearing request
// here, and its operation labels are a deliberately closed set -- Op cannot be
// built from outside the package, which is what stops response-controlled text
// reaching a log line. Four of those labels name ConductorOne. That is a decided
// coupling rather than drift, and the fix for a decided coupling is an allowlist
// entry with the reason attached.
//
// The entry is one FILE. This case is what keeps it that way: the package's other
// files, tests included, are still checked.
func TestTheC1IdiomExemptionIsOneCredhttpFileNotThePackage(t *testing.T) {
	t.Parallel()
	rule := DefaultC1IdiomRule()

	exempt := SourceFile{
		Path: "internal/credhttp/credhttp.go",
		Content: []byte(`package credhttp

func OpC1MintCredential() Op { return Op{label: "c1: mint credential"} }
`),
	}
	if leaks := rule.Check([]SourceFile{exempt}); len(leaks) != 0 {
		t.Errorf("%s is exempt and was flagged anyway: %v", exempt.Path, leaks)
	}

	for _, path := range []string{
		"internal/credhttp/opset_test.go",
		"internal/credhttp/credhttp_test.go",
		"internal/credhttp/policy.go",
	} {
		f := SourceFile{Path: path, Content: []byte(`package credhttp

var label = "c1: mint credential"
`)}
		if leaks := rule.Check([]SourceFile{f}); len(leaks) == 0 {
			t.Errorf("%s is not the exempt file and was not checked", path)
		}
	}
}

// TestImportPathsAreNotIdiomLeaks pins the one place these rules deliberately do
// not look.
//
// An import path is the import rules' subject, judged over a union graph that is
// a proof rather than a lexical net. Reporting it here as well would describe one
// coupling twice and misname the second report. It closes nothing: a package
// importing credentials/c1 is a c1-optional violation, and the same path written
// as a string anywhere other than an import declaration -- a plugin lookup, a
// registry key -- is still matched here, which is the case below.
func TestImportPathsAreNotIdiomLeaks(t *testing.T) {
	t.Parallel()
	rule := DefaultC1IdiomRule()

	imported := SourceFile{
		Path: "compute/aws/wire.go",
		Content: []byte(`package aws

import (
	_ "github.com/conductorone/apphub/credentials/c1"
	c1sdk "github.com/conductorone/conductorone-sdk-go/pkg/client"
)

var _ = c1sdk.New
`),
	}
	if leaks := rule.Check([]SourceFile{imported}); len(leaks) != 0 {
		t.Errorf("an import declaration was reported as an idiom leak: %v; the import half "+
			"owns that finding and states it as a dependency, which is what it is", leaks)
	}

	// The same path, not in an import declaration. This is the shape the import
	// graph genuinely cannot see, and it is still caught.
	byName := SourceFile{
		Path: "compute/aws/wire.go",
		Content: []byte(`package aws

const provider = "github.com/conductorone/apphub/credentials/c1"
`),
	}
	if leaks := rule.Check([]SourceFile{byName}); len(leaks) == 0 {
		t.Error("a package named as a string, which no import graph can see, was not caught")
	}
}

// TestTokenNeedleIsNotRunThroughTheAssemblyNet states a limit rather than a
// property, the way TestRuntimeAssemblyIsAStatedLimit does.
//
// The conservative net asks whether constant fragments could tile a needle in any
// order. What sits either side of the result is a runtime value it cannot see, so
// the delimiter test that makes "c1" mean anything cannot be applied there -- and
// without it the needle is assemblable from any pair of fragments ending in "c"
// and beginning with "1", which is not a check.
//
// The cost is small and is bounded by the first half of this case: the exact
// folder still evaluates a concatenation and a constant fmt.Sprintf, delimiter
// test intact.
func TestTokenNeedleIsNotRunThroughTheAssemblyNet(t *testing.T) {
	t.Parallel()
	rule := DefaultC1IdiomRule()

	folded := SourceFile{Path: "compute/aws/x.go", Content: []byte(`package aws

const id = "c" + "1"
`)}
	if leaks := rule.Check([]SourceFile{folded}); len(leaks) == 0 {
		t.Error(`"c" + "1" is "c1" to the compiler and was not caught`)
	}

	// strings.Join is modelled exactly too, so this is not the bound either -- it
	// is the same folder reaching one construct further.
	joined := SourceFile{Path: "compute/aws/x.go", Content: []byte(`package aws

import "strings"

var id = strings.Join([]string{"c", "1"}, "")
`)}
	if leaks := rule.Check([]SourceFile{joined}); len(leaks) == 0 {
		t.Error("strings.Join of the two characters is exactly folded and was not caught")
	}

	// The stated bound. A helper the folder has never heard of assembling the same
	// two characters is not reported, because the conservative net that would
	// catch it cannot apply the delimiter test. This case exists so that the limit
	// is written down and noticed if it ever changes.
	viaHelper := SourceFile{Path: "compute/aws/x.go", Content: []byte(`package aws

func concat(a, b string) string { return a + b }

var id = concat("c", "1")
`)}
	if leaks := rule.Check([]SourceFile{viaHelper}); len(leaks) != 0 {
		t.Logf("the assembly net now reports a two-character token needle: %v", leaks)
		t.Log("that may be an improvement, but MatchToken's documented bound and this " +
			"case have to be updated together")
		t.Fail()
	}

	// The long needles, which are the ones assembly plausibly hides, stay in the
	// net -- including through the very helper the bound above escapes with.
	assembled := SourceFile{Path: "compute/aws/x.go", Content: []byte(`package aws

func concat(a, b, c string) string { return a + b + c }

var role = concat("conductor", "one", "-datasource")
`)}
	if leaks := rule.Check([]SourceFile{assembled}); len(leaks) == 0 {
		t.Error("a vendor name assembled through an unmodelled helper was not caught")
	}
}

// TestC1IdiomRuleCleanFilesAreClean guards against the failure this rule is most
// exposed to: a needle so generic it fires on ordinary Go.
//
// `c1, c2 := ...` is the case that made "c1" StringsOnly. It is an abbreviation
// for a local variable and it is everywhere in test code; a boundary gate that
// turns it red would be removed within a week, and rightly.
func TestC1IdiomRuleCleanFilesAreClean(t *testing.T) {
	t.Parallel()
	content := `package deploy

import "fmt"

type doc1 struct {
	svc1 string
	rec1 int
}

const digest = "9f7c1e4ab2c1d0"

func render(d doc1) string {
	c1, c2 := d.svc1, d.rec1
	return fmt.Sprintf("%s/%d/%s", c1, c2, digest)
}
`
	if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: "modules/deploy/render.go", Content: []byte(content)}}); len(got) != 0 {
		t.Fatalf("clean file flagged: %v", got)
	}
}

// This module's own path spells the vendor's organization. Naming a package of
// this module is not coupling to the vendor, whether the path is a whole literal
// or an argument to a call the rule can only see as fragments.
func TestC1IdiomRuleMasksThisModulesPath(t *testing.T) {
	t.Parallel()
	content := `package deploy

import "fmt"

const pkg = "github.com/conductorone/apphub/store"

func describe(name string) string {
	return fmt.Sprint("github.com/conductorone/apphub/compute", name)
}
`
	if got := DefaultC1IdiomRule().Check([]SourceFile{{Path: "modules/deploy/describe.go", Content: []byte(content)}}); len(got) != 0 {
		t.Fatalf("this module's own path was flagged: %v", got)
	}
}

// TestIdiomRuleValidateRefusesARuleThatCannotReport keeps the discipline the rest
// of this package keeps: a gate configured with nothing to look for inspects
// every file in the tree and reports that the rule held.
func TestIdiomRuleValidateRefusesARuleThatCannotReport(t *testing.T) {
	t.Parallel()
	base := func() IdiomRule {
		return IdiomRule{
			Name:    "n",
			Subject: "s",
			Advice:  "a",
			Needles: []Needle{{Text: "t", Reason: "r"}},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("a complete rule was refused: %v", err)
	}

	cases := map[string]func(*IdiomRule){
		"no name":           func(r *IdiomRule) { r.Name = "" },
		"no subject":        func(r *IdiomRule) { r.Subject = "" },
		"no advice":         func(r *IdiomRule) { r.Advice = "" },
		"no needles":        func(r *IdiomRule) { r.Needles = nil },
		"needle no text":    func(r *IdiomRule) { r.Needles[0].Text = "" },
		"needle no reason":  func(r *IdiomRule) { r.Needles[0].Reason = "" },
		"empty needle list": func(r *IdiomRule) { r.Needles = []Needle{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := base()
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestValidateIdiomRulesRefusesAnEmptySetAndDuplicateNames(t *testing.T) {
	t.Parallel()
	if err := ValidateIdiomRules(nil); err == nil {
		t.Error("an empty rule set was accepted; it would hold over every file in the tree")
	}
	one := DefaultDynamoDBIdiomRule()
	if err := ValidateIdiomRules([]IdiomRule{one, one}); err == nil {
		t.Error("two rules with one name were accepted; a finding from them cannot be attributed")
	}
}

// TestDefaultIdiomRulesAreShippedComplete: the shipped set, through the same
// validation the command runs, so a rule added without a subject or an advice
// fails here rather than printing a blank line in CI.
func TestDefaultIdiomRulesAreShippedComplete(t *testing.T) {
	t.Parallel()
	rules := DefaultIdiomRules()
	if len(rules) != 2 {
		t.Fatalf("got %d idiom rules, want the 2 this repository ships "+
			"(dynamodb-idiom-fenced, c1-idiom-fenced)", len(rules))
	}
	if err := ValidateIdiomRules(rules); err != nil {
		t.Fatalf("the shipped rules do not validate: %v", err)
	}
	want := map[string]bool{"dynamodb-idiom-fenced": true, "c1-idiom-fenced": true}
	for _, r := range rules {
		if !want[r.Name] {
			t.Errorf("unexpected rule %q", r.Name)
		}
		if !strings.HasSuffix(r.Advice, "\n") {
			t.Errorf("%s: advice must end in a newline; it is printed verbatim", r.Name)
		}
	}
}

// TestLeakStringNamesItsRule: with two rules, the one-line rendering has to say
// which fence was broken.
func TestLeakStringNamesItsRule(t *testing.T) {
	t.Parallel()
	l := Leak{Rule: "c1-idiom-fenced", Path: "a/b.go", Line: 7, Token: "c1", Needle: "c1", Reason: "because"}
	got := l.String()
	for _, want := range []string{"c1-idiom-fenced", "a/b.go:7", "because"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not contain %q", got, want)
		}
	}
	_ = fmt.Sprint(l)
}
