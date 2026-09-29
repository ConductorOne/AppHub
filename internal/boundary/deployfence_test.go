// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// The deploy fence (USOSS-15) is the acceptance test for the whole Compute
// abstraction: modules/deploy must reach no substrate SDK. These tests are
// about the fence itself, and they are written the way the four historical
// bypasses of this checker say they have to be.
//
// Three things have to hold, and only the first is obvious:
//
//  1. it fires, on every import form somebody has actually used to get past an
//     import check here — blank, aliased, dotted, in-package test, external
//     test, transitive through the provider, and a file no Linux build compiles;
//  2. it does NOT fire on a sibling module that is not a subject, nor on a
//     package inside the subject set that names no substrate. A table proving
//     eight things are caught is indistinguishable from a rule that fires on
//     everything;
//  3. it is not satisfied by an empty set. A subject-scoped rule whose subject
//     package is renamed away goes on passing while guarding nothing, which is
//     the vacuous-pass failure this repository has paid for repeatedly.
//
// They run against a real module directory, not a synthetic node set, and
// against the SHIPPED [DefaultConfig] rather than a rule spelled here. A fixture
// rule would agree with whatever this file believes the shipped one says.

const (
	deployFenceFixture = "testdata/union/deployfence"
	// The fixture module declares this repository's own module path, because
	// Judge refuses a prefix that is not the tree's main module and the shipped
	// rule names real package paths. Nothing in the fixture imports this
	// repository: the paths are the point, the code is stubs.
	deployFenceRule     = "deploy-is-substrate-free"
	deployAllowlistRule = "deploy-imports-are-an-allowlist"
	deploySubject       = DefaultModulePrefix + "/modules/deploy"
	deployFenceAWSStub  = "github.com/aws/aws-sdk-go-v2"
	// A cloud SDK from a vendor the substrate denylist does not name. Review
	// planted exactly this and the denylist stayed green.
	deployFenceOtherVendor = "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	// A module whose path has NO DOT in its first element, reached through a
	// replace directive. The allowlist's membership test used to read it as
	// standard library, which is a bypass of the fence rather than of a
	// diagnostic — see TestNoDotModulePathIsNotStandardLibrary.
	deployFenceNoDotModule = "cloud/sdk/azidentity"
)

// judgeDeployFence loads the fixture and judges it under the shipped rules.
func judgeDeployFence(t *testing.T, cfg Config) *Findings {
	t.Helper()
	u, err := LoadUnion(deployFenceFixture)
	if err != nil {
		t.Fatalf("LoadUnion(%s): %v", deployFenceFixture, err)
	}
	f, err := u.Judge(cfg)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	return f
}

// finding is a violation reduced to what this test is about.
type finding struct {
	pkg      string
	imported string
	kind     ImportKind
	via      string
}

func findingsOf(t *testing.T, f *Findings, rule string) []finding {
	t.Helper()
	var out []finding
	for _, v := range f.Violations() {
		if v.RuleName != rule {
			continue
		}
		out = append(out, finding{
			pkg: v.Package, imported: v.Import, kind: v.Kind,
			via: strings.Join(v.Via, " -> "),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].imported < out[j].imported })
	return out
}

// TestDeployFenceCatchesEveryImportFormAndNothingElse is the planted-import
// control. Every case in want is a form that has to be caught; the assertion is
// an EQUALITY over the fence's whole output, so a finding against the
// non-subject sibling or against the clean subpackage fails it too. Asserting
// containment would let the fence widen silently, which is the failure mode a
// subject set exists to prevent.
func TestDeployFenceCatchesEveryImportFormAndNothingElse(t *testing.T) {
	t.Parallel()
	f := judgeDeployFence(t, DefaultConfig())

	want := []finding{
		// Rewriting the form of an import must not change the answer.
		{deploySubject, deployFenceAWSStub + "/aliased", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/blank", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/direct", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/dotted", KindBuild, ""},
		// A test dependency is not acceptable either: a test that reaches for
		// the SDK is a test that is no longer checking the abstraction.
		{deploySubject, deployFenceAWSStub + "/exttest", KindExternalTest, ""},
		{deploySubject, deployFenceAWSStub + "/intest", KindTest, ""},
		// The interesting one. Importing the AWS provider package is how the
		// dependency comes back without the deploy module naming the SDK at
		// all, and it is the shape a well-meaning "just wire it up here" edit
		// produces.
		{deploySubject, deployFenceAWSStub + "/viaprovider", KindBuild, DefaultModulePrefix + "/compute/aws"},
		// Declared in a *_windows.go file, which no compatibility pass on this
		// host compiles. The union graph ignores build constraints, which is
		// the entire reason it is the proof.
		{deploySubject, deployFenceAWSStub + "/winonly", KindBuild, ""},
		// The fence is about substrates, not about AWS. A deploy module that
		// swapped one SDK for another would still have failed the ticket.
		{deploySubject, "k8s.io/api/core", KindBuild, ""},
	}

	assertFindings(t, findingsOf(t, f, deployFenceRule), want, deployFenceRule)

	// The denylist is deliberately silent about the fourth vendor. That is not
	// a bug in it — it is the reason the allowlist below exists, and asserting
	// it here is what stops somebody "fixing" the denylist by adding a fourth
	// prefix and believing the population defect closed.
	for _, got := range findingsOf(t, f, deployFenceRule) {
		if got.imported == deployFenceOtherVendor {
			t.Errorf("the substrate denylist now names the fourth vendor; adding a prefix "+
				"closes one spelling and leaves the population defect, so this test would "+
				"stop meaning anything: %+v", got)
		}
	}
}

// assertFindings compares a rule's whole output to want, by equality.
func assertFindings(t *testing.T, got, want []finding, rule string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s produced %d finding(s), want %d", rule, len(got), len(want))
	}
	for i := range want {
		if i >= len(got) {
			t.Errorf("%s: missing finding: %+v", rule, want[i])
			continue
		}
		if got[i] != want[i] {
			t.Errorf("%s finding %d:\n got %+v\nwant %+v", rule, i, got[i], want[i])
		}
	}
	for i := len(want); i < len(got); i++ {
		t.Errorf("%s: unexpected finding: %+v", rule, got[i])
	}
}

// TestTheImportAllowlistCatchesTheSubstrateTheDenylistCannotSee is the
// regression test for the review finding on #42, at the reviewer's own entry
// point: a compileable import of a cloud SDK from a vendor the denylist does
// not name.
//
// The property is not "Azure is caught". It is **the complement**: the deploy
// module may reach the packages the allowlist names and nothing else, so a
// dependency nobody anticipated fails without anybody remembering to anticipate
// it. Naming a fourth vendor in the denylist would have closed one spelling and
// left the population exactly as blind.
//
// So the assertion is an equality over the allowlist rule's whole output, which
// is what makes the population claim rather than the vendor claim.
func TestTheImportAllowlistCatchesTheSubstrateTheDenylistCannotSee(t *testing.T) {
	t.Parallel()
	f := judgeDeployFence(t, DefaultConfig())

	want := []finding{
		// A module path with no dot in its first element. Sorted first, and it
		// is the reproduction from round two: the membership test was path
		// spelling, so this was admitted as standard library.
		{deploySubject, deployFenceNoDotModule, KindBuild, ""},
		// The one the denylist cannot see.
		{deploySubject, deployFenceOtherVendor, KindBuild, ""},
		// And everything the denylist does see, because an allowlist forbids
		// what it does not name and it does not name these either.
		{deploySubject, deployFenceAWSStub + "/aliased", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/blank", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/direct", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/dotted", KindBuild, ""},
		{deploySubject, deployFenceAWSStub + "/exttest", KindExternalTest, ""},
		{deploySubject, deployFenceAWSStub + "/intest", KindTest, ""},
		{deploySubject, deployFenceAWSStub + "/viaprovider", KindBuild, DefaultModulePrefix + "/compute/aws"},
		{deploySubject, deployFenceAWSStub + "/winonly", KindBuild, ""},
		{deploySubject, "k8s.io/api/core", KindBuild, ""},
	}
	assertFindings(t, findingsOf(t, f, deployAllowlistRule), want, deployAllowlistRule)

	// The controls in the other direction, and they are what stop an allowlist
	// that forbids everything from passing the table above.
	//
	// The fixture's deploy module also imports the compute interface, the AWS
	// provider package and the standard library, and none of the three produces
	// a finding: the first two are named, and the standard library is permitted
	// without being named. A rule that flagged those would be indistinguishable
	// from one that works.
	permitted := []string{
		DefaultModulePrefix + "/compute",
		DefaultModulePrefix + "/compute/aws",
	}
	std, err := StandardPackages(deployFenceFixture, DefaultGOOS, DefaultGOARCH)
	if err != nil {
		t.Fatalf("StandardPackages: %v", err)
	}
	for _, v := range f.Violations() {
		if v.RuleName != deployAllowlistRule {
			continue
		}
		for _, p := range permitted {
			if v.Import == p {
				t.Errorf("the allowlist flagged %s, which it names", p)
			}
		}
		if std[v.Import] {
			t.Errorf("the allowlist flagged the standard-library import %s", v.Import)
		}
	}
	src, readErr := os.ReadFile(deployFenceFixture + "/modules/deploy/deploy.go")
	if readErr != nil {
		t.Fatalf("reading the fixture: %v", readErr)
	}
	for _, want := range []string{
		DefaultModulePrefix + "/compute\"",
		DefaultModulePrefix + "/compute/aws\"",
		"\"strings\"",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("the fixture no longer imports %s, so the control above passes because "+
				"there was nothing to get wrong", want)
		}
	}
}

// TestAnAllowlistRuleMustBeBoundedAndUnambiguous pins the two configuration
// shapes that would make an allowlist rule mean something other than it says.
func TestAnAllowlistRuleMustBeBoundedAndUnambiguous(t *testing.T) {
	t.Parallel()
	std, err := StandardPackages(".", DefaultGOOS, DefaultGOARCH)
	if err != nil {
		t.Fatalf("StandardPackages: %v", err)
	}
	base := func() Config {
		c := DefaultConfig()
		c.ReleaseTags = []string{"go1.25"}
		c.StandardPackages = std
		return c
	}
	cases := map[string]func(*Rule){
		"both a denylist and an allowlist": func(r *Rule) {
			r.DeniedPrefixes = []string{"example.com/x"}
		},
		"an allowlist with no subject set": func(r *Rule) {
			r.SubjectPrefixes = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			var found bool
			for i := range cfg.Rules {
				if cfg.Rules[i].Name == deployAllowlistRule {
					found = true
					mutate(&cfg.Rules[i])
				}
			}
			if !found {
				t.Fatalf("no %q rule in the shipped configuration", deployAllowlistRule)
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("the configuration validated")
			}
		})
	}
	// And the shipped configuration validates, or every case above passes
	// because Validate refuses everything.
	if err := base().Validate(); err != nil {
		t.Fatalf("the shipped configuration does not validate: %v", err)
	}
}

// TestDeployFenceIsSilentOnPackagesItDoesNotJudge states the negative half
// explicitly rather than leaving it implied by the equality above, because the
// two failures it distinguishes are the ones a reader most needs told apart: a
// rule aimed at the whole tree, and a rule whose subject set is right.
//
// modules/review imports the same stub the deploy module does. If the fence
// reported it, the subject set is not doing anything and the rule is a
// repository-wide ban on the AWS SDK wearing a narrower name.
func TestDeployFenceIsSilentOnPackagesItDoesNotJudge(t *testing.T) {
	t.Parallel()
	f := judgeDeployFence(t, DefaultConfig())
	for _, v := range f.Violations() {
		if v.RuleName != deployFenceRule {
			continue
		}
		if v.Package != deploySubject {
			t.Errorf("the fence judged %s, which is not in its subject set: %s", v.Package, v)
		}
	}
	// And the fixture really does contain a non-subject importer, so the loop
	// above is not passing because there was nothing to get wrong.
	const sibling = DefaultModulePrefix + "/modules/review"
	src, err := os.ReadFile(deployFenceFixture + "/modules/review/review.go")
	if err != nil {
		t.Fatalf("reading the non-subject control: %v", err)
	}
	if !strings.Contains(string(src), deployFenceAWSStub+"/direct") {
		t.Fatalf("%s no longer imports a denied package, so it is not a control", sibling)
	}
}

// TestDeployFenceRuleRefusesToPassOverAnEmptySubjectSet mutates the shipped
// rule the way a rename would and asserts the run fails.
//
// This is the check that stops the fence becoming a green tick with no input.
// Nothing else in the tree would notice: the violations list would be empty,
// every root would be judged, and the summary would report success.
func TestDeployFenceRuleRefusesToPassOverAnEmptySubjectSet(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	var found bool
	for i := range cfg.Rules {
		if cfg.Rules[i].Name != deployFenceRule {
			continue
		}
		found = true
		cfg.Rules[i].SubjectPrefixes = []string{DefaultModulePrefix + "/modules/deploy-renamed-away"}
	}
	if !found {
		t.Fatalf("the shipped configuration has no %q rule, so this test is measuring nothing", deployFenceRule)
	}

	f := judgeDeployFence(t, cfg)
	err := f.Validate()
	if err == nil {
		t.Fatal("a rule that judged no package validated: the fence can be satisfied by an empty set")
	}
	if !strings.Contains(err.Error(), deployFenceRule) {
		t.Errorf("the failure does not name the inert rule, so it does not tell a reader what to fix: %v", err)
	}
	// The mutation must not have worked by breaking something unrelated: the
	// unmutated configuration validates over the same fixture.
	if err := judgeDeployFence(t, DefaultConfig()).Validate(); err != nil {
		t.Fatalf("the unmutated configuration should validate over this fixture: %v", err)
	}
}

// TestSubjectScopingDoesNotWeakenTheTreeWideRules pins the negative for the
// other three rules. They have no subject set, so they judge every root, and a
// refactor that gave them one by accident would narrow two security fences and
// the ext allowlist without changing a single denied prefix.
func TestSubjectScopingDoesNotWeakenTheTreeWideRules(t *testing.T) {
	t.Parallel()
	// The two rules that are claims about one package, and every other rule is
	// a claim about the whole tree. Stated as a partition rather than as a list
	// of the scoped ones, so a rule added to either side without a decision
	// fails here.
	scopedRules := map[string]bool{deployFenceRule: true, deployAllowlistRule: true}
	var seenScoped int
	for _, r := range DefaultConfig().Rules {
		scoped := len(r.SubjectPrefixes) > 0
		if scopedRules[r.Name] {
			seenScoped++
			if !scoped {
				t.Errorf("%s must be subject-scoped: stated tree-wide, one would need an "+
					"allowlist of every substrate-touching package and the other would forbid "+
					"every dependency this repository has", r.Name)
			}
			continue
		}
		if scoped {
			t.Errorf("%s acquired a subject set (%v); it is a claim about the whole tree",
				r.Name, r.SubjectPrefixes)
		}
	}
	if seenScoped != len(scopedRules) {
		t.Errorf("found %d of the %d subject-scoped rules in the shipped configuration; the "+
			"partition above is over a set that no longer exists", seenScoped, len(scopedRules))
	}
}

// TestEveryDeniedPrefixOfTheDeployFenceNamesSomethingInThisModule cross-checks
// the rule's denied set against a population obtained a different way: the
// module requirements this repository actually declares.
//
// The rule's prefixes are a declaration, not a restatement, so they cannot go
// stale against another document. They can be aimed at nothing — a typo, or a
// substrate that left the tree — and a fence aimed at nothing is a fence that
// passes. Reading go.mod is deliberately a different mechanism from the fixture
// above, whose stub module paths are ones this file spelled itself.
func TestEveryDeniedPrefixOfTheDeployFenceNamesSomethingInThisModule(t *testing.T) {
	t.Parallel()
	// ../.. is the module root: this package is internal/boundary.
	gomod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	required := requiredModulePaths(string(gomod))
	if len(required) == 0 {
		t.Fatal("derived no module requirements from go.mod, so every property over them is vacuous")
	}

	var rule Rule
	for _, r := range DefaultConfig().Rules {
		if r.Name == deployFenceRule {
			rule = r
		}
	}
	if rule.Name == "" {
		t.Fatalf("the shipped configuration has no %q rule", deployFenceRule)
	}
	if len(rule.DeniedPrefixes) == 0 {
		t.Fatal("the fence denies nothing")
	}

	for _, denied := range rule.DeniedPrefixes {
		var matched []string
		for _, mod := range required {
			if hasPathPrefix(mod, denied) {
				matched = append(matched, mod)
			}
		}
		if len(matched) == 0 {
			t.Errorf("denied prefix %q matches no module this repository requires: the fence "+
				"is aimed at something that is not in this tree, so it can never fire", denied)
			continue
		}
		t.Logf("%s: %d module(s), e.g. %s", denied, len(matched), matched[0])
	}
}

// requiredModulePaths pulls the module paths out of a go.mod's require blocks.
//
// Deliberately a small reader rather than a parse of the whole file: it is
// looking for a population to cross-check against, and a line it does not
// recognise as a requirement is one it leaves out — which can only make the
// cross-check above stricter, never weaker, because a missing module can only
// turn a matched prefix into an unmatched one and fail the test.
func requiredModulePaths(gomod string) []string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(gomod, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[0], "/") {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}

// TestNoDotModulePathIsNotStandardLibrary pins the membership test the import
// allowlist rests on.
//
// Round two of review defeated the allowlist by adding a locally replaced module
// named `cloud` and importing `cloud/sdk/azidentity` from the fixture's deploy
// module. The membership test was the go command's rule for telling a module
// path from a standard-library one — a dot in the first element — and a
// `replace` target may declare any path it likes.
//
// The inference was SOUND while every rule was a denylist: calling something
// standard by mistake could only stop the walk early on a package no denied
// prefix covered. It became unsound the moment the complement decided admission.
// That asymmetry is the finding, and it is why this test asserts the property
// from both ends rather than checking one string.
func TestNoDotModulePathIsNotStandardLibrary(t *testing.T) {
	t.Parallel()
	std, err := StandardPackages(deployFenceFixture, DefaultGOOS, DefaultGOARCH)
	if err != nil {
		t.Fatalf("StandardPackages: %v", err)
	}
	if len(std) < 100 {
		t.Fatalf("the standard-library set has %d entries, which cannot be right; every "+
			"assertion below would pass over a set that permits nothing", len(std))
	}

	// The reproduction: a real module path with no dot is not standard.
	if std[deployFenceNoDotModule] {
		t.Errorf("%q is treated as standard library; it is provided by a locally replaced "+
			"module and the allowlist would admit it", deployFenceNoDotModule)
	}
	// Neither is its module root, nor a first-party path, nor a vendor path.
	for _, path := range []string{
		"cloud",
		deployFenceOtherVendor,
		DefaultModulePrefix + "/modules/deploy",
		deployFenceAWSStub + "/direct",
	} {
		if std[path] {
			t.Errorf("%q is treated as standard library", path)
		}
	}
	// And the other direction, which is what stops a set that says no to
	// everything from passing the cases above: real standard packages are in
	// it, including ones this host cannot build, and the cgo pseudo-package.
	for _, path := range []string{
		"fmt", "strings", "context", "os/exec", "net/http", "unsafe", CgoPseudoPackage,
		// Platform-specific, and the reason the set is a union over the
		// supported matrix rather than one `go list std`: a Linux-only answer
		// omits these, and the union graph would then try to resolve them as
		// third-party imports when it judged a darwin build.
		"crypto/x509/internal/macos", "internal/routebsd", "internal/syscall/windows",
	} {
		if !std[path] {
			t.Errorf("%q is not in the standard-library set", path)
		}
	}
}

// TestAnImportAllowlistWithoutAStandardLibrarySetIsRefused. Without one, the
// allowlist denies every standard import — loudly rather than silently, but
// still wrongly, and the refusal says what to call.
func TestAnImportAllowlistWithoutAStandardLibrarySetIsRefused(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.ReleaseTags = []string{"go1.25"}
	cfg.StandardPackages = nil
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a configuration with an import allowlist and no standard-library set validated")
	}
	if !strings.Contains(err.Error(), "StandardPackages") {
		t.Errorf("the refusal does not name what to call: %v", err)
	}

	std, serr := StandardPackages(".", DefaultGOOS, DefaultGOARCH)
	if serr != nil {
		t.Fatalf("StandardPackages: %v", serr)
	}
	cfg.StandardPackages = std
	if err := cfg.Validate(); err != nil {
		t.Fatalf("with the set supplied it should validate: %v", err)
	}
}

// TestStandardPackagesRefusesAnEmptyPlatformMatrix. A derivation over no
// platforms returns the cgo pseudo-package and nothing else, which would deny
// the standard library while looking like a set.
func TestStandardPackagesRefusesAnEmptyPlatformMatrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ goos, goarch []string }{
		{nil, DefaultGOARCH},
		{DefaultGOOS, nil},
		{nil, nil},
	} {
		if _, err := StandardPackages(".", tc.goos, tc.goarch); err == nil {
			t.Errorf("goos=%v goarch=%v produced a set", tc.goos, tc.goarch)
		}
	}
}
