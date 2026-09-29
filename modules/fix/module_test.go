// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/modules"
	"github.com/conductorone/apphub/modules/fix"
	"github.com/conductorone/apphub/modules/review"
)

// configFields classifies every field of [fix.Config] and of the nested
// [fix.Limits], and is the population TestNewRefusesEveryAbsentDependency
// quantifies over.
//
// The map is checked against the struct by reflection rather than trusted: a
// field with no entry is fatal. The previous version of this test claimed that
// "a field added to fix.Config without a guard fails this test" while being a
// hand-written list, and a review added a field and watched it pass. A claim
// about future fields has to be derived from the type or it is a claim about
// the fields somebody remembered.
//
// interfaceDep says the field is an interface, which gets two absences rather
// than one: the untyped nil, and an interface holding a nil pointer. The
// second is the one that was open -- an interface value with a type in it is
// not nil, so a constructor comparing to nil accepts it and the module panics
// on first use.
type fieldClass struct {
	// absences returns the ways this field can be absent, each as a mutation
	// of an otherwise-complete configuration.
	absences map[string]func(*fix.Config)
}

func configFields() map[string]fieldClass {
	return map[string]fieldClass{
		"Fixer": {absences: map[string]func(*fix.Config){
			"untyped nil": func(c *fix.Config) { c.Fixer = nil },
			"typed nil":   func(c *fix.Config) { c.Fixer = (*stubFixer)(nil) },
		}},
		"Source": {absences: map[string]func(*fix.Config){
			"untyped nil": func(c *fix.Config) { c.Source = nil },
			"typed nil":   func(c *fix.Config) { c.Source = (*stubFetcher)(nil) },
		}},
		"Git": {absences: map[string]func(*fix.Config){
			"untyped nil": func(c *fix.Config) { c.Git = nil },
			"typed nil":   func(c *fix.Config) { c.Git = (*stubGit)(nil) },
		}},
		"Scans": {absences: map[string]func(*fix.Config){
			"untyped nil": func(c *fix.Config) { c.Scans = nil },
			"typed nil":   func(c *fix.Config) { c.Scans = (*stubScans)(nil) },
		}},
		"Store": {absences: map[string]func(*fix.Config){
			"untyped nil": func(c *fix.Config) { c.Store = nil },
			"typed nil":   func(c *fix.Config) { c.Store = (*stubStore)(nil) },
		}},
		"Logger": {absences: map[string]func(*fix.Config){
			"nil": func(c *fix.Config) { c.Logger = nil },
		}},
		"Identity": {absences: map[string]func(*fix.Config){
			"zero":         func(c *fix.Config) { c.Identity = fix.Identity{} },
			"not a slug":   func(c *fix.Config) { c.Identity = fix.Identity{Name: "not a slug"} },
			"leading dash": func(c *fix.Config) { c.Identity = fix.Identity{Name: "-x"} },
		}},
		"MaxSourceBytes": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.MaxSourceBytes = 0 },
			"negative": func(c *fix.Config) { c.MaxSourceBytes = -1 },
		}},
		"Limits.MaxFiles": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.Limits.MaxFiles = 0 },
			"negative": func(c *fix.Config) { c.Limits.MaxFiles = -1 },
		}},
		"Limits.MaxLines": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.Limits.MaxLines = 0 },
			"negative": func(c *fix.Config) { c.Limits.MaxLines = -1 },
		}},
		"Limits.MaxBytesPerFile": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.Limits.MaxBytesPerFile = 0 },
			"negative": func(c *fix.Config) { c.Limits.MaxBytesPerFile = -1 },
		}},
		"Limits.MaxEncodedPatchBytes": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.Limits.MaxEncodedPatchBytes = 0 },
			"negative": func(c *fix.Config) { c.Limits.MaxEncodedPatchBytes = -1 },
		}},
		"Limits.TerminalWriteTimeout": {absences: map[string]func(*fix.Config){
			"zero":     func(c *fix.Config) { c.Limits.TerminalWriteTimeout = 0 },
			"negative": func(c *fix.Config) { c.Limits.TerminalWriteTimeout = -time.Second },
		}},
	}
}

func completeConfig() fix.Config {
	return fix.Config{
		Fixer: &stubFixer{}, Source: &stubFetcher{}, Git: newGit(),
		Scans: &stubScans{}, Store: &stubStore{}, Logger: discardLogger(),
		Identity: fix.Identity{Name: "apphub"}, Limits: testLimits(),
		MaxSourceBytes: review.SuggestedMaxSourceBytes,
	}
}

// TestEveryConfigFieldIsClassified derives the population from the types. An
// unclassified field is fatal, which is what makes the test below a rule about
// fix.Config rather than about the fields that were listed.
func TestEveryConfigFieldIsClassified(t *testing.T) {
	classified := configFields()

	// Derive the field set from the types. Limits is a struct of bounds rather
	// than a dependency, so it contributes its own fields under a prefix and
	// not an entry of its own.
	var declared []string
	for i, typ := 0, reflect.TypeOf(fix.Config{}); i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if typ.Field(i).Type == reflect.TypeOf(fix.Limits{}) {
			for j, lim := 0, reflect.TypeOf(fix.Limits{}); j < lim.NumField(); j++ {
				declared = append(declared, name+"."+lim.Field(j).Name)
			}
			continue
		}
		declared = append(declared, name)
	}
	if len(declared) == 0 {
		t.Fatal("reflection produced no fields; the derivation is not reading the types")
	}

	for _, name := range declared {
		if _, ok := classified[name]; !ok {
			t.Errorf("fix.Config field %q is not classified in configFields(), so nothing checks that "+
				"New guards it. Add it, with the ways it can be absent", name)
		}
	}
	for name := range classified {
		if !slices.Contains(declared, name) {
			t.Errorf("configFields() classifies %q, which is no longer a field of fix.Config or "+
				"fix.Limits; the population has drifted from the type", name)
		}
	}
	t.Logf("classified %d field(s) derived from fix.Config and fix.Limits", len(declared))
}

// TestNewRefusesEveryAbsentDependency quantifies over that derived population,
// and over both kinds of nil for every interface.
func TestNewRefusesEveryAbsentDependency(t *testing.T) {
	cases := 0
	for field, class := range configFields() {
		if len(class.absences) == 0 {
			t.Errorf("%s is classified with no way of being absent, so nothing is checked for it", field)
			continue
		}
		for how, mutate := range class.absences {
			cases++
			cfg := completeConfig()
			mutate(&cfg)
			m, err := fix.New(cfg)
			what := field + " (" + how + ")"
			if err == nil {
				t.Errorf("New with %s returned a module and no error; it must fail closed", what)
				continue
			}
			if m != nil {
				t.Errorf("New with %s returned a non-nil module alongside its error", what)
			}
			if !errors.Is(err, modules.ErrNotConfigured) {
				t.Errorf("New with %s returned %v, which does not match modules.ErrNotConfigured", what, err)
			}
		}
	}
	// The control in the other direction: a constructor that refused
	// everything would satisfy every assertion above.
	if _, err := fix.New(completeConfig()); err != nil {
		t.Fatalf("New with everything supplied failed: %v", err)
	}
	t.Logf("refused %d absent-dependency configuration(s) and accepted the complete one", cases)
}

// TestATypedNilDependencyNeverReachesExecute is the consequence the guard
// exists for, stated separately because "the constructor refused it" and "no
// module holding one can be built" are different claims, and it was the second
// that failed: both constructors returned usable-looking modules and both
// panicked on their first call.
func TestATypedNilDependencyNeverReachesExecute(t *testing.T) {
	typedNils := 0
	for field, class := range configFields() {
		mutate, ok := class.absences["typed nil"]
		if !ok {
			continue
		}
		typedNils++
		cfg := completeConfig()
		mutate(&cfg)
		m, err := fix.New(cfg)
		if err == nil || m != nil {
			t.Fatalf("New accepted a typed-nil %s, so Execute can be reached with one", field)
		}
	}
	if typedNils == 0 {
		t.Fatal("no field is classified with a typed nil, so this checks nothing")
	}
	t.Logf("checked %d typed-nil interface dependencies", typedNils)
}

// TestIdentityValidateAdmitsOnlySlugs runs both directions. The name is
// spliced into a ref, a label, and markup, so what it may contain is the
// intersection of what all three accept.
func TestIdentityValidateAdmitsOnlySlugs(t *testing.T) {
	good := []string{"a", "A", "9", "apphub", "on-sight", "AppHub9", strings.Repeat("a", 39)}
	for _, name := range good {
		if err := (fix.Identity{Name: name}).Validate(); err != nil {
			t.Errorf("Identity{%q}.Validate() = %v, want accepted", name, err)
		}
	}
	bad := []string{
		"", " ", "-x", "_x", ".x", "a/b", "a b", "a.b", "a_b", "a\nb", "a\x00b",
		"a:b", "a?b", "a#b", "a%b", "a\\b", "a~b", "a^b", "a`b", "a*b", "a[b",
		"a@b", "é", "refs/heads/x", "..", strings.Repeat("a", 40),
	}
	for _, name := range bad {
		if err := (fix.Identity{Name: name}).Validate(); err == nil {
			t.Errorf("Identity{%q}.Validate() accepted an unsafe name", name)
		}
	}
	t.Logf("accepted %d identity names and refused %d", len(good), len(bad))
}

// TestExecuteOpensADraftPullRequest states what a whole successful run does,
// including the order of the write sequence and the fact that the pull request
// is a draft.
func TestExecuteOpensADraftPullRequest(t *testing.T) {
	h := newHarness(t)
	res, err := h.module.Execute(context.Background(), "user-1", validParams())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute reported Success false on a clean run: %+v", res)
	}
	wantStore := "MarkRunning,MarkStatus:validating,RecordVerdict,MarkStatus:patching,RecordPatch,MarkStatus:pushing,RecordCost,Complete"
	if got := strings.Join(h.store.seq, ","); got != wantStore {
		t.Fatalf("store sequence =\n  %q\nwant\n  %q", got, wantStore)
	}
	wantGit := "BranchHead:main,CommitTree:basesha,CreateBlob,CreateTree,CreateCommit,CreateBranch:apphub/fix-scan-1-0,OpenPullRequest,AddLabels"
	if got := strings.Join(h.git.seq, ","); got != wantGit {
		t.Fatalf("git sequence =\n  %q\nwant\n  %q", got, wantGit)
	}
	if !h.git.opened.Draft {
		t.Error("the pull request was not opened as a draft; a person is the last step of this pipeline")
	}
	if h.git.opened.Base != "main" || h.git.opened.Head != "apphub/fix-scan-1-0" {
		t.Errorf("the pull request was %s -> %s", h.git.opened.Head, h.git.opened.Base)
	}
	if h.git.baseTree != "basetree" {
		t.Errorf("the new tree was derived from %q, not the base commit's tree", h.git.baseTree)
	}
	if len(h.git.labels) != 1 || h.git.labels[0] != "apphub" {
		t.Errorf("labels = %v, want the identity", h.git.labels)
	}
	if h.store.outcome == nil || h.store.outcome.PullRequestNumber != 7 {
		t.Errorf("outcome = %+v", h.store.outcome)
	}
	// The fix ran against the scan's revision, not the caller's.
	if h.fetcher.lastAt.Ref != "main" {
		t.Errorf("the snapshot was fetched at %q, want the scan's revision", h.fetcher.lastAt.Ref)
	}
	if res.Data["prUrl"] != "pull/7" {
		t.Errorf("Data[prUrl] = %v", res.Data["prUrl"])
	}
}

// TestExecuteStopsAtAVerdictThatIsNotReal covers the whole verdict set. Only
// one opens a pull request; the other two are terminal and successful.
func TestExecuteStopsAtAVerdictThatIsNotReal(t *testing.T) {
	opened := 0
	for _, verdict := range fix.Verdicts() {
		t.Run(string(verdict), func(t *testing.T) {
			h := newHarness(t, func(h *harness) {
				h.fixer.verdict = &fix.VerdictResult{
					Verdict: verdict,
					Cost:    review.Cost{Model: "m", Usage: review.Usage{Calls: 1}, EstimatedCostMicros: 3},
				}
			})
			res, err := h.module.Execute(context.Background(), "u", validParams())
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if !res.Success {
				t.Fatalf("a verdict of %q was reported as a failure", verdict)
			}
			if verdict.Opens() {
				opened++
				if h.fixer.proposeN != 1 {
					t.Fatalf("a verdict of %q did not lead to a patch", verdict)
				}
				return
			}
			if h.fixer.proposeN != 0 {
				t.Fatalf("a verdict of %q drafted a patch anyway", verdict)
			}
			if len(h.git.seq) != 0 {
				t.Fatalf("a verdict of %q wrote to the repository: %v", verdict, h.git.seq)
			}
			want := "MarkRunning,MarkStatus:validating,RecordVerdict,RecordCost,FinalizeRejected"
			if got := strings.Join(h.store.seq, ","); got != want {
				t.Fatalf("store sequence = %q, want %q", got, want)
			}
			// The verdict is recorded whatever it was, so a person can see why.
			if h.store.verdict == nil || h.store.verdict.Verdict != verdict {
				t.Fatalf("the verdict was not recorded: %+v", h.store.verdict)
			}
		})
	}
	if opened != 1 {
		t.Fatalf("%d of %d verdicts opened a pull request, want exactly 1", opened, len(fix.Verdicts()))
	}
}

// TestOnlyACompletedScanCanBeFixed states the precondition on the input. A
// finding from a scan that never completed has not been through the
// sanitising the completed state guarantees, and a scan still running may
// still change what it reported.
func TestOnlyACompletedScanCanBeFixed(t *testing.T) {
	h := newHarness(t, func(h *harness) { h.scans.scan.Complete = false })
	_, err := h.module.Execute(context.Background(), "u", validParams())
	if err == nil {
		t.Fatal("Execute ran against a scan that had not completed")
	}
	if len(h.git.seq) != 0 {
		t.Fatalf("an incomplete scan reached the repository: %v", h.git.seq)
	}
	if h.fixer.validateN != 0 {
		t.Fatalf("an incomplete scan reached the agent")
	}
	if h.store.failCalls != 1 || !strings.Contains(strings.ToLower(h.store.failMessage), "complete") {
		t.Errorf("the requester was told %q", h.store.failMessage)
	}
	// The other direction, so this is not passing on a module that refuses
	// every scan.
	h2 := newHarness(t)
	if _, err := h2.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("a completed scan was refused: %v", err)
	}
}

// TestNothingIsWrittenUntilEveryLimitHolds is the property the whole of caps.go
// exists for, over the full set of violations. After the first blob there is no
// decision left to make, so every refusal has to happen before it.
func TestNothingIsWrittenUntilEveryLimitHolds(t *testing.T) {
	limits := testLimits()
	violations := []struct {
		name  string
		files []fix.FileChange
	}{
		{"too many files", manyFiles(limits.MaxFiles + 1)},
		{"a traversing path", []fix.FileChange{{Path: "../x", Contents: "x"}}},
		{"a file that is not in the tree", []fix.FileChange{{Path: "new.go", Contents: "x"}}},
		{"a file over the byte cap", []fix.FileChange{{Path: "a.go", Contents: strings.Repeat("x", limits.MaxBytesPerFile+1)}}},
		{"over the line cap", []fix.FileChange{{Path: "a.go", Contents: strings.Repeat("y\n", limits.MaxLines+1)}}},
		{"no files at all", nil},
	}
	for _, v := range violations {
		t.Run(v.name, func(t *testing.T) {
			h := newHarness(t, func(h *harness) {
				h.fixer.patch = &fix.Patch{Summary: "s", Files: v.files}
			})
			if _, err := h.module.Execute(context.Background(), "u", validParams()); err == nil {
				t.Fatalf("Execute accepted a patch with %s", v.name)
			}
			if len(h.git.seq) != 0 {
				t.Fatalf("a patch with %s reached the repository: %v", v.name, h.git.seq)
			}
			if h.store.failCalls != 1 {
				t.Fatalf("Fail was called %d times, want once", h.store.failCalls)
			}
			if h.store.failMessage == "" {
				t.Fatal("the refusal reached the record with no message")
			}
		})
	}
	t.Logf("refused %d patches before any write", len(violations))
}

// A rejected CI edit must not produce a blob even when an ordinary file comes
// first in the patch and the model supplies a category normally allowed to
// modify dependency/build files.
func TestPlatformExecutedCIIsRefusedBeforeBlobWrites(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", ".github/actions/test/action.yml"} {
		for _, category := range []string{"ci", "supply-chain"} {
			t.Run(path+"/"+category, func(t *testing.T) {
				h := newHarness(t, func(h *harness) {
					tree := h.fetcher.tree.(*stubTree)
					tree.files[path] = []byte("original\n")
					h.scans.scan.Findings[0].Category = category
					h.fixer.patch.Files = []fix.FileChange{
						{Path: "a.go", Contents: "changed\n"},
						{Path: path, Contents: "malicious\n"},
					}
				})
				_, err := h.module.Execute(context.Background(), "u", validParams())
				if err == nil || !strings.Contains(err.Error(), path) {
					t.Fatalf("Execute err = %v, want refusal naming %q", err, path)
				}
				if len(h.git.seq) != 0 {
					t.Fatalf("CI change reached Git before refusal: %v", h.git.seq)
				}
				if h.store.patchFiles != nil {
					t.Fatalf("CI change was recorded as an accepted patch: %v", h.store.patchFiles)
				}
			})
		}
	}
}

// TestTheEncodedPatchIsWhatTheStorageCeilingApplies is the migration of the
// source's comment into behaviour. Content that is cheap raw and expensive
// encoded is exactly what a raw-byte sum under-counts.
func TestTheEncodedPatchIsWhatTheStorageCeilingApplies(t *testing.T) {
	limits := testLimits()
	limits.MaxEncodedPatchBytes = 4096
	// Every byte of this content needs six bytes when it is JSON-encoded, so
	// the raw sum is a sixth of what is stored.
	raw := strings.Repeat("\x01", 1000)
	h := &harness{
		fixer: &stubFixer{
			verdict: &fix.VerdictResult{Verdict: fix.VerdictReal},
			patch:   &fix.Patch{Summary: "s", Files: []fix.FileChange{{Path: "a.go", Contents: raw}}},
		},
		fetcher: &stubFetcher{tree: newTree(map[string]string{"a.go": "x"}), commit: "basesha"},
		git:     newGit(),
		scans: &stubScans{scan: &fix.Scan{Complete: true, Owner: "acme", Repo: "widget", Ref: "main",
			Findings: []review.Finding{{Severity: review.SeverityHigh, Title: "t"}}}},
		store: &stubStore{},
	}
	m, err := fix.New(fix.Config{
		Fixer: h.fixer, Source: h.fetcher, Git: h.git, Scans: h.scans, Store: h.store,
		Logger: discardLogger(), Identity: fix.Identity{Name: "apphub"},
		Limits: limits, MaxSourceBytes: review.SuggestedMaxSourceBytes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(raw) >= limits.MaxEncodedPatchBytes {
		t.Fatal("the raw content is already over the cap, so this proves nothing about encoding")
	}
	if _, err := m.Execute(context.Background(), "u", validParams()); err == nil {
		t.Fatal("a patch whose encoded form is over the ceiling was accepted")
	}
	if len(h.git.seq) != 0 {
		t.Fatalf("the oversized patch reached the repository: %v", h.git.seq)
	}
	if !strings.Contains(h.store.failMessage, "encoded") {
		t.Errorf("the refusal message was %q, which does not say the encoded form is what is bounded", h.store.failMessage)
	}
	t.Logf("%d raw bytes encode to more than the %d-byte ceiling", len(raw), limits.MaxEncodedPatchBytes)
}

// TestSpendIsBookedExactlyOnceOnEveryPath is the ledger property. The running
// totals a store keeps are additive, so booking twice over-counts and booking
// never loses what was billed.
func TestSpendIsBookedExactlyOnceOnEveryPath(t *testing.T) {
	cost := review.Cost{Model: "m", Usage: review.Usage{Calls: 1, InputTokens: 10}, EstimatedCostMicros: 4}
	cases := []struct {
		name      string
		mutate    func(*harness)
		wantCalls int
		wantTotal int64
	}{
		{"a clean run", func(*harness) {}, 1, 8},
		{"a rejected finding", func(h *harness) {
			h.fixer.verdict = &fix.VerdictResult{Verdict: fix.VerdictFalsePositive, Cost: cost}
		}, 1, 4},
		{"the agent declining to patch", func(h *harness) {
			h.fixer.patch = nil
			h.fixer.patchErr = &fix.NoPatchError{Explanation: "no safe change exists", Cost: cost}
		}, 1, 8},
		{"a transport failure while drafting", func(h *harness) {
			h.fixer.patch = nil
			h.fixer.patchErr = errors.New("upstream fell over")
		}, 1, 4},
		{"a push failure", func(h *harness) { h.git.openPRErr = errors.New("upstream fell over") }, 1, 8},
		{"a failure recording the pull request", func(h *harness) {
			h.store.completeErr = errors.New("throttled")
		}, 1, 8},
		{"a validation failure before any spend", func(h *harness) {
			h.fixer.verdict = nil
			h.fixer.verdictErr = errors.New("upstream fell over")
		}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(h *harness) {
				h.fixer.verdict = &fix.VerdictResult{Verdict: fix.VerdictReal, Cost: cost}
				h.fixer.patch = &fix.Patch{Summary: "s", Cost: cost,
					Files: []fix.FileChange{{Path: "a.go", Contents: "x\n"}}}
				tc.mutate(h)
			})
			_, _ = h.module.Execute(context.Background(), "u", validParams())
			if h.store.costCalls != tc.wantCalls {
				t.Fatalf("RecordCost was called %d times, want %d", h.store.costCalls, tc.wantCalls)
			}
			if tc.wantCalls == 0 {
				return
			}
			if h.store.cost == nil || h.store.cost.EstimatedCostMicros != tc.wantTotal {
				t.Fatalf("booked %+v, want %d micros", h.store.cost, tc.wantTotal)
			}
		})
	}
}

// TestTheRecordAlwaysReachesATerminalState is the property a reader polling it
// depends on. Every way a run can end is enumerated from the outside: whatever
// goes wrong, the record does not stay in a running state.
func TestTheRecordAlwaysReachesATerminalState(t *testing.T) {
	terminal := map[string]bool{"Complete": true, "Fail": true, "FinalizeRejected": true}
	cases := map[string]func(*harness){
		"the scan is missing":                 func(h *harness) { h.scans.scan, h.scans.err = nil, notFound() },
		"the scan never completed":            func(h *harness) { h.scans.scan.Complete = false },
		"the finding index is past the end":   func(h *harness) { h.scans.scan.Findings = nil },
		"the snapshot cannot be fetched":      func(h *harness) { h.fetcher.tree, h.fetcher.err = nil, review.ErrSourceNotFound },
		"the fetcher returns nothing at all":  func(h *harness) { h.fetcher.tree, h.fetcher.err = nil, nil },
		"validation fails":                    func(h *harness) { h.fixer.verdict, h.fixer.verdictErr = nil, errors.New("x") },
		"validation returns nothing at all":   func(h *harness) { h.fixer.verdict, h.fixer.verdictErr = nil, nil },
		"the finding is a false positive":     func(h *harness) { h.fixer.verdict = &fix.VerdictResult{Verdict: fix.VerdictFalsePositive} },
		"drafting fails":                      func(h *harness) { h.fixer.patch, h.fixer.patchErr = nil, errors.New("x") },
		"drafting returns nothing at all":     func(h *harness) { h.fixer.patch, h.fixer.patchErr = nil, nil },
		"the agent declines":                  func(h *harness) { h.fixer.patch, h.fixer.patchErr = nil, &fix.NoPatchError{Explanation: "no"} },
		"the patch breaks a limit":            func(h *harness) { h.fixer.patch = &fix.Patch{Files: manyFiles(99)} },
		"the base is a tag":                   func(h *harness) { h.scans.scan.Ref, h.git.tags["v1"] = "v1", true },
		"the base is a commit":                func(h *harness) { h.scans.scan.Ref = "0123456789abcdef" },
		"the base branch does not exist":      func(h *harness) { h.scans.scan.Ref = "nope" },
		"the branch cannot be created":        func(h *harness) { h.git.createRefErr = errors.New("x") },
		"every branch name is taken":          func(h *harness) { h.git.createRefFails = 99 },
		"the pull request cannot be opened":   func(h *harness) { h.git.openPRErr = errors.New("x") },
		"the pull request cannot be recorded": func(h *harness) { h.store.completeErr = errors.New("x") },
		"nothing goes wrong":                  func(*harness) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			_, _ = h.module.Execute(context.Background(), "u", validParams())
			last := ""
			for _, e := range h.store.seq {
				if terminal[e] {
					last = e
				}
			}
			if last == "" {
				t.Fatalf("the record never reached a terminal state; the sequence was %v", h.store.seq)
			}
		})
	}
	t.Logf("checked %d ways a run can end", len(cases))
}

// TestAFailureMessageNeverQuotesTheUpstreamError is the disclosure rule for
// the one string a requester reads. An upstream error can carry a response
// body, a branch name and authorisation hints.
func TestAFailureMessageNeverQuotesTheUpstreamError(t *testing.T) {
	const secret = "UPSTREAMSECRET"
	cases := map[string]func(*harness){
		"a fetch failure":       func(h *harness) { h.fetcher.tree, h.fetcher.err = nil, errors.New(secret) },
		"a validation failure":  func(h *harness) { h.fixer.verdict, h.fixer.verdictErr = nil, errors.New(secret) },
		"a drafting failure":    func(h *harness) { h.fixer.patch, h.fixer.patchErr = nil, errors.New(secret) },
		"a push failure":        func(h *harness) { h.git.openPRErr = errors.New(secret) },
		"a branch failure":      func(h *harness) { h.git.createRefErr = errors.New(secret) },
		"a scan read failure":   func(h *harness) { h.scans.scan, h.scans.err = nil, errors.New(secret) },
		"a base lookup failure": func(h *harness) { h.git.branchHeadErr = errors.New(secret) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			_, err := h.module.Execute(context.Background(), "u", validParams())
			if err == nil {
				t.Fatal("Execute returned no error")
			}
			if !strings.Contains(err.Error(), secret) {
				t.Fatalf("the returned error lost the cause, so this case proves nothing: %v", err)
			}
			if strings.Contains(h.store.failMessage, secret) {
				t.Fatalf("the requester message quoted the upstream error: %q", h.store.failMessage)
			}
			if h.store.failMessage == "" {
				t.Fatal("the requester was told nothing at all")
			}
		})
	}
	t.Logf("checked %d failure paths for disclosure", len(cases))
}

// TestValidateEnforcesEveryDeclaredConstraint walks the parameter map. The two
// identifiers are checked hardest because the scan identifier is spliced into
// a branch name in somebody else's repository.
func TestValidateEnforcesEveryDeclaredConstraint(t *testing.T) {
	h := newHarness(t)
	unsafeIDs := []any{
		"", " ", "-x", "_x", ".x", "a/b", "a b", "a.b", "a\nb", "a\x00b", "a:b",
		"a?b", "a~b", "a^b", "a*b", "a[b", "a\\b", "a`b", "..", "x..y",
		"x.lock", strings.Repeat("a", 129), 7,
	}
	checked := 0
	for _, key := range []string{"fixId", "scanId"} {
		for _, bad := range unsafeIDs {
			checked++
			if err := h.module.Validate(with(validParams(), key, bad)); err == nil {
				t.Errorf("Validate accepted %s=%#v", key, bad)
			}
		}
	}
	other := []struct {
		name  string
		key   string
		value any
	}{
		{"findingIndex absent", "findingIndex", nil},
		{"findingIndex negative", "findingIndex", -1},
		{"findingIndex fractional", "findingIndex", 0.5},
		{"findingIndex a string", "findingIndex", "0"},
		{"installationId absent", "installationId", nil},
		{"installationId zero", "installationId", 0},
		{"owner absent", "owner", nil},
		{"owner unsafe", "owner", "a/b"},
		{"repo unsafe", "repo", ".."},
		{"mode public", "mode", string(review.ModePublic)},
		{"mode unknown", "mode", "anything"},
		{"an undeclared parameter", "auditId", "x"},
	}
	for _, tc := range other {
		t.Run(tc.name, func(t *testing.T) {
			checked++
			if err := h.module.Validate(with(validParams(), tc.key, tc.value)); err == nil {
				t.Errorf("Validate accepted %s", tc.name)
			}
		})
	}
	// Both directions.
	if err := h.module.Validate(validParams()); err != nil {
		t.Fatalf("Validate refused a complete valid parameter map: %v", err)
	}
	if err := h.module.Validate(with(validParams(), "mode", nil)); err != nil {
		t.Fatalf("Validate refused a map with the defaulted mode omitted: %v", err)
	}
	for _, ok := range []string{"a", "A9", "scan-1", "scan_1", strings.Repeat("a", 128)} {
		if err := h.module.Validate(with(validParams(), "scanId", ok)); err != nil {
			t.Errorf("Validate refused the ordinary identifier %q: %v", ok, err)
		}
	}
	t.Logf("refused %d invalid parameter maps", checked)
}

// TestExecuteValidatesBeforeItActs: a bad map must not reach anything.
func TestExecuteValidatesBeforeItActs(t *testing.T) {
	h := newHarness(t)
	if _, err := h.module.Execute(context.Background(), "u", with(validParams(), "scanId", "a b")); err == nil {
		t.Fatal("Execute ran on an invalid parameter map")
	}
	if len(h.store.seq) != 0 || len(h.git.seq) != 0 || h.fetcher.calls != 0 || h.fixer.validateN != 0 {
		t.Fatalf("an invalid map reached the collaborators: store=%v git=%v fetch=%d fixer=%d",
			h.store.seq, h.git.seq, h.fetcher.calls, h.fixer.validateN)
	}
}

// TestSchemaAndValidatorAgree checks the published contract against what is
// enforced, in both directions.
func TestSchemaAndValidatorAgree(t *testing.T) {
	h := newHarness(t)
	schema := h.module.Schema()
	if len(schema.Properties) == 0 || len(schema.Required) == 0 {
		t.Fatal("the schema publishes nothing")
	}
	for _, req := range schema.Required {
		if _, ok := schema.Properties[req]; !ok {
			t.Errorf("the schema requires %q without declaring it", req)
		}
		if err := h.module.Validate(with(validParams(), req, nil)); err == nil {
			t.Errorf("the schema requires %q but Validate accepts a map without it", req)
		}
	}
	for _, value := range schema.Properties["mode"].Enum {
		if err := h.module.Validate(with(validParams(), "mode", value)); err != nil {
			t.Errorf("the schema publishes mode=%q but Validate refuses it: %v", value, err)
		}
	}
	t.Logf("checked %d required keys against %d declared properties", len(schema.Required), len(schema.Properties))
}

// TestModuleMetadataIsStable guards the identifier the framework says must not
// change.
func TestModuleMetadataIsStable(t *testing.T) {
	h := newHarness(t)
	var m modules.Module = h.module
	if m.ID() != "agentic-fix-pr" || m.ID() != fix.ModuleID {
		t.Errorf("ID() = %q; it is persisted on stored work and must not change", m.ID())
	}
	for name, value := range map[string]string{"Name": m.Name(), "Description": m.Description(), "Icon": m.Icon(), "Category": m.Category()} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("%s() is empty", name)
		}
	}
}

// TestSuggestedLimitsAreUsable is a control on the suggested values: a
// suggestion the constructor refuses would be a trap.
func TestSuggestedLimitsAreUsable(t *testing.T) {
	limits := fix.Limits{
		MaxFiles:             fix.SuggestedMaxFiles,
		MaxLines:             fix.SuggestedMaxLines,
		MaxBytesPerFile:      fix.SuggestedMaxBytesPerFile,
		MaxEncodedPatchBytes: fix.SuggestedMaxEncodedPatchBytes,
		TerminalWriteTimeout: 30 * time.Second,
	}
	_, err := fix.New(fix.Config{
		Fixer: &stubFixer{}, Source: &stubFetcher{}, Git: newGit(), Scans: &stubScans{},
		Store: &stubStore{}, Logger: discardLogger(), Identity: fix.Identity{Name: "apphub"},
		Limits: limits, MaxSourceBytes: review.SuggestedMaxSourceBytes,
	})
	if err != nil {
		t.Fatalf("the suggested limits were refused by New: %v", err)
	}
	// The encoded ceiling has to leave room inside a storage item, which is
	// the reason it is the value it is.
	if fix.SuggestedMaxEncodedPatchBytes >= 400<<10 {
		t.Errorf("SuggestedMaxEncodedPatchBytes is %d, which leaves no room inside a 400 KiB item", fix.SuggestedMaxEncodedPatchBytes)
	}
}
