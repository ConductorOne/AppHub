// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/modules"
	"github.com/conductorone/apphub/modules/review"
)

// newArgs is the population TestNewRefusesEveryAbsentDependency quantifies
// over: one entry per parameter of [review.New], derived from the function's
// own type rather than listed, and each carrying every way that parameter can
// be absent.
//
// Interface parameters get two absences, not one. An interface holding a nil
// pointer is not nil, so a constructor comparing its parameter to nil accepts
// it, returns a module that looks wired, and panics on the first call. That
// was open here: the first version of this test contained only untyped nils,
// and a review passed a typed one straight through.
type absence struct {
	how    string
	mutate func(*newArgsValues)
}

type newArgsValues struct {
	scanner review.Scanner
	source  review.SourceFetcher
	store   review.ResultStore
	logger  *slog.Logger
	limits  review.Limits
}

func completeArgs() newArgsValues {
	return newArgsValues{
		scanner: &stubScanner{},
		source:  &stubFetcher{},
		store:   &stubStore{},
		logger:  discardLogger(),
		limits:  testLimits(),
	}
}

func (v newArgsValues) call() (*review.Module, error) {
	return review.New(v.scanner, v.source, v.store, v.logger, v.limits)
}

func newArgAbsences() map[string][]absence {
	return map[string][]absence{
		"scanner": {
			{"untyped nil", func(v *newArgsValues) { v.scanner = nil }},
			{"typed nil", func(v *newArgsValues) { v.scanner = (*stubScanner)(nil) }},
		},
		"source fetcher": {
			{"untyped nil", func(v *newArgsValues) { v.source = nil }},
			{"typed nil", func(v *newArgsValues) { v.source = (*stubFetcher)(nil) }},
		},
		"result store": {
			{"untyped nil", func(v *newArgsValues) { v.store = nil }},
			{"typed nil", func(v *newArgsValues) { v.store = (*stubStore)(nil) }},
		},
		"logger": {
			{"nil", func(v *newArgsValues) { v.logger = nil }},
		},
		"limits": {
			{"zero MaxSourceBytes", func(v *newArgsValues) { v.limits.MaxSourceBytes = 0 }},
			{"negative MaxSourceBytes", func(v *newArgsValues) { v.limits.MaxSourceBytes = -1 }},
			{"zero TerminalWriteTimeout", func(v *newArgsValues) { v.limits.TerminalWriteTimeout = 0 }},
			{"negative TerminalWriteTimeout", func(v *newArgsValues) { v.limits.TerminalWriteTimeout = -1 }},
		},
	}
}

// TestEveryConstructorParameterIsCovered derives the parameter count from
// [review.New]'s own type, so a parameter added to the constructor without a
// matching entry fails here rather than going unguarded.
func TestEveryConstructorParameterIsCovered(t *testing.T) {
	fn := reflect.TypeOf(review.New)
	if fn.Kind() != reflect.Func {
		t.Fatalf("review.New is a %s, not a function", fn.Kind())
	}
	if fn.NumIn() == 0 {
		t.Fatal("review.New takes no parameters; the derivation is not reading the type")
	}
	absences := newArgAbsences()
	if fn.NumIn() != len(absences) {
		t.Fatalf("review.New takes %d parameter(s) and %d are covered; a parameter with no entry "+
			"is a parameter nothing checks the guard for", fn.NumIn(), len(absences))
	}
	// Every interface parameter must have a typed-nil absence, because that is
	// the one a nil comparison lets through.
	interfaces := 0
	for i := 0; i < fn.NumIn(); i++ {
		if fn.In(i).Kind() == reflect.Interface {
			interfaces++
		}
	}
	typed := 0
	for _, list := range absences {
		for _, a := range list {
			if a.how == "typed nil" {
				typed++
			}
		}
	}
	if typed != interfaces {
		t.Errorf("review.New takes %d interface parameter(s) and %d typed-nil absence(s) are covered",
			interfaces, typed)
	}
	t.Logf("covered %d parameter(s), %d of them interfaces", fn.NumIn(), interfaces)
}

// TestNewRefusesEveryAbsentDependency quantifies over that population.
func TestNewRefusesEveryAbsentDependency(t *testing.T) {
	cases := 0
	for name, list := range newArgAbsences() {
		if len(list) == 0 {
			t.Errorf("%s is covered with no way of being absent", name)
			continue
		}
		for _, a := range list {
			cases++
			v := completeArgs()
			a.mutate(&v)
			m, err := v.call()
			what := name + " (" + a.how + ")"
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
	if _, err := completeArgs().call(); err != nil {
		t.Fatalf("New with everything supplied failed: %v", err)
	}
	t.Logf("refused %d incomplete configuration(s) and accepted the complete one", cases)
}

// TestExecuteHappyPathSanitisesAndCompletes states what a successful run does:
// it reaches the store exactly once in each state, it sanitises whatever the
// scanner returned, and it derives the highest severity rather than trusting a
// field.
func TestExecuteHappyPathSanitisesAndCompletes(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.scanner.result = &review.ScanResult{
			Findings: []review.Finding{
				{Severity: "low", Title: "a", Path: "ok.go", Line: 3},
				{Severity: "invented", Title: "b", Path: "../escape", Line: 9},
				{Severity: "high", Title: "c", Snippet: strings.Repeat("é", 900)},
			},
			Iterations: 2,
			BytesRead:  1024,
			Cost:       review.Cost{Model: "m", Usage: review.Usage{Calls: 1, InputTokens: 10}, EstimatedCostMicros: 5},
		}
	})
	res, err := h.module.Execute(context.Background(), "user-1", validParams())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute reported Success false on a clean run: %+v", res)
	}
	if got := strings.Join(h.store.seq, ","); got != "MarkRunning,Complete" {
		t.Fatalf("store sequence = %q, want %q", got, "MarkRunning,Complete")
	}
	c := h.store.completion
	if c == nil {
		t.Fatal("Complete was called with no completion")
	}
	if len(c.Findings) != 3 {
		t.Fatalf("stored %d findings, want 3", len(c.Findings))
	}
	// The escaping path is dropped, and its line goes with it.
	if c.Findings[1].Path != "" || c.Findings[1].Line != 0 {
		t.Errorf("the traversing path survived: %+v", c.Findings[1])
	}
	// The invented severity is not carried, and does not decide the highest.
	if c.Findings[1].Severity != review.SeverityInfo {
		t.Errorf("finding severity = %q, want %q", c.Findings[1].Severity, review.SeverityInfo)
	}
	if c.HighestSeverity != review.SeverityHigh {
		t.Errorf("HighestSeverity = %q, want %q", c.HighestSeverity, review.SeverityHigh)
	}
	if len(c.Findings[2].Snippet) > review.MaxSnippetBytes+3 {
		t.Errorf("the oversized snippet was stored at %d bytes", len(c.Findings[2].Snippet))
	}
	if c.Cost.EstimatedCostMicros != 5 || c.Cost.Model != "m" {
		t.Errorf("cost = %+v, want the scanner's", c.Cost)
	}
	if c.Iterations != 2 || c.BytesRead != 1024 {
		t.Errorf("diagnostics = %d/%d, want 2/1024", c.Iterations, c.BytesRead)
	}
	if h.fetcher.lastCapB != review.SuggestedMaxSourceBytes {
		t.Errorf("the fetcher was given a cap of %d, want the configured %d", h.fetcher.lastCapB, review.SuggestedMaxSourceBytes)
	}
	if res.Data["requestedBy"] != "user-1" {
		t.Errorf("Data[requestedBy] = %v, want the requester", res.Data["requestedBy"])
	}
}

// TestExecuteRecordsWhatTheScanWasProducedAgainst is the producer side of the
// binding modules/fix depends on.
//
// A completed scan is read back by a later, separate invocation that decides
// what to write into a repository on the strength of it. If the record does
// not say which repository and which revision the findings came from, the
// consumer has nothing to check and possession of a scan identifier becomes
// authority over any repository -- which was reproduced against the first
// version of these packages. So this is a requirement on what is stored, not
// provenance decoration.
func TestExecuteRecordsWhatTheScanWasProducedAgainst(t *testing.T) {
	h := newHarness(t, func(h *harness) { h.fetcher.commit = "resolved-commit" })
	if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	c := h.store.completion
	if c == nil {
		t.Fatal("Complete was called with no completion")
	}
	for name, got := range map[string]string{
		"Owner":  c.Owner,
		"Repo":   c.Repo,
		"Ref":    c.Ref,
		"Commit": c.Commit,
	} {
		if got == "" {
			t.Errorf("Completion.%s is empty; the consumer cannot check a binding that was not recorded", name)
		}
	}
	if c.Owner != "acme" || c.Repo != "widget" || c.Ref != "main" {
		t.Errorf("the completion names %s/%s@%s, not the repository that was scanned", c.Owner, c.Repo, c.Ref)
	}
	// The commit is the fetcher's resolved revision, not the ref that was
	// asked for. A branch name here would defeat the point: it moves.
	if c.Commit != "resolved-commit" {
		t.Errorf("Completion.Commit is %q, want the revision the snapshot resolved to", c.Commit)
	}
	if c.Commit == c.Ref {
		t.Errorf("Completion.Commit equals the requested ref, so it is not an immutable revision")
	}
}

// TestExecuteRefusesASnapshotItCannotIdentify is the fail-closed half. A
// fetcher that returns contents without saying which revision they came from
// leaves nothing for a later step to compare against, so it is refused here
// rather than accepted and discovered downstream.
func TestExecuteRefusesASnapshotItCannotIdentify(t *testing.T) {
	for name, mutate := range map[string]func(*harness){
		"no commit":   func(h *harness) { h.fetcher.commit = "" },
		"no contents": func(h *harness) { h.fetcher.tree = nil },
		"no snapshot": func(h *harness) { h.fetcher.noSnap = true },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			if _, err := h.module.Execute(context.Background(), "u", validParams()); err == nil {
				t.Fatal("Execute accepted a snapshot it could not identify")
			}
			if h.scanner.calls != 0 {
				t.Errorf("the scanner ran against a snapshot the module could not identify")
			}
			if h.store.failCalls != 1 {
				t.Errorf("Fail was called %d times, want once", h.store.failCalls)
			}
		})
	}
	// The control: an identified snapshot is scanned.
	h := newHarness(t)
	if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("an identified snapshot was refused: %v", err)
	}
	if h.scanner.calls != 1 {
		t.Fatalf("the scanner ran %d times on the control", h.scanner.calls)
	}
}

// TestExecuteMapsEveryFetchFailureToItsOwnMessage covers the whole sentinel
// set in both modes. The two directions here are that each sentinel gets its
// own message and that an unrecognised error gets the general one -- a mapping
// that returned the same string for everything would satisfy neither.
func TestExecuteMapsEveryFetchFailureToItsOwnMessage(t *testing.T) {
	sentinels := []error{
		review.ErrSourceNotFound,
		review.ErrSourceTooLarge,
		review.ErrSourceForbidden,
		errors.New("something else entirely"),
	}
	seen := map[string]int{}
	for _, mode := range []review.Mode{review.ModeInstallation, review.ModePublic} {
		for _, sentinel := range sentinels {
			h := newHarness(t, func(h *harness) {
				h.fetcher.err = fmt.Errorf("wrapped: %w", sentinel)
				h.fetcher.tree = nil
			})
			params := with(validParams(), "mode", string(mode))
			if mode == review.ModePublic {
				params = with(params, "installationId", nil)
			}
			_, err := h.module.Execute(context.Background(), "u", params)
			if err == nil {
				t.Fatalf("%v in %s mode: Execute returned no error", sentinel, mode)
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("%v in %s mode: the returned error lost the cause", sentinel, mode)
			}
			if h.store.failCalls != 1 {
				t.Errorf("%v in %s mode: Fail was called %d times, want once", sentinel, mode, h.store.failCalls)
			}
			seen[h.store.failMessage]++
			// A message must never carry the upstream error, which can hold a
			// response body.
			if strings.Contains(h.store.failMessage, "wrapped") {
				t.Errorf("%v in %s mode: the requester message quoted the upstream error: %q", sentinel, mode, h.store.failMessage)
			}
		}
	}
	// Four sentinels, and the forbidden one says something different depending
	// on whether an installation was involved, so there are five distinct
	// messages across the eight runs.
	if len(seen) != 5 {
		t.Fatalf("the eight runs produced %d distinct messages, want 5: %v", len(seen), seen)
	}
	t.Logf("checked %d fetch failures across 2 modes, producing %d distinct messages", len(sentinels)*2, len(seen))
}

// TestExecuteBooksSpendOnAFailedScan is the ledger property: what was billed
// is recorded whatever the outcome. It also checks the other direction, that a
// scan which spent nothing writes nothing -- a store call for a zero cost is a
// row that says a scan happened when none did.
func TestExecuteBooksSpendOnAFailedScan(t *testing.T) {
	spent := review.Cost{Model: "m", Usage: review.Usage{Calls: 3, InputTokens: 99}, EstimatedCostMicros: 7}
	for _, tc := range []struct {
		name    string
		partial *review.ScanResult
		want    string
	}{
		{"spent before failing", &review.ScanResult{Cost: spent}, "MarkRunning,RecordPartialCost,Fail"},
		{"failed before spending", &review.ScanResult{}, "MarkRunning,Fail"},
		{"failed with no result at all", nil, "MarkRunning,Fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(h *harness) {
				h.scanner.result = tc.partial
				h.scanner.err = errors.New("the provider fell over")
			})
			if _, err := h.module.Execute(context.Background(), "u", validParams()); err == nil {
				t.Fatal("Execute returned no error on a failed scan")
			}
			if got := strings.Join(h.store.seq, ","); got != tc.want {
				t.Fatalf("store sequence = %q, want %q", got, tc.want)
			}
			if tc.partial != nil && !tc.partial.Cost.Empty() {
				if h.store.partialCost == nil || h.store.partialCost.EstimatedCostMicros != 7 {
					t.Fatalf("partial cost = %+v, want the scanner's", h.store.partialCost)
				}
			}
		})
	}
}

// TestExecuteTreatsADeletedRecordAsCancellation covers both places a record
// can vanish. Neither is a failure: nobody is waiting for the result.
func TestExecuteTreatsADeletedRecordAsCancellation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*harness)
		wantSeq  string
		scanCall int
	}{
		{"deleted before the run started", func(h *harness) {
			h.store.markRunningErr = fmt.Errorf("gone: %w", review.ErrRecordNotFound)
		}, "MarkRunning", 0},
		{"deleted while the run was in flight", func(h *harness) {
			h.store.completeErr = fmt.Errorf("gone: %w", review.ErrRecordNotFound)
		}, "MarkRunning,Complete", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.mutate)
			res, err := h.module.Execute(context.Background(), "u", validParams())
			if err != nil {
				t.Fatalf("Execute returned an error for a deleted record: %v", err)
			}
			if res == nil || !res.Success {
				t.Fatalf("Execute reported failure for a deleted record: %+v", res)
			}
			if got := strings.Join(h.store.seq, ","); got != tc.wantSeq {
				t.Fatalf("store sequence = %q, want %q", got, tc.wantSeq)
			}
			if h.scanner.calls != tc.scanCall {
				t.Fatalf("the scanner ran %d times, want %d", h.scanner.calls, tc.scanCall)
			}
		})
	}
}

// TestExecuteContinuesWhenMarkRunningFailsForAnotherReason is the boundary
// beside the case above: a storage blip is not a deleted record, and losing a
// scan over one would be worse than a stale display.
func TestExecuteContinuesWhenMarkRunningFailsForAnotherReason(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.store.markRunningErr = errors.New("throttled")
	})
	if _, err := h.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := strings.Join(h.store.seq, ","); got != "MarkRunning,Complete" {
		t.Fatalf("store sequence = %q, want the run to have continued", got)
	}
}

// TestPublicModeCannotBorrowAnInstallation is the property that makes "public
// means anonymous" structural. A caller that sends an installation identifier
// alongside public mode does not get an authenticated fetch.
func TestPublicModeCannotBorrowAnInstallation(t *testing.T) {
	h := newHarness(t)
	params := with(with(validParams(), "mode", string(review.ModePublic)), "installationId", 77)
	if _, err := h.module.Execute(context.Background(), "u", params); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if h.fetcher.lastAt.InstallationID != 0 {
		t.Fatalf("the fetcher was given installation %d in public mode", h.fetcher.lastAt.InstallationID)
	}
	if h.fetcher.lastAt.Authenticated() {
		t.Fatal("a public-mode fetch was authenticated")
	}
	// The other direction, so this is not passing on a fetcher that never sees
	// an installation at all.
	h2 := newHarness(t)
	if _, err := h2.module.Execute(context.Background(), "u", validParams()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if h2.fetcher.lastAt.InstallationID != 42 {
		t.Fatalf("installation-mode fetch carried installation %d, want 42", h2.fetcher.lastAt.InstallationID)
	}
}

// TestValidateRejectsEveryUndeclaredParameter is the framework's rule applied
// here: the published schema is the contract, so a key it does not declare is
// refused rather than ignored.
func TestValidateRejectsEveryUndeclaredParameter(t *testing.T) {
	h := newHarness(t)
	declared := h.module.Schema().Properties
	if len(declared) == 0 {
		t.Fatal("the schema declares no properties")
	}
	for _, key := range []string{"auditId", "Owner", "extra", "installationID", "scan_type", ""} {
		if _, ok := declared[key]; ok {
			continue
		}
		if err := h.module.Validate(with(validParams(), key, "x")); err == nil {
			t.Errorf("Validate accepted the undeclared parameter %q", key)
		}
	}
	// And the declared set is accepted, so the check is not simply refusing.
	if err := h.module.Validate(validParams()); err != nil {
		t.Fatalf("Validate refused a complete valid parameter map: %v", err)
	}
	t.Logf("the schema declares %d parameters", len(declared))
}

// TestValidateEnforcesEveryDeclaredConstraint walks the parameter map one key
// at a time. Each row states what is wrong with the value, so a constraint
// that stops being enforced fails with its own name.
func TestValidateEnforcesEveryDeclaredConstraint(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value any
	}{
		{"scanId absent", "scanId", nil},
		{"scanId empty", "scanId", ""},
		{"scanId not a string", "scanId", 7},
		{"owner absent", "owner", nil},
		{"owner unsafe", "owner", "a/b"},
		{"repo absent", "repo", nil},
		{"repo unsafe", "repo", ".."},
		{"ref unsafe", "ref", "a b"},
		{"ref traversing", "ref", "a/../b"},
		{"ref with an empty component", "ref", "a//b"},
		{"mode unknown", "mode", "private"},
		{"scanType unknown", "scanType", "scan-medium"},
		{"installationId zero in installation mode", "installationId", 0},
		{"installationId negative", "installationId", -1},
		{"installationId fractional", "installationId", 1.5},
		{"installationId a string", "installationId", "42"},
	}
	h := newHarness(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.module.Validate(with(validParams(), tc.key, tc.value)); err == nil {
				t.Errorf("Validate accepted %s", tc.name)
			}
		})
	}
	// Both directions: the values a caller may legitimately omit are omitted,
	// and the map is still accepted.
	optional := with(with(validParams(), "ref", nil), "scanType", nil)
	if err := h.module.Validate(optional); err != nil {
		t.Fatalf("Validate refused a map with only its optional keys omitted: %v", err)
	}
	public := with(with(validParams(), "mode", string(review.ModePublic)), "installationId", nil)
	if err := h.module.Validate(public); err != nil {
		t.Fatalf("Validate refused a public-mode map with no installation: %v", err)
	}
	t.Logf("refused %d invalid parameter maps and accepted 3 valid ones", len(cases))
}

// TestExecuteValidatesBeforeItActs is the convention modules/doc.go adopts: a
// module does not assume its caller validated. A bad map must not reach the
// store or the fetcher.
func TestExecuteValidatesBeforeItActs(t *testing.T) {
	h := newHarness(t)
	if _, err := h.module.Execute(context.Background(), "u", with(validParams(), "owner", "a/b")); err == nil {
		t.Fatal("Execute ran on an invalid parameter map")
	}
	if len(h.store.seq) != 0 {
		t.Fatalf("an invalid map reached the store: %v", h.store.seq)
	}
	if h.fetcher.calls != 0 || h.scanner.calls != 0 {
		t.Fatalf("an invalid map reached the fetcher (%d) or the scanner (%d)", h.fetcher.calls, h.scanner.calls)
	}
}

// TestSchemaEnumerationsMatchTheValidator checks the two restatements of every
// enumeration against each other: what the schema publishes and what Validate
// admits. They are derived from the same slices, and this is what says so.
func TestSchemaEnumerationsMatchTheValidator(t *testing.T) {
	h := newHarness(t)
	schema := h.module.Schema()

	for _, row := range []struct {
		key      string
		declared []string
	}{
		{"mode", schema.Properties["mode"].Enum},
		{"scanType", schema.Properties["scanType"].Enum},
	} {
		if len(row.declared) == 0 {
			t.Fatalf("the schema publishes no enumeration for %q", row.key)
		}
		for _, value := range row.declared {
			params := with(validParams(), row.key, value)
			if row.key == "mode" && value == string(review.ModePublic) {
				params = with(params, "installationId", nil)
			}
			if err := h.module.Validate(params); err != nil {
				t.Errorf("the schema publishes %s=%q but Validate refuses it: %v", row.key, value, err)
			}
		}
		// And a value one character away from a published one is refused, so
		// the enumeration is an enumeration rather than a suggestion.
		if err := h.module.Validate(with(validParams(), row.key, row.declared[0]+"x")); err == nil {
			t.Errorf("Validate accepted %s=%q, which the schema does not publish", row.key, row.declared[0]+"x")
		}
	}
	// Every required key is declared. A required key with no property is a
	// contract that publishes nothing about what it demands.
	for _, req := range schema.Required {
		if _, ok := schema.Properties[req]; !ok {
			t.Errorf("the schema requires %q without declaring it", req)
		}
	}
	t.Logf("checked %d required keys against %d declared properties", len(schema.Required), len(schema.Properties))
}

// TestTerminalWritesSurviveACancelledContext is the property the fresh context
// exists for. The source's own comment says a record left in running makes a
// reader poll for ever; this is that comment as a test.
func TestTerminalWritesSurviveACancelledContext(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.fetcher.err = review.ErrSourceNotFound
		h.fetcher.tree = nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = h.module.Execute(ctx, "u", validParams())
	if h.store.failCalls != 1 {
		t.Fatalf("Fail was called %d times under a cancelled context, want once", h.store.failCalls)
	}
	// The record reached a terminal state, which is the property. A run that
	// left it in running would have polled a reader for ever.
	if got := strings.Join(h.store.seq, ","); got != "MarkRunning,Fail" {
		t.Fatalf("store sequence under a cancelled context = %q, want %q", got, "MarkRunning,Fail")
	}
}

// TestProgressIsReportedThroughTheFrameworkChannel checks the module reports
// through the context reporter rather than anywhere of its own, and that the
// reports are monotonic and inside the documented range.
func TestProgressIsReportedThroughTheFrameworkChannel(t *testing.T) {
	var reports []int
	ctx := modules.WithProgress(context.Background(), func(_ context.Context, progress int, _ string) {
		reports = append(reports, progress)
	})
	h := newHarness(t)
	if _, err := h.module.Execute(ctx, "u", validParams()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(reports) < 2 {
		t.Fatalf("the run reported %d progress values, want several", len(reports))
	}
	for i, p := range reports {
		if p < 0 || p > 100 {
			t.Errorf("progress report %d was %d, outside [0, 100]", i, p)
		}
		if i > 0 && p < reports[i-1] {
			t.Errorf("progress went backwards: %d then %d", reports[i-1], p)
		}
	}
	if reports[len(reports)-1] != 100 {
		t.Errorf("the last progress report was %d, want 100", reports[len(reports)-1])
	}
	t.Logf("observed %d progress reports", len(reports))
}

// TestModuleMetadataIsStable guards the identifier the framework says must not
// change, and checks the module satisfies the interface as a value of the type
// callers hold.
func TestModuleMetadataIsStable(t *testing.T) {
	h := newHarness(t)
	var m modules.Module = h.module
	if m.ID() != "agentic-repo-scan" {
		t.Errorf("ID() = %q; it is persisted on stored work and must not change", m.ID())
	}
	if m.ID() != review.ModuleID {
		t.Errorf("ID() = %q but ModuleID = %q", m.ID(), review.ModuleID)
	}
	for name, value := range map[string]string{"Name": m.Name(), "Description": m.Description(), "Icon": m.Icon(), "Category": m.Category()} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("%s() is empty", name)
		}
	}
}

// TestSuggestedLimitsAreUsable is a control on the suggested values: a
// suggestion that the constructor refuses is a trap.
func TestSuggestedLimitsAreUsable(t *testing.T) {
	limits := review.Limits{
		MaxSourceBytes:       review.SuggestedMaxSourceBytes,
		TerminalWriteTimeout: review.SuggestedTerminalWriteTimeout,
	}
	if _, err := review.New(&stubScanner{}, &stubFetcher{}, &stubStore{}, discardLogger(), limits); err != nil {
		t.Fatalf("the suggested limits were refused by New: %v", err)
	}
	if review.SuggestedTerminalWriteTimeout <= 0 || review.SuggestedMaxSourceBytes <= 0 {
		t.Fatal("a suggested limit is not positive")
	}
}
