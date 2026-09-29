// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// wantIncomplete runs fn and requires it to have failed with an
// *IncompleteError mentioning each of want.
func wantIncomplete(t *testing.T, want []string, fn func()) {
	t.Helper()
	var err error
	func() {
		defer recoverFail(&err)
		fn()
	}()
	if err == nil {
		t.Fatalf("wanted an incomplete-audit failure mentioning %q, got success", want)
	}
	var ie *IncompleteError
	if !errors.As(err, &ie) {
		t.Fatalf("wanted *IncompleteError, got %T: %v", err, err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("failure message does not mention %q:\n%s", w, err.Error())
		}
	}
}

func wantOK(t *testing.T, fn func()) {
	t.Helper()
	var err error
	func() {
		defer recoverFail(&err)
		fn()
	}()
	if err != nil {
		t.Fatalf("wanted success, got: %v", err)
	}
}

// declare builds a fixture declaration. Prose is filled in because an empty
// Claim or How is itself fatal, which its own test covers.
func declare(ids ...string) []evidenceRow {
	rows := make([]evidenceRow, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, evidenceRow{ID: id, Claim: "a claim", How: "derived"})
	}
	return rows
}

// fixtureEmit is the stand-in deriving function the recorder tests emit through,
// so the generated table's "Derived by" column has something to name.
func fixtureEmit(r *recorder, id string, facts ...fact) { r.emit(id, facts...) }

// TestARequiredRowThatIsNeverEmittedFailsTheRun is the regression fixture for
// the round-seven blocker, and it is the reason generating the table did not
// simply delete this contract.
//
// Before the row-set contract the auditor asserted nothing about which rows it
// produced: deleting a single emit call printed a smaller number and still
// exited 0. Generating the table from whatever the tool emitted would have
// reopened exactly that, because the table would be whatever was printed. The
// declaration is what stops it: delete an emit and the declaration still names
// the row.
//
// This names the class rather than the case: the property is "a declared row
// that was not emitted ends the run naming it", which holds for any row.
func TestARequiredRowThatIsNeverEmittedFailsTheRun(t *testing.T) {
	t.Parallel()
	rows := declare("E1", "E2", "E3")
	for _, skip := range []string{"E1", "E2", "E3"} {
		t.Run("missing_"+skip, func(t *testing.T) {
			t.Parallel()
			wantIncomplete(t, []string{"never derived", skip}, func() {
				r := newRecorder(rows)
				for _, row := range rows {
					if row.ID == skip {
						continue // the deleted emit call
					}
					fixtureEmit(r, row.ID, ratio(1, 2))
				}
				r.finish()
			})
		})
	}
}

func TestEveryDeclaredRowEmittedOncePasses(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	wantOK(t, func() {
		r := newRecorder(declare("E1", "E2", "E3"))
		fixtureEmit(r, "E1", total(4))
		fixtureEmit(r, "E2", ratio(0, 7))
		fixtureEmit(r, "E3", labelled("files", 1, 2), labelled("packages", 1, 1))
		r.finish()
		r.writeTable(&buf)
	})
	for _, want := range []string{"| E1 | a claim | 4 | fixtureEmit | derived |",
		"| E2 | a claim | 0 / 7 | fixtureEmit | derived |",
		"| E3 | a claim | 1 / 2 files; 1 / 1 packages | fixtureEmit | derived |"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("generated table missing %q:\n%s", want, buf.String())
		}
	}
}

func TestAnEmittedRowTheDeclarationDoesNotStateFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"E17p", "does not declare"}, func() {
		r := newRecorder(declare("E17"))
		fixtureEmit(r, "E17", ratio(1, 2))
		fixtureEmit(r, "E17p", ratio(1, 2))
	})
}

func TestARowEmittedTwiceFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"E1", "twice"}, func() {
		r := newRecorder(declare("E1"))
		fixtureEmit(r, "E1", ratio(1, 2))
		fixtureEmit(r, "E1", ratio(1, 2))
	})
}

func TestARunThatEmitsNothingFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"emitted no rows at all", "2 declared"}, func() {
		newRecorder(declare("E1", "E2")).finish()
	})
}

func TestARowWithNoFiguresFailsTheRun(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"E1", "no figures"}, func() {
		fixtureEmit(newRecorder(declare("E1")), "E1")
	})
}

func TestAZeroDenominatorFailsTheRun(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    fact
		want string
	}{
		{"zero denominator", ratio(0, 0), "denominator is 0"},
		{"negative denominator", ratio(0, -1), "denominator is -1"},
		{"zero population", total(0), "population is 0"},
		{"numerator above denominator", ratio(3, 2), "not within its denominator"},
		{"negative numerator", ratio(-1, 2), "not within its denominator"},
		{"a label outside the grammar", labelled("Files (exact)", 1, 2), "lowercase words"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wantIncomplete(t, []string{"E1", tc.want}, func() {
				fixtureEmit(newRecorder(declare("E1")), "E1", tc.f)
			})
		})
	}
}

// TestTheDeclarationIsValidatedOnItsOwn. The declaration is the single artefact
// now, so the three things it can be wrong about without reference to anything
// else have to be fatal at construction.
func TestTheDeclarationIsValidatedOnItsOwn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rows []evidenceRow
		want string
	}{
		{"empty", nil, "declares no rows"},
		{"duplicate id", append(declare("E1"), evidenceRow{ID: "E1", Claim: "c", How: "h"}),
			"declares row E1 twice"},
		{"no identifier", []evidenceRow{{Claim: "c", How: "h"}}, "has no identifier"},
		{"no claim", []evidenceRow{{ID: "E1", How: "h"}}, "has no claim"},
		{"no how", []evidenceRow{{ID: "E1", Claim: "c"}}, "does not say how"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			wantIncomplete(t, []string{tc.want}, func() { validatedIDs(tc.rows) })
		})
	}
}

// TestTheShippedDeclarationIsWellFormed runs the same validation over the real
// declaration, so a row added without prose fails in CI rather than at the next
// person to run the audit.
func TestTheShippedDeclarationIsWellFormed(t *testing.T) {
	t.Parallel()
	var ids []string
	wantOK(t, func() { ids = requiredRows() })
	if len(ids) == 0 {
		t.Fatal("the shipped evidence table declares no rows")
	}
}

// TestDetailsAreNotRows pins the mapping an earlier round got wrong by
// coincidence: it printed 29 lines for a 30-row table because one row was split
// into four and one line was not a row at all. Supporting figures must not be
// countable as rows.
func TestDetailsAreNotRows(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	var details int
	wantOK(t, func() {
		r := newRecorder(declare("E1"))
		fixtureEmit(r, "E1", ratio(1, 2))
		r.detail("supporting evidence")
		r.detail("more supporting evidence")
		r.finish()
		r.writeTable(&buf)
		details = r.writeDetails(&buf)
	})
	if details != 2 {
		t.Errorf("counted %d details, want 2", details)
	}
	if n := strings.Count(buf.String(), "\n| E1 "); n != 1 {
		t.Errorf("E1 appears as %d table rows, want 1:\n%s", n, buf.String())
	}
}

func TestADetailBeforeAnyRowIsFatal(t *testing.T) {
	t.Parallel()
	wantIncomplete(t, []string{"before any row was emitted"}, func() {
		newRecorder(declare("E1")).detail("orphan")
	})
}
