// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// canonicalLabel is the grammar a figure's label must fit: lowercase words
// separated by single spaces, and nothing else.
//
// Nothing parses these any more, so this is no longer a reading rule; it is a
// writing rule, which keeps the generated Count column uniform and short enough
// to read in a table cell.
var canonicalLabel = regexp.MustCompile(`^[a-z]+(?: [a-z]+)*$`)

// fact is one figure belonging to a row. A row carries at least one.
//
// Rows are the unit the bijection is stated over; facts are the unit a row's
// claim is stated in. Keeping them separate is what removes the mapping table:
// E24 partitions its population four ways and E17 counts both files and
// packages, and each is still exactly one row.
type fact struct {
	label string
	num   int
	den   int
	total bool // a bare population size rather than a ratio
}

// total is a population size. Zero is refused: nothing derived from an empty
// population is a count.
func total(n int) fact { return fact{num: n, total: true} }

// ratio is a count with the denominator that makes it a claim. "Three files
// import X" is not a claim; "three of seven" is.
func ratio(num, den int) fact { return fact{num: num, den: den} }

// labelled is a ratio that says which of a row's several figures it is.
func labelled(label string, num, den int) fact {
	return fact{label: label, num: num, den: den}
}

func (f fact) String() string {
	var s string
	if f.total {
		s = fmt.Sprintf("%d", f.num)
	} else {
		s = fmt.Sprintf("%d / %d", f.num, f.den)
	}
	if f.label != "" {
		s += " " + f.label
	}
	return s
}

// validate refuses the two shapes that are the absence of a count rather than a
// count.
func (f fact) validate(id string) {
	if f.label != "" && !canonicalLabel.MatchString(f.label) {
		fail("%s: the figure label %q is not lowercase words separated by single spaces",
			id, f.label)
	}
	if f.total {
		if f.num <= 0 {
			fail("%s: population is %d; nothing derived from it would be a count", id, f.num)
		}
		return
	}
	if f.den <= 0 {
		fail("%s: denominator is %d. A 0 / 0 row is the absence of a count, not a count. "+
			"If this population is legitimately empty, edit the tool to say so and print "+
			"why", id, f.den)
	}
	if f.num < 0 || f.num > f.den {
		fail("%s: count %d is not within its denominator %d", id, f.num, f.den)
	}
}

func factsString(fs []fact) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.String())
	}
	return strings.Join(parts, "; ")
}

// derivedRow is one row of the generated table.
type derivedRow struct {
	row       evidenceRow
	facts     []fact
	derivedBy string
	details   []string
}

// recorder accumulates the audit's rows and renders the evidence table.
//
// Its contract is a bijection against [evidenceTable]: after a complete run
// every declared row has been emitted exactly once and nothing else has been
// emitted at all. That check is what stops the table becoming whatever the tool
// happened to print -- generating the document removes the drift, but it would
// also make "every row was derived" vacuous if nothing held the emissions to a
// declaration.
type recorder struct {
	byID     map[string]evidenceRow
	order    []string
	produced map[string]*derivedRow
	last     *derivedRow
}

func newRecorder(rows []evidenceRow) *recorder {
	ids := validatedIDs(rows) // validates the declaration and refuses an empty one
	r := &recorder{
		byID:     make(map[string]evidenceRow, len(rows)),
		order:    ids,
		produced: make(map[string]*derivedRow, len(rows)),
	}
	for _, row := range rows {
		r.byID[row.ID] = row
	}
	return r
}

// callerFunc names the function that called emit.
//
// Taken from the running program rather than written down, so the generated
// table's pointer into the code is what actually happened rather than a name
// someone maintained alongside it.
func callerFunc() string {
	pc, _, _, ok := runtime.Caller(2) // callerFunc -> emit -> the deriving function
	if !ok {
		fail("cannot determine which function emitted a row")
	}
	full := runtime.FuncForPC(pc).Name()
	if i := strings.LastIndex(full, "."); i >= 0 {
		full = full[i+1:]
	}
	return full
}

// emit records that the audit derived one row of the evidence table.
//
// There is no description argument: the row's prose lives in the declaration, so
// the tool cannot describe a row one way and the table another.
func (r *recorder) emit(id string, facts ...fact) {
	row, declared := r.byID[id]
	if !declared {
		fail("the audit emitted row %s, which the evidence table does not declare. "+
			"Either the declaration is missing a row the audit derives, or this row's "+
			"identifier is wrong; the two must name the same set", id)
	}
	if _, dup := r.produced[id]; dup {
		fail("the audit emitted row %s twice; each row of the evidence table must be "+
			"derived exactly once, or the table's figure for it is ambiguous", id)
	}
	if len(facts) == 0 {
		fail("%s: emitted with no figures; a row with nothing in it is not a count", id)
	}
	for _, f := range facts {
		f.validate(id)
	}
	d := &derivedRow{row: row, facts: facts, derivedBy: callerFunc()}
	r.produced[id] = d
	r.last = d
}

// detail attaches supporting evidence to the row just emitted. Details are not
// rows: they are printed under the table, named as details, and counted
// separately.
func (r *recorder) detail(format string, a ...any) {
	if r.last == nil {
		fail("a detail was recorded before any row was emitted")
	}
	r.last.details = append(r.last.details, fmt.Sprintf(format, a...))
}

// finish asserts the bijection.
func (r *recorder) finish() {
	var missing []string
	for _, id := range r.order {
		if _, ok := r.produced[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(r.produced) == 0 {
		fail("the audit emitted no rows at all against %d declared; a run that derives "+
			"nothing must not report success", len(r.order))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fail("%d of the %d rows the evidence table declares were never derived: %s. "+
			"Either derive them or remove them from the declaration", len(missing),
			len(r.order), strings.Join(missing, " "))
	}
}

// writeTable renders the evidence table as Markdown.
//
// This is the artefact. Nothing reads it back: the only check over it is a byte
// comparison against a freshly generated one, which has no parse and therefore
// no grammar to be wrong about. Claim and How are carried through verbatim from
// the declaration -- prose a human wrote, attached to its row by construction
// rather than by a lookup that could silently miss.
// printf is the only way this package writes. The write error is dropped
// deliberately: the audit's verdict is its exit status, and a failed write must
// not be reported as an incomplete audit, which would say something false about
// the source. The command flushes and checks its own buffered writer.
func wf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func (r *recorder) writeTable(w io.Writer) {
	wf(w, "| # | Claim | Count | Derived by | How it is determined |\n")
	wf(w, "| --- | --- | --- | --- | --- |\n")
	for _, id := range r.order {
		d := r.produced[id]
		wf(w, "| %s | %s | %s | %s | %s |\n",
			d.row.ID, d.row.Claim, factsString(d.facts), d.derivedBy, d.row.How)
	}
}

// writeDetails renders the supporting evidence, which is not part of the table.
func (r *recorder) writeDetails(w io.Writer) int {
	n := 0
	for _, id := range r.order {
		for _, det := range r.produced[id].details {
			if n == 0 {
				wf(w, "\nSupporting details. These are evidence for the rows above "+
					"and are not rows:\n\n")
			}
			wf(w, "* **%s** — %s\n", id, det)
			n++
		}
	}
	return n
}
