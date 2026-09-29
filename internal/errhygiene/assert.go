// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package errhygiene

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// assertDerivation is the first check because a derivation that finds nothing
// satisfies every assertion made over it. This project has shipped that mistake
// once, in an auditor that emitted a complete consistent table from a tree it had
// only partly walked.
func (s Subject) assertDerivation(t *testing.T, d surface) {
	t.Helper()
	if len(d.Entries) == 0 {
		t.Fatalf("derived no exported inputs from %s; a subject with an empty surface passes every "+
			"check made over it", s.ImportPath)
	}
	if d.deepEmbedding {
		t.Errorf("the field walk hit its %d-level embedding bound, so part of this package's "+
			"promoted field set was not derived", maxEmbedDepth)
	}

	byCat := map[category]int{}
	for _, e := range d.Entries {
		byCat[e.Category]++
	}
	var cats []string
	for c, n := range byCat {
		cats = append(cats, fmt.Sprintf("%s=%d", c, n))
	}
	sort.Strings(cats)

	renderers := sortedKeys(d.Renderers)
	producers := sortedKeys(d.TextProducers)
	s.checkPopulation(t, PopulationRenderers, len(renderers), renderers)
	s.checkPopulation(t, PopulationTextProducers, len(producers), producers)

	t.Logf("%s: %s (%s), %s",
		s.ImportPath,
		plural(len(d.Entries), "entry point", "entry points"),
		strings.Join(cats, " "),
		plural(len(d.Parameterless), "parameterless callable", "parameterless callables"))
}

// assertAccounting is the check the count 33-of-37 would have failed.
//
// Every exported callable the type checker reports is filed as an entry point or as
// parameterless, and countExportedCallables recomputes the type checker's own total
// by a traversal that does not share the derivation's filing. A future narrowing of
// the derivation shows up as a failure here rather than as a smaller number nobody
// reads.
func (s Subject) assertAccounting(t *testing.T, d surface) {
	t.Helper()
	total := countExportedCallables(d.pkg)
	if total == 0 {
		t.Fatal("the type checker reports no exported callables at all")
	}
	// Promoted func-typed fields have no declaration on the owning type, so the
	// independent recount cannot see them and they are added back rather than
	// tolerated as a mismatch.
	want := total + d.promotedFields
	filed := len(d.Entries) + len(d.Parameterless)
	if filed != want {
		t.Errorf("the type checker reports %d exported callables (+%d promoted func-typed fields); "+
			"the derivation filed %d (%d entry points + %d parameterless). Something exported is "+
			"being dropped.",
			total, d.promotedFields, filed, len(d.Entries), len(d.Parameterless))
	}
	t.Logf("%d exported callables, all filed: %d with arguments, %d without",
		want, len(d.Entries), len(d.Parameterless))
}

// assertPopulation is the population check, and it exists because assertAccounting
// is not one.
//
// assertAccounting asks go/types for a total and compares it with what the
// derivation filed. That catches the derivation shrinking. It cannot catch the
// derivation never having been the whole set, because both sides ask the same
// question of the same package view -- and review proved the point by adding a
// //go:build windows file with an exported input, which every check passed while
// still reporting "91 exported callables". A cross-check that shares the
// derivation's blind spot is not a cross-check.
//
// So this obtains the population a different way: go/parser over every file in the
// package directory, which applies no build constraints at all. That is the same
// answer USOSS-28 reached for the boundary graph -- parse everything, ignore every
// tag -- and it is reused rather than reinvented. The two mechanisms disagree by
// construction whenever a constrained file exists, and the disagreement is the
// finding.
//
// The limit, stated rather than implied: this sees *declarations*. It cannot see a
// method promoted into an exported type, because promotion has no declaration --
// that is what the type checker is for, and recordFields covers it. Neither
// mechanism alone is sufficient, which is the lesson: go/types is necessary and not
// sufficient, because the configuration you type-check in is itself a population
// choice.
func (s Subject) assertPopulation(t *testing.T, d surface) {
	t.Helper()

	// Every name the derivation knows about, however it got there.
	known := map[string]bool{}
	for k := range d.Entries {
		known[k] = true
	}
	for k := range d.Parameterless {
		known[k] = true
	}
	for k := range d.Renderers {
		known[k] = true
	}

	files, decls, where, err := sweep(s.dir())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if files == 0 || len(decls) == 0 {
		t.Fatalf("the sweep of %s parsed %d file(s) and found %d declaration(s); it would pass "+
			"vacuously", s.dir(), files, len(decls))
	}

	used := map[string]bool{}
	for _, alts := range decls {
		if anyKnown(known, alts) {
			continue
		}
		if why := s.PlatformExcluded[alts[0]]; why != "" {
			used[alts[0]] = true
			t.Logf("%s is excluded: %s", alts[0], why)
			continue
		}
		t.Errorf("%s is declared in %s and the go/types derivation does not know it. Either it is "+
			"behind a build constraint this configuration does not satisfy -- in which case it is "+
			"still exported API and must be driven or named in Subject.PlatformExcluded -- or the "+
			"derivation has a hole.", alts[0], where[alts[0]])
	}
	for key := range s.PlatformExcluded {
		if !used[key] {
			t.Errorf("Subject.PlatformExcluded names %q, and the sweep did not find it outside the "+
				"derivation. The exclusion covers nothing.", key)
		}
	}
	t.Logf("swept %d file(s) and %d exported declaration(s) with every build constraint ignored",
		files, len(decls))
}

// assertDrivenOrExempt is the cross-check that makes the rest of this a statement
// about a class rather than about four cases.
//
// The four inputs review reported against the first version of this mechanism are
// all covered, and none of them is named: they are members of the derived set,
// which is why a fifth one cannot pass. A previous round committed the reviewer's
// four reproductions as four tests, and the reviewer's next pass found a fifth path
// through the same shape.
func (s Subject) assertDrivenOrExempt(t *testing.T, d surface) {
	t.Helper()

	var missing, stale []string
	for _, key := range sortedKeys(d.Entries) {
		if _, ok := s.Drivers[key]; !ok {
			e := d.Entries[key]
			missing = append(missing, fmt.Sprintf("%s [%s, %s]", key, e.Category, e.Where))
		}
	}
	for _, key := range sortedKeys(s.Drivers) {
		if _, ok := d.Entries[key]; !ok {
			stale = append(stale, key)
		}
	}
	for _, m := range missing {
		t.Errorf("exported input %s has no driver and no exemption: add one to the driver map, or "+
			"say why it cannot render caller-supplied text", m)
	}
	for _, st := range stale {
		t.Errorf("driver %q matches no derived exported input: it was renamed or removed, and this "+
			"driver now covers nothing", st)
	}

	var driven, exempt int
	for _, key := range sortedKeys(s.Drivers) {
		dr := s.Drivers[key]
		switch {
		case dr.Run != nil && dr.Why != "":
			t.Errorf("driver %q may be driven or exempt, not both", key)
		case dr.Run != nil:
			driven++
		case dr.Why != "":
			exempt++
		default:
			t.Errorf("driver %q has neither a Run nor a Why, so it claims nothing", key)
		}
	}
	if driven == 0 {
		t.Fatal("nothing is driven, so the invariant below cannot fail")
	}
	t.Logf("%d exported inputs: %d driven, %d exempt", len(d.Entries), driven, exempt)
}

// assertNoForeignText is the invariant.
//
// Two checks per input, because one of them is not enough and this has the
// receipts. Containment catches text that leaks whole. Differential equality
// catches text derived from the input without appearing in it -- the fourth input
// review reported leaked exactly one byte, through encoding/json's "invalid
// character 'R'", and a containment check for the whole sentinel passed while the
// leak was real.
func (s Subject) assertNoForeignText(t *testing.T, d surface, invoked map[string]bool) {
	t.Helper()
	for _, key := range sortedKeys(d.Entries) {
		dr := s.Drivers[key]
		if dr.Run == nil {
			continue
		}
		t.Run(key, func(t *testing.T) {
			a := renderAll(dr.run(t, sentinelA))
			b := renderAll(dr.run(t, sentinelB))

			if a.Count == 0 {
				t.Fatal("the driver produced nothing that renders; either return the values this " +
					"input can produce, or make it an exemption saying why there are none")
			}
			if strings.Contains(a.Text, sentinelA) {
				t.Errorf("a rendering carries the sentinel whole:\n%s", firstLineWith(a.Text, sentinelA))
			}
			if a.Text != b.Text {
				t.Errorf("two inputs of equal length rendered differently, so something in the "+
					"rendering is derived from the input:\n%s", firstDiff(a.Text, b.Text))
			}

			// The paths that do not render. Review's live holes have all been here:
			// reflection into an unexported field, a slog.Handler that reflects into
			// an unresolved value, and a zero-argument method a template calls by
			// name. No list of verbs reaches any of them, so these checks are over
			// the representation and over the method set rather than over the
			// rendering.
			if dr.ReachableExempt != "" {
				t.Logf("reachable checks skipped for this driver: %s", dr.ReachableExempt)
				return
			}

			valuesA, valuesB := dr.run(t, sentinelA), dr.run(t, sentinelB)
			walkedA, walkedB := reachableText(valuesA), reachableText(valuesB)
			if walkedA.Truncated || walkedB.Truncated {
				t.Errorf("the reachable walk hit its budget, so part of this driver's output was " +
					"not checked; reduce what the driver returns rather than leaving it under-checked")
			}
			if len(walkedA.Texts) == 0 {
				t.Error("the reachable walk found nothing at all, which no check over it can notice")
			}
			if leak := leakedSlots(walkedA, walkedB, sentinelA, sentinelB); leak != "" {
				t.Errorf("ordinary reflection reaches the input: %s", leak)
			}

			hostileA := reachable{Texts: hostileSlogText(valuesA)}
			hostileB := reachable{Texts: hostileSlogText(valuesB)}
			hostileA.Paths = labels("hostile-slog", len(hostileA.Texts))
			hostileB.Paths = labels("hostile-slog", len(hostileB.Texts))
			if leak := leakedSlots(hostileA, hostileB, sentinelA, sentinelB); leak != "" {
				t.Errorf("a slog.Handler that does not resolve LogValuer and reflects into the "+
					"value reaches the input: %s", leak)
			}

			// Every exported zero-argument method that can produce text, called
			// directly and through text/template. The template half is the one that
			// matters: an exported no-argument method is reachable BY NAME from a
			// template, which is USOSS-43's path, and review reproduced it against
			// a zero-argument Foreign.Reveal.
			//
			// Not every driver produces a value with a zero-argument method, and
			// that is fine here: non-vacuity for this check is
			// assertTextProducersInvoked, which asserts over the whole derived set
			// rather than per driver.
			methA := methodAndTemplateText(valuesA)
			methB := methodAndTemplateText(valuesB)
			if leak := leakedSlots(methA, methB, sentinelA, sentinelB); leak != "" {
				t.Errorf("a zero-argument method or a template over one reaches the input: %s", leak)
			}
			for _, m := range methA.Paths {
				invoked[methodKey(m)] = true
			}
		})
	}
}

// methodKey turns "#0 credentials.Foreign.String (direct)" into
// "credentials.Foreign.String".
func methodKey(path string) string {
	i, j := strings.Index(path, " "), strings.LastIndex(path, " (")
	if i < 0 || j <= i {
		return path
	}
	return path[i+1 : j]
}

// assertRenderersExercised covers part of the gap the entry-point derivation
// leaves -- the part reachable through the eight rendering method names.
//
// It is NOT the whole gap, and an earlier version of this comment said it was.
// Review escaped it with a zero-argument Reveal, which is text-producing and is none
// of those eight names. assertTextProducersInvoked is the general version and
// derives the class instead of naming it; this one stays because requiring every
// rendering TYPE to be produced by some driver is a different and still useful
// assertion.
//
// Entry points are functions with arguments, so a zero-argument rendering method --
// Error, String, LogValue -- is not one. They are reachable all the same, because a
// driver produces the value and renderAll pushes it through all of them. This
// asserts that generatively: every exported type in this package that has a
// rendering method was actually produced by some driver, or is a named exemption.
// Without it, a new error type could hold foreign text and be tested by nothing.
func (s Subject) assertRenderersExercised(t *testing.T, d surface) {
	t.Helper()
	covered := map[string]bool{}
	for _, key := range sortedKeys(s.Drivers) {
		dr := s.Drivers[key]
		if dr.Run == nil {
			continue
		}
		for k := range renderAll(dr.run(t, sentinelA)).Types {
			covered[k] = true
		}
	}
	if len(covered) == 0 {
		t.Fatal("no driver produced a renderable value")
	}

	for _, k := range sortedKeys(d.Renderers) {
		if covered[k] {
			continue
		}
		if why := s.RendererExemptions[k]; why != "" {
			t.Logf("renderer %s is exempt: %s", k, why)
			continue
		}
		t.Errorf("type %s has rendering methods %v and is produced by no driver, so nothing checks "+
			"what it renders; produce it from a driver or add a named exemption",
			k, d.Renderers[k].Methods)
	}
	for k := range s.RendererExemptions {
		if _, ok := d.Renderers[k]; !ok {
			t.Errorf("renderer exemption %q matches no derived rendering type", k)
		}
	}
}

// assertTextProducersInvoked replaces a hard-coded list of eight method names.
//
// assertRenderersExercised derives which TYPES have a rendering method, from a fixed
// set of eight names -- Error, String, GoString, Format, LogValue and the three
// marshalers. Review escaped it with a zero-argument Foreign.Reveal: text/template
// called the method by name and recovered every byte, while the derivation filed it
// under Parameterless and nothing invoked it.
//
// So the population here is not a list of names. It is every exported zero-argument
// method whose results can carry text, derived by the type checker, and the
// assertion is that each one was actually called -- directly and through a template
// -- on a value some driver built from the sentinel. A method nobody has written yet
// is covered because the class is derived rather than enumerated.
func (s Subject) assertTextProducersInvoked(t *testing.T, d surface, invoked map[string]bool) {
	t.Helper()
	if len(d.TextProducers) == 0 {
		// Declared empty, and checked as such by assertDerivation. Nothing to do.
		return
	}

	// Run every driver once so that what was produced and what was invoked are
	// populated independently of which subtests ran.
	produced := map[string]bool{}
	for _, key := range sortedKeys(s.Drivers) {
		dr := s.Drivers[key]
		if dr.Run == nil {
			continue
		}
		values := dr.run(t, sentinelA)
		for _, v := range values {
			if v == nil {
				continue
			}
			if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
				continue
			}
			produced[typeKey(v)] = true
		}
		if dr.ReachableExempt != "" {
			continue
		}
		for _, m := range methodAndTemplateText(values).Paths {
			invoked[methodKey(m)] = true
		}
	}
	if len(produced) == 0 || len(invoked) == 0 {
		t.Fatal("no driver produced a value, or no method was invoked")
	}

	var missing int
	for _, key := range sortedKeys(d.TextProducers) {
		owner := d.TextProducers[key]
		method := key[strings.LastIndex(key, ".")+1:]
		if invoked[owner+"."+method] {
			continue
		}
		if why := s.TextProducerExemptions[owner]; why != "" {
			t.Logf("text producer %s is exempt: %s", key, why)
			continue
		}
		missing++
		if produced[owner] {
			t.Errorf("%s is an exported zero-argument method that can produce text, on a type the "+
				"drivers do build, and nothing invoked it", key)
			continue
		}
		t.Errorf("%s is an exported zero-argument method that can produce text, and no driver "+
			"produces a %s for it to be called on. Return one from a driver, or exempt the type "+
			"with a reason.", key, owner)
	}
	for owner := range s.TextProducerExemptions {
		used := false
		for _, o := range d.TextProducers {
			if o == owner {
				used = true
			}
		}
		if !used {
			t.Errorf("text-producer exemption %q matches no derived type", owner)
		}
	}
	t.Logf("%d text-producing zero-argument methods derived, %d invoked, %d unaccounted",
		len(d.TextProducers), len(invoked), missing)
}
