// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the accounting for the *compatibility* checks -- the concrete
// build configurations that run beside the union graph. The boundary proof lives
// in union.go and accounts for itself (see Findings).
//
// It exists because one property kept coming back. Four separate times this
// checker could report that the rules held over something it had not examined.
// It discarded `go list -e` load errors, so a graph could be missing a subtree.
// It accepted build constraints no configuration selected, so a file could sit
// outside every pass. An empty GOOS or GOARCH produced zero passes and the
// command still printed success. And then this very type -- introduced to stop
// the third -- proved only that *some* graph had completed, not that every
// configured one had, so evidence from one target could stand in for six.
//
// A fifth round documented the remaining seam honestly rather than closing it:
// Complete took a target and a package count as arguments, so a caller could
// record a completion for a graph that was never loaded. The ordering in `run`
// was the only thing keeping that straight, and an ordering is not a type.
//
// That seam is now closed by construction. Complete takes the sealed values
// themselves -- the *Union built from real directories and the *Graph returned by
// LoadGraph -- and derives the target, the package count, and the file count from
// them. There is no number to supply and therefore nothing to get wrong or to
// forge: a caller who has not loaded a graph has nothing to pass. Complete also
// runs the differential itself (every edge the concrete graph reports must exist
// in the union) rather than accepting a caller's word that it passed.
//
// The general lesson, recorded in docs/decisions/ and applied here: prefer a
// type that cannot express a violation over a check that notices one, because
// the check lives one level out from the mistake -- which is exactly where each
// of these kept reappearing.

// Coverage is the evidence that a run inspected everything it was configured to
// inspect.
//
// It is created by NewCoverage from the target set the run must cover. The zero
// value is expecting nothing, has completed nothing, and fails Validate: an
// empty Coverage cannot be talked into endorsing anything.
type Coverage struct {
	// union is the graph every completed configuration is checked against. It
	// is also where the file count comes from, so no caller supplies one.
	union *Union
	// expected is the target set this run must account for, in order.
	expected []Target
	// expectedKeys is the same set, for membership tests.
	expectedKeys map[string]bool
	// completed maps a target key to the package count its closure returned.
	completed map[string]int
}

// newCoverage is called by Union.NewCoverage, which is the only way to make one.
//
// The union is required rather than optional: a completed configuration means
// "this graph was loaded from this tree and every edge in it was already in the
// union", and there is nowhere else to check the rest of that.
func newCoverage(u *Union, targets []Target) *Coverage {
	c := &Coverage{
		union:        u,
		expected:     append([]Target(nil), targets...),
		expectedKeys: make(map[string]bool, len(targets)),
		completed:    make(map[string]int, len(targets)),
	}
	for _, t := range targets {
		c.expectedKeys[t.String()] = true
	}
	return c
}

// Complete records that one expected configuration's dependency graph was
// loaded, and that it agreed with the union graph.
//
// Everything it records is read from the arguments: the target and the package
// count come off the *Graph, which only LoadGraph can produce, and the
// differential is computed here rather than taken on trust. It rejects an
// unsealed or nil Graph, a target that was not expected, and a target already
// recorded. There is no way to record a completion for a configuration that was
// not actually loaded.
func (c *Coverage) Complete(g *Graph) error {
	u := c.union
	if u == nil || !u.sealed {
		return fmt.Errorf("coverage has no union graph to check against; construct it with " +
			"NewCoverage(union, targets)")
	}
	if g == nil || !g.sealed {
		return fmt.Errorf("coverage was offered a dependency graph that LoadGraph did not " +
			"produce; evidence must come from a graph that was really loaded")
	}
	// Provenance. A sealed graph proves something was loaded; it does not prove
	// it was loaded *from here*. Review built a temporary module declaring the
	// same module path, loaded a real but empty graph from it, and had it accepted
	// as coverage for this checkout -- so the check is on the resolved directory,
	// which is the one thing a declared name cannot imitate.
	if g.root != u.root {
		return fmt.Errorf("provenance mismatch: this coverage accounts for the module at %s "+
			"and the dependency graph offered for %s was loaded from %s.\n\nA graph loaded "+
			"somewhere else says nothing about the tree being judged, however faithfully it was "+
			"loaded and whatever module path it declares", u.root, g.target, g.root)
	}
	target := g.target
	key := target.String()
	switch {
	case !c.expectedKeys[key]:
		return fmt.Errorf("coverage recorded for %s, which is not one of the %d configured "+
			"build configurations; evidence must correspond to the run that was asked for",
			target, len(c.expected))
	case c.completed[key] != 0:
		return fmt.Errorf("coverage recorded twice for %s; a duplicate cannot stand in for "+
			"a configuration that has not run", target)
	case len(g.nodes) == 0:
		return fmt.Errorf("the dependency graph for %s was empty, so nothing was checked for it", target)
	}

	// The differential invariant. G(c) is a subgraph of U by construction, so a
	// missing edge is not a violation of the rules -- it is a defect in the union
	// resolver, which means the proof does not hold for this tree.
	missing, err := u.Differential(g)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "the union import graph is missing %d edge(s) that the real %s build "+
			"graph reports:\n", len(missing), target)
		for _, m := range missing {
			fmt.Fprintf(&b, "    %s\n", m)
		}
		b.WriteString("\nEvery concrete build graph must be a subgraph of the union -- that is the " +
			"whole\nproof. A missing edge means the union resolver missed a toolchain behaviour, so " +
			"the\nunion's silence about a forbidden path cannot be trusted. Fix the resolver in\n" +
			"internal/boundary/union.go rather than this accounting.")
		return fmt.Errorf("%s", b.String())
	}

	c.completed[key] = len(g.nodes)
	return nil
}

// Validate reports whether the recorded evidence accounts for every configured
// build configuration.
//
// It requires a real union graph and that the completed set is *exactly* the
// expected set. Every completion in it was recorded from a loaded graph that
// agreed with the union, so this is now a statement about work that happened
// rather than about numbers a caller reported.
func (c *Coverage) Validate() error {
	if len(c.expected) == 0 {
		return fmt.Errorf("nothing was checked: this run was configured with no build " +
			"configurations at all, so no dependency graph could have been examined")
	}
	if u := c.union; u == nil || !u.sealed {
		return fmt.Errorf("nothing was checked: there is no union import graph, so no " +
			"configuration could have been compared against one")
	}
	if c.union.Files() == 0 {
		return fmt.Errorf("nothing was checked: the union graph parsed no Go files, " +
			"so no declared import was examined")
	}
	var missing []string
	for _, t := range c.expected {
		if c.completed[t.String()] == 0 {
			missing = append(missing, t.String())
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("incomplete: %d of %d build configurations did not complete (%s), so a "+
			"forbidden dependency reachable only on one of them would not have been seen",
			len(missing), len(c.expected), strings.Join(missing, ", "))
	}
	// Belt and braces. Complete already refuses an unexpected target, so this
	// can only fire if someone adds another way in.
	if len(c.completed) != len(c.expected) {
		return fmt.Errorf("coverage accounts for %d build configurations but %d were configured",
			len(c.completed), len(c.expected))
	}
	return nil
}

// Endorse is the only way to obtain a success line, and it will not assemble one
// out of evidence that does not fit together.
//
// It exists because the command layer was the last place holding an invariant
// that belongs in a type. `reportSuccess` took a *Findings and a *Coverage and
// validated each in turn, so nothing stopped it being handed a judgement of one
// tree and coverage of another -- or a judgement made under a *different rule
// set* than the one being reported. Both are the same defect this package has now
// met five times: a claim about work that was not done.
//
// So there is one method, and it requires:
//
//   - both pieces of evidence to be real (each was produced by the union, not
//     assembled by a caller) and to validate on their own terms;
//   - both to come from the *same resolved module directory*;
//   - the findings to have been produced under exactly the rules being reported,
//     so a run cannot judge a permissive rule set and report a strict one.
//
// The returned string is derived from the evidence, so the message cannot claim
// more than was checked.
func (c *Coverage) Endorse(cfg Config, f *Findings) (string, error) {
	u := c.union
	if u == nil || !u.sealed {
		return "", fmt.Errorf("nothing was checked: this coverage has no union import graph")
	}
	if f == nil || !f.sealed {
		return "", fmt.Errorf("nothing was checked: no union judgement was produced")
	}
	if f.root != u.root {
		return "", fmt.Errorf("provenance mismatch: the union judgement covers the module at %s "+
			"and this coverage accounts for %s; neither endorses the other", f.root, u.root)
	}
	want := make([]string, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		want = append(want, rule.Name)
	}
	if strings.Join(want, ",") != strings.Join(f.rules, ",") {
		return "", fmt.Errorf("the rules judged (%s) are not the rules being reported (%s); a run "+
			"may not enforce one rule set and claim another",
			strings.Join(f.rules, ", "), strings.Join(want, ", "))
	}
	if err := f.Validate(); err != nil {
		return "", err
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d rule(s) (%s) held over the union import graph of %s: %s\n"+
		"compatibility checks passed over %s",
		len(f.rules), strings.Join(f.rules, ", "), u.MainModule().Path, f.Summary(), c.Summary()), nil
}

// Summary describes what was inspected, for the success line. It is derived
// from the same record Validate judges, so the message cannot claim coverage
// the run did not have.
func (c *Coverage) Summary() string {
	parts := make([]string, 0, len(c.expected)+1)
	files := 0
	if c.union != nil {
		files = c.union.Files()
	}
	parts = append(parts, fmt.Sprintf("%d Go files", files))
	for _, t := range c.expected {
		parts = append(parts, fmt.Sprintf("%d packages on %s", c.completed[t.String()], t))
	}
	return strings.Join(parts, "; ")
}

// Validate rejects a configuration that could not check anything.
//
// The command layer builds a Config from flags and any other caller can build
// one directly, so "the Makefile passes both dimensions" is not a safety
// property. An empty dimension is rejected here, by name, before any work
// starts -- and Coverage catches it again afterwards, from the other direction.
// It reads the configuration the run will actually use.
func (c Config) Validate() error {
	if len(c.GOOS) == 0 {
		return fmt.Errorf("empty GOOS: the support matrix needs at least one operating " +
			"system, or the closure runs no passes and accepts no platform constraint")
	}
	if len(c.GOARCH) == 0 {
		return fmt.Errorf("empty GOARCH: the support matrix needs at least one " +
			"architecture, or the closure runs no passes and accepts no platform constraint")
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("no rules configured: there is nothing to enforce")
	}
	for _, r := range c.Rules {
		for root, kind := range r.CompositionRoots {
			if root == "" || (kind != KindBuild && kind != KindTest) {
				return fmt.Errorf("rule %q has an invalid composition root", r.Name)
			}
		}
		// A rule states one kind of claim. Both together would make the
		// question "does this rule forbid X" depend on which branch happened to
		// be consulted first, which is a rule nobody can read off its own
		// declaration.
		if len(r.DeniedPrefixes) > 0 && len(r.PermittedImportPrefixes) > 0 {
			return fmt.Errorf("rule %q names both denied prefixes and permitted import "+
				"prefixes; a rule either forbids what it names or forbids everything it does "+
				"not name, and one that claims both cannot be read off its declaration", r.Name)
		}
		if len(r.ExemptImportPrefixes) > 0 && len(r.DeniedPrefixes) == 0 {
			return fmt.Errorf("rule %q names exempt import prefixes but no denied prefix; an "+
				"exemption only narrows a denial, so it has nothing to carve out of", r.Name)
		}
		if len(r.DeniedPrefixes) == 0 && len(r.PermittedImportPrefixes) == 0 {
			return fmt.Errorf("rule %q forbids nothing: it names no denied prefix and no "+
				"permitted import prefix, so it would judge every package and find nothing",
				r.Name)
		}
		// An allowlist rule bounded to nothing would judge the whole tree
		// against a list drawn up for one package.
		if len(r.PermittedImportPrefixes) > 0 && len(c.StandardPackages) == 0 {
			return fmt.Errorf("rule %q permits an import list and no standard-library set is "+
				"configured; an allowlist forbids everything it does not name, and without the "+
				"toolchain's answer to what the standard library contains it would deny every "+
				"standard import. Call StandardPackages and set Config.StandardPackages", r.Name)
		}
		if len(r.PermittedImportPrefixes) > 0 && len(r.SubjectPrefixes) == 0 {
			return fmt.Errorf("rule %q permits an import list with no subject set; an allowlist "+
				"is a claim about specific packages, and applied tree-wide it would forbid "+
				"every dependency this repository has", r.Name)
		}
	}
	if len(c.ReleaseTags) == 0 {
		return fmt.Errorf("no toolchain release tags: go1.N build constraints could not be judged")
	}
	if len(c.Targets()) == 0 {
		// Unreachable given the checks above, and here anyway: Targets() is the
		// thing the rest of the run depends on, so it is the thing to assert.
		return fmt.Errorf("the support matrix produced no build configurations to check")
	}
	return nil
}
