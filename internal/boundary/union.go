// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This file is the boundary proof. Everything else in this package is either
// support for it or a compatibility check beside it.
//
// # Why the previous primitive could not work
//
// The policy is universal:
//
//	No supported build configuration may give a disallowed first-party package
//	a dependency path to a denied package.
//
// `go list` answers something existentially narrower: what dependency graph did
// *this one concrete build configuration* select? No finite list of builds
// proves a universal property, and this checker was defeated four times saying
// otherwise -- by a transitive import through a third-party wrapper, by a
// `*_windows.go` blank import, by an `arm64`-only import behind an accepted but
// unexecuted selector, and by coverage blessing a success line from a subset of
// targets. Each fix was correct. Each time the property reappeared one level up,
// because the primitive could not express the claim.
//
// # The construction-level invariant
//
// Let G(c) be the import graph selected by any supported configuration c. Let U
// be the graph containing every syntactically declared production import edge
// from every Go file in every reachable package, regardless of build constraint,
// plus test imports for first-party packages -- because the rule intentionally
// covers tests.
//
//	for every supported configuration c:   G(c) is a subgraph of U
//	therefore: if U contains no forbidden path, no G(c) contains one.
//
// That is the whole proof, and adding an architecture, a custom tag, a nested
// negation, a release tag, or a new supported platform cannot open a hole in it.
// Those things only *select* edges, and every edge they could select is already
// in U, where it has already been judged. The checker stops needing to know
// which configurations exist.
//
// # Over-approximation is the intended behaviour
//
// U may contain an edge no supported configuration selects, so this can report
// an import that no build performs today. For an architectural security fence
// that is the right trade: code behind an unsupported selector is exactly the
// code that becomes reachable later without anyone revisiting the boundary. If
// such an import is genuinely harmless, deleting it or moving it behind the
// allowed provider package is safer than teaching a security gate a
// configuration exception. Constraints are parsed here for diagnostics and for
// fail-closed validation; they never remove an edge.
//
// # What is out of scope
//
// U proves the property for committed Go import declarations. Native linker
// flags, runtime plugin loading, reflection-based network calls, and source
// generated after the check are different policies and are not claimed. A
// `//go:generate` directive is not an import edge. Generated Go that ships must
// be committed, and is therefore scanned like anything else.

// Edge is one declared import, with the evidence for it.
type Edge struct {
	// From is the importing package's path.
	From string
	// To is the imported path exactly as the source declares it.
	To string
	// Kind says whether the declaring file is production source, an in-package
	// test, or an external test.
	Kind ImportKind
	// File is the declaring file, rendered for a human: relative to the
	// repository root for first-party files, module-qualified for a dependency.
	File string
	// Line is the line the import spec sits on.
	Line int
}

// ChainEdge is one hop of a reported dependency path. A violation carries the
// whole chain, with a file and line for every hop, because "package A reaches
// forbidden package Z" is not actionable and "A imports B at a.go:7, B imports Z
// at b.go:12" is.
type ChainEdge struct {
	From string
	To   string
	File string
	Line int
	Kind ImportKind
}

// unionPackage is one node of U: a directory's worth of declared imports.
type unionPackage struct {
	importPath string
	module     Module
	dir        string
	edges      []Edge
	fileCount  int
}

// Union is the build-constraint-independent import graph.
//
// Its fields are unexported, it has no exported way to add a node or an edge,
// and the only constructor reads real directories off disk. That is deliberate,
// and it is the lesson this repository already paid for: the previous evidence
// type took a package count from its caller, so a caller could assemble a claim
// that corresponded to no real work. Here there is nothing to assemble --
// every edge in U came from a file that was parsed, and every judgement is made
// by a method on this type.
type Union struct {
	// sealed is set only by LoadUnion. A zero Union endorses nothing: it is not
	// merely empty, it is refused.
	sealed bool
	// root is the canonical main-module directory this graph was built from, and
	// the identity every piece of evidence about this run must match. Review
	// showed why a declared module path will not do: a temporary module that
	// declared the same path produced a real graph a real Coverage accepted.
	root string
	mods *ModuleSet
	// std is the toolchain's own answer to what the standard library contains,
	// for the tree this union was loaded from. It is the union's, not a
	// caller's: the proof must not depend on a set somebody handed in. See
	// [StandardPackages] for why it is asked rather than inferred.
	std  map[string]bool
	fset *token.FileSet
	// packages is the parse cache, keyed by import path. A directory is parsed
	// at most once.
	packages map[string]*unionPackage
	// roots is every package in the main module, sorted. These are the packages
	// the rules judge; everything else in U is a dependency being inspected.
	roots     []string
	fileCount int
	edgeCount int
}

// LoadUnion builds the union import graph for the module rooted at dir.
//
// Every package in the main module is parsed eagerly, because every one of them
// is a root that has to be judged. Dependency packages are parsed lazily, when
// the traversal first reaches them, and cached -- so the cost is bounded by what
// is actually reachable rather than by the size of the module cache.
func LoadUnion(dir string) (*Union, error) {
	mods, err := LoadModules(dir)
	if err != nil {
		return nil, err
	}
	root, err := canonicalDir(mods.Main().Dir)
	if err != nil {
		return nil, fmt.Errorf("resolving the main module directory for %s: %w", mods.Main().Path, err)
	}
	// The supported matrix, not the host: the union must be a superset of every
	// concrete build graph, and the standard library is a different set on each
	// platform.
	std, err := StandardPackages(dir, DefaultGOOS, DefaultGOARCH)
	if err != nil {
		return nil, err
	}
	u := &Union{
		sealed:   true,
		root:     root,
		mods:     mods,
		std:      std,
		fset:     token.NewFileSet(),
		packages: map[string]*unionPackage{},
	}
	if err := u.loadMainModule(); err != nil {
		return nil, err
	}
	if len(u.roots) == 0 {
		return nil, fmt.Errorf("no Go packages found in the main module %s at %s: a check that "+
			"examined nothing must not be able to report that the rules held",
			mods.Main().Path, mods.Main().Dir)
	}
	return u, nil
}

// MainModule returns the module being judged.
func (u *Union) MainModule() Module { return u.mods.Main() }

// ModuleDir returns the canonical directory this union was built from. It is the
// provenance every piece of evidence about this run is checked against.
func (u *Union) ModuleDir() string {
	if u == nil {
		return ""
	}
	return u.root
}

// NewCoverage returns the compatibility-coverage accounting for this union.
//
// It is a method so that a Coverage is bound to a union at construction and
// there is no way to pair one with another union's evidence. Combined with
// LoadGraph being a method, a Coverage can only ever be offered graphs from the
// tree it belongs to.
func (u *Union) NewCoverage(targets []Target) *Coverage {
	return newCoverage(u, targets)
}

// Roots returns every first-party package path, sorted.
func (u *Union) Roots() []string { return append([]string(nil), u.roots...) }

// Files reports how many Go files have been parsed into U so far.
func (u *Union) Files() int { return u.fileCount }

// Packages reports how many package directories have been parsed into U so far.
func (u *Union) Packages() int { return len(u.packages) }

// Edges reports how many import edges U holds so far.
func (u *Union) Edges() int { return u.edgeCount }

// loadMainModule parses every package in the main module, recording each as a
// root to be judged.
//
// Which directories those are is [PackageDirs], the single implementation of that
// question -- not a rule restated here. This function used to walk the tree with
// its own skip list, and that list was wrong twice.
func (u *Union) loadMainModule() error {
	main := u.mods.Main()
	dirs, err := PackageDirs(main.Dir)
	if err != nil {
		return err
	}
	for _, rel := range dirs {
		importPath := packagePath(main.Path, rel)
		pkg, parseErr := u.parseDir(importPath, main, filepath.Join(main.Dir, filepath.FromSlash(rel)), true)
		if parseErr != nil {
			return parseErr
		}
		if pkg == nil {
			// PackageDirs already required a compilable file name here, so this
			// is unreachable; it is not an error either way.
			continue
		}
		u.roots = append(u.roots, importPath)
	}
	sort.Strings(u.roots)
	return nil
}

// node returns the graph node for an import path, parsing its directory on first
// use.
//
// An import that cannot be resolved to a directory is a fatal
// *UnresolvedImportError rather than an absent node: a missing node is a
// subgraph that was not examined, and the whole point of this type is that it
// does not report success over something it did not look at.
func (u *Union) node(importPath string) (*unionPackage, error) {
	if pkg, ok := u.packages[importPath]; ok {
		return pkg, nil
	}
	mod, dir, err := u.mods.Resolve(importPath)
	if err != nil {
		return nil, err
	}
	// A dependency's own tests are excluded: `go test ./...` does not run them,
	// so an import that only their test files declare is not part of any build
	// or test of this module. (A first-party package's tests are included --
	// they are parsed by loadMainModule, which passes true.)
	pkg, err := u.parseDir(importPath, mod, dir, false)
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		return nil, &UnresolvedImportError{
			Import: importPath,
			Reason: fmt.Sprintf("%s exists but contains no Go files", dir),
		}
	}
	return pkg, nil
}

// parseDir reads one directory into a node. It returns nil when the directory
// contains no Go files at all, which is not an error for a parent directory in
// the main module.
//
// Every `.go` file is parsed. Build constraints are read but never obeyed: a
// `*_windows.go`, a `//go:build customtag`, a nested negation, and a
// `//go:build ignore` all contribute their imports exactly like an
// unconstrained file. A malformed constraint is fatal -- it must never be a way
// to make a file invisible.
func (u *Union) parseDir(importPath string, mod Module, dir string, includeTests bool) (*unionPackage, error) {
	if pkg, ok := u.packages[importPath]; ok {
		return pkg, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading package directory %s: %w", dir, err)
	}
	pkg := &unionPackage{importPath: importPath, module: mod, dir: dir}
	sawGo := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		isTest := strings.HasSuffix(entry.Name(), "_test.go")
		if isTest && !includeTests {
			continue
		}
		sawGo = true
		abs := filepath.Join(dir, entry.Name())
		f, parseErr := parser.ParseFile(u.fset, abs, nil, parser.ImportsOnly|parser.ParseComments)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing %s: %w\n\nA file that cannot be parsed is a file "+
				"whose imports are unknown, so this is fatal rather than skipped", abs, parseErr)
		}
		if constraintErr := validateConstraints(u.fset, f, u.mods.displayPath(mod, abs)); constraintErr != nil {
			return nil, constraintErr
		}
		kind := KindBuild
		if isTest {
			kind = KindTest
			if f.Name != nil && strings.HasSuffix(f.Name.Name, "_test") {
				kind = KindExternalTest
			}
		}
		display := u.mods.displayPath(mod, abs)
		for _, spec := range f.Imports {
			imported, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return nil, fmt.Errorf("%s:%d: import path %s is not a valid string literal: %w",
					display, u.fset.Position(spec.Pos()).Line, spec.Path.Value, unquoteErr)
			}
			pkg.edges = append(pkg.edges, Edge{
				From: importPath,
				To:   imported,
				Kind: kind,
				File: display,
				Line: u.fset.Position(spec.Pos()).Line,
			})
		}
		pkg.fileCount++
	}
	if !sawGo {
		return nil, nil
	}
	sortEdges(pkg.edges)
	u.packages[importPath] = pkg
	u.fileCount += pkg.fileCount
	u.edgeCount += len(pkg.edges)
	return pkg, nil
}

// kindRank orders import kinds by severity, so that when a package declares the
// same import from both production source and a test, the traversal reports the
// production one -- the serious case, and the one that lands in an adopter's
// build.
func kindRank(k ImportKind) int {
	switch k {
	case KindBuild:
		return 0
	case KindTest:
		return 1
	case KindExternalTest:
		return 2
	}
	return 3
}

func sortEdges(edges []Edge) {
	sort.SliceStable(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Kind != b.Kind {
			return kindRank(a.Kind) < kindRank(b.Kind)
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

// validateConstraints parses the file's build constraints and fails on one it
// cannot understand.
//
// The constraints do not affect U -- every edge is included regardless. They are
// validated anyway, because "this file has a constraint I could not parse" must
// never resolve to "so I will treat the file as absent". The one thing this
// checker may not do is quietly stop looking at something.
func validateConstraints(fset *token.FileSet, f *ast.File, file string) error {
	for _, group := range f.Comments {
		// Constraints sit before the package clause. A //go:build-looking line
		// after it is an ordinary comment and the toolchain ignores it too.
		if group.Pos() >= f.Package {
			break
		}
		for _, c := range group.List {
			if !constraint.IsGoBuild(c.Text) && !constraint.IsPlusBuild(c.Text) {
				continue
			}
			if _, err := constraint.Parse(c.Text); err != nil {
				return fmt.Errorf("%s:%d: malformed build constraint %q: %w\n\n"+
					"This is fatal rather than ignored. A constraint the checker cannot parse must "+
					"not become a reason to treat the file as absent -- that is exactly how a file "+
					"becomes invisible to a gate", file, fset.Position(c.Pos()).Line, c.Text, err)
			}
		}
	}
	return nil
}

// Findings is the result of judging U, and the only thing that can say the
// boundary rules held.
//
// It is produced solely by (*Union).Judge, its fields are unexported, and it
// records the roots it actually judged rather than a count handed to it. A
// caller cannot construct one that endorses work that did not happen: the zero
// value is refused by Validate, and there is no exported way to put anything
// into one.
type Findings struct {
	sealed bool
	// root is the canonical module directory these findings were produced from,
	// so a judgement of one tree cannot endorse a run over another.
	root       string
	violations []Violation
	// expectedRoots is every first-party package that had to be judged.
	expectedRoots []string
	// judgedRoots is every one that was, recorded as the traversal completed.
	judgedRoots map[string]bool
	rules       []string
	// judgedByRule counts, per rule name, how many first-party roots that rule
	// actually judged. A rule that judged none checked nothing, and a run that
	// checked nothing must not report that the rules held.
	judgedByRule map[string]int
	// subjectScoped names the rules whose subject set bounds them, so Validate
	// can distinguish "this rule judged nothing because its subject package is
	// gone" from a tree-wide rule, which judges every root by construction.
	subjectScoped map[string]bool
	packages      int
	edges         int
	files         int
}

// Violations returns the rule violations found in U, most legible first.
func (f *Findings) Violations() []Violation {
	if f == nil {
		return nil
	}
	return append([]Violation(nil), f.violations...)
}

// Validate reports whether this result may be used to say the rules held.
//
// Exact root accounting, by the same argument the target accounting used to
// make and could not keep: every first-party package that existed must have been
// judged. The difference is that nothing here is supplied by a caller.
func (f *Findings) Validate() error {
	if f == nil || !f.sealed {
		return fmt.Errorf("nothing was checked: this result was not produced by judging a " +
			"union import graph")
	}
	if len(f.rules) == 0 {
		return fmt.Errorf("nothing was checked: no rules were configured, so there was " +
			"nothing to enforce")
	}
	if len(f.expectedRoots) == 0 {
		return fmt.Errorf("nothing was checked: the main module contained no packages")
	}
	if f.files == 0 || f.packages == 0 {
		return fmt.Errorf("nothing was checked: the union graph holds %d packages from %d files",
			f.packages, f.files)
	}
	var missing []string
	for _, root := range f.expectedRoots {
		if !f.judgedRoots[root] {
			missing = append(missing, root)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("incomplete: %d of %d first-party packages were not judged (%s), so a "+
			"forbidden dependency of one of them would not have been seen",
			len(missing), len(f.expectedRoots), strings.Join(missing, ", "))
	}
	// A subject-scoped rule quantifies over a population, and a population that
	// came out empty satisfies every property stated over it. The way that
	// happens in practice is mundane -- the subject package is renamed, moved or
	// deleted -- and the symptom is a rule that goes on passing while guarding
	// nothing. Non-emptiness is therefore part of the result being usable, not a
	// separate nicety.
	var inert []string
	for _, name := range f.rules {
		if f.subjectScoped[name] && f.judgedByRule[name] == 0 {
			inert = append(inert, name)
		}
	}
	if len(inert) > 0 {
		sort.Strings(inert)
		return fmt.Errorf("inert: rule(s) %s judged no first-party package, so they were "+
			"satisfied by an empty set; their subject packages no longer exist under the "+
			"names the rule names", strings.Join(inert, ", "))
	}
	return nil
}

// Summary describes what was proved, for the success line. It is derived from
// the same record Validate judges, so the message cannot overstate the work.
func (f *Findings) Summary() string {
	return fmt.Sprintf("%d first-party package(s), %d package(s) and %d import edge(s) "+
		"from %d Go file(s), every build constraint ignored",
		len(f.expectedRoots), f.packages, f.edges, f.files)
}

// Judge walks U from every first-party root and reports every rule violation.
//
// The allowed prefix applies to the root being judged, not to anything along the
// way. So `credentials/c1 -> wrapper -> c1 SDK` is allowed because the root is
// the c1 provider, while `modules/deploy -> the same wrapper -> c1 SDK` is a
// violation. A third-party package cannot launder a denied dependency for a
// caller that is not itself allowed to have it.
func (u *Union) Judge(cfg Config) (*Findings, error) {
	if u == nil || !u.sealed {
		return nil, fmt.Errorf("the union graph was not loaded; call LoadUnion")
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("no rules configured: there is nothing to enforce")
	}
	// The module prefix bounds which packages are judged, so a wrong one would
	// silently judge nothing. It is checked against the module the toolchain
	// reports rather than trusted.
	main := u.mods.Main().Path
	if cfg.ModulePrefix != main {
		return nil, fmt.Errorf("configured module prefix %q is not the main module %q; the "+
			"first-party packages this would judge are not the ones in this tree",
			cfg.ModulePrefix, main)
	}

	f := &Findings{
		sealed:        true,
		root:          u.root,
		expectedRoots: u.Roots(),
		judgedRoots:   map[string]bool{},
		judgedByRule:  map[string]int{},
		subjectScoped: map[string]bool{},
	}
	for _, rule := range cfg.Rules {
		f.rules = append(f.rules, rule.Name)
		f.subjectScoped[rule.Name] = len(rule.SubjectPrefixes) > 0
	}

	for _, root := range f.expectedRoots {
		for _, rule := range cfg.Rules {
			if !rule.judges(root) {
				continue
			}
			f.judgedByRule[rule.Name]++
			// The union's own standard-library set, never the configuration's.
			// The proof is about the tree this union was loaded from, and a
			// caller-supplied set would be a second opinion about it -- which
			// is the shape review defeated three times in this checker.
			found, err := u.search(root, rule, u.std)
			if err != nil {
				return nil, err
			}
			f.violations = append(f.violations, found...)
		}
		f.judgedRoots[root] = true
	}
	f.violations = Merge(f.violations)
	f.packages, f.edges, f.files = u.Packages(), u.Edges(), u.Files()
	return f, nil
}

// visit is one node of the breadth-first search, with a parent pointer so the
// reported chain is reconstructed rather than copied at every hop.
type visit struct {
	importPath string
	edge       Edge
	parent     int
}

// search walks U from one root, breadth-first, and returns a violation for each
// denied package it can reach.
//
// Breadth-first so the reported chain is a shortest one; a reader chasing a
// six-hop path when a two-hop path exists is a reader who stops trusting the
// output.
//
// Only the first hop may be a test import. Beyond it the traversal follows
// production edges only, because a first-party package's tests are not compiled
// into anything that imports it -- and that package is judged on its own account
// as another root, where its test import is reported against it rather than
// against its consumers. Dependency tests are not in U at all.
func (u *Union) search(root string, rule Rule, std map[string]bool) ([]Violation, error) {
	visits := []visit{{importPath: root, parent: -1}}
	seen := map[string]bool{root: true}
	var out []Violation

	for i := 0; i < len(visits); i++ {
		cur := visits[i]
		if i > 0 {
			if cur.parent == 0 && rule.composesBoundary(root, cur.edge.Kind, cur.importPath) {
				continue
			}
			if denied, ok := rule.denies(cur.importPath, std); ok {
				out = append(out, u.violation(root, denied, rule, visits, i))
				// Stop here. What the denied package itself imports is its own
				// business, and walking through it would bury the finding.
				continue
			}
		}
		// The standard library is a leaf: nothing in it can reach a denied
		// package, and nothing outside it can reach one through it. Membership
		// is the toolchain's answer, not a guess about spelling -- see
		// [StandardPackages].
		if std[cur.importPath] {
			continue
		}
		pkg, err := u.node(cur.importPath)
		if err != nil {
			var unresolved *UnresolvedImportError
			if errors.As(err, &unresolved) {
				// Attach the position of the import that led here, which is the
				// line somebody has to fix.
				unresolved.From = cur.importPath
				if i > 0 {
					unresolved.From = cur.edge.From
					unresolved.File, unresolved.Line = cur.edge.File, cur.edge.Line
				}
				return nil, unresolved
			}
			return nil, err
		}
		for _, edge := range pkg.edges {
			if i > 0 && edge.Kind != KindBuild {
				continue
			}
			if seen[edge.To] {
				continue
			}
			seen[edge.To] = true
			visits = append(visits, visit{importPath: edge.To, edge: edge, parent: i})
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Import < out[b].Import })
	return out, nil
}

// violation renders the path from root to the denied package as a finding,
// naming every hop and the package that introduced the reachability.
func (u *Union) violation(root, denied string, rule Rule, visits []visit, at int) Violation {
	var chain []ChainEdge
	for i := at; i > 0; i = visits[i].parent {
		e := visits[i].edge
		chain = append(chain, ChainEdge{From: e.From, To: e.To, File: e.File, Line: e.Line, Kind: e.Kind})
	}
	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}
	v := Violation{
		RuleName: rule.Name,
		Package:  root,
		Import:   denied,
		Kind:     chain[0].Kind,
		File:     chain[0].File,
		Line:     chain[0].Line,
		Chain:    chain,
		// The last hop's importer is what actually created the reachability,
		// which for a transitive finding is the interesting package and is not
		// otherwise obvious from the chain.
		Introducer: chain[len(chain)-1].From,
		Reason:     rule.Reason,
	}
	for _, hop := range chain[:len(chain)-1] {
		v.Via = append(v.Via, hop.To)
	}
	return v
}

// MissingEdge is an import edge that a concrete build configuration's dependency
// graph reported and U does not contain.
//
// There should never be one. G(c) is a subgraph of U by construction, so a
// missing edge means the union resolver missed a toolchain behaviour -- and
// therefore that the proof does not hold for the tree in front of it. It fails
// the gate rather than being logged.
type MissingEdge struct {
	Target Target
	From   string
	To     string
	Reason string
}

func (m MissingEdge) String() string {
	s := fmt.Sprintf("%s -> %s (reported by %s)", m.From, m.To, m.Target)
	if m.Reason != "" {
		s += ": " + m.Reason
	}
	return s
}

// Differential checks the invariant that makes the concrete targets worth
// running: every edge the toolchain reports for a real build configuration must
// already be in U.
//
// It takes a *Graph, which only LoadGraph can produce, so the comparison is
// against a graph that was really loaded rather than against a value a caller
// assembled.
func (u *Union) Differential(g *Graph) ([]MissingEdge, error) {
	if u == nil || !u.sealed {
		return nil, fmt.Errorf("the union graph was not loaded; call LoadUnion")
	}
	if g == nil || !g.sealed {
		return nil, fmt.Errorf("the dependency graph was not loaded by LoadGraph, so there " +
			"is nothing to compare against")
	}
	if g.root != u.root {
		return nil, fmt.Errorf("provenance mismatch: the dependency graph was loaded from %s "+
			"and this union graph was built from %s.\n\nComparing them would say nothing about "+
			"either tree. Provenance is judged on the resolved directory, not on the module path "+
			"the two happen to declare", g.root, u.root)
	}
	byPath := make(map[string]Node, len(g.nodes))
	for _, n := range g.nodes {
		byPath[n.ImportPath] = n
	}

	var missing []MissingEdge
	reported := map[string]bool{}
	for _, n := range g.nodes {
		from := ownerPath(n.ImportPath, n.ForTest)
		// The standard library is a leaf in U on purpose, and the synthesised
		// test-main package is not a directory anybody can parse.
		if u.std[from] || strings.HasSuffix(n.ImportPath, ".test") {
			continue
		}
		pkg, err := u.node(from)
		if err != nil {
			key := from + "|"
			if !reported[key] {
				reported[key] = true
				missing = append(missing, MissingEdge{Target: g.target, From: from,
					Reason: "the union graph could not read this package: " + err.Error()})
			}
			continue
		}
		have := map[string]bool{}
		for _, e := range pkg.edges {
			have[e.To] = true
		}
		for _, imp := range n.Imports {
			to := ownerPath(imp, byPath[imp].ForTest)
			if to == from || u.std[to] || have[to] {
				continue
			}
			key := from + "|" + to
			if reported[key] {
				continue
			}
			reported[key] = true
			missing = append(missing, MissingEdge{Target: g.target, From: from, To: to})
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].From != missing[j].From {
			return missing[i].From < missing[j].From
		}
		return missing[i].To < missing[j].To
	})
	return missing, nil
}

// FileScanCrossCheck reports any finding the shallow file scan made that the
// union graph did not.
//
// The two views read the same first-party files through different code, so the
// union must be a superset: anything a file declares directly is an edge from
// that package. A disagreement means the union walker missed a file the scanner
// saw -- a gap in the primitive that the rest of this package now rests on --
// and it fails the gate for the same reason a missing differential edge does.
func FileScanCrossCheck(fileFindings []Violation, unionFindings *Findings) []Violation {
	have := map[string]bool{}
	for _, v := range unionFindings.Violations() {
		have[v.key()] = true
	}
	var missed []Violation
	for _, v := range fileFindings {
		if !have[v.key()] {
			missed = append(missed, v)
		}
	}
	sortViolations(missed)
	return missed
}
