// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file answers one question: which build constraints may a file in this
// repository carry?
//
// Since USOSS-28 this is **hygiene, not the fence**. The boundary proof is the
// union graph in union.go, which reads every file regardless of its constraints,
// so a tag nothing selects can no longer hide an import from it. What the rule
// below still buys is that every file is compiled by some configuration the
// compatibility passes run -- a file outside all of them is a file nothing
// type-checks. The reasoning that follows is the history of how it came to exist,
// and it is worth keeping because the drift it describes is a general trap.
//
// The first answer was "a list of tags we consider normal", and review took it
// apart on an ordinary target. Every GOOS, every GOARCH, and every `go1.N` were
// accepted, while the dependency closure ran three GOOS values on amd64 alone.
// So `//go:build arm64` was an accepted constraint on a file no closure pass
// ever selected -- and an arm64-only import of a third-party wrapper that
// imported the forbidden package went straight through. arm64 is Graviton and
// Apple Silicon; this was not an exotic corner.
//
// The lesson is not "add arm64". It is that a hand-maintained accepted-tags
// list and a hand-maintained target list are two lists that drift, and the
// drift is invisible until somebody goes looking. So there is one list. The
// support matrix on Config defines the build configurations the closure runs,
// and the accepted selectors are *derived from it*: a constraint is acceptable
// exactly when some pass the closure actually executes would select it.
//
// Widening acceptance therefore means widening coverage, in the same edit.

const buildTagRuleName = "declared-build-tags"

// unixGOOS is Go's own definition of the `unix` meta-tag. It is a property of
// the language, not a coverage claim -- but whether `unix` is *accepted* still
// depends on whether the matrix contains one of these.
var unixGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true,
	"linux": true, "netbsd": true, "openbsd": true, "solaris": true,
}

// platformFileSuffix is Go's vocabulary of GOOS and GOARCH names, used only to
// decide whether a `_something` filename suffix is a build constraint at all.
//
// This is a language fact, not a coverage claim: recognising that
// `probe_arm64.go` is constrained to arm64 is separate from deciding whether
// arm64 is a platform the closure examines. AcceptedSelectors decides that, and
// a name here that is missing from the matrix is rejected like any other
// uncovered selector.
var platformFileSuffix = func() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		// GOOS
		"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos",
		"ios", "js", "linux", "nacl", "netbsd", "openbsd", "plan9", "solaris",
		"wasip1", "windows", "zos",
		// GOARCH
		"386", "amd64", "amd64p32", "arm", "arm64", "arm64be", "armbe",
		"loong64", "mips", "mips64", "mips64le", "mips64p32", "mips64p32le",
		"mipsle", "ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390",
		"s390x", "sparc", "sparc64", "wasm",
	} {
		m[name] = true
	}
	return m
}()

// goVersionTag recognises a release selector such as go1.25. Which ones are
// satisfiable is not a matter of spelling -- it is whatever the toolchain
// running the closure reports -- so the set is derived, not parsed.
var goVersionTag = regexp.MustCompile(`^go1\.\d+$`)

// SelectorKind says what justifies accepting a selector.
type SelectorKind string

const (
	// SelectedByTarget means a specific closure pass compiles files behind it.
	SelectedByTarget SelectorKind = "target"
	// SelectedByToolchain means every pass does, because it is a property of
	// the toolchain running them -- the gc tag, and the release tags it reports.
	SelectedByToolchain SelectorKind = "toolchain"
)

// Selector is an accepted build constraint together with what justifies it.
//
// The justification is structured rather than prose. An earlier version carried
// a free-form sentence and the "structural" invariant test checked that the
// sentence mentioned a target -- which a hand-written string satisfies just as
// easily as a real one. A test whose evidence is a message is not a test.
type Selector struct {
	// Name is the tag.
	Name string
	// Kind says which justification applies.
	Kind SelectorKind
	// Target is the pass that selects it, when Kind is SelectedByTarget.
	Target Target
	// Because is for humans, and for humans only.
	Because string
}

// AcceptedSelectors returns every build constraint this configuration accepts,
// derived from the configurations it runs.
//
// This is the *only* acceptance decision. Accepts consults it and nothing else,
// so there is no second route -- an earlier version accepted release tags down
// a separate code path, and the invariant tests, which enumerated this
// function, could not see decisions the other path made.
//
// Nothing may be added here that is not justified by a target in Targets() or
// by the toolchain itself. TestEveryAcceptedSelectorIsActuallySelected holds
// that line by compiling a file behind each one and checking a pass finds it.
func (c Config) AcceptedSelectors() []Selector {
	seen := map[string]Selector{}
	note := func(s Selector) {
		if _, ok := seen[s.Name]; !ok {
			seen[s.Name] = s
		}
	}
	byTarget := func(name string, t Target, because string) {
		note(Selector{Name: name, Kind: SelectedByTarget, Target: t, Because: because})
	}

	for _, t := range c.Targets() {
		byTarget(t.GOOS, t, "the closure runs "+t.String())
		byTarget(t.GOARCH, t, "the closure runs "+t.String())
		if unixGOOS[t.GOOS] {
			byTarget("unix", t, t.GOOS+" is a unix system and the closure runs "+t.String())
		}
		if t.Cgo {
			byTarget("cgo", t, "the closure runs "+t.String()+" with cgo enabled")
		}
		for _, tag := range t.Tags {
			byTarget(tag, t, "the closure runs "+t.String())
		}
	}
	// The gc toolchain is the one running the closure, so a file behind `gc` is
	// selected by every pass. gccgo is deliberately absent: no pass uses it, so
	// a file behind it would never be examined.
	note(Selector{Name: "gc", Kind: SelectedByToolchain, Because: "every pass runs under the gc toolchain"})
	// Release tags come from the toolchain, not from the module's go directive:
	// a Go 1.26 toolchain selects a //go:build go1.25 file in a module that
	// declares go 1.21. So the set is whatever the toolchain reports, which is
	// the fact that actually decides whether a pass reads the file.
	for _, tag := range c.ReleaseTags {
		note(Selector{Name: tag, Kind: SelectedByToolchain,
			Because: "the toolchain running the closure reports " + tag})
	}

	out := make([]Selector, 0, len(seen))
	for _, sel := range seen {
		out = append(out, sel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Accepts is the single acceptance decision, used by CheckBuildTags and
// enumerable by AcceptedSelectors. Every judgement about a build constraint
// goes through here.
func (c Config) Accepts(tag string) bool {
	for _, sel := range c.AcceptedSelectors() {
		if sel.Name == tag {
			return true
		}
	}
	return false
}

// CheckBuildTags reports every build constraint that no build configuration this
// checker compiles would select.
//
// This is no longer about hiding a dependency -- the union graph reads the file
// whatever its constraint says. It is about a file that *no configuration
// type-checks*: nothing compiles it, so nothing tells you it is broken, and the
// compatibility passes cannot vouch for it. That is true whether the constraint is
// something invented (`reviewbypass`), something real but uncovered (`freebsd`,
// `riscv64`, `race`), or something not yet possible (`go1.99`).
func (c Config) CheckBuildTags(files []FileImports) []Violation {
	var out []Violation
	for _, f := range files {
		for _, tag := range f.BuildTags {
			if c.Accepts(tag.Name) {
				continue
			}
			out = append(out, Violation{
				RuleName: buildTagRuleName,
				Package:  f.Package,
				Tag:      tag.Name,
				File:     f.File,
				Line:     tag.Line,
				Kind:     f.Kind,
				Reason:   c.explainRejection(tag.Name),
			})
		}
	}
	return dedupe(out)
}

// explainRejection says, in terms a contributor can act on, why nothing selects
// this tag. It decides nothing -- Accepts already did -- so there is no way for
// a message to become an acceptance route.
func (c Config) explainRejection(tag string) string {
	if goVersionTag.MatchString(tag) {
		return fmt.Sprintf(
			"the toolchain running this checker does not report %q, so no build it runs "+
				"selects a file behind that constraint. Release tags reported: %s.",
			tag, strings.Join(c.ReleaseTags, ", "))
	}
	return fmt.Sprintf(
		"no build configuration this checker compiles selects %q, so no pass type-checks a file "+
			"behind it. The union import graph still read it -- the boundary rules are enforced "+
			"regardless of constraints -- but nothing proves the file builds. Either remove the "+
			"constraint, or extend the compatibility matrix in internal/boundary (Config.GOOS, "+
			"Config.GOARCH, Config.CgoEnabled, Config.AllowedBuildTags) so a pass covers it. "+
			"Currently covered: %s.", tag, c.coverageSummary())
}

func (c Config) coverageSummary() string {
	var platform, release []string
	for _, sel := range c.AcceptedSelectors() {
		if goVersionTag.MatchString(sel.Name) {
			release = append(release, sel.Name)
			continue
		}
		platform = append(platform, sel.Name)
	}
	summary := strings.Join(platform, ", ")
	if len(release) > 0 {
		// The release tags are a contiguous run; naming the ends is enough.
		summary += fmt.Sprintf(", and %s through %s", release[0], release[len(release)-1])
	}
	return summary
}

// Target is one build configuration the dependency closure is evaluated in.
type Target struct {
	GOOS   string
	GOARCH string
	// Tags are custom build constraints to enable for this pass.
	Tags []string
	// Cgo runs the pass with CGO_ENABLED=1. Without one, files behind `cgo`
	// are never selected -- and so `cgo` is not an accepted constraint.
	Cgo bool
}

func (t Target) String() string {
	s := t.GOOS + "/" + t.GOARCH
	if t.Cgo {
		s += " +cgo"
	}
	if len(t.Tags) > 0 {
		s += " +" + strings.Join(t.Tags, ",")
	}
	return s
}

// Targets is the full set of build configurations the closure runs: the support
// matrix, crossed with the optional cgo and declared-tag dimensions.
//
// This is the same data AcceptedSelectors derives from. That is the whole
// design: coverage and acceptance cannot disagree because there is one list.
//
// Caveat worth stating rather than hiding: enabling all declared tags at once
// does not cover a constraint requiring one tag on and another off. With no
// declared tags that is vacuous; if this repository ever carries several
// interacting tags, this is the function to revisit.
func (c Config) Targets() []Target {
	var out []Target
	for _, goos := range c.GOOS {
		for _, goarch := range c.GOARCH {
			base := []Target{{GOOS: goos, GOARCH: goarch}}
			if c.CgoEnabled {
				base = append(base, Target{GOOS: goos, GOARCH: goarch, Cgo: true})
			}
			for _, t := range base {
				out = append(out, t)
				if len(c.AllowedBuildTags) > 0 {
					tagged := t
					tagged.Tags = c.AllowedBuildTags
					out = append(out, tagged)
				}
			}
		}
	}
	return out
}

// LoadError is a package the toolchain could not load.
//
// These used to be discarded. `go list -e` reports a broken package rather than
// failing, which is what lets the closure survive a package that does not build
// on a cross target -- but silently dropping the error meant a graph could be
// missing an entire subtree while the check reported that the rule held. A gate
// claiming to have verified something it did not verify is worse than no gate.
type LoadError struct {
	Package     string
	Pos         string
	Err         string
	ImportStack []string
}

func (e LoadError) String() string {
	s := e.Package
	if e.Pos != "" {
		s += " (" + e.Pos + ")"
	}
	return s + ": " + e.Err
}

// LoadErrors is a set of them, with a message that says why it is fatal.
type LoadErrors struct {
	Target Target
	Errors []LoadError
}

func (e *LoadErrors) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the dependency graph for %s is incomplete, so it was not checked:\n", e.Target)
	for _, le := range e.Errors {
		fmt.Fprintf(&b, "    %s\n", le)
	}
	b.WriteString("\nA package that cannot be loaded is a package whose dependencies are unknown.\n" +
		"Fix the load error rather than ignoring it: a boundary check over a partial\n" +
		"graph reports that the rule held when it has not been tested.")
	return b.String()
}
