// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// DefaultGOOS and DefaultGOARCH are this repository's compatibility matrix.
//
// These are the configurations the tree is compiled against, and the definition
// of which build constraints a file may carry (see Config.AcceptedSelectors).
// They are *not* what proves the import boundary: no finite set of
// configurations could, which is why the proof is the union graph in union.go.
// Narrowing this list weakens the compatibility checks and leaves the proof
// untouched.
//
// One configuration would not even be enough for compatibility: `go list`
// reports only the files the current build context selects, so a `*_windows.go`
// is invisible to a Linux run and an arm64-only file to every amd64 run -- which
// is how review got past two earlier versions of this check. arm64 is Graviton
// and Apple Silicon, so leaving it out was not a corner case.
var (
	DefaultGOOS   = []string{"linux", "darwin", "windows"}
	DefaultGOARCH = []string{"amd64", "arm64"}
)

// DefaultReleaseTags reports the go1.N build constraints the toolchain that
// built this binary satisfies.
//
// It is the fallback for callers that cannot run `go`; ToolchainReleaseTags
// asks the toolchain that will actually run the closure, and a test asserts the
// two agree. Either way the answer comes from a toolchain rather than from a
// list somebody maintains.
func DefaultReleaseTags() []string {
	return releaseTagsUpTo(runtime.Version())
}

// ToolchainReleaseTags asks the `go` binary that will run the closure which
// release tags its build context supplies.
//
// This is the fact that decides whether a `//go:build go1.N` file is compiled,
// which is the only thing the boundary check cares about.
func ToolchainReleaseTags(dir string) ([]string, error) {
	cmd := exec.Command("go", "list", "-f", "{{join context.ReleaseTags \"\\n\"}}", "--", "runtime")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("asking the toolchain for its release tags: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var tags []string
	for _, line := range strings.Split(string(out), "\n") {
		if tag := strings.TrimSpace(line); tag != "" {
			tags = append(tags, tag)
		}
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("the toolchain reported no release tags")
	}
	return tags, nil
}

// releaseTagsUpTo expands a version string such as "go1.26.5" into go1.1 ..
// go1.26, which is what the toolchain reports.
func releaseTagsUpTo(version string) []string {
	m := regexp.MustCompile(`^go1\.(\d+)`).FindStringSubmatch(version)
	if m == nil {
		return nil
	}
	minor, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}
	tags := make([]string, 0, minor)
	for i := 1; i <= minor; i++ {
		tags = append(tags, "go1."+strconv.Itoa(i))
	}
	return tags
}

// Graph is one build configuration's dependency graph, as the toolchain
// reported it.
//
// It exists so that evidence about a build configuration cannot be minted by a
// caller, and it took two rounds to get that right.
//
// The first round: Coverage took a target and a package count as *arguments*, so
// a caller could record a completion for a graph that was never loaded. Sealing
// the graph fixed that -- a Graph can only come out of a loader, its fields are
// unexported, and the zero value carries sealed=false.
//
// The second round, which review found: sealing proved a graph had been *loaded*,
// not that it had been loaded *from here*. A temporary module declaring the same
// module path yielded a real sealed graph with an empty edge set, and a Coverage
// for the real checkout accepted it -- so success was granted over a tree that had
// nothing to do with the one being judged. Hence root: the canonical directory the
// graph was loaded from, stamped by the loader and checked by every evidence type.
// And hence the only exported loader is [Union.LoadGraph], which loads from the
// union's own module root, so a graph from anywhere else cannot be obtained
// without first loading a union of that other tree.
type Graph struct {
	sealed bool
	// root is the canonical (absolute, symlinks resolved) main-module directory
	// this graph was loaded from. Provenance is judged on this and never on a
	// declared module path, because the declared path is exactly what the attack
	// made match.
	root   string
	target Target
	nodes  []Node
}

// Target reports which build configuration produced this graph.
func (g *Graph) Target() Target { return g.target }

// Root reports the canonical module directory this graph was loaded from.
func (g *Graph) Root() string {
	if g == nil {
		return ""
	}
	return g.root
}

// Nodes returns the packages in the graph.
func (g *Graph) Nodes() []Node {
	if g == nil {
		return nil
	}
	return append([]Node(nil), g.nodes...)
}

// Packages reports how many packages the graph contains.
func (g *Graph) Packages() int {
	if g == nil {
		return 0
	}
	return len(g.nodes)
}

// LoadGraph asks the Go toolchain to describe every package in this union's
// module and everything it depends on, including test dependencies, for one
// build target.
//
// It is a method rather than a function taking a directory, and that is the
// point: there is no exported way to load a dependency graph for some *other*
// directory, so a graph whose provenance does not match the tree being judged
// cannot be handed to the evidence types. Obtaining one would mean loading a
// union of that other tree first -- at which point its coverage judges that tree,
// consistently.
//
// This is a compatibility check rather than the boundary proof -- see the package
// comment and union.go.
func (u *Union) LoadGraph(target Target) (*Graph, error) {
	if u == nil || !u.sealed {
		return nil, fmt.Errorf("the union graph was not loaded; call LoadUnion")
	}
	return loadGraph(u.root, target)
}

// loadGraph runs `go list` in root and returns a graph stamped with it.
//
// It shells out rather than importing golang.org/x/tools/go/packages, which would
// put a dependency in go.mod purely to police go.mod. `go list` is already
// installed wherever this can run.
//
// A load error is returned as *LoadErrors and must not be ignored: `go list -e`
// keeps going past a package it cannot resolve, and the resulting graph is
// missing whatever that package depended on.
func loadGraph(root string, target Target) (*Graph, error) {
	dir := root
	// -deps gives the transitive closure, which is the whole point: the direct
	// imports of this module's packages are exactly what missed a forbidden
	// dependency arriving through a third-party wrapper.
	// -test adds the test variants, so a test-only dependency is not a blind spot.
	// -e reports a package that does not load instead of aborting the whole
	// run; the errors are collected below and are fatal, but collecting all of
	// them beats stopping at the first.
	args := []string{"list", "-e", "-deps", "-test", "-json"}
	if len(target.Tags) > 0 {
		args = append(args, "-tags", strings.Join(target.Tags, ","))
	}
	args = append(args, "./...")

	// Fixed argv[0]; every element of args comes from this repository's own
	// configuration, not from anything a caller supplies.
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cgo := "0"
	if target.Cgo {
		cgo = "1"
	}
	cmd.Env = append(os.Environ(),
		"GOOS="+target.GOOS,
		"GOARCH="+target.GOARCH,
		// Explicit, because the default differs between a host build and a
		// cross build -- and whether `cgo` is an acceptable build constraint
		// depends on whether some pass actually sets this.
		"CGO_ENABLED="+cgo,
		// Offline, and this time actually offline: -mod=mod still permitted an
		// HTTPS module lookup, which contradicted the comment that used to sit
		// here. The module cache is populated by `go mod download` before this
		// runs; if something is missing, `go list` reports a load error and the
		// caller fails rather than reaching for the network mid-check.
		"GOPROXY=off",
		"GOFLAGS=-mod=readonly",
		// A go.work anywhere above the fixture or the checkout would silently
		// change which modules are in scope.
		"GOWORK=off",
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s (%s): %w: %s", strings.Join(args, " "), target, err, strings.TrimSpace(stderr.String()))
	}

	// `go list -json` emits a stream of concatenated objects, not an array.
	dec := json.NewDecoder(strings.NewReader(string(stdout)))
	var nodes []Node
	var loadErrs []LoadError
	for {
		var raw struct {
			ImportPath string
			ForTest    string
			Imports    []string
			Error      *jsonPackageError
			DepsErrors []*jsonPackageError
		}
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		if raw.Error != nil && !benignLoadError(raw.Error.Err) {
			loadErrs = append(loadErrs, raw.Error.toLoadError(raw.ImportPath))
		}
		for _, de := range raw.DepsErrors {
			if benignLoadError(de.Err) {
				continue
			}
			loadErrs = append(loadErrs, de.toLoadError(raw.ImportPath))
		}
		// Test imports belong to the test variants `go list -test` emits
		// ("B [B.test]" and "B_test [B.test]"), which carry them already. They
		// are deliberately *not* folded into the base node: doing that made
		// every consumer of B inherit B's test dependencies, so a package that
		// merely imported B was reported for something only B's tests reach.
		// `go test ./...` compiles B's test files only when testing B, and B is
		// judged on its own account, so attributing them to B's variant is both
		// the accurate and the actionable answer. A package with no test files
		// reports no test imports either way, so nothing is lost.
		nodes = append(nodes, Node{
			ImportPath: raw.ImportPath,
			Imports:    append([]string(nil), raw.Imports...),
			ForTest:    raw.ForTest,
		})
	}
	if len(loadErrs) > 0 {
		return nil, &LoadErrors{Target: target, Errors: dedupeLoadErrors(loadErrs)}
	}
	if len(nodes) == 0 {
		// Better a loud failure than a check that silently passes because it
		// inspected nothing.
		return nil, fmt.Errorf("go list (%s) matched no packages in %s", target, dir)
	}
	return &Graph{sealed: true, root: root, target: target, nodes: nodes}, nil
}

// benignLoadError recognises the one failure that is not a gap in the graph.
//
// A package whose files are all excluded on this target contributes no
// dependencies to it, which is the correct answer rather than a missing one.
// Its files are still read by the file scan and its constraints still have to
// name a configuration some pass selects, so nothing hides behind it.
func benignLoadError(err string) bool {
	return strings.Contains(err, "build constraints exclude all Go files")
}

type jsonPackageError struct {
	ImportStack []string
	Pos         string
	Err         string
}

func (e *jsonPackageError) toLoadError(pkg string) LoadError {
	return LoadError{Package: pkg, Pos: e.Pos, Err: e.Err, ImportStack: e.ImportStack}
}

// dedupeLoadErrors collapses the same failure reported once against the broken
// package and again against everything that imports it.
func dedupeLoadErrors(in []LoadError) []LoadError {
	seen := map[string]bool{}
	var out []LoadError
	for _, e := range in {
		key := e.Pos + "|" + e.Err
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

// ScanFiles parses every Go file beneath root and reports its imports and build
// constraints, with the constraints recorded rather than obeyed.
//
// This is the half of the check that sees a `*_windows.go`, a
// `//go:build ignore`, or a file behind any custom tag. It is deliberately
// shallow -- it knows only what each file declares, not what those imports in
// turn reach -- and it is deliberately dumb about the build: it never asks
// whether a file would compile, because a file that does not compile here may
// compile perfectly well on somebody else's machine.
func ScanFiles(root, modulePath string) ([]FileImports, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// Which directories are packages is [PackageDirs] and nothing else. This
	// function used to walk the tree with its own copy of the rule; two copies of
	// a rule are two chances to be wrong about it, and both were taken.
	dirs, err := PackageDirs(absRoot)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	var out []FileImports
	for _, relDir := range dirs {
		absDir := filepath.Join(absRoot, filepath.FromSlash(relDir))
		entries, readErr := os.ReadDir(absDir)
		if readErr != nil {
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			abs := filepath.Join(absDir, entry.Name())
			// ImportsOnly stops at the import block, which is all this needs and
			// keeps a file with a syntax error further down from failing the scan.
			// ParseComments keeps the build constraints, which are comments.
			f, parseErr := parser.ParseFile(fset, abs, nil, parser.ImportsOnly|parser.ParseComments)
			if parseErr != nil {
				return nil, fmt.Errorf("parsing %s: %w", abs, parseErr)
			}
			rel := entry.Name()
			if relDir != "." {
				rel = relDir + "/" + entry.Name()
			}
			fi := FileImports{
				File:      rel,
				Package:   packagePath(modulePath, relDir),
				Kind:      fileKind(entry.Name(), f),
				BuildTags: buildTags(fset, f, entry.Name()),
			}
			for _, spec := range f.Imports {
				imported, unquoteErr := strconv.Unquote(spec.Path.Value)
				if unquoteErr != nil {
					continue
				}
				fi.Imports = append(fi.Imports, Import{
					Path: imported,
					Line: fset.Position(spec.Pos()).Line,
				})
			}
			// Every parsed file is recorded, including ones with no imports and
			// no constraints. The count is evidence that the scan actually ran.
			out = append(out, fi)
		}
	}
	return out, nil
}

// buildTags returns every identifier the file's build constraints name, from
// both comment forms and from the filename.
func buildTags(fset *token.FileSet, f *ast.File, name string) []BuildTag {
	var out []BuildTag
	seen := map[string]bool{}
	add := func(tag string, line int, implicit bool) {
		if tag == "" || seen[tag] {
			return
		}
		seen[tag] = true
		out = append(out, BuildTag{Name: tag, Line: line, Implicit: implicit})
	}

	for _, group := range f.Comments {
		// Constraints appear before the package clause; a //go:build-looking
		// line further down is an ordinary comment.
		if group.Pos() >= f.Package {
			break
		}
		for _, c := range group.List {
			if !constraint.IsGoBuild(c.Text) && !constraint.IsPlusBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				// An unparseable constraint is not a licence to skip the file;
				// name it so somebody fixes it.
				add("<unparseable build constraint>", fset.Position(c.Pos()).Line, false)
				continue
			}
			line := fset.Position(c.Pos()).Line
			for _, tag := range constraintTags(expr) {
				add(tag, line, false)
			}
		}
	}

	// A filename suffix is a constraint too: foo_windows_amd64.go. These are
	// always GOOS/GOARCH values, so they never fail the check, but recording
	// them keeps the file's real constraint set honest.
	base := strings.TrimSuffix(name, ".go")
	base = strings.TrimSuffix(base, "_test")
	if parts := strings.Split(base, "_"); len(parts) > 1 {
		for _, part := range parts[1:] {
			if platformFileSuffix[part] {
				add(part, 0, true)
			}
		}
	}
	return out
}

// constraintTags walks a parsed build expression and returns every tag it
// mentions.
//
// It walks rather than calling Expr.Eval with a collecting function: Eval short
// circuits, so `a || b` can return without ever asking about b, and a tag the
// enumeration never sees is a tag the check never rejects.
func constraintTags(expr constraint.Expr) []string {
	var out []string
	var walk func(constraint.Expr)
	walk = func(e constraint.Expr) {
		switch t := e.(type) {
		case *constraint.TagExpr:
			out = append(out, t.Tag)
		case *constraint.NotExpr:
			walk(t.X)
		case *constraint.AndExpr:
			walk(t.X)
			walk(t.Y)
		case *constraint.OrExpr:
			walk(t.X)
			walk(t.Y)
		}
	}
	walk(expr)
	return out
}

func fileKind(name string, f *ast.File) ImportKind {
	if !strings.HasSuffix(name, "_test.go") {
		return KindBuild
	}
	if f.Name != nil && strings.HasSuffix(f.Name.Name, "_test") {
		return KindExternalTest
	}
	return KindTest
}

// packagePath turns a directory relative to the module root into an import
// path. It is a string operation on purpose: asking the toolchain would
// reintroduce the build context this scan exists to ignore.
func packagePath(modulePath, relDir string) string {
	if relDir == "." || relDir == "" {
		return modulePath
	}
	return modulePath + "/" + relDir
}
