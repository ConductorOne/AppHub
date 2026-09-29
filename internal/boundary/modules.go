// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// This file answers one question: given an import path, which directory on disk
// holds that package's source?
//
// The union graph is built by parsing files, so it needs directories rather than
// the toolchain's opinion about which packages are in a build. But it must not
// guess where those directories are. Module cache paths are escaped (an
// uppercase letter becomes `!x`), a `replace` can point anywhere, and a
// GOMODCACHE may be somewhere unexpected. So the layout comes from
// `go list -m -json all` -- Go's own reported Dir -- and everything else is a
// prefix match over that.

// Module is one module in the build list, with the directory Go says holds it.
type Module struct {
	// Path is the module path, which is also the prefix of the import paths it
	// provides.
	Path string
	// Version is the selected version, empty for the main module.
	Version string
	// Dir is the directory holding the module's source. Empty means the module
	// is in the build list but not present locally, which is fatal only if an
	// import actually resolves into it.
	Dir string
	// Main is true for the module being checked.
	Main bool
	// Err is what the toolchain said when it could not provide the module.
	Err string
}

// String renders the module for a diagnostic.
func (m Module) String() string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}

// ModuleSet is the build list: every module that could supply an import,
// indexed for longest-prefix resolution.
//
// Its fields are unexported and it is only produced by LoadModules, so a caller
// cannot invent a module directory. That matters because the whole union graph
// is read from the directories this type reports.
type ModuleSet struct {
	// byLength is every module, longest path first, so resolution picks
	// example.com/a/b over example.com/a.
	byLength []Module
	main     Module
	// root is the directory the checker was pointed at, for rendering paths
	// relative to something a reader recognises.
	root string
}

// LoadModules asks the toolchain for the build list of the module rooted at dir.
//
// It runs offline and read-only: the module cache is populated by the explicit
// `go mod download` step before the check, and a check that reaches for the
// network mid-run is a check whose answer depends on the network.
//
// `-e` is deliberate. `go list -m all` walks the whole module graph, which
// includes modules needed only to build some dependency's *tests* -- and
// `go mod download` does not fetch those, so without `-e` the command fails on a
// module no production import can ever reach. With `-e` such a module is
// reported with an error and no directory, and resolving an import into it is
// fatal at that point (see Resolve). Nothing is silently skipped; the failure
// just happens when it means something.
func LoadModules(dir string) (*ModuleSet, error) {
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := rejectVendorTree(absRoot); err != nil {
		return nil, err
	}
	if err := rejectWorkspace(absRoot); err != nil {
		return nil, err
	}

	// Fixed argv; nothing here comes from user input.
	cmd := exec.Command("go", "list", "-m", "-e", "-json", "all")
	cmd.Dir = absRoot
	cmd.Env = append(os.Environ(),
		"GOPROXY=off",
		"GOFLAGS=-mod=readonly",
		"GOWORK=off",
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m -e -json all in %s: %w: %s",
			absRoot, err, strings.TrimSpace(stderr.String()))
	}

	set := &ModuleSet{root: absRoot}
	dec := json.NewDecoder(strings.NewReader(string(stdout)))
	for {
		var raw struct {
			Path    string
			Version string
			Dir     string
			Main    bool
			Error   *struct{ Err string }
			Replace *struct {
				Path    string
				Version string
				Dir     string
			}
		}
		if decErr := dec.Decode(&raw); decErr != nil {
			if errors.Is(decErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parsing go list -m output: %w", decErr)
		}
		mod := Module{Path: raw.Path, Version: raw.Version, Dir: raw.Dir, Main: raw.Main}
		if raw.Error != nil {
			mod.Err = raw.Error.Err
		}
		// A replaced module is read from the replacement's directory. The
		// toolchain reports that in Dir, and also in Replace.Dir; take whichever
		// is populated rather than depending on which.
		if mod.Dir == "" && raw.Replace != nil {
			mod.Dir = raw.Replace.Dir
		}
		if mod.Main {
			set.main = mod
		}
		set.byLength = append(set.byLength, mod)
	}

	if set.main.Path == "" {
		return nil, fmt.Errorf("go list -m reported no main module in %s, so there is "+
			"nothing to judge; is this a module root?", absRoot)
	}
	if set.main.Err != "" {
		return nil, fmt.Errorf("the main module %s could not be loaded: %s", set.main.Path, set.main.Err)
	}
	if set.main.Dir == "" {
		return nil, fmt.Errorf("the toolchain reported no directory for the main module %s", set.main.Path)
	}
	sort.SliceStable(set.byLength, func(i, j int) bool {
		return len(set.byLength[i].Path) > len(set.byLength[j].Path)
	})
	return set, nil
}

// rejectVendorTree fails when the module root has a vendor directory.
//
// This is a policy this repository already holds (docs/decisions/), stated as
// a failure rather than as a skipped directory, because "the scanner ignores
// vendor/" plus "a vendor tree exists" is a bypass: the vendored copy is what
// gets compiled and the scanner reads the module cache instead. `-mod=readonly`
// makes the divergence worse rather than better -- the toolchain this checker
// runs would read the cache while an ordinary `go build` in the same tree reads
// vendor/.
//
// Adopting vendoring therefore means giving this checker a vendor mode that
// scans the tree as the dependency source of truth. Until that exists, the tree
// is refused.
func rejectVendorTree(absRoot string) error {
	vendorDir := filepath.Join(absRoot, "vendor")
	info, err := os.Stat(vendorDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking for a vendor tree in %s: %w", absRoot, err)
	}
	if !info.IsDir() {
		return nil
	}
	return fmt.Errorf("%s exists, and this checker has no vendoring mode.\n\n"+
		"With a vendor tree present, `go build` compiles the vendored copy of every\n"+
		"dependency while this checker resolves modules through the module cache, so the\n"+
		"graph it proves things about is not the graph that gets built. A forbidden\n"+
		"import added to a vendored file would be invisible to it.\n\n"+
		"Either remove the vendor tree (see docs/decisions/, which records that this\n"+
		"repository does not vendor), or extend internal/boundary with a vendor mode that\n"+
		"treats vendor/ as the dependency source of truth", vendorDir)
}

// rejectWorkspace fails when a go.work file would be in effect for this directory.
//
// This is the vendor-tree argument in a second costume, and it is invisible to
// the differential because both loaders set GOWORK=off and therefore agree with
// each other while disagreeing with what an ordinary `go build` here would do. A
// workspace redirects module resolution wholesale: the union would judge the
// module versions go.mod selects while the build compiled whatever the workspace
// pointed at. Rather than prove a property about a tree nobody builds, refuse.
//
// The question is put to the toolchain rather than answered by looking for a
// file, because a workspace may sit in a parent directory or be named by GOWORK,
// and the toolchain is the authority on which one a build would use. go.work is
// gitignored in this repository, so this cannot fire in CI; it fires for someone
// running the check inside a local workspace, where the answer would have been
// misleading.
func rejectWorkspace(absRoot string) error {
	cmd := exec.Command("go", "env", "GOWORK")
	cmd.Dir = absRoot
	// Deliberately NOT GOWORK=off: the question is what a normal build would use.
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("asking the toolchain whether a workspace is in effect in %s: %w", absRoot, err)
	}
	work := strings.TrimSpace(string(out))
	if work == "" || work == "off" {
		return nil
	}
	return fmt.Errorf("a Go workspace is in effect (%s), and this checker has no workspace mode.\n\n"+
		"A workspace redirects module resolution, so the dependency directories a build here\n"+
		"would compile are not the ones go.mod selects -- and this check would prove a property\n"+
		"about a tree nobody builds. Run it outside the workspace, or set GOWORK=off for a\n"+
		"build you want it to describe", work)
}

// Main returns the module being judged.
func (s *ModuleSet) Main() Module { return s.main }

// Root returns the directory the checker was pointed at.
func (s *ModuleSet) Root() string { return s.root }

// Modules returns the build list, longest module path first.
func (s *ModuleSet) Modules() []Module {
	return append([]Module(nil), s.byLength...)
}

// UnresolvedImportError is an import no module in the build list can supply, or
// one whose module is not on disk.
//
// It is fatal on purpose. An import the checker cannot follow is a subgraph the
// checker did not examine, and a fence that reports success over an unexamined
// subgraph is the defect this whole package exists to avoid. It carries the
// declaring file and line so the failure is actionable rather than mysterious.
type UnresolvedImportError struct {
	// Import is the path that could not be resolved.
	Import string
	// From is the package that declared it.
	From string
	// File and Line locate the import declaration.
	File string
	Line int
	// Reason says what went wrong.
	Reason string
}

func (e *UnresolvedImportError) Error() string {
	return fmt.Sprintf("%s:%d: %s imports %s, which cannot be resolved: %s\n\n"+
		"An import the union graph cannot follow is a dependency subtree it did not\n"+
		"examine, so the check fails rather than reporting that the rules held over a\n"+
		"graph with a hole in it. If the module is simply not downloaded, run\n"+
		"`go mod download` (which `make boundary` does) before the check.",
		e.File, e.Line, e.From, e.Import, e.Reason)
}

// Resolve maps an import path to the directory holding its source, by longest
// matching module path.
//
// The returned error is always an *UnresolvedImportError describing why, with
// the position filled in by the caller that had it.
func (s *ModuleSet) Resolve(importPath string) (Module, string, error) {
	for _, mod := range s.byLength {
		if !hasPathPrefix(importPath, mod.Path) {
			continue
		}
		if mod.Dir == "" {
			reason := fmt.Sprintf("module %s is in the build list but is not present on disk", mod)
			if mod.Err != "" {
				reason += ": " + mod.Err
			}
			return mod, "", &UnresolvedImportError{Import: importPath, Reason: reason}
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(importPath, mod.Path), "/")
		dir := mod.Dir
		if rel != "" {
			dir = filepath.Join(mod.Dir, filepath.FromSlash(rel))
		}
		// A directory below a module root that has its own go.mod belongs to a
		// different module, and this import path does not name it. Treating it
		// as part of the enclosing module would read files no build of this
		// module compiles -- and, worse, could make an unresolvable import look
		// resolvable.
		nested, nestedErr := nestedModuleBetween(mod.Dir, dir)
		if nestedErr != nil {
			return mod, "", &UnresolvedImportError{Import: importPath, Reason: nestedErr.Error()}
		}
		if nested != "" {
			return mod, "", &UnresolvedImportError{
				Import: importPath,
				Reason: fmt.Sprintf("the directory it would name lies inside the nested module at %s, "+
					"which module %s does not provide", nested, mod),
			}
		}
		info, statErr := os.Stat(dir)
		if statErr != nil || !info.IsDir() {
			return mod, "", &UnresolvedImportError{
				Import: importPath,
				Reason: fmt.Sprintf("module %s provides no directory %s", mod, dir),
			}
		}
		return mod, dir, nil
	}
	return Module{}, "", &UnresolvedImportError{
		Import: importPath,
		Reason: "no module in the build list provides it; if it is a new dependency, " +
			"add it to go.mod",
	}
}

// nestedModuleBetween reports the first go.mod strictly below modDir on the path
// down to dir, inclusive of dir.
func nestedModuleBetween(modDir, dir string) (string, error) {
	if modDir == dir {
		return "", nil
	}
	rel, err := filepath.Rel(modDir, dir)
	if err != nil {
		return "", fmt.Errorf("locating %s inside %s: %w", dir, modDir, err)
	}
	cur := modDir
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		if _, statErr := os.Stat(filepath.Join(cur, "go.mod")); statErr == nil {
			return cur, nil
		}
	}
	return "", nil
}

// canonicalDir resolves a directory to the identity used for provenance: an
// absolute path with every symlink expanded.
//
// Provenance has to be judged on the resolved path and never on a declared
// module path. Review demonstrated why: a temporary module that *declares* the
// same module path as this repository produced a real, sealed dependency graph
// that a Coverage for the real tree accepted, because the two agreed on
// everything a name can carry. Two directories are the same tree only if they
// are the same directory.
func canonicalDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", dir, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// A directory that cannot be resolved cannot be vouched for.
		return "", fmt.Errorf("resolving %s: %w", abs, err)
	}
	return resolved, nil
}

// displayPath renders an absolute file path the way a reader can act on it:
// relative to the repository for first-party files, and module-qualified for a
// dependency, because "/home/somebody/go/pkg/mod/..." is noise.
func (s *ModuleSet) displayPath(mod Module, absFile string) string {
	if rel, err := filepath.Rel(s.root, absFile); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	if mod.Dir != "" {
		if rel, err := filepath.Rel(mod.Dir, absFile); err == nil && !strings.HasPrefix(rel, "..") {
			return mod.String() + "/" + filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(absFile)
}

// CgoPseudoPackage is the import path cgo files use. It is not a package at
// all and nothing can parse it, so every view of the tree treats it as a leaf.
const CgoPseudoPackage = "C"

// StandardPackages asks the toolchain which packages the standard library
// contains, in dir.
//
// # Why this is asked rather than inferred
//
// It used to be inferred, from the go command's rule that a module path's first
// element contains a dot and a standard-library path's does not. That inference
// was sound for a DENYLIST and unsound the moment an allowlist arrived, and the
// difference is the whole reason this function exists.
//
// Under a denylist, calling something standard by mistake cannot hide a
// violation: every denied prefix is a module path with a dot, so a path the
// heuristic calls standard is not beneath one anyway. Under an allowlist the
// implication runs the other way -- "standard" means PERMITTED -- so a
// misclassification is a bypass.
//
// And the heuristic really is wrong, which review demonstrated rather than
// argued: a module reached through a `replace` directive may declare any path
// it likes, including one with no dot. A local module named `cloud` providing
// `cloud/sdk/azidentity` compiles, is a perfectly ordinary Go module, and was
// waved through the import allowlist as standard library.
//
// So the set comes from `go list std`, which is the toolchain's own answer, and
// is exhaustive by construction rather than by pattern. An empty result is an
// error: a permission set that permits nothing would make the allowlist deny
// the standard library, and a derivation that returns nothing satisfies every
// property stated over it.
// # The standard library is a different set on every platform
//
// `go list std` answers for one GOOS/GOARCH. It omits crypto/x509/internal/macos
// on Linux and internal/routebsd on Windows, and a set missing those is not a
// superset of what a darwin build imports -- which the union graph's own
// differential invariant caught within a minute of the first version of this
// function, by comparing a real darwin graph against a union built from a Linux
// answer.
//
// So the set is the UNION over the supported matrix. Over-approximating is the
// safe direction here and is not a widening of the allowlist: a package that is
// standard on any supported platform is in the Go distribution, and no module
// in a build list is allowed to shadow one.
func StandardPackages(dir string, goos, goarch []string) (map[string]bool, error) {
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", dir, err)
	}
	// Memoised for the process, because the answer is a property of the
	// toolchain and this is six subprocesses per call: without it, a test suite
	// that loads a union per case spends minutes asking the same question. The
	// key includes the directory and the matrix so a different question gets a
	// different answer, and a returned map is copied so a caller cannot mutate
	// the cached one out from under the next.
	key := absRoot + "\x00" + strings.Join(goos, ",") + "\x00" + strings.Join(goarch, ",")
	stdCacheMu.Lock()
	cached, hit := stdCache[key]
	stdCacheMu.Unlock()
	if hit {
		return maps.Clone(cached), nil
	}
	if len(goos) == 0 || len(goarch) == 0 {
		return nil, fmt.Errorf("no platforms given: the standard library differs between them, "+
			"so a set derived from none of them is not a superset of any (goos=%v goarch=%v)",
			goos, goarch)
	}
	out := map[string]bool{
		// Not reported by `go list std`, and not a package: cgo files import it
		// and nothing can parse it.
		CgoPseudoPackage: true,
	}
	for _, goosName := range goos {
		for _, arch := range goarch {
			// Fixed argv; nothing here comes from user input. Same hermetic
			// environment as every other go invocation in this package, so the
			// answer describes the same build the rest of the check describes.
			cmd := exec.Command("go", "list", "std")
			cmd.Dir = absRoot
			cmd.Env = append(os.Environ(),
				"GOPROXY=off",
				"GOFLAGS=-mod=readonly",
				"GOWORK=off",
				"CGO_ENABLED=0",
				"GOOS="+goosName,
				"GOARCH="+arch,
			)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			stdout, cmdErr := cmd.Output()
			if cmdErr != nil {
				return nil, fmt.Errorf("go list std for %s/%s in %s: %w: %s",
					goosName, arch, absRoot, cmdErr, strings.TrimSpace(stderr.String()))
			}
			var found int
			for _, line := range strings.Split(string(stdout), "\n") {
				if p := strings.TrimSpace(line); p != "" {
					out[p] = true
					found++
				}
			}
			// Per platform, not only in total: one configuration returning
			// nothing while the others return hundreds would leave the union
			// looking healthy and missing exactly that platform's packages.
			if found == 0 {
				return nil, fmt.Errorf("go list std for %s/%s in %s reported no packages",
					goosName, arch, absRoot)
			}
		}
	}
	stdCacheMu.Lock()
	stdCache[key] = out
	stdCacheMu.Unlock()
	return maps.Clone(out), nil
}

var (
	stdCacheMu sync.Mutex
	stdCache   = map[string]map[string]bool{}
)
