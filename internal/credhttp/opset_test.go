// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credhttp_test

import (
	"go/importer"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// TestTheOpSetIsExactlyWhatThePackageDeclares cross-checks the hand-written map in
// TestTheOpSetIsClosedAndRepositoryOwned against the set the type checker reports.
//
// It exists because that map is a restatement of a set, and a restatement of a set
// drifts from the set. This project has paid for that twice already: the
// go-command directory rules were restated and wrong in both directions, and the
// Granter port list was a hand-maintained map that a port carrying a Granter
// passed straight through.
//
// The set cannot be *driven* from a derivation -- a function name recovered from
// go/types is a string, and calling it needs a value -- so what is enforced instead
// is a bijection: every exported niladic function in this package returning an Op
// has an entry, and every entry names one. Adding an Op without adding an entry is
// then a failing test rather than an Op that nothing checks for a duplicate label.
func TestTheOpSetIsExactlyWhatThePackageDeclares(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	pkg, err := importer.ForCompiler(fset, "source", nil).
		Import("github.com/conductorone/apphub/internal/credhttp")
	if err != nil {
		t.Fatalf("type-check internal/credhttp: %v", err)
	}

	var declared []string
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		fn, ok := scope.Lookup(name).(*types.Func)
		if !ok || !fn.Exported() {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
			continue
		}
		named, ok := sig.Results().At(0).Type().(*types.Named)
		if !ok || named.Obj().Name() != "Op" || named.Obj().Pkg() != pkg {
			continue
		}
		declared = append(declared, name)
	}
	sort.Strings(declared)

	// A derivation that returns nothing passes every check made over it.
	if len(declared) == 0 {
		t.Fatal("no Op constructors were derived; the walk is not finding them")
	}

	restated := restatedOpNames()
	sort.Strings(restated)

	if strings.Join(declared, ",") != strings.Join(restated, ",") {
		missing, stale := diff(declared, restated), diff(restated, declared)
		if len(missing) > 0 {
			t.Errorf("these Op constructors exist and are not in TestTheOpSetIsClosedAndRepositoryOwned's map, "+
				"so nothing checks their labels for emptiness or collision: %v", missing)
		}
		if len(stale) > 0 {
			t.Errorf("these entries name no Op constructor in the package: %v", stale)
		}
	}
	t.Logf("%d Op constructor(s): %s", len(declared), strings.Join(declared, ", "))
}

// diff returns the members of a that are not in b.
func diff(a, b []string) []string {
	in := make(map[string]struct{}, len(b))
	for _, s := range b {
		in[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := in[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

// restatedOpNames is the keys of the map under test.
//
// It is a function rather than a shared variable so that the two tests stay
// independently readable, and it is here rather than there so that the file the
// USOSS-7 review is reading changes by four lines instead of forty.
func restatedOpNames() []string {
	return []string{
		"OpDatadogCreateAPIKey",
		"OpDatadogDeleteAPIKey",
		"OpDatadogStatusCheck",
		"OpGitHubAppMintInstallationToken",
		"OpGitHubAppListInstallations",
		"OpGitHubAppGetInstallation",
		"OpGitHubAppListInstallationRepositories",
		"OpGitHubAppManifestConversion",
		"OpC1FetchToken",
		"OpC1MintCredential",
		"OpC1RevokeCredential",
		"OpC1GetCredential",
		"OpC1DirectoryFetchToken",
		"OpC1DirectorySearchEntitlements",
		"OpC1DirectorySearchUsers",
		"OpC1DirectorySearchGrants",
	}
}
