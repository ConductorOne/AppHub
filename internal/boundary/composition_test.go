// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package boundary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompositionRootsOnlyWireDirectExistingBoundaries(t *testing.T) {
	const module = "example.com/composition"
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                      "module " + module + "\n\ngo 1.23\n",
		"sdk/sdk.go":                  "package sdk\n",
		"provider/provider.go":        "package provider\nimport _ \"" + module + "/sdk\"\n",
		"cmd/server/main.go":          "package main\nimport _ \"" + module + "/provider\"\nfunc main(){}\n",
		"cmd/server/direct/direct.go": "package direct\nimport _ \"" + module + "/sdk\"\n",
		"cmd/wrapped/main.go":         "package main\nimport _ \"" + module + "/wrapper\"\nfunc main(){}\n",
		"wrapper/wrapper.go":          "package wrapper\nimport _ \"" + module + "/provider\"\n",
		"integration/fixture_test.go": "package integration_test\nimport _ \"" + module + "/provider\"\n",
		"production/fixture.go":       "package production\nimport _ \"" + module + "/provider\"\n",
	}
	for name, source := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := unionConfig(module, module+"/sdk", module+"/provider")
	cfg.Rules[0].CompositionRoots = map[string]ImportKind{module + "/cmd/server": KindBuild, module + "/cmd/wrapped": KindBuild, module + "/integration": KindTest, module + "/production": KindTest}
	union, err := LoadUnion(root)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := union.Judge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{module + "/cmd/server/direct": true, module + "/cmd/wrapped": true, module + "/wrapper": true, module + "/production": true}
	for _, v := range findings.Violations() {
		if !expected[v.Package] || v.Import != module+"/sdk" {
			t.Fatalf("unexpected boundary finding: %+v", v)
		}
		delete(expected, v.Package)
	}
	if len(expected) != 0 {
		t.Fatalf("composition permission hid unsafe dependencies: %v", expected)
	}
	// Direct SDK imports remain forbidden even at the exact executable root.
	if err := os.WriteFile(filepath.Join(root, "cmd/server/sdk.go"), []byte("package main\nimport _ \""+module+"/sdk\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	scanned, err := ScanFiles(root, module)
	if err != nil {
		t.Fatal(err)
	}
	foundDirect := false
	for _, v := range cfg.CheckFiles(scanned) {
		if v.Package == module+"/cmd/server" && v.Import == module+"/sdk" {
			foundDirect = true
		}
	}
	if !foundDirect {
		t.Fatal("composition root bypassed direct SDK import fence")
	}
	nodes := []Node{{ImportPath: module + "/cmd/server", Imports: []string{module + "/provider", module + "/sdk"}}, {ImportPath: module + "/provider", Imports: []string{module + "/sdk"}}, {ImportPath: module + "/sdk"}}
	graph := cfg.CheckGraph(nodes, "linux")
	if len(graph) != 1 || graph[0].Package != module+"/cmd/server" || len(graph[0].Via) != 0 {
		t.Fatalf("concrete graph lost direct dependency: %+v", graph)
	}
	union, err = LoadUnion(root)
	if err != nil {
		t.Fatal(err)
	}
	findings, err = union.Judge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	foundDirect = false
	for _, v := range findings.Violations() {
		if v.Package == module+"/cmd/server" && len(v.Via) == 0 {
			foundDirect = true
		}
	}
	if !foundDirect {
		t.Fatal("union traversal bypassed a direct SDK import")
	}
}

func TestCompositionRootSyntheticTestMainIsNotAProviderWrapper(t *testing.T) {
	const root = "example.com/composition/cmd/server"
	const provider = "example.com/composition/provider"
	const sdk = "example.com/composition/sdk"
	variant := root + " [" + root + ".test]"
	cfg := unionConfig("example.com/composition", sdk, provider)
	cfg.Rules[0].CompositionRoots = map[string]ImportKind{root: KindBuild}
	nodes := []Node{
		{ImportPath: root + ".test", Imports: []string{variant}},
		{ImportPath: variant, ForTest: root, Imports: []string{provider}},
		{ImportPath: provider, Imports: []string{sdk}},
		{ImportPath: sdk},
	}
	if violations := cfg.CheckGraph(nodes, "linux"); len(violations) != 0 {
		t.Fatalf("generated test-main changed the source import boundary: %+v", violations)
	}
	nodes[1].Imports = append(nodes[1].Imports, sdk)
	if violations := cfg.CheckGraph(nodes, "linux"); len(violations) != 1 || violations[0].Package != root {
		t.Fatalf("test variant concealed direct SDK import: %+v", violations)
	}
}
