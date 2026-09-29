// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"testing"
	"testing/fstest"
)

func TestPlantedDisclosuresAreCaught(t *testing.T) {
	acct := "1234" + "5678" + "9012"
	privateNameDash := "union" + "-" + "station"
	privateNameUnderscore := "union" + "_" + "station"
	buildPath := "/" + "data/" + "squire/" + "src/source"
	privateRepo := "github.com/" + "ductone/" + "apphub/internal"
	privateSquire := "https" + "://ops." + "squi" + "re.internal/tasks/1"
	privateHostURL := "https" + "://db.service." + "corp/health"
	arn := fmt.Sprintf("arn:aws:iam::%s:role/Example", acct)

	fsys := fstest.MapFS{
		"docs/a.md":                             &fstest.MapFile{Data: []byte(privateNameDash + "\n" + buildPath + "\n" + privateRepo + "\n")},
		"docs/b.md":                             &fstest.MapFile{Data: []byte(privateSquire + "\n" + privateHostURL + "\n" + acct + "\n" + arn + "\n")},
		"docs/" + privateNameUnderscore + ".md": &fstest.MapFile{Data: []byte("path names are publication too\n")},
	}
	findings, cov, err := scan(fsys, ".", nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if cov.paths != 3 || cov.files != 3 {
		t.Fatalf("coverage = %+v, want three paths and three files", cov)
	}
	got := map[string]int{}
	for _, f := range findings {
		got[f.rule]++
	}
	for _, id := range []string{
		"private-source-system-name",
		"build-host-absolute-path",
		"private-ductone-repository-url",
		"private-squire-url",
		"aws-account-id",
		"aws-account-arn",
		"internal-host-url",
	} {
		if got[id] == 0 {
			t.Fatalf("%s was not reported; findings were %#v", id, findings)
		}
	}
}

func TestCleanPublicShapesPass(t *testing.T) {
	fsys := fstest.MapFS{
		"go.mod":          &fstest.MapFile{Data: []byte("module github.com/conductorone/apphub\n")},
		"README.md":       &fstest.MapFile{Data: []byte("See https://docs.github.com/ and https://github.com/conductorone/apphub.\n")},
		"docs/example.md": &fstest.MapFile{Data: []byte("Use https://tenant.example.invalid in fixtures and source system @ backend/file.go in citations.\n")},
	}
	findings, cov, err := scan(fsys, ".", nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean tree produced findings: %#v", findings)
	}
	if cov.lines != 3 {
		t.Fatalf("lines scanned = %d, want 3", cov.lines)
	}
}

func TestEmptyTreeFailsClosed(t *testing.T) {
	_, _, err := scan(fstest.MapFS{}, ".", nil)
	if err == nil {
		t.Fatal("empty tree passed; a gate over nothing is not a gate")
	}
}

func TestUnpublishableFilesAreSkipped(t *testing.T) {
	acct := "1234" + "5678" + "9012"
	fsys := fstest.MapFS{
		"README.md":                 &fstest.MapFile{Data: []byte("public\n")},
		"terraform/local.tfvars":    &fstest.MapFile{Data: []byte(acct + "\n")},
		"frontend/dist/bundle.js":   &fstest.MapFile{Data: []byte(acct + "\n")},
		"docs/committed-example.md": &fstest.MapFile{Data: []byte(acct + "\n")},
	}
	publishable := func(rel string) bool { return rel == "README.md" || rel == "docs/committed-example.md" }
	findings, cov, err := scan(fsys, ".", publishable)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if cov.paths != 2 {
		t.Fatalf("paths scanned = %d, want 2", cov.paths)
	}
	if len(findings) != 1 || findings[0].file != "docs/committed-example.md" {
		t.Fatalf("findings = %#v, want one in the publishable file", findings)
	}
}

func TestNothingPublishableFailsClosed(t *testing.T) {
	fsys := fstest.MapFS{"ignored.txt": &fstest.MapFile{Data: []byte("x\n")}}
	if _, _, err := scan(fsys, ".", func(string) bool { return false }); err == nil {
		t.Fatal("a scan that inspected nothing passed")
	}
}

func TestDocumentedExampleAccountIsAllowedOnlyWhereGitleaksAllowsIt(t *testing.T) {
	example := "1234" + "5678" + "9012"
	fsys := fstest.MapFS{
		"store/cmd/devseed/application.go": &fstest.MapFile{Data: []byte(example + "\n")},
		".gitleaks.toml":                   &fstest.MapFile{Data: []byte(example + "\n")},
		"store/other.go":                   &fstest.MapFile{Data: []byte(example + "\n")},
		"store/cmd/devseed/extra.go":       &fstest.MapFile{Data: []byte("2109" + "8765" + "4321" + "\n")},
	}
	findings, _, err := scan(fsys, ".", nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.file] = true
	}
	if len(findings) != 2 || !got["store/other.go"] || !got["store/cmd/devseed/extra.go"] {
		t.Fatalf("findings = %#v, want exactly store/other.go and store/cmd/devseed/extra.go", findings)
	}
}
