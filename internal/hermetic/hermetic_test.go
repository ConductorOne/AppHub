// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package hermetic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) []Finding {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	got, err := CheckWorkflow(filepath.ToSlash(path), data)
	if err != nil {
		t.Fatalf("CheckWorkflow(%s): %v", name, err)
	}
	return got
}

func kinds(findings []Finding) map[Kind]int {
	out := map[Kind]int{}
	for _, f := range findings {
		out[f.Kind]++
	}
	return out
}

// The fixture that matters most: this exact workflow returned success from the
// previous grep-based checker. It holds both doors open at once -- a stored
// secret and OIDC write -- and both are merely quoted.
func TestReviewerBypassIsCaught(t *testing.T) {
	t.Parallel()
	got := load(t, "workflows/reviewer-bypass.yml")
	k := kinds(got)
	if k[KindIDTokenWrite] != 1 {
		t.Errorf("id-token: \"write\" must be caught despite the quotes; findings: %v", got)
	}
	if k[KindSecretsContext] != 1 {
		t.Errorf("secrets['AWS_KEY'] must be caught; findings: %v", got)
	}
	if k[KindCredentialValue] != 1 {
		t.Errorf("AWS_ACCESS_KEY_ID given a value must be caught; findings: %v", got)
	}
}

// A pattern would need one case per spelling. A parser needs none.
func TestEveryQuotingOfIDTokenWriteIsCaught(t *testing.T) {
	t.Parallel()
	got := load(t, "workflows/quoting-variants.yml")
	if n := kinds(got)[KindIDTokenWrite]; n != 4 {
		t.Fatalf("got %d id-token findings, want 4 (single-quoted, tagged, flow mapping, write-all): %v", n, got)
	}
}

func TestEverySpellingOfSecretsAccessIsCaught(t *testing.T) {
	t.Parallel()
	got := load(t, "workflows/secrets-spellings.yml")
	// dotted, bracketed, toJSON(secrets), a folded block scalar, and one inside
	// a step's run script.
	if n := kinds(got)[KindSecretsContext]; n != 5 {
		t.Fatalf("got %d secrets findings, want 5: %v", n, got)
	}
}

func TestAliasedPermissionsAreResolved(t *testing.T) {
	t.Parallel()
	got := load(t, "workflows/anchored.yml")
	// The anchor definition and the job that aliases it are both reported; the
	// point is that aliasing does not make the permission disappear.
	if n := kinds(got)[KindIDTokenWrite]; n < 1 {
		t.Fatalf("an aliased id-token: write must still be caught: %v", got)
	}
	var sawJob bool
	for _, f := range got {
		if strings.HasPrefix(f.Path, "jobs.aliased.") {
			sawJob = true
		}
	}
	if !sawJob {
		t.Errorf("the finding should point at the job that holds the permission: %v", got)
	}
}

func TestSecretsPassedToAReusableWorkflowIsCaught(t *testing.T) {
	t.Parallel()
	got := load(t, "workflows/reusable-caller.yml")
	if n := kinds(got)[KindSecretsInput]; n != 1 {
		t.Fatalf("`secrets: inherit` needs no expression and must still be caught: %v", got)
	}
}

// The gate has to stay usable, or it gets deleted. Blanking a credential
// variable is the technique the test job uses to prove it needs none, and a job
// may be named "secrets" without that being secret-passing.
func TestCleanWorkflowPasses(t *testing.T) {
	t.Parallel()
	if got := load(t, "clean/ok.yml"); len(got) != 0 {
		t.Fatalf("clean workflow should produce no findings, got %v", got)
	}
}

func TestBlankedCredentialIsAllowedButAnyValueIsNot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, value string
		want        int
	}{
		{"empty double-quoted", `""`, 0},
		{"empty single-quoted", `''`, 0},
		{"absent value", ``, 0},
		{"a literal value", `not-empty`, 1},
		{"whitespace only", `"   "`, 0},
		{"a path", `/run/secrets/aws`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := "jobs:\n  a:\n    env:\n      AWS_SECRET_ACCESS_KEY: " + tc.value + "\n"
			got, err := CheckWorkflow("t.yml", []byte(doc))
			if err != nil {
				t.Fatalf("CheckWorkflow: %v", err)
			}
			if n := kinds(got)[KindCredentialValue]; n != tc.want {
				t.Errorf("got %d credential findings, want %d: %v", n, tc.want, got)
			}
		})
	}
}

func TestCheckDirFailsWhenItInspectsNothing(t *testing.T) {
	t.Parallel()
	// A check that finds no workflows and reports success is the most
	// dangerous kind of green.
	if _, _, err := CheckDir(filepath.Join("testdata", "empty")); err == nil {
		t.Fatal("CheckDir must fail when there are no workflows to inspect")
	}
}

func TestCheckDirReadsEveryWorkflow(t *testing.T) {
	t.Parallel()
	findings, files, err := CheckDir(filepath.Join("testdata", "workflows"))
	if err != nil {
		t.Fatalf("CheckDir: %v", err)
	}
	if len(files) != 5 {
		t.Errorf("read %d workflow files, want 5", len(files))
	}
	if len(findings) == 0 {
		t.Error("the fixture directory is full of violations; finding none means the walk is broken")
	}
}

func TestCheckDirAcceptsACleanDirectory(t *testing.T) {
	t.Parallel()
	findings, files, err := CheckDir(filepath.Join("testdata", "clean"))
	if err != nil {
		t.Fatalf("CheckDir: %v", err)
	}
	if len(files) != 1 || len(findings) != 0 {
		t.Errorf("got %d files and %d findings, want 1 and 0: %v", len(files), len(findings), findings)
	}
}

func TestMalformedWorkflowIsAnErrorNotAPass(t *testing.T) {
	t.Parallel()
	if _, err := CheckWorkflow("bad.yml", []byte("jobs:\n  - [unbalanced\n")); err == nil {
		t.Fatal("unparseable YAML must fail the check rather than be skipped")
	}
}
