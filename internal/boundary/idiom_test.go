// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"fmt"
	"go/ast"
	"go/parser"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The contract for a new gate is that it must fail on a fixture built to defeat
// it and pass on one that should be clean. Three of this repository's gates were
// defeated on the first PR by fixtures nobody had written, so each case below is
// an attempt on this check rather than a demonstration of it.

// leakFixtures are the ways DynamoDB idiom can reach business logic *without*
// importing the SDK -- which is exactly what makes them invisible to the import
// rule in boundary.go.
var leakFixtures = []struct {
	name    string
	needle  string
	content string
}{
	{
		name:   "struct tag with no SDK import",
		needle: "dynamodbav",
		// The whole file compiles with no AWS dependency at all, so the import
		// checker sees nothing wrong. The type is still a DynamoDB record.
		content: `package lifecycle

type Record struct {
	ID string ` + "`dynamodbav:\"ID\"`" + `
}
`,
	},
	{
		name:   "hand-written key condition in a plain string",
		needle: "begins_with",
		content: `package lifecycle

const listQuery = "PK = :pk AND begins_with(SK, :sk)"
`,
	},
	{
		name:   "conditional-write expression built as a string",
		needle: "attribute_not_exists",
		content: `package lifecycle

func guard() string { return "attribute_not_exists(PK)" }
`,
	},
	{
		name:   "request field name on a local type",
		needle: "FilterExpression",
		content: `package lifecycle

type query struct {
	FilterExpression string
	ExpressionAttributeValues map[string]string
}
`,
	},
	{
		name:   "pagination cursor threaded through business logic",
		needle: "LastEvaluatedKey",
		content: `package lifecycle

type page struct {
	LastEvaluatedKey map[string]string
}
`,
	},
	{
		name:   "single-table index key on an exported type",
		needle: "GSI1SK",
		content: `package lifecycle

type Record struct {
	GSI1PK string
	GSI1SK string
}
`,
	},
	{
		name:    "idiom inside a raw string literal",
		needle:  "attribute_exists",
		content: "package lifecycle\n\nconst q = `attribute_exists(PK) AND Revision = :rev`\n",
	},
}

func TestIdiomRuleCatchesLeaks(t *testing.T) {
	t.Parallel()
	rule := DefaultDynamoDBIdiomRule()

	for _, tc := range leakFixtures {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rule.Check([]SourceFile{{
				Path:    "credentials/lifecycle/record.go",
				Content: []byte(tc.content),
			}})
			if len(got) == 0 {
				t.Fatalf("no leak reported for %q; this fixture needs no SDK import, so "+
					"the import rule cannot catch it either", tc.needle)
			}
			var found bool
			for _, leak := range got {
				if leak.Needle == tc.needle {
					found = true
					if leak.Line == 0 {
						t.Error("leak has no line number; a violation you cannot navigate to is a bug report")
					}
					if leak.Reason == "" {
						t.Error("leak has no reason; the message has to explain the rule, not just cite it")
					}
				}
			}
			if !found {
				t.Errorf("leaks %v do not include the expected needle %q", got, tc.needle)
			}
		})
	}
}

// TestIdiomRuleIgnoresComments is the false-positive half. Documentation must be
// able to explain the fence: a check that fires on its own rationale gets
// suppressed within a week, and a suppressed check is worse than none.
func TestIdiomRuleIgnoresComments(t *testing.T) {
	t.Parallel()
	content := `package lifecycle

// Records is the persistence port. Implementations may use dynamodbav struct
// tags and expressions like "PK = :pk AND begins_with(SK, :sk)"; none of that
// appears here, and GSI1PK is not this package's business.
/*
   A block comment mentioning attribute_not_exists(PK) and LastEvaluatedKey.
*/
type Records interface{}
`
	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{Path: "credentials/lifecycle/records.go", Content: []byte(content)}})
	if len(got) != 0 {
		t.Fatalf("comments were flagged as leaks: %v", got)
	}
}

func TestIdiomRuleAllowsTheFenceItself(t *testing.T) {
	t.Parallel()
	content := `package store

type credentialItem struct {
	PK string ` + "`dynamodbav:\"PK\"`" + `
	GSI1SK string ` + "`dynamodbav:\"GSI1SK\"`" + `
}

const q = "PK = :pk AND begins_with(SK, :sk)"
`
	for _, path := range []string{"store/credentials.go", "store/credentials_test.go", "store/nested/thing.go"} {
		got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{Path: path, Content: []byte(content)}})
		if len(got) != 0 {
			t.Errorf("%s: the fence's own package was flagged: %v", path, got)
		}
	}
}

// TestIdiomRuleIsNotFooledByAPrefix pins the same near-miss the import rule
// guards against: a package called "storefront" is not the fence.
func TestIdiomRuleIsNotFooledByAPrefix(t *testing.T) {
	t.Parallel()
	content := "package storefront\n\nconst q = \"attribute_exists(PK)\"\n"
	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{Path: "storefront/queries.go", Content: []byte(content)}})
	if len(got) == 0 {
		t.Fatal("storefront/ was treated as store/")
	}
}

// TestIdiomRuleCleanFileIsClean guards against a needle so generic it fires on
// ordinary Go.
func TestIdiomRuleCleanFileIsClean(t *testing.T) {
	t.Parallel()
	content := `package lifecycle

import "context"

type Records interface {
	Get(ctx context.Context, id string) (*Record, error)
}

type Record struct {
	ID       string
	Revision uint64
	Status   string
}

func (r *Record) Terminal() bool { return r.Status == "revoked" }
`
	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{Path: "credentials/lifecycle/records.go", Content: []byte(content)}})
	if len(got) != 0 {
		t.Fatalf("clean file flagged: %v", got)
	}
}

// TestRepositoryHasNoIdiomLeaks is the check running against the real tree, so
// the fixtures above are not the only thing it has ever seen.
func TestRepositoryHasNoIdiomLeaks(t *testing.T) {
	t.Parallel()

	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}
	// Through the same scan the CLI uses, so the test cannot pass over a file set
	// the real gate would never see.
	scanned, err := ScanFiles(root, DefaultModulePrefix)
	if err != nil {
		t.Fatalf("scanning %s: %v", root, err)
	}
	files, err := SourcesFrom(root, scanned)
	if err != nil {
		t.Fatalf("reading sources under %s: %v", root, err)
	}
	// A check that silently inspected nothing is the failure mode that matters
	// most here, because it looks exactly like success.
	if len(files) < 10 {
		t.Fatalf("only %d Go files found under %s; the walk is not working", len(files), root)
	}

	// Every shipped rule, not just the first. A second fence added to
	// DefaultIdiomRules and not run here would be a fence nothing ever pointed at
	// the real tree.
	for _, rule := range DefaultIdiomRules() {
		if leaks := rule.Check(files); len(leaks) != 0 {
			var b strings.Builder
			for _, leak := range leaks {
				b.WriteString("\n  " + leak.String())
			}
			t.Errorf("%s: %s:%s", rule.Name, rule.Subject, b.String())
		}
	}
}

// moduleRoot walks up from this package to the directory holding go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// --- Regression: the escape-and-assembly bypass found in review on PR #6 -----
//
// The first version of this rule matched needles against the raw token spelling.
// A reviewer defeated it with a compiling fixture in three ways at once: a field
// tag written with a hex escape, an expression assembled by fmt.Sprintf from
// escaped fragments, and an escaped map key. `go test` passed and
// `go run ./hack/boundarycheck` reported zero leaks.
//
// The pair of tests below is why that cannot recur. The first proves the escaped
// forms really are the DynamoDB spellings -- compiled by the Go compiler in this
// very binary, so it is a fact rather than a claim. The second feeds the same
// source text to the rule and requires it to catch all three.

// escapedTagRecord is compiled as part of this test binary. Note the tag is an
// interpreted string literal rather than the usual backquoted one, which is
// ordinary Go: a struct tag is just a string literal, and only an interpreted one
// can carry an escape.
type escapedTagRecord struct {
	PK     string "\x64ynamodbav:\"PK\""
	GSI1SK string "\x64ynamodbav:\"\x47SI1SK\""
}

// TestEscapedIdiomIsRealIdiom establishes the premise: these spellings are not a
// clever trick that only looks like DynamoDB idiom, they are DynamoDB idiom. If
// this test ever fails, the fixture below has stopped being a real bypass and the
// rule below it is guarding nothing.
func TestEscapedIdiomIsRealIdiom(t *testing.T) {
	t.Parallel()

	fields := reflect.TypeOf(escapedTagRecord{})

	// reflect resolves the escaped tag to the real dynamodbav tag, which is what
	// the AWS SDK would read.
	if got := fields.Field(0).Tag.Get("dynamodbav"); got != "PK" {
		t.Errorf(`escaped tag resolved to dynamodbav=%q, want "PK"`, got)
	}
	if got := fields.Field(1).Tag.Get("dynamodbav"); got != "GSI1SK" {
		t.Errorf(`escaped tag resolved to dynamodbav=%q, want "GSI1SK"`, got)
	}

	// The assembled expression is the expression DynamoDB would receive.
	if got := fmt.Sprintf("%s_exists(PK)", "\x61ttribute"); got != "attribute_exists(PK)" {
		t.Errorf("assembled expression = %q, want attribute_exists(PK)", got)
	}
	// And the escaped key is the real index key.
	if got := "\x47SI1PK"; got != "GSI1PK" {
		t.Errorf("escaped key = %q, want GSI1PK", got)
	}
}

// escapeBypassSource is the reviewer's fixture as source text. It is a raw string
// literal, so the escapes reach the parser exactly as they appear in a real file.
//
// The path it is checked under is a _test.go outside store, pinning that test
// files get no exemption -- the reviewer's probe was a test file precisely
// because that is the easiest place to slip something in.
const escapeBypassSource = `package lifecycle

import "fmt"

// A tag written with a hex escape. Ordinary Go; resolves to dynamodbav.
type record struct {
	PK     string "\x64ynamodbav:\"PK\""
	Region string "\x64ynamodbav:\"Region\""
}

// An expression assembled from escaped fragments rather than written down.
func condition() string {
	return fmt.Sprintf("%s_exists(PK)", "\x61ttribute")
}

// The same trick with concatenation instead of a format call.
func filter() string {
	return "\x62egins_with" + "(SK, :sk)"
}

// And an escaped index key used as a map key.
func keys() map[string]string {
	return map[string]string{"\x47SI1PK": "owner"}
}
`

func TestIdiomRuleCatchesEscapeAndAssemblyBypass(t *testing.T) {
	t.Parallel()

	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path:    "credentials/lifecycle/reviewprobe_test.go",
		Content: []byte(escapeBypassSource),
	}})

	// Every one of these was invisible to the raw-spelling version of the rule.
	for _, want := range []string{"dynamodbav", "attribute_exists", "begins_with", "GSI1PK"} {
		var found bool
		for _, leak := range got {
			if leak.Needle == want {
				found = true
				// The message must name what the code means, not how it was
				// written, or the reader is sent to a line that looks innocent.
				if strings.Contains(leak.Token, `\x`) {
					t.Errorf("leak for %q reports the raw spelling %q; it should report the resolved value",
						want, leak.Token)
				}
				break
			}
		}
		if !found {
			t.Errorf("bypass not caught: no leak for %q in %v", want, got)
		}
	}
}

// TestFoldConstStringCoversTheAssemblyForms unit-tests the folding directly, so a
// regression in one form is not masked by another form catching the same file.
func TestFoldConstStringCoversTheAssemblyForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, expr, want string
		foldable         bool
	}{
		{"plain literal", `"attribute_exists(PK)"`, "attribute_exists(PK)", true},
		{"hex escape", `"\x61ttribute_exists(PK)"`, "attribute_exists(PK)", true},
		{"octal escape", `"\141ttribute_exists(PK)"`, "attribute_exists(PK)", true},
		{"unicode escape", `"attribute_exists(PK)"`, "attribute_exists(PK)", true},
		{"raw string", "`attribute_exists(PK)`", "attribute_exists(PK)", true},
		{"concatenation", `"attribute" + "_exists(PK)"`, "attribute_exists(PK)", true},
		{"parenthesised concatenation", `("attribute" + ("_exists" + "(PK)"))`, "attribute_exists(PK)", true},
		{"escaped concatenation", `"\x61ttribute" + "_exists(PK)"`, "attribute_exists(PK)", true},
		{"Sprintf", `fmt.Sprintf("%s_exists(PK)", "attribute")`, "attribute_exists(PK)", true},
		{"Sprintf with escapes", `fmt.Sprintf("%s_exists(PK)", "\x61ttribute")`, "attribute_exists(PK)", true},
		{"Sprintf two holes", `fmt.Sprintf("%s_%s(PK)", "attribute", "exists")`, "attribute_exists(PK)", true},
		{"Sprintf literal percent", `fmt.Sprintf("100%% %s", "done")`, "100% done", true},
		{"Sprint", `fmt.Sprint("attribute", "_exists(PK)")`, "attribute_exists(PK)", true},
		{"nested Sprintf in concatenation", `"attr" + fmt.Sprintf("%s_exists(PK)", "ibute")`, "attribute_exists(PK)", true},

		// A hole filled at runtime must NOT fold to something that can match; the
		// placeholder is unmatchable on purpose.
		{"runtime argument", `fmt.Sprintf("%s_exists(PK)", somevar)`, unfoldable + "_exists(PK)", true},
		// Not a string expression at all.
		{"non-string literal", `42`, "", false},
		{"identifier", `somevar`, "", false},
		{"unrelated call", `strings.ToUpper("x")`, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expr, err := parser.ParseExpr(tc.expr)
			if err != nil {
				t.Fatalf("parsing %s: %v", tc.expr, err)
			}
			got, ok := foldConstString(expr)
			if ok != tc.foldable {
				t.Fatalf("foldConstString(%s) foldable = %v, want %v (got %q)", tc.expr, ok, tc.foldable, got)
			}
			if ok && got != tc.want {
				t.Errorf("foldConstString(%s) = %q, want %q", tc.expr, got, tc.want)
			}
		})
	}
}

// TestRuntimeAssemblyIsAStatedLimit records the bound rather than implying it. A
// string whose forbidden part only exists at runtime is not caught, and no
// lexical rule can catch it. The rule's job is to stop the fence eroding by
// ordinary convenience, which is how the source system reached 1,456 tags.
func TestRuntimeAssemblyIsAStatedLimit(t *testing.T) {
	t.Parallel()

	source := `package lifecycle

import "fmt"

func condition(verb string) string {
	return fmt.Sprintf("%s_exists(PK)", verb)
}
`
	if got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path: "credentials/lifecycle/runtime.go", Content: []byte(source),
	}}); len(got) != 0 {
		t.Fatalf("unexpectedly caught runtime assembly, which would mean the "+
			"placeholder can match: %v", got)
	}
}

// TestUnparseableFileStillScanned makes sure the parser fallback is not a hole: a
// file the parser rejects must still be inspected, escapes included.
func TestUnparseableFileStillScanned(t *testing.T) {
	t.Parallel()

	// Deliberately broken Go: an unterminated function body.
	source := "package lifecycle\n\nfunc broken() { const q = \"\\x64ynamodbav:\\\"PK\\\"\"\n"
	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path: "credentials/lifecycle/broken.go", Content: []byte(source),
	}})
	if len(got) == 0 {
		t.Fatal("a file that does not parse was skipped entirely; that is a hole")
	}
	if got[0].Needle != "dynamodbav" {
		t.Errorf("needle = %q, want dynamodbav", got[0].Needle)
	}
}

// TestSourcesFromHasNoOpinionOnDirectories is the regression for the second
// blocker, and it is deliberately not a test that `node_modules` is scanned.
//
// The bug was that this package kept its own copy of the go command's directory
// rules, and skipped `node_modules` -- a directory `go build ./...` compiles.
// Restating those rules correctly here would have left two copies of a rule that
// has already been wrong twice. So the fix was to delete the copy, and what needs
// pinning is the absence: SourcesFrom must read whatever it is handed, so that
// fixing the shared predicate (USOSS-28) fixes this rule with no edit here.
func TestSourcesFromHasNoOpinionOnDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// Every one of these is a directory some walker somewhere has an opinion
	// about. SourcesFrom must have none.
	for _, rel := range []string{
		"node_modules/park/leak.go",
		"vendor/thing/leak.go",
		"cmd/vendor/leak.go",
		"testdata/leak.go",
		".hidden/leak.go",
		"_ignored/leak.go",
		"ordinary/leak.go",
	} {
		dir := filepath.Join(root, filepath.Dir(rel))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		body := "package p\n\nconst q = \"attribute_exists(PK)\"\n"
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	scanned := []FileImports{
		{File: "node_modules/park/leak.go"},
		{File: "vendor/thing/leak.go"},
		{File: "cmd/vendor/leak.go"},
		{File: "testdata/leak.go"},
		{File: ".hidden/leak.go"},
		{File: "_ignored/leak.go"},
		{File: "ordinary/leak.go"},
		// A duplicate, because a scan reports a package's test files alongside it.
		{File: "ordinary/leak.go"},
	}
	files, err := SourcesFrom(root, scanned)
	if err != nil {
		t.Fatalf("SourcesFrom: %v", err)
	}
	if len(files) != 7 {
		t.Fatalf("read %d files, want 7 (one per distinct path)", len(files))
	}

	leaks := DefaultDynamoDBIdiomRule().Check(files)
	if len(leaks) != 7 {
		t.Fatalf("got %d leaks, want 7 -- SourcesFrom must not filter by directory: %v", len(leaks), leaks)
	}
	// Named explicitly so a future skip-list cannot be added quietly.
	for _, want := range []string{"node_modules/park/leak.go", "cmd/vendor/leak.go", "vendor/thing/leak.go"} {
		var found bool
		for _, l := range leaks {
			if l.Path == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s was not inspected; a directory opinion has crept back in", want)
		}
	}
}

// --- Regression: indexed and non-sequential fmt operands (review round 2) ------
//
// The folder assumed every directive consumed the next argument. Go's indexed
// directives do not: %[2]s selects the second operand. So
// fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute") produced the real
// expression at run time while the gate reported success -- no literal in the file
// contained a needle, and the folder's own reassembly was wrong rather than absent.
//
// The lesson is in TestFormatDirectiveGrammarIsEnumerated below: this folder
// evaluates a small language, and every unmodelled corner of it is a bypass. So
// the grammar is enumerated and anything outside it refuses rather than guesses.

// TestIndexedOperandsAreReallyReordered establishes the premise by compiling it,
// the same way the escaped-tag regression does.
func TestIndexedOperandsAreReallyReordered(t *testing.T) {
	t.Parallel()

	if got := fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute"); got != "attribute_exists(PK)" {
		t.Fatalf("indexed directives resolved to %q; the fixture below is no longer a bypass", got)
	}
	// Width from an argument shifts which operand a later verb consumes, which is
	// the other way an argument-counting folder goes wrong.
	if got := fmt.Sprintf("%*s%s", 1, "", "begins_with"); got != " begins_with" {
		t.Fatalf("star-width resolved to %q", got)
	}
}

const indexedBypassSource = `package lifecycle

import "fmt"

// Indexed directives: the operands are written in the opposite order.
func condition() string {
	return fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute")
}

// A star-width directive consumes an argument of its own before the verb does.
func filter() string {
	return fmt.Sprintf("%*s%[3]s", 0, "", "begins_with")
}

// Assembled by a function the folder does not model at all. The fragment net has
// to catch this one, because modelling fmt exactly buys nothing here.
func joined() string {
	return strings.Join([]string{"attribute", "_exists(PK)"}, "")
}
`

func TestIdiomRuleCatchesIndexedAndUnmodelledAssembly(t *testing.T) {
	t.Parallel()

	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path:    "credentials/lifecycle/reviewprobe_test.go",
		Content: []byte(indexedBypassSource),
	}})

	for _, want := range []string{"attribute_exists", "begins_with"} {
		var found bool
		for _, leak := range got {
			if leak.Needle == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bypass not caught: no leak for %q in %v", want, got)
		}
	}
}

// TestFormatDirectiveGrammarIsEnumerated is the answer to "what else does fmt do
// that you do not model". Every row is a directive form; each is either modelled
// exactly or refused, and there is no third outcome.
func TestFormatDirectiveGrammarIsEnumerated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, expr string
		want       string
		exact      bool
	}{
		// Modelled exactly.
		{"sequential", `fmt.Sprintf("%s_exists(PK)", "attribute")`, "attribute_exists(PK)", true},
		{"indexed", `fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute")`, "attribute_exists(PK)", true},
		{"indexed then indexed", `fmt.Sprintf("%[2]s%[1]s", "b", "a")`, "ab", true},
		{"indexed repeated operand", `fmt.Sprintf("%[1]s%[1]s", "ab")`, "abab", true},
		{"literal percent", `fmt.Sprintf("100%% %s", "done")`, "100% done", true},
		{"flags", `fmt.Sprintf("%-+# 0s", "x")`, "x", true},
		{"width", `fmt.Sprintf("%10s", "x")`, "x", true},
		{"precision", `fmt.Sprintf("%.3s", "x")`, "x", true},
		// Verified against real fmt: "%*s%s" with (4,"a","b") is "   ab" and
		// "%.*s%s" is "ab". The star consumes its own operand -- which is the
		// property that matters -- and the padding is dropped; see
		// TestRenderingIsNotByteIdentical.
		{"star width consumes an argument", `fmt.Sprintf("%*s%s", 4, "a", "b")`, "ab", true},
		{"star precision consumes an argument", `fmt.Sprintf("%.*s%s", 4, "a", "b")`, "ab", true},
		{"unknown verb still eats its operand", `fmt.Sprintf("%y%s", "a", "b")`, "ab", true},
		{"runtime operand becomes unmatchable", `fmt.Sprintf("%s_exists(PK)", v)`, "\x00_exists(PK)", true},
		{"Sprint", `fmt.Sprint("attribute", "_exists(PK)")`, "attribute_exists(PK)", true},
		{"Sprintln separates and terminates", `fmt.Sprintln("a", "b")`, "a b\n", true},
		{"strings.Join", `strings.Join([]string{"attribute", "_exists(PK)"}, "")`, "attribute_exists(PK)", true},
		{"strings.Join with separator", `strings.Join([]string{"a", "b"}, "-")`, "a-b", true},
		{"strings.Repeat", `strings.Repeat("ab", 3)`, "ababab", true},

		// Refused rather than guessed at.
		{"truncated directive", `fmt.Sprintf("%")`, "", false},
		{"index with no digits", `fmt.Sprintf("%[]s", "a")`, "", false},
		{"unterminated index", `fmt.Sprintf("%[1s", "a")`, "", false},
		{"zero index", `fmt.Sprintf("%[0]s", "a")`, "", false},
		// Verified against real fmt: "%[1]*[3]s_%[2]s(PK)" with (0,"exists",
		// "attribute") is "attribute_exists(PK)". This form was refused until it
		// bypassed the gate, so it is modelled now: an index may appear before the
		// width and again before the verb.
		{"index before width and before verb", `fmt.Sprintf("%[1]*[3]s_%[2]s(PK)", 0, "exists", "attribute")`, "attribute_exists(PK)", true},
		// Numeric operands are not strings, so they fold to the unmatchable
		// placeholder; real fmt renders "2" here. Selection is what matters.
		{"index after width, numeric operands", `fmt.Sprintf("%[1]*[2]d", 1, 2)`, "\x00", true},
		{"star width with a following index", `fmt.Sprintf("%*[2]d", 3, 7)`, "\x00", true},
		{"too few operands", `fmt.Sprintf("%s%s", "a")`, "", false},
		// Real fmt renders "a%!s(MISSING)" here: after an explicit index the next
		// sequential verb continues past it and runs out. Refusing beats emitting
		// fmt's error text as though it were the value.
		{"sequential verb after an index runs out", `fmt.Sprintf("%[2]s%s", "b", "a")`, "", false},
		{"index past the operands", `fmt.Sprintf("%[9]s", "a")`, "", false},
		{"non-constant format", `fmt.Sprintf(format, "a")`, "", false},
		{"runaway repeat", `strings.Repeat("ab", 100000)`, "", false},
		{"unmodelled helper", `strings.ToUpper("attribute_exists(PK)")`, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expr, err := parser.ParseExpr(tc.expr)
			if err != nil {
				t.Fatalf("parsing %s: %v", tc.expr, err)
			}
			call, ok := expr.(*ast.CallExpr)
			if !ok {
				t.Fatalf("%s is not a call", tc.expr)
			}
			got, exact := foldFormatCall(call)
			if exact != tc.exact {
				t.Fatalf("foldFormatCall(%s) exact = %v, want %v (got %q)", tc.expr, exact, tc.exact, got)
			}
			if exact && got != tc.want {
				t.Errorf("foldFormatCall(%s) = %q, want %q", tc.expr, got, tc.want)
			}
		})
	}
}

// TestRefusedFoldStillMatchesFragments is the reason refusing is safe. When the
// folder declines, the conservative net still sees the pieces, so declining costs
// coverage only for a construct that also reorders them.
func TestRefusedFoldStillMatchesFragments(t *testing.T) {
	t.Parallel()

	source := `package lifecycle

import "strings"

// Neither modelled nor sequential: a helper this rule has never heard of.
func q() string {
	return strings.ToUpper(build("attribute", "_exists(PK)"))
}
`
	if got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path: "credentials/lifecycle/unmodelled.go", Content: []byte(source),
	}}); len(got) == 0 {
		t.Fatal("an unmodelled helper hid a needle split across its constant arguments")
	}
}

// TestRenderingIsNotByteIdentical states the one way the folder's output differs
// from fmt's, so nobody reads "exact" as a stronger claim than it is.
//
// The flag means every directive's *argument selection* was modelled. It does not
// mean the result is byte-identical to fmt: width padding is dropped and an
// unknown verb's error decoration is not reproduced. Both omissions can only join
// fragments that fmt would have separated, so the risk they carry is a false
// positive, never a miss -- and no configured needle contains a space, which is
// what padding would have supplied.
func TestRenderingIsNotByteIdentical(t *testing.T) {
	t.Parallel()

	// Real fmt pads to width 4; the folder does not.
	if padded := fmt.Sprintf("%*s%s", 4, "a", "b"); padded != "   ab" {
		t.Fatalf("premise: fmt now renders %q", padded)
	}
	expr, err := parser.ParseExpr(`fmt.Sprintf("%*s%s", 4, "a", "b")`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, exact := foldFormatCall(expr.(*ast.CallExpr))
	if !exact {
		t.Fatal("argument selection here is fully modelled and should be reported as such")
	}
	if got != "ab" {
		t.Errorf("folded to %q, want %q -- padding is deliberately dropped", got, "ab")
	}
}

// --- Regression: a refusal must not degrade to a pass (review round 3) --------
//
// fmt.Sprintf("%[1]*[3]s_%[2]s(PK)", 0, "exists", "attribute") produced the real
// expression while the gate reported success. Two mechanisms failed together, and
// that combination is the lesson: the folder refused the form (an index after a
// width, deliberately unmodelled), and the net that made refusal safe joined
// fragments in *source* order -- which reads "exists" before "attribute" and so
// never assembles the needle either.
//
// Both are fixed. The form is modelled, because it is valid Go that fmt accepts.
// And the net is order-independent, because the next refused form will have its
// operands in the wrong order too -- that is what being refused tends to mean.

func TestIndexBeforeWidthIsReallyReordered(t *testing.T) {
	t.Parallel()
	// Compiled here, so the fixture below rests on a fact rather than a claim.
	if got := fmt.Sprintf("%[1]*[3]s_%[2]s(PK)", 0, "exists", "attribute"); got != "attribute_exists(PK)" {
		t.Fatalf("resolved to %q; the fixture below is no longer a bypass", got)
	}
}

const refusedFormSource = `package lifecycle

import "fmt"

// An index before the width and another before the verb.
func condition() string {
	return fmt.Sprintf("%[1]*[3]s_%[2]s(PK)", 0, "exists", "attribute")
}
`

func TestIdiomRuleCatchesIndexBeforeWidth(t *testing.T) {
	t.Parallel()
	got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
		Path: "credentials/lifecycle/reviewprobe_test.go", Content: []byte(refusedFormSource),
	}})
	if len(got) == 0 {
		t.Fatal("the reordered form was not caught")
	}
	if got[0].Needle != "attribute_exists" {
		t.Errorf("needle = %q, want attribute_exists", got[0].Needle)
	}
}

// TestRefusedCallsStillFailClosed is the general property, and the one that
// matters more than the specific form above: when the folder declines, the
// fragments must still be checked in a way that does not depend on their order.
//
// Each fixture below uses a construct the folder refuses outright, with the pieces
// deliberately written in an order no concatenation would reassemble.
func TestRefusedCallsStillFailClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, source string
	}{
		{"unmodelled helper, reversed operands", `package lifecycle

func q() string { return build("_exists(PK)", "attribute") }
`},
		{"non-constant format, reversed operands", `package lifecycle

import "fmt"

func q(format string) string { return fmt.Sprintf(format, "_exists(PK)", "attribute") }
`},
		{"runaway repeat leaves its fragments visible", `package lifecycle

import "strings"

func q() string { return strings.Repeat("GSI1"+"PK", 100000) }
`},
		{"pieces spread across nested calls", `package lifecycle

func q() string { return outer(inner("exists"), "attribute", "_") }
`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DefaultDynamoDBIdiomRule().Check([]SourceFile{{
				Path: "credentials/lifecycle/x.go", Content: []byte(tc.source),
			}}); len(got) == 0 {
				t.Error("a refused call hid a needle in its fragments; refusal has degraded to a pass")
			}
		})
	}
}

// TestAssemblableIsOrderIndependentButNotIndiscriminate pins both directions. It
// over-approximates on purpose -- fragments that *could* tile a needle are flagged
// -- but it must not fire on fragments that cannot.
func TestAssemblableIsOrderIndependentButNotIndiscriminate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		needle    string
		fragments []string
		want      bool
	}{
		{"whole needle in one fragment", "attribute_exists", []string{"x", "attribute_exists(PK)"}, true},
		{"two fragments in order", "attribute_exists", []string{"attribute", "_exists(PK)"}, true},
		{"two fragments reversed", "attribute_exists", []string{"_exists(PK)", "attribute"}, true},
		{"three fragments scrambled", "attribute_exists", []string{"exists", "attribute", "_"}, true},
		{"a fragment reused", "GSI1PKGSI1PK", []string{"GSI1PK"}, true},
		{"leading context on the first fragment", "GSI1PK", []string{"prefix-GSI1", "PK-suffix"}, true},

		{"no fragments", "attribute_exists", nil, false},
		{"a missing middle", "attribute_exists", []string{"attribute", "exists"}, false},
		{"unrelated fragments", "attribute_exists", []string{"select", "from", "where"}, false},
		{"partial only", "attribute_exists", []string{"attribute"}, false},
		{"needle spelled with a gap", "GSI1PK", []string{"GSI", "1P"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := assemblable(tc.needle, tc.fragments); got != tc.want {
				t.Errorf("assemblable(%q, %q) = %v, want %v", tc.needle, tc.fragments, got, tc.want)
			}
		})
	}
}
