// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/internal/awscode"
	"github.com/conductorone/apphub/internal/boundary"
)

// This file holds the second half of the ticket's central property. config_test.go
// says every configuration field is required; this says nothing identifier-shaped
// is compiled in for such a field to have been a default for.
//
// The two populations are obtained by different mechanisms on purpose. One is the
// reflect type of Config. This one is the package's own source: every string
// literal in every non-test file in this directory, and every package-level
// declaration whose value is one. A cross-check that shares the derivation's
// blind spot is not a cross-check.

// sourceFiles returns every non-test Go file in this package's directory.
//
// The population is the directory listing, not a list in this file, and a file
// that will not parse is a failure rather than an omission. No count is asserted:
// a count here would be a claim the code does not make and would go stale on the
// next file added. What is asserted is that the mechanism found something -- a
// derivation that returns nothing passes every check made over it.
func sourceFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	files, _ := sourceFilesWithFset(t)
	return files
}

// sourceFilesWithFset is sourceFiles plus the position information, for a caller
// that needs to render a node back to source -- printing a signature in a failure
// message, for instance.
func sourceFilesWithFset(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		out[name] = f
	}
	if len(out) == 0 {
		t.Fatal("found no non-test Go files; the derivation would be vacuous")
	}
	return out, fset
}

// The shapes a disclosure takes. Every one matches a shape and never a value:
// writing a known account number into a pattern would publish that number in the
// pattern, which is the disclosure the pattern exists to prevent.
var (
	arnWithAccount  = regexp.MustCompile(`arn:aws[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:`)
	twelveDigits    = regexp.MustCompile(`(^|[^0-9])[0-9]{12}([^0-9]|$)`)
	infraIdentifier = regexp.MustCompile(`\b(?:vpc|subnet|sg|igw|nat|rtb|acl|eni|vol|snap|ami)-(?:[0-9a-f]{8}|[0-9a-f]{17})\b`)
	accessKeyID     = regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`)
	hostnameShaped  = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){2,}[a-z]{2,}\b`)
)

// hostsThisPackageMayName is the closed set of hostnames that may appear in this
// package's source.
//
// Both are public AWS service names, and both are load-bearing: a provider that
// could not name the STS audience could not federate, and one that could not name
// the Bedrock service principal could not scope a credential to Bedrock. The
// repository's secret scan allows any single-label host under amazonaws.com, which
// is wider than this package needs -- a deployment-specific endpoint fits that
// pattern -- so the set is narrowed here to the two that are actually used.
var hostsThisPackageMayName = map[string]bool{
	"sts.amazonaws.com":     true,
	"bedrock.amazonaws.com": true,
}

// TestNoStringLiteralInThisPackageIsAnInfrastructureIdentifier is the property
// the ticket is named for.
//
// The repository's secret scan catches an account ID and an internal hostname.
// It does not catch an AWS managed-policy ARN, an IAM path naming a project, or a
// hostname it has allowlisted at a wider shape than this package needs -- and the
// identifier this ticket removed from the source was exactly the first of those.
// So this is not a restatement of that gate: it is a narrower rule over a
// population the gate does not have, which is this package's own literals.
func TestNoStringLiteralInThisPackageIsAnInfrastructureIdentifier(t *testing.T) {
	t.Parallel()
	files := sourceFiles(t)
	literals := 0
	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				// A literal this test cannot read is a literal it cannot check.
				// Failing rather than skipping is the difference between a gate
				// and a gate with a hole in it.
				t.Fatalf("%s: cannot unquote %s: %v", name, lit.Value, err)
			}
			literals++
			for _, rule := range []struct {
				name string
				re   *regexp.Regexp
			}{
				{"an ARN carrying an account ID", arnWithAccount},
				{"a twelve-digit number, the shape of an AWS account ID", twelveDigits},
				{"an AWS infrastructure identifier", infraIdentifier},
				{"an AWS access key ID", accessKeyID},
			} {
				if rule.re.MatchString(value) {
					t.Errorf("%s: string literal %q is %s", name, value, rule.name)
				}
			}
			for _, host := range hostnameShaped.FindAllString(value, -1) {
				if !hostsThisPackageMayName[host] {
					t.Errorf("%s: string literal %q names host %q, which is not in the closed set "+
						"this package may name", name, value, host)
				}
			}
			return true
		})
	}
	if literals == 0 {
		t.Fatal("found no string literals; the property above was checked over nothing")
	}
	t.Logf("checked %d string literals across %d files", literals, len(files))
}

// TestTheDisclosureRulesFire is the control, and it is the whole reason the test
// above means anything.
//
// A pattern set that matched nothing would pass over any source at all. Each
// pattern is driven against a synthetic example of its own class, built at run
// time so that no example is written down here either.
func TestTheDisclosureRulesFire(t *testing.T) {
	t.Parallel()
	account := strings.Repeat("7", 12)
	cases := []struct {
		re    *regexp.Regexp
		fires string
	}{
		{arnWithAccount, "arn:aws:iam::" + account + ":role/example"},
		{twelveDigits, `{"aws_account_id": "` + account + `"}`},
		{twelveDigits, account},
		{infraIdentifier, "vpc-" + strings.Repeat("a", 8)},
		{accessKeyID, "AKIA" + strings.Repeat("Q", 16)},
		// Under .invalid, which the repository's secret scan allowlists, rather than
		// the reserved .example TLD, which it does not. The pattern under test still
		// matches it: what is being checked is that a three-label host is
		// recognised, and the suffix is not the discriminator.
		{hostnameShaped, "vault.internal.invalid"},
	}
	for _, tc := range cases {
		if !tc.re.MatchString(tc.fires) {
			t.Errorf("%v does not fire on %q", tc.re, tc.fires)
		}
	}
	// And the other direction: the patterns must not fire on the ordinary source
	// they run over, or the test above would be unwritable and somebody would
	// loosen a rule to make it pass. A loosened recogniser is the bypass.
	quiet := []struct {
		re    *regexp.Regexp
		value string
	}{
		{twelveDigits, "1234567890123"}, // thirteen digits: a millisecond timestamp
		{twelveDigits, "12345678901"},   // eleven
		{arnWithAccount, "arn:aws:iam::aws:policy/ExampleManaged"},
		{infraIdentifier, "sg-notahexstring"},
		{accessKeyID, "AKIAshort"},
		{hostnameShaped, "example.com"}, // two labels
	}
	for _, tc := range quiet {
		if tc.re.MatchString(tc.value) {
			t.Errorf("%v fires on %q, which is not a disclosure", tc.re, tc.value)
		}
	}
}

// declaredStrings collects every package-level declaration whose value is a
// string literal, with the type it was declared at.
type declaredString struct {
	Name  string
	Type  string // the declared type name, or "" for an untyped declaration
	Value string
	File  string
}

func packageLevelStrings(t *testing.T) []declaredString {
	t.Helper()
	var out []declaredString
	for name, file := range sourceFiles(t) {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					t.Fatalf("%s: a %s declaration holds a %T, which this derivation cannot classify",
						name, gen.Tok, spec)
				}
				typeName := ""
				if id, ok := vs.Type.(*ast.Ident); ok {
					typeName = id.Name
				}
				for i, ident := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s: cannot unquote %s: %v", name, lit.Value, err)
					}
					out = append(out, declaredString{Name: ident.Name, Type: typeName, Value: value, File: name})
				}
			}
		}
	}
	return out
}

// stringConstantsThisPackageDeclares is the allowlist, and it is an allowlist
// rather than a pattern on purpose.
//
// Every entry is a protocol fact: a name AWS or this repository defines, which an
// operator could only break by changing. Adding one is a decision somebody makes
// by editing this map, which is the construction rule -- prefer a shape that
// cannot express the violation over a check that notices one -- rather than a
// recogniser that can be argued into admitting the next thing.
//
// An identifier belonging to a deployment cannot be added here without saying so
// in the same commit, which is the whole point.
var stringConstantsThisPackageDeclares = map[string]string{
	"ProviderID":              "the registry key, which is this repository's own name for the provider",
	"handleStatic":            "the platform-key-ID discriminator for an IAM-user credential",
	"handleDynamic":           "the platform-key-ID discriminator for a Bedrock bearer token",
	"tagManagedBy":            "this repository's ownership tag key; cross-checked against compute/aws",
	"tagName":                 "this repository's name tag key",
	"tagComponent":            "this repository's component tag key",
	"managedByValue":          "the project name, which is public and never a deployment",
	"componentCredentialUser": "what this provider creates an IAM user as",
	"bedrockTokenPrefix":      "the Bedrock bearer-token wire format",
	"bedrockTokenVersion":     "the Bedrock bearer-token wire format",
	"stsAudience":             "the audience AWS requires on a web identity presented to STS",
	"bedrockServiceName":      "the AWS service principal a Bedrock service credential is scoped to",
	"expiresMiddlewareID":     "this repository's name for its own smithy build step",
}

// TestEveryStringConstantIsAProtocolFactOrIsNamed is the no-defaults property
// from the source side.
//
// A configuration field with no default is only half of it: the other half is that
// there is no compiled-in string for such a field to have been defaulted from.
// Constants of type op are exempt as a class, because an op is prose for an error
// message and the type cannot be constructed outside this package -- so no op
// value can reach AWS.
func TestEveryStringConstantIsAProtocolFactOrIsNamed(t *testing.T) {
	t.Parallel()
	declared := packageLevelStrings(t)
	if len(declared) == 0 {
		t.Fatal("derived no package-level string declarations")
	}
	seen := map[string]bool{}
	for _, d := range declared {
		seen[d.Name] = true
		if d.Type == "op" {
			continue
		}
		if _, ok := stringConstantsThisPackageDeclares[d.Name]; !ok {
			t.Errorf("%s declares the string constant %s and this test does not know why. "+
				"If it is a protocol fact, add it to stringConstantsThisPackageDeclares with the "+
				"reason. If it names something belonging to a deployment, it is a Config field.",
				d.File, d.Name)
		}
	}
	// The allowlist is checked in the other direction too: an entry for something
	// that no longer exists is a rule with no input, which reads as coverage and
	// is not.
	for name := range stringConstantsThisPackageDeclares {
		if !seen[name] {
			t.Errorf("stringConstantsThisPackageDeclares names %s, which this package no longer declares", name)
		}
	}
	t.Logf("classified %d package-level string declarations", len(declared))
}

// TestTagVocabularyAgreesWithComputeAWS cross-checks a restatement against its
// source.
//
// The ownership tag key and value are declared in compute/aws too, unexported.
// Two packages writing the same marker at two spellings would mean an operator
// seeing two markers and each package refusing to recognise the other's
// resources. Reading the sibling declaration makes that a test failure.
//
// It looks up two names rather than enumerating a population, which is why a
// syntax read is the right tool here: the set is stated by this test, and a name
// it cannot find is a failure.
func TestTagVocabularyAgreesWithComputeAWS(t *testing.T) {
	t.Parallel()
	const sibling = "../../compute/aws/names.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Clean(sibling), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", sibling, err)
	}
	want := map[string]string{"tagManagedBy": tagManagedBy, "managedByValue": managedByValue,
		"tagName": tagName, "tagComponent": tagComponent}
	found := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, ident := range vs.Names {
			if _, interesting := want[ident.Name]; !interesting || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("%s declares %s as something other than a string literal; this "+
					"cross-check cannot read it", sibling, ident.Name)
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: cannot unquote %s: %v", sibling, lit.Value, err)
			}
			found[ident.Name] = value
		}
		return true
	})
	for name, mine := range want {
		theirs, ok := found[name]
		if !ok {
			t.Fatalf("%s no longer declares %s; the cross-check has nothing to compare against, "+
				"which is a failure and not a pass", sibling, name)
		}
		if theirs != mine {
			t.Errorf("%s = %q here and %q in %s", name, mine, theirs, sibling)
		}
	}
}

// TestOnlyTheCreatePathsDeriveAName is the structural half of the property that
// makes a non-injective sanitisation safe.
//
// Two distinct credential names can fold to one IAM user name, so a name must
// never be re-derived in order to act on an existing resource: it travels in the
// platform key ID and is read from there. The behavioural half is
// TestNamesAreOnlyEverReadFromTheHandle. Neither covers the other -- this one sees
// a call site no test exercises, and that one sees behaviour a call site does not
// describe -- so both are named here so a later reader does not delete one.
func TestOnlyTheCreatePathsDeriveAName(t *testing.T) {
	t.Parallel()
	permitted := map[string]bool{"createDynamic": true, "createStatic": true}
	callers := map[string]bool{}
	for name, file := range sourceFiles(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "prefixedName" {
					callers[fn.Name.Name] = true
					if !permitted[fn.Name.Name] {
						t.Errorf("%s: %s derives a resource name; only the create paths may, "+
							"because the mapping is not injective and cannot be used to find "+
							"an existing resource", name, fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	if len(callers) == 0 {
		t.Fatal("found no call to prefixedName; this check ran over nothing")
	}
	for fn := range permitted {
		if !callers[fn] {
			t.Errorf("%s no longer derives a name; this check's population has shrunk and the "+
				"reason should be recorded rather than inherited", fn)
		}
	}
}

// TestRetryableCodesMatchTheSDK cross-checks the copied classification set
// against the SDK's own, generatively.
//
// The set in internal/awscode is a copy, and a copy is a restatement that drifts.
// It drifts in the dangerous direction: a code AWS adds after the copy was made is
// classified terminal, so a caller is told to give up when waiting was the whole
// remedy. Deriving the expected set here means that becomes a test failure.
//
// # This test now covers both AWS providers, and it did not before
//
// The set used to be declared twice -- retryableCodes in this package's fault.go
// and an identical throttleCodes in compute/aws -- and only this one was checked.
// So the sole way the two could diverge was the harmful one: a code AWS adds would
// turn this test red and pass unnoticed in compute/aws, which is a throttle
// classified terminal in the provider that runs deploys. USOSS-63 converged them
// into [awscode.RetryableCodes], and this cross-check is now the single gate over
// the single declaration.
//
// The test stays HERE rather than moving to internal/awscode for a boundary
// reason rather than a stylistic one. It has to import the SDK's retry package to
// derive the expectation, internal/boundary's aws-sdk-confined rule counts test
// imports, and credentials/aws is already on that rule's allowlist. Moving the
// test would have meant widening an import fence to accommodate a deduplication,
// which is a bad trade; internal/awscode imports nothing at all instead.
//
// # The two exclusions, and why only one of them is spelled out
//
// Both are DynamoDB's, and this repository fences DynamoDB into store/, so neither
// can be returned by an IAM or STS client.
//
// One of them cannot be written down here at all. Naming it is itself a
// DynamoDB-idiom leak -- `make boundary` reported this exact line, which is the
// fence doing its job on a list pasted from the SDK without asking what these
// clients can return. So that exclusion is derived from the fence instead: any code
// whose text the repository's own idiom rule forbids outside store/ is excluded,
// with the fence's own reason. If the needle list changes, this follows it.
//
// The other is named, because the fence's needles are request and response *field*
// names and none of them matches it. The asymmetry is informative rather than
// untidy: it says the fence is about the storage shape and not about error codes,
// so one of these two is caught by a rule and the other needs a decision.
func TestRetryableCodesMatchTheSDK(t *testing.T) {
	t.Parallel()

	fence := boundary.DefaultDynamoDBIdiomRule()
	if len(fence.Needles) == 0 {
		t.Fatal("the DynamoDB idiom fence has no needles; the derived exclusion below would be empty")
	}
	// Needle.Found rather than a substring test of our own: a needle's match rules
	// are the fence's to state, and a second opinion here is a restatement that
	// drifts the first time one of them gains a case fold or a delimiter rule.
	fencedOut := func(code string) (string, bool) {
		for _, n := range fence.Needles {
			if n.Found(code) {
				return n.Reason, true
			}
		}
		return "", false
	}

	// The one exclusion the fence does not catch, with its reason.
	namedExclusions := map[string]string{
		"TransactionInProgressException": "DynamoDB's; an IAM or STS client cannot return it, " +
			"and no idiom needle matches it because the fence is about the storage shape",
	}

	want := map[string]struct{}{}
	fenceExcluded, nameExcluded := 0, 0
	for code := range retry.DefaultThrottleErrorCodes {
		if _, ok := fencedOut(code); ok {
			fenceExcluded++
			continue
		}
		if _, ok := namedExclusions[code]; ok {
			nameExcluded++
			continue
		}
		want[code] = struct{}{}
	}
	for code := range retry.DefaultRetryableErrorCodes {
		if _, ok := fencedOut(code); ok {
			fenceExcluded++
			continue
		}
		if _, ok := namedExclusions[code]; ok {
			nameExcluded++
			continue
		}
		want[code] = struct{}{}
	}
	if len(want) == 0 {
		t.Fatal("derived no codes from the SDK")
	}
	// Both exclusion mechanisms must have had something to exclude. A mechanism
	// with no input is a rule that reads as coverage and is not.
	if fenceExcluded == 0 {
		t.Error("the fence-derived exclusion matched nothing; either the SDK dropped the code " +
			"or this mechanism has stopped working")
	}
	if nameExcluded == 0 {
		t.Error("the named exclusion matched nothing; it is a rule with no input and should be " +
			"removed rather than kept for reassurance")
	}

	shared := map[string]struct{}{}
	for _, code := range awscode.RetryableCodes() {
		shared[code] = struct{}{}
	}
	for code := range want {
		if _, ok := shared[code]; !ok {
			t.Errorf("the SDK treats %s as retryable and this package does not; a throttle "+
				"classified terminal tells a caller to give up when waiting would have worked", code)
		}
	}
	for code := range shared {
		if _, ok := want[code]; !ok {
			t.Errorf("this package treats %s as retryable and the SDK does not", code)
		}
	}
	t.Logf("cross-checked %d retryable codes against the SDK; %d excluded by the DynamoDB fence, "+
		"%d by name", len(shared), fenceExcluded, nameExcluded)
}

// TestTheSharedRetryableSetIsLoadBearingHere asserts that [isTransient] actually
// honours every code in [awscode.RetryableCodes].
//
// TestRetryableCodesMatchTheSDK above proves the shared set equals the SDK's. It
// says nothing about whether this package still reads it, and USOSS-63 moved the
// declaration two packages away -- so the arm could be deleted, or narrowed to a
// subset, and the cross-check would stay green over a set nothing consulted.
//
// The fault is FaultClient deliberately. [isTransient] answers true to any
// FaultServer error before it reaches the code arm, so a fixture carrying one
// would pass whether the arm worked or not.
func TestTheSharedRetryableSetIsLoadBearingHere(t *testing.T) {
	t.Parallel()

	codes := awscode.RetryableCodes()
	if len(codes) == 0 {
		t.Fatal("the shared set is empty; every assertion below would hold vacuously")
	}
	for _, code := range codes {
		if !isTransient(&smithy.GenericAPIError{
			Code: code, Message: "slow down", Fault: smithy.FaultClient,
		}) {
			t.Errorf("%s is in the shared retryable set and isTransient says terminal; a "+
				"throttle reported terminal tells a caller to give up when waiting was the "+
				"remedy", code)
		}
	}

	// The control. Without it a predicate answering true to everything passes.
	const notInTheSet = "SomeFutureValidationException"
	if awscode.IsRetryable(notInTheSet) {
		t.Fatalf("%s is in the shared set; this control no longer controls anything", notInTheSet)
	}
	if isTransient(&smithy.GenericAPIError{
		Code: notInTheSet, Message: "no", Fault: smithy.FaultClient,
	}) {
		t.Errorf("%s is not in the shared set and isTransient called it transient", notInTheSet)
	}
}

// TestAnIAMThrottleIsTransientAndAnIAMQuotaIsNot settles USOSS-63's premise on the
// errors IAM actually sends.
//
// The ticket reported that an IAM throttle reaches this package as
// ErrorCode() == "LimitExceeded", misses a set carrying only ECR's longer
// spelling, and is classified terminal. The first half is a true fact about a
// real type and the second half does not follow from it, and separating them is
// the whole content of this class of bug:
//
//   - "LimitExceeded" is what iamtypes.LimitExceededException reports, and that
//     type is a QUOTA exhaustion -- the account is at its IAM limit. Retrying
//     does not create head-room. The SDK classifies it terminal and so does this
//     package, and TestEveryDeclaredSDKErrorIsClassified has held that decision
//     with the SDK's own type as the witness since USOSS-9.
//   - IAM's THROTTLE is a different error with no Go type at all: IAM is a
//     query-protocol service, so a rate refusal arrives as the common wire code
//     "Throttling". That code is in the shared set, and was in both of the sets
//     the shared one replaced, so an IAM throttle has been transient throughout.
//
// Both are pinned here, adjacent, because the claim under review was that they
// were one error. Note the fixture asymmetry and why it is not avoidable: the
// quota case uses the SDK's own type, and the throttle case cannot, because
// there is no type to use. awscode's TestATypeNameIsNotAWireCode is what checks
// that -- it reads every error type iam declares and none of them reports
// "Throttling".
func TestAnIAMThrottleIsTransientAndAnIAMQuotaIsNot(t *testing.T) {
	t.Parallel()

	throttle := &smithy.GenericAPIError{
		Code: "Throttling", Message: "Rate exceeded", Fault: smithy.FaultClient,
	}
	if !isTransient(throttle) {
		t.Error("an IAM throttle is classified terminal; a caller is told to give up on a " +
			"rate refusal that a second attempt would have survived")
	}

	quota := &iamtypes.LimitExceededException{}
	if code := quota.ErrorCode(); code != "LimitExceeded" {
		t.Fatalf("iamtypes.LimitExceededException now reports %q; the premise of this test, "+
			"and of the whole type-name-is-not-the-code argument, has changed", code)
	}
	if isTransient(quota) {
		t.Error("an IAM quota exhaustion is classified transient. That is the reverted 'fix' " +
			"growing back: the Go type name LimitExceededException is in the shared set and " +
			"the code LimitExceeded is not, and the code is what AWS sends")
	}
}
