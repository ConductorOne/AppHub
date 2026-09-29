// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

// This file exists because the cross-check in identifiers_test.go structurally
// cannot see the defect that motivated it.
//
// TestRetryableCodesMatchTheSDK compares this package's classification set with
// the SDK's two maps. Both sides are the SDK's answer to "which wire codes are
// retryable", so the comparison proves the copy did not DRIFT and can never prove
// the copy was the RIGHT SET. It was not: ConcurrentModification and
// EntityTemporarilyUnmodifiable are in neither SDK map, are both FaultClient, and
// are exactly what two concurrent reconciles on one IAM user produce.
// compute/aws had already found them (awssdk.go:280-292) and this package had
// copied only the part of that file that looked relevant.
//
// So the population here is obtained a different way: every error type the iam and
// sts packages DECLARE, read out of the SDK's own generated source. That straddles
// the boundary the property is about -- does this package classify what these
// services can actually return -- which the SDK's retryable map does not.
//
// Each declared code carries a decision, in the sense USOSS-54 settled for the
// compute taxonomy: an undecided code is fatal, and a decision for a code the SDK
// no longer declares is fatal too. A code AWS adds is therefore a test failure
// rather than a silently terminal classification.

// disposition is what this package does with one AWS error.
type disposition string

const (
	dispTransient disposition = "transient"
	dispTerminal  disposition = "terminal"
)

// declaredSDKError is one error type the SDK declares, the wire code it reports, and
// the decision this package has made about it.
type declaredSDKError struct {
	// Err is a value of the type, for driving the classifier.
	Err error
	// Code is the wire code the type reports. It is asserted against the SDK's
	// own source, which is what ties this hand-written value to the declaration --
	// and it is not the type name: IAM's ConcurrentModificationException reports
	// "ConcurrentModification". A classifier matching on the code string would be
	// a second spelling of one grammar.
	Code string
	// Want is what isTransient must answer.
	Want disposition
	// Why is required for a transient decision and empty for a terminal one.
	// Terminal is the default answer for a client error; the interesting claim is
	// always the other one.
	Why string
}

// declaredSDKErrors is the decision for every error type iam and sts declare.
//
// The name carries "SDK" because compute has a declaredErrors of its own -- a
// function returning its sentinel taxonomy's population, compute/contract_test.go:653,
// checked by TestEveryDeclaredErrorIsClassified at compute/contract_test.go:769.
// Two identically-spelled identifiers with
// different subjects in one repository cost a reader and never cost a build: both
// packages compile, both tests pass go test ./..., and a grep result arrives
// WITHOUT its package -- so somebody auditing "what do we assert about declared
// errors" reads one hit and believes they have read the class. The disambiguating
// word therefore has to name the subject and be recoverable from the identifier
// alone.
//
// Generated from the SDK's own types/errors.go rather than typed, then each
// decision made by hand. Nothing may be absent and nothing may be extra; see
// TestEveryDeclaredSDKErrorIsClassified.
//
// # What "terminal" in this table claims, and what it does not
//
// It claims what isTransient answers, and isTransient is complete for the errors
// this package's fifteen AWS calls can actually produce. For the rest it is the
// default, and the table makes no claim about their semantics: iam
// CredentialReportNotReady reports ReportInProgress, which is plainly a
// wait-and-retry condition, and it is terminal here because nothing in iamAPI
// generates or reads a credential report. If a call that can reach one is ever
// added, that decision has to be revisited -- and this comment is where a reader
// finds out it was a decision rather than an oversight.
//
// The narrow claim is deliberate. A table that said "terminal means retrying
// cannot help" would be false about several rows, and a stated gap is a smaller
// liability than an implied guarantee.
//
// What the table buys is that the rows which are NOT terminal are visible with
// their reasons, and that the next error AWS adds cannot arrive as a silent
// terminal.
var declaredSDKErrors = map[string]declaredSDKError{
	"iam.AccountNotManagementOrDelegatedAdministratorException": {&iamtypes.AccountNotManagementOrDelegatedAdministratorException{}, "AccountNotManagementOrDelegatedAdministratorException", dispTerminal, ""},
	"iam.CallerIsNotManagementAccountException":                 {&iamtypes.CallerIsNotManagementAccountException{}, "CallerIsNotManagementAccountException", dispTerminal, ""},
	"iam.ConcurrentModificationException": {&iamtypes.ConcurrentModificationException{}, "ConcurrentModification", dispTransient,
		"two callers changing one entity at once; the lifecycle layer retries revokes, so two passes overlap on one user"},
	"iam.CredentialReportExpiredException":    {&iamtypes.CredentialReportExpiredException{}, "ReportExpired", dispTerminal, ""},
	"iam.CredentialReportNotPresentException": {&iamtypes.CredentialReportNotPresentException{}, "ReportNotPresent", dispTerminal, ""},
	"iam.CredentialReportNotReadyException":   {&iamtypes.CredentialReportNotReadyException{}, "ReportInProgress", dispTerminal, ""},
	"iam.DeleteConflictException":             {&iamtypes.DeleteConflictException{}, "DeleteConflict", dispTerminal, ""},
	"iam.DuplicateCertificateException":       {&iamtypes.DuplicateCertificateException{}, "DuplicateCertificate", dispTerminal, ""},
	"iam.DuplicateSSHPublicKeyException":      {&iamtypes.DuplicateSSHPublicKeyException{}, "DuplicateSSHPublicKey", dispTerminal, ""},
	"iam.EntityAlreadyExistsException":        {&iamtypes.EntityAlreadyExistsException{}, "EntityAlreadyExists", dispTerminal, ""},
	"iam.EntityTemporarilyUnmodifiableException": {&iamtypes.EntityTemporarilyUnmodifiableException{}, "EntityTemporarilyUnmodifiable", dispTransient,
		"the same race from the other side: IAM is still applying somebody else's change"},
	"iam.FeatureDisabledException":                  {&iamtypes.FeatureDisabledException{}, "FeatureDisabled", dispTerminal, ""},
	"iam.FeatureEnabledException":                   {&iamtypes.FeatureEnabledException{}, "FeatureEnabled", dispTerminal, ""},
	"iam.InvalidAuthenticationCodeException":        {&iamtypes.InvalidAuthenticationCodeException{}, "InvalidAuthenticationCode", dispTerminal, ""},
	"iam.InvalidCertificateException":               {&iamtypes.InvalidCertificateException{}, "InvalidCertificate", dispTerminal, ""},
	"iam.InvalidInputException":                     {&iamtypes.InvalidInputException{}, "InvalidInput", dispTerminal, ""},
	"iam.InvalidPublicKeyException":                 {&iamtypes.InvalidPublicKeyException{}, "InvalidPublicKey", dispTerminal, ""},
	"iam.InvalidUserTypeException":                  {&iamtypes.InvalidUserTypeException{}, "InvalidUserType", dispTerminal, ""},
	"iam.KeyPairMismatchException":                  {&iamtypes.KeyPairMismatchException{}, "KeyPairMismatch", dispTerminal, ""},
	"iam.LimitExceededException":                    {&iamtypes.LimitExceededException{}, "LimitExceeded", dispTerminal, ""},
	"iam.MalformedCertificateException":             {&iamtypes.MalformedCertificateException{}, "MalformedCertificate", dispTerminal, ""},
	"iam.MalformedPolicyDocumentException":          {&iamtypes.MalformedPolicyDocumentException{}, "MalformedPolicyDocument", dispTerminal, ""},
	"iam.NameConflictException":                     {&iamtypes.NameConflictException{}, "NameConflict", dispTerminal, ""},
	"iam.NoSuchEntityException":                     {&iamtypes.NoSuchEntityException{}, "NoSuchEntity", dispTerminal, ""},
	"iam.OpenIdIdpCommunicationErrorException":      {&iamtypes.OpenIdIdpCommunicationErrorException{}, "OpenIdIdpCommunicationError", dispTerminal, ""},
	"iam.OrganizationNotFoundException":             {&iamtypes.OrganizationNotFoundException{}, "OrganizationNotFoundException", dispTerminal, ""},
	"iam.OrganizationNotInAllFeaturesModeException": {&iamtypes.OrganizationNotInAllFeaturesModeException{}, "OrganizationNotInAllFeaturesModeException", dispTerminal, ""},
	"iam.PasswordPolicyViolationException":          {&iamtypes.PasswordPolicyViolationException{}, "PasswordPolicyViolation", dispTerminal, ""},
	"iam.PolicyEvaluationException": {&iamtypes.PolicyEvaluationException{}, "PolicyEvaluation", dispTransient,
		"IAM's own policy evaluator failed rather than the policy being bad; FaultServer, so the fault check reaches it without knowing the code"},
	"iam.PolicyNotAttachableException":           {&iamtypes.PolicyNotAttachableException{}, "PolicyNotAttachable", dispTerminal, ""},
	"iam.ReportGenerationLimitExceededException": {&iamtypes.ReportGenerationLimitExceededException{}, "ReportGenerationLimitExceeded", dispTerminal, ""},
	"iam.RoleModifiedException":                  {&iamtypes.RoleModifiedException{}, "RoleModified", dispTerminal, ""},
	"iam.RoleTemplateDisabledException":          {&iamtypes.RoleTemplateDisabledException{}, "RoleTemplateDisabled", dispTerminal, ""},
	"iam.ServiceAccessNotEnabledException":       {&iamtypes.ServiceAccessNotEnabledException{}, "ServiceAccessNotEnabledException", dispTerminal, ""},
	"iam.ServiceFailureException": {&iamtypes.ServiceFailureException{}, "ServiceFailure", dispTransient,
		"IAM's own 500; FaultServer, so the fault check reaches it without knowing the code"},
	"iam.ServiceNotSupportedException":           {&iamtypes.ServiceNotSupportedException{}, "NotSupportedService", dispTerminal, ""},
	"iam.UnmodifiableEntityException":            {&iamtypes.UnmodifiableEntityException{}, "UnmodifiableEntity", dispTerminal, ""},
	"iam.UnrecognizedPublicKeyEncodingException": {&iamtypes.UnrecognizedPublicKeyEncodingException{}, "UnrecognizedPublicKeyEncoding", dispTerminal, ""},
	"sts.ExpiredTokenException": {&ststypes.ExpiredTokenException{}, "ExpiredTokenException", dispTransient,
		"the minted web identity token aged out before STS read it; a retry mints a fresh one"},
	"sts.ExpiredTradeInTokenException": {&ststypes.ExpiredTradeInTokenException{}, "ExpiredTradeInTokenException", dispTerminal, ""},
	"sts.IDPCommunicationErrorException": {&ststypes.IDPCommunicationErrorException{}, "IDPCommunicationError", dispTransient,
		"STS could not reach the identity provider; nothing about the request would change that"},
	"sts.IDPRejectedClaimException": {&ststypes.IDPRejectedClaimException{}, "IDPRejectedClaim", dispTransient,
		"the SDK documents this as possibly meaning the claim expired, which a fresh mint fixes; possibly revoked, which it does not, and transient is the safe side of an ambiguity bounded retry ends"},
	"sts.InvalidAuthorizationMessageException": {&ststypes.InvalidAuthorizationMessageException{}, "InvalidAuthorizationMessageException", dispTerminal, ""},
	"sts.InvalidIdentityTokenException": {&ststypes.InvalidIdentityTokenException{}, "InvalidIdentityToken", dispTransient,
		"the SDK's own text prescribes the remedy -- get a new identity token and retry -- and this provider mints one per attempt"},
	"sts.JWTPayloadSizeExceededException":                {&ststypes.JWTPayloadSizeExceededException{}, "JWTPayloadSizeExceededException", dispTerminal, ""},
	"sts.MalformedPolicyDocumentException":               {&ststypes.MalformedPolicyDocumentException{}, "MalformedPolicyDocument", dispTerminal, ""},
	"sts.OutboundWebIdentityFederationDisabledException": {&ststypes.OutboundWebIdentityFederationDisabledException{}, "OutboundWebIdentityFederationDisabledException", dispTerminal, ""},
	"sts.PackedPolicyTooLargeException":                  {&ststypes.PackedPolicyTooLargeException{}, "PackedPolicyTooLarge", dispTerminal, ""},
	"sts.RegionDisabledException":                        {&ststypes.RegionDisabledException{}, "RegionDisabledException", dispTerminal, ""},
	"sts.SessionDurationEscalationException":             {&ststypes.SessionDurationEscalationException{}, "SessionDurationEscalationException", dispTerminal, ""},
}

// sdkErrorSource locates the SDK source for one service, at the version this
// module pins.
//
// It asks the toolchain for the module cache rather than guessing a path, which is
// the same choice internal/boundary/load.go made for the import graph: the
// toolchain's answer is the one the build actually used. A path it cannot resolve
// is fatal, never skipped -- a skip here would turn the whole population below
// into a vacuous pass.
func sdkErrorSource(t *testing.T, service string) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("asking the toolchain for GOMODCACHE: %v", err)
	}
	cache := strings.TrimSpace(string(out))
	if cache == "" {
		t.Fatal("GOMODCACHE is empty; this population cannot be derived and must not be skipped")
	}
	modPath := "github.com/aws/aws-sdk-go-v2/service/" + service
	version := moduleVersion(t, modPath)
	return filepath.Join(cache, filepath.FromSlash(modPath)+"@"+version, "types", "errors.go")
}

// moduleVersion reads a require line out of go.mod.
var requireLine = regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta("github.com/aws/aws-sdk-go-v2/service/") + `(\w+) (v[^\s]+)`)

func moduleVersion(t *testing.T, modPath string) string {
	t.Helper()
	data, readErr := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if readErr != nil {
		t.Fatalf("reading go.mod: %v", readErr)
	}
	want := strings.TrimPrefix(modPath, "github.com/aws/aws-sdk-go-v2/service/")
	for _, m := range requireLine.FindAllStringSubmatch(string(data), -1) {
		if m[1] == want {
			return m[2]
		}
	}
	t.Fatalf("go.mod does not require %s; the derivation has nothing to read", modPath)
	return ""
}

// declaredCodes parses one service's generated errors.go.
//
// Every ErrorCode method must be matched. The count of matched methods is compared
// with the count of ErrorCode declarations in the file, so a generated form this
// parser does not recognise is a failure rather than a member of the population
// that quietly went missing.
func declaredCodes(t *testing.T, service string) map[string]string {
	t.Helper()
	path := sdkErrorSource(t, service)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := map[string]string{}
	declarations := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "ErrorCode" {
			continue
		}
		declarations++
		typeName := receiverTypeName(fn.Recv.List[0].Type)
		if typeName == "" {
			t.Fatalf("%s: cannot name the receiver of an ErrorCode method", path)
		}
		code, ok := literalReturn(fn)
		if !ok {
			t.Fatalf("%s: %s.ErrorCode has a shape this parser does not recognise; the "+
				"population is incomplete and that is a failure, not an omission", path, typeName)
		}
		out[typeName] = code
	}
	if declarations == 0 {
		t.Fatalf("%s declares no ErrorCode methods; the derivation would be vacuous", path)
	}
	if len(out) != declarations {
		t.Fatalf("%s: parsed %d of %d ErrorCode methods", path, len(out), declarations)
	}
	return out
}

// literalReturn finds the first string literal returned in a function body.
//
// The generated shape is a nil-or-override guard returning the code, then the
// override. Taking the first literal is not a guess about that shape: any body
// with no string literal at all fails above, and the assertion in
// TestEveryDeclaredSDKErrorIsClassified compares this against what the constructed
// value's own ErrorCode method actually returns -- so a literal read out of the
// wrong branch would disagree with the SDK and fail.
func literalReturn(fn *ast.FuncDecl) (string, bool) {
	var found string
	var ok bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ok {
			return false
		}
		lit, isLit := n.(*ast.BasicLit)
		if !isLit || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		found, ok = value, true
		return false
	})
	return found, ok
}

// TestEveryDeclaredSDKErrorIsClassified is the population that found
// isConsistencyRace missing.
func TestEveryDeclaredSDKErrorIsClassified(t *testing.T) {
	t.Parallel()

	derived := map[string]string{}
	for _, service := range []string{"iam", "sts"} {
		for typeName, code := range declaredCodes(t, service) {
			derived[service+"."+typeName] = code
		}
	}
	if len(derived) == 0 {
		t.Fatal("derived no declared error types")
	}

	var missing, stale []string
	for key := range derived {
		if _, ok := declaredSDKErrors[key]; !ok {
			missing = append(missing, key)
		}
	}
	for key := range declaredSDKErrors {
		if _, ok := derived[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("the SDK declares error types this package has made no decision about: %s",
			strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("decisions for error types the SDK no longer declares: %s", strings.Join(stale, ", "))
	}

	transient := 0
	for key, decided := range declaredSDKErrors {
		wantCode, ok := derived[key]
		if !ok {
			continue
		}
		// The constructed value must be the type the SDK declares under that name.
		// Without this the table could hold a value that classifies differently
		// from the thing it claims to represent, and every assertion below would
		// be about the wrong object.
		// errors.As rather than a type assertion, and the linter is right to insist:
		// a bare assertion only sees the top of the chain, which is the same defect
		// this whole file is about one level down.
		var api smithy.APIError
		if !errors.As(decided.Err, &api) {
			t.Errorf("%s: the value in the table is not a smithy.APIError", key)
			continue
		}
		if got := api.ErrorCode(); got != wantCode {
			t.Errorf("%s: the table says the code is %q, the value reports %q, the SDK source says %q",
				key, decided.Code, got, wantCode)
		}
		if decided.Code != wantCode {
			t.Errorf("%s: the table's recorded code %q is not the SDK's %q", key, decided.Code, wantCode)
		}

		gotTransient := isTransient(decided.Err)
		wantTransient := decided.Want == dispTransient
		if gotTransient != wantTransient {
			t.Errorf("%s (%s): isTransient = %v, want %v (%s)", key, wantCode, gotTransient,
				wantTransient, decided.Why)
		}
		switch decided.Want {
		case dispTransient:
			transient++
			if decided.Why == "" {
				t.Errorf("%s is classified transient with no reason recorded", key)
			}
		case dispTerminal:
			if decided.Why != "" {
				t.Errorf("%s is terminal and carries a reason; terminal is the default and the "+
					"reason belongs on the exceptions", key)
			}
		default:
			t.Errorf("%s has the unrecognised disposition %q", key, decided.Want)
		}
	}

	// Both directions have to be non-empty, or the property is about one pole.
	if transient == 0 {
		t.Error("no declared error is classified transient; a classifier that answers terminal " +
			"to everything would pass every other assertion here")
	}
	if transient == len(declaredSDKErrors) {
		t.Error("every declared error is classified transient")
	}
	t.Logf("classified %d declared error types across iam and sts: %d transient, %d terminal",
		len(declaredSDKErrors), transient, len(declaredSDKErrors)-transient)
}

// atomicPredicateExceptions are the predicates in fault.go that are deliberately
// NOT atomic, with the reason each one is not. Everything else must match at most
// one AWS error type; see TestTheTypedErrorPredicatesAreDisjoint.
//
// A predicate absent from here and from the atomic wiring is fatal. A predicate
// present here and gone from fault.go is fatal. And an entry with an EMPTY REASON is
// fatal -- review moved isNoSuchEntity into this map with no reason at all, and the
// first version of this test accepted it and reported 8 of 45 instead of 9. A
// carve-out that can be extended silently is not a carve-out, it is a hole.
var atomicPredicateExceptions = map[string]string{
	"isTransient": "the top-level classification; it deliberately answers true for " +
		"everything the others match, plus faults and statuses",
	"isWebIdentityRetryable": "the union of the four web-identity predicates, which is " +
		"the whole point of it",
}

// expectedPredicateMatches is the population the disjointness property runs over,
// asserted rather than printed.
//
// It exists because "9 of 45" was decoration. Moving a predicate out of the atomic
// set took it to 8 of 45 and nothing failed -- the number was logged, and a logged
// number is compared to nothing. So the mapping is stated and checked in both
// directions, and the count is a consequence of it rather than a claim of its own.
//
// Each entry says which single atomic predicate an AWS error type matches. A type
// matching none is not listed; a type matching two fails the disjointness property
// itself.
var expectedPredicateMatches = map[string]string{
	"iam.ConcurrentModificationException":        "isConsistencyRace",
	"iam.DeleteConflictException":                "isDeleteConflict",
	"iam.EntityAlreadyExistsException":           "isEntityAlreadyExists",
	"iam.EntityTemporarilyUnmodifiableException": "isConsistencyRace",
	"iam.NoSuchEntityException":                  "isNoSuchEntity",
	"sts.ExpiredTokenException":                  "isExpiredSTSToken",
	"sts.IDPCommunicationErrorException":         "isIdentityProviderUnreachable",
	"sts.IDPRejectedClaimException":              "isIdentityProviderRejectedClaim",
	"sts.InvalidIdentityTokenException":          "isInvalidIdentityToken",
}

// TestTheTypedErrorPredicatesAreDisjoint is what the switch in Provider.assume
// actually relies on, and it exists because the comments there claimed something
// else.
//
// Those comments said the order of the switch cases was load-bearing and asserted.
// Review falsified that: swapping the expired and invalid cases -- each with its
// body -- compiles and leaves every test green, including the one the comment named.
// The order is irrelevant *because the predicates are disjoint*, so the disjointness
// is the property worth having, and a comment claiming the order decides anything
// was a claim nothing checked.
//
// That is the same defect this package's citation gate was written for, one artefact
// in: a statement adjacent to the code, believed because it is adjacent, supported
// by nothing. It was written in a comment about that very class.
//
// # What is asserted
//
// Three things, and the second and third are what the first version lacked:
//
//  1. no AWS error type matches more than one atomic predicate;
//  2. every is* function in fault.go is either wired as atomic or excepted with a
//     non-empty reason, and a signature the wiring cannot express is fatal rather
//     than skipped;
//  3. the set of types that match, and which predicate each matches, is exactly
//     expectedPredicateMatches -- so the population cannot shrink quietly.
//
// # What it does not cover
//
// It does not claim the predicates are disjoint over arbitrary error chains.
// errors.As walks a chain, so an error carrying both an ExpiredTokenException and an
// InvalidIdentityTokenException matches two predicates, and the case order would
// then decide which sentinel a caller gets.
//
// Two separate facts bound how far that reaches, and they bound different things:
//
//   - What the SDK returns is one typed error per response, so the disjointness
//     above is the whole answer for an unmodified client.
//   - What this package constructs joins errors at four sites -- errors.Join at
//     none, fmt.Errorf with two or more %w at four -- and none carries two AWS typed
//     errors: three join this package's own sentinels, and the fourth joins two wrap
//     results, which propagate the underlying error only on the context-cancelled
//     branch. Established by search over all four sites, not by assumption.
//
// Neither covers what remains: NewProvider takes its clients from the composition
// root, so a caller-supplied client wrapping its own errors could hand this code a
// joined chain. This test cannot see that, and the order would decide it.
func TestTheTypedErrorPredicatesAreDisjoint(t *testing.T) {
	t.Parallel()

	predicates := map[string]func(error) bool{
		"isNoSuchEntity":                  isNoSuchEntity,
		"isEntityAlreadyExists":           isEntityAlreadyExists,
		"isDeleteConflict":                isDeleteConflict,
		"isConsistencyRace":               isConsistencyRace,
		"isInvalidIdentityToken":          isInvalidIdentityToken,
		"isExpiredSTSToken":               isExpiredSTSToken,
		"isIdentityProviderRejectedClaim": isIdentityProviderRejectedClaim,
		"isIdentityProviderUnreachable":   isIdentityProviderUnreachable,
	}

	// (2) Account for every is* declaration, whatever its signature.
	decls := errorPredicateDecls(t)
	if len(decls) == 0 {
		t.Fatal("derived no predicates")
	}
	byName := map[string]predicateDecl{}
	for _, d := range decls {
		byName[d.Name] = d
		_, atomic := predicates[d.Name]
		reason, excepted := atomicPredicateExceptions[d.Name]
		switch {
		case atomic && excepted:
			t.Errorf("%s is both wired as atomic and named as an exception", d.Name)
		case !atomic && !excepted:
			t.Errorf("fault.go declares %s %s and this test has no decision about whether it "+
				"is atomic; an unclassified predicate is how a disjointness claim goes vacuous",
				d.Name, d.Signature)
		case excepted && strings.TrimSpace(reason) == "":
			t.Errorf("%s is excepted from the atomic set with no reason recorded; a carve-out "+
				"that can be extended silently is a hole", d.Name)
		}
		// A signature the atomic wiring cannot express must be excepted, not atomic.
		// This is what closes the variadic variant review escaped the first version
		// with: it is not canonical, so it cannot be atomic, so it must be named.
		if !d.Canonical && atomic {
			t.Errorf("%s is wired as atomic and its signature %s is not func(error) bool",
				d.Name, d.Signature)
		}
		if !d.Canonical && !excepted {
			t.Errorf("fault.go declares %s with signature %s, which the atomic wiring cannot "+
				"express, and it is not named as an exception -- so nothing checks it",
				d.Name, d.Signature)
		}
	}
	for name := range predicates {
		if _, ok := byName[name]; !ok {
			t.Errorf("fault.go no longer declares %s", name)
		}
	}
	for name := range atomicPredicateExceptions {
		if _, ok := byName[name]; !ok {
			t.Errorf("the exception for %s has no input; fault.go no longer declares it", name)
		}
	}

	// (1) and (3): disjointness, and the population it runs over.
	observed := map[string]string{}
	for key, decided := range declaredSDKErrors {
		var hits []string
		for name, fn := range predicates {
			if fn(decided.Err) {
				hits = append(hits, name)
			}
		}
		sort.Strings(hits)
		switch len(hits) {
		case 0:
		case 1:
			observed[key] = hits[0]
		default:
			t.Errorf("%s matches %d atomic predicates (%s); the switch in assume would then "+
				"depend on its case order", key, len(hits), strings.Join(hits, ", "))
		}
	}

	for key, want := range expectedPredicateMatches {
		got, ok := observed[key]
		switch {
		case !ok:
			t.Errorf("%s is expected to match %s and matches nothing; a predicate has been "+
				"narrowed or removed", key, want)
		case got != want:
			t.Errorf("%s matches %s, expected %s", key, got, want)
		}
	}
	for key, got := range observed {
		if _, ok := expectedPredicateMatches[key]; !ok {
			t.Errorf("%s matches %s and is not in the expected set; a predicate has been "+
				"widened", key, got)
		}
	}
	if len(observed) != len(expectedPredicateMatches) {
		t.Errorf("%d types match a predicate and %d are expected to",
			len(observed), len(expectedPredicateMatches))
	}
	// Non-emptiness in the direction that matters: "at most one" is vacuously true
	// over an empty match set.
	if len(observed) == 0 {
		t.Fatal("no declared error matched any predicate; the disjointness above is vacuous")
	}
	t.Logf("%d of %d declared error types match exactly one atomic predicate, asserted as a set",
		len(observed), len(declaredSDKErrors))
}

// expectedSwitchPredicates is the set of predicates the error switch in
// Provider.assume dispatches on, asserted from the switch itself.
//
// This is the usage side. atomicPredicateExceptions and the wiring above are the
// declaration side, and the difference is the whole reason this exists: review
// escaped a declaration census with
//
//	var isReviewPredicate = func(error) bool { ... }
//
// called from the switch's invalid case. It matched both expired and invalid, so the
// case ORDER became load-bearing in production code -- the exact property this file
// exists to establish became false -- and every test passed, because a var bound to
// a func literal is not a FuncDecl and a FuncDecl inventory cannot see one.
//
// The first four escapes on this project were all "recognise a declaration": a
// spelling, an alias, a defined type, a signature variant. This one is not a
// declaration at all, and no fifth spelling would have caught it. So the gate stops
// asking what is declared and asks what the switch CALLS.
var expectedSwitchPredicates = []string{
	"isExpiredSTSToken",
	"isIdentityProviderRejectedClaim",
	"isInvalidIdentityToken",
}

// TestTheErrorSwitchDispatchesOnlyOnCheckedPredicates derives the callees of the
// switch and requires every one to be a predicate whose disjointness is checked.
//
// # Every unresolvable callee shape is fatal
//
// A case callee that is not a plain top-level function in this package stops the
// test rather than being skipped. That is what closes the open-ended tail: a
// package-level var, a method value, a struct field, whatever a factory returns --
// none of them can be inventoried by a declaration walk, and there is no list of
// shapes to keep extending. The gate has two outcomes on every callee, resolved or
// fatal.
func TestTheErrorSwitchDispatchesOnlyOnCheckedPredicates(t *testing.T) {
	t.Parallel()

	files, fset := sourceFilesWithFset(t)

	// The package's own declaration inventory, so an unresolved callee can be
	// diagnosed rather than merely rejected: a var reads differently from a typo.
	funcs := map[string]bool{}
	vars := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					funcs[d.Name.Name] = true
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, n := range vs.Names {
						vars[n.Name] = true
					}
				}
			}
		}
	}
	if len(funcs) == 0 {
		t.Fatal("found no top-level functions; the inventory is empty")
	}

	dynamic, ok := files["dynamic.go"]
	if !ok {
		t.Fatal("dynamic.go is gone; this derivation has nothing to read, which is a failure")
	}
	assume := findFuncDecl(t, dynamic, "assume")

	// Every switch in assume, and every callee in every case expression.
	callees := map[string]bool{}
	switches := 0
	ast.Inspect(assume, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		switches++
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				t.Fatalf("a switch in assume holds a %T, which this derivation cannot read", stmt)
			}
			for _, expr := range clause.List {
				collectCallees(t, fset, expr, funcs, vars, callees)
			}
		}
		return true
	})
	if switches == 0 {
		t.Fatal("found no switch in assume; the derivation would be vacuous")
	}
	if len(callees) == 0 {
		t.Fatal("found no predicate calls in assume's switch cases")
	}

	// The wiring whose disjointness TestTheTypedErrorPredicatesAreDisjoint checks.
	checked := map[string]bool{}
	for key := range expectedPredicateMatches {
		checked[expectedPredicateMatches[key]] = true
	}

	var got []string
	for name := range callees {
		got = append(got, name)
		if !checked[name] {
			t.Errorf("assume's switch dispatches on %s, whose disjointness nothing checks; "+
				"the order of the cases is load-bearing until it does", name)
		}
	}
	sort.Strings(got)

	want := append([]string(nil), expectedSwitchPredicates...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("assume's switch dispatches on [%s]; expected [%s]",
			strings.Join(got, ", "), strings.Join(want, ", "))
	}
	t.Logf("assume's switch dispatches on %d predicates, all with checked disjointness: %s",
		len(got), strings.Join(got, ", "))
}

// findFuncDecl returns the named function or method, and fails if it is absent.
func findFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("no function named %s; this derivation has nothing to read", name)
	return nil
}

// collectCallees records the name of every function called in expr, and fails on
// any callee shape it cannot resolve to a top-level function in this package.
func collectCallees(t *testing.T, fset *token.FileSet, expr ast.Expr, funcs, vars map[string]bool, into map[string]bool) {
	t.Helper()
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		where := fset.Position(call.Pos())
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			switch {
			case funcs[fn.Name]:
				into[fn.Name] = true
			case vars[fn.Name]:
				t.Errorf("%s: the switch calls %s, which is a package-level VAR and not a "+
					"function declaration. A declaration census cannot inventory it, so its "+
					"disjointness is unchecked and the case order is load-bearing. Make it a "+
					"func, or the gate cannot see it", where, fn.Name)
			default:
				t.Errorf("%s: the switch calls %s, which this package does not declare at the "+
					"top level; this derivation cannot resolve it and will not skip it",
					where, fn.Name)
			}
		default:
			t.Errorf("%s: the switch calls a %T, which is not a plain function call -- a method "+
				"value, a field, or whatever a factory returned. This derivation cannot resolve "+
				"it to something whose disjointness is checked, so it fails rather than skipping",
				where, call.Fun)
		}
		return true
	})
}

// conditionCalleesThisPackageMakes is every non-package callee that appears in a
// CONDITION in this package's non-test files, each with the reason it is not a
// predicate whose disjointness needs checking.
//
// It is an allowlist rather than a skip, and that distinction is the whole fix. The
// first version of the census below CONTINUED past every non-Ident callee, with a
// comment arguing that flagging method calls "would make this test about something
// else". Review defeated that with a method predicate --
//
//	p.isReviewPredicate(err)   matching both DeleteConflict and NoSuchEntity
//
// -- in static teardown. The if order became load-bearing, all three guards passed,
// and the census logged "every one classified" over the sites it could resolve. So
// the population had become the directory while the RESOLUTION RULE stayed local:
// resolve-or-fail inside assume, skip-what-you-cannot-name everywhere else. A filter
// had become the denominator.
//
// Every entry here was read off the tree rather than guessed; a callee that is not
// on this list and is not a package function is fatal, so adding one is a decision
// somebody makes by editing this map.
//
// The keys carry a trailing "()" because these are CALLS rather than field reads,
// and because without it the clock accessor -- Provider.now, two lowercase labels --
// is a token that is the whole of a Go string literal, which the repository's secret
// scan correctly reads as a hostname assigned as a value. The standing ruling on that
// class is to rename rather than to loosen the rule, since a recogniser relaxed to
// clear a false positive stops catching the thing it is for. Naming a call as a call
// is the honest rename.
//
// This comment was itself the second finding: the first wording quoted the bare
// selector, and a quoted two-label token is the shape whatever surrounds it. Writing
// about the class is not an exemption from it.
var conditionCalleesThisPackageMakes = map[string]string{
	"errors.As()":         "the standard library's error inspection, which is how every predicate here is built",
	"errors.Is()":         "sentinel comparison against this package's own errors",
	"strings.Contains()":  "handle parsing, not error classification",
	"strings.HasPrefix()": "handle parsing, not error classification",
	"strings.TrimSpace()": "configuration and name normalisation",
	"awssdk.ToString()":   "dereferences an SDK pointer field; no classification",
	"api.ErrorFault()":    "smithy's fault accessor, read inside isTransient rather than being a predicate",
	"api.ErrorCode()": "smithy's wire-code accessor, read inside isTransient and handed to " +
		"awscode.IsRetryable. It is the reason this whole file exists: the code is what AWS " +
		"sends, and the Go type name -- which is what two reviewers matched on instead -- is not it",
	"awscode.IsRetryable()": "a set membership test on a string, in internal/awscode. It " +
		"classifies a CODE and not an error, so it has no error type to be disjoint from: it " +
		"cannot see a wrapper, a fault or a status, and isTransient reaches it only after " +
		"errors.As has already produced the smithy.APIError. USOSS-63 moved the set there from " +
		"this file so compute/aws could stop keeping a second copy of it",
	"iamNameRunes.MatchString()": "IAM name grammar validation",
	"pattern.MatchString()":      "configuration grammar validation",
	"p.now()":                    "the injected clock, so expiry comparisons are testable",
	"token.IsZero()":             "credentials.Secret emptiness, which is not an error",
	"<call>.Before()":            "time comparison on a value returned by the call before it",
}

// builtinsInConditions are the Go builtins permitted in a condition. Named for the
// same reason: a builtin is not resolvable as a package function, so without this it
// would be fatal, and a silent exemption is what this test exists to remove.
var builtinsInConditions = map[string]string{
	"len": "length comparison; cannot classify an error",
}

// TestEveryConditionCalleeResolvesOrFails is the package-wide resolve-or-fatal.
//
// # Why the population is conditions rather than switches, and rather than all calls
//
// A switch derivation reads one dispatch shape. This package dispatches on these
// predicates in eleven switches and, more to the point, in plain ifs: static.go
// alone has nine isNoSuchEntity guards that no switch derivation reaches. So the
// subject is every condition in the directory.
//
// Not every call, because that would be about something other than error
// classification -- but every callee IN a condition, because a condition is where an
// error becomes a branch, and a branch is where order becomes load-bearing.
//
// # There is no skip
//
// An Ident must resolve to a top-level function in this package or a named builtin.
// A selector must be on conditionCalleesThisPackageMakes. Anything else -- an index
// expression selecting a predicate from a map, a call returning a func, a type
// conversion -- is FATAL. That is what closes the tail rather than adding a case for
// each shape review finds next, and five altitudes of this defect say the tail is
// otherwise endless.
//
// # And an is* callee must additionally be classified
//
// Resolving is necessary and not sufficient: a resolvable predicate whose
// disjointness nothing checks still makes the order load-bearing.
func TestEveryConditionCalleeResolvesOrFails(t *testing.T) {
	t.Parallel()

	files, fset := sourceFilesWithFset(t)

	funcs := map[string]bool{}
	vars := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					funcs[d.Name.Name] = true
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							vars[n.Name] = true
						}
					}
				}
			}
		}
	}

	checked := map[string]bool{}
	for _, name := range expectedPredicateMatches {
		checked[name] = true
	}
	for name := range atomicPredicateExceptions {
		checked[name] = true
	}
	if len(checked) == 0 {
		t.Fatal("no predicate is classified; this check would pass over anything")
	}

	sites, predicateSites := 0, 0
	filesWithSites := map[string]bool{}

	inspect := func(file string, expr ast.Expr) {
		if expr == nil {
			return
		}
		ast.Inspect(expr, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sites++
			filesWithSites[file] = true
			where := fset.Position(call.Pos())
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				switch {
				case vars[fn.Name]:
					t.Errorf("%s: a condition calls %s, which is a package-level VAR; a "+
						"declaration census cannot inventory it, so nothing checks it", where, fn.Name)
				case funcs[fn.Name]:
					if strings.HasPrefix(fn.Name, "is") {
						predicateSites++
						if !checked[fn.Name] {
							t.Errorf("%s: a condition calls %s, which is neither an atomic "+
								"predicate whose disjointness is checked nor a named exception",
								where, fn.Name)
						}
					}
				case builtinsInConditions[fn.Name] != "":
				default:
					t.Errorf("%s: a condition calls %s, which this package does not declare and "+
						"which is not a named builtin; this derivation will not skip what it "+
						"cannot resolve", where, fn.Name)
				}
			case *ast.SelectorExpr:
				name := renderSelector(fn)
				if _, ok := conditionCalleesThisPackageMakes[name]; !ok {
					t.Errorf("%s: a condition calls %s, which is not on the decided list of "+
						"non-predicate condition callees. If it cannot classify an error, add it "+
						"with the reason; if it can, it needs its disjointness checked. A method "+
						"predicate is exactly how the previous version of this census was "+
						"defeated", where, name)
				}
			default:
				t.Errorf("%s: a condition calls a %T, which this derivation cannot resolve to "+
					"anything whose disjointness is checked -- an index expression, a call "+
					"returning a func, or a conversion. It fails rather than skipping", where, call.Fun)
			}
			return true
		})
	}

	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.IfStmt:
				inspect(name, s.Cond)
			case *ast.SwitchStmt:
				inspect(name, s.Tag)
			case *ast.CaseClause:
				for _, e := range s.List {
					inspect(name, e)
				}
			case *ast.ForStmt:
				inspect(name, s.Cond)
			}
			return true
		})
	}

	if sites == 0 {
		t.Fatal("found no condition callees; this check ran over nothing")
	}
	if predicateSites == 0 {
		t.Fatal("found no predicate call in any condition; the classification above is vacuous")
	}
	// An entry that no longer matches anything is a rule with no input.
	t.Logf("resolved %d condition callees across %d of %d source files; %d are predicate calls",
		sites, len(filesWithSites), len(files), predicateSites)
}

// renderSelector renders a selector callee stably, and names an unrenderable
// receiver rather than dropping it.
func renderSelector(s *ast.SelectorExpr) string {
	switch x := s.X.(type) {
	case *ast.Ident:
		return x.Name + "." + s.Sel.Name + "()"
	case *ast.SelectorExpr:
		return strings.TrimSuffix(renderSelector(x), "()") + "." + s.Sel.Name + "()"
	case *ast.CallExpr:
		return "<call>." + s.Sel.Name + "()"
	default:
		return "<unrenderable>." + s.Sel.Name + "()"
	}
}
