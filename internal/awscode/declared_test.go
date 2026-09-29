// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package awscode

import (
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
)

// This file is the guard the package comment promises: it enumerates every place
// an AWS error type's Go NAME and its wire CODE disagree about membership of this
// package's set, over every AWS service this module depends on, and requires a
// recorded decision for each.
//
// It exists because reading a type name as a wire code has cost this repository
// two review rounds in two packages, both times on the same type name, and both
// times the reader had no way to see the population they were reasoning about. A
// comment saying "the type name is not the code" is a comment; this is the list.
//
// The population is derived from the SDK's own generated source rather than from
// the SDK's Go API, which is what lets it live here: this package imports nothing
// from github.com/aws, so internal/boundary's aws-sdk-confined rule -- which
// counts test imports -- does not have to be widened to accommodate a shared
// table. Reading errors.go as text asks the same question of the same authority.

// trap is one error type whose Go name and wire code give different answers to
// [IsRetryable].
type trap struct {
	// Service is the SDK service package the type is declared in.
	Service string
	// TypeName is the generated Go type's name.
	TypeName string
	// Code is what that type's ErrorCode method actually returns.
	Code string
	// ByName is [IsRetryable] applied to TypeName -- the answer a reader gets
	// when they match on the type instead of the code.
	ByName bool
	// ByCode is [IsRetryable] applied to Code -- the answer this repository
	// actually gives, because every classifier here keys on ErrorCode().
	ByCode bool
	// Why records what going the wrong way costs, because a trap with no stated
	// consequence reads as trivia and gets deleted as noise.
	Why string
}

// typeNameTraps is the decided population.
//
// Nothing may be missing and nothing may be extra: a type AWS adds whose name and
// code disagree is a test failure here rather than an ambush in review, and an
// entry for a type the SDK no longer declares is a failure too.
//
// It is two, and the two run in opposite directions. That is the reason to state
// them together rather than to write the IAM one down where it was found: every
// argument this repository has had about this class of bug has been about IAM, so
// the IAM entry alone reads as a fact about IAM. The elbv2 entry says it is a
// fact about generated code.
var typeNameTraps = map[string]trap{
	"iam.LimitExceededException": {
		Service: "iam", TypeName: "LimitExceededException", Code: "LimitExceeded",
		ByName: true, ByCode: false,
		Why: "matching the type makes an IAM quota exhaustion retryable, which is not what a " +
			"quota is and not what the SDK says; this exact 'fix' was written and reverted twice, " +
			"in compute/aws and again in credentials/aws, and ecrtypes.LimitExceededException -- " +
			"same Go name, code 'LimitExceededException' -- is why it looked right both times",
	},
	"elasticloadbalancingv2.PriorRequestNotCompleteException": {
		Service: "elasticloadbalancingv2", TypeName: "PriorRequestNotCompleteException",
		Code: "PriorRequestNotComplete", ByName: false, ByCode: true,
		Why: "the mirror image, and the one nobody had noticed: matching the type would classify " +
			"a retryable ELBv2 condition terminal, telling a caller its spec has to change while " +
			"the previous request finishes. compute/aws holds an ELBv2 client, so it is live",
	},
}

// servicesWithNoDeclaredErrors are the SDK service packages that ship no
// types/errors.go at all, each with the reason.
//
// Named rather than skipped. A missing file that the walk shrugged at would take
// a whole service out of the population without anybody being told, which is the
// same failure as an unchecked copy one level up.
var servicesWithNoDeclaredErrors = map[string]string{
	"ec2": "EC2 is a query-protocol service and the SDK models none of its errors as Go " +
		"types; there is no types/errors.go to read, so there are no type names that could " +
		"be mistaken for codes",
}

var serviceRequire = regexp.MustCompile(`(?m)^\s*github\.com/aws/aws-sdk-go-v2/service/([a-z0-9]+) (v[^\s]+)`)

// awsServices reads every AWS service module this repository requires, with its
// pinned version, out of go.mod.
//
// Derived rather than listed, for the reason a list is the wrong shape for this:
// a service added to go.mod tomorrow must join the population without anybody
// remembering to add it here, and that is exactly the maintenance failure the
// converged table exists to end.
//
// Indirect requirements are included. A transitively-pulled service's error types
// are as capable of colliding with a code as a direct one's, and excluding them
// would make the population a claim about what this repository imports rather than
// about what its dependency closure can name.
func awsServices(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	out := map[string]string{}
	for _, m := range serviceRequire.FindAllStringSubmatch(string(data), -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("go.mod requires no AWS service module; the population would be vacuous")
	}
	return out
}

// declaredCodes parses one service's generated errors.go into type name -> wire code.
//
// Every ErrorCode method must be matched: the count of matched methods is compared
// with the count of declarations, so a generated shape this parser does not
// recognise is a failure rather than a member of the population that quietly went
// missing. It returns nil, false when the service declares no errors at all, which
// the caller must account for by name.
func declaredCodes(t *testing.T, cache, service, version string) (map[string]string, bool) {
	t.Helper()
	path := filepath.Join(cache, filepath.FromSlash("github.com/aws/aws-sdk-go-v2/service/"+service)+
		"@"+version, "types", "errors.go")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := map[string]string{}
	declarations := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "ErrorCode" || len(fn.Recv.List) == 0 {
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
		t.Fatalf("%s exists and declares no ErrorCode methods; the derivation would be vacuous", path)
	}
	if len(out) != declarations {
		t.Fatalf("%s: parsed %d of %d ErrorCode methods", path, len(out), declarations)
	}
	return out, true
}

func receiverTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// literalReturn finds the first string literal returned in a function body. The
// generated shape is a nil-or-override guard returning the code, then the
// override; a body with no string literal at all is fatal above.
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

// TestATypeNameIsNotAWireCode is the guard against the mistake in the package
// comment being made a third time.
func TestATypeNameIsNotAWireCode(t *testing.T) {
	t.Parallel()

	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("asking the toolchain for GOMODCACHE: %v", err)
	}
	cache := strings.TrimSpace(string(out))
	if cache == "" {
		t.Fatal("GOMODCACHE is empty; this population cannot be derived and must not be skipped")
	}

	services := awsServices(t)
	found := map[string]trap{}
	scanned, withErrors := 0, 0
	for service, version := range services {
		codes, ok := declaredCodes(t, cache, service, version)
		if !ok {
			if _, named := servicesWithNoDeclaredErrors[service]; !named {
				t.Errorf("%s ships no types/errors.go and no reason is recorded for it; a "+
					"service dropping out of this population silently is the failure this "+
					"test exists to prevent", service)
			}
			continue
		}
		withErrors++
		for typeName, code := range codes {
			scanned++
			byName, byCode := IsRetryable(typeName), IsRetryable(code)
			if byName == byCode {
				continue
			}
			found[service+"."+typeName] = trap{
				Service: service, TypeName: typeName, Code: code, ByName: byName, ByCode: byCode,
			}
		}
	}
	if scanned == 0 || withErrors == 0 {
		t.Fatal("derived no declared error types; the property would hold vacuously")
	}
	for service := range servicesWithNoDeclaredErrors {
		if _, required := services[service]; !required {
			t.Errorf("a reason is recorded for %s and go.mod no longer requires it; an "+
				"exclusion with no input is a hole rather than a carve-out", service)
		}
	}

	var missing, stale []string
	for key, got := range found {
		decided, ok := typeNameTraps[key]
		if !ok {
			missing = append(missing, key+" (code "+got.Code+")")
			continue
		}
		if decided.Code != got.Code || decided.TypeName != got.TypeName ||
			decided.Service != got.Service {
			t.Errorf("%s: recorded as %s.%s reporting %q, the SDK declares %s.%s reporting %q",
				key, decided.Service, decided.TypeName, decided.Code,
				got.Service, got.TypeName, got.Code)
		}
		if decided.ByName != got.ByName || decided.ByCode != got.ByCode {
			t.Errorf("%s: recorded as by-name=%v by-code=%v, measured by-name=%v by-code=%v",
				key, decided.ByName, decided.ByCode, got.ByName, got.ByCode)
		}
		if decided.Why == "" {
			t.Errorf("%s is recorded with no consequence; a trap whose cost is not stated "+
				"reads as trivia and gets deleted as noise", key)
		}
	}
	for key := range typeNameTraps {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("the SDK declares error types whose Go name and wire code disagree about "+
			"IsRetryable and which are not recorded: %s. Decide each one: the code is the "+
			"answer this repository gives, and the name is what a reader will match on by "+
			"mistake", strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("recorded traps the SDK no longer declares: %s", strings.Join(stale, ", "))
	}

	// Both directions, asserted rather than assumed. A population that is all
	// name-in-set-code-not would be indistinguishable from a rule about one
	// service's spelling habit, which is how this was misread twice.
	var nameOnly, codeOnly int
	for _, decided := range typeNameTraps {
		if decided.ByName && !decided.ByCode {
			nameOnly++
		}
		if decided.ByCode && !decided.ByName {
			codeOnly++
		}
	}
	if nameOnly == 0 {
		t.Error("no recorded trap has a retryable-looking NAME and a terminal code; that is " +
			"the direction that makes a quota exhaustion retry forever")
	}
	if codeOnly == 0 {
		t.Error("no recorded trap has a terminal-looking NAME and a retryable code; that is " +
			"the direction that costs a deploy, and it is the one that was missed")
	}
	t.Logf("scanned %d declared error types across %d services with %d recorded traps "+
		"(%d retryable-by-name-only, %d retryable-by-code-only)",
		scanned, withErrors, len(typeNameTraps), nameOnly, codeOnly)
}
