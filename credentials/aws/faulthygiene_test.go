// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/printer"
	"reflect"
	"sort"
	"strings"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/conductorone/apphub/credentials"
)

// This file exists because of a mutation that survived.
//
// hygiene_test.go drives every exported entry point with sentinels in every input
// position, and a mutation that interpolated the IAM user name into the
// already-exists error passed the whole suite. The reason is the third instance in
// /shared/apphub/POPULATION-FAILURES.md: exhaustive over *where* input enters,
// blind to *what* input reaches the branch under test. Every AWS failure the
// fixture injected was a generic 500, so every typed-error branch -- the ones with
// their own message -- was unreached.
//
// So the population here is the typed-error branches themselves, derived from the
// predicates in fault.go rather than listed. A predicate with no error to drive it
// is a failure, which is what makes the derivation an enumeration rather than a
// list of the branches somebody remembered.

// predicateDecl is one is* function declared in fault.go, with enough of its
// signature to decide whether the census can wire it.
type predicateDecl struct {
	// Name is the function name.
	Name string
	// Signature is the rendered signature, for a failure message that names what
	// it could not classify rather than only that it could not.
	Signature string
	// Canonical reports whether the signature is exactly func(error) bool -- the
	// only shape assignable into a map[string]func(error) bool.
	Canonical bool
}

// errorPredicateDecls collects EVERY top-level is* function in fault.go, whatever
// its signature.
//
// # The three skip paths this replaced were a bypass
//
// The first version required exactly one parameter of type error and returned only
// the name. Review defeated it with func isReviewPredicate(err error, _ ...bool)
// bool: a real predicate, overlapping InvalidIdentityToken, that the census walked
// straight past -- so the disjointness property was asserted over a set that did
// not contain it, and the test still reported 9 of 45.
//
// That is the fourth form of one failure on this project: a gate recognising a
// thing by the shape it expected rather than asking what the thing is. An alias, a
// defined type, an identifier in an uninvoked closure, and now a signature variant.
//
// So nothing is skipped here. Every is* function is collected and classified, and
// a signature the census cannot wire is FATAL at the call site rather than absent
// from the population.
func errorPredicateDecls(t *testing.T) []predicateDecl {
	t.Helper()
	files, fset := sourceFilesWithFset(t)
	file, ok := files["fault.go"]
	if !ok {
		t.Fatal("fault.go is gone; this derivation has nothing to read and that is a failure, not a pass")
	}
	var out []predicateDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "is") {
			continue
		}
		var rendered bytes.Buffer
		if err := printer.Fprint(&rendered, fset, fn.Type); err != nil {
			t.Fatalf("cannot render the signature of %s: %v", fn.Name.Name, err)
		}
		out = append(out, predicateDecl{
			Name:      fn.Name.Name,
			Signature: rendered.String(),
			Canonical: isCanonicalPredicate(fn.Type),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		t.Fatal("derived no error predicates from fault.go")
	}
	return out
}

// isCanonicalPredicate reports whether a signature is exactly func(error) bool.
//
// Exactly: one parameter, one name or none, type the identifier error and not a
// variadic or a defined type spelled differently; one result, type the identifier
// bool. Anything else is not canonical, which makes it the caller's problem rather
// than something quietly dropped.
func isCanonicalPredicate(ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) != 1 {
		return false
	}
	if ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	param := ft.Params.List[0]
	if len(param.Names) > 1 {
		// One field can declare several parameters: (a, b error).
		return false
	}
	if id, ok := param.Type.(*ast.Ident); !ok || id.Name != "error" {
		return false
	}
	res := ft.Results.List[0]
	if len(res.Names) > 1 {
		return false
	}
	id, ok := res.Type.(*ast.Ident)
	return ok && id.Name == "bool"
}

// errorPredicates is the name list, for the callers that only need names.
func errorPredicates(t *testing.T) []string {
	t.Helper()
	decls := errorPredicateDecls(t)
	out := make([]string, 0, len(decls))
	for _, d := range decls {
		out = append(out, d.Name)
	}
	return out
}

// errorsForPredicate maps each predicate to an error it recognises.
//
// The map is hand-written and the population is not, which is the right way round:
// a predicate added to fault.go fails TestEveryTypedErrorBranchIsDriven until it
// appears here, and cannot be silently absent.
func errorsForPredicate() map[string]error {
	return map[string]error{
		"isNoSuchEntity": &iamtypes.NoSuchEntityException{
			Message: strptr(sentinelAWS),
		},
		"isEntityAlreadyExists": &iamtypes.EntityAlreadyExistsException{
			Message: strptr(sentinelAWS),
		},
		"isDeleteConflict": &iamtypes.DeleteConflictException{
			Message: strptr(sentinelAWS),
		},
		"isInvalidIdentityToken": &ststypes.InvalidIdentityTokenException{
			Message: strptr(sentinelAWS),
		},
		"isConsistencyRace": &iamtypes.ConcurrentModificationException{
			Message: strptr(sentinelAWS),
		},
		"isExpiredSTSToken": &ststypes.ExpiredTokenException{
			Message: strptr(sentinelAWS),
		},
		"isIdentityProviderUnreachable": &ststypes.IDPCommunicationErrorException{
			Message: strptr(sentinelAWS),
		},
		"isIdentityProviderRejectedClaim": &ststypes.IDPRejectedClaimException{
			Message: strptr(sentinelAWS),
		},
		"isWebIdentityRetryable": &ststypes.InvalidIdentityTokenException{
			Message: strptr(sentinelAWS),
		},
		"isTransient": withStatus(503, apiError{code: sentinelAWS}),
	}
}

func strptr(s string) *string { return &s }

// TestEveryTypedErrorBranchIsDriven is the accounting.
func TestEveryTypedErrorBranchIsDriven(t *testing.T) {
	t.Parallel()
	predicates := errorPredicates(t)
	built := errorsForPredicate()
	var missing, stale []string
	for _, name := range predicates {
		if _, ok := built[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range built {
		if !slicesContains(predicates, name) {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("fault.go has predicates with no error to drive them: %s", strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("errors are built for predicates fault.go no longer has: %s", strings.Join(stale, ", "))
	}
	// And each constructed error really is recognised by its own predicate. Without
	// this the map could hold an error that nothing classifies, and every branch
	// below would take the generic path -- which is the defect this file exists for,
	// one level down.
	recognisers := map[string]func(error) bool{
		"isNoSuchEntity":                  isNoSuchEntity,
		"isEntityAlreadyExists":           isEntityAlreadyExists,
		"isDeleteConflict":                isDeleteConflict,
		"isInvalidIdentityToken":          isInvalidIdentityToken,
		"isConsistencyRace":               isConsistencyRace,
		"isExpiredSTSToken":               isExpiredSTSToken,
		"isIdentityProviderUnreachable":   isIdentityProviderUnreachable,
		"isIdentityProviderRejectedClaim": isIdentityProviderRejectedClaim,
		"isWebIdentityRetryable":          isWebIdentityRetryable,
		"isTransient":                     isTransient,
	}
	for name, err := range built {
		fn, ok := recognisers[name]
		if !ok {
			t.Errorf("no recogniser wired for %s", name)
			continue
		}
		if !fn(err) {
			t.Errorf("%s does not recognise the error built to drive it", name)
		}
	}
	t.Logf("driving %d typed-error branches", len(predicates))
}

// TestNoTypedErrorBranchRendersForeignText is the property.
//
// Each typed error carries the sentinel in its own Message field, injected at every
// AWS call in turn, across both credential types and all three provider methods.
// Nothing this package returns may contain it.
func TestNoTypedErrorBranchRendersForeignText(t *testing.T) {
	t.Parallel()
	built := errorSlice(errorsForPredicate())

	// The injection sites are derived the same way the create and teardown
	// enumerations are: every IAM and STS method the fence declares.
	iamMethods := interfaceMethods(t, (*iamAPI)(nil))
	stsMethods := interfaceMethods(t, (*stsAPI)(nil))
	if len(iamMethods) == 0 || len(stsMethods) == 0 {
		t.Fatal("derived no injection sites")
	}

	type operation struct {
		name string
		run  func(h *harness) []any
	}
	operations := []operation{
		{"create dynamic", func(h *harness) []any {
			res, err := h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeDynamic))
			return []any{err, res}
		}},
		{"create static", func(h *harness) []any {
			res, err := h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
			return []any{err, res}
		}},
		{"revoke", func(h *harness) []any {
			return []any{h.p.RevokeCredential(context.Background(),
				staticHandle("example-bedrock-example-app", "sscred-1"), sentinelMetadataBag())}
		}},
		{"status", func(h *harness) []any {
			status, err := h.p.GetCredentialStatus(context.Background(),
				staticHandle("example-bedrock-example-app", "sscred-1"), sentinelMetadataBag())
			return []any{err, status}
		}},
	}

	drove := 0
	for _, injected := range built {
		for _, method := range append(append([]string{}, iamMethods...), stsMethods...) {
			for _, op := range operations {
				h := newHarness(t, fullConfig()).withFakeTokens(sentinelToken)
				fail := func(m string, _ int) error {
					if m == method {
						return injected.err
					}
					return nil
				}
				h.iam.fail = fail
				h.sts.fail = fail
				for _, v := range op.run(h) {
					if isNilValue(v) {
						continue
					}
					drove++
					forbidden := allSentinels()
					if _, isResult := v.(*credentials.CreateResult); isResult {
						forbidden = withoutHandleAttribution(forbidden)
					}
					assertNoSentinel(t, injected.name+" at "+method+" during "+op.name, v, forbidden)
				}
			}
		}
	}
	if drove == 0 {
		t.Fatal("nothing was driven")
	}
	t.Logf("checked %d returned values across %d typed errors and %d injection sites",
		drove, len(built), len(iamMethods)+len(stsMethods))
}

type namedError struct {
	name string
	err  error
}

func errorSlice(in map[string]error) []namedError {
	out := make([]namedError, 0, len(in))
	for name, err := range in {
		out = append(out, namedError{name: name, err: err})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func interfaceMethods(t *testing.T, iface any) []string {
	t.Helper()
	typ := reflect.TypeOf(iface).Elem()
	var names []string
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	return names
}

// TestTheAlreadyExistsBranchIsWhatTheMutationExposed is the specific case, kept
// alongside the general property above rather than instead of it.
//
// The general property is what catches the next one; this names the one that got
// through, so a later reader can see what the general property is for. It is the
// same relationship as a regression test to an invariant.
func TestTheAlreadyExistsBranchIsWhatTheMutationExposed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	// A user already under the name the sentinel request would want.
	h.iam.users["example-bedrock-SENTINEL-credential-name"] = &fakeUser{tags: map[string]string{}}
	h.iam.mu.Unlock()

	_, err := h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("want ErrNotOwned, got %v", err)
	}
	if strings.Contains(err.Error(), sentinelName) {
		t.Fatalf("the error names the IAM user it refused to create: %v", err)
	}
}
