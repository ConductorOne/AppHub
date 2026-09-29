// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/workload"
)

// contractVerifier implements the normative contract and nothing more: one method,
// exactly the signature the contract specifies. The compile-time assertion below is
// the regression test for an interface that had grown a second method -- a verifier
// written against the frozen document has only this method, so if Verifier ever
// requires another, this stops compiling.
type contractVerifier struct{ subject string }

func (f contractVerifier) Verify(_ context.Context, expected workload.ExpectedAttestation, proof workload.AttestationProof) (workload.Identity, error) {
	if proof.Method != expected.Method || f.subject != expected.Subject {
		return workload.Identity{}, workload.ErrAttestationRejected
	}
	return workload.Identity{Subject: expected.Subject, Method: expected.Method}, nil
}

var _ workload.Verifier = contractVerifier{}

// TestVerifierIsExactlyTheContractInterface pins the method set. The compile-time
// assertion above catches an *added* requirement; this catches a removed or
// altered one, which is how the guard on this interface came to be missing: the
// reviewer deleted Method() from Verifier and the entire package still passed.
func TestVerifierIsExactlyTheContractInterface(t *testing.T) {
	typ := reflect.TypeOf((*workload.Verifier)(nil)).Elem()
	if got := typ.NumMethod(); got != 1 {
		t.Fatalf("Verifier has %d methods, contract specifies exactly 1: %s", got, methodNames(typ))
	}
	m := typ.Method(0)
	if m.Name != "Verify" {
		t.Errorf("Verifier's method is %q, contract specifies Verify", m.Name)
	}
	const want = "func(context.Context, workload.ExpectedAttestation, workload.AttestationProof) (workload.Identity, error)"
	if got := m.Type.String(); got != want {
		t.Errorf("Verify signature is\n  %s\ncontract specifies\n  %s", got, want)
	}
}

func methodNames(typ reflect.Type) []string {
	out := make([]string, 0, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		out = append(out, typ.Method(i).Name)
	}
	return out
}

// TestVerifierRegistryDispatchesOnTheExpectedScheme: dispatch metadata moved out of
// the interface, so the registry is where a scheme mismatch has to be caught.
func TestVerifierRegistryDispatchesOnTheExpectedScheme(t *testing.T) {
	reg := workload.NewVerifierRegistry()
	if err := reg.Register(workload.MethodAWSSTSCallerIdentity, contractVerifier{subject: "app:1"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(workload.MethodAWSSTSCallerIdentity, contractVerifier{}); err == nil {
		t.Error("Register accepted a second verifier for one scheme; wiring order would decide which opinion applies")
	}
	if err := reg.Register("", contractVerifier{}); err == nil {
		t.Error("Register accepted an empty method")
	}
	if err := reg.Register(workload.MethodK8sServiceAccount, nil); err == nil {
		t.Error("Register accepted a nil verifier")
	}

	expected := workload.ExpectedAttestation{Method: workload.MethodAWSSTSCallerIdentity, Subject: "app:1"}
	proof := workload.AttestationProof{
		Method: workload.MethodAWSSTSCallerIdentity,
		Proof:  map[string]credentials.Secret{"authorization": credentials.NewSecret("sigv4")},
	}
	if _, err := reg.Verify(context.Background(), expected, proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A proof may not choose its own verifier: that would let a submitter pick the
	// weakest scheme a deployment happens to accept.
	mismatched := proof
	mismatched.Method = workload.MethodK8sServiceAccount
	if _, err := reg.Verify(context.Background(), expected, mismatched); !errors.Is(err, workload.ErrAttestationRejected) {
		t.Errorf("Verify(scheme mismatch) = %v, want ErrAttestationRejected", err)
	}

	// An unregistered scheme is rejected the same way, so the error does not
	// enumerate which schemes the deployment accepts.
	unregistered := workload.ExpectedAttestation{Method: workload.MethodK8sServiceAccount, Subject: "app:1"}
	k8sProof := workload.AttestationProof{Method: workload.MethodK8sServiceAccount}
	if _, err := reg.Verify(context.Background(), unregistered, k8sProof); !errors.Is(err, workload.ErrAttestationRejected) {
		t.Errorf("Verify(unregistered scheme) = %v, want ErrAttestationRejected", err)
	}

	if n := len(reg.Methods()); n != 1 {
		t.Errorf("Methods() returned %d schemes, want 1", n)
	}
	if _, ok := reg.For(workload.MethodK8sServiceAccount); ok {
		t.Error("For() found a verifier that was never registered")
	}
}

// TestSchemeIdentifiersAreTheContractValues pins the strings themselves. A
// registry keyed by one spelling silently fails to select a provider registered
// under another, which is how the two parallel designs ended up with "aws-sts"
// on one side and "aws-sts-caller-identity" on the other.
func TestSchemeIdentifiersAreTheContractValues(t *testing.T) {
	if workload.MethodAWSSTSCallerIdentity != "aws-sts-caller-identity" {
		t.Errorf("MethodAWSSTSCallerIdentity = %q, want %q", workload.MethodAWSSTSCallerIdentity, "aws-sts-caller-identity")
	}
	if workload.MethodK8sServiceAccount != "k8s-service-account" {
		t.Errorf("MethodK8sServiceAccount = %q, want %q", workload.MethodK8sServiceAccount, "k8s-service-account")
	}
}

// TestSchemeLiteralsAppearOnlyInTheirDeclaration enforces the contract rule that
// no string literal naming a scheme may appear anywhere else. A second spelling of
// the same scheme is invisible in review -- both look correct -- and a registry
// keyed by one silently fails to select the other.
//
// The first version of this guard scanned file text for the quoted forms. A review
// fixture walked through it twice: a raw Go string literal in this very package
// passed, and an ordinary quoted literal in compute passed because the scan only
// covered one directory. This version parses every Go file in the repository and
// unquotes each string literal, so quoting style is irrelevant and no package is
// out of scope. It is the guard that protects the contract once the duplicate
// declaration on the compute branch is deleted, so its coverage has to match its
// claim.
//
// Known limit, stated rather than hidden: a literal assembled by concatenation
// ("aws-sts-" + "caller-identity") is not detected, because each fragment is its
// own literal. Nothing stops that; it is also not something anyone does by
// accident, which is the class of mistake this guard is for.
func TestSchemeLiteralsAppearOnlyInTheirDeclaration(t *testing.T) {
	root := repoRoot(t)
	schemes := map[string]int{
		string(workload.MethodAWSSTSCallerIdentity): 0,
		string(workload.MethodK8sServiceAccount):    0,
	}
	where := map[string][]string{}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".tools", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Test files may quote the values in order to assert them -- this file does.
		// That is the one legitimate second occurrence, and a test cannot coin a
		// scheme that ships.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			// Unquote handles both interpreted and raw (backtick) literals.
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, tracked := schemes[v]; tracked {
				schemes[v]++
				where[v] = append(where[v], fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for scheme, n := range schemes {
		if n != 1 {
			t.Errorf("scheme literal %q appears %d times in non-test sources, want exactly 1 (its declaration); found at %v",
				scheme, n, where[scheme])
		}
		for _, loc := range where[scheme] {
			if !strings.HasPrefix(loc, filepath.Join("credentials", "workload", "attestation.go")) {
				t.Errorf("scheme literal %q declared at %s; the canonical declaration is credentials/workload/attestation.go", scheme, loc)
			}
		}
	}
}

// repoRoot walks up from the package directory to the module root, so the guard
// above covers every package rather than the one it happens to live in.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the package directory")
		}
		dir = parent
	}
}

// TestExpectedAttestationHoldsNoMaterial: the stored policy is persisted and
// logged, so it must be structurally incapable of carrying a secret. This is the
// invariant that keeps the expectation from becoming a second copy of the thing
// being proven.
func TestExpectedAttestationHoldsNoMaterial(t *testing.T) {
	secretType := reflect.TypeOf(credentials.Secret{})
	for _, typ := range []reflect.Type{
		reflect.TypeOf(workload.ExpectedAttestation{}),
		reflect.TypeOf(workload.Identity{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if containsType(f.Type, secretType) {
				t.Errorf("%s.%s can hold credential material", typ.Name(), f.Name)
			}
		}
	}

	// The proof, by contrast, is where material belongs.
	proof := reflect.TypeOf(workload.AttestationProof{})
	field, ok := proof.FieldByName("Proof")
	if !ok || !containsType(field.Type, secretType) {
		t.Error("AttestationProof.Proof should carry credentials.Secret values")
	}
}

func containsType(t, target reflect.Type) bool {
	if t == target {
		return true
	}
	switch t.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.Pointer:
		return containsType(t.Elem(), target)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if containsType(t.Field(i).Type, target) {
				return true
			}
		}
	}
	return false
}

// TestProvisionerHasExactlyTwoMethods: both independent reviews concluded that
// Rotate then Materials is sufficient, and the contract forbids a third
// credential-facing provisioning method.
func TestProvisionerHasExactlyTwoMethods(t *testing.T) {
	typ := reflect.TypeOf((*workload.Provisioner)(nil)).Elem()
	if got := typ.NumMethod(); got != 2 {
		t.Fatalf("Provisioner has %d methods, want exactly 2", got)
	}
	for _, name := range []string{"Materials", "Rotate"} {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("Provisioner is missing %s", name)
		}
	}
}

func TestVerifyRejectsAMismatchedSubject(t *testing.T) {
	v := contractVerifier{subject: "app:1"}
	expected := workload.ExpectedAttestation{Method: workload.MethodAWSSTSCallerIdentity, Subject: "app:2"}
	proof := workload.AttestationProof{
		Method: workload.MethodAWSSTSCallerIdentity,
		Proof:  map[string]credentials.Secret{"authorization": credentials.NewSecret("sigv4")},
	}

	if _, err := v.Verify(context.Background(), expected, proof); !errors.Is(err, workload.ErrAttestationRejected) {
		t.Errorf("Verify(mismatched subject) = %v, want ErrAttestationRejected", err)
	}

	expected.Subject = "app:1"
	id, err := v.Verify(context.Background(), expected, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != expected.Subject {
		t.Errorf("Identity.Subject = %q, want the expected subject it was checked against", id.Subject)
	}
}

func TestTokenTTLMatchesTheSourceSystem(t *testing.T) {
	if workload.DefaultTokenTTL != time.Hour {
		t.Errorf("DefaultTokenTTL = %s, want 1h", workload.DefaultTokenTTL)
	}
}

// TestAttestationShapesMatchTheContract pins the declarations that another
// package holds a temporary copy of while the two branches land. The copy is
// deleted after this one merges, and a deletion is only clean if the two agree
// exactly -- a differing field name or order would turn the removal into a silent
// behavior change. The literals below are the contract's, not this package's.
func TestAttestationShapesMatchTheContract(t *testing.T) {
	shapes := map[reflect.Type][][2]string{
		reflect.TypeOf(workload.ExpectedAttestation{}): {
			{"Method", "workload.Method"},
			{"Subject", "string"},
			{"Issuer", "string"},
			{"Audience", "string"},
		},
		reflect.TypeOf(workload.AttestationProof{}): {
			{"Method", "workload.Method"},
			{"Proof", "map[string]credentials.Secret"},
		},
	}
	for typ, want := range shapes {
		if got := typ.NumField(); got != len(want) {
			t.Errorf("%s has %d fields, contract specifies %d", typ.Name(), got, len(want))
			continue
		}
		for i, w := range want {
			f := typ.Field(i)
			if f.Name != w[0] {
				t.Errorf("%s field %d is %q, contract specifies %q (order is part of the contract)", typ.Name(), i, f.Name, w[0])
			}
			if got := f.Type.String(); got != w[1] {
				t.Errorf("%s.%s is %s, contract specifies %s", typ.Name(), f.Name, got, w[1])
			}
		}
	}

	if reflect.TypeOf(workload.MethodAWSSTSCallerIdentity).Kind() != reflect.String {
		t.Error("Method must be a string type")
	}
}
