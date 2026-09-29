// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/conductorone/apphub/credentials"
)

// TestEveryAWSCallIsExercised states a property over the fence rather than over
// the tests.
//
//	Every method on this package's AWS interfaces is reached by some path the
//	suite drives, and no method sits in the fence unexercised.
//
// The population is the interface method set, taken from the reflect type. That
// matters more than it looks: the alternative is a list of method names in a test
// file, and this project has four counted instances of a derivation that was exact
// over a set the derivation itself chose. An interface is the semantic authority
// for "what does this package call", and adding a method to it puts the method in
// this population whether or not anybody remembers to write a scenario.
//
// A method in the interface that no scenario reaches is a failure in both
// readings, and both are worth catching: either the suite has a gap, or the fence
// declares a call the package does not make -- which is API surface with no
// caller, and the next author will assume something drives it.
func TestEveryAWSCallIsExercised(t *testing.T) {
	t.Parallel()

	declared := func(iface any) []string {
		typ := reflect.TypeOf(iface).Elem()
		if typ.Kind() != reflect.Interface {
			t.Fatalf("%v is not an interface", typ)
		}
		var names []string
		for i := range typ.NumMethod() {
			names = append(names, typ.Method(i).Name)
		}
		sort.Strings(names)
		return names
	}
	wantIAM := declared((*iamAPI)(nil))
	wantSTS := declared((*stsAPI)(nil))
	if len(wantIAM) == 0 || len(wantSTS) == 0 {
		t.Fatal("derived no interface methods; a derivation that returns nothing passes every check over it")
	}

	seenIAM := map[string]bool{}
	seenSTS := map[string]bool{}
	record := func(h *harness) {
		for _, c := range h.iam.called() {
			seenIAM[c] = true
		}
		for _, c := range h.sts.called() {
			seenSTS[c] = true
		}
	}

	ctx := context.Background()

	// Scenarios. This list is hand-written and the population above is not, which
	// is the right way round: a missing scenario shows up as an uncovered method.
	{
		h := newHarness(t, fullConfig())
		if _, err := h.p.CreateCredential(ctx, dynamicRequest()); err != nil {
			t.Fatalf("dynamic create: %v", err)
		}
		record(h)
	}
	{
		h := newHarness(t, fullConfig()).withFakeTokens("fake-web-identity-token")
		if _, err := h.p.CreateCredential(ctx, dynamicRequest()); err != nil {
			t.Fatalf("federated dynamic create: %v", err)
		}
		record(h)
	}
	{
		h := newHarness(t, fullConfig())
		res, err := h.p.CreateCredential(ctx, staticRequest())
		if err != nil {
			t.Fatalf("static create: %v", err)
		}
		if _, err := h.p.GetCredentialStatus(ctx, res.PlatformKeyID, nil); err != nil {
			t.Fatalf("status: %v", err)
		}
		if err := h.p.RevokeCredential(ctx, res.PlatformKeyID, nil); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		record(h)
	}
	{
		// A user carrying every kind of child, so the teardown paths that only run
		// when something is attached are reached.
		const userName = "example-bedrock-coverage"
		h := newHarness(t, fullConfig())
		h.iam.mu.Lock()
		h.iam.users[userName] = &fakeUser{
			tags: map[string]string{
				tagManagedBy: managedByValue,
				tagName:      userName,
				tagComponent: componentCredentialUser,
			},
			attached: []string{"arn:aws:iam::aws:policy/ExampleOne"},
			inline:   []string{"inline-one"},
			keys:     []string{"key-one"},
			sscs:     []fakeSSC{{id: "sscred-9", service: bedrockServiceName, status: iamtypes.StatusTypeActive}},
		}
		h.iam.mu.Unlock()
		if err := h.p.RevokeCredential(ctx, staticHandle(userName, "sscred-9"), nil); err != nil {
			t.Fatalf("revoke with children: %v", err)
		}
		record(h)
	}

	report := func(kind string, want []string, seen map[string]bool) {
		var missing []string
		for _, name := range want {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s methods declared in the fence and never reached: %s",
				kind, strings.Join(missing, ", "))
		}
		for name := range seen {
			if !slicesContains(want, name) {
				t.Errorf("%s method %s was called and is not in the fence", kind, name)
			}
		}
		t.Logf("%s: %d of %d methods exercised", kind, len(seen), len(want))
	}
	report("iamAPI", wantIAM, seenIAM)
	report("stsAPI", wantSTS, seenSTS)
}

func slicesContains(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

// TestTheProviderSatisfiesTheContractItDeclares is the compile-time assertion
// stated behaviourally, so a change that keeps the interfaces satisfied and stops
// honouring them is visible.
func TestTheProviderSatisfiesTheContractItDeclares(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	var p credentials.CredentialProvider = h.p
	if p.ID() == "" || p.Name() == "" {
		t.Fatal("a provider with no identity")
	}
	// CapabilitiesOf clears RecoverCreate for a provider that does not implement
	// credentials.CreateRecoverer. This provider does not, deliberately, and the
	// declaration must agree -- a provider admitted as recoverable and then unable
	// to recover is the state the write-ahead ordering exists to prevent.
	if _, ok := p.(credentials.CreateRecoverer); ok {
		t.Fatal("this provider now implements CreateRecoverer; Capabilities must declare it " +
			"and the reasoning in Provider.Capabilities must be revised")
	}
	if credentials.CapabilitiesOf(p).RecoverCreate {
		t.Fatal("RecoverCreate is declared and not implementable")
	}
}
