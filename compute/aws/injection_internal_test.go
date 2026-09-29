// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestEverySubstrateMethodConsultsTheFailureInjection derives the obligation from
// the interface rather than restating it.
//
// USOSS-32 found the defect this guards against in compute/fake: one delete was
// hand-rolled while every other delete went through a shared body, so its
// failure injection was silently ignored and that method's error mapping was
// untestable — a hole no test could see, because the thing missing was a call.
//
// The check is a reflection over [ParameterStore] and [IAMAPI] and then a
// behavioural drive of every method with a failure armed. Reflection alone would
// only prove the methods exist; driving them proves each one actually looks. A
// method added later that forgets the injection fails here rather than becoming
// a method whose mapping nothing verifies.
//
// IAMAPI embeds [RolePolicyAPI] rather than listing its methods directly, and
// reflect.Type.NumMethod on an interface counts an embedded interface's methods
// too — there is no separate "own methods" view. So the derived want-set already
// includes GetRolePolicy/PutRolePolicy/DeleteRolePolicy, and the call table below
// has to drive those three as well or the both-directions equality check fails
// with "is not driven by this test" for each.
func TestEverySubstrateMethodConsultsTheFailureInjection(t *testing.T) {
	t.Parallel()
	armed := errors.New("aws: armed by the injection audit")

	t.Run("ParameterStore", func(t *testing.T) {
		t.Parallel()
		want := interfaceMethods[ParameterStore](t)
		params := NewMemoryParameters()
		ctx := context.Background()
		// One parameter, so that a method which would otherwise fail for its own
		// reasons reaches the injection instead.
		if _, err := params.Put(ctx, PutParameterInput{
			Name: "/p/apps/a/T", Value: compute.NewSecretValue("m"), Tier: TierStandard,
		}); err != nil {
			t.Fatalf("seeding: %v", err)
		}
		calls := map[string]func() error{
			"Put": func() error {
				_, err := params.Put(ctx, PutParameterInput{
					Name: "/p/apps/a/T", Value: compute.NewSecretValue("m2"),
					Tier: TierStandard, Overwrite: true,
				})
				return err
			},
			"Get":            func() error { _, err := params.Get(ctx, "/p/apps/a/T"); return err },
			"Describe":       func() error { _, err := params.Describe(ctx, "/p/apps/a/T"); return err },
			"DescribeByPath": func() error { _, err := params.DescribeByPath(ctx, "/p/apps/a"); return err },
			"Tags":           func() error { _, err := params.Tags(ctx, "/p/apps/a/T"); return err },
			"SetTags": func() error {
				return params.SetTags(ctx, "/p/apps/a/T", map[string]string{"k": "v"}, nil)
			},
			"Delete": func() error { return params.Delete(ctx, "/p/apps/a/T") },
		}
		assertEveryMethodDriven(t, "ParameterStore", want, calls, func() { params.Fail(armed) },
			func() { params.Fail(nil) }, armed)
	})

	t.Run("IAMAPI", func(t *testing.T) {
		t.Parallel()
		want := interfaceMethods[IAMAPI](t)
		roles := NewMemoryIAM()
		ctx := context.Background()
		// A role, and an inline policy on it, so that a method which would
		// otherwise fail for its own reasons (no such role, no such policy)
		// reaches the injection instead.
		if _, err := roles.CreateRole(ctx, CreateRoleRequest{Name: "r", Path: "/"}); err != nil {
			t.Fatalf("seeding: %v", err)
		}
		if err := roles.PutRolePolicy(ctx, "r", "p", "doc"); err != nil {
			t.Fatalf("seeding: %v", err)
		}
		calls := map[string]func() error{
			"CreateRole": func() error {
				_, err := roles.CreateRole(ctx, CreateRoleRequest{Name: "r2", Path: "/"})
				return err
			},
			"GetRole":                func() error { _, err := roles.GetRole(ctx, "r"); return err },
			"UpdateAssumeRolePolicy": func() error { return roles.UpdateAssumeRolePolicy(ctx, "r", "new-doc") },
			"DeleteRole":             func() error { return roles.DeleteRole(ctx, "r") },
			"TagRole":                func() error { return roles.TagRole(ctx, "r", map[string]string{"k": "v"}) },
			"UntagRole":              func() error { return roles.UntagRole(ctx, "r", []string{"k"}) },
			// Embedded via RolePolicyAPI; see the doc comment above.
			"GetRolePolicy":    func() error { _, err := roles.GetRolePolicy(ctx, "r", "p"); return err },
			"PutRolePolicy":    func() error { return roles.PutRolePolicy(ctx, "r", "p", "doc2") },
			"DeleteRolePolicy": func() error { return roles.DeleteRolePolicy(ctx, "r", "p") },
			// Added to IAMAPI by USOSS-11's container port, which needs a
			// declarative reconcile to derive its removal set from the role
			// rather than from a list of the policies it knows how to add.
			// It arrived without an entry here and this test demanded one,
			// which is the whole point of taking the population from the
			// interface: nothing had to be remembered.
			"ListRolePolicyNames": func() error {
				_, err := roles.ListRolePolicyNames(ctx, "r")
				return err
			},
		}
		// MemoryIAM's injector is the shared failNext embed, not a bespoke
		// Fail method: FailUntilStopped arms every call and hands back a stop
		// closure rather than taking a separate disarm call, so the stop
		// closure is threaded through a captured variable to fit the arm/disarm
		// shape assertEveryMethodDriven expects.
		var stop func()
		assertEveryMethodDriven(t, "IAMAPI", want, calls,
			func() { stop = roles.FailUntilStopped(armed) },
			func() { stop() },
			armed)
	})
}

// interfaceMethods returns the method names of an interface type.
func interfaceMethods[T any](t *testing.T) []string {
	t.Helper()
	rt := reflect.TypeFor[T]()
	if rt.Kind() != reflect.Interface {
		t.Fatalf("%s is not an interface", rt)
	}
	out := make([]string, 0, rt.NumMethod())
	for i := range rt.NumMethod() {
		out = append(out, rt.Method(i).Name)
	}
	return out
}

// assertEveryMethodDriven is the shared body: the table covers the interface
// exactly, and every entry surfaces the armed failure.
func assertEveryMethodDriven(
	t *testing.T,
	iface string,
	want []string,
	calls map[string]func() error,
	arm, disarm func(),
	armed error,
) {
	t.Helper()
	// A derivation that returns nothing passes every check over it.
	if len(want) == 0 {
		t.Fatalf("%s reflected to no methods, so this test asserts nothing", iface)
	}
	for _, name := range want {
		if _, ok := calls[name]; !ok {
			t.Errorf("%s.%s is not driven by this test, so whether it consults the failure "+
				"injection is unverified; add it to the table", iface, name)
		}
	}
	for name := range calls {
		if !containsString(want, name) {
			t.Errorf("this test drives %s.%s, which is not a method of the interface", iface, name)
		}
	}
	for _, name := range want {
		call, ok := calls[name]
		if !ok {
			continue
		}
		arm()
		err := call()
		disarm()
		if !errors.Is(err, armed) {
			t.Errorf("%s.%s returned %v with a failure armed; it does not consult the injection, "+
				"so its error mapping cannot be tested", iface, name, err)
		}
		if strings.Contains(fmt.Sprint(err), "m2") {
			t.Errorf("%s.%s leaked a value into its error", iface, name)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
