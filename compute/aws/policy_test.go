// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// bindings turns a set of stored secrets into the bindings a runtime would put
// on a workload.
func bindings(refs ...compute.Ref) []compute.SecretBinding {
	out := make([]compute.SecretBinding, 0, len(refs))
	for i, ref := range refs {
		out = append(out, compute.SecretBinding{EnvName: "SECRET_" + string(rune('A'+i)), Secret: ref})
	}
	return out
}

// resolved runs bindings through the ARN resolution a runtime would perform
// before either building a task definition or asking for the grant.
func resolved(t *testing.T, p *aws.Provider, bs []compute.SecretBinding) []aws.SecretParameterRef {
	t.Helper()
	out, err := p.SecretParameterARNs(context.Background(), bs)
	if err != nil {
		t.Fatalf("SecretParameterARNs: %v", err)
	}
	return out
}

// TestSecretParameterARNsReadsBackRatherThanComposing covers the resolution the
// container and function runtimes need in order to reference a parameter at all,
// and the refusals that keep a task definition from being built around a
// reference nothing will resolve.
func TestSecretParameterARNsReadsBackRatherThanComposing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, nil)

	got, err := p.SecretParameterARNs(ctx, bindings(ref))
	if err != nil {
		t.Fatalf("SecretParameterARNs: %v", err)
	}
	want := "arn:aws:ssm:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":parameter" + paramOf(t, ref)
	if len(got) != 1 || got[0].ARN != want || got[0].EnvName != "SECRET_A" {
		t.Fatalf("resolved to %+v, want one entry SECRET_A -> %q", got, want)
	}

	// Two variables from one parameter is an ordinary thing for a deploy to do,
	// and both entries survive: the runtime needs both bindings even though the
	// grant needs one resource.
	pair, err := p.SecretParameterARNs(ctx, []compute.SecretBinding{
		{EnvName: "A", Secret: ref}, {EnvName: "B", Secret: ref},
	})
	if err != nil {
		t.Fatalf("SecretParameterARNs: %v", err)
	}
	if len(pair) != 2 {
		t.Fatalf("two bindings on one parameter resolved to %d entries", len(pair))
	}

	// A reference to a parameter that no longer exists is caught here, where a
	// runtime is still building a specification, rather than as an opaque
	// container-launch failure later.
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.SecretParameterARNs(ctx, bindings(ref)); !errors.Is(err, compute.ErrNotFound) {
		t.Fatalf("resolving a deleted parameter returned %v, want compute.ErrNotFound", err)
	}
}

// TestSecretParameterARNsRefusesRatherThanOmits: dropping a binding it cannot
// resolve would build a task definition that looks right and a workload that
// starts without a credential it was written to require.
func TestSecretParameterARNsRefusesRatherThanOmits(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	good := put(t, store, "app-1", "TOKEN", material, nil)
	for _, tc := range []struct {
		what    string
		binding compute.SecretBinding
		want    error
	}{
		{"a foreign reference", compute.SecretBinding{EnvName: "X", Secret: compute.Ref{
			Provider: "somebody-else", Kind: compute.KindSecret, ID: good.ID,
		}}, compute.ErrForeignRef},
		{"a reference outside the prefix", compute.SecretBinding{EnvName: "X", Secret: compute.Ref{
			Provider: p.Name(), Kind: compute.KindSecret, ID: "/somebody/elses/tree/T",
		}}, compute.ErrInvalidSpec},
		{"a wrong-kind reference", compute.SecretBinding{EnvName: "X", Secret: compute.Ref{
			Provider: p.Name(), Kind: compute.KindBucket, ID: good.ID,
		}}, compute.ErrInvalidSpec},
		{"no environment variable", compute.SecretBinding{EnvName: "", Secret: good}, compute.ErrInvalidSpec},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			out, err := p.SecretParameterARNs(context.Background(),
				[]compute.SecretBinding{{EnvName: "OK", Secret: good}, tc.binding})
			if !errors.Is(err, tc.want) {
				t.Fatalf("resolving %s returned %v, want %v", tc.what, err, tc.want)
			}
			if out != nil {
				t.Fatalf("resolving %s returned both an error and %d entries", tc.what, len(out))
			}
		})
	}
}

// TestSecretReadPolicyCannotInventAnARN is the property that comes from taking
// resolved references rather than bindings: the only ARNs the grant can name are
// ones the substrate reported.
func TestSecretReadPolicyCannotInventAnARN(t *testing.T) {
	t.Parallel()
	p, _, _ := newStore(t, nil)
	for _, tc := range []struct {
		what string
		ref  aws.SecretParameterRef
	}{
		{"no ARN", aws.SecretParameterRef{EnvName: "A"}},
		{"something that is not an ARN", aws.SecretParameterRef{EnvName: "A", ARN: "/apphub/x"}},
		{"a wildcard", aws.SecretParameterRef{
			EnvName: "A", ARN: "arn:aws:ssm:eu-west-2:x:parameter/apphub/conformance/apps/*",
		}},
		{"no environment variable", aws.SecretParameterRef{ARN: "arn:aws:ssm:eu-west-2:x:parameter/a"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			doc, err := p.SecretReadPolicy([]aws.SecretParameterRef{tc.ref})
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("a reference with %s produced %v, want compute.ErrInvalidSpec", tc.what, err)
			}
			if !doc.IsEmpty() {
				t.Fatalf("a refused reference still produced %d statement(s)", len(doc.Statement))
			}
		})
	}
}

// TestSecretReadPolicyGrantsExactlyWhatIsBound is the least-privilege
// invariant, stated as a property rather than as a golden document: the Resource
// element is exactly the set of parameters the workload binds, and a sibling
// secret in the same scope — the nearest thing a widened grant would pick up —
// is not in it.
func TestSecretReadPolicyGrantsExactlyWhatIsBound(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	bound := put(t, store, "app-1", "BOUND", material, nil)
	sibling := put(t, store, "app-1", "SIBLING", material, nil)
	otherApp := put(t, store, "app-2", "THEIRS", material, nil)

	doc, err := p.SecretReadPolicy(resolved(t, p, bindings(bound)))
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}
	if doc.IsEmpty() {
		t.Fatal("a policy for one binding is empty")
	}
	read := doc.Statement[0]
	want := []string{"arn:aws:ssm:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":parameter" + paramOf(t, bound)}
	if !slices.Equal(read.Resource, want) {
		t.Fatalf("Resource is %v, want %v", read.Resource, want)
	}
	rendered := mustJSON(t, doc)
	for _, unbound := range []compute.Ref{sibling, otherApp} {
		if strings.Contains(rendered, paramOf(t, unbound)) {
			t.Fatalf("the policy reaches %s, which the workload did not bind", paramOf(t, unbound))
		}
	}
}

// TestSecretReadPolicyHasNoWildcardAndNoEnumeration names the class rather than
// the case: no element of the document may be a wildcard, and every action in it
// has to be one of the two named reads.
//
// The enumeration actions are called out because they are the specific way this
// grant goes wrong quietly. ssm:GetParametersByPath against a hierarchy lets a
// principal discover and read every secret under it, which turns a grant scoped
// to one application into a grant over all of them — which is what the source
// system's execution-role policy does
// (terraform/modules/ecs/iam.tf:43-46, Resource "…:parameter{prefix}/apps/*").
func TestSecretReadPolicyHasNoWildcardAndNoEnumeration(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	var refs []compute.Ref
	for _, name := range []string{"A", "B", "C"} {
		refs = append(refs, put(t, store, "app-1", name, material, nil))
	}
	doc, err := p.SecretReadPolicy(resolved(t, p, bindings(refs...)))
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}

	allowedActions := map[string]bool{"ssm:GetParameter": true, "ssm:GetParameters": true, "kms:Decrypt": true}
	forbidden := []string{
		"ssm:GetParametersByPath", "ssm:DescribeParameters", "ssm:GetParameterHistory",
		"ssm:PutParameter", "ssm:DeleteParameter", "ssm:DeleteParameters",
		"ssm:AddTagsToResource", "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource",
		"ssm:*", "*",
	}
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			t.Fatalf("statement %q has effect %q", st.Sid, st.Effect)
		}
		if len(st.Action) == 0 {
			t.Fatalf("statement %q grants no action", st.Sid)
		}
		for _, action := range st.Action {
			if !allowedActions[action] {
				t.Fatalf("statement %q grants %q, which is not one of the reads this port needs",
					st.Sid, action)
			}
			if slices.Contains(forbidden, action) {
				t.Fatalf("statement %q grants %q", st.Sid, action)
			}
		}
		for _, resource := range st.Resource {
			if strings.ContainsAny(resource, "*?") {
				t.Fatalf("statement %q names resource %q, which is a pattern", st.Sid, resource)
			}
		}
	}
	// And nothing anywhere in the serialised document, including a Sid or a
	// condition value.
	if rendered := mustJSON(t, doc); strings.ContainsAny(rendered, "*") {
		t.Fatalf("the policy document contains a wildcard: %s", rendered)
	}
	// One resource per distinct binding, so a grant cannot be collapsed into a
	// pattern by accident.
	if got := len(doc.Statement[0].Resource); got != len(refs) {
		t.Fatalf("%d bindings produced %d resources", len(refs), got)
	}
}

// TestSecretReadPolicyDeduplicatesRatherThanRepeating covers two environment
// variables fed from one parameter, which is an ordinary thing for a deploy to
// do and which must not produce a duplicated Resource element.
func TestSecretReadPolicyDeduplicatesRatherThanRepeating(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, nil)
	doc, err := p.SecretReadPolicy(resolved(t, p, []compute.SecretBinding{
		{EnvName: "A", Secret: ref}, {EnvName: "B", Secret: ref},
	}))
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}
	if got := len(doc.Statement[0].Resource); got != 1 {
		t.Fatalf("one parameter bound twice produced %d resources", got)
	}
}

// TestSecretReadPolicyForNoBindingsGrantsNothing keeps the empty case from
// becoming the widest one.
func TestSecretReadPolicyForNoBindingsGrantsNothing(t *testing.T) {
	t.Parallel()
	p, _, _ := newStore(t, nil)
	doc, err := p.SecretReadPolicy(nil)
	if err != nil {
		t.Fatalf("SecretReadPolicy(nil): %v", err)
	}
	if !doc.IsEmpty() {
		t.Fatalf("no bindings produced %d statement(s): %s", len(doc.Statement), mustJSON(t, doc))
	}
}

// TestSecretReadPolicyWithoutTheCapability is the typed refusal: a provider with
// no secret store cannot be asked for a grant against one.
func TestSecretReadPolicyWithoutTheCapability(t *testing.T) {
	t.Parallel()
	p := providerOver(t, aws.NewMemorySubstrate(), noSecretConfig())
	_, err := p.SecretReadPolicy(nil)
	if !errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("SecretReadPolicy on a provider with no secret store returned %v, want "+
			"compute.ErrUnsupported", err)
	}
}

// TestKMSDecryptOnlyForACustomerManagedKey covers both halves of a decision that
// is easy to get backwards: with a customer-managed key the grant is required
// and scopeable, and with the AWS-managed key it is neither.
func TestKMSDecryptOnlyForACustomerManagedKey(t *testing.T) {
	t.Parallel()

	t.Run("with a key", func(t *testing.T) {
		t.Parallel()
		// Configured here rather than in the shared fixture, so that both halves
		// of this test say which configuration they are about: the other subtest
		// needs the key ABSENT, and a default would make one of the two silently
		// depend on the fixture rather than on its own name.
		p, _, store := newStore(t, func(c *aws.Config) {
			c.Secrets.KMSKeyARN = "arn:aws:kms:" + aws.MemoryRegion + ":" + aws.MemoryAccount +
				":key/apphub-conformance"
		})
		ref := put(t, store, "app-1", "TOKEN", material, nil)
		doc, err := p.SecretReadPolicy(resolved(t, p, bindings(ref)))
		if err != nil {
			t.Fatalf("SecretReadPolicy: %v", err)
		}
		if len(doc.Statement) != 2 {
			t.Fatalf("a configured key produced %d statements, want 2", len(doc.Statement))
		}
		kms := doc.Statement[1]
		if !slices.Equal(kms.Action, []string{"kms:Decrypt"}) {
			t.Fatalf("the key statement grants %v", kms.Action)
		}
		want := "arn:aws:kms:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":key/apphub-conformance"
		if !slices.Equal(kms.Resource, []string{want}) {
			t.Fatalf("the key statement names %v, want %q", kms.Resource, want)
		}
		if got := kms.Condition["StringEquals"]["kms:ViaService"]; got != "ssm."+aws.MemoryRegion+".amazonaws.com" {
			t.Fatalf("the key statement's ViaService condition is %q; without it the workload could "+
				"decrypt ciphertext it obtained anywhere", got)
		}
	})

	t.Run("without a key", func(t *testing.T) {
		t.Parallel()
		p, _, store := newStore(t, func(c *aws.Config) { c.Secrets.KMSKeyARN = "" })
		ref := put(t, store, "app-1", "TOKEN", material, nil)
		doc, err := p.SecretReadPolicy(resolved(t, p, bindings(ref)))
		if err != nil {
			t.Fatalf("SecretReadPolicy: %v", err)
		}
		if len(doc.Statement) != 1 {
			t.Fatalf("no configured key produced %d statements, want 1: %s",
				len(doc.Statement), mustJSON(t, doc))
		}
		if strings.Contains(mustJSON(t, doc), "kms") {
			t.Fatal("the policy grants KMS against the AWS-managed key, which is neither needed " +
				"nor scopeable to one key")
		}
	})
}

// TestTheConfiguredKMSKeyIsPassedThroughAndNothingElseIsAccepted replaces a test
// that covered three ways an operator could name a key.
//
// Two of those three are gone: a bare key id and a bare alias used to be composed
// into an ARN against the configured partition, region and account, and composing
// an ARN is the one thing this package does not do -- every ARN it emits is read
// back from the substrate, because an ARN this package assembled is a claim about
// the account that nothing verified. Supporting the bare forms would have forced
// an account number back into Config, which is the only place one was ever
// configured here.
//
// So the surviving behaviour is pass-through, and the refusal is what stops a
// bare id becoming a policy Resource element IAM will not honour. Both halves are
// asserted: silently emitting a non-ARN would be a grant that fails at deploy
// time with no explanation, which is worse than refusing at construction.
func TestTheConfiguredKMSKeyIsPassedThroughAndNothingElseIsAccepted(t *testing.T) {
	t.Parallel()

	const keyARN = "arn:aws:kms:us-east-1:" + aws.MemoryAccount + ":key/already-an-arn"
	p, _, store := newStore(t, func(c *aws.Config) { c.Secrets.KMSKeyARN = keyARN })
	ref := put(t, store, "app-1", "TOKEN", material, nil)
	doc, err := p.SecretReadPolicy(resolved(t, p, bindings(ref)))
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}
	if got := doc.Statement[1].Resource[0]; got != keyARN {
		t.Fatalf("the configured key became %q, want it passed through as %q", got, keyARN)
	}

	for _, bad := range []string{
		"alias/apphub",
		"12345678-1234-1234-1234-123456789abc",
		"apphub-key",
	} {
		cfg := secretStoreConfig()
		cfg.Secrets.KMSKeyARN = bad
		if _, err := aws.New(aws.NewMemorySubstrate(), cfg); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("a KMS key configured as %q returned %v, want compute.ErrInvalidSpec: it "+
				"would reach a policy Resource element as-is", bad, err)
		}
	}
}

// TestPolicyResourceARNHasNoSeparatorBeforeThePath is the boundary an ARN
// composed by concatenation gets wrong, and it gets it wrong in both directions:
// an extra slash produces an ARN that matches nothing (fails closed but breaks
// the deploy) and a missing leading slash produces one that is not the
// parameter.
func TestPolicyResourceARNHasNoSeparatorBeforeThePath(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, nil)
	doc, err := p.SecretReadPolicy(resolved(t, p, bindings(ref)))
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}
	got := doc.Statement[0].Resource[0]
	if !strings.HasSuffix(got, ":parameter"+paramOf(t, ref)) {
		t.Fatalf("the resource ARN is %q; the parameter name already begins with a slash, so the "+
			"resource part is \"parameter\" immediately followed by it", got)
	}
	if strings.Contains(got, "parameter//") {
		t.Fatalf("the resource ARN has a doubled separator and matches nothing: %q", got)
	}
}

func mustJSON(t *testing.T, doc aws.PolicyDocument) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling the policy: %v", err)
	}
	return string(b)
}
