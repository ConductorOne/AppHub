// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// The security properties of the function and endpoint ports.
//
// Two of the conformance suite's security checks cannot exercise anything
// against this provider: security/secret-bindings-travel-by-reference and
// security/secret-material-does-not-appear-in-rendered-artefacts both need a
// secret store to plant their sentinel, and this provider has none.
//
// They used to report a *pass* for that — scanning the rendered artefacts for a
// sentinel nobody had planted — which is what USOSS-10's friction doc §4 was
// about. USOSS-32 turned that into an honest skip, so the suite no longer
// overstates. It still does not check anything here, which is why these tests
// exist: an honest skip is information, not coverage.

// --- ownership across four components ---------------------------------------

// TestTheFourEndpointComponentsAreNotInterchangeable is the §10 class check the
// ticket asks for, applied to every object this port creates.
//
// The finding it generalises: an ownership check that reads only the ownership
// tag makes every resource apphub owns interchangeable by name. This port
// creates four objects — a function, a load balancer, a target group and a
// security group — under two physical names, and the load balancer and the
// target group deliberately **share** one. What keeps them apart is the
// apphub:component tag, so the check has to be that a resource apphub owns as
// something else is refused, not merely that a resource nobody owns is.
//
// conformance's own ownership check plants a resource with *no* ownership tag,
// which is the easier half. This is the harder half: a resource with the right
// owner tag and the wrong component, which is what a sibling AWS port creating
// its own security group in the same VPC would produce.
func TestTheFourEndpointComponentsAreNotInterchangeable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		what  string
		plant func(t *testing.T, sub *aws.Substrate, physical string)
	}{
		{
			what: "a security group apphub owns as something else",
			plant: func(t *testing.T, sub *aws.Substrate, physical string) {
				t.Helper()
				// Exactly what a sibling port creating a service's own security
				// group in this VPC would leave behind: apphub's owner tag, a
				// different component.
				if _, err := sub.EndpointEC2.CreateSecurityGroup(ctx, aws.EndpointCreateSecurityGroupRequest{
					Name:  physical,
					VpcID: aws.MemoryVPC,
					Tags: map[string]string{
						"apphub:managed-by": "apphub",
						"apphub:name":       physical,
						"apphub:component":  "container-service",
					},
				}); err != nil {
					t.Fatalf("planting the security group: %v", err)
				}
			},
		},
		{
			what: "a target group apphub owns as something else",
			plant: func(t *testing.T, sub *aws.Substrate, physical string) {
				t.Helper()
				if _, err := sub.ELBv2.CreateTargetGroup(ctx, aws.CreateTargetGroupRequest{
					Name:       physical,
					TargetType: aws.TargetTypeLambda,
					Tags: map[string]string{
						"apphub:managed-by": "apphub",
						"apphub:name":       physical,
						// The load balancer's own component, which is the
						// interesting case: the two share a physical name.
						"apphub:component": "function-endpoint",
					},
				}); err != nil {
					t.Fatalf("planting the target group: %v", err)
				}
			},
		},
		{
			what: "a load balancer apphub owns as something else",
			plant: func(t *testing.T, sub *aws.Substrate, physical string) {
				t.Helper()
				if _, err := sub.ELBv2.CreateLoadBalancer(ctx, aws.CreateLoadBalancerRequest{
					Name:      physical,
					SubnetIDs: []string{aws.MemorySubnetA, aws.MemorySubnetB},
					Scheme:    "internet-facing",
					Tags: map[string]string{
						"apphub:managed-by": "apphub",
						"apphub:name":       physical,
						"apphub:component":  "function-endpoint-targets",
					},
				}); err != nil {
					t.Fatalf("planting the load balancer: %v", err)
				}
			},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			p, sub, rt, fn := endpointFixture(t, nil)
			const logical = "collision"

			// The plant lands under the logical name, which is also the physical
			// one here: "collision" is short and already in the sanitized
			// alphabet, so it renders verbatim.
			//
			// That is an assumption, and it is worth saying why it does not need
			// its own assertion. If the mapping changed and the plant landed
			// where the provider does not look, there would be no collision, so
			// EnsureEndpoint would **succeed** — and a success is what this test
			// fails on. The test cannot pass for the wrong reason; it can only
			// fail with a message that blames the wrong thing.
			tc.plant(t, sub, logical)

			_, err := rt.EnsureEndpoint(ctx, endpointSpec(logical, fn))
			if !errors.Is(err, compute.ErrNotOwned) {
				t.Fatalf("%s was adopted (%v). The ownership tag alone makes every resource "+
					"apphub owns interchangeable by name, and this port creates four objects "+
					"under two names — two of which are deliberately the same name",
					tc.what, err)
			}
			// And nothing was written to it on the way to the refusal. An Ensure
			// that refuses after mutating has already done the damage the
			// refusal exists to prevent.
			for _, line := range rendered(t, p) {
				if strings.Contains(line, "container-service") &&
					strings.Contains(line, "ingress=tcp") {
					t.Errorf("rules were authorised on a security group this port then refused "+
						"to adopt: %s", line)
				}
			}
		})
	}
}

// TestThisPortCreatesNoIAMRole.
//
// The instruction it answers: "if your port creates an IAM role, tag it with a
// distinct component and check both — an IAM role is account-global and every
// AWS port here creates roles." This one does not create any. A function's
// execution role arrives as compute.FunctionSpec.Identity, resolved through the
// workload-identity port that already owns roles, so the source system's
// ensureLambdaRole (lambda.go:935-985) is deliberately not ported.
//
// Checked rather than claimed, because "this port creates no roles" is exactly
// the kind of statement that stops being true in a later commit and takes a
// second account-global namespace with it.
func TestThisPortCreatesNoIAMRole(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, sub, rt, fn := endpointFixture(t, nil)
	mem, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("expected the in-memory IAM substrate")
	}
	before := len(mem.Dump())
	if before == 0 {
		t.Fatal("no role exists before the endpoint deploy, so this test would pass against a " +
			"provider that created one and a fixture that created none")
	}

	if _, err := rt.EnsureEndpoint(ctx, endpointSpec("no-roles", fn)); err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	if after := len(mem.Dump()); after != before {
		t.Fatalf("deploying an endpoint created %d IAM role(s). An IAM role is account-global, "+
			"the workload-identity port already owns that namespace, and a second port creating "+
			"roles is how a trust relationship gets repurposed:\n%s",
			after-before, strings.Join(mem.Dump(), "\n"))
	}
	_ = p
}

// TestNoAWSManagedPolicyIsAttachedToAFunctionsRole.
//
// The source system attaches AWSLambdaBasicExecutionRole to every execution role
// it creates (lambda.go:970-976), and that managed policy grants
// logs:CreateLogGroup, logs:CreateLogStream and logs:PutLogEvents on
// arn:aws:logs:*:*:* — every log group in the account, not the function's own.
// It is reported as a source finding and not fixed here, and this port does not
// reproduce it: it attaches nothing at all, which is a strictly narrower
// position than attaching a narrowed policy would be.
//
// The consequence is stated in the report: a function deployed through this port
// has no CloudWatch Logs permission unless the operator's identity configuration
// gives it one, which is a behaviour difference a reviewer should check rather
// than a defect to fix inside a port whose contract is that a role it touches
// carries a trust policy and nothing else.
func TestNoAWSManagedPolicyIsAttachedToAFunctionsRole(t *testing.T) {
	t.Parallel()

	p, _, rt, fn := endpointFixture(t, nil)
	if _, err := rt.EnsureEndpoint(context.Background(), endpointSpec("no-policies", fn)); err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}
	for _, line := range rendered(t, p) {
		for _, forbidden := range []string{
			"AWSLambdaBasicExecutionRole",
			"arn:aws:iam::aws:policy",
			"arn:aws:logs:*",
		} {
			if strings.Contains(line, forbidden) {
				t.Errorf("a policy was attached to a role by this port (%q in %q). A role this "+
					"package touches carries a trust policy and tags and nothing else, and a "+
					"port that attaches a policy owns detaching it", forbidden, line)
			}
		}
	}
}

// --- no material and no identifier in anything rendered ---------------------

// TestNothingThisPortRendersCarriesMaterialOrAnInternalIdentifier is this port's
// replacement for the two vacuous suite checks.
//
// It is stronger than a sentinel search in one respect and weaker in another,
// and both are worth stating. Stronger: it looks for the shapes of the things
// CONTRACT.md forbids committing, not for one planted value, so a hostname or an
// account-shaped number arriving from anywhere is caught. Weaker: it can only
// see what the harness renders, so a value the provider held and never wrote is
// invisible to it — which is why the refusal tests exist alongside it rather
// than instead of it.
func TestNothingThisPortRendersCarriesMaterialOrAnInternalIdentifier(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _, rt, fn := endpointFixture(t, nil)
	// A caller's own metadata, which is the one place a caller-supplied string
	// legitimately reaches a rendered artefact. Included so that the scan below
	// has something real to walk rather than only provider-authored text.
	spec := endpointSpec("rendered", fn)
	spec.Labels = map[string]string{"owner": "test", "application": "checkout"}
	if _, err := rt.EnsureEndpoint(ctx, spec); err != nil {
		t.Fatalf("EnsureEndpoint failed: %v", err)
	}

	artefacts := rendered(t, p)
	if len(artefacts) == 0 {
		t.Fatal("nothing was rendered, so this test proved nothing")
	}
	joined := strings.Join(artefacts, "\n")

	for _, forbidden := range []struct {
		value string
		what  string
	}{
		// A certificate-less TLS listener is the artefact the source system
		// produces for every port other than 80. It must be unrenderable here,
		// and it is: the certificate token is written only inside the branch
		// that has an ARN.
		{`certificate=""`, "a TLS listener with no certificate"},
		{"certificate=)", "a TLS listener with no certificate"},
		// Credential material has no path into this port at all — a
		// SecretBinding is refused — so any of these appearing would mean a path
		// nobody intended.
		{"AKIA", "an access key identifier"},
		{"ASIA", "a session access key identifier"},
		{"aws_secret_access_key", "a credential file key"},
		{"BEGIN PRIVATE KEY", "a private key"},
	} {
		if strings.Contains(joined, forbidden.value) {
			t.Errorf("%s (%q) appears in a rendered artefact:\n%s",
				forbidden.what, forbidden.value, joined)
		}
	}

	// The account position in every fixture ARN is a word, not a number, so a
	// twelve-digit run anywhere is either a real account identifier that reached
	// a fixture or a shape indistinguishable from one. Checked as a shape rather
	// than against a value, because a detection rule containing a real
	// identifier is itself a leak.
	if run := longestDigitRun(joined); run >= 12 {
		t.Errorf("a run of %d digits appears in a rendered artefact, which is the shape of an "+
			"AWS account identifier; every fixture here puts a word in that position:\n%s",
			run, joined)
	}
}

// longestDigitRun reports the longest run of consecutive digits in s.
//
// A shape test rather than a value test, which is the rule CONTRACT.md states:
// "do not put a real identifier into a detection rule."
func longestDigitRun(s string) int {
	best, run := 0, 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			run++
			if run > best {
				best = run
			}
			continue
		}
		run = 0
	}
	return best
}

// TestAFunctionsEnvironmentIsOnlyWhatTheCallerDeclared.
//
// The environment is the one durable place this port writes caller-supplied
// strings, and it is durable in a way a task definition is not: it is readable
// by anyone with lambda:GetFunction. So two things have to hold, and the second
// is the one an implementation gets wrong. The variables the caller declared are
// there; **nothing else** is, and in particular the provider does not add any of
// its own — a provider that injected an identifier or a handler hint would be
// putting information into a place a caller reasonably treats as theirs.
func TestAFunctionsEnvironmentIsOnlyWhatTheCallerDeclared(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	spec := functionSpec("environment", functionIdentity(t, p, "environment"))
	spec.Env = []compute.EnvVar{
		{Name: "DECLARED_ONE", Value: "a"},
		{Name: "DECLARED_TWO", Value: "b"},
	}
	if _, err := rt.EnsureFunction(ctx, spec); err != nil {
		t.Fatalf("EnsureFunction failed: %v", err)
	}

	var line string
	for _, l := range rendered(t, p) {
		if strings.HasPrefix(l, "Function ") && strings.Contains(l, "environment") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("the function was not rendered, so this test proved nothing")
	}
	for _, want := range []string{"DECLARED_ONE=a", "DECLARED_TWO=b"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q is missing from the function's environment: %s", want, line)
		}
	}
	// Count the variables rather than look for known-bad names, because the
	// point is that the set is exactly the caller's and a name nobody thought of
	// would pass a denylist.
	if got := strings.Count(line, "DECLARED_"); got != 2 {
		t.Errorf("expected exactly the two declared variables, found %d occurrences: %s", got, line)
	}
	for _, unexpected := range []string{
		"APPHUB_", "AWS_", "_HANDLER", "LAMBDA_",
	} {
		if strings.Contains(line, unexpected) {
			t.Errorf("the provider added %q to the function's environment; the environment is "+
				"durable and readable with lambda:GetFunction, and it belongs to the caller: %s",
				unexpected, line)
		}
	}
}

// TestAnEnvironmentVariableRemovedFromASpecIsGone is the declarative half for the
// one durable caller-supplied surface this port writes.
//
// The suite checks this through its own marker, and it does run for the function
// port — but only through the effective spec and the rendered dump, both of which
// this test also uses. It is repeated here because the failure mode is specific
// and worth its own name: Lambda's UpdateFunctionConfiguration *replaces* the
// environment, so an implementation that merged instead would accumulate every
// variable the application had ever declared, including ones whose values were
// rotated out.
func TestAnEnvironmentVariableRemovedFromASpecIsGone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	spec := functionSpec("shrinking", functionIdentity(t, p, "shrinking"))
	spec.Env = []compute.EnvVar{
		{Name: "KEPT", Value: "yes"},
		{Name: "REMOVED", Value: "yes"},
	}
	st, err := rt.EnsureFunction(ctx, spec)
	if err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}
	if !renderedContains(t, p, "REMOVED=yes") {
		t.Fatal("the variable was never written, so this test cannot show it being removed")
	}

	if _, err := rt.WaitForFunction(ctx, st.Ref, waitBriefly()); err != nil {
		t.Fatalf("settling the function: %v", err)
	}
	spec.Env = []compute.EnvVar{{Name: "KEPT", Value: "yes"}}
	if _, err := rt.EnsureFunction(ctx, spec); err != nil {
		t.Fatalf("the second Ensure failed: %v", err)
	}
	if renderedContains(t, p, "REMOVED=yes") {
		t.Fatalf("the variable survived a spec that omits it; Ensure merged rather than "+
			"replacing:\n%s", strings.Join(rendered(t, p), "\n"))
	}
	if !renderedContains(t, p, "KEPT=yes") {
		t.Error("the variable the spec still names was removed too")
	}
}

func waitBriefly() compute.WaitOptions {
	return compute.WaitOptions{Timeout: 2 * time.Second}
}
