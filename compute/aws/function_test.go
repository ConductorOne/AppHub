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

// The tests in this file cover what the conformance suite cannot, and each one
// says which gap it is filling. Three of them exist because a check in the suite
// passes *vacuously* for a provider with this capability set — a green suite is
// not coverage — and the rest are behaviours the interface leaves to a provider.

// --- fixtures ---------------------------------------------------------------

// functionIdentity ensures the workload identity a function runs as.
//
// RunsOn is [compute.RuntimeFunction] deliberately in every call: it decides the
// trust policy, and a container identity produces a role Lambda cannot assume.
// TestAContainerIdentityCannotRunAFunction is the test that this matters.
func functionIdentity(t *testing.T, p *aws.Provider, name string) compute.Ref {
	t.Helper()
	id, err := p.Identities().EnsureWorkloadIdentity(context.Background(),
		compute.WorkloadIdentitySpec{Name: name, RunsOn: compute.RuntimeFunction})
	if err != nil {
		t.Fatalf("ensuring the function identity: %v", err)
	}
	return id.Ref
}

// functionSpec is a spec this provider accepts, so that each test below can
// change exactly one thing and show that the change is what was refused.
func functionSpec(name string, identity compute.Ref) compute.FunctionSpec {
	return compute.FunctionSpec{
		Name:      name,
		Runtime:   testRuntime,
		Handler:   "bootstrap",
		Code:      compute.CodeSource{Inline: []byte("bundle")},
		Resources: compute.Resources{MemoryMiB: 256},
		Timeout:   30 * time.Second,
		Env:       []compute.EnvVar{{Name: "KEPT", Value: "yes"}},
		Identity:  identity,
	}
}

func functionsOf(t *testing.T, p *aws.Provider) compute.FunctionRuntime {
	t.Helper()
	rt, err := p.Functions()
	if err != nil {
		t.Fatalf("acquiring the function port: %v", err)
	}
	return rt
}

// --- the transient mapping, per method of every port ------------------------

// TestEveryFunctionPortMethodMapsATransientFailureToErrTransient strengthens a
// conformance check rather than replacing one.
//
// **The suite's own gate runs now.** It used to skip unless the provider
// advertised CapSecretStore — "because a secret Put is the cheapest write on any
// provider" — which this provider does not, so
// provider/a-retryable-failure-is-ErrTransient did not execute at all and the
// friction USOSS-10 reported was real. USOSS-32 fixed it to drive whichever port
// the provider has, and it passes here.
//
// This is still worth having, and the difference is the population. The suite
// drives *one* port; this enumerates **every method of both**, because the
// mapping is per service: an implementation that reached ErrTransient from
// Lambda and ErrFailed from EC2 would satisfy any single-call check and still
// abandon a deploy that would have worked. Harness.InduceTransient arms Lambda,
// ELBv2, EC2, ECR, IAM and STS at once, so whichever service a method reaches
// first is the one that fails.
//
// USOSS-10 and USOSS-13 wrote the same shape for their ports while the gate was
// still unreachable; this is that shape applied to the function and endpoint
// ports, kept because the per-method population outlives the reason it was
// written.
func TestEveryFunctionPortMethodMapsATransientFailureToErrTransient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		method string
		call   func(rt compute.FunctionRuntime, fn, endpoint compute.Ref, id compute.Ref) error
	}{
		{"EnsureFunction", func(rt compute.FunctionRuntime, _, _ compute.Ref, id compute.Ref) error {
			_, err := rt.EnsureFunction(ctx, functionSpec("transient-ensure", id))
			return err
		}},
		{"DescribeFunction", func(rt compute.FunctionRuntime, fn, _ compute.Ref, _ compute.Ref) error {
			_, err := rt.DescribeFunction(ctx, fn)
			return err
		}},
		{"WaitForFunction", func(rt compute.FunctionRuntime, fn, _ compute.Ref, _ compute.Ref) error {
			_, err := rt.WaitForFunction(ctx, fn, compute.WaitOptions{Timeout: time.Second})
			return err
		}},
		{"DeleteFunction", func(rt compute.FunctionRuntime, fn, _ compute.Ref, _ compute.Ref) error {
			return rt.DeleteFunction(ctx, fn)
		}},
		{"EnsureEndpoint", func(rt compute.FunctionRuntime, fn, _ compute.Ref, _ compute.Ref) error {
			_, err := rt.EnsureEndpoint(ctx, endpointSpec("transient-endpoint", fn))
			return err
		}},
		{"DescribeEndpoint", func(rt compute.FunctionRuntime, _, ep compute.Ref, _ compute.Ref) error {
			_, err := rt.DescribeEndpoint(ctx, ep)
			return err
		}},
		{"WaitForEndpoint", func(rt compute.FunctionRuntime, _, ep compute.Ref, _ compute.Ref) error {
			_, err := rt.WaitForEndpoint(ctx, ep, compute.WaitOptions{Timeout: time.Second})
			return err
		}},
		{"DeleteEndpoint", func(rt compute.FunctionRuntime, _, ep compute.Ref, _ compute.Ref) error {
			return rt.DeleteEndpoint(ctx, ep)
		}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			rt := functionsOf(t, p)
			id := functionIdentity(t, p, "transient")

			// A function and an endpoint that exist, so that the read and delete
			// methods have a real resource to be interrupted on rather than
			// failing for absence.
			fn, err := rt.EnsureFunction(ctx, functionSpec("transient-target", id))
			if err != nil {
				t.Fatalf("seeding the function: %v", err)
			}
			ep, err := rt.EnsureEndpoint(ctx, endpointSpec("transient-seed", fn.Ref))
			if err != nil {
				t.Fatalf("seeding the endpoint: %v", err)
			}

			stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
			if err != nil {
				t.Fatalf("arming the transient failure: %v", err)
			}
			defer stop()

			err = tc.call(rt, fn.Ref, ep.Ref, id)
			switch {
			case err == nil:
				// Not a failure by itself: some methods reach a cached decision
				// or return before touching the armed service. Said out loud so
				// that a method quietly dropping out of coverage is visible.
				t.Skipf("%s did not reach the armed service, so its mapping was not exercised",
					tc.method)
			case errors.Is(err, compute.ErrTransient):
			case errors.Is(err, compute.ErrFailed):
				t.Fatalf("%s mapped a throttle to compute.ErrFailed (%v). That tells the caller "+
					"its spec has to change, and the deploy would have succeeded on a retry",
					tc.method, err)
			default:
				t.Fatalf("%s mapped a throttle to %v, which is neither ErrTransient nor a "+
					"recognised terminal error", tc.method, err)
			}
		})
	}
}

// --- placement, which the suite's own check skips ---------------------------

// TestAnUnconfiguredPlacementIsRefusedRatherThanDefaulted replaces another check
// that does not run here.
//
// conformance's abstraction/placement-is-an-operator-configured-name check skips
// with "Options do not supply a port that takes a Placement" — it drives the
// container, bucket, relational and secret ports, and this provider has none of
// them. Both ports in this package take a Placement, so the invariant is
// reachable and simply is not reached; that is a gap in the suite worth
// reporting, and meanwhile this is the check.
//
// The ruling this pins: a placement on AWS is **refused** when it cannot be
// honoured, never ignored. A caller that named a placement and silently got a
// resource somewhere else has been handed something it did not ask for, and has
// no way to find out.
func TestAnUnconfiguredPlacementIsRefusedRatherThanDefaulted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "placement")

	spec := functionSpec("placement", id)
	spec.Placement = compute.Placement{Name: "no-such-placement"}
	_, err := rt.EnsureFunction(ctx, spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("an unconfigured placement was answered with %v; it must be ErrInvalidSpec, "+
			"because falling back to a default strands the resource somewhere nothing addresses", err)
	}

	fn, err := rt.EnsureFunction(ctx, functionSpec("placement-ok", id))
	if err != nil {
		t.Fatalf("seeding the function: %v", err)
	}
	ep := endpointSpec("placement-endpoint", fn.Ref)
	ep.Placement = compute.Placement{Name: "no-such-placement"}
	if _, err := rt.EnsureEndpoint(ctx, ep); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("an unconfigured placement on an endpoint was answered with %v, want "+
			"ErrInvalidSpec", err)
	}
}

// TestAPlacementInAnotherRegionIsRefused is the sharper half of the same ruling.
//
// The interface's own text says an AWS provider "can ignore" placement because
// an IAM role is account-global. That reading is wrong for anything regional,
// and PlacementConfig.Region exists precisely so a placement can differ in
// region — so the mismatch is reachable through ordinary configuration, and a
// provider that ignored it would create a function in the region its clients
// happen to address while the caller asked for another.
func TestAPlacementInAnotherRegionIsRefused(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, func(cfg *aws.Config) {
		pc := endpointPlacement()
		pc.Region = "some-other-region"
		cfg.Placements["elsewhere"] = pc
	})
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "region")

	spec := functionSpec("region", id)
	spec.Placement = compute.Placement{Name: "elsewhere"}
	_, err := rt.EnsureFunction(ctx, spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a placement in another region was answered with %v; this provider's clients "+
			"address one region and silently using it is handing the caller a resource it did "+
			"not ask for", err)
	}
	if !strings.Contains(err.Error(), "some-other-region") {
		t.Errorf("the refusal does not name the region the caller asked for: %v", err)
	}
}

// --- the two-mutation path --------------------------------------------------

// TestASpecChangingBothCodeAndConfigurationIsTransientRatherThanBlocking is the
// behaviour EnsureFunction's doc comment describes, driven rather than asserted.
//
// Lambda refuses a code update while a configuration update is in flight, and
// compute.Status forbids blocking inside an asynchronous Ensure. So the only
// answer that neither blocks nor reports success with half a spec applied is to
// apply the configuration, report compute.ErrTransient, and let the caller's
// retry finish the job.
//
// The in-memory substrate reproduces the conflict rather than describing it,
// which is what makes this a test and not a comment: MemoryLambda refuses a
// second mutation while LastUpdateStatus is InProgress, exactly as Lambda does.
func TestASpecChangingBothCodeAndConfigurationIsTransientRatherThanBlocking(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "twostep")

	spec := functionSpec("twostep", id)
	created, err := rt.EnsureFunction(ctx, spec)
	if err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}
	// Settle it, the way a caller's Wait would between the create and the next
	// deploy. Nothing in this test may reach EnsureFunction incidentally: an
	// Ensure is a mutation, and one issued as a side effect of a helper would put
	// the function back into an updating state and make the conflict below look
	// like a defect in the retry rather than in the test.
	if _, err := rt.WaitForFunction(ctx, created.Ref, compute.WaitOptions{
		Timeout: 2 * time.Second,
	}); err != nil {
		t.Fatalf("waiting for the function: %v", err)
	}

	changed := spec
	changed.Resources = compute.Resources{MemoryMiB: 512}
	changed.Code = compute.CodeSource{Inline: []byte("a different bundle")}

	start := time.Now()
	_, err = rt.EnsureFunction(ctx, changed)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a spec changing both the configuration and the code was accepted in one call; " +
			"Lambda serialises the two mutations, so either this blocked (which compute.Status " +
			"forbids) or the code update did not happen")
	}
	if !errors.Is(err, compute.ErrTransient) {
		t.Fatalf("the refusal was %v; it has to be compute.ErrTransient, because the caller's "+
			"correct next move is to re-Ensure the same spec", err)
	}
	if elapsed > time.Second {
		t.Errorf("the call took %s, which suggests it waited for the configuration update to "+
			"settle; an asynchronous Ensure must not block", elapsed)
	}

	// The retry finishes it, which is what makes ErrTransient the honest answer
	// rather than an excuse. Without this half, the test would accept a provider
	// that returned ErrTransient forever.
	if _, err := rt.WaitForFunction(ctx, created.Ref, compute.WaitOptions{
		Timeout: 2 * time.Second,
	}); err != nil {
		t.Fatalf("waiting between the two Ensures: %v", err)
	}
	st, err := rt.EnsureFunction(ctx, changed)
	if err != nil {
		t.Fatalf("the retry failed with %v; the whole justification for ErrTransient is that the "+
			"retry converges", err)
	}
	if st.Spec.Resources.MemoryMiB != 512 {
		t.Errorf("the effective spec reports %d MiB after both Ensures, want 512",
			st.Spec.Resources.MemoryMiB)
	}
}

// --- the refusals -----------------------------------------------------------

// TestTheFunctionPortRefusesWhatItCannotHonour is one table over every spec
// field this port declines, because each of them is a place where accepting
// would report something the provider did not do.
//
// A class rather than a case: the shared property is "a field this substrate
// cannot honour is refused, not ignored", and every entry is an instance of it.
// Written as a table so that adding a field to FunctionSpec forces a decision
// about which side of the line it is on.
func TestTheFunctionPortRefusesWhatItCannotHonour(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		what   string
		mutate func(*compute.FunctionSpec)
		why    string
	}{
		{
			what:   "an unconfigured runtime",
			mutate: func(s *compute.FunctionSpec) { s.Runtime = "nodejs99.x" },
			why: "substituting a runtime runs the caller's bundle under an interpreter it was " +
				"not built for, which is what the source system does for an empty one",
		},
		{
			what:   "an empty runtime",
			mutate: func(s *compute.FunctionSpec) { s.Runtime = "" },
			why:    "the source system substitutes a default here",
		},
		{
			what:   "no handler",
			mutate: func(s *compute.FunctionSpec) { s.Handler = "" },
			why: "the source system derives one from the runtime and defaults to a Node.js " +
				"handler for a runtime it does not recognise, so a Go bundle deploys and fails " +
				"at the first invocation",
		},
		{
			what:   "no code at all",
			mutate: func(s *compute.FunctionSpec) { s.Code = compute.CodeSource{} },
			why: "the source system synthesises a placeholder bundle, which deploys a function " +
				"indistinguishable from a broken application",
		},
		{
			what: "both an inline bundle and an object location",
			mutate: func(s *compute.FunctionSpec) {
				// The key is a path with no file extension deliberately. A bare
				// two-label string is what the disclosure scan reads as a
				// hostname — correctly, since it cannot tell one from the other —
				// and this case is about CodeSource carrying two fields, so the
				// key's spelling carries no information.
				s.Code.Object = &compute.ObjectLocation{Key: "artifacts/bundle"}
			},
			why: "CodeSource admits exactly one",
		},
		{
			what: "an explicit CPU allocation",
			mutate: func(s *compute.FunctionSpec) {
				s.Resources.CPUMillicores = 500
			},
			why: "Lambda derives CPU from memory and cannot honour a request; accepting one " +
				"hands the caller a function with a capacity it did not ask for",
		},
		{
			what:   "memory below what the substrate accepts",
			mutate: func(s *compute.FunctionSpec) { s.Resources.MemoryMiB = 64 },
			why:    "reported against the spec rather than by the Lambda API mid-deploy",
		},
		{
			what:   "memory above what the substrate accepts",
			mutate: func(s *compute.FunctionSpec) { s.Resources.MemoryMiB = 20000 },
			why:    "same",
		},
		{
			what:   "a timeout longer than the substrate allows",
			mutate: func(s *compute.FunctionSpec) { s.Timeout = time.Hour },
			why:    "same",
		},
		{
			what:   "a timeout that is not a whole number of seconds",
			mutate: func(s *compute.FunctionSpec) { s.Timeout = 1500 * time.Millisecond },
			why: "refused rather than rounded: rounding down is a shorter timeout than the " +
				"caller asked for and rounding up bills for longer, and three sibling ports " +
				"made the same call",
		},
		{
			what:   "an architecture the interface does not define",
			mutate: func(s *compute.FunctionSpec) { s.Architecture = "riscv64" },
			why:    "a bundle built for one architecture does not run on another",
		},
		{
			what: "an ingress rule",
			mutate: func(s *compute.FunctionSpec) {
				s.Ingress = []compute.IngressRule{
					{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443},
				}
			},
			why: "a Lambda function has no inbound network surface, so accepting a rule set " +
				"would report a restriction the provider did not apply",
		},
		{
			what:   "no identity",
			mutate: func(s *compute.FunctionSpec) { s.Identity = compute.Ref{} },
			why:    "a workload with no identity cannot be granted access to anything",
		},
		{
			what:   "an empty name",
			mutate: func(s *compute.FunctionSpec) { s.Name = "" },
			why:    "there is no physical name for it",
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			rt := functionsOf(t, p)
			spec := functionSpec("refusal", functionIdentity(t, p, "refusal"))
			tc.mutate(&spec)
			_, err := rt.EnsureFunction(context.Background(), spec)
			if err == nil {
				t.Fatalf("%s was accepted; %s", tc.what, tc.why)
			}
			if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrUnsupported) {
				t.Fatalf("%s was refused with %v, which is neither ErrInvalidSpec nor "+
					"ErrUnsupported, so a caller cannot tell a bad spec from a broken provider", tc.what, err)
			}
		})
	}
	_ = ctx
}

// TestASecretBindingIsRefusedRatherThanResolved is separated out because it is a
// security property and not a validation rule.
//
// compute.SecretBinding is explicit that the value is never read by apphub at
// deploy time: the provider hands the runtime a reference and the runtime
// resolves it at launch. Lambda has no such mechanism — a function's environment
// holds literal values — so honouring a binding would mean this provider reading
// the material and writing it into durable function configuration readable by
// anyone with lambda:GetFunction. That is exactly the property the type exists to
// protect.
func TestASecretBindingIsRefusedRatherThanResolved(t *testing.T) {
	t.Parallel()

	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	spec := functionSpec("secret", functionIdentity(t, p, "secret"))
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "secret/x"},
	}}
	_, err := rt.EnsureFunction(context.Background(), spec)
	if err == nil {
		t.Fatal("a secret binding was accepted. Lambda resolves no reference at launch, so " +
			"either the material was read and written into durable function configuration, or " +
			"the binding resolves to nothing at runtime")
	}
	// ErrInvalidSpec, not ErrUnsupported: this provider advertises
	// CapSecretStore (fullConfig configures Config.Secrets), so the refusal
	// cannot honestly name an absent capability -- it is this field, on this
	// resource, that cannot be honoured. See the refusal site in function.go.
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("the refusal was %v, want ErrInvalidSpec: the provider advertises "+
			"CapSecretStore, so this cannot honestly be reported as an absent capability", err)
	}
	if errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("the refusal was %v and also matches ErrUnsupported: this provider "+
			"advertises CapSecretStore, so a caller checking Capabilities() first and then "+
			"seeing ErrUnsupported here would be told two contradictory things", err)
	}
}

// TestASecretBindingRefusalDoesNotContradictCapabilities is B2's regression
// pin: the SecretBinding refusal above must never be reported through
// [compute.UnsupportedError] naming [compute.CapSecretStore], because this
// provider advertises that capability whenever Config.Secrets is configured --
// which fullConfig always does. A caller that does the discoverable thing --
// check Capabilities(), then act -- must not be told two opposite things by the
// same provider.
func TestASecretBindingRefusalDoesNotContradictCapabilities(t *testing.T) {
	t.Parallel()

	p, _ := newProvider(t, nil)
	if !p.Capabilities().Has(compute.CapSecretStore) {
		t.Fatal("fullConfig configures Config.Secrets, so this provider must advertise " +
			"CapSecretStore; the rest of this test is meaningless otherwise")
	}
	rt := functionsOf(t, p)
	spec := functionSpec("secret-cap", functionIdentity(t, p, "secret-cap"))
	spec.Secrets = []compute.SecretBinding{{
		EnvName: "TOKEN",
		Secret:  compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "secret/x"},
	}}
	_, err := rt.EnsureFunction(context.Background(), spec)
	if err == nil {
		t.Fatal("a secret binding was accepted")
	}
	var unsupported *compute.UnsupportedError
	if errors.As(err, &unsupported) && unsupported.Capability == compute.CapSecretStore {
		t.Fatalf("the refusal names CapSecretStore as unsupported (%v), while "+
			"Capabilities().Has(CapSecretStore) is true -- this is exactly the contradiction B2 "+
			"reported", err)
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("the refusal was %v, want ErrInvalidSpec", err)
	}
}

// TestAnUnrecognisedWorkloadCapabilityIsErrInvalidSpec is N1's fix and pin.
//
// compute/identity.go is explicit that an unrecognised [compute.WorkloadCapability]
// resolves to the empty [compute.Capability], "which a provider must treat as
// [compute.ErrInvalidSpec] rather than as 'no requirement'". An earlier revision
// refused with ErrUnsupported naming CapModelInference regardless of what the
// caller actually asked for.
func TestAnUnrecognisedWorkloadCapabilityIsErrInvalidSpec(t *testing.T) {
	t.Parallel()

	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	spec := functionSpec("bad-cap", functionIdentity(t, p, "bad-cap"))
	spec.Capabilities = []compute.WorkloadCapability{"not-a-real-capability"}
	_, err := rt.EnsureFunction(context.Background(), spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("an unrecognised workload capability was answered with %v, want ErrInvalidSpec",
			err)
	}
	if errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("the refusal was %v and also matches ErrUnsupported: an unrecognised value must "+
			"not be treated as 'no requirement' widened to a fixed known capability", err)
	}
	var unsupported *compute.UnsupportedError
	if errors.As(err, &unsupported) {
		t.Fatalf("the refusal names capability %q; an unrecognised value was never asked for it",
			unsupported.Capability)
	}
}

// TestADuplicateEnvironmentVariableIsRefused is B3's fix and pin.
//
// [compute.EnvVar] carries one value per name; two entries for the same name are
// ambiguous, and letting the last one win would silently drop the first without
// the caller ever finding out which value actually reached the function. This
// pins the refusal implementing environment's own doc comment describes.
func TestADuplicateEnvironmentVariableIsRefused(t *testing.T) {
	t.Parallel()

	p, _ := newProvider(t, nil)
	rt := functionsOf(t, p)
	spec := functionSpec("dup-env", functionIdentity(t, p, "dup-env"))
	spec.Env = []compute.EnvVar{
		{Name: "TOKEN", Value: "first"},
		{Name: "TOKEN", Value: "second"},
	}
	_, err := rt.EnsureFunction(context.Background(), spec)
	if err == nil {
		t.Fatal("a spec with two entries for the same environment variable was accepted; the " +
			"effective spec cannot say which value reached the function")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("the refusal was %v, want ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "TOKEN") {
		t.Errorf("the refusal does not name the duplicate variable: %v", err)
	}
}

// TestAContainerIdentityCannotRunAFunction pins the trust-policy check.
//
// compute.WorkloadIdentitySpec.RunsOn exists for this substrate: an AWS role
// trusted by ecs-tasks.amazonaws.com cannot be assumed by Lambda. Without the
// check a caller who reused a container identity gets a function that creates
// successfully and cannot start, reported by Lambda as an obscure
// InvalidParameterValueException about a role it cannot assume.
func TestAContainerIdentityCannotRunAFunction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, _ := newProvider(t, nil)
	id, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "container-identity", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("ensuring the container identity: %v", err)
	}
	rt := functionsOf(t, p)
	_, err = rt.EnsureFunction(ctx, functionSpec("wrong-identity", id.Ref))
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a container identity was accepted for a function (%v); the role's trust policy "+
			"names ecs-tasks.amazonaws.com and Lambda cannot assume it", err)
	}
}

// TestAnObjectKeyThatCouldTraverseIsRefused covers the confinement obligation
// compute.ObjectLocation.Key states.
//
// It is validated on the **raw** key, and this table is why: cleaning first and
// then checking is checking a different string from the one that reaches the
// service — path.Clean turns "a/../../b" into "../b", so a prefix check on the
// cleaned form passes for a key whose raw form escapes.
//
// The provider has no object store configured, so a legal key is refused too —
// with ErrUnsupported, not ErrInvalidSpec. The distinction is the assertion:
// this test would pass vacuously if every key were refused the same way, so the
// legal key's refusal is checked to be the *other* error.
func TestAnObjectKeyThatCouldTraverseIsRefused(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// No object store, so the control case below reaches ErrUnsupported rather
	// than a real bucket lookup -- fullConfig has advertised CapObjectStore
	// since USOSS-13, and the control's whole point is showing the traversal
	// table above is about key validation and not about a missing port.
	p, _ := newProvider(t, func(cfg *aws.Config) { cfg.ObjectStore = nil })
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "keys")
	bucket := compute.Ref{Provider: p.Name(), Kind: compute.KindBucket, ID: "bucket/artifacts"}

	for _, key := range []string{
		"",
		"/bundle.zip",
		"../bundle.zip",
		"a/../../b/bundle.zip",
		"a/b/../../../bundle.zip",
		"a//bundle.zip",
		"./bundle.zip",
		"bundle.zip/",
		"a/./b/bundle.zip",
		"bundle\x00.zip",
		"a\\..\\bundle.zip",
	} {
		t.Run("refused:"+key, func(t *testing.T) {
			t.Parallel()
			spec := functionSpec("key", id)
			spec.Code = compute.CodeSource{Object: &compute.ObjectLocation{Bucket: bucket, Key: key}}
			_, err := rt.EnsureFunction(ctx, spec)
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("key %q was answered with %v; a key that could address something "+
					"outside the bucket has to be ErrInvalidSpec, and it has to be decided on "+
					"the raw key rather than a cleaned one", key, err)
			}
		})
	}

	// The control. A legal key reaches the object-store lookup and is refused
	// there, for a different reason — which is what shows the table above is
	// testing key validation rather than the absence of an object store.
	spec := functionSpec("key-ok", id)
	spec.Code = compute.CodeSource{Object: &compute.ObjectLocation{Bucket: bucket, Key: "a/b/bundle.zip"}}
	_, err := rt.EnsureFunction(ctx, spec)
	switch {
	case err == nil:
		t.Fatal("a legal object key was accepted against a provider with no object store")
	case errors.Is(err, compute.ErrInvalidSpec):
		t.Fatalf("a legal object key was refused as a bad spec (%v); it should reach the "+
			"object-store port and be refused as an absent capability, and if it is not then "+
			"the table above proves nothing about key validation", err)
	case !errors.Is(err, compute.ErrUnsupported):
		t.Fatalf("a legal object key was refused with %v, want ErrUnsupported naming the "+
			"missing object store", err)
	}
}

// TestAnInlineBundleOverTheLimitIsNamedRatherThanTruncated covers the obligation
// compute.CodeSource.Inline states. A truncated zip is not a smaller deployment,
// it is a corrupt one, and Lambda reports it as a runtime error in a function
// that deployed successfully.
func TestAnInlineBundleOverTheLimitIsNamedRatherThanTruncated(t *testing.T) {
	t.Parallel()

	p, _ := newProvider(t, func(cfg *aws.Config) {
		cfg.Function.MaxInlineBytes = 16
	})
	rt := functionsOf(t, p)
	spec := functionSpec("big", functionIdentity(t, p, "big"))
	spec.Code = compute.CodeSource{Inline: make([]byte, 17)}
	_, err := rt.EnsureFunction(context.Background(), spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("an oversized bundle was answered with %v, want ErrInvalidSpec naming the limit", err)
	}
	if !strings.Contains(err.Error(), "16") {
		t.Errorf("the refusal does not name the limit: %v", err)
	}
}

// TestTheCallersBundleIsNotAliasedIntoTheProvider.
//
// compute.Status requires that a read-back share no storage with the provider,
// and the conformance suite checks that direction. This is the other direction,
// which nothing checks: the provider holds a slice the caller supplied. A caller
// that reused its buffer for the next deploy would be editing what this provider
// believes it uploaded.
func TestTheCallersBundleIsNotAliasedIntoTheProvider(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p, sub := newProvider(t, nil)
	rt := functionsOf(t, p)
	id := functionIdentity(t, p, "alias")

	bundle := []byte("original bundle")
	spec := functionSpec("alias", id)
	spec.Code = compute.CodeSource{Inline: bundle}
	if _, err := rt.EnsureFunction(ctx, spec); err != nil {
		t.Fatalf("the first Ensure failed: %v", err)
	}
	mem, ok := sub.Lambda.(*aws.MemoryLambda)
	if !ok {
		t.Fatal("expected the in-memory Lambda substrate")
	}
	before := mem.Dump()

	// The caller reuses its buffer, which is the ordinary thing to do.
	copy(bundle, "OVERWRITTEN!!!!")

	after := mem.Dump()
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("overwriting the caller's slice changed what the substrate holds. The provider "+
			"stored a window onto the caller's storage.\n  before: %v\n   after: %v", before, after)
	}
}
