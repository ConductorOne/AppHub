// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// TestAReadAloneConsultsTheInjector is the measurement that killed a wrong
// diagnosis, kept because the wrong one will look plausible to the next reader
// too (USOSS-60).
//
// The symptom was that only the first driven method of a conformance run
// surfaced an induced failure. Two hypotheses explain it exactly:
//
//  1. the injector is consulted by writes and not by reads;
//  2. the injector is one-shot, so the first intercepted call — whichever verb —
//     consumes the arming.
//
// The first was reported as a finding across three providers, and the pattern
// made it feel derived rather than guessed. It is false, and this is the two
// lines that show it: with an arming in place a read *alone* surfaces the
// induced failure, and the read immediately after it does not. Reads consult the
// injector; the arming was simply gone.
//
// Widening the hooks to reads would have changed nothing and shipped as a fix
// reporting coverage that had not improved. **A population inferred from an
// outcome is not a derived population** — both hypotheses predicted the same
// numbers, and only a measurement separated them.
func TestAReadAloneConsultsTheInjector(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	repo := mustEnsureRepo(t, p, "read-probe")
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}

	stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
	if err != nil {
		t.Fatalf("arming the throttle: %v", err)
	}
	defer stop()

	if _, err := reg.DescribeRepository(ctx, repo.Ref); !errors.Is(err, compute.ErrTransient) {
		t.Fatalf("a read with the injection armed returned %v; if reads did not consult the "+
			"injector this would be nil, and the hypothesis that they do not would be the "+
			"right one", err)
	}
}

// TestEveryDrivenMethodSurfacesTheInducedFailure is the acceptance criterion.
//
// One arming, every method of every port this provider implements, and each one
// asserted to surface [compute.ErrTransient]. With the one-shot injector this
// passed for exactly one method and reported the rest as unexercised — 1 of 3 on
// the image registry, 1 of 3 on workload identity — which the conformance gate
// printed honestly and which nothing else noticed.
//
// Each case also asserts the injection was **observed to fire**. A cell whose
// injection was never reached is not evidence, and counting it as a pass is how a
// construction reports coverage it does not have: without that assertion this
// test would pass just as well against a harness whose arming did nothing, since
// "no induced failure surfaced" and "the method is fine" are the same silence.
func TestEveryDrivenMethodSurfacesTheInducedFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Each case sets up its fixture BEFORE the throttle is armed. With the setup
	// inside the armed window the injection lands on the setup and the case
	// proves nothing about the method it names.
	type probe struct {
		setup func(*aws.Provider) any
		call  func(*aws.Provider, any) error
	}
	repoRef := func(p *aws.Provider) any { return mustEnsureRepo(t, p, "probe").Ref }
	identityRef := func(p *aws.Provider) any { return mustEnsureIdentity(t, p, "probe").Ref }
	none := func(*aws.Provider) any { return nil }
	serviceRef := func(p *aws.Provider) any {
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers(): %v", err)
		}
		id := mustEnsureIdentity(t, p, "probe")
		st, err := rt.EnsureService(ctx, containerProbeSpec(id.Ref))
		if err != nil {
			t.Fatalf("planting a service to probe against: %v", err)
		}
		return st.Ref
	}
	secretRef := func(p *aws.Provider) any {
		store, err := p.Secrets()
		if err != nil {
			t.Fatalf("Secrets(): %v", err)
		}
		stored, err := store.Put(ctx, compute.SecretSpec{
			Name: "PROBE", Scope: "probe", Value: compute.NewSecretValue("probe-material"),
		})
		if err != nil {
			t.Fatalf("planting a secret to probe against: %v", err)
		}
		// The Ref, not the whole StoredSecret: the probes below type-assert this
		// back to a compute.Ref, and Put reports a revision alongside it.
		return stored.Ref
	}

	probes := map[string]probe{
		"ImageRegistry.EnsureRepository": {none, func(p *aws.Provider, _ any) error {
			reg, err := p.Registry()
			if err != nil {
				return err
			}
			_, err = reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "probe"})
			return err
		}},
		"ImageRegistry.DescribeRepository": {repoRef, func(p *aws.Provider, f any) error {
			reg, err := p.Registry()
			if err != nil {
				return err
			}
			_, err = reg.DescribeRepository(ctx, f.(compute.Ref))
			return err
		}},
		"ImageRegistry.DeleteRepository": {repoRef, func(p *aws.Provider, f any) error {
			reg, err := p.Registry()
			if err != nil {
				return err
			}
			return reg.DeleteRepository(ctx, f.(compute.Ref))
		}},
		"IdentityService.EnsureWorkloadIdentity": {none, func(p *aws.Provider, _ any) error {
			_, err := p.Identities().EnsureWorkloadIdentity(ctx,
				compute.WorkloadIdentitySpec{Name: "probe", RunsOn: compute.RuntimeContainer})
			return err
		}},
		"IdentityService.DescribeWorkloadIdentity": {identityRef, func(p *aws.Provider, f any) error {
			_, err := p.Identities().DescribeWorkloadIdentity(ctx, f.(compute.Ref))
			return err
		}},
		"IdentityService.DeleteWorkloadIdentity": {identityRef, func(p *aws.Provider, f any) error {
			return p.Identities().DeleteWorkloadIdentity(ctx, f.(compute.Ref))
		}},
		// The secret store, added by USOSS-26. The denominator below is what
		// made this an obligation rather than an oversight: a new port whose
		// error mapping is not driven here is a port whose mapping this gate
		// silently excludes from "every driven method".
		"SecretStore.Put": {none, func(p *aws.Provider, _ any) error {
			store, err := p.Secrets()
			if err != nil {
				return err
			}
			_, err = store.Put(ctx, compute.SecretSpec{
				Name: "PROBE", Scope: "probe", Value: compute.NewSecretValue("probe-material"),
			})
			return err
		}},
		"SecretStore.Get": {secretRef, func(p *aws.Provider, f any) error {
			store, err := p.Secrets()
			if err != nil {
				return err
			}
			_, err = store.Get(ctx, f.(compute.Ref))
			return err
		}},
		"SecretStore.Delete": {secretRef, func(p *aws.Provider, f any) error {
			store, err := p.Secrets()
			if err != nil {
				return err
			}
			return store.Delete(ctx, f.(compute.Ref))
		}},
		"SecretStore.DeleteScope": {secretRef, func(p *aws.Provider, _ any) error {
			store, err := p.Secrets()
			if err != nil {
				return err
			}
			return store.DeleteScope(ctx, "probe")
		}},
		// The container service, added by USOSS-11, and the scheduled job
		// service, added by USOSS-33, are covered here for exactly the reason the
		// paragraph above the denominator names: ports arrived, their methods
		// were not driven here, and "every driven method" silently stopped
		// covering the provider. TestARetryableSubstrateFailureIsErrTransientOnEveryMethod
		// holds the detailed accounting against both port interfaces.
		"ContainerRuntime.EnsureService": {identityRef, func(p *aws.Provider, f any) error {
			rt, err := p.Containers()
			if err != nil {
				return err
			}
			_, err = rt.EnsureService(ctx, containerProbeSpec(f.(compute.Ref)))
			return err
		}},
		"ContainerRuntime.DescribeService": {serviceRef, func(p *aws.Provider, f any) error {
			rt, err := p.Containers()
			if err != nil {
				return err
			}
			_, err = rt.DescribeService(ctx, f.(compute.Ref))
			return err
		}},
		"ContainerRuntime.WaitForService": {serviceRef, func(p *aws.Provider, f any) error {
			rt, err := p.Containers()
			if err != nil {
				return err
			}
			_, err = rt.WaitForService(ctx, f.(compute.Ref), 1,
				compute.WaitOptions{Timeout: time.Second})
			return err
		}},
		"ContainerRuntime.ScaleService": {serviceRef, func(p *aws.Provider, f any) error {
			rt, err := p.Containers()
			if err != nil {
				return err
			}
			return rt.ScaleService(ctx, f.(compute.Ref), 3)
		}},
		"ContainerRuntime.DeleteService": {serviceRef, func(p *aws.Provider, f any) error {
			rt, err := p.Containers()
			if err != nil {
				return err
			}
			return rt.DeleteService(ctx, f.(compute.Ref))
		}},
	}

	// A denominator, so "every driven method" is a claim with a population rather
	// than a list somebody happened to write. It is asserted rather than printed:
	// a probe map that lost an entry would otherwise quietly narrow the claim.
	//
	// It also catches the opposite drift, which is how USOSS-26 came to add four
	// entries here: a new port arrives, its methods are not driven, and the claim
	// silently stops covering the provider. The number has to be edited either
	// way, and editing it is where somebody notices.
	const wantProbes = 15
	if len(probes) != wantProbes {
		t.Fatalf("this test drives %d methods and claims %d; the denominator and the population "+
			"have to agree or the claim means nothing", len(probes), wantProbes)
	}

	for name, pr := range probes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			fixture := pr.setup(p)

			stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
			if err != nil {
				t.Fatalf("arming the throttle: %v", err)
			}
			defer stop()

			err = pr.call(p, fixture)
			switch {
			case err == nil:
				t.Fatal("the throttled call succeeded, so this case checks nothing")
			case errors.Is(err, compute.ErrTransient):
			case errors.Is(err, compute.ErrFailed):
				t.Errorf("a throttled call surfaced as compute.ErrFailed, which is documented as "+
					"not retryable without changing the spec; a caller that believes that "+
					"abandons a deploy that would have worked: %v", err)
			default:
				t.Errorf("a throttled call surfaced as %v, which matches no sentinel that would "+
					"make sense for it", err)
			}
			if !p.Harness().InjectionFired() {
				t.Error("the substrate reports that the arming was never consumed, so this case " +
					"observed a healthy provider rather than a throttled one — and a clean result " +
					"from an injection that never fired is not evidence about the mapping")
			}
		})
	}
}

// TestOneArmingCoversEveryMethodDrivenUnderIt is the test that actually
// distinguishes the fix from the defect, and it exists because the one above
// does not.
//
// TestEveryDrivenMethodSurfacesTheInducedFailure gives each method a fresh
// provider and its own arming, so it passes with the one-shot injector too —
// measured: 6 of 6 either way. It verifies six mappings and says nothing about
// USOSS-60, because one arming is enough for one call. The defect is only visible
// when **many methods are driven inside one armed window**, which is what the
// conformance gate does and what that test does not.
//
// So this drives all six under a single arming. With the one-shot injector the
// first consumes it and the remaining five see a healthy substrate; with
// FailUntilStopped every one surfaces the induced failure. That is the whole
// content of the ticket, and it is the assertion the fix has to be judged on.
func TestOneArmingCoversEveryMethodDrivenUnderIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}

	// Fixtures first, unarmed, so the arming is spent on the driven calls rather
	// than on the setup.
	repo := mustEnsureRepo(t, p, "one-arming")
	identity := mustEnsureIdentity(t, p, "one-arming")
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets(): %v", err)
	}
	stored, err := store.Put(ctx, compute.SecretSpec{
		Name: "ONE_ARMING", Scope: "one-arming", Value: compute.NewSecretValue("probe-material"),
	})
	if err != nil {
		t.Fatalf("planting a secret: %v", err)
	}
	secret := stored.Ref

	stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
	if err != nil {
		t.Fatalf("arming the throttle: %v", err)
	}
	defer stop()

	calls := []struct {
		method string
		do     func() error
	}{
		{"ImageRegistry.EnsureRepository", func() error {
			_, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "one-arming-2"})
			return err
		}},
		{"ImageRegistry.DescribeRepository", func() error {
			_, err := reg.DescribeRepository(ctx, repo.Ref)
			return err
		}},
		{"ImageRegistry.DeleteRepository", func() error {
			return reg.DeleteRepository(ctx, repo.Ref)
		}},
		{"IdentityService.EnsureWorkloadIdentity", func() error {
			_, err := p.Identities().EnsureWorkloadIdentity(ctx,
				compute.WorkloadIdentitySpec{Name: "one-arming-2", RunsOn: compute.RuntimeContainer})
			return err
		}},
		{"IdentityService.DescribeWorkloadIdentity", func() error {
			_, err := p.Identities().DescribeWorkloadIdentity(ctx, identity.Ref)
			return err
		}},
		{"IdentityService.DeleteWorkloadIdentity", func() error {
			return p.Identities().DeleteWorkloadIdentity(ctx, identity.Ref)
		}},
		// The secret store, added by USOSS-26, and this is the gate that makes
		// the sticky arming load-bearing for it: the per-method test above gives
		// each probe a fresh provider and drives one call, so a one-shot
		// injector satisfies it. Only a shared arming across many calls can tell
		// the two apart, which is USOSS-60's whole point.
		{"SecretStore.Put", func() error {
			_, err := store.Put(ctx, compute.SecretSpec{
				Name: "ONE_ARMING_2", Scope: "one-arming",
				Value: compute.NewSecretValue("probe-material"),
			})
			return err
		}},
		{"SecretStore.Get", func() error {
			_, err := store.Get(ctx, secret)
			return err
		}},
		{"SecretStore.Delete", func() error {
			return store.Delete(ctx, secret)
		}},
		{"SecretStore.DeleteScope", func() error {
			return store.DeleteScope(ctx, "one-arming")
		}},
	}

	surfaced := 0
	for _, c := range calls {
		if errors.Is(c.do(), compute.ErrTransient) {
			surfaced++
			continue
		}
		t.Errorf("%s did not surface the induced failure under an arming shared with the other "+
			"%d methods. One arming has to cover every method driven under it: the conformance "+
			"gate drives them all in one window, and an injector consumed by the first call "+
			"reports the rest as unexercised while looking green", c.method, len(calls)-1)
	}
	// Stated positively, as the coverage line does: the fraction, not the
	// exclusions.
	t.Logf("one arming covered %d of %d driven methods", surfaced, len(calls))
	if !p.Harness().InjectionFired() {
		t.Error("the arming was never consumed at all")
	}
}

// TestNothingArmedSurfacesNoInducedFailure is the control in the other
// direction, and it is what stops the test above being satisfied by a provider
// that fails everything.
func TestNothingArmedSurfacesNoInducedFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	repo := mustEnsureRepo(t, p, "control")
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}

	for _, c := range []struct {
		what string
		err  error
	}{
		{"DescribeRepository", describeErr(ctx, reg, repo.Ref)},
		{"EnsureRepository", ensureErr(ctx, reg)},
	} {
		if errors.Is(c.err, compute.ErrTransient) {
			t.Errorf("%s surfaced compute.ErrTransient with nothing armed (%v); an injector that "+
				"fires unbidden makes every case above pass for the wrong reason", c.what, c.err)
		}
	}
	if p.Harness().InjectionFired() {
		t.Error("the substrate reports an arming was consumed although none was made")
	}
}

func describeErr(ctx context.Context, reg compute.ImageRegistry, ref compute.Ref) error {
	_, err := reg.DescribeRepository(ctx, ref)
	return err
}

func ensureErr(ctx context.Context, reg compute.ImageRegistry) error {
	_, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: fmt.Sprintf("control-%d", 1)})
	return err
}

// containerProbeSpec is the smallest service spec this provider accepts, for the
// probes above.
//
// It is deliberately minimal: no ingress, no secrets, no routes. A probe exists
// to land one armed failure on one method's own call sites, and every optional
// field adds a foreign round trip the injection could land on instead — which
// would make the case pass while saying nothing about the method it names.
func containerProbeSpec(identity compute.Ref) compute.ServiceSpec {
	return compute.ServiceSpec{
		Name:      "probe",
		Image:     "example-registry/apphub/probe:v1",
		Resources: compute.Resources{CPUMillicores: 250, MemoryMiB: 512},
		Replicas:  1,
		Identity:  identity,
	}
}
