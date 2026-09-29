// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// TestATransientFailureReachesEveryPortAndVerb is the evidence for the widened
// fault injection, and the reason it was widened.
//
// USOSS-32 reworked the conformance suite's transient-error gate so that it
// records, per method, what the provider's InduceTransient hook could not reach.
// Against this provider it named nine unexercised methods on the full-cluster
// configuration: [Harness.FailNextApply] used to fail cluster *applies* only, so
// every read-back path, every delete path, and both substrates that are not the
// cluster went through [Provider.substrateError] and [Provider.backingError]
// without ever being handed a failure.
//
// A green suite was therefore not evidence about this provider's error mapping —
// it was evidence about one write path. This test is what makes the widened
// injection a claim rather than an intention: it drives a read, a delete, and
// both non-cluster substrates with a failure armed, and requires
// [compute.ErrTransient] from each.
//
// # Why ErrTransient specifically, and not merely "an error"
//
// Getting this wrong is not a missing test, it is a wrong answer. A retryable
// failure reported as [compute.ErrFailed] tells a caller its specification has to
// change when the operation would have succeeded on a second attempt — a deploy
// abandoned for no reason. That distinction is what earned an amendment to the
// compute error taxonomy (F2), and asserting only "it failed" would pass for the
// exact defect the amendment exists to prevent. So every case below asserts the
// sentinel and asserts the absence of the two it must not be.
func TestATransientFailureReachesEveryPortAndVerb(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	sub := newSubstrate(cfg)
	p := k8s.New(sub, cfg)

	// Everything is provisioned first, with no failure armed, so that each call
	// below fails because of the injection rather than because the resource was
	// never there.
	identity := mustIdentity(t, p, "api")

	registry, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}

	containers, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	service, err := containers.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef(repo.Prefix + ":v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  identity,
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}

	restore := p.Harness().FailNextApply(k8s.ErrOptimisticConcurrency)
	defer restore()

	// Each entry names the substrate it exercises, because the point of the
	// widening is coverage across substrates rather than across methods of one.
	cases := map[string]error{
		// The cluster, on a verb that is not Apply. These are the paths an
		// apply-only injection left unexercised.
		"cluster read (DescribeService)": func() error {
			_, err := containers.DescribeService(ctx, service.Ref)
			return err
		}(),
		"cluster delete (DeleteService)": containers.DeleteService(ctx, service.Ref),
		"cluster write (Secrets.Put)": errFrom(func() error {
			_, e := secrets.Put(ctx, compute.SecretSpec{
				Name:  "db-password",
				Scope: "api",
				Value: compute.NewSecretValue("not-a-real-password"),
			})
			return e
		}),

		// The registry: a whole substrate an apply-only injection cannot touch.
		"registry write (EnsureRepository)": errFrom(func() error {
			_, e := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "another"})
			return e
		}),
		"registry read (DescribeRepository)": errFrom(func() error {
			_, e := registry.DescribeRepository(ctx, repo.Ref)
			return e
		}),
		"registry delete (DeleteRepository)": registry.DeleteRepository(ctx, repo.Ref),

		// The object store: the other one.
		"object-store write (EnsureBucket)": errFrom(func() error {
			_, e := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "another"})
			return e
		}),
		"object-store read (DescribeBucket)": errFrom(func() error {
			_, e := stores.DescribeBucket(ctx, bucket.Ref)
			return e
		}),
		"object-store delete (DeleteBucket)": stores.DeleteBucket(ctx, bucket.Ref),
		"object-store grant (Grant)":         stores.Grant(ctx, bucket.Ref, identity, compute.AccessRead),
	}

	for name, got := range cases {
		switch {
		case got == nil:
			t.Errorf("%s succeeded with a substrate failure armed, so it never reached the "+
				"substrate and its error mapping is still unverified", name)
		case errors.Is(got, compute.ErrInvalidSpec), errors.Is(got, compute.ErrForeignRef):
			// Validation refused it before the substrate was reached. Not a
			// mapping failure, but not evidence either, so it is called out.
			t.Logf("%s was refused by validation before the substrate (%v); this case proves "+
				"nothing about the mapping", name, got)
		case !errors.Is(got, compute.ErrTransient):
			t.Errorf("%s returned %v; want an error wrapping compute.ErrTransient. A retryable "+
				"failure reported as anything else tells a caller its spec has to change when a "+
				"retry would have worked.", name, got)
		case errors.Is(got, compute.ErrFailed):
			t.Errorf("%s returned an error that is both ErrTransient and ErrFailed (%v); the two "+
				"say opposite things to a caller", name, got)
		case errors.Is(got, compute.ErrNotOwned):
			t.Errorf("%s returned an error that is both ErrTransient and ErrNotOwned (%v); the "+
				"second tells a caller to give up because the resource is somebody else's", name, got)
		}
	}
}

// TestADenialReachesEveryPortAndVerb is the denial half of the test above, and
// it exists for the same reason with one difference that matters.
//
// The conformance suite's denial gate drives one verb per port — Ensure — so a
// green run says nothing about the read and delete halves of
// [Provider.substrateError] and [Provider.backingError], which is exactly the
// gap USOSS-32 measured for the transient gate and the reason FailNextApply was
// widened. This drives a read, a delete and a grant with a denial armed on each
// of the three substrates.
//
// # Why one substrate at a time
//
// [Harness.InduceDenial] arms the substrate behind the kind it is given and
// nothing else, unlike FailNextApply which arms all three. That is the property
// under test as much as the mapping is: a hook that quietly armed everything
// would let the conformance suite report ten ports driven while proving only
// that whichever substrate answered first is mapped. So each group below arms
// through one kind and drives only that substrate's verbs.
func TestADenialReachesEveryPortAndVerb(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)

	// Provisioned with nothing armed, so every failure below is the injection
	// rather than a resource that was never there.
	identity := mustIdentity(t, p, "api")

	registry, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}

	containers, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	service, err := containers.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef(repo.Prefix + ":v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  identity,
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}

	// Each group names the kind it arms through and the substrate that stands
	// behind that kind, because the point is coverage across substrates: the
	// three have three unrelated mappings.
	groups := []struct {
		substrate string
		kind      compute.Kind
		drive     func() map[string]error
	}{
		{"cluster", compute.KindService, func() map[string]error {
			return map[string]error{
				"cluster read (DescribeService)": errFrom(func() error {
					_, e := containers.DescribeService(ctx, service.Ref)
					return e
				}),
				"cluster delete (DeleteService)": containers.DeleteService(ctx, service.Ref),
				"cluster write (Secrets.Put)": errFrom(func() error {
					_, e := secrets.Put(ctx, compute.SecretSpec{
						Name:  "db-password",
						Scope: "api",
						Value: compute.NewSecretValue("not-a-real-password"),
					})
					return e
				}),
			}
		}},
		{"registry", compute.KindImageRepository, func() map[string]error {
			return map[string]error{
				"registry write (EnsureRepository)": errFrom(func() error {
					_, e := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "another"})
					return e
				}),
				"registry read (DescribeRepository)": errFrom(func() error {
					_, e := registry.DescribeRepository(ctx, repo.Ref)
					return e
				}),
				"registry delete (DeleteRepository)": registry.DeleteRepository(ctx, repo.Ref),
			}
		}},
		{"object store", compute.KindBucket, func() map[string]error {
			return map[string]error{
				"object-store write (EnsureBucket)": errFrom(func() error {
					_, e := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "another"})
					return e
				}),
				"object-store read (DescribeBucket)": errFrom(func() error {
					_, e := stores.DescribeBucket(ctx, bucket.Ref)
					return e
				}),
				"object-store delete (DeleteBucket)": stores.DeleteBucket(ctx, bucket.Ref),
				"object-store grant (Grant)":         stores.Grant(ctx, bucket.Ref, identity, compute.AccessRead),
			}
		}},
	}

	for _, g := range groups {
		stop, err := p.Harness().InduceDenial(ctx, g.kind)
		if err != nil {
			t.Errorf("InduceDenial(%q), which should arm the %s: %v", g.kind, g.substrate, err)
			continue
		}
		cases := g.drive()
		stop()

		for name, got := range cases {
			switch {
			case got == nil:
				t.Errorf("%s succeeded with a denial armed on the %s, so it never reached the "+
					"substrate and its error mapping is still unverified", name, g.substrate)
			case errors.Is(got, compute.ErrInvalidSpec), errors.Is(got, compute.ErrForeignRef):
				t.Logf("%s was refused by validation before the substrate (%v); this case proves "+
					"nothing about the mapping", name, got)
			case !errors.Is(got, compute.ErrNotPermitted):
				t.Errorf("%s returned %v; want an error wrapping compute.ErrNotPermitted. An "+
					"authorization failure reported as anything else sends an operator looking "+
					"for a broken resource instead of a missing permission.", name, got)
			case errors.Is(got, compute.ErrFailed):
				t.Errorf("%s returned an error that is both ErrNotPermitted and ErrFailed (%v); "+
					"a caller branching on the second is told the resource reached a terminal "+
					"phase, which nothing did", name, got)
			case errors.Is(got, compute.ErrTransient):
				t.Errorf("%s returned an error that is both ErrNotPermitted and ErrTransient "+
					"(%v); the second says retry a call that cannot succeed until somebody "+
					"changes a ClusterRole", name, got)
			}
		}
	}
}

// TestInducingADenialRefusesAKindWithNoSubstrateBehindIt pins the honest half of
// the hook.
//
// A key-value table is the kind this provider refuses outright, so there is
// nothing to deny for it. Returning a no-op stop and a nil error would report
// that port as driven and its mapping as verified — the inert-hook shape the
// gate's own count exists to expose. The suite records an error here as "that
// port could not be driven", by name, and drives the others.
func TestInducingADenialRefusesAKindWithNoSubstrateBehindIt(t *testing.T) {
	t.Parallel()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)

	stop, err := p.Harness().InduceDenial(context.Background(), compute.KindKeyValueTable)
	if err == nil {
		t.Fatal("InduceDenial accepted a key-value table, a kind this provider has no substrate " +
			"for; the suite would record that port's mapping as verified")
	}
	// Still safe to call: a caller that defers stop before checking the error
	// must not panic.
	stop()
}

// TestRestoringADenialActuallyRestoresIt is [TestRestoringTheInjectionActuallyRestoresIt]
// for the denial hook. The substrate is shared across a whole conformance run,
// so a stop that left one substrate armed would surface as an unrelated check
// failing later.
func TestRestoringADenialActuallyRestoresIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)

	registry, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}

	armed := map[string]struct {
		kind compute.Kind
		call func() error
	}{
		"cluster": {compute.KindWorkloadIdentity, func() error {
			_, e := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
				Name: "api", RunsOn: compute.RuntimeContainer,
			})
			return e
		}},
		"registry": {compute.KindImageRepository, func() error {
			_, e := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"})
			return e
		}},
		"object store": {compute.KindBucket, func() error {
			_, e := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"})
			return e
		}},
	}

	for name, a := range armed {
		stop, err := p.Harness().InduceDenial(ctx, a.kind)
		if err != nil {
			t.Errorf("InduceDenial(%q): %v", a.kind, err)
			continue
		}
		if err := a.call(); err == nil {
			t.Errorf("the %s was not armed", name)
		}
		stop()
		if err := a.call(); err != nil {
			t.Errorf("the %s is still failing after stop: %v", name, err)
		}
	}
}

// errFrom runs f and returns its error, so a map literal can hold a call that
// returns two values.
func errFrom(f func() error) error { return f() }

// TestRestoringTheInjectionActuallyRestoresIt guards the fixture rather than the
// provider.
//
// The widened injection now arms three substrates and hands back one closure. A
// closure that restored two of the three would leave a failure armed for every
// subsequent check in the same run, and because the substrate is shared across a
// conformance run the symptom would appear somewhere else entirely — the worst
// kind of test failure to diagnose.
func TestRestoringTheInjectionActuallyRestoresIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)

	registry, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}

	restore := p.Harness().FailNextApply(k8s.ErrOptimisticConcurrency)
	if _, err := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"}); err == nil {
		t.Fatal("the registry was not armed")
	}
	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); err == nil {
		t.Fatal("the object store was not armed")
	}
	if _, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "api", RunsOn: compute.RuntimeContainer,
	}); err == nil {
		t.Fatal("the cluster was not armed")
	}

	restore()

	if _, err := registry.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"}); err != nil {
		t.Errorf("the registry is still failing after restore: %v", err)
	}
	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); err != nil {
		t.Errorf("the object store is still failing after restore: %v", err)
	}
	if _, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "api", RunsOn: compute.RuntimeContainer,
	}); err != nil {
		t.Errorf("the cluster is still failing after restore: %v", err)
	}
}
