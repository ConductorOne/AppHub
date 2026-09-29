// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// watchMode is how the test cluster's Watch behaves.
type watchMode int

const (
	// watchNever hands out a channel nothing will ever write to, which is what
	// a watch on an idle object looks like.
	watchNever watchMode = iota
	// watchTicks hands out a channel with changes already pending.
	watchTicks
	// watchStops hands out a channel that is already closed, which is how
	// ClientCluster reports that change notification has stopped working.
	watchStops
	// watchRefuses fails to establish the watch at all.
	watchRefuses
)

// watchingCluster is a [k8s.MemoryCluster] that also implements [k8s.Watcher],
// under the test's control, and counts the reads the provider makes.
//
// It exists because the difference between watching and polling is not visible
// in the result of a wait — both eventually return the same status — and this
// project's eighth lesson is to verify at the resolution the failure lives at.
// The resolution here is *how many times the provider read the object*, and a
// count is the only thing that separates "blocked on a change" from "asked again
// on a timer".
type watchingCluster struct {
	*k8s.MemoryCluster
	mode watchMode

	mu      sync.Mutex
	reads   map[schema.GroupVersionKind]int
	watches int
	stops   int
}

func newWatchingCluster(mode watchMode) *watchingCluster {
	return &watchingCluster{
		MemoryCluster: k8s.NewMemoryCluster(),
		mode:          mode,
		reads:         map[schema.GroupVersionKind]int{},
	}
}

func (c *watchingCluster) Get(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	c.mu.Lock()
	c.reads[gvk]++
	c.mu.Unlock()
	return c.MemoryCluster.Get(ctx, gvk, namespace, name)
}

func (c *watchingCluster) Watch(_ context.Context, _ schema.GroupVersionKind, _, name string) (<-chan struct{}, func(), error) {
	c.mu.Lock()
	c.watches++
	c.mu.Unlock()
	if c.mode == watchRefuses {
		return nil, nil, errors.New("k8s_test: this cluster refuses to establish a watch")
	}
	changes := make(chan struct{}, 8)
	switch c.mode {
	case watchTicks:
		for range 8 {
			changes <- struct{}{}
		}
	case watchStops:
		close(changes)
	case watchNever, watchRefuses:
	}
	_ = name
	stop := func() {
		c.mu.Lock()
		c.stops++
		c.mu.Unlock()
	}
	return changes, stop, nil
}

func (c *watchingCluster) readsOf(gvk schema.GroupVersionKind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads[gvk]
}

func (c *watchingCluster) counts() (watches, stops int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.watches, c.stops
}

// serviceUnderWait ensures a service on a provider over cluster and returns its
// ref.
func serviceUnderWait(t *testing.T, cluster k8s.Cluster) (*k8s.Provider, compute.Ref) {
	t.Helper()
	ctx := context.Background()
	cfg := fullConfig()
	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(true)
	sub := &k8s.Substrate{
		Cluster:  cluster,
		Registry: registry,
		Objects:  k8s.NewMemoryObjectStore(),
	}
	p := k8s.New(sub, cfg)

	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	return p, svc.Ref
}

// TestAWatchedWaitDoesNotPoll is the test that makes the corrected claim
// checkable.
//
// USOSS-27's report said there were "no sleeps anywhere in the package". That was
// false: compute/k8s/wait.go polled with time.Sleep on a live path, and the audit
// of USOSS-19 found it.
//
// The replacement claim was *also* too strong for a while — "the watched path runs
// no timer" — and the watched path does arm one, for the caller's deadline, as any
// wait that can give up must. What this test establishes is the narrower and true
// property: **the watched path runs no periodic poll timer.** It counts reads
// rather than timers, which is exactly why the test was right while the sentence
// over it was wrong.
//
// # Why it counts reads, and why it counts them twice
//
// The difference between watching and polling is invisible in a wait's result:
// both return the same status. It is visible in how many times the provider read
// the object, so that is what is measured — this project's eighth lesson is to
// verify at the resolution the failure lives at.
//
// A single count would be a threshold to argue about, so both arms run: the same
// wait, over the same substrate, for the same duration, once against a cluster
// that reports changes and once against one that cannot. The wait is deliberately
// unsatisfiable (two ready replicas asked of a one-replica service), so neither
// arm can finish early and the only variable left is the clock the loop runs on.
// Watching must read once. Polling must read many times. The assertion is the
// ratio, not either number.
func TestAWatchedWaitDoesNotPoll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const window = 50 * time.Millisecond

	reads := func(t *testing.T, mode watchMode) int {
		t.Helper()
		cluster := newWatchingCluster(mode)
		p, ref := serviceUnderWait(t, cluster)
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers: %v", err)
		}
		before := cluster.readsOf(deploymentGVK)
		// Two ready replicas of a one-replica service: this can never be
		// satisfied, so the wait runs for the whole window in both arms.
		_, err = rt.WaitForService(ctx, ref, 2, compute.WaitOptions{Timeout: window})
		if !errors.Is(err, compute.ErrTimeout) {
			t.Fatalf("an unsatisfiable wait returned %v, want compute.ErrTimeout", err)
		}
		return cluster.readsOf(deploymentGVK) - before
	}

	watched := reads(t, watchNever)
	polled := reads(t, watchRefuses)

	if watched != 1 {
		t.Errorf("over %v, the watched wait read the Deployment %d times; want exactly 1. "+
			"More than one means the loop re-read on a timer, which is the poll path the watch "+
			"was supposed to replace.", window, watched)
	}
	// The floor is deliberately low. An earlier version required ten reads in a
	// 50ms window at a 1ms interval, which is true on an idle machine and not on
	// this one — it is shared with several other workers, and the check failed at
	// nine. A threshold tuned to a quiet machine is a flake, and the discriminating
	// property was never the count anyway: it is that one path reads *once* and the
	// other reads *repeatedly*. Three is enough to establish "repeatedly" and would
	// need a machine spending 17ms per loop iteration to produce a false failure.
	//
	// The mutation this test exists to catch is still caught twice over: making the
	// watched path poll breaks the "exactly 1" assertion above, and breaks the
	// ratio below.
	if polled < 3 {
		t.Errorf("over %v, the polling fallback read the Deployment only %d times with a %v "+
			"poll interval; that is not repeated reading, so this test is no longer comparing "+
			"two different clocks and the assertion above proves nothing",
			window, polled, pollIntervalForTest)
	}
	if polled <= watched {
		t.Errorf("polling read %d times and watching read %d; the two paths are "+
			"indistinguishable, so nothing here is evidence about either", polled, watched)
	}

	// The watch must also be established once and stopped once. An unstopped
	// watch leaks a goroutine per wait, which a long-lived deploy process would
	// accumulate.
	cluster := newWatchingCluster(watchNever)
	p, ref := serviceUnderWait(t, cluster)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if _, err := rt.WaitForService(ctx, ref, 2, compute.WaitOptions{Timeout: window}); !errors.Is(err, compute.ErrTimeout) {
		t.Fatalf("WaitForService: %v", err)
	}
	watches, stops := cluster.counts()
	if watches != 1 || stops != 1 {
		t.Errorf("the wait established %d watches and stopped %d; want 1 and 1", watches, stops)
	}
}

// pollIntervalForTest mirrors the package's unexported poll interval so the
// failure message above can name it. It is only ever printed; nothing branches
// on it, so a drift between the two cannot change an outcome.
const pollIntervalForTest = time.Millisecond

// TestAWatchedWaitAdvancesOnAChange is the other half: a change must actually
// drive the loop forward. A watch that was never read from would produce the same
// timeout as the test above for the opposite reason.
func TestAWatchedWaitAdvancesOnAChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cluster := newWatchingCluster(watchTicks)
	p, ref := serviceUnderWait(t, cluster)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	// A deadline long enough that a failure is a failure of the mechanism rather
	// than of the machine, and short enough not to hang the suite.
	status, err := rt.WaitForService(ctx, ref, 1, compute.WaitOptions{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("WaitForService against a substrate that reports changes: %v", err)
	}
	if status.Phase != compute.PhaseReady {
		t.Errorf("the service settled in phase %q", status.Phase)
	}
}

// TestAWaitFallsBackToPollingWhenTheWatchStops pins the documented fallback.
//
// A watch ends for ordinary reasons, and ClientCluster reports a watch it could
// not re-establish by closing the channel. If the wait treated a closed channel
// as "nothing will ever change", a bounded wait would turn into a wait that runs
// to its deadline for no reason. It has to drop to the poll path instead, and the
// evidence that it did is that the wait *succeeds* — which, per the test above, is
// only possible with a timer running.
func TestAWaitFallsBackToPollingWhenTheWatchStops(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for name, mode := range map[string]watchMode{
		"the watch channel closes":        watchStops,
		"the watch cannot be established": watchRefuses,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cluster := newWatchingCluster(mode)
			p, ref := serviceUnderWait(t, cluster)
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			status, err := rt.WaitForService(ctx, ref, 1, compute.WaitOptions{Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("the wait did not fall back to polling: %v", err)
			}
			if status.Phase != compute.PhaseReady {
				t.Errorf("the service settled in phase %q", status.Phase)
			}
		})
	}
}

// TestAWaitStillRefusesToWaitForever guards the invariant the rework could most
// easily have broken: a wait with neither a timeout nor a context deadline is
// refused rather than blocking on a channel until the process ends.
//
// This mattered more after the change than before it. The poll loop checked the
// deadline every millisecond, so a missing deadline would have shown up as a busy
// loop; the watch path blocks, so the same bug would be an indefinite hang — the
// failure mode compute.Status's contract exists to forbid.
func TestAWaitStillRefusesToWaitForever(t *testing.T) {
	t.Parallel()

	for name, mode := range map[string]watchMode{
		"watching": watchNever,
		"polling":  watchRefuses,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cluster := newWatchingCluster(mode)
			p, ref := serviceUnderWait(t, cluster)
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			// context.Background() has no deadline and WaitOptions carries no
			// timeout, so there is no deadline at all.
			done := make(chan error, 1)
			go func() {
				_, err := rt.WaitForService(context.Background(), ref, 2, compute.WaitOptions{})
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, compute.ErrInvalidSpec) {
					t.Errorf("a deadline-less wait returned %v, want ErrInvalidSpec", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a deadline-less wait did not return; no path may wait forever")
			}
		})
	}
}

// TestAWaitHonoursCancellationOnTheWatchedPath checks the third arm of the
// select. A caller that cancels must be answered, not left blocked on a channel
// the substrate will never write to.
func TestAWaitHonoursCancellationOnTheWatchedPath(t *testing.T) {
	t.Parallel()

	cluster := newWatchingCluster(watchNever)
	p, ref := serviceUnderWait(t, cluster)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		// Unsatisfiable, so the wait is genuinely blocked when the
		// cancellation arrives rather than already finished.
		_, err := rt.WaitForService(ctx, ref, 2, compute.WaitOptions{Timeout: time.Minute})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, compute.ErrTimeout) {
			t.Errorf("a cancelled wait returned %v, want an error wrapping compute.ErrTimeout", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled wait returned %v, which does not carry the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled wait did not return")
	}
}

// TestScalingDoesNotStaleTheEffectiveSpec is the regression for a defect USOSS-39
// found with a conformance check, in this package, that no test here could see.
//
// DescribeService rebuilds the effective spec from the annotation EnsureService
// wrote, not from the Deployment's fields. ScaleService changed
// dep.Spec.Replicas and left the annotation alone, so afterwards:
//
//	ServiceStatus.DesiredReplicas  read from dep.Spec.Replicas  -> the new count
//	ServiceStatus.Spec.Replicas    read from the annotation      -> the old count
//
// Two answers about the same resource at the same moment, which is exactly the
// disagreement USOSS-2's effective-spec read-back exists to make impossible. And
// it is not cosmetic: **a caller reconciling from Spec sees the old count,
// concludes there is nothing to do, and never converges.**
//
// # Why it was invisible here, which is the transferable part
//
// The zero-pauses check reads DesiredReplicas and passed. USOSS-39's own check
// passed too, while it compared two marker substrings of the stringified spec —
// a reviewer defeated that version by preserving both markers and deleting five
// other fields, and all 167 checks stayed green. Comparing two members of a
// population cannot see a defect in the rest of it. Comparing the whole spec found
// this on the first run.
//
// So this test compares the whole thing too, rather than the field that happens to
// be wrong today.
func TestScalingDoesNotStaleTheEffectiveSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	spec := compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  2,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
		Labels:    map[string]string{"app": "web"},
	}
	svc, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	before, err := rt.DescribeService(ctx, svc.Ref)
	if err != nil {
		t.Fatalf("DescribeService: %v", err)
	}

	if err := rt.ScaleService(ctx, svc.Ref, 1); err != nil {
		t.Fatalf("ScaleService: %v", err)
	}
	after, err := rt.DescribeService(ctx, svc.Ref)
	if err != nil {
		t.Fatalf("DescribeService after scale: %v", err)
	}

	// The disagreement itself, which is the defect.
	if after.Spec.Replicas != after.DesiredReplicas {
		t.Errorf("after ScaleService(1): Spec.Replicas=%d but DesiredReplicas=%d.\n"+
			"Two answers about the same resource at the same moment. A caller reconciling from "+
			"Spec sees %d, concludes nothing needs doing, and never converges.",
			after.Spec.Replicas, after.DesiredReplicas, after.Spec.Replicas)
	}
	if after.Spec.Replicas != 1 {
		t.Errorf("Spec.Replicas=%d after scaling to 1", after.Spec.Replicas)
	}

	// And the whole spec, normalised only for the field the scale was allowed to
	// change. Comparing Replicas alone is what let this hide: a mutation that
	// dropped Ports or Labels while fixing Replicas would pass a Replicas-only
	// check. This is the population, not two members of it.
	normalised := after.Spec
	normalised.Replicas = before.Spec.Replicas
	if got, want := fmt.Sprint(normalised), fmt.Sprint(before.Spec); got != want {
		t.Errorf("scaling changed more of the effective spec than the replica count.\n"+
			" before: %s\n  after: %s", want, got)
	}

	// Scaling back must be equally honest, so the fix is not one-directional.
	if err := rt.ScaleService(ctx, svc.Ref, 3); err != nil {
		t.Fatalf("ScaleService(3): %v", err)
	}
	back, err := rt.DescribeService(ctx, svc.Ref)
	if err != nil {
		t.Fatalf("DescribeService after scaling back: %v", err)
	}
	if back.Spec.Replicas != back.DesiredReplicas || back.Spec.Replicas != 3 {
		t.Errorf("after ScaleService(3): Spec.Replicas=%d DesiredReplicas=%d, want both 3",
			back.Spec.Replicas, back.DesiredReplicas)
	}
}

// TestScaleServiceRefusesACountItCannotRepresent covers the bound that replaced a
// lint suppression.
//
// A Deployment's replica count is an int32. The conversion used to carry a
// //nolint:gosec directive claiming it was "bounded by the check above", and the
// check above bounded only the *lower* end — so on a 64-bit platform a count past
// int32 would have wrapped and written a negative replica count to the cluster. A
// real bound is better than a comment asserting one.
func TestScaleServiceRefusesACountItCannotRepresent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	p := k8s.New(newSubstrate(cfg), cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	for name, count := range map[string]int{
		"negative":            -1,
		"past int32":          math.MaxInt32 + 1,
		"absurdly past int32": math.MaxInt64 / 2,
	} {
		if err := rt.ScaleService(ctx, svc.Ref, count); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("ScaleService(%s=%d) returned %v, want compute.ErrInvalidSpec",
				name, count, err)
		}
	}
	// The control: a representable count still works, so the bound is not a
	// blanket refusal.
	if err := rt.ScaleService(ctx, svc.Ref, 3); err != nil {
		t.Errorf("ScaleService(3): %v", err)
	}
}

// TestScalingRefusesAnUnreadableEffectiveSpec asserts a CLASS of refusal, after
// three rounds of review each found one more input than the last check covered.
//
// The sequence is the finding. Round three: an *absent* annotation was refused and
// an *unparseable* one was not, because decodeSpec discards its unmarshal error, so
// the mutation was applied to a zero spec — replacing a garbled read-back with a
// **fabricated** one, which is worse, because garbled state at least shows that
// something is wrong. Round four fixed that. Round five found `{}`: valid JSON,
// unmarshals cleanly, decodes to the zero spec, and walked through both checks to
// fabricate exactly the same way.
//
// Adding a third input to a list would have been the same mistake a third time.
// **An effective spec this provider wrote is a fixed point of encode-then-decode**,
// so anything that is not that fixed point is refused whether or not anybody has
// thought of it. The table below therefore includes inputs from all three rounds
// AND inputs nobody reported, and the ones nobody reported are the point: they are
// caught by the predicate rather than by having been enumerated.
func TestScalingRefusesAnUnreadableEffectiveSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// wantFragment is the half of the message that has to differ, because
	// unparseable and incomplete send an operator to different places: one means
	// something wrote the annotation badly, the other means something wrote a
	// spec this provider did not render.
	cases := map[string]struct {
		annotation   string
		wantFragment string
	}{
		// Reported in round three.
		"malformed JSON":        {`{"Name":"api",`, "not valid JSON"},
		"a JSON scalar":         {`"not-an-object"`, "not valid JSON"},
		"not JSON at all":       {`¯\_(ツ)_/¯`, "not valid JSON"},
		"the empty JSON string": {`""`, "not valid JSON"},

		// Reported in round five: valid JSON that decodes to the zero spec. These
		// now fail the PROVENANCE question rather than the canonicality one, and
		// that is the more accurate diagnosis: they are not a different version
		// of a spec, they are not a spec this provider ever wrote.
		"the empty JSON object": {`{}`, "could have written"},

		// Not reported by anyone. These are caught because the condition is a
		// class rather than a list, and they are here to show that.
		"a partial object":        {`{"Name":"api"}`, "could have written"},
		"a JSON null":             {`null`, "could have written"},
		"an unknown extra field":  {`{"Name":"api","NoSuchField":1}`, "could have written"},
		"a plausible-looking one": {`{"Name":"api","Replicas":3}`, "could have written"},
	}
	for name, tc := range cases {
		annotation := tc.annotation
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := fullConfig()
			sub := newSubstrate(cfg)
			p := k8s.New(sub, cfg)
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
				Name:      "api",
				Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
				Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
				Replicas:  2,
				Ports:     []compute.PortSpec{{Number: 8080}},
				Identity:  mustIdentity(t, p, "api"),
			})
			if err != nil {
				t.Fatalf("EnsureService: %v", err)
			}

			// Corrupt the stored annotation, as a foreign writer or a partial
			// write would.
			if err := corruptEffectiveSpec(ctx, sub, annotation); err != nil {
				t.Fatalf("corrupting the annotation: %v", err)
			}

			err = rt.ScaleService(ctx, svc.Ref, 1)
			if err == nil {
				t.Fatalf("ScaleService succeeded with %s in the effective-spec annotation. The "+
					"mutation was applied to a zero spec, so the read-back is now fabricated "+
					"rather than merely wrong.", name)
			}
			if !errors.Is(err, compute.ErrFailed) {
				t.Errorf("ScaleService returned %v, want an error wrapping compute.ErrFailed", err)
			}
			// The message must say which of the two inputs it was, because a
			// missing annotation and a malformed one send an operator to
			// different places.
			if !strings.Contains(err.Error(), tc.wantFragment) {
				t.Errorf("the refusal for %s does not contain %q, so it does not distinguish "+
					"this case from the others: %v", name, tc.wantFragment, err)
			}
			// A fail-closed refusal an operator cannot act on is
			// fail-confusing, so the skew case has to carry the REMEDY and not
			// only the diagnosis.
			//
			// Asserting on the bare word "Ensure" was too weak, and round seven
			// said so: every one of these messages mentions Ensure somewhere,
			// including the provenance one, so the check passed on text that
			// tells an operator nothing to do. It asserts the actionable
			// instruction now -- an imperative naming what to run.
			if tc.wantFragment == "VERSION SKEW" {
				const remedy = "run an Ensure against this resource to re-render"
				if !strings.Contains(strings.ToLower(err.Error()), remedy) {
					t.Errorf("the refusal for %s names version skew but does not tell the "+
						"operator what to run; %q is not present, so after an upgrade they "+
						"cannot tell skew from corruption: %v", name, remedy, err)
				}
			}
		})
	}

	// The control: an absent annotation is still refused, and with the other
	// message. Closing one input must not have opened the other.
	cfg := fullConfig()
	sub := newSubstrate(cfg)
	p := k8s.New(sub, cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  2,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	if err := corruptEffectiveSpec(ctx, sub, ""); err != nil {
		t.Fatalf("removing the annotation: %v", err)
	}
	err = rt.ScaleService(ctx, svc.Ref, 1)
	if err == nil {
		t.Fatal("ScaleService succeeded with no effective-spec annotation")
	}
	if !strings.Contains(err.Error(), "no effective spec") {
		t.Errorf("the absent case no longer has its own message: %v", err)
	}
}

// corruptEffectiveSpec overwrites (or removes, when raw is empty) the
// effective-spec annotation on the Deployment behind ref, reaching past the
// provider to do it — which is the only way to produce a state the provider itself
// never writes.
//
// It finds the Deployment by listing rather than by composing a name. The provider
// sanitises logical names into substrate ones, so a test that reconstructed the
// name would be restating a mapping the provider owns — and would break the moment
// the sanitiser changed, for reasons having nothing to do with what it is testing.
func corruptEffectiveSpec(ctx context.Context, sub *k8s.Substrate, raw string) error {
	gvk := k8s.DeploymentGVKForTest()
	found, err := sub.Cluster.List(ctx, gvk, "", nil)
	if err != nil {
		return err
	}
	if len(found) != 1 {
		return fmt.Errorf("expected exactly one Deployment to corrupt, found %d", len(found))
	}
	dep, ok := found[0].(*appsv1.Deployment)
	if !ok {
		return fmt.Errorf("expected a Deployment, got %T", found[0])
	}
	if dep.Annotations == nil {
		dep.Annotations = map[string]string{}
	}
	if raw == "" {
		delete(dep.Annotations, k8s.EffectiveSpecAnnotationForTest())
	} else {
		dep.Annotations[k8s.EffectiveSpecAnnotationForTest()] = raw
	}
	return sub.Cluster.Apply(ctx, gvk, dep)
}

// TestScalingReportsVersionSkewDistinctlyFromAForgery keeps the two questions
// reencodeSpec asks distinguishable, and keeps the canonicality branch from going
// vacuous.
//
// # Why this test had to exist the moment provenance was added
//
// Round seven's fix added a provenance check ahead of the byte round-trip, and
// every input in the malformed-annotation table above then failed on provenance —
// correctly, because none of them is a spec this provider wrote. But that left the
// **canonicality** branch, and the version-skew remedy message with it, exercised
// by nothing at all. A guard no input reaches is a guard whose behaviour is
// asserted by its author rather than by a test, which is the shape of the
// vacuity findings this branch has spent seven rounds on.
//
// So this constructs the one input that reaches it: a spec that IS valid — it
// passes the same validation EnsureService runs, so provenance is satisfied — and
// is NOT in this build's canonical form, because a field has been dropped from
// its JSON. That is exactly what an annotation written by a build with a different
// spec type looks like, which is the case the remedy text is written for.
func TestScalingReportsVersionSkewDistinctlyFromAForgery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	sub := newSubstrate(cfg)
	p := k8s.New(sub, cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	valid := compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  2,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
	}
	svc, err := rt.EnsureService(ctx, valid)
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	// Build the skewed annotation by dropping one field from the canonical
	// encoding of a spec that is otherwise exactly what this build writes. The
	// field is chosen for a reason: it must be one the validation does NOT
	// examine, or the input would fail provenance and never reach canonicality.
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	const dropped = "ExecEnabled"
	if _, present := generic[dropped]; !present {
		t.Fatalf("the spec encoding no longer contains %q, so this test is not constructing "+
			"the input it describes; pick another field the validation does not examine", dropped)
	}
	delete(generic, dropped)
	skewed, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if err := corruptEffectiveSpec(ctx, sub, string(skewed)); err != nil {
		t.Fatalf("planting the skewed annotation: %v", err)
	}

	err = rt.ScaleService(ctx, svc.Ref, 1)
	if err == nil {
		t.Fatal("ScaleService accepted an annotation that is not in this build's canonical form; " +
			"the canonicality branch is not reached, so version skew is undetected")
	}
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("ScaleService returned %v, want an error wrapping compute.ErrFailed", err)
	}
	// It must be reported as SKEW, not as a forgery: this spec is valid and the
	// two diagnoses send an operator to different places.
	if !strings.Contains(err.Error(), "VERSION SKEW") {
		t.Errorf("a valid-but-non-canonical annotation was not reported as version skew: %v\n"+
			"If this now reports it as a spec the provider could not have written, the "+
			"provenance check has become strict enough to reject a spec Ensure accepts, and "+
			"the two questions have collapsed into one.", err)
	}
	const remedy = "run an ensure against this resource to re-render"
	if !strings.Contains(strings.ToLower(err.Error()), remedy) {
		t.Errorf("the version-skew refusal does not tell the operator what to run; %q absent: %v",
			remedy, err)
	}
}

// TestScalingRefusesTheCanonicalZeroSpec is round seven's B2 reproduction, kept as
// a permanent test because it is the counter-example that showed a byte round-trip
// answers the wrong question.
//
// `{}` in the table above is NOT this case, and the difference is the whole
// finding: `{}` is not a fixed point of encode-then-decode, so the round-trip
// guard caught it. **`json.Marshal(compute.ServiceSpec{})` IS a fixed point** — it
// is precisely what this build writes for a zero spec — so it satisfied
// canonicality completely, and was accepted, and the mutation was applied to a
// fabricated spec. Four rounds of closing that fabrication path and it was still
// reachable, through a *canonical* annotation rather than a malformed one.
//
// The lesson is in the framing rather than the case: the guard was testing
// **self-consistency** where it was placed to test **provenance**, and
// self-consistency is a property a forgery has too. This test asserts the
// property, and the fixed-point assertion below is part of it — if a future change
// made the zero spec non-canonical, this test would start passing for the wrong
// reason and would say so.
func TestScalingRefusesTheCanonicalZeroSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := fullConfig()
	sub := newSubstrate(cfg)
	p := k8s.New(sub, cfg)
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  2,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  mustIdentity(t, p, "api"),
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	zero, err := json.Marshal(compute.ServiceSpec{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The premise, asserted rather than assumed: this input must actually BE a
	// byte fixed point, or the test is not exercising the hole it was written for
	// and would pass through the canonicality branch instead.
	var back compute.ServiceSpec
	if err := json.Unmarshal(zero, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	again, err := json.Marshal(back)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(again) != string(zero) {
		t.Fatalf("the canonical zero spec is no longer a byte fixed point, so this test no "+
			"longer reproduces B2: it would now be caught by the canonicality check instead of "+
			"the provenance check.\n got: %s\nwant: %s", again, zero)
	}

	if err := corruptEffectiveSpec(ctx, sub, string(zero)); err != nil {
		t.Fatalf("planting the canonical zero spec: %v", err)
	}
	err = rt.ScaleService(ctx, svc.Ref, 1)
	if err == nil {
		t.Fatal("ScaleService accepted the CANONICAL zero spec and fabricated an effective " +
			"spec from it. This is round seven's B2: the byte round-trip admits this input " +
			"because it genuinely is a fixed point, so canonicality cannot be the only check.")
	}
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("ScaleService returned %v, want an error wrapping compute.ErrFailed", err)
	}
	// It must be reported as a spec Ensure could not have written, NOT as skew:
	// this annotation is in exactly this build's format, so calling it skew would
	// send an operator looking for an upgrade that did not happen.
	if !strings.Contains(err.Error(), "could have written") {
		t.Errorf("the canonical zero spec was not refused on provenance grounds: %v\n"+
			"It is in this build's exact format, so a version-skew diagnosis would be wrong.", err)
	}
}

// TestScaleAndEnsureAgreeOnEverySpecTheyRefuse is round eight's B reproduction,
// generalised past the field it was reported on.
//
// # Why it is an equivalence rather than a list of bad specs
//
// The reported case was a route with target port 70000: EnsureService refused it
// and ScaleService accepted the same spec as a canonical annotation. The cause was
// that ScaleService's provenance check called three of Ensure's validators by hand
// and omitted two. **A list of calls drifts exactly the way a list of rules does**,
// so a test asserting "routes are validated too" would close the reported case and
// leave the next field.
//
// The property is the equivalence: for any spec, EnsureService accepting it and
// ScaleService accepting it as an effective spec must be the same answer. Each
// case below turns exactly one field of a valid spec bad, and asserts BOTH paths
// refuse. Ensure's refusal is the control -- without it a case proves nothing,
// because a spec both paths accept would pass an equivalence test vacuously.
func TestScaleAndEnsureAgreeOnEverySpecTheyRefuse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	valid := func(identity compute.Ref) compute.ServiceSpec {
		return compute.ServiceSpec{
			Name:      "api",
			Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  2,
			Ports:     []compute.PortSpec{{Number: 8080}},
			Identity:  identity,
		}
	}

	// One invalid field per case, named by the validation rule it trips.
	//
	// The route cases are one of the two rules the hand-assembled callback
	// omitted. The other -- the exec-capability check -- is NOT covered here and
	// cannot be: Config.capabilities() puts CapWorkloadExec in the unconditional
	// set, so no Config can produce a provider that refuses ExecEnabled, and the
	// branch is unreachable. Measured, not assumed (a zero Config has it too).
	// Said here rather than left as a silent hole in the table, because a rule
	// that cannot be exercised is worth naming and a gap that looks covered is not.
	cases := map[string]func(compute.ServiceSpec) compute.ServiceSpec{
		"a route with an out-of-range target port": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Routes = []compute.Route{{Host: "app.invalid", TargetPort: 70000, AllowPlaintext: true}}
			return s
		},
		"a route with no host": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Routes = []compute.Route{{Host: "", TargetPort: 8080, AllowPlaintext: true}}
			return s
		},
		"an ingress rule with an out-of-range port": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Ingress = []compute.IngressRule{
				{From: compute.Peer{Kind: compute.PeerInternet}, Port: 70000},
			}
			return s
		},
		"a container port out of range": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Ports = []compute.PortSpec{{Number: 70000}}
			return s
		},
		"a replica count past int32": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Replicas = math.MaxInt32 + 1
			return s
		},
		"no image": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Image = ""
			return s
		},
		"no resources": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Resources = compute.Resources{}
			return s
		},
		"an empty name": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Name = ""
			return s
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := fullConfig()
			sub := newSubstrate(cfg)
			p := k8s.New(sub, cfg)
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			identity := mustIdentity(t, p, "api")

			// A real service to scale, from the untouched valid spec.
			svc, err := rt.EnsureService(ctx, valid(identity))
			if err != nil {
				t.Fatalf("EnsureService with the valid spec: %v", err)
			}

			bad := mutate(valid(identity))

			// The control. If Ensure accepts this, the case is not testing a
			// refusal and the equivalence below would hold vacuously.
			if _, err := rt.EnsureService(ctx, bad); err == nil {
				t.Fatalf("EnsureService ACCEPTED %s, so this case asserts nothing about "+
					"agreement; pick a field Ensure actually validates", name)
			}

			// The property: the same spec, planted as a canonical effective spec,
			// must be refused by ScaleService too.
			raw, err := json.Marshal(bad)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := corruptEffectiveSpec(ctx, sub, string(raw)); err != nil {
				t.Fatalf("planting the annotation: %v", err)
			}
			if err := rt.ScaleService(ctx, svc.Ref, 1); err == nil {
				t.Errorf("EnsureService refuses %s but ScaleService accepted it as an effective "+
					"spec and mutated it.\nThe two paths disagree about what a valid spec is, "+
					"which means ScaleService's provenance check is not asking Ensure's "+
					"question -- it is asking a hand-assembled approximation of it.", name)
			}
		})
	}
}

// TestARefusedSpecGrantsNoRegistryAccess is round nine's B reproduction, driven
// through every Ensure path that builds a workload rather than only the one it was
// reported on.
//
// # What it is about
//
// buildWorkload discharged the image-pull obligation: it granted repository read,
// minted a robot credential and attached a pull secret. Every validation that ran
// AFTER it could therefore refuse a spec that had already been authorized. The
// reported case was a service with a route target port of 70000 -- correctly
// refused with ErrInvalidSpec, and it left the repository's robot count
// incremented.
//
// Two things make it worse than a stray write. The acceptance phase was extracted
// in round eight specifically so that refusal would be side-effect free, and **the
// phase itself wrote** -- so the fix for validation-after-mutation contained an
// instance of it. And extending that phase to ScaleService's provenance check
// meant a READ, asking whether Ensure would accept a spec, granted registry access
// as a side effect of asking.
//
// # Why all three paths
//
// The defect was in buildWorkload, so it belonged to every caller. The scheduled
// job path validates its schedule AFTER buildWorkload, so it had the same defect
// by the same mechanism; a job refused for an unrepresentable schedule had already
// been granted access. Testing only the reported path would have been the
// round-three mistake again: a fix aimed at the function the defect was reported
// in rather than at the operation.
func TestARefusedSpecGrantsNoRegistryAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	type refusal struct {
		// drive submits a spec the provider must refuse.
		drive func(*testing.T, *k8s.Provider) error
	}
	image := compute.ImageRef("registry.invalid/apphub/api:v1")
	res := compute.Resources{CPUMillicores: 500, MemoryMiB: 512}

	cases := map[string]refusal{
		"service refused for a route target port": {func(t *testing.T, p *k8s.Provider) error {
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			_, err = rt.EnsureService(ctx, compute.ServiceSpec{
				Name: "api", Image: image, Resources: res, Replicas: 1,
				Ports:    []compute.PortSpec{{Number: 8080}},
				Identity: mustIdentity(t, p, "api"),
				Routes:   []compute.Route{{Host: "app.invalid", TargetPort: 70000, AllowPlaintext: true}},
			})
			return err
		}},
		"service refused for a replica count": {func(t *testing.T, p *k8s.Provider) error {
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			_, err = rt.EnsureService(ctx, compute.ServiceSpec{
				Name: "api", Image: image, Resources: res, Replicas: math.MaxInt32 + 1,
				Ports:    []compute.PortSpec{{Number: 8080}},
				Identity: mustIdentity(t, p, "api"),
			})
			return err
		}},
		"scheduled job refused for its schedule": {func(t *testing.T, p *k8s.Provider) error {
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			_, err = rt.EnsureScheduledJob(ctx, compute.ScheduledJobSpec{
				Name: "nightly", Image: image, Resources: res,
				Identity: mustIdentity(t, p, "nightly"),
				Schedule: compute.Schedule{Expression: "rate(7 hours)"},
			})
			return err
		}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// The ROBOT-CREDENTIAL path, which writes most: a repository grant, a
			// minted credential, and an attached pull secret.
			//
			// Selecting it requires turning federation off in the CONFIG, not on
			// the registry. Provider.pullByWorkloadIdentity reads
			// cfg.Registry.FederatesClusterOIDC, so an earlier version of this
			// test that called registry.SetFederatesClusterOIDC(false) took the
			// IDENTITY path instead -- and the robots assertion below could never
			// fail, because no credential was ever minted. A comment claiming the
			// write-heaviest path while running the lightest one, with an inert
			// assertion under it. Measured: fullConfig gives robots=0 here,
			// federation-off gives robots=1.
			cfg := fullConfig()
			cfg.Registry.FederatesClusterOIDC = false
			registry := k8s.NewMemoryRegistry()
			registry.SetFederatesClusterOIDC(cfg.Registry.FederatesClusterOIDC)
			sub := &k8s.Substrate{
				Cluster:  k8s.NewMemoryCluster(),
				Registry: registry,
				Objects:  k8s.NewMemoryObjectStore(),
			}
			p := k8s.New(sub, cfg)

			// The repository has to exist and be ours, or ownRepositories finds
			// nothing and the grant path is never reached -- the test would pass
			// without asserting anything.
			reg, err := p.Registry()
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "api"}); err != nil {
				t.Fatalf("EnsureRepository: %v", err)
			}
			if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "nightly"}); err != nil {
				t.Fatalf("EnsureRepository: %v", err)
			}

			grantsBefore, robotsBefore := k8s.RegistryAuthorizationStateForTest(registry)

			if err := tc.drive(t, p); err == nil {
				t.Fatalf("the provider ACCEPTED the spec, so this case asserts nothing about a "+
					"refusal; %s must be refused for the case to be meaningful", name)
			} else if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Errorf("refusal was %v, want compute.ErrInvalidSpec", err)
			}

			grantsAfter, robotsAfter := k8s.RegistryAuthorizationStateForTest(registry)
			if grantsAfter != grantsBefore || robotsAfter != robotsBefore {
				t.Errorf("a REFUSED spec changed registry authorization state: grants %d -> %d, "+
					"robots %d -> %d.\nThe caller was told the operation did not happen. "+
					"buildWorkload used to grant repository read, mint a robot credential and "+
					"attach a pull secret, so every validation after it could refuse a spec that "+
					"had already been authorized -- and the acceptance phase extracted to make "+
					"refusal side-effect free contained that write.",
					grantsBefore, grantsAfter, robotsBefore, robotsAfter)
			}
		})
	}
}

// TestScaleAcceptsEveryEffectiveSpecEnsureWrote is the other direction of the
// equivalence, and it is the half that was missing.
//
// # Why one direction was not enough
//
// [TestScaleAndEnsureAgreeOnEverySpecTheyRefuse] asserts *Ensure refuses ⇒ Scale
// refuses*. That is an implication, not an equivalence, and round nine showed what
// it cannot see: a Scale-only refusal on a spec Ensure accepts left that test and
// the whole package suite green. The untested half is the one where a caller is
// refused work that should proceed — arguably the worse failure, because a false
// refusal blocks a deploy that is legitimate.
//
// # Why nothing is planted here
//
// The refusal direction plants an annotation, because a spec Ensure rejects never
// gets written. This direction must NOT plant: Ensure normalises the spec before
// encoding it (Placement becomes the resolved placement's name), so a
// hand-planted copy of the input is not what Ensure would have written and the
// canonicality check would refuse it for a legitimate reason — the test would pass
// for the wrong reason and prove nothing about provenance.
//
// So this drives the real flow: Ensure writes the annotation, and Scale must
// accept what Ensure wrote. Every optional field is varied, because the provenance
// check runs Ensure's whole acceptance phase and any field it treats differently
// on the read-back path is a candidate for a false refusal.
func TestScaleAcceptsEveryEffectiveSpecEnsureWrote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	base := func(identity compute.Ref) compute.ServiceSpec {
		return compute.ServiceSpec{
			Name:      "api",
			Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  2,
			Ports:     []compute.PortSpec{{Number: 8080}},
			Identity:  identity,
		}
	}

	variants := map[string]func(compute.ServiceSpec) compute.ServiceSpec{
		"the plain spec": func(s compute.ServiceSpec) compute.ServiceSpec { return s },
		"with labels": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Labels = map[string]string{"team": "platform", "tier": "api"}
			return s
		},
		"with a route": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Routes = []compute.Route{{Host: "app.invalid", TargetPort: 8080, AllowPlaintext: true}}
			return s
		},
		"with an ingress rule": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Ingress = []compute.IngressRule{
				{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080},
			}
			return s
		},
		"with several ports": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Ports = []compute.PortSpec{{Number: 8080}, {Number: 9090}}
			return s
		},
		"with environment": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Env = []compute.EnvVar{{Name: "LOG_LEVEL", Value: "info"}}
			return s
		},
		"with exec enabled": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.ExecEnabled = true
			return s
		},
		"at zero replicas": func(s compute.ServiceSpec) compute.ServiceSpec {
			s.Replicas = 0
			return s
		},
	}

	for name, vary := range variants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := fullConfig()
			p := k8s.New(newSubstrate(cfg), cfg)
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			spec := vary(base(mustIdentity(t, p, "api")))

			// The control: this direction is only meaningful for specs Ensure
			// ACCEPTS. A variant Ensure rejects belongs in the other test.
			svc, err := rt.EnsureService(ctx, spec)
			if err != nil {
				t.Fatalf("EnsureService refused %s: %v\nThis direction of the equivalence is "+
					"about specs Ensure accepts; if this variant is invalid it belongs in the "+
					"refusal test instead", name, err)
			}

			if err := rt.ScaleService(ctx, svc.Ref, 1); err != nil {
				t.Errorf("ScaleService refused an effective spec that EnsureService itself "+
					"wrote (%s): %v\nA provenance check that refuses what Ensure produced is "+
					"blocking legitimate work, which is the direction the refusal-only "+
					"equivalence cannot see.", name, err)
			}
			// And the scale must have taken effect, or a refusal could hide as a
			// silent no-op.
			st, err := rt.DescribeService(ctx, svc.Ref)
			if err != nil {
				t.Fatalf("DescribeService: %v", err)
			}
			if st.Spec.Replicas != 1 {
				t.Errorf("after ScaleService(1) the effective spec reports %d replicas (%s); the "+
					"scale was accepted but not applied", st.Spec.Replicas, name)
			}
		})
	}
}

// TestAnOwnershipRefusalGrantsNoRegistryAccess is round ten's (a) reproduction.
//
// # Why this is a security finding rather than a tidiness one
//
// grantPullAccess writes: it grants repository read, and on a cluster that cannot
// pull by workload identity it mints a robot credential too. [Provider.claim] is a
// Get plus an ownership check that returns [compute.ErrNotOwned] and writes
// nothing.
//
// With the grant first, a spec refused *because the object belongs to somebody
// else* had already widened repository-read authorization. That is the worst
// direction for an ordering bug: the refusal an operator relies on to mean "I
// touched nothing" was the refusal that granted.
//
// Round nine moved the write out of the validation phase. This is the same class
// one step later — the phase boundary was right and one refusal was on the wrong
// side of it, so the fix for validation-after-mutation still had a mutation before
// a refusal.
//
// # What it does NOT close
//
// Claim-before-grant closes this route. It does not close the class: an apply
// AFTER the grant can still fail, leaving the grant made and the resource absent.
// That needs grant-last or explicit compensation and is not something an ordering
// change can fix. Stated here so a passing test is not read as more than it is.
func TestAnOwnershipRefusalGrantsNoRegistryAccess(t *testing.T) {
	t.Parallel()

	// # The population of CELLS, not just the state inside each cell
	//
	// Every cell below carries a positive control, so a cell that cannot detect a
	// grant fails rather than passing. That protects every cell that EXISTS and
	// says nothing about a path that never gets a cell -- and "a fourth path added
	// later cannot be added blind" was the claim. Replacing grantingPaths' body
	// with `return nil` made this test pass with ZERO subtests.
	//
	// So the table is checked against the source: every function that calls
	// [Provider.grantPullAccess] must have a cell, keyed by that function's own
	// name so the two sets are directly comparable and no mapping table can drift
	// between them. Add a fourth granting path and this fails until its cell
	// exists.
	//
	// The callee is resolved by the TYPE CHECKER rather than matched as a
	// selector, because a spelling census is what a derivation must not be. What
	// it cannot see is a DIFFERENT granting function added beside this one -- the
	// check is anchored on grantPullAccess specifically, and a new
	// grantSomethingElse would be outside it. Stated rather than implied.
	table := grantingPaths()
	callers := callersOfGrantPullAccess(t)
	if len(table) == 0 {
		t.Fatal("grantingPaths returned no cells; a table of zero cells passes every assertion " +
			"in this test and asserts nothing")
	}
	if len(callers) == 0 {
		t.Fatal("no callers of grantPullAccess were found in the package source. Either the " +
			"method was renamed, or the derivation is looking in the wrong place -- and an empty " +
			"derived set would let this test agree with any table at all")
	}
	for fn := range callers {
		if _, ok := table[fn]; !ok {
			t.Errorf("%s calls grantPullAccess and has no cell in grantingPaths, so the "+
				"ownership-before-grant order is unpinned on that path. That is exactly how the "+
				"scheduled-job and function paths went unpinned after round ten fixed all three.", fn)
		}
	}
	for fn := range table {
		if !callers[fn] {
			t.Errorf("grantingPaths has a cell for %s, which does not call grantPullAccess; the "+
				"cell is testing an ordering that path does not have", fn)
		}
	}

	for name, path := range table {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertOwnershipRefusalGrantsNothing(t, path)
		})
	}
}

// grantingPaths enumerates every Ensure that calls grantPullAccess, which is the
// population [TestAnOwnershipRefusalGrantsNoRegistryAccess] has to cover.
//
// # Why this is a table and was not
//
// Round ten found grant-before-claim on all three of these paths and the fix
// changed all three -- on the reasoning that repairing only the reported one is
// route-not-population. **The test kept the reported one's shape.** So the
// delivered order was right everywhere and pinned in one place: swapping grant
// and claim on the scheduled-job or function path left the entire compute/k8s
// suite green. Reproduced on both before this table existed.
//
// That is the same asymmetry the fix avoided, arriving in the test instead -- a
// fix generalised over a population and a regression that was not. Worth naming
// because the fix's own commit message argued against exactly this.
//
// Each entry drives its own Ensure twice: once to create the resource, then again
// under a second workload identity after the object has been made somebody
// else's. The second identity is load-bearing; see the note in
// assertOwnershipRefusalGrantsNothing.
func grantingPaths() map[string]func(*testing.T, context.Context, *k8s.Provider, string) (compute.Ref, func(compute.Ref) error) {
	image := compute.ImageRef("registry.invalid/apphub/api:v1")
	res := compute.Resources{CPUMillicores: 500, MemoryMiB: 512}
	return map[string]func(*testing.T, context.Context, *k8s.Provider, string) (compute.Ref, func(compute.Ref) error){
		"EnsureService": func(t *testing.T, ctx context.Context, p *k8s.Provider, name string) (compute.Ref, func(compute.Ref) error) {
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			spec := compute.ServiceSpec{
				Name: name, Image: image, Resources: res, Replicas: 1,
				Ports:    []compute.PortSpec{{Number: 8080}},
				Identity: mustIdentity(t, p, name),
			}
			svc, err := rt.EnsureService(ctx, spec)
			if err != nil {
				t.Fatalf("EnsureService: %v", err)
			}
			return svc.Ref, func(_ compute.Ref) error {
				retry := spec
				retry.Identity = mustIdentity(t, p, name+"-two")
				_, err := rt.EnsureService(ctx, retry)
				return err
			}
		},
		"EnsureFunction": func(t *testing.T, ctx context.Context, p *k8s.Provider, name string) (compute.Ref, func(compute.Ref) error) {
			fns, err := p.Functions()
			if err != nil {
				t.Fatalf("Functions: %v", err)
			}
			// A function pulls its RUNTIME image, not an application image, so the
			// repository that has to exist is the runtime's. Without it
			// ownRepositories finds nothing, no grant is made, and the counter this
			// cell asserts on cannot move -- which is exactly how this cell passed
			// against its own mutation before the positive control below existed.
			reg, err := p.Registry()
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "runtime-python"}); err != nil {
				t.Fatalf("EnsureRepository(runtime-python): %v", err)
			}
			spec := compute.FunctionSpec{
				Name: name, Runtime: "python-3.12", Handler: "index.handler",
				Code:      compute.CodeSource{Inline: []byte("bundle")},
				Resources: compute.Resources{MemoryMiB: 512},
				Timeout:   30 * time.Second,
				Identity:  mustIdentity(t, p, name),
			}
			fn, err := fns.EnsureFunction(ctx, spec)
			if err != nil {
				t.Fatalf("EnsureFunction: %v", err)
			}
			return fn.Ref, func(_ compute.Ref) error {
				retry := spec
				retry.Identity = mustIdentity(t, p, name+"-two")
				_, err := fns.EnsureFunction(ctx, retry)
				return err
			}
		},
		"EnsureScheduledJob": func(t *testing.T, ctx context.Context, p *k8s.Provider, name string) (compute.Ref, func(compute.Ref) error) {
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			spec := compute.ScheduledJobSpec{
				Name: name, Image: image, Resources: res,
				Identity: mustIdentity(t, p, name),
				Schedule: compute.Schedule{Expression: "0 3 * * *"},
			}
			job, err := rt.EnsureScheduledJob(ctx, spec)
			if err != nil {
				t.Fatalf("EnsureScheduledJob: %v", err)
			}
			return job.Ref, func(_ compute.Ref) error {
				retry := spec
				retry.Identity = mustIdentity(t, p, name+"-two")
				_, err := rt.EnsureScheduledJob(ctx, retry)
				return err
			}
		},
	}
}

// assertOwnershipRefusalGrantsNothing is the body round ten wrote for one path,
// parameterised over the path.
func assertOwnershipRefusalGrantsNothing(
	t *testing.T,
	build func(*testing.T, context.Context, *k8s.Provider, string) (compute.Ref, func(compute.Ref) error),
) {
	t.Helper()
	ctx := context.Background()

	// The robot-credential path, selected in the CONFIG rather than on the
	// registry -- see the note in TestARefusedSpecGrantsNoRegistryAccess. Getting
	// this wrong leaves the robots assertion unable to fail.
	cfg := fullConfig()
	cfg.Registry.FederatesClusterOIDC = false
	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(cfg.Registry.FederatesClusterOIDC)
	cluster := k8s.NewMemoryCluster()
	sub := &k8s.Substrate{Cluster: cluster, Registry: registry, Objects: k8s.NewMemoryObjectStore()}
	p := k8s.New(sub, cfg)

	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	const name = "api"
	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: name}); err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	ref, reEnsure := build(t, ctx, p, name)

	// Make the object somebody else's, which is what claim exists to refuse. Done
	// through the harness rather than by composing a name, so a change to the
	// naming rules cannot make this test silently stop reaching the object.
	if err := p.Harness().CreateUnowned(ctx, ref); err != nil {
		t.Fatalf("CreateUnowned: %v", err)
	}

	// The refused Ensure runs under a DIFFERENT workload identity, and that detail
	// is load-bearing.
	//
	// The first version of this test re-Ensured with the same identity. The grant
	// is idempotent per principal, so a grant-before-claim ordering re-granted the
	// principal that already held access and the counter did not move: the test
	// passed against the very defect it was written for. A counter is only evidence
	// when the state it counts can actually change. Under a second identity the
	// principal is new, so a grant before the ownership refusal is visible as
	// grants going up.
	grantsBefore, robotsBefore := k8s.RegistryAuthorizationStateForTest(registry)

	// THE POSITIVE CONTROL, and it is the reason this test is trustworthy rather
	// than merely green.
	//
	// This cell detects a grant that happens before the ownership refusal. If the
	// first Ensure granted nothing -- because the repository the image pulls from
	// does not exist, so ownRepositories found nothing -- then there is no grant
	// path to get the ordering wrong on, and the assertion below cannot fail
	// whatever the provider does.
	//
	// That is not hypothetical: the function cell was written without the runtime
	// repository and passed cleanly against a deliberate grant-before-claim
	// mutation on its own path. A cell that cannot fail is decoration, and it
	// looks exactly like coverage.
	if grantsBefore == 0 {
		t.Fatalf("no grant was made by the successful Ensure, so this cell cannot detect a grant "+
			"before the ownership refusal and asserts nothing. Ensure the repository this path's "+
			"image pulls from exists. grants=%d robots=%d", grantsBefore, robotsBefore)
	}

	if err := reEnsure(ref); !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("re-Ensure over an unowned object returned %v, want compute.ErrNotOwned; "+
			"without that refusal this test is not exercising the ownership path", err)
	}

	grantsAfter, robotsAfter := k8s.RegistryAuthorizationStateForTest(registry)
	if grantsAfter != grantsBefore || robotsAfter != robotsBefore {
		t.Errorf("an OWNERSHIP refusal widened registry authorization: grants %d -> %d, "+
			"robots %d -> %d.\nThe caller was told the resource belongs to somebody else and "+
			"nothing was done. A refusal that grants repository read is worse than a refusal "+
			"that half-applies, because the access outlives the failed call and nothing in the "+
			"error mentions it.",
			grantsBefore, grantsAfter, robotsBefore, robotsAfter)
	}
}
