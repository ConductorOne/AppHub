// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
)

// deferredRetirementRuntime models a provider accepting deletion before it has
// completed. Until Describe converges, the real fake substrate still has the
// old workload. Starting the other mode during that window is refused.
type deferredRetirementRuntime struct {
	compute.ContainerRuntime
	prior     compute.Ref
	pending   bool
	observed  bool
	stall     bool
	deleteErr error
}

func (r *deferredRetirementRuntime) DeleteService(_ context.Context, _ compute.Ref) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.pending = true
	return nil
}

func (r *deferredRetirementRuntime) DeleteScheduledJob(ctx context.Context, ref compute.Ref) error {
	return r.DeleteService(ctx, ref)
}

func (r *deferredRetirementRuntime) advance(ctx context.Context, ref compute.Ref) error {
	if ref != r.prior || !r.pending || r.stall {
		return nil
	}
	if !r.observed {
		r.observed = true
		return nil
	}
	var err error
	if ref.Kind == compute.KindService {
		err = r.ContainerRuntime.DeleteService(ctx, ref)
	} else {
		err = r.ContainerRuntime.DeleteScheduledJob(ctx, ref)
	}
	if err == nil {
		r.pending = false
	}
	return err
}

func (r *deferredRetirementRuntime) DescribeService(ctx context.Context, ref compute.Ref) (*compute.ServiceStatus, error) {
	if err := r.advance(ctx, ref); err != nil {
		return nil, err
	}
	return r.ContainerRuntime.DescribeService(ctx, ref)
}

func (r *deferredRetirementRuntime) DescribeScheduledJob(ctx context.Context, ref compute.Ref) (*compute.ScheduledJobStatus, error) {
	if err := r.advance(ctx, ref); err != nil {
		return nil, err
	}
	return r.ContainerRuntime.DescribeScheduledJob(ctx, ref)
}

func (r *deferredRetirementRuntime) previousGone(ctx context.Context) error {
	if r.prior.Kind == compute.KindService {
		status, err := r.ContainerRuntime.DescribeService(ctx, r.prior)
		if err != nil {
			return err
		}
		if status.Phase == compute.PhaseGone {
			return nil
		}
	} else {
		_, err := r.ContainerRuntime.DescribeScheduledJob(ctx, r.prior)
		if errors.Is(err, compute.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return errors.New("new workload would overlap the previous execution mode")
}

func (r *deferredRetirementRuntime) EnsureService(ctx context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	if err := r.previousGone(ctx); err != nil {
		return nil, err
	}
	return r.ContainerRuntime.EnsureService(ctx, spec)
}

func (r *deferredRetirementRuntime) EnsureScheduledJob(ctx context.Context, spec compute.ScheduledJobSpec) (*compute.ScheduledJobStatus, error) {
	if err := r.previousGone(ctx); err != nil {
		return nil, err
	}
	return r.ContainerRuntime.EnsureScheduledJob(ctx, spec)
}

func setExecution(app *Application, mode ExecutionMode) {
	app.Execution = mode
	app.Routes = nil
	app.Schedule = compute.Schedule{}
	if mode == ExecutionScheduled {
		app.Schedule = compute.Schedule{Expression: "rate(1 hour)", Timezone: "UTC"}
	}
}

func TestExecutionModeSwitchRetiresOldWorkloadBeforeStartingNew(t *testing.T) {
	t.Parallel()
	for _, initial := range []ExecutionMode{ExecutionService, ExecutionScheduled} {
		t.Run(string(initial), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			p := newTestProvider(t)
			app := minimalApplication()
			setExecution(app, initial)
			store := newMemStore(app)
			m, _, _ := newTestModule(t, p, store, testConfig())
			if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
				t.Fatal(err)
			}
			updated := *store.saved(app.ID)
			prior := updated.Artifacts.Workload
			next := ExecutionScheduled
			if initial == ExecutionScheduled {
				next = ExecutionService
			}
			setExecution(&updated, next)
			if err := store.SaveApplication(ctx, &updated); err != nil {
				t.Fatal(err)
			}
			runtime, err := p.Containers()
			if err != nil {
				t.Fatal(err)
			}
			delayed := &deferredRetirementRuntime{ContainerRuntime: runtime, prior: prior}
			m, _, _ = newTestModule(t, oneReplicaProvider{p, delayed}, store, testConfig())
			result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
			if err != nil || result == nil || !result.Success {
				t.Fatalf("mode switch: result=%+v error=%v", result, err)
			}
			if err := delayed.previousGone(ctx); err != nil {
				t.Fatal(err)
			}
			current := store.saved(app.ID).Artifacts.Workload
			if current.IsZero() || current.Kind == prior.Kind {
				t.Fatalf("new workload was not installed: %v", current)
			}
			if next == ExecutionScheduled {
				if _, err := runtime.DescribeScheduledJob(ctx, current); err != nil {
					t.Fatal(err)
				}
			} else {
				status, err := runtime.DescribeService(ctx, current)
				if err != nil || status.Phase != compute.PhaseReady {
					t.Fatalf("new service not ready: %v", err)
				}
			}
		})
	}
}

func TestRetirementFailureKeepsOldReferenceAndDoesNotStartNewWorkload(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"delete", "timeout", "checkpoint"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			p := newTestProvider(t)
			app := minimalApplication()
			memory := newMemStore(app)
			m, _, _ := newTestModule(t, p, memory, testConfig())
			if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
				t.Fatal(err)
			}
			updated := *memory.saved(app.ID)
			prior := updated.Artifacts.Workload
			setExecution(&updated, ExecutionScheduled)
			if err := memory.SaveApplication(ctx, &updated); err != nil {
				t.Fatal(err)
			}
			runtime, err := p.Containers()
			if err != nil {
				t.Fatal(err)
			}
			outage := errors.New("retirement unavailable")
			delayed := &deferredRetirementRuntime{ContainerRuntime: runtime, prior: prior, stall: true}
			if failure == "delete" {
				delayed.deleteErr = outage
			}
			store := &checkpointStore{memStore: memory, beforeSave: func(_ context.Context, a *Application) error {
				if failure == "checkpoint" && a.Status == StatusDeploying && a.DeployStep == stepWorkloadRetireReady {
					return outage
				}
				return nil
			}}
			cfg := testConfig()
			cfg.WaitTimeout = 20 * time.Millisecond
			m, _, _ = newTestModule(t, oneReplicaProvider{p, delayed}, store, cfg)
			result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
			want := outage
			if failure == "timeout" {
				want = compute.ErrTimeout
			}
			if !errors.Is(err, want) || result == nil || result.Success {
				t.Fatalf("retirement failure: result=%+v error=%v", result, err)
			}
			if result.Data["workload"] != prior.String() || store.saved(app.ID).Artifacts.Workload != prior {
				t.Fatal("uncertain previous workload reference was discarded")
			}
			if err := delayed.previousGone(ctx); err == nil {
				t.Fatal("fixture did not retain the previous workload")
			}
			for _, row := range rendered(t, p) {
				if len(row) >= len("scheduled-job ") && row[:len("scheduled-job ")] == "scheduled-job " {
					t.Fatal("new schedule installed before old service stopped")
				}
			}
		})
	}
}

type reportedAddressRuntime struct {
	compute.ContainerRuntime
	addresses []string
}

func (r reportedAddressRuntime) DescribeService(ctx context.Context, ref compute.Ref) (*compute.ServiceStatus, error) {
	status, err := r.ContainerRuntime.DescribeService(ctx, ref)
	if status != nil {
		status.RouteAddresses = r.addresses
	}
	return status, err
}

func TestPublishedLinksRequireProviderReportedConfiguredTLSRoute(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := minimalApplication()
	app.Routes = []Route{{Hostname: "reports"}, {Hostname: "plaintext", AllowPlaintext: true}}
	store := newMemStore(app)
	runtime, err := p.Containers()
	if err != nil {
		t.Fatal(err)
	}
	reported := []string{
		"reports.apps.example.test", "https://reports.apps.example.test/",
		"https://evil.test", "plaintext.apps.example.test", "https://reports.apps.example.test@evil.test",
		"https://reports.apps.example.test/redirect", "https://reports.apps.example.test?token=canary",
		"https://reports.apps.example.test#canary", "http://reports.apps.example.test",
	}
	m, _, _ := newTestModule(t, oneReplicaProvider{p, reportedAddressRuntime{runtime, reported}}, store, testConfig())
	result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://reports.apps.example.test"}
	if !reflect.DeepEqual(store.saved(app.ID).Artifacts.Addresses, want) || !reflect.DeepEqual(result.Data["addresses"], want) {
		t.Fatalf("unsafe or missing published links: %+v", result.Data["addresses"])
	}
	for _, untrusted := range reported[2:] {
		if got := tlsRouteAddresses(planFor(t, app).Routes, []string{untrusted}); len(got) != 0 {
			t.Errorf("untrusted address %q produced links %v", untrusted, got)
		}
	}
}
