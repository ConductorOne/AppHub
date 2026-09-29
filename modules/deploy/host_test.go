// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/modules"
)

func TestNativeIdentityRetainsProviderAccessWithoutPlatformAttestation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Artifacts.AttestationRevision = 17 // a prior platform deployment
	store := newMemStore(app)
	cfg := testConfig()
	cfg.WorkloadIdentityMode = "native"
	m, err := New(p, store, newFetcher(t), nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err != nil || result == nil || !result.Success {
		t.Fatalf("native deployment: result=%+v error=%v", result, err)
	}
	saved := store.saved(app.ID)
	if saved.Artifacts.AttestationRevision != 0 {
		t.Fatal("native deployment retained a platform attestation revision")
	}
	if _, err := p.Identities().DescribeWorkloadIdentity(ctx, saved.Artifacts.Identity); err != nil {
		t.Fatalf("provider identity does not exist: %v", err)
	}
	if err := p.Harness().Write(ctx, saved.Artifacts.Bucket, saved.Artifacts.Identity); err != nil {
		t.Fatalf("native workload cannot use its bucket: %v", err)
	}
	runtime, err := p.Containers()
	if err != nil {
		t.Fatal(err)
	}
	status, err := runtime.DescribeService(ctx, saved.Artifacts.Workload)
	if err != nil {
		t.Fatal(err)
	}
	if status.Spec.Identity != saved.Artifacts.Identity {
		t.Fatal("service does not run under the provider identity")
	}
	var passwordRef compute.Ref
	for _, binding := range status.Spec.Secrets {
		if binding.EnvName == EnvDatabasePassword {
			passwordRef = binding.Secret
		}
	}
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	password, err := secrets.Get(ctx, passwordRef)
	if err != nil {
		t.Fatalf("workload database password binding: %v", err)
	}
	if err := p.Harness().Login(ctx, saved.Artifacts.Relational, app.Database.AdminUsername, password); err != nil {
		t.Fatalf("bound password cannot access the database: %v", err)
	}
}

func TestPlatformIdentityStillRequiresProvisionerAndRejectsUnknownModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"", "platform"} {
		cfg := testConfig()
		cfg.WorkloadIdentityMode = mode
		_, err := New(newTestProvider(t), newMemStore(), newFetcher(t), nil, cfg)
		if !errors.Is(err, modules.ErrNotConfigured) {
			t.Fatalf("mode %q accepted a missing platform provisioner: %v", mode, err)
		}
	}
	for _, mode := range []string{"Native", " native", "none"} {
		cfg := testConfig()
		cfg.WorkloadIdentityMode = mode
		_, err := New(newTestProvider(t), newMemStore(), newFetcher(t), &stubAttestations{}, cfg)
		if !errors.Is(err, modules.ErrNotConfigured) {
			t.Fatalf("undefined identity mode %q accepted: %v", mode, err)
		}
	}
}

// checkpointStore injects failures at meaningful persisted transitions, not at
// incidental save counts. The real fake compute substrate observes later effects.
type checkpointStore struct {
	*memStore
	beforeSave func(context.Context, *Application) error
}

func (s *checkpointStore) SaveApplication(ctx context.Context, app *Application) error {
	if err := s.beforeSave(ctx, app); err != nil {
		return err
	}
	return s.memStore.SaveApplication(ctx, app)
}

func TestCheckpointFailureStopsLaterEffectsAndRetainsPartialResources(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		at      func(*Application) bool
		absent  string
		partial string
	}{
		{"identity-intent", func(a *Application) bool { return a.DeployStep == "workload-identity" && a.Artifacts.Identity.IsZero() }, "identity ", ""},
		{"identity-result", func(a *Application) bool { return !a.Artifacts.Identity.IsZero() }, "image-repository ", "identity"},
		{"image-pushed", func(a *Application) bool { return a.Artifacts.Image != "" }, "secret ", "image"},
		{"password-published", func(a *Application) bool { return len(a.Artifacts.Secrets) > 0 }, "relational ", "secrets"},
		{"database-created", func(a *Application) bool { return !a.Artifacts.Relational.IsZero() }, "bucket ", "relational"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newTestProvider(t)
			app := testApplication()
			outage := errors.New("checkpoint unavailable")
			store := &checkpointStore{memStore: newMemStore(app)}
			store.beforeSave = func(_ context.Context, a *Application) error {
				if a.Status == StatusDeploying && tc.at(a) {
					return outage
				}
				return nil
			}
			m, _, _ := newTestModule(t, p, store, testConfig())
			result, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
			if !errors.Is(err, outage) || result == nil || result.Success {
				t.Fatalf("checkpoint failure lost: result=%+v error=%v", result, err)
			}
			if tc.partial != "" && result.Data[tc.partial] == nil {
				t.Fatalf("partial result omitted %s: %+v", tc.partial, result.Data)
			}
			if strings.Contains(strings.Join(rendered(t, p), "\n"), tc.absent) {
				t.Fatalf("provider performed %q after checkpoint failure", tc.absent)
			}
			if store.saved(app.ID).Status != StatusFailed {
				t.Fatal("failure was not durably recorded")
			}
		})
	}
}

type sourceFetchFunc func(context.Context, Source) (string, error)

func (f sourceFetchFunc) Fetch(ctx context.Context, src Source) (string, error) { return f(ctx, src) }

func TestCanceledDeployPersistsFailureAndPreservesStorageErrors(t *testing.T) {
	t.Parallel()
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "save", true: "save-outage"}[unavailable], func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			app := minimalApplication()
			store := &checkpointStore{memStore: newMemStore(app)}
			outage := errors.New("failure storage unavailable")
			attempted := false
			store.beforeSave = func(saveCtx context.Context, a *Application) error {
				if a.Status != StatusFailed {
					return nil
				}
				attempted = true
				if saveCtx.Err() != nil {
					t.Error("failure persistence inherited cancellation")
				}
				deadline, ok := saveCtx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Error("failure persistence is unbounded")
				}
				if unavailable {
					return outage
				}
				return nil
			}
			m, _, _ := newTestModule(t, newTestProvider(t), store, testConfig())
			m.fetcher = sourceFetchFunc(func(context.Context, Source) (string, error) {
				cancel()
				return "", ctx.Err()
			})
			result, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
			if !errors.Is(err, context.Canceled) || result == nil || result.Success || !attempted {
				t.Fatalf("canceled failure: result=%+v error=%v attempted=%v", result, err, attempted)
			}
			if unavailable && !errors.Is(err, outage) {
				t.Fatal("storage error was discarded")
			}
			if !unavailable && store.saved(app.ID).Status != StatusFailed {
				t.Fatal("canceled deployment failure was not saved")
			}
			if result.Data["repository"] == nil {
				t.Fatal("canceled result lost created repository")
			}
		})
	}
}

// The substrate really only runs one replica, modeling incomplete capacity.
// Its actual WaitForService must therefore time out when the deploy asks for more.
type oneReplicaRuntime struct{ compute.ContainerRuntime }

func (r oneReplicaRuntime) EnsureService(ctx context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	spec.Replicas = 1
	return r.ContainerRuntime.EnsureService(ctx, spec)
}

type oneReplicaProvider struct {
	compute.Provider
	runtime compute.ContainerRuntime
}

func (p oneReplicaProvider) Containers() (compute.ContainerRuntime, error) { return p.runtime, nil }

func TestServiceWaitRequiresEffectiveRequestedReplicas(t *testing.T) {
	t.Parallel()
	for _, requested := range []int{0, 3} {
		p := newTestProvider(t)
		runtime, err := p.Containers()
		if err != nil {
			t.Fatal(err)
		}
		app := minimalApplication()
		app.Replicas = requested
		cfg := testConfig()
		cfg.WaitTimeout = 20 * time.Millisecond
		store := newMemStore(app)
		m, _, _ := newTestModule(t, oneReplicaProvider{p, oneReplicaRuntime{runtime}}, store, cfg)
		result, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
		if requested == 0 {
			if err != nil || result == nil || !result.Success {
				t.Fatalf("effective one replica refused: %v", err)
			}
		} else {
			if err == nil || result == nil || result.Success || store.saved(app.ID).FailedStep != "service-ready" {
				t.Fatalf("one ready replica satisfied three requested: result=%+v error=%v", result, err)
			}
		}
	}
}

type partialBuildProvider struct {
	compute.Provider
	builder compute.ImageBuilder
}

func (p partialBuildProvider) Builder() (compute.ImageBuilder, error) { return p.builder, nil }

type partialBuild struct {
	compute.ImageBuilder
	err error
}

func (b partialBuild) Build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	result, err := b.ImageBuilder.Build(ctx, req)
	return result, errors.Join(err, b.err)
}

func TestPartialProviderResultSurvivesBothCheckpointAndFailureSaveErrors(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	builder, err := p.Builder()
	if err != nil {
		t.Fatal(err)
	}
	app := minimalApplication()
	providerErr := errors.New("push completed but provider failed")
	checkpointErr := errors.New("checkpoint lost")
	failureErr := errors.New("failure save lost")
	store := &checkpointStore{memStore: newMemStore(app)}
	store.beforeSave = func(_ context.Context, a *Application) error {
		if a.Status == StatusFailed {
			return failureErr
		}
		if a.Artifacts.Image != "" {
			return checkpointErr
		}
		return nil
	}
	m, _, _ := newTestModule(t, partialBuildProvider{p, partialBuild{builder, providerErr}}, store, testConfig())
	result, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	for _, want := range []error{providerErr, checkpointErr, failureErr} {
		if !errors.Is(err, want) {
			t.Errorf("lost error %v: %v", want, err)
		}
	}
	if result == nil || result.Success || result.Data["image"] == nil {
		t.Fatalf("lost pushed image: %+v", result)
	}
	if strings.Contains(strings.Join(rendered(t, p), "\n"), "service ") {
		t.Fatal("service started after image checkpoint failed")
	}
}

func TestFinalCheckpointFailureDoesNotAdvanceLastSuccessfulDeployment(t *testing.T) {
	t.Parallel()
	app := minimalApplication()
	app.LastDeployedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lastSuccess := app.LastDeployedAt
	outage := errors.New("completion unavailable")
	store := &checkpointStore{memStore: newMemStore(app)}
	store.beforeSave = func(_ context.Context, a *Application) error {
		if a.Status == StatusRunning {
			return outage
		}
		return nil
	}
	m, _, _ := newTestModule(t, newTestProvider(t), store, testConfig())
	result, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if !errors.Is(err, outage) || result == nil || result.Success || result.Data["workload"] == nil {
		t.Fatalf("completion failure: result=%+v error=%v", result, err)
	}
	saved := store.saved(app.ID)
	if saved.Status != StatusFailed || !saved.LastDeployedAt.Equal(lastSuccess) {
		t.Fatalf("failed finalization replaced successful deployment: %+v", saved)
	}
}
