// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
)

// recordingObserver keeps what a teardown reported, and can refuse a step.
type recordingObserver struct {
	started   []TeardownStep
	completed []TeardownStep
	remaining Artifacts
	failStart TeardownStep
}

func (o *recordingObserver) StartStep(_ context.Context, step TeardownStep) error {
	if step == o.failStart {
		return errors.New("checkpoint refused")
	}
	o.started = append(o.started, step)
	return nil
}

func (o *recordingObserver) CompleteStep(_ context.Context, step TeardownStep, remaining Artifacts) error {
	o.completed = append(o.completed, step)
	o.remaining = remaining
	return nil
}

var fastTeardown = TeardownOptions{InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, PollInterval: time.Millisecond}

// deployedApplication runs a real deploy of the full fixture and returns the
// artifacts it recorded, so teardown is tested against what a deploy creates.
func deployedApplication(t *testing.T, p *fake.Provider) Artifacts {
	t.Helper()
	app := testApplication()
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())
	result, err := m.Execute(context.Background(), "u1", map[string]any{"applicationId": app.ID})
	if err != nil || !result.Success {
		t.Fatalf("deploy: %v %+v", err, result)
	}
	return store.saved(app.ID).Artifacts
}

func TestTeardownDeletesEverythingADeployCreated(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	obs := &recordingObserver{}

	if err := Teardown(context.Background(), p, "app-1", artifacts, obs, fastTeardown); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	want := []TeardownStep{StepDeleteWorkload, StepDeleteDatabase, StepDeleteBucket, StepDeleteSecrets, StepDeleteIdentity, StepDeleteImageRepository}
	if !slices.Equal(obs.started, want) || !slices.Equal(obs.completed, want) {
		t.Fatalf("steps started %v, completed %v; want %v", obs.started, obs.completed, want)
	}
	if got := TeardownPlan(p.Capabilities(), obs.remaining); !slices.Equal(got, []TeardownStep{StepDeleteSecrets, StepDeleteRecords}) {
		t.Errorf("a finished teardown still plans %v; a retry would redo deleted work", got)
	}
	requireGone(t, p, artifacts)
}

// requireGone asks each port for each resource. A provider may keep a deleted
// resource observable as gone, so the substrate's contents are not the test.
func requireGone(t *testing.T, p *fake.Provider, a Artifacts) {
	t.Helper()
	ctx := context.Background()
	runtime, _ := p.Containers()
	if service, err := runtime.DescribeService(ctx, a.Workload); !errors.Is(err, compute.ErrNotFound) && (err != nil || service.Phase != compute.PhaseGone) {
		t.Errorf("service survived teardown: %v", err)
	}
	relational, _ := p.Relational()
	if database, err := relational.DescribeRelational(ctx, a.Relational); !errors.Is(err, compute.ErrNotFound) && (err != nil || database.Phase != compute.PhaseGone) {
		t.Errorf("database survived teardown: %v", err)
	}
	store, _ := p.ObjectStores()
	if _, err := store.DescribeBucket(ctx, a.Bucket); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("bucket survived teardown: %v", err)
	}
	if _, err := p.Identities().DescribeWorkloadIdentity(ctx, a.Identity); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("identity survived teardown: %v", err)
	}
	registry, _ := p.Registry()
	if _, err := registry.DescribeRepository(ctx, a.Repository); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("image repository survived teardown: %v", err)
	}
	secrets, _ := p.Secrets()
	for name, ref := range a.Secrets {
		if _, err := secrets.Describe(ctx, ref); !errors.Is(err, compute.ErrNotFound) {
			t.Errorf("secret %s survived teardown: %v", name, err)
		}
	}
}

func TestTeardownRunsAgainAfterEverythingIsGone(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	if err := Teardown(context.Background(), p, "app-1", artifacts, &recordingObserver{}, fastTeardown); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	// The original artifacts, as a retry that lost the checkpoints would see.
	if err := Teardown(context.Background(), p, "app-1", artifacts, &recordingObserver{}, fastTeardown); err != nil {
		t.Fatalf("a repeated teardown failed on resources that are already gone: %v", err)
	}
}

func TestTeardownRetriesTransientFailures(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	transient := fmt.Errorf("%w: cluster still has a member", compute.ErrTransient)
	for range 3 {
		p.Harness().FailNext(fake.OpDelete, compute.KindRelational, transient)
	}

	if err := Teardown(context.Background(), p, "app-1", artifacts, &recordingObserver{}, fastTeardown); err != nil {
		t.Fatalf("a transient failure ended the teardown instead of being retried: %v", err)
	}
	if n := p.Harness().PendingFailures(); n != 0 {
		t.Fatalf("%d injected failures were never reached", n)
	}
}

func TestTeardownStopsAtAPermanentFailure(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	p.Harness().FailNext(fake.OpDelete, compute.KindRelational, fmt.Errorf("%w: denied", compute.ErrNotPermitted))
	obs := &recordingObserver{}

	err := Teardown(context.Background(), p, "app-1", artifacts, obs, fastTeardown)
	var failure *TeardownError
	if !errors.As(err, &failure) || failure.Step != StepDeleteDatabase || failure.Class != "not-permitted" {
		t.Fatalf("got %v, want a not-permitted failure at %s", err, StepDeleteDatabase)
	}
	if !slices.Equal(obs.completed, []TeardownStep{StepDeleteWorkload}) {
		t.Fatalf("completed %v; the steps after a failure must not run", obs.completed)
	}
	if obs.remaining.Relational.IsZero() || !obs.remaining.Workload.IsZero() {
		t.Error("the checkpoint does not say the workload is gone and the database remains")
	}
}

func TestTeardownGivesUpWhenItsDeadlineEnds(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	stop := p.Harness().FailEvery(fmt.Errorf("%w: throttled", compute.ErrTransient))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := Teardown(ctx, p, "app-1", artifacts, &recordingObserver{}, fastTeardown)
	var failure *TeardownError
	if !errors.As(err, &failure) || !errors.Is(err, compute.ErrTimeout) {
		t.Fatalf("got %v, want a timeout once the deadline ends", err)
	}
}

func TestTeardownStopsWhenProgressCannotBeRecorded(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := deployedApplication(t, p)
	obs := &recordingObserver{failStart: StepDeleteDatabase}

	err := Teardown(context.Background(), p, "app-1", artifacts, obs, fastTeardown)
	var failure *TeardownError
	if !errors.As(err, &failure) || failure.Class != "checkpoint" || failure.Step != StepDeleteDatabase {
		t.Fatalf("got %v, want a checkpoint failure at %s", err, StepDeleteDatabase)
	}
	relational, err := p.Relational()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relational.DescribeRelational(context.Background(), artifacts.Relational); err != nil {
		t.Errorf("the database was deleted although its step could not be recorded: %v", err)
	}
}

func TestTeardownPlanSkipsWhatWasNeverCreated(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	if got := TeardownPlan(p.Capabilities(), Artifacts{}); !slices.Equal(got, []TeardownStep{StepDeleteSecrets, StepDeleteRecords}) {
		t.Errorf("plan for nothing = %v", got)
	}
	if got := TeardownPlan(compute.CapabilitySet{}, Artifacts{}); !slices.Equal(got, []TeardownStep{StepDeleteRecords}) {
		t.Errorf("plan without a secret store = %v", got)
	}
}

func TestTeardownRefusesAnUnknownWorkloadKind(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	artifacts := Artifacts{Workload: compute.Ref{Provider: p.Name(), Kind: compute.KindFunction, ID: "f"}}
	err := Teardown(context.Background(), p, "app-1", artifacts, &recordingObserver{}, fastTeardown)
	if !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("got %v, want ErrInvalidApplication", err)
	}
}
