// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestCheckpointsPreserveImmutableRequestDuringConcurrentHeartbeats(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	if err := operation.prepare(ctx, fixtureCommit); err != nil {
		t.Fatal(err)
	}
	editable, err := operation.GetApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Even a module accidentally modifying an input may not rewrite the request.
	editable.Name = "module must not change input"
	editable.Source.URL = "https://unapproved.example.test/project"
	editable.Source.Ref = "other-ref"
	editable.Replicas = 999
	editable.DeployStep = "image-build"
	editable.Artifacts.Image = compute.ImageRef("registry.invalid/test@sha256:partial")
	editable.Artifacts.Secrets = map[string]compute.Ref{"database-password": {Provider: "worker-test", Kind: compute.KindSecret, ID: "opaque-secret-reference"}}
	failures := make(chan error, 40)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() { defer wg.Done(); failures <- operation.heartbeat(ctx) }()
		go func() { defer wg.Done(); failures <- operation.SaveApplication(ctx, editable) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("heartbeat/checkpoint created a false CAS loss: %v", err)
		}
	}
	// The module retains its own map, not a pointer into the heartbeat snapshot.
	editable.Artifacts.Secrets["database-password"] = compute.Ref{}
	dep, app := f.deployment(t), f.application(t)
	if !reflect.DeepEqual(dep.Application, f.dep.Application) || dep.RequestedSourceRef != "main" || dep.ResolvedCommit != fixtureCommit {
		t.Fatal("checkpoint overwrote the immutable requested specification")
	}
	if !reflect.DeepEqual(app.Owners, f.app.Owners) || app.Revision != f.app.Revision || !reflect.DeepEqual(app.Input, f.app.Input) || app.Application.Name != f.app.Application.Name || app.Application.Source != f.app.Application.Source || app.Application.Replicas != f.app.Application.Replicas {
		t.Fatal("checkpoint overwrote application ownership, inputs or revision")
	}
	if app.Application.Artifacts.Image != editable.Artifacts.Image || dep.Artifacts.Secrets["database-password"].IsZero() || dep.Step != "image-build" {
		t.Fatal("checkpoint failed to retain owned runtime outputs")
	}
	again, err := operation.GetApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Source.Ref != fixtureCommit || again.Source.URL != f.dep.Application.Source.URL || again.Artifacts.Secrets["database-password"].IsZero() {
		t.Fatal("module mutations corrupted the prepared snapshot")
	}
}

func TestCanceledCheckpointUsesIndependentFailurePersistenceAndRetainsLock(t *testing.T) {
	f := newWorkerFixture(t)
	operation, jobCtx := f.claim(t)
	partial, err := operation.GetApplication(jobCtx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	partial.Artifacts.Repository = compute.Ref{Provider: "worker-test", Kind: compute.KindImageRepository, ID: "created-before-cancellation"}
	partial.DeployStep = "image-repository"
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := operation.SaveApplication(canceled, partial); !errors.Is(err, context.Canceled) {
		t.Fatalf("save did not report canceled persistence: %v", err)
	}
	if jobCtx.Err() == nil {
		t.Fatal("failed checkpoint did not stop local effects")
	}
	if err := operation.finish(cp.Failed, "deployment_failed", "Failed."); err != nil {
		t.Fatal(err)
	}
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Interrupted || app.ActiveDeploymentID != dep.ID || dep.Artifacts.Repository != partial.Artifacts.Repository || app.Application.Artifacts.Repository != partial.Artifacts.Repository {
		t.Fatalf("canceled save lost partial resources or released uncertain lock: %+v", dep)
	}
}

func TestPersistenceOutageCannotTurnPartialEffectsIntoSuccess(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	partial, err := operation.GetApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	partial.Artifacts.Workload = compute.Ref{Provider: "worker-test", Kind: compute.KindService, ID: "service-may-exist"}
	partial.DeployStep = "service"
	f.repo.SetError(cp.ErrUnavailable)
	if err := operation.SaveApplication(ctx, partial); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := operation.finish(cp.Succeeded, "", "ready"); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("storage outage was hidden: %v", err)
	}
	f.repo.SetError(nil)
	if f.deployment(t).State != cp.Running || f.application(t).ActiveDeploymentID != f.dep.ID {
		t.Fatal("outage falsely settled the deployment")
	}
	if err := operation.finish(cp.Succeeded, "", "ready"); err != nil {
		t.Fatal(err)
	}
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Interrupted || app.ActiveDeploymentID != dep.ID || dep.Artifacts.Workload != partial.Artifacts.Workload || app.LastSuccessfulDeploymentID != "" {
		t.Fatal("recovered persistence claimed success after execution lost its fence")
	}
}

func TestApplicationCASLossCancelsOldWorkerAndPreservesNewerRecord(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID})
	if err != nil {
		t.Fatal(err)
	}
	app, err := cp.Decode[cp.ApplicationRecord](row)
	if err != nil {
		t.Fatal(err)
	}
	app.ActiveDeploymentID = "different-operation"
	app.Revision++
	mutation, err := recordMutation(row, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{mutation}); err != nil {
		t.Fatal(err)
	}
	if err := operation.heartbeat(ctx); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("heartbeat ignored application fence loss: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("application CAS loss left old worker running")
	}
	if err := operation.finish(cp.Succeeded, "", "ready"); !errors.Is(err, cp.ErrConflict) {
		t.Fatal("fenced attempt wrote terminal state")
	}
	if f.application(t).ActiveDeploymentID != "different-operation" || f.application(t).Revision != app.Revision {
		t.Fatal("old worker overwrote a newer application")
	}
}

// A transport can fail after DynamoDB accepted its transaction. The worker must
// stop effects, reconcile the exact same attempt, and preserve uncertainty.
type ambiguousCommitRepository struct {
	cp.Repository
	fail bool
}

func (r *ambiguousCommitRepository) Commit(ctx context.Context, mutations []cp.Mutation) error {
	if err := r.Repository.Commit(ctx, mutations); err != nil {
		return err
	}
	if r.fail {
		r.fail = false
		return cp.ErrUnavailable
	}
	return nil
}

func TestAmbiguousCheckpointCommitReconcilesWithoutRepeatingEffects(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	wrapper := &ambiguousCommitRepository{Repository: f.repo, fail: true}
	operation.repo = wrapper
	partial, err := operation.GetApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	partial.Artifacts.Image = "registry.invalid/test@sha256:already-pushed"
	partial.DeployStep = "image-build"
	if err := operation.SaveApplication(ctx, partial); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := operation.finish(cp.Succeeded, "", "ready"); err != nil {
		t.Fatal(err)
	}
	dep := f.deployment(t)
	if dep.State != cp.Interrupted || dep.Artifacts.Image != partial.Artifacts.Image || f.application(t).ActiveDeploymentID != dep.ID {
		t.Fatal("ambiguous transaction was replayed or treated as success")
	}
}

func TestProgressCoalescesWithoutPersistingUntrustedMessages(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	const canary = "provider-error-containing-secret"
	var wg sync.WaitGroup
	for percentage := range 200 {
		wg.Add(1)
		go func() { defer wg.Done(); operation.report(ctx, percentage, canary) }()
	}
	wg.Wait()
	operation.report(ctx, -5, canary)
	if err := operation.heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	dep := f.deployment(t)
	if dep.Progress != "99%" || dep.State != cp.Running {
		t.Fatalf("progress was unbounded or falsely terminal: %+v", dep)
	}
	row, err := f.repo.Read(ctx, cp.RecordID{Kind: cp.DeploymentKind, ID: dep.ID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row.Value), canary) {
		t.Fatal("untrusted progress message was persisted")
	}
}
