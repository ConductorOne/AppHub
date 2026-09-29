// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	cp "github.com/conductorone/apphub/internal/controlplane"
)

// deployThenQueueTeardown deploys the fixture for real, then queues a teardown
// the way DeleteApplication does: the application locked on it and marked for
// deletion. It also files a hostname reservation and usage record, so the
// test can see the control-plane records go too.
func deployThenQueueTeardown(t *testing.T) *workerFixture {
	t.Helper()
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	if dep := f.deployment(t); dep.State != cp.Succeeded {
		t.Fatalf("fixture deployment did not succeed: %+v", dep)
	}
	app := f.application(t)
	now := time.Now().UTC()
	teardown := cp.DeploymentRecord{ID: "teardown-one", Operation: cp.OperationTeardown, Attempt: 1, ApplicationID: app.ID, RequesterUserID: f.dep.RequesterUserID, Requester: f.dep.Requester, ApplicationRevision: app.Revision, TargetID: app.TargetID, Application: app.Application, State: cp.Queued, Artifacts: app.Application.Artifacts, CreatedAt: now}
	putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ParentID: app.ID, ID: teardown.ID}, teardown)
	putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: "held.example.test"}, cp.HostnameReservation{TargetID: app.TargetID, Hostname: "held.example.test", ApplicationID: app.ID})
	putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.ApplicationUsageKind, ID: app.ID}, cp.ApplicationUsageRecord{ID: app.ID})
	row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	if err != nil {
		t.Fatal(err)
	}
	app.ActiveDeploymentID, app.LatestDeploymentID = teardown.ID, teardown.ID
	app.ReservedHostnames = []string{"held.example.test"}
	app.DeletionRequestedAt = now
	m, err := recordMutation(row, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}
	f.dep = teardown
	return f
}

func (f *workerFixture) runTeardown(t *testing.T) {
	t.Helper()
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
}

func gone(t *testing.T, repo cp.Repository, id cp.RecordID) bool {
	t.Helper()
	_, err := repo.Read(context.Background(), id)
	if err != nil && !errors.Is(err, cp.ErrNotFound) {
		t.Fatal(err)
	}
	return errors.Is(err, cp.ErrNotFound)
}

func TestTeardownDeletesResourcesAndEveryRecord(t *testing.T) {
	f := deployThenQueueTeardown(t)
	workload := f.application(t).Application.Artifacts.Workload
	f.runTeardown(t)

	for _, id := range []cp.RecordID{
		{Kind: cp.ApplicationKind, ID: f.app.ID},
		{Kind: cp.DeploymentKind, ID: "teardown-one"},
		{Kind: cp.DeploymentKind, ID: "deploy-one"},
		{Kind: cp.HostnameKind, ParentID: f.app.TargetID, ID: "held.example.test"},
		{Kind: cp.ApplicationUsageKind, ID: f.app.ID},
	} {
		if !gone(t, f.repo, id) {
			t.Errorf("%s %s survived a successful teardown", id.Kind, id.ID)
		}
	}
	runtime, err := f.provider.Containers()
	if err != nil {
		t.Fatal(err)
	}
	status, err := runtime.DescribeService(context.Background(), workload)
	if err == nil && status.Phase != compute.PhaseGone {
		t.Fatalf("the service is still %s after teardown", status.Phase)
	}
}

func TestFailedTeardownKeepsTheApplicationLockedAndSaysWhere(t *testing.T) {
	f := deployThenQueueTeardown(t)
	f.provider.Harness().FailNext(fake.OpDelete, compute.KindWorkloadIdentity, fmt.Errorf("%w: denied", compute.ErrNotPermitted))
	f.runTeardown(t)

	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Failed || dep.ErrorCode != "teardown_failed" || dep.Step != "delete-identity" {
		t.Fatalf("teardown outcome = %s %s at %q: %s", dep.State, dep.ErrorCode, dep.Step, dep.Message)
	}
	if app.ActiveDeploymentID != dep.ID {
		t.Fatal("a failed teardown released the lock, so a part-deleted application could be deployed")
	}
	if !app.Application.Artifacts.Workload.IsZero() || app.Application.Artifacts.Identity.IsZero() {
		t.Error("the application does not record which resources were deleted and which remain")
	}
	if dep.Message == "" || dep.FinishedAt.IsZero() {
		t.Errorf("failure has no safe message or finish time: %+v", dep)
	}
}

func TestStaleTeardownIsRequeuedNotInterrupted(t *testing.T) {
	f := deployThenQueueTeardown(t)
	operation, ctx := f.claim(t)
	if err := f.d.interrupt(context.Background(), f.dep.ID, time.Now().Add(2*f.d.cfg.Worker.StaleAfter)); err != nil {
		t.Fatal(err)
	}
	dep := f.deployment(t)
	if dep.State != cp.Queued || dep.AttemptID != "" || dep.Attempt != 2 {
		t.Fatalf("stale teardown = %s attempt %d; want queued for attempt 2", dep.State, dep.Attempt)
	}
	if err := operation.heartbeat(context.Background()); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("the stale attempt was not fenced: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("losing the fence did not cancel the stale attempt's work")
	}
	f.runTeardown(t)
	if !gone(t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID}) {
		t.Fatal("the requeued attempt did not finish the deletion")
	}
}

func TestTeardownStopsRequeueingAfterItsLastAttempt(t *testing.T) {
	f := deployThenQueueTeardown(t)
	for attempt := 1; attempt <= cp.MaxTeardownAttempts; attempt++ {
		_, _ = f.claim(t)
		if err := f.d.interrupt(context.Background(), f.dep.ID, time.Now().Add(2*f.d.cfg.Worker.StaleAfter)); err != nil {
			t.Fatal(err)
		}
	}
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Failed || dep.ErrorCode != "teardown_interrupted" || app.ActiveDeploymentID != dep.ID {
		t.Fatalf("after %d lost workers the teardown is %s %s; want failed and still holding the lock", cp.MaxTeardownAttempts, dep.State, dep.ErrorCode)
	}
}

func TestInterruptedTeardownAttemptIsRequeued(t *testing.T) {
	f := deployThenQueueTeardown(t)
	operation, _ := f.claim(t)
	if err := operation.finish(cp.Interrupted, "teardown_interrupted", "Deletion was stopped before it finished."); err != nil {
		t.Fatal(err)
	}
	if dep := f.deployment(t); dep.State != cp.Queued || dep.Attempt != 2 {
		t.Fatalf("an interrupted teardown is %s attempt %d; want requeued", dep.State, dep.Attempt)
	}
}

func TestTeardownDeletesC1ApplicationBeforeAppHubRecords(t *testing.T) {
	f := deployThenQueueTeardown(t)
	provisioner := &recordedProvisioner{}
	f.d.provisioner = provisioner
	f.runTeardown(t)
	if provisioner.deleteCalls != 1 || provisioner.appID != f.app.ID {
		t.Fatalf("external deletion calls = %d for %q, want one for %q", provisioner.deleteCalls, provisioner.appID, f.app.ID)
	}
	if !gone(t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID}) {
		t.Fatal("AppHub records survived successful external deletion")
	}
}

func TestFailedC1DeletionRetainsApplicationForRetry(t *testing.T) {
	f := deployThenQueueTeardown(t)
	f.d.provisioner = &recordedProvisioner{deleteErr: errors.New("upstream details must not escape")}
	f.runTeardown(t)
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Failed || dep.ErrorCode != "external_deletion_failed" || app.ActiveDeploymentID != dep.ID {
		t.Fatalf("failed external deletion lost the application lock: %+v %+v", dep, app)
	}
	if dep.Message == "" || dep.Message == "upstream details must not escape" {
		t.Fatalf("unsafe or missing failure message: %q", dep.Message)
	}
}

func TestTeardownRefusesEnabledC1IntegrationWithoutCredentials(t *testing.T) {
	f := deployThenQueueTeardown(t)
	enableProvisionFlag(t, f, cp.FeatureProvisionAppCatalog)
	f.runTeardown(t)
	dep := f.deployment(t)
	if dep.State != cp.Failed || dep.ErrorCode != "external_deletion_failed" {
		t.Fatalf("external deletion without credentials = %+v, want a retryable failure", dep)
	}
	if gone(t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID}) {
		t.Fatal("AppHub records were removed without checking external ownership")
	}
}
