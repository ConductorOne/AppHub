// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"slices"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func (f *serviceFixture) remove(t *testing.T, app cp.ApplicationView, key string) *cp.DeploymentAccepted {
	t.Helper()
	result, err := f.service.DeleteApplication(t.Context(), f.owner, app.ID, cp.DeleteApplicationInput{ConfirmName: app.Specification.Name}, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *serviceFixture) setState(t *testing.T, id string, state cp.DeploymentState) {
	t.Helper()
	d := loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: id})
	d.State = state
	storeValue(t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ParentID: d.ApplicationID, ID: id}, d)
}

// settle ends the application's active deployment as a worker would.
func (f *serviceFixture) settle(t *testing.T, appID string, state cp.DeploymentState) {
	t.Helper()
	appRecord := cp.RecordID{Kind: cp.ApplicationKind, ID: appID}
	app := loadValue[cp.ApplicationRecord](t, f.repo, appRecord)
	f.setState(t, app.ActiveDeploymentID, state)
	if state != cp.Interrupted {
		app.ActiveDeploymentID = ""
		storeValue(t, f.repo, appRecord, app)
	}
}

func TestDeletingANeverDeployedDraftIsImmediate(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	if result := f.remove(t, app, "delete"); result != nil {
		t.Fatalf("a draft deletion queued a teardown: %+v", result)
	}
	_, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	requireProblem(t, err, 404, "not_found")
	if n := countKind(f.repo, cp.HostnameKind); n != 0 {
		t.Errorf("%d hostname reservations survived the draft", n)
	}
}

func TestDeletionRequiresTheExactName(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	_, err := f.service.DeleteApplication(t.Context(), f.owner, app.ID, cp.DeleteApplicationInput{ConfirmName: "example"}, "delete")
	requireProblem(t, err, 422, "confirmation_mismatch")
	if _, err := f.service.GetApplication(t.Context(), f.owner, app.ID); err != nil {
		t.Fatalf("a mismatched confirmation deleted the application: %v", err)
	}
}

func TestOnlyTheOwnerOrAnAdminCanDelete(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	_, err := f.service.DeleteApplication(t.Context(), f.other, app.ID, cp.DeleteApplicationInput{ConfirmName: app.Specification.Name}, "delete")
	requireProblem(t, err, 404, "not_found")
	if _, err := f.service.DeleteApplication(t.Context(), f.admin, app.ID, cp.DeleteApplicationInput{ConfirmName: app.Specification.Name}, "delete"); err != nil {
		t.Fatalf("an administrator could not delete: %v", err)
	}
}

func TestDeletionQueuesATeardownAndLocksTheApplication(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	f.submit(t, app, "submit")
	f.settle(t, app.ID, cp.Succeeded)

	accepted := f.remove(t, app, "delete")
	if accepted == nil || accepted.State != cp.Queued {
		t.Fatalf("deletion was not queued: %+v", accepted)
	}
	view, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "deleting" || view.DeletionRequestedAt == nil || view.ActiveDeploymentID != accepted.DeploymentID {
		t.Fatalf("application after deletion = %s, active %q", view.Status, view.ActiveDeploymentID)
	}
	for _, action := range []string{"applications:write", "deployments:write", "applications:delete"} {
		if slices.Contains(view.PermittedActions, action) {
			t.Errorf("a deleting application still permits %s", action)
		}
	}
	teardown, err := f.service.GetDeployment(t.Context(), f.owner, accepted.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if teardown.Operation != "teardown" || teardown.Attempt != 1 || len(teardown.PlannedSteps) == 0 || teardown.PlannedSteps[len(teardown.PlannedSteps)-1] != "delete-records" {
		t.Fatalf("teardown view = %+v", teardown)
	}

	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, f.input, view.Revision)
	requireProblem(t, err, 409, "application_deleting")
	_, err = f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: view.Revision}, "again")
	requireProblem(t, err, 409, "application_deleting")

	again := f.remove(t, app, "second-click")
	if again == nil || again.DeploymentID != accepted.DeploymentID {
		t.Fatalf("a second request while deleting started another teardown: %+v", again)
	}
}

func TestDeletionWaitsForARunningDeployment(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	job := f.submit(t, app, "submit")
	f.setState(t, job.DeploymentID, cp.Running)
	_, err := f.service.DeleteApplication(t.Context(), f.owner, app.ID, cp.DeleteApplicationInput{ConfirmName: app.Specification.Name}, "delete")
	requireProblem(t, err, 409, "deployment_running")
}

func TestDeletionCancelsAQueuedDeployment(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	job := f.submit(t, app, "submit")
	f.remove(t, app, "delete")
	cancelled := loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: job.DeploymentID})
	if cancelled.State != cp.Failed || cancelled.ErrorCode != "cancelled_by_deletion" {
		t.Fatalf("queued deployment = %s %s; want cancelled", cancelled.State, cancelled.ErrorCode)
	}
}

func TestDeletionSupersedesAnInterruptedDeployment(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	job := f.submit(t, app, "submit")
	f.settle(t, app.ID, cp.Interrupted)
	if f.remove(t, app, "delete") == nil {
		t.Fatal("deletion of an interrupted application was not queued")
	}
	superseded := loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: job.DeploymentID})
	if superseded.ResolvedAt.IsZero() || superseded.ResolvedBy != f.owner.UserID {
		t.Fatal("the interrupted deployment was not marked resolved by the deletion")
	}
}

func TestAFailedTeardownCanBeRetried(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	f.submit(t, app, "submit")
	f.settle(t, app.ID, cp.Succeeded)
	first := f.remove(t, app, "delete")
	// A failed teardown keeps the application's lock, as the worker leaves it.
	f.setState(t, first.DeploymentID, cp.Failed)

	view, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "deletion_failed" || !slices.Contains(view.PermittedActions, "applications:delete") {
		t.Fatalf("after a failed teardown: status %s, actions %v", view.Status, view.PermittedActions)
	}
	if replay := f.remove(t, app, "delete"); replay.DeploymentID != first.DeploymentID {
		t.Fatal("replaying the original key did not return the original teardown")
	}
	retry := f.remove(t, app, "retry")
	if retry == nil || retry.DeploymentID == first.DeploymentID || retry.State != cp.Queued {
		t.Fatalf("retry did not queue a new teardown: %+v", retry)
	}
	view, err = f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "deleting" || view.ActiveDeploymentID != retry.DeploymentID {
		t.Fatalf("after retry: status %s, active %s", view.Status, view.ActiveDeploymentID)
	}
}
