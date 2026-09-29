// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/modules/deploy"
)

// DeleteApplication accepts deletion of an application and everything it owns.
//
// # What it does not do
//
// It deletes no cloud resource itself. It queues a teardown operation the
// worker runs under the same lease, heartbeat and fence a deployment has, and
// returns where to watch it. The one exception is an application that was never
// deployed: it owns nothing outside the control plane, so its records are
// deleted here and the result is nil.
//
// # How it interacts with other operations
//
// A running deployment is refused, because its outcome decides what there is
// to delete. A queued one is cancelled in the same commit, and an interrupted
// one is superseded: its lock was only waiting for an operator to say the old
// worker stopped, and a teardown deletes whatever that worker left. A queued or
// running teardown is returned as-is, so a second click is not an error. A
// failed teardown is replaced by a new one, which is how deletion is retried.
func (s *Service) DeleteApplication(ctx context.Context, p Principal, appID string, input DeleteApplicationInput, key string) (*DeploymentAccepted, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return nil, err
	}
	app, r, err := s.application(ctx, p, appID)
	if err != nil {
		return nil, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return nil, err
	}
	const operation = "applications.delete"
	idemID, err := idempotencyID(p, operation, key)
	if err != nil {
		return nil, err
	}
	hash, err := requestHash(struct {
		ApplicationID string                 `json:"applicationId"`
		Input         DeleteApplicationInput `json:"input"`
	}{appID, input})
	if err != nil {
		return nil, err
	}
	if result, found, err := s.idempotency(ctx, idemID, operation, hash); err != nil {
		return nil, err
	} else if found {
		accepted, err := s.replayedDeployment(ctx, appID, result)
		return &accepted, err
	}
	if input.ConfirmName != app.Input.Name {
		return nil, &Error{Status: 422, Code: "confirmation_mismatch", Message: "Type the application's name exactly to confirm deletion.", FieldErrors: map[string]string{"confirmName": "Does not match the application's name."}}
	}
	if app.LatestDeploymentID == "" && app.ActiveDeploymentID == "" {
		return nil, s.deleteDraft(auditPrincipal(ctx, p, "application.delete", "application:"+appID), app, r)
	}
	var superseded []Mutation
	if app.ActiveDeploymentID != "" {
		active, activeRecord, err := s.deployment(ctx, app.ActiveDeploymentID)
		if err != nil {
			return nil, err
		}
		if active.Operation == OperationTeardown && !active.State.Terminal() {
			accepted := accepted(active)
			return &accepted, nil
		}
		if superseded, err = supersede(p, active, activeRecord); err != nil {
			return nil, err
		}
	}
	capabilities := s.targetCapabilities(ctx, app.TargetID)
	result, err := s.enqueue(ctx, p, app, r, enqueueRequest{idemID: idemID, operation: operation, hash: hash, revision: app.Revision, extra: superseded, prepare: func(d *DeploymentRecord, app *ApplicationRecord) error {
		prepareTeardown(capabilities, p, d, app)
		return nil
	}})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// supersede ends the operation holding the application's lock so a teardown
// can take it, or refuses when that operation is still running.
func supersede(p Principal, active DeploymentRecord, r Record) ([]Mutation, error) {
	now := time.Now().UTC()
	switch {
	case active.Operation == OperationTeardown:
		// A stopped teardown needs nothing written: the new one replaces it as
		// the application's lock, and it stays in the history until deleted.
		return nil, nil
	case active.State == Running:
		return nil, Problem(409, "deployment_running", "A deployment is running. Delete the application once it finishes.")
	case active.State == Queued:
		active.State, active.ErrorCode = Failed, "cancelled_by_deletion"
		active.Message = "Cancelled because the application is being deleted."
		active.SealedSecrets = nil
		active.FinishedAt = now
	case active.State == Interrupted:
		active.ResolutionReason = "Superseded by deletion of the application."
		active.ResolvedBy, active.ResolvedAt = p.UserID, now
		active.SealedSecrets = nil
	default:
		return nil, unavailable()
	}
	m, err := mutation(r.RecordID, r.Version, active)
	if err != nil {
		return nil, err
	}
	return []Mutation{m}, nil
}

// targetCapabilities is the worker's last advertised capability set. It only
// shapes the previewed plan; the worker replans from its provider when it
// claims the teardown, so a missing descriptor costs nothing but the preview.
func (s *Service) targetCapabilities(ctx context.Context, targetID string) compute.CapabilitySet {
	t, ok := s.targets[targetID]
	if !ok {
		return compute.CapabilitySet{}
	}
	d, _, err := s.descriptor(ctx, t)
	if err != nil {
		return compute.CapabilitySet{}
	}
	return d.Capabilities
}

// prepareTeardown turns the deployment record enqueue built into a teardown
// and marks the application as being deleted.
func prepareTeardown(capabilities compute.CapabilitySet, p Principal, d *DeploymentRecord, app *ApplicationRecord) {
	d.Operation = OperationTeardown
	d.Attempt = 1
	d.Message = "Deletion queued."
	d.SealedSecrets = nil
	d.PlannedSteps = PlannedTeardown(capabilities, app.Application.Artifacts)
	if app.DeletionRequestedAt.IsZero() {
		app.DeletionRequestedAt = time.Now().UTC()
		app.DeletionRequestedBy = p.UserID
	}
}

// PlannedTeardown is the stored form of [deploy.TeardownPlan].
func PlannedTeardown(capabilities compute.CapabilitySet, a deploy.Artifacts) []string {
	var steps []string
	for _, step := range deploy.TeardownPlan(capabilities, a) {
		steps = append(steps, string(step))
	}
	return steps
}

// deleteDraft deletes an application that never had a deployment. With no
// deployment there is no provider resource: only the application, its owner
// index entries, and the hostname its specification reserved.
func (s *Service) deleteDraft(ctx context.Context, app ApplicationRecord, r Record) error {
	mutations := []Mutation{{Record: r, ExpectedVersion: r.Version, Delete: true}}
	hostnames := append([]string{EffectiveHostname(app.ID, app.Input)}, app.ReservedHostnames...)
	seen := map[string]bool{"": true}
	for _, hostname := range hostnames {
		if seen[hostname] {
			continue
		}
		seen[hostname] = true
		row, err := s.repo.Read(ctx, RecordID{Kind: HostnameKind, ParentID: app.TargetID, ID: hostname})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return unavailable()
		}
		reservation, err := Decode[HostnameReservation](row)
		if err != nil {
			return unavailable()
		}
		if reservation.ApplicationID == app.ID {
			mutations = append(mutations, Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
		}
	}
	for _, owner := range app.Owners {
		row, err := s.repo.Read(ctx, OwnerRecordID(app.ID, owner))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return unavailable()
		}
		mutations = append(mutations, Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
	}
	if err := s.repo.Commit(ctx, mutations); err != nil {
		if errors.Is(err, ErrConflict) {
			return Problem(409, "conflict", "The application changed concurrently. Reload before trying again.")
		}
		return unavailable()
	}
	return nil
}

// deletionStatus is deleting while a teardown is queued or running and
// deletion_failed once it has stopped, whether it failed or was interrupted.
func (s *Service) deletionStatus(ctx context.Context, app ApplicationRecord) string {
	if app.ActiveDeploymentID == "" {
		return "deletion_failed"
	}
	d, _, err := s.deployment(ctx, app.ActiveDeploymentID)
	if err != nil || d.Operation != OperationTeardown || d.State.Terminal() {
		return "deletion_failed"
	}
	return "deleting"
}

// deletable reports whether an application in this status may be deleted now.
func deletable(status string) bool {
	return status != "deploying" && status != "deleting"
}

// safeTeardownStep passes only the steps the teardown can record.
func safeTeardownStep(step string) string {
	switch deploy.TeardownStep(step) {
	case deploy.StepDeleteWorkload, deploy.StepDeleteDatabase, deploy.StepDeleteKeyValue, deploy.StepDeleteBucket, deploy.StepDeleteSecrets, deploy.StepDeleteIdentity, deploy.StepDeleteImageRepository, deploy.StepDeleteRecords:
		return step
	}
	return ""
}

// teardownView fills a teardown's view. Its message and error code are the
// worker's own fixed text (internal/worker/teardown.go), never provider output,
// so unlike a deployment's they are passed through.
func teardownView(d DeploymentRecord, v *DeploymentView) {
	v.Operation = string(OperationTeardown)
	v.Step = safeTeardownStep(d.Step)
	v.Progress = d.Progress
	v.StepStartedAt = d.StepStartedAt
	v.ErrorCode, v.Message = d.ErrorCode, d.Message
	for _, step := range d.PlannedSteps {
		if safeTeardownStep(step) != "" {
			v.PlannedSteps = append(v.PlannedSteps, step)
		}
	}
	if !d.State.Terminal() {
		v.PollAfterMs = 2000
	}
	if v.Message == "" {
		v.Message = "Deleting the application."
	}
}
