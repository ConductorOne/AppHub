// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

// recordsTimeout bounds deleting an application's control-plane records, which
// is many small commits rather than the one a deployment's finish makes.
const recordsTimeout = 2 * time.Minute

// recordDeleteBatch keeps each commit well inside a transaction's item limit.
const recordDeleteBatch = 25

var _ deploy.TeardownObserver = (*operationStore)(nil)

// timeout reads the operation kind from the queue row to pick the job's
// deadline. The kind is immutable, so an eventually consistent row is enough.
func (d *Dispatcher) timeout(row cp.Record) time.Duration {
	if dep, err := cp.Decode[cp.DeploymentRecord](row); err == nil && dep.Operation == cp.OperationTeardown {
		return d.cfg.Worker.TeardownTimeout
	}
	return d.cfg.Worker.DeploymentTimeout
}

// teardown deletes the application's provider resources and reports the
// outcome finish should record. Deleting the records themselves is finish's
// job, because only finish holds the fence that makes it safe.
func (d *Dispatcher) teardown(ctx context.Context, s *operationStore, provider compute.Provider) (cp.DeploymentState, string, string) {
	s.mu.Lock()
	appID, artifacts := s.dep.ApplicationID, cloneArtifacts(s.prepared.Artifacts)
	s.mu.Unlock()
	err := deploy.Teardown(ctx, provider, appID, artifacts, s, deploy.TeardownOptions{})
	if ctx.Err() != nil {
		return cp.Interrupted, "teardown_interrupted", "Deletion was stopped before it finished."
	}
	if err != nil {
		var failure *deploy.TeardownError
		if errors.As(err, &failure) {
			return cp.Failed, "teardown_failed", teardownFailureMessage(failure)
		}
		return cp.Failed, "teardown_failed", "Deletion failed. Resources that were already deleted stay deleted; retry to continue."
	}
	// Do not discard the AppHub identity until its owned C1 application has
	// been removed. The flag may be disabled after provisioning, so reconcile
	// deletion whenever the integration is configured.
	if d.provisioner == nil {
		enabled, err := d.provisionFlag(ctx, cp.FeatureProvisionAppCatalog)
		if err != nil || enabled {
			return cp.Failed, "external_deletion_failed", "External application deletion could not be checked. Configure the integration and retry deletion."
		}
	} else if err := d.provisioner.DeleteApplication(ctx, appID); err != nil {
		slog.Error("external application deletion failed", "application", appID, "err", err)
		return cp.Failed, "external_deletion_failed", "Deleting the external application failed. Check the integration and retry deletion."
	}
	if ctx.Err() != nil {
		return cp.Interrupted, "teardown_interrupted", "Deletion was stopped before it finished."
	}
	if err := s.StartStep(ctx, deploy.StepDeleteRecords); err != nil {
		return cp.Interrupted, "teardown_interrupted", "Deletion progress could not be recorded."
	}
	return cp.Succeeded, "", "Application deleted."
}

// teardownFailureMessage is safe for the owner: a step and a failure class,
// never provider text.
func teardownFailureMessage(e *deploy.TeardownError) string {
	what := teardownStepNoun(e.Step)
	switch e.Class {
	case "not-permitted":
		return fmt.Sprintf("AppHub is not permitted to delete %s. An operator must grant the platform access, then retry.", what)
	case "not-owned":
		return fmt.Sprintf("AppHub does not manage %s, so it was not deleted. An operator must remove it, then retry.", what)
	case "timeout", "transient":
		return fmt.Sprintf("Deleting %s did not finish in time. Retrying continues where it stopped.", what)
	default:
		return fmt.Sprintf("Deleting %s failed. Resources already deleted stay deleted; retrying continues where it stopped.", what)
	}
}

func teardownStepNoun(step deploy.TeardownStep) string {
	switch step {
	case deploy.StepDeleteWorkload:
		return "the running workload"
	case deploy.StepDeleteDatabase:
		return "the database"
	case deploy.StepDeleteKeyValue:
		return "the key-value table"
	case deploy.StepDeleteBucket:
		return "the bucket"
	case deploy.StepDeleteSecrets:
		return "the secrets"
	case deploy.StepDeleteIdentity:
		return "the workload identity"
	case deploy.StepDeleteImageRepository:
		return "the image repository"
	case deploy.StepDeleteRecords:
		return "the application's records"
	default:
		return "the application"
	}
}

// requeueTeardown returns a teardown whose attempt stopped to the queue, or
// fails it once it has used every attempt. Either way the application keeps
// its lock on this operation, so nothing else can start in between.
func requeueTeardown(dep *cp.DeploymentRecord, now time.Time, cause string) {
	dep.Attempt = max(1, dep.Attempt)
	if dep.Attempt >= cp.MaxTeardownAttempts {
		dep.State, dep.ErrorCode = cp.Failed, "teardown_interrupted"
		dep.Message = fmt.Sprintf("%s Deletion stopped after %d attempts; retry it once the worker is healthy.", cause, dep.Attempt)
		dep.FinishedAt = now
		dep.HeartbeatAt = now
		return
	}
	dep.Attempt++
	dep.State, dep.AttemptID, dep.ErrorCode = cp.Queued, "", ""
	dep.Message = cause + " Retrying automatically."
	dep.HeartbeatAt = now
}

// StartStep implements [deploy.TeardownObserver].
func (s *operationStore) StartStep(ctx context.Context, step deploy.TeardownStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return cp.ErrUnavailable
	}
	s.dep.Step = string(step)
	s.dep.StepStartedAt = time.Now().UTC()
	s.dep.Message = "Deleting " + teardownStepNoun(step) + "."
	s.report(ctx, teardownPercentage(s.dep.PlannedSteps, step), "")
	return s.write(ctx, false)
}

// CompleteStep implements [deploy.TeardownObserver].
func (s *operationStore) CompleteStep(ctx context.Context, _ deploy.TeardownStep, remaining deploy.Artifacts) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prepared.Artifacts = cloneArtifacts(remaining)
	s.dep.Artifacts = cloneArtifacts(remaining)
	s.app.Application.Artifacts = cloneArtifacts(remaining)
	if s.uncertain {
		return cp.ErrUnavailable
	}
	return s.write(ctx, true)
}

func teardownPercentage(plan []string, step deploy.TeardownStep) int {
	for i, planned := range plan {
		if planned == string(step) {
			return i * 100 / len(plan)
		}
	}
	return 0
}

// finishTeardown records a teardown's outcome. Its caller, finish, has already
// strongly reread both rows and checked this attempt still holds them.
//
// A failed teardown keeps the application's lock, unlike a failed deployment:
// the application is part-deleted and must not be deployed or edited, and the
// lock is what every write path already checks.
func (s *operationStore) finishTeardown(ctx context.Context, dr cp.Record, dep cp.DeploymentRecord, ar cp.Record, app cp.ApplicationRecord, state cp.DeploymentState, code, message string) error {
	now := time.Now().UTC()
	dep.SealedSecrets = nil
	dep.Artifacts = cloneArtifacts(s.prepared.Artifacts)
	dep.Step, dep.StepStartedAt = s.dep.Step, s.dep.StepStartedAt
	dep.Progress = fmt.Sprintf("%d%%", s.percentage.Load())
	dep.HeartbeatAt = now
	app.Application.Artifacts = cloneArtifacts(dep.Artifacts)
	app.UpdatedAt = now
	switch state {
	case cp.Succeeded:
		return s.deleteApplicationRecords(dr, ar, app)
	case cp.Interrupted:
		requeueTeardown(&dep, now, message)
	default:
		dep.State, dep.ErrorCode, dep.Message = state, code, message
		dep.FinishedAt = now
	}
	dm, err := recordMutation(dr, dep)
	if err != nil {
		return s.stop(err)
	}
	am, err := recordMutation(ar, app)
	if err != nil {
		return s.stop(err)
	}
	if err := s.repo.Commit(ctx, []cp.Mutation{dm, am}); err != nil {
		return s.stop(err)
	}
	s.dep, s.app, s.depRow, s.appRow = dep, app, dm.Record, am.Record
	s.finished = true
	return nil
}

// deleteApplicationRecords removes everything the control plane holds for a
// deleted application. Deployment history goes first, in batches; the
// application, this teardown, its owner index entries, hostname reservations
// and usage go last
// in one commit fenced on the rows finish verified. If this stops part way the
// teardown is still running and holding the application, so the reaper
// requeues it and the next attempt deletes what is left.
//
// Idempotency results are not deleted. They are filed under the principal
// that made each request and cannot be enumerated by application; a replay of
// one resolves to an application that no longer exists and returns 404.
func (s *operationStore) deleteApplicationRecords(dr, ar cp.Record, app cp.ApplicationRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), recordsTimeout)
	defer cancel()
	if err := s.deleteHistory(ctx, app.ID, dr.ID); err != nil {
		return s.stop(err)
	}
	final := []cp.Mutation{
		{Record: ar, ExpectedVersion: ar.Version, Delete: true},
		{Record: dr, ExpectedVersion: dr.Version, Delete: true},
	}
	hostnames := append([]string{cp.EffectiveHostname(app.ID, app.Input)}, app.ReservedHostnames...)
	seen := map[string]bool{"": true}
	for _, hostname := range hostnames {
		if seen[hostname] {
			continue
		}
		seen[hostname] = true
		row, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: hostname})
		if errors.Is(err, cp.ErrNotFound) {
			continue
		}
		if err != nil {
			return s.stop(err)
		}
		reservation, err := cp.Decode[cp.HostnameReservation](row)
		if err != nil {
			return s.stop(err)
		}
		if reservation.ApplicationID == app.ID {
			final = append(final, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
		}
	}
	for _, owner := range app.Owners {
		row, err := s.repo.Read(ctx, cp.OwnerRecordID(app.ID, owner))
		if errors.Is(err, cp.ErrNotFound) {
			continue
		}
		if err != nil {
			return s.stop(err)
		}
		final = append(final, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
	}
	usage, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.ApplicationUsageKind, ID: app.ID})
	switch {
	case err == nil:
		final = append(final, cp.Mutation{Record: usage, ExpectedVersion: usage.Version, Delete: true})
	case !errors.Is(err, cp.ErrNotFound):
		return s.stop(err)
	}
	if err := s.repo.Commit(ctx, final); err != nil {
		return s.stop(err)
	}
	s.finished = true
	return nil
}

// deleteHistory deletes every deployment of appID except the running teardown.
// Each row is reread strongly before deletion, because a queue page can lag
// and a delete must match the current version.
func (s *operationStore) deleteHistory(ctx context.Context, appID, keep string) error {
	cursor := ""
	for {
		page, err := s.repo.Query(ctx, cp.Query{Kind: cp.DeploymentKind, ApplicationID: appID, Limit: 100, Cursor: cursor})
		if err != nil {
			return err
		}
		var batch []cp.Mutation
		for _, listed := range page.Records {
			if listed.ID == keep {
				continue
			}
			row, err := s.repo.Read(ctx, listed.RecordID)
			if errors.Is(err, cp.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			batch = append(batch, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
			if len(batch) == recordDeleteBatch {
				if err := s.repo.Commit(ctx, batch); err != nil {
					return err
				}
				batch = nil
			}
		}
		if len(batch) > 0 {
			if err := s.repo.Commit(ctx, batch); err != nil {
				return err
			}
		}
		if page.Cursor == "" {
			return nil
		}
		cursor = page.Cursor
	}
}
