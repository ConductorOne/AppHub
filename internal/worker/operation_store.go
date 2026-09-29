// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

const persistenceTimeout = 5 * time.Second

// operationStore is bound to one immutable revision and one worker attempt.
// Its mutex serializes checkpoints, heartbeats and terminal writes so they
// cannot invalidate one another's CAS versions. No provider runs under the lock.
type operationStore struct {
	mu         sync.Mutex
	repo       cp.Repository
	app        cp.ApplicationRecord
	dep        cp.DeploymentRecord
	appRow     cp.Record
	depRow     cp.Record
	prepared   deploy.Application
	opener     SecretOpener
	cancel     context.CancelFunc
	fenced     bool
	uncertain  bool
	finished   bool
	percentage atomic.Int32
}

var _ deploy.Store = (*operationStore)(nil)

func recordMutation(row cp.Record, value any) (cp.Mutation, error) {
	record, err := cp.Encode(row.RecordID, row.Version+1, value)
	if err != nil {
		return cp.Mutation{}, err
	}
	if len(record.Value) > 128<<10 {
		return cp.Mutation{}, errors.New("deployment checkpoint exceeds document limit")
	}
	return cp.Mutation{Record: record, ExpectedVersion: row.Version}, nil
}

func cloneArtifacts(a deploy.Artifacts) deploy.Artifacts {
	a.Secrets = maps.Clone(a.Secrets)
	a.Addresses = slices.Clone(a.Addresses)
	return a
}

func newOperationStore(repo cp.Repository, app cp.ApplicationRecord, appRow cp.Record, dep cp.DeploymentRecord, depRow cp.Record, cancel context.CancelFunc) (*operationStore, error) {
	// The module receives a separate mutable copy, never the historical request.
	raw, err := json.Marshal(dep.Application)
	if err != nil {
		return nil, err
	}
	var prepared deploy.Application
	if err := json.Unmarshal(raw, &prepared); err != nil {
		return nil, err
	}
	prepared.Artifacts = cloneArtifacts(dep.Artifacts)
	return &operationStore{repo: repo, app: app, dep: dep, appRow: appRow, depRow: depRow, prepared: prepared, cancel: cancel}, nil
}

func (s *operationStore) GetApplication(ctx context.Context, id string) (*deploy.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id != s.dep.ApplicationID {
		return nil, cp.ErrNotFound
	}
	if s.fenced || s.finished || s.uncertain {
		return nil, cp.ErrConflict
	}
	raw, err := json.Marshal(s.prepared)
	if err != nil {
		return nil, err
	}
	var app deploy.Application
	if err := json.Unmarshal(raw, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// report deliberately discards text: provider callbacks can include raw errors.
// A single atomic integer is a bounded, nonblocking, coalescing progress slot.
func (s *operationStore) report(_ context.Context, percentage int, _ string) {
	percentage = min(99, max(0, percentage))
	for old := s.percentage.Load(); int32(percentage) > old; old = s.percentage.Load() {
		if s.percentage.CompareAndSwap(old, int32(percentage)) {
			break
		}
	}
}

func (s *operationStore) stop(err error) error {
	s.uncertain = true
	if errors.Is(err, cp.ErrConflict) {
		s.fenced = true
	}
	s.cancel()
	return err
}

func (s *operationStore) write(ctx context.Context, application bool) error {
	if s.fenced || s.finished {
		return cp.ErrConflict
	}
	s.dep.Progress = fmt.Sprintf("%d%%", s.percentage.Load())
	s.dep.HeartbeatAt = time.Now().UTC()
	dm, err := recordMutation(s.depRow, s.dep)
	if err != nil {
		return s.stop(err)
	}
	mutations := []cp.Mutation{dm}
	var am cp.Mutation
	if application {
		s.app.UpdatedAt = s.dep.HeartbeatAt
		am, err = recordMutation(s.appRow, s.app)
		if err != nil {
			return s.stop(err)
		}
		mutations = append(mutations, am)
	}
	bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
	defer cancel()
	if err := s.repo.Commit(bounded, mutations); err != nil {
		return s.stop(err)
	}
	s.depRow = dm.Record
	if application {
		s.appRow = am.Record
	}
	return nil
}

func (s *operationStore) SaveApplication(ctx context.Context, app *deploy.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if app == nil || app.ID != s.dep.ApplicationID {
		return cp.ErrNotFound
	}
	if s.fenced || s.finished {
		return cp.ErrConflict
	}
	// Retain returned partial artifacts even if this save's context expired. The
	// independent terminal write can record them without repeating a cloud call.
	s.prepared.Artifacts = cloneArtifacts(app.Artifacts)
	s.prepared.DeployStep = app.DeployStep
	s.prepared.FailedStep = app.FailedStep
	s.prepared.FailureClass = app.FailureClass
	s.dep.Artifacts = cloneArtifacts(app.Artifacts)
	s.dep.Step = app.DeployStep
	s.app.Application.Artifacts = cloneArtifacts(app.Artifacts)
	s.app.Application.DeployStep = app.DeployStep
	s.app.Application.FailedStep = app.FailedStep
	s.app.Application.FailureClass = app.FailureClass
	// A module's successful checkpoint is not a durable operation success yet.
	s.app.Application.Status = deploy.StatusDeploying
	if s.uncertain {
		return cp.ErrUnavailable
	}
	return s.write(ctx, true)
}

func (s *operationStore) heartbeat(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return cp.ErrUnavailable
	}
	return s.write(cp.WithAuditContext(ctx, "system", "deployment.heartbeat", "deployment:"+s.dep.ID), true)
}

func (s *operationStore) prepare(ctx context.Context, commit string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return cp.ErrUnavailable
	}
	s.dep.ResolvedCommit = commit
	s.dep.Step = "source-prepared"
	s.prepared.Source.Ref = commit
	return s.write(ctx, true)
}

// finish reconciles a potentially ambiguous persistence response by strongly
// rereading both aggregates. Only the same still-running attempt may finish.
// If an interruption/operator resolution won the CAS, this worker is fenced.
func (s *operationStore) finish(state cp.DeploymentState, code, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced || s.finished {
		return cp.ErrConflict
	}
	ctx, cancel := context.WithTimeout(context.Background(), persistenceTimeout)
	defer cancel()
	dr, err := s.repo.Read(ctx, s.depRow.RecordID)
	if err != nil {
		return s.stop(err)
	}
	dep, err := cp.Decode[cp.DeploymentRecord](dr)
	if err != nil {
		return s.stop(err)
	}
	ar, err := s.repo.Read(ctx, s.appRow.RecordID)
	if err != nil {
		return s.stop(err)
	}
	app, err := cp.Decode[cp.ApplicationRecord](ar)
	if err != nil {
		return s.stop(err)
	}
	if dep.State != cp.Running || dep.AttemptID != s.dep.AttemptID || app.ActiveDeploymentID != dep.ID || app.Revision != dep.ApplicationRevision {
		return s.stop(cp.ErrConflict)
	}
	if s.uncertain {
		state, code, message = cp.Interrupted, "deployment_interrupted", "Deployment outcome is uncertain. An operator must stop the old worker and resolve this operation."
	}
	if dep.Operation == cp.OperationTeardown {
		if s.uncertain {
			message = "Deletion progress could not be recorded."
		}
		return s.finishTeardown(ctx, dr, dep, ar, app, state, code, message)
	}
	// Never rewrite dep.Application, requested ref, identity, ownership or inputs.
	// Sealed values are the exception: they exist only to reach this attempt.
	dep.SealedSecrets = nil
	dep.Artifacts = cloneArtifacts(s.prepared.Artifacts)
	dep.Step = s.dep.Step
	dep.ResolvedCommit = s.dep.ResolvedCommit
	dep.State, dep.ErrorCode, dep.Message = state, code, message
	dep.FinishedAt = time.Now().UTC()
	dep.HeartbeatAt = dep.FinishedAt
	dep.Progress = fmt.Sprintf("%d%%", s.percentage.Load())
	app.Application.Artifacts = cloneArtifacts(dep.Artifacts)
	app.Application.DeployStep = dep.Step
	app.Application.FailedStep = s.prepared.FailedStep
	app.Application.FailureClass = s.prepared.FailureClass
	app.Application.Status = deploy.StatusFailed
	app.UpdatedAt = dep.FinishedAt
	if state != cp.Interrupted {
		app.ActiveDeploymentID = ""
	}
	var releases []cp.Mutation
	if state == cp.Succeeded {
		dep.Progress = "100%"
		dep.Addresses = slices.Clone(dep.Artifacts.Addresses)
		app.Application.Status = deploy.StatusRunning
		app.Application.LastDeployedAt = dep.FinishedAt
		app.Application.FailedStep, app.Application.FailureClass = "", ""
		app.LastSuccessfulDeploymentID = dep.ID
		app.LastSuccessfulArtifacts = cloneArtifacts(dep.Artifacts)
		app.LastDeployedAt = dep.FinishedAt
		app.Addresses = slices.Clone(dep.Addresses)
		// EnsureService (or retirement before a mode switch) has now reconciled
		// the old ingress. Release obsolete reservations atomically with success.
		current := cp.EffectiveHostname(app.ID, app.Input)
		for _, hostname := range app.ReservedHostnames {
			if hostname == current {
				continue
			}
			row, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.HostnameKind, ParentID: app.TargetID, ID: hostname})
			if err != nil {
				return s.stop(err)
			}
			reservation, err := cp.Decode[cp.HostnameReservation](row)
			if err != nil {
				return s.stop(err)
			}
			if reservation.ApplicationID != app.ID {
				return s.stop(cp.ErrConflict)
			}
			releases = append(releases, cp.Mutation{Record: row, ExpectedVersion: row.Version, Delete: true})
		}
		app.ReservedHostnames = nil
		if current != "" {
			app.ReservedHostnames = []string{current}
		}
	}
	dm, err := recordMutation(dr, dep)
	if err != nil {
		return s.stop(err)
	}
	am, err := recordMutation(ar, app)
	if err != nil {
		return s.stop(err)
	}
	if err := s.repo.Commit(ctx, append([]cp.Mutation{dm, am}, releases...)); err != nil {
		return s.stop(err)
	}
	s.dep, s.app, s.depRow, s.appRow = dep, app, dm.Record, am.Record
	s.finished = true
	return nil
}
