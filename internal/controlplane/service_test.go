// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
)

type liveEligibility struct {
	mu         sync.Mutex
	principals map[string]cp.Principal
	failure    error
	// roles resolves ResolveRole by email, for the tests that exercise it
	// (see ListMembers); every other test leaves it nil and gets the same
	// RoleMember default an unmapped directory entitlement resolves to.
	roles map[string]cp.Principal
}

func (e *liveEligibility) CheckPrincipal(_ context.Context, p cp.Principal) (cp.Principal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failure != nil {
		return cp.Principal{}, e.failure
	}
	current, ok := e.principals[p.UserID]
	if !ok {
		return cp.Principal{}, cp.Problem(401, "disabled", "disabled")
	}
	return current, nil
}
func (e *liveEligibility) remove(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.principals, id)
}
func (e *liveEligibility) ResolveRole(_ context.Context, email string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.roles[email]; ok {
		return p.Role, p.VulnAdmin
	}
	return cp.RoleMember, false
}

type serviceFixture struct {
	repo                *testutil.Repository
	service             *cp.Service
	eligibility         *liveEligibility
	owner, other, admin cp.Principal
	input               cp.ApplicationInput
	target              cp.TargetPolicy
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	owner := cp.Principal{UserID: "owner", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "owner-subject"}
	other := cp.Principal{UserID: "other", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "other-subject"}
	admin := cp.Principal{UserID: "admin", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "admin-subject", Admin: true}
	eligibility := &liveEligibility{principals: map[string]cp.Principal{owner.UserID: owner, other.UserID: other, admin.UserID: admin}}
	target := cp.TargetPolicy{ID: "org", Label: "Organization", ConfigHash: "policy-hash", DeployConfig: deploy.Config{ResourcePrefix: "test", AllowedSourceHosts: []string{"github.com"}, RouteDomain: "apps.example", RouteCertificate: "operator-certificate"}, ResourceSizes: []cp.ResourceInput{{CPU: 500, Memory: 1024}}, MaxReplicas: 4, ExecutionModes: []string{"service", "scheduled"}, PublicExposure: true, Repositories: []string{"https://github.com/example/app"}}
	repo := testutil.NewRepository()
	service, err := cp.NewService(repo, eligibility, map[string]cp.TargetPolicy{target.ID: target})
	if err != nil {
		t.Fatal(err)
	}
	f := &serviceFixture{repo: repo, service: service, eligibility: eligibility, owner: owner, other: other, admin: admin, target: target, input: cp.ApplicationInput{Name: "Example", TargetID: "org", Source: cp.SourceInput{URL: "https://github.com/example/app", Ref: "main", Dockerfile: "Dockerfile"}, Execution: deploy.ExecutionService, Port: 8080, Resources: cp.ResourceInput{CPU: 500, Memory: 1024}, Replicas: 2, Exposure: cp.ExposureInput{Mode: "private"}}}
	f.setDescriptor(t, time.Now().UTC(), target.ConfigHash, compute.NewCapabilitySet(compute.CapImageBuild, compute.CapImageRegistry, compute.CapContainerService, compute.CapScheduledJob, compute.CapPlatformIngress, compute.CapIngressAuth))
	return f
}
func storeValue(t *testing.T, repo cp.Repository, id cp.RecordID, value any) {
	t.Helper()
	previous, err := repo.Read(t.Context(), id)
	if err != nil && !errors.Is(err, cp.ErrNotFound) {
		t.Fatal(err)
	}
	record, err := cp.Encode(id, previous.Version+1, value)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(t.Context(), []cp.Mutation{{Record: record, ExpectedVersion: previous.Version}}); err != nil {
		t.Fatal(err)
	}
}
func loadValue[T any](t *testing.T, repo cp.Repository, id cp.RecordID) T {
	t.Helper()
	record, err := repo.Read(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cp.Decode[T](record)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func (f *serviceFixture) setDescriptor(t *testing.T, heartbeat time.Time, hash string, caps compute.CapabilitySet) {
	t.Helper()
	storeValue(t, f.repo, cp.RecordID{Kind: cp.TargetKind, ID: f.target.ID}, cp.TargetDescriptor{ID: f.target.ID, ProviderName: "test", ConfigHash: hash, HeartbeatAt: heartbeat, Capabilities: caps})
}
func (f *serviceFixture) create(t *testing.T, key string) cp.ApplicationView {
	t.Helper()
	result, err := f.service.CreateApplication(t.Context(), f.owner, f.input, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func (f *serviceFixture) submit(t *testing.T, app cp.ApplicationView, key string) cp.DeploymentAccepted {
	t.Helper()
	result, err := f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func requireProblem(t *testing.T, err error, status int, code string) {
	t.Helper()
	var problem *cp.Error
	if !errors.As(err, &problem) || problem.Status != status || code != "" && problem.Code != code {
		t.Fatalf("got error %v; want status %d code %q", err, status, code)
	}
}
func countKind(repo *testutil.Repository, kind cp.RecordKind) int {
	n := 0
	for _, r := range repo.Snapshot() {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func TestServiceOwnershipPrecedesScopeAndWriteDoesNotRequireRead(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "create")
	job := f.submit(t, app, "submit")
	blocked := f.other
	blocked.Bearer = true
	blocked.Scopes = []string{"applications:read:extra"}
	calls := []func() error{
		func() error { _, err := f.service.GetApplication(t.Context(), blocked, app.ID); return err },
		func() error {
			_, err := f.service.UpdateApplication(t.Context(), blocked, app.ID, f.input, app.Revision)
			return err
		},
		func() error {
			_, err := f.service.SubmitDeployment(t.Context(), blocked, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, "foreign")
			return err
		},
		func() error { _, err := f.service.GetDeployment(t.Context(), blocked, job.DeploymentID); return err },
		func() error {
			_, err := f.service.ListDeployments(t.Context(), blocked, app.ID, cp.ListOptions{})
			return err
		},
		func() error {
			_, err := f.service.ResolveInterrupted(t.Context(), blocked, job.DeploymentID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "stopped"})
			return err
		},
	}
	for _, call := range calls {
		requireProblem(t, call(), 404, "not_found")
	}
	ownNoScope := f.owner
	ownNoScope.Bearer = true
	ownNoScope.Scopes = []string{"applications:read:extra"}
	_, err := f.service.GetApplication(t.Context(), ownNoScope, app.ID)
	requireProblem(t, err, 403, "insufficient_scope")
	_, err = f.service.GetDeployment(t.Context(), ownNoScope, job.DeploymentID)
	requireProblem(t, err, 403, "insufficient_scope")
	view, err := f.service.GetApplication(t.Context(), f.admin, app.ID)
	if err != nil || view.ID != app.ID {
		t.Fatalf("administrator read: %+v %v", view, err)
	}
	onlyWrite := f.owner
	onlyWrite.Bearer = true
	onlyWrite.Scopes = []string{cp.ApplicationsWrite}
	draft, err := f.service.CreateApplication(t.Context(), onlyWrite, f.input, "write-only")
	if err != nil {
		t.Fatal(err)
	}
	changed := f.input
	changed.Name = "Changed"
	updated, err := f.service.UpdateApplication(t.Context(), onlyWrite, draft.ID, changed, draft.Revision)
	if err != nil || updated.Specification.Name != "Changed" {
		t.Fatalf("write-only update: %+v %v", updated, err)
	}
	onlyWrite.Scopes = []string{cp.DeploymentsWrite}
	accepted, err := f.service.SubmitDeployment(t.Context(), onlyWrite, updated.ID, cp.SubmitDeploymentInput{ApplicationRevision: updated.Revision}, "write-deploy")
	if err != nil || accepted.DeploymentID == "" {
		t.Fatalf("write-only submission: %+v %v", accepted, err)
	}
	page, err := f.service.ListApplications(t.Context(), f.other, cp.ListOptions{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("cross-owner inventory: %+v %v", page, err)
	}
	_, err = f.service.ListApplications(t.Context(), f.other, cp.ListOptions{All: true})
	requireProblem(t, err, 403, "forbidden")
}

func TestCreateApplicationRequiresAppOwnerRole(t *testing.T) {
	f := newServiceFixture(t)
	member := cp.Principal{UserID: "member", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "member-subject", Role: cp.RoleMember}
	f.eligibility.principals[member.UserID] = member

	_, err := f.service.CreateApplication(t.Context(), member, f.input, "member-create")
	requireProblem(t, err, 403, "forbidden")

	// A member role does not block reading what they can already see.
	if _, err := f.service.ListApplications(t.Context(), member, cp.ListOptions{}); err != nil {
		t.Fatalf("member read was blocked: %v", err)
	}

	// f.owner has the zero-value Role (unset, the pre-role-mapping default
	// every identity resolves to absent a directory mapping) and may still
	// create -- the member gate must not regress an untouched deployment.
	if _, err := f.service.CreateApplication(t.Context(), f.owner, f.input, "owner-create"); err != nil {
		t.Fatalf("the default role was blocked from creating: %v", err)
	}

	// Admin creates regardless of Role, even an incidentally-set Member.
	admin := f.admin
	admin.Role = cp.RoleMember
	f.eligibility.principals[admin.UserID] = admin
	adminInput := f.input
	adminInput.Name = "Admin App"
	if _, err := f.service.CreateApplication(t.Context(), admin, adminInput, "admin-create"); err != nil {
		t.Fatalf("admin create was blocked despite Admin=true: %v", err)
	}
}

func TestServiceConcurrentIdempotencyHasOneDurableResult(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "same"}
	const clients = 16
	var wg sync.WaitGroup
	apps := make([]cp.ApplicationView, clients)
	errs := make([]error, clients)
	start := make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			apps[i], errs[i] = f.service.CreateApplication(t.Context(), f.owner, f.input, "same-create")
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil || apps[i].ID != apps[0].ID {
			t.Fatalf("create %d: %+v %v", i, apps[i], err)
		}
	}
	if countKind(f.repo, cp.ApplicationKind) != 1 || countKind(f.repo, cp.HostnameKind) != 1 {
		t.Fatal("duplicate application or reservation")
	}
	changed := f.input
	changed.Name = "Different"
	_, err := f.service.CreateApplication(t.Context(), f.owner, changed, "same-create")
	requireProblem(t, err, 409, "idempotency_conflict")
	jobs := make([]cp.DeploymentAccepted, clients)
	start = make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			jobs[i], errs[i] = f.service.SubmitDeployment(t.Context(), f.owner, apps[0].ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "same-submit")
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil || jobs[i].DeploymentID != jobs[0].DeploymentID {
			t.Fatalf("submit %d: %+v %v", i, jobs[i], err)
		}
	}
	if countKind(f.repo, cp.DeploymentKind) != 1 || countKind(f.repo, cp.IdempotencyKind) != 2 {
		t.Fatal("duplicate durable deployment/idempotency intent")
	}
	d := loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: jobs[0].DeploymentID})
	if d.State != cp.Queued || d.RequesterUserID != f.owner.UserID || d.Requester.Subject != f.owner.Subject || d.Application.Source.Ref != "main" || d.ApplicationRevision != 1 {
		t.Fatalf("immutable requester/snapshot missing: %+v", d)
	}
	current := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: apps[0].ID})
	if current.ActiveDeploymentID != d.ID || current.LatestDeploymentID != d.ID {
		t.Fatal("accepted deployment lacks application lock/latest pointer")
	}
	_, err = f.service.SubmitDeployment(t.Context(), f.owner, apps[0].ID, cp.SubmitDeploymentInput{ApplicationRevision: 2}, "same-submit")
	requireProblem(t, err, 409, "idempotency_conflict")
	// Replays remain usable during worker outages, but are still authorized.
	f.setDescriptor(t, time.Now().Add(-time.Hour), f.target.ConfigHash, nil)
	replay, err := f.service.SubmitDeployment(t.Context(), f.owner, apps[0].ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "same-submit")
	if err != nil || replay.DeploymentID != d.ID {
		t.Fatalf("replay during worker outage: %+v %v", replay, err)
	}
}

func TestServiceRevisionActiveLockAndHostnameTransactions(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "original"}
	app := f.create(t, "one")
	conflicting := f.input
	conflicting.Name = "Other"
	_, err := f.service.CreateApplication(t.Context(), f.owner, conflicting, "duplicate-host")
	requireProblem(t, err, 409, "hostname_conflict")
	if countKind(f.repo, cp.ApplicationKind) != 1 || countKind(f.repo, cp.IdempotencyKind) != 1 {
		t.Fatal("failed hostname claim leaked records")
	}
	changed := f.input
	changed.Exposure.Hostname = "replacement"
	changed.Name = "Updated"
	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, 2)
	requireProblem(t, err, 409, "revision_conflict")
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, 1)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	_, err = f.repo.Read(t.Context(), cp.RecordID{Kind: cp.HostnameKind, ParentID: "org", ID: "original"})
	if !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("old hostname not released: %v", err)
	}
	reservation := loadValue[cp.HostnameReservation](t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: "org", ID: "replacement"})
	if reservation.ApplicationID != app.ID {
		t.Fatal("new hostname not reserved for application")
	}
	// Released names can be claimed; a conflicting update cannot lose its old name.
	other := f.create(t, "claim-released")
	_, err = f.service.UpdateApplication(t.Context(), f.owner, other.ID, changed, other.Revision)
	requireProblem(t, err, 409, "hostname_conflict")
	reservation = loadValue[cp.HostnameReservation](t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: "org", ID: "original"})
	if reservation.ApplicationID != other.ID {
		t.Fatal("failed update lost old reservation")
	}
	moved := changed
	moved.TargetID = "different"
	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, moved, 2)
	requireProblem(t, err, 422, "immutable_target")
	_, err = f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "stale")
	requireProblem(t, err, 409, "revision_conflict")
	f.submit(t, updated, "active")
	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, 2)
	requireProblem(t, err, 409, "deployment_active")
	_, err = f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 2}, "second")
	requireProblem(t, err, 409, "deployment_active")
}

func TestServiceValidationAndTargetReadinessPrecedePersistence(t *testing.T) {
	for _, test := range []struct {
		name      string
		heartbeat time.Time
		hash      string
		caps      compute.CapabilitySet
	}{
		{name: "expired", heartbeat: time.Now().Add(-time.Minute), hash: "policy-hash"},
		{name: "mismatched", heartbeat: time.Now(), hash: "other-policy"},
		{name: "future", heartbeat: time.Now().Add(time.Hour), hash: "policy-hash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newServiceFixture(t)
			app := f.create(t, "before-outage")
			f.setDescriptor(t, test.heartbeat, test.hash, test.caps)
			targets, err := f.service.ListTargets(t.Context(), f.owner)
			if err != nil || len(targets) != 1 || targets[0].Ready || len(targets[0].ExecutionModes) != 0 {
				t.Fatalf("stale descriptor exposed usable options: %+v %v", targets, err)
			}
			_, err = f.service.CreateApplication(t.Context(), f.owner, f.input, "unready-create")
			requireProblem(t, err, 503, "target_unavailable")
			_, err = f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "unready-submit")
			requireProblem(t, err, 503, "target_unavailable")
			got, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
			if err != nil || got.Status != "draft" {
				t.Fatalf("existing draft unavailable: %+v %v", got, err)
			}
			if countKind(f.repo, cp.ApplicationKind) != 1 || countKind(f.repo, cp.DeploymentKind) != 0 || countKind(f.repo, cp.IdempotencyKind) != 1 {
				t.Fatal("unready target persisted intent")
			}
		})
	}
	f := newServiceFixture(t)
	f.setDescriptor(t, time.Now(), f.target.ConfigHash, compute.NewCapabilitySet(compute.CapImageBuild, compute.CapImageRegistry))
	_, err := f.service.CreateApplication(t.Context(), f.owner, f.input, "missing-capability")
	requireProblem(t, err, 422, "invalid_specification")
	if countKind(f.repo, cp.ApplicationKind) != 0 {
		t.Fatal("pure provider capability refusal persisted app")
	}
	f = newServiceFixture(t)
	invalid := f.input
	invalid.Source.URL = "https://github.com/unapproved/repo"
	_, err = f.service.CreateApplication(t.Context(), f.owner, invalid, "unapproved")
	requireProblem(t, err, 422, "invalid_specification")
	invalid = f.input
	invalid.Source.Dockerfile = strings.Repeat("d", 65<<10)
	_, err = f.service.CreateApplication(t.Context(), f.owner, invalid, "oversize")
	requireProblem(t, err, 413, "specification_too_large")
	_, err = f.service.CreateApplication(t.Context(), f.owner, f.input, "")
	requireProblem(t, err, 400, "invalid_idempotency_key")
	if countKind(f.repo, cp.ApplicationKind) != 0 || countKind(f.repo, cp.IdempotencyKind) != 0 {
		t.Fatal("invalid requests persisted records")
	}
}

func TestServiceLiveEligibilityAndOutageNeverBecomeEmptySuccess(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "one")
	job := f.submit(t, app, "job")
	f.repo.SetError(errors.New("secret-provider-canary"))
	_, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{})
	requireProblem(t, err, 503, "unavailable")
	if strings.Contains(err.Error(), "canary") {
		t.Fatal("storage diagnostic leaked")
	}
	_, err = f.service.GetApplication(t.Context(), f.owner, app.ID)
	requireProblem(t, err, 503, "unavailable")
	f.repo.SetError(nil)
	f.eligibility.remove(f.owner.UserID)
	calls := []func() error{
		func() error { _, err := f.service.ListTargets(t.Context(), f.owner); return err },
		func() error { _, err := f.service.CreateApplication(t.Context(), f.owner, f.input, "one"); return err },
		func() error {
			_, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, f.input, 1)
			return err
		},
		func() error { _, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{}); return err },
		func() error { _, err := f.service.GetApplication(t.Context(), f.owner, app.ID); return err },
		func() error {
			_, err := f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "job")
			return err
		},
		func() error { _, err := f.service.GetDeployment(t.Context(), f.owner, job.DeploymentID); return err },
		func() error {
			_, err := f.service.ListDeployments(t.Context(), f.owner, app.ID, cp.ListOptions{})
			return err
		},
		func() error {
			_, err := f.service.ResolveInterrupted(t.Context(), f.owner, job.DeploymentID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "stopped"})
			return err
		},
	}
	for _, call := range calls {
		requireProblem(t, call(), 401, "")
	}
	// Client-asserted admin authority cannot override the current effective role.
	forged := f.other
	forged.Admin = true
	_, err = f.service.GetApplication(t.Context(), forged, app.ID)
	requireProblem(t, err, 404, "not_found")
	f.eligibility.mu.Lock()
	f.eligibility.failure = cp.ErrUnavailable
	f.eligibility.mu.Unlock()
	_, err = f.service.ListApplications(t.Context(), f.admin, cp.ListOptions{})
	requireProblem(t, err, 503, "unavailable")
}

func TestServiceInterruptedResolutionPreservesUncertainOutcomeAndArtifacts(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "one")
	job := f.submit(t, app, "job")
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID}
	deploymentID := cp.RecordID{Kind: cp.DeploymentKind, ParentID: app.ID, ID: job.DeploymentID}
	record := loadValue[cp.ApplicationRecord](t, f.repo, appID)
	d := loadValue[cp.DeploymentRecord](t, f.repo, deploymentID)
	artifacts := deploy.Artifacts{Workload: compute.Ref{Provider: "test", ID: "provider-secret-canary"}, Secrets: map[string]compute.Ref{"arbitrary-secret-name-canary": {Provider: "test", ID: "secret-reference-canary"}}, Image: compute.ImageRef("private-registry-canary")}
	d.State = cp.Interrupted
	d.Artifacts = artifacts
	d.Step = "service"
	d.Message = "provider-error-canary"
	d.Progress = "raw-log-canary"
	record.Application.Artifacts = artifacts
	storeValue(t, f.repo, deploymentID, d)
	storeValue(t, f.repo, appID, record)
	_, err := f.service.ResolveInterrupted(t.Context(), f.owner, d.ID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "stopped"})
	requireProblem(t, err, 403, "forbidden")
	noWrite := f.admin
	noWrite.Bearer = true
	noWrite.Scopes = []string{cp.DeploymentsRead}
	_, err = f.service.ResolveInterrupted(t.Context(), noWrite, d.ID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "stopped"})
	requireProblem(t, err, 403, "insufficient_scope")
	_, err = f.service.ResolveInterrupted(t.Context(), f.admin, d.ID, cp.ResolveInterruptedInput{Reason: "stopped"})
	requireProblem(t, err, 422, "invalid_resolution")
	_, err = f.service.ResolveInterrupted(t.Context(), f.admin, d.ID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "  "})
	requireProblem(t, err, 422, "invalid_resolution")
	locked, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil || locked.ActiveDeploymentID != d.ID || locked.Status != "interrupted" {
		t.Fatalf("uncertain lock: %+v %v", locked, err)
	}
	safe, err := f.service.GetDeployment(t.Context(), f.owner, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(safe)
	if strings.Contains(string(encoded), "canary") || !safe.Terminal || len(safe.PartialResources) != 3 {
		t.Fatalf("unsafe/incomplete partial view: %s", encoded)
	}
	resolved, err := f.service.ResolveInterrupted(t.Context(), f.admin, d.ID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "Worker process and build container terminated."})
	if err != nil || resolved.State != cp.Interrupted || !resolved.Terminal {
		t.Fatalf("resolution changed outcome: %+v %v", resolved, err)
	}
	after := loadValue[cp.DeploymentRecord](t, f.repo, deploymentID)
	if after.ResolvedBy != f.admin.UserID || after.ResolvedAt.IsZero() || after.ResolutionReason == "" || !reflect.DeepEqual(after.Artifacts, artifacts) {
		t.Fatalf("acknowledgement/artifacts missing: %+v", after)
	}
	current := loadValue[cp.ApplicationRecord](t, f.repo, appID)
	if current.ActiveDeploymentID != "" || !reflect.DeepEqual(current.Application.Artifacts, artifacts) {
		t.Fatal("resolution lost partial resources or retained lock")
	}
	changed := f.input
	changed.Name = "Next attempt"
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, 1)
	if err != nil {
		t.Fatal(err)
	}
	current = loadValue[cp.ApplicationRecord](t, f.repo, appID)
	if !reflect.DeepEqual(current.Application.Artifacts, artifacts) {
		t.Fatal("spec edit lost partial resources")
	}
	next := f.submit(t, updated, "explicit-new-attempt")
	if next.DeploymentID == d.ID {
		t.Fatal("resolution replayed old operation")
	}
	nextRecord := loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: next.DeploymentID})
	if !reflect.DeepEqual(nextRecord.Application.Artifacts, artifacts) || nextRecord.State != cp.Queued {
		t.Fatal("new operation lost retained artifacts")
	}
	_, err = f.service.ResolveInterrupted(t.Context(), f.admin, d.ID, cp.ResolveInterruptedInput{WorkerStopped: true, Reason: "stopped"})
	requireProblem(t, err, 409, "not_interrupted")
}

func TestServiceViewsSeparateLastSuccessFromLatestFailureAndBoundPages(t *testing.T) {
	f := newServiceFixture(t)
	first := f.create(t, "first")
	second := f.create(t, "second")
	page, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Cursor == "" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	next, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{Limit: 1, Cursor: page.Cursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID {
		t.Fatalf("next page: %+v %v", next, err)
	}
	_, err = f.service.ListApplications(t.Context(), f.other, cp.ListOptions{Cursor: page.Cursor})
	requireProblem(t, err, 400, "invalid_cursor")
	_, err = f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{Limit: 101})
	requireProblem(t, err, 400, "invalid_pagination")
	job := f.submit(t, first, "success")
	id := cp.RecordID{Kind: cp.DeploymentKind, ParentID: first.ID, ID: job.DeploymentID}
	d := loadValue[cp.DeploymentRecord](t, f.repo, id)
	d.State = cp.Succeeded
	d.FinishedAt = time.Now().UTC()
	storeValue(t, f.repo, id, d)
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: first.ID}
	app := loadValue[cp.ApplicationRecord](t, f.repo, appID)
	app.ActiveDeploymentID = ""
	app.LastSuccessfulDeploymentID = d.ID
	app.Addresses = []string{"https://app.example/", "https://user:secret@app.example/", "javascript:alert(1)"}
	storeValue(t, f.repo, appID, app)
	success, err := f.service.GetApplication(t.Context(), f.owner, first.ID)
	if err != nil || success.Status != "running" || len(success.Addresses) != 1 {
		t.Fatalf("success view: %+v %v", success, err)
	}
	failed := f.submit(t, first, "failed")
	failedID := cp.RecordID{Kind: cp.DeploymentKind, ParentID: first.ID, ID: failed.DeploymentID}
	bad := loadValue[cp.DeploymentRecord](t, f.repo, failedID)
	bad.State = cp.Failed
	storeValue(t, f.repo, failedID, bad)
	app = loadValue[cp.ApplicationRecord](t, f.repo, appID)
	app.ActiveDeploymentID = ""
	storeValue(t, f.repo, appID, app)
	latest, err := f.service.GetApplication(t.Context(), f.owner, first.ID)
	if err != nil || latest.Status != "failed" || latest.LastSuccessfulDeploymentID != job.DeploymentID || latest.LatestDeploymentID != failed.DeploymentID || len(latest.Addresses) != 1 {
		t.Fatalf("last success/latest failure view: %+v %v", latest, err)
	}
	history, err := f.service.ListDeployments(t.Context(), f.owner, first.ID, cp.ListOptions{})
	if err != nil || len(history.Items) != 2 || history.Items[0].CreatedAt.Before(history.Items[1].CreatedAt) || history.Items[0].ID != failed.DeploymentID {
		t.Fatalf("history: %+v %v", history, err)
	}
	draft, err := f.service.GetApplication(t.Context(), f.owner, second.ID)
	if err != nil || draft.Status != "draft" || len(draft.Addresses) != 0 {
		t.Fatalf("draft: %+v %v", draft, err)
	}
}

type failingCommitRepository struct{ cp.Repository }

func (r failingCommitRepository) Commit(context.Context, []cp.Mutation) error {
	return errors.New("storage-secret-canary")
}

func TestServiceCommitOutageCannotReturnAcceptedOrLeakPartialIntent(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "existing")
	failing, err := cp.NewService(failingCommitRepository{f.repo}, f.eligibility, map[string]cp.TargetPolicy{f.target.ID: f.target})
	if err != nil {
		t.Fatal(err)
	}
	before := f.repo.Snapshot()
	input := f.input
	input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "must-not-leak"}
	_, err = failing.CreateApplication(t.Context(), f.owner, input, "failed-create")
	requireProblem(t, err, 503, "unavailable")
	accepted, err := failing.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "failed-submit")
	requireProblem(t, err, 503, "unavailable")
	if accepted.DeploymentID != "" || !reflect.DeepEqual(before, f.repo.Snapshot()) {
		t.Fatal("failed commit returned acceptance or leaked durable intent")
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatal("commit diagnostic leaked")
	}
	recovered, err := f.service.SubmitDeployment(t.Context(), f.owner, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: 1}, "failed-submit")
	if err != nil || recovered.State != cp.Queued {
		t.Fatalf("same-key recovery: %+v %v", recovered, err)
	}
}

func TestServiceMissingDescriptorAndSafeTargetOptions(t *testing.T) {
	f := newServiceFixture(t)
	options, err := f.service.ListTargets(t.Context(), f.owner)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(options)
	if strings.Contains(string(encoded), "operator-certificate") || strings.Contains(string(encoded), "apps.example") || strings.Contains(string(encoded), "policy-hash") {
		t.Fatalf("target leaked operator configuration: %s", encoded)
	}
	descriptor, err := f.repo.Read(t.Context(), cp.RecordID{Kind: cp.TargetKind, ID: f.target.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(t.Context(), []cp.Mutation{{Record: descriptor, ExpectedVersion: descriptor.Version, Delete: true}}); err != nil {
		t.Fatal(err)
	}
	options, err = f.service.ListTargets(t.Context(), f.owner)
	if err != nil || len(options) != 1 || options[0].Ready || len(options[0].ExecutionModes) != 0 {
		t.Fatalf("missing descriptor appears ready: %+v %v", options, err)
	}
	_, err = f.service.CreateApplication(t.Context(), f.owner, f.input, "no-worker")
	requireProblem(t, err, 503, "target_unavailable")
	if countKind(f.repo, cp.ApplicationKind) != 0 || countKind(f.repo, cp.IdempotencyKind) != 0 {
		t.Fatal("missing descriptor persisted application")
	}
}

func TestServiceConcurrentRevisionUpdatesCannotSilentlyOverwrite(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "one")
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]cp.ApplicationView, 2)
	failures := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			input := f.input
			input.Name = []string{"First edit", "Second edit"}[i]
			results[i], failures[i] = f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range failures {
		if err == nil {
			if winner != -1 {
				t.Fatal("both stale-revision updates succeeded")
			}
			winner = i
		} else {
			requireProblem(t, err, 409, "revision_conflict")
		}
	}
	if winner == -1 {
		t.Fatal("no revision update committed")
	}
	current, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil || current.Revision != 2 || current.Specification.Name != results[winner].Specification.Name {
		t.Fatalf("committed edit was overwritten: %+v %v", current, err)
	}
}

func TestMCPAuthMapsOnlyPublicApplicationRoutes(t *testing.T) {
	f := newServiceFixture(t)
	public := f.input
	public.Exposure = cp.ExposureInput{Mode: "public", Hostname: "assistant", MCPAuthEnabled: true}
	application, err := cp.MapApplication("application-id", public, f.target)
	if err != nil {
		t.Fatal(err)
	}
	if len(application.Routes) != 1 || !application.Routes[0].RequireAuth || application.Routes[0].MCPAuthApplicationID != "application-id" {
		t.Fatalf("MCP auth route = %+v", application.Routes)
	}

	private := f.input
	private.Exposure.MCPAuthEnabled = true
	_, err = cp.MapApplication("application-id", private, f.target)
	var problem *cp.Error
	if !errors.As(err, &problem) || problem.FieldErrors["exposure.mcpAuthEnabled"] == "" {
		t.Fatalf("private MCP auth returned %v", err)
	}
}

func TestServiceRejectsInvalidRelationalCapacityCeiling(t *testing.T) {
	f := newServiceFixture(t)
	for _, cap := range []float64{-1, math.NaN(), math.Inf(1)} {
		target := f.target
		target.MaxRelationalCapacityUnits = cap
		if _, err := cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{target.ID: target}); err == nil {
			t.Fatalf("accepted invalid relational capacity ceiling %v", cap)
		}
	}
}

func TestRequestDetectionRequiresAppOwnerRole(t *testing.T) {
	f := newServiceFixture(t)
	member := cp.Principal{UserID: "member", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "member-subject", Role: cp.RoleMember, Bearer: true, Scopes: []string{cp.ApplicationsWrite}}
	f.eligibility.principals[member.UserID] = member
	input := cp.DetectionInput{URL: f.input.Source.URL}

	// The caller's cached role cannot override the current resolved member role.
	stale := member
	stale.Role = cp.RoleAppOwner
	_, err := f.service.RequestDetection(t.Context(), stale, f.target.ID, input)
	requireProblem(t, err, 403, "forbidden")
	queued, err := f.repo.Query(t.Context(), cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if err != nil || len(queued.Records) != 0 {
		t.Fatalf("member detection reached worker queue: %+v %v", queued, err)
	}

	if _, err := f.service.RequestDetection(t.Context(), f.owner, f.target.ID, input); err != nil {
		t.Fatalf("application owner detection blocked: %v", err)
	}
	admin := f.admin
	admin.Role = cp.RoleMember
	f.eligibility.principals[admin.UserID] = admin
	if _, err := f.service.RequestDetection(t.Context(), admin, f.target.ID, input); err != nil {
		t.Fatalf("administrator detection blocked: %v", err)
	}
	queued, err = f.repo.Query(t.Context(), cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if err != nil || len(queued.Records) != 2 {
		t.Fatalf("owner/admin detections were not queued: %+v %v", queued, err)
	}
}

func TestGitHubInstallationAllowlistsSourceWhenOperatorListIsEmpty(t *testing.T) {
	f := newServiceFixture(t)
	target := f.target
	target.Repositories = nil
	service, err := cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{target.ID: target})
	if err != nil {
		t.Fatal(err)
	}
	input := f.input
	input.Source.URL = "https://github.com/example-org/app"

	_, err = service.CreateApplication(t.Context(), f.owner, input, "no-install")
	requireProblem(t, err, 422, "invalid_specification")

	storeValue(t, f.repo, cp.RecordID{Kind: cp.GitHubInstallationKind, ID: "7"}, cp.GitHubInstallationRecord{
		ID: "7", InstallationID: 7, AccountLogin: "example-org", AccountType: "Organization", SyncedAt: time.Now().UTC(),
		Repositories: []string{"https://github.com/example-org/app", "https://github.com/example-org/other"},
	})
	if _, err := service.CreateApplication(t.Context(), f.owner, input, "with-install"); err != nil {
		t.Fatal(err)
	}

	other := input
	other.Name, other.Source.URL = "Other", "https://github.com/other-org/app"
	_, err = service.CreateApplication(t.Context(), f.owner, other, "other-org")
	requireProblem(t, err, 422, "invalid_specification")

	storeValue(t, f.repo, cp.RecordID{Kind: cp.GitHubInstallationKind, ID: "8"}, cp.GitHubInstallationRecord{
		ID: "8", InstallationID: 8, AccountLogin: "paused-org", AccountType: "Organization", SuspendedAt: time.Now().UTC(), SyncedAt: time.Now().UTC(),
		Repositories: []string{"https://github.com/paused-org/app"},
	})
	paused := input
	paused.Name, paused.Source.URL = "Paused", "https://github.com/paused-org/app"
	_, err = service.CreateApplication(t.Context(), f.owner, paused, "paused")
	requireProblem(t, err, 422, "invalid_specification")

	if _, err := service.RequestDetection(t.Context(), f.owner, target.ID, cp.DetectionInput{URL: input.Source.URL}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RequestDetection(t.Context(), f.owner, target.ID, cp.DetectionInput{URL: other.Source.URL}); err == nil {
		t.Fatal("detection of an uninstalled owner succeeded")
	}

	views, err := service.ListTargets(t.Context(), f.owner)
	if err != nil || len(views) != 1 || views[0].Repositories == nil || len(views[0].Repositories) != 0 {
		t.Fatalf("empty operator list must serialize as an empty slice: %+v %v", views, err)
	}
	want := []string{"https://github.com/example-org/app", "https://github.com/example-org/other"}
	if len(views[0].RepositorySuggestions) != len(want) || views[0].RepositorySuggestions[0] != want[0] || views[0].RepositorySuggestions[1] != want[1] {
		t.Fatalf("suggestions = %#v", views[0].RepositorySuggestions)
	}
}

func TestOperatorRepositoryListStillRestrictsGitHubInstallations(t *testing.T) {
	f := newServiceFixture(t)
	storeValue(t, f.repo, cp.RecordID{Kind: cp.GitHubInstallationKind, ID: "7"}, cp.GitHubInstallationRecord{
		ID: "7", InstallationID: 7, AccountLogin: "example", AccountType: "Organization", SyncedAt: time.Now().UTC(),
	})
	input := f.input
	input.Source.URL = "https://github.com/example/other"
	_, err := f.service.CreateApplication(t.Context(), f.owner, input, "listed-only")
	requireProblem(t, err, 422, "invalid_specification")
}
