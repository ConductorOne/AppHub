// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
)

// All injected identity/source/provider behavior in this file is test-only.
type workerEligibility struct {
	err    error
	admin  bool
	groups []string
}

func (e workerEligibility) CheckPrincipal(_ context.Context, p cp.Principal) (cp.Principal, error) {
	p.Admin = e.admin
	p.Groups = e.groups
	return p, e.err
}
func (e workerEligibility) ResolveRole(_ context.Context, _ string) (string, bool) {
	return cp.RoleMember, false
}

type workerSource struct {
	dir         string
	beforeFetch func(deploy.Source) error
	prepare     func(context.Context) error
	closeErr    error
}

const fixtureCommit = "1234567890abcdef1234567890abcdef12345678"

func (s *workerSource) Prepare(ctx context.Context, _ deploy.Source) (string, error) {
	if s.prepare != nil {
		if err := s.prepare(ctx); err != nil {
			return "", err
		}
	}
	return fixtureCommit, nil
}
func (s *workerSource) Fetch(_ context.Context, src deploy.Source) (string, error) {
	if src.Ref != fixtureCommit {
		return "", errors.New("module did not use prepared commit")
	}
	if s.beforeFetch != nil {
		if err := s.beforeFetch(src); err != nil {
			return "", err
		}
	}
	return s.dir, nil
}
func (s *workerSource) Close() error { return s.closeErr }

type workerFixture struct {
	d        *Dispatcher
	repo     *testutil.Repository
	provider *fake.Provider
	source   *workerSource
	app      cp.ApplicationRecord
	dep      cp.DeploymentRecord
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	repo := testutil.NewRepository()
	provider := fake.New(fake.NewStore(), fake.Config{Name: "worker-test", ObservationsToReady: 1})
	target := cp.TargetPolicy{ID: "test", Label: "Test", ConfigHash: "test-policy", ResourceSizes: []cp.ResourceInput{{CPU: 256, Memory: 512}}, MaxReplicas: 3, ExecutionModes: []string{"service", "scheduled"}, Repositories: []string{"https://code.example.test/org/app.git"}, DeployConfig: deploy.Config{ResourcePrefix: "apphub", AllowedSourceHosts: []string{"code.example.test"}, SecretStoreName: provider.Name(), Placement: compute.Placement{Name: "default"}, WaitTimeout: time.Second, WorkloadIdentityMode: "native"}}
	input := cp.ApplicationInput{Name: "Test app", TargetID: target.ID, Source: cp.SourceInput{URL: target.Repositories[0], Ref: "main", Dockerfile: "Dockerfile"}, Execution: deploy.ExecutionService, Port: 8080, Resources: target.ResourceSizes[0], Replicas: 3, Exposure: cp.ExposureInput{Mode: "private"}}
	application, err := cp.MapApplication("app-one", input, target)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	app := cp.ApplicationRecord{ID: application.ID, Owners: []cp.ApplicationOwner{{Kind: cp.OwnerUser, ID: "user-one"}}, TargetID: target.ID, Revision: 7, Input: input, Application: application, ActiveDeploymentID: "deploy-one", LatestDeploymentID: "deploy-one", CreatedAt: now, UpdatedAt: now}
	dep := cp.DeploymentRecord{ID: "deploy-one", ApplicationID: app.ID, RequesterUserID: "user-one", Requester: cp.Principal{UserID: "user-one", ProviderID: "oidc", Issuer: "https://issuer.example.test", Subject: "subject-one"}, ApplicationRevision: app.Revision, TargetID: app.TargetID, Application: application, RequestedSourceRef: "main", State: cp.Queued, CreatedAt: now}
	putWorkerRecord(t, repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID}, app)
	putWorkerRecord(t, repo, cp.RecordID{Kind: cp.DeploymentKind, ParentID: app.ID, ID: dep.ID}, dep)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := &workerSource{dir: dir}
	d, err := NewWithSourceFactory(serverconfig.Config{}, repo, workerEligibility{}, map[string]compute.Provider{target.ID: provider}, map[string]cp.TargetPolicy{target.ID: target}, func() (PreparedSource, error) { return source, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := d.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &workerFixture{d: d, repo: repo, provider: provider, source: source, app: app, dep: dep}
}

func putWorkerRecord(t *testing.T, repo cp.Repository, id cp.RecordID, value any) {
	t.Helper()
	row, err := cp.Encode(id, 1, value)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: row, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}
func readWorkerRecord[T any](t *testing.T, repo cp.Repository, id cp.RecordID) T {
	t.Helper()
	row, err := repo.Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cp.Decode[T](row)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func (f *workerFixture) deployment(t *testing.T) cp.DeploymentRecord {
	return readWorkerRecord[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ID: f.dep.ID})
}
func (f *workerFixture) application(t *testing.T) cp.ApplicationRecord {
	return readWorkerRecord[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: f.app.ID})
}
func (f *workerFixture) claim(t *testing.T) (*operationStore, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	operation, err := f.d.claim(context.Background(), f.dep.ID, cancel)
	if err != nil {
		t.Fatal(err)
	}
	return operation, ctx
}

func TestConcurrentClaimsExecuteOneDurableAttempt(t *testing.T) {
	f := newWorkerFixture(t)
	start := make(chan struct{})
	winners := make(chan *operationStore, 8)
	failures := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithCancel(context.Background())
			operation, err := f.d.claim(ctx, f.dep.ID, cancel)
			if err != nil {
				cancel()
				failures <- err
				return
			}
			winners <- operation
		}()
	}
	close(start)
	wg.Wait()
	close(winners)
	close(failures)
	var winner *operationStore
	for operation := range winners {
		if winner != nil {
			t.Fatal("two workers acquired the same deployment")
		}
		winner = operation
	}
	if winner == nil {
		t.Fatal("no worker claimed the queued deployment")
	}
	defer winner.cancel()
	for err := range failures {
		if !errors.Is(err, cp.ErrConflict) {
			t.Fatal(err)
		}
	}
	f.source.beforeFetch = func(src deploy.Source) error {
		dep := f.deployment(t)
		if dep.ResolvedCommit != fixtureCommit || dep.Application.Source.Ref != "main" || dep.RequestedSourceRef != "main" || src.Ref != fixtureCommit {
			return errors.New("commit was not durable before cloud/module execution")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f.d.execute(ctx, winner)
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Succeeded || app.ActiveDeploymentID != "" || app.LastSuccessfulDeploymentID != dep.ID {
		t.Fatalf("operation did not settle successfully: %+v", dep)
	}
	runtime, err := f.provider.Containers()
	if err != nil {
		t.Fatal(err)
	}
	status, err := runtime.DescribeService(ctx, dep.Artifacts.Workload)
	if err != nil {
		t.Fatal(err)
	}
	if status.ReadyReplicas != 3 || status.Spec.Image != dep.Artifacts.Image {
		t.Fatal("durable success differs from the deployed immutable image or requested readiness")
	}
	if _, err := f.d.claim(ctx, dep.ID, func() {}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("terminal deployment was claimable: %v", err)
	}
}

func TestStaleAttemptIsInterruptedAndFencedWithoutReclaim(t *testing.T) {
	f := newWorkerFixture(t)
	operation, ctx := f.claim(t)
	if err := f.d.interrupt(context.Background(), f.dep.ID, time.Now().Add(2*f.d.cfg.Worker.StaleAfter)); err != nil {
		t.Fatal(err)
	}
	if err := operation.heartbeat(context.Background()); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("old heartbeat was not fenced: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("CAS loss did not cancel local work")
	}
	if err := operation.finish(cp.Succeeded, "", "ready"); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("old attempt could declare success: %v", err)
	}
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Interrupted || app.ActiveDeploymentID != dep.ID || dep.AttemptID == "" {
		t.Fatal("interruption lost the uncertain attempt or its execution lock")
	}
	if _, err := f.d.claim(context.Background(), dep.ID, func() {}); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("interrupted deployment was reclaimed: %v", err)
	}
}

func TestFreshHeartbeatDefeatsStaleDiscovery(t *testing.T) {
	f := newWorkerFixture(t)
	operation, _ := f.claim(t)
	old := f.deployment(t)
	if err := operation.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.d.interrupt(context.Background(), old.ID, old.HeartbeatAt.Add(f.d.cfg.Worker.StaleAfter-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if f.deployment(t).State != cp.Running {
		t.Fatal("stale discovery interrupted a freshly heartbeating attempt")
	}
}

func TestRequesterRevocationPreventsSourceAndCloudExecution(t *testing.T) {
	f := newWorkerFixture(t)
	f.d.eligibility = workerEligibility{err: cp.Problem(401, "unauthorized", "disabled")}
	f.source.prepare = func(context.Context) error {
		t.Error("ineligible requester reached source execution")
		return errors.New("unexpected source")
	}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	dep := f.deployment(t)
	if dep.State != cp.Failed || dep.ErrorCode != "requester_ineligible" || !dep.Artifacts.Identity.IsZero() || f.application(t).ActiveDeploymentID != "" {
		t.Fatalf("ineligible operation did not fail before effects: %+v", dep)
	}
}

func TestModuleFailureRetainsPartialEffectsWithoutProviderErrorText(t *testing.T) {
	f := newWorkerFixture(t)
	const canary = "secret-provider-canary-do-not-persist"
	f.source.beforeFetch = func(deploy.Source) error { return errors.New(canary) }
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	dep, app := f.deployment(t), f.application(t)
	if dep.State != cp.Failed || dep.Artifacts.Identity.IsZero() || dep.Artifacts.Repository.IsZero() || app.Application.Artifacts.Repository != dep.Artifacts.Repository {
		t.Fatalf("failure lost previously created resources: %+v", dep)
	}
	row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.DeploymentKind, ID: dep.ID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row.Value), canary) {
		t.Fatal("provider error leaked into durable deployment")
	}
	if app.LastSuccessfulDeploymentID != "" || app.ActiveDeploymentID != "" {
		t.Fatal("failed operation reported success or retained a non-uncertain execution lock")
	}
}

func TestSourceCleanupFailureRetainsExecutionLock(t *testing.T) {
	for _, phase := range []string{"after-deployment", "after-preparation-failure"} {
		t.Run(phase, func(t *testing.T) {
			f := newWorkerFixture(t)
			const canary = "private-source-cleanup-canary"
			f.source.closeErr = errors.New(canary)
			if phase == "after-preparation-failure" {
				f.source.prepare = func(context.Context) error { return errors.New("source unavailable") }
			}
			operation, ctx := f.claim(t)
			f.d.execute(ctx, operation)
			dep, app := f.deployment(t), f.application(t)
			if dep.State != cp.Interrupted || dep.ErrorCode != "source_cleanup_failed" || app.ActiveDeploymentID != dep.ID || app.LastSuccessfulDeploymentID != "" {
				t.Fatalf("unconfirmed source cleanup lost its execution lock or reported success: %+v", dep)
			}
			row, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.DeploymentKind, ID: dep.ID})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(row.Value), canary) {
				t.Fatal("source cleanup error leaked into durable deployment")
			}
		})
	}
}

func TestShutdownDoesNotCancelAnAcceptedDeployment(t *testing.T) {
	f := newWorkerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.source.prepare = func(ctx context.Context) error {
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- f.d.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("worker never started accepted operation")
	}
	cancel()
	close(release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not drain")
	}
	if f.deployment(t).State != cp.Succeeded {
		t.Fatalf("shutdown canceled rather than drained operation: %+v", f.deployment(t))
	}
}
