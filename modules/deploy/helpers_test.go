// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/workload"
)

// The test fixtures. They are deliberately small: every interesting behaviour
// is exercised against compute/fake, which is a working provider with a
// conformance suite behind it, rather than against a stub that agrees with
// whatever this package happens to do.

// memStore is an in-memory [Store].
type memStore struct {
	mu   sync.Mutex
	apps map[string]*Application
	// saves counts calls, so a test can assert that a refusal wrote nothing.
	saves int
	// failSave, when set, is returned by SaveApplication.
	failSave error
	// failGet, when set, is returned by GetApplication.
	failGet error
}

func newMemStore(apps ...*Application) *memStore {
	s := &memStore{apps: map[string]*Application{}}
	for _, a := range apps {
		s.apps[a.ID] = a
	}
	return s
}

func (s *memStore) GetApplication(_ context.Context, id string) (*Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGet != nil {
		return nil, s.failGet
	}
	app, ok := s.apps[id]
	if !ok {
		return nil, fmt.Errorf("no application %q", id)
	}
	// A copy, so a test can tell what was persisted from what the module
	// mutated in memory.
	clone := *app
	return &clone, nil
}

func (s *memStore) SaveApplication(_ context.Context, app *Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.failSave != nil {
		return s.failSave
	}
	clone := *app
	s.apps[app.ID] = &clone
	return nil
}

func (s *memStore) saved(id string) *Application {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apps[id]
}

// stubFetcher is a [SourceFetcher] over a real temporary directory.
//
// A real directory rather than a name, because the fake provider's builder
// reads the build context: a fetcher returning a path that does not exist would
// make every build fail for a reason unrelated to what is under test.
type stubFetcher struct {
	dir  string
	err  error
	seen []Source
}

// newFetcher writes a minimal build context under the test's own temporary
// directory, which the framework removes.
func newFetcher(t *testing.T) *stubFetcher {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("writing the build context: %v", err)
	}
	return &stubFetcher{dir: dir}
}

func (f *stubFetcher) Fetch(_ context.Context, src Source) (string, error) {
	f.seen = append(f.seen, src)
	if f.err != nil {
		return "", f.err
	}
	return f.dir, nil
}

// stubAttestations is an [AttestationProvisioner].
//
// Its materials are settable so a test can drive the SecretRef conversion with
// references the deploy did and did not issue.
type stubAttestations struct {
	revision  int
	rotations int
	materials workload.Materials
	rotateErr error
	// secretsFor, when set, builds the materials from the revision, so a test
	// can make them depend on the rotation having happened.
	secretsFor func(revision int) workload.Materials
}

func (a *stubAttestations) Rotate(context.Context, workload.Ref) (int, error) {
	if a.rotateErr != nil {
		return 0, a.rotateErr
	}
	a.rotations++
	a.revision++
	return a.revision, nil
}

func (a *stubAttestations) Materials(_ context.Context, ref workload.Ref) (workload.Materials, error) {
	if a.secretsFor != nil {
		return a.secretsFor(ref.Revision), nil
	}
	return a.materials, nil
}

// testConfig is a configuration with everything set, which every test then
// narrows rather than widens.
func testConfig() Config {
	return Config{
		ResourcePrefix:     "apphub",
		RouteDomain:        "apps.example.test",
		AllowedSourceHosts: []string{"code.example.test"},
		SecretStoreName:    "fake-store",
		RouteCertificate:   "cert-default",
		// Named rather than left to the provider's default, because an
		// application that binds provider-held secrets requires it: a binding's
		// placement is checked against this one before anything is created, and
		// there is nothing to check against when it is empty.
		Placement: compute.Placement{Name: "default"},
	}
}

// testApplication is a container application that asks for everything portable:
// a relational database, a bucket, a published route, an application secret and
// a workload capability. Tests narrow it.
func testApplication() *Application {
	return &Application{
		ID:   "app-1",
		Name: "Reports",
		Source: Source{
			URL:        "https://code.example.test/team/reports",
			Dockerfile: "Dockerfile",
		},
		Workload:  WorkloadContainer,
		Execution: ExecutionService,
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Replicas:  2,
		Port:      8080,
		Database: Database{
			Kind:          DatabaseRelational,
			Engine:        compute.EnginePostgres,
			EngineVersion: "16",
			DatabaseName:  "appdb",
			AdminUsername: "appadmin",
		},
		Bucket:       Bucket{Kind: BucketStandard},
		Capabilities: []compute.WorkloadCapability{compute.WorkloadCapabilityModelInference},
		Routes:       []Route{{Hostname: "reports", RequireAuth: true, PublicPaths: []string{"/healthz"}}},
		Labels:       map[string]string{"team": "platform"},
	}
}

// minimalApplication is a valid container service that asks for nothing
// optional: no database, no bucket, no route, no secret.
//
// It exists so that a test can drive a field OUTSIDE its variant. Every
// conditional field in the applicability table has a condition that is false
// here, which testApplication's does not — it has a relational database and a
// bucket, so half the conditions hold on it.
func minimalApplication() *Application {
	return &Application{
		ID:        "app-1",
		Name:      "Reports",
		Source:    Source{URL: "https://code.example.test/team/reports", Dockerfile: "Dockerfile"},
		Workload:  WorkloadContainer,
		Execution: ExecutionService,
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Replicas:  1,
		Port:      8080,
	}
}

// testScheduledApplication is the same application as a scheduled job.
//
// A separate fixture rather than a field flipped on the service one, because
// the schedule and the routes are now mutually exclusive by construction: a
// scheduled workload has nothing for a hostname to reach, and a record that
// carries a schedule it does not run on is refused rather than ignored.
func testScheduledApplication() *Application {
	app := testApplication()
	app.Execution = ExecutionScheduled
	app.Schedule = compute.Schedule{Expression: "rate(1 hour)", Timezone: "UTC"}
	app.Routes = nil
	return app
}

// planFixture is the provider name every plan built in a test is for. It
// matches newTestProvider's configured name, so a Ref the fake issues is one
// the plan accepts.
const planFixtureProvider = "fake-store"

// newTestProvider builds a fake provider with every capability, plus whatever
// defects a test asks for.
func newTestProvider(t *testing.T, defects ...fake.Defect) *fake.Provider {
	t.Helper()
	return fake.New(fake.NewStore(), fake.Config{
		Name:                "fake-store",
		Defects:             defects,
		ObservationsToReady: 1,
	})
}

// newTestModule wires a module over a fake provider.
func newTestModule(t *testing.T, p compute.Provider, store Store, cfg Config) (*Module, *stubFetcher, *stubAttestations) {
	t.Helper()
	fetcher := newFetcher(t)
	att := &stubAttestations{}
	m, err := New(p, store, fetcher, att, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, fetcher, att
}

// rendered is everything the provider has put into its substrate.
func rendered(t *testing.T, p *fake.Provider) []string {
	t.Helper()
	out, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	return out
}

// secretRef builds a credential-layer reference for the binder tests.
func secretRef(store, name, version, envVar string) credentials.SecretRef {
	return credentials.SecretRef{Store: store, Name: name, Version: version, EnvVar: envVar}
}

// errIs is errors.Is with a message a reader can act on.
func errIs(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want it to wrap %v", what, err, target)
	}
}
