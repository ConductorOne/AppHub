// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/workload"
	"github.com/conductorone/apphub/modules"
)

func TestADeployCreatesEverythingTheApplicationAsksFor(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Secrets = nil // provider-held secrets are covered separately
	store := newMemStore(app)
	m, fetcher, att := newTestModule(t, p, store, testConfig())

	result, err := m.Execute(context.Background(), "u1", map[string]any{"applicationId": app.ID})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Success {
		t.Fatalf("result reports failure: %+v", result)
	}

	got := store.saved(app.ID)
	if got.Status != StatusRunning {
		t.Errorf("status = %q, want %q", got.Status, StatusRunning)
	}
	for name, ref := range map[string]compute.Ref{
		"identity":   got.Artifacts.Identity,
		"repository": got.Artifacts.Repository,
		"workload":   got.Artifacts.Workload,
		"bucket":     got.Artifacts.Bucket,
		"relational": got.Artifacts.Relational,
	} {
		if ref.IsZero() {
			t.Errorf("%s reference was not recorded, so the next deploy cannot find it and a "+
				"teardown cannot remove it", name)
		}
	}
	if got.Artifacts.Image == "" {
		t.Error("no image was recorded")
	}
	if _, ok := got.Artifacts.Secrets[EnvDatabasePassword]; !ok {
		t.Error("the generated administrative password was not recorded")
	}
	if att.rotations != 1 {
		t.Errorf("attestation rotations = %d, want exactly 1 per deploy", att.rotations)
	}
	if got.Artifacts.AttestationRevision == 0 {
		t.Error("the attestation revision was not recorded")
	}
	if len(fetcher.seen) != 1 {
		t.Fatalf("the source was fetched %d times, want 1", len(fetcher.seen))
	}

	// And the substrate really holds them: the record agreeing with itself is
	// not evidence that anything was created.
	subs := strings.Join(rendered(t, p), "\n")
	for _, want := range []string{"service ", "bucket ", "relational ", "image-repository ", "identity ", "secret "} {
		if !strings.Contains(subs, want) {
			t.Errorf("the provider rendered no %q; it rendered:\n%s", want, subs)
		}
	}
}

// TestTheWorkloadRunsAnImmutableImageReference pins the property, not the
// spelling: whatever the workload is told to run must not be a reference a
// later push can repoint. ":latest" is pushed for humans and is never it.
func TestTheWorkloadRunsAnImmutableImageReference(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	if _, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	image := string(store.saved(app.ID).Artifacts.Image)
	if strings.HasSuffix(image, ":latest") {
		t.Errorf("the workload runs %q, which every deploy of this application moves", image)
	}
	if !strings.Contains(image, "@") && !strings.Contains(image, ":deploy-") {
		t.Errorf("the workload runs %q, which is neither a digest nor a per-deploy tag", image)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "image="+image) {
		t.Errorf("the substrate does not run the recorded image %q:\n%s", image, subs)
	}
}

// TestARedeployKeepsTheAdministrativePasswordWorking is verified through the
// substrate's own authentication rather than by comparing what this module
// stored with what it stored. Comparing our copy to itself would pass just as
// happily if the provider had rotated the real one.
func TestARedeployKeepsTheAdministrativePasswordWorking(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	ctx := context.Background()
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	first := store.saved(app.ID)
	firstRef := first.Artifacts.Secrets[EnvDatabasePassword]

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	stored, err := secrets.Get(ctx, firstRef)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Control: the password we stored is the one the database accepts *now*.
	// Without this the assertion after the redeploy could pass because neither
	// works.
	if err := p.Harness().Login(ctx, first.Artifacts.Relational, app.Database.AdminUsername, stored); err != nil {
		t.Fatalf("the stored password does not authenticate before the redeploy, so this test "+
			"cannot tell a preserved password from a broken one: %v", err)
	}

	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	second := store.saved(app.ID)
	if second.Artifacts.Secrets[EnvDatabasePassword] != firstRef {
		t.Errorf("the redeploy filed the password under a different reference: %v then %v",
			firstRef, second.Artifacts.Secrets[EnvDatabasePassword])
	}
	after, err := secrets.Get(ctx, second.Artifacts.Secrets[EnvDatabasePassword])
	if err != nil {
		t.Fatalf("Get after redeploy: %v", err)
	}
	if err := p.Harness().Login(ctx, second.Artifacts.Relational, app.Database.AdminUsername, after); err != nil {
		t.Errorf("after a redeploy the stored password no longer authenticates: %v", err)
	}
}

// TestTheHarnessCanObserveARotatedPassword is the control for the test above.
//
// It does not run this module at all, and that is the point: the preservation
// property is "a redeploy never supplies a different password", and a module
// that honours it can never make the provider rotate. So the thing to establish
// separately is that the instrument would notice if one did — otherwise the
// assertion above is satisfied by a harness whose Login always succeeds.
//
// Both directions, against the same two calls: with the rotation defect the
// first password stops working, and without it, it does not.
func TestTheHarnessCanObserveARotatedPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	spec := func(pw string) compute.RelationalSpec {
		return compute.RelationalSpec{
			Name: "db", Engine: compute.EnginePostgres, EngineVersion: "16",
			DatabaseName: "appdb", AdminUsername: "appadmin",
			AdminPassword: compute.NewSecretValue(pw),
		}
	}
	for _, tc := range []struct {
		name        string
		defects     []fake.Defect
		wantWorking bool
	}{
		{"a provider that rotates", []fake.Defect{fake.DefectRotatesAdminPassword}, false},
		{"a conformant provider", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newTestProvider(t, tc.defects...)
			prov, err := p.Relational()
			if err != nil {
				t.Fatalf("Relational: %v", err)
			}
			first, err := prov.EnsureRelational(ctx, spec("first-password"))
			if err != nil {
				t.Fatalf("first EnsureRelational: %v", err)
			}
			if _, err := prov.EnsureRelational(ctx, spec("second-password")); err != nil {
				t.Fatalf("second EnsureRelational: %v", err)
			}
			err = p.Harness().Login(ctx, first.Ref, "appadmin", compute.NewSecretValue("first-password"))
			if tc.wantWorking && err != nil {
				t.Errorf("the original password stopped working against a conformant provider: %v", err)
			}
			if !tc.wantWorking && err == nil {
				t.Error("a deliberately rotating provider was not observed to rotate, so the " +
					"preservation test's instrument cannot see the failure it exists to detect")
			}
		})
	}
}

// TestARedeployStoresNoNewPassword rules out the other way the property breaks:
// generating a fresh password, storing it, and leaving the database on the old
// one. Login would still pass in that case for a provider that refuses to
// rotate, so it needs its own assertion.
func TestARedeployStoresNoNewPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	ref := store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword]
	before, err := secrets.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	after, err := secrets.Get(ctx, store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword])
	if err != nil {
		t.Fatalf("Get after redeploy: %v", err)
	}
	// Revealing both is what the assertion is: the values have to be compared,
	// and neither is written anywhere.
	if compute.RevealSecret(before) != compute.RevealSecret(after) {
		t.Error("the redeploy replaced the stored administrative password, so the database and " +
			"the store now disagree about what it is")
	}
	if before.IsZero() {
		t.Fatal("no password was stored at all, so the comparison above compares nothing")
	}
}

// TestAFailedDeployRecordsWhatItAlreadyCreated. A resource that exists and is
// not on the record is a resource nothing will ever remove.
func TestAFailedDeployRecordsWhatItAlreadyCreated(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	store := newMemStore(app)
	m, fetcher, _ := newTestModule(t, p, store, testConfig())
	fetcher.err = errors.New("the source could not be fetched")

	result, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a failing fetch produced no error")
	}
	if result == nil {
		t.Fatal("no Result alongside the error, so a caller cannot see what exists")
	}
	saved := store.saved(app.ID)
	if saved.Status != StatusFailed {
		t.Errorf("status = %q, want %q", saved.Status, StatusFailed)
	}
	if saved.FailedStep != "source-fetch" {
		t.Errorf("failed step = %q, want %q", saved.FailedStep, "source-fetch")
	}
	// The identity and the repository were created before the fetch.
	if saved.Artifacts.Identity.IsZero() || saved.Artifacts.Repository.IsZero() {
		t.Errorf("the deploy created an identity and a repository and recorded %+v", saved.Artifacts)
	}
}

// TestARefusedApplicationChangesNothingAtAll. The whole record is compared,
// normalised for nothing, so a field added to Application later is covered by
// construction rather than by somebody remembering to add it here.
func TestARefusedApplicationChangesNothingAtAll(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	// Contradictory: a scheduled workload cannot carry a route.
	app.Execution = ExecutionScheduled
	app.Schedule = compute.Schedule{Expression: "rate(1 hour)"}
	store := newMemStore(app)
	before := *store.saved(app.ID)

	m, _, _ := newTestModule(t, p, store, testConfig())
	if _, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err == nil {
		t.Fatal("a scheduled application carrying a route was accepted")
	}

	if store.saves != 0 {
		t.Errorf("the record was written %d time(s) by a refusal", store.saves)
	}
	if after := *store.saved(app.ID); !reflect.DeepEqual(before, after) {
		t.Errorf("the record changed:\n before %+v\n  after %+v", before, after)
	}
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("a refused application created %d substrate resource(s): %v", len(r), r)
	}
}

// TestAProviderMissingACapabilityIsRefusedBeforeAnythingIsCreated. The
// interesting half is the second assertion: a deploy that discovers halfway
// through that the provider cannot do something has already made resources.
func TestAProviderMissingACapabilityIsRefusedBeforeAnythingIsCreated(t *testing.T) {
	t.Parallel()
	// Everything except scheduled jobs, which is the AWS provider's real state
	// today: EnsureScheduledJob there returns an UnsupportedError.
	var caps []compute.Capability
	for _, c := range fake.AllCapabilities() {
		if c != compute.CapScheduledJob {
			caps = append(caps, c)
		}
	}
	if len(caps) == 0 {
		t.Fatal("derived an empty capability set, so this test would assert nothing")
	}
	p := fake.New(fake.NewStore(), fake.Config{Name: "fake-store", Capabilities: caps})

	app := testScheduledApplication()
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a scheduled application was accepted by a provider with no scheduled jobs")
	}
	errIs(t, err, compute.ErrUnsupported, "the refusal")
	if !strings.Contains(err.Error(), string(compute.CapScheduledJob)) {
		t.Errorf("the refusal does not name the missing capability: %v", err)
	}
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("the deploy created %d resource(s) before refusing: %v", len(r), r)
	}
	if store.saves != 0 {
		t.Errorf("the record was written %d time(s) before refusing", store.saves)
	}
}

// TestAScheduledApplicationDeploysAsAScheduledJob is the positive half: the
// refusal above must be about the capability and not about scheduled jobs being
// unimplemented here.
func TestAScheduledApplicationDeploysAsAScheduledJob(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testScheduledApplication()
	app.Bucket = Bucket{}
	app.Database = Database{}
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	if _, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if store.saved(app.ID).Artifacts.Workload.Kind != compute.KindScheduledJob {
		t.Errorf("workload kind = %q, want %q",
			store.saved(app.ID).Artifacts.Workload.Kind, compute.KindScheduledJob)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if strings.Contains(subs, "service ") {
		t.Errorf("a scheduled application also produced a service:\n%s", subs)
	}
}

// TestFunctionWorkloadsAreRefusedRatherThanDeployedAsSomethingElse pins the
// negative for what this change deliberately does not port.
func TestFunctionWorkloadsAreRefusedRatherThanDeployedAsSomethingElse(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Workload = WorkloadFunction
	app.Runtime = "python3.13"
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a function application was deployed by a module that deploys containers")
	}
	errIs(t, err, compute.ErrUnsupported, "the refusal")
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("a refused function application created %d resource(s): %v", len(r), r)
	}
}

// TestTheConstructorRefusesEveryDependencyItHolds derives its population from
// the Module struct rather than listing the four dependencies this file happens
// to know about. A dependency added without a nil check fails here.
func TestTheConstructorRefusesEveryDependencyItHolds(t *testing.T) {
	t.Parallel()
	// The four arguments New takes, in order, with a nil in each position.
	full := func() (compute.Provider, Store, SourceFetcher, AttestationProvisioner) {
		return newTestProvider(t), newMemStore(), newFetcher(t), &stubAttestations{}
	}
	cases := map[string]func() (*Module, error){
		"compute provider": func() (*Module, error) {
			_, s, f, a := full()
			return New(nil, s, f, a, testConfig())
		},
		"application store": func() (*Module, error) {
			p, _, f, a := full()
			return New(p, nil, f, a, testConfig())
		},
		"application source fetcher": func() (*Module, error) {
			p, s, _, a := full()
			return New(p, s, nil, a, testConfig())
		},
		"workload attestation provisioner": func() (*Module, error) {
			p, s, f, _ := full()
			return New(p, s, f, nil, testConfig())
		},
	}

	// The population: every interface-typed field of Module. If one gains a
	// fifth, this count disagrees and the test says which name is missing.
	var deps []string
	rt := reflect.TypeOf(Module{})
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type.Kind() == reflect.Interface {
			deps = append(deps, rt.Field(i).Name)
		}
	}
	if len(deps) == 0 {
		t.Fatal("derived no dependencies from the Module type, so every case below is vacuous")
	}
	if len(deps) != len(cases) {
		t.Errorf("Module holds %d interface dependencies (%v) and this test covers %d; a "+
			"dependency with no nil check is a module that fails on its first use",
			len(deps), deps, len(cases))
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, err := build()
			if err == nil {
				t.Fatalf("a nil %s was accepted", name)
			}
			if m != nil {
				t.Errorf("a refused constructor returned a module: %v", m)
			}
			errIs(t, err, modules.ErrNotConfigured, "the refusal")
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the refusal does not name what is missing: %v", err)
			}
		})
	}

	// And the other direction: with everything supplied it succeeds. A
	// constructor that refused unconditionally would satisfy every case above.
	p, s, f, a := full()
	if _, err := New(p, s, f, a, testConfig()); err != nil {
		t.Fatalf("a fully wired constructor was refused: %v", err)
	}
}

// TestTheConstructorRefusesAnIncompleteConfiguration covers the other half of
// fail-closed wiring: an identifier with no default and no value.
func TestTheConstructorRefusesAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string]func(Config) Config{
		"ResourcePrefix": func(c Config) Config { c.ResourcePrefix = ""; return c },
		"AllowedSourceHosts": func(c Config) Config {
			c.AllowedSourceHosts = nil
			return c
		},
		"a prefix that is not a legal name": func(c Config) Config {
			c.ResourcePrefix = "AppHub Apps"
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(newTestProvider(t), newMemStore(), newFetcher(t), &stubAttestations{},
				mutate(testConfig()))
			if err == nil {
				t.Fatalf("a configuration missing %s was accepted", name)
			}
			errIs(t, err, modules.ErrNotConfigured, "the refusal")
		})
	}
}

// TestAnApplicationWithARouteAndNoConfiguredDomainIsRefused. RouteDomain has no
// default because a default is a hostname somebody else owns.
func TestAnApplicationWithARouteAndNoConfiguredDomainIsRefused(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.RouteDomain = ""
	p := newTestProvider(t)
	app := testApplication()
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, cfg)

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("an application asking for a route was deployed with no domain configured")
	}
	errIs(t, err, modules.ErrNotConfigured, "the refusal")

	// And the positive control: the same application, with a domain, deploys
	// and is published under it.
	p2 := newTestProvider(t)
	store2 := newMemStore(testApplication())
	m2, _, _ := newTestModule(t, p2, store2, testConfig())
	if _, err := m2.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute with a domain configured: %v", err)
	}
	if subs := strings.Join(rendered(t, p2), "\n"); !strings.Contains(subs, "reports.apps.example.test") {
		t.Errorf("the route was not published under the configured domain:\n%s", subs)
	}
}

// TestWorkloadMaterialsReachTheWorkload drives the SecretRef conversion through
// Execute, which is the entry point that matters: a test of the binder alone
// can pass while nothing wires it up.
func TestWorkloadMaterialsReachTheWorkload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, att := newTestModule(t, p, store, testConfig())

	// The credential layer's material has to exist in the provider's store
	// before the deploy can bind it, which is what the platform's own
	// credential writer does. Here it is written directly and adopted from the
	// application's recorded artifacts, which is the same path a second deploy
	// takes.
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	stored, err := secrets.Put(ctx, compute.SecretSpec{
		Name:  "ATTESTATION",
		Scope: app.ID,
		Value: compute.NewSecretValue("attestation-material"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	app.Artifacts.Secrets = map[string]compute.Ref{"ATTESTATION": ref}
	if err := store.SaveApplication(ctx, app); err != nil {
		t.Fatalf("SaveApplication: %v", err)
	}
	att.materials = workload.Materials{
		Env:     map[string]string{"APPHUB_TOKEN_URL": "https://platform.example.test/token"},
		Secrets: []credentials.SecretRef{secretRef("fake-store", "ATTESTATION", "", "APPHUB_ATTESTATION")},
	}

	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "APPHUB_ATTESTATION") {
		t.Errorf("the attestation material was not bound into the workload:\n%s", subs)
	}
	if !strings.Contains(subs, "APPHUB_TOKEN_URL") {
		t.Errorf("the non-secret material was not set on the workload:\n%s", subs)
	}
	if strings.Contains(subs, "attestation-material") {
		t.Errorf("the attestation material's VALUE reached the substrate rendering:\n%s", subs)
	}
}

// TestAnEnvironmentCollisionIsRefusedRatherThanResolved.
//
// The credential layer's materials are set verbatim, and this module sets its
// own; two values for one variable means one of them is discarded, and which
// one is not something to decide by map iteration order. A workload that got
// the wrong DATABASE_HOST would connect somewhere it was not meant to.
func TestAnEnvironmentCollisionIsRefusedRatherThanResolved(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, att := newTestModule(t, p, store, testConfig())
	att.materials = workload.Materials{Env: map[string]string{
		EnvDatabaseHost: "somewhere-else.example.test",
	}}

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("two values for one environment variable were resolved silently")
	}
	errIs(t, err, ErrInvalidApplication, "the refusal")
	if !strings.Contains(err.Error(), EnvDatabaseHost) {
		t.Errorf("the refusal does not name the variable: %v", err)
	}

	// Control: a name that does not collide deploys, so the refusal above is
	// about the collision and not about materials env in general.
	p2 := newTestProvider(t)
	store2 := newMemStore(testApplication())
	store2.apps[app.ID].Bucket = Bucket{}
	store2.apps[app.ID].Routes = nil
	m2, _, att2 := newTestModule(t, p2, store2, testConfig())
	att2.materials = workload.Materials{Env: map[string]string{"APPHUB_ISSUER": "https://x.test"}}
	if _, err := m2.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a non-colliding material variable was refused: %v", err)
	}
}

// TestASourceOnAnUnallowedHostIsRefusedThroughExecute. ValidateSourceURL has its
// own tests, and they say nothing about whether anything calls it: a check at a
// lower seam can be correct while the path that matters never reaches it.
func TestASourceOnAnUnallowedHostIsRefusedThroughExecute(t *testing.T) {
	t.Parallel()
	for _, url := range []string{
		"https://evil.test/team/repo",
		"http://code.example.test/team/repo",
		"https://oauth2:token@code.example.test/team/repo",
		"https://code.example.test.evil.test/team/repo",
	} {
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			p := newTestProvider(t)
			app := testApplication()
			app.Source.URL = url
			store := newMemStore(app)
			m, fetcher, _ := newTestModule(t, p, store, testConfig())

			_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
			if err == nil {
				t.Fatalf("deployed from %q", url)
			}
			errIs(t, err, ErrSourceRefused, "the refusal")
			if len(fetcher.seen) != 0 {
				t.Errorf("the refused location was handed to the fetcher anyway: %+v", fetcher.seen)
			}
			if r := rendered(t, p); len(r) != 0 {
				t.Errorf("a refused source created %d resource(s): %v", len(r), r)
			}
			if store.saves != 0 {
				t.Errorf("a refused source wrote the record %d time(s)", store.saves)
			}
		})
	}

	// The other direction: the fetcher is handed the CANONICAL location, not
	// the one the record happened to spell.
	p := newTestProvider(t)
	app := testApplication()
	app.Source.URL = "https://CODE.EXAMPLE.TEST/team/reports/"
	store := newMemStore(app)
	m, fetcher, _ := newTestModule(t, p, store, testConfig())
	if _, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fetcher.seen) != 1 || fetcher.seen[0].URL != "https://code.example.test/team/reports" {
		t.Errorf("the fetcher was handed %+v, not the canonical location", fetcher.seen)
	}
}

// TestTheSchemaIsTheEnforcedContract. A module's Schema is its published
// contract, and a Validate that checks only the parameters it expects does not
// enforce it: every other key a caller invents is accepted, and any key Execute
// reads without publishing becomes silently caller-settable.
//
// The source read four keys its schema never declared. This module declares one
// parameter and reads one, and these are the assertions that keep it that way —
// driven through Execute as well as through Validate, because a Validate that
// is correct and unreached enforces nothing.
func TestTheSchemaIsTheEnforcedContract(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	declared := m.Schema()
	if declared == nil || len(declared.Properties) == 0 {
		t.Fatal("the module declares no parameters, so every key is undeclared and this test " +
			"cannot distinguish anything")
	}

	for _, params := range []map[string]any{
		{"applicationId": app.ID, "repoUrl": "https://code.example.test/x/y"},
		{"applicationId": app.ID, "ecsCpu": 1024},
		{"applicationId": app.ID, "databaseType": "postgres"},
		{"applicationId": app.ID, "bucketName": "somebody-elses-bucket"},
	} {
		if err := m.Validate(params); err == nil {
			t.Errorf("Validate accepted undeclared parameters: %v", params)
		}
		if _, err := m.Execute(context.Background(), "", params); err == nil {
			t.Errorf("Execute accepted undeclared parameters: %v", params)
		}
	}
	for _, params := range []map[string]any{
		{},
		{"applicationId": ""},
		{"applicationId": "   "},
		{"applicationId": 7},
		{"applicationId": nil},
	} {
		if err := m.Validate(params); err == nil {
			t.Errorf("Validate accepted %v", params)
		}
	}
	// And the other direction, or the cases above are satisfied by a Validate
	// that refuses everything.
	if err := m.Validate(map[string]any{"applicationId": app.ID}); err != nil {
		t.Errorf("the declared parameter was refused: %v", err)
	}
	if store.saves != 0 {
		t.Errorf("a refused invocation wrote the record %d time(s)", store.saves)
	}
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("a refused invocation created %d resource(s): %v", len(r), r)
	}
}

// TestTheModuleReportsStableMetadata. The identifier is persisted on request
// rows and used as a queue job type in the system this was ported from, so
// changing it orphans stored work.
func TestTheModuleReportsStableMetadata(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestModule(t, newTestProvider(t), newMemStore(), testConfig())
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	for name, got := range map[string]string{
		"Name":        m.Name(),
		"Description": m.Description(),
		"Icon":        m.Icon(),
		"Category":    m.Category(),
	} {
		if got == "" {
			t.Errorf("%s is empty; a caller listing modules has nothing to show", name)
		}
	}
}
