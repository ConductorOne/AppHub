// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// valueStore is a memStore that also carries this deploy's secret values, the
// way the worker's operation store does.
type valueStore struct {
	*memStore
	values map[string]compute.SecretValue
}

func (s *valueStore) EnvSecretValues(_ context.Context, _ string) (map[string]compute.SecretValue, error) {
	return s.values, nil
}

func envSecretApp() *Application {
	app := testApplication()
	app.Secrets = nil
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil
	return app
}

func deployOnce(t *testing.T, m *Module, app *Application) error {
	t.Helper()
	_, err := m.Execute(context.Background(), "u1", map[string]any{"applicationId": app.ID})
	return err
}

func TestAnEnvironmentSecretIsStoredAndBoundByName(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	app.EnvSecrets = []string{"STRIPE_KEY"}
	store := &valueStore{memStore: newMemStore(app), values: map[string]compute.SecretValue{"STRIPE_KEY": compute.NewSecretValue("sk_live_1")}}
	m, _, _ := newTestModule(t, p, store, testConfig())

	if err := deployOnce(t, m, app); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	ref, ok := store.saved(app.ID).Artifacts.Secrets[envSecretPrefix+"STRIPE_KEY"]
	if !ok {
		t.Fatalf("the secret was not recorded; artifacts hold %v", store.saved(app.ID).Artifacts.Secrets)
	}
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	got, err := secrets.Get(context.Background(), ref)
	if err != nil || compute.RevealSecret(got) != "sk_live_1" {
		t.Fatalf("stored value does not match what the owner set (err %v)", err)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "STRIPE_KEY->") {
		t.Errorf("the workload does not bind STRIPE_KEY:\n%s", subs)
	}
	if strings.Contains(subs, "sk_live_1") {
		t.Error("the secret value reached the rendered workload definition")
	}
}

func TestARedeployKeepsAnUnchangedSecretAndDeletesARemovedOne(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	app.EnvSecrets = []string{"KEEP", "DROP"}
	store := &valueStore{memStore: newMemStore(app), values: map[string]compute.SecretValue{
		"KEEP": compute.NewSecretValue("kept"), "DROP": compute.NewSecretValue("dropped"),
	}}
	m, _, _ := newTestModule(t, p, store, testConfig())
	if err := deployOnce(t, m, app); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	dropped := store.saved(app.ID).Artifacts.Secrets[envSecretPrefix+"DROP"]

	next := store.saved(app.ID)
	next.EnvSecrets = []string{"KEEP"}
	store.apps[app.ID] = next
	store.values = nil
	if err := deployOnce(t, m, next); err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	artifacts := store.saved(app.ID).Artifacts.Secrets
	if _, ok := artifacts[envSecretPrefix+"DROP"]; ok {
		t.Error("the removed secret is still recorded")
	}
	secrets, _ := p.Secrets()
	if _, err := secrets.Get(context.Background(), dropped); err == nil {
		t.Error("the removed secret is still stored")
	}
	kept, err := secrets.Get(context.Background(), artifacts[envSecretPrefix+"KEEP"])
	if err != nil || compute.RevealSecret(kept) != "kept" {
		t.Errorf("the unchanged secret did not survive a redeploy without a value (err %v)", err)
	}
}

func TestAListedSecretWithNoStoredValueIsRefused(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	app.EnvSecrets = []string{"NEVER_SET"}
	m, _, _ := newTestModule(t, p, newMemStore(app), testConfig())
	err := deployOnce(t, m, app)
	if !errors.Is(err, ErrInvalidApplication) || !strings.Contains(err.Error(), "NEVER_SET") {
		t.Fatalf("got %v; want a refusal naming NEVER_SET", err)
	}
}

func TestAValueForAnUnlistedSecretIsRefused(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	store := &valueStore{memStore: newMemStore(app), values: map[string]compute.SecretValue{"STRAY": compute.NewSecretValue("x")}}
	m, _, _ := newTestModule(t, p, store, testConfig())
	if err := deployOnce(t, m, app); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("got %v; want ErrInvalidApplication", err)
	}
}

func TestEnvironmentSecretNames(t *testing.T) {
	t.Parallel()
	for name, ok := range map[string]bool{
		"STRIPE_KEY": true, "_PRIVATE": true, "A1": true,
		"": false, "lower": false, "1LEADING": false, "HAS-DASH": false, strings.Repeat("A", 101): false,
		"PORT": false, "DATABASE_URL": false, "AWS_REGION": false, "APPHUB_TOKEN": false, "ECS_AGENT": false,
		"TABLE_NAME": false, "BUCKET_URI": false,
	} {
		if err := ValidateEnvSecretName(name); (err == nil) != ok {
			t.Errorf("ValidateEnvSecretName(%q) = %v; want ok=%t", name, err, ok)
		}
	}
}

func TestAnEnvironmentSecretCannotShadowAnotherBinding(t *testing.T) {
	t.Parallel()
	app := reachBaseline()
	app.EnvSecrets = []string{"API_TOKEN"}
	if _, err := newPlan(testConfig(), app, planFixtureProvider); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("got %v; want a refusal for a name an existing binding uses", err)
	}
}

func TestAPinnedImageRedeploysWithoutFetchingOrBuilding(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	store := &valueStore{memStore: newMemStore(app)}
	m, fetcher, _ := newTestModule(t, p, store, testConfig())
	if err := deployOnce(t, m, app); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	built := store.saved(app.ID).Artifacts.Image

	next := store.saved(app.ID)
	next.PinnedImage = built
	next.EnvSecrets = []string{"STRIPE_KEY"}
	store.apps[app.ID] = next
	store.values = map[string]compute.SecretValue{"STRIPE_KEY": compute.NewSecretValue("sk_live_2")}
	if err := deployOnce(t, m, next); err != nil {
		t.Fatalf("pinned Execute: %v", err)
	}
	if len(fetcher.seen) != 1 {
		t.Errorf("source fetched %d times; a pinned redeploy must not fetch", len(fetcher.seen))
	}
	got := store.saved(app.ID)
	if got.Artifacts.Image != built {
		t.Errorf("image = %q; want the pinned %q", got.Artifacts.Image, built)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "image="+string(built)) || !strings.Contains(subs, "STRIPE_KEY->") {
		t.Errorf("the service does not run the pinned image with the new secret:\n%s", subs)
	}
}

func TestAPinnedImageWithoutARecordedRepositoryIsRefused(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := envSecretApp()
	app.PinnedImage = "registry.invalid/never-built@sha256:00"
	m, fetcher, _ := newTestModule(t, p, newMemStore(app), testConfig())
	if err := deployOnce(t, m, app); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("got %v; want a refusal", err)
	}
	if len(fetcher.seen) != 0 {
		t.Error("a refused pinned deploy fetched source")
	}
}

func TestAnInternalRouteUsesTheInternalDomainAndCertificate(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.InternalRouteDomain = "internal.apps.example.test"
	cfg.InternalRouteCertificate = "internal-cert"
	app := minimalApplication()
	app.Routes = []Route{{Hostname: "reports", Internal: true, RequireAuth: true}}
	plan, err := newPlan(cfg, app, planFixtureProvider)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].Host != "reports.internal.apps.example.test" || !plan.Routes[0].Internal ||
		plan.Routes[0].TLS == nil || plan.Routes[0].TLS.CertificateRef != "internal-cert" {
		t.Fatalf("routes = %+v", plan.Routes)
	}
	if len(plan.Ingress) != 1 || plan.Ingress[0].From.Kind != compute.PeerPlatformIngress {
		t.Errorf("ingress = %+v; want the platform ingress admitted", plan.Ingress)
	}

	cfg.InternalRouteDomain = ""
	if _, err := newPlan(cfg, app, planFixtureProvider); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("got %v; want an internal route refused without an internal domain", err)
	}
}
