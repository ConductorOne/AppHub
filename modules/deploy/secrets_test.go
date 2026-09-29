// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/workload"
)

// binderWith returns a binder over a fake provider holding one secret called
// "KNOWN", plus the reference it was issued.
func binderWith(t *testing.T, cfg Config) (*secretBinder, compute.Ref) {
	t.Helper()
	p := newTestProvider(t)
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	b := newSecretBinder(p.Name(), store, cfg, "app-1")
	ref, err := b.put(context.Background(), "KNOWN", compute.NewSecretValue("material"), nil)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	return b, ref
}

// TestTheConversionRefusesEveryReferenceItCannotHonour derives its population
// from [credentials.SecretRef] itself: for every field, there is a value the
// conversion must refuse, and a field added to that type with no case here
// fails the count.
//
// The conversion is normative — the workload-identity contract assigns it to
// this layer and to nobody else — so the thing worth testing is not that it
// works on a good reference but that it never quietly produces a binding that
// is subtly not what the credential layer asked for.
func TestTheConversionRefusesEveryReferenceItCannotHonour(t *testing.T) {
	t.Parallel()
	cfg := testConfig()

	cases := []struct {
		name string
		// field is the SecretRef field this case is about, so the coverage
		// check below can be stated over the type rather than over this table.
		field string
		ref   credentials.SecretRef
		// want names a substring the refusal must contain, so a refusal that is
		// right for the wrong reason still fails.
		want string
	}{
		{
			name:  "a store this provider does not back",
			field: "Store",
			ref:   secretRef("some-other-store", "KNOWN", "", "TARGET"),
			want:  "some-other-store",
		},
		{
			name:  "a name this deploy never stored",
			field: "Name",
			ref:   secretRef("fake-store", "NEVER-STORED", "", "TARGET"),
			want:  "NEVER-STORED",
		},
		{
			name:  "no target variable",
			field: "EnvVar",
			ref:   secretRef("fake-store", "KNOWN", "", ""),
			want:  "environment variable",
		},
	}

	// The population: every field of credentials.SecretRef. A field added there
	// without a case here is a way of asking for something this conversion
	// might silently drop.
	rt := reflect.TypeOf(credentials.SecretRef{})
	covered := map[string]bool{
		// Version is the one field with no row here, and it is exempted by name
		// rather than by omission. USOSS-35 gave compute.SecretBinding a version,
		// so a pinned reference is no longer something this conversion cannot
		// honour: it travels through, and the PROVIDER refuses a revision it
		// cannot honour rather than falling back to the current one. That is the
		// property, and it is asserted by
		// TestAPinnedReferenceTravelsThroughToTheProvider (here) and
		// TestAVersionPinnedReferenceReachesTheProviderThroughExecute (end to
		// end). If the field ever stops travelling, those fail; deleting them
		// without a row here fails this count.
		"Version": true,
	}
	for _, c := range cases {
		covered[c.field] = true
	}
	if rt.NumField() == 0 {
		t.Fatal("credentials.SecretRef has no fields, so this test asserts nothing")
	}
	for i := 0; i < rt.NumField(); i++ {
		if name := rt.Field(i).Name; rt.Field(i).IsExported() && !covered[name] {
			t.Errorf("credentials.SecretRef.%s has no case here: a reference can ask for "+
				"something through it and this conversion has never been asked what it does", name)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, _ := binderWith(t, cfg)
			binding, err := b.bind(tc.ref)
			if err == nil {
				t.Fatalf("bound %+v to %+v", tc.ref, binding)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not mention %q, so it does not say what is wrong: %v",
					tc.want, err)
			}
			if binding != (compute.SecretBinding{}) {
				t.Errorf("a refused conversion returned a binding: %+v", binding)
			}
		})
	}

	// The other direction, and without it the table above is satisfied by a
	// conversion that refuses everything.
	b, ref := binderWith(t, cfg)
	binding, err := b.bind(secretRef("fake-store", "KNOWN", "", "TARGET"))
	if err != nil {
		t.Fatalf("a reference this deploy issued was refused: %v", err)
	}
	if binding.EnvName != "TARGET" || binding.Secret != ref {
		t.Errorf("binding = %+v, want TARGET bound to %v", binding, ref)
	}

	// And a reference naming no store at all is the deployment's default store,
	// which is this provider.
	if _, err := b.bind(secretRef("", "KNOWN", "", "TARGET")); err != nil {
		t.Errorf("a reference naming no store was refused: %v", err)
	}
}

// TestAReferenceNamingAStoreIsRefusedWhenNoStoreNameIsConfigured is the
// fail-closed half of [Config.SecretStoreName]: unset must not mean "accept
// anything", because the whole job of the conversion is to establish that the
// named store is the one this provider backs.
func TestAReferenceNamingAStoreIsRefusedWhenNoStoreNameIsConfigured(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.SecretStoreName = ""
	b, _ := binderWith(t, cfg)

	if _, err := b.bind(secretRef("fake-store", "KNOWN", "", "TARGET")); err == nil {
		t.Fatal("a reference naming a store was accepted with no store name configured")
	} else {
		errIs(t, err, ErrNotConfigured, "the refusal")
	}
	// A reference naming no store is still fine: that is the deployment's
	// default, which is this provider by definition.
	if _, err := b.bind(secretRef("", "KNOWN", "", "TARGET")); err != nil {
		t.Errorf("a reference naming no store was refused: %v", err)
	}
}

// TestAPinnedReferenceTravelsThroughToTheProvider is the unit half of what
// replaced the interim refusal.
//
// The conversion does not validate a revision and must not: a revision is
// provider-issued and opaque above the interface, so a check here would be this
// module guessing at another package's vocabulary. What it must do is carry the
// pin through unchanged, because the two failure modes either side of that are
// both silent — dropping it hands the workload the current revision under a
// reference that asked for a different one, and rewriting it hands it a third.
func TestAPinnedReferenceTravelsThroughToTheProvider(t *testing.T) {
	t.Parallel()
	b, ref := binderWith(t, testConfig())

	// Not "1": the assertion has to fail if the conversion substitutes the
	// revision the write happened to create, which for this binder IS "1".
	const pinned = "7"
	binding, err := b.bind(secretRef("fake-store", "KNOWN", pinned, "TARGET"))
	if err != nil {
		t.Fatalf("a pinned reference was refused: %v", err)
	}
	if binding.Version != pinned {
		t.Fatalf("the binding pins revision %q and the reference asked for %q; a pin this "+
			"conversion changes or drops is a workload wired to material the credential "+
			"layer did not authorise", binding.Version, pinned)
	}
	if binding.Secret != ref || binding.EnvName != "TARGET" {
		t.Errorf("binding = %+v, want TARGET bound to %v", binding, ref)
	}

	// And the unpinned case still means "current" rather than some default
	// revision, because an empty version is the only way to say that.
	current, err := b.bind(secretRef("fake-store", "KNOWN", "", "TARGET"))
	if err != nil {
		t.Fatalf("an unpinned reference was refused: %v", err)
	}
	if current.Version != "" {
		t.Errorf("an unpinned reference produced version %q, and a binding that pins a "+
			"revision nobody asked for freezes the next rotation out", current.Version)
	}
}

// TestAVersionPinnedReferenceReachesTheProviderThroughExecute verifies the pin
// at the entry point that matters. A conversion tested only in isolation can be
// correct while nothing calls it — and this test is what the interim refusal
// this replaced was standing in for: before USOSS-35 the only two outcomes here
// were "refuse the pin" and "silently bind the current revision", and the whole
// point of the field is that there is now a third.
//
// Both halves, because either alone passes on the wrong provider:
//
//   - a pin to a revision that EXISTS deploys, and the workload is wired to that
//     revision rather than to the current one; without this half, a provider
//     that refused every pin would pass;
//   - a pin to a revision that does NOT exist fails the deploy, and fails it
//     with compute.ErrNotFound rather than falling back; without this half, a
//     provider that ignored the field would pass.
func TestAVersionPinnedReferenceReachesTheProviderThroughExecute(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)
	m, _, att := newTestModule(t, p, store, testConfig())

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	first, err := secrets.Put(ctx, compute.SecretSpec{Name: "ATTESTATION", Scope: app.ID,
		Value: compute.NewSecretValue("material")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if first.Version == "" {
		t.Fatal("the store reported no revision, so there is no pin to drive this with")
	}
	app.Artifacts.Secrets = map[string]compute.Ref{"ATTESTATION": first.Ref}
	if err := store.SaveApplication(ctx, app); err != nil {
		t.Fatalf("SaveApplication: %v", err)
	}

	// Control first: unpinned, the material deploys.
	att.materials = workload.Materials{Secrets: []credentials.SecretRef{
		secretRef("fake-store", "ATTESTATION", "", "APPHUB_ATTESTATION"),
	}}
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("an unpinned reference did not deploy, so nothing below proves anything: %v", err)
	}

	// Rotate, so that the pin below names a revision that is NOT the current
	// one. Pinning the latest revision would pass against a provider that
	// ignored the field entirely.
	rotated, err := secrets.Put(ctx, compute.SecretSpec{Name: "ATTESTATION", Scope: app.ID,
		Value: compute.NewSecretValue("material-rotated")})
	if err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if rotated.Version == first.Version {
		t.Fatalf("the store reported revision %q for a new value as well as the old one, so a "+
			"pin cannot distinguish them", rotated.Version)
	}

	att.materials.Secrets[0].Version = first.Version
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a pin to revision %q, which exists, did not deploy: %v", first.Version, err)
	}
	// The workload is wired to the pinned revision, not the current one. Read
	// off the rendered service, because that is the only place above the
	// interface where "the pin was honoured" is observable at all.
	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	needle := "APPHUB_ATTESTATION->" + first.Ref.String() + "@" + first.Version
	if !slices.ContainsFunc(rendered, func(s string) bool { return strings.Contains(s, needle) }) {
		t.Fatalf("no rendered specification carries %q, so nothing establishes that the "+
			"workload was wired to the pinned revision rather than the current one: %q",
			needle, rendered)
	}

	// And a pin to a revision that does not exist fails the deploy rather than
	// falling back to the current value.
	att.materials.Secrets[0].Version = "99"
	_, err = m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a pin to a revision that does not exist was bound to the current one instead")
	}
	if !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("a pin to an unknown revision answered %v, want compute.ErrNotFound: a caller "+
			"cannot tell a refused pin from a broken deploy otherwise", err)
	}
	if store.saved(app.ID).Status != StatusFailed {
		t.Errorf("the deploy did not record the failure: %+v", store.saved(app.ID).Status)
	}
}

// TestEveryCheckableThingAboutASecretBindingIsCheckedBeforeMutation.
//
// The population is what the plan can establish about a
// [github.com/conductorone/apphub/compute.Ref] without reading credential
// material: it is non-zero, it names a secret, it was issued by the provider
// this deploy is against, and no two bindings claim one variable. Every one is
// refused before the record is marked deploying and before a resource exists.
//
// # The one thing that is not on that list, and why
//
// Whether the secret still EXISTS is not checkable here. SecretStore has Put,
// Get, Delete and DeleteScope, and the only read returns the value — so proving
// a reference resolves would mean pulling credential material through this
// module for no other reason. A reference to a secret somebody deleted is
// therefore refused by the provider when the workload is created, which is a
// partial apply, and it is written up as a follow-up rather than papered over.
// The assertion at the bottom pins that as the CURRENT behaviour so that a
// later provider-side existence check turns this test red rather than passing
// unnoticed.
func TestEveryCheckableThingAboutASecretBindingIsCheckedBeforeMutation(t *testing.T) {
	t.Parallel()
	good := compute.Ref{Provider: planFixtureProvider, Kind: compute.KindSecret, ID: "api-token"}

	cases := map[string]struct {
		bindings []SecretBinding
		want     error
		says     string
	}{
		"a reference this provider did not issue": {
			bindings: []SecretBinding{{EnvName: "API_TOKEN", Secret: compute.Ref{
				Provider: "some-other-provider", Kind: compute.KindSecret, ID: "api-token"}}},
			want: compute.ErrForeignRef,
			says: "some-other-provider",
		},
		"a reference to something that is not a secret": {
			bindings: []SecretBinding{{EnvName: "API_TOKEN", Secret: compute.Ref{
				Provider: planFixtureProvider, Kind: compute.KindBucket, ID: "api-token"}}},
			want: ErrInvalidApplication,
			says: string(compute.KindBucket),
		},
		"no reference at all": {
			bindings: []SecretBinding{{EnvName: "API_TOKEN"}},
			want:     ErrInvalidApplication,
			says:     "names no secret",
		},
		"no target variable": {
			bindings: []SecretBinding{{Secret: good}},
			want:     ErrInvalidApplication,
			says:     "names no environment variable",
		},
		"two bindings claiming one variable": {
			bindings: []SecretBinding{{EnvName: "API_TOKEN", Secret: good}, {EnvName: "API_TOKEN", Secret: good}},
			want:     ErrInvalidApplication,
			says:     "already binds it",
		},
		"a variable this module sets itself": {
			bindings: []SecretBinding{{EnvName: EnvDatabaseHost, Secret: good}},
			want:     ErrInvalidApplication,
			says:     EnvDatabaseHost,
		},
		"the database password this module binds": {
			bindings: []SecretBinding{{EnvName: EnvDatabasePassword, Secret: good}},
			want:     ErrInvalidApplication,
			says:     EnvDatabasePassword,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newTestProvider(t)
			app := testApplication()
			app.Secrets = tc.bindings
			store := newMemStore(app)
			m, _, _ := newTestModule(t, p, store, testConfig())

			_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
			if err == nil {
				t.Fatal("deployed")
			}
			errIs(t, err, tc.want, "the refusal")
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal does not say what is wrong: %v", err)
			}
			// The half that matters: refused BEFORE anything happened.
			//
			// This is the property, and it is asserted at the entry point that
			// matters. It does NOT establish which layer refused: the preflight
			// asks the provider about every binding, so a provider that answers
			// ErrForeignRef would produce the same observable outcome as this
			// module refusing at plan time. TestThePlanItselfRefusesAForeignRef
			// pins the plan-level claim separately, because a mutation removing
			// it was not caught by this test alone.
			if r := rendered(t, p); len(r) != 0 {
				t.Errorf("the refusal came after %d resource(s) were created: %v", len(r), r)
			}
			if store.saves != 0 {
				t.Errorf("the record was written %d time(s) before the refusal", store.saves)
			}
		})
	}

	// The other direction: a well-formed binding to a secret the provider
	// really holds deploys, and the workload receives it. Without this every
	// case above is satisfied by a module that refuses all bindings.
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	stored, err := secrets.Put(ctx, compute.SecretSpec{Name: "API_TOKEN", Scope: app.ID,
		Value: compute.NewSecretValue("token-material")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref}}
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a binding to a secret the provider holds was refused: %v", err)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "API_TOKEN") {
		t.Errorf("the workload did not receive the secret:\n%s", subs)
	}
	if strings.Contains(subs, "token-material") {
		t.Errorf("the secret's value reached the substrate rendering:\n%s", subs)
	}

	// A syntactically perfect reference to a secret that is not there. This was
	// the residue round two documented and pinned; a metadata read closed it,
	// and the pin is what made that visible rather than something to remember.
	p2 := newTestProvider(t)
	app2 := testApplication()
	app2.Database = Database{}
	app2.Bucket = Bucket{}
	app2.Routes = nil
	app2.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: compute.Ref{
		Provider: planFixtureProvider, Kind: compute.KindSecret, ID: "never-stored"}}}
	store2 := newMemStore(app2)
	m2, _, _ := newTestModule(t, p2, store2, testConfig())
	_, err = m2.Execute(ctx, "", map[string]any{"applicationId": app2.ID})
	if err == nil {
		t.Fatal("a reference to a secret nobody stored was deployed")
	}
	errIs(t, err, compute.ErrNotFound, "the refusal")
	if r := rendered(t, p2); len(r) != 0 {
		t.Errorf("%d resource(s) were created before the refusal: %v", len(r), r)
	}
	if store2.saves != 0 {
		t.Errorf("the record was written %d time(s) before the refusal", store2.saves)
	}
}

// TestTheSecretPreflightReadsNoMaterial. The preflight is permitted to exist
// because it asks a metadata question; a preflight that reached for Get would
// be pulling every application secret through this module on every deploy.
//
// The instrument is the provider itself: a store that counts what it was asked.
func TestTheSecretPreflightReadsNoMaterial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()
	app.Database = Database{} // no database, so nothing legitimately calls Get
	app.Bucket = Bucket{}
	app.Routes = nil

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	stored, err := secrets.Put(ctx, compute.SecretSpec{Name: "API_TOKEN", Scope: app.ID,
		Value: compute.NewSecretValue("token-material")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref}}

	counted := &countingSecretStore{SecretStore: secrets}
	m, _, _ := newTestModule(t, &countingProvider{Provider: p, secrets: counted}, newMemStore(app), testConfig())
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if counted.describes == 0 {
		t.Error("the deploy never described a binding, so this test is measuring nothing")
	}
	if counted.gets != 0 {
		t.Errorf("the deploy called Get %d time(s) on an application with no database; the "+
			"preflight is a metadata read and must not pull material", counted.gets)
	}
}

// countingProvider substitutes a counting secret store.
type countingProvider struct {
	compute.Provider
	secrets compute.SecretStore
}

func (p *countingProvider) Secrets() (compute.SecretStore, error) { return p.secrets, nil }

// countingSecretStore records which operations a caller reached for.
type countingSecretStore struct {
	compute.SecretStore
	gets      int
	describes int
}

func (s *countingSecretStore) Get(ctx context.Context, ref compute.Ref) (compute.SecretValue, error) {
	s.gets++
	return s.SecretStore.Get(ctx, ref)
}

func (s *countingSecretStore) Describe(ctx context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	s.describes++
	return s.SecretStore.Describe(ctx, ref)
}

// TestThePlanItselfRefusesAForeignRef pins a claim the end-to-end assertions
// cannot distinguish.
//
// [newPlan] refuses a reference issued by another provider, and so does the
// preflight, because Describe answers ErrForeignRef for one. Both refuse before
// mutation, so the two are indistinguishable through Execute — a mutation
// removing the plan-level check was caught by nothing until this existed.
//
// Two reasons the plan-level check is kept rather than left to the provider:
// the refusal names both providers, which a substrate's own error need not; and
// it holds for a provider whose Describe is laxer than compute requires.
func TestThePlanItselfRefusesAForeignRef(t *testing.T) {
	t.Parallel()
	app := testApplication()
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: compute.Ref{
		Provider: "some-other-provider", Kind: compute.KindSecret, ID: "api-token"}}}

	_, err := newPlan(testConfig(), app, planFixtureProvider)
	if err == nil {
		t.Fatal("the plan accepted a reference issued by another provider")
	}
	errIs(t, err, compute.ErrForeignRef, "the refusal")
	for _, want := range []string{"some-other-provider", planFixtureProvider} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name provider %q: %v", want, err)
		}
	}

	// The control: the same binding with this provider's name is planned. A
	// plan that refused every binding would satisfy the case above.
	app.Secrets[0].Secret.Provider = planFixtureProvider
	if _, err := newPlan(testConfig(), app, planFixtureProvider); err != nil {
		t.Fatalf("a reference issued by this provider was refused: %v", err)
	}
}
