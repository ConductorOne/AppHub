// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
)

// The reproductions from the round-one review of #42, at the reviewer's own
// entry point.
//
// They are here as a named group rather than folded into the property tests
// that now cover their classes, because a regression test for a reported defect
// is the reporter's reproduction and not a tighter one the author found
// convenient. The property tests are what stop the next instance; these are
// what prove the reported ones are closed.
//
// All four were one shape: **validation happened after mutation began, so a
// rejected plan partially applied.** The reviewer measured `saves=2` and four
// or five rendered resources on each. Every assertion below therefore checks
// the same two things — the record was never written, and the substrate is
// empty — and not merely that an error came back.

// TestReviewStandardBucketWithAZoneIsRefusedBeforeMutation.
//
// Reviewer: "invalid application reached provider: saves=2 rendered=4
// error=fake: bucket ... names zone ... but is not zonal".
func TestReviewStandardBucketWithAZoneIsRefusedBeforeMutation(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{Kind: BucketStandard, Zone: "zone-a"}
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a standard bucket carrying a zone was deployed")
	}
	errIs(t, err, ErrInvalidApplication, "the refusal")
	if !strings.Contains(err.Error(), "Bucket.Zone") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("the reviewer measured rendered=4; this run rendered %d: %v", len(r), r)
	}
	if store.saves != 0 {
		t.Errorf("the reviewer measured saves=2; this run saved %d times", store.saves)
	}
}

// TestReviewAnUndefinedBucketAccessLevelIsRefusedBeforeMutation.
//
// Reviewer: "saves=2 rendered=5 error=fake: access level \"owner\" is not one
// this interface defines". The previous form refused only the admin level and
// accepted every other string.
func TestReviewAnUndefinedBucketAccessLevelIsRefusedBeforeMutation(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	app := testApplication()
	app.Bucket = Bucket{Kind: BucketStandard, Access: compute.AccessLevel("owner")}
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())

	_, err := m.Execute(context.Background(), "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("an undefined access level was deployed")
	}
	errIs(t, err, ErrInvalidApplication, "the refusal")
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("the refusal does not name the level: %v", err)
	}
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("the reviewer measured rendered=5; this run rendered %d: %v", len(r), r)
	}
	if store.saves != 0 {
		t.Errorf("the reviewer measured saves=2; this run saved %d times", store.saves)
	}
}

// TestReviewARouteCannotTargetAPortTheWorkloadDoesNotDeclare.
//
// Reviewer: "saves=2 rendered=5 error=fake: service ... route 0 targets port
// 9090, which the workload does not declare".
//
// This one is not closed by a check, and that is why the assertion looks
// different from the two above: the field is gone. This module declares exactly
// one port, so a settable route target offered a choice the model could not
// honour. Asserting the absence of the field is asserting the construction —
// there is no value anybody can set, so there is nothing to validate and
// nothing to get wrong later.
func TestReviewARouteCannotTargetAPortTheWorkloadDoesNotDeclare(t *testing.T) {
	t.Parallel()
	rt := reflect.TypeOf(Route{})
	if _, exists := rt.FieldByName("TargetPort"); exists {
		t.Fatal("Route has a TargetPort again. A single-workload single-port model has exactly " +
			"one target, so a settable one is a choice this module cannot honour; if the model " +
			"has grown more ports, the field needs validating against them and this test needs " +
			"replacing with that check rather than deleting")
	}
	if rt.NumField() == 0 {
		t.Fatal("Route has no fields, so the assertion above is vacuous")
	}

	// And the route that is produced targets the application's own port, which
	// is what makes the absence safe rather than merely tidy.
	app := testApplication()
	app.Port = 8080
	p := planFor(t, app)
	if len(p.Routes) != 1 {
		t.Fatalf("planned %d routes, want 1", len(p.Routes))
	}
	if p.Routes[0].TargetPort != app.Port {
		t.Errorf("route targets port %d, want the application's own %d",
			p.Routes[0].TargetPort, app.Port)
	}
	declared := p.Service(resolved{}).Ports
	if len(declared) != 1 || declared[0].Number != app.Port {
		t.Errorf("the workload declares %+v, which the route target has to match", declared)
	}
}

// TestReviewASecretTheProviderHoldsCanBeBoundThroughTheSupportedInput.
//
// Reviewer: the public input was a list of names documented as "already held in
// the provider under the application's scope", and the execution path could not
// resolve one — "Execute refused it ... with identity/image/repository refs",
// after three resources existed.
//
// The input is now a provider-issued reference, which is resolvable by
// construction. This drives the reviewer's scenario with no private state
// injected: a secret really put into the provider, referenced only through the
// supported application input.
func TestReviewASecretTheProviderHoldsCanBeBoundThroughTheSupportedInput(t *testing.T) {
	t.Parallel()
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
	stored, err := secrets.Put(ctx, compute.SecretSpec{
		Name:  "API_TOKEN",
		Scope: app.ID,
		Value: compute.NewSecretValue("token-material"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref

	// The supported input, and nothing else. Artifacts.Secrets stays empty:
	// that is record output, and the reviewer's point was that the previous
	// positive test only worked by copying a ref into it by hand.
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref}}
	if !app.Artifacts.Secrets["API_TOKEN"].IsZero() {
		t.Fatal("the fixture pre-populated the artifact map, which is what made the old test " +
			"pass without the input working")
	}

	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a secret the provider holds could not be bound through the supported input: %v", err)
	}
	subs := strings.Join(rendered(t, p), "\n")
	if !strings.Contains(subs, "API_TOKEN") {
		t.Errorf("the workload did not receive the secret:\n%s", subs)
	}
	if strings.Contains(subs, "token-material") {
		t.Errorf("the value reached the substrate rendering:\n%s", subs)
	}
}

// --- round two ---------------------------------------------------------------

// TestReviewRoundTwoADeletedSecretIsRefusedBeforeMutation.
//
// Reviewer: "invalid record was refused only after mutation: saves=2 rendered=2
// ([image-repository ... identity ...]), error=... secret ... does not exist".
//
// A genuine provider-issued reference to a secret somebody has since deleted.
// The plan can establish everything about the reference's SHAPE and nothing
// about its truth; compute.SecretStore.Describe is the metadata read that makes
// the difference, and the preflight runs before the first save.
func TestReviewRoundTwoADeletedSecretIsRefusedBeforeMutation(t *testing.T) {
	t.Parallel()
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

	// The operator transition: the secret is deleted after the record was
	// written and before this deploy runs.
	if err := secrets.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, testConfig())
	_, err = m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a binding to a deleted secret was deployed")
	}
	errIs(t, err, compute.ErrNotFound, "the refusal")
	if r := rendered(t, p); len(r) != 0 {
		t.Errorf("the reviewer measured rendered=2; this run rendered %d: %v", len(r), r)
	}
	if store.saves != 0 {
		t.Errorf("the reviewer measured saves=2; this run saved %d times", store.saves)
	}
}

// TestReviewRoundTwoASecretInAnotherPlacementIsRefusedBeforeMutation.
//
// Reviewer: "saves=2 rendered=3 ([image-repository ... secret API_TOKEN ...
// identity ...]), error=... secret in placement \"secondary\" and workload in
// \"default\"".
//
// Rendered counts below are one, not zero, and the one is the secret the test
// itself stored: a deploy that creates nothing still runs in a substrate that
// already holds the fixture. What matters is that no resource this DEPLOY would
// create exists and the record was never written.
func TestReviewRoundTwoASecretInAnotherPlacementIsRefusedBeforeMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{
		Name:                planFixtureProvider,
		Placements:          []string{"default", "secondary"},
		ObservationsToReady: 1,
	})
	app := testApplication()
	app.Database = Database{}
	app.Bucket = Bucket{}
	app.Routes = nil

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	// The operator transition: the secret lives somewhere the workload does not.
	stored, err := secrets.Put(ctx, compute.SecretSpec{
		Name:      "API_TOKEN",
		Scope:     app.ID,
		Placement: compute.Placement{Name: "secondary"},
		Value:     compute.NewSecretValue("token-material"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref}}

	cfg := testConfig()
	cfg.Placement = compute.Placement{Name: "default"}
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, cfg)

	_, err = m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a binding to a secret in another placement was deployed")
	}
	errIs(t, err, ErrInvalidApplication, "the refusal")
	for _, want := range []string{"secondary", "default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name placement %q: %v", want, err)
		}
	}
	if r := rendered(t, p); len(r) != 1 {
		t.Errorf("the reviewer measured rendered=3; this run rendered %d beyond the fixture "+
			"secret: %v", len(r)-1, r)
	}
	if store.saves != 0 {
		t.Errorf("the reviewer measured saves=2; this run saved %d times", store.saves)
	}

	// The control: the same secret in the workload's own placement deploys.
	// Without it this case is satisfied by a module that refuses all bindings.
	p2 := fake.New(fake.NewStore(), fake.Config{
		Name: planFixtureProvider, Placements: []string{"default", "secondary"},
		ObservationsToReady: 1,
	})
	secrets2, err := p2.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	good := testApplication()
	good.Database = Database{}
	good.Bucket = Bucket{}
	good.Routes = nil
	stored2, err := secrets2.Put(ctx, compute.SecretSpec{Name: "API_TOKEN", Scope: good.ID,
		Placement: compute.Placement{Name: "default"},
		Value:     compute.NewSecretValue("token-material")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref2 := stored2.Ref
	good.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref2}}
	m2, _, _ := newTestModule(t, p2, newMemStore(good), cfg)
	if _, err := m2.Execute(ctx, "", map[string]any{"applicationId": good.ID}); err != nil {
		t.Fatalf("a binding in the workload's own placement was refused: %v", err)
	}
}

// TestAnApplicationBindingSecretsNeedsAConfiguredPlacement is the other half of
// how the placement case is closed: with no configured placement there is no
// name to compare a binding against, so the deploy is refused before anything is
// created rather than compared against a resolved name after something is.
//
// It is a real restriction on an operator — a deployment that binds secrets a
// SCOPED store holds must name its placement — and it is stated so that the
// restriction is visible rather than discovered. It applies only to a scoped
// store: [TestAGlobalStoreNeedsNoConfiguredPlacement] is the other side, and
// requiring a placement unconditionally would have imposed configuration on AWS
// deployments to satisfy a check that can never fire on them.
func TestAnApplicationBindingSecretsNeedsAConfiguredPlacement(t *testing.T) {
	t.Parallel()
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

	cfg := testConfig()
	cfg.Placement = compute.Placement{} // the provider's default, whatever it is
	store := newMemStore(app)
	m, _, _ := newTestModule(t, p, store, cfg)
	_, err = m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("an application binding secrets deployed with no configured placement")
	}
	errIs(t, err, ErrNotConfigured, "the refusal")
	if !strings.Contains(err.Error(), "Placement") {
		t.Errorf("the refusal does not name what to configure: %v", err)
	}
	if r := rendered(t, p); len(r) != 1 {
		t.Errorf("%d resource(s) beyond the fixture secret were created: %v", len(r)-1, r)
	}
	if store.saves != 0 {
		t.Errorf("the record was written %d time(s)", store.saves)
	}

	// And the control, twice over: the same application deploys with a
	// placement configured, and an application with NO bindings deploys without
	// one — so the requirement is about bindings and not about placement.
	cfg.Placement = compute.Placement{Name: "default"}
	m2, _, _ := newTestModule(t, p, newMemStore(app), cfg)
	if _, err := m2.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("with a placement configured it should deploy: %v", err)
	}
	bare := minimalApplication()
	bareCfg := testConfig()
	bareCfg.Placement = compute.Placement{}
	m3, _, _ := newTestModule(t, newTestProvider(t), newMemStore(bare), bareCfg)
	if _, err := m3.Execute(ctx, "", map[string]any{"applicationId": bare.ID}); err != nil {
		t.Fatalf("an application with no bindings should not need a placement: %v", err)
	}
}

// TestAGlobalStoreNeedsNoConfiguredPlacement is the reproduction from round
// three of review, from the deploy module's side.
//
// The AWS store described every secret as living in the provider's DEFAULT
// placement while Put accepted any configured one, so a deployment to a second
// placement would have had its own secret refused as cross-placement. The store
// now reports that placement does not constrain binding at all, and this asserts
// the deploy module believes it: no configured placement is required, and no
// comparison is made.
func TestAGlobalStoreNeedsNoConfiguredPlacement(t *testing.T) {
	t.Parallel()
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

	// The fake places secrets, so it reports scoped. Wrapping it to report
	// global is how a store like AWS's answers, and the module must then require
	// nothing and compare nothing.
	global := &globalPlacementStore{SecretStore: secrets}
	cfg := testConfig()
	cfg.Placement = compute.Placement{} // deliberately unset
	m, _, _ := newTestModule(t, &countingProvider{Provider: p, secrets: global}, newMemStore(app), cfg)
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a global store required a configured placement: %v", err)
	}
	if global.describes == 0 {
		t.Error("the preflight never asked the store about the binding, so this test is " +
			"measuring nothing")
	}

	// And a scope this module cannot interpret is FATAL, not ignored. A provider
	// answering with a value outside the closed set would otherwise have its
	// placement silently unchecked, which is the one outcome the preflight
	// exists to prevent.
	unknown := &globalPlacementStore{SecretStore: secrets, scope: "something-else"}
	m2, _, _ := newTestModule(t, &countingProvider{Provider: p, secrets: unknown}, newMemStore(app), cfg)
	_, err = m2.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a placement scope outside the closed set was accepted")
	}
	errIs(t, err, compute.ErrFailed, "the refusal")
	if !strings.Contains(err.Error(), "something-else") {
		t.Errorf("the refusal does not name the scope it could not interpret: %v", err)
	}
}

// globalPlacementStore reports a placement scope of its own choosing, which is
// how a store whose secrets are account-global answers.
type globalPlacementStore struct {
	compute.SecretStore
	scope     compute.SecretPlacementScope
	describes int
}

func (s *globalPlacementStore) Describe(ctx context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	info, err := s.SecretStore.Describe(ctx, ref)
	if err != nil {
		return nil, err
	}
	s.describes++
	out := *info
	out.PlacementScope = compute.SecretPlacementGlobal
	if s.scope != "" {
		out.PlacementScope = s.scope
	}
	out.Placement = compute.Placement{}
	return &out, nil
}

// The reproduction from the round-four review of #42.
//
// It is the same shape as the four above — a refusal that arrives after mutation
// has begun — in the one binding the preflight did not cover: the administrative
// password this module stores for itself. It is not on [Application.Secrets],
// which is what the plan is built from; it is on [Artifacts.Secrets], where an
// earlier deploy left it, and the preflight now walks both.
//
// The reviewer measured `saves=2` on both halves, with a fresh image built and
// pushed on the first and a new identity, repository and database in a new
// placement on the second — the substrate mutated four resources deep before the
// refusal. So both halves assert the same two things the group above does: the
// second deploy wrote nothing to the record, and it left the substrate exactly
// as the first deploy did.

// TestReviewRoundFourADeletedStoredPasswordIsRefusedBeforeMutation.
//
// Reviewer: "second Execute err = reading back the stored administrative
// password: fake: no secret ...: compute: resource not found / saves delta = 2 /
// image recorded on second run: registry.invalid/...@sha256:...".
//
// The operator transition is the same one the round-two case covers for a
// declared binding — somebody deleted the secret between deploys — reached
// through the reference this module issued rather than one the record declares.
func TestReviewRoundFourADeletedStoredPasswordIsRefusedBeforeMutation(t *testing.T) {
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
	ref := store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword]
	if ref.IsZero() {
		t.Fatal("the first deploy stored no administrative password, so this test is measuring " +
			"nothing")
	}
	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	if err := secrets.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	before := rendered(t, p)
	savedBefore := store.saves
	_, err = m.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("a deploy whose own stored password no longer exists ran to completion")
	}
	errIs(t, err, compute.ErrNotFound, "the refusal")
	// The step names WHEN, which is the whole finding: the reviewer got
	// "relational-database", after the image was built and pushed.
	if !strings.HasPrefix(err.Error(), "secret-preflight: ") {
		t.Errorf("the refusal did not come from the preflight, so it arrived after mutation "+
			"began: %v", err)
	}
	if store.saves != savedBefore {
		t.Errorf("the reviewer measured saves=2; this run saved %d times where the first "+
			"deploy had saved %d", store.saves, savedBefore)
	}
	if after := rendered(t, p); !reflect.DeepEqual(after, before) {
		t.Errorf("the refused deploy changed the substrate: %v then %v", before, after)
	}
}

// TestReviewRoundFourAChangedPlacementIsRefusedBeforeMutation.
//
// Reviewer: "second Execute err = fake: service \"apphub-app-1\": ... secret
// binding 0 refers to a secret in placement \"default\" and the workload is in
// \"secondary\" ... / failed step = \"service\" / saves delta = 2 / rendered:
// 6 (4 before the second run: a new identity, repository and database now exist
// in the new placement)".
//
// Moving an application to another placement is an ordinary operator change,
// and the secret it cannot bring with it is the one this module stored for it.
// Round three closed cross-placement binding "by a construction, not a check" —
// but that construction requires the application to name the placement, and this
// binding is not the application's.
func TestReviewRoundFourAChangedPlacementIsRefusedBeforeMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{
		Name:                planFixtureProvider,
		Placements:          []string{"default", "secondary"},
		ObservationsToReady: 1,
	})
	app := testApplication()
	app.Bucket = Bucket{}
	app.Routes = nil
	store := newMemStore(app)

	cfg := testConfig()
	cfg.Placement = compute.Placement{Name: "default"}
	m, _, _ := newTestModule(t, p, store, cfg)
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if store.saved(app.ID).Artifacts.Secrets[EnvDatabasePassword].IsZero() {
		t.Fatal("the first deploy stored no administrative password, so this test is measuring " +
			"nothing")
	}

	// The operator transition: the same record, the same provider, deployed to
	// the other placement. The stored password stays where it was put.
	moved := cfg
	moved.Placement = compute.Placement{Name: "secondary"}
	m2, _, _ := newTestModule(t, p, store, moved)

	before := rendered(t, p)
	savedBefore := store.saves
	_, err := m2.Execute(ctx, "", map[string]any{"applicationId": app.ID})
	if err == nil {
		t.Fatal("an application was moved to a placement its own stored password cannot be " +
			"bound from")
	}
	errIs(t, err, ErrInvalidApplication, "the refusal")
	if !strings.HasPrefix(err.Error(), "secret-preflight: ") {
		t.Errorf("the refusal did not come from the preflight, so it arrived after mutation "+
			"began: %v", err)
	}
	for _, want := range []string{"default", "secondary", EnvDatabasePassword} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if store.saves != savedBefore {
		t.Errorf("the reviewer measured saves=2; this run saved %d times where the first "+
			"deploy had saved %d", store.saves, savedBefore)
	}
	if after := rendered(t, p); !reflect.DeepEqual(after, before) {
		t.Errorf("the reviewer measured rendered 4 then 6; this run changed the substrate "+
			"from %v to %v", before, after)
	}

	// The control: the same second deploy with the placement left alone runs.
	// Without it both halves are satisfied by a module that refuses every
	// redeploy of an application that holds a secret.
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("a redeploy to the application's own placement was refused: %v", err)
	}
}

// TestEverySecretBindingTheWorkloadReceivesWasPreflighted is the property
// behind the two reproductions above, and the reason they are not three checks.
//
// The defect was not that one binding was missed. It was that the preflight's
// subject set was chosen by hand — "the application's bindings" — while the set
// that actually reaches [compute.ContainerRuntime.EnsureService] is assembled
// somewhere else, from three sources ([Module.workloadInputs]). Any future
// binding added to that assembly escapes the preflight silently, exactly as the
// administrative password did.
//
// So this asserts the relation instead of the membership: every binding the
// workload is created with was either described before the first write, or
// stored by this deploy — in which case it exists, and in this deploy's own
// placement, by construction. A redeploy is the interesting run, because
// nothing is stored on it and every binding must therefore have been described.
func TestEverySecretBindingTheWorkloadReceivesWasPreflighted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newTestProvider(t)
	app := testApplication()

	secrets, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	stored, err := secrets.Put(ctx, compute.SecretSpec{Name: "API_TOKEN", Scope: app.ID,
		Placement: compute.Placement{Name: "default"},
		Value:     compute.NewSecretValue("token-material")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	app.Secrets = []SecretBinding{{EnvName: "API_TOKEN", Secret: ref}}

	recorder := &recordingSecretStore{SecretStore: secrets}
	runtime, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	watched := &recordingContainers{ContainerRuntime: runtime}
	m, _, _ := newTestModule(t, &recordingProvider{
		Provider: p, secrets: recorder, containers: watched,
	}, newMemStore(app), testConfig())

	// The first deploy: a binding is legitimate if it was described OR stored
	// here, since a secret this deploy just wrote exists and is in the
	// placement it was written to.
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if len(watched.bindings) == 0 {
		t.Fatal("the workload was created with no secret bindings, so this test is measuring " +
			"nothing")
	}
	for _, b := range watched.bindings {
		if !recorder.described[b.Secret] && !recorder.put[b.Secret] {
			t.Errorf("the workload binds %q to %s, which the preflight never described and this "+
				"deploy did not store", b.EnvName, b.Secret)
		}
	}

	// The redeploy: nothing is stored, so "described" is the whole of it. This
	// is the run the reported defect fails.
	recorder.reset()
	watched.bindings = nil
	if _, err := m.Execute(ctx, "", map[string]any{"applicationId": app.ID}); err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if len(recorder.put) != 0 {
		t.Errorf("the redeploy stored %d secret(s); it was supposed to adopt what the first "+
			"deploy left, which is what makes the assertion below the whole set",
			len(recorder.put))
	}
	if len(watched.bindings) == 0 {
		t.Fatal("the redeploy created no workload")
	}
	for _, b := range watched.bindings {
		if !recorder.described[b.Secret] {
			t.Errorf("the redeploy binds %q to %s without the preflight ever asking about it, "+
				"so a deleted secret or a changed placement would be found by EnsureService",
				b.EnvName, b.Secret)
		}
	}
}

// recordingProvider substitutes a recording secret store and container runtime.
type recordingProvider struct {
	compute.Provider
	secrets    compute.SecretStore
	containers compute.ContainerRuntime
}

func (p *recordingProvider) Secrets() (compute.SecretStore, error) { return p.secrets, nil }

func (p *recordingProvider) Containers() (compute.ContainerRuntime, error) {
	return p.containers, nil
}

// recordingSecretStore remembers which references were described and which were
// stored, which is the two ways a binding can be legitimate.
type recordingSecretStore struct {
	compute.SecretStore
	described map[compute.Ref]bool
	put       map[compute.Ref]bool
}

func (s *recordingSecretStore) reset() {
	s.described = nil
	s.put = nil
}

func (s *recordingSecretStore) Describe(ctx context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	info, err := s.SecretStore.Describe(ctx, ref)
	if err != nil {
		return nil, err
	}
	if s.described == nil {
		s.described = map[compute.Ref]bool{}
	}
	s.described[ref] = true
	return info, nil
}

func (s *recordingSecretStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	stored, err := s.SecretStore.Put(ctx, spec)
	if err != nil {
		return stored, err
	}
	if s.put == nil {
		s.put = map[compute.Ref]bool{}
	}
	s.put[stored.Ref] = true
	return stored, nil
}

// recordingContainers remembers the bindings a service was created with, which
// is the set the preflight has to have covered.
type recordingContainers struct {
	compute.ContainerRuntime
	bindings []compute.SecretBinding
}

func (c *recordingContainers) EnsureService(ctx context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	c.bindings = append(c.bindings, spec.Secrets...)
	return c.ContainerRuntime.EnsureService(ctx, spec)
}
