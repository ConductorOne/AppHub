// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// recordingSealer seals by tagging plaintext with its subject, so a test can
// see what was bound to what without real cryptography.
type recordingSealer struct {
	subjects []cp.SecretSubject
	fail     bool
}

func (r *recordingSealer) Seal(_ context.Context, subject cp.SecretSubject, plaintext []byte) ([]byte, error) {
	if r.fail {
		return nil, errors.New("kms down")
	}
	r.subjects = append(r.subjects, subject)
	return []byte("sealed(" + subject.ApplicationID + "/" + subject.DeploymentID + "/" + subject.Name + ")" + strings.Repeat("*", len(plaintext))), nil
}

func secretFixture(t *testing.T) (*serviceFixture, *recordingSealer, cp.ApplicationView) {
	t.Helper()
	f := newServiceFixture(t)
	sealer := &recordingSealer{}
	service, err := cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{f.target.ID: f.target}, cp.WithSecretSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	return f, sealer, f.create(t, "secret-app")
}

func set(name, value string) cp.SecretChange {
	return cp.SecretChange{Name: name, Action: cp.SecretSet, Value: value}
}
func del(name string) cp.SecretChange { return cp.SecretChange{Name: name, Action: cp.SecretDelete} }

func deploymentRecord(t *testing.T, f *serviceFixture, appID, id string) cp.DeploymentRecord {
	t.Helper()
	return loadValue[cp.DeploymentRecord](t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ParentID: appID, ID: id})
}

func TestSecretChangesSealValuesForTheirDeploymentAndStoreOnlyNames(t *testing.T) {
	f, sealer, app := secretFixture(t)
	accepted, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("STRIPE_KEY", "sk_live_1"), set("API_TOKEN", "tok")}}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	d := deploymentRecord(t, f, app.ID, accepted.DeploymentID)
	if !slices.Equal(d.Application.EnvSecrets, []string{"API_TOKEN", "STRIPE_KEY"}) {
		t.Errorf("deployment binds %v; want both names, sorted", d.Application.EnvSecrets)
	}
	if len(d.SealedSecrets) != 2 {
		t.Fatalf("sealed %d values; want 2", len(d.SealedSecrets))
	}
	for _, s := range sealer.subjects {
		if s.ApplicationID != app.ID || s.DeploymentID != accepted.DeploymentID {
			t.Errorf("value sealed for %+v; want this application's new deployment", s)
		}
	}
	for _, r := range f.repo.Snapshot() {
		if strings.Contains(string(r.Value), "sk_live_1") {
			t.Fatalf("plaintext reached the %s record", r.Kind)
		}
	}
	list, err := f.service.ListSecrets(t.Context(), f.owner, app.ID)
	if err != nil || !list.Available || len(list.Items) != 2 || list.Items[0].Name != "API_TOKEN" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), "sk_live_1") || strings.Contains(string(encoded), "sealed(") {
		t.Fatalf("the list exposed material: %s", encoded)
	}
}

func TestADeleteRemovesTheNameAndAnOrdinaryDeployKeepsTheRest(t *testing.T) {
	f, _, app := secretFixture(t)
	first, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("KEEP", "a"), set("DROP", "b")}}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	finishDeployment(t, f, app.ID, first.DeploymentID)
	second, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{del("DROP")}}, "k2")
	if err != nil {
		t.Fatal(err)
	}
	d := deploymentRecord(t, f, app.ID, second.DeploymentID)
	if !slices.Equal(d.Application.EnvSecrets, []string{"KEEP"}) || len(d.SealedSecrets) != 0 {
		t.Fatalf("delete deployment binds %v with %d sealed values", d.Application.EnvSecrets, len(d.SealedSecrets))
	}
	finishDeployment(t, f, app.ID, second.DeploymentID)
	current, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain := f.submit(t, current, "plain")
	if got := deploymentRecord(t, f, app.ID, plain.DeploymentID).Application.EnvSecrets; !slices.Equal(got, []string{"KEEP"}) {
		t.Fatalf("an ordinary deploy binds %v; want the remaining secret", got)
	}
}

func TestInvalidSecretChangesAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	f, sealer, app := secretFixture(t)
	for name, changes := range map[string][]cp.SecretChange{
		"empty batch":       {},
		"reserved name":     {set("DATABASE_URL", "x")},
		"lowercase name":    {set("stripe", "x")},
		"empty value":       {set("A", "")},
		"oversized value":   {set("A", strings.Repeat("x", 4097))},
		"duplicate name":    {set("A", "x"), set("A", "y")},
		"delete of unknown": {del("NOPE")},
		"delete with value": {{Name: "A", Action: cp.SecretDelete, Value: "x"}},
		"unknown action":    {{Name: "A", Action: "rotate"}},
		"batch over 48 KiB": {set("A", strings.Repeat("x", 4096)), set("B", strings.Repeat("x", 4096)), set("C", strings.Repeat("x", 4096)), set("D", strings.Repeat("x", 4096)), set("E", strings.Repeat("x", 4096)), set("F", strings.Repeat("x", 4096)), set("G", strings.Repeat("x", 4096)), set("H", strings.Repeat("x", 4096)), set("I", strings.Repeat("x", 4096)), set("J", strings.Repeat("x", 4096)), set("K", strings.Repeat("x", 4096)), set("L", strings.Repeat("x", 4096)), set("M", strings.Repeat("x", 1))},
	} {
		_, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: changes}, "bad-"+name)
		requireProblem(t, err, 422, "invalid_secret")
		var problem *cp.Error
		errors.As(err, &problem)
		if strings.Contains(problem.Message+strings.Join(mapValues(problem.FieldErrors), " "), "xxxx") {
			t.Errorf("%s: a value reached the error", name)
		}
	}
	if len(sealer.subjects) != 0 || countKind(f.repo, cp.DeploymentKind) != 0 {
		t.Fatal("a refused batch sealed or recorded something")
	}
}

func TestSecretChangesFollowTheDeploymentRules(t *testing.T) {
	f, _, app := secretFixture(t)
	changes := []cp.SecretChange{set("A", "x")}
	_, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision + 1, Changes: changes}, "stale")
	requireProblem(t, err, 409, "")
	_, err = f.service.DeploySecretChanges(t.Context(), f.other, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: changes}, "stranger")
	requireProblem(t, err, 404, "")

	first, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: changes}, "once")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: changes}, "once")
	if err != nil || replay.DeploymentID != first.DeploymentID {
		t.Fatalf("replay = %+v, %v; want the original deployment", replay, err)
	}
	_, err = f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("B", "y")}}, "while-active")
	requireProblem(t, err, 409, "")
}

func TestSecretChangesAreUnavailableWithoutASealer(t *testing.T) {
	f := newServiceFixture(t)
	app := f.create(t, "no-sealer")
	list, err := f.service.ListSecrets(t.Context(), f.owner, app.ID)
	if err != nil || list.Available || list.Items == nil {
		t.Fatalf("list = %+v, %v; want an empty, unavailable list", list, err)
	}
	_, err = f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("A", "x")}}, "k")
	requireProblem(t, err, 503, "secrets_unavailable")
}

func TestASealingFailureSavesNothing(t *testing.T) {
	f, sealer, app := secretFixture(t)
	sealer.fail = true
	idempotencyBefore := countKind(f.repo, cp.IdempotencyKind)
	_, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("A", "x")}}, "k")
	requireProblem(t, err, 503, "secrets_unavailable")
	if countKind(f.repo, cp.DeploymentKind) != 0 || countKind(f.repo, cp.IdempotencyKind) != idempotencyBefore {
		t.Fatal("a sealing failure recorded a deployment")
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// finishDeployment stands in for the worker: it marks a deployment succeeded
// and releases the application's active lock.
func finishDeployment(t *testing.T, f *serviceFixture, appID, deploymentID string) {
	t.Helper()
	id := cp.RecordID{Kind: cp.DeploymentKind, ParentID: appID, ID: deploymentID}
	d := loadValue[cp.DeploymentRecord](t, f.repo, id)
	d.State = cp.Succeeded
	d.SealedSecrets = nil
	storeValue(t, f.repo, id, d)
	appRecord := cp.RecordID{Kind: cp.ApplicationKind, ID: appID}
	app := loadValue[cp.ApplicationRecord](t, f.repo, appRecord)
	app.ActiveDeploymentID = ""
	storeValue(t, f.repo, appRecord, app)
}

// succeed records a deployment as the worker would on success, with a built
// image and a resolved commit.
func succeed(t *testing.T, f *serviceFixture, appID, deploymentID string) {
	t.Helper()
	id := cp.RecordID{Kind: cp.DeploymentKind, ParentID: appID, ID: deploymentID}
	d := loadValue[cp.DeploymentRecord](t, f.repo, id)
	d.State = cp.Succeeded
	d.ResolvedCommit = "1234567890abcdef1234567890abcdef12345678"
	d.Artifacts.Image = "registry.example/app@sha256:built"
	storeValue(t, f.repo, id, d)
	appRecord := cp.RecordID{Kind: cp.ApplicationKind, ID: appID}
	app := loadValue[cp.ApplicationRecord](t, f.repo, appRecord)
	app.ActiveDeploymentID = ""
	app.LastSuccessfulDeploymentID = d.ID
	app.LastSuccessfulArtifacts = d.Artifacts
	storeValue(t, f.repo, appRecord, app)
}

func TestASecretChangeReusesTheImageOfTheCurrentRevision(t *testing.T) {
	f, _, app := secretFixture(t)
	first := f.submit(t, app, "build")
	succeed(t, f, app.ID, first.DeploymentID)

	accepted, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: app.Revision, Changes: []cp.SecretChange{set("A", "x")}}, "pin")
	if err != nil {
		t.Fatal(err)
	}
	d := deploymentRecord(t, f, app.ID, accepted.DeploymentID)
	if d.Application.PinnedImage != "registry.example/app@sha256:built" || d.ResolvedCommit != "1234567890abcdef1234567890abcdef12345678" {
		t.Fatalf("pinned image %q commit %q; want the last successful build", d.Application.PinnedImage, d.ResolvedCommit)
	}
}

func TestASecretChangeRebuildsWhenTheRevisionWasNeverDeployed(t *testing.T) {
	f, _, app := secretFixture(t)
	first := f.submit(t, app, "build")
	succeed(t, f, app.ID, first.DeploymentID)
	edited := app.Specification
	edited.Replicas = 1
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, edited, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.service.DeploySecretChanges(t.Context(), f.owner, app.ID, cp.SecretChangesInput{ApplicationRevision: updated.Revision, Changes: []cp.SecretChange{set("A", "x")}}, "rebuild")
	if err != nil {
		t.Fatal(err)
	}
	if d := deploymentRecord(t, f, app.ID, accepted.DeploymentID); d.Application.PinnedImage != "" {
		t.Fatalf("pinned %q across a specification change; want a full build", d.Application.PinnedImage)
	}

	fresh := f.create(t, "never-deployed")
	accepted, err = f.service.DeploySecretChanges(t.Context(), f.owner, fresh.ID, cp.SecretChangesInput{ApplicationRevision: fresh.Revision, Changes: []cp.SecretChange{set("A", "x")}}, "first")
	if err != nil {
		t.Fatal(err)
	}
	if d := deploymentRecord(t, f, fresh.ID, accepted.DeploymentID); d.Application.PinnedImage != "" {
		t.Fatal("pinned an image for an application that never deployed")
	}
}
