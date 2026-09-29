// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

// subjectOpener opens "subject|value" ciphertexts only for the subject they
// name, standing in for KMS encryption-context binding.
type subjectOpener struct{}

func sealFor(subject cp.SecretSubject, value string) []byte {
	return []byte(subject.ApplicationID + "/" + subject.DeploymentID + "/" + subject.Name + "|" + value)
}

func (subjectOpener) Open(_ context.Context, subject cp.SecretSubject, ciphertext []byte) (compute.SecretValue, error) {
	prefix, value, ok := strings.Cut(string(ciphertext), "|")
	if !ok || prefix != subject.ApplicationID+"/"+subject.DeploymentID+"/"+subject.Name {
		return compute.SecretValue{}, errors.New("wrong subject")
	}
	return compute.NewSecretValue(value), nil
}

func withSealedSecret(t *testing.T, f *workerFixture, name, value string) {
	t.Helper()
	id := cp.RecordID{Kind: cp.DeploymentKind, ParentID: f.app.ID, ID: f.dep.ID}
	row, err := f.repo.Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	dep, err := cp.Decode[cp.DeploymentRecord](row)
	if err != nil {
		t.Fatal(err)
	}
	dep.Application.EnvSecrets = []string{name}
	dep.SealedSecrets = []cp.SealedSecret{{Name: name, Ciphertext: sealFor(cp.SecretSubject{ApplicationID: f.app.ID, DeploymentID: f.dep.ID, Name: name}, value)}}
	m, err := recordMutation(row, dep)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}
}

func TestASealedSecretIsStoredBoundAndItsCiphertextCleared(t *testing.T) {
	f := newWorkerFixture(t)
	f.d.opener = subjectOpener{}
	withSealedSecret(t, f, "STRIPE_KEY", "sk_live_1")
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)

	dep := f.deployment(t)
	if dep.State != cp.Succeeded {
		t.Fatalf("deployment %s: %s %s", dep.State, dep.ErrorCode, dep.Message)
	}
	if len(dep.SealedSecrets) != 0 {
		t.Error("ciphertext outlived the deployment")
	}
	ref, ok := dep.Artifacts.Secrets["env.STRIPE_KEY"]
	if !ok {
		t.Fatalf("secret not recorded; artifacts %v", dep.Artifacts.Secrets)
	}
	store, err := f.provider.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(ctx, ref)
	if err != nil || compute.RevealSecret(value) != "sk_live_1" {
		t.Fatalf("stored value mismatch (err %v)", err)
	}
	runtime, _ := f.provider.Containers()
	status, err := runtime.DescribeService(ctx, dep.Artifacts.Workload)
	if err != nil {
		t.Fatal(err)
	}
	bound := false
	for _, b := range status.Spec.Secrets {
		bound = bound || (b.EnvName == "STRIPE_KEY" && b.Secret == ref)
	}
	if !bound {
		t.Errorf("the service does not bind STRIPE_KEY to the stored secret: %+v", status.Spec.Secrets)
	}
}

func TestAWorkerWithoutAnOpenerFailsBeforeTouchingTheTarget(t *testing.T) {
	f := newWorkerFixture(t)
	withSealedSecret(t, f, "STRIPE_KEY", "sk_live_1")
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	dep := f.deployment(t)
	if dep.State != cp.Failed || dep.ErrorCode != "secrets_unavailable" || len(dep.SealedSecrets) != 0 {
		t.Fatalf("got %s/%s with %d sealed values; want a clean secrets_unavailable failure", dep.State, dep.ErrorCode, len(dep.SealedSecrets))
	}
	if !dep.Artifacts.Workload.IsZero() {
		t.Error("a workload was created")
	}
}

func TestACiphertextForAnotherDeploymentIsRefused(t *testing.T) {
	f := newWorkerFixture(t)
	f.d.opener = subjectOpener{}
	withSealedSecret(t, f, "STRIPE_KEY", "sk_live_1")
	dep := f.deployment(t)
	dep.SealedSecrets[0].Ciphertext = sealFor(cp.SecretSubject{ApplicationID: f.app.ID, DeploymentID: "other-deploy", Name: "STRIPE_KEY"}, "stolen")
	id := cp.RecordID{Kind: cp.DeploymentKind, ParentID: f.app.ID, ID: f.dep.ID}
	row, _ := f.repo.Read(context.Background(), id)
	m, err := recordMutation(row, dep)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	got := f.deployment(t)
	if got.State != cp.Failed || strings.Contains(got.Message, "stolen") {
		t.Fatalf("got %s: %s; want a failure", got.State, got.Message)
	}
	if store, _ := f.provider.Secrets(); store != nil {
		if ref, ok := got.Artifacts.Secrets["env.STRIPE_KEY"]; ok {
			if v, err := store.Get(ctx, ref); err == nil && compute.RevealSecret(v) == "stolen" {
				t.Fatal("a value sealed for another deployment was stored")
			}
		}
	}
}

func TestAPinnedDeploymentTouchesNoSourceAndRunsThePinnedImage(t *testing.T) {
	f := newWorkerFixture(t)
	f.d.opener = subjectOpener{}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	first := f.deployment(t)
	if first.State != cp.Succeeded {
		t.Fatalf("initial build %s: %s", first.State, first.Message)
	}

	app := f.application(t)
	second := first
	second.ID, second.AttemptID, second.State = "deploy-two", "", cp.Queued
	second.Application = app.Application
	second.Application.PinnedImage = app.LastSuccessfulArtifacts.Image
	second.Application.EnvSecrets = []string{"STRIPE_KEY"}
	second.Artifacts = app.Application.Artifacts
	second.SealedSecrets = []cp.SealedSecret{{Name: "STRIPE_KEY", Ciphertext: sealFor(cp.SecretSubject{ApplicationID: app.ID, DeploymentID: "deploy-two", Name: "STRIPE_KEY"}, "sk_live_2")}}
	putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.DeploymentKind, ParentID: app.ID, ID: second.ID}, second)
	appRow, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	if err != nil {
		t.Fatal(err)
	}
	app.ActiveDeploymentID, app.LatestDeploymentID = second.ID, second.ID
	m, err := recordMutation(appRow, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{m}); err != nil {
		t.Fatal(err)
	}

	f.source.prepare = func(context.Context) error { return errors.New("a pinned deployment prepared source") }
	f.source.beforeFetch = func(deploy.Source) error { return errors.New("a pinned deployment fetched source") }
	f.dep = second
	operation, ctx = f.claim(t)
	f.d.execute(ctx, operation)
	got := f.deployment(t)
	if got.State != cp.Succeeded {
		t.Fatalf("pinned deployment %s: %s %s", got.State, got.ErrorCode, got.Message)
	}
	if got.Artifacts.Image != first.Artifacts.Image || got.ResolvedCommit != first.ResolvedCommit {
		t.Errorf("image %q commit %q; want the pinned %q %q", got.Artifacts.Image, got.ResolvedCommit, first.Artifacts.Image, first.ResolvedCommit)
	}
	runtime, _ := f.provider.Containers()
	status, err := runtime.DescribeService(ctx, got.Artifacts.Workload)
	if err != nil {
		t.Fatal(err)
	}
	if status.Spec.Image != first.Artifacts.Image || len(status.Spec.Secrets) != 1 || status.Spec.Secrets[0].EnvName != "STRIPE_KEY" {
		t.Fatalf("service runs %q with %+v; want the pinned image binding STRIPE_KEY", status.Spec.Image, status.Spec.Secrets)
	}
}
