// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

type recordedProvisioner struct {
	appID, appName, appURL string
	alias, targetURL       string
	appCalls, linkCalls    int
	deleteCalls            int
	err, deleteErr         error
}

func (p *recordedProvisioner) ProvisionApplication(_ context.Context, id, name, url string) error {
	p.appID, p.appName, p.appURL = id, name, url
	p.appCalls++
	return p.err
}

func (p *recordedProvisioner) ProvisionGoLink(_ context.Context, id, alias, url string) error {
	p.appID, p.alias, p.targetURL = id, alias, url
	p.linkCalls++
	return p.err
}

func (p *recordedProvisioner) DeleteApplication(_ context.Context, id string) error {
	p.appID = id
	p.deleteCalls++
	return p.deleteErr
}

func enableProvisionFlag(t *testing.T, f *workerFixture, key string) {
	t.Helper()
	putWorkerRecord(t, f.repo, cp.RecordID{Kind: cp.FeatureFlagKind, ID: key}, cp.FeatureFlagRecord{ID: key, Mode: cp.FeatureFlagOn})
}

func TestProvisionDeploymentIndependentWorkspaceToggles(t *testing.T) {
	for _, tc := range []struct {
		name, flag        string
		wantApp, wantLink int
	}{
		{"app only", cp.FeatureProvisionAppCatalog, 1, 0},
		{"golink only", cp.FeatureProvisionShortLink, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWorkerFixture(t)
			provider := &recordedProvisioner{}
			f.d.provisioner = provider
			enableProvisionFlag(t, f, tc.flag)
			app := f.app
			app.Application.Routes = []deploy.Route{{Hostname: "test-app", Internal: true}}
			target := f.d.targets[app.TargetID]
			target.DeployConfig.InternalRouteDomain = "internal.example.test"
			if err := f.d.provisionDeployment(t.Context(), app, target); err != nil {
				t.Fatal(err)
			}
			if provider.appCalls != tc.wantApp || provider.linkCalls != tc.wantLink {
				t.Fatalf("calls app=%d golink=%d, want %d/%d", provider.appCalls, provider.linkCalls, tc.wantApp, tc.wantLink)
			}
			if tc.wantApp != 0 && (provider.appID != app.ID || provider.appName != app.Input.Name || provider.appURL != "https://test-app.internal.example.test") {
				t.Fatalf("application catalog identity/URL = %+v", provider)
			}
			if tc.wantLink != 0 && (provider.appID != app.ID || provider.alias != app.Input.Name || provider.targetURL != "https://test-app.internal.example.test") {
				t.Fatalf("GoLink alias/URL = %+v", provider)
			}
		})
	}
}

func TestProvisionDeploymentDisabledDoesNotCallUnconfiguredC1(t *testing.T) {
	f := newWorkerFixture(t)
	if err := f.d.provisionDeployment(t.Context(), f.app, f.d.targets[f.app.TargetID]); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionDeploymentRefusesMissingCredentialsAndURL(t *testing.T) {
	f := newWorkerFixture(t)
	enableProvisionFlag(t, f, cp.FeatureProvisionShortLink)
	if err := f.d.provisionDeployment(t.Context(), f.app, f.d.targets[f.app.TargetID]); err == nil {
		t.Fatal("enabled integration succeeded without credentials")
	}
	f.d.provisioner = &recordedProvisioner{}
	if err := f.d.provisionDeployment(t.Context(), f.app, f.d.targets[f.app.TargetID]); err == nil {
		t.Fatal("golink provisioning accepted an application without a URL")
	}
}

func TestProvisionDeploymentNamesTheApplicationStage(t *testing.T) {
	f := newWorkerFixture(t)
	enableProvisionFlag(t, f, cp.FeatureProvisionAppCatalog)
	sentinel := errors.New("upstream unavailable")
	f.d.provisioner = &recordedProvisioner{err: sentinel}

	err := f.d.provisionDeployment(t.Context(), f.app, f.d.targets[f.app.TargetID])
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the sentinel via errors.Is", err)
	}
	if !strings.Contains(err.Error(), "provision external application") {
		t.Fatalf("error = %v, want the failing stage named", err)
	}
}

func TestProvisionDeploymentNamesTheGoLinkStage(t *testing.T) {
	f := newWorkerFixture(t)
	enableProvisionFlag(t, f, cp.FeatureProvisionShortLink)
	app := f.app
	app.Application.Routes = []deploy.Route{{Hostname: "test-app", Internal: true}}
	target := f.d.targets[app.TargetID]
	target.DeployConfig.InternalRouteDomain = "internal.example.test"
	sentinel := errors.New("upstream unavailable")
	f.d.provisioner = &recordedProvisioner{err: sentinel}

	err := f.d.provisionDeployment(t.Context(), app, target)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the sentinel via errors.Is", err)
	}
	if !strings.Contains(err.Error(), "provision GoLink") {
		t.Fatalf("error = %v, want the failing stage named", err)
	}
}

func TestProvisionDeploymentFailurePreventsFalseSuccess(t *testing.T) {
	f := newWorkerFixture(t)
	enableProvisionFlag(t, f, cp.FeatureProvisionAppCatalog)
	f.d.provisioner = &recordedProvisioner{err: errors.New("upstream unavailable")}
	operation, ctx := f.claim(t)
	f.d.execute(ctx, operation)
	dep := f.deployment(t)
	if dep.State != cp.Failed || dep.ErrorCode != "external_provisioning_failed" || f.application(t).LastSuccessfulDeploymentID != "" {
		t.Fatalf("partial deployment misreported as ready: %+v", dep)
	}
}
