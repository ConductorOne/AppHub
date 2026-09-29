// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package controlplane_test

import (
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestPublishedHTTPRouteRequiresPlatformAuth(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "reports"}
	app := f.create(t, "publish")
	stored := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	routes := stored.Application.Routes
	if len(routes) != 1 || !routes[0].RequireAuth || routes[0].Hostname != "reports" || len(routes[0].PublicPaths) != 0 {
		t.Fatalf("published route = %+v", routes)
	}

	f.setDescriptor(t, time.Now().UTC(), f.target.ConfigHash, compute.NewCapabilitySet(compute.CapImageBuild, compute.CapImageRegistry, compute.CapContainerService, compute.CapScheduledJob, compute.CapPlatformIngress))
	targets, err := f.service.ListTargets(t.Context(), f.owner)
	if err != nil || len(targets) != 1 || targets[0].PublicExposure {
		t.Fatalf("public exposure without ingress auth: %+v %v", targets, err)
	}
	_, err = f.service.CreateApplication(t.Context(), f.owner, f.input, "no-proxy")
	requireProblem(t, err, 422, "invalid_specification")
}

func TestPublishedHostnameRemainsOwnedAcrossFailedDeploymentEdits(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "published"}
	app := f.create(t, "original")
	accepted := f.submit(t, app, "attempt")
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID}
	stored := loadValue[cp.ApplicationRecord](t, f.repo, appID)
	depID := cp.RecordID{Kind: cp.DeploymentKind, ParentID: app.ID, ID: accepted.DeploymentID}
	dep := loadValue[cp.DeploymentRecord](t, f.repo, depID)
	dep.State = cp.Failed
	stored.ActiveDeploymentID = ""
	storeValue(t, f.repo, depID, dep)
	storeValue(t, f.repo, appID, stored)
	changed := f.input
	changed.Exposure.Hostname = "replacement"
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(t.Context(), f.other, f.input, "steal-live-host")
	requireProblem(t, err, 409, "hostname_conflict")
	// Returning to a hostname already held by this application is not a conflict.
	updated, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, f.input, updated.Revision)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(t.Context(), f.other, changed, "steal-uncertain-host")
	requireProblem(t, err, 409, "hostname_conflict")
	private := f.input
	private.Exposure = cp.ExposureInput{Mode: "private"}
	if _, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, private, updated.Revision); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(t.Context(), f.other, f.input, "steal-before-removal")
	requireProblem(t, err, 409, "hostname_conflict")
}
