// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

func internalTarget(t *testing.T) *serviceFixture {
	t.Helper()
	f := newServiceFixture(t)
	f.target.DeployConfig.InternalRouteDomain = "internal.apps.example"
	f.target.DeployConfig.InternalRouteCertificate = "internal-certificate"
	service, err := cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{f.target.ID: f.target})
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	return f
}

func TestAPrivateServiceIsPublishedOnTheInternalIngressUnderAReservedHostname(t *testing.T) {
	f := internalTarget(t)
	app := f.create(t, "private")
	record := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	want := cp.EffectiveHostname(app.ID, f.input)
	if len(record.Application.Routes) != 1 || !record.Application.Routes[0].Internal || !record.Application.Routes[0].RequireAuth || record.Application.Routes[0].Hostname != want {
		t.Fatalf("routes = %+v; want one authenticated internal route on %q", record.Application.Routes, want)
	}
	reservation := loadValue[cp.HostnameReservation](t, f.repo, cp.RecordID{Kind: cp.HostnameKind, ParentID: f.target.ID, ID: want})
	if reservation.ApplicationID != app.ID {
		t.Fatal("the derived hostname was not reserved")
	}
	if cp.EffectiveHostname(app.ID, f.input) != want {
		t.Fatal("the derived hostname is not stable")
	}

	named := f.input
	named.Exposure.Hostname = "reports"
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, named, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	record = loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: updated.ID})
	if record.Application.Routes[0].Hostname != "reports" {
		t.Fatalf("routes = %+v; want the requested private hostname", record.Application.Routes)
	}
}

func TestAPrivateHostnameIsRefusedWithoutAnInternalIngress(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Exposure.Hostname = "reports"
	_, err := f.service.CreateApplication(t.Context(), f.owner, input, "no-internal")
	requireProblem(t, err, 422, "invalid_specification")

	app := f.create(t, "private-no-internal")
	record := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	if len(record.Application.Routes) != 0 {
		t.Fatalf("routes = %+v; want none without an internal ingress", record.Application.Routes)
	}
}

func TestAPrivateScheduledJobHasNoRoute(t *testing.T) {
	f := internalTarget(t)
	f.input.Execution = deploy.ExecutionScheduled
	f.input.Schedule = &cp.ScheduleInput{Expression: "rate(1 hour)", Timezone: "UTC"}
	if got := cp.EffectiveHostname("id", f.input); got != "" {
		t.Fatalf("a scheduled job got hostname %q", got)
	}
}

func TestTargetsReportInternalExposure(t *testing.T) {
	f := internalTarget(t)
	targets, err := f.service.ListTargets(t.Context(), f.owner)
	if err != nil || len(targets) != 1 || !targets[0].InternalExposure {
		t.Fatalf("targets = %+v, %v; want internal exposure reported", targets, err)
	}
}

func TestTheApplicationViewCarriesItsURLBeforeTheFirstDeploy(t *testing.T) {
	f := internalTarget(t)
	private := f.create(t, "private-url")
	if want := "https://" + cp.EffectiveHostname(private.ID, f.input) + ".internal.apps.example"; private.URL != want || private.URLScope != "internal" {
		t.Fatalf("url %q scope %q; want %q internal", private.URL, private.URLScope, want)
	}
	public := f.input
	public.Exposure = cp.ExposureInput{Mode: "public", Hostname: "reports"}
	view, err := f.service.CreateApplication(t.Context(), f.owner, public, "public-url")
	if err != nil {
		t.Fatal(err)
	}
	if view.URL != "https://reports.apps.example" || view.URLScope != "public" {
		t.Fatalf("url %q scope %q", view.URL, view.URLScope)
	}

	plain := newServiceFixture(t)
	if app := plain.create(t, "no-route"); app.URL != "" || app.URLScope != "" {
		t.Fatalf("an unrouted application reports url %q", app.URL)
	}
}
