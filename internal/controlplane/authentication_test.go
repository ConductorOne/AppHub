// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"errors"
	"reflect"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func boolPtr(b bool) *bool { return &b }

func TestSignInRequiredDefaultsToTrueOnAPublicRoute(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "assistant"}
	app, err := cp.MapApplication("application-id", input, f.target)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Routes) != 1 || !app.Routes[0].RequireAuth {
		t.Fatalf("routes = %+v; an omitted signInRequired must keep today's behavior (auth on)", app.Routes)
	}
}

func TestSignInRequiredFalseTurnsOffRouteAuthAndDropsPublicPathsFromTheRoute(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Exposure = cp.ExposureInput{
		Mode: "public", Hostname: "assistant", SignInRequired: boolPtr(false),
		PublicPaths: []cp.PublicPathInput{{Path: "/healthz", Note: "LB check"}},
	}
	app, err := cp.MapApplication("application-id", input, f.target)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.Routes) != 1 || app.Routes[0].RequireAuth {
		t.Fatalf("routes = %+v; signInRequired=false must turn RequireAuth off", app.Routes)
	}
	if len(app.Routes[0].PublicPaths) != 0 {
		t.Fatalf("routes = %+v; an unauthenticated route must not carry public paths -- they are "+
			"already redundant and modules/deploy's applicability check refuses them", app.Routes)
	}
}

func TestPublicPathsPassThroughToTheRouteWhenSignInIsOn(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Exposure = cp.ExposureInput{
		Mode: "public", Hostname: "assistant",
		PublicPaths: []cp.PublicPathInput{{Path: "/healthz"}, {Path: "/api/webhooks/*", Note: "Stripe"}},
	}
	app, err := cp.MapApplication("application-id", input, f.target)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/healthz", "/api/webhooks/*"}
	if len(app.Routes) != 1 || !app.Routes[0].RequireAuth || !reflect.DeepEqual(app.Routes[0].PublicPaths, want) {
		t.Fatalf("routes = %+v; want RequireAuth true and PublicPaths %v", app.Routes, want)
	}
}

func TestSignInSettingsOnARoutelessPrivateApplicationAreRejected(t *testing.T) {
	f := newServiceFixture(t)
	for name, mutate := range map[string]func(*cp.ExposureInput){
		"signInRequired false": func(e *cp.ExposureInput) { e.SignInRequired = boolPtr(false) },
		"a non-empty publicPaths": func(e *cp.ExposureInput) {
			e.PublicPaths = []cp.PublicPathInput{{Path: "/healthz"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := f.input // mode "private", and this target has no internal ingress
			mutate(&input.Exposure)
			_, err := cp.MapApplication("application-id", input, f.target)
			var problem *cp.Error
			if !errors.As(err, &problem) {
				t.Fatalf("got %v; want a field error", err)
			}
			if problem.FieldErrors["exposure.signInRequired"] == "" && problem.FieldErrors["exposure.publicPaths"] == "" {
				t.Fatalf("field errors = %+v; want exposure.signInRequired or exposure.publicPaths", problem.FieldErrors)
			}
		})
	}
	// An explicit true is the same as the default and is not rejected: it is
	// not a value that "would do nothing" differently from omitting it.
	trueInput := f.input
	trueInput.Exposure.SignInRequired = boolPtr(true)
	if _, err := cp.MapApplication("application-id", trueInput, f.target); err != nil {
		t.Fatalf("explicit signInRequired=true on a routeless private app: %v", err)
	}
}

func TestPublicPathValidationRules(t *testing.T) {
	f := newServiceFixture(t)
	cases := []struct {
		name  string
		paths []cp.PublicPathInput
	}{
		{"empty path", []cp.PublicPathInput{{Path: ""}}},
		{"missing leading slash", []cp.PublicPathInput{{Path: "healthz"}}},
		{"contains a space", []cp.PublicPathInput{{Path: "/health check"}}},
		{"wildcard not trailing", []cp.PublicPathInput{{Path: "/api/*/webhooks"}}},
		{"bare wildcard", []cp.PublicPathInput{{Path: "/*"}}},
		{"disallowed character", []cp.PublicPathInput{{Path: "/health%2e%2e"}}},
		{"empty segment", []cp.PublicPathInput{{Path: "/api//webhooks"}}},
		{"dot-dot segment", []cp.PublicPathInput{{Path: "/api/../secret"}}},
		{"duplicate path", []cp.PublicPathInput{{Path: "/healthz"}, {Path: "/healthz"}}},
		{"path too long", []cp.PublicPathInput{{Path: "/" + string(make([]byte, 256))}}},
		{"note too long", []cp.PublicPathInput{{Path: "/healthz", Note: string(make([]byte, 121))}}},
		{"too many paths", make([]cp.PublicPathInput, 33)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := f.input
			input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "assistant", PublicPaths: tc.paths}
			_, err := cp.MapApplication("application-id", input, f.target)
			var problem *cp.Error
			if !errors.As(err, &problem) || problem.FieldErrors["exposure.publicPaths"] == "" {
				t.Fatalf("got %v; want a field error on exposure.publicPaths", err)
			}
		})
	}
}

func TestValidPublicPathsAreAccepted(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Exposure = cp.ExposureInput{
		Mode: "public", Hostname: "assistant",
		PublicPaths: []cp.PublicPathInput{
			{Path: "/healthz", Note: "LB check"},
			{Path: "/api/webhooks/*", Note: "Stripe"},
			{Path: "/robots.txt"},
		},
	}
	if _, err := cp.MapApplication("application-id", input, f.target); err != nil {
		t.Fatalf("valid public paths were rejected: %v", err)
	}
}

func TestDisablingSignInGoesThroughUpdateApplicationAndKeepsPublicPathsOnTheRecord(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Exposure = cp.ExposureInput{Mode: "public", Hostname: "assistant"}
	app := f.create(t, "create-key")

	off := f.input
	off.Exposure.SignInRequired = boolPtr(false)
	off.Exposure.PublicPaths = []cp.PublicPathInput{{Path: "/healthz", Note: "LB check"}}
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, off, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	// The record's own specification keeps the rule the owner entered, even
	// though it is inert while sign-in is off, so it applies again the
	// moment sign-in is turned back on.
	if len(updated.Specification.Exposure.PublicPaths) != 1 || updated.Specification.Exposure.PublicPaths[0].Path != "/healthz" {
		t.Fatalf("specification.exposure.publicPaths = %+v; want the submitted rule kept", updated.Specification.Exposure.PublicPaths)
	}
	record := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
	if record.Application.Routes[0].RequireAuth {
		t.Fatalf("routes = %+v; want RequireAuth false", record.Application.Routes)
	}
	if len(record.Application.Routes[0].PublicPaths) != 0 {
		t.Fatalf("routes = %+v; want no public paths on the deployed route while sign-in is off", record.Application.Routes)
	}
}
