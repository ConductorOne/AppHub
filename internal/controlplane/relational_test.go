// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

func newRelationalFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := newServiceFixture(t)
	f.target.DeployConfig.PostgresRootCertPath = "/operator/aurora-ca.pem"
	var err error
	f.service, err = cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{f.target.ID: f.target})
	if err != nil {
		t.Fatal(err)
	}
	f.setDescriptor(t, time.Now().UTC(), f.target.ConfigHash, compute.NewCapabilitySet(
		compute.CapImageBuild, compute.CapImageRegistry, compute.CapContainerService,
		compute.CapRelationalDatabase, compute.CapSecretStore))
	return f
}

// TestRelationalDefaultsOnCreate covers the fields an omitted relational
// request gets filled in for, so an API/MCP caller who only names a database
// kind does not also have to know an engine, an admin username, or a
// database name -- the same parity [TestKeyValueTableKeys] already covers
// for a key-value table's partition and sort keys.
func TestRelationalDefaultsOnCreate(t *testing.T) {
	tests := []struct {
		name            string
		db              cp.DatabaseInput
		appName         string
		wantEngine      compute.SQLEngine
		wantAdmin       string
		wantDatabase    string
		engineVersion   string // carried through unchanged; version is never defaulted
		wantEngineEqual bool
	}{
		{name: "everything omitted defaults engine, admin and database name", db: cp.DatabaseInput{Kind: deploy.DatabaseRelational, EngineVersion: "16"}, appName: "My Example App", wantEngine: compute.EnginePostgres, wantAdmin: "appuser", wantDatabase: "my_example_app"},
		{name: "app name sanitizes away to nothing falls back to app", db: cp.DatabaseInput{Kind: deploy.DatabaseRelational, EngineVersion: "16"}, appName: "42", wantEngine: compute.EnginePostgres, wantAdmin: "appuser", wantDatabase: "app"},
		{name: "app name that sanitizes to a reserved word falls back to app", db: cp.DatabaseInput{Kind: deploy.DatabaseRelational, EngineVersion: "16"}, appName: "Postgres", wantEngine: compute.EnginePostgres, wantAdmin: "appuser", wantDatabase: "app"},
		{name: "caller-supplied values are kept", db: cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, EngineVersion: "16", DatabaseName: "custom_db", AdminUsername: "custom_admin"}, appName: "My Example App", wantEngine: compute.EnginePostgres, wantAdmin: "custom_admin", wantDatabase: "custom_db"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelationalFixture(t)
			f.input.Name = tc.appName
			db := tc.db
			f.input.Database = &db
			app := f.create(t, "relational-defaults")
			got := app.Specification.Database
			if got.Engine != tc.wantEngine {
				t.Errorf("engine = %q; want %q", got.Engine, tc.wantEngine)
			}
			if got.AdminUsername != tc.wantAdmin {
				t.Errorf("admin username = %q; want %q", got.AdminUsername, tc.wantAdmin)
			}
			if got.DatabaseName != tc.wantDatabase {
				t.Errorf("database name = %q; want %q", got.DatabaseName, tc.wantDatabase)
			}
			if db.Engine != tc.db.Engine || db.AdminUsername != tc.db.AdminUsername || db.DatabaseName != tc.db.DatabaseName {
				t.Fatal("defaulting mutated the caller's input")
			}
		})
	}
}

// TestRelationalDefaultsOnUpdate mirrors [TestKeyValueKeysDefaultOnUpdate]:
// adding a relational database on an update that leaves the fields empty
// gets the same defaults a create does.
func TestRelationalDefaultsOnUpdate(t *testing.T) {
	f := newRelationalFixture(t)
	f.input.Name = "Reporting Service"
	app := f.create(t, "no-database")
	input := f.input
	input.Database = &cp.DatabaseInput{Kind: deploy.DatabaseRelational, EngineVersion: "16"}
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	got := updated.Specification.Database
	if got.Engine != compute.EnginePostgres || got.AdminUsername != "appuser" || got.DatabaseName != "reporting_service" {
		t.Fatalf("database = %+v; want engine postgres, admin appuser, name reporting_service", got)
	}
}

// TestRelationalDefaultsNeverOverwriteExistingCluster guards the reason
// withRelationalDefaults only fills empty fields: an update that left the
// database name and admin username empty again must not change the values
// an already-created cluster is running with, since those are immutable once
// provisioned (see compute/aws/database.go:checkClusterImmutables).
func TestRelationalDefaultsNeverOverwriteExistingCluster(t *testing.T) {
	f := newRelationalFixture(t)
	f.input.Database = &cp.DatabaseInput{
		Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, EngineVersion: "16",
		DatabaseName: "custom_db", AdminUsername: "custom_admin",
	}
	app := f.create(t, "relational-immutable")
	input := f.input
	input.Name = "Renamed App"
	input.Database = &cp.DatabaseInput{Kind: deploy.DatabaseRelational, EngineVersion: "16"}
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	got := updated.Specification.Database
	if got.DatabaseName != "custom_db" || got.AdminUsername != "custom_admin" {
		t.Fatalf("database = %+v; an update that omitted these must not have changed them", got)
	}
}

func TestOwnerRelationalCapacityCannotExceedTarget(t *testing.T) {
	f := newRelationalFixture(t)
	input := f.input
	input.Database = &cp.DatabaseInput{
		Kind: deploy.DatabaseRelational, EngineVersion: "16",
		Capacity: cp.CapacityInput{MinUnits: 128, MaxUnits: 128},
	}
	_, err := f.service.CreateApplication(t.Context(), f.owner, input, "oversized-create")
	requireCapacityRefusal(t, err)

	input.Database.Capacity = cp.CapacityInput{MinUnits: 0.25, MaxUnits: 2}
	app, err := f.service.CreateApplication(t.Context(), f.owner, input, "valid-create")
	if err != nil {
		t.Fatalf("capacity at the default limit: %v", err)
	}

	for _, capacity := range []cp.CapacityInput{
		{MinUnits: 128, MaxUnits: 0},
		{MinUnits: 0.25, MaxUnits: 128},
	} {
		input.Database.Capacity = capacity
		_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
		requireCapacityRefusal(t, err)
	}

	// A policy override raises the approved ceiling without turning off checks.
	f.target.MaxRelationalCapacityUnits = 4
	input.Database.Capacity = cp.CapacityInput{MinUnits: 0.25, MaxUnits: 4}
	if _, err := cp.MapApplication("custom", input, f.target); err != nil {
		t.Fatalf("operator-approved capacity: %v", err)
	}
	input.Database.Capacity.MaxUnits = 4.25
	_, err = cp.MapApplication("custom", input, f.target)
	requireCapacityRefusal(t, err)
}

func requireCapacityRefusal(t *testing.T, err error) {
	t.Helper()
	var problem *cp.Error
	if !errors.As(err, &problem) || problem.Status != 422 || problem.FieldErrors["database.capacity"] == "" {
		t.Fatalf("capacity refusal = %v; want 422 on database.capacity", err)
	}
}
