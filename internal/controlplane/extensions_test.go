// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

func newRelationalExtensionFixture(t *testing.T) *serviceFixture {
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
	f.input.Database = &cp.DatabaseInput{
		Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, EngineVersion: "16",
		DatabaseName: "appdb", AdminUsername: "appadmin", Extensions: []string{"vector", "pg_trgm"},
	}
	return f
}

func TestInvalidExtensionsDoNotMutateApplication(t *testing.T) {
	f := newRelationalExtensionFixture(t)
	created := f.create(t, "extension-before-update")
	original := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: created.ID})
	cases := []struct {
		name string
		db   cp.DatabaseInput
	}{
		{"unsupported", cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{"dblink"}}},
		{"non-exact", cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{" Vector "}}},
		{"duplicate", cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{"vector", "vector"}}},
		{"mysql", cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EngineMySQL, Extensions: []string{"vector"}}},
		{"key-value", cp.DatabaseInput{Kind: deploy.DatabaseKeyValue, Extensions: []string{"vector"}}},
		{"none", cp.DatabaseInput{Extensions: []string{"vector"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := f.input
			input.Database = &tc.db
			_, err := f.service.UpdateApplication(t.Context(), f.owner, created.ID, input, created.Revision)
			requireProblem(t, err, 422, "invalid_specification")
			current := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: created.ID})
			if current.Revision != original.Revision || !reflect.DeepEqual(current.Input, original.Input) ||
				!reflect.DeepEqual(current.Application, original.Application) {
				t.Fatalf("rejected update changed persisted application: before=%+v after=%+v", original, current)
			}
		})
	}
}
