// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

func newKeyValueFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := newServiceFixture(t)
	f.setDescriptor(t, time.Now().UTC(), f.target.ConfigHash, compute.NewCapabilitySet(
		compute.CapImageBuild, compute.CapImageRegistry, compute.CapContainerService,
		compute.CapPlatformIngress, compute.CapIngressAuth, compute.CapKeyValueTable,
		compute.CapWorkloadGrants))
	return f
}

func TestKeyValueTableKeys(t *testing.T) {
	tests := []struct {
		name          string
		partition     string
		sort          string
		wantPartition string
		wantSort      string
	}{
		{name: "neither key named defaults both", wantPartition: "pk", wantSort: "sk"},
		{name: "blank partition key defaults both", partition: "  ", wantPartition: "pk", wantSort: "sk"},
		{name: "sort key alone keeps it", sort: "created", wantPartition: "pk", wantSort: "created"},
		{name: "partition key alone means no sort key", partition: "id", wantPartition: "id"},
		{name: "both named are kept", partition: "id", sort: "at", wantPartition: "id", wantSort: "at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newKeyValueFixture(t)
			f.input.Database = &cp.DatabaseInput{Kind: deploy.DatabaseKeyValue, PartitionKey: tt.partition, SortKey: tt.sort}
			app := f.create(t, "key-value")
			got := app.Specification.Database
			if got.PartitionKey != tt.wantPartition || got.SortKey != tt.wantSort {
				t.Fatalf("specification keys = %q/%q; want %q/%q", got.PartitionKey, got.SortKey, tt.wantPartition, tt.wantSort)
			}
			stored := loadValue[cp.ApplicationRecord](t, f.repo, cp.RecordID{Kind: cp.ApplicationKind, ID: app.ID})
			if stored.Application.Database.PartitionKey != tt.wantPartition || stored.Application.Database.SortKey != tt.wantSort {
				t.Fatalf("deployed keys = %q/%q; want %q/%q", stored.Application.Database.PartitionKey,
					stored.Application.Database.SortKey, tt.wantPartition, tt.wantSort)
			}
		})
	}
}

func TestKeyValueKeysDefaultOnUpdate(t *testing.T) {
	f := newKeyValueFixture(t)
	app := f.create(t, "no-database")
	input := f.input
	input.Database = &cp.DatabaseInput{Kind: deploy.DatabaseKeyValue}
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if got := updated.Specification.Database; got.PartitionKey != "pk" || got.SortKey != "sk" {
		t.Fatalf("keys = %q/%q; want pk/sk", got.PartitionKey, got.SortKey)
	}
	if input.Database.PartitionKey != "" {
		t.Fatal("defaulting mutated the caller's input")
	}
}
