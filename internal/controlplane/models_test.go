// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package controlplane

import "testing"

func TestHighestRole(t *testing.T) {
	cases := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"empty defaults to member", nil, RoleMember},
		{"unranked candidates default to member", []string{"bogus"}, RoleMember},
		{"a single member match resolves to member", []string{RoleMember}, RoleMember},
		{"a single admin match resolves to admin", []string{RoleAdmin}, RoleAdmin},
		{"admin outranks member", []string{RoleMember, RoleAdmin}, RoleAdmin},
		{"admin outranks app-owner", []string{RoleAppOwner, RoleAdmin}, RoleAdmin},
		{"order does not matter", []string{RoleAdmin, RoleMember, RoleAppOwner}, RoleAdmin},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HighestRole(c.candidates); got != c.want {
				t.Fatalf("HighestRole(%v) = %q, want %q", c.candidates, got, c.want)
			}
		})
	}
}

func TestFeatureFlagRecordGatingGroupIDs(t *testing.T) {
	cases := []struct {
		name string
		rec  FeatureFlagRecord
		want []string
	}{
		{"empty", FeatureFlagRecord{}, nil},
		{"slice", FeatureFlagRecord{GroupEntitlementIDs: []string{"a", "", "b", "a"}}, []string{"a", "b"}},
		{"legacy singular", FeatureFlagRecord{GroupEntitlementID: "legacy"}, []string{"legacy"}},
		{"slice preferred over legacy", FeatureFlagRecord{GroupEntitlementIDs: []string{"a"}, GroupEntitlementID: "legacy"}, []string{"a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.rec.GatingGroupIDs()
			if len(got) != len(c.want) {
				t.Fatalf("GatingGroupIDs() = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("GatingGroupIDs() = %v, want %v", got, c.want)
				}
			}
		})
	}
}
