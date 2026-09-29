// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/testutil"
)

// fakeGroupLookup is a GroupLookup whose response and error are set per
// test and whose call count records how many times it was actually invoked,
// so a test can assert the TTL cache avoided a redundant lookup.
type fakeGroupLookup struct {
	groupIDs []string
	err      error
	calls    int
	block    bool
}

func (f *fakeGroupLookup) ListUserGroupIDs(ctx context.Context, _ string) ([]string, error) {
	f.calls++
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.groupIDs, nil
}

func setRoleMapping(t *testing.T, repo *testutil.Repository, entitlementID, role string) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.RoleMappingKind, ID: entitlementID}, 0, cp.RoleMappingRecord{ID: entitlementID, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}

func setFeatureFlag(t *testing.T, repo *testutil.Repository, key, mode, groupEntitlementID string) {
	t.Helper()
	var ids []string
	if groupEntitlementID != "" {
		ids = []string{groupEntitlementID}
	}
	setFeatureFlagGroups(t, repo, key, mode, ids)
}

func setFeatureFlagGroups(t *testing.T, repo *testutil.Repository, key, mode string, groupIDs []string) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.FeatureFlagKind, ID: key}, 0, cp.FeatureFlagRecord{ID: key, Mode: mode, GroupEntitlementIDs: groupIDs})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}

func setLegacyFeatureFlag(t *testing.T, repo *testutil.Repository, key, mode, groupEntitlementID string) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.FeatureFlagKind, ID: key}, 0, cp.FeatureFlagRecord{ID: key, Mode: mode, GroupEntitlementID: groupEntitlementID})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}

func seedMembershipCache(t *testing.T, repo *testutil.Repository, email string, groupIDs []string, syncedAt time.Time) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.GroupMembershipKind, ID: email}, 0, cp.GroupMembershipRecord{ID: email, GroupIDs: groupIDs, SyncedAt: syncedAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRoleDefaultsToMemberWithoutDirectory(t *testing.T) {
	repo := testutil.NewRepository()
	e := NewEligibility(serverconfig.AuthConfig{}, repo, nil)
	role, vulnAdmin, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleMember || vulnAdmin || len(features) != 0 {
		t.Fatalf("resolveAccess = (%q, %v, %v), want (%q, false, nil) when no directory is configured", role, vulnAdmin, features, cp.RoleMember)
	}
}

func TestResolveRoleDefaultsToMemberWithNoMappingConfigured(t *testing.T) {
	repo := testutil.NewRepository()
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-1"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, _, _ := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleMember {
		t.Fatalf("resolveAccess role = %q, want %q when no role mapping exists", role, cp.RoleMember)
	}
	if lookup.calls != 1 {
		t.Fatalf("resolveAccess skipped the live directory lookup on admission (calls=%d)", lookup.calls)
	}
	cached, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.GroupMembershipKind, ID: "dana@acme.dev"})
	if err != nil {
		t.Fatalf("membership cache was not written: %v", err)
	}
	rec, err := cp.Decode[cp.GroupMembershipRecord](cached)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.GroupIDs) != 1 || rec.GroupIDs[0] != "ent-1" {
		t.Fatalf("cached GroupIDs = %+v, want [ent-1]", rec.GroupIDs)
	}
}

func TestResolveRoleGrantsMappedRoleFromHeldEntitlement(t *testing.T) {
	repo := testutil.NewRepository()
	setRoleMapping(t, repo, "ent-admin", cp.RoleAdmin)
	setRoleMapping(t, repo, "ent-member", cp.RoleMember)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-member", "ent-unrelated"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, _, _ := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleMember {
		t.Fatalf("resolveAccess role = %q, want %q", role, cp.RoleMember)
	}
}

func TestResolveRolePicksHighestRankAmongMultipleHeldGroups(t *testing.T) {
	repo := testutil.NewRepository()
	setRoleMapping(t, repo, "ent-admin", cp.RoleAdmin)
	setRoleMapping(t, repo, "ent-member", cp.RoleMember)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-member", "ent-admin"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, _, _ := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleAdmin {
		t.Fatalf("resolveAccess role = %q, want the higher-ranked %q", role, cp.RoleAdmin)
	}
}

func TestResolveRoleIgnoresGroupsNotMappedToARole(t *testing.T) {
	repo := testutil.NewRepository()
	setRoleMapping(t, repo, "ent-admin", cp.RoleAdmin)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-unrelated"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, _, _ := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleMember {
		t.Fatalf("resolveAccess role = %q, want the default %q for an unmapped group", role, cp.RoleMember)
	}
}

func TestResolveAccessGrantsVulnAdminFromHeldEntitlementAlongsideRole(t *testing.T) {
	repo := testutil.NewRepository()
	setRoleMapping(t, repo, "ent-app-owner", cp.RoleAppOwner)
	setRoleMapping(t, repo, "ent-vuln", cp.RoleVulnAdmin)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-app-owner", "ent-vuln"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, vulnAdmin, _ := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleAppOwner {
		t.Fatalf("role = %q, want %q (vuln-admin must not affect the member/app-owner/admin ladder)", role, cp.RoleAppOwner)
	}
	if !vulnAdmin {
		t.Fatal("vuln-admin entitlement did not grant VulnAdmin")
	}
}

func TestResolveAccessFeatureFlagOff(t *testing.T) {
	repo := testutil.NewRepository()
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-1"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 0 {
		t.Fatalf("features = %v, want none with no flags configured", features)
	}
	if lookup.calls != 1 {
		t.Fatalf("resolveAccess skipped the live directory lookup on admission (calls=%d)", lookup.calls)
	}
}

func TestResolveAccessFeatureFlagOnGrantsEveryIdentity(t *testing.T) {
	repo := testutil.NewRepository()
	setFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagOn, "")
	lookup := &fakeGroupLookup{groupIDs: nil}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("features = %v, want [%s]", features, cp.FeatureVulnerabilities)
	}
	// "on" mode does not consult membership, but admission still warms the cache.
	if lookup.calls != 1 {
		t.Fatalf("resolveAccess skipped the live directory lookup on admission (calls=%d)", lookup.calls)
	}
}

func TestResolveAccessFeatureFlagOnWorksWithNoDirectoryConfiguredAtAll(t *testing.T) {
	// Regression: an "on" flag must take effect even when this deployment
	// has no ConductorOne directory configured (groups is nil, not merely a
	// GroupLookup that happens to return nothing) -- resolveAccess must not
	// treat "no directory" as "ignore feature flags entirely".
	repo := testutil.NewRepository()
	setFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagOn, "")
	e := NewEligibility(serverconfig.AuthConfig{}, repo, nil)
	role, vulnAdmin, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("features = %v, want [%s] with no directory configured at all", features, cp.FeatureVulnerabilities)
	}
	if role != cp.RoleMember || vulnAdmin {
		t.Fatalf("role=%q vulnAdmin=%v, want the untouched defaults", role, vulnAdmin)
	}
}

func TestResolveAccessFeatureFlagGroupModeDisabledWithNoDirectoryConfigured(t *testing.T) {
	// A group-mode flag has no membership signal to check without a
	// directory, so it must resolve to disabled -- not panic on a nil
	// GroupLookup, and not silently enable it either.
	repo := testutil.NewRepository()
	setFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, "ent-security")
	e := NewEligibility(serverconfig.AuthConfig{}, repo, nil)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 0 {
		t.Fatalf("features = %v, want none: a group-mode flag has no directory to check membership against", features)
	}
}

func TestResolveAccessFeatureFlagGroupGatesOnMembership(t *testing.T) {
	repo := testutil.NewRepository()
	setFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, "ent-security")

	inGroup := &fakeGroupLookup{groupIDs: []string{"ent-security"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, inGroup)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("features = %v, want [%s] for a member of the gating group", features, cp.FeatureVulnerabilities)
	}

	outOfGroup := &fakeGroupLookup{groupIDs: []string{"ent-other"}}
	e = NewEligibility(serverconfig.AuthConfig{}, repo, outOfGroup)
	_, _, features = unpack(e.resolveAccess(context.Background(), "milo@acme.dev"))
	if len(features) != 0 {
		t.Fatalf("features = %v, want none for a non-member of the gating group", features)
	}
}

func TestResolveAccessFeatureFlagGroupGatesOnAnyOfMultipleGroups(t *testing.T) {
	repo := testutil.NewRepository()
	setFeatureFlagGroups(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, []string{"ent-security", "ent-eng"})

	inSecond := &fakeGroupLookup{groupIDs: []string{"ent-eng"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, inSecond)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("features = %v, want [%s] for a member of any gating group", features, cp.FeatureVulnerabilities)
	}

	inNeither := &fakeGroupLookup{groupIDs: []string{"ent-other"}}
	e = NewEligibility(serverconfig.AuthConfig{}, repo, inNeither)
	_, _, features = unpack(e.resolveAccess(context.Background(), "milo@acme.dev"))
	if len(features) != 0 {
		t.Fatalf("features = %v, want none for a non-member of every gating group", features)
	}
}

func TestResolveAccessFeatureFlagGroupGatesOnLegacySingularField(t *testing.T) {
	repo := testutil.NewRepository()
	setLegacyFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, "ent-security")
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-security"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	_, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("features = %v, want [%s] for a legacy singular groupEntitlementId record", features, cp.FeatureVulnerabilities)
	}
}

func TestResolveAccessSharesOneMembershipLookupForRoleAndFeatureFlag(t *testing.T) {
	repo := testutil.NewRepository()
	setRoleMapping(t, repo, "ent-admin", cp.RoleAdmin)
	setFeatureFlag(t, repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, "ent-security")
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-admin", "ent-security"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	role, _, features := unpack(e.resolveAccess(context.Background(), "dana@acme.dev"))
	if role != cp.RoleAdmin || len(features) != 1 || features[0] != cp.FeatureVulnerabilities {
		t.Fatalf("role=%q features=%v, want admin + [%s]", role, features, cp.FeatureVulnerabilities)
	}
	if lookup.calls != 1 {
		t.Fatalf("resolveAccess made %d live directory lookups, want exactly 1 shared between role and flag resolution", lookup.calls)
	}
}

func TestMembershipCachesWithinTTLAndRefreshesWhenStale(t *testing.T) {
	repo := testutil.NewRepository()
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-1"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)

	first := e.membership(context.Background(), "Dana@Acme.dev")
	if lookup.calls != 1 || len(first) != 1 || first[0] != "ent-1" {
		t.Fatalf("first membership call = %+v (calls=%d), want one live lookup returning [ent-1]", first, lookup.calls)
	}

	second := e.membership(context.Background(), "dana@acme.dev")
	if lookup.calls != 1 {
		t.Fatalf("membership re-queried the directory within the TTL window (calls=%d)", lookup.calls)
	}
	if len(second) != 1 || second[0] != "ent-1" {
		t.Fatalf("cached membership = %+v, want [ent-1]", second)
	}

	// Force staleness by rewriting the cache record with an old SyncedAt.
	rec, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.GroupMembershipKind, ID: "dana@acme.dev"})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := cp.Encode(rec.RecordID, rec.Version, cp.GroupMembershipRecord{ID: "dana@acme.dev", GroupIDs: []string{"ent-1"}, SyncedAt: time.Now().Add(-cp.GroupMembershipCacheTTL - time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: stale, ExpectedVersion: rec.Version}}); err != nil {
		t.Fatal(err)
	}

	lookup.groupIDs = []string{"ent-2"}
	third := e.membership(context.Background(), "dana@acme.dev")
	if lookup.calls != 2 {
		t.Fatalf("membership did not refresh a stale cache entry (calls=%d)", lookup.calls)
	}
	if len(third) != 1 || third[0] != "ent-2" {
		t.Fatalf("refreshed membership = %+v, want [ent-2]", third)
	}
}

func TestMembershipRefreshesAnOversizedCacheWithinTTL(t *testing.T) {
	repo := testutil.NewRepository()
	oversized := make([]string, maxCachedMembershipIDs+1)
	for i := range oversized {
		oversized[i] = "ent-noise"
	}
	seedMembershipCache(t, repo, "dana@acme.dev", oversized, time.Now())
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-security"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)

	got := e.membership(context.Background(), "dana@acme.dev")
	if lookup.calls != 1 {
		t.Fatalf("oversized cache was treated as fresh (calls=%d)", lookup.calls)
	}
	if len(got) != 1 || got[0] != "ent-security" {
		t.Fatalf("membership = %+v, want the live lookup [ent-security]", got)
	}
}

func TestMembershipFailsOpenToLastCachedValueOnLookupError(t *testing.T) {
	repo := testutil.NewRepository()
	seedMembershipCache(t, repo, "dana@acme.dev", []string{"ent-1"}, time.Now().Add(-cp.GroupMembershipCacheTTL-time.Minute))
	lookup := &fakeGroupLookup{err: errors.New("directory unreachable")}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)

	got := e.membership(context.Background(), "dana@acme.dev")
	if lookup.calls != 1 {
		t.Fatalf("membership did not attempt a live lookup for a stale cache (calls=%d)", lookup.calls)
	}
	if len(got) != 1 || got[0] != "ent-1" {
		t.Fatalf("membership on lookup failure = %+v, want the stale cache [ent-1] preserved", got)
	}
}

func TestMembershipDoesNotFailOpenToAnOversizedCache(t *testing.T) {
	repo := testutil.NewRepository()
	oversized := make([]string, maxCachedMembershipIDs+1)
	for i := range oversized {
		oversized[i] = "ent-noise"
	}
	seedMembershipCache(t, repo, "dana@acme.dev", oversized, time.Now())
	lookup := &fakeGroupLookup{err: errors.New("directory unreachable")}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)

	got := e.membership(context.Background(), "dana@acme.dev")
	if lookup.calls != 1 {
		t.Fatalf("membership did not attempt a live lookup (calls=%d)", lookup.calls)
	}
	if len(got) != 0 {
		t.Fatalf("membership on lookup failure = %d ids, want empty rather than the truncated all-grants cache", len(got))
	}
}

func TestMembershipAbandonsASlowLookupBeforeTheHTTPWriteTimeout(t *testing.T) {
	old := membershipLookupTimeout
	membershipLookupTimeout = 50 * time.Millisecond
	t.Cleanup(func() { membershipLookupTimeout = old })

	repo := testutil.NewRepository()
	seedMembershipCache(t, repo, "dana@acme.dev", []string{"ent-1"}, time.Now().Add(-cp.GroupMembershipCacheTTL-time.Minute))
	lookup := &fakeGroupLookup{block: true}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)

	start := time.Now()
	got := e.membership(context.Background(), "dana@acme.dev")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("membership blocked for %s, want it to abandon the live lookup quickly", elapsed)
	}
	if lookup.calls != 1 {
		t.Fatalf("membership did not attempt a live lookup (calls=%d)", lookup.calls)
	}
	if len(got) != 1 || got[0] != "ent-1" {
		t.Fatalf("membership on lookup timeout = %+v, want the stale cache [ent-1]", got)
	}
}

func TestMembershipReturnsNilWithoutCacheOnFirstLookupFailure(t *testing.T) {
	repo := testutil.NewRepository()
	lookup := &fakeGroupLookup{err: errors.New("directory unreachable")}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	if got := e.membership(context.Background(), "dana@acme.dev"); got != nil {
		t.Fatalf("membership = %+v, want nil for an identity never successfully looked up", got)
	}
}

func TestCheckPrincipalLegacyAdminOverridesDirectoryRole(t *testing.T) {
	h := newHarness(t, 1)
	setRoleMapping(t, h.repo, "ent-member", cp.RoleMember)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-member"}}
	h.manager.Eligibility = NewEligibility(h.config.Auth, h.repo, lookup)

	_, a, _ := h.login(t, "primary") // "primary"/subject-a is the harness's static admin.
	checked, err := h.manager.CheckPrincipal(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !checked.Admin || checked.Role != cp.RoleAdmin {
		t.Fatalf("legacy auth.admins did not override a member-mapped directory role: %+v", checked)
	}
}

func TestCheckPrincipalGrantsAdminFromDirectoryRoleAlone(t *testing.T) {
	h := newHarness(t, 2)
	setRoleMapping(t, h.repo, "ent-admin", cp.RoleAdmin)
	lookup := &fakeGroupLookup{groupIDs: []string{"ent-admin"}}
	h.manager.Eligibility = NewEligibility(h.config.Auth, h.repo, lookup)

	_, b, _ := h.login(t, "secondary") // not in the static auth.admins list.
	checked, err := h.manager.CheckPrincipal(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if !checked.Admin || checked.Role != cp.RoleAdmin {
		t.Fatalf("a directory-mapped admin role did not grant Admin: %+v", checked)
	}
	if !checked.VulnAdmin {
		t.Fatalf("Admin did not imply VulnAdmin: %+v", checked)
	}
}

func TestCheckPrincipalCarriesFeaturesAndDoesNotImplyThemForAdmin(t *testing.T) {
	h := newHarness(t, 1)
	setFeatureFlag(t, h.repo, cp.FeatureVulnerabilities, cp.FeatureFlagGroup, "ent-security")
	lookup := &fakeGroupLookup{groupIDs: nil} // the harness's admin holds no groups.
	h.manager.Eligibility = NewEligibility(h.config.Auth, h.repo, lookup)

	_, a, _ := h.login(t, "primary") // the harness's static admin.
	checked, err := h.manager.CheckPrincipal(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !checked.Admin {
		t.Fatalf("expected the static admin to remain admin: %+v", checked)
	}
	if len(checked.Features) != 0 {
		t.Fatalf("Features = %v, want none -- Admin must not bypass an \"off\"/unmatched group flag", checked.Features)
	}
}

// unpack splits what resolveAccess grants for the tests that predate groups.
func unpack(a access) (string, bool, []string) { return a.role, a.vulnAdmin, a.features }

func TestResolveAccessReportsHeldGroupsForOwnership(t *testing.T) {
	repo := testutil.NewRepository()
	lookup := &fakeGroupLookup{groupIDs: []string{"grp-platform", "grp-billing"}}
	e := NewEligibility(serverconfig.AuthConfig{}, repo, lookup)
	granted := e.resolveAccess(context.Background(), "dana@acme.dev")
	if !slices.Equal(granted.groups, []string{"grp-billing", "grp-platform"}) {
		t.Fatalf("groups = %v, want every held entitlement, sorted, so group-owned applications resolve", granted.groups)
	}
	if got := e.resolveAccess(context.Background(), "").groups; got != nil {
		t.Fatalf("an identity without an email holds groups %v", got)
	}
}
