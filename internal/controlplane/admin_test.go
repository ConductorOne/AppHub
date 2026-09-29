// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
)

func testRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

type fakeKeyStore struct {
	stored  string
	putErr  error
	delErr  error
	puts    int
	deletes int
}

func (f *fakeKeyStore) Put(_ context.Context, key credentials.Secret) error {
	f.puts++
	if f.putErr != nil {
		return f.putErr
	}
	f.stored = credentials.Reveal(key)
	return nil
}
func (f *fakeKeyStore) Delete(_ context.Context) error {
	f.deletes++
	if f.delErr != nil {
		return f.delErr
	}
	f.stored = ""
	return nil
}

type recordingAuditWriter struct {
	actor, action, target string
	err                   error
}

func (w *recordingAuditWriter) AppendAudit(_ context.Context, actor, action, target string, _ map[string]string) error {
	w.actor, w.action, w.target = actor, action, target
	return w.err
}

type fakeLogReader struct {
	sawGroup string
	sawQuery cp.LogQuery
	result   cp.LogResult
	err      error
}

func (f *fakeLogReader) Filter(_ context.Context, group string, q cp.LogQuery) (cp.LogResult, error) {
	f.sawGroup, f.sawQuery = group, q
	if f.err != nil {
		return cp.LogResult{}, f.err
	}
	return f.result, nil
}

type adminFixture struct {
	repo        *testutil.Repository
	service     *cp.Service
	admin       cp.Principal
	other       cp.Principal
	eligibility *liveEligibility
}

func newAdminFixture(t *testing.T, opts ...cp.ServiceOption) *adminFixture {
	t.Helper()
	admin := cp.Principal{UserID: "admin", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "admin-subject", Admin: true}
	other := cp.Principal{UserID: "other", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "other-subject"}
	eligibility := &liveEligibility{principals: map[string]cp.Principal{admin.UserID: admin, other.UserID: other}}
	target := cp.TargetPolicy{ID: "org", Label: "Organization", ConfigHash: "policy-hash", DeployConfig: deploy.Config{ResourcePrefix: "test", AllowedSourceHosts: []string{"github.com"}}, ResourceSizes: []cp.ResourceInput{{CPU: 500, Memory: 1024}}, MaxReplicas: 4, ExecutionModes: []string{"service"}, Repositories: []string{"https://github.com/example/app"}}
	repo := testutil.NewRepository()
	service, err := cp.NewService(repo, eligibility, map[string]cp.TargetPolicy{target.ID: target}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return &adminFixture{repo: repo, service: service, admin: admin, other: other, eligibility: eligibility}
}

func TestGitHubAppStatusUnavailableWhenNotConfigured(t *testing.T) {
	f := newAdminFixture(t)
	view, err := f.service.GetGitHubAppStatus(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if view.Available {
		t.Fatalf("Available = true with no WithGitHubAppAdmin option: %+v", view)
	}
}

func TestGitHubAppStatusRequiresAdmin(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	if _, err := f.service.GetGitHubAppStatus(context.Background(), f.other); err == nil {
		t.Fatal("non-admin read the GitHub App status")
	}
	var problem *cp.Error
	if _, err := f.service.GetGitHubAppStatus(context.Background(), f.other); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestListDirectoryEntitlementsRequiresAdmin(t *testing.T) {
	f := newAdminFixture(t)
	var problem *cp.Error
	if _, err := f.service.ListDirectoryEntitlements(context.Background(), f.other); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestListDirectoryEntitlementsEmptyWhenNothingSynced(t *testing.T) {
	f := newAdminFixture(t)
	views, err := f.service.ListDirectoryEntitlements(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 0 {
		t.Fatalf("expected an empty list with nothing synced, got %+v", views)
	}
}

func TestListDirectoryEntitlementsReturnsSyncedRecordsSorted(t *testing.T) {
	f := newAdminFixture(t)
	now := time.Now().UTC()
	for _, rec := range []cp.DirectoryEntitlementRecord{
		{ID: "ent-2", DisplayName: "Zebra", Bindable: false, SyncedAt: now},
		{ID: "ent-1", DisplayName: "Alpha", AppID: "app-1", Bindable: true, SyncedAt: now},
	} {
		encoded, err := cp.Encode(cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: rec.ID}, 0, rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: encoded}}); err != nil {
			t.Fatal(err)
		}
	}
	views, err := f.service.ListDirectoryEntitlements(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].DisplayName != "Alpha" {
		t.Fatalf("unexpected views: %+v, want only the bindable group", views)
	}
	if !views[0].Bindable || views[0].AppID != "app-1" {
		t.Fatalf("Alpha's fields did not round-trip: %+v", views[0])
	}
}

func seedDirectoryEntitlement(t *testing.T, f *adminFixture, rec cp.DirectoryEntitlementRecord) {
	t.Helper()
	encoded, err := cp.Encode(cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: rec.ID}, 0, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: encoded}}); err != nil {
		t.Fatal(err)
	}
}

func seedUser(t *testing.T, f *adminFixture, rec cp.User) {
	t.Helper()
	encoded, err := cp.Encode(cp.RecordID{Kind: cp.UserKind, ID: rec.ID}, 0, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Commit(context.Background(), []cp.Mutation{{Record: encoded}}); err != nil {
		t.Fatal(err)
	}
}

func TestListMembersRequiresAdmin(t *testing.T) {
	f := newAdminFixture(t)
	var problem *cp.Error
	if _, err := f.service.ListMembers(context.Background(), f.other); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestListMembersEmptyWhenNobodyHasSignedIn(t *testing.T) {
	f := newAdminFixture(t)
	views, err := f.service.ListMembers(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 0 {
		t.Fatalf("expected an empty list with no persisted users, got %+v", views)
	}
}

func TestListMembersJoinsResolvedRoleAndOrdersByLastSeen(t *testing.T) {
	f := newAdminFixture(t)
	older := time.Now().UTC().Add(-time.Hour)
	newer := time.Now().UTC()
	seedUser(t, f, cp.User{ID: "user-dana", Email: "dana@acme.dev", Name: "Dana", CreatedAt: older, UpdatedAt: older})
	seedUser(t, f, cp.User{ID: "user-milo", Email: "milo@acme.dev", Name: "Milo", Disabled: true, CreatedAt: older, UpdatedAt: newer})
	f.eligibility.roles = map[string]cp.Principal{
		"dana@acme.dev": {Role: cp.RoleAdmin, VulnAdmin: true},
		"milo@acme.dev": {Role: cp.RoleMember},
	}

	views, err := f.service.ListMembers(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 || views[0].Email != "milo@acme.dev" || views[1].Email != "dana@acme.dev" {
		t.Fatalf("expected milo (more recently seen) before dana, got %+v", views)
	}
	if views[0].Role != cp.RoleMember || !views[0].Disabled {
		t.Fatalf("milo's fields did not resolve: %+v", views[0])
	}
	if views[1].Role != cp.RoleAdmin || !views[1].VulnAdmin || views[1].Disabled {
		t.Fatalf("dana's fields did not resolve: %+v", views[1])
	}
}

func TestSetRoleMappingRequiresAdmin(t *testing.T) {
	f := newAdminFixture(t)
	var problem *cp.Error
	if _, err := f.service.SetRoleMapping(context.Background(), f.other, "ent-1", cp.RoleMappingInput{Role: cp.RoleAdmin}); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestSetRoleMappingRejectsAnUnknownRole(t *testing.T) {
	f := newAdminFixture(t)
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Engineering", Bindable: true, SyncedAt: time.Now().UTC()})
	if _, err := f.service.SetRoleMapping(context.Background(), f.admin, "ent-1", cp.RoleMappingInput{Role: "superuser"}); err == nil {
		t.Fatal("an unknown role name was accepted")
	}
}

func TestSetRoleMappingRejectsAnUnsyncedEntitlement(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.service.SetRoleMapping(context.Background(), f.admin, "ent-missing", cp.RoleMappingInput{Role: cp.RoleAdmin}); err == nil {
		t.Fatal("an entitlement with no synced record was accepted")
	}
}

func TestSetRoleMappingRejectsANonBindableEntitlement(t *testing.T) {
	f := newAdminFixture(t)
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Fine-grained grant", Bindable: false, SyncedAt: time.Now().UTC()})
	if _, err := f.service.SetRoleMapping(context.Background(), f.admin, "ent-1", cp.RoleMappingInput{Role: cp.RoleAdmin}); err == nil {
		t.Fatal("a non-bindable entitlement was accepted as a role mapping target")
	}
}

func TestSetRoleMappingCreatesUpdatesAndListsJoinedWithDisplayName(t *testing.T) {
	f := newAdminFixture(t)
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Engineering", Bindable: true, SyncedAt: time.Now().UTC()})

	view, err := f.service.SetRoleMapping(context.Background(), f.admin, "ent-1", cp.RoleMappingInput{Role: cp.RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if view.EntitlementID != "ent-1" || view.DisplayName != "Engineering" || view.Role != cp.RoleMember || view.UpdatedBy != f.admin.UserID {
		t.Fatalf("unexpected view after create: %+v", view)
	}

	// Setting it again with a different role updates the same record rather
	// than creating a second one.
	view, err = f.service.SetRoleMapping(context.Background(), f.admin, "ent-1", cp.RoleMappingInput{Role: cp.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if view.Role != cp.RoleAdmin {
		t.Fatalf("role did not update in place: %+v", view)
	}

	views, err := f.service.ListRoleMappings(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Role != cp.RoleAdmin {
		t.Fatalf("expected exactly one updated mapping, got %+v", views)
	}
}

func TestDeleteRoleMappingRequiresAdminAndRemovesTheMapping(t *testing.T) {
	f := newAdminFixture(t)
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Engineering", Bindable: true, SyncedAt: time.Now().UTC()})
	if _, err := f.service.SetRoleMapping(context.Background(), f.admin, "ent-1", cp.RoleMappingInput{Role: cp.RoleAdmin}); err != nil {
		t.Fatal(err)
	}

	var problem *cp.Error
	if err := f.service.DeleteRoleMapping(context.Background(), f.other, "ent-1"); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}

	if err := f.service.DeleteRoleMapping(context.Background(), f.admin, "ent-1"); err != nil {
		t.Fatal(err)
	}
	views, err := f.service.ListRoleMappings(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 0 {
		t.Fatalf("expected no mappings after delete, got %+v", views)
	}
	if err := f.service.DeleteRoleMapping(context.Background(), f.admin, "ent-1"); err == nil {
		t.Fatal("deleting an already-deleted mapping did not fail")
	}
}

func TestListFeatureFlagsRequiresAdminAndDefaultsEveryKnownKeyToOff(t *testing.T) {
	f := newAdminFixture(t)
	var problem *cp.Error
	if _, err := f.service.ListFeatureFlags(context.Background(), f.other); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}

	views, err := f.service.ListFeatureFlags(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != len(cp.KnownFeatureFlags) {
		t.Fatalf("views = %+v, want one entry per known flag", views)
	}
	for _, v := range views {
		if v.Mode != cp.FeatureFlagOff {
			t.Fatalf("unconfigured flag %q defaulted to %q, want %q", v.Key, v.Mode, cp.FeatureFlagOff)
		}
	}
}

func TestSetFeatureFlagRejectsAnUnknownKey(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.service.SetFeatureFlag(context.Background(), f.admin, "not-a-real-flag", cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}); err == nil {
		t.Fatal("an unknown flag key was accepted")
	}
}

func TestSetFeatureFlagRejectsAnUnknownMode(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: "sometimes"}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}

func TestSetFeatureFlagGroupModeRequiresABindableSyncedEntitlement(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup}); err == nil {
		t.Fatal("group mode with no entitlement ID was accepted")
	}
	if _, err := f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup, GroupEntitlementIDs: []string{"ent-missing"}}); err == nil {
		t.Fatal("group mode naming an unsynced entitlement was accepted")
	}
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-1", DisplayName: "Fine-grained grant", Bindable: false, SyncedAt: time.Now().UTC()})
	if _, err := f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup, GroupEntitlementIDs: []string{"ent-1"}}); err == nil {
		t.Fatal("group mode naming a non-bindable entitlement was accepted")
	}
}

func TestSetFeatureFlagCreatesUpdatesAndListsJoinedWithDisplayName(t *testing.T) {
	f := newAdminFixture(t)
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-security", DisplayName: "Security", Bindable: true, SyncedAt: time.Now().UTC()})
	seedDirectoryEntitlement(t, f, cp.DirectoryEntitlementRecord{ID: "ent-eng", DisplayName: "Engineering", Bindable: true, SyncedAt: time.Now().UTC()})

	view, err := f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup, GroupEntitlementIDs: []string{"ent-security", "ent-eng", "ent-security"}})
	if err != nil {
		t.Fatal(err)
	}
	if view.Key != cp.FeatureVulnerabilities || view.Mode != cp.FeatureFlagGroup || view.UpdatedBy != f.admin.UserID {
		t.Fatalf("unexpected view after create: %+v", view)
	}
	if len(view.Groups) != 2 || view.Groups[0].ID != "ent-security" || view.Groups[0].DisplayName != "Security" || view.Groups[1].ID != "ent-eng" || view.Groups[1].DisplayName != "Engineering" {
		t.Fatalf("groups were not joined and de-duplicated: %+v", view.Groups)
	}

	// Setting it again to "on" clears the stale group entitlements rather
	// than keeping them around unused.
	view, err = f.service.SetFeatureFlag(context.Background(), f.admin, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagOn})
	if err != nil {
		t.Fatal(err)
	}
	if view.Mode != cp.FeatureFlagOn || len(view.Groups) != 0 {
		t.Fatalf("mode did not update in place: %+v", view)
	}

	views, err := f.service.ListFeatureFlags(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != len(cp.KnownFeatureFlags) {
		t.Fatalf("expected exactly one entry per known flag, got %+v", views)
	}
	var found bool
	for _, v := range views {
		if v.Key == cp.FeatureVulnerabilities {
			found = true
			if v.Mode != cp.FeatureFlagOn {
				t.Fatalf("listing did not reflect the update: %+v", v)
			}
		}
	}
	if !found {
		t.Fatalf("vulnerabilities flag missing from listing: %+v", views)
	}
}

func TestDeploymentIntegrationTogglesAreIndependentAndWorkspaceWide(t *testing.T) {
	f := newAdminFixture(t)
	for _, key := range []string{cp.FeatureProvisionAppCatalog, cp.FeatureProvisionShortLink} {
		if _, err := f.service.SetFeatureFlag(t.Context(), f.admin, key, cp.FeatureFlagInput{Mode: cp.FeatureFlagGroup, GroupEntitlementIDs: []string{"a"}}); err == nil {
			t.Fatalf("%s accepted group-limited provisioning", key)
		}
	}
	if _, err := f.service.SetFeatureFlag(t.Context(), f.admin, cp.FeatureProvisionShortLink, cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}); err != nil {
		t.Fatal(err)
	}
	flags, err := f.service.ListFeatureFlags(t.Context(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range flags {
		if flag.Key == cp.FeatureProvisionShortLink && flag.Mode != cp.FeatureFlagOn {
			t.Fatalf("GoLink flag not enabled: %+v", flag)
		}
		if flag.Key == cp.FeatureProvisionAppCatalog && flag.Mode != cp.FeatureFlagOff {
			t.Fatalf("application creation was enabled by the separate GoLink toggle: %+v", flag)
		}
	}
}

func TestSetFeatureFlagRequiresAdmin(t *testing.T) {
	f := newAdminFixture(t)
	var problem *cp.Error
	if _, err := f.service.SetFeatureFlag(context.Background(), f.other, cp.FeatureVulnerabilities, cp.FeatureFlagInput{Mode: cp.FeatureFlagOn}); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestSetGitHubAppConfigStoresAndNeverReturnsTheKey(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	pemKey := testRSAPEM(t)

	view, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, cp.GitHubAppConfigInput{AppID: 42, APIBaseURL: "https://ghe.example.com/api/v3", PrivateKey: pemKey})
	if err != nil {
		t.Fatalf("SetGitHubAppConfig: %v", err)
	}
	if !view.Configured || !view.PrivateKeyConfigured || view.AppID != 42 {
		t.Fatalf("unexpected view: %+v", view)
	}
	if keys.puts != 1 || keys.stored != pemKey {
		t.Fatalf("key store not written correctly: puts=%d stored=%q", keys.puts, keys.stored)
	}

	status, err := f.service.GetGitHubAppStatus(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if status.AppID != 42 || !status.PrivateKeyConfigured {
		t.Fatalf("status did not persist: %+v", status)
	}
}

func TestGitHubPrivateKeySideEffectRequiresAuditWrite(t *testing.T) {
	keys := &fakeKeyStore{}
	audit := &recordingAuditWriter{err: errors.New("audit unavailable")}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys), cp.WithAuditWriter(audit))
	input := cp.GitHubAppConfigInput{AppID: 42, PrivateKey: testRSAPEM(t)}
	_, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, input)
	var problem *cp.Error
	if !errors.As(err, &problem) || problem.Status != 503 {
		t.Fatalf("missing side-effect audit should surface 503, got %v", err)
	}
	if keys.puts != 1 || audit.actor != f.admin.UserID || audit.action != "githubApp.privateKey.replace" || audit.target != "githubAppConfig:config" {
		t.Fatalf("key side effect not audited with safe metadata: %+v", audit)
	}
	if _, err := f.repo.Read(context.Background(), cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("config committed despite failed key audit: %v", err)
	}
	audit.err = nil
	if _, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, input); err != nil {
		t.Fatalf("audited key replacement: %v", err)
	}
}

func TestSetGitHubAppConfigRejectsAnUnparseableKey(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	if _, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: "not a real key"}); err == nil {
		t.Fatal("an unparseable key was accepted")
	}
	if keys.puts != 0 {
		t.Fatal("an invalid key reached the store")
	}
}

func TestSetGitHubAppConfigRequiresFreshKeyForDestinationChange(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	originalKey, replacementKey := testRSAPEM(t), testRSAPEM(t)
	originalURL := "https://ghe.example.com/api/v3"
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 1, APIBaseURL: originalURL, PrivateKey: originalKey}); err != nil {
		t.Fatal(err)
	}
	recordID := cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}
	before, err := f.repo.Read(t.Context(), recordID)
	if err != nil {
		t.Fatal(err)
	}

	// The form sentinel may keep the key only at the current destination.
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 2, APIBaseURL: "https://attacker.example/api/v3", PrivateKey: "MASKED:****"}); err == nil {
		t.Fatal("redirected the existing signing key")
	} else {
		var problem *cp.Error
		if !errors.As(err, &problem) || problem.Status != 422 {
			t.Fatalf("unexpected error for redirected key: %v", err)
		}
	}
	after, err := f.repo.Read(t.Context(), recordID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != before.Version || string(after.Value) != string(before.Value) || keys.puts != 1 || keys.deletes != 0 || keys.stored != originalKey {
		t.Fatal("rejected redirect changed the persisted destination or stored key")
	}

	view, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 2, APIBaseURL: originalURL, PrivateKey: "MASKED:****"})
	if err != nil || view.APIBaseURL != originalURL || view.AppID != 2 || !view.PrivateKeyConfigured || keys.puts != 1 || keys.stored != originalKey {
		t.Fatalf("same-destination key retention failed: view=%+v err=%v puts=%d", view, err, keys.puts)
	}

	view, err = f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 3, APIBaseURL: "https://ghe-new.example.com/api/v3", PrivateKey: replacementKey})
	if err != nil || view.APIBaseURL != "https://ghe-new.example.com/api/v3" || view.AppID != 3 || !view.PrivateKeyConfigured || keys.puts != 2 || keys.stored != replacementKey {
		t.Fatalf("fresh-key Enterprise URL change failed: view=%+v err=%v puts=%d", view, err, keys.puts)
	}
}

func TestSetGitHubAppConfigValidatesURLWithAnyKeyAction(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	pemKey := testRSAPEM(t)
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: pemKey}); err != nil {
		t.Fatal(err)
	}
	recordID := cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}
	before, err := f.repo.Read(t.Context(), recordID)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"MASKED:****", "", testRSAPEM(t)} {
		if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: 1, APIBaseURL: "http://untrusted.example", PrivateKey: key}); err == nil {
			t.Fatalf("invalid destination accepted with key action %q", key)
		}
		after, err := f.repo.Read(t.Context(), recordID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Version != before.Version || string(after.Value) != string(before.Value) || keys.puts != 1 || keys.deletes != 0 || keys.stored != pemKey {
			t.Fatal("invalid destination changed configuration or key")
		}
	}
}

func TestSetGitHubAppConfigMaskedSentinelWithNoExistingKeyIsRefused(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	if _, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: "MASKED:****"}); err == nil {
		t.Fatal("masked sentinel accepted with nothing stored")
	}
}

func TestSetGitHubAppConfigEmptyClearsTheKey(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	if _, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: testRSAPEM(t)}); err != nil {
		t.Fatal(err)
	}
	view, err := f.service.SetGitHubAppConfig(context.Background(), f.admin, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: ""})
	if err != nil {
		t.Fatal(err)
	}
	if view.PrivateKeyConfigured || keys.deletes != 1 {
		t.Fatalf("key not cleared: view=%+v deletes=%d", view, keys.deletes)
	}
}

func TestGitHubAppInstallationsListedAndForgettable(t *testing.T) {
	keys := &fakeKeyStore{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys))
	now := time.Now().UTC()
	storeValue(t, f.repo, cp.RecordID{Kind: cp.GitHubInstallationKind, ID: "7"}, cp.GitHubInstallationRecord{ID: "7", InstallationID: 7, AccountLogin: "example-org", AccountType: "Organization", SyncedAt: now})

	status, err := f.service.GetGitHubAppStatus(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Installations) != 1 || status.Installations[0].AccountLogin != "example-org" {
		t.Fatalf("unexpected installations: %+v", status.Installations)
	}

	if err := f.service.ForgetGitHubAppInstallation(context.Background(), f.admin, "7"); err != nil {
		t.Fatal(err)
	}
	status, err = f.service.GetGitHubAppStatus(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Installations) != 0 {
		t.Fatalf("installation not forgotten: %+v", status.Installations)
	}
	if err := f.service.ForgetGitHubAppInstallation(context.Background(), f.admin, "7"); err == nil {
		t.Fatal("forgetting an already-forgotten installation succeeded")
	}
}

// fakeManifestConverter stands in for a real call to GitHub's manifest
// conversion endpoint, so these tests never reach the network.
type fakeManifestConverter struct {
	calls    int
	lastCode string
	result   githubapp.ManifestConversion
	err      error
}

func (f *fakeManifestConverter) convert(_ context.Context, code, _ string) (githubapp.ManifestConversion, error) {
	f.calls++
	f.lastCode = code
	if f.err != nil {
		return githubapp.ManifestConversion{}, f.err
	}
	return f.result, nil
}

func TestStartGitHubAppManifestRequiresAdmin(t *testing.T) {
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(&fakeKeyStore{}), cp.WithPublicOrigin("https://portal.example.com"))
	var problem *cp.Error
	if _, err := f.service.StartGitHubAppManifest(context.Background(), f.other, cp.GitHubAppManifestInput{}); !errors.As(err, &problem) || problem.Status != 403 {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestStartGitHubAppManifestRequiresKeyStoreAndPublicOrigin(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.service.StartGitHubAppManifest(context.Background(), f.admin, cp.GitHubAppManifestInput{}); err == nil {
		t.Fatal("expected an error with neither GitHubAppAdmin nor a public origin configured")
	}
	withKeyStore := newAdminFixture(t, cp.WithGitHubAppAdmin(&fakeKeyStore{}))
	if _, err := withKeyStore.service.StartGitHubAppManifest(context.Background(), withKeyStore.admin, cp.GitHubAppManifestInput{}); err == nil {
		t.Fatal("expected an error with no public origin configured")
	}
}

func TestStartGitHubAppManifestBuildsManifestAndCreateURL(t *testing.T) {
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(&fakeKeyStore{}), cp.WithPublicOrigin("https://portal.example.com"))

	personal, err := f.service.StartGitHubAppManifest(context.Background(), f.admin, cp.GitHubAppManifestInput{})
	if err != nil {
		t.Fatal(err)
	}
	if personal.State == "" || personal.CreateURL != "https://github.com/settings/apps/new" {
		t.Fatalf("unexpected personal-account start: %+v", personal)
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(personal.ManifestJSON), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["url"] != "https://portal.example.com" || manifest["redirect_url"] != "https://portal.example.com/api/v1/admin/github-app/manifest/callback" || manifest["public"] != false {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}

	org, err := f.service.StartGitHubAppManifest(context.Background(), f.admin, cp.GitHubAppManifestInput{Organization: "acme-org"})
	if err != nil {
		t.Fatal(err)
	}
	if org.CreateURL != "https://github.com/organizations/acme-org/settings/apps/new" {
		t.Fatalf("unexpected organization create URL: %q", org.CreateURL)
	}
	if org.State == personal.State {
		t.Fatal("two starts minted the same state token")
	}
}

func TestCompleteGitHubAppManifestRejectsAnUnknownOrExpiredState(t *testing.T) {
	converter := &fakeManifestConverter{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(&fakeKeyStore{}), cp.WithPublicOrigin("https://portal.example.com"), cp.WithManifestConverter(converter.convert))
	if _, err := f.service.CompleteGitHubAppManifest(context.Background(), f.admin, "a-code", "never-started"); err == nil {
		t.Fatal("an unknown state was accepted")
	}
	if converter.calls != 0 {
		t.Fatal("GitHub was called despite an invalid state")
	}
}

func TestCompleteGitHubAppManifestRejectsADifferentAdministrator(t *testing.T) {
	converter := &fakeManifestConverter{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(&fakeKeyStore{}), cp.WithPublicOrigin("https://portal.example.com"), cp.WithManifestConverter(converter.convert))
	secondAdmin := cp.Principal{UserID: "second-admin", ProviderID: "oidc", Issuer: "https://identity.example", Subject: "second-admin-subject", Admin: true}
	f.eligibility.principals[secondAdmin.UserID] = secondAdmin

	started, err := f.service.StartGitHubAppManifest(context.Background(), f.admin, cp.GitHubAppManifestInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.CompleteGitHubAppManifest(context.Background(), secondAdmin, "a-code", started.State); err == nil {
		t.Fatal("a different administrator completed another admin's started flow")
	}
	if converter.calls != 0 {
		t.Fatal("GitHub was called despite the admin mismatch")
	}
}

func TestCompleteGitHubAppManifestExchangesAndStoresTheApp(t *testing.T) {
	keys := &fakeKeyStore{}
	converter := &fakeManifestConverter{result: githubapp.ManifestConversion{AppID: 987654, Slug: "apphub-example", PrivateKeyPEM: credentials.NewSecret("-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n"), HTMLURL: "https://github.com/apps/apphub-example"}}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys), cp.WithPublicOrigin("https://portal.example.com"), cp.WithManifestConverter(converter.convert))
	// A stale Enterprise Server base URL from an earlier manual entry must
	// not leak into a github.com-created App.
	storeValue(t, f.repo, cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}, cp.GitHubAppConfigRecord{ID: cp.GitHubAppConfigID, APIBaseURL: "https://ghe.example.com/api/v3"})

	started, err := f.service.StartGitHubAppManifest(context.Background(), f.admin, cp.GitHubAppManifestInput{})
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.service.CompleteGitHubAppManifest(context.Background(), f.admin, "one-time-code", started.State)
	if err != nil {
		t.Fatal(err)
	}
	if status.AppID != 987654 || !status.PrivateKeyConfigured || status.APIBaseURL != "" {
		t.Fatalf("unexpected status after completion: %+v", status)
	}
	if converter.calls != 1 || converter.lastCode != "one-time-code" {
		t.Fatalf("converter calls=%d lastCode=%q, want 1 and the given code", converter.calls, converter.lastCode)
	}
	if keys.stored == "" {
		t.Fatal("the private key was never stored")
	}
	configID := cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}
	before, err := f.repo.Read(t.Context(), configID)
	if err != nil {
		t.Fatal(err)
	}
	manifestKey := keys.stored
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: status.AppID, APIBaseURL: "https://attacker.example/api/v3", PrivateKey: "MASKED:****"}); err == nil {
		t.Fatal("manifest-created app key redirected to another host")
	}
	after, err := f.repo.Read(t.Context(), configID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Version != after.Version || string(before.Value) != string(after.Value) || keys.stored != manifestKey || keys.puts != 1 || keys.deletes != 0 {
		t.Fatal("manifest key or destination changed after rejected redirect")
	}
	// The github.com default is pinned as the empty stored URL, not just a
	// normalized equivalent supplied by the browser.
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: status.AppID, APIBaseURL: githubapp.DefaultAPIBaseURL, PrivateKey: "MASKED:****"}); err == nil {
		t.Fatal("manifest-created app accepted a changed URL without a new key")
	}
	if _, err := f.service.SetGitHubAppConfig(t.Context(), f.admin, cp.GitHubAppConfigInput{AppID: status.AppID, PrivateKey: "MASKED:****"}); err != nil {
		t.Fatalf("manifest-created app refused the same URL: %v", err)
	}

	// The state token is single-use: completing again with the same state
	// must fail rather than re-exchange the code.
	if _, err := f.service.CompleteGitHubAppManifest(context.Background(), f.admin, "replay-code", started.State); err == nil {
		t.Fatal("a completed state token was accepted a second time")
	}
	if converter.calls != 1 {
		t.Fatal("GitHub was called again on a replayed state")
	}
}

func TestLogsUnavailableWhenNotConfigured(t *testing.T) {
	f := newAdminFixture(t)
	names, err := f.service.ListLogGroups(context.Background(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("log groups without WithLogs: %v", names)
	}
	if _, err := f.service.QueryLogs(context.Background(), f.admin, "serve", cp.LogQuery{}); err == nil {
		t.Fatal("QueryLogs succeeded with no reader configured")
	}
}

func TestQueryLogsResolvesTheConfiguredGroupName(t *testing.T) {
	reader := &fakeLogReader{result: cp.LogResult{Events: []cp.LogEvent{{Message: "hello"}}}}
	f := newAdminFixture(t, cp.WithLogs(reader, []cp.LogGroup{{Name: "serve", LogGroup: "/ecs/apphub/serve"}, {Name: "worker", LogGroup: "/ecs/apphub/worker"}}))

	names, err := f.service.ListLogGroups(context.Background(), f.admin)
	if err != nil || len(names) != 2 {
		t.Fatalf("ListLogGroups = %v, %v", names, err)
	}

	res, err := f.service.QueryLogs(context.Background(), f.admin, "worker", cp.LogQuery{FilterPattern: "ERROR"})
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if reader.sawGroup != "/ecs/apphub/worker" {
		t.Fatalf("wrong log group reached the reader: %q", reader.sawGroup)
	}
	if reader.sawQuery.FilterPattern != "ERROR" {
		t.Fatalf("filter pattern not forwarded: %+v", reader.sawQuery)
	}
	if len(res.Events) != 1 || res.Events[0].Message != "hello" {
		t.Fatalf("unexpected result: %+v", res)
	}

	if _, err := f.service.QueryLogs(context.Background(), f.admin, "nonexistent", cp.LogQuery{}); err == nil {
		t.Fatal("an unknown log group name was accepted")
	}
}

func TestAdminEndpointsRefuseNonAdmins(t *testing.T) {
	keys := &fakeKeyStore{}
	reader := &fakeLogReader{}
	f := newAdminFixture(t, cp.WithGitHubAppAdmin(keys), cp.WithLogs(reader, []cp.LogGroup{{Name: "serve", LogGroup: "/ecs/apphub/serve"}}))
	if _, err := f.service.SetGitHubAppConfig(context.Background(), f.other, cp.GitHubAppConfigInput{AppID: 1, PrivateKey: testRSAPEM(t)}); err == nil {
		t.Fatal("non-admin set the GitHub App config")
	}
	if err := f.service.ForgetGitHubAppInstallation(context.Background(), f.other, "1"); err == nil {
		t.Fatal("non-admin forgot an installation")
	}
	if _, err := f.service.ListLogGroups(context.Background(), f.other); err == nil {
		t.Fatal("non-admin listed log groups")
	}
	if _, err := f.service.QueryLogs(context.Background(), f.other, "serve", cp.LogQuery{}); err == nil {
		t.Fatal("non-admin queried logs")
	}
}
