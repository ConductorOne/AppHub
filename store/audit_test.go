// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func auditTestRepository(t *testing.T) (*ControlPlaneRecords, *fakeDynamo) {
	t.Helper()
	fake := newFakeDynamo("state-test")
	fake.auditTableName = "state-test-audit"
	client := newTestClient(fake)
	client.auditTableName = fake.auditTableName
	repo, err := NewControlPlaneRecords(client)
	if err != nil {
		t.Fatal(err)
	}
	return repo, fake
}

func TestAuditTransactionPaginationAndSecretExclusion(t *testing.T) {
	repo, fake := auditTestRepository(t)
	ctx := cp.WithAuditContext(context.Background(), "verified-admin", "POST /api/v1/applications", "")
	for i := range 5 {
		id := fmt.Sprintf("application-%d", i)
		if err := repo.Commit(ctx, cpTestOwned(t, id, cpTestUser("owner"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Commit(ctx, cpTestOwned(t, "application-0", cpTestUser("owner"))); !errors.Is(err, cp.ErrConflict) {
		t.Fatalf("idempotent conflict = %v", err)
	}
	secret := "NEVER-LOG-THIS-SESSION-SECRET"
	session := cpTestRecord(t, cp.RecordID{Kind: cp.SessionKind, ID: cp.Hash(secret)}, cp.Session{ID: cp.NewID(), UserID: cp.NewID(), CSRF: secret})
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: session}}); err != nil {
		t.Fatal(err)
	}
	var entries []cp.AuditEntry
	cursor := ""
	for {
		page, err := repo.ListAudit(context.Background(), 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 2 {
			t.Fatalf("page exceeded limit: %d", len(page.Items))
		}
		entries = append(entries, page.Items...)
		if page.Cursor == "" {
			break
		}
		if page.Cursor == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = page.Cursor
	}
	if len(entries) != 6 {
		t.Fatalf("successful commits = 6, audit entries = %d", len(entries))
	}
	for _, entry := range entries {
		if strings.Contains(fmt.Sprint(entry), secret) || strings.Contains(fmt.Sprint(entry), cp.Hash(secret)) {
			t.Fatalf("session material appeared in audit entry: %+v", entry)
		}
		if entry.Actor == "verified-admin" && (entry.Action != "POST /api/v1/applications" || !strings.HasPrefix(entry.Target, "application:")) {
			t.Fatalf("authenticated audit metadata = %+v", entry)
		}
	}
	if fake.callCount("Scan") != 0 {
		t.Fatal("audit listing scanned the table")
	}
	if _, err := repo.ListAudit(context.Background(), 2, "%%%invalid"); !errors.Is(err, cp.ErrInvalidCursor) {
		t.Fatalf("invalid cursor = %v", err)
	}
}

func TestAuditWriteFailureCannotCommitDomainState(t *testing.T) {
	repo, fake := auditTestRepository(t)
	repo.client.auditTableName = "missing-audit-table"
	mutations := cpTestOwned(t, "cannot-commit", cpTestUser("owner"))
	if err := repo.Commit(context.Background(), mutations); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("audit transaction failure = %v", err)
	}
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationKind, ID: "cannot-commit"}); !errors.Is(err, cp.ErrNotFound) {
		t.Fatalf("domain state survived failed audit: %v", err)
	}
	if len(fake.items[auditPartition]) != 0 {
		t.Fatal("failed audit transaction persisted an audit entry")
	}
}
func TestTargetHeartbeatDoesNotHideConfigurationChanges(t *testing.T) {
	repo, _ := auditTestRepository(t)
	id := cp.RecordID{Kind: cp.TargetKind, ID: "target-one"}
	target := cp.TargetDescriptor{ID: id.ID, ProviderName: "provider-a", ConfigHash: "hash-a", HeartbeatAt: time.Now().UTC()}
	create := cpTestRecord(t, id, target)
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: create}}); err != nil {
		t.Fatal(err)
	}
	target.HeartbeatAt = target.HeartbeatAt.Add(time.Second)
	heartbeat := cpTestRecord(t, id, target)
	ctx := cp.WithAuditContext(context.Background(), "system", "target.heartbeat", "target:"+id.ID)
	if err := repo.Commit(ctx, []cp.Mutation{{Record: heartbeat, ExpectedVersion: 1}}); err != nil {
		t.Fatal(err)
	}
	target.ConfigHash = "hash-b"
	change := cpTestRecord(t, id, target)
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: change, ExpectedVersion: 2}}); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListAudit(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Action != "target.update" ||
		page.Items[0].Target != "target:"+id.ID || page.Items[1].Action != "target.create" {
		t.Fatalf("target audit events = %+v", page.Items)
	}
}

func TestDeploymentHeartbeatDoesNotHideStateTransition(t *testing.T) {
	repo, _ := auditTestRepository(t)
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: "app"}
	depID := cp.RecordID{Kind: cp.DeploymentKind, ID: "deploy", ParentID: "app"}
	app := cpTestApplication(t, appID.ID, "owner")
	deployment := cpTestRecord(t, depID, cp.DeploymentRecord{ID: depID.ID, ApplicationID: appID.ID, State: cp.Queued, CreatedAt: time.Now().UTC()})
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: app}, {Record: deployment}}); err != nil {
		t.Fatal(err)
	}
	app, err := repo.Read(context.Background(), appID)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err = repo.Read(context.Background(), depID)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := []cp.Mutation{{Record: deployment, ExpectedVersion: deployment.Version}, {Record: app, ExpectedVersion: app.Version}}
	ctx := cp.WithAuditContext(context.Background(), "system", "deployment.heartbeat", "deployment:"+depID.ID)
	if err := repo.Commit(ctx, heartbeat); err != nil {
		t.Fatal(err)
	}
	state, err := cp.Decode[cp.DeploymentRecord](deployment)
	if err != nil {
		t.Fatal(err)
	}
	state.State = cp.Running
	heartbeat[0].Record = cpTestRecord(t, depID, state)
	heartbeat[0].ExpectedVersion++
	heartbeat[1].ExpectedVersion++
	if err := repo.Commit(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListAudit(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Action != "deployment.update" ||
		page.Items[0].Target != "deployment:"+depID.ID || page.Items[0].Details["state"] != "running" {
		t.Fatalf("heartbeat should be omitted while the state transition remains audited: %+v", page.Items)
	}
}

func TestAuditDetailsOnlyContainApprovedMetadata(t *testing.T) {
	repo, _ := auditTestRepository(t)
	id := cp.RecordID{Kind: cp.FeatureFlagKind, ID: "vulnerabilities"}
	record := cpTestRecord(t, id, struct {
		ID     string `json:"id"`
		Mode   string `json:"mode"`
		Secret string `json:"secret"`
	}{ID: id.ID, Mode: cp.FeatureFlagOn, Secret: "NEVER-LOG-THIS-VALUE"})
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: record}}); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListAudit(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Details["mode"] != cp.FeatureFlagOn ||
		strings.Contains(fmt.Sprint(page.Items), "NEVER-LOG-THIS-VALUE") {
		t.Fatalf("audit details exposed unapproved content: %+v", page.Items)
	}
}

func TestDirectorySyncIsOneSummaryEntry(t *testing.T) {
	repo, _ := auditTestRepository(t)
	sync := cp.WithAuditContext(context.Background(), "system", cp.DirectorySyncAction, "directory:groups")
	for i := range 3 {
		id := cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: fmt.Sprintf("ent-%d", i)}
		rec := cpTestRecord(t, id, cp.DirectoryEntitlementRecord{ID: id.ID, DisplayName: "Group", Bindable: true})
		if err := repo.Commit(sync, []cp.Mutation{{Record: rec}}); err != nil {
			t.Fatal(err)
		}
	}
	details := map[string]string{"groups": "3", "written": "3", "removed": "0"}
	if err := repo.AppendAudit(context.Background(), "system", cp.DirectorySyncAction, "directory:groups", details); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListAudit(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Action != cp.DirectorySyncAction || page.Items[0].Details["groups"] != "3" {
		t.Fatalf("directory sync audit = %+v; want one summary entry", page.Items)
	}

	// The label only hides directory records. A commit that also changes
	// something else under the same label is still audited.
	targetID := cp.RecordID{Kind: cp.TargetKind, ID: "target-one"}
	target := cpTestRecord(t, targetID, cp.TargetDescriptor{ID: targetID.ID, ProviderName: "provider-a"})
	entitlement := cpTestRecord(t, cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: "ent-9"},
		cp.DirectoryEntitlementRecord{ID: "ent-9", Bindable: true})
	if err := repo.Commit(sync, []cp.Mutation{{Record: entitlement}, {Record: target}}); err != nil {
		t.Fatal(err)
	}
	page, err = repo.ListAudit(context.Background(), 10, "")
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("mixed commit under the sync label = %+v, %v; want it audited", page.Items, err)
	}
}

func TestExternalAuditWriteAndReadinessFailClosed(t *testing.T) {
	repo, _ := auditTestRepository(t)
	if err := repo.Ready(context.Background()); err != nil {
		t.Fatalf("ready with both tables = %v", err)
	}
	if err := repo.AppendAudit(context.Background(), "admin", "githubApp.privateKey.replace", "githubAppConfig:config", nil); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListAudit(context.Background(), 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Actor != "admin" || page.Items[0].Action != "githubApp.privateKey.replace" {
		t.Fatalf("external side-effect audit = %+v, %v", page, err)
	}
	repo.client.auditTableName = "missing-audit-table"
	if err := repo.Ready(context.Background()); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("missing audit table was ready: %v", err)
	}
	if err := repo.AppendAudit(context.Background(), "admin", "githubApp.privateKey.delete", "githubAppConfig:config", nil); !errors.Is(err, cp.ErrUnavailable) {
		t.Fatalf("unlogged side effect returned success: %v", err)
	}
}
