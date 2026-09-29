// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"testing"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

type staticKeyReader struct{ key credentials.Secret }

func (s staticKeyReader) Get(context.Context) (credentials.Secret, error) { return s.key, nil }

func TestLoadAdminGitHubAppSkipsUnconfiguredApps(t *testing.T) {
	if app := loadAdminGitHubApp(nil, staticKeyReader{}); app != nil {
		t.Fatal("nil repository produced an app")
	}
	repo := testutil.NewRepository()
	if app := loadAdminGitHubApp(repo, nil); app != nil {
		t.Fatal("nil key reader produced an app")
	}
	if app := loadAdminGitHubApp(repo, staticKeyReader{key: credentials.NewSecret("not-a-key")}); app != nil {
		t.Fatal("missing config record produced an app")
	}
	rec, err := cp.Encode(cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}, 1, cp.GitHubAppConfigRecord{ID: cp.GitHubAppConfigID, AppID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(t.Context(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}); err != nil {
		t.Fatal(err)
	}
	if app := loadAdminGitHubApp(repo, staticKeyReader{key: credentials.NewSecret("not-a-key")}); app != nil {
		t.Fatal("unparseable key produced an app")
	}
}
