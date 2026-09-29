// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/testutil"
)

type fakeKeyReader struct {
	key credentials.Secret
	err error
}

func (f *fakeKeyReader) Get(context.Context) (credentials.Secret, error) { return f.key, f.err }

type fakeInstallationsAPI struct {
	installs []githubapp.Installation
	repos    map[int64][]string
	reposErr error
	err      error
}

func (f *fakeInstallationsAPI) ListInstallations(context.Context) ([]githubapp.Installation, error) {
	return f.installs, f.err
}

func (f *fakeInstallationsAPI) ListInstallationRepositories(_ context.Context, id int64) ([]string, error) {
	if f.reposErr != nil {
		return nil, f.reposErr
	}
	return f.repos[id], nil
}

func newGitHubSyncerForTest(t *testing.T, repo cp.Repository, keys GitHubAppKeyReader, api githubInstallationsAPI) *GitHubSyncer {
	t.Helper()
	g, err := NewGitHubSyncer(repo, keys)
	if err != nil {
		t.Fatal(err)
	}
	g.newApp = func(int64, credentials.Secret, string) (githubInstallationsAPI, error) { return api, nil }
	return g
}

func TestGitHubSyncerSkipsWhenUnconfigured(t *testing.T) {
	repo := testutil.NewRepository()
	g := newGitHubSyncerForTest(t, repo, &fakeKeyReader{}, &fakeInstallationsAPI{})
	g.tick(context.Background())
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("synced installations with no app configured: %+v", page.Records)
	}
}

func TestGitHubSyncerSkipsWhenKeyUnavailable(t *testing.T) {
	repo := testutil.NewRepository()
	setGitHubAppConfigForTest(t, repo, 42)
	api := &fakeInstallationsAPI{installs: []githubapp.Installation{{ID: 1, Account: githubapp.InstallationAccount{Login: "org"}}}}
	g := newGitHubSyncerForTest(t, repo, &fakeKeyReader{err: errors.New("not found")}, api)
	g.tick(context.Background())
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("synced installations without a resolvable key: %+v", page.Records)
	}
}

func TestGitHubSyncerUpsertsAndPrunes(t *testing.T) {
	repo := testutil.NewRepository()
	setGitHubAppConfigForTest(t, repo, 42)
	api := &fakeInstallationsAPI{installs: []githubapp.Installation{
		{ID: 1, Account: githubapp.InstallationAccount{Login: "org-one", Type: "Organization"}, RepositorySelection: "selected"},
		{ID: 2, Account: githubapp.InstallationAccount{Login: "org-two", Type: "Organization"}},
	}}
	g := newGitHubSyncerForTest(t, repo, &fakeKeyReader{key: credentials.NewSecret("pem")}, api)
	g.tick(context.Background())

	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 installations, got %d: %+v", len(page.Records), page.Records)
	}

	// A second sync with one installation removed must prune the other.
	api.installs = []githubapp.Installation{{ID: 1, Account: githubapp.InstallationAccount{Login: "org-one", Type: "Organization"}}}
	g.tick(context.Background())
	page, err = repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected pruning to leave 1 installation, got %d: %+v", len(page.Records), page.Records)
	}
	rec, err := cp.Decode[cp.GitHubInstallationRecord](page.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "1" || rec.AccountLogin != "org-one" || rec.SyncedAt.IsZero() {
		t.Fatalf("unexpected surviving record: %+v", rec)
	}
}

func TestGitHubSyncerStoresRepositorySuggestions(t *testing.T) {
	repo := testutil.NewRepository()
	setGitHubAppConfigForTest(t, repo, 42)
	api := &fakeInstallationsAPI{
		installs: []githubapp.Installation{{ID: 1, Account: githubapp.InstallationAccount{Login: "org-one", Type: "Organization"}}},
		repos:    map[int64][]string{1: {"https://github.com/org-one/b", "https://github.com/org-one/a"}},
	}
	g := newGitHubSyncerForTest(t, repo, &fakeKeyReader{key: credentials.NewSecret("pem")}, api)
	g.tick(context.Background())
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := cp.Decode[cp.GitHubInstallationRecord](page.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Repositories) != 2 || rec.Repositories[0] != "https://github.com/org-one/a" || rec.Repositories[1] != "https://github.com/org-one/b" {
		t.Fatalf("repositories = %#v", rec.Repositories)
	}

	api.reposErr = errors.New("github unavailable")
	g.tick(context.Background())
	page, err = repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	rec, err = cp.Decode[cp.GitHubInstallationRecord](page.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Repositories) != 2 {
		t.Fatalf("a failed listing wiped suggestions: %#v", rec.Repositories)
	}
}

func TestGitHubSyncerDoesNotPruneOnTruncation(t *testing.T) {
	repo := testutil.NewRepository()
	setGitHubAppConfigForTest(t, repo, 42)
	seedInstallation(t, repo, "99")
	api := &fakeInstallationsAPI{installs: []githubapp.Installation{{ID: 1, Account: githubapp.InstallationAccount{Login: "org-one"}}}, err: githubapp.ErrInstallationsTruncated}
	g := newGitHubSyncerForTest(t, repo, &fakeKeyReader{key: credentials.NewSecret("pem")}, api)
	g.tick(context.Background())

	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.GitHubInstallationKind})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range page.Records {
		ids[r.ID] = true
	}
	if !ids["99"] {
		t.Fatal("truncated sync pruned a record it cannot vouch for")
	}
	if !ids["1"] {
		t.Fatal("truncated sync did not still upsert what it did see")
	}
}

func setGitHubAppConfigForTest(t *testing.T, repo cp.Repository, appID int64) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID}, 0, cp.GitHubAppConfigRecord{ID: cp.GitHubAppConfigID, AppID: appID, PrivateKeyConfigured: true, UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec}}); err != nil {
		t.Fatal(err)
	}
}

func seedInstallation(t *testing.T, repo cp.Repository, id string) {
	t.Helper()
	rec, err := cp.Encode(cp.RecordID{Kind: cp.GitHubInstallationKind, ID: id}, 0, cp.GitHubInstallationRecord{ID: id, SyncedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: rec}}); err != nil {
		t.Fatal(err)
	}
}
