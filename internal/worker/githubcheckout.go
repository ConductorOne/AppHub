// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/source"
)

func newSourceCheckout(cfg serverconfig.Config, repo cp.Repository, keyReader GitHubAppKeyReader) (*source.Checkout, error) {
	return source.NewCheckout(cfg.Source, cfg.Worker.WorkDir, source.WithAdminApp(loadAdminGitHubApp(repo, keyReader)))
}

func loadAdminGitHubApp(repo cp.Repository, keyReader GitHubAppKeyReader) *githubapp.App {
	if repo == nil || keyReader == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), persistenceTimeout)
	defer cancel()
	r, err := repo.Read(ctx, cp.RecordID{Kind: cp.GitHubAppConfigKind, ID: cp.GitHubAppConfigID})
	if err != nil {
		return nil
	}
	cfg, err := cp.Decode[cp.GitHubAppConfigRecord](r)
	if err != nil || cfg.AppID <= 0 {
		return nil
	}
	key, err := keyReader.Get(ctx)
	if err != nil {
		return nil
	}
	app, err := githubapp.NewApp(githubapp.AppConfig{AppID: cfg.AppID, PrivateKeyPEM: key, BaseURL: cfg.APIBaseURL})
	if err != nil {
		return nil
	}
	return app
}
