// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"

	// Register the pgx database/sql driver used by postgres.NewSQLConn below.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/postgres"
)

// installPostgresExtensions is the worker's SQL composition: the deploy module
// owns the database lifecycle and lends the worker temporary network ingress.
// This is the only layer that registers the concrete database/sql driver.
func installPostgresExtensions(ctx context.Context, endpoint compute.SQLEndpoint, username string, password compute.SecretValue, rootCertPath string, extensions []string) error {
	cfg := postgres.ConnectionConfig{
		Endpoint: endpoint, Username: username,
		TLS: postgres.TLSVerifyFull, RootCertPath: rootCertPath,
	}
	dsn, err := cfg.DSN(password)
	if err != nil {
		return err
	}
	conn, err := postgres.NewSQLConn("pgx", cfg.Where(), dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	provisioner, err := postgres.NewProvisioner(conn, endpoint.DatabaseName)
	if err != nil {
		return err
	}
	return provisioner.EnsureExtensions(ctx, extensions)
}
