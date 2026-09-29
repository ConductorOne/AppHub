// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package postgres provisions what lives *inside* a relational endpoint: roles,
// their privileges, and extensions.
//
// It is deliberately, provably cloud-neutral. Everything here is ordinary SQL
// over a standard driver, which is why [compute.RelationalProvisioner] says so
// explicitly: "Everything the source system does to a database *after* it exists
// — creating Postgres roles, granting privileges, enabling row-level security,
// installing extensions (postgres_roles.go:25-121,
// database_extensions.go:26-73) — is vanilla SQL over a standard driver and
// belongs above this interface."
//
// # The seam, and what it buys
//
// The source system's two files take an aws.Config, and they take it for exactly
// one reason: to read the master password out of SSM Parameter Store
// (postgres_roles.go:154-165). database_extensions.go imports the AWS SDK
// *solely* to pass that config through to that one lookup
// (database_extensions.go:26,31) and makes no AWS call of its own.
//
// Here the password comes from a [compute.SecretStore], so this package's only
// dependencies are [compute], [credentials], and the standard library. That is
// not a claim about tidiness — the deploy layer above it can now run this code
// against a Kubernetes-hosted Postgres with no change at all, which is what
// "cloud-neutral" has to mean to be worth saying.
//
// It is enforced rather than asserted. The `aws-sdk-confined` rule in
// internal/boundary denies every AWS SDK import to every package except
// compute/aws and store, so "this package has no AWS import" is a property of
// the import graph checked by `make boundary` on every commit, not a sentence in
// a comment. The acceptance criterion for USOSS-14 was that
// database_extensions.go has no AWS import after the port; a structural check
// over the whole package is the strongest available form of it.
//
// # The database driver is the caller's
//
// This package needs a Postgres connection and does not import a Postgres
// driver. [Conn] is the surface it uses; [NewSQLConn] adapts a *database/sql DB
// to it using nothing but the standard library, and registering a driver — pgx,
// in the source system (postgres_roles.go:19) — is the composition root's job.
//
// Two things follow, and both are the reason rather than a consequence. A
// hermetic test can drive every path here through a [Conn] it controls, with no
// database, no container, and no port binding. And the driver, which is the one
// dependency here with a licence and a CVE history, is not in this package's
// import graph at all.
//
// # What this package will not do
//
// It does not generate passwords, and it does not decide where a credential is
// stored. Both belong to the caller: [compute.RelationalSpec.AdminPassword]
// documents the ordering obligation — store the secret before provisioning — and
// a package that generated its own credentials would have to store them
// somewhere, which is a policy decision the deploy layer owns.
package postgres
