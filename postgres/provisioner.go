// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// Provisioner runs role and extension provisioning against one database.
//
// It holds the connection and the database's name, which is the whole of its
// state. The name is here rather than a parameter on each method because the
// CONNECT grant has to spell a database and Postgres has no keyword for "the one
// I am connected to": a parameter would let a caller grant CONNECT on a database
// this connection is not against, which is a privilege on a database nobody
// looked at.
type Provisioner struct {
	conn     Conn
	database string
	// where is a non-secret description of the endpoint, for diagnostics that
	// replace a driver message this package will not render. Empty when the
	// provisioner was built directly from a Conn.
	where    string
	prepared bool
}

// NewProvisioner wraps a connection.
//
// It does not own the connection's lifetime: [Conn.Close] is the caller's to
// call, because a caller doing roles and then extensions should not need two
// connections.
func NewProvisioner(conn Conn, database string) (*Provisioner, error) {
	switch {
	case conn == nil:
		return nil, fmt.Errorf("%w: a provisioner needs a connection", compute.ErrInvalidSpec)
	case strings.TrimSpace(database) == "":
		return nil, fmt.Errorf("%w: a provisioner needs the name of the database it is against; "+
			"it is what the CONNECT grant spells", compute.ErrInvalidSpec)
	}
	return &Provisioner{conn: conn, database: database, where: database}, nil
}

// prepare pings and puts the session into a known string-literal mode.
//
// Once per provisioner rather than once per call: it is a session setting, and a
// provisioner holds one session by construction ([NewSQLConn] caps the pool at
// one connection). Doing it once also means a caller creating five roles pays for
// one ping rather than five, which matters because the ping is the slow part
// against a cluster that has just become available.
func (p *Provisioner) prepare(ctx context.Context) error {
	if p.prepared {
		return nil
	}
	if err := p.conn.Ping(ctx); err != nil {
		// ErrTransient, and the classification is the useful part: a freshly
		// available Aurora Serverless v2 instance — and a just-added
		// security-group rule — take seconds to begin accepting connections, so
		// the first attempt after provisioning legitimately fails. The source
		// system's answer is a twelve-attempt loop inside the call
		// (postgres_roles.go:128-152); here the retry decision is the caller's,
		// which is the same choice [compute.RelationalProvisioner] makes by
		// leaving readiness to a separate Wait.
		// Sealed, and this is the path that makes sealing everything necessary
		// rather than sealing two: a ping failure IS a connection failure, and
		// this connection was opened with a DSN that carries the password.
		return fmt.Errorf("%w: the endpoint at %s did not answer; a cluster that has just become "+
			"available, or a security-group rule that has just been added, takes seconds to begin "+
			"accepting connections: %w", compute.ErrTransient, p.where, seal(err))
	}
	if err := p.setStandardConformingStrings(ctx); err != nil {
		return err
	}
	p.prepared = true
	return nil
}

// Connect opens an admin connection to an endpoint, reading the admin password
// out of a [compute.SecretStore].
//
// This is the function the whole "cloud-neutral" claim rests on. In the source
// system the equivalent takes an aws.Config and calls ssm.GetParameter
// (postgres_roles.go:154-165), and database_extensions.go imports the AWS SDK for
// no other purpose than to pass that config through to it
// (database_extensions.go:26,31). Here the lookup is a [compute.SecretStore.Get],
// which is what that interface's own documentation says it is for: "Used only
// where apphub genuinely needs the material itself — the master database
// password, which it must present to Postgres to create roles."
//
// The material's whole journey is: out of the store, into a DSN that is a
// [compute.SecretValue], into the driver. It is not logged, not returned, not put
// in an error, and not held on the [Provisioner].
//
// driverName is the name a Postgres driver registered with database/sql. The
// caller supplies it, and supplies the driver, so that this package depends on
// none.
func Connect(
	ctx context.Context,
	store compute.SecretStore,
	adminPassword compute.Ref,
	cfg ConnectionConfig,
	driverName string,
) (*Provisioner, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: no secret store to read the admin password from",
			compute.ErrInvalidSpec)
	}
	if strings.TrimSpace(driverName) == "" {
		return nil, fmt.Errorf("%w: no database driver named; this package registers none, so the "+
			"caller supplies both the driver and its name", compute.ErrInvalidSpec)
	}
	password, err := store.Get(ctx, adminPassword)
	if err != nil {
		// The reference is in the error and the material is not. A Ref is
		// opaque and non-secret by contract, and "which secret could not be
		// read" is the first thing an operator needs.
		return nil, fmt.Errorf("reading the admin password %s: %w", adminPassword, err)
	}
	if password.IsZero() {
		return nil, fmt.Errorf("%w: the secret store returned an empty admin password for %s; a "+
			"provisioning run that proceeded would authenticate as nobody and report an "+
			"authentication failure against the database rather than against the store",
			compute.ErrNotFound, adminPassword)
	}
	dsn, err := cfg.DSN(password)
	if err != nil {
		return nil, err
	}
	conn, err := NewSQLConn(driverName, cfg.Where(), dsn)
	if err != nil {
		return nil, err
	}
	p, err := NewProvisioner(conn, cfg.Endpoint.DatabaseName)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	p.where = cfg.Where()
	return p, nil
}

// Close releases the connection.
func (p *Provisioner) Close() error { return p.conn.Close() }

// Database reports the database this provisioner is against.
func (p *Provisioner) Database() string { return p.database }
