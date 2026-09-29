// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// Conn is the database surface this package needs.
//
// It is an interface for two reasons, and the second one is the load-bearing
// one.
//
// The first is hermeticity. The conformance bar for this repository is "no
// network, no real credentials, no cluster, no fixed ports", and every path here
// — creating a role, granting privileges, installing an extension — is a
// sequence of statements whose *composition* is the thing worth testing. A
// [Conn] a test controls makes that testable without a Postgres; a containerised
// one would bind a port, and this environment is shared.
//
// The second is that it is where a security obligation can be *stated*.
// [Conn.Exec] carries one, in the same style as [compute] puts an obligation on
// a build runner:
//
//	An implementation MUST NOT put the statement into the error it returns.
//
// Postgres cannot parameterise a role password — CREATE ROLE ... PASSWORD takes
// a literal — so exactly one statement this package builds contains credential
// material. If a driver error carried the statement, that material would reach a
// log, an API response, and usually durable storage. The obligation is here, and
// [sealed] is how that obligation is kept for the one statement that has to
// carry a password, and it works by never rendering the cause rather than by
// matching representations of the secret.
type Conn interface {
	// Ping verifies the connection is usable.
	Ping(ctx context.Context) error

	// Exec runs one statement with no parameters, for the DDL that cannot take
	// them. See the type comment for the obligation on the error.
	Exec(ctx context.Context, stmt string) error

	// QueryExists runs a query that yields one boolean and returns it. It is
	// the one read this package performs — "does this role already exist" —
	// and it takes parameters, because it can.
	QueryExists(ctx context.Context, query string, args ...any) (bool, error)

	// Close releases the connection.
	Close() error
}

// TLSMode is how a client verifies the server it connected to.
//
// It is a named type with no zero-value default rather than a string, because
// the difference between two of its values is the difference between an
// encrypted connection and an authenticated one, and that is not a distinction
// to make by typo.
type TLSMode string

// The TLS modes this package will use.
//
// [TLSVerifyFull] is the default and the only one that authenticates the server.
// The other two are named so that an operator who needs them has to say so in a
// field a reviewer can grep for.
const (
	// TLSVerifyFull encrypts, verifies the server certificate against a root,
	// and checks the hostname. The default.
	TLSVerifyFull TLSMode = "verify-full"

	// TLSVerifyCA encrypts and verifies the certificate chain but not the
	// hostname. Weaker than [TLSVerifyFull] against an attacker who can present
	// a certificate issued by the same root.
	TLSVerifyCA TLSMode = "verify-ca"

	// TLSRequire encrypts and verifies nothing.
	//
	// This is what the source system uses (postgres_roles.go:40,
	// database_extensions.go:41), and it is worth being precise about what it
	// costs rather than describing it as "less secure": "require" means the
	// client will not proceed without TLS and will accept *any* certificate,
	// so it stops a passive observer and does nothing at all against an active
	// one. The master password of a managed database is exactly the material an
	// active attacker is after.
	//
	// It is available because verify-full needs a root certificate the operator
	// has to supply and a deployment may not have one wired up yet. It is not
	// the default, and choosing it is a line in a configuration struct rather
	// than an omission.
	TLSRequire TLSMode = "require"
)

// ConnectionConfig is what it takes to reach a relational endpoint.
//
// It carries no credential material: the password is a separate argument to
// [ConnectionConfig.DSN], so that a config value can be logged, rendered, or
// held in a struct that gets marshalled without a password going with it.
type ConnectionConfig struct {
	// Endpoint is where to connect, as the provider reported it.
	Endpoint compute.SQLEndpoint

	// Username is the account to connect as — the admin account, for
	// everything this package does, because only a Postgres superuser-equivalent
	// may CREATE ROLE or CREATE EXTENSION.
	Username string

	// TLS is how the server is verified. Empty means [TLSVerifyFull].
	TLS TLSMode

	// RootCertPath is the file holding the certificate authority the server's
	// certificate is verified against. Required for [TLSVerifyFull] and
	// [TLSVerifyCA]; ignored for [TLSRequire].
	//
	// It has no default, and there is deliberately no compiled-in bundle: the
	// root that signs a managed database's certificate is a property of a
	// deployment's cloud and region, and a library that shipped one would be
	// shipping a deployment identifier.
	RootCertPath string

	// ConnectTimeout bounds a single connection attempt. Zero means
	// [DefaultConnectTimeout].
	ConnectTimeout time.Duration
}

// DefaultConnectTimeout bounds one connection attempt.
//
// Ten seconds, which is the source system's per-attempt bound
// (postgres_roles.go:132) and exists for the reason it documents: a dropped SYN
// — which is what a missing security-group rule looks like — hangs until the
// kernel gives up, and without a per-attempt bound one such attempt consumes the
// whole retry window.
const DefaultConnectTimeout = 10 * time.Second

// DSN renders the connection string, with the password in it.
//
// It returns a [compute.SecretValue] rather than a string, and that is the whole
// reason this is a method rather than a fmt.Sprintf at the call site: a DSN
// containing a password is credential material, it is exactly the kind of string
// that ends up in an error from a driver's parser, and a type that redacts on
// every stringification path makes the safe behaviour the default.
//
// It is a key/value connection string rather than a URL. The source system builds
// a URL (postgres_roles.go:35-41), and a URL puts the password in the userinfo
// component, where it is subject to percent-encoding rules that differ between
// parsers and where it survives into anything that logs a redacted URL by
// stripping only the parts it recognises. A key/value string has one escaping
// rule, applied here, and no component that another library will try to
// interpret.
func (c ConnectionConfig) DSN(password compute.SecretValue) (compute.SecretValue, error) {
	if err := c.validate(); err != nil {
		return compute.SecretValue{}, err
	}
	mode := c.TLS
	if mode == "" {
		mode = TLSVerifyFull
	}
	timeout := c.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	pairs := [][2]string{
		{"host", c.Endpoint.Host},
		{"port", fmt.Sprint(c.Endpoint.Port)},
		{"dbname", c.Endpoint.DatabaseName},
		{"user", c.Username},
		{"password", compute.RevealSecret(password)},
		{"sslmode", string(mode)},
		{"connect_timeout", fmt.Sprint(int(timeout.Seconds()))},
	}
	if mode != TLSRequire {
		pairs = append(pairs, [2]string{"sslrootcert", c.RootCertPath})
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p[0]+"="+quoteDSNValue(p[1]))
	}
	return compute.NewSecretValue(strings.Join(parts, " ")), nil
}

// Where renders a non-secret description of the endpoint, for a diagnosis.
//
// Host, port, database and account. Every one of those is already in an
// operator's configuration and none of them is material, which is what makes it
// safe to put in a message that replaces a driver's own.
func (c ConnectionConfig) Where() string {
	return fmt.Sprintf("%s:%d/%s as %q", c.Endpoint.Host, c.Endpoint.Port,
		c.Endpoint.DatabaseName, c.Username)
}

// validate refuses a configuration that cannot make a safe connection.
func (c ConnectionConfig) validate() error {
	switch {
	case strings.TrimSpace(c.Endpoint.Host) == "":
		// A provider leaves the host empty until the endpoint is ready, which is
		// what the interface says and what a caller must handle. Saying so is
		// better than a connection attempt to port 5432 on nothing.
		return fmt.Errorf("%w: the endpoint has no host; a provider leaves it empty until the "+
			"endpoint is ready, so wait for it before connecting", compute.ErrInvalidSpec)
	case c.Endpoint.Port <= 0 || c.Endpoint.Port > 65535:
		return fmt.Errorf("%w: the endpoint names port %d", compute.ErrInvalidSpec, c.Endpoint.Port)
	case strings.TrimSpace(c.Endpoint.DatabaseName) == "":
		return fmt.Errorf("%w: the endpoint names no database", compute.ErrInvalidSpec)
	case strings.TrimSpace(c.Username) == "":
		return fmt.Errorf("%w: no username to connect as", compute.ErrInvalidSpec)
	}
	switch c.TLS {
	case "", TLSVerifyFull, TLSVerifyCA:
		if strings.TrimSpace(c.RootCertPath) == "" {
			// Fail closed. The alternative is what every driver does by
			// default: fall back to an unverified connection, which is the
			// same wire protocol and none of the protection, and which nothing
			// in the resulting deployment would report.
			return fmt.Errorf("%w: TLS mode %q verifies the server's certificate and no "+
				"RootCertPath was given. This is refused rather than downgraded: an unverified "+
				"connection carries the database's master password past anyone able to answer on "+
				"its address. Supply the root, or set TLS to %q and accept that",
				compute.ErrInvalidSpec, mode(c.TLS), TLSRequire)
		}
	case TLSRequire:
	default:
		return fmt.Errorf("%w: TLS mode %q is not one this package defines (%q, %q, %q)",
			compute.ErrInvalidSpec, c.TLS, TLSVerifyFull, TLSVerifyCA, TLSRequire)
	}
	return nil
}

func mode(m TLSMode) TLSMode {
	if m == "" {
		return TLSVerifyFull
	}
	return m
}

// quoteDSNValue escapes a value for a libpq key/value connection string.
//
// The rule is short and complete: a value containing a space, a single quote or a
// backslash is wrapped in single quotes with those two characters escaped; an
// empty value is an empty quoted string. Applying it unconditionally rather than
// only when it looks necessary is the point — the values that need it are
// exactly the ones a test never tries.
func quoteDSNValue(v string) string {
	escaped := strings.ReplaceAll(v, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

// sqlConn adapts a *database/sql DB to [Conn].
//
// It uses nothing but the standard library, so this package depends on no
// Postgres driver: registering one, and choosing which, is the composition
// root's decision. The source system's choice is pgx
// (postgres_roles.go:19), which the caller supplies with a blank import.
type sqlConn struct{ db *sql.DB }

// NewSQLConn opens a connection from a DSN and returns it as a [Conn].
//
// driverName is the name a driver registered with database/sql — "pgx" for
// jackc/pgx's stdlib adapter. The DSN carries the password, so it is a
// [compute.SecretValue] and this function is one of the few places
// [compute.SecretValue.Reveal] is called.
//
// where is a non-secret description of the endpoint, for the diagnosis. It is a
// parameter rather than derived here so that this function holds nothing it
// could accidentally render: the only value it has is the DSN, and it never
// formats that.
//
// # The error path
//
// sql.Open parses the DSN, and a driver's parse error can quote what it could
// not parse. The cause is therefore [seal]ed rather than scrubbed — see [sealed]
// for why matching representations was the wrong shape.
func NewSQLConn(driverName, where string, dsn compute.SecretValue) (Conn, error) {
	db, err := sql.Open(driverName, compute.RevealSecret(dsn))
	if err != nil {
		// The cause is sealed and the diagnosis is composed from values that are
		// not secret. A driver's DSN-parse error is exactly the error most likely
		// to quote what it could not parse.
		return nil, fmt.Errorf("%w: opening a %q connection to %s: %w", compute.ErrInvalidSpec,
			driverName, where, seal(err))
	}
	// One connection. Everything this package does is a short sequence of DDL
	// statements against one endpoint, some of it order-dependent, and a pool
	// would let two of them land on two sessions — which matters because
	// standard_conforming_strings is set per session.
	db.SetMaxOpenConns(1)
	return &sqlConn{db: db}, nil
}

func (c *sqlConn) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// Exec implements [Conn].
//
// It honours the obligation on [Conn.Exec]: the statement is not in the error.
// The driver's own error is returned as it came, because the statement text is
// not something database/sql adds — and if a driver ever did add it, the caller
// is what decides whether the cause may be rendered. See [sealed]: the one
// caller that builds a statement containing material seals what comes back.
func (c *sqlConn) Exec(ctx context.Context, stmt string) error {
	_, err := c.db.ExecContext(ctx, stmt)
	return err
}

func (c *sqlConn) QueryExists(ctx context.Context, query string, args ...any) (bool, error) {
	var out bool
	if err := c.db.QueryRowContext(ctx, query, args...).Scan(&out); err != nil {
		return false, err
	}
	return out, nil
}

func (c *sqlConn) Close() error { return c.db.Close() }

// sealed hides an error's message while keeping its identity reachable.
//
// # Why this replaces a redactor, rather than extending one
//
// The first version of this scrubbed the secret out of the driver's message by
// string replacement. Review found three escapes and the third is the one that
// matters, because it is not a missing case — it is the wrong shape:
//
//  1. the DSN path scrubbed the whole DSN, so a driver error containing only the
//     *password* went through unchanged;
//  2. the role path scrubbed the raw password, so a driver echoing the statement
//     — which contains the password's SQL-literal encoding, `pa”ssword` for
//     `pa'ssword` — went through unchanged;
//  3. and where replacement did work, Unwrap handed back the original
//     credential-bearing error, so any ordinary errors.Unwrap(err).Error()
//     recovered the plaintext.
//
// The first two are the same defect: **a redactor matches one representation of
// a secret, and a driver may return any of them.** Adding those two strings to a
// replacement list would leave percent-encoding, JSON escaping, dollar-quoting
// and whatever the next driver does. There is no complete list, which is the
// argument for not needing one.
//
// So this package does not redact. It never renders a driver's message at all,
// and the contract is stated rather than enumerated:
//
//	This package renders no error a database driver returned. Every driver
//	cause is sealed, and no observation of a sealed error — Error, any fmt
//	verb, a wrapped chain, an explicit Unwrap, or an errors.As to the driver's
//	own type — renders it.
//
// # Why every path, and not just the two that carry material
//
// The first attempt at this contract said "two operations hand material to a
// driver: the DSN and the CREATE ROLE statement, so those two seal". That was
// wrong, and the test that quantifies over the product of representations and
// observations is what showed it: **the connection was opened with the DSN, so
// any operation on it can surface a connection error that carries one.** A pool
// establishes lazily, so the first Exec — a session setting, a grant, an
// extension — can return a connect error. A ping failure *is* a connect failure.
//
// The narrower contract was defensible about the statements this package builds
// and silent about the connection those statements travel over. Sealing
// everything costs the driver's text on paths that would have been safe, and
// buys a contract with no case analysis in it.
//
// # What is given up, and what replaces it
//
// The driver's text. In exchange the caller gets a message this package composed
// from values it knows are not secret — the driver name, the endpoint, the
// database, the account, which statement was running — which is more useful for
// diagnosis than "syntax error at or near" and cannot carry a password whatever
// the driver decides to quote.
// The cause is held as a *closure*, not as a field, and that is the part of this
// type that is not obvious.
//
// A field holding the driver's error is reachable by reflection, and `%#v` is
// reflection: fmt walks an error chain field by field, and every field in that
// chain is **unexported** — fmt.wrapError.err, and this type's own cause — so
// reflect.Value.CanInterface is false for all of them and fmt never consults
// Format, Error or GoString at any depth. It prints the struct. A method on this
// type cannot close that, which is why the first two attempts at it did not:
// Error alone left `%#v` leaking, and adding Format did too.
//
// A func field has nothing to descend into. `%#v` renders it as an address, the
// driver's error lives in the closure's environment where reflect cannot follow,
// and errors.Is keeps full fidelity rather than being reduced to a list of
// sentinels this package remembered to preserve.
type sealed struct{ is func(error) bool }

// sealedText is what a sealed error renders, on every path.
const sealedText = "[REDACTED: the driver's message may contain credential material]"

// Error renders nothing about the cause. This is the whole mechanism: there is
// no representation to match because there is no rendering.
func (s sealed) Error() string { return sealedText }

// Format keeps every fmt verb on the same answer.
//
// It is not what closes `%#v` — the closure field is — but it is what stops a
// verb this package did not think to test from finding some other rendering, and
// it costs one method.
func (s sealed) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, sealedText)
}

// Is delegates to the sealed cause, so errors.Is against a sentinel still works
// through a seal — a caller can still tell a cancelled context from a refused
// credential.
//
// Note what is deliberately absent: there is no Unwrap and no As. Unwrap is the
// path review demonstrated recovering the plaintext, and As would hand the
// caller the driver's own error to print. Identity is preserved by delegation
// instead, which answers "is this that kind of failure" without ever producing a
// value whose String method holds material.
//
// # This delegation does execute the cause's own Is, and that is accepted (USOSS-67)
//
// errors.Is calls Is(target) on every chain member it walks, so if the real
// cause defines Is, this delegation runs it -- code a hostile driver wrote. What
// that method receives is exactly target, the caller's own sentinel; it is never
// handed this sealed value, the cause it is part of, or anything else in scope
// here. A hostile Is can therefore only do what it could already do with its own
// fields (the driver already has the password) or lie about a sentinel match,
// which a driver could already achieve by returning a different err outright. See
// docs/decisions/usoss-67-a-hostile-chain-member-s-is-as-method-only-ever-
// receives-the-target-its-caller-supplied.md, and
// TestASealedErrorsIsDelegationCannotExfiltrateThroughAHostileCause.
func (s sealed) Is(target error) bool { return s.is != nil && s.is(target) }

// seal wraps a cause that may carry credential material. A nil cause seals to
// nil, so a caller can seal unconditionally.
func seal(err error) error {
	if err == nil {
		return nil
	}
	// Captured, not stored. See [sealed] for why the difference matters.
	return sealed{is: func(target error) bool { return errors.Is(err, target) }}
}
