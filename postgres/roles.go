// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// RoleType is the privilege level a database role gets.
type RoleType string

// The role types this package grants.
//
// They are the source system's three (database/application.go:1914-1920) and the
// grant sets below are its (postgres_roles.go:186-223).
const (
	// RoleApplication reads and writes rows and may not change the schema.
	RoleApplication RoleType = "application"
	// RoleMigration may change the schema as well.
	RoleMigration RoleType = "migration"
	// RoleReadonly may only read.
	RoleReadonly RoleType = "readonly"
)

// RoleSpec is a database role to create.
type RoleSpec struct {
	// Username is the Postgres role name.
	Username string

	// Type is the privilege level.
	Type RoleType

	// Password is the role's password. The caller generates it and stores it;
	// this package presents it to Postgres and never retains it.
	Password compute.SecretValue

	// EnableRowSecurity sets row_security on for the role, so that policies on
	// its tables apply to it.
	EnableRowSecurity bool
}

// EnsureRole creates or updates one role and grants it the privileges its type
// implies.
//
// # Order, and why it is not the source's
//
// The source system creates the role, grants, and then enables row security
// (postgres_roles.go:78-100), and on a failure of any step it logs and moves to
// the next role. That leaves a role that exists and can log in but has no
// privileges, or has privileges and no row security — states an operator has to
// diagnose from a log line. Here a failure at any step is returned, so the caller
// decides; the role may still exist, which is stated on the error rather than
// hidden, because CREATE ROLE and GRANT cannot be one transaction in a way that
// survives a connection drop.
//
// Row security is enabled **before** the grants rather than after. The source's
// order leaves a window in which the role can select from tables whose policies
// do not yet apply to it — short, and on a fresh database usually empty, but the
// order costs nothing to get right.
//
// # The password
//
// Postgres cannot parameterise a role password: CREATE ROLE ... PASSWORD takes a
// literal, so exactly one statement here contains credential material. Three
// things follow.
//
// The literal is escaped for a session with standard_conforming_strings on, which
// this function sets first. That matters: with it *off*, a backslash in the
// literal is an escape character and the source system's doubling of backslashes
// (postgres_roles.go:259) is correct; with it *on*, which the source also sets
// (postgres_roles.go:53), doubling inserts two backslashes and the password
// Postgres stores is not the password the caller stored. The source contains both
// halves and they contradict each other. See [escapeLiteral].
//
// A password containing a NUL byte is refused rather than stripped. The source
// strips it (postgres_roles.go:261), which means the role's password silently
// differs from the caller's copy — the same class of defect as the backslash one
// and with the same symptom, an authentication failure far from its cause.
//
// The statement never appears in an error. See [Conn].
//
// # What is not fixed here
//
// A password in a DDL literal reaches the server's statement log if
// log_statement is 'ddl' or 'all', and a managed database's admin account cannot
// reliably turn that off for its session. Passing a pre-computed SCRAM verifier
// instead would keep the plaintext off the wire and out of the log, and it is not
// done here because it cannot be verified against a real Postgres under this
// repository's hermetic-test bar — an untested SCRAM derivation that is wrong
// produces a role nobody can log into. It is recorded as a known limitation and a
// follow-up rather than attempted blind.
func (p *Provisioner) EnsureRole(ctx context.Context, spec RoleSpec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	if err := p.prepare(ctx); err != nil {
		return err
	}

	quoted := quoteIdentifier(spec.Username)
	exists, err := p.conn.QueryExists(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", spec.Username)
	if err != nil {
		return fmt.Errorf("%w: checking whether role %q exists: %w", compute.ErrFailed,
			spec.Username, seal(err))
	}

	verb := "CREATE ROLE "
	if exists {
		verb = "ALTER ROLE "
	}
	stmt := verb + quoted + " WITH LOGIN PASSWORD " + escapeLiteral(compute.RevealSecret(spec.Password))
	if err := p.conn.Exec(ctx, stmt); err != nil {
		// The only statement this package builds that contains credential
		// material, so the only place besides the DSN whose cause is sealed.
		//
		// Sealed rather than scrubbed. A driver that echoes the statement echoes
		// the password's *SQL-literal encoding* — `pa''ssword` for `pa'ssword` —
		// which a redactor matching the raw password does not recognise, and
		// that is one representation of an open-ended set. See [sealed].
		//
		// What the caller is told instead is the role name and the fact that the
		// role may now exist without the privileges this call would have
		// granted, which is what they need in order to decide what to do.
		return fmt.Errorf("%w: setting the password for role %q; the role may exist without the "+
			"privileges this call would have granted: %w", compute.ErrFailed, spec.Username,
			seal(err))
	}

	if spec.EnableRowSecurity {
		// Before the grants, not after: see the function comment.
		if err := p.conn.Exec(ctx, "ALTER ROLE "+quoted+" SET row_security = on"); err != nil {
			// Fatal, unlike the source, which logs a warning and continues
			// (postgres_roles.go:96-100). A role that was asked for row-level
			// security and did not get it reads rows a policy was written to
			// hide, and reporting that as a warning on a successful deploy is
			// the shape of failure this port exists to remove.
			return fmt.Errorf("%w: enabling row security for role %q: %w", compute.ErrFailed,
				spec.Username, seal(err))
		}
	}
	return p.grantPrivileges(ctx, spec, quoted)
}

func (s RoleSpec) validate() error {
	switch {
	case strings.TrimSpace(s.Username) == "":
		return fmt.Errorf("%w: a role needs a username", compute.ErrInvalidSpec)
	case s.Password.IsZero():
		return fmt.Errorf("%w: role %q has no password; a login role with no password is a role "+
			"nothing can use, and a role created without one would have to be found and fixed by "+
			"hand", compute.ErrInvalidSpec, s.Username)
	case strings.ContainsRune(compute.RevealSecret(s.Password), 0):
		// Refused, not stripped. Stripping makes the password Postgres stores
		// differ from the caller's stored copy, and the symptom is an
		// authentication failure on a later deploy with nothing pointing here.
		return fmt.Errorf("%w: the password for role %q contains a NUL byte, which cannot appear "+
			"in a Postgres string literal. It is refused rather than stripped, because a stripped "+
			"password no longer matches the copy the caller stored", compute.ErrInvalidSpec,
			s.Username)
	}
	switch s.Type {
	case RoleApplication, RoleMigration, RoleReadonly:
		return nil
	default:
		// No default privilege set. A typo in a role type must not silently
		// become the widest one, and it must not silently become the narrowest
		// either: either guess produces a working deploy with the wrong access.
		return fmt.Errorf("%w: role %q has type %q, which is not one this package defines (%q, "+
			"%q, %q)", compute.ErrInvalidSpec, s.Username, s.Type, RoleApplication, RoleMigration,
			RoleReadonly)
	}
}

// grantPrivileges issues the GRANT statements a role type implies.
//
// The sets are the source system's (postgres_roles.go:189-215). They are
// reproduced rather than redesigned, because narrowing them is a change to what
// deployed applications can do and belongs in its own review — but two things are
// worth writing down about them, since a reader will otherwise assume they were
// chosen here.
//
// [RoleMigration] gets ALL PRIVILEGES on tables and sequences plus CREATE on the
// schema, which includes DROP. A migration role is therefore able to destroy the
// application's data, and the platform gives one to any component that asks for
// it. That is the source's model and it is the widest grant here by a long way.
//
// [RoleApplication] gets no TRUNCATE and no REFERENCES, which is a real narrowing
// and worth keeping.
func (p *Provisioner) grantPrivileges(ctx context.Context, spec RoleSpec, quotedUser string) error {
	// The database the role may connect to is the one this Provisioner is
	// against, held on the Provisioner rather than taken as a parameter — as
	// the source does (postgres_roles.go:186) — because a parameter invites a
	// grant on a database the caller is not connected to.
	grants := []string{
		"GRANT CONNECT ON DATABASE " + quoteIdentifier(p.database) + " TO " + quotedUser,
		"GRANT USAGE ON SCHEMA public TO " + quotedUser,
	}
	switch spec.Type {
	case RoleApplication:
		grants = append(grants,
			"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "+quotedUser,
			"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "+quotedUser,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "+quotedUser,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "+quotedUser,
		)
	case RoleMigration:
		grants = append(grants,
			"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "+quotedUser,
			"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "+quotedUser,
			"GRANT CREATE ON SCHEMA public TO "+quotedUser,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO "+quotedUser,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO "+quotedUser,
		)
	case RoleReadonly:
		grants = append(grants,
			"GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+quotedUser,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "+quotedUser,
		)
	}
	for _, grant := range grants {
		if err := p.conn.Exec(ctx, grant); err != nil {
			// The statement is in this error and that is safe: a GRANT contains
			// a role name and a privilege list and never credential material.
			// The password-bearing statement is the one in EnsureRole, and it
			// is the only one whose text is withheld.
			// The statement is named and the cause is sealed. A GRANT contains a
			// role name and a privilege list and never material, so naming it is
			// safe and useful; the *cause* is sealed because it may be a
			// connection error, and this connection was opened with a DSN.
			return fmt.Errorf("%w: executing %q: %w", compute.ErrFailed, grant, seal(err))
		}
	}
	return nil
}

// setStandardConformingStrings puts the session into the string-literal mode
// [escapeLiteral] escapes for.
//
// It is not a formality. The escaping rule for a Postgres string literal depends
// on this setting, so a function that escapes one way and a session that
// interprets the other way produce a password, a name, or a value that is not the
// one that was passed. Setting it explicitly makes the pairing checkable instead
// of dependent on a server default.
func (p *Provisioner) setStandardConformingStrings(ctx context.Context) error {
	if err := p.conn.Exec(ctx, "SET standard_conforming_strings = on"); err != nil {
		return fmt.Errorf("%w: setting standard_conforming_strings: %w", compute.ErrFailed, seal(err))
	}
	return nil
}

// quoteIdentifier renders a Postgres identifier safely.
//
// The rule is complete for a quoted identifier: double every embedded double
// quote and wrap. Nothing else can end the identifier, so nothing else can escape
// it.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// escapeLiteral renders a Postgres string literal, including the quotes.
//
// # The rule, and the bug it is written against
//
// With standard_conforming_strings **on** — which
// [setStandardConformingStrings] guarantees — a backslash inside a single-quoted
// literal is an ordinary character and the only escape is a doubled single
// quote. So doubling a single quote is the whole rule, and doubling a backslash
// is *wrong*: it inserts two backslashes where the caller had one.
//
// The source system does both. It sets standard_conforming_strings on
// (postgres_roles.go:53) and then escapes as though it were off, doubling
// backslashes (postgres_roles.go:259). The two halves contradict each other, and
// the effect is that a password containing a backslash is stored in the platform's
// secret store with one and set in Postgres with two — so the role cannot log in,
// and the failure surfaces on a later deploy as an authentication error with
// nothing pointing at the escaping. It is unreachable in the source only because
// its generated passwords are alphanumeric (database.go:409); a caller-supplied
// password reaches it.
//
// Returning the quotes rather than taking them from the caller is deliberate: an
// escaping function whose output has to be wrapped by its caller is a function
// somebody eventually forgets to wrap.
func escapeLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
