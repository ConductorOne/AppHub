// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"text/template"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/postgres"
)

// Every test here runs with no database. That is not a compromise, it is the
// design: [postgres.Conn] is the seam, so the composition of statements — which
// is the whole of what this package does — is exercised directly, and the
// repository's hermeticity bar (no network, no cluster, no fixed ports) is met by
// construction rather than by a container that this shared environment could not
// bind a port for anyway.
//
// What that does *not* cover is stated rather than implied, in
// [TestWhatIsNotVerifiedHere].

// --- a Conn under the test's control ----------------------------------------

// recordingConn is a [postgres.Conn] that remembers every statement and can be
// made to fail any of them.
type recordingConn struct {
	stmts   []string
	queries []string
	// exists is what QueryExists answers.
	exists bool
	// failOn makes Exec fail for the first statement containing this substring.
	failOn string
	// failWith is the error it fails with. A driver that echoed the statement
	// would produce one of these, which is how the redaction obligation is
	// tested.
	failWith error
	// pingErr makes Ping fail.
	pingErr error
	// queryErr makes QueryExists fail.
	queryErr error
	closed   bool
}

func (c *recordingConn) Ping(context.Context) error { return c.pingErr }

func (c *recordingConn) Exec(_ context.Context, stmt string) error {
	c.stmts = append(c.stmts, stmt)
	if c.failOn != "" && strings.Contains(stmt, c.failOn) {
		if c.failWith != nil {
			return c.failWith
		}
		return errors.New("substrate refused the statement")
	}
	return nil
}

func (c *recordingConn) QueryExists(_ context.Context, query string, _ ...any) (bool, error) {
	c.queries = append(c.queries, query)
	return c.exists, c.queryErr
}

func (c *recordingConn) Close() error {
	c.closed = true
	return nil
}

// all returns every statement joined, for a containment assertion.
func (c *recordingConn) all() string { return strings.Join(c.stmts, "\n") }

func newProvisioner(t *testing.T, conn postgres.Conn) *postgres.Provisioner {
	t.Helper()
	p, err := postgres.NewProvisioner(conn, "appdb")
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p
}

// rolePassword is the sentinel this file plants and hunts for.
const rolePassword = "apphub-test-role-password-sentinel"

// --- the extension allowlist ------------------------------------------------

// TestTheExtensionAllowlistRefusesEverythingNotOnIt states the security control
// as a property over a generated population, not as three named cases.
//
// The control is that CREATE EXTENSION runs the extension's own script with the
// admin account's privileges, so the set of names an application may use is an
// allowlist. Naming three extensions that are refused would leave the
// interesting shapes untried: the whole risk in an allowlist implemented with a
// map lookup is that something *normalises* the input — trims it, lowercases it,
// unquotes it — and thereby accepts a string the list does not contain.
//
// So the population is built *from the allowlist itself*: every member, mutated
// every way a normalising implementation would forgive. That is a class, and it
// grows automatically if the allowlist does.
func TestTheExtensionAllowlistRefusesEverythingNotOnIt(t *testing.T) {
	t.Parallel()

	allowed := postgres.AllowedExtensions()
	if len(allowed) == 0 {
		// A derivation that returns nothing passes every check over it.
		t.Fatal("AllowedExtensions() is empty, so every assertion below is about nothing")
	}
	// Sorted, because it is used in an operator-facing message and in an API
	// validation error.
	if !sort.StringsAreSorted(allowed) {
		t.Errorf("AllowedExtensions() is not sorted: %v", allowed)
	}
	// The derivation and the predicate have to agree, in both directions.
	for _, name := range allowed {
		if !postgres.IsAllowedExtension(name) {
			t.Errorf("AllowedExtensions() returned %q and IsAllowedExtension refuses it", name)
		}
	}

	// Every way a normalising implementation would let a non-member through.
	mutations := map[string]func(string) string{
		"upper case":            strings.ToUpper,
		"title case":            func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		"leading space":         func(s string) string { return " " + s },
		"trailing space":        func(s string) string { return s + " " },
		"surrounding space":     func(s string) string { return " " + s + " " },
		"tab":                   func(s string) string { return "\t" + s },
		"newline":               func(s string) string { return s + "\n" },
		"double-quoted":         func(s string) string { return `"` + s + `"` },
		"single-quoted":         func(s string) string { return "'" + s + "'" },
		"schema-qualified":      func(s string) string { return "public." + s },
		"trailing semicolon":    func(s string) string { return s + ";" },
		"statement appended":    func(s string) string { return s + "; DROP SCHEMA public CASCADE" },
		"comment appended":      func(s string) string { return s + " --" },
		"quote break-out":       func(s string) string { return s + `"; DROP SCHEMA public CASCADE --` },
		"prefix of a member":    func(s string) string { return s[:len(s)-1] },
		"member with a suffix":  func(s string) string { return s + "x" },
		"null byte appended":    func(s string) string { return s + "\x00" },
		"unicode look-alike":    func(s string) string { return strings.Replace(s, "e", "е", 1) },
		"repeated":              func(s string) string { return s + s },
		"wrapped in whitespace": func(s string) string { return "\n\t " + s + " \t\n" },
	}
	checked := 0
	for _, member := range allowed {
		for what, mutate := range mutations {
			candidate := mutate(member)
			if candidate == member {
				// A mutation that changed nothing is not a test of anything.
				continue
			}
			checked++
			if postgres.IsAllowedExtension(candidate) {
				t.Errorf("IsAllowedExtension accepted %q (%s of the allowlisted %q). The control "+
					"is an allowlist, so its accepted language must be exactly the set of names "+
					"in it; anything wider is an unenumerated surface on a privilege boundary",
					candidate, what, member)
			}
		}
	}
	if checked < len(allowed)*10 {
		t.Fatalf("only %d mutations were tried across %d allowlisted names, which is too few for "+
			"the property to mean anything", checked, len(allowed))
	}

	// And names with no relationship to the list, including the ones a
	// privilege-escalation attempt would actually reach for.
	for _, name := range []string{
		"", " ", "*", "all",
		// Extensions that exist and are deliberately not on the list, because
		// they need shared_preload_libraries or because they are the escalation
		// path itself.
		"plpythonu", "plperlu", "pltclu", "file_fdw", "postgres_fdw", "dblink",
		"adminpack", "pg_cron", "pg_stat_statements", "lo", "pageinspect",
	} {
		if postgres.IsAllowedExtension(name) {
			t.Errorf("IsAllowedExtension accepted %q", name)
		}
	}
}

// TestEnsureExtensionsRefusesTheWholeCallOnOneBadName is the behaviour change
// this port makes deliberately.
//
// The source system logs a warning and carries on
// (database_extensions.go:55-58), which produces a successful deploy of an
// application whose database is missing the type it depends on — the failure
// arrives later, at runtime, from a component nobody was changing. Its own API
// layer refuses the same set (services/application.go:1187-1188), so the two
// halves of the source disagree; this agrees with the half that fails closed.
//
// The assertion has two parts, and the second is the one that matters: nothing
// was executed. A call that installed the good extensions and then refused would
// leave a caller reasoning about a half-applied set.
func TestEnsureExtensionsRefusesTheWholeCallOnOneBadName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := &recordingConn{}
	p := newProvisioner(t, conn)

	err := p.EnsureExtensions(ctx, []string{"vector", "dblink", "pg_trgm"})
	if err == nil {
		t.Fatal("a request naming an extension off the allowlist succeeded")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "dblink") {
		t.Errorf("the error does not name the extension that was refused: %v", err)
	}
	if len(conn.stmts) != 0 {
		t.Errorf("the call executed %d statements before refusing: %v. Validating every name "+
			"before executing any statement is what makes a retry after fixing the name reason "+
			"about nothing half-applied", len(conn.stmts), conn.stmts)
	}
}

// TestEnsureExtensionsIsIdempotentAndQuotes covers the happy path's two
// properties.
func TestEnsureExtensionsIsIdempotentAndQuotes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := &recordingConn{}
	p := newProvisioner(t, conn)

	// uuid-ossp is the reason the identifier is quoted rather than the reason it
	// is safe: it contains a hyphen, so an unquoted statement would be a syntax
	// error for a name that is on the allowlist.
	if err := p.EnsureExtensions(ctx, []string{"vector", "uuid-ossp"}); err != nil {
		t.Fatalf("EnsureExtensions: %v", err)
	}
	if !strings.Contains(conn.all(), `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`) {
		t.Errorf("the statement for a hyphenated extension name is not quoted: %v", conn.stmts)
	}
	if !strings.Contains(conn.all(), "IF NOT EXISTS") {
		t.Error("the statement is not idempotent; this runs on every deploy")
	}
	if !strings.Contains(conn.all(), "standard_conforming_strings = on") {
		t.Error("the session's string-literal mode was not set, so the escaping this package " +
			"applies and the mode the server interprets are not paired")
	}
	// An empty request does nothing at all, including not connecting.
	fresh := &recordingConn{}
	if err := newProvisioner(t, fresh).EnsureExtensions(ctx, nil); err != nil {
		t.Errorf("an empty extension list returned %v", err)
	}
	if len(fresh.stmts) != 0 {
		t.Errorf("an empty extension list executed %v", fresh.stmts)
	}
}

// --- roles ------------------------------------------------------------------

// TestEnsureRoleGrantsExactlyItsTypesPrivileges pins each role type's grant set
// against the properties that distinguish them, rather than against a golden
// list of statements.
//
// A golden list would pass while saying nothing about what the sets *mean*, and
// what they mean is the whole point: a read-only role that could write is a
// privilege bug, and a migration role that could not create is a broken deploy.
func TestEnsureRoleGrantsExactlyItsTypesPrivileges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		role    postgres.RoleType
		granted []string
		refused []string
	}{
		{
			role:    postgres.RoleReadonly,
			granted: []string{"GRANT CONNECT", "GRANT USAGE ON SCHEMA", "GRANT SELECT ON ALL TABLES"},
			refused: []string{"INSERT", "UPDATE", "DELETE", "ALL PRIVILEGES", "GRANT CREATE"},
		},
		{
			role: postgres.RoleApplication,
			granted: []string{
				"GRANT CONNECT", "GRANT USAGE ON SCHEMA",
				"SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
				"ALTER DEFAULT PRIVILEGES",
			},
			// The narrowing worth keeping: an application role cannot change
			// the schema and cannot truncate.
			refused: []string{"ALL PRIVILEGES", "GRANT CREATE", "TRUNCATE", "REFERENCES"},
		},
		{
			role: postgres.RoleMigration,
			granted: []string{
				"GRANT CONNECT", "ALL PRIVILEGES ON ALL TABLES", "GRANT CREATE ON SCHEMA",
			},
			refused: nil,
		},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			t.Parallel()
			conn := &recordingConn{}
			p := newProvisioner(t, conn)
			if err := p.EnsureRole(ctx, postgres.RoleSpec{
				Username: "webapp_user",
				Type:     tc.role,
				Password: compute.NewSecretValue(rolePassword),
			}); err != nil {
				t.Fatalf("EnsureRole: %v", err)
			}
			all := conn.all()
			for _, want := range tc.granted {
				if !strings.Contains(all, want) {
					t.Errorf("a %s role was not granted %q: %v", tc.role, want, conn.stmts)
				}
			}
			for _, unwanted := range tc.refused {
				if strings.Contains(all, unwanted) {
					t.Errorf("a %s role was granted %q, which is wider than its type means",
						tc.role, unwanted)
				}
			}
			// The CONNECT grant names the database this provisioner is against,
			// quoted. Taking it as a parameter would let a caller grant CONNECT
			// on a database nobody looked at.
			if !strings.Contains(all, `GRANT CONNECT ON DATABASE "appdb"`) {
				t.Errorf("the CONNECT grant does not name the provisioner's own database: %v",
					conn.stmts)
			}
		})
	}
}

// TestEnsureRoleUsesAlterForAnExistingRole is the idempotence property: this
// runs on every deploy.
func TestEnsureRoleUsesAlterForAnExistingRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, exists := range []bool{false, true} {
		conn := &recordingConn{exists: exists}
		p := newProvisioner(t, conn)
		if err := p.EnsureRole(ctx, postgres.RoleSpec{
			Username: "webapp_user",
			Type:     postgres.RoleApplication,
			Password: compute.NewSecretValue(rolePassword),
		}); err != nil {
			t.Fatalf("EnsureRole (exists=%v): %v", exists, err)
		}
		want, unwanted := "CREATE ROLE", "ALTER ROLE "
		if exists {
			want, unwanted = "ALTER ROLE ", "CREATE ROLE"
		}
		if !strings.Contains(conn.all(), want) {
			t.Errorf("exists=%v used neither %q: %v", exists, want, conn.stmts)
		}
		if strings.Contains(conn.all(), unwanted) && !exists {
			t.Errorf("exists=%v used %q: %v", exists, unwanted, conn.stmts)
		}
		if len(conn.queries) == 0 {
			t.Error("the role's existence was never checked")
		}
	}
}

// TestRowSecurityIsEnabledBeforeTheGrants pins an ordering the source system gets
// the other way round.
//
// The source grants first and then enables row security
// (postgres_roles.go:87-100), which leaves a window in which the role can select
// from tables whose policies do not apply to it. Short, and on a fresh database
// usually empty — but the order costs nothing to get right, and an ordering that
// is only correct by accident is one a later edit reverses.
func TestRowSecurityIsEnabledBeforeTheGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := &recordingConn{}
	p := newProvisioner(t, conn)
	if err := p.EnsureRole(ctx, postgres.RoleSpec{
		Username:          "webapp_user",
		Type:              postgres.RoleApplication,
		Password:          compute.NewSecretValue(rolePassword),
		EnableRowSecurity: true,
	}); err != nil {
		t.Fatalf("EnsureRole: %v", err)
	}
	rls, grant := -1, -1
	for i, stmt := range conn.stmts {
		if strings.Contains(stmt, "row_security = on") && rls < 0 {
			rls = i
		}
		if strings.Contains(stmt, "GRANT SELECT") && grant < 0 {
			grant = i
		}
	}
	switch {
	case rls < 0:
		t.Fatalf("row security was never enabled: %v", conn.stmts)
	case grant < 0:
		t.Fatalf("no privileges were granted: %v", conn.stmts)
	case rls > grant:
		t.Errorf("row security was enabled at statement %d and privileges granted at %d; the "+
			"role can read rows a policy was written to hide in between", rls, grant)
	}
}

// TestAFailureToEnableRowSecurityIsFatal is the other half of the same decision.
//
// The source logs a warning and continues (postgres_roles.go:96-100), so a role
// that asked for row-level security and did not get it reads rows a policy was
// written to hide, and the deploy reports success.
func TestAFailureToEnableRowSecurityIsFatal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := &recordingConn{failOn: "row_security"}
	err := newProvisioner(t, conn).EnsureRole(ctx, postgres.RoleSpec{
		Username:          "webapp_user",
		Type:              postgres.RoleApplication,
		Password:          compute.NewSecretValue(rolePassword),
		EnableRowSecurity: true,
	})
	if err == nil {
		t.Fatal("a failure to enable row security was not reported; the deploy would report " +
			"success with the role reading rows a policy was written to hide")
	}
	if strings.Contains(conn.all(), "GRANT SELECT") {
		t.Error("privileges were granted after row security failed to apply")
	}
}

// --- the credential path ----------------------------------------------------

// TestNoObservationOfAnErrorYieldsCredentialMaterial is the population review
// showed the first version of this test was not counting.
//
// The first version used one alphanumeric password, one driver error shape, and
// checked only the outer err.Error(). It called that a class and it was not: the
// class has **two axes**, and the defects review found were one in each.
//
//   - **Representation.** A driver may return the secret in any encoding. The
//     raw password, its SQL-literal encoding (`pa”ssword` for `pa'ssword`,
//     which is what a driver echoing the statement contains), the DSN it is
//     embedded in, a percent-encoded form, a JSON-escaped form. A redactor
//     matching one of these misses the rest, and there is no complete list.
//   - **Observation.** A caller may look at the error in several ways.
//     err.Error(), any fmt verb, the message of an error that wrapped it,
//     walking the Unwrap chain to exhaustion, and errors.As to the driver's own
//     type. Review recovered the plaintext through Unwrap while Error() was
//     clean.
//
// So this quantifies over the product of the two, and it passes for a reason
// that does not depend on the representation axis being complete:
// [postgres.sealed] never renders the cause at all. That is why the fix was not
// three more strings in a replacement list.
func TestNoObservationOfAnErrorYieldsCredentialMaterial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Passwords chosen so that their encodings differ from their raw form. An
	// alphanumeric password — which is all the first version used, and all the
	// source system generates — makes every representation identical and the
	// representation axis vacuous.
	for _, password := range []string{
		`pa'ssword`,      // SQL-literal encoding doubles the quote
		`pa\ssword`,      // a backslash, which some drivers escape
		`pa ss word`,     // spaces, which the DSN quotes
		`pa"ss'word\x00`, // several at once, minus the NUL this package refuses
		"review-password-sentinel",
	} {
		t.Run(password, func(t *testing.T) {
			t.Parallel()
			representations := representationsOf(t, password)
			// Non-vacuity: the encodings must actually differ from the raw form
			// for at least one of these, or the axis proves nothing.
			if len(representations) < 2 {
				t.Fatalf("only %d representation(s) of %q, so this axis is about nothing",
					len(representations), password)
			}

			spec := postgres.RoleSpec{
				Username:          "webapp_user",
				Type:              postgres.RoleApplication,
				Password:          compute.NewSecretValue(password),
				EnableRowSecurity: true,
			}

			// Every path that fails while the material is in flight, driven with
			// a driver error carrying every representation at once.
			for what, conn := range map[string]*recordingConn{
				"the ping fails":            {pingErr: leakingError{body: representations}},
				"the existence query fails": {queryErr: leakingError{body: representations}},
				"the session setting fails": {failOn: "standard_conforming_strings", failWith: leakingError{body: representations}},
				"the role statement fails":  {failOn: "ROLE", failWith: leakingError{body: representations}},
				"row security fails":        {failOn: "row_security", failWith: leakingError{body: representations}},
				"a grant fails":             {failOn: "GRANT", failWith: leakingError{body: representations}},
			} {
				t.Run(what, func(t *testing.T) {
					t.Parallel()
					err := newProvisioner(t, conn).EnsureRole(ctx, spec)
					if err == nil {
						t.Fatal("the call succeeded, so this path was not searched")
					}
					assertNoMaterial(t, err, representations)
				})
			}
		})
	}
}

// representationsOf builds the encodings of a secret a driver might return.
//
// Deduplicated against the raw form, so a password whose encodings coincide with
// it contributes one entry and the non-vacuity check above notices.
func representationsOf(t *testing.T, password string) []string {
	t.Helper()
	cfg := postgres.ConnectionConfig{
		Endpoint:     compute.SQLEndpoint{Host: "cluster.rds.invalid", Port: 5432, DatabaseName: "appdb"},
		Username:     "appuser",
		RootCertPath: "/etc/apphub/rds-root.pem",
	}
	dsn, err := cfg.DSN(compute.NewSecretValue(password))
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
	candidates := []string{
		password,
		// The SQL-literal encoding, which is what a driver echoing the statement
		// contains. This is review's finding 2.
		strings.ReplaceAll(password, "'", "''"),
		// The whole DSN, which is what the connection path used to scrub — and
		// review's finding 1 is that scrubbing this leaves a password-only error
		// untouched, so both have to be in the population.
		compute.RevealSecret(dsn),
		// A percent-encoded form, which a driver that built a URL would produce.
		url.QueryEscape(password),
		// A JSON-escaped form, which a driver reporting a structured error would.
		strings.Trim(mustJSON(t, password), `"`),
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(b)
}

// leakingError is a driver error that returns every representation it was given,
// and keeps one nested a level deeper so an Unwrap walk has somewhere to find it.
type leakingError struct{ body []string }

func (e leakingError) Error() string {
	return "syntax error at or near: " + strings.Join(e.body, " / ")
}

// Unwrap returns a cause that also renders the material, which is what makes the
// Unwrap axis of this test real: a seal that only cleaned the top level would
// pass Error() and fail here.
func (e leakingError) Unwrap() error { return leakingCause(e) }

type leakingCause leakingError

func (e leakingCause) Error() string { return "underlying: " + strings.Join(e.body, " / ") }

// assertNoMaterial observes err every way a caller can and fails if any
// observation renders any representation.
//
// # Two corrections to what this used to cover
//
// **Every verb, not the five that came to mind.** `fmt` dispatches some verbs
// ahead of [fmt.Formatter] — `%p` is the one that has caught two other redacting
// types on this project — so a type that redacts on the verbs somebody thought
// of is not a type that redacts. The list below is every verb `fmt` defines, on
// the principle that closing them one at a time is enumeration.
//
// **The chain walk could not traverse.** The errors this package returns are
// built with two `%w` verbs, which produces a wrapper implementing
// `Unwrap() []error` — and `errors.Unwrap` returns **nil** for those. So the
// single-error walk reached depth 1 and stopped, proving nothing about the seal
// it was supposed to reach. Both walks now run: the single-error one for
// ordinary chains, and the multi-error one, which visits three nodes here.
func assertNoMaterial(t *testing.T, err error, representations []string) {
	t.Helper()

	// Every verb fmt defines. Several are meaningless for an error and produce a
	// %!verb(...) rendering — which is exactly the path worth checking, because
	// that rendering is produced by reflection over the value rather than by any
	// method on it.
	verbs := []string{
		"%v", "%s", "%q", "%d", "%p", "%T", "%x", "%X", "%b", "%o", "%O",
		"%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%#v", "%+v",
	}
	observations := map[string]string{
		"Error()":        err.Error(),
		"wrapped":        fmt.Errorf("deploy failed: %w", err).Error(),
		"doubly wrapped": fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", err)).Error(),
	}
	for _, verb := range verbs {
		observations[verb] = fmt.Sprintf(verb, err)
	}

	// The single-error chain. Kept even though it cannot traverse a two-%w
	// wrapper, because a caller will use it and an ordinary chain does traverse.
	depth := 0
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		for _, verb := range verbs {
			observations[fmt.Sprintf("Unwrap depth %d %s", depth, verb)] = fmt.Sprintf(verb, cause)
		}
		depth++
		if depth > 20 {
			t.Fatal("the error chain does not terminate")
		}
	}

	// The multi-error chain, which is the one that actually reaches the seal.
	visited := 0
	var walk func(error)
	walk = func(e error) {
		visited++
		if visited > 40 {
			t.Fatal("the multi-error chain does not terminate")
		}
		multi, ok := e.(interface{ Unwrap() []error })
		if !ok {
			return
		}
		for i, cause := range multi.Unwrap() {
			for _, verb := range verbs {
				observations[fmt.Sprintf("multi %d.%d %s", visited, i, verb)] = fmt.Sprintf(verb, cause)
			}
			walk(cause)
		}
	}
	walk(err)
	if visited < 2 {
		// A walk that reached only the outer error proves nothing about the
		// seal underneath it, which is the mistake the first version made.
		t.Fatalf("the multi-error walk visited %d node(s); it is not reaching the sealed cause",
			visited)
	}

	// And errors.As to the driver's own types, which would hand the caller
	// something whose Error method holds material.
	var driverErr leakingError
	if errors.As(err, &driverErr) {
		observations["errors.As(leakingError)"] = driverErr.Error()
	}
	var driverCause leakingCause
	if errors.As(err, &driverCause) {
		observations["errors.As(leakingCause)"] = driverCause.Error()
	}

	for how, rendered := range observations {
		for _, representation := range representations {
			if strings.Contains(rendered, representation) {
				// Deliberately prints neither the observation nor the material.
				t.Errorf("observing the error via %s renders a representation of the credential. "+
					"An error is logged, returned to an API caller, and on this platform persisted "+
					"onto a job record and rendered in an interface", how)
			}
		}
	}
}

// TestASealedErrorKeepsItsIdentity is the other half: sealing must not cost the
// caller the ability to tell what kind of failure it was.
//
// Without this, "seal everything" would pass the test above and leave a caller
// unable to distinguish a cancelled context from a refused credential — which is
// the reason a redactor was reached for in the first place.
func TestASealedErrorKeepsItsIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	spec := postgres.RoleSpec{
		Username: "webapp_user",
		Type:     postgres.RoleApplication,
		Password: compute.NewSecretValue(rolePassword),
	}
	for name, sentinel := range map[string]error{
		"a cancelled context": context.Canceled,
		"a deadline":          context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn := &recordingConn{
				failOn:   "ROLE",
				failWith: fmt.Errorf("driver gave up on %s: %w", rolePassword, sentinel),
			}
			err := newProvisioner(t, conn).EnsureRole(ctx, spec)
			if err == nil {
				t.Fatal("the call succeeded")
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("errors.Is could not see %v through the seal; sealing must hide the "+
					"message and keep the identity, or a caller cannot tell a cancellation from a "+
					"credential failure", sentinel)
			}
			// And still no material, from an error that carried it alongside the
			// sentinel.
			assertNoMaterial(t, err, []string{rolePassword})
			// The compute taxonomy survives too.
			if !errors.Is(err, compute.ErrFailed) {
				t.Error("the compute sentinel was lost")
			}
		})
	}
}

// TestASealedErrorsIsDelegationCannotExfiltrateThroughAHostileCause is
// USOSS-67's pin on the note-only residual PR #27's reviewer found:
// [sealed.Is] delegates to the real cause, so a hostile driver error's own Is
// method genuinely executes.
//
// It receives exactly one thing: the target the caller passed to errors.Is,
// same as at every other errors.Is call site in this repository (see
// docs/decisions/usoss-67-a-hostile-chain-member-s-is-as-method-only-ever-
// receives-the-target-its-caller-supplied.md). It is never handed the cause
// it is part of, this package's Provisioner, or anything else in scope here
// -- Go's method dispatch does not expose a caller's other locals to a
// callee. So a hostile Is has two capabilities and no others: whatever its
// own fields already hold (the driver already has the password; that is not
// new), and the power to lie about whichever sentinel the caller compared
// against -- which grants nothing a driver could not already do by returning
// a different err outright.
//
// This drives both: the hostile cause carries the same representations
// [assertNoMaterial] hunts for, and its Is method claims a match for
// anything it is asked about while recording every target it was ever handed.
func TestASealedErrorsIsDelegationCannotExfiltrateThroughAHostileCause(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	representations := representationsOf(t, rolePassword)
	var seenTargets []error
	cause := hostileCause{body: representations, seen: &seenTargets}

	spec := postgres.RoleSpec{
		Username: "webapp_user",
		Type:     postgres.RoleApplication,
		Password: compute.NewSecretValue(rolePassword),
	}
	conn := &recordingConn{failOn: "ROLE", failWith: cause}
	err := newProvisioner(t, conn).EnsureRole(ctx, spec)
	if err == nil {
		t.Fatal("the call succeeded")
	}

	// However adversarial the delegated Is is, it must not be able to make an
	// observation of the sealed error render the driver's text.
	assertNoMaterial(t, err, representations)

	// The hostile cause lies unconditionally, so errors.Is against ANY
	// sentinel now reports true -- the bounded, already-possible consequence
	// named above, not a new one. Demonstrated rather than merely asserted,
	// so a change that made sealed refuse to delegate at all (closing this
	// capability along with the identity-preservation it exists for) shows up
	// here as a behaviour change and not just doc rot.
	if !errors.Is(err, compute.ErrTimeout) {
		t.Fatal("a hostile cause's lie did not reach errors.Is through the seal; either the " +
			"delegation changed or this test stopped exercising it")
	}

	// And it was reached with exactly the sentinel this test compared
	// against -- never the cause itself, the Provisioner, the connection, or
	// anything else in this function's scope. This is the positive half of
	// the claim, not only the absence of leaked material: it is what "in
	// reach" means for a hostile Is, made observable rather than argued.
	if len(seenTargets) == 0 {
		t.Fatal("the hostile cause's Is was never called; this test verified nothing")
	}
	for _, target := range seenTargets {
		if target != compute.ErrTimeout { //nolint:errorlint // exact target identity is the invariant under test.
			t.Errorf("the hostile cause's Is saw %v, want compute.ErrTimeout: sealed.Is must "+
				"delegate with exactly the caller's target and nothing else", target)
		}
	}
}

// hostileCause is a driver cause whose Is method is adversarial in the two
// ways a hostile dependency actually could be: it renders every
// representation of the material it was given, so [assertNoMaterial] can
// tell whether any observation reaches it, and it claims a match for any
// target at all while recording what it was asked about. A test that only
// drove a truthful Is would prove nothing about what the delegation exposes
// when the cause does not cooperate.
type hostileCause struct {
	body []string
	seen *[]error
}

func (h hostileCause) Error() string {
	return "syntax error at or near: " + strings.Join(h.body, " / ")
}

func (h hostileCause) Is(target error) bool {
	*h.seen = append(*h.seen, target)
	return true
}

// TestTheDSNRedactsAndValidates covers the connection string, which is the other
// thing in this package that holds material.
func TestTheDSNRedactsAndValidates(t *testing.T) {
	t.Parallel()
	cfg := postgres.ConnectionConfig{
		Endpoint: compute.SQLEndpoint{
			Host: "cluster.rds.invalid", Port: 5432, DatabaseName: "appdb", RequireTLS: true,
		},
		Username:     "appuser",
		RootCertPath: "/etc/apphub/rds-root.pem",
	}
	dsn, err := cfg.DSN(compute.NewSecretValue(rolePassword))
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
	// A SecretValue, so every stringification path redacts. The formatted forms
	// are checked one by one because each of them is a separate way a value
	// escapes, and %#v is the verb people reach for when debugging.
	//
	// The %s row went through dsn.String() until USOSS-43 (#28) removed that
	// method, which is itself a leak closed: an exported String() is a
	// stringification path that no verb has to ask for. The row is *kept* rather
	// than dropped, through the verb, because what it was testing is that %s
	// redacts -- and deleting a row from a leak table is how a migration silently
	// narrows the property it was migrating.
	for what, rendered := range map[string]string{
		// The verb IS the subject of this assertion, so it stays spelled out
		// rather than collapsed into the String() call a simplification would
		// prefer. It carried a //nolint for that until golangci-lint v2 stopped
		// reporting it; the directive went when its reason stopped applying,
		// because an unused suppression is one nobody can tell is still needed.
		"%s":    fmt.Sprintf("%s", dsn),
		"%v":    fmt.Sprintf("%v", dsn),
		"%#v":   fmt.Sprintf("%#v", dsn),
		"%+v":   fmt.Sprintf("%+v", dsn),
		"Error": fmt.Sprint(dsn),
	} {
		if strings.Contains(rendered, rolePassword) {
			t.Errorf("formatting the DSN with %s reveals the password", what)
		}
	}
	// And it really does carry the password, so the assertions above are not
	// about an empty string.
	if !strings.Contains(compute.RevealSecret(dsn), rolePassword) {
		t.Fatal("the DSN does not carry the password, so this test is about nothing")
	}
	// The value is quoted, so a password containing a space or a quote cannot
	// end the field. This is the one escaping rule a key/value DSN has, applied
	// unconditionally rather than when it looks necessary.
	awkward := `pa ss'w\ord`
	quoted, err := cfg.DSN(compute.NewSecretValue(awkward))
	if err != nil {
		t.Fatalf("DSN with an awkward password: %v", err)
	}
	if !strings.Contains(compute.RevealSecret(quoted), `password='pa ss\'w\\ord'`) {
		t.Errorf("a password containing a space, a quote and a backslash is not escaped "+
			"correctly; the rendered DSN would end the field early: %s",
			strings.ReplaceAll(compute.RevealSecret(quoted), awkward, "<material>"))
	}
}

// TestTLSFailsClosed is the fail-closed decision, stated as the property that
// distinguishes it from the source.
//
// The source connects with sslmode=require (postgres_roles.go:40), which encrypts
// and verifies nothing: it stops a passive observer and does nothing at all
// against an active one, while carrying a managed database's master password.
// This package defaults to verify-full and refuses rather than downgrading when
// it has no root to verify against.
func TestTLSFailsClosed(t *testing.T) {
	t.Parallel()
	base := postgres.ConnectionConfig{
		Endpoint: compute.SQLEndpoint{Host: "cluster.rds.invalid", Port: 5432, DatabaseName: "appdb"},
		Username: "appuser",
	}
	password := compute.NewSecretValue(rolePassword)

	// The default is verify-full, and with no root it refuses rather than
	// falling back.
	if _, err := base.DSN(password); err == nil {
		t.Error("a configuration with no TLS mode and no root certificate produced a DSN; the " +
			"default has to be the verifying mode, and a verifying mode with no root has to " +
			"refuse rather than downgrade")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}

	withRoot := base
	withRoot.RootCertPath = "/etc/apphub/rds-root.pem"
	dsn, err := withRoot.DSN(password)
	if err != nil {
		t.Fatalf("a configuration with a root certificate was refused: %v", err)
	}
	if !strings.Contains(compute.RevealSecret(dsn), "sslmode='verify-full'") {
		t.Error("the default TLS mode is not verify-full")
	}
	if !strings.Contains(compute.RevealSecret(dsn), "sslrootcert=") {
		t.Error("a verifying mode did not pass the root certificate")
	}

	// verify-ca also needs a root.
	verifyCA := base
	verifyCA.TLS = postgres.TLSVerifyCA
	if _, err := verifyCA.DSN(password); err == nil {
		t.Error("verify-ca with no root certificate produced a DSN")
	}

	// The explicit downgrade works, and is the only way to get it.
	insecure := base
	insecure.TLS = postgres.TLSRequire
	dsn, err = insecure.DSN(password)
	if err != nil {
		t.Fatalf("an explicit sslmode=require was refused: %v", err)
	}
	if !strings.Contains(compute.RevealSecret(dsn), "sslmode='require'") {
		t.Error("an explicit require did not produce sslmode=require")
	}

	// An undefined mode is not a synonym for anything.
	bogus := base
	bogus.TLS = postgres.TLSMode("prefer")
	if _, err := bogus.DSN(password); err == nil {
		t.Error("an undefined TLS mode was accepted; 'prefer' silently allows a plaintext " +
			"connection, which is exactly the kind of value a typo produces")
	}
}

// TestTheEscapingAndTheSessionModeArePaired is the source defect this port fixes,
// asserted as a pair.
//
// The source sets standard_conforming_strings on (postgres_roles.go:53) and then
// escapes as though it were off, doubling backslashes (postgres_roles.go:259).
// With the setting on, doubling inserts two backslashes, so the password Postgres
// stores is not the password the caller stored — and the symptom is an
// authentication failure on a later deploy with nothing pointing at the escaping.
// It is unreachable in the source only because its generated passwords are
// alphanumeric (database.go:409); a caller-supplied password reaches it.
//
// The two halves are asserted together because either alone is consistent with
// the bug.
func TestTheEscapingAndTheSessionModeArePaired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	password := `p\a's\\s`
	conn := &recordingConn{}
	if err := newProvisioner(t, conn).EnsureRole(ctx, postgres.RoleSpec{
		Username: "webapp_user",
		Type:     postgres.RoleReadonly,
		Password: compute.NewSecretValue(password),
	}); err != nil {
		t.Fatalf("EnsureRole: %v", err)
	}

	// Half one: the mode is set, and before the statement that depends on it.
	mode, role := -1, -1
	for i, stmt := range conn.stmts {
		if strings.Contains(stmt, "standard_conforming_strings = on") && mode < 0 {
			mode = i
		}
		if strings.Contains(stmt, "ROLE") && strings.Contains(stmt, "PASSWORD") && role < 0 {
			role = i
		}
	}
	switch {
	case mode < 0:
		t.Fatal("standard_conforming_strings was never set")
	case role < 0:
		t.Fatal("no password statement was issued")
	case mode > role:
		t.Errorf("the session's string-literal mode is set at statement %d and the password "+
			"statement is at %d, so the escaping and the interpretation are not paired", mode, role)
	}

	// Half two: with the mode on, only the single quote is doubled. A doubled
	// backslash here would store a different password from the one passed.
	stmt := conn.stmts[role]
	if !strings.Contains(stmt, `'p\a''s\\s'`) {
		t.Errorf("the password literal is not escaped for standard_conforming_strings=on. Only "+
			"the single quote is an escape in that mode, so doubling backslashes would set a "+
			"password with two where the caller had one, and the role could not log in. Got: %s",
			strings.ReplaceAll(stmt, password, "<material>"))
	}
}

// TestANulByteIsRefusedRatherThanStripped is the same class one step along.
//
// The source strips it (postgres_roles.go:261), which makes the stored password
// differ from the caller's copy — the same silent divergence as the backslash
// case, with the same symptom.
func TestANulByteIsRefusedRatherThanStripped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := &recordingConn{}
	err := newProvisioner(t, conn).EnsureRole(ctx, postgres.RoleSpec{
		Username: "webapp_user",
		Type:     postgres.RoleReadonly,
		Password: compute.NewSecretValue("pass\x00word"),
	})
	if err == nil {
		t.Fatal("a password containing a NUL byte was accepted; stripping it makes the password " +
			"Postgres stores differ from the copy the caller stored")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}
	if len(conn.stmts) != 0 {
		t.Errorf("statements were executed before the refusal: %v", conn.stmts)
	}
}

// TestIdentifiersAreQuoted covers the injection surface that is not the
// password.
//
// A role name comes from an application record and is therefore caller-influenced,
// so it is quoted everywhere it appears. The population is names built to end an
// identifier or a statement.
func TestIdentifiersAreQuoted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, username := range []string{
		`webapp"user`,
		`webapp"; DROP SCHEMA public CASCADE; --`,
		`webapp user`,
		`webapp'user`,
		`"webapp"`,
		`WebApp`,
		`webapp--user`,
	} {
		conn := &recordingConn{}
		if err := newProvisioner(t, conn).EnsureRole(ctx, postgres.RoleSpec{
			Username: username,
			Type:     postgres.RoleReadonly,
			Password: compute.NewSecretValue(rolePassword),
		}); err != nil {
			t.Fatalf("EnsureRole(%q): %v", username, err)
		}
		want := `"` + strings.ReplaceAll(username, `"`, `""`) + `"`
		for _, stmt := range conn.stmts {
			if !strings.Contains(stmt, username) && !strings.Contains(stmt, want) {
				continue
			}
			if !strings.Contains(stmt, want) {
				t.Errorf("a statement names %q unquoted: %s", username, stmt)
			}
		}
		// The DROP has to have been neutralised, not merely quoted somewhere.
		if strings.Contains(conn.all(), "DROP SCHEMA public CASCADE;") &&
			!strings.Contains(conn.all(), want) {
			t.Errorf("a role name containing a statement terminator was not neutralised: %v",
				conn.stmts)
		}
	}
}

// TestARoleTypeThisPackageDoesNotDefineIsRefused pins that there is no default
// privilege set.
//
// A typo in a role type must not silently become the widest set, and must not
// silently become the narrowest either: both produce a working deploy with the
// wrong access.
func TestARoleTypeThisPackageDoesNotDefineIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, rt := range []postgres.RoleType{"", "admin", "Application", "readonly ", "superuser"} {
		conn := &recordingConn{}
		err := newProvisioner(t, conn).EnsureRole(ctx, postgres.RoleSpec{
			Username: "webapp_user",
			Type:     rt,
			Password: compute.NewSecretValue(rolePassword),
		})
		if err == nil {
			t.Errorf("role type %q was accepted", rt)
			continue
		}
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("role type %q was refused with %v, want compute.ErrInvalidSpec", rt, err)
		}
		if len(conn.stmts) != 0 {
			t.Errorf("role type %q executed %v before being refused", rt, conn.stmts)
		}
	}
}

// --- the secret store seam --------------------------------------------------

// fakeStore is a [compute.SecretStore] under the test's control.
type fakeStore struct {
	value compute.SecretValue
	err   error
	gets  []compute.Ref
}

func (s *fakeStore) Put(context.Context, compute.SecretSpec) (compute.StoredSecret, error) {
	return compute.StoredSecret{}, errors.New("not used")
}

func (s *fakeStore) Get(_ context.Context, ref compute.Ref) (compute.SecretValue, error) {
	s.gets = append(s.gets, ref)
	return s.value, s.err
}

// Describe is here because [compute.SecretStore] requires it, and this package
// never calls it: postgres.Connect needs the material, so it goes through Get.
// Returning the ref with a global scope is the honest answer for a fake that
// keys nothing by placement, and it cannot carry a value — SecretInfo has no
// field that could.
func (s *fakeStore) Describe(_ context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	return &compute.SecretInfo{Ref: ref, PlacementScope: compute.SecretPlacementGlobal}, nil
}

func (s *fakeStore) Delete(context.Context, compute.Ref) error { return nil }
func (s *fakeStore) DeleteScope(context.Context, string) error { return nil }

// TestConnectReadsThePasswordThroughTheSecretStore is the acceptance criterion's
// behavioural half.
//
// The structural half — that this package imports no AWS SDK — is a boundary rule
// (internal/boundary, `aws-sdk-confined`) and is checked by `make boundary` over
// the import graph. This is the other half: the master password comes out of a
// [compute.SecretStore], which is what makes the same code work against a
// Kubernetes-hosted Postgres.
func TestConnectReadsThePasswordThroughTheSecretStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ref := compute.Ref{Provider: "test", Kind: compute.KindSecret, ID: "secret/db-password"}
	cfg := postgres.ConnectionConfig{
		Endpoint:     compute.SQLEndpoint{Host: "cluster.rds.invalid", Port: 5432, DatabaseName: "appdb"},
		Username:     "appuser",
		RootCertPath: "/etc/apphub/rds-root.pem",
	}

	// A store that refuses. The reference is in the error and the material is
	// not — a Ref is opaque and non-secret by contract, and "which secret could
	// not be read" is the first thing an operator needs.
	failing := &fakeStore{err: errors.New("access denied")}
	if _, err := postgres.Connect(ctx, failing, ref, cfg, "nosuchdriver"); err == nil {
		t.Error("Connect succeeded with a store that refused")
	} else if !strings.Contains(err.Error(), ref.ID) {
		t.Errorf("the error does not name the secret that could not be read: %v", err)
	}
	if len(failing.gets) != 1 || failing.gets[0] != ref {
		t.Errorf("the store was asked for %v, want exactly one Get of %s", failing.gets, ref)
	}

	// A store that returns nothing. Proceeding would authenticate as nobody and
	// report an authentication failure against the database rather than against
	// the store.
	empty := &fakeStore{}
	if _, err := postgres.Connect(ctx, empty, ref, cfg, "nosuchdriver"); err == nil {
		t.Error("Connect succeeded with an empty password")
	} else if !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("an empty password was refused with %v, want compute.ErrNotFound", err)
	}

	// No store at all, and no driver name. Both are refusals rather than
	// panics, because this is a composition-root mistake and the composition
	// root is where it has to be reported.
	if _, err := postgres.Connect(ctx, nil, ref, cfg, "nosuchdriver"); err == nil {
		t.Error("Connect succeeded with no secret store")
	}
	good := &fakeStore{value: compute.NewSecretValue(rolePassword)}
	if _, err := postgres.Connect(ctx, good, ref, cfg, ""); err == nil {
		t.Error("Connect succeeded with no driver name; this package registers no driver, so a " +
			"caller that names none has not supplied one")
	}
}

// TestNewProvisionerRefusesWhatItCannotWorkWith.
func TestNewProvisionerRefusesWhatItCannotWorkWith(t *testing.T) {
	t.Parallel()
	if _, err := postgres.NewProvisioner(nil, "appdb"); err == nil {
		t.Error("a provisioner with no connection was accepted")
	}
	if _, err := postgres.NewProvisioner(&recordingConn{}, ""); err == nil {
		t.Error("a provisioner with no database name was accepted; the CONNECT grant has to spell " +
			"a database, and Postgres has no keyword for 'the one I am connected to'")
	}
	if _, err := postgres.NewProvisioner(&recordingConn{}, "   "); err == nil {
		t.Error("a provisioner with a blank database name was accepted")
	}
}

// TestConnectionConfigCarriesNoMaterial pins a design choice whose value was
// confirmed by measurement rather than assumed.
//
// The password is a separate argument to [postgres.ConnectionConfig.DSN] rather
// than a field, so a config value can be logged, marshalled, or rendered by a
// template without a password going with it. That mattered more than it looked:
// USOSS-43 found that compute.SecretValue's plaintext is reachable from
// text/template as `{{.Reveal}}`, and one field deep as `{{.V.Reveal}}`, with no
// reflection at all — an exported no-arg string method is reachable by name from
// any template walking the value.
//
// Measured against this package's own types, five of seven paths leak. The two
// that do not are this one and a whole-struct render (see
// TestARenderedStructDoesNotLeak). This test is what stops a later edit adding a
// Password field to ConnectionConfig "for convenience" and putting it back in the
// blast radius.
func TestConnectionConfigCarriesNoMaterial(t *testing.T) {
	t.Parallel()
	cfg := postgres.ConnectionConfig{
		Endpoint:     compute.SQLEndpoint{Host: "cluster.rds.invalid", Port: 5432, DatabaseName: "appdb"},
		Username:     "appuser",
		RootCertPath: "/etc/apphub/rds-root.pem",
		TLS:          postgres.TLSVerifyFull,
	}
	// Every field, by reflection, so a field added later is covered without
	// editing this test.
	typ := reflect.TypeOf(cfg)
	if typ.NumField() == 0 {
		t.Fatal("ConnectionConfig has no fields, so this is about nothing")
	}
	for i := range typ.NumField() {
		if secretBearing(typ.Field(i).Type) {
			t.Errorf("ConnectionConfig.%s is a %s, which carries credential material. The password "+
				"is deliberately an argument to DSN rather than a field, so that a config value "+
				"can be logged or rendered without one going with it",
				typ.Field(i).Name, typ.Field(i).Type)
		}
	}
	// And behaviourally, through the path that actually leaks.
	if out := renderTemplate(t, "{{.}}", cfg); strings.Contains(out, rolePassword) {
		t.Errorf("rendering a ConnectionConfig produced the password")
	}
	// Non-vacuously: the material really is in play, it is just not in this
	// struct. Without this the assertion above would pass against a fixture
	// that never held a password at all.
	dsn, err := cfg.DSN(compute.NewSecretValue(rolePassword))
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
	if !strings.Contains(compute.RevealSecret(dsn), rolePassword) {
		t.Fatal("the DSN built from this config does not carry the password, so the assertion " +
			"above is about a fixture with no material in it")
	}
}

// secretBearing reports whether a type is, or contains, credential material.
func secretBearing(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct:
		if t.Name() == "SecretValue" || t.Name() == "Secret" {
			return true
		}
		for i := range t.NumField() {
			if secretBearing(t.Field(i).Type) {
				return true
			}
		}
		return false
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return secretBearing(t.Elem())
	default:
		return t.Name() == "SecretValue" || t.Name() == "Secret"
	}
}

// TestARenderedStructDoesNotLeak pins the ordinary logging shape.
//
// The leak USOSS-43 found needs `.Reveal` to be *named*. A template that renders
// a struct's fields — which is what a logging or diagnostic template does — goes
// through String() and redacts. Measured, not assumed: rendering a RoleSpec
// yields "webapp_user|[REDACTED]".
//
// This is the half that holds, and it is worth pinning separately from the half
// that does not, because the two are easy to conflate into "templates are safe"
// or "templates leak" and neither is true.
func TestARenderedStructDoesNotLeak(t *testing.T) {
	t.Parallel()
	spec := postgres.RoleSpec{
		Username: "webapp_user",
		Type:     postgres.RoleApplication,
		Password: compute.NewSecretValue(rolePassword),
	}
	for _, tmpl := range []string{
		"{{.Username}}|{{.Password}}",
		"{{.}}",
		"{{printf \"%v\" .Password}}",
		"{{printf \"%s\" .Password}}",
	} {
		if out := renderTemplate(t, tmpl, spec); strings.Contains(out, rolePassword) {
			t.Errorf("template %q rendered the password", tmpl)
		}
	}
}

// renderTemplate renders data through text/template, returning the output or the
// execution error's text. Either is searched for material: a template error that
// quoted the value it could not render would leak just as surely.
func renderTemplate(t *testing.T, tmpl string, data any) string {
	t.Helper()
	var b strings.Builder
	parsed, err := template.New("probe").Parse(tmpl)
	if err != nil {
		t.Fatalf("parsing %q: %v", tmpl, err)
	}
	if err := parsed.Execute(&b, data); err != nil {
		return b.String() + " exec error: " + err.Error()
	}
	return b.String()
}

// TestWhatIsNotVerifiedHere states the gap rather than leaving a reader to infer
// that everything is covered.
//
// It is a test so that it lives next to the code and shows up in a run, not
// because it asserts anything about the implementation. Contract lesson: an
// honest statement of an untested surface is worth more than a test that
// pretends.
func TestWhatIsNotVerifiedHere(t *testing.T) {
	t.Parallel()
	t.Log(`Not verified by this package's tests, and not verifiable hermetically:

  1. That Postgres accepts these statements. Every assertion here is about the
     statement text and the order of statements, checked through the Conn seam.
     A syntax error, a privilege that does not exist in a given major version, or
     an extension name Aurora includes but rejects would all pass here. The
     nearest available check is a real Postgres, which this repository's
     hermeticity bar excludes (no network, no cluster, no fixed ports) and which
     this shared environment could not bind a port for.

  2. That the escaping this package applies is what a real server interprets.
     TestTheEscapingAndTheSessionModeArePaired checks that the escaping matches
     the mode this package *sets*, which is the half that was wrong in the source
     system. It does not check that Postgres agrees, and no unit test can.

  3. That a password in a DDL literal does not reach the server's statement log.
     It does, if log_statement is 'ddl' or 'all', and a managed database's admin
     account cannot reliably change that for its session. Passing a pre-computed
     SCRAM verifier would keep the plaintext off the wire entirely; it is not
     attempted because an untested SCRAM derivation that is wrong produces a role
     nobody can log into. Recorded as a follow-up.

  4. The real driver's behaviour. NewSQLConn is exercised only for its refusals,
     because opening a connection needs a registered driver and this package
     deliberately imports none. What IS established, and did not used to be, is
     that no driver error this package returns can be rendered at all: review
     found three escapes from the redactor that preceded it — a password-only
     error where the DSN was scrubbed, the SQL-literal encoding of a password
     where the raw form was scrubbed, and errors.Unwrap handing back the
     credential-bearing cause. Those are two axes, representation and
     observation, and the fix was to stop rendering rather than to enumerate
     either: see postgres.sealed. A fourth escape, Go-syntax formatting, was
     found by the test
     for it and needed the cause held in a closure rather than a field, because
     Go-syntax formatting walks unexported fields by reflection and consults no
     method on the way.

  5. That compute.SecretValue's redaction holds on every path. It does not, and
     the claims in this package that rest on it were resting on something
     untrue. USOSS-43 found four leaks in that type; measured against this
     package's own types, five of seven paths leak today:

         {{.Reveal}} on a SecretValue                     LEAKS
         {{.Password.Reveal}} on postgres.RoleSpec        LEAKS  (one field deep)
         {{.AdminPassword.Reveal}} on RelationalSpec      LEAKS
         {{.Reveal}} on the DSN this package builds       LEAKS
         reflect.ValueOf(v).Field(0).String()             LEAKS
         {{.Username}}|{{.Password}} on a RoleSpec        redacts
         {{.}} on a ConnectionConfig                      redacts

     The two that redact are pinned by TestARenderedStructDoesNotLeak and
     TestConnectionConfigCarriesNoMaterial. The five that leak are closed by
     USOSS-43 making Reveal a package function rather than a method, which
     removes the name a template can reach. What this package can do on its own
     is keep material out of types that get rendered — which is why
     ConnectionConfig takes the password as an argument — and that is the half
     that was already right.

     The permanent test for the class, once Reveal is no longer a method: assert
     by reflection that SecretValue exposes no exported no-arg method returning
     a string. That is the property, rather than the three templates that
     happened to be tried.`)
}

// TestSecretValueVendsNoStringAccessor guards a property this package's redaction
// claims rest on, in the type it does not own.
//
// # Why it is here and not in compute
//
// USOSS-43 (#28) removed `SecretValue.Reveal()` in favour of the package function
// `compute.RevealSecret(v)`, and removed `String()` with it. Both removals are the
// same idea: **an exported no-argument method returning a string is a
// stringification path that no caller has to ask for.** `fmt` will find it,
// `text/template` will find it, a struct printer will find it, and every one of
// those is a way material escapes without anybody writing the word "reveal".
//
// The permanent form of that decision is not "we deleted two methods" — it is
// that no such method may come back. This is the assertion, by reflection over
// the method set rather than over a list of names, so a *differently* named
// accessor is caught too.
//
// It is deliberately stricter than "no method that leaks": a `String()` that
// returned the redacted placeholder would leak nothing today and would still fail
// here. That is the point. The hazard is the *path* existing, because the next
// edit to it is one line from revealing, and nothing at the call sites would
// change. A safe accessor is a leak with a delay.
//
// It belongs in `compute`, next to the type. It is here because this package is
// where the claim is load-bearing — `postgres/` puts a `SecretValue` into a DSN
// and asserts every rendering of it redacts — and because adding a file to
// somebody else's package mid-queue is a conflict rather than a contribution.
// Flagged for USOSS-43's owner to adopt.
func TestSecretValueVendsNoStringAccessor(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(compute.SecretValue{})
	if typ.NumMethod() == 0 {
		t.Fatal("SecretValue has no exported methods at all, so this assertion is about nothing")
	}
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		// Method values carry the receiver, so NumIn()==1 is a no-argument method.
		if m.Type.NumIn() != 1 || m.Type.NumOut() != 1 {
			continue
		}
		if m.Type.Out(0).Kind() == reflect.String {
			t.Errorf("SecretValue.%s() returns a string with no arguments. That is a "+
				"stringification path no caller has to ask for: fmt, text/template and any "+
				"struct printer will find it, so material escapes without anybody writing "+
				"the word reveal. Revealing is deliberate and belongs in the package function "+
				"compute.RevealSecret, which USOSS-43 introduced by removing Reveal() and "+
				"String() for exactly this reason", m.Name)
		}
	}
}
