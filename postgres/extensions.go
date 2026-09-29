// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// allowedExtensions is the set of PostgreSQL extensions an application may
// request.
//
// It is a security control derived from Union Station's application allowlist,
// not merely a compatibility list. CREATE EXTENSION runs the extension's own
// SQL script as the installing role, and a managed database's admin account is
// a member of the instance's privileged role. Some extensions expose functions
// that read files, execute untrusted code, or open network connections. An
// application that could name any extension could turn "install a search index"
// into arbitrary execution inside the database, so names must be allowlisted.
//
// The membership rule from the source, which is a second, narrower control: only
// extensions that install with a plain CREATE EXTENSION — no
// shared_preload_libraries, so no custom parameter group and no reboot — and that
// the managed service includes in its own supported set. Extensions requiring
// preload (pg_stat_statements, pg_cron) are excluded until the platform supports
// custom cluster parameter groups.
var allowedExtensions = map[string]bool{
	"vector":        true, // pgvector — vector similarity search
	"pg_trgm":       true, // trigram fuzzy text search
	"pgcrypto":      true, // cryptographic functions
	"fuzzystrmatch": true, // soundex/levenshtein
	"unaccent":      true, // accent-insensitive search
	"citext":        true, // case-insensitive text
	"hstore":        true, // key/value pairs
	"btree_gin":     true, // GIN over scalar types
	"btree_gist":    true, // GiST over scalar types
	"uuid-ossp":     true, // uuid generation
}

// IsAllowedExtension reports whether name is an extension an application may
// provision.
//
// Exact match, and the exactness is the control. It is not case-insensitive, it
// does not trim, and it does not normalise: every one of those would widen the
// set of accepted strings beyond the set of names in [allowedExtensions], and a
// control whose accepted language is larger than its allowlist is a control with
// an unenumerated surface. A caller that sends " Vector " gets a refusal, which
// is the correct answer to a name that is not on the list.
func IsAllowedExtension(name string) bool { return allowedExtensions[name] }

// AllowedExtensions returns the provisionable extension names, sorted.
//
// Derived from [allowedExtensions] rather than restated beside it, because a
// hand-maintained second copy of a set drifts from the set — and this one would
// drift in the direction of an API error message that names extensions the
// installer refuses, or omits ones it accepts.
func AllowedExtensions() []string {
	out := make([]string, 0, len(allowedExtensions))
	for name := range allowedExtensions {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// EnsureExtensions installs the requested extensions, idempotently.
//
// Only the admin account may CREATE EXTENSION on a managed database, so conn has
// to be an admin connection — the same constraint the source system documents
// (database_extensions.go:23-25).
//
// # The one behaviour change, and it is deliberate
//
// A name that is not on the allowlist **fails the whole call**. The source system
// logs a warning and continues (database_extensions.go:55-58), and the
// consequence is a successful deploy of an application whose database is missing
// the type it depends on: the failure arrives later, at runtime, as "type vector
// does not exist", from a component nobody was changing. The API layer validates
// the same set (services/application.go:1187-1188) and *does* refuse, so the two
// halves of the source disagree with each other; this agrees with the half that
// fails closed.
//
// Refusing before installing anything also makes the call atomic in the way that
// matters: a spec with one bad name installs nothing, so a caller retrying after
// fixing the name is not reasoning about a half-applied set.
func (p *Provisioner) EnsureExtensions(ctx context.Context, extensions []string) error {
	if len(extensions) == 0 {
		return nil
	}
	// Validate every name before executing any statement.
	var rejected []string
	for _, ext := range extensions {
		if !IsAllowedExtension(ext) {
			rejected = append(rejected, ext)
		}
	}
	if len(rejected) > 0 {
		return fmt.Errorf("%w: %s is not on the platform's extension allowlist. "+
			"CREATE EXTENSION runs the extension's own script with the admin account's "+
			"privileges, so the set an application may name is an allowlist rather than a "+
			"filter; the allowed names are %s",
			compute.ErrInvalidSpec, quoteAll(rejected), strings.Join(AllowedExtensions(), ", "))
	}

	if err := p.prepare(ctx); err != nil {
		return err
	}
	for _, ext := range extensions {
		// Quoted even though the name came off an allowlist. Two reasons, and
		// the first is not defence in depth: "uuid-ossp" contains a hyphen and
		// is not a legal bare identifier, so an unquoted statement would be a
		// syntax error for a name on the list. The second is that a quoted
		// identifier cannot become anything else if the allowlist is ever
		// widened by somebody who does not read this comment.
		stmt := "CREATE EXTENSION IF NOT EXISTS " + quoteIdentifier(ext)
		if err := p.conn.Exec(ctx, stmt); err != nil {
			// The extension name is in the error and nothing else is. It came
			// off an allowlist, so it is not attacker-controlled text, and a
			// caller with five extensions needs to know which one failed.
			return fmt.Errorf("%w: creating extension %q: %w", compute.ErrFailed, ext, seal(err))
		}
	}
	return nil
}

// quoteAll renders a list of names for a diagnostic, each quoted.
func quoteAll(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, fmt.Sprintf("%q", n))
	}
	return strings.Join(out, ", ")
}
