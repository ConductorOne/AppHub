// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The tag vocabulary this provider writes on every IAM user it creates.
//
// It is the same vocabulary compute/aws writes (compute/aws/names.go:24-31), and
// the spellings are a cross-package restatement rather than a shared constant --
// they are unexported there, and moving them belongs in a ticket of its own
// rather than in a pull request about credential vending.
// TestTagVocabularyAgreesWithComputeAWS reads the sibling declaration and fails
// if the two ever disagree, so the restatement cannot drift silently.
//
// The marker exists to be *read*. The source system writes an ownership tag on
// the resources it creates and then never checks it, which is the same as having
// none: an IAM user name is derived from a mutable application name in an
// account-global namespace, so a name that was ours once can belong to somebody
// else later. Teardown here refuses to touch a user that does not carry both
// tags.
const (
	tagManagedBy = "apphub:managed-by"
	tagName      = "apphub:name"
	tagComponent = "apphub:component"

	// managedByValue names the project, which is public, and never a deployment.
	managedByValue = "apphub"

	// componentCredentialUser says what apphub created the user *as*. Checking
	// only the ownership tag would make every IAM user this platform owns
	// interchangeable by name, and they are not: a user that holds a vended
	// Bedrock credential and a user that holds something else are the same kind
	// of object in the same namespace.
	//nolint:gosec // G101 reads this as a hardcoded credential; it is an AWS tag
	// value saying what this platform created a resource as.
	componentCredentialUser = "bedrock-credential-user"
)

// Handle kinds. A platform key ID is parsed strictly: the two prefixes below are
// the only things this package will read, and anything else is an error.
//
// The source recognised a static handle by whether it started with "{" and
// treated everything else as a dynamic one (claude.go:288-290, claude.go:316) --
// so an empty, truncated or foreign handle took the "nothing to revoke" path and
// RevokeCredential returned nil. A revoke that reports success without doing
// anything is the worst available outcome, because the record is then finalized
// as revoked. A gate has two outcomes on every input, recognised or fatal.
const (
	handleStatic  = "iam-user"
	handleDynamic = "bedrock-token"
)

// ErrUnrecognizedHandle means a platform key ID is not one this provider minted.
//
// It is returned rather than swallowed. See the note on the handle kinds above:
// the alternative is a revoke that succeeds without revoking.
var ErrUnrecognizedHandle = errors.New("aws: the platform key ID is not one this provider minted")

// ErrNameNotUsable means the requested credential name cannot be turned into an
// AWS resource name. The limit or the reason is in the message.
var ErrNameNotUsable = errors.New("aws: the requested name cannot be used as an AWS resource name")

// sanitize maps a caller's name onto IAM's grammar.
//
// # It is not injective, and that is safe here for one specific reason
//
// Two distinct requests can sanitize to one name, because every character
// outside IAM's set folds to "-". So the mapping cannot be inverted and must
// never be used to *find* a resource -- and it is not: the IAM user name travels
// in the platform key ID, and revoke and status read it from there. Nothing in
// this package re-derives a name from a request in order to act on an existing
// user. TestNamesAreOnlyEverReadFromTheHandle pins that, because it is the
// property that makes the collision harmless rather than a way to delete
// somebody else's credential.
//
// What a collision does produce is IAM refusing the second CreateUser with
// EntityAlreadyExists, which surfaces as an error rather than as an adoption.
//
// # What it does not do
//
// It does not fall back to a name of its own. The source returned the internal
// project's name for an input that sanitized to nothing (claude.go:426-428,
// claude.go:447-449) -- an identifier compiled in, and a resource whose name says
// nothing about what asked for it. An empty result is refused instead.
//
// It does not truncate. The source cut over-long names to fit (claude.go:103-105,
// claude.go:423-425, claude.go:444-446), and truncation is the collision case
// again with the fold removed: two long distinct names become one short name. The
// limit is named and the request refused, per the rule about refusing at the spec
// rather than approximating.
func sanitize(name string) string {
	out := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '+', c == '=', c == ',', c == '.', c == '@', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// hasAlphanumeric reports whether a sanitized name carries any of the caller's
// own alphabet, as opposed to only the separators everything else folds into.
func hasAlphanumeric(s string) bool {
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			return true
		}
	}
	return false
}

// prefixedName joins a configured prefix and a sanitized name, refusing anything
// that will not fit.
//
// field is a constant from the caller so that the message says which limit was
// hit without echoing the value that hit it.
func prefixedName(field, prefix, name string, maxLen int) (string, error) {
	clean := sanitize(strings.TrimSpace(name))
	if !hasAlphanumeric(clean) {
		// Emptiness is the wrong test, and writing this test found that out. Every
		// character outside IAM's set folds to "-", so a name of "///" sanitizes
		// to "---": non-empty, a legal IAM name, and carrying nothing at all of
		// what the caller asked for. A resource whose name says nothing about what
		// asked for it is the state the removed compiled-in fallback produced, so
		// refusing it is the same rule and not a new one.
		return "", fmt.Errorf("aws: %s has no usable characters: %w", field, ErrNameNotUsable)
	}
	full := prefix + "-" + clean
	if len(full) > maxLen {
		return "", fmt.Errorf("aws: %s would be %d bytes (max %d): %w",
			field, len(full), maxLen, ErrNameNotUsable)
	}
	return full, nil
}

// staticHandle renders the platform key ID for an IAM-user credential.
//
// Both components come from AWS -- the name this package asked for and the
// credential ID IAM chose -- and neither is material. The separator is ":",
// which IAM's user-name grammar and the credential-ID alphabet both exclude, so
// the rendering is unambiguous rather than merely conventional.
func staticHandle(userName, credentialID string) string {
	return handleStatic + ":" + userName + ":" + credentialID
}

// parseStaticHandle recovers what staticHandle wrote.
func parseStaticHandle(h string) (userName, credentialID string, err error) {
	rest, ok := strings.CutPrefix(h, handleStatic+":")
	if !ok {
		return "", "", ErrUnrecognizedHandle
	}
	userName, credentialID, ok = strings.Cut(rest, ":")
	if !ok || userName == "" || credentialID == "" {
		return "", "", ErrUnrecognizedHandle
	}
	if strings.Contains(credentialID, ":") {
		return "", "", ErrUnrecognizedHandle
	}
	if !iamNameRunes.MatchString(userName) {
		// A handle whose user name is not in IAM's grammar cannot have been
		// minted here, and acting on it would mean sending a name this package
		// would have refused to create.
		return "", "", ErrUnrecognizedHandle
	}
	return userName, credentialID, nil
}

// dynamicHandle renders the platform key ID for a Bedrock bearer token.
//
// A presigned request has no server-side identifier at all: nothing in AWS can
// be asked about it and nothing can revoke it. So the handle carries what is
// actually known -- the session name, which is what a CloudTrail row will show,
// and the expiry, which is what liveness is derived from. This is
// credentials/github's construction (github.go:41-44) rather than a new idea; the
// two providers have the same problem.
func dynamicHandle(sessionName string, expiresAt time.Time) string {
	return handleDynamic + ":" + sessionName + ":" + strconv.FormatInt(expiresAt.Unix(), 10)
}

// parseDynamicHandle recovers the expiry from a handle this provider minted.
func parseDynamicHandle(h string) (time.Time, error) {
	rest, ok := strings.CutPrefix(h, handleDynamic+":")
	if !ok {
		return time.Time{}, ErrUnrecognizedHandle
	}
	session, unix, ok := strings.Cut(rest, ":")
	if !ok || session == "" {
		return time.Time{}, ErrUnrecognizedHandle
	}
	secs, err := strconv.ParseInt(unix, 10, 64)
	if err != nil {
		return time.Time{}, ErrUnrecognizedHandle
	}
	return time.Unix(secs, 0).UTC(), nil
}

// handleKind reports which of the two shapes a platform key ID is, so a caller
// can dispatch without guessing. An unrecognised handle is an error, never a
// third silent branch.
func handleKind(h string) (string, error) {
	switch {
	case strings.HasPrefix(h, handleStatic+":"):
		return handleStatic, nil
	case strings.HasPrefix(h, handleDynamic+":"):
		return handleDynamic, nil
	default:
		return "", ErrUnrecognizedHandle
	}
}
