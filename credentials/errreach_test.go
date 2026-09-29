// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// USOSS-67 found that errors.Is and errors.As run a method (Is(error) bool,
// As(any) bool) on every error in the chain they walk, including one this
// repository did not write. See docs/decisions/usoss-67-a-hostile-chain-
// member-s-is-as-method-only-ever-receives-the-target-its-caller-supplied.md
// for the full derivation; what this file pins is the one fact the whole
// repository's conclusion rests on:
//
//	A hostile chain member's Is/As method receives, as its only argument, the
//	target/destination this repository's own call site supplied. errors.Is's
//	target parameter is statically typed error, and errors.As's destination
//	must satisfy error (or be an interface) at the point a custom As method
//	would run, or the standard library panics before any foreign code does.
//	Neither Secret nor Foreign can be handed to a hostile method that way
//	unless one of them implements error -- and if either ever does, every
//	errors.Is/errors.As call site in credentials/, compute/, and store/ has to
//	be re-audited for whether a chain containing a caller- or
//	dependency-supplied cause could be compared against, or destined for, a
//	live Secret or Foreign.
//
// Neither type has a reason to implement error -- they hold material, not
// failures -- so this is expected to stay closed permanently. It is pinned
// so that a change adding an Error() string method to either type (to make a
// marshal failure %w-friendly, say) fails here instead of silently reopening
// USOSS-67's population.
package credentials_test

import (
	"testing"

	"github.com/conductorone/apphub/credentials"
)

func TestSecretIsNotAnError(t *testing.T) {
	if _, ok := any(credentials.Secret{}).(error); ok {
		t.Fatal("credentials.Secret now implements error. Re-run the USOSS-67 audit: a Secret can " +
			"now be the target of errors.Is or the destination of errors.As, so a chain containing " +
			"a caller- or dependency-supplied cause could hand a hostile Is/As method a live Secret.")
	}
	if _, ok := any(&credentials.Secret{}).(error); ok {
		t.Fatal("*credentials.Secret now implements error. Re-run the USOSS-67 audit: see " +
			"TestSecretIsNotAnError.")
	}
}

func TestForeignIsNotAnError(t *testing.T) {
	if _, ok := any(credentials.Foreign{}).(error); ok {
		t.Fatal("credentials.Foreign now implements error. Re-run the USOSS-67 audit: a Foreign can " +
			"now be the target of errors.Is or the destination of errors.As, so a chain containing " +
			"a caller- or dependency-supplied cause could hand a hostile Is/As method a live Foreign.")
	}
	if _, ok := any(&credentials.Foreign{}).(error); ok {
		t.Fatal("*credentials.Foreign now implements error. Re-run the USOSS-67 audit: see " +
			"TestForeignIsNotAnError.")
	}
}
