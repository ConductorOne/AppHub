// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute_test

import (
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/internal/reachable"
)

const recombinationMaterial = "usoss43-material-never-log-1c9f4e2a"

// TestNoRecombinationOfReachableStateReversesASecretValue is the property that
// separates this construction from masking a value beside its own mask.
//
// The mask-beside-the-material shape was defeated on two types in this repository
// by eleven lines of ordinary reflection — no unsafe, no build tags — and
// compute.SecretValue was rebuilt into that shape on main a release after
// credentials.Secret was rescued from it. So this is the assertion that has to
// hold, and it has to hold against a search wider than the pair that broke those
// two: naming the pair would have caught both instances and nothing else.
//
// Three things about how it is written, each of them a correction:
//
//  1. THE WALK IS SHARED AND RECURSIVE. internal/reachable descends structs,
//     pointers, interfaces, slices, arrays and maps with no depth cap. The local
//     walker this replaced skipped maps and every kind its switch did not list,
//     and the credentials copy of the same idea returned nil for a struct field —
//     which is how a reviewer hid the real key in an unexported one-field holder
//     inside the type and kept a whole suite green.
//
//  2. THE ATTACK IS OUTSIDE THE PACKAGE AND REIMPLEMENTS THE DERIVATION. A test
//     that calls this package's keystream shares this package's bugs: if the
//     derivation stopped using its key, the attack would faithfully fail to
//     reverse anything and report a pass. The reviewer's recovery worked because
//     they wrote the four lines out themselves.
//
//  3. THE DRIFT IS ASSERTED, NOT HOPED FOR. An independent copy that falls behind
//     attacks a construction nobody ships, and its silence would read as a pass.
//     So the agreement between the two derivations is checked first, and a
//     divergence is a loud failure with instructions.
func TestNoRecombinationOfReachableStateReversesASecretValue(t *testing.T) {
	t.Parallel()

	var probeKey [32]byte
	copy(probeKey[:], "an-arbitrary-key-for-comparison-")
	agrees := reachable.AgreesWith(func(k [32]byte, nonce []byte, n int) []byte {
		var fixed [16]byte
		copy(fixed[:], nonce)
		return compute.KeystreamForTest(k, fixed, n)
	}, probeKey, []byte("sixteen-byte-non"), 128)
	if !agrees {
		t.Fatal("internal/reachable's keystream no longer agrees with this package's. Fix the " +
			"reimplementation: an attack against a derivation nobody ships proves nothing, and its " +
			"silence would read as a pass here")
	}

	sv := compute.NewSecretValue(recombinationMaterial)
	r, err := reachable.Walk(sv)
	if err != nil {
		t.Fatalf("walking a SecretValue: %v", err)
	}
	if len(r.Blobs) < 2 {
		t.Fatalf("only %d reachable blob(s) in a SecretValue; the walk is not descending and every "+
			"assertion below would pass vacuously", len(r.Blobs))
	}
	if len(r.Unreadable) != 0 {
		t.Errorf("a SecretValue has %d location(s) reflection cannot read: %v. A func or channel "+
			"field on this type is a place material can sit where no walk follows it",
			len(r.Unreadable), r.Unreadable)
	}
	for _, a := range reachable.Recover(r, recombinationMaterial) {
		t.Errorf("reachable state reverses a SecretValue: %s (key=%s nonce=%s target=%s)",
			a.How, a.KeyPath, a.NoncePath, a.TargetPath)
	}

	if compute.RevealSecret(sv) != recombinationMaterial {
		t.Fatal("RevealSecret did not round-trip; the assertions above prove nothing about a " +
			"construction that does not work")
	}
}
