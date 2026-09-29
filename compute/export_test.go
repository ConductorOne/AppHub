// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"crypto/sha256"
	"encoding/binary"
)

// LeaksMaterialForTest exposes this package's single leak predicate to the
// external test package.
//
// Test-only by file, so it is not part of the package's API. It exists so that
// secret_hygiene_test.go, which is in compute_test, checks its rendered output
// with the SAME predicate as the internal tests. An external copy would be a
// second definition of "did this leak", and the copy that fell behind would
// score a real leak as clean -- which is exactly what happened while the
// predicate was a plain strings.Contains in both places.
func LeaksMaterialForTest(out, material string) bool { return leaksMaterial(out, material) }

// KeystreamForTest exposes this package's masking derivation with the key as a
// parameter, so the external recombination test can assert that
// internal/reachable's independent reimplementation still agrees with what this
// package actually ships.
//
// Only for the agreement check. The attack itself deliberately uses the
// independent implementation: a test that reverses a secret with the package's own
// keystream shares the package's own bugs, so a derivation that quietly stopped
// using its key would faithfully fail to reverse anything and report a pass.
func KeystreamForTest(key [32]byte, nonce [16]byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, len(key)+len(nonce)+8)
	for block := uint64(0); len(out) < n; block++ {
		buf = buf[:0]
		buf = append(buf, key[:]...)
		buf = append(buf, nonce[:]...)
		buf = binary.BigEndian.AppendUint64(buf, block)
		sum := sha256.Sum256(buf)
		out = append(out, sum[:]...)
	}
	return out[:n]
}
