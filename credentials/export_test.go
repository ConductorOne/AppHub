// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

// KeystreamForTest exposes the keystream derivation to the package's external
// tests, so the recombination search can attempt the REAL construction with a
// reachable field standing in for the key rather than approximating it.
//
// Test-only by file, so it is not part of the package's API. An external test
// that reimplemented the derivation would be testing its own copy: if the two
// drifted, the search would fail to reverse a secret it should have reversed and
// report that as a pass.
func KeystreamForTest(key [32]byte, nonce [nonceLen]byte, n int) []byte {
	return keystreamWith(key, nonce, n)
}
