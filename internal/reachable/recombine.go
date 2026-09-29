// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package reachable

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Keystream is an INDEPENDENT reimplementation of the masking derivation used by
// credentials.Secret, credentials.Foreign and compute.SecretValue:
// SHA-256(key || nonce || big-endian block counter), concatenated and truncated.
//
// Independent on purpose, and this is the part that makes an attack an attack. A
// recombination test that calls the package's own keystream shares the
// implementation's bugs: if the real derivation stopped using its key, the test
// would faithfully fail to reverse anything and report a pass. The reviewer who
// defeated the fixture this package replaces succeeded precisely because they did
// not call ours — they wrote the four lines out and recovered all 39 bytes.
//
// The obvious objection is drift: an independent copy that falls behind attacks a
// construction nobody ships, and reports "not reversible" about the wrong thing.
// That is answered by asserting the agreement rather than hoping for it — see
// [AgreesWith], which every caller of [Recover] is expected to use, so a
// divergence is a loud failure instead of a silently weakened attack.
func Keystream(key [32]byte, nonce []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, len(key)+len(nonce)+8)
	for block := uint64(0); len(out) < n; block++ {
		buf = buf[:0]
		buf = append(buf, key[:]...)
		buf = append(buf, nonce...)
		buf = binary.BigEndian.AppendUint64(buf, block)
		sum := sha256.Sum256(buf)
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// AgreesWith reports whether the package under test derives the same bytes as
// [Keystream] for a key and nonce it is given.
//
// Callers pass their own derivation as shipped. A false result means this file and
// the shipped construction have diverged, and the correct response is to fix this
// file — not to conclude anything about reversibility, because an attack against
// a construction nobody ships proves nothing either way.
func AgreesWith(shipped func(key [32]byte, nonce []byte, n int) []byte, key [32]byte, nonce []byte, n int) bool {
	return bytes.Equal(shipped(key, nonce, n), Keystream(key, nonce, n))
}

// Attempt is one recovery that succeeded, named so a failure message says which
// two locations combined to defeat the type.
type Attempt struct {
	How        string
	KeyPath    string
	NoncePath  string
	TargetPath string
}

// Recover tries to reconstruct material from the blobs a [Walk] found.
//
// Three attacks, and each one has actually worked against a redacting type in
// this repository:
//
//  1. keystream reconstruction — a blob as the key, a blob as the nonce, XORed
//     against a third. This is the reviewer's nested-holder recovery: move the
//     real key anywhere inside the value and it comes back.
//  2. direct XOR of a pair — the adjacent-mask defect, twice: credentials.Secret
//     held its mask in the next field, and compute.SecretValue was rebuilt that
//     way a release later.
//  3. plaintext in a field — the original defect, and still worth trying first
//     because it is the one a refactor reintroduces by accident.
//
// Every ordered pair is tried rather than a named pair. Naming the pair would
// have caught the two instances above and nothing else; a third field, or a mask
// split in two, defeats it.
func Recover(r Result, material string) []Attempt {
	want := []byte(material)
	var found []Attempt

	for _, t := range r.Blobs {
		if bytes.Contains(t.Bytes, want) {
			found = append(found, Attempt{How: "plaintext in a reachable field", TargetPath: t.Path})
		}
	}

	for _, target := range r.Blobs {
		if len(target.Bytes) < len(want) {
			continue
		}
		for _, k := range r.Blobs {
			// 2. the pairwise XOR.
			if len(k.Bytes) >= len(want) && xorEqual(target.Bytes, k.Bytes, want) {
				found = append(found, Attempt{
					How: "XOR of two reachable fields", KeyPath: k.Path, TargetPath: target.Path,
				})
			}
			// 1. keystream reconstruction, with every blob tried as the key at
			//    every blob's nonce.
			var key [32]byte
			copy(key[:], k.Bytes)
			for _, n := range r.Blobs {
				ks := Keystream(key, n.Bytes, len(want))
				if xorEqual(target.Bytes, ks, want) {
					found = append(found, Attempt{
						How: "keystream reconstruction", KeyPath: k.Path, NoncePath: n.Path,
						TargetPath: target.Path,
					})
				}
			}
		}
	}
	return found
}

// xorEqual reports whether a XOR b, over the length of want, equals want.
func xorEqual(a, b, want []byte) bool {
	if len(a) < len(want) || len(b) < len(want) {
		return false
	}
	for i := range want {
		if a[i]^b[i] != want[i] {
			return false
		}
	}
	return true
}
