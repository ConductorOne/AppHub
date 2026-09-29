// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is the one in-package test in this package.
//
// It is in-package because the property it checks is about maskingKey, which is
// unexported and must stay that way: exporting it to make it testable would hand
// every caller the thing the type exists to keep out of reach. Everything else
// about Foreign is tested from outside, where a caller sits.

package credentials

import (
	"bytes"
	"testing"
)

// TestTheMaskingKeyIsNotAConstant catches the second way a refactor can quietly
// remove this type's only real ingredient.
//
// The first way -- moving the key into the struct -- is caught by
// TestForeignKeepsItsKeyOutOfTheValue. This is the other one: replacing the
// random key with a constant, which is the kind of change that gets made to
// remove a crypto/rand dependency or to make a test deterministic. In a repository
// that is going public, a compiled-in key is not a key: the masking would be
// reversible by anybody holding the source, and every claim in the Foreign comment
// would be false while every other test stayed green.
//
// What this can and cannot check is worth being exact about, because the
// difference is the whole value of the test:
//
//   - It catches a zero or low-entropy constant, which is what the plausible
//     refactor actually produces.
//   - It cannot catch a high-entropy constant compiled into the binary, because
//     freshness is a property across processes and this test runs in one. That
//     property rests on reading maskingKey's definition -- a sync.OnceValue over
//     crypto/rand -- and not on any assertion here. Said plainly rather than
//     implied, because a test that looked like it covered this would be worse than
//     no test.
func TestTheMaskingKeyIsNotAConstant(t *testing.T) {
	key := maskingKey()

	var zero [32]byte
	if key == zero {
		t.Fatal("maskingKey is the zero value: the masking is an identity function and " +
			"every claim in the Foreign doc comment is false")
	}

	distinct := map[byte]bool{}
	for _, b := range key {
		distinct[b] = true
	}
	// A 32-byte draw from a real random source has ~28 distinct values on average
	// and essentially never fewer than 16. Any repeated-byte or patterned constant
	// falls far below that.
	if len(distinct) < 16 {
		t.Errorf("maskingKey has only %d distinct byte values across 32 bytes, which no random "+
			"draw plausibly produces; it looks like a constant", len(distinct))
	}

	// The key must also be stable within the process, or two calls to
	// RevealForeign on one value would disagree.
	if maskingKey() != key {
		t.Error("maskingKey is not stable within the process, so RevealForeign is not a function " +
			"of its argument")
	}
}

// TestTheKeyIsLoadBearing closes a hole that neither the reachable walk, nor the
// freshness check, nor the construction-aware key test could see.
//
// A sibling worker on USOSS-43 found it while checking whether their version of
// the recombination test was more general than this package's: derive the keystream
// from the nonce alone and leave the key unused. Every existing check passes. The
// masked bytes still vary per value; no field holds the plaintext; and a test that
// tries reachable blobs as candidate keys is blind by construction, because the key
// it is searching for is no longer part of the derivation. The value is then
// recoverable by anyone who can read the nonce -- which is reachable -- and read
// foreign.go. That was reproduced on this type before this test existed.
//
// The property is stated over the derivation rather than over the value:
//
//	the process key changes the keystream, and keystream uses the process key.
//
// Two assertions, because a rewrite could land in either function. If keystreamWith
// stops using its key, the first fails. If keystream stops delegating -- inlining a
// derivation that ignores the key -- the second fails. Neither can be satisfied by
// a derivation the key does not reach.
func TestTheKeyIsLoadBearing(t *testing.T) {
	var nonce [nonceLen]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	const n = 96

	var k1, k2 [32]byte
	for i := range k1 {
		k1[i] = byte(i + 1)
		k2[i] = byte(i + 2)
	}

	// 1. The derivation uses its key.
	if bytes.Equal(keystreamWith(k1, nonce, n), keystreamWith(k2, nonce, n)) {
		t.Fatal("two different keys produce the same keystream, so the key is not part of the " +
			"derivation and the masking is reversible from reachable state alone")
	}

	// 2. And keystream uses the process key rather than a derivation of its own.
	if !bytes.Equal(keystream(nonce, n), keystreamWith(maskingKey(), nonce, n)) {
		t.Fatal("keystream does not agree with keystreamWith under the process key, so it has a " +
			"derivation of its own and the key may not be in it")
	}

	// The nonce must matter too, or every value shares a keystream.
	var other [nonceLen]byte
	other[0] = 0xFF
	if bytes.Equal(keystreamWith(k1, nonce, n), keystreamWith(k1, other, n)) {
		t.Error("two different nonces produce the same keystream, so values share a keystream")
	}

	// Length is honoured exactly; a short return would leave plaintext tail bytes.
	//
	// The lengths either side of 32 and 64 are the block boundary: SHA-256 emits
	// 32 bytes at a time, so an off-by-one in the block loop shows up at 31/32/33
	// and again at 63/64/65 and nowhere else. 4096 is there because a truncation
	// bug that only appears after many blocks would otherwise be invisible.
	// Extended by USOSS-46, which needed this property for Secret too and found
	// the pin already here rather than writing a second one.
	for _, want := range []int{1, 15, 31, 32, 33, 63, 64, 65, 96, 100, 4096} {
		if got := len(keystream(nonce, want)); got != want {
			t.Errorf("keystream(%d) returned %d bytes", want, got)
		}
	}
}
