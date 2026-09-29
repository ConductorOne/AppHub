// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// notRendered is what a Foreign renders as everywhere except RevealForeign.
const notRendered = "[NOT RENDERED]"

// ErrForeignMarshal is returned when something tries to serialize a Foreign.
//
// Refusing rather than writing the placeholder is deliberate: an encoder that
// silently substituted "[NOT RENDERED]" would produce a record that looks like
// data and is not, which is worse than a failed encode. A caller that genuinely
// needs the value on a wire calls RevealForeign and names the field it is
// building.
var ErrForeignMarshal = errors.New("credentials: refusing to serialize text this repository did not author; call credentials.RevealForeign explicitly")

// Foreign holds a string this repository did not author: a provider ID handed to
// the registry, a handle chosen by an upstream API, an operator's configuration
// value.
//
// # Why the type exists
//
// This package and its providers hold an invariant that is stated as a property
// rather than a list of call sites:
//
//	No error returned by credentials, credentials/datadog, credentials/github,
//	internal/githubapp or internal/credhttp contains any text that did not come
//	from a constant in this repository, a numeric count, or a Go type name.
//
// Two rounds of review found that invariant false while every comment asserting
// it was still in place, and the second round found it false in code written
// specifically to hold it. Both times the mechanism was the same: a field held a
// caller-supplied string, some rendering path formatted that field, and the only
// thing standing between the two was a comment saying the value was
// repository-owned. The APIs accepted arbitrary text, so the comment described a
// convention rather than a constraint.
//
// docs/DECISIONS.md records the general form -- prefer a construction that cannot
// express the violation over a check that notices one -- and this type is that
// construction for this invariant. A field of type Foreign cannot be formatted
// into a message: every fmt verb, Stringer, GoStringer and slog.LogValuer answers
// with a placeholder, and the encoders refuse outright. Writing
// fmt.Errorf("%q", e.providerID) no longer leaks; it renders the placeholder.
// Recovering the value takes a call to RevealForeign, which is a deliberate,
// greppable act -- the same standard Secret already sets for material.
//
// # Why the text is not stored as a string
//
// The first version of this type held one unexported string field, on the
// reasoning that unexported closes reflect.Value.Interface and field setting.
// Review falsified that: reflect.Value.String does not require an exported field,
// so reflect.ValueOf(f).Field(0).String() returned the whole value, and so did a
// custom slog.Handler that generically reflected into an unresolved slog.Any.
// Neither path needs unsafe.
//
// That is the failure mode worth designing against, and it is not an attacker. It
// is a logging handler or a debug dumper that walks a struct -- and such a reader
// never calls the accessor, so a type that holds plaintext and relies on every
// reader going through RevealForeign is a check rather than a construction. The
// property built to instead is stated as a property:
//
//	No reachable field of a Foreign contains the plaintext bytes.
//
// So the bytes are held XOR a keystream derived from a per-process key and a
// per-value random nonce. A reflection walk over a Foreign yields the ciphertext
// and the nonce; the key is a package-level variable that no Foreign value
// references, so recombining the fields a walk can see does not reverse it. The
// nonce means no two values share a keystream.
//
// # This is obfuscation, and the distinction matters
//
// It is not secrecy and must not be described as such. The key lives in the same
// address space: code in this process that wants the value calls RevealForeign, or
// reads the package variable with unsafe, or reads a memory dump. Nothing here
// prevents any of that and nothing here tries to.
//
// What it does provide is that no *generic* reader recovers the text -- not a fmt
// verb, not an encoder, not a structured logger, not a reflection walk over the
// value, not a template. Those are the readers that leak by accident, and accident
// is the failure this repository has actually shipped three times.
//
// It is one step stronger than Secret on exactly one axis: Secret stores its mask
// beside its masked bytes, so a walk that recombines two reachable fields recovers
// the material, which Secret's own comment says plainly. Foreign's reversing key
// is not reachable from the value. That is not a claim that Foreign matters more
// than Secret; it is a reason to ask whether Secret should be changed the same
// way, which is a decision for both types at once and not for this type's commit.
//
// # What it is not
//
// Foreign is not Secret and does not replace it. Secret holds credential material
// and exists to keep material from escaping at all. Foreign holds text that is
// merely not ours: safe to hold, safe to send back to the system that chose it,
// and unsafe only to render. A value that is material stays a Secret.
//
// The zero value is an empty Foreign and renders like any other.
type Foreign struct {
	// masked is the text XOR keystream(nonce). A reflection walk that reads this
	// field gets ciphertext: unexported stops Interface and field setting, but it
	// does not stop reflect.Value.String or reflect.Value.Bytes, which is how the
	// string-typed first version of this field was defeated.
	masked []byte
	// nonce is random per value, so no two Foreign values share a keystream. It is
	// not the key and is useless without it; the key is maskingKey below, which no
	// Foreign value references.
	nonce [nonceLen]byte
}

// nonceLen is the per-value nonce size.
const nonceLen = 16

// maskingKey is the per-process keystream key.
//
// It is package-level rather than a field on purpose: a key stored beside the
// ciphertext is recovered by the same walk that reads the ciphertext, which is the
// one weakness Secret documents about itself. Reflection over a Foreign value
// cannot reach this.
//
// crypto/rand.Read does not return an error on any supported platform; it panics
// if the system source fails, which is the correct outcome here -- a zero key
// would silently store the text in the clear.
//
// # Two refactors that would remove the point of this type
//
// Both are easy to make, and neither is visible to any check that does not exist
// specifically for it. The tests named here are load-bearing: nothing else catches
// either, so do not delete one believing it is covered elsewhere.
//
//   - Moving this into the Foreign struct, alongside the ciphertext. That is what
//     Secret does, and it is the one axis on which this type is stronger. A
//     generic recombining walk would still not recover the text -- the keystream is
//     a hash of the key rather than the key itself -- so the obvious test does not
//     see it. TestForeignKeepsItsKeyOutOfTheValue does: it treats every window of
//     a value's reachable bytes as a candidate key and nonce and runs the same
//     derivation, independently reimplemented -- deliberately not this function,
//     because a test that called it would pass by sharing any bug in it.
//   - Replacing the random draw with a constant, to drop the crypto/rand
//     dependency or to make something deterministic. In a public repository a
//     compiled-in key is not a key. TestTheMaskingKeyIsNotAConstant catches the zero
//     and low-entropy cases, and says plainly which case it cannot catch.
var maskingKey = sync.OnceValue(func() [32]byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k
})

// keystream returns n bytes of keystream for a nonce, under the process key.
//
// Shared by [Foreign] and [Secret]. One key per process for both is correct
// rather than a shortcut: the property each type needs is that the reversing term
// is not reachable FROM THE VALUE, and a single package-level key satisfies that
// for every value of every type. A second key would be a second thing to get
// wrong, and USOSS-46 added the Secret caller precisely because a private,
// adjacent mask was the failure.
//
// It delegates to keystreamWith rather than reading maskingKey inline, and that
// split exists for one reason: it makes "the key is load-bearing" a testable
// property instead of an inspectable one. See TestTheKeyIsLoadBearing.
func keystream(nonce [nonceLen]byte, n int) []byte {
	return keystreamWith(maskingKey(), nonce, n)
}

// keystreamWith returns n bytes of keystream for a key and a nonce.
//
// SHA-256 over key || nonce || block index. A keystream generator and not an
// authenticated cipher, deliberately: there is no adversary in the threat model
// who is denied the key, only a generic reader who never asks for it. See the
// obfuscation section of the Foreign comment.
//
// # Why the key is a parameter
//
// A sibling worker on USOSS-43, asked whether their recombination test was more
// general than this package's, went looking for a case that separated the two and
// found one that defeats both: derive the keystream from the *nonce alone* and
// leave the key silently unused. Everything stays green. The masked bytes still
// differ per value, so a freshness check passes; no field holds the plaintext, so
// the reachable walk passes; and a recombination test that tries reachable blobs
// as candidate keys passes, because the key is no longer part of the derivation it
// is testing. Meanwhile the value is recoverable by anyone who can read the nonce
// -- which is reachable -- and read this file.
//
// Verified on this type before it was fixed: with the key dropped, an external
// probe reversed the value from reachable state alone while every test in
// credentials and internal/errhygiene passed.
//
// The key being a parameter is what closes it. TestTheKeyIsLoadBearing calls this
// with two different keys and requires different output, and requires keystream to
// agree with this function under the process key -- so a rewrite that ignores the
// key fails one of the two, whichever function it rewrites.
func keystreamWith(key [32]byte, nonce [nonceLen]byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, len(key)+nonceLen+8)
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

// NewForeign wraps a string that did not come from this repository.
//
// This is the only way to construct a populated Foreign, which makes the points
// where foreign text enters a type as greppable as the points where it leaves.
func NewForeign(s string) Foreign {
	if s == "" {
		return Foreign{}
	}
	var nonce [nonceLen]byte
	_, _ = rand.Read(nonce[:])
	ks := keystream(nonce, len(s))
	masked := make([]byte, len(s))
	for i := range len(s) {
		masked[i] = s[i] ^ ks[i]
	}
	return Foreign{masked: masked, nonce: nonce}
}

// RevealForeign returns the string inside a Foreign.
//
// It is a package-level function and not a method for the same reason Reveal is:
// a method named Reveal is reachable by name from text/template, and a method is
// promoted through embedding. A function is neither.
//
// Every call site is a place where text this repository did not author crosses
// into something we build. Sending it back to the system that chose it -- a URL
// path, a request body, a revoke call -- is the intended use. Putting it in an
// error, a log line or a metric label is the thing this type exists to prevent,
// and doing it here rather than by accident is at least visible in a diff.
func RevealForeign(f Foreign) string {
	if len(f.masked) == 0 {
		return ""
	}
	ks := keystream(f.nonce, len(f.masked))
	out := make([]byte, len(f.masked))
	for i := range f.masked {
		out[i] = f.masked[i] ^ ks[i]
	}
	return string(out)
}

// IsZero reports whether the value is empty, without revealing it.
func (f Foreign) IsZero() bool { return len(f.masked) == 0 }

// Len reports the length in bytes of the wrapped string. A count is permitted by
// the invariant, and a length is often the whole of what an error needs to say.
func (f Foreign) Len() int { return len(f.masked) }

// Format implements fmt.Formatter for every verb, which is what makes %q, %s, %v
// and %#v equally safe. This is the load-bearing method: package fmt consults a
// Formatter before Stringer or GoStringer, so String and GoString below are
// unreachable through fmt and exist only for a direct caller.
func (f Foreign) Format(st fmt.State, _ rune) {
	_, _ = io.WriteString(st, notRendered)
}

// String implements fmt.Stringer for the direct-call case.
func (f Foreign) String() string { return notRendered }

// GoString implements fmt.GoStringer for the direct-call case.
func (f Foreign) GoString() string { return "credentials.Foreign(" + notRendered + ")" }

// LogValue implements slog.LogValuer, so a structured logger records the
// placeholder rather than the value.
func (f Foreign) LogValue() slog.Value { return slog.StringValue(notRendered) }

// MarshalJSON always fails. See ErrForeignMarshal.
func (f Foreign) MarshalJSON() ([]byte, error) { return nil, ErrForeignMarshal }

// MarshalText always fails, and also covers the encoders that prefer
// encoding.TextMarshaler.
func (f Foreign) MarshalText() ([]byte, error) { return nil, ErrForeignMarshal }

// GobEncode always fails. encoding/gob consults neither MarshalJSON nor
// MarshalText, so without this a gob stream carrying any struct with a Foreign in
// it would write the value out in the clear.
func (f Foreign) GobEncode() ([]byte, error) { return nil, ErrForeignMarshal }

// GobDecode always fails; gob requires a GobEncoder to be a GobDecoder too.
func (f *Foreign) GobDecode([]byte) error { return ErrForeignMarshal }
