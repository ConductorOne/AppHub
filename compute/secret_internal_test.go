// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

// The two tests in this file exist because USOSS-7 reported that its own probe
// did not catch either of the refactors most likely to undo this construction,
// and that both passed every check it already had — including one that looked
// like it covered the first. So these mutate the *finished construction* rather
// than the leak paths.
//
// The leak paths are covered by secret_hygiene_test.go, which derives the class
// from go/types. That file asserts the plaintext is nowhere reachable. It cannot
// notice the key becoming reachable, or the randomness becoming a constant,
// because in both cases the plaintext is still not sitting in a field.

const secretMaterial = "usoss43-material-never-log-1c9f4e2a"

// The recombination property is NOT in this file. It lives in
// secret_recombination_test.go, in the external test package, over the one
// recursive reachability walk in internal/reachable.
//
// It was here, with a local walker, and USOSS-59 is why it moved. The
// credentials copy of the same idea walked only immediate fields and a reviewer
// hid the key in a one-field struct inside the type; this copy did recurse
// through structs, but it silently skipped maps and any kind its switch did not
// list, and two copies of "what is reachable" drift with the shallower one
// guarding the material. The attack also belongs OUTSIDE the package: calling
// this package's own keystream means sharing its bugs, so a derivation that
// quietly stopped using its key would fail to reverse anything and report a pass.
//
// What stays here is what needs unexported access to make its point: the
// key-omitted derivation below, and the freshness and length properties.

// TestTheMaskingIsDrawnFreshPerValue catches the randomness becoming a constant.
//
// Two secrets over the same plaintext must not share masked bytes. If the nonce
// draw were replaced by a constant they would be identical, and identical
// ciphertext across values leaks equality: an observer of two dumps learns that
// two applications share a password without learning either.
//
// It also asserts the key is non-zero, which is the specific accident that turns
// the whole construction into a no-op — a zero key with a zero nonce makes the
// keystream a fixed function of nothing.
//
// Stated plainly because the limit matters: this catches a constant *nonce* and a
// zero *key*. It does not catch a key that is a non-zero compile-time constant,
// because nothing inside the process can tell a constant from a value drawn once.
// That one is only visible in review, which is why the key's own comment says
// where it comes from.
func TestTheMaskingIsDrawnFreshPerValue(t *testing.T) {
	t.Parallel()

	a := NewSecretValue(secretMaterial)
	b := NewSecretValue(secretMaterial)

	if bytes.Equal(a.masked, b.masked) {
		t.Error("two secrets over the same plaintext have identical masked bytes; the per-value " +
			"draw has become a constant, and identical ciphertext leaks that two values are equal")
	}
	if a.nonce == b.nonce {
		t.Error("two secrets share a nonce; the per-value draw has become a constant")
	}
	var zero [32]byte
	if secretKey() == zero {
		t.Error("the package key is all zeroes, which makes the keystream a fixed function of the " +
			"nonce alone and the masking a no-op an attacker can reproduce")
	}
	// Both still reveal, so the difference above is not a broken construction.
	for i, sv := range []SecretValue{a, b} {
		if RevealSecret(sv) != secretMaterial {
			t.Errorf("secret %d did not round-trip", i)
		}
	}
}

// TestTheKeyIsActuallyInTheKeystream catches the mutation every other check in
// this package misses: a keystream derived from the nonce alone, with the
// package key silently unused.
//
// Found by USOSS-7 asking whether this file's recombination test dominated
// theirs. It does not, and this is why. Verified by making
// [secretKeystream] drop the key while still hashing the nonce:
//
//	the probe                    PASS   (masked != plaintext, so no field holds it)
//	the freshness test           PASS   (nonces still differ, so masked bytes differ)
//	the recombination test       PASS   (it uses the real derivation, which no longer
//	                                     needs the key, so trying reachable blobs AS
//	                                     the key changes nothing)
//
// All three green while the material is recoverable by anyone who can read the
// nonce — which is reachable — and knows the derivation, which is in the source.
// That is the whole construction defeated with nothing to show it.
//
// The check has to be stated as the property directly: the keystream must depend
// on the key. It cannot be tested by varying the key, because [secretKey] is a
// sync.OnceValue and there is no second key in the process. So it is tested from
// the other side — reverse the value using ONLY reachable state, with the key
// omitted from an otherwise-identical derivation. If that succeeds, the key is
// not in play.
func TestTheKeyIsActuallyInTheKeystream(t *testing.T) {
	t.Parallel()
	sv := NewSecretValue(secretMaterial)

	// The real derivation with the key term removed. Everything else identical:
	// same hash, same nonce, same block counter, same order.
	keyless := func(nonce [16]byte, n int) []byte {
		out := make([]byte, 0, n+sha256.Size)
		buf := make([]byte, 0, len(nonce)+8)
		for block := uint64(0); len(out) < n; block++ {
			buf = buf[:0]
			buf = append(buf, nonce[:]...)
			buf = binary.BigEndian.AppendUint64(buf, block)
			sum := sha256.Sum256(buf)
			out = append(out, sum[:]...)
		}
		return out[:n]
	}

	ks := keyless(sv.nonce, len(sv.masked))
	out := make([]byte, len(sv.masked))
	for i := range sv.masked {
		out[i] = sv.masked[i] ^ ks[i]
	}
	if string(out) == secretMaterial {
		t.Fatal("the secret reverses using only the nonce, with the package key omitted; the key " +
			"is not part of the keystream, so the material is recoverable by anyone who can read " +
			"the value's own fields and read this file")
	}

	// And the construction still works, or the assertion above is vacuous.
	if RevealSecret(sv) != secretMaterial {
		t.Fatal("RevealSecret did not round-trip, so the check above proves nothing")
	}
}

// TestTheKeystreamIsExactlyAsLongAsAsked closes a gap found by probing for one
// rather than by argument.
//
// A keystream one byte short panics today — the XOR loops are bounded by the
// plaintext, so a short keystream indexes past its end. That is detection, but it
// is detection by accident of the loop bounds rather than by a property, and the
// signal is an index out of range rather than a statement about the construction.
//
// The reason it is worth a real assertion: the obvious "fix" for that panic is to
// bound the loop to the shorter of the two. Then a short keystream leaves the
// tail of the plaintext **unmasked**, and nothing catches it — the reachable-field
// probe searches for the whole material with strings.Contains, so a partial
// plaintext tail does not match, and neither the freshness nor the key-relevance
// test looks at length at all. Silent partial plaintext in the field, from a
// two-character edit that reads as a bug fix.
//
// The lengths include several that are not multiples of the 32-byte hash block,
// because that is where an off-by-one in the block loop hides.
//
// Property credited to USOSS-7, who pinned it on credentials.Foreign; I added it
// here after confirming the panic-only path above.
func TestTheKeystreamIsExactlyAsLongAsAsked(t *testing.T) {
	t.Parallel()
	var nonce [16]byte
	for _, n := range []int{1, 15, 31, 32, 33, 63, 64, 65, 100, 4096} {
		if got := len(secretKeystream(nonce, n)); got != n {
			t.Errorf("secretKeystream asked for %d bytes returned %d; a short keystream leaves "+
				"the tail of the plaintext unmasked if either XOR loop is ever bounded by the "+
				"keystream rather than by the value", n, got)
		}
	}
	// And the round trip holds at those lengths, so the assertion above is not
	// satisfied by a keystream that is the right length and wrong.
	for _, n := range []int{1, 31, 32, 33, 65} {
		material := strings.Repeat("m", n)
		if got := RevealSecret(NewSecretValue(material)); got != material {
			t.Errorf("a %d-byte secret did not round-trip", n)
		}
	}
}

// secretValueSurface is the COMPLETE set of exported methods permitted on
// [SecretValue] or *[SecretValue], with the reason each one is on it.
//
// An allowlist, and the inversion is the point. The previous version of this
// test prohibited a *shape* — exported, zero arguments, exactly one string
// result — on the claim that it was "the only shape text/template can call by
// name". That claim is false, and PR #28's reviewer falsified it twice from
// text/template's own documentation: the final method in a command MAY take
// arguments, and a niladic method MAY return two results with an error second.
// Both of these rendered the exact plaintext with the shape prohibition green:
//
//	func (s SecretValue) Leak(_ string) string { return RevealSecret(s) }   // {{.Leak "x"}}
//	func (s SecretValue) Leak() (string, error) { return RevealSecret(s), nil } // {{.Leak}}
//
// Widening the recogniser to those two shapes loses again, and the reason it
// loses is structural rather than a matter of care: {{.M}} renders whatever
// comes back through fmt, so a method returning []byte, or a named type whose
// own formatting reaches the material, leaks identically. A denylist of leaky
// result shapes is a hand-maintained restatement of somebody else's grammar,
// and the next shape in that grammar is always available. The parallel USOSS-53
// work priced this: enumerating the fmt verb space found 462 leaking paths on
// the unhardened type where a hand-written probe had found five.
//
// So the rule states no shape at all. Anything not named here is fatal, whatever
// its arity and whatever it returns. Adding to this type's surface is then an
// edit to this list — a decision someone makes, in a diff a reviewer reads —
// rather than a signature that happens to fall outside a recogniser.
//
// What the earlier comment here got right, and this list must not lose: "String
// is allowed because it redacts today" is a claim about a method body, and a
// method body is what a future edit changes. This list does not license bodies.
// Every entry redacts, and that each one redacts is asserted elsewhere — the
// fmt verb table and the slog and JSON paths in compute_test.go, and the
// reachability probe in secret_hygiene_test.go. The list licenses the method's
// EXISTENCE; those tests hold its behaviour. Neither is sufficient alone, and
// dropping either was how this ticket got three rounds.
//
// Three of these entries -- MarshalText, GobEncode, GobDecode -- arrived from
// USOSS-53 on main, and this test is what made adding them a decision: the
// rebase failed until each one was named with a reason. That is the mechanism
// working rather than a nuisance. Each was then checked rather than waved
// through: MarshalText returns the same constant as MarshalJSON, and both gob
// methods return an error and never bytes, so none of the three has a
// material-shaped result to render.
//
// [SecretValue.String] and GoString are absent because they were deleted, not
// because they were overlooked: Format takes precedence over fmt.Stringer and
// fmt.GoStringer for every verb, so they were redundant for redaction while
// remaining live template calls into the type.
var secretValueSurface = map[string]string{
	"Format": "fmt.Formatter, and the only formatting method: it redacts under " +
		"every verb, including the ones a String method never sees",
	"LogValue":    "slog.LogValuer: a handler that resolves values gets [REDACTED]",
	"MarshalJSON": "json.Marshaler: redacts to a constant, which is also what keeps spec hashing stable",
	"MarshalText": "encoding.TextMarshaler: same redaction, for the encoders that never consult MarshalJSON",
	"UnmarshalJSON": "json.Unmarshaler: accepts only the redacted marker MarshalJSON writes and always " +
		"produces the zero value; no material-shaped result exists to leak, only an error carrying the " +
		"caller's own bytes back to them",
	"GobEncode": "gob has no redacted form to emit, so this refuses; it returns an error, never bytes",
	"GobDecode": "the decode half gob requires of an encoder, and it refuses too",
	"IsZero":    "reports emptiness as a bool; no material-shaped result exists to leak",
}

// exportedFields returns every exported field VISIBLE on rt, promotions included.
//
// The second half of the surface rule, and it was missing. A reviewer added an
// exported field
//
//	Leak func() string
//
// to the sibling type credentials.Secret, populated with a closure returning the
// material, and the entire suite passed while {{call .Leak}} rendered every byte.
// A method-name allowlist cannot see that: nothing on the method set changed.
//
// reflect.VisibleFields rather than NumField, because a field promoted from an
// embedded type is reachable by the same name from a template while the declared
// field list does not mention it.
//
// The rule is EMPTY rather than a list, and it is asserted rather than documented:
// this type's own comment already said the fields were unexported, which made the
// invariant prose. Prose is what every gate in this chain of findings turned out
// to be resting on.
func exportedFields(rt reflect.Type) []string {
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for _, f := range reflect.VisibleFields(rt) {
		if f.IsExported() {
			out = append(out, f.Name)
		}
	}
	return out
}

// unlicensedMethods returns the exported methods of rt that allow does not name.
//
// reflect.Type.NumMethod over a non-interface type reports the method SET, which
// includes methods promoted from embedded fields. That is load-bearing here and
// TestTheSecretSurfaceIsExactlyTheAllowlist proves it with a control rather than
// asserting it from the documentation.
func unlicensedMethods(rt reflect.Type, allow map[string]string) []string {
	var out []string
	for i := range rt.NumMethod() {
		if name := rt.Method(i).Name; allow[name] == "" {
			out = append(out, name)
		}
	}
	return out
}

// promotedSurface carries the three method shapes that have defeated a
// recogniser on this type, on a POINTER receiver and reached by promotion.
//
// A pointer receiver because the first version of this gate enumerated
// reflect.TypeOf(v) — the value method set — and a pointer-receiver leak was
// invisible to it. By promotion because a method set is not the declared method
// list, and a gate that reads the declaration misses an embedded type entirely.
type promotedSurface struct {
	// ReviewField is the field half of the control: exported, promoted, and of
	// func type — the exact shape that rendered the material through
	// {{call .Leak}} on the sibling type while every method-based gate stayed
	// green.
	ReviewField func() string
}

// The three shapes. Each returns something a template renders, and each is
// called once below: a control that returns nothing proves nothing.
func (*promotedSurface) ReviewNiladic() string              { return secretMaterial }
func (*promotedSurface) ReviewWithArgument(_ string) string { return secretMaterial }
func (*promotedSurface) ReviewTwoResults() (string, error)  { return secretMaterial, nil }

// surfaceControl embeds it the way a real refactor would: an unexported type
// folded in for its helpers, silently exporting three methods.
type surfaceControl struct {
	*promotedSurface
}

// TestTheSecretSurfaceIsExactlyTheAllowlist is the durable invariant this ticket
// is about, and it is asserted on the method surface rather than on the leak
// paths that motivated it — because the leak paths are instances and the surface
// is the class.
//
// Three assertions, and each one has been the thing that failed:
//
//  1. Nothing outside the allowlist exists. This is the rule.
//  2. Every allowlist entry exists. A stale entry is a standing licence for a
//     future method to reuse that name; String and GoString would have left two.
//  3. The check flags the control. Without this the first assertion passes just
//     as well when the enumeration is looking at the wrong method set, which is
//     exactly the defect that opened round two.
func TestTheSecretSurfaceIsExactlyTheAllowlist(t *testing.T) {
	t.Parallel()

	value := reflect.TypeFor[SecretValue]()
	pointer := reflect.PointerTo(value)

	// A derivation that inspects nothing passes every check over it.
	if value.NumMethod() == 0 && pointer.NumMethod() == 0 {
		t.Fatal("neither SecretValue nor *SecretValue reports any method, so this test is not " +
			"inspecting the surface it claims to")
	}

	for _, rt := range []reflect.Type{value, pointer} {
		for _, name := range unlicensedMethods(rt, secretValueSurface) {
			t.Errorf("%s exposes %s, which secretValueSurface does not name. Every exported "+
				"method on this type is reachable by name from text/template — with arguments, "+
				"and with an error second result — and whatever it returns is rendered through "+
				"fmt. Delete it, or add it to secretValueSurface with the reason it cannot carry "+
				"material out, and expect that line to be read", rt, name)
		}
	}

	// 2. No stale licences.
	for name, why := range secretValueSurface {
		_, onValue := value.MethodByName(name)
		_, onPointer := pointer.MethodByName(name)
		if !onValue && !onPointer {
			t.Errorf("secretValueSurface licenses %q (%s), which exists on neither SecretValue "+
				"nor *SecretValue: it was renamed or removed, and the entry now pre-authorises "+
				"whatever is added under that name next", name, why)
		}
	}

	// 2b. And no exported fields at all, on either receiver. A template reads an
	//     exported field by name with no method involved.
	for _, rt := range []reflect.Type{value, pointer} {
		for _, name := range exportedFields(rt) {
			t.Errorf("%s has an exported field %s: {{.%s}} renders a string field and "+
				"{{call .%s}} calls a func field, neither of which touches the method set the "+
				"allowlist governs. Every field on this type must be unexported", rt, name, name, name)
		}
	}

	// 3. The control. Its three methods are the shapes that defeated the
	//    recogniser this list replaced, promoted from an embedded pointer, plus an
	//    exported promoted field for the half above.
	c := &surfaceControl{promotedSurface: &promotedSurface{}}
	two, err := c.ReviewTwoResults()
	if c.ReviewNiladic() == "" || c.ReviewWithArgument("") == "" || two == "" || err != nil {
		t.Fatal("the control's methods returned nothing, so it controls for nothing")
	}
	if fields := exportedFields(reflect.TypeFor[*surfaceControl]()); len(fields) == 0 {
		t.Error("the field derivation found no exported field on *surfaceControl, which embeds a " +
			"type carrying one: it is reading declared fields rather than visible ones, so a " +
			"promoted exported field would go unnoticed")
	} else if fields[0] != "ReviewField" {
		t.Errorf("the field derivation found %v, not the control's promoted ReviewField", fields)
	}

	got := unlicensedMethods(reflect.TypeFor[*surfaceControl](), secretValueSurface)
	want := map[string]bool{"ReviewNiladic": false, "ReviewWithArgument": false, "ReviewTwoResults": false}
	for _, name := range got {
		if _, expected := want[name]; !expected {
			t.Errorf("the control reported an unexpected method %q", name)
			continue
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("the check did not flag %s on *surfaceControl, so it is not evaluating the "+
				"full method set: %s is exported, promoted from an embedded pointer, and callable "+
				"from a template. Found %v", name, name, got)
		}
	}
}

// leaksMaterial reports whether out exposes the material, in either of the two
// spellings fmt produces for it.
//
// The literal substring is the obvious one. The second is not, and it was a live
// blind spot in BOTH test files in this package: fmt prints a byte slice as
// decimal byte values, so a path that renders []byte(material) -- or a struct
// whose fields are byte slices, which is what %p does to this type -- emitted
// "[117 115 111 ...]" and a substring check saw nothing. That is a leak; a run
// of decimals is the material to anyone reading the log.
//
// It was found twice in one sitting, once in the hygiene probe's template walk
// and once in this file's own %p test, which is why there is one definition
// rather than one per file. Two copies of a leak predicate drift, and drift
// turns a failure to detect into a pass. The external test package reaches it
// through [LeaksMaterialForTest].
func leaksMaterial(out, material string) bool {
	if strings.Contains(out, material) {
		return true
	}
	// The decimal spelling, taken from fmt itself rather than assembled here, so
	// that if fmt ever changes how it prints a byte slice this predicate follows
	// it instead of checking for a format nothing produces any more.
	//
	// Handed over as an any on purpose, and not only to keep staticcheck from
	// helpfully converting it to a string: an any holding a []byte is exactly
	// how the material reaches fmt on the paths this catches -- a method result
	// a template renders, or a struct field %p falls through to.
	var raw any = []byte(material)
	spelled := strings.Trim(fmt.Sprint(raw), "[]")
	return spelled != "" && strings.Contains(out, spelled)
}

// TestFormatCannotCoverThePointerVerb pins the reason the field masking and
// [SecretValue.Format] are not two ways of doing one thing.
//
// fmt resolves %p BEFORE it consults fmt.Formatter, so no method on any type can
// redact it: fmt falls through to printing the struct's fields, prefixed
// %!p(...). Verified here rather than taken from the documentation, and verified
// with a control, because "Format covers every verb" is exactly the belief that
// would justify deleting the masking in a later simplification.
//
// So the division of labour is: Format covers the verbs that consult it, and the
// fields are masked for the verbs that do not. Dropping either leaves a live
// path — this one for the masking, and %s/%v/%q/%x for Format.
func TestFormatCannotCoverThePointerVerb(t *testing.T) {
	t.Parallel()

	// The control: a type whose only defence is Format. It must leak, or this
	// test is asserting something about fmt that is not true.
	control := fmt.Sprintf("%p", formatOnly{value: secretMaterial})
	if !leaksMaterial(control, secretMaterial) {
		t.Fatalf("a Format-only type did not leak under %%p (%q), so either fmt now consults "+
			"fmt.Formatter for %%p or this control no longer controls for anything. Re-derive "+
			"the division of labour in this test's comment before trusting it", control)
	}

	sv := NewSecretValue(secretMaterial)
	for _, tc := range []struct {
		what string
		v    any
	}{
		{"bare", sv},
		{"nested in a struct", struct{ V SecretValue }{sv}},
		{"behind a pointer", &sv},
	} {
		if got := fmt.Sprintf("%p", tc.v); leaksMaterial(got, secretMaterial) {
			t.Errorf("%%p over a SecretValue %s rendered the material: %q. Format is not consulted "+
				"for this verb; the fields are what stop it", tc.what, got)
		}
	}
}

// formatOnly stands in for the version of this type that redacts by method and
// stores its material in the clear.
type formatOnly struct{ value string }

func (formatOnly) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedValue) }
