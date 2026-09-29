// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"reflect"
	"testing"
)

// These tests mutate the FINISHED CONSTRUCTION rather than the leak paths.
//
// The leak paths are covered by secret_test.go, which walks every reachable field
// and tries to recombine them. That cannot notice the key becoming reachable, the
// randomness becoming a constant, or the key ceasing to matter, because in each of
// those the plaintext is still not sitting in a field. Every one of the three has
// now been demonstrated to slip past a check that looked like it covered it --
// once on credentials.Foreign, once on compute.SecretValue, and once here.

const keyTestMaterial = "usoss46-material-never-log-7b2e91af"

// The key-is-load-bearing property and the keystream length pin are NOT here.
//
// A first draft of this file had both, and they were duplicates: this package
// already asserts them in foreign_internal_test.go, over the same [keystream] and
// [keystreamWith] that [NewSecret] now uses. The compiler said so — two functions
// and one test name redeclared — which is the cheapest possible way to be told.
//
// Two copies of a security property drift, and the copy that falls behind is the
// one nobody re-derives. So the shared derivation has one set of assertions, and
// this file holds only what is specific to Secret: that the masking is drawn fresh
// per value, that no recombination of reachable fields reverses one, and that the
// exported surface is exactly what an allowlist names.
//
// USOSS-46 added the extra block-boundary lengths to that shared length pin rather
// than restating it here.

// TestTheMaskingIsDrawnFreshPerValue catches the randomness becoming a constant.
//
// Identical ciphertext across two values leaks equality: an observer of two dumps
// learns that two providers share an admin key without learning either.
//
// The limit, stated rather than implied: this catches a constant nonce and a zero
// key. It does not catch a key that is a non-zero compile-time constant, because
// nothing inside the process can tell a constant from a value drawn once. Only
// [secretKey]'s own source guards that, and PR #28's reviewer independently
// ratified the same limit on compute.SecretValue as honest.
func TestTheMaskingIsDrawnFreshPerValue(t *testing.T) {
	t.Parallel()
	a, b := NewSecret(keyTestMaterial), NewSecret(keyTestMaterial)

	if bytes.Equal(a.masked, b.masked) {
		t.Error("two secrets over the same material have identical masked bytes; the per-value " +
			"draw has become a constant, and identical ciphertext leaks that two values are equal")
	}
	if a.nonce == b.nonce {
		t.Error("two secrets share a nonce; the per-value draw has become a constant")
	}
	// The key being non-zero is asserted by TestTheMaskingKeyIsNotAConstant, over
	// the one key both types share; not restated here.
	for i, s := range []Secret{a, b} {
		if Reveal(s) != keyTestMaterial {
			t.Errorf("secret %d did not round-trip", i)
		}
	}
}

// secretSurface is the COMPLETE set of exported methods permitted on [Secret] or
// *[Secret], with the reason each one is on it.
//
// An allowlist, and the inversion is the point. This test used to prohibit a
// SHAPE -- exported, zero arguments, exactly one string result -- on the claim
// that it was "the only shape text/template can call by name". PR #28's reviewer
// falsified that claim twice from text/template's own documentation: the final
// method in a command MAY take arguments, and a niladic method MAY return two
// results with an error second. Both render the plaintext:
//
//	func (s Secret) Leak(_ string) string   { return Reveal(s) }   // {{.Leak "x"}}
//	func (s Secret) Leak() (string, error)  { return Reveal(s), nil } // {{.Leak}}
//
// Widening the recogniser to those two shapes loses again, and structurally
// rather than through carelessness: {{.M}} renders whatever comes back through
// fmt, so a method returning []byte, or a named type whose own formatting reaches
// the material, leaks identically. A denylist of leaky result shapes is a
// hand-maintained restatement of somebody else's grammar.
//
// So this states no shape at all. Anything not named here is fatal, whatever its
// arity and whatever it returns. Adding to this type's surface becomes an edit to
// this list -- a decision someone makes, in a diff a reviewer reads.
//
// What the earlier version got right, and this must not lose: "String is fine
// because the body redacts today" is a claim about a method body, and a method
// body is what an edit changes. This list does not license bodies. That each of
// these redacts is asserted in secret_test.go, over the fmt verbs and the slog,
// JSON, text and gob paths. The list licenses EXISTENCE; those tests hold
// behaviour, and neither is sufficient alone.
//
// String and GoString are absent because they were deleted, not overlooked:
// [Secret.Format] takes precedence over fmt.Stringer and fmt.GoStringer for every
// verb, so they were redundant for redaction while remaining live template calls
// into a type holding credential material.
var secretSurface = map[string]string{
	"Format":      "fmt.Formatter, and the only formatting method: it redacts under every verb",
	"LogValue":    "slog.LogValuer: a handler that resolves values gets the redaction",
	"MarshalJSON": "fails closed with ErrSecretMarshal; returns no bytes at all",
	"MarshalText": "fails closed the same way, for the encoders that never consult MarshalJSON",
	"GobEncode":   "fails closed; gob has no redacted form to emit",
	"GobDecode":   "the decode half gob requires of an encoder, and it refuses too",
	"UnmarshalJSON": "CONSUMES material rather than emitting it: it takes bytes and returns only " +
		"an error, and the error is a constant so no input byte reaches it",
	"IsZero": "reports emptiness as a bool; no material-shaped result exists to leak",
}

// exportedFields returns every exported field VISIBLE on rt, promotions included.
//
// The second half of the allowlist, and it was missing. A reviewer added an
// exported field
//
//	Leak func() string
//
// to Secret, populated with a closure returning the material, and the entire
// credentials suite passed while {{call .Leak}} rendered all 32 bytes. A
// method-name allowlist cannot see that: nothing on the method set changed.
//
// reflect.VisibleFields rather than NumField, because a field promoted from an
// embedded type is reachable by the same name from a template, and the declared
// field list does not mention it.
//
// The rule is EMPTY rather than a list. Secret's own documentation already says
// unexported fields are the design -- it just had no test, so the invariant
// existed only as prose, which is the shape this whole chain of findings is
// about.
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
// includes methods promoted from embedded fields. That is load-bearing, and
// TestTheSecretSurfaceIsExactlyTheAllowlist proves it with a control rather than
// citing the documentation.
func unlicensedMethods(rt reflect.Type, allow map[string]string) []string {
	var out []string
	for i := range rt.NumMethod() {
		if name := rt.Method(i).Name; allow[name] == "" {
			out = append(out, name)
		}
	}
	return out
}

// promotedSurface carries the three method shapes that have defeated a recogniser
// on a redacting type in this repository, on a POINTER receiver and reached by
// promotion.
//
// A pointer receiver because the first version of this gate on the sibling type
// enumerated the value method set and a pointer-receiver leak was invisible to it.
// By promotion because a method SET is not the declared method list, and a gate
// that reads declarations misses an embedded type entirely.
type promotedSurface struct {
	// ReviewField is the field half of the control: exported, promoted, and of
	// func type, which is the exact shape a reviewer used to render the material
	// with {{call .Leak}} while every method-based gate stayed green.
	ReviewField func() string
}

func (*promotedSurface) ReviewNiladic() string              { return keyTestMaterial }
func (*promotedSurface) ReviewWithArgument(_ string) string { return keyTestMaterial }
func (*promotedSurface) ReviewTwoResults() (string, error)  { return keyTestMaterial, nil }

// surfaceControl embeds it the way a real refactor would: an unexported type
// folded in for its helpers, silently exporting three methods.
type surfaceControl struct {
	*promotedSurface
}

// TestTheSecretSurfaceIsExactlyTheAllowlist is the durable invariant, asserted on
// the method surface rather than on the leak paths that motivated it.
//
// Three assertions, and each one has been the thing that failed on the sibling
// type:
//
//  1. Nothing outside the allowlist exists. This is the rule.
//  2. Every allowlist entry exists. A stale entry is a standing licence for a
//     future method to reuse that name; String and GoString would have left two.
//  3. The check flags the control. Without this, assertion 1 passes just as well
//     when the enumeration is reading the wrong method set.
func TestTheSecretSurfaceIsExactlyTheAllowlist(t *testing.T) {
	t.Parallel()

	value := reflect.TypeFor[Secret]()
	pointer := reflect.PointerTo(value)
	if value.NumMethod() == 0 && pointer.NumMethod() == 0 {
		t.Fatal("neither Secret nor *Secret reports any method, so this test inspects nothing")
	}

	for _, rt := range []reflect.Type{value, pointer} {
		for _, name := range unlicensedMethods(rt, secretSurface) {
			t.Errorf("%s exposes %s, which secretSurface does not name. Every exported method on "+
				"this type is reachable by name from text/template -- with arguments, and with an "+
				"error second result -- and whatever it returns is rendered through fmt. Delete it, "+
				"or add it to secretSurface with the reason it cannot carry material out, and expect "+
				"that line to be read", rt, name)
		}
	}

	for name, why := range secretSurface {
		_, onValue := value.MethodByName(name)
		_, onPointer := pointer.MethodByName(name)
		if !onValue && !onPointer {
			t.Errorf("secretSurface licenses %q (%s), which exists on neither Secret nor *Secret: "+
				"it was renamed or removed, and the entry now pre-authorises whatever is added under "+
				"that name next", name, why)
		}
	}

	// The field half: EMPTY, for both receivers.
	for _, rt := range []reflect.Type{value, pointer} {
		for _, name := range exportedFields(rt) {
			t.Errorf("%s has an exported field %s. A template reaches an exported field by name "+
				"with no method involved -- {{.%s}} for a string, {{call .%s}} for a func -- so a "+
				"method allowlist cannot see it. Every field on this type must be unexported",
				rt, name, name, name)
		}
	}

	c := &surfaceControl{promotedSurface: &promotedSurface{}}
	two, err := c.ReviewTwoResults()
	if c.ReviewNiladic() == "" || c.ReviewWithArgument("") == "" || two == "" || err != nil {
		t.Fatal("the control's methods returned nothing, so it controls for nothing")
	}
	// The control's exported field, promoted from the embedded type, must be
	// flagged too -- otherwise the emptiness assertion above passes just as well
	// when the derivation is reading the declared field list.
	if fields := exportedFields(reflect.TypeFor[*surfaceControl]()); len(fields) == 0 {
		t.Error("the field derivation found no exported field on *surfaceControl, which embeds a " +
			"type carrying one: it is reading declared fields rather than visible ones, and a " +
			"promoted exported field would go unnoticed")
	} else if fields[0] != "ReviewField" {
		t.Errorf("the field derivation found %v, not the control's promoted ReviewField", fields)
	}

	got := unlicensedMethods(reflect.TypeFor[*surfaceControl](), secretSurface)
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
			t.Errorf("the check did not flag %s on *surfaceControl, so it is not evaluating the full "+
				"method set: %s is exported, promoted from an embedded pointer, and callable from a "+
				"template. Found %v", name, name, got)
		}
	}
}
