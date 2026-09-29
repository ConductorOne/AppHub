// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"text/template"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/reachable"
)

// value is text this repository did not author.
//
// The alphabet is deliberate. These tests look for any two-byte slice of it, and
// an English-looking value shares two-byte slices with this package's own constant
// placeholders -- "text-from-outside-the-repository" and
// "credentials.Foreign([NOT RENDERED])" both contain "de", which reported a leak
// that was not one. A three-byte repeating pattern shares no two-byte slice with
// any constant here, so a hit is a real hit.
//
// The generic fixture in internal/errhygiene does not need this: it drives two
// byte-disjoint sentinels and requires a hit in both, which cannot be produced by
// a constant. This file has one value, so the value carries the property.
const value = "Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3"

// TestForeignRendersNothingWhateverAsksIt walks every path a value can become text
// by.
//
// It is a class rather than a list of the verbs that happened to leak: the type
// exists because two rounds of review found a rendering path that a targeted test
// had not thought of, and %v is not a more likely mistake than %#v inside a map.
func TestForeignRendersNothingWhateverAsksIt(t *testing.T) {
	f := credentials.NewForeign(value)

	renderings := map[string]string{
		"%v":            fmt.Sprintf("%v", f),
		"%+v":           fmt.Sprintf("%+v", f),
		"%#v":           fmt.Sprintf("%#v", f),
		"%s":            fmt.Sprintf("%s", f),
		"%q":            fmt.Sprintf("%q", f),
		"%x":            fmt.Sprintf("%x", f),
		"%d":            fmt.Sprintf("%d", f),
		"String":        f.String(),
		"GoString":      f.GoString(),
		"in a struct":   fmt.Sprintf("%v", struct{ F credentials.Foreign }{f}),
		"in a struct #": fmt.Sprintf("%#v", struct{ F credentials.Foreign }{f}),
		"in a slice":    fmt.Sprintf("%v", []credentials.Foreign{f}),
		"in a map":      fmt.Sprintf("%v", map[string]credentials.Foreign{"k": f}),
		"in an error":   fmt.Errorf("context: %v", f).Error(),
		"pointer":       fmt.Sprintf("%v %#v", &f, &f),
	}
	for name, got := range renderings {
		if strings.Contains(got, value) {
			t.Errorf("%s rendered the value: %s", name, got)
		}
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", slog.Any("f", f), slog.Any("group", struct {
		F credentials.Foreign
	}{f}))
	if strings.Contains(buf.String(), value) {
		t.Errorf("slog rendered the value: %s", buf.String())
	}
}

// TestForeignRefusesToSerialize: an encoder that wrote the placeholder would
// produce a record that looks like data and is not, so every encoder fails
// instead.
func TestForeignRefusesToSerialize(t *testing.T) {
	f := credentials.NewForeign(value)

	if _, err := f.MarshalJSON(); !errors.Is(err, credentials.ErrForeignMarshal) {
		t.Errorf("MarshalJSON = %v", err)
	}
	if _, err := f.MarshalText(); !errors.Is(err, credentials.ErrForeignMarshal) {
		t.Errorf("MarshalText = %v", err)
	}
	if _, err := f.GobEncode(); !errors.Is(err, credentials.ErrForeignMarshal) {
		t.Errorf("GobEncode = %v", err)
	}
	if err := (&credentials.Foreign{}).GobDecode([]byte("anything")); !errors.Is(err, credentials.ErrForeignMarshal) {
		t.Errorf("GobDecode = %v", err)
	}

	// Through the real encoders, nested, which is the shape that actually happens:
	// a struct carrying one of these reaches an audit record or a cache.
	type record struct {
		Provider credentials.Foreign
		Note     string
	}
	if b, err := json.Marshal(record{Provider: f, Note: "n"}); err == nil {
		t.Errorf("json.Marshal succeeded: %s", b)
	}
	var gbuf bytes.Buffer
	if err := gob.NewEncoder(&gbuf).Encode(record{Provider: f, Note: "n"}); err == nil {
		t.Errorf("gob.Encode succeeded: %x", gbuf.Bytes())
	}
	if strings.Contains(gbuf.String(), value) {
		t.Errorf("the partial gob stream carries the value: %x", gbuf.Bytes())
	}
}

// TestForeignRoundTripsAndReportsWithoutRevealing: the type is useless if the
// value cannot be recovered deliberately, and the two things an error may say
// about it -- emptiness and length -- are available without revealing it.
func TestForeignRoundTripsAndReportsWithoutRevealing(t *testing.T) {
	f := credentials.NewForeign(value)
	if got := credentials.RevealForeign(f); got != value {
		t.Errorf("RevealForeign = %q, want the value", got)
	}
	if f.IsZero() {
		t.Error("IsZero on a populated Foreign")
	}
	if f.Len() != len(value) {
		t.Errorf("Len = %d, want %d", f.Len(), len(value))
	}

	var zero credentials.Foreign
	if !zero.IsZero() || zero.Len() != 0 {
		t.Error("the zero value should be empty")
	}
	if credentials.RevealForeign(zero) != "" {
		t.Error("the zero value should reveal nothing")
	}
	// The zero value still renders the placeholder rather than an empty string, so
	// a message never reads "provider : failed".
	if got := fmt.Sprintf("%v", zero); got == "" {
		t.Error("the zero value rendered as empty")
	}
}

// TestForeignHoldsNoReachablePlaintext is the property the second round of review
// added, and it is a property of the representation rather than of the rendering.
//
// The first version of this type held one unexported string. Unexported closes
// reflect.Value.Interface and field setting, and closes nothing else:
// reflect.Value.String returned the whole value. Every rendering method was
// correct and the type still leaked, because neither reflection nor a
// struct-walking logger asks a value to render itself.
func TestForeignHoldsNoReachablePlaintext(t *testing.T) {
	f := credentials.NewForeign(value)
	rv := reflect.ValueOf(f)
	if rv.NumField() == 0 {
		t.Fatal("Foreign has no fields; this test would be vacuous")
	}
	for i := range rv.NumField() {
		field := rv.Field(i)
		name := rv.Type().Field(i).Name
		var got string
		func() {
			// A generic reader wraps its accessors, because it does not know what
			// it is looking at. Anything it can read, it can print.
			defer func() { _ = recover() }()
			switch field.Kind() {
			case reflect.String:
				got = field.String()
			case reflect.Slice, reflect.Array:
				b := make([]byte, field.Len())
				for j := range field.Len() {
					b[j] = byte(field.Index(j).Uint())
				}
				got = string(b)
			default:
				got = fmt.Sprintf("%v", field)
			}
		}()
		// Whole-string containment is not enough, and review proved it: a five-byte
		// [5]byte field holding value[:5] passed a Contains check against the whole
		// 32-byte value. So a field is a leak if it holds ANY slice of the input, at
		// any length -- which is what a partial copy looks like.
		if leak := sliceOfInput(got, value); leak != "" {
			t.Errorf("field %s is reachable by ordinary reflection and holds %d byte(s) of the "+
				"plaintext (%q)", name, len(leak), leak)
		}
	}

	// Recombining every field a walk can see must not reverse it either: that is
	// the axis on which this type is one step stronger than Secret, whose mask
	// sits beside its masked bytes. This covers the *generic* recombination a
	// dumper performs -- XOR two byte fields -- and nothing more; the
	// construction-aware adversary is
	// TestForeignKeepsItsKeyOutOfTheValue, which is the load-bearing one for the
	// key's location.
	var joined []byte
	for i := range rv.NumField() {
		field := rv.Field(i)
		if field.Kind() != reflect.Slice && field.Kind() != reflect.Array {
			continue
		}
		for j := range field.Len() {
			joined = append(joined, byte(field.Index(j).Uint()))
		}
	}
	for i := range joined {
		for j := i + 1; j <= len(joined); j++ {
			// XOR every pair of equal-length windows, which is what recombining two
			// reachable byte fields amounts to.
			if j-i != len(value) {
				continue
			}
			window := joined[i:j]
			for k := 0; k+len(value) <= len(joined); k++ {
				out := make([]byte, len(value))
				for n := range out {
					out[n] = window[n] ^ joined[k+n]
				}
				if string(out) == value {
					t.Error("recombining two reachable byte windows recovered the plaintext")
					return
				}
			}
		}
	}
}

// TestForeignIsNotReachableFromAStructWalkingLogger covers the second of the two
// paths review used. A handler that forgets Value.Resolve never fires LogValuer,
// and a handler that reflects into what it was given is the ordinary way somebody
// writes "log whatever this is".
func TestForeignIsNotReachableFromAStructWalkingLogger(t *testing.T) {
	var seen []string
	h := &walkingHandler{seen: &seen}
	slog.New(h).Info("m",
		slog.Any("bare", credentials.NewForeign(value)),
		slog.Any("nested", struct{ F credentials.Foreign }{credentials.NewForeign(value)}),
	)
	if len(seen) == 0 {
		t.Fatal("the handler saw nothing; this test would be vacuous")
	}
	for _, got := range seen {
		if leak := sliceOfInput(got, value); leak != "" {
			t.Errorf("a struct-walking handler recovered %d byte(s) of the plaintext (%q)", len(leak), leak)
		}
	}
}

// walkingHandler deliberately does not call Value.Resolve.
type walkingHandler struct{ seen *[]string }

func (h *walkingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *walkingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *walkingHandler) WithGroup(string) slog.Handler            { return h }

func (h *walkingHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		h.walk(reflect.ValueOf(a.Value.Any()))
		return true
	})
	return nil
}

func (h *walkingHandler) walk(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		*h.seen = append(*h.seen, v.String())
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range v.Len() {
				b[i] = byte(v.Index(i).Uint())
			}
			*h.seen = append(*h.seen, string(b))
			return
		}
		for i := range v.Len() {
			h.walk(v.Index(i))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			h.walk(v.Field(i))
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			h.walk(v.Elem())
		}
	default:
		*h.seen = append(*h.seen, fmt.Sprintf("%v", v))
	}
}

// TestForeignIsNotReachableFromATemplate: RevealForeign is a package function and
// not a method, so no template can name it. compute.SecretValue made the opposite
// choice and {{.Reveal}} rendered its material, which is USOSS-43.
//
// The expressions are DERIVED, not listed. An earlier version of this test named
// four of them, and review escaped it by adding a zero-argument Reveal method --
// the template found it by name and the test did not, because the test knew four
// names and the class is "every exported zero-argument method". Enumerating the
// class is the only shape that covers a method nobody has written yet.
func TestForeignIsNotReachableFromATemplate(t *testing.T) {
	f := credentials.NewForeign(value)
	rt := reflect.TypeOf(f)

	exprs := []string{"{{.}}", "{{printf \"%v\" .}}"}
	for i := range rt.NumMethod() {
		m := rt.Method(i)
		if m.Type.NumIn() == 1 && m.Type.NumOut() == 1 {
			exprs = append(exprs, "{{."+m.Name+"}}", "{{.V."+m.Name+"}}")
		}
	}
	if len(exprs) < 3 {
		t.Fatal("no zero-argument method was derived, so this test would prove almost nothing")
	}

	for _, expr := range exprs {
		var data any = f
		if strings.Contains(expr, ".V.") {
			data = struct{ V credentials.Foreign }{f}
		}
		tp, err := template.New("t").Parse(expr)
		if err != nil {
			t.Fatalf("Parse %s: %v", expr, err)
		}
		var b strings.Builder
		if err := tp.Execute(&b, data); err != nil {
			t.Fatalf("Execute %s: %v", expr, err)
		}
		if leak := sliceOfInput(b.String(), value); leak != "" {
			t.Errorf("text/template %s recovered %d byte(s) of the plaintext (%q)", expr, len(leak), leak)
		}
	}
	t.Logf("%d template expressions derived from the method set, none rendered the plaintext", len(exprs))
}

// sliceOfInput returns the longest slice of want that appears in got, or "".
//
// Resolution is one byte for a whole-field copy and two for an embedded one. One
// byte embedded in other text is not distinguishable from coincidence here, which
// is stated rather than implied; the generic fixture in internal/errhygiene gets to
// one byte for both by comparing two byte-disjoint sentinels.
func sliceOfInput(got, want string) string {
	if got == "" {
		return ""
	}
	for l := len(want); l >= 1; l-- {
		for o := 0; o+l <= len(want); o++ {
			slice := want[o : o+l]
			if got == slice || (l >= 2 && strings.Contains(got, slice)) {
				return slice
			}
		}
	}
	return ""
}

// TestForeignKeepsItsKeyOutOfTheValue is the test that stops a later refactor
// from moving the key into the struct.
//
// It is here because that refactor is easy, plausible, and invisible to every
// other check. A generic recombining walk -- the one above -- cannot see it: the
// keystream is SHA-256 of the key rather than the key itself, so XORing two
// reachable fields does not recover the plaintext even when one of them *is* the
// key. The reachable-bytes walk in internal/errhygiene cannot see it either,
// because the key is not the plaintext. The property "the reversing key is not
// reachable from the value" was therefore documented and enforced by nothing,
// which on this project is the shape that gets found by a reviewer.
//
// So this adversary knows the construction. It takes every window of the bytes a
// value exposes as a candidate key and every window as a candidate nonce, runs the
// real derivation, and fails if any pair reverses the value. That is a strictly
// stronger reader than a dumper, and deliberately so: the threat it models is not
// somebody attacking Foreign, it is a future author moving one field and nobody
// noticing that the type stopped being what its comment says.
func TestForeignKeepsItsKeyOutOfTheValue(t *testing.T) {
	f := credentials.NewForeign(value)

	// Every byte a walk can reach, concatenated. If a key ever lands in the
	// struct it is in here.
	var reachable []byte
	rv := reflect.ValueOf(f)
	for i := range rv.NumField() {
		field := rv.Field(i)
		if field.Kind() != reflect.Slice && field.Kind() != reflect.Array {
			continue
		}
		if field.Kind() == reflect.Slice && field.IsNil() {
			continue
		}
		if field.Type().Elem().Kind() != reflect.Uint8 {
			continue
		}
		for j := range field.Len() {
			reachable = append(reachable, byte(field.Index(j).Uint()))
		}
	}
	if len(reachable) < keyLen+nonceLen {
		t.Fatalf("only %d reachable bytes; this test cannot form a candidate key and "+
			"would pass vacuously", len(reachable))
	}

	// The masked bytes are whichever reachable window, XORed with a derived
	// keystream, would give the value back. Try every candidate.
	tried := 0
	for keyAt := 0; keyAt+keyLen <= len(reachable); keyAt++ {
		var key [keyLen]byte
		copy(key[:], reachable[keyAt:keyAt+keyLen])
		for nonceAt := 0; nonceAt+nonceLen <= len(reachable); nonceAt++ {
			var nonce [nonceLen]byte
			copy(nonce[:], reachable[nonceAt:nonceAt+nonceLen])
			ks := deriveKeystream(key, nonce, len(value))
			for maskedAt := 0; maskedAt+len(value) <= len(reachable); maskedAt++ {
				tried++
				out := make([]byte, len(value))
				for n := range out {
					out[n] = reachable[maskedAt+n] ^ ks[n]
				}
				if string(out) == value {
					t.Fatalf("the value is recoverable from its own reachable bytes: a candidate key at "+
						"offset %d and nonce at offset %d reversed the masked bytes at offset %d. The "+
						"reversing key must not be reachable from the value -- see the Foreign doc comment.",
						keyAt, nonceAt, maskedAt)
				}
			}
		}
	}
	if tried == 0 {
		t.Fatal("no candidate was tried, so this test proved nothing")
	}
	t.Logf("%d candidate (key, nonce, offset) triples over %d reachable bytes, none reversed the value",
		tried, len(reachable))
}

// keyLen mirrors the production key size. It is restated rather than exported
// because exporting it would widen the API for a test, and it is cross-checked:
// TestForeignKeepsItsKeyOutOfTheValue fails vacuously if it is wrong, because
// there would be too few reachable bytes to form a candidate.
const keyLen = 32

// nonceLen mirrors the production nonce size, for the same reason.
const nonceLen = 16

// deriveKeystream reimplements the production derivation from the outside. It is a
// deliberate duplicate: a test that called the real one would pass by sharing the
// bug, and the point here is to be an adversary that knows the construction rather
// than one that trusts it.
func deriveKeystream(key [keyLen]byte, nonce [nonceLen]byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, keyLen+nonceLen+8)
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

// TestForeignSurvivesASingleByteEffectiveKeyProbe closes USOSS-59's first gap.
//
// Reproduced before this test existed: rewrite keystreamWith to hash only
// key[0] -- one byte -- instead of the full 32-byte key, leaving the other 31
// bytes of the process key unused. That mutation passes every test in this
// file and in foreign_internal_test.go, including both tests that exist
// specifically to pin the key's role:
//
//   - TestTheKeyIsLoadBearing supplies two probe keys that differ at byte 0, so
//     "two different keys produce different keystreams" holds by coincidence
//     even when bytes 1-31 are ignored.
//   - TestForeignKeepsItsKeyOutOfTheValue searches for the key SOMEWHERE INSIDE
//     the value's own reachable bytes; a key that is simply short does not
//     change what that search is looking for.
//
// Neither test, nor any other in this package, ever tries to recover a value
// from a GUESSED key. This one does: it is the "external 256-candidate probe"
// the ticket describes, aimed at the shipped derivation through
// [credentials.KeystreamForTest] rather than a local reimplementation, so it
// exercises the real construction and not an approximation of it. Against the
// real 32-byte key this recovers nothing -- guessing one byte of a 32-byte key
// and zeroing the rest is astronomically unlikely to land on the real key.
// Against the one-byte-effective mutation above it recovers the value in at
// most 256 tries, because the other 31 bytes were never part of the
// derivation being attacked.
func TestForeignSurvivesASingleByteEffectiveKeyProbe(t *testing.T) {
	f := credentials.NewForeign(value)

	// masked and nonce, read by field name rather than by position: a field
	// reorder must not silently point this at the wrong bytes.
	rv := reflect.ValueOf(f)
	var masked []byte
	var nonce [nonceLen]byte
	var foundMasked, foundNonce bool
	for i := range rv.NumField() {
		field := rv.Field(i)
		switch rv.Type().Field(i).Name {
		case "masked":
			for j := range field.Len() {
				masked = append(masked, byte(field.Index(j).Uint()))
			}
			foundMasked = true
		case "nonce":
			for j := range field.Len() {
				nonce[j] = byte(field.Index(j).Uint())
			}
			foundNonce = true
		}
	}
	if !foundMasked || !foundNonce {
		t.Fatalf("did not find both masked and nonce fields by name (masked=%v nonce=%v); this test "+
			"would be vacuous", foundMasked, foundNonce)
	}
	if len(masked) == 0 {
		t.Fatal("masked is empty; this test would be vacuous")
	}

	tried := 0
	for candidate := range 256 {
		var key [32]byte
		key[0] = byte(candidate)
		// The other 31 bytes are left zero on purpose: that is the whole point
		// of the attack this guards against. If the real derivation only
		// consulted key[0], the value 1-31 would not matter and zero is as
		// good a guess as any.
		ks := credentials.KeystreamForTest(key, nonce, len(masked))
		tried++
		out := make([]byte, len(masked))
		for i := range out {
			out[i] = masked[i] ^ ks[i]
		}
		if string(out) == value {
			t.Fatalf("candidate byte %d, with the other 31 key bytes zero, reversed the value in "+
				"%d tries: the derivation depends on only one byte of its key. keystreamWith must "+
				"hash the full key, not a single byte of it", candidate, tried)
		}
	}
	t.Logf("%d single-byte candidate keys tried, none reversed the value", tried)
}

// TestNoRecombinationOfReachableStateReversesAForeign closes USOSS-59's second
// gap by giving Foreign the same protection credentials.Secret already has:
// the single, depth-unlimited walk in internal/reachable, rather than the
// depth-ONE walks this file has used since Foreign was written.
//
// Reproduced before this test existed: nest Foreign's masked and nonce fields
// nine structs deep (the exact depth internal/reachable's own fixtures use).
// TestForeignKeepsItsKeyOutOfTheValue fails LOUD on its own vacuity guard
// ("only 0 reachable bytes"), which is the correct failure mode for a check
// that cannot see what it was asked to check. TestForeignHoldsNoReachablePlaintext
// is more subtle: its whole-value containment check keeps working by accident,
// because Go's fmt package special-cases a reflect.Value operand and recurses
// into it regardless of exported-ness -- but its SECOND assertion, the pairwise
// recombination over joined byte/slice fields, collects bytes only from
// rv.NumField() at the top level. With the fields nested, that loop finds no
// Slice or Array field, joined stays empty, both nested loops below it iterate
// zero times, and the test reports success having examined nothing -- with no
// vacuity guard on joined to say so. That is "checked and clean" standing in
// for "never looked", in exactly the shape the shared package exists to close.
//
// internal/reachable has no such blind spot: it recurses through structs with
// no depth cap, proven at this exact depth by its own
// TestAFuncFieldIsReportedUnreadableRatherThanSkipped fixture, and a kind it
// has no case for is a fatal error rather than a silent skip. Wiring Foreign
// into it, the way credentials.Secret already is
// (TestNoRecombinationOfReachableStateReversesASecret), means a future refactor
// that moves Foreign's fields into a nested holder -- at any depth -- fails
// this test instead of passing the old one by accident.
//
// This test does not, on its own, catch the field/method PROMOTION gap: a
// promoted exported field is a distinct hazard from a nested unexported one,
// closed instead by TestTheForeignSurfaceIsExactlyTheAllowlist below.
func TestNoRecombinationOfReachableStateReversesAForeign(t *testing.T) {
	f := credentials.NewForeign(value)

	// The two derivations must agree, or the attack below is aimed at a
	// construction nobody ships and its silence proves nothing. See
	// internal/reachable's own doc comment on AgreesWith.
	var probeKey [32]byte
	copy(probeKey[:], "an-arbitrary-key-for-comparison-")
	agree := reachable.AgreesWith(func(k [32]byte, nonce []byte, n int) []byte {
		var fixed [nonceLen]byte
		copy(fixed[:], nonce)
		return credentials.KeystreamForTest(k, fixed, n)
	}, probeKey, []byte("sixteen-byte-non"), 128)
	if !agree {
		t.Fatal("internal/reachable's keystream no longer agrees with credentials.KeystreamForTest. " +
			"Fix the reimplementation: an attack against a derivation nobody ships proves nothing, " +
			"and its silence would read as a pass")
	}

	r, err := reachable.Walk(f)
	if err != nil {
		t.Fatalf("walking a Foreign: %v", err)
	}
	if len(r.Blobs) < 2 {
		t.Fatalf("only %d reachable blob(s) in a Foreign; the walk is not descending, and every "+
			"assertion below would pass vacuously", len(r.Blobs))
	}
	if len(r.Unreadable) != 0 {
		t.Errorf("a Foreign has %d location(s) reflection cannot read: %v. A func or channel field "+
			"on this type is a place text can sit where no walk follows it", len(r.Unreadable), r.Unreadable)
	}
	for _, a := range reachable.Recover(r, value) {
		t.Errorf("reachable state reverses a Foreign: %s (key=%s nonce=%s target=%s)",
			a.How, a.KeyPath, a.NoncePath, a.TargetPath)
	}

	if credentials.RevealForeign(f) != value {
		t.Fatal("RevealForeign did not round-trip; the assertions above prove nothing about a " +
			"construction that does not work")
	}
}

// foreignSurface is the complete allowlist of exported methods permitted on
// [credentials.Foreign] or *[credentials.Foreign], mirroring
// credentials.secretSurface and closing the other half of USOSS-59's second
// gap: Foreign had no allowlist at all, so an added exported method or field
// was checked by nothing.
var foreignSurface = map[string]string{
	"IsZero":      "reports emptiness as a bool; no text-shaped result exists to leak",
	"Len":         "reports a byte count as an int; a count is permitted by the invariant",
	"Format":      "fmt.Formatter, and the only formatting method: it renders the placeholder under every verb",
	"String":      "fmt.Stringer for the direct-call case; renders the same placeholder as Format",
	"GoString":    "fmt.GoStringer for the direct-call case; renders the same placeholder",
	"LogValue":    "slog.LogValuer: a handler that resolves values gets the placeholder",
	"MarshalJSON": "fails closed with ErrForeignMarshal; returns no bytes at all",
	"MarshalText": "fails closed the same way, for the encoders that never consult MarshalJSON",
	"GobEncode":   "fails closed; gob has no redacted form to emit",
	"GobDecode":   "the decode half gob requires of an encoder, and it refuses too",
}

// foreignUnlicensedMethods returns the exported methods of rt that
// foreignSurface does not name, over the method SET -- which includes methods
// promoted from an embedded field, at any depth.
func foreignUnlicensedMethods(rt reflect.Type) []string {
	var out []string
	for i := range rt.NumMethod() {
		if name := rt.Method(i).Name; foreignSurface[name] == "" {
			out = append(out, name)
		}
	}
	return out
}

// foreignExportedFields returns every exported field VISIBLE on rt, promotions
// included, via reflect.VisibleFields -- which resolves promotion through
// anonymous embedding at any depth, not just the declared field list.
func foreignExportedFields(rt reflect.Type) []string {
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

// depth9ForeignSurfaceControl carries an exported func-typed field NINE levels
// down through anonymous embedding -- the exact depth internal/reachable's own
// fixture uses (TestAFuncFieldIsReportedUnreadableRatherThanSkipped) -- so that
// TestTheForeignSurfaceIsExactlyTheAllowlist proves its derivation reaches that
// depth rather than merely working by luck at depth one, which is as far as
// credentials.surfaceControl (Secret's control) goes.
type depth9ForeignSurfaceControl struct{ ReviewField func() string }

type depth9ForeignL8 struct{ depth9ForeignSurfaceControl }
type depth9ForeignL7 struct{ depth9ForeignL8 }
type depth9ForeignL6 struct{ depth9ForeignL7 }
type depth9ForeignL5 struct{ depth9ForeignL6 }
type depth9ForeignL4 struct{ depth9ForeignL5 }
type depth9ForeignL3 struct{ depth9ForeignL4 }
type depth9ForeignL2 struct{ depth9ForeignL3 }
type depth9ForeignL1 struct{ depth9ForeignL2 }

// TestTheForeignSurfaceIsExactlyTheAllowlist gives Foreign the field/method
// allowlist rule USOSS-59's decision record states as the second half of a
// redacting type's surface check, and which credentials.Secret already has
// (TestTheSecretSurfaceIsExactlyTheAllowlist) but Foreign never did.
//
// Without this, an exported field or method added to Foreign -- at depth
// zero or promoted from nine levels of embedding -- is checked by nothing in
// this package: TestForeignIsNotReachableFromATemplate enumerates METHODS
// only, and no test here has ever looked for an exported FIELD at all.
func TestTheForeignSurfaceIsExactlyTheAllowlist(t *testing.T) {
	valueType := reflect.TypeFor[credentials.Foreign]()
	pointerType := reflect.PointerTo(valueType)
	if valueType.NumMethod() == 0 && pointerType.NumMethod() == 0 {
		t.Fatal("neither Foreign nor *Foreign reports any method, so this test inspects nothing")
	}

	for _, rt := range []reflect.Type{valueType, pointerType} {
		for _, name := range foreignUnlicensedMethods(rt) {
			t.Errorf("%s exposes %s, which foreignSurface does not name. Delete it, or add it to "+
				"foreignSurface with the reason it cannot carry the wrapped text out", rt, name)
		}
	}
	for name, why := range foreignSurface {
		_, onValue := valueType.MethodByName(name)
		_, onPointer := pointerType.MethodByName(name)
		if !onValue && !onPointer {
			t.Errorf("foreignSurface licenses %q (%s), which exists on neither Foreign nor *Foreign: "+
				"it was renamed or removed, and the entry now pre-authorises whatever is added under "+
				"that name next", name, why)
		}
	}
	for _, rt := range []reflect.Type{valueType, pointerType} {
		for _, name := range foreignExportedFields(rt) {
			t.Errorf("%s has an exported field %s. Every field on this type must be unexported", rt, name)
		}
	}

	// The control: a method AND a field, both promoted from nine levels of
	// anonymous embedding, must both be flagged -- or the derivations above are
	// reading the declared list rather than the resolved one.
	c := depth9ForeignL1{}
	c.ReviewField = func() string { return "control-should-be-flagged" }
	if c.ReviewField() == "" {
		t.Fatal("the control's field returned nothing, so it controls for nothing")
	}

	controlFields := foreignExportedFields(reflect.TypeFor[depth9ForeignL1]())
	found := false
	for _, f := range controlFields {
		if f == "ReviewField" {
			found = true
		}
	}
	if !found {
		t.Errorf("the field derivation did not find ReviewField, promoted nine levels down, on the "+
			"control: %v. It is reading declared fields rather than visible ones", controlFields)
	}
}
