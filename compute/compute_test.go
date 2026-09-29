// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute_test

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"text/template"

	"github.com/conductorone/apphub/compute"
)

// This package is a design artifact: it has interfaces, not implementations.
// What it does have is a handful of pure values that carry real obligations —
// a Ref must survive a round trip through storage, an UnsupportedError must be
// recognisable through errors.Is, and a SecretValue must not print itself. Each
// of those is load-bearing for a provider or for the security bar, so each is
// tested here rather than left for the first implementation to discover.

func TestRefRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []compute.Ref{
		{Provider: "aws", Kind: compute.KindService, ID: "svc-1"},
		// Provider IDs routinely contain colons (an ARN has five). String and
		// ParseRef must not lose anything to them.
		{Provider: "aws", Kind: compute.KindBucket, ID: "arn:aws:s3:::example-bucket"},
		{Provider: "kubernetes", Kind: compute.KindService, ID: "apps/my-app"},
	}

	for _, want := range cases {
		t.Run(want.ID, func(t *testing.T) {
			t.Parallel()
			got, err := compute.ParseRef(want.String())
			if err != nil {
				t.Fatalf("ParseRef(%q) returned error: %v", want.String(), err)
			}
			if got != want {
				t.Errorf("round trip changed the ref: got %#v, want %#v", got, want)
			}
		})
	}
}

func TestParseRefRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "aws", "aws:service", "aws::svc-1", ":service:svc-1", "aws:service:"} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			t.Parallel()
			if _, err := compute.ParseRef(in); err == nil {
				t.Errorf("ParseRef(%q) accepted a malformed reference", in)
			}
		})
	}
}

func TestRefIsZero(t *testing.T) {
	t.Parallel()

	if !(compute.Ref{}).IsZero() {
		t.Error("the zero Ref does not report IsZero")
	}
	if (compute.Ref{Provider: "aws"}).IsZero() {
		t.Error("a partially populated Ref reports IsZero")
	}
}

func TestUnsupportedErrorIsRecognisable(t *testing.T) {
	t.Parallel()

	err := compute.Unsupported("kubernetes", compute.CapKeyValueTable)

	if !errors.Is(err, compute.ErrUnsupported) {
		t.Fatal("Unsupported() does not match ErrUnsupported; callers branching on the sentinel would miss it")
	}

	var target *compute.UnsupportedError
	if !errors.As(err, &target) {
		t.Fatal("Unsupported() is not an *UnsupportedError")
	}
	if target.Provider != "kubernetes" || target.Capability != compute.CapKeyValueTable {
		t.Errorf("error lost its detail: %#v", target)
	}
	// The message has to name both, because it is what an operator sees when a
	// deploy fails and it must tell them which side to change.
	if msg := err.Error(); msg == "" ||
		!strings.Contains(msg, "kubernetes") ||
		!strings.Contains(msg, string(compute.CapKeyValueTable)) {
		t.Errorf("message %q does not name both the provider and the capability", msg)
	}
}

func TestCapabilitySet(t *testing.T) {
	t.Parallel()

	s := compute.NewCapabilitySet(compute.CapObjectStore, compute.CapContainerService)

	if !s.Has(compute.CapObjectStore) {
		t.Error("Has reports a member as absent")
	}
	if s.Has(compute.CapFunction) {
		t.Error("Has reports a non-member as present")
	}

	// Sorted, so a conformance failure or an admin listing reads the same way
	// every time.
	got := s.List()
	want := []compute.Capability{compute.CapContainerService, compute.CapObjectStore}
	if len(got) != len(want) {
		t.Fatalf("List returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List returned %v, want %v", got, want)
		}
	}

	if len(compute.CapabilitySet(nil).List()) != 0 {
		t.Error("the nil CapabilitySet should list nothing")
	}
	if compute.CapabilitySet(nil).Has(compute.CapObjectStore) {
		t.Error("the nil CapabilitySet should contain nothing")
	}
}

// TestSecretValueDoesNotLeak covers the security bar: the whole point of the
// type is that a secret does not reach output by accident.
//
// # Why the verbs are enumerated rather than listed
//
// The previous version of this test checked %v, %s, %+v and %#v. Those are four
// of the five verbs fmt routes through [fmt.Stringer] — in other words, every
// verb it checked was a verb that could not leak, and the verbs that did leak
// (%d, %t, %f, %c and every other non-Stringer verb, which fmt renders by
// printing the struct's fields) were exactly the ones absent. The test passed
// throughout.
//
// That is the failure mode, not the oversight: a hand-picked list verifies the
// cases someone thought of and never the complement, and the complement is
// where the leak lives. So this enumerates the whole single-letter verb space
// instead of choosing from it. Verbs fmt does not define are included on
// purpose — they cost nothing and they mean the population cannot go stale when
// fmt gains one.
func TestSecretValueDoesNotLeak(t *testing.T) {
	t.Parallel()

	const material = "correct-horse-battery-staple"
	s := compute.NewSecretValue(material)

	if compute.RevealSecret(s) != material {
		t.Fatal("Reveal did not return the material")
	}
	if !compute.NewSecretValue("").IsZero() {
		t.Error("an empty SecretValue does not report IsZero")
	}
	if s.IsZero() {
		t.Error("a populated SecretValue reports IsZero")
	}

	for _, leak := range leakPaths(t, s, material) {
		t.Errorf("a SecretValue leaked its material: %s", leak)
	}
}

// TestTheLeakProbeCanFail is the negative fixture for TestSecretValueDoesNotLeak.
//
// A probe that reports nothing is indistinguishable from a probe that checks
// nothing, and this package has had that exact failure: the test above passed
// for the whole life of the leaking type. So the probe runs against a type
// carrying the defences SecretValue used to have — a plain string field, String,
// GoString and MarshalJSON, and nothing else — and every leak class it is meant
// to detect must show up.
func TestTheLeakProbeCanFail(t *testing.T) {
	t.Parallel()

	const material = "correct-horse-battery-staple"
	found := leakPaths(t, unhardened{value: material}, material)

	// Each of these is a path the current SecretValue closes, so each must be
	// one the probe can actually see. "template" covers the walk folded in from
	// the standalone tripwire; without a Reveal-shaped method on the fixture it
	// would never fire and its absence would go unnoticed.
	want := []string{"%d", "%p", "reflect", "template"}
	for _, w := range want {
		if !slices.ContainsFunc(found, func(s string) bool { return strings.Contains(s, w) }) {
			t.Errorf("the probe did not detect the %s leak; it found %v", w, found)
		}
	}
	if len(found) == 0 {
		t.Fatal("the probe found nothing at all against an unprotected type, so it proves nothing above")
	}
}

// unhardened has the shape SecretValue had before masking and Format: an
// unexported string field, redacted on the three paths somebody thought of, and
// an exported Reveal method.
//
// It stays pointed at the OLD shape on purpose. Its job is to prove the probe can
// SEE a leak, not to model the type as it is now; repointing it at the current
// construction would quietly remove the only thing establishing that the probe
// works at all.
//
// Reveal is part of that old shape and is here for the same reason as the string
// field: without it the template walk folded into leakPaths has nothing to find,
// and a capability no fixture exercises is indistinguishable from one that does
// not work.
type unhardened struct{ value string }

func (u unhardened) String() string               { return "[REDACTED]" }
func (u unhardened) GoString() string             { return "[REDACTED]" }
func (u unhardened) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (u unhardened) Reveal() string               { return u.value }

// leakPaths returns a label for every output path that exposed material.
//
// It walks the paths material actually escapes through, not a sample of them:
// every single-letter fmt verb both bare and embedded in a struct (a secret
// escapes because someone logs the spec, not the field), reflection over the
// unexported fields, the two slog handlers, JSON, text, and gob.
func leakPaths(t *testing.T, v any, material string) []string {
	t.Helper()

	var found []string
	check := func(label, got string) {
		// compute.LeaksMaterialForTest, not strings.Contains: fmt prints a byte
		// slice as decimal byte values, so a path rendering []byte(material)
		// emits "[99 111 114 ...]" and a substring check scores it clean. That
		// was a live blind spot in this probe -- and it sat on MarshalJSON,
		// which returns ([]byte, error) and is exactly the shape a template
		// renders. One predicate in the package, so the copy that falls behind
		// cannot score a real leak as clean.
		if compute.LeaksMaterialForTest(got, material) {
			found = append(found, label+": "+got)
		}
	}

	// Every ASCII-letter verb, with and without the flags that change how fmt
	// dispatches. %p is the reason masking exists: fmt handles it before it
	// consults fmt.Formatter, so no method can redact it.
	holder := struct {
		Name     string
		Password any
	}{Name: "db", Password: v}
	for c := byte('A'); c <= byte('z'); c++ {
		if c > 'Z' && c < 'a' {
			continue
		}
		for _, flags := range []string{"", "+", "#", "-8", " "} {
			verb := "%" + flags + string(c)
			check("bare "+verb, fmt.Sprintf(verb, v))
			check("struct "+verb, fmt.Sprintf(verb, holder))
		}
	}

	// Reflection over the unexported fields. reflect.Value.String does not
	// panic on one, so a plain string field hands the material back in a single
	// call; Bytes behaves the same way on a []byte field.
	rv := reflect.ValueOf(v)
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		check(fmt.Sprintf("reflect Field(%d).String", i), f.String())
		check(fmt.Sprintf("reflect print Field(%d)", i), fmt.Sprint(f))
	}

	// Both stdlib handlers, as an attribute and inside a struct.
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(h(&buf)).Info("msg", "secret", v, "spec", holder)
		check(name, buf.String())
	}

	// text/template, which needs no reflection at all: it resolves exported
	// methods BY NAME, so {{.Password.Reveal}} used to print the material from a
	// template that merely walked the spec. Folded in here from the standalone
	// tripwire test that recorded that leak, which is where its own comment
	// asked it to go once the leak was closed.
	//
	// Derived over the method set rather than listed, and over both T and *T,
	// because a caller very often holds a pointer and a pointer-receiver method
	// was invisible to an earlier version of a gate in this package. Restricted
	// to the methods a probe can INVOKE -- no arguments, one result or two with
	// an error second. That is narrower than what a template can call: a
	// command's final method may take arguments, and no probe can synthesise a
	// meaningful argument for an arbitrary signature. The class is carried
	// structurally instead, by the allowlist in secret_internal_test.go, and
	// this walk is what catches a permitted method whose BODY starts leaking.
	rt := reflect.TypeOf(v)
	for _, typ := range []reflect.Type{rt, reflect.PointerTo(rt)} {
		var bare, nested any = v, holder
		if typ.Kind() == reflect.Pointer {
			pv := reflect.New(rt)
			pv.Elem().Set(reflect.ValueOf(v))
			bare = pv.Interface()
			nested = struct {
				Name     string
				Password any
			}{Name: "db", Password: pv.Interface()}
		}
		for i := range typ.NumMethod() {
			m := typ.Method(i)
			sig := m.Type
			if sig.NumIn() != 1 || sig.IsVariadic() {
				continue
			}
			if sig.NumOut() == 2 && sig.Out(1) != reflect.TypeFor[error]() {
				continue
			} else if sig.NumOut() != 1 && sig.NumOut() != 2 {
				continue
			}
			for _, tc := range []struct {
				expr string
				data any
			}{
				{"{{." + m.Name + "}}", bare},
				{"{{.Password." + m.Name + "}}", nested},
			} {
				tpl, err := template.New("t").Parse(tc.expr)
				if err != nil {
					continue
				}
				var out strings.Builder
				if tpl.Execute(&out, tc.data) != nil {
					continue
				}
				check("template "+tc.expr+" over "+typ.String(), out.String())
			}
		}
	}
	// The bare renderings too, which need no method at all.
	for _, expr := range []string{"{{.}}", "{{.Password}}", `{{printf "%v" .Password}}`} {
		var out strings.Builder
		if template.Must(template.New("t").Parse(expr)).Execute(&out, holder) == nil {
			check("template "+expr, out.String())
		}
	}

	// Serialization. An error is not a leak: it is the refusal working.
	b, err := json.Marshal(holder)
	check("json.Marshal", fmt.Sprintf("%s (err=%v)", b, err))
	if m, ok := v.(encoding.TextMarshaler); ok {
		tb, terr := m.MarshalText()
		check("MarshalText", fmt.Sprintf("%s (err=%v)", tb, terr))
	}
	var gb bytes.Buffer
	gerr := gob.NewEncoder(&gb).Encode(holder)
	check("gob", fmt.Sprintf("%q (err=%v)", gb.String(), gerr))

	return found
}

// TestTheSerializationRefusalIsIdentifiable asserts that the gob paths fail with
// [compute.ErrSecretSerialize] rather than with some error.
//
// This is the only thing that matches that sentinel, and it is the reason the
// sentinel is exported at all. Without it, ErrSecretSerialize is an exported
// symbol nobody can be shown to need — and nonTaxonomy() in contract_test.go
// excuses it from the taxonomy on the stated grounds that "a caller matches it to
// assert that the refusal happened". An exception whose reason describes a use
// that does not exist is special pleading, so the use exists here.
//
// credentials.ErrSecretMarshal is matched the same way and for the same reason
// (credentials/secret_test.go): a type that fails closed is only demonstrably
// failing closed if the failure is identifiable.
func TestTheSerializationRefusalIsIdentifiable(t *testing.T) {
	t.Parallel()

	s := compute.NewSecretValue("correct-horse-battery-staple")

	if _, err := s.GobEncode(); !errors.Is(err, compute.ErrSecretSerialize) {
		t.Errorf("GobEncode error = %v, want ErrSecretSerialize", err)
	}
	if err := (&s).GobDecode(nil); !errors.Is(err, compute.ErrSecretSerialize) {
		t.Errorf("GobDecode error = %v, want ErrSecretSerialize", err)
	}

	// Through an encoder, which is how it is actually reached: gob consults
	// neither MarshalJSON nor MarshalText, so this path is the one that would
	// otherwise write material out in the clear.
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(struct{ Password compute.SecretValue }{Password: s})
	if !errors.Is(err, compute.ErrSecretSerialize) {
		t.Errorf("gob.Encode of a struct holding a SecretValue error = %v, want ErrSecretSerialize", err)
	}
}

// TestATemplateCannotReachTheMaterial is the inversion of a tripwire, kept
// rather than deleted.
//
// It was written to FAIL when USOSS-43 landed: it asserted that
// {{.Password.Reveal}} printed the material, so that a known-open leak showed up
// in a test run instead of only in a review comment. Its own comment asked for
// this disposition — invert it, and fold the general template probe into
// leakPaths, which is done above.
//
// What it pins now is the specific historical expression, by name. leakPaths
// carries the class; this carries the instance, and the instance is worth its own
// line because it is the one that needed no reflection at all: any template that
// merely walked a spec rendered the plaintext. `Reveal` is a package function
// now, so this expression cannot resolve — an execution error is the pass
// condition, and silence would not be: a template that renders nothing looks
// identical to one that was never executed.
func TestATemplateCannotReachTheMaterial(t *testing.T) {
	t.Parallel()

	const material = "correct-horse-battery-staple"
	holder := struct{ Password compute.SecretValue }{Password: compute.NewSecretValue(material)}

	var out strings.Builder
	err := template.Must(template.New("t").Parse("{{.Password.Reveal}}")).Execute(&out, holder)
	if err == nil {
		t.Errorf("the template executed, so SecretValue has something named Reveal again: %q. "+
			"RevealSecret is a package function precisely so that no template can name it", out.String())
	}
	if compute.LeaksMaterialForTest(out.String(), material) {
		t.Errorf("the template rendered the material: %q", out.String())
	}
	if !strings.Contains(fmt.Sprint(err), "Reveal") {
		t.Errorf("the template failed for some reason other than Reveal being absent (%v), so this "+
			"test is no longer pinning what it claims to", err)
	}
}
