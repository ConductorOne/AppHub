// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
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

// material is a value that must never appear in this test's output. Every
// assertion below is really the same assertion: it is not in there.
const material = "sk-live-do-not-print-me"

func TestSecretRedactsUnderEveryVerb(t *testing.T) {
	s := credentials.NewSecret(material)

	// %q is the verb a String method would not have covered: fmt formats %q
	// against the underlying string kind and never consults fmt.Stringer.
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%d", "%10s"} {
		got := fmt.Sprintf(format, s)
		if strings.Contains(got, material) {
			t.Errorf("Sprintf(%q) leaked material: %s", format, got)
		}
	}

	// Through fmt, not through a String method: Secret has no String method any
	// more, because an exported no-argument string method is exactly what a
	// template can call by name. The Sprintf loop above already covers every
	// verb via Format, which is what String was redundantly duplicating.

	// The common accidental case: a secret nested in a struct that someone dumps.
	type wrapper struct {
		Key      credentials.Secret
		Metadata credentials.Metadata
	}
	w := wrapper{Key: s, Metadata: credentials.Metadata{"admin_api_key": material, "region": "us-east-1"}}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, w)
		if strings.Contains(got, material) {
			t.Errorf("Sprintf(%q) on wrapper leaked material: %s", format, got)
		}
	}
}

func TestSecretRefusesToMarshal(t *testing.T) {
	s := credentials.NewSecret(material)

	if _, err := json.Marshal(s); !errors.Is(err, credentials.ErrSecretMarshal) {
		t.Errorf("json.Marshal(Secret) error = %v, want ErrSecretMarshal", err)
	}
	if _, err := s.MarshalText(); !errors.Is(err, credentials.ErrSecretMarshal) {
		t.Errorf("MarshalText error = %v, want ErrSecretMarshal", err)
	}

	// A struct that grows a Secret field fails to serialize rather than leaking.
	payload := struct {
		Name string             `json:"name"`
		Key  credentials.Secret `json:"key"`
	}{Name: "prod", Key: s}
	if b, err := json.Marshal(payload); err == nil {
		t.Errorf("json.Marshal of struct containing Secret succeeded: %s", b)
	}

	if _, err := json.Marshal(credentials.Metadata{"admin_api_key": material}); !errors.Is(err, credentials.ErrSecretMarshal) {
		t.Errorf("json.Marshal(Metadata) error = %v, want ErrSecretMarshal", err)
	}
}

func TestSecretRedactsUnderSlog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	log.Info("vended",
		slog.Any("key", credentials.NewSecret(material)),
		slog.Any("metadata", credentials.Metadata{"admin_api_key": material, "region": "us-east-1"}),
	)
	if got := buf.String(); strings.Contains(got, material) {
		t.Errorf("slog output leaked material: %s", got)
	}
	if got := buf.String(); !strings.Contains(got, "region") {
		t.Errorf("slog output dropped the metadata keys, which are the useful half: %s", got)
	}
}

func TestSecretRoundTripsThroughReveal(t *testing.T) {
	var s credentials.Secret
	if err := json.Unmarshal([]byte(`"`+material+`"`), &s); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if credentials.Reveal(s) != material {
		t.Errorf("Reveal() = %q, want the material back", credentials.Reveal(s))
	}
	if s.IsZero() {
		t.Error("IsZero() = true for a populated secret")
	}
}

func TestMetadataKeysAreSortedAndValuesAreNot(t *testing.T) {
	m := credentials.Metadata{"region": "us-east-1", "admin_api_key": material, "installation_id": "1"}
	got := m.Keys()
	want := []string{"admin_api_key", "installation_id", "region"}
	if len(got) != len(want) {
		t.Fatalf("Keys() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Keys() = %v, want %v", got, want)
		}
	}
	// Metadata is a plain map underneath, so ported provider code is unaffected.
	if m["region"] != "us-east-1" {
		t.Error("Metadata lookup did not behave like a map")
	}
}

func TestSecretRefIsALocatorNotMaterial(t *testing.T) {
	ref := credentials.SecretRef{Store: "aws-ssm", Name: "/apphub/apps/1/DATADOG_API_KEY", EnvVar: "DATADOG_API_KEY"}
	if ref.IsZero() {
		t.Error("IsZero() = true for a populated ref")
	}
	if !strings.Contains(ref.String(), "aws-ssm") {
		t.Errorf("String() = %q, want the store named", ref.String())
	}
	if (credentials.SecretRef{}).IsZero() != true {
		t.Error("zero SecretRef should report IsZero")
	}
	envOnly := credentials.SecretRef{EnvVar: "APPHUB_AUTH_GOOGLE_CLIENT_SECRET"}
	if envOnly.IsZero() {
		t.Error("IsZero() = true for an env-only locator")
	}
	if envOnly.String() != "APPHUB_AUTH_GOOGLE_CLIENT_SECRET" {
		t.Errorf("String() = %q, want the environment variable name", envOnly.String())
	}
}

// --- Regression: the three vectors an adversarial fixture found against the
// earlier defined-string Secret. Each of these returned the raw material before
// Secret became an opaque struct with an unexported byte field and a
// package-level Reveal.

func TestSecretDoesNotLeakThroughGob(t *testing.T) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(credentials.NewSecret(material)); err == nil {
		t.Errorf("gob encoded a Secret: %q", buf.String())
	}
	if strings.Contains(buf.String(), material) {
		t.Errorf("gob stream leaked material: %q", buf.String())
	}

	// The realistic case: a Secret nested inside something being gob-encoded.
	buf.Reset()
	payload := struct {
		Name string
		Key  credentials.Secret
	}{Name: "prod", Key: credentials.NewSecret(material)}
	if err := gob.NewEncoder(&buf).Encode(payload); err == nil {
		t.Error("gob encoded a struct containing a Secret")
	}
	if strings.Contains(buf.String(), material) {
		t.Errorf("gob stream leaked nested material: %q", buf.String())
	}

	buf.Reset()
	if err := gob.NewEncoder(&buf).Encode(credentials.Metadata{"admin_api_key": material}); err == nil {
		t.Error("gob encoded a Metadata")
	}
	if strings.Contains(buf.String(), material) {
		t.Errorf("gob stream leaked metadata values: %q", buf.String())
	}
}

func TestSecretDoesNotLeakThroughReflection(t *testing.T) {
	s := credentials.NewSecret(material)

	// A defined string type returns its underlying value here.
	if got := reflect.ValueOf(s).String(); strings.Contains(got, material) {
		t.Errorf("reflect.Value.String leaked material: %q", got)
	}

	// No accessor anywhere in the value yields the material, through the one
	// recursive walk this repository has rather than a local loop over the
	// immediate fields -- which is what a reviewer defeated with a nested holder
	// struct. reflect.Value.Bytes is deliberately not used inside it: Bytes panics
	// on an unaddressable byte ARRAY, and skipping arrays for that reason is an
	// accidental bound dressed as a safety property, so the walk reads them
	// element by element.
	v := reflect.ValueOf(s)
	r, err := reachable.Walk(s)
	if err != nil {
		t.Fatalf("walking a Secret: %v", err)
	}
	if len(r.Blobs) == 0 {
		t.Fatal("the walk found nothing in a Secret, so this assertion is vacuous")
	}
	for _, b := range r.Blobs {
		if strings.Contains(string(b.Bytes), material) {
			t.Errorf("reflection at %s (%s) leaked material: %q", b.Path, b.Kind, b.Bytes)
		}
	}

	// Interface still panics on an unexported field, which is what stops a
	// well-behaved dumper before it starts.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("reflect.Value.Interface on an unexported field did not panic")
			}
		}()
		_ = v.Field(0).Interface()
	}()
}

func TestSecretHasNoExportedEscapeMethodForTemplates(t *testing.T) {
	// text/template can call any exported method by name, so an exported Reveal
	// method was reachable as {{.Reveal}}. Reveal is now a package function.
	if _, ok := reflect.TypeOf(credentials.Secret{}).MethodByName("Reveal"); ok {
		t.Fatal("Secret has an exported Reveal method; a template can call it by name")
	}

	for _, src := range []string{`{{.}}`, `{{printf "%q" .}}`, `{{.Reveal}}`, `{{.String}}`} {
		tmpl, err := template.New("t").Parse(src)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		var out bytes.Buffer
		// An error is a fine outcome (no such method); leaking is not.
		_ = tmpl.Execute(&out, credentials.NewSecret(material))
		if strings.Contains(out.String(), material) {
			t.Errorf("template %q leaked material: %q", src, out.String())
		}
	}
}

// TestSecretIsHonestAboutItsLimits documents the boundary rather than asserting a
// property the type does not have. Recovering the material takes deliberately
// combining two unexported fields -- which is exactly the point: nothing does that
// by accident, and the doc comment says so rather than implying a vault.
// TestNoRecombinationOfReachableStateReversesASecret replaces a test that
// asserted the OPPOSITE, and the inversion is the whole of USOSS-46.
//
// The old test was called TestSecretIsHonestAboutItsLimits and it asserted that a
// deliberate two-field XOR DOES reach the material. That was honest about the
// design it documented: the mask sat beside the masked bytes, so anything that
// found both won. The justification was "a generic dumper does not XOR field
// pairs" -- a claim about what readers do, not a property of the type, and eleven
// lines of ordinary reflection falsified it.
//
// # Why the walk is not in this file any more
//
// The first inversion walked the IMMEDIATE fields of a Secret. A reviewer moved
// the real key into an unexported one-field holder struct inside the type, used it
// for NewSecret and Reveal, and the whole suite stayed green -- because the helper
// this test used returned nil for a struct field. One struct wrapper defeated the
// entire fixture, and the name said EveryReachableField.
//
// That was the third shallow-reachability defect in this package. So there is one
// walk, in internal/reachable, recursing through structs, pointers, interfaces,
// slices, arrays and maps with no depth cap, and it is a fatal error rather than a
// skip when it meets a kind it has no case for. Both shapes that have defeated a
// walk here -- the nested holder and a func field nine levels down with a
// same-name decoy -- are permanent fixtures of that package.
//
// # Why the attack does not use this package's own derivation
//
// It used to, on the reasoning that attacking the REAL construction is stronger
// than attacking an approximation of it. That reasoning is half right and the
// other half is the failure mode: a test that calls the shipped keystream shares
// the shipped keystream's bugs, so a derivation that quietly stopped using its key
// would faithfully fail to reverse anything and report a pass. The reviewer's
// recovery worked precisely because they wrote the four lines out themselves.
//
// Both halves are kept. internal/reachable has its own implementation, and the
// agreement between the two is ASSERTED below rather than hoped for -- so a
// divergence is a loud failure instead of an attack against a construction nobody
// ships.
func TestNoRecombinationOfReachableStateReversesASecret(t *testing.T) {
	s := credentials.NewSecret(material)

	// The two implementations must agree, or the attack below is aimed at the
	// wrong construction and its silence means nothing.
	var probeKey [32]byte
	copy(probeKey[:], "an-arbitrary-key-for-comparison-")
	agree := reachable.AgreesWith(func(k [32]byte, nonce []byte, n int) []byte {
		var fixed [16]byte
		copy(fixed[:], nonce)
		return credentials.KeystreamForTest(k, fixed, n)
	}, probeKey, []byte("sixteen-byte-non"), 128)
	if !agree {
		t.Fatal("internal/reachable's keystream no longer agrees with this package's. Fix the " +
			"reimplementation: an attack against a derivation nobody ships proves nothing, and " +
			"its silence would read as a pass")
	}

	r, err := reachable.Walk(s)
	if err != nil {
		t.Fatalf("walking a Secret: %v", err)
	}
	if len(r.Blobs) < 2 {
		t.Fatalf("only %d reachable blob(s) in a Secret; the walk is not descending, and every "+
			"assertion below would pass vacuously", len(r.Blobs))
	}
	if len(r.Unreadable) != 0 {
		t.Errorf("a Secret has %d location(s) reflection cannot read: %v. A func or channel field "+
			"on this type is a place material can sit where no walk follows it", len(r.Unreadable), r.Unreadable)
	}
	for _, a := range reachable.Recover(r, material) {
		t.Errorf("reachable state reverses a Secret: %s (key=%s nonce=%s target=%s)",
			a.How, a.KeyPath, a.NoncePath, a.TargetPath)
	}

	if credentials.Reveal(s) != material {
		t.Fatal("Reveal did not round-trip; the assertions above prove nothing about a " +
			"construction that does not work")
	}
}

func TestSecretMasksAtRest(t *testing.T) {
	s := credentials.NewSecret(material)
	if credentials.Reveal(s) != material {
		t.Error("Reveal did not round-trip the material")
	}
	// Two secrets over the same material must not share ANY reachable blob, or
	// the mask is not per-secret and the storage is a substitution cipher. Over
	// the whole walk rather than field 0, because "field 0" is a guess about the
	// layout and the layout is what a refactor changes.
	first, err := reachable.Walk(s)
	if err != nil {
		t.Fatalf("walking a Secret: %v", err)
	}
	second, err := reachable.Walk(credentials.NewSecret(material))
	if err != nil {
		t.Fatalf("walking a second Secret: %v", err)
	}
	if len(first.Blobs) == 0 || len(second.Blobs) == 0 {
		t.Fatal("the walk found nothing, so the comparison below is vacuous")
	}
	for _, a := range first.Blobs {
		if string(a.Bytes) == material {
			t.Errorf("material is stored in the clear at %s", a.Path)
		}
		for _, b := range second.Blobs {
			if len(a.Bytes) == len(material) && string(a.Bytes) == string(b.Bytes) {
				t.Errorf("two Secrets over the same material share the bytes at %s and %s; the "+
					"per-value draw has become a constant", a.Path, b.Path)
			}
		}
	}
	if credentials.NewSecret("").IsZero() != true {
		t.Error("an empty Secret should report IsZero")
	}
}

// TestTheUnmarshalSentinelDoesNotCoverAMalformedDocument asserts a limit rather
// than a guarantee, and asserts it in the direction that will notice if the limit
// ever moves.
//
// ErrSecretUnmarshal exists so that a decode failure does not carry a byte of the
// input into an error string, and it does that for every input that reaches
// [Secret.UnmarshalJSON]. When the surrounding document is malformed,
// encoding/json fails in its top-level scanner and never calls the custom
// unmarshaler, so the error is the decoder's and it names the offending byte.
//
// # Why this uses == and not errors.Is
//
// errors.Is CANNOT EXPRESS "nothing was added". It is satisfied by any wrapper, so
// an assertion built on it is structurally incapable of detecting the thing this
// test exists to detect. Review demonstrated exactly that: the reached path was
// mutated to fmt.Errorf("%w: %c", ErrSecretUnmarshal, lastInputByte) and this test
// PASSED -- the wrapper still satisfied errors.Is, and the byte appended was not
// one of the two spellings the assertion happened to look for.
//
// So the two closed cases assert IDENTITY: err == ErrSecretUnmarshal. That is
// also what the constant's own contract promises, and it makes a byte-by-byte
// search unnecessary rather than merely redundant -- if the error IS the constant,
// nothing of the input can be in it. The sentinel-matching idiom is right
// everywhere else in this repository and wrong precisely here, because the claim
// is about the error's identity and not about its class.
//
// The old assertion also checked two named byte spellings, which is an enumeration
// standing in for a property: the property is "no byte of the input appears", and
// a third byte defeats a list of two. The leaking case below quantifies over the
// input's bytes instead of naming any.
//
// # What it covers, by count
//
// ONE asserted-leaking shape (a malformed outer document), and TWO asserted-closed
// (the unmarshaler called directly, and a well-formed document of the wrong JSON
// type). Stated as a count because a pinned negative whose count is wrong is a
// claim about coverage nobody can check -- and my own earlier description of this
// test said two leaking shapes when the code has one.
func TestTheUnmarshalSentinelDoesNotCoverAMalformedDocument(t *testing.T) {
	const foreign = "REVIEWER-FOREIGN-7d1c"

	// Closed, reached directly. Identity, not class.
	var s credentials.Secret
	if err := s.UnmarshalJSON([]byte(foreign)); err != credentials.ErrSecretUnmarshal { //nolint:errorlint // identity is the assertion
		t.Errorf("UnmarshalJSON called directly returned %#v; it must be ErrSecretUnmarshal "+
			"ITSELF, because any wrapper could carry a byte of the input and errors.Is would "+
			"still be satisfied", err)
	}

	// Closed, reached through a well-formed document of the wrong JSON type.
	var payload struct {
		Token credentials.Secret `json:"token"`
	}
	err := json.Unmarshal([]byte(`{"token": {"a":"`+foreign+`"}}`), &payload)
	if err != credentials.ErrSecretUnmarshal { //nolint:errorlint // identity is the assertion
		t.Errorf("a well-formed document of the wrong type returned %#v, want ErrSecretUnmarshal "+
			"itself", err)
	}

	// NOT closed: the scanner fails first, so the unmarshaler is never called.
	// Asserted as leaking, so the boundary is a fact in a test run rather than a
	// sentence in a comment. If a future Go release delegates here, or a wrapper
	// is introduced at the decode site, this fails and says so -- which is the
	// correct outcome for both.
	err = json.Unmarshal([]byte(`{"token": `+foreign+`}`), &payload)
	if errors.Is(err, credentials.ErrSecretUnmarshal) {
		t.Fatalf("encoding/json now delegates to UnmarshalJSON for a malformed document (%v). "+
			"That is an improvement: delete this assertion and narrow the limit recorded above "+
			"ErrSecretUnmarshal", err)
	}
	if quoted := quotedInputBytes(err, foreign); len(quoted) == 0 {
		t.Errorf("the decoder error no longer names any byte of the input (%v); the limit recorded "+
			"above ErrSecretUnmarshal may have moved and should be re-derived", err)
	}
}

// quotedInputBytes returns every byte of input that err names in the way a
// decoder names one: quoted, as 'x'.
//
// Quantified over the input rather than over a list of spellings somebody chose.
// The bare-substring form is not usable here -- every sentinel message shares
// letters with any plausible input -- so the property is specifically "the error
// QUOTES a byte of the input", which is what a scanner diagnostic does and what a
// constant cannot do.
func quotedInputBytes(err error, input string) []string {
	if err == nil {
		return nil
	}
	msg := err.Error()
	var found []string
	for i := range len(input) {
		if q := "'" + input[i:i+1] + "'"; strings.Contains(msg, q) {
			found = append(found, q)
		}
	}
	return found
}
