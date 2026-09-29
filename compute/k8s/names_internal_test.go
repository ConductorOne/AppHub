// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"errors"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// testSpec is a minimal stand-in for the real specs decodeSpec is
// instantiated with; only its shape (something JSON-unmarshalable) matters.
type testSpec struct {
	Name string
}

// TestDecodeSpecDistinguishesAbsentFromMalformed is the direct, in-package
// unit test for the defect USOSS-69 reports: decodeSpec used to discard its
// json.Unmarshal error with `_ = json.Unmarshal(...)`, so an annotation that
// was never set, one that was set to invalid JSON, and one that was set to
// valid JSON of the wrong shape all produced the identical zero value with no
// way for a caller to tell them apart.
//
// This test would have failed against the pre-fix decodeSpec: every case
// below produced (testSpec{}, no way to know why) before the signature
// changed to return an error.
func TestDecodeSpecDistinguishesAbsentFromMalformed(t *testing.T) {
	t.Parallel()

	t.Run("absent annotation: zero value, nil error", func(t *testing.T) {
		t.Parallel()
		got, err := decodeSpec[testSpec](map[string]string{})
		if err != nil {
			t.Fatalf("decodeSpec with no annotationSpec key returned %v, want nil: absence is not "+
				"a defect", err)
		}
		if got != (testSpec{}) {
			t.Errorf("decodeSpec with no annotationSpec key returned %+v, want the zero value", got)
		}
	})

	t.Run("empty-string annotation: zero value, nil error", func(t *testing.T) {
		t.Parallel()
		// annotationsFor and friends never write an empty string, but a
		// caller that cleared the annotation rather than deleting the key
		// leaves exactly this, and it must be treated the same as absent.
		got, err := decodeSpec[testSpec](map[string]string{annotationSpec: ""})
		if err != nil {
			t.Fatalf("decodeSpec with an empty annotation returned %v, want nil", err)
		}
		if got != (testSpec{}) {
			t.Errorf("decodeSpec with an empty annotation returned %+v, want the zero value", got)
		}
	})

	malformedCases := map[string]string{
		"invalid JSON":               `{"Name":`,
		"not JSON at all":            `not json`,
		"valid JSON, wrong shape":    `"just a string"`,
		"valid JSON, unknown fields": `{"Unrelated":1}`, // note: this one is NOT malformed for testSpec below
	}
	// "valid JSON, unknown fields" unmarshals cleanly into testSpec (Go's
	// decoder ignores unrecognised fields), so it is not a malformed case for
	// THIS type -- kept out of the error-asserting loop and verified
	// separately to document why it is not in the malformed set.
	delete(malformedCases, "valid JSON, unknown fields")

	for name, raw := range malformedCases {
		raw := raw
		t.Run("malformed annotation ("+name+"): zero value, an error wrapping ErrFailed", func(t *testing.T) {
			t.Parallel()
			got, err := decodeSpec[testSpec](map[string]string{annotationSpec: raw})
			if err == nil {
				t.Fatalf("decodeSpec(%q) returned a nil error, want one wrapping compute.ErrFailed: "+
					"this is exactly the bug USOSS-69 reports -- a present-but-unparseable "+
					"annotation must not be silently indistinguishable from an absent one", raw)
			}
			if !errors.Is(err, compute.ErrFailed) {
				t.Errorf("decodeSpec(%q) returned %v, want an error wrapping compute.ErrFailed", raw, err)
			}
			if got != (testSpec{}) {
				t.Errorf("decodeSpec(%q) returned %+v alongside its error, want the zero value", raw, got)
			}
		})
	}

	t.Run("well-formed annotation: the decoded value, nil error", func(t *testing.T) {
		t.Parallel()
		got, err := decodeSpec[testSpec](map[string]string{annotationSpec: `{"Name":"api"}`})
		if err != nil {
			t.Fatalf("decodeSpec with a well-formed annotation returned %v, want nil", err)
		}
		if got != (testSpec{Name: "api"}) {
			t.Errorf("decodeSpec with a well-formed annotation returned %+v, want {Name:api}", got)
		}
	})

	t.Run("unrecognised fields unmarshal cleanly, which is why they are not treated as malformed", func(t *testing.T) {
		t.Parallel()
		got, err := decodeSpec[testSpec](map[string]string{annotationSpec: `{"Unrelated":1}`})
		if err != nil {
			t.Fatalf("decodeSpec(%q) returned %v, want nil: Go's json.Unmarshal ignores unknown "+
				"fields by default, so this is valid JSON of a compatible shape, not a defect",
				`{"Unrelated":1}`, err)
		}
		if got != (testSpec{}) {
			t.Errorf("decodeSpec(%q) returned %+v, want the zero value", `{"Unrelated":1}`, got)
		}
	})
}
