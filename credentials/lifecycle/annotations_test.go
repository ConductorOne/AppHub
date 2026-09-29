// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle_test

import (
	"errors"
	"testing"

	"github.com/conductorone/apphub/credentials/lifecycle"
)

const adminKey = "dd-admin-key-do-not-persist"

// TestAnnotationsRejectUndeclaredKeys is the regression test for the defect a
// review fixture found: the previous denylist checked key substrings, so the same
// secret sailed through under "key", "access_key", "authorization", "data" and
// "value". An allowlist has no such gap -- a key nobody declared is refused
// whatever it is called.
func TestAnnotationsRejectUndeclaredKeys(t *testing.T) {
	reg := lifecycle.NewAnnotationRegistry()
	if err := reg.Register("datadog", lifecycle.AnnotationRegion, lifecycle.AnnotationAccountAlias); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for _, key := range []lifecycle.AnnotationKey{"key", "access_key", "authorization", "data", "value", "x"} {
		err := reg.Validate("datadog", lifecycle.Annotations{key: adminKey})
		if !errors.Is(err, lifecycle.ErrUndeclaredAnnotation) {
			t.Errorf("Validate(%q) = %v, want ErrUndeclaredAnnotation", key, err)
		}
	}

	if err := reg.Validate("datadog", lifecycle.Annotations{lifecycle.AnnotationRegion: "us-east-1"}); err != nil {
		t.Errorf("Validate(declared key) = %v, want nil", err)
	}
}

// TestAnnotationsFailClosedForUnknownProvider: a provider that declared no schema
// persists nothing at all, rather than persisting anything it likes.
func TestAnnotationsFailClosedForUnknownProvider(t *testing.T) {
	reg := lifecycle.NewAnnotationRegistry()

	err := reg.Validate("never-registered", lifecycle.Annotations{lifecycle.AnnotationRegion: "us-east-1"})
	if !errors.Is(err, lifecycle.ErrUndeclaredAnnotation) {
		t.Errorf("Validate(unknown provider) = %v, want ErrUndeclaredAnnotation", err)
	}
	// An empty map is fine: it persists nothing.
	if err := reg.Validate("never-registered", nil); err != nil {
		t.Errorf("Validate(no annotations) = %v, want nil", err)
	}
}

func TestAnnotationSchemaLintsKeyNames(t *testing.T) {
	reg := lifecycle.NewAnnotationRegistry()

	// The denylist survives here, where it belongs: catching a developer about to
	// declare a material-shaped key, once, in a reviewable diff.
	for _, key := range []lifecycle.AnnotationKey{"admin_api_key", "AwsSessionToken", "app_secret", "deploy_signature", "user_password"} {
		if err := reg.Register("p-"+string(key), key); !errors.Is(err, lifecycle.ErrSecretAnnotation) {
			t.Errorf("Register(%q) = %v, want ErrSecretAnnotation", key, err)
		}
	}

	if err := reg.Register("ok", lifecycle.AnnotationRegion, lifecycle.AnnotationDeviceID); err != nil {
		t.Errorf("Register(non-secret keys) = %v, want nil", err)
	}
	if err := reg.Register("ok", lifecycle.AnnotationRegion); !errors.Is(err, lifecycle.ErrSchemaAlreadyRegistered) {
		t.Errorf("Register(duplicate) = %v, want ErrSchemaAlreadyRegistered", err)
	}
	if err := reg.Register("", lifecycle.AnnotationRegion); err == nil {
		t.Error("Register accepted an empty provider ID")
	}
	if err := reg.Register("long", lifecycle.AnnotationKey(string(make([]byte, 65)))); err == nil {
		t.Error("Register accepted an oversized key name")
	}
}

func TestAnnotationsBoundSize(t *testing.T) {
	reg := lifecycle.NewAnnotationRegistry()
	if err := reg.Register("p", lifecycle.AnnotationRegion); err != nil {
		t.Fatalf("Register: %v", err)
	}

	oversized := lifecycle.Annotations{lifecycle.AnnotationRegion: string(make([]byte, lifecycle.MaxAnnotationValueLen+1))}
	if err := reg.Validate("p", oversized); err == nil {
		t.Error("Validate accepted an oversized value")
	}

	tooMany := make(lifecycle.Annotations, lifecycle.MaxAnnotationKeys+1)
	for i := 0; i <= lifecycle.MaxAnnotationKeys; i++ {
		tooMany[lifecycle.AnnotationKey(string(rune('a'+i%26))+string(rune('a'+i/26)))] = "v"
	}
	if err := reg.Validate("p", tooMany); err == nil {
		t.Error("Validate accepted more annotations than the cap")
	}

	if err := reg.Register("wide", make([]lifecycle.AnnotationKey, lifecycle.MaxAnnotationKeys+1)...); err == nil {
		t.Error("Register accepted a schema wider than the cap")
	}
}

func TestAnnotationRegistryReportsWhatItDeclared(t *testing.T) {
	reg := lifecycle.NewAnnotationRegistry()
	if err := reg.Register("github", lifecycle.AnnotationInstallationID); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := reg.Declared("github")
	if len(got) != 1 || got[0] != lifecycle.AnnotationInstallationID {
		t.Errorf("Declared() = %v, want [installation_id]", got)
	}
	if n := len(reg.Declared("nobody")); n != 0 {
		t.Errorf("Declared(unknown) returned %d keys, want 0", n)
	}
}
