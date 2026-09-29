// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"testing"

	"github.com/conductorone/apphub/credentials/lifecycle"
	"github.com/conductorone/apphub/credentials/lifecycle/fake"
	"github.com/conductorone/apphub/credentials/lifecycle/lifecycletest"
)

// TestConformance is what makes the fake worth having. Without it the fake is one
// person's recollection of how the database behaves; with it, the same suite that
// passes here passes against store.
func TestConformance(t *testing.T) {
	lifecycletest.RunConformance(t, func(t *testing.T, reg *lifecycle.AnnotationRegistry) lifecycle.Records {
		t.Helper()
		recs, err := fake.New(reg)
		if err != nil {
			t.Fatalf("fake.New: %v", err)
		}
		return recs
	})
}

func TestNewRequiresRegistry(t *testing.T) {
	// A fake that accepted any annotation would pass tests production fails.
	if _, err := fake.New(nil); err == nil {
		t.Fatal("fake.New(nil) succeeded; the annotation registry is required")
	}
}
