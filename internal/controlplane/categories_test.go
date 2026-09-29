// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"errors"
	"slices"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestListCategoriesReturnsKnownCategories(t *testing.T) {
	f := newServiceFixture(t)
	got, err := f.service.ListCategories(t.Context(), f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, cp.KnownCategories) {
		t.Fatalf("got %+v; want %+v", got, cp.KnownCategories)
	}
	got[0].Label = "mutated"
	if cp.KnownCategories[0].Label == "mutated" {
		t.Fatal("ListCategories exposed the shared catalog for mutation")
	}
}

func TestUnknownCategoryIsRejectedBeforePersistence(t *testing.T) {
	f := newServiceFixture(t)
	input := f.input
	input.Category = "not-a-category"
	_, err := f.service.CreateApplication(t.Context(), f.owner, input, "bad-category")
	requireFieldError(t, err, "category")
	if countKind(f.repo, cp.ApplicationKind) != 0 {
		t.Fatal("rejected category persisted an application")
	}

	app := f.create(t, "no-category")
	if app.Specification.Category != "" {
		t.Fatalf("category defaulted to %q; want uncategorized", app.Specification.Category)
	}
	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, input, app.Revision)
	requireFieldError(t, err, "category")
}

func TestCategoryIsStoredAndRetiredCategoryDoesNotBlockEditsOrDeploys(t *testing.T) {
	f := newServiceFixture(t)
	f.input.Category = cp.KnownCategories[0].Key
	app := f.create(t, "categorized")
	if app.Specification.Category != cp.KnownCategories[0].Key {
		t.Fatalf("category = %q; want %q", app.Specification.Category, cp.KnownCategories[0].Key)
	}

	original := cp.KnownCategories
	cp.KnownCategories = original[1:]
	t.Cleanup(func() { cp.KnownCategories = original })

	edited := app.Specification
	edited.Name = "Renamed"
	updated, err := f.service.UpdateApplication(t.Context(), f.owner, app.ID, edited, app.Revision)
	if err != nil {
		t.Fatalf("unchanged retired category blocked an edit: %v", err)
	}
	changed := edited
	changed.Category = original[0].Key + "-other"
	_, err = f.service.UpdateApplication(t.Context(), f.owner, app.ID, changed, updated.Revision)
	requireFieldError(t, err, "category")
	f.submit(t, updated, "retired-category-deploy")
}

func requireFieldError(t *testing.T, err error, field string) {
	t.Helper()
	requireProblem(t, err, 422, "invalid_specification")
	var problem *cp.Error
	errors.As(err, &problem)
	if _, ok := problem.FieldErrors[field]; !ok {
		t.Fatalf("field errors %v do not name %q", problem.FieldErrors, field)
	}
}
