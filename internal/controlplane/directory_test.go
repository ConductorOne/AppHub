// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"encoding/json"
	"strings"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func TestEveryMemberCanDiscoverApplicationsWithoutReadingThem(t *testing.T) {
	f := newServiceFixture(t)
	storeValue(t, f.repo, cp.RecordID{Kind: cp.UserKind, ID: f.owner.UserID}, cp.User{ID: f.owner.UserID, Name: "Dana Whitfield", Email: "dana@example.com"})
	f.input.Category = cp.KnownCategories[0].Key
	app := f.create(t, "discoverable")

	page, err := f.service.ListDirectory(t.Context(), f.other, cp.ListOptions{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("directory = %+v, %v; want the other member's application listed", page, err)
	}
	entry := page.Items[0]
	if entry.ID != app.ID || entry.Name != "Example" || len(entry.Owners) != 1 || entry.Owners[0].Name != "Dana Whitfield" || entry.Owned || entry.Yours || entry.Category != cp.KnownCategories[0].Key || entry.Status != "draft" {
		t.Fatalf("entry = %+v", entry)
	}
	encoded, _ := json.Marshal(entry)
	for _, leaked := range []string{"github.com/example/app", "Dockerfile", "replicas", "permittedActions", "dana@example.com"} {
		if strings.Contains(string(encoded), leaked) {
			t.Errorf("the summary exposes %q: %s", leaked, encoded)
		}
	}

	single, err := f.service.GetDirectoryEntry(t.Context(), f.other, app.ID)
	if err != nil || single.ID != app.ID || single.Owned {
		t.Fatalf("entry = %+v, %v", single, err)
	}
	mine, err := f.service.GetDirectoryEntry(t.Context(), f.owner, app.ID)
	if err != nil || !mine.Owned {
		t.Fatalf("owner entry = %+v, %v; want owned", mine, err)
	}
	_, err = f.service.GetApplication(t.Context(), f.other, app.ID)
	requireProblem(t, err, 404, "")
	_, err = f.service.GetDirectoryEntry(t.Context(), f.other, "missing")
	requireProblem(t, err, 404, "")
}
