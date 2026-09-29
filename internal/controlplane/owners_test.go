// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"encoding/json"
	"slices"
	"testing"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

const platformGroup = "grp-platform"

// withOwnersDirectory files the users and group an owner can be chosen from,
// and puts "other" in the platform group.
func withOwnersDirectory(t *testing.T, f *serviceFixture) {
	t.Helper()
	for _, u := range []cp.User{{ID: f.owner.UserID, Name: "Olive Owner", Email: "olive@example.com"}, {ID: f.other.UserID, Name: "Oscar Other", Email: "oscar@example.com"}, {ID: "disabled", Name: "Gone", Disabled: true}} {
		storeValue(t, f.repo, cp.RecordID{Kind: cp.UserKind, ID: u.ID}, u)
	}
	storeValue(t, f.repo, cp.RecordID{Kind: cp.DirectoryEntitlementKind, ID: platformGroup}, cp.DirectoryEntitlementRecord{ID: platformGroup, DisplayName: "Platform team"})
	f.eligibility.mu.Lock()
	other := f.eligibility.principals[f.other.UserID]
	other.Groups = []string{platformGroup}
	f.eligibility.principals[f.other.UserID] = other
	f.eligibility.mu.Unlock()
}

func ownerKeys(list cp.OwnerList) []string {
	keys := []string{}
	for _, o := range list.Items {
		keys = append(keys, o.Key)
	}
	return keys
}

func TestTheCreatorIsTheFirstOwner(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	if len(app.Owners) != 1 || app.Owners[0].Key != "user:"+f.owner.UserID || app.Owners[0].Name != "Olive Owner" {
		t.Fatalf("owners = %+v", app.Owners)
	}
	if !slices.Contains(app.PermittedActions, "owners:write") {
		t.Error("the creator cannot change owners")
	}
	page, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != app.ID {
		t.Fatalf("the creator's listing = %+v, %v", page, err)
	}
}

func TestAnAddedUserOwnerHasFullControl(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	_, err := f.service.GetApplication(t.Context(), f.other, app.ID)
	requireProblem(t, err, 404, "not_found")

	list, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"user:" + f.owner.UserID, "user:" + f.other.UserID}; !slices.Equal(ownerKeys(list), want) {
		t.Fatalf("owners = %v, want %v sorted by name", ownerKeys(list), want)
	}
	again, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID})
	if err != nil || len(again.Items) != 2 {
		t.Fatalf("adding an existing owner = %+v, %v; want no change", again, err)
	}
	view, err := f.service.GetApplication(t.Context(), f.other, app.ID)
	if err != nil {
		t.Fatalf("an added owner cannot open the application: %v", err)
	}
	if view.Revision != app.Revision {
		t.Error("adding an owner changed the revision, which would conflict with a queued deployment")
	}
	if _, err := f.service.SubmitDeployment(t.Context(), f.other, app.ID, cp.SubmitDeploymentInput{ApplicationRevision: view.Revision}, "deploy"); err != nil {
		t.Fatalf("an added owner cannot deploy: %v", err)
	}
	page, err := f.service.ListApplications(t.Context(), f.other, cp.ListOptions{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("the added owner's listing = %+v, %v", page, err)
	}
}

func TestAGroupOwnerMakesItsHoldersOwners(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	if _, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerGroup, ID: platformGroup}); err != nil {
		t.Fatal(err)
	}
	view, err := f.service.GetApplication(t.Context(), f.other, app.ID)
	if err != nil {
		t.Fatalf("a group holder cannot open a group-owned application: %v", err)
	}
	group := view.Owners[len(view.Owners)-1]
	if group.Kind != cp.OwnerGroup || group.Name != "Platform team" {
		t.Errorf("group owner = %+v", group)
	}
	page, err := f.service.ListApplications(t.Context(), f.other, cp.ListOptions{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("a group holder's listing = %+v, %v", page, err)
	}
	summary, err := f.service.GetDirectoryEntry(t.Context(), f.other, app.ID)
	if err != nil || !summary.Owned || !summary.Yours {
		t.Fatalf("summary for a group holder = %+v, %v", summary, err)
	}

	// Leaving the group ends ownership on the next request.
	f.eligibility.mu.Lock()
	other := f.eligibility.principals[f.other.UserID]
	other.Groups = nil
	f.eligibility.principals[f.other.UserID] = other
	f.eligibility.mu.Unlock()
	_, err = f.service.GetApplication(t.Context(), f.other, app.ID)
	requireProblem(t, err, 404, "not_found")
}

func TestOwnersCannotBeUnknownOrTooMany(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	for _, input := range []cp.OwnerInput{{Kind: cp.OwnerUser, ID: "nobody"}, {Kind: cp.OwnerUser, ID: "disabled"}, {Kind: cp.OwnerGroup, ID: "grp-missing"}, {Kind: "robot", ID: f.other.UserID}, {Kind: cp.OwnerUser, ID: ""}} {
		_, err := f.service.AddOwner(t.Context(), f.owner, app.ID, input)
		requireProblem(t, err, 422, "unknown_owner")
	}
	for i := range cp.MaxApplicationOwners - 1 {
		id := "extra-" + string(rune('a'+i))
		storeValue(t, f.repo, cp.RecordID{Kind: cp.UserKind, ID: id}, cp.User{ID: id, Email: id + "@example.com"})
		if _, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID})
	requireProblem(t, err, 422, "too_many_owners")
}

func TestOwnersCanBeRemovedButNeverTheLast(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	ownerKey := "user:" + f.owner.UserID
	_, err := f.service.RemoveOwner(t.Context(), f.owner, app.ID, ownerKey)
	requireProblem(t, err, 409, "last_owner")

	if _, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID}); err != nil {
		t.Fatal(err)
	}
	list, err := f.service.RemoveOwner(t.Context(), f.owner, app.ID, ownerKey)
	if err != nil || !slices.Equal(ownerKeys(list), []string{"user:" + f.other.UserID}) {
		t.Fatalf("after removing themselves = %v, %v", ownerKeys(list), err)
	}
	if n := countKind(f.repo, cp.ApplicationOwnerKind); n != 1 {
		t.Fatalf("%d owner index entries after a removal, want 1", n)
	}
	_, err = f.service.GetApplication(t.Context(), f.owner, app.ID)
	requireProblem(t, err, 404, "not_found")
	page, err := f.service.ListApplications(t.Context(), f.owner, cp.ListOptions{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("a removed owner still lists the application: %+v, %v", page, err)
	}
	if _, err := f.service.RemoveOwner(t.Context(), f.other, app.ID, "user:not-an-owner"); err != nil {
		t.Fatalf("removing a non-owner should change nothing: %v", err)
	}
	_, err = f.service.RemoveOwner(t.Context(), f.other, app.ID, "robot:x")
	requireProblem(t, err, 400, "invalid_owner")
}

func TestOwnersWaitForAnActiveDeployment(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	f.submit(t, app, "deploy")
	_, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID})
	requireProblem(t, err, 409, "deployment_active")
	view, err := f.service.GetApplication(t.Context(), f.owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(view.PermittedActions, "owners:write") {
		t.Error("owners:write is offered while an operation holds the application")
	}
}

func TestAnAdministratorCanChangeOwnersWithoutOwning(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	if _, err := f.service.AddOwner(t.Context(), f.admin, app.ID, cp.OwnerInput{Kind: cp.OwnerUser, ID: f.other.UserID}); err != nil {
		t.Fatalf("an administrator could not add an owner: %v", err)
	}
	summary, err := f.service.GetDirectoryEntry(t.Context(), f.admin, app.ID)
	if err != nil || !summary.Owned || summary.Yours {
		t.Fatalf("admin summary = owned %v, yours %v, %v; want owned but not yours", summary.Owned, summary.Yours, err)
	}
	_, err = f.service.AddOwner(t.Context(), f.other, app.ID, cp.OwnerInput{Kind: cp.OwnerGroup, ID: platformGroup})
	if err != nil {
		t.Fatalf("an added owner could not add another: %v", err)
	}
}

func TestSearchFindsUsersAndGroups(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	result, err := f.service.SearchPrincipals(t.Context(), f.other, "OSCAR")
	if err != nil || len(result.Users) != 1 || result.Users[0].ID != f.other.UserID || len(result.Groups) != 0 {
		t.Fatalf("search by name = %+v, %v", result, err)
	}
	if result.Users[0].Email != "" {
		t.Error("a member's search returned another member's email")
	}
	if byEmail, err := f.service.SearchPrincipals(t.Context(), f.other, "olive@"); err != nil || len(byEmail.Users) != 1 {
		t.Fatalf("search by email = %+v, %v; emails are matched even when not returned", byEmail, err)
	}
	result, err = f.service.SearchPrincipals(t.Context(), f.other, "platform")
	if err != nil || len(result.Groups) != 1 || result.Groups[0].Key != "group:"+platformGroup {
		t.Fatalf("search by group = %+v, %v", result, err)
	}
	result, err = f.service.SearchPrincipals(t.Context(), f.other, "")
	if err != nil || len(result.Users) != 2 {
		t.Fatalf("empty search = %+v, %v; want every enabled user", result, err)
	}
}

func TestALegacySingleOwnerRecordReadsAsAnOwnerSet(t *testing.T) {
	var app cp.ApplicationRecord
	if err := json.Unmarshal([]byte(`{"id":"a1","ownerUserId":"u1","revision":3}`), &app); err != nil {
		t.Fatal(err)
	}
	if len(app.Owners) != 1 || app.Owners[0] != (cp.ApplicationOwner{Kind: cp.OwnerUser, ID: "u1"}) || app.Revision != 3 {
		t.Fatalf("legacy record = %+v", app)
	}
	encoded, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatal(err)
	}
	if _, legacy := round["ownerUserId"]; legacy {
		t.Error("ownerUserId is still written")
	}
}

func TestDeletingADraftRemovesItsOwnerIndex(t *testing.T) {
	f := newServiceFixture(t)
	withOwnersDirectory(t, f)
	app := f.create(t, "create")
	if _, err := f.service.AddOwner(t.Context(), f.owner, app.ID, cp.OwnerInput{Kind: cp.OwnerGroup, ID: platformGroup}); err != nil {
		t.Fatal(err)
	}
	if n := countKind(f.repo, cp.ApplicationOwnerKind); n != 2 {
		t.Fatalf("%d owner index entries, want 2", n)
	}
	f.remove(t, app, "delete")
	if n := countKind(f.repo, cp.ApplicationOwnerKind); n != 0 {
		t.Fatalf("%d owner index entries survived deleting the application", n)
	}
}
