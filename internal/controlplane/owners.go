// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

// OwnerInput names a user or directory group to add as an owner.
type OwnerInput struct {
	Kind OwnerKind `json:"kind"`
	ID   string    `json:"id"`
}

// OwnerView is an owner with what a person needs to recognise it.
type OwnerView struct {
	Kind   OwnerKind `json:"kind"`
	ID     string    `json:"id"`
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Email  string    `json:"email,omitempty"`
	Avatar string    `json:"avatar,omitempty"`
}

// OwnerList is an application's owner set.
type OwnerList struct {
	Items []OwnerView `json:"items"`
}

// PrincipalSearchResult is the people and groups that match a search.
type PrincipalSearchResult struct {
	Users  []OwnerView `json:"users"`
	Groups []OwnerView `json:"groups"`
}

// principalSearchLimit bounds each half of a search result.
const principalSearchLimit = 25

// ownedApplicationLimit bounds how many owned applications one listing
// gathers across a principal's user and group keys before paging.
const ownedApplicationLimit = 1000

// ownerNames caches display names within one request, keyed by owner key.
type ownerNames map[string]OwnerView

// ListOwners returns an owned application's owners.
func (s *Service) ListOwners(ctx context.Context, p Principal, appID string) (OwnerList, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return OwnerList{}, err
	}
	app, _, err := s.application(ctx, p, appID)
	if err != nil {
		return OwnerList{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return OwnerList{}, err
	}
	return OwnerList{Items: s.ownerViews(ctx, app.Owners, ownerNames{})}, nil
}

// AddOwner adds a user or group to an owned application's owners. Adding an
// existing owner changes nothing.
func (s *Service) AddOwner(ctx context.Context, p Principal, appID string, input OwnerInput) (OwnerList, error) {
	app, r, err := s.ownersWritable(ctx, p, appID)
	if err != nil {
		return OwnerList{}, err
	}
	owner := ApplicationOwner{Kind: input.Kind, ID: strings.TrimSpace(input.ID)}
	if err := s.requireOwnerExists(ctx, owner); err != nil {
		return OwnerList{}, err
	}
	if slices.Contains(app.Owners, owner) {
		return OwnerList{Items: s.ownerViews(ctx, app.Owners, ownerNames{})}, nil
	}
	if len(app.Owners) >= MaxApplicationOwners {
		return OwnerList{}, Problem(422, "too_many_owners", "An application can have at most 20 owners. Add a directory group instead of more people.")
	}
	after := append(slices.Clone(app.Owners), owner)
	return s.commitOwners(auditPrincipal(ctx, p, "application.owner.add", "application:"+appID), app, r, after, nil)
}

// RemoveOwner removes an owner by key. Any owner may remove any owner,
// themselves included; the last owner cannot be removed.
func (s *Service) RemoveOwner(ctx context.Context, p Principal, appID, key string) (OwnerList, error) {
	owner, ok := ParseOwnerKey(key)
	if !ok {
		return OwnerList{}, Problem(400, "invalid_owner", "The owner key must be user:<id> or group:<id>.")
	}
	app, r, err := s.ownersWritable(ctx, p, appID)
	if err != nil {
		return OwnerList{}, err
	}
	if !slices.Contains(app.Owners, owner) {
		return OwnerList{Items: s.ownerViews(ctx, app.Owners, ownerNames{})}, nil
	}
	if len(app.Owners) == 1 {
		return OwnerList{}, Problem(409, "last_owner", "An application needs at least one owner. Add another owner first.")
	}
	existing := map[string]Record{}
	row, err := s.repo.Read(ctx, OwnerRecordID(app.ID, owner))
	switch {
	case err == nil:
		existing[owner.Key()] = row
	case !errors.Is(err, ErrNotFound):
		return OwnerList{}, unavailable()
	}
	after := slices.DeleteFunc(slices.Clone(app.Owners), func(o ApplicationOwner) bool { return o == owner })
	return s.commitOwners(auditPrincipal(ctx, p, "application.owner.remove", "application:"+appID), app, r, after, existing)
}

// ownersWritable loads an application whose owners the caller may change now.
//
// The owner set lives on the application record, which a running worker
// rewrites under compare-and-swap. A change mid-operation would fence that
// worker and interrupt its deployment, so ownership waits for the operation
// like every other write to the application does.
func (s *Service) ownersWritable(ctx context.Context, p Principal, appID string) (ApplicationRecord, Record, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return ApplicationRecord{}, Record{}, err
	}
	app, r, err := s.application(ctx, p, appID)
	if err != nil {
		return ApplicationRecord{}, Record{}, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return ApplicationRecord{}, Record{}, err
	}
	if !app.DeletionRequestedAt.IsZero() {
		return ApplicationRecord{}, Record{}, deletionConflict()
	}
	if app.ActiveDeploymentID != "" {
		return ApplicationRecord{}, Record{}, Problem(409, "deployment_active", "Owners can be changed once the current deployment finishes.")
	}
	return app, r, nil
}

// commitOwners writes the new owner set and its index entries in one commit.
// The revision is unchanged: ownership is not part of what a deployment pins.
func (s *Service) commitOwners(ctx context.Context, app ApplicationRecord, r Record, after []ApplicationOwner, existing map[string]Record) (OwnerList, error) {
	index, err := OwnerIndexMutations(app.ID, app.Owners, after, existing)
	if err != nil {
		return OwnerList{}, unavailable()
	}
	app.Owners = after
	app.UpdatedAt = time.Now().UTC()
	m, err := mutation(r.RecordID, r.Version, app)
	if err != nil {
		return OwnerList{}, err
	}
	if err := s.repo.Commit(ctx, append([]Mutation{m}, index...)); err != nil {
		if errors.Is(err, ErrConflict) {
			return OwnerList{}, Problem(409, "conflict", "The application changed concurrently. Reload its owners and try again.")
		}
		return OwnerList{}, unavailable()
	}
	return OwnerList{Items: s.ownerViews(ctx, after, ownerNames{})}, nil
}

// requireOwnerExists admits a signed-in, enabled user or a synced group.
func (s *Service) requireOwnerExists(ctx context.Context, o ApplicationOwner) error {
	unknown := Problem(422, "unknown_owner", "No AppHub user or directory group has that ID. Search for the person or group and choose a result.")
	if o.ID == "" || len(o.ID) > 256 || strings.ContainsFunc(o.ID, unicode.IsControl) || strings.Contains(o.ID, ":") {
		return unknown
	}
	switch o.Kind {
	case OwnerUser:
		user, err := readValue[User](ctx, s.repo, RecordID{Kind: UserKind, ID: o.ID})
		if errors.Is(err, ErrNotFound) || err == nil && (user.ID != o.ID || user.Disabled) {
			return unknown
		}
		if err != nil {
			return unavailable()
		}
	case OwnerGroup:
		group, err := readValue[DirectoryEntitlementRecord](ctx, s.repo, RecordID{Kind: DirectoryEntitlementKind, ID: o.ID})
		if errors.Is(err, ErrNotFound) || err == nil && group.ID != o.ID {
			return unknown
		}
		if err != nil {
			return unavailable()
		}
	default:
		return Problem(422, "unknown_owner", "An owner is a user or a group.")
	}
	return nil
}

func readValue[T any](ctx context.Context, repo Repository, id RecordID) (T, error) {
	var zero T
	r, err := repo.Read(ctx, id)
	if err != nil {
		return zero, err
	}
	v, err := Decode[T](r)
	if err != nil {
		return zero, ErrUnavailable
	}
	return v, nil
}

// ownerViews names each owner, users first, then by name. A name that cannot
// be read degrades to the ID rather than hiding the owner.
func (s *Service) ownerViews(ctx context.Context, owners []ApplicationOwner, cache ownerNames) []OwnerView {
	views := make([]OwnerView, 0, len(owners))
	for _, o := range owners {
		v, ok := cache[o.Key()]
		if !ok {
			v = s.ownerView(ctx, o)
			cache[o.Key()] = v
		}
		views = append(views, v)
	}
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Kind != views[j].Kind {
			return views[i].Kind == OwnerUser
		}
		return strings.ToLower(views[i].Name) < strings.ToLower(views[j].Name)
	})
	return views
}

func (s *Service) ownerView(ctx context.Context, o ApplicationOwner) OwnerView {
	v := OwnerView{Kind: o.Kind, ID: o.ID, Key: o.Key(), Name: o.ID}
	switch o.Kind {
	case OwnerUser:
		v.Name = "Unknown member"
		if user, err := readValue[User](ctx, s.repo, RecordID{Kind: UserKind, ID: o.ID}); err == nil {
			v = userOwnerView(user)
		}
	case OwnerGroup:
		v.Name = "Unknown group"
		if group, err := readValue[DirectoryEntitlementRecord](ctx, s.repo, RecordID{Kind: DirectoryEntitlementKind, ID: o.ID}); err == nil && group.DisplayName != "" {
			v.Name = group.DisplayName
		}
	}
	return v
}

func userOwnerView(u User) OwnerView {
	name := u.Name
	if name == "" {
		name = u.Email
	}
	if name == "" {
		name = "Unknown member"
	}
	o := ApplicationOwner{Kind: OwnerUser, ID: u.ID}
	return OwnerView{Kind: OwnerUser, ID: u.ID, Key: o.Key(), Name: name, Email: u.Email, Avatar: u.Avatar}
}

// SearchPrincipals finds users and groups to choose as owners. Any member may
// search: owners' names are already visible to every member in the directory.
func (s *Service) SearchPrincipals(ctx context.Context, p Principal, q string) (PrincipalSearchResult, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return PrincipalSearchResult{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return PrincipalSearchResult{}, err
	}
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > 200 || strings.ContainsFunc(q, unicode.IsControl) {
		return PrincipalSearchResult{}, Problem(400, "invalid_query", "Search with at most 200 printable characters.")
	}
	users, err := s.searchUsers(ctx, q)
	if err != nil {
		return PrincipalSearchResult{}, err
	}
	// Emails are matched but not returned to members, as in the directory:
	// a search that answered q="" with every address would be an export.
	if !p.Admin {
		for i := range users {
			users[i].Email = ""
		}
	}
	groups, err := s.searchGroups(ctx, q)
	if err != nil {
		return PrincipalSearchResult{}, err
	}
	return PrincipalSearchResult{Users: users, Groups: groups}, nil
}

func matches(q string, fields ...string) bool {
	if q == "" {
		return true
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (s *Service) searchUsers(ctx context.Context, q string) ([]OwnerView, error) {
	out := []OwnerView{}
	err := s.eachRecord(ctx, Query{Kind: UserKind}, func(r Record) bool {
		u, err := Decode[User](r)
		if err == nil && !u.Disabled && matches(q, u.Name, u.Email) {
			out = append(out, userOwnerView(u))
		}
		return len(out) < principalSearchLimit
	})
	return out, err
}

func (s *Service) searchGroups(ctx context.Context, q string) ([]OwnerView, error) {
	out := []OwnerView{}
	err := s.eachRecord(ctx, Query{Kind: DirectoryEntitlementKind}, func(r Record) bool {
		g, err := Decode[DirectoryEntitlementRecord](r)
		if err == nil && g.ID != "" && matches(q, g.DisplayName, g.Description) {
			o := ApplicationOwner{Kind: OwnerGroup, ID: g.ID}
			name := g.DisplayName
			if name == "" {
				name = g.ID
			}
			out = append(out, OwnerView{Kind: OwnerGroup, ID: g.ID, Key: o.Key(), Name: name})
		}
		return len(out) < principalSearchLimit
	})
	return out, err
}

// eachRecord pages a directory until visit returns false or it ends.
func (s *Service) eachRecord(ctx context.Context, q Query, visit func(Record) bool) error {
	q.Limit = 100
	for {
		page, err := s.repo.Query(ctx, q)
		if err != nil {
			return unavailable()
		}
		for _, r := range page.Records {
			if !visit(r) {
				return nil
			}
		}
		if page.Cursor == "" {
			return nil
		}
		q.Cursor = page.Cursor
	}
}

// ownedApplicationIDs gathers every application a principal owns directly or
// through a group, sorted, from the owner index. It is bounded rather than
// paged per key because one listing spans several keys.
func (s *Service) ownedApplicationIDs(ctx context.Context, p Principal) ([]string, error) {
	seen := map[string]bool{}
	var ids []string
	for _, key := range OwnerKeys(p) {
		err := s.eachRecord(ctx, Query{Kind: ApplicationOwnerKind, OwnerKey: key}, func(r Record) bool {
			if !seen[r.ParentID] {
				seen[r.ParentID] = true
				ids = append(ids, r.ParentID)
			}
			return len(ids) < ownedApplicationLimit
		})
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// ownedCursor continues an owned-application listing after the last ID the
// previous page returned. It names the principal it was issued to, so like
// every repository cursor it is refused for another caller.
type ownedCursor struct {
	UserID string `json:"u"`
	After  string `json:"a"`
}

// ownedPage is one page of ownedApplicationIDs after the cursor.
func ownedPage(p Principal, ids []string, cursor string, limit int) ([]string, string, error) {
	start := 0
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var c ownedCursor
		if err != nil || json.Unmarshal(raw, &c) != nil || c.UserID != p.UserID || c.After == "" {
			return nil, "", queryError(ErrInvalidCursor)
		}
		start, _ = slices.BinarySearch(ids, c.After)
		if start < len(ids) && ids[start] == c.After {
			start++
		}
	}
	end := min(len(ids), start+limit)
	if end >= len(ids) {
		return ids[start:end], "", nil
	}
	raw, err := json.Marshal(ownedCursor{UserID: p.UserID, After: ids[end-1]})
	if err != nil {
		return nil, "", unavailable()
	}
	return ids[start:end], base64.RawURLEncoding.EncodeToString(raw), nil
}
