// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"encoding/json"
	"slices"
	"strings"
)

// OwnerKind says what an application owner names.
type OwnerKind string

// A user owner is an AppHub user ID. A group owner is a directory entitlement
// ID from the synced catalog (DirectoryEntitlementKind): everyone currently
// holding it owns the application, as Eligibility resolves on every request.
const (
	OwnerUser  OwnerKind = "user"
	OwnerGroup OwnerKind = "group"
)

// MaxApplicationOwners bounds one application's owner set, so the owners and
// their ownership records always fit in one transaction with the application.
const MaxApplicationOwners = 20

// ApplicationOwnerKind is one owner's index entry for one application. It is
// written in the same commit as every change to ApplicationRecord.Owners, and
// exists so "the applications this principal owns" is an indexed query per
// owner key rather than a walk of every application.
const ApplicationOwnerKind RecordKind = "applicationOwner"

// ApplicationOwner is one member of an application's owner set. All owners
// are equal: each may edit, deploy, delete, and change the owner set.
type ApplicationOwner struct {
	Kind OwnerKind `json:"kind"`
	ID   string    `json:"id"`
}

// Key is the owner's index key, and the ApplicationOwnerRecord's ID.
func (o ApplicationOwner) Key() string { return string(o.Kind) + ":" + o.ID }

// ApplicationOwnerRecord is filed under RecordID{Kind: ApplicationOwnerKind,
// ParentID: application ID, ID: owner key}.
type ApplicationOwnerRecord struct {
	ApplicationID string    `json:"applicationId"`
	OwnerKey      string    `json:"ownerKey"`
	Kind          OwnerKind `json:"kind"`
	OwnerID       string    `json:"ownerId"`
}

// UnmarshalJSON reads an application written before owner sets existed, whose
// single owner was the ownerUserId field, as an owner set of that one user.
// Nothing writes ownerUserId any more; the worker's ownership backfill files
// the index records such an application is missing.
func (a *ApplicationRecord) UnmarshalJSON(data []byte) error {
	type plain ApplicationRecord
	var decoded struct {
		plain
		LegacyOwnerUserID string `json:"ownerUserId"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = ApplicationRecord(decoded.plain)
	if len(a.Owners) == 0 && decoded.LegacyOwnerUserID != "" {
		a.Owners = []ApplicationOwner{{Kind: OwnerUser, ID: decoded.LegacyOwnerUserID}}
	}
	return nil
}

// Owns reports whether a principal may act on an application as an owner:
// an administrator, a user owner, or a holder of a group owner.
func Owns(p Principal, app ApplicationRecord) bool {
	if p.Admin {
		return true
	}
	return ownedDirectly(p, app.Owners)
}

// ownedDirectly is ownership without the administrator override: the "yours"
// in a listing, as opposed to "you may open it".
func ownedDirectly(p Principal, owners []ApplicationOwner) bool {
	for _, o := range owners {
		switch o.Kind {
		case OwnerUser:
			if p.UserID != "" && o.ID == p.UserID {
				return true
			}
		case OwnerGroup:
			if slices.Contains(p.Groups, o.ID) {
				return true
			}
		}
	}
	return false
}

// OwnerKeys are the index keys a principal owns applications under.
func OwnerKeys(p Principal) []string {
	keys := []string{ApplicationOwner{Kind: OwnerUser, ID: p.UserID}.Key()}
	for _, g := range p.Groups {
		keys = append(keys, ApplicationOwner{Kind: OwnerGroup, ID: g}.Key())
	}
	return keys
}

// ParseOwnerKey is the inverse of Key.
func ParseOwnerKey(key string) (ApplicationOwner, bool) {
	kind, id, ok := strings.Cut(key, ":")
	o := ApplicationOwner{Kind: OwnerKind(kind), ID: id}
	return o, ok && id != "" && (o.Kind == OwnerUser || o.Kind == OwnerGroup)
}

// OwnerRecordID names one owner's index record.
func OwnerRecordID(appID string, o ApplicationOwner) RecordID {
	return RecordID{Kind: ApplicationOwnerKind, ParentID: appID, ID: o.Key()}
}

// OwnerIndexMutations are the index writes that take an application from the
// owner set before to after, for the same commit as the application itself.
// Owners in both sets are untouched, so their records' versions do not matter.
func OwnerIndexMutations(appID string, before, after []ApplicationOwner, existing map[string]Record) ([]Mutation, error) {
	var out []Mutation
	for _, o := range after {
		if slices.Contains(before, o) {
			continue
		}
		r, err := Encode(OwnerRecordID(appID, o), 1, ApplicationOwnerRecord{ApplicationID: appID, OwnerKey: o.Key(), Kind: o.Kind, OwnerID: o.ID})
		if err != nil {
			return nil, err
		}
		out = append(out, Mutation{Record: r, ExpectedVersion: 0})
	}
	for _, o := range before {
		if slices.Contains(after, o) {
			continue
		}
		r, ok := existing[o.Key()]
		if !ok {
			continue
		}
		out = append(out, Mutation{Record: r, ExpectedVersion: r.Version, Delete: true})
	}
	return out, nil
}
