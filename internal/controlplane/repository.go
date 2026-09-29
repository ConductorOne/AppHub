// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
)

// RecordKind names a domain aggregate, not a storage table or key prefix.
type RecordKind string

// Record kinds select the aggregate schema and supported repository directories.
const (
	UserKind        RecordKind = "user"
	IdentityKind    RecordKind = "identity"
	SessionKind     RecordKind = "session"
	LoginKind       RecordKind = "login"
	ConsentKind     RecordKind = "consent"
	CodeKind        RecordKind = "code"
	OAuthClientKind RecordKind = "oauthClient"
	FamilyKind      RecordKind = "family"
	AccessKind      RecordKind = "access"
	RefreshKind     RecordKind = "refresh"
	ApplicationKind RecordKind = "application"
	DeploymentKind  RecordKind = "deployment"
	IdempotencyKind RecordKind = "idempotency"
	HostnameKind    RecordKind = "hostname"
	TargetKind      RecordKind = "target"
	DetectionKind   RecordKind = "detection"
	// GitHubAppConfigKind is the admin-managed GitHub App's non-secret
	// identity: a singleton record at ID "config". Its private key is never
	// part of this record; see internal/ghappkey.
	GitHubAppConfigKind RecordKind = "githubAppConfig"
	// GitHubInstallationKind is one GitHub App installation, synced from
	// GitHub by the worker and read by the Workspace admin UI.
	GitHubInstallationKind RecordKind = "githubInstallation"
	// DirectoryEntitlementKind is one directory entitlement (a group or a
	// finer-grained grant), synced from an operator-configured identity
	// directory by the worker and read by the Workspace admin UI. This
	// package has no idea which directory: see credentials/c1directory,
	// the one directory source a composition root may wire in today.
	DirectoryEntitlementKind RecordKind = "directoryEntitlement"
	// RoleMappingKind binds one directory entitlement ID to the AppHub role
	// it grants members it covers. Admin-authored via the Workspace's Role
	// assignment tab; read by Eligibility on every admission recheck.
	RoleMappingKind RecordKind = "roleMapping"
	// GroupMembershipKind is one identity's cached, TTL-bounded snapshot of
	// which directory entitlement IDs it currently holds -- membership, not
	// the entitlement catalog DirectoryEntitlementKind holds. Populated
	// lazily by Eligibility, keyed by normalized email, so an admission
	// recheck reads a live ConductorOne lookup only once per
	// GroupMembershipCacheTTL per identity rather than on every request.
	GroupMembershipKind RecordKind = "groupMembership"
	// FeatureFlagKind is one known feature flag's admin-configured mode.
	// Admin-authored via the Workspace's Feature flags tab; read by
	// Eligibility on every admission recheck alongside RoleMappingKind.
	FeatureFlagKind RecordKind = "featureFlag"
	// GitHubManifestKind is one short-lived, single-use state token binding
	// an administrator's started GitHub App Manifest flow to the callback
	// that must complete it -- the same role a LoginKind transaction plays
	// for browser login, scoped down to what this flow needs: no directory
	// listing, read only by its own ID, and always deleted on first use.
	GitHubManifestKind RecordKind = "githubManifest"
)

// Repository errors distinguish absence, concurrent writes, outages and invalid cursors.
var (
	ErrNotFound      = errors.New("record not found")
	ErrConflict      = errors.New("concurrent record modification")
	ErrUnavailable   = errors.New("persistence unavailable")
	ErrInvalidCursor = errors.New("invalid query cursor")
)

// RecordID identifies an aggregate. ParentID is the application for a deployment,
// the target for a hostname, or the principal for an idempotency result.
// Backend keys and indexes are deliberately absent from this port.
type RecordID struct {
	Kind     RecordKind `json:"kind"`
	ID       string     `json:"id"`
	ParentID string     `json:"parentId,omitempty"`
}

// Record is a versioned domain value with no backend-specific key representation.
type Record struct {
	RecordID
	Version int64           `json:"version"`
	Value   json.RawMessage `json:"value"`
}

// Mutation requires the exact previously observed version. Zero means absent.
// All predicates are checked atomically with all writes, including deletions.
type Mutation struct {
	Record          Record
	ExpectedVersion int64
	Delete          bool
}

// Query selects one supported, bounded directory rather than an arbitrary table scan.
type Query struct {
	Kind        RecordKind
	OwnerUserID string
	// OwnerKey selects ApplicationOwnerKind index entries for one owner key
	// (see ApplicationOwner.Key). It is not an OwnerUserID: a key may name a
	// group, and the two select different directories.
	OwnerKey      string
	ApplicationID string
	State         string
	Limit         int
	Cursor        string
}

// RecordPage is the repository's bounded result and opaque continuation cursor.
type RecordPage struct {
	Records []Record
	Cursor  string
}

// Repository is the transaction boundary used by application, authentication,
// and worker aggregates. Reads are authoritative, never TTL-based authorization.
// Query supports only the explicit owner/history/queue/session directories;
// implementations must not turn an unsupported query into a table scan.
type Repository interface {
	Read(context.Context, RecordID) (Record, error)
	Commit(context.Context, []Mutation) error
	Query(context.Context, Query) (RecordPage, error)
	Ready(context.Context) error
}

// Decode unmarshals a record's domain value without discarding malformed-data errors.
func Decode[T any](record Record) (T, error) {
	var value T
	err := json.Unmarshal(record.Value, &value)
	return value, err
}

// Encode marshals a domain value with its logical identity and transaction version.
func Encode(id RecordID, version int64, value any) (Record, error) {
	data, err := json.Marshal(value)
	return Record{RecordID: id, Version: version, Value: data}, err
}
