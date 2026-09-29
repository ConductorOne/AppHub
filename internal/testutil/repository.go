// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package testutil provides hermetic test support. Production code must never
// import it or use its repository as a persistence fallback.
package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/conductorone/apphub/internal/controlplane"
)

// Repository is an isolated, in-process implementation of the domain transaction
// port for tests. All observations and entire mutation batches share one lock.
// It retains expired records: expiry is an authorization decision, not cleanup.
// Construct it with NewRepository; its zero value is not ready for writes.
type Repository struct {
	mu      sync.RWMutex
	records map[controlplane.RecordID]controlplane.Record
	failure error
}

var _ controlplane.Repository = (*Repository)(nil)

// NewRepository creates an empty repository with no external dependencies.
func NewRepository() *Repository {
	return &Repository{records: make(map[controlplane.RecordID]controlplane.Record)}
}

// SetError injects an error into Read, Commit, Query and Ready until cleared with
// nil. Pass controlplane.ErrUnavailable to simulate a dependency outage.
// Snapshot remains available so tests can inspect failed operations for leaks.
func (r *Repository) SetError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failure = err
}

// Ready reports context cancellation, an uninitialized repository or an injected outage.
func (r *Repository) Ready(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.check(ctx)
}

func (r *Repository) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.records == nil {
		return controlplane.ErrUnavailable
	}
	return r.failure
}

func copyRecord(record controlplane.Record) controlplane.Record {
	record.Value = bytes.Clone(record.Value)
	return record
}

func (r *Repository) Read(ctx context.Context, id controlplane.RecordID) (controlplane.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.check(ctx); err != nil {
		return controlplane.Record{}, err
	}
	// The store has no lookup for an owner index entry that does not name its
	// application, so neither does this.
	if id.Kind == controlplane.ApplicationOwnerKind && id.ParentID == "" {
		return controlplane.Record{}, errors.New("missing parent identity")
	}
	if id.Kind == controlplane.DeploymentKind && id.ParentID == "" {
		for storedID, record := range r.records {
			if storedID.Kind == id.Kind && storedID.ID == id.ID {
				return copyRecord(record), nil
			}
		}
	}
	record, ok := r.records[id]
	if !ok {
		return controlplane.Record{}, controlplane.ErrNotFound
	}
	return copyRecord(record), nil
}

// Commit checks every predicate before making any write visible. Input Version
// is not trusted: each written version is exactly ExpectedVersion + 1. Multiple
// mutations of the same aggregate in a batch are rejected, not applied in order.
func (r *Repository) Commit(ctx context.Context, mutations []controlplane.Mutation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.check(ctx); err != nil {
		return err
	}
	if len(mutations) > 100 {
		return errors.New("too many mutations")
	}
	seen := make(map[controlplane.RecordID]bool, len(mutations))
	deployments := make(map[string]bool)
	for _, mutation := range mutations {
		id := mutation.Record.RecordID
		if err := validateID(id); err != nil {
			return err
		}
		if seen[id] {
			return errors.New("duplicate mutation")
		}
		seen[id] = true
		if mutation.ExpectedVersion < 0 || mutation.ExpectedVersion == math.MaxInt64 {
			return errors.New("invalid expected version")
		}
		stored, exists := r.records[id]
		if (mutation.ExpectedVersion == 0 && exists) ||
			(mutation.ExpectedVersion != 0 && (!exists || stored.Version != mutation.ExpectedVersion)) {
			return controlplane.ErrConflict
		}
		if id.Kind == controlplane.DeploymentKind {
			if deployments[id.ID] {
				return errors.New("duplicate deployment mutation")
			}
			deployments[id.ID] = true
			for existing := range r.records {
				if existing.Kind == id.Kind && existing.ID == id.ID && existing.ParentID != id.ParentID {
					return controlplane.ErrConflict
				}
			}
		}
		if !mutation.Delete {
			if err := validateValue(mutation.Record, stored); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, mutation := range mutations {
		if mutation.Delete {
			delete(r.records, mutation.Record.RecordID)
			continue
		}
		record := copyRecord(mutation.Record)
		record.Version = mutation.ExpectedVersion + 1
		r.records[record.RecordID] = record
	}
	return nil
}

func validateID(id controlplane.RecordID) error {
	if id.ID == "" {
		return errors.New("missing record identity")
	}
	switch id.Kind {
	case controlplane.IdentityKind, controlplane.IdempotencyKind,
		controlplane.HostnameKind, controlplane.DeploymentKind, controlplane.ApplicationOwnerKind:
		if id.ParentID == "" {
			return errors.New("missing parent identity")
		}
	case controlplane.UserKind, controlplane.SessionKind, controlplane.LoginKind,
		controlplane.ConsentKind, controlplane.CodeKind, controlplane.FamilyKind,
		controlplane.AccessKind, controlplane.RefreshKind, controlplane.ApplicationKind,
		controlplane.TargetKind, controlplane.OAuthClientKind, controlplane.DetectionKind,
		controlplane.GitHubAppConfigKind, controlplane.GitHubInstallationKind,
		controlplane.DirectoryEntitlementKind, controlplane.RoleMappingKind,
		controlplane.GroupMembershipKind, controlplane.FeatureFlagKind, controlplane.GitHubManifestKind,
		controlplane.ApplicationUsageKind, controlplane.BuildSlotLeaseKind:
		if id.ParentID != "" {
			return errors.New("unexpected parent identity")
		}
	default:
		return errors.New("unsupported record kind")
	}
	return nil
}

// directoryFields are domain data, not persistence keys or index attributes.
type directoryFields struct {
	ID            string                       `json:"id"`
	UserID        string                       `json:"userId"`
	ApplicationID string                       `json:"applicationId"`
	Issuer        string                       `json:"issuer"`
	Subject       string                       `json:"subject"`
	State         controlplane.DeploymentState `json:"state"`
	CreatedAt     time.Time                    `json:"createdAt"`
	Application   json.RawMessage              `json:"application"`
	Input         json.RawMessage              `json:"input"`
}

// component mirrors the store's key-component rule for the values it builds
// owner index keys from: non-empty, bounded, valid UTF-8, no separator, no
// control characters.
func component(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.Contains(value, "#") &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

// ownerKey reports whether key is spelled exactly as ApplicationOwner.Key
// would spell the owner it parses to, as the store requires.
func ownerKey(key string) bool {
	owner, ok := controlplane.ParseOwnerKey(key)
	return ok && owner.Key() == key && component(key) && component(owner.ID)
}

// validateOwners refuses what the store refuses on write: an application
// must carry a non-empty owner set of well-formed, distinct users and groups,
// and never the legacy ownerUserId. The store still reads legacy rows, but
// this repository only holds what was committed, so it never has one.
func validateOwners(value []byte) error {
	var decoded struct {
		Owners      []controlplane.ApplicationOwner `json:"owners"`
		OwnerUserID *string                         `json:"ownerUserId"`
	}
	if err := json.Unmarshal(value, &decoded); err != nil {
		return errors.New("invalid application owners")
	}
	if len(decoded.Owners) == 0 || decoded.OwnerUserID != nil || len(decoded.Owners) > controlplane.MaxApplicationOwners {
		return errors.New("application needs one to MaxApplicationOwners owners and no ownerUserId")
	}
	seen := make(map[string]bool, len(decoded.Owners))
	for _, owner := range decoded.Owners {
		key := owner.Key()
		if (owner.Kind != controlplane.OwnerUser && owner.Kind != controlplane.OwnerGroup) ||
			!component(owner.ID) || !component(key) || seen[key] {
			return errors.New("invalid or duplicate application owner")
		}
		seen[key] = true
	}
	return nil
}

// validateOwnerRecord checks an owner index entry against its identity: its
// application is its parent and its owner key is its ID.
func validateOwnerRecord(record controlplane.Record) error {
	var entry controlplane.ApplicationOwnerRecord
	owner, ok := controlplane.ParseOwnerKey(record.ID)
	if !ok || !ownerKey(record.ID) || !component(record.ParentID) || json.Unmarshal(record.Value, &entry) != nil ||
		entry.ApplicationID != record.ParentID || entry.OwnerKey != record.ID || entry.Kind != owner.Kind ||
		entry.OwnerID != owner.ID {
		return errors.New("application owner does not match record")
	}
	return nil
}

func validateValue(record, previous controlplane.Record) error {
	value := bytes.TrimSpace(record.Value)
	if len(value) == 0 || len(record.Value) > 128*1024 || value[0] != '{' || !json.Valid(value) {
		return errors.New("invalid record document")
	}
	var fields directoryFields
	if err := json.Unmarshal(value, &fields); err != nil {
		return errors.New("invalid record fields")
	}
	switch record.Kind {
	case controlplane.IdentityKind:
		if fields.Issuer != record.ParentID || fields.Subject != record.ID {
			return errors.New("identity does not match record")
		}
	case controlplane.ApplicationKind:
		if fields.ID != record.ID {
			return errors.New("application does not match record")
		}
		if err := validateOwners(value); err != nil {
			return err
		}
		if len(fields.Application) > 64*1024 || len(fields.Input) > 64*1024 {
			return errors.New("application specification too large")
		}
	case controlplane.ApplicationOwnerKind:
		if err := validateOwnerRecord(record); err != nil {
			return err
		}
	case controlplane.DeploymentKind:
		if fields.ID != record.ID || fields.ApplicationID != record.ParentID || fields.CreatedAt.IsZero() {
			return errors.New("deployment does not match record")
		}
		if fields.State != controlplane.Queued && fields.State != controlplane.Running && !fields.State.Terminal() {
			return errors.New("invalid deployment state")
		}
		if len(fields.Application) > 64*1024 {
			return errors.New("deployment specification too large")
		}
		if previous.Version != 0 {
			var old directoryFields
			if err := json.Unmarshal(previous.Value, &old); err != nil || !old.CreatedAt.Equal(fields.CreatedAt) {
				return errors.New("deployment creation time is immutable")
			}
		}
	case controlplane.SessionKind, controlplane.FamilyKind:
		if fields.UserID == "" || fields.ID == "" {
			return errors.New("session identity missing")
		}
	case controlplane.DetectionKind:
		if fields.ID != record.ID {
			return errors.New("detection does not match record")
		}
		switch controlplane.DetectionState(fields.State) {
		case controlplane.DetectionQueued, controlplane.DetectionSucceeded, controlplane.DetectionFailed:
		default:
			return errors.New("invalid detection state")
		}
	case controlplane.GitHubAppConfigKind, controlplane.GitHubInstallationKind, controlplane.DirectoryEntitlementKind,
		controlplane.RoleMappingKind, controlplane.GroupMembershipKind, controlplane.FeatureFlagKind, controlplane.GitHubManifestKind,
		controlplane.ApplicationUsageKind, controlplane.BuildSlotLeaseKind:
		if fields.ID != record.ID {
			return errors.New("record does not match its identity")
		}
	}
	return nil
}

type queryScope struct {
	Kind        controlplane.RecordKind `json:"kind"`
	Owner       string                  `json:"owner,omitempty"`
	OwnerKey    string                  `json:"ownerKey,omitempty"`
	Application string                  `json:"application,omitempty"`
	State       string                  `json:"state,omitempty"`
}

type queryPosition struct {
	Order string                `json:"order"`
	ID    controlplane.RecordID `json:"id"`
}

type pageCursor struct {
	Version int           `json:"version"`
	Scope   queryScope    `json:"scope"`
	After   queryPosition `json:"after"`
}

func compareID(a, b controlplane.RecordID) int {
	if n := strings.Compare(string(a.Kind), string(b.Kind)); n != 0 {
		return n
	}
	if n := strings.Compare(a.ParentID, b.ParentID); n != 0 {
		return n
	}
	return strings.Compare(a.ID, b.ID)
}

func comparePosition(a, b queryPosition) int {
	if n := strings.Compare(a.Order, b.Order); n != 0 {
		return n
	}
	return compareID(a.ID, b.ID)
}

func validateQuery(query controlplane.Query) (queryScope, int, error) {
	scope := queryScope{query.Kind, query.OwnerUserID, query.OwnerKey, query.ApplicationID, query.State}
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return scope, 0, errors.New("invalid query limit")
	}
	// OwnerKey selects only the owner index, as in the store.
	if scope.OwnerKey != "" && query.Kind != controlplane.ApplicationOwnerKind {
		return scope, 0, errors.New("unsupported query")
	}
	valid := false
	switch query.Kind {
	case controlplane.ApplicationKind:
		valid = scope.Owner == "" && scope.Application == "" && scope.State == ""
	case controlplane.ApplicationOwnerKind:
		valid = ownerKey(scope.OwnerKey) && scope.Owner == "" && scope.Application == "" && scope.State == ""
	case controlplane.DeploymentKind:
		valid = scope.Owner == "" && ((scope.Application != "" && scope.State == "") ||
			(scope.Application == "" && (scope.State == string(controlplane.Queued) || scope.State == string(controlplane.Running))))
	case controlplane.SessionKind, controlplane.FamilyKind:
		valid = scope.Owner != "" && scope.Application == "" && scope.State == ""
	case controlplane.DetectionKind:
		valid = scope.Owner == "" && scope.Application == "" && scope.State == string(controlplane.DetectionQueued)
	case controlplane.GitHubInstallationKind, controlplane.DirectoryEntitlementKind, controlplane.RoleMappingKind, controlplane.FeatureFlagKind, controlplane.UserKind:
		valid = scope.Owner == "" && scope.Application == "" && scope.State == ""
	}
	if !valid {
		return scope, 0, errors.New("unsupported query")
	}
	return scope, limit, nil
}

// Query returns a bounded, ordered, copy-isolated page. Cursors bind the kind and
// filters, but not page size. Like the real repository, pages are observations
// at the time of each query, not a snapshot spanning multiple requests.
func (r *Repository) Query(ctx context.Context, query controlplane.Query) (controlplane.RecordPage, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.check(ctx); err != nil {
		return controlplane.RecordPage{}, err
	}
	scope, limit, err := validateQuery(query)
	if err != nil {
		return controlplane.RecordPage{}, err
	}
	var cursor pageCursor
	if query.Cursor != "" {
		if len(query.Cursor) > 4096 {
			return controlplane.RecordPage{}, controlplane.ErrInvalidCursor
		}
		data, err := base64.RawURLEncoding.DecodeString(query.Cursor)
		if err != nil {
			return controlplane.RecordPage{}, controlplane.ErrInvalidCursor
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if !json.Valid(data) || decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.Scope != scope ||
			cursor.After.ID.Kind != scope.Kind || cursor.After.ID.ID == "" {
			return controlplane.RecordPage{}, controlplane.ErrInvalidCursor
		}
	}
	// Application history is newest first so a limit returns the latest attempts.
	// Queue listings stay oldest first so workers claim earlier work.
	historyDescending := query.Kind == controlplane.DeploymentKind && scope.Application != ""
	type candidate struct {
		record   controlplane.Record
		position queryPosition
	}
	matches := make([]candidate, 0)
	for _, record := range r.records {
		if record.Kind != query.Kind {
			continue
		}
		var fields directoryFields
		if err := json.Unmarshal(record.Value, &fields); err != nil {
			return controlplane.RecordPage{}, errors.New("invalid stored record")
		}
		order := record.ID
		switch query.Kind {
		case controlplane.ApplicationOwnerKind:
			// The store's owner index sorts one owner's entries by application.
			if record.ID != scope.OwnerKey {
				continue
			}
			order = record.ParentID
		case controlplane.DeploymentKind:
			if (scope.Application != "" && fields.ApplicationID != scope.Application) ||
				(scope.State != "" && string(fields.State) != scope.State) {
				continue
			}
			order = fields.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z") + record.ID
		case controlplane.SessionKind, controlplane.FamilyKind:
			if fields.UserID != scope.Owner {
				continue
			}
			order = fields.ID
		case controlplane.DetectionKind:
			if scope.State != "" && string(fields.State) != scope.State {
				continue
			}
			order = fields.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z") + record.ID
		}
		position := queryPosition{Order: order, ID: record.RecordID}
		if query.Cursor != "" {
			cmp := comparePosition(position, cursor.After)
			if historyDescending && cmp >= 0 || !historyDescending && cmp <= 0 {
				continue
			}
		}
		matches = append(matches, candidate{record, position})
	}
	slices.SortFunc(matches, func(a, b candidate) int {
		order := comparePosition(a.position, b.position)
		if historyDescending {
			return -order
		}
		return order
	})
	count := min(limit, len(matches))
	page := controlplane.RecordPage{Records: make([]controlplane.Record, 0, count)}
	for _, match := range matches[:count] {
		page.Records = append(page.Records, copyRecord(match.record))
	}
	if count < len(matches) {
		data, err := json.Marshal(pageCursor{Version: 1, Scope: scope, After: matches[count-1].position})
		if err != nil {
			return controlplane.RecordPage{}, err
		}
		page.Cursor = base64.RawURLEncoding.EncodeToString(data)
		if len(page.Cursor) > 4096 {
			return controlplane.RecordPage{}, errors.New("query cursor too large")
		}
	}
	return page, nil
}

// Snapshot returns every persisted domain record, including expired/revoked
// records, ordered by kind, parent and ID. The slice and JSON bytes are owned by
// the caller. It bypasses injected outages for secret-leak and atomicity checks.
func (r *Repository) Snapshot() []controlplane.Record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	records := make([]controlplane.Record, 0, len(r.records))
	for _, record := range r.records {
		records = append(records, copyRecord(record))
	}
	slices.SortFunc(records, func(a, b controlplane.Record) int { return compareID(a.RecordID, b.RecordID) })
	return records
}
