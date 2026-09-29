// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package fake implements lifecycle.Records in memory.
//
// It exists so the credential lifecycle can be tested with no AWS account, no
// credentials, and no network -- the property CI depends on. The DynamoDB
// implementation lives behind the store fence and cannot run without a table, so
// without this package every test of an Issuer or a Reconciler would need one.
//
// It is not a simulation of DynamoDB and does not try to be. What makes it usable
// as a stand-in is that both it and store are checked against the same
// conformance suite (credentials/lifecycle/lifecycletest), so a behaviour a test
// relies on here is a behaviour production has too.
package fake

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/conductorone/apphub/credentials/lifecycle"
)

// Records is an in-memory lifecycle.Records.
//
// Safe for concurrent use, as lifecycle.Records requires. That is not decoration:
// the race this interface's Revision field exists to close is a concurrency bug,
// and a fake that serialised everything could not be used to test the fix.
type Records struct {
	mu          sync.RWMutex
	byID        map[string]lifecycle.Record
	annotations *lifecycle.AnnotationRegistry
}

var _ lifecycle.Records = (*Records)(nil)

// New returns an empty Records validating annotations against reg.
//
// reg is required for the same reason store.NewCredentialRecords requires it: a
// fake that accepted any annotation would pass tests that production fails,
// which is worse than having no fake.
func New(reg *lifecycle.AnnotationRegistry) (*Records, error) {
	if reg == nil {
		return nil, errors.New("fake: annotation registry is required (see lifecycle.NewAnnotationRegistry)")
	}
	return &Records{byID: make(map[string]lifecycle.Record), annotations: reg}, nil
}

// Create writes a new record, failing on a duplicate ID.
func (r *Records) Create(_ context.Context, rec *lifecycle.Record) error {
	if rec == nil {
		return errors.New("fake: record is required")
	}
	if rec.ID == "" {
		return errors.New("fake: record ID is required; the issuer assigns it before vending")
	}
	if rec.Status == "" {
		return errors.New("fake: record Status is required; the store does not default it")
	}
	if err := r.annotations.Validate(rec.ProviderID, rec.Annotations); err != nil {
		return fmt.Errorf("fake: create credential %s: %w", rec.ID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[rec.ID]; exists {
		return fmt.Errorf("%w: %s", lifecycle.ErrAlreadyExists, rec.ID)
	}

	stored := copyRecord(*rec)
	stored.Revision = 1
	r.byID[rec.ID] = stored
	rec.Revision = stored.Revision
	return nil
}

// Update writes an existing record if rec.Revision matches the stored revision.
func (r *Records) Update(_ context.Context, rec *lifecycle.Record) error {
	if rec == nil {
		return errors.New("fake: record is required")
	}
	if rec.ID == "" {
		return errors.New("fake: record ID is required")
	}
	if err := r.annotations.Validate(rec.ProviderID, rec.Annotations); err != nil {
		return fmt.Errorf("fake: update credential %s: %w", rec.ID, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.byID[rec.ID]
	if !exists {
		return fmt.Errorf("%w: %s", lifecycle.ErrNotFound, rec.ID)
	}
	if current.Revision != rec.Revision {
		return fmt.Errorf("%w: %s", lifecycle.ErrConflict, rec.ID)
	}

	stored := copyRecord(*rec)
	stored.Revision = current.Revision + 1
	r.byID[rec.ID] = stored
	rec.Revision = stored.Revision
	return nil
}

// Get returns the record for id, or lifecycle.ErrNotFound.
func (r *Records) Get(_ context.Context, id string) (*lifecycle.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, exists := r.byID[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", lifecycle.ErrNotFound, id)
	}
	out := copyRecord(rec)
	return &out, nil
}

// Delete removes a record, or reports lifecycle.ErrNotFound.
func (r *Records) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[id]; !exists {
		return fmt.Errorf("%w: %s", lifecycle.ErrNotFound, id)
	}
	delete(r.byID, id)
	return nil
}

// ListByRequester returns a requester's records, newest first.
func (r *Records) ListByRequester(_ context.Context, requesterID string) ([]lifecycle.Record, error) {
	if requesterID == "" {
		return nil, errors.New("fake: requester ID is required")
	}
	return r.collect(func(rec lifecycle.Record) bool {
		return rec.Requester.ID == requesterID
	}), nil
}

// ListByApplication returns records vended for an application.
func (r *Records) ListByApplication(_ context.Context, applicationID string, activeOnly bool) ([]lifecycle.Record, error) {
	if applicationID == "" {
		return nil, errors.New("fake: application ID is required")
	}
	return r.collect(func(rec lifecycle.Record) bool {
		if rec.ApplicationID != applicationID {
			return false
		}
		return !activeOnly || rec.Status == lifecycle.StatusActive
	}), nil
}

// ListByStatus returns every record in a given status.
func (r *Records) ListByStatus(_ context.Context, status lifecycle.Status) ([]lifecycle.Record, error) {
	if status == "" {
		return nil, errors.New("fake: status is required")
	}
	return r.collect(func(rec lifecycle.Record) bool {
		return rec.Status == status
	}), nil
}

// ListExpiring returns non-terminal records whose ExpiresAt is at or before at.
//
// Record.Expired is the predicate rather than a hand-rolled comparison, so a
// record with no expiry at all is excluded here for the same reason it is
// excluded in store: a zero ExpiresAt means "does not expire", and sweeping those
// up as expired would have the reconciler retire credentials that still work.
func (r *Records) ListExpiring(_ context.Context, at time.Time) ([]lifecycle.Record, error) {
	return r.collect(func(rec lifecycle.Record) bool {
		return !rec.Status.Terminal() && rec.Expired(at)
	}), nil
}

// collect returns matching records newest first, as copies.
func (r *Records) collect(match func(lifecycle.Record) bool) []lifecycle.Record {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []lifecycle.Record
	for _, rec := range r.byID {
		if match(rec) {
			out = append(out, copyRecord(rec))
		}
	}
	// Newest first, as ListByRequester documents. Ties break on ID so that a
	// caller iterating results does not see map iteration order and start
	// depending on whatever it happened to be.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// copyRecord deep-copies the reference-typed fields.
//
// Without this the fake would hand callers a window into its own state: a test
// mutating a returned record would change what the next read sees, which no real
// implementation does. Bugs that behave differently against the fake than against
// the database are the one thing a fake must not introduce.
func copyRecord(rec lifecycle.Record) lifecycle.Record {
	out := rec

	if rec.GrantedScope != nil {
		out.GrantedScope = append([]string(nil), rec.GrantedScope...)
	}
	if rec.RequestedScope != nil {
		out.RequestedScope = append([]string(nil), rec.RequestedScope...)
	}
	if rec.Annotations != nil {
		out.Annotations = make(lifecycle.Annotations, len(rec.Annotations))
		for k, v := range rec.Annotations {
			out.Annotations[k] = v
		}
	}
	if rec.RevokedAt != nil {
		t := *rec.RevokedAt
		out.RevokedAt = &t
	}
	return out
}
