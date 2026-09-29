// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/conductorone/apphub/credentials"
)

// ErrNotFound is returned when no record exists for an ID.
//
// The source system returned (nil, nil) for a missing credential, which every
// caller then had to remember to check separately from the error -- and a caller
// that forgets dereferences nil in the revoke path. A sentinel makes the missing
// case impossible to skip.
var ErrNotFound = errors.New("credential record not found")

// ErrConflict is returned when an Update's Revision does not match the stored
// record: someone else wrote first. The caller re-reads, re-decides, and retries.
var ErrConflict = errors.New("credential record was modified concurrently")

// ErrAlreadyExists is returned when Create is given an ID that is already taken.
var ErrAlreadyExists = errors.New("credential record already exists")

// Records is the persistence port for credential lifecycle state.
//
// This is the interface store/ must satisfy (USOSS-5). It is declared here, by
// the consumer, so that the fence around persistence is a fence: this package
// knows there is somewhere to put a record and nothing about tables, partition
// keys, or which cloud is holding them. Every method is expected to be safe for
// concurrent use.
//
// Listing methods return records, not material, because there is no material to
// return -- see Record.
type Records interface {
	// Create writes a new record. It fails with ErrAlreadyExists rather than
	// overwriting, because the issuer writes its intent down before vending and
	// a colliding ID means two vends believe they own one credential.
	Create(ctx context.Context, rec *Record) error

	// Update writes an existing record if rec.Revision matches the stored
	// revision, returning ErrConflict if it does not and ErrNotFound if the
	// record is gone. On success the implementation increments rec.Revision so
	// the caller can keep writing.
	Update(ctx context.Context, rec *Record) error

	// Get returns the record for id, or ErrNotFound.
	Get(ctx context.Context, id string) (*Record, error)

	// Delete removes a record. Deleting is for administrative cleanup only:
	// the lifecycle's own terminal states are Revoked, Expired and Orphaned,
	// and deleting a record instead of finalizing it destroys the audit trail
	// of a credential that existed.
	Delete(ctx context.Context, id string) error

	// ListByRequester returns a requester's records, newest first.
	ListByRequester(ctx context.Context, requesterID string) ([]Record, error)

	// ListByApplication returns records vended for an application. When
	// activeOnly is true, only records in StatusActive.
	ListByApplication(ctx context.Context, applicationID string, activeOnly bool) ([]Record, error)

	// ListByStatus returns every record in a given status. The reconciler uses it
	// for StatusPendingRevoke and StatusPending.
	ListByStatus(ctx context.Context, status Status) ([]Record, error)

	// ListExpiring returns non-terminal records whose ExpiresAt is at or before
	// the given time. The reconciler passes "now"; a caller wanting to warn ahead
	// of expiry passes a future time.
	ListExpiring(ctx context.Context, at time.Time) ([]Record, error)
}

// SecretWriter stores credential material for a workload to consume, returning a
// locator and never keeping the material itself.
//
// It is separate from Records because the two have different blast radii: a
// Records implementation that leaks tells an attacker who has credentials, and a
// SecretWriter that leaks hands over the credentials. Keeping them as separate
// ports keeps that difference visible in the wiring.
type SecretWriter interface {
	// Write stores each named secret for the given application, returning one
	// locator per entry in the same order. An implementation must be idempotent
	// on name: writing the same name twice replaces the value.
	Write(ctx context.Context, applicationID string, secrets []NamedSecret) ([]credentials.SecretRef, error)

	// Delete removes previously written material. Called when a credential is
	// revoked, so that a revoked credential does not stay readable by the
	// workload it was vended for.
	Delete(ctx context.Context, applicationID string, refs []credentials.SecretRef) error
}

// NamedSecret is one piece of credential material on its way to a secret store,
// named as the consuming workload expects to find it.
type NamedSecret struct {
	// Name is the environment-variable-shaped name the workload reads.
	Name string
	// Value is the material. It exists for the duration of the Write call.
	Value credentials.Secret
}
