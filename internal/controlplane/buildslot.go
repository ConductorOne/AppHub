// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// BuildSlotLeaseKind is one build slot's exclusive lease. A build slot is a
// build task definition and the one share directory its access point confines
// it to. Every worker sees the same slots, so which one a build uses must be
// decided somewhere every worker can see, and this is that place.
const BuildSlotLeaseKind RecordKind = "buildSlotLease"

// BuildSlotLease is held by one build at a time. Its holder renews ExpiresAt;
// expiry stops that holder from trusting the lease but does not grant another
// worker the slot. A crashed holder may have left an ECS task running, so the
// expired record stays quarantined until explicit, verified recovery.
type BuildSlotLease struct {
	// ID is BuildSlotLeaseID(Slot).
	ID string `json:"id"`
	// Slot is the slot's task definition, as the build configuration names it.
	Slot string `json:"slot"`
	// LeaseID changes on every acquisition, so a holder that lost its lease
	// and a new holder never both match it.
	LeaseID string `json:"leaseId"`
	// Holder names the worker process, for an operator reading the record.
	Holder     string    `json:"holder"`
	AcquiredAt time.Time `json:"acquiredAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// BuildSlotLeaseID keys a slot's lease. A task definition name can carry an
// ARN's colons and slashes, which are not record ID characters, so the ID is
// its digest.
func BuildSlotLeaseID(slot string) string {
	sum := sha256.Sum256([]byte(slot))
	return hex.EncodeToString(sum[:])
}
