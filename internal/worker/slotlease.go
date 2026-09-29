// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// Lease timings. A holder renews every slotLeaseRenew and a lease lives for
// slotLeaseTTL. An expired record is NOT automatically reclaimed: its holder
// may have crashed after ECS accepted RunTask, before ECS ListTasks can see it.
// A holder stops trusting its lease slotLeaseMargin before expiry.
const (
	slotLeaseTTL     = 60 * time.Second
	slotLeaseRenew   = 15 * time.Second
	slotLeaseMargin  = 15 * time.Second
	slotLeaseRetry   = time.Second
	slotLeaseTimeout = 5 * time.Second
)

// SlotLeases grants exclusive use of build slots across every worker, through
// one BuildSlotLease record per slot in the control-plane store.
//
// A slot is taken by a compare-and-swap write only if its record is absent,
// then kept by renewing it. Expired records are quarantined until an operator
// verifies the old task stopped and clears the record. Every write names a
// fresh lease ID, so a worker that lost its lease cannot mistake a future
// holder's record for its own. See the compute/aws SlotLeaser port for why
// this cannot be a semaphore inside one process.
type SlotLeases struct {
	repo   cp.Repository
	holder string
	now    func() time.Time
	ttl    time.Duration
	renew  time.Duration
	margin time.Duration
	retry  time.Duration
}

// NewSlotLeases leases slots in repo on behalf of holder, a name an operator
// can recognise the worker process by.
func NewSlotLeases(repo cp.Repository, holder string) (*SlotLeases, error) {
	if repo == nil || holder == "" {
		return nil, errors.New("slot leases require a repository and a holder name")
	}
	return &SlotLeases{repo: repo, holder: holder, now: time.Now, ttl: slotLeaseTTL, renew: slotLeaseRenew, margin: slotLeaseMargin, retry: slotLeaseRetry}, nil
}

// SlotLease is one held slot. Its methods are safe for concurrent use.
type SlotLease struct {
	leases  *SlotLeases
	slot    string
	index   int
	leaseID string

	mu        sync.Mutex
	version   int64
	expiresAt time.Time
	lost      chan struct{}
	lostOnce  sync.Once
	stop      chan struct{}
	stopOnce  sync.Once
	renewDone chan struct{}
}

// Acquire waits until one of slots is free, leases it and starts renewing it.
// Slots are tried from a random start so concurrent workers spread out rather
// than all contending for the first.
func (l *SlotLeases) Acquire(ctx context.Context, slots []string) (*SlotLease, error) {
	if len(slots) == 0 {
		return nil, errors.New("no build slots are configured")
	}
	for {
		start := rand.IntN(len(slots)) //nolint:gosec // G404: spreads contention across slots; exclusivity comes from the compare-and-swap, not from this value.
		for n := range slots {
			i := (start + n) % len(slots)
			lease, err := l.take(ctx, slots[i], i)
			if err != nil {
				return nil, err
			}
			if lease != nil {
				go lease.keep()
				return lease, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("no build slot became available within the build's deadline")
		case <-time.After(l.retry):
		}
	}
}

// take leases one slot if no lease record exists. An expired record is
// quarantined rather than reclaimed: ECS task listing is eventually consistent
// and cannot prove a crashed holder's task stopped immediately after expiry.
func (l *SlotLeases) take(ctx context.Context, slot string, index int) (*SlotLease, error) {
	bounded, cancel := context.WithTimeout(ctx, slotLeaseTimeout)
	defer cancel()
	id := cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(slot)}
	row, err := l.repo.Read(bounded, id)
	switch {
	case err == nil:
		if _, err := cp.Decode[cp.BuildSlotLease](row); err != nil {
			return nil, err
		}
		return nil, nil
	case !errors.Is(err, cp.ErrNotFound):
		return nil, err
	}
	const version int64 = 0
	now := l.now().UTC()
	value := cp.BuildSlotLease{ID: id.ID, Slot: slot, LeaseID: cp.NewID(), Holder: l.holder, AcquiredAt: now, ExpiresAt: now.Add(l.ttl)}
	written, err := cp.Encode(id, version+1, value)
	if err != nil {
		return nil, err
	}
	if err := l.repo.Commit(bounded, []cp.Mutation{{Record: written, ExpectedVersion: version}}); err != nil {
		if errors.Is(err, cp.ErrConflict) {
			return nil, nil
		}
		return nil, err
	}
	return &SlotLease{leases: l, slot: slot, index: index, leaseID: value.LeaseID, version: written.Version, expiresAt: value.ExpiresAt, lost: make(chan struct{}), stop: make(chan struct{}), renewDone: make(chan struct{})}, nil
}

// Slot is the leased slot's index in the list Acquire was given.
func (s *SlotLease) Slot() int { return s.index }

// Lost is closed when the lease can no longer be trusted.
func (s *SlotLease) Lost() <-chan struct{} { return s.lost }

func (s *SlotLease) markLost() { s.lostOnce.Do(func() { close(s.lost) }) }

// keep renews the lease until it is released. A renewal that loses the
// compare-and-swap means somebody else holds the slot, which is final. One
// that fails for an outage is retried, until too little time is left on the
// lease to trust it.
func (s *SlotLease) keep() {
	defer close(s.renewDone)
	ticker := time.NewTicker(s.leases.renew)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
		err := s.renewOnce()
		if errors.Is(err, cp.ErrConflict) {
			s.markLost()
			return
		}
		if err != nil && !s.trustworthy() {
			s.markLost()
			return
		}
	}
}

func (s *SlotLease) renewOnce() error {
	ctx, cancel := context.WithTimeout(context.Background(), slotLeaseTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	id := cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(s.slot)}
	row, err := s.leases.repo.Read(ctx, id)
	if errors.Is(err, cp.ErrNotFound) {
		return cp.ErrConflict
	}
	if err != nil {
		return err
	}
	current, err := cp.Decode[cp.BuildSlotLease](row)
	if err != nil {
		return err
	}
	if current.LeaseID != s.leaseID || row.Version != s.version {
		return cp.ErrConflict
	}
	current.ExpiresAt = s.leases.now().UTC().Add(s.leases.ttl)
	written, err := cp.Encode(id, row.Version+1, current)
	if err != nil {
		return err
	}
	if err := s.leases.repo.Commit(ctx, []cp.Mutation{{Record: written, ExpectedVersion: row.Version}}); err != nil {
		return err
	}
	s.version, s.expiresAt = written.Version, current.ExpiresAt
	return nil
}

// trustworthy reports whether enough of the lease is left to act on it.
func (s *SlotLease) trustworthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leases.now().Add(s.leases.margin).Before(s.expiresAt)
}

// Confirm reads the lease back and checks it is still this holder's and has
// time left. The runner calls it before trusting the slot's contents.
func (s *SlotLease) Confirm(ctx context.Context) error {
	select {
	case <-s.lost:
		return errSlotLeaseLost
	default:
	}
	bounded, cancel := context.WithTimeout(ctx, slotLeaseTimeout)
	defer cancel()
	row, err := s.leases.repo.Read(bounded, cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(s.slot)})
	if err != nil {
		return err
	}
	current, err := cp.Decode[cp.BuildSlotLease](row)
	if err != nil {
		return err
	}
	if current.LeaseID != s.leaseID || !s.leases.now().Add(s.leases.margin).Before(current.ExpiresAt) {
		s.markLost()
		return errSlotLeaseLost
	}
	return nil
}

// Release removes only a still-trustworthy lease held by this worker. A lost
// or expired lease stays quarantined until an operator verifies ECS has no
// non-STOPPED task for this slot family and removes the record.
func (s *SlotLease) Release(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.renewDone
	bounded, cancel := context.WithTimeout(ctx, slotLeaseTimeout)
	defer cancel()
	id := cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(s.slot)}
	row, err := s.leases.repo.Read(bounded, id)
	if errors.Is(err, cp.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	current, err := cp.Decode[cp.BuildSlotLease](row)
	if err != nil {
		return err
	}
	if current.LeaseID != s.leaseID || !s.leases.now().Add(s.leases.margin).Before(current.ExpiresAt) {
		return nil
	}
	err = s.leases.repo.Commit(bounded, []cp.Mutation{{Record: row, ExpectedVersion: row.Version, Delete: true}})
	if errors.Is(err, cp.ErrConflict) {
		return nil
	}
	return err
}

var errSlotLeaseLost = errors.New("the build slot lease was lost")
