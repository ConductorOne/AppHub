// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"sync"
)

// SlotLeaser grants one build exclusive use of one build slot.
//
// # Why exclusivity is a port and not a semaphore
//
// A slot is a task definition and the share directory its access point
// confines a build to. That confinement is the only thing keeping one
// application's source and image out of another's build, and it holds only if
// one build uses a slot at a time. [BuildTaskRunner.prepareSlot] empties the
// slot it is given, and the runner reads back whatever image it finds there.
//
// Every worker process sees the same slots. A channel inside one process
// cannot see another's builds, so two workers once both believed slot zero
// free: the second emptied the first's context mid-build, or the first pushed
// the second's image as its own. The decision therefore belongs to something
// every worker can see. The worker implements this over the control-plane
// store; [NewProcessSlotLeaser] is the single-process implementation.
type SlotLeaser interface {
	// Acquire waits until one of slots can be leased exclusively and returns
	// the lease. slots are the task definitions, in slot order.
	Acquire(ctx context.Context, slots []string) (SlotLease, error)
}

// SlotLease is exclusive use of one slot until it is released or lost.
type SlotLease interface {
	// Slot is the index of the leased slot in the list given to Acquire.
	Slot() int
	// Lost is closed once exclusivity can no longer be assured, for example
	// because a renewal failed. A build must stop using the slot.
	Lost() <-chan struct{}
	// Confirm checks with the authority that the lease is still held, now.
	// The runner calls it before each step that trusts the slot's contents:
	// emptying it, and reading a build's image back out of it.
	Confirm(ctx context.Context) error
	// Release gives the slot back. It is safe to call after the lease is lost.
	Release(ctx context.Context) error
}

// ErrSlotLeaseLost reports that a lease stopped being exclusive.
var ErrSlotLeaseLost = errors.New("aws: the build slot lease was lost")

// NewProcessSlotLeaser leases slots within this process only. It is correct
// only while exactly one process uses a set of slots: tests, and a local
// worker. A deployed worker must use a leaser every worker can see.
func NewProcessSlotLeaser() SlotLeaser {
	return &processSlotLeaser{held: map[string]bool{}, freed: make(chan struct{})}
}

type processSlotLeaser struct {
	mu   sync.Mutex
	held map[string]bool
	// freed is closed and replaced on every release, waking every waiter.
	freed chan struct{}
}

func (l *processSlotLeaser) Acquire(ctx context.Context, slots []string) (SlotLease, error) {
	if len(slots) == 0 {
		return nil, errors.New("aws: no build slots are configured")
	}
	for {
		l.mu.Lock()
		for i, slot := range slots {
			if !l.held[slot] {
				l.held[slot] = true
				l.mu.Unlock()
				return &processSlotLease{leaser: l, slot: slot, index: i, lost: make(chan struct{})}, nil
			}
		}
		freed := l.freed
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, errors.New("aws: no build slot became available within the build's deadline")
		case <-freed:
		}
	}
}

type processSlotLease struct {
	leaser *processSlotLeaser
	slot   string
	index  int
	lost   chan struct{}
	done   bool
}

func (p *processSlotLease) Slot() int                     { return p.index }
func (p *processSlotLease) Lost() <-chan struct{}         { return p.lost }
func (p *processSlotLease) Confirm(context.Context) error { return nil }

func (p *processSlotLease) Release(context.Context) error {
	l := p.leaser
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.done {
		return nil
	}
	p.done = true
	delete(l.held, p.slot)
	close(l.freed)
	l.freed = make(chan struct{})
	return nil
}
