// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

// clock is a settable time source shared by the "workers" in a test.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// twoWorkers are two lease clients over one store, as two worker processes are.
func twoWorkers(t *testing.T) (*SlotLeases, *SlotLeases, *clock) {
	t.Helper()
	repo := testutil.NewRepository()
	c := &clock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	client := func(name string) *SlotLeases {
		l, err := NewSlotLeases(repo, name)
		if err != nil {
			t.Fatal(err)
		}
		// Renewal is driven by the tests, not a ticker, so they are deterministic.
		l.now, l.renew, l.retry = c.Now, time.Hour, time.Millisecond
		return l
	}
	return client("worker-a"), client("worker-b"), c
}

var slots = []string{"arn:aws:ecs:us-west-2:0:task-definition/build-0:3", "arn:aws:ecs:us-west-2:0:task-definition/build-1:3"}

func TestTwoWorkersNeverHoldTheSameSlot(t *testing.T) {
	a, b, _ := twoWorkers(t)
	ctx := context.Background()
	first, err := a.Acquire(ctx, slots)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Acquire(ctx, slots)
	if err != nil {
		t.Fatal(err)
	}
	if first.Slot() == second.Slot() {
		t.Fatalf("both workers leased slot %d", first.Slot())
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := a.Acquire(short, slots); err == nil {
		t.Fatal("a third build leased a slot while both were held")
	}
	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}
	third, err := b.Acquire(ctx, slots)
	if err != nil || third.Slot() != first.Slot() {
		t.Fatalf("the released slot was not leasable: %v", err)
	}
}

func TestExpiredLeaseQuarantinedUntilVerifiedRecovery(t *testing.T) {
	a, b, c := twoWorkers(t)
	ctx := context.Background()
	stale, err := a.Acquire(ctx, slots[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Confirm(ctx); err != nil {
		t.Fatalf("a fresh lease does not confirm: %v", err)
	}
	c.Advance(slotLeaseTTL - slotLeaseMargin)
	if err := stale.Confirm(ctx); err == nil {
		t.Fatal("a lease inside its safety margin still confirmed")
	}
	c.Advance(slotLeaseMargin)
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(short, slots[:1]); err == nil {
		t.Fatal("an expired record was reclaimed before its ECS task was verified stopped")
	}
	if err := stale.Release(ctx); err != nil {
		t.Fatal(err)
	}
	short, cancelAgain := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelAgain()
	if _, err := b.Acquire(short, slots[:1]); err == nil {
		t.Fatal("an expired holder removed its quarantine record")
	}

	// Operator recovery is an explicit action after verifying ECS has no
	// non-STOPPED task in this slot's task-definition family.
	id := cp.RecordID{Kind: cp.BuildSlotLeaseKind, ID: cp.BuildSlotLeaseID(slots[0])}
	row, err := a.repo.Read(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.repo.Commit(ctx, []cp.Mutation{{Record: row, ExpectedVersion: row.Version, Delete: true}}); err != nil {
		t.Fatal(err)
	}
	next, err := b.Acquire(ctx, slots[:1])
	if err != nil {
		t.Fatalf("a verified, cleared slot was not leasable: %v", err)
	}
	if err := next.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalKeepsALeasePastItsFirstExpiry(t *testing.T) {
	a, b, c := twoWorkers(t)
	ctx := context.Background()
	lease, err := a.Acquire(ctx, slots[:1])
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		c.Advance(slotLeaseRenew)
		if err := lease.renewOnce(); err != nil {
			t.Fatalf("renewal failed: %v", err)
		}
	}
	if err := lease.Confirm(ctx); err != nil {
		t.Fatalf("a renewed lease does not confirm: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(short, slots[:1]); err == nil {
		t.Fatal("a renewed lease was taken over")
	}
}

func TestAnOutageLosesTheLeaseOnlyWhenItRunsOut(t *testing.T) {
	a, _, c := twoWorkers(t)
	repo := a.repo.(*testutil.Repository)
	a.renew = 5 * time.Millisecond
	lease, err := a.Acquire(context.Background(), slots[:1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Release(context.Background()) }()
	repo.SetError(errors.New("store unavailable"))
	time.Sleep(30 * time.Millisecond)
	select {
	case <-lease.Lost():
		t.Fatal("a short outage lost a lease with time left on it")
	default:
	}
	c.Advance(slotLeaseTTL - slotLeaseMargin)
	select {
	case <-lease.Lost():
	case <-time.After(time.Second):
		t.Fatal("a lease that could not be renewed was trusted past its margin")
	}
	repo.SetError(nil)
}

func TestConcurrentBuildsGetDistinctSlots(t *testing.T) {
	a, b, _ := twoWorkers(t)
	many := []string{"s0", "s1", "s2", "s3"}
	var held [4]atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func(l *SlotLeases) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			lease, err := l.Acquire(ctx, many)
			if err != nil {
				errs <- err
				return
			}
			if held[lease.Slot()].Add(1) != 1 {
				errs <- errors.New("two builds held one slot at once")
			}
			time.Sleep(2 * time.Millisecond)
			held[lease.Slot()].Add(-1)
			if err := lease.Release(context.Background()); err != nil {
				errs <- err
			}
		}(map[bool]*SlotLeases{true: a, false: b}[i%2 == 0])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
