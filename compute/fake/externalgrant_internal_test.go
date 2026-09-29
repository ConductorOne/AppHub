// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"reflect"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// TestAnExternalGrantSnapshotSurvivesAnInPlaceMutation is the only test that can
// detect whether [Harness.ExternalGrants] copies or aliases.
//
// # Why it has to be an internal test, and why the external one could not work
//
// The external version re-granted with different constraints and compared the two
// snapshots. **A test that REPLACES a slice can never detect aliasing**: assigning
// a new slice produces a new backing array whether or not the snapshot copied, so
// the comparison differs either way. Deleting copyExternalGrant left that test
// green, which is the proof — the operation the test performed was not the
// operation the invariant is about.
//
// Only mutation *in place* distinguishes a copy from a shared reference, and the
// live grant's slice is unexported, so the mutation can only be written from inside
// the package. That is what this file is for.
func TestAnExternalGrantSnapshotSurvivesAnInPlaceMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New(NewStore(), Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	const id = "caller-supplied-principal"
	original := []string{"tenant one", "tenant two"}
	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id, Constraints: original}, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}

	snapshot, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	got, ok := snapshot[id].(externalGrant)
	if !ok {
		t.Fatalf("the snapshot holds a %T, not an externalGrant", snapshot[id])
	}
	if !reflect.DeepEqual(got.constraints, original) {
		t.Fatalf("the snapshot does not match what was granted: %v vs %v", got.constraints, original)
	}

	// Mutate the LIVE grant's slice in place. Not a replacement: the element is
	// overwritten inside the existing backing array, which is the only operation
	// a shared reference and a copy answer differently.
	resourceID, err := p.resolve(bucket.Ref, compute.KindBucket)
	if err != nil {
		t.Fatalf("resolving the bucket ref: %v", err)
	}
	p.store.mu.Lock()
	key := grantKey{resource: resourceID, subject: id}
	live, present := p.store.external[key]
	if !present {
		p.store.mu.Unlock()
		t.Fatal("the grant is not in the store")
	}
	if len(live.constraints) == 0 {
		p.store.mu.Unlock()
		t.Fatal("the stored grant has no constraints to mutate, so this proves nothing")
	}
	live.constraints[0] = "tampered"
	p.store.mu.Unlock()

	if got.constraints[0] == "tampered" {
		t.Error("an in-place change to the stored grant changed the snapshot, so ExternalGrants " +
			"returns a slice aliasing live store state. A snapshot that moves with the store " +
			"cannot detect a wrongful mutation: the before and the after are the same memory")
	}
	if !reflect.DeepEqual(got.constraints, original) {
		t.Errorf("the snapshot is now %v, want %v", got.constraints, original)
	}
}

// TestAReGrantReplacesTheStoredGrantEntirely closes the half of the replacement
// contract the external tests structurally cannot reach.
//
// # What the existing pair does and does not establish
//
// Two tests already touch a re-grant, and neither reads the result:
//
//   - TestAnExternalGrantSnapshotReflectsARealChange asserts the two snapshots
//     **differ**. An inequality is satisfied by the level alone changing, so a
//     re-grant that applied the new level and kept every old constraint passes it.
//   - The plural-constraints table asserts the stored constraints element by
//     element, but only for the **first** grant to a principal. Nothing observes
//     what a second grant to the same principal leaves behind.
//
// So the pair covers creation content and replacement occurrence, and the
// intersection — replacement *content* — was covered by neither. That is the same
// shape as Len-versus-content one layer out: the axis was traversed and nothing
// read where it went.
//
// # Why this is an internal test
//
// The expected value is an externalGrant, whose fields are unexported. An external
// test can read them by reflection field-by-field, but cannot compare the whole
// struct against a literal — and field-by-field is exactly the enumeration that
// goes stale when a field is added. Comparing the whole value means a new field
// with a wrong value after a re-grant fails here without anybody updating a list.
func TestAReGrantReplacesTheStoredGrantEntirely(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New(NewStore(), Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	const id = "caller-supplied-principal"
	// Disjoint sets, and the second SHORTER than the first: a replacement that
	// appended, or that overwrote in place and kept the tail, both leave a longer
	// slice than the new one. Same-length sets cannot tell those apart.
	first := []string{"tenant one", "tenant two", "tenant three"}
	second := []string{"tenant four"}

	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id, Constraints: first}, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}
	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id, Constraints: second}, compute.AccessReadWrite); err != nil {
		t.Fatalf("re-GrantExternal(): %v", err)
	}

	snapshot, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	// Replacement rather than accumulation, at the map level: a second grant to
	// one principal is one grant, not two.
	if len(snapshot) != 1 {
		t.Errorf("two grants to one principal left %d stored grants, want 1: %#v",
			len(snapshot), snapshot)
	}
	got, ok := snapshot[id].(externalGrant)
	if !ok {
		t.Fatalf("the snapshot holds a %T, not an externalGrant", snapshot[id])
	}
	want := externalGrant{level: compute.AccessReadWrite, constraints: second, owned: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after a re-grant the stored grant is %+v, want %+v.\n"+
			"A re-grant REPLACES the previous grant to the same principal. Retaining any part "+
			"of the first one leaves the principal holding access the last call did not ask "+
			"for, and an inequality-only assertion between two snapshots cannot see it: the "+
			"level changing is enough to make them differ", got, want)
	}
}
