// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// TestOwnershipIsReEstablishedAtTheWriteNotInheritedFromTheRead.
//
// EnsureRepository resolves ownership first and then makes several more API
// calls — scanning configuration, tag mutability, tag convergence — before it
// writes the lifecycle policy. Review found that a repository whose ownership
// marker was removed in that interval was still written, and the call returned
// nil: the decision was made at the read and inherited all the way to the write.
//
// Same class as "a Ref that was valid once is not a capability", one scope
// smaller: **a decision that was valid several round trips ago is not a licence
// to write now.**
//
// This test is in the internal package deliberately. Driving Ensure end to end
// cannot exercise the interval — the in-memory substrate does not interleave, so
// a revocation applied before the call is caught by Ensure's own first read and
// the test passes whether or not the fix exists. I wrote that version first and
// it was green against the defect. The only way to reach the state the fix
// covers is to hold the ownership decision the read produced, revoke, and then
// write through it, which is precisely what the interval is.
//
// What the fix buys and does not buy: it narrows the window from several round
// trips to one. It does not close it — ECR has no conditional write, so the
// check and the write cannot be atomic — and this test does not pretend
// otherwise.
//
// Round five moved where the property lives, and this test moved with it. The
// first fix put the re-read inside applyLifecycle, so this drove applyLifecycle
// directly. That was the defect one level in: a check next to *one* write says
// nothing about the writes before it. The invariant now belongs to
// [imageRegistry.writeOwned], which every write in the file goes through, so
// that is what this drives. See [TestEveryMutatingCallIsPrecededByItsOwnProof]
// for the structural half.
func TestOwnershipIsReEstablishedAtTheWriteNotInheritedFromTheRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sub := NewMemorySubstrate()
	p, err := New(sub, Config{
		Region: MemoryRegion, DefaultPlacement: "d",
		Placements: map[string]PlacementConfig{"d": {}},
		Registry:   &RegistryConfig{NamePrefix: "apphub/"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reg := &imageRegistry{p: p}
	mem, ok := sub.ECR.(*MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"}); err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	// The decision, taken at the read.
	owned, found, err := reg.ownedByName(ctx, "apphub/app")
	if err != nil || !found {
		t.Fatalf("ownedByName: found=%v err=%v", found, err)
	}

	// Ownership is revoked in the interval.
	if err := mem.UntagResource(ctx, owned.rec.ARN, []string{tagManagedBy}); err != nil {
		t.Fatalf("revoking ownership: %v", err)
	}

	// The write must not proceed on the strength of the earlier decision.
	policy, err := lifecyclePolicy(compute.RetentionPolicy{KeepLast: 5})
	if err != nil {
		t.Fatalf("lifecyclePolicy: %v", err)
	}
	err = reg.writeOwned(ctx, owned.rec.Name, func(fresh *ownedRepository) error {
		return reg.applyLifecycle(ctx, fresh, policy)
	})
	if err == nil {
		t.Fatal("the lifecycle policy of a repository this platform no longer owns was written, " +
			"because ownership was established at the read and never re-established at the write")
	}
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("refused with %v, want compute.ErrNotOwned", err)
	}
	if _, err := mem.GetLifecyclePolicy(ctx, "apphub/app"); err == nil {
		t.Error("a lifecycle policy was written onto the repository despite the refusal")
	}
}

// ecrSpy records the order of substrate calls and can run a hook the moment one
// of them returns.
//
// The hook is what lets a test reach the interval between a read and a write.
// Applying a change before the call under test cannot do it: the in-memory
// substrate does not interleave, so Ensure's own first read sees the change and
// the test passes whether or not the fix exists. That is not a hypothetical —
// the first version of the test above was written that way and was green against
// the defect it exists to catch.
type ecrSpy struct {
	ECRAPI
	mu    sync.Mutex
	calls []string
	after func(call string)
}

func (s *ecrSpy) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	hook := s.after
	s.mu.Unlock()
	if hook != nil {
		hook(call)
	}
}

func (s *ecrSpy) seq() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *ecrSpy) DescribeRepository(ctx context.Context, name string) (*RepositoryRecord, error) {
	out, err := s.ECRAPI.DescribeRepository(ctx, name)
	s.record("DescribeRepository")
	return out, err
}

func (s *ecrSpy) CreateRepository(ctx context.Context, name string, scan, immutable bool, tags map[string]string) (*RepositoryRecord, error) {
	out, err := s.ECRAPI.CreateRepository(ctx, name, scan, immutable, tags)
	s.record("CreateRepository")
	return out, err
}

func (s *ecrSpy) DeleteRepository(ctx context.Context, name string) error {
	err := s.ECRAPI.DeleteRepository(ctx, name)
	s.record("DeleteRepository")
	return err
}

func (s *ecrSpy) PutImageScanningConfiguration(ctx context.Context, name string, scan bool) error {
	err := s.ECRAPI.PutImageScanningConfiguration(ctx, name, scan)
	s.record("PutImageScanningConfiguration")
	return err
}

func (s *ecrSpy) PutImageTagMutability(ctx context.Context, name string, immutable bool) error {
	err := s.ECRAPI.PutImageTagMutability(ctx, name, immutable)
	s.record("PutImageTagMutability")
	return err
}

func (s *ecrSpy) GetLifecyclePolicy(ctx context.Context, name string) (string, error) {
	out, err := s.ECRAPI.GetLifecyclePolicy(ctx, name)
	s.record("GetLifecyclePolicy")
	return out, err
}

func (s *ecrSpy) PutLifecyclePolicy(ctx context.Context, name, policy string) error {
	err := s.ECRAPI.PutLifecyclePolicy(ctx, name, policy)
	s.record("PutLifecyclePolicy")
	return err
}

func (s *ecrSpy) DeleteLifecyclePolicy(ctx context.Context, name string) error {
	err := s.ECRAPI.DeleteLifecyclePolicy(ctx, name)
	s.record("DeleteLifecyclePolicy")
	return err
}

func (s *ecrSpy) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.ECRAPI.ListTags(ctx, arn)
	s.record("ListTags")
	return out, err
}

func (s *ecrSpy) TagResource(ctx context.Context, arn string, tags map[string]string) error {
	err := s.ECRAPI.TagResource(ctx, arn, tags)
	s.record("TagResource")
	return err
}

func (s *ecrSpy) UntagResource(ctx context.Context, arn string, keys []string) error {
	err := s.ECRAPI.UntagResource(ctx, arn, keys)
	s.record("UntagResource")
	return err
}

// spiedSubstrate builds an in-memory substrate whose ECR is wrapped in a spy.
func spiedSubstrate(t *testing.T) (*Substrate, *ecrSpy, *MemoryECR) {
	t.Helper()
	sub := NewMemorySubstrate()
	mem, ok := sub.ECR.(*MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	spy := &ecrSpy{ECRAPI: mem}
	sub.ECR = spy
	return sub, spy, mem
}

// registryOver builds a registry on a substrate. Two of them over one substrate
// is how a test drives operator configuration changing under an existing
// repository, which is the only way to reach the tag-mutability write.
func registryOver(t *testing.T, sub *Substrate, immutable bool) *imageRegistry {
	t.Helper()
	p, err := New(sub, Config{
		Region: MemoryRegion, DefaultPlacement: "d",
		Placements: map[string]PlacementConfig{"d": {}},
		Registry:   &RegistryConfig{NamePrefix: "apphub/", ImmutableTags: immutable},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &imageRegistry{p: p}
}

// mutatingECRCalls is every ECRAPI method that changes something.
//
// Enumerated rather than pattern-matched on the name, so that a method added
// later is absent from this set and the test that uses it silently stops
// covering it — which is why [TestEveryMutatingCallIsPrecededByItsOwnProof] also
// asserts the set is complete against the interface.
var mutatingECRCalls = map[string]bool{
	"CreateRepository":              true,
	"DeleteRepository":              true,
	"PutImageScanningConfiguration": true,
	"PutImageTagMutability":         true,
	"PutLifecyclePolicy":            true,
	"DeleteLifecyclePolicy":         true,
	"TagResource":                   true,
	"UntagResource":                 true,
}

// TestEveryMutatingCallIsPrecededByItsOwnProof.
//
// Round four moved the ownership check next to the last write in Ensure. Round
// five found that this said nothing about the three writes before it: a
// repository whose ownership marker was removed after the create-or-adopt read
// had its scanning configuration changed, and only then got ErrNotOwned from the
// lifecycle step. The mutation stood.
//
// So the property is not "the write that had a bug now checks". It is
// structural, and this asserts it as a structure: **every mutating ECR call is
// immediately preceded by the ListTags that authorised it.** The one exception
// is CreateRepository, whose authorisation is a DescribeRepository that reported
// the name free — there are no tags on a repository that does not exist yet.
//
// Stated over the call sequence rather than over the code so that a fifth write
// added later cannot pass by being written in the same style as the other four.
//
// # What this test cannot see, and what covers it
//
// It is necessary and it is not sufficient. A stale proof and a fresh one look
// identical in the sequence when nothing ran between them, so the FIRST write
// after the create-or-adopt read satisfies "immediately preceded by ListTags"
// whether or not it re-read. Against the round-four code this test flagged the
// second, third and fourth writes and said nothing about the first — which is
// the one review actually caught. [TestARevokedOwnershipStopsTheFirstWriteAndNotJustTheLast]
// is what covers it, by changing the answer between the read and the write.
// Neither test alone would have failed on the whole defect.
func TestEveryMutatingCallIsPrecededByItsOwnProof(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The set above is only as good as its completeness.
	var api ECRAPI = (*MemoryECR)(nil)
	typ := reflect.TypeOf(&api).Elem()
	readOnly := map[string]bool{
		"DescribeRepository": true, "DescribeImage": true, "GetLifecyclePolicy": true, "ListTags": true,
	}
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		if !mutatingECRCalls[name] && !readOnly[name] {
			t.Fatalf("ECRAPI.%s is in neither mutatingECRCalls nor the read-only set, so this "+
				"test does not know whether it needs a proof", name)
		}
	}

	sub, spy, _ := spiedSubstrate(t)
	if _, err := registryOver(t, sub, false).EnsureRepository(ctx, compute.RepositorySpec{
		Name: "app", Labels: map[string]string{"team": "core"},
	}); err != nil {
		t.Fatalf("first EnsureRepository: %v", err)
	}

	// A second converge, through a provider whose operator configuration turned
	// tag immutability on, driving every remaining write: scanning changes,
	// immutability changes, one label is added and another removed, and a
	// retention policy appears.
	reg := registryOver(t, sub, true)
	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name:       "app",
		ScanOnPush: true,
		Labels:     map[string]string{"owner": "platform"},
		Retention:  compute.RetentionPolicy{KeepLast: 5},
	}); err != nil {
		t.Fatalf("second EnsureRepository: %v", err)
	}
	if err := reg.DeleteRepository(ctx,
		reg.p.ref(compute.KindImageRepository, "apphub/app")); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	seen := map[string]bool{}
	seq := spy.seq()
	for i, call := range seq {
		if !mutatingECRCalls[call] {
			continue
		}
		seen[call] = true
		want := "ListTags"
		if call == "CreateRepository" {
			want = "DescribeRepository"
		}
		if i == 0 || seq[i-1] != want {
			got := "nothing"
			if i > 0 {
				got = seq[i-1]
			}
			t.Errorf("%s ran with %s immediately before it, want %s. A write authorised by "+
				"anything older than the call before it is a write on elapsed proof.\nsequence: %v",
				call, got, want, seq)
		}
	}
	for call := range mutatingECRCalls {
		if !seen[call] {
			t.Errorf("%s was never driven, so this test says nothing about it", call)
		}
	}
}

// TestARevokedOwnershipStopsTheFirstWriteAndNotJustTheLast.
//
// The witness for the finding above, at the port rather than at the structure:
// ownership is revoked after Ensure's create-or-adopt read has returned owned,
// and before any write. The call must refuse, and it must refuse having changed
// nothing.
//
// Against the round-four code it refused — from the lifecycle step — after
// having already set ScanOnPush. Asserting only the error is what let that
// through, so the assertion here is on the repository.
func TestARevokedOwnershipStopsTheFirstWriteAndNotJustTheLast(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sub, spy, mem := spiedSubstrate(t)
	reg := registryOver(t, sub, false)
	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"}); err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	arn := repositoryARN("apphub/app")

	// Revoke ownership the instant the create-or-adopt read returns, which is
	// the interval a pre-call change cannot reach.
	var once sync.Once
	spy.mu.Lock()
	spy.after = func(call string) {
		if call != "ListTags" {
			return
		}
		once.Do(func() {
			if err := mem.UntagResource(ctx, arn, []string{tagManagedBy}); err != nil {
				t.Errorf("revoking ownership: %v", err)
			}
		})
	}
	spy.mu.Unlock()

	_, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name:       "app",
		ScanOnPush: true,
		Retention:  compute.RetentionPolicy{KeepLast: 5},
	})
	if err == nil {
		t.Fatal("Ensure converged a repository this platform no longer owns")
	}
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("refused with %v, want compute.ErrNotOwned", err)
	}
	rec, err := mem.DescribeRepository(ctx, "apphub/app")
	if err != nil {
		t.Fatalf("DescribeRepository: %v", err)
	}
	if rec.ScanOnPush {
		t.Error("the refusal left ScanOnPush changed on a repository this platform does not own: " +
			"the ownership proof gated the last write and not the first")
	}
	if _, err := mem.GetLifecyclePolicy(ctx, "apphub/app"); err == nil {
		t.Error("a lifecycle policy was written despite the refusal")
	}
}
