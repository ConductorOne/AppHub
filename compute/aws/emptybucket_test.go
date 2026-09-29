// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// memoryS3 returns the in-memory S3 substrate behind a store from newObjectStore.
func memoryS3(t *testing.T, sub *aws.Substrate) *aws.MemoryS3 {
	t.Helper()
	mem, ok := sub.S3.(*aws.MemoryS3)
	if !ok {
		t.Fatalf("the substrate's object store is a %T", sub.S3)
	}
	return mem
}

// countOps counts how many times op appears in a substrate trace.
func countOps(trace []string, op string) int {
	n := 0
	for _, got := range trace {
		if got == op {
			n++
		}
	}
	return n
}

// TestEmptyBucketRemovesEveryVersionAcrossPages is the property EmptyBucket
// exists for: after it, DeleteBucket succeeds on a versioned bucket that a plain
// object listing already reports as empty.
//
// # Why the control runs first
//
// The bucket holds a key whose every version sits under a delete marker, which is
// what an application's own "delete" leaves in a versioned bucket. IsEmpty lists
// objects and answers true for that bucket, so DeleteBucket gets past its own
// precondition and S3 refuses it. The control asserts that refusal. Without it,
// an EmptyBucket that listed objects rather than versions would pass this test,
// because the bucket it failed to clear would never have been tried.
//
// # Why 2,204 entries
//
// More than two pages of S3's 1,000-key limit, so the loop has to go round three
// times and the last page is a partial one. A bucket that fit in one page would
// pass an implementation that never looped.
func TestEmptyBucketRemovesEveryVersionAcrossPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, sub, store := newObjectStore(t)
	mem := memoryS3(t, sub)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "versioned"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	mem.PutObjectVersions(bucket.Name, "deleted-by-the-app", 1200, true)

	empty, err := mem.IsEmpty(ctx, bucket.Name)
	if err != nil {
		t.Fatalf("IsEmpty(): %v", err)
	}
	if !empty {
		t.Fatal("control: a bucket whose only key is under a delete marker lists no objects in " +
			"S3, and the memory substrate says it does; the rest of this test would not be " +
			"exercising the version-only case")
	}
	if err := store.DeleteBucket(ctx, bucket.Ref); err == nil {
		t.Fatal("control: DeleteBucket succeeded on a bucket holding noncurrent versions, so " +
			"the substrate does not model S3's refusal and emptying proves nothing here")
	}

	mem.PutObjectVersions(bucket.Name, "live", 1000, false)
	for range 3 {
		mem.PutObject(bucket.Name)
	}

	mem.ResetOperations()
	if err := store.EmptyBucket(ctx, bucket.Ref); err != nil {
		t.Fatalf("EmptyBucket(): %v", err)
	}
	trace := mem.Operations()
	if got := countOps(trace, "DeleteObjectVersions"); got != 3 {
		t.Errorf("EmptyBucket issued %d batch deletes for 2,204 versions, want 3: one per page "+
			"of at most 1,000", got)
	}
	if got := countOps(trace, "ListObjectVersions"); got != 4 {
		t.Errorf("EmptyBucket listed %d times, want 4: three pages and the empty listing that "+
			"ends the loop", got)
	}

	if _, err := store.DescribeBucket(ctx, bucket.Ref); err != nil {
		t.Errorf("the bucket is unreadable after EmptyBucket: %v. Emptying removes the data and "+
			"must leave the bucket", err)
	}
	if err := store.DeleteBucket(ctx, bucket.Ref); err != nil {
		t.Fatalf("DeleteBucket after EmptyBucket: %v", err)
	}
	if _, err := store.DescribeBucket(ctx, bucket.Ref); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("DescribeBucket after the delete = %v, want compute.ErrNotFound", err)
	}
}

// TestEmptyBucketRefusesABucketItDoesNotOwn checks that nothing is deleted before
// the refusal, not only that the refusal comes back.
//
// An implementation that listed and deleted first and checked the tags on the way
// out would return the same ErrNotOwned, and the stranger's data would be gone.
// So the trace is read as well as the error.
func TestEmptyBucketRefusesABucketItDoesNotOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, sub, store := newObjectStore(t)
	mem := memoryS3(t, sub)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "theirs"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	mem.PutUnowned(bucket.Name, aws.MemoryRegion)
	mem.PutObject(bucket.Name)

	mem.ResetOperations()
	if err := store.EmptyBucket(ctx, bucket.Ref); !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("EmptyBucket on an unowned bucket = %v, want compute.ErrNotOwned", err)
	}
	for _, op := range []string{"ListObjectVersions", "DeleteObjectVersions"} {
		if slices.Contains(mem.Operations(), op) {
			t.Errorf("EmptyBucket called %s on a bucket it does not own before refusing", op)
		}
	}
	empty, err := mem.IsEmpty(ctx, bucket.Name)
	if err != nil {
		t.Fatalf("IsEmpty(): %v", err)
	}
	if empty {
		t.Error("the unowned bucket's object is gone after a refused EmptyBucket")
	}
}

// TestEmptyBucketOnAnAbsentBucketIsNil is idempotence at the end of a teardown:
// a retry that runs after the bucket was deleted meets no bucket, and absent is
// empty.
func TestEmptyBucketOnAnAbsentBucketIsNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, _, store := newObjectStore(t)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "gone"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	if err := store.DeleteBucket(ctx, bucket.Ref); err != nil {
		t.Fatalf("DeleteBucket(): %v", err)
	}
	if err := store.EmptyBucket(ctx, bucket.Ref); err != nil {
		t.Errorf("EmptyBucket on a deleted bucket = %v, want nil", err)
	}
}

// TestEmptyBucketThrottlingIsTransient covers both substrate calls the loop makes.
//
// Each is targeted by name, and the trace confirms the targeted call happened: an
// armed failure the loop never reached would leave the error nil, and a test
// asserting only on a non-nil error would be asserting on nothing.
func TestEmptyBucketThrottlingIsTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, op := range []string{"ListObjectVersions", "DeleteObjectVersions"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem := memoryS3(t, sub)
			bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "throttled"})
			if err != nil {
				t.Fatalf("EnsureBucket(): %v", err)
			}
			mem.PutObject(bucket.Name)

			mem.ResetOperations()
			stop := mem.FailOn(op, aws.ErrThrottled)
			err = store.EmptyBucket(ctx, bucket.Ref)
			stop()
			if !slices.Contains(mem.Operations(), op) {
				t.Fatalf("EmptyBucket never called %s, so the armed throttle proves nothing", op)
			}
			if !errors.Is(err, compute.ErrTransient) {
				t.Errorf("EmptyBucket throttled at %s = %v, want compute.ErrTransient", op, err)
			}
			if err := store.EmptyBucket(ctx, bucket.Ref); err != nil {
				t.Errorf("EmptyBucket retried after the throttle cleared: %v", err)
			}
		})
	}
}

// TestEmptyBucketStopsWhenCancelled checks cancellation stops the deletion before
// any batch is sent, and is reported as the cancellation rather than as a retry.
func TestEmptyBucketStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	_, sub, store := newObjectStore(t)
	mem := memoryS3(t, sub)
	bucket, err := store.EnsureBucket(context.Background(), compute.BucketSpec{Name: "cancelled"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	mem.PutObject(bucket.Name)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mem.ResetOperations()
	err = store.EmptyBucket(ctx, bucket.Ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("EmptyBucket with a cancelled context = %v, want context.Canceled", err)
	}
	if errors.Is(err, compute.ErrTransient) {
		t.Error("a cancelled EmptyBucket answered ErrTransient, which tells the caller to retry " +
			"the call it just cancelled")
	}
	if slices.Contains(mem.Operations(), "DeleteObjectVersions") {
		t.Error("EmptyBucket sent a batch delete after its context was cancelled")
	}
}

// TestMemoryS3RefusesAnOversizedBatchDelete pins the substrate's own limit, which
// is S3's: a batch of more than 1,000 keys is malformed.
func TestMemoryS3RefusesAnOversizedBatchDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, sub, store := newObjectStore(t)
	mem := memoryS3(t, sub)
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "oversized"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	err = mem.DeleteObjectVersions(ctx, bucket.Name, make([]aws.ObjectVersion, 1001))
	if !errors.Is(err, aws.ErrMalformed) {
		t.Errorf("a 1,001-key batch delete = %v, want aws.ErrMalformed", err)
	}
}
