// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import "context"

// ObjectClass is the storage class of a bucket.
//
// The source system has four bucket "types" (bucket.go:157-179), and they are
// not four points on one axis — they are two different kinds of difference. A
// general bucket and a directory bucket differ in *placement and latency* while
// presenting the same API and the same binding to the application. A table
// bucket and a vector bucket differ in *what the application talks to*: a
// different API, a different client library, different environment variables
// (bucket.go:394-412).
//
// So the first difference is a class here, with a capability
// ([CapObjectStoreZonal]) for the substrates that lack it, and the second is not
// in this interface at all — see compute/ext.
type ObjectClass string

const (
	// ObjectClassStandard is durable, multi-zone object storage. Every provider
	// with [CapObjectStore] has it.
	ObjectClassStandard ObjectClass = "standard"

	// ObjectClassZonal is object storage pinned to one availability zone for
	// lower latency, at the cost of zone-level durability. Requires
	// [CapObjectStoreZonal]. A provider without it must return
	// [ErrUnsupported]: the caller asked for a latency property, and quietly
	// giving them a standard bucket would satisfy the type signature while
	// breaking the reason they asked.
	ObjectClassZonal ObjectClass = "zonal"
)

// BucketSpec describes an object-storage bucket.
type BucketSpec struct {
	// Name is the requested bucket name. The provider applies its namespace
	// rules and returns the actual name in [Bucket.Name]; the two may differ
	// and the caller must use what came back. Determinism is required: the same
	// Name must always yield the same physical bucket, because teardown has to
	// find a bucket whose provisioned name may never have been persisted
	// (bucket.go:81-88).
	Name string

	// Class is the storage class. Empty means [ObjectClassStandard].
	Class ObjectClass

	// Zone selects the availability zone for [ObjectClassZonal]. It is an
	// operator-supplied, provider-defined string, opaque to this interface.
	// Required for zonal, [ErrInvalidSpec] for any other class.
	Zone string

	// PublicAccess allows anonymous read. Defaults to false, and a provider
	// must apply whatever blocks its substrate offers to make false actually
	// mean it — the source system sets all four S3 public-access-block flags
	// (bucket.go:245-253), and an implementation that merely omits a public
	// policy is not equivalent.
	PublicAccess bool

	// Labels are non-secret metadata for ownership tagging.
	Labels map[string]string
}

// Bucket is a provisioned bucket.
type Bucket struct {
	// Ref addresses the bucket.
	Ref Ref
	// Name is the bucket's actual name, after the provider's namespace rules.
	Name string
	// Class is the storage class it was created with.
	Class ObjectClass
	// URI is a client-usable address for the bucket, in whatever scheme the
	// provider's clients expect ("s3://name", "gs://name"). Opaque to this
	// interface; handed to the application so it can find its own storage.
	URI string
	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec BucketSpec
}

// ObjectStore provisions object-storage buckets.
//
// # What the caller does with the result, and what it must not do
//
// The application learns about its bucket through environment variables the
// deploy module composes — the source system's APP_S3_BUCKET_NAME and friends
// (bucket.go:394-412). Those names are an apphub convention, not a provider
// one, so composing them stays above this interface. The provider returns
// facts; the module decides what to call them.
//
// Encryption at rest is not a field. Every substrate this targets encrypts by
// default or can be configured to at the account level, and the source system
// only ever sets the provider default (bucket.go:259-270). A provider must
// ensure buckets it creates are encrypted at rest; making it optional would
// invite a spec that turns it off.
//
// # Sketch: how a Kubernetes provider satisfies this
//
// Kubernetes has no object storage, so a "Kubernetes provider" here means a
// provider configured against whatever object store the cluster's operator
// runs — MinIO, Ceph RGW, or a cloud bucket service. [ObjectClassStandard],
// PublicAccess, and Grant map cleanly onto any S3-compatible implementation.
// [ObjectClassZonal] usually does not, and that provider simply does not
// advertise [CapObjectStoreZonal].
type ObjectStore interface {
	Granter

	// EnsureBucket creates or updates a bucket. Idempotent: an existing bucket
	// this platform owns is returned as-is, and one it does not own is
	// [ErrNotOwned].
	EnsureBucket(ctx context.Context, spec BucketSpec) (*Bucket, error)

	// DescribeBucket returns an existing bucket, or [ErrNotFound].
	DescribeBucket(ctx context.Context, ref Ref) (*Bucket, error)

	// DeleteBucket removes a bucket. Idempotent.
	//
	// DeleteBucket never empties a bucket first: removing the objects is a
	// destructive-data decision, and a teardown must not make it as a side
	// effect. A caller that has made it says so by calling [ObjectStore.EmptyBucket]
	// first. What DeleteBucket does with a non-empty bucket still differs per
	// substrate -- refuse it, or leave the objects to a lifecycle rule -- and a
	// provider must document its behaviour and must not silently delete objects a
	// caller did not know were there.
	DeleteBucket(ctx context.Context, ref Ref) error

	// EmptyBucket permanently deletes every object in a bucket this platform owns,
	// including every noncurrent version and delete marker, so a following
	// DeleteBucket can succeed. Idempotent: an absent or already-empty bucket
	// returns nil. A bucket this platform does not own is [ErrNotOwned].
	//
	// A separate method rather than a flag on DeleteBucket because it is the
	// destructive half, and a caller should have to name it. Nothing it removes
	// can be recovered, so a caller reaches it only on an explicit decision to
	// destroy the data -- deleting the application that owns the bucket -- and
	// never from a reconcile.
	EmptyBucket(ctx context.Context, ref Ref) error
}
