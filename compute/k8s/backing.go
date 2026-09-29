// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"time"

	"github.com/conductorone/apphub/compute"
)

// This file holds the seams for the two substrates that are not the cluster.
//
// # Why they exist
//
// USOSS-27 put a [Cluster] interface between the provider and the API server, and
// that is what made a production client a few hundred lines instead of a rewrite.
// It did not do the same for the registry or the object store: [MemoryRegistry]
// and [MemoryObjectStore] were reached directly, as concrete types, so they were
// not *an* implementation — they were the only one it was possible to have.
//
// Both interfaces below take a [context.Context] and return an error on every
// method. Neither the in-memory registry nor the in-memory store needed either,
// which is exactly the tell: an in-memory substrate cannot fail and cannot be
// cancelled, so a seam shaped around one silently makes both unrepresentable. A
// real client is a network call, and a network call needs a deadline it can be
// held to and a failure it can report. Adding them is most of what turned these
// from concrete types into seams.
//
// # What crosses them
//
// Value types ([RepositoryState], [BucketState]) rather than the internal
// structs. The internals carry things a real substrate does not have — an
// in-memory map of stored objects, a table of minted tokens — and a seam that
// exposed them would oblige every implementation to model an in-memory store's
// bookkeeping.

// ErrBackingTransient is what a real [Registry] or [ObjectStore] client returns
// for a failure a retry would fix: a 5xx, a 429, a dialling error, a reset
// connection.
//
// It exists so the mapping onto [compute.ErrTransient] is a decision the client
// makes — it is the only layer that knows an HTTP status code — rather than a
// guess the provider makes from a string. The in-memory implementations never
// return it, because an in-memory map has no transient failures, which is
// precisely why USOSS-27 had no reason to invent it.
var ErrBackingTransient = errors.New("k8s: the backing service failed in a way a retry may fix")

// RepositoryState is what an OCI registry knows about one repository.
type RepositoryState struct {
	// Name is the repository name within the registry's project.
	Name string
	// KeepLast and MaxAge are the retention policy. A registry with no
	// lifecycle feature must refuse them rather than accept them and not apply
	// them; the provider checks [RegistryConfig.SupportsRetention] before it
	// gets here.
	KeepLast int
	MaxAge   time.Duration
	// ScanOnPush requests vulnerability scanning on push.
	ScanOnPush bool
	// Labels are the caller's labels, as the provider chose to carry them.
	Labels map[string]string
	// Owned reports whether this platform created the repository. A repository
	// that exists and is not owned is [compute.ErrNotOwned], which is the check
	// every Ensure on every port has to make.
	Owned bool
}

// BucketState is what an object store knows about one bucket.
type BucketState struct {
	// Name is the bucket name, after the store's naming rules have been applied.
	Name string
	// Class is the durability/latency class the bucket was created with.
	Class compute.ObjectClass
	// PublicRead reports whether anonymous read access is permitted. It is
	// applied rather than merely recorded: the store's anonymous-read path
	// consults it, so a provider that dropped it would create a public bucket
	// while reporting a private one.
	PublicRead bool
	// Labels are the caller's labels.
	Labels map[string]string
	// Claim is what the store's own record says about who manages this bucket.
	//
	// It is a three-answer question rather than a bool, and that is not a
	// refinement -- it is the whole ownership contract for a substrate that
	// cannot create conditionally. See [BucketClaim].
	Claim BucketClaim
}

// BucketClaim is what a store's record of a bucket says about who manages it.
//
// # Why ownership is three answers here and a bool everywhere else
//
// [RepositoryState.Owned] is a bool because a registry's repository either
// carries this platform's marker or does not. An object store has a third state
// that matters, because **S3 cannot create a bucket conditionally**: there is no
// create-if-absent that fails when the name is taken, so a bucket that exists and
// carries no tags at all is genuinely ambiguous between
//
//   - one this provider created a millisecond ago and failed to tag, and
//   - one another actor in this account created and has not tagged.
//
// Collapsing that into "not ours" makes the provider unable to recover from its
// own partial failure, permanently, on a bucket it really does own. Collapsing it
// into "ours" adopts anything untagged. Neither bool is right, so the answer is
// not a bool.
//
// # One vocabulary, on purpose
//
// This type exists because there used to be two ownership authorities that
// disagreed: a bool on this struct, read by [objectStore.EnsureBucket], and a
// three-state assessment inside [S3ObjectStore.PutBucket]. The lower one was
// correct and unreachable -- `EnsureBucket` refused an untagged bucket before
// `PutBucket` ever ran, so the fix and its test agreed with each other while the
// original reproduction still failed. Both paths now read this one field, derived
// by one classifier.
type BucketClaim int

const (
	// ClaimUnknown is the zero value and is refused. A caller that forgot to set
	// the claim gets a refusal rather than an adoption, because the failure that
	// matters here is fail-open.
	ClaimUnknown BucketClaim = iota
	// ClaimOurs means this platform's ownership marker is present.
	ClaimOurs
	// ClaimUnclaimed means the store holds no record of who manages the bucket:
	// for S3, no tags at all. Claiming it is permitted. See [BucketClaim] for
	// why this is not folded into ClaimForeign.
	ClaimUnclaimed
	// ClaimForeign means the store's record names a manager and it is not this
	// platform. Refused.
	ClaimForeign
)

// Claimable reports whether an Ensure may write to a bucket in this state.
//
// It is a method rather than a comparison at each call site so that adding a
// fourth answer cannot silently read as claimable at one of them.
func (c BucketClaim) Claimable() bool { return c == ClaimOurs || c == ClaimUnclaimed }

// String implements [fmt.Stringer] so a refusal can name the state it saw.
func (c BucketClaim) String() string {
	switch c {
	case ClaimOurs:
		return "managed by this platform"
	case ClaimUnclaimed:
		return "unclaimed"
	case ClaimForeign:
		return "managed by something else"
	default:
		return "unknown"
	}
}

// Registry is the OCI registry operations this provider needs.
//
// # What a real implementation of this runs into, which is a finding
//
// Only two of these methods correspond to anything in a vendor-neutral registry
// API. The OCI Distribution specification covers pulling and pushing content and
// the token exchange that authorises them — [Registry.Pull] and [Registry.Push],
// more or less. It has no notion of *creating* a repository (a repository comes
// into existence when something is pushed to it), no retention policy, no
// vulnerability scanning, no robot accounts, and no per-repository authorisation
// grants.
//
// Every one of those is required by [compute.ImageRegistry], and every one of
// them is a *vendor control-plane* API: Harbor's, GAR's, ECR's, and Quay's are
// four different APIs with four different authentication models. So "a real
// registry client" is not one thing a Kubernetes provider can have — it is a
// fifth substrate choice on top of the four [Substrate] already admits to, and
// which one is installed is operator configuration in the same way the Postgres
// operator's kind is. See the USOSS-19 report for why this branch ships the seam
// and declines to invent a client for an API it cannot verify against.
type Registry interface {
	// GetRepository returns a repository's state, or false if it does not exist.
	GetRepository(ctx context.Context, name string) (RepositoryState, bool, error)

	// PutRepository creates or updates a repository. Idempotent. It must
	// preserve grants already made against the repository: the provider
	// re-Ensures a repository on every reconcile, and dropping the grants would
	// revoke every workload's pull access as a side effect of a no-op.
	PutRepository(ctx context.Context, state RepositoryState) error

	// DeleteRepository removes a repository. Deleting an absent one is not an
	// error.
	DeleteRepository(ctx context.Context, name string) error

	// RepositoryNames lists the repositories in the registry's project, so that
	// deleting a workload identity can revoke everything granted to it.
	RepositoryNames(ctx context.Context) ([]string, error)

	// MintCredential returns a registry credential for subject, creating one if
	// there is none. It must be idempotent per subject: a second call for the
	// same subject returns the same credential rather than leaving the first one
	// live and unrotated.
	//
	// This is the method finding F1 is about. It exists because most registries
	// cannot authorise a Kubernetes ServiceAccount, so the only way to let a
	// workload pull is to create long-lived credential material and attach it.
	// A configuration that does not need it never calls it.
	MintCredential(ctx context.Context, subject string) (string, error)

	// CredentialFor returns the credential already minted for subject, if any,
	// without minting one.
	CredentialFor(ctx context.Context, subject string) (string, bool, error)

	// Grant authorises a principal — a minted credential, or a ServiceAccount
	// subject on a registry that federates the cluster's issuer — against a
	// repository at level. Last-write-wins, because narrowing an existing grant
	// must actually narrow it.
	Grant(ctx context.Context, repository, principal string, level compute.AccessLevel) error

	// Revoke removes a principal's authorisation. Revoking one that has none is
	// not an error.
	Revoke(ctx context.Context, repository, principal string) error

	// Pull and Push attempt a data-plane operation as a principal, and they are
	// NOT the same kind of method as each other.
	//
	// Pull exists for the conformance harness: the compute contract states that a
	// workload can pull the image its own spec names, and nothing else in this
	// interface can observe whether that is true. It has no production caller.
	//
	// Push has one. [imageBuilder.Build] pushes the images it built, which is what
	// a builder is for. So Push is an ordinary mutating data-plane operation that
	// the harness also happens to drive -- not a probe.
	//
	// The previous version of this comment said both existed for the harness, and
	// that was false about Push when it was written: Build already called it. A
	// doc comment claiming a method exists for one purpose is a checkable assertion
	// about its call sites, and nothing checked it. See the USOSS-74 decision entry
	// on why this interface's own comments could not be used to derive which
	// methods an acceptance phase may call.
	Pull(ctx context.Context, repository, principal string) error
	Push(ctx context.Context, repository, principal string) error

	// Describe renders the registry's state one line per repository, for the
	// conformance suite's Rendered hook. It must never include credential
	// material: the suite scans the output for secret values.
	Describe(ctx context.Context, host, project string) ([]string, error)
}

// ObjectStore is the S3-compatible object-store operations this provider needs.
//
// Unlike [Registry], every method here does correspond to a specified,
// vendor-neutral API call — CreateBucket, HeadBucket, DeleteBucket,
// PutBucketPolicy, DeleteBucketPolicy, GetObject, PutObject — which is why
// [S3ObjectStore] is a real client and there is no equivalent for the registry.
type ObjectStore interface {
	// GetBucket returns a bucket's state, or false if it does not exist.
	GetBucket(ctx context.Context, name string) (BucketState, bool, error)

	// PutBucket creates or updates a bucket. Idempotent, and it must preserve
	// the bucket's existing policies and contents for the same reason
	// [Registry.PutRepository] must preserve grants.
	PutBucket(ctx context.Context, state BucketState) error

	// DeleteBucket removes a bucket. It does not empty it first: a provider must
	// not silently delete data a caller did not know was there, and a caller that
	// wants the data gone says so with EmptyBucket.
	DeleteBucket(ctx context.Context, name string) error

	// EmptyBucket permanently deletes every object in a bucket, every noncurrent
	// version and delete marker included. An absent bucket is not an error.
	// Ownership is not this method's concern: [objectStore.EmptyBucket] checks
	// the claim before it calls this, the way it does before every other write.
	EmptyBucket(ctx context.Context, name string) error

	// BucketNames lists the buckets, so that deleting a workload identity can
	// revoke everything granted to it.
	BucketNames(ctx context.Context) ([]string, error)

	// SetPolicy authorises an OIDC subject against a bucket at level.
	// Last-write-wins.
	SetPolicy(ctx context.Context, bucket, subject string, level compute.AccessLevel) error

	// ClearPolicy removes a subject's authorisation.
	ClearPolicy(ctx context.Context, bucket, subject string) error

	// GetPolicy reports the level a subject is authorised at, and whether it is
	// authorised at all.
	//
	// The bool rather than an error for the absent case, because "this subject has
	// no access" is an ordinary answer here and a store that made it an error
	// would put its own sentinel in front of [compute.Granter.DescribeGrant]'s.
	// A missing *bucket* is still an error.
	//
	// It is the read half of SetPolicy and belongs to whoever implements that
	// half: a store that cannot express a grant cannot report one either, and
	// [S3ObjectStore] refuses all three together rather than pretending the read
	// is cheaper than the write.
	GetPolicy(ctx context.Context, bucket, subject string) (compute.AccessLevel, bool, error)

	// Read and Write attempt a data-plane operation as an OIDC subject, for the
	// conformance harness.
	Read(ctx context.Context, bucket, subject string) error
	Write(ctx context.Context, bucket, subject string) error

	// AnonymousRead attempts an unauthenticated read, which is how
	// "public access is off unless it was asked for" is checked.
	AnonymousRead(ctx context.Context, bucket string) error

	// Describe renders the store's state one line per bucket, for the
	// conformance suite's Rendered hook.
	Describe(ctx context.Context, scheme string) ([]string, error)
}

var (
	_ Registry    = (*MemoryRegistry)(nil)
	_ ObjectStore = (*MemoryObjectStore)(nil)
)

// --- MemoryRegistry implements Registry ----------------------------------------
//
// These are adapters over the in-memory bookkeeping below, not a second
// implementation of it. Each ignores its context, and says so, because an
// in-memory map cannot be cancelled — which is the reason a seam derived from
// this type alone would have had no context at all.

// GetRepository implements [Registry].
func (r *MemoryRegistry) GetRepository(_ context.Context, name string) (RepositoryState, bool, error) {
	if err := r.injected(); err != nil {
		return RepositoryState{}, false, err
	}
	repo, ok := r.get(name)
	if !ok {
		return RepositoryState{}, false, nil
	}
	return RepositoryState{
		Name:       repo.name,
		KeepLast:   repo.keepLast,
		MaxAge:     repo.maxAge,
		ScanOnPush: repo.scanOnPush,
		Labels:     copyLabels(repo.labels),
		Owned:      repo.owned,
	}, true, nil
}

// PutRepository implements [Registry].
func (r *MemoryRegistry) PutRepository(_ context.Context, state RepositoryState) error {
	if err := r.injected(); err != nil {
		return err
	}
	r.put(&registryRepository{
		name:       state.Name,
		keepLast:   state.KeepLast,
		maxAge:     state.MaxAge,
		scanOnPush: state.ScanOnPush,
		labels:     copyLabels(state.Labels),
		owned:      state.Owned,
	})
	return nil
}

// DeleteRepository implements [Registry].
func (r *MemoryRegistry) DeleteRepository(_ context.Context, name string) error {
	if err := r.injected(); err != nil {
		return err
	}
	r.delete(name)
	return nil
}

// RepositoryNames implements [Registry].
func (r *MemoryRegistry) RepositoryNames(_ context.Context) ([]string, error) {
	if err := r.injected(); err != nil {
		return nil, err
	}
	return r.repoNames(), nil
}

// MintCredential implements [Registry].
func (r *MemoryRegistry) MintCredential(_ context.Context, subject string) (string, error) {
	if err := r.injected(); err != nil {
		return "", err
	}
	return r.mintRobot(subject), nil
}

// CredentialFor implements [Registry].
func (r *MemoryRegistry) CredentialFor(_ context.Context, subject string) (string, bool, error) {
	if err := r.injected(); err != nil {
		return "", false, err
	}
	token, ok := r.robotFor(subject)
	return token, ok, nil
}

// Grant implements [Registry].
func (r *MemoryRegistry) Grant(_ context.Context, repository, principal string, level compute.AccessLevel) error {
	if err := r.injected(); err != nil {
		return err
	}
	return r.grant(repository, principal, level)
}

// Revoke implements [Registry].
func (r *MemoryRegistry) Revoke(_ context.Context, repository, principal string) error {
	if err := r.injected(); err != nil {
		return err
	}
	r.revoke(repository, principal)
	return nil
}

// Describe implements [Registry].
func (r *MemoryRegistry) Describe(_ context.Context, host, project string) ([]string, error) {
	if err := r.injected(); err != nil {
		return nil, err
	}
	return r.dump(host, project), nil
}

// --- MemoryObjectStore implements ObjectStore ----------------------------------

// GetBucket implements [ObjectStore].
func (s *MemoryObjectStore) GetBucket(_ context.Context, name string) (BucketState, bool, error) {
	if err := s.injected(); err != nil {
		return BucketState{}, false, err
	}
	b, ok := s.get(name)
	if !ok {
		return BucketState{}, false, nil
	}
	return BucketState{
		Name:       b.name,
		Class:      b.class,
		PublicRead: b.publicRead,
		Labels:     copyLabels(b.labels),
		Claim:      b.claim,
	}, true, nil
}

// PutBucket implements [ObjectStore].
func (s *MemoryObjectStore) PutBucket(_ context.Context, state BucketState) error {
	if err := s.injected(); err != nil {
		return err
	}
	s.put(&storeBucket{
		name:       state.Name,
		class:      state.Class,
		publicRead: state.PublicRead,
		labels:     copyLabels(state.Labels),
		claim:      state.Claim,
	})
	return nil
}

// DeleteBucket implements [ObjectStore].
func (s *MemoryObjectStore) DeleteBucket(_ context.Context, name string) error {
	if err := s.injected(); err != nil {
		return err
	}
	s.delete(name)
	return nil
}

// EmptyBucket implements [ObjectStore].
func (s *MemoryObjectStore) EmptyBucket(_ context.Context, name string) error {
	if err := s.injected(); err != nil {
		return err
	}
	s.empty(name)
	return nil
}

// BucketNames implements [ObjectStore].
func (s *MemoryObjectStore) BucketNames(_ context.Context) ([]string, error) {
	if err := s.injected(); err != nil {
		return nil, err
	}
	return s.bucketNames(), nil
}

// SetPolicy implements [ObjectStore].
func (s *MemoryObjectStore) SetPolicy(_ context.Context, bucket, subject string, level compute.AccessLevel) error {
	if err := s.injected(); err != nil {
		return err
	}
	return s.setPolicy(bucket, subject, level)
}

// ClearPolicy implements [ObjectStore].
func (s *MemoryObjectStore) ClearPolicy(_ context.Context, bucket, subject string) error {
	if err := s.injected(); err != nil {
		return err
	}
	s.clearPolicy(bucket, subject)
	return nil
}

// GetPolicy implements [ObjectStore].
func (s *MemoryObjectStore) GetPolicy(_ context.Context, bucket, subject string) (compute.AccessLevel, bool, error) {
	if err := s.injected(); err != nil {
		return "", false, err
	}
	return s.getPolicy(bucket, subject)
}

// Describe implements [ObjectStore].
func (s *MemoryObjectStore) Describe(_ context.Context, scheme string) ([]string, error) {
	if err := s.injected(); err != nil {
		return nil, err
	}
	return s.dump(scheme), nil
}
