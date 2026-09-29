// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/conductorone/apphub/compute"
)

// substrateEpoch is the fixed instant the logical clock counts from. A fixed
// epoch keeps a run reproducible; a non-zero one keeps [compute.Status.UpdatedAt]
// distinguishable from "never observed".
var substrateEpoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

var substrateTicks atomic.Int64

func (s *Substrate) clock() *logicalClock {
	return &logicalClock{base: substrateEpoch, tick: func() int64 { return substrateTicks.Add(1) }}
}

// --- OCI registry --------------------------------------------------------------

// ErrRegistryDenied is the registry's 403.
var ErrRegistryDenied = errors.New("k8s: the registry refused the credential")

// registryRepository is one repository in the registry's project.
type registryRepository struct {
	name       string
	keepLast   int
	maxAge     time.Duration
	scanOnPush bool
	labels     map[string]string
	owned      bool
	// grants maps a *principal* onto what it may do. A principal is either a
	// robot account's token or, on a registry that federates the cluster's OIDC
	// issuer, a ServiceAccount subject. Which of the two a provider ends up
	// using is the whole of finding F1; see [MemoryRegistry].
	grants map[string]compute.AccessLevel
}

// MemoryRegistry stands in for Harbor, GAR, or ECR.
//
// # Why this type exists in this shape
//
// It can authenticate a principal two ways, and which ways a given registry
// offers is the substance of finding F1:
//
//   - A **robot account holding a token**, which every OCI registry does. The
//     token has to be created, stored somewhere the kubelet can read it, and
//     rotated by somebody.
//   - A **cluster-issued ServiceAccount subject**, if the registry federates the
//     cluster's OIDC issuer *and* the kubelet forwards a pod-bound token to a
//     credential-provider plugin. Then a grant really can name the workload
//     identity, with nothing persisted in between.
//
// The second is off by default here, matching the default state of a registry
// and of a cluster. [MemoryRegistry.SetFederatesClusterOIDC] turns it on.
type MemoryRegistry struct {
	mu    sync.Mutex
	repos map[string]*registryRepository
	// robots maps a minted token onto the workload identity it was minted for,
	// so a test can ask "can this identity pull" and get an answer that goes
	// through the credential the provider had to create.
	robots map[string]string
	// federatesOIDC reports whether this registry accepts a cluster-issued
	// ServiceAccount subject as a principal.
	federatesOIDC bool
	// failEvery, when set, is returned from every operation. See
	// [MemoryRegistry.FailEvery].
	failEvery error
}

// FailEvery makes every operation on this registry return err until the returned
// function is called.
//
// It exists because the conformance suite's transient-error gate could previously
// only fail the cluster, so the registry half of this provider's error mapping —
// EnsureRepository, DescribeRepository, DeleteRepository, and the grant paths —
// was never exercised. That was measured by USOSS-32's rework of the gate, which
// reports unexercised methods by name rather than passing silently.
func (r *MemoryRegistry) FailEvery(err error) func() {
	r.mu.Lock()
	r.failEvery = err
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.failEvery = nil
		r.mu.Unlock()
	}
}

// injected returns the armed failure, if any, without taking the lock twice.
func (r *MemoryRegistry) injected() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failEvery
}

// NewMemoryRegistry returns an empty registry that does not federate any
// cluster, which is the default state of every registry surveyed.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{repos: map[string]*registryRepository{}, robots: map[string]string{}}
}

// SetFederatesClusterOIDC configures the registry to accept a cluster-issued
// ServiceAccount subject as a principal, as Harbor, GAR, and ECR can each be
// configured to do.
func (r *MemoryRegistry) SetFederatesClusterOIDC(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.federatesOIDC = v
}

func (r *MemoryRegistry) get(name string) (*registryRepository, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[name]
	return repo, ok
}

func (r *MemoryRegistry) put(repo *registryRepository) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.repos[repo.name]; ok {
		repo.grants = existing.grants
	}
	if repo.grants == nil {
		repo.grants = map[string]compute.AccessLevel{}
	}
	r.repos[repo.name] = repo
}

func (r *MemoryRegistry) delete(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.repos, name)
}

// mintRobot creates a registry credential for a workload identity. Returns the
// token.
func (r *MemoryRegistry) mintRobot(subject string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for token, s := range r.robots {
		if s == subject {
			return token
		}
	}
	token := "robot$" + strconv.FormatInt(substrateTicks.Add(1), 36)
	r.robots[token] = subject
	return token
}

// repoNames lists the repositories, under the lock.
func (r *MemoryRegistry) repoNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sortedKeys(r.repos)
}

// robotFor returns the token already minted for subject, if any.
func (r *MemoryRegistry) robotFor(subject string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for token, s := range r.robots {
		if s == subject {
			return token, true
		}
	}
	return "", false
}

// grant authorises a principal — a robot token, or a ServiceAccount subject on
// a federating registry — against a repository.
func (r *MemoryRegistry) grant(repo, principal string, level compute.AccessLevel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr, ok := r.repos[repo]
	if !ok {
		return fmt.Errorf("%w: repository %q does not exist", compute.ErrNotFound, repo)
	}
	rr.grants[principal] = level
	return nil
}

func (r *MemoryRegistry) revoke(repo, principal string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rr, ok := r.repos[repo]; ok {
		delete(rr.grants, principal)
	}
}

// Pull attempts a pull as a principal.
func (r *MemoryRegistry) Pull(_ context.Context, repo, principal string) error {
	return r.access(repo, principal, compute.AccessRead)
}

// Push attempts a push as a principal.
func (r *MemoryRegistry) Push(_ context.Context, repo, principal string) error {
	return r.access(repo, principal, compute.AccessReadWrite)
}

// oidcSubjectPrefix is what a cluster-issued ServiceAccount subject looks like.
const oidcSubjectPrefix = "system:serviceaccount:"

func (r *MemoryRegistry) access(repo, principal string, need compute.AccessLevel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr, ok := r.repos[repo]
	if !ok {
		return fmt.Errorf("%w: repository %q does not exist", compute.ErrNotFound, repo)
	}
	_, isRobot := r.robots[principal]
	isSubject := r.federatesOIDC && strings.HasPrefix(principal, oidcSubjectPrefix)
	if !isRobot && !isSubject {
		if strings.HasPrefix(principal, oidcSubjectPrefix) {
			return fmt.Errorf("%w: this registry does not federate the cluster, so a "+
				"ServiceAccount is not a principal it can authenticate", ErrRegistryDenied)
		}
		return fmt.Errorf("%w: the presented credential is not a principal of this registry",
			ErrRegistryDenied)
	}
	level, granted := rr.grants[principal]
	if !granted {
		return fmt.Errorf("%w: the principal has no access to %q", ErrRegistryDenied, repo)
	}
	if need == compute.AccessReadWrite && level == compute.AccessRead {
		return fmt.Errorf("%w: the principal may pull from %q but not push", ErrRegistryDenied, repo)
	}
	return nil
}

func (r *MemoryRegistry) dump(host, project string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.repos))
	for _, name := range sortedKeys(r.repos) {
		repo := r.repos[name]
		fields := []string{
			"keep-last=" + strconv.Itoa(repo.keepLast),
			"max-age=" + repo.maxAge.String(),
			"scan=" + strconv.FormatBool(repo.scanOnPush),
			"robots=" + strconv.Itoa(len(repo.grants)),
		}
		if l := encodeLabels(repo.labels); l != "" {
			fields = append(fields, l)
		}
		out = append(out, fmt.Sprintf("Repository %s/%s/%s: %s",
			host, project, name, strings.Join(fields, " ")))
	}
	return out
}

// --- S3-compatible object store --------------------------------------------------

// ErrObjectStoreDenied is the object store's 403.
var ErrObjectStoreDenied = errors.New("k8s: the object store refused the request")

type storeBucket struct {
	name       string
	class      compute.ObjectClass
	publicRead bool
	labels     map[string]string
	claim      BucketClaim
	// policies maps an OIDC subject — "system:serviceaccount:<ns>:<name>" — onto
	// what it may do. Unlike the registry, an S3-compatible store can federate
	// the cluster's ServiceAccount tokens, which is the only reason
	// [compute.ObjectStore]'s Granter is implementable here.
	policies map[string]compute.AccessLevel
	objects  map[string][]byte
}

// MemoryObjectStore stands in for MinIO or Ceph RGW.
type MemoryObjectStore struct {
	mu      sync.Mutex
	buckets map[string]*storeBucket
	// trustsOIDC mirrors [ObjectStoreConfig.TrustsClusterOIDC]; a store that
	// does not federate the cluster cannot honour a grant to a ServiceAccount.
	trustsOIDC bool
	// failEvery, when set, is returned from every operation. See
	// [MemoryObjectStore.FailEvery].
	failEvery error
}

// FailEvery makes every operation on this store return err until the returned
// function is called. See [MemoryRegistry.FailEvery] for why it exists.
func (s *MemoryObjectStore) FailEvery(err error) func() {
	s.mu.Lock()
	s.failEvery = err
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.failEvery = nil
		s.mu.Unlock()
	}
}

// injected returns the armed failure, if any.
func (s *MemoryObjectStore) injected() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failEvery
}

// NewMemoryObjectStore returns an empty store that federates the cluster.
func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{buckets: map[string]*storeBucket{}, trustsOIDC: true}
}

func (s *MemoryObjectStore) get(name string) (*storeBucket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[name]
	return b, ok
}

func (s *MemoryObjectStore) put(b *storeBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.buckets[b.name]; ok {
		b.policies, b.objects = existing.policies, existing.objects
	}
	if b.policies == nil {
		b.policies = map[string]compute.AccessLevel{}
	}
	if b.objects == nil {
		b.objects = map[string][]byte{}
	}
	s.buckets[b.name] = b
}

func (s *MemoryObjectStore) delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buckets, name)
}

// empty drops a bucket's objects and keeps the bucket and its policies, under
// the lock.
func (s *MemoryObjectStore) empty(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[name]; ok {
		b.objects = map[string][]byte{}
	}
}

// bucketNames lists the buckets, under the lock.
func (s *MemoryObjectStore) bucketNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedKeys(s.buckets)
}

func (s *MemoryObjectStore) setPolicy(bucket, subject string, level compute.AccessLevel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return fmt.Errorf("%w: bucket %q does not exist", compute.ErrNotFound, bucket)
	}
	b.policies[subject] = level
	return nil
}

func (s *MemoryObjectStore) getPolicy(bucket, subject string) (compute.AccessLevel, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return "", false, fmt.Errorf("%w: bucket %q does not exist", compute.ErrNotFound, bucket)
	}
	level, granted := b.policies[subject]
	return level, granted, nil
}

func (s *MemoryObjectStore) clearPolicy(bucket, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[bucket]; ok {
		delete(b.policies, subject)
	}
}

// Read performs a data-plane read as an OIDC subject.
func (s *MemoryObjectStore) Read(_ context.Context, bucket, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return fmt.Errorf("%w: bucket %q does not exist", compute.ErrNotFound, bucket)
	}
	if _, granted := b.policies[subject]; !granted {
		return fmt.Errorf("%w: %q may not read %q", ErrObjectStoreDenied, subject, bucket)
	}
	return nil
}

// Write performs a data-plane write as an OIDC subject.
func (s *MemoryObjectStore) Write(_ context.Context, bucket, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return fmt.Errorf("%w: bucket %q does not exist", compute.ErrNotFound, bucket)
	}
	level, granted := b.policies[subject]
	if !granted || level == compute.AccessRead {
		return fmt.Errorf("%w: %q may not write %q", ErrObjectStoreDenied, subject, bucket)
	}
	b.objects[subject] = []byte("written")
	return nil
}

// AnonymousRead performs an unauthenticated read.
func (s *MemoryObjectStore) AnonymousRead(_ context.Context, bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return fmt.Errorf("%w: bucket %q does not exist", compute.ErrNotFound, bucket)
	}
	if !b.publicRead {
		return fmt.Errorf("%w: %q does not permit anonymous access", ErrObjectStoreDenied, bucket)
	}
	return nil
}

func (s *MemoryObjectStore) dump(scheme string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := sortedKeys(s.buckets)
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		b := s.buckets[name]
		fields := []string{
			"class=" + string(b.class),
			"public=" + strconv.FormatBool(b.publicRead),
			"grants=" + strconv.Itoa(len(b.policies)),
		}
		if l := encodeLabels(b.labels); l != "" {
			fields = append(fields, l)
		}
		out = append(out, fmt.Sprintf("Bucket %s://%s: %s", scheme, name, strings.Join(fields, " ")))
	}
	return out
}
