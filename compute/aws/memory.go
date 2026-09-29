// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
)

// The in-memory substrate.
//
// It is exported and lives beside the provider rather than in a test package,
// for the same reason compute/k8s's MemoryCluster does: the conformance suite
// is the contract, it has to run with no network and no account, and a
// substrate that only the package's own tests could reach would leave every
// other package unable to exercise a provider at all.
//
// It is a model of the services, not a mock. It refuses a create that would
// collide, reports its own 404, and holds the tags and policies the provider
// wrote — because the invariants worth checking are things like "an Ensure that
// finds an unowned repository refuses", and a mock that returns whatever the
// test wants proves nothing about that.
//
// # The fixtures here contain no AWS identifier of any kind
//
// Every ARN this substrate reports uses a placeholder in the account position
// rather than a twelve-digit number, and every registry host is under the
// reserved .invalid TLD rather than the real ECR hostname shape. That is not
// squeamishness: this repository is going public, a synthetic twelve-digit
// number is indistinguishable from a real account ID to every scanner and every
// reader, and a fixture is exactly where a real one gets pasted "just for the
// test". The provider never parses these, which is why it can hold them.

// MemoryAccount is the placeholder this substrate puts where an account
// identifier would go.
//
// It is deliberately not a number. See the note above.
const MemoryAccount = "apphub-test-account"

// MemoryRegistryHost is the registry hostname this substrate reports.
//
// Real ECR hosts are "<account>.dkr.ecr.<region>.amazonaws.com", which embeds
// the account. Nothing in this package parses a registry host — the provider
// compares against the URI the registry reported — so the fixture does not have
// to imitate the shape, and imitating it would mean writing an account-shaped
// number into a public repository.
const MemoryRegistryHost = "registry.invalid"

// MemoryRegion is the placeholder this substrate puts where a region would go.
// It is not a real region slug, for the same reason MemoryAccount is not a
// number: a fixture that imitates the real shape is a fixture somebody
// eventually fills in with the real value.
const MemoryRegion = "test-region"

// NewMemorySubstrate returns a substrate backed entirely by memory.
func NewMemorySubstrate() *Substrate {
	return &Substrate{
		ECR:         NewMemoryECR(),
		IAM:         NewMemoryIAM(),
		STS:         NewMemorySTS(),
		Builder:     NewRecordingBuilder(),
		Pusher:      NewRecordingPusher(),
		Lambda:      NewMemoryLambda(),
		ELBv2:       NewMemoryELBv2(),
		EndpointEC2: NewMemoryEndpointEC2(),
		Parameters:  NewMemoryParameters(),
		RDS:         NewMemoryRDS(),
		EC2:         NewMemoryEC2(),
		DynamoDB:    NewMemoryDynamoDB(),
		ECS:         NewMemoryECS(),
		Scheduler:   NewMemoryScheduler(),
		S3:          NewMemoryS3(),
		S3Tables:    NewMemoryS3Tables(),
		S3Vectors:   NewMemoryS3Vectors(),
	}
}

// failNext is the failure injector every in-memory service embeds.
//
// It exists for the conformance suite's retry gate: [compute.ErrTransient] is
// otherwise a sentinel with no test, and the provider that maps a throttle to
// [compute.ErrFailed] tells its caller the spec has to change when the deploy
// would have succeeded.
//
// It offers two durations, and the distinction is load-bearing (USOSS-60):
//
//   - [failNext.FailNext] arms ONE call. That models a genuinely transient
//     failure the caller's own retry recovers from, which is what
//     conformance.Options.InduceTransient documents, and it is the right tool
//     for a test that asserts a retry succeeds.
//   - [failNext.FailUntilStopped] arms every call until its stop function runs.
//     That is what a gate driving many methods needs.
//
// The one-shot form was the only form, and it made the suite's coverage
// silently partial: the FIRST intercepted call of an operation consumed the
// injection, whichever verb it was, so a method that reads before it writes
// spent the arming on the read. Every method after the first in a run then saw
// a healthy substrate and the gate counted it unexercised.
//
// The near-miss is worth recording next to the fix, because it nearly shipped.
// The first diagnosis was "the hooks reach writes and not reads" — inferred from
// the pattern of results across three providers, which made it feel derived. It
// was false, and measurement is what separated them: with the injection armed, a
// DescribeRepository alone surfaces the induced failure, and a second one does
// not. Reads consult the injector; the arming was simply gone. Both hypotheses
// predict the identical symptom — only the first driven method surfaces the
// failure — so widening the hooks to reads would have changed nothing and
// shipped as a fix reporting coverage that had not improved. **A population
// inferred from an outcome is not a derived population.**
type failNext struct {
	mu     sync.Mutex
	err    error
	sticky bool
	fired  bool
}

// FailNext arms exactly ONE call, which fails with err. Passing nil clears it.
//
// The returned function cancels an arming that has not been consumed yet; an
// arming that a call has already taken is gone either way. The old wording said
// "the next call, until the returned function is called", which reads as sticky
// and is not — and this is the method whose one-shot semantics the rest of this
// type depends on being unambiguous.
//
// One-shot on purpose: see [failNext] for why this is not the same tool as
// [failNext.FailUntilStopped], and TestFailNextIsStillOneShot for the pin that
// keeps it that way. Making this sticky would silently change what every
// existing caller measures — a caller that arms one failure and asserts a retry
// succeeds would start asserting nothing, because the retry would fail too.
func (f *failNext) FailNext(err error) func() {
	return f.arm(err, false)
}

// FailUntilStopped makes EVERY call fail with err until the returned function is
// called.
//
// This is what a gate that drives many methods needs: with the one-shot form,
// only the first intercepted call of the run sees the injection and every method
// after it is scored as unexercised. Passing nil clears it.
func (f *failNext) FailUntilStopped(err error) func() {
	return f.arm(err, true)
}

func (f *failNext) arm(err error, sticky bool) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
	f.sticky = sticky
	f.fired = false
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.err = nil
		f.sticky = false
	}
}

// take returns the injected error, clearing it unless it was armed to persist.
//
// The one-shot clear is what makes an injected failure genuinely transient: the
// retry a caller is told to make succeeds.
func (f *failNext) take() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.err
	if err != nil {
		f.fired = true
	}
	if !f.sticky {
		f.err = nil
	}
	return err
}

// injectionFired reports whether an arming has been consumed at least once.
//
// A cell whose injection was never reached is not evidence, and counting it as a
// pass is how a construction reports coverage it does not have. Only a test
// reads this.
func (f *failNext) injectionFired() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

// --- ECR ------------------------------------------------------------------------

type memoryRepository struct {
	rec    RepositoryRecord
	tags   map[string]string
	policy string
	// images maps a tag to the manifest digest the registry stored. Nil means
	// no image was seeded, and DescribeImage then reports
	// [MemoryPushedImageDigest] for any tag — the recording pusher does not
	// write manifests, and a build still has to read a digest back.
	images map[string]string
}

// MemoryPushedImageDigest is the manifest digest an in-memory registry reports
// for a tag that was not seeded with [MemoryECR.PutImage].
//
// It is not the recording builder's digest. Those two strings differ on
// purpose: the digest a workload runs is the one the registry stored after the
// push, not the one the builder wrote while constructing the image.
var MemoryPushedImageDigest = "sha256:" + strings.Repeat("cd", 32)

// MemoryECR is an in-memory container registry.
type MemoryECR struct {
	failNext
	mu    sync.Mutex
	repos map[string]*memoryRepository
}

var _ ECRAPI = (*MemoryECR)(nil)

// NewMemoryECR returns an empty registry.
func NewMemoryECR() *MemoryECR {
	return &MemoryECR{repos: map[string]*memoryRepository{}}
}

// repositoryARN and repositoryURI are how this substrate answers the two
// questions the provider asks it. Both are read back by the provider and never
// composed by it, which is the property that keeps an account identifier out of
// the provider entirely.
func repositoryARN(name string) string {
	return "arn:aws:ecr:" + MemoryRegion + ":" + MemoryAccount + ":repository/" + name
}

func repositoryURI(name string) string { return MemoryRegistryHost + "/" + name }

// PutUnowned puts a repository into the registry without apphub's ownership
// tag, so an Ensure has a collision to refuse.
func (r *MemoryECR) PutUnowned(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repos[name] = &memoryRepository{
		rec:  RepositoryRecord{Name: name, ARN: repositoryARN(name), URI: repositoryURI(name)},
		tags: map[string]string{"created-by": "somebody-else"},
	}
}

// PutImage records the manifest digest a tag resolves to. Seeding any tag
// turns the repository from "every tag exists" into "only seeded tags exist".
func (r *MemoryECR) PutImage(repository, tag, digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[repository]
	if !ok {
		return fmt.Errorf("%w: repository %q", ErrNoSuchResource, repository)
	}
	if repo.images == nil {
		repo.images = map[string]string{}
	}
	repo.images[tag] = digest
	return nil
}

// DescribeImage implements [ECRAPI].
func (r *MemoryECR) DescribeImage(_ context.Context, repository, tag, digest string) (string, error) {
	if err := r.take(); err != nil {
		return "", err
	}
	if (tag == "") == (digest == "") {
		return "", fmt.Errorf("aws: DescribeImage needs a tag or a digest, not both and not neither")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[repository]
	if !ok {
		return "", fmt.Errorf("%w: repository %q", ErrNoSuchResource, repository)
	}
	if repo.images != nil {
		if tag != "" {
			got, ok := repo.images[tag]
			if !ok {
				return "", fmt.Errorf("%w: image %s:%s", ErrNoSuchResource, repository, tag)
			}
			return got, nil
		}
		for _, got := range repo.images {
			if got == digest {
				return got, nil
			}
		}
		return "", fmt.Errorf("%w: image %s@%s", ErrNoSuchResource, repository, digest)
	}
	if digest != "" {
		return digest, nil
	}
	return MemoryPushedImageDigest, nil
}

// DescribeRepository implements [ECRAPI].
func (r *MemoryECR) DescribeRepository(_ context.Context, name string) (*RepositoryRecord, error) {
	if err := r.take(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[name]
	if !ok {
		return nil, fmt.Errorf("%w: repository %q", ErrNoSuchResource, name)
	}
	rec := repo.rec
	return &rec, nil
}

// CreateRepository implements [ECRAPI].
func (r *MemoryECR) CreateRepository(_ context.Context, name string, scanOnPush, immutableTags bool, tags map[string]string) (*RepositoryRecord, error) {
	if err := r.take(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.repos[name]; ok {
		return nil, fmt.Errorf("%w: repository %q", ErrAlreadyExists, name)
	}
	repo := &memoryRepository{
		rec: RepositoryRecord{
			Name: name, ARN: repositoryARN(name), URI: repositoryURI(name),
			ScanOnPush: scanOnPush, ImmutableTags: immutableTags,
		},
		tags: copyTags(tags),
	}
	if repo.tags == nil {
		repo.tags = map[string]string{}
	}
	r.repos[name] = repo
	rec := repo.rec
	return &rec, nil
}

// DeleteRepository implements [ECRAPI].
func (r *MemoryECR) DeleteRepository(_ context.Context, name string) error {
	if err := r.take(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.repos[name]; !ok {
		return fmt.Errorf("%w: repository %q", ErrNoSuchResource, name)
	}
	delete(r.repos, name)
	return nil
}

// PutImageScanningConfiguration implements [ECRAPI].
func (r *MemoryECR) PutImageScanningConfiguration(_ context.Context, name string, scanOnPush bool) error {
	return r.withRepo(name, func(repo *memoryRepository) error {
		repo.rec.ScanOnPush = scanOnPush
		return nil
	})
}

// PutImageTagMutability implements [ECRAPI].
func (r *MemoryECR) PutImageTagMutability(_ context.Context, name string, immutableTags bool) error {
	return r.withRepo(name, func(repo *memoryRepository) error {
		repo.rec.ImmutableTags = immutableTags
		return nil
	})
}

// GetLifecyclePolicy implements [ECRAPI].
func (r *MemoryECR) GetLifecyclePolicy(_ context.Context, name string) (string, error) {
	if err := r.take(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[name]
	if !ok {
		return "", fmt.Errorf("%w: repository %q", ErrNoSuchResource, name)
	}
	if repo.policy == "" {
		return "", fmt.Errorf("%w: repository %q has no lifecycle policy", ErrNoSuchResource, name)
	}
	return repo.policy, nil
}

// PutLifecyclePolicy implements [ECRAPI].
func (r *MemoryECR) PutLifecyclePolicy(_ context.Context, name, policy string) error {
	return r.withRepo(name, func(repo *memoryRepository) error {
		repo.policy = policy
		return nil
	})
}

// DeleteLifecyclePolicy implements [ECRAPI].
func (r *MemoryECR) DeleteLifecyclePolicy(_ context.Context, name string) error {
	return r.withRepo(name, func(repo *memoryRepository) error {
		if repo.policy == "" {
			return fmt.Errorf("%w: repository %q has no lifecycle policy", ErrNoSuchResource, name)
		}
		repo.policy = ""
		return nil
	})
}

// ListTags implements [ECRAPI].
func (r *MemoryECR) ListTags(_ context.Context, arn string) (map[string]string, error) {
	if err := r.take(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, repo := range r.repos {
		if repo.rec.ARN == arn {
			return copyTags(repo.tags), nil
		}
	}
	return nil, fmt.Errorf("%w: no resource with ARN %q", ErrNoSuchResource, arn)
}

// TagResource implements [ECRAPI].
func (r *MemoryECR) TagResource(_ context.Context, arn string, tags map[string]string) error {
	return r.withARN(arn, func(repo *memoryRepository) error {
		for k, v := range tags {
			repo.tags[k] = v
		}
		return nil
	})
}

// UntagResource implements [ECRAPI].
func (r *MemoryECR) UntagResource(_ context.Context, arn string, keys []string) error {
	return r.withARN(arn, func(repo *memoryRepository) error {
		for _, k := range keys {
			delete(repo.tags, k)
		}
		return nil
	})
}

func (r *MemoryECR) withRepo(name string, fn func(*memoryRepository) error) error {
	if err := r.take(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	repo, ok := r.repos[name]
	if !ok {
		return fmt.Errorf("%w: repository %q", ErrNoSuchResource, name)
	}
	return fn(repo)
}

func (r *MemoryECR) withARN(arn string, fn func(*memoryRepository) error) error {
	if err := r.take(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, repo := range r.repos {
		if repo.rec.ARN == arn {
			return fn(repo)
		}
	}
	return fmt.Errorf("%w: no resource with ARN %q", ErrNoSuchResource, arn)
}

// Dump renders every repository, for the conformance suite's rendered-artefact
// invariants.
func (r *MemoryECR) Dump() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.repos))
	for name := range r.repos {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		repo := r.repos[name]
		retention, _ := parseLifecyclePolicy(repo.policy)
		fields := []string{
			"keep-last=" + strconv.Itoa(retention.KeepLast),
			"max-age=" + retention.MaxAge.String(),
			"scan=" + strconv.FormatBool(repo.rec.ScanOnPush),
			"immutable-tags=" + strconv.FormatBool(repo.rec.ImmutableTags),
		}
		if pairs := sortedPairs(repo.tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("Repository %s: %s", repo.rec.URI, strings.Join(fields, " ")))
	}
	return out
}

// --- IAM ------------------------------------------------------------------------

// MemoryIAM is an in-memory identity service.
type MemoryIAM struct {
	failNext
	mu    sync.Mutex
	roles map[string]*RoleRecord
	// policies is role name -> policy name -> document. Inline policies are
	// kept because a grant is one of them, and the conformance suite checks a
	// grant by performing a data-plane operation as the identity rather than by
	// reading a policy back — which needs the substrate to be able to answer
	// "what is this role permitted to do".

	// policies holds each role's inline policies, by role name then policy
	// name. Inline policies are a separate API surface from the role itself on
	// IAM, so they are stored separately here too rather than hung off
	// RoleRecord -- a GetRole against the real service does not return them,
	// and a substrate that volunteered them would let the provider read them
	// without the call that really costs one. (USOSS-11.)
	policies map[string]map[string]string
}

var _ IAMAPI = (*MemoryIAM)(nil)

// NewMemoryIAM returns an empty identity service.
func NewMemoryIAM() *MemoryIAM {
	return &MemoryIAM{
		roles:    map[string]*RoleRecord{},
		policies: map[string]map[string]string{},
	}
}

// roleARN is how this substrate answers "what is this role's ARN". See
// [MemoryAccount] for why the account position holds a word.
func roleARN(name string) string { return "arn:aws:iam::" + MemoryAccount + ":role/" + name }

// PutUnowned puts a role into IAM without apphub's ownership tag.
func (m *MemoryIAM) PutUnowned(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roles[name] = &RoleRecord{
		Name: name, ARN: roleARN(name),
		Tags: map[string]string{"created-by": "somebody-else"},
	}
}

// GetRole implements [IAMAPI].
func (m *MemoryIAM) GetRole(_ context.Context, name string) (*RoleRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.roles[name]
	if !ok {
		return nil, fmt.Errorf("%w: role %q", ErrNoSuchResource, name)
	}
	return copyRole(role), nil
}

// CreateRole implements [IAMAPI].
func (m *MemoryIAM) CreateRole(_ context.Context, in CreateRoleRequest) (*RoleRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[in.Name]; ok {
		return nil, fmt.Errorf("%w: role %q", ErrAlreadyExists, in.Name)
	}
	role := &RoleRecord{
		Name: in.Name, ARN: roleARN(in.Name),
		AssumeRolePolicy: in.AssumeRolePolicy,
		Tags:             copyTags(in.Tags),
	}
	if role.Tags == nil {
		role.Tags = map[string]string{}
	}
	m.roles[in.Name] = role
	return copyRole(role), nil
}

// UpdateAssumeRolePolicy implements [IAMAPI].
func (m *MemoryIAM) UpdateAssumeRolePolicy(_ context.Context, name, policy string) error {
	return m.withRole(name, func(role *RoleRecord) error {
		role.AssumeRolePolicy = policy
		return nil
	})
}

// DeleteRole implements [IAMAPI].
//
// Real IAM refuses this with DeleteConflictException while the role still
// carries an inline policy, and does not take them with it -- a role's
// policies are separate objects a caller must remove first with
// DeleteRolePolicy. This model used to delete them along with the role, which
// let [identityService.DeleteWorkloadIdentity] pass against the fixture while
// failing against every real account with a key-value or object-store grant
// on the role it was tearing down. See [ErrConflict].
func (m *MemoryIAM) DeleteRole(_ context.Context, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; !ok {
		return fmt.Errorf("%w: role %q", ErrNoSuchResource, name)
	}
	if len(m.policies[name]) > 0 {
		return fmt.Errorf("%w: role %q still has %d inline policy(ies) attached",
			ErrConflict, name, len(m.policies[name]))
	}
	delete(m.roles, name)
	delete(m.policies, name)
	return nil
}

// TagRole implements [IAMAPI].
func (m *MemoryIAM) TagRole(_ context.Context, name string, tags map[string]string) error {
	return m.withRole(name, func(role *RoleRecord) error {
		for k, v := range tags {
			role.Tags[k] = v
		}
		return nil
	})
}

// UntagRole implements [IAMAPI].
func (m *MemoryIAM) UntagRole(_ context.Context, name string, keys []string) error {
	return m.withRole(name, func(role *RoleRecord) error {
		for _, k := range keys {
			delete(role.Tags, k)
		}
		return nil
	})
}

func (m *MemoryIAM) withRole(name string, fn func(*RoleRecord) error) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	role, ok := m.roles[name]
	if !ok {
		return fmt.Errorf("%w: role %q", ErrNoSuchResource, name)
	}
	return fn(role)
}

// Dump renders every role.
func (m *MemoryIAM) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.roles))
	for name := range m.roles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		role := m.roles[name]
		fields := []string{"runs-on=" + string(runtimeFromTrustPolicy(role.AssumeRolePolicy))}
		for _, k := range sortedKeys(role.Tags) {
			label, ok := strings.CutPrefix(k, tagLabelPrefix)
			if !ok {
				continue
			}
			fields = append(fields, label+"="+role.Tags[k])
		}
		out = append(out, fmt.Sprintf("Role %s: %s", role.Name, strings.Join(fields, " ")))
	}
	return out
}

func copyRole(in *RoleRecord) *RoleRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	return &out
}

// sortedKeys is generic over the value type: the in-memory stores hold different
// record types under a string key, and a second copy of four lines per record
// type is four places for the ordering to drift.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- STS ------------------------------------------------------------------------

// MemorySTS mints credentials that are not credentials.
//
// The material it hands out is a fixed, obviously-synthetic string rather than
// anything shaped like a real AWS key. That matters twice over: a fixture that
// looks like a credential is where a real one eventually gets pasted, and an
// access key ID with a real AWS prefix in a public repository is a finding for
// every scanner that reads it.
type MemorySTS struct {
	failNext
	mu       sync.Mutex
	requests []AssumeRoleRequest
	now      time.Time
}

var _ STSAPI = (*MemorySTS)(nil)

// The synthetic material. Deliberately not shaped like an AWS credential.
//
//nolint:gosec // G101: fixed synthetic values make the in-memory STS response deterministic.
const (
	memoryAccessKeyID     = "apphub-test-access-key-id"
	memorySecretAccessKey = "apphub-test-secret-access-key"
	memorySessionToken    = "apphub-test-session-token"
)

// memoryEpoch is the fixed instant this substrate's clock counts from, so a
// test run is reproducible.
var memoryEpoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// NewMemorySTS returns a token service that has minted nothing.
func NewMemorySTS() *MemorySTS { return &MemorySTS{now: memoryEpoch} }

// AssumeRole implements [STSAPI].
func (s *MemorySTS) AssumeRole(_ context.Context, in AssumeRoleRequest) (PushCredentials, error) {
	if err := s.take(); err != nil {
		return PushCredentials{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, in)
	return PushCredentials{
		AccessKeyID:     credentials.NewSecret(memoryAccessKeyID),
		SecretAccessKey: credentials.NewSecret(memorySecretAccessKey),
		SessionToken:    credentials.NewSecret(memorySessionToken),
		Expires:         s.now.Add(in.Duration),
	}, nil
}

// Requests returns every credential request this service received, so a test
// can assert on the scope and the duration the provider asked for.
func (s *MemorySTS) Requests() []AssumeRoleRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AssumeRoleRequest(nil), s.requests...)
}

// --- the builder ------------------------------------------------------------------

// RecordingBuilder records the build it was asked to run instead of running it.
//
// **This type cannot reveal the push credential, and since USOSS-41 that is a
// property of [BuildCommand] rather than of this code.** The command it is handed
// has no field that could carry one, so "a recording runner has no material to
// leak" is true by the same construction that makes it true of a real kaniko.
//
// The history is worth keeping, because the argument moved twice. It first read
// "this type never calls [credentials.Reveal], so a change that broke it would
// not compile without a Reveal somebody would have to review". USOSS-39 gave that
// up on purpose: a runner that *cannot* emit the credential cannot support a
// check that the provider does not leak it, and a benign fixture and a correct
// implementation are indistinguishable — bypassing the provider's redacting
// writer entirely turned nothing red. So leak flags were added here. USOSS-41
// then removed the credential from the build phase altogether, which makes the
// build-phase leak flags unimplementable rather than merely unused; the equivalent
// hostility now lives on [RecordingPusher], which is the phase that really does
// hold material.
//
// What is left here is the *other* half of the same threat, and it is the half
// that measures USOSS-41's actual claim: LeakEnvironment prints the environment
// the provider handed the build, which is exactly what a "RUN env" line does. A
// build environment containing credential material would show up in the caller's
// log, and TestTheBuildPhaseHasNoCredentialInItsEnvironment reads it.
type RecordingBuilder struct {
	failNext
	mu   sync.Mutex
	runs []BuildCommand
	// Digest is what the builder writes to its --digest-file, so the digest
	// path can be exercised. Empty means it writes nothing, which is the case
	// [compute.BuildResult.Digest] tells callers to expect.
	Digest string

	// LeakEnvironment makes this runner print every variable it was given to its
	// output, and return them in an error when FailWithOutputInError is set.
	//
	// It models what a hostile Dockerfile actually does — a RUN line that prints
	// the executor's environment — and it is the measurement behind USOSS-41's
	// claim rather than an assertion of it: whatever the provider puts in the
	// build phase's environment arrives in the caller's log, where a test can
	// scan it for material.
	//
	// It replaces a LeakCredentials flag that read [BuildCommand.Credentials],
	// which no longer exists. See [RecordingPusher.LeakCredentials] for the flag
	// that still emits real material, on the phase that has it.
	LeakEnvironment bool

	// FailWithOutputInError makes this runner return an error carrying its own
	// output, which is the obligation on [BuildRunner] being broken on purpose.
	//
	// Separate from LeakEnvironment because the two exercise different channels
	// and a runner that does both is non-conformant for a reason that has
	// nothing to do with leaks: a build of a legal context that always fails also
	// fails the invariant that a build writes its progress to the writer it was
	// given. Keeping them apart lets a conformance run use a substrate that
	// leaks into the log while still building successfully, which is what gives
	// the credential-egress check an input rather than a skip.
	FailWithOutputInError bool

	// emissions are markers a test asked this runner to put into a channel, so a
	// check can establish the channel is observable before scanning it. Distinct
	// from the leak flags: those emit what the provider handed the phase, this
	// emits an arbitrary string the suite chose, which is what makes the arrival
	// checkable without asserting anything about a credential.
	emissions map[string]string
}

var _ BuildRunner = (*RecordingBuilder)(nil)

// NewRecordingBuilder returns a builder that records and succeeds, and that
// emits nothing it was not asked to: both flags are off, so the default is
// benign and a test has to opt into hostility explicitly.
func NewRecordingBuilder() *RecordingBuilder {
	return &RecordingBuilder{
		Digest: "sha256:" + strings.Repeat("ab", 32),
	}
}

// Run implements [BuildRunner].
func (b *RecordingBuilder) Run(ctx context.Context, cmd BuildCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.take(); err != nil {
		return err
	}
	b.mu.Lock()
	b.runs = append(b.runs, cmd)
	digest := b.Digest
	b.mu.Unlock()

	env := strings.Join(cmd.Env, " ")
	if cmd.Output != nil {
		_, _ = fmt.Fprintf(cmd.Output, "recording builder: %s\n", strings.Join(cmd.Args, " "))
		if m := b.emission(ChannelBuildLog); m != "" {
			_, _ = fmt.Fprintf(cmd.Output, "recording builder:%s\n", m)
		}
		if b.LeakEnvironment {
			// What a Dockerfile "RUN env" produces. It goes through cmd.Output on
			// purpose: that is the writer the caller persists.
			_, _ = fmt.Fprintf(cmd.Output, "recording builder: env %s\n", env)
		}
	}
	if b.FailWithOutputInError {
		return fmt.Errorf("recording builder: failed with env %s", env)
	}
	// The artefact and the digest, in that order, because the provider refuses to
	// mint a credential for a build that produced no artefact -- so a fake that
	// wrote only the digest would exercise the refusal on every build rather than
	// the push. Both paths are conditional on the flag being present, since a
	// builder invoked without one writes nothing.
	for _, arg := range cmd.Args {
		if path, ok := strings.CutPrefix(arg, "--tar-path="); ok {
			// Not a real tarball. What the provider checks is that a build that
			// exits zero left something to push, and a fake that leaves an empty
			// file would exercise the refusal instead.
			if err := os.WriteFile(filepath.Clean(path), []byte("recording builder artefact\n"), 0o600); err != nil {
				return err
			}
		}
	}
	if digest == "" {
		return nil
	}
	for _, arg := range cmd.Args {
		if path, ok := strings.CutPrefix(arg, "--digest-file="); ok {
			return os.WriteFile(filepath.Clean(path), []byte(digest+"\n"), 0o600)
		}
	}
	return nil
}

// Runs returns every build this builder was asked to run.
func (b *RecordingBuilder) Runs() []BuildCommand {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]BuildCommand(nil), b.runs...)
}

// Dump renders every build, for the conformance suite's rendered-artefact
// invariants. The environment and the arguments are rendered in full, which is
// the whole command: since USOSS-41 a [BuildCommand] has no other field, so
// "secret material appears in nothing the provider renders" is not a claim about
// what this method chose to print.
func (b *RecordingBuilder) Dump() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.runs))
	for _, run := range b.runs {
		env := append([]string(nil), run.Env...)
		sort.Strings(env)
		out = append(out, fmt.Sprintf("Build %s %s [env: %s]",
			run.Executable, strings.Join(run.Args, " "), strings.Join(env, " ")))
	}
	return out
}

// --- the pusher -------------------------------------------------------------------

// RecordingPusher records the push it was asked to run instead of running it.
//
// It is the phase that holds credential material, so it is where the hostility
// that used to live on [RecordingBuilder] moved (USOSS-41). Both flags are off by
// default: a benign fixture is what a test that means to assert something has to
// opt out of, and USOSS-39's lesson was that a benign fixture and a correct
// implementation are indistinguishable.
//
// The provider's redacting writer is doing observable work only when
// LeakCredentials is on. Removing newRedactingWriter turns the provider test and
// the conformance credential-egress gate red on all three secrets, and that is
// the only reason either is evidence.
type RecordingPusher struct {
	failNext
	mu   sync.Mutex
	runs []PushCommand

	// LeakCredentials makes this pusher print the credential it was handed to
	// its output.
	//
	// A pusher is not repository-authored code, so this is a weaker threat than
	// the one the builder used to model — and it is not hypothetical: a tool that
	// dumps its environment when a registry call fails is common, and this
	// process's environment is where the credential is. The provider redacts
	// where it consumes pusher output precisely because it cannot assume
	// otherwise.
	LeakCredentials bool

	// FailWithCredentialsInError makes this pusher return an error containing
	// the credential, which is the obligation on [ImagePusher] being broken on
	// purpose. Separate from LeakCredentials for the same reason the builder's
	// two flags are separate: a fixture that always fails cannot also be the
	// fixture a successful conformance build runs against.
	FailWithCredentialsInError bool
}

var _ ImagePusher = (*RecordingPusher)(nil)

// NewRecordingPusher returns a pusher that records and succeeds.
func NewRecordingPusher() *RecordingPusher { return &RecordingPusher{} }

// Push implements [ImagePusher].
func (p *RecordingPusher) Push(ctx context.Context, cmd PushCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.take(); err != nil {
		return err
	}
	p.mu.Lock()
	p.runs = append(p.runs, cmd)
	p.mu.Unlock()

	if cmd.Output != nil {
		_, _ = fmt.Fprintf(cmd.Output, "recording pusher: %s\n", strings.Join(cmd.Args, " "))
		if p.LeakCredentials {
			// Through cmd.Output on purpose: that is the writer the provider is
			// supposed to have wrapped.
			_, _ = fmt.Fprintf(cmd.Output, "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_SESSION_TOKEN=%s\n",
				credentials.Reveal(cmd.Credentials.AccessKeyID),
				credentials.Reveal(cmd.Credentials.SecretAccessKey),
				credentials.Reveal(cmd.Credentials.SessionToken))
		}
	}
	if p.FailWithCredentialsInError {
		return fmt.Errorf("recording pusher: failed with AWS_SESSION_TOKEN=%s in scope",
			credentials.Reveal(cmd.Credentials.SessionToken))
	}
	return nil
}

// Runs returns every push this pusher was asked to run.
func (p *RecordingPusher) Runs() []PushCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PushCommand(nil), p.runs...)
}

// Dump renders every push, for the conformance suite's rendered-artefact
// invariants.
//
// The environment and the arguments are rendered in full; the credential is not,
// because this method does not format [PushCommand.Credentials] and the field
// holds [credentials.Secret] values rather than strings. The claim is about this
// method rather than about the type — the type does reveal material, under the
// two flags above — and it is still sufficient: nothing here reaches the field.
func (p *RecordingPusher) Dump() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.runs))
	for _, run := range p.runs {
		env := append([]string(nil), run.Env...)
		sort.Strings(env)
		out = append(out, fmt.Sprintf("Push %s %s [env: %s]",
			run.Executable, strings.Join(run.Args, " "), strings.Join(env, " ")))
	}
	return out
}

// --- Lambda -------------------------------------------------------------------

// MemoryLambda is an in-memory function service.
//
// # It models Lambda's state machine, and that is the point
//
// A mock that accepted every call in any order would make this package's
// hardest behaviour untestable. Lambda mutates a function's configuration and
// its code through two calls and **refuses the second while the first is still
// in flight**, which is the whole reason
// [compute.FunctionRuntime.WaitForFunction] exists and the reason
// [functionRuntime.EnsureFunction] can return [compute.ErrTransient] having
// applied half a spec. So this reproduces it: a mutation leaves the function
// [UpdateStatusInProgress], and a second mutation while it is returns
// [ErrConflict].
//
// Convergence happens on **observation**: a GetFunction against a function that
// is pending or updating settles it. That is a model of an
// eventually-consistent service whose settling time is shorter than the
// interval between two API calls, and it is the behaviour that lets the
// conformance suite's Ensure-then-Ensure sequences work while still making the
// within-one-Ensure conflict reachable — because a provider that papered over
// the conflict by re-reading in between would be observably doing so.
//
// [MemoryLambda.Stall] switches settling off for one function, which is what
// gives a Wait something to time out on.
type MemoryLambda struct {
	failNext
	mu    sync.Mutex
	funcs map[string]*memoryFunction
}

type memoryFunction struct {
	rec      FunctionRecord
	policy   map[string]string
	stalled  bool
	revision int
}

var _ LambdaAPI = (*MemoryLambda)(nil)

// NewMemoryLambda returns an empty function service.
func NewMemoryLambda() *MemoryLambda {
	return &MemoryLambda{funcs: map[string]*memoryFunction{}}
}

// functionARN is how this substrate answers "what is this function's ARN". The
// account position holds a placeholder word; see the note at the top of this
// file for why it is not a twelve-digit number.
func functionARN(name string) string {
	return "arn:aws:lambda:" + MemoryRegion + ":" + MemoryAccount + ":function:" + name
}

// PutUnowned puts a function into the service without apphub's ownership tags,
// so an Ensure has a collision to refuse.
func (l *MemoryLambda) PutUnowned(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.funcs[name] = &memoryFunction{
		rec: FunctionRecord{
			Name: name, ARN: functionARN(name),
			State: FunctionStateActive, LastUpdateStatus: UpdateStatusSuccessful,
			Tags: map[string]string{"created-by": "somebody-else"},
		},
		policy: map[string]string{},
	}
}

// Stall stops a function from ever settling, so that a Wait against it times
// out. Returns a function that lets it settle again.
func (l *MemoryLambda) Stall(name string) func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[name]
	if !ok {
		return func() {}
	}
	fn.stalled = true
	fn.rec.State = FunctionStatePending
	fn.rec.LastUpdateStatus = UpdateStatusInProgress
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		fn.stalled = false
	}
}

// GetFunction implements [LambdaAPI]. It settles a converging function, which is
// what makes it the observation point described on [MemoryLambda].
func (l *MemoryLambda) GetFunction(_ context.Context, name string) (*FunctionRecord, error) {
	if err := l.take(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[name]
	if !ok {
		return nil, fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	if !fn.stalled {
		fn.rec.State = FunctionStateActive
		fn.rec.LastUpdateStatus = UpdateStatusSuccessful
	}
	return copyFunction(&fn.rec), nil
}

// CreateFunction implements [LambdaAPI].
func (l *MemoryLambda) CreateFunction(_ context.Context, in CreateFunctionRequest) (*FunctionRecord, error) {
	if err := l.take(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.funcs[in.Name]; ok {
		return nil, fmt.Errorf("%w: function %q", ErrAlreadyExists, in.Name)
	}
	fn := &memoryFunction{
		rec: FunctionRecord{
			Name: in.Name, ARN: functionARN(in.Name),
			Runtime: in.Runtime, Handler: in.Handler, RoleARN: in.RoleARN,
			MemoryMiB: in.MemoryMiB, TimeoutSeconds: in.TimeoutSeconds,
			Architecture: in.Architecture,
			Env:          copyTags(in.Env),
			// A create carries configuration and code together, so there is
			// nothing to conflict with and the function is merely pending.
			State:            FunctionStatePending,
			LastUpdateStatus: "",
			CodeDigest:       memoryCodeDigest(in.Code),
			Tags:             copyTags(in.Tags),
		},
		policy:   map[string]string{},
		revision: 1,
	}
	if fn.rec.Env == nil {
		fn.rec.Env = map[string]string{}
	}
	if fn.rec.Tags == nil {
		fn.rec.Tags = map[string]string{}
	}
	fn.rec.Revision = strconv.Itoa(fn.revision)
	l.funcs[in.Name] = fn
	return copyFunction(&fn.rec), nil
}

// UpdateFunctionConfiguration implements [LambdaAPI].
func (l *MemoryLambda) UpdateFunctionConfiguration(_ context.Context, in UpdateFunctionConfigurationRequest) (*FunctionRecord, error) {
	return l.mutate(in.Name, func(fn *memoryFunction) {
		fn.rec.Runtime = in.Runtime
		fn.rec.Handler = in.Handler
		fn.rec.RoleARN = in.RoleARN
		fn.rec.MemoryMiB = in.MemoryMiB
		fn.rec.TimeoutSeconds = in.TimeoutSeconds
		fn.rec.Env = copyTags(in.Env)
		if fn.rec.Env == nil {
			fn.rec.Env = map[string]string{}
		}
	})
}

// UpdateFunctionCode implements [LambdaAPI].
func (l *MemoryLambda) UpdateFunctionCode(_ context.Context, name, arch string, code FunctionCode) (*FunctionRecord, error) {
	return l.mutate(name, func(fn *memoryFunction) {
		fn.rec.Architecture = arch
		fn.rec.CodeDigest = memoryCodeDigest(code)
	})
}

// mutate applies one change under Lambda's serialisation rule.
func (l *MemoryLambda) mutate(name string, apply func(*memoryFunction)) (*FunctionRecord, error) {
	if err := l.take(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[name]
	if !ok {
		return nil, fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	if fn.rec.LastUpdateStatus == UpdateStatusInProgress {
		// The behaviour that makes the two-mutation path in
		// [functionRuntime.EnsureFunction] reachable by a test rather than only
		// describable in a comment.
		return nil, fmt.Errorf("%w: function %q", ErrConflict, name)
	}
	apply(fn)
	fn.revision++
	fn.rec.Revision = strconv.Itoa(fn.revision)
	fn.rec.State = FunctionStateActive
	fn.rec.LastUpdateStatus = UpdateStatusInProgress
	return copyFunction(&fn.rec), nil
}

// DeleteFunction implements [LambdaAPI].
func (l *MemoryLambda) DeleteFunction(_ context.Context, name string) error {
	if err := l.take(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.funcs[name]; !ok {
		return fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	delete(l.funcs, name)
	return nil
}

// AddPermission implements [LambdaAPI].
func (l *MemoryLambda) AddPermission(_ context.Context, in AddPermissionRequest) error {
	if err := l.take(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[in.Name]
	if !ok {
		return fmt.Errorf("%w: function %q", ErrNoSuchResource, in.Name)
	}
	if _, exists := fn.policy[in.StatementID]; exists {
		// Lambda's own behaviour, and the reason the provider reads the policy
		// before writing to it: there is no upsert for a statement.
		return fmt.Errorf("%w: statement %q on function %q",
			ErrAlreadyExists, in.StatementID, in.Name)
	}
	// The whole statement is stored, so that a rendered artefact can show what
	// was granted to whom and a test can assert the source condition is present.
	fn.policy[in.StatementID] = in.Principal + " may " + in.Action + " when source is " + in.SourceARN
	return nil
}

// RemovePermission implements [LambdaAPI].
func (l *MemoryLambda) RemovePermission(_ context.Context, name, statementID string) error {
	if err := l.take(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[name]
	if !ok {
		return fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	if _, exists := fn.policy[statementID]; !exists {
		return fmt.Errorf("%w: statement %q on function %q", ErrNoSuchResource, statementID, name)
	}
	delete(fn.policy, statementID)
	return nil
}

// ListStatementIDs implements [LambdaAPI].
func (l *MemoryLambda) ListStatementIDs(_ context.Context, name string) ([]string, error) {
	if err := l.take(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fn, ok := l.funcs[name]
	if !ok {
		return nil, fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	if len(fn.policy) == 0 {
		// Lambda's own answer: a function with no resource policy has no policy
		// to get, rather than an empty one.
		return nil, fmt.Errorf("%w: function %q has no resource policy", ErrNoSuchResource, name)
	}
	return sortedKeys(fn.policy), nil
}

// ListTags implements [LambdaAPI].
func (l *MemoryLambda) ListTags(_ context.Context, arn string) (map[string]string, error) {
	if err := l.take(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, fn := range l.funcs {
		if fn.rec.ARN == arn {
			return copyTags(fn.rec.Tags), nil
		}
	}
	return nil, fmt.Errorf("%w: no function with ARN %q", ErrNoSuchResource, arn)
}

// TagResource implements [LambdaAPI].
func (l *MemoryLambda) TagResource(_ context.Context, arn string, tags map[string]string) error {
	return l.withARN(arn, func(fn *memoryFunction) {
		for k, v := range tags {
			fn.rec.Tags[k] = v
		}
	})
}

// UntagResource implements [LambdaAPI].
func (l *MemoryLambda) UntagResource(_ context.Context, arn string, keys []string) error {
	return l.withARN(arn, func(fn *memoryFunction) {
		for _, k := range keys {
			delete(fn.rec.Tags, k)
		}
	})
}

func (l *MemoryLambda) withARN(arn string, apply func(*memoryFunction)) error {
	if err := l.take(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, fn := range l.funcs {
		if fn.rec.ARN == arn {
			apply(fn)
			return nil
		}
	}
	return fmt.Errorf("%w: no function with ARN %q", ErrNoSuchResource, arn)
}

// Dump renders every function and every resource-policy statement.
//
// The environment is rendered as key=value pairs because that is where the
// conformance suite's convergence marker lives: a variable removed from a spec
// has to be absent here, and a provider that implemented Ensure as
// create-or-add would leave it. The resource policy is rendered because the
// invoke grant is the one thing on this port whose scope a reviewer has to be
// able to see.
func (l *MemoryLambda) Dump() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.funcs))
	for _, name := range functionNames(l.funcs) {
		fn := l.funcs[name]
		fields := []string{
			"runtime=" + fn.rec.Runtime,
			"handler=" + fn.rec.Handler,
			"arch=" + fn.rec.Architecture,
			"memory=" + strconv.Itoa(fn.rec.MemoryMiB),
			"timeout=" + strconv.Itoa(fn.rec.TimeoutSeconds),
			"role=" + fn.rec.RoleARN,
			"code=" + fn.rec.CodeDigest,
		}
		if pairs := sortedPairs(fn.rec.Env); pairs != "" {
			fields = append(fields, pairs)
		}
		if pairs := sortedPairs(fn.rec.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("Function %s: %s", name, strings.Join(fields, " ")))
		for _, id := range sortedKeys(fn.policy) {
			out = append(out, fmt.Sprintf("FunctionPolicy %s: %s=%s", name, id, fn.policy[id]))
		}
	}
	return out
}

func functionNames(m map[string]*memoryFunction) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func copyFunction(in *FunctionRecord) *FunctionRecord {
	out := *in
	out.Env = copyTags(in.Env)
	out.Tags = copyTags(in.Tags)
	return &out
}

// memoryCodeDigest renders a bundle's identity the way Lambda reports one.
//
// For an object bundle there is no content to digest — this substrate holds no
// objects — so the location stands in. That is not a shortcut being hidden: the
// provider never compares digests on that path, precisely because a caller's
// deploy flow overwrites the same key, so a location-derived digest is never
// consulted. See [codeChanged].
func memoryCodeDigest(code FunctionCode) string {
	if code.Zip != nil {
		return codeDigest(code.Zip)
	}
	return "object:" + code.Bucket + "/" + code.Key
}

// --- ELBv2 --------------------------------------------------------------------

// MemoryELBv2 is an in-memory load balancing service.
//
// Like [MemoryLambda] it models the state machine rather than accepting
// everything: a load balancer is created [LoadBalancerProvisioning] and settles
// on observation, so that the endpoint port's Ensure genuinely returns
// [compute.PhasePending] and its Wait genuinely has something to wait for. It
// also enforces the two constraints the provider's convergence logic depends on
// — one listener per port, and a name unique per service — because a substrate
// that let two listeners share a port would hide a real defect in
// [Provider.convergeListeners].
type MemoryELBv2 struct {
	failNext
	mu        sync.Mutex
	balancers map[string]*memoryLoadBalancer
	groups    map[string]*memoryTargetGroup
	listeners map[string]*ListenerRecord
	nextID    int
}

type memoryLoadBalancer struct {
	rec     LoadBalancerRecord
	stalled bool
}

type memoryTargetGroup struct {
	rec TargetGroupRecord
	// targets maps a target identifier to its health state. A map rather than a
	// slice of identifiers because health is the answer to "is this endpoint
	// serving", and a substrate that held only identifiers could not fail a
	// provider that treated registration as health.
	targets map[string]string
	// stalled stops this group's targets from ever becoming healthy. Per group
	// rather than per substrate, for the same reason [memoryLoadBalancer.stalled]
	// is: the conformance suite's stall hook is one-way — it never un-stalls —
	// so a substrate-wide flag set by one check would hold every later check's
	// endpoint pending forever. That is not hypothetical; it is what the first
	// version of this did, and the suite caught it.
	stalled bool
}

var _ ELBv2API = (*MemoryELBv2)(nil)

// NewMemoryELBv2 returns an empty load balancing service.
func NewMemoryELBv2() *MemoryELBv2 {
	return &MemoryELBv2{
		balancers: map[string]*memoryLoadBalancer{},
		groups:    map[string]*memoryTargetGroup{},
		listeners: map[string]*ListenerRecord{},
	}
}

// The ARN shapes this substrate reports. The account position holds a
// placeholder word rather than a number, for the reason at the top of this file.
func loadBalancerARN(name string) string {
	return "arn:aws:elasticloadbalancing:" + MemoryRegion + ":" + MemoryAccount +
		":loadbalancer/app/" + name
}

func targetGroupARN(name string) string {
	return "arn:aws:elasticloadbalancing:" + MemoryRegion + ":" + MemoryAccount +
		":targetgroup/" + name
}

// loadBalancerDNS is the hostname this substrate assigns.
//
// Under the reserved .invalid TLD rather than imitating the real ELBv2 hostname
// shape, for the same reason [MemoryRegistryHost] is: a fixture that looks like
// the real thing is a fixture somebody fills in with the real thing.
func loadBalancerDNS(name string) string { return name + ".lb.invalid" }

// PutUnowned puts a load balancer into the service without apphub's ownership
// tags, so an Ensure has a collision to refuse.
func (e *MemoryELBv2) PutUnowned(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.balancers[name] = &memoryLoadBalancer{rec: LoadBalancerRecord{
		Name: name, ARN: loadBalancerARN(name), DNSName: loadBalancerDNS(name),
		Scheme: SchemeInternetFacing, State: LoadBalancerActive,
		Tags: map[string]string{"created-by": "somebody-else"},
	}}
	e.groups[name] = &memoryTargetGroup{
		rec: TargetGroupRecord{
			Name: name, ARN: targetGroupARN(name), TargetType: TargetTypeLambda,
			Tags: map[string]string{"created-by": "somebody-else"},
		},
		targets: map[string]string{},
	}
}

// Stall stops a load balancer from ever becoming active.
func (e *MemoryELBv2) Stall(name string) func() {
	e.mu.Lock()
	defer e.mu.Unlock()
	lb, ok := e.balancers[name]
	if !ok {
		return func() {}
	}
	lb.stalled = true
	lb.rec.State = LoadBalancerProvisioning
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		lb.stalled = false
	}
}

// DescribeLoadBalancer implements [ELBv2API]. It settles a provisioning load
// balancer, which makes it the observation point.
func (e *MemoryELBv2) DescribeLoadBalancer(_ context.Context, name string) (*LoadBalancerRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	lb, ok := e.balancers[name]
	if !ok {
		return nil, fmt.Errorf("%w: load balancer %q", ErrNoSuchResource, name)
	}
	if !lb.stalled {
		lb.rec.State = LoadBalancerActive
	}
	return copyLoadBalancer(&lb.rec), nil
}

// CreateLoadBalancer implements [ELBv2API].
func (e *MemoryELBv2) CreateLoadBalancer(_ context.Context, in CreateLoadBalancerRequest) (*LoadBalancerRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.balancers[in.Name]; ok {
		return nil, fmt.Errorf("%w: load balancer %q", ErrAlreadyExists, in.Name)
	}
	lb := &memoryLoadBalancer{rec: LoadBalancerRecord{
		Name: in.Name, ARN: loadBalancerARN(in.Name), DNSName: loadBalancerDNS(in.Name),
		Scheme: in.Scheme, State: LoadBalancerProvisioning,
		SecurityGroupIDs: append([]string(nil), in.SecurityGroupIDs...),
		SubnetIDs:        append([]string(nil), in.SubnetIDs...),
		Tags:             copyTags(in.Tags),
	}}
	if lb.rec.Tags == nil {
		lb.rec.Tags = map[string]string{}
	}
	e.balancers[in.Name] = lb
	return copyLoadBalancer(&lb.rec), nil
}

// DeleteLoadBalancer implements [ELBv2API].
func (e *MemoryELBv2) DeleteLoadBalancer(_ context.Context, arn string) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, lb := range e.balancers {
		if lb.rec.ARN != arn {
			continue
		}
		delete(e.balancers, name)
		// Its listeners go with it, which is what ELBv2 does and what makes a
		// re-run of a teardown find nothing rather than orphans.
		for id, l := range e.listeners {
			if strings.HasPrefix(id, arn+"/") {
				delete(e.listeners, id)
				_ = l
			}
		}
		return nil
	}
	return fmt.Errorf("%w: load balancer %q", ErrNoSuchResource, arn)
}

// SetSecurityGroups implements [ELBv2API].
func (e *MemoryELBv2) SetSecurityGroups(_ context.Context, arn string, ids []string) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, lb := range e.balancers {
		if lb.rec.ARN == arn {
			lb.rec.SecurityGroupIDs = append([]string(nil), ids...)
			return nil
		}
	}
	return fmt.Errorf("%w: load balancer %q", ErrNoSuchResource, arn)
}

// DescribeTargetGroup implements [ELBv2API].
func (e *MemoryELBv2) DescribeTargetGroup(_ context.Context, name string) (*TargetGroupRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tg, ok := e.groups[name]
	if !ok {
		return nil, fmt.Errorf("%w: target group %q", ErrNoSuchResource, name)
	}
	return copyTargetGroup(&tg.rec), nil
}

// CreateTargetGroup implements [ELBv2API].
func (e *MemoryELBv2) CreateTargetGroup(_ context.Context, in CreateTargetGroupRequest) (*TargetGroupRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.groups[in.Name]; ok {
		return nil, fmt.Errorf("%w: target group %q", ErrAlreadyExists, in.Name)
	}
	tg := &memoryTargetGroup{
		rec: TargetGroupRecord{
			Name: in.Name, ARN: targetGroupARN(in.Name), TargetType: in.TargetType,
			Tags: copyTags(in.Tags),
		},
		targets: map[string]string{},
	}
	if tg.rec.Tags == nil {
		tg.rec.Tags = map[string]string{}
	}
	e.groups[in.Name] = tg
	return copyTargetGroup(&tg.rec), nil
}

// DeleteTargetGroup implements [ELBv2API].
func (e *MemoryELBv2) DeleteTargetGroup(_ context.Context, arn string) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, tg := range e.groups {
		if tg.rec.ARN == arn {
			delete(e.groups, name)
			return nil
		}
	}
	return fmt.Errorf("%w: target group %q", ErrNoSuchResource, arn)
}

// DescribeTargets implements [ELBv2API]. Like the load balancer, a target
// settles on observation — from [TargetInitial] to [TargetHealthy] — so that a
// Wait has something to converge to and a Stall has something to hold back.
func (e *MemoryELBv2) DescribeTargets(_ context.Context, arn string) ([]TargetHealth, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, tg := range e.groups {
		if tg.rec.ARN != arn {
			continue
		}
		out := make([]TargetHealth, 0, len(tg.targets))
		for _, id := range sortedKeys(tg.targets) {
			if tg.targets[id] == TargetInitial && !tg.stalled {
				tg.targets[id] = TargetHealthy
			}
			out = append(out, TargetHealth{ID: id, State: tg.targets[id]})
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: target group %q", ErrNoSuchResource, arn)
}

// SetTargetHealth forces every target in the named group into a state, so that a
// test can drive the unhealthy half of readiness. An absent group is ignored.
func (e *MemoryELBv2) SetTargetHealth(name, state string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	tg, ok := e.groups[name]
	if !ok {
		return
	}
	// Stalled as well as set, so the next observation does not settle the state
	// the caller just asked for back to healthy.
	tg.stalled = true
	for id := range tg.targets {
		tg.targets[id] = state
	}
}

// StallTargets stops the named group's targets from ever becoming healthy, so
// that a Wait against an active load balancer with a registered target still has
// something to time out on. An absent group is ignored.
func (e *MemoryELBv2) StallTargets(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if tg, ok := e.groups[name]; ok {
		tg.stalled = true
	}
}

// RegisterTargets implements [ELBv2API]. A new target starts [TargetInitial],
// which is what ELBv2 reports and what keeps "registered" from meaning
// "healthy".
func (e *MemoryELBv2) RegisterTargets(_ context.Context, arn string, targets []string) error {
	return e.withGroup(arn, func(tg *memoryTargetGroup) {
		if tg.targets == nil {
			tg.targets = map[string]string{}
		}
		for _, t := range targets {
			if _, ok := tg.targets[t]; !ok {
				tg.targets[t] = TargetInitial
			}
		}
	})
}

// DeregisterTargets implements [ELBv2API].
func (e *MemoryELBv2) DeregisterTargets(_ context.Context, arn string, targets []string) error {
	return e.withGroup(arn, func(tg *memoryTargetGroup) {
		for _, t := range targets {
			delete(tg.targets, t)
		}
	})
}

func (e *MemoryELBv2) withGroup(arn string, apply func(*memoryTargetGroup)) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, tg := range e.groups {
		if tg.rec.ARN == arn {
			apply(tg)
			return nil
		}
	}
	return fmt.Errorf("%w: target group %q", ErrNoSuchResource, arn)
}

// DescribeListeners implements [ELBv2API].
func (e *MemoryELBv2) DescribeListeners(_ context.Context, lbARN string) ([]ListenerRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ListenerRecord
	for id, l := range e.listeners {
		if strings.HasPrefix(id, lbARN+"/") {
			out = append(out, *l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// CreateListener implements [ELBv2API]. One listener per port, which ELBv2 also
// enforces and which the provider's convergence logic relies on.
func (e *MemoryELBv2) CreateListener(_ context.Context, in CreateListenerRequest) (*ListenerRecord, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.findLoadBalancer(in.LoadBalancerARN); !ok {
		return nil, fmt.Errorf("%w: load balancer %q", ErrNoSuchResource, in.LoadBalancerARN)
	}
	for id, l := range e.listeners {
		if strings.HasPrefix(id, in.LoadBalancerARN+"/") && l.Port == in.Port {
			return nil, fmt.Errorf("%w: a listener on port %d", ErrAlreadyExists, in.Port)
		}
	}
	e.nextID++
	rec := &ListenerRecord{
		ARN:            fmt.Sprintf("%s/listener-%d", in.LoadBalancerARN, e.nextID),
		Port:           in.Port,
		Protocol:       in.Protocol,
		CertificateARN: in.CertificateARN,
		TargetGroupARN: in.TargetGroupARN,
	}
	e.listeners[rec.ARN] = rec
	out := *rec
	return &out, nil
}

// DeleteListener implements [ELBv2API].
func (e *MemoryELBv2) DeleteListener(_ context.Context, arn string) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.listeners[arn]; !ok {
		return fmt.Errorf("%w: listener %q", ErrNoSuchResource, arn)
	}
	delete(e.listeners, arn)
	return nil
}

// ListTags implements [ELBv2API].
func (e *MemoryELBv2) ListTags(_ context.Context, arn string) (map[string]string, error) {
	if err := e.take(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if lb, ok := e.findLoadBalancer(arn); ok {
		return copyTags(lb.rec.Tags), nil
	}
	for _, tg := range e.groups {
		if tg.rec.ARN == arn {
			return copyTags(tg.rec.Tags), nil
		}
	}
	return nil, fmt.Errorf("%w: no resource with ARN %q", ErrNoSuchResource, arn)
}

// AddTags implements [ELBv2API].
func (e *MemoryELBv2) AddTags(_ context.Context, arn string, tags map[string]string) error {
	return e.withTags(arn, func(t map[string]string) {
		for k, v := range tags {
			t[k] = v
		}
	})
}

// RemoveTags implements [ELBv2API].
func (e *MemoryELBv2) RemoveTags(_ context.Context, arn string, keys []string) error {
	return e.withTags(arn, func(t map[string]string) {
		for _, k := range keys {
			delete(t, k)
		}
	})
}

func (e *MemoryELBv2) withTags(arn string, apply func(map[string]string)) error {
	if err := e.take(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if lb, ok := e.findLoadBalancer(arn); ok {
		apply(lb.rec.Tags)
		return nil
	}
	for _, tg := range e.groups {
		if tg.rec.ARN == arn {
			apply(tg.rec.Tags)
			return nil
		}
	}
	return fmt.Errorf("%w: no resource with ARN %q", ErrNoSuchResource, arn)
}

func (e *MemoryELBv2) findLoadBalancer(arn string) (*memoryLoadBalancer, bool) {
	for _, lb := range e.balancers {
		if lb.rec.ARN == arn {
			return lb, true
		}
	}
	return nil, false
}

// Dump renders every load balancer with its listeners, and every target group
// with its targets.
//
// The listeners are rendered by [renderListeners], whose format the conformance
// suite reads: it looks for "80/plaintext" before and after a spec that drops
// that listener, so a provider that only ever adds listeners fails there. The
// certificate token appears only for a TLS listener, which is what makes the
// suite's search for `certificate=""` a real check rather than one that could
// never fire.
func (e *MemoryELBv2) Dump() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	names := make([]string, 0, len(e.balancers))
	for name := range e.balancers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lb := e.balancers[name]
		var listeners []ListenerRecord
		for id, l := range e.listeners {
			if strings.HasPrefix(id, lb.rec.ARN+"/") {
				listeners = append(listeners, *l)
			}
		}
		fields := []string{
			"scheme=" + lb.rec.Scheme,
			"subnets=" + strings.Join(lb.rec.SubnetIDs, ","),
			"groups=" + strings.Join(lb.rec.SecurityGroupIDs, ","),
			"listeners=" + renderListeners(listeners),
		}
		if pairs := sortedPairs(lb.rec.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("LoadBalancer %s: %s", name, strings.Join(fields, " ")))
	}
	groups := make([]string, 0, len(e.groups))
	for name := range e.groups {
		groups = append(groups, name)
	}
	sort.Strings(groups)
	for _, name := range groups {
		tg := e.groups[name]
		fields := []string{
			"type=" + tg.rec.TargetType,
			"targets=" + sortedPairs(tg.targets),
		}
		if pairs := sortedPairs(tg.rec.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("TargetGroup %s: %s", name, strings.Join(fields, " ")))
	}
	return out
}

func copyLoadBalancer(in *LoadBalancerRecord) *LoadBalancerRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	out.SecurityGroupIDs = append([]string(nil), in.SecurityGroupIDs...)
	out.SubnetIDs = append([]string(nil), in.SubnetIDs...)
	return &out
}

func copyTargetGroup(in *TargetGroupRecord) *TargetGroupRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	return &out
}

// --- EC2 ----------------------------------------------------------------------

// MemoryEndpointEC2 is an in-memory network service.
//
// It holds a fixed set of subnets, supplied at construction, because a subnet is
// not something apphub creates: it is operator-owned infrastructure this
// provider only reads. Modelling it as read-only is what makes the placement
// checks in [Provider.describeNetwork] testable — a substrate that invented a
// subnet for any identifier asked of it could not fail them.
type MemoryEndpointEC2 struct {
	failNext
	mu         sync.Mutex
	subnets    map[string]EndpointSubnetRecord
	groups     map[string]*memoryEndpointSecurityGroup
	nextID     int
	failDelete error
}

// memoryEndpointSecurityGroup holds a group and its rules separately, because EC2 does:
// a rule is its own taggable object with its own identifier, reported by its own
// API. Modelling it as a field on the group is what let an earlier revision of
// the provider read ownership from a caller-supplied description, since the
// group-level read carries neither identifiers nor tags.
type memoryEndpointSecurityGroup struct {
	rec   EndpointSecurityGroupRecord
	rules []EndpointSecurityGroupRule
}

var _ EndpointEC2API = (*MemoryEndpointEC2)(nil)

// The subnet fixtures. Two subnets in two availability zones, which is the
// minimum an application load balancer accepts.
//
// The identifiers are deliberately not shaped like real ones: a real subnet
// identifier is "subnet-" plus seventeen hex digits, and a fixture imitating
// that shape is a fixture somebody eventually pastes a real one into. The
// provider never parses them.
const (
	MemorySubnetA = "subnet-placeholder-a"
	MemorySubnetB = "subnet-placeholder-b"
	// MemorySubnetOtherVPC and MemorySubnetOtherVPCB are subnets in a different
	// VPC. One of them gives the one-VPC-per-placement check something to refuse;
	// the pair gives a *valid* placement in a second VPC, which is what the
	// removed-placement teardown transition needs — without two, that transition
	// cannot be constructed and the test that found the defect could not exist.
	MemorySubnetOtherVPC  = "subnet-placeholder-other-vpc"
	MemorySubnetOtherVPCB = "subnet-placeholder-other-vpc-b"
	// MemorySubnetSameZone is a second subnet in zone A, so that the
	// two-availability-zone check has something to refuse.
	MemorySubnetSameZone = "subnet-placeholder-same-zone"

	// MemoryOtherVPC is the second VPC those subnets live in. The first is
	// [MemoryVPC], shared with the relational port's fixtures so the package
	// does not carry two placeholder spellings of one concept.
	MemoryOtherVPC = "vpc-placeholder-other"

	// MemoryZoneA and MemoryZoneB are the two availability zones. Not real zone
	// slugs, for the same reason MemoryRegion is not a real region slug.
	MemoryZoneA = "test-zone-a"
	MemoryZoneB = "test-zone-b"

	// MemoryIngressGroup is the security group a placement can name as its
	// platform ingress proxy, so that a PeerPlatformIngress rule has something
	// to resolve to.
	MemoryIngressGroup = "sg-placeholder-ingress"
)

// NewMemoryEndpointEC2 returns a network service holding the fixture subnets.
func NewMemoryEndpointEC2() *MemoryEndpointEC2 {
	return &MemoryEndpointEC2{
		subnets: map[string]EndpointSubnetRecord{
			MemorySubnetA:         {ID: MemorySubnetA, VpcID: MemoryVPC, AvailabilityZone: MemoryZoneA},
			MemorySubnetB:         {ID: MemorySubnetB, VpcID: MemoryVPC, AvailabilityZone: MemoryZoneB},
			MemorySubnetSameZone:  {ID: MemorySubnetSameZone, VpcID: MemoryVPC, AvailabilityZone: MemoryZoneA},
			MemorySubnetOtherVPC:  {ID: MemorySubnetOtherVPC, VpcID: MemoryOtherVPC, AvailabilityZone: MemoryZoneB},
			MemorySubnetOtherVPCB: {ID: MemorySubnetOtherVPCB, VpcID: MemoryOtherVPC, AvailabilityZone: MemoryZoneA},
		},
		groups: map[string]*memoryEndpointSecurityGroup{},
	}
}

// PutUnowned puts a security group into the service without apphub's ownership
// tags.
func (c *MemoryEndpointEC2) PutUnowned(vpcID, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := fmt.Sprintf("sg-placeholder-%d", c.nextID)
	c.groups[groupKey(vpcID, name)] = &memoryEndpointSecurityGroup{rec: EndpointSecurityGroupRecord{
		ID: id, Name: name, VpcID: vpcID,
		Tags: map[string]string{"created-by": "somebody-else"},
	}}
}

func groupKey(vpcID, name string) string { return vpcID + "/" + name }

// DescribeSecurityGroup implements [EndpointEC2API].
func (c *MemoryEndpointEC2) DescribeSecurityGroup(_ context.Context, vpcID, name string) (*EndpointSecurityGroupRecord, error) {
	if err := c.take(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.groups[groupKey(vpcID, name)]
	if !ok {
		return nil, fmt.Errorf("%w: security group %q in %q", ErrNoSuchResource, name, vpcID)
	}
	return copySecurityGroup(&g.rec), nil
}

// FindSecurityGroups implements [EndpointEC2API].
//
// Region-wide by construction: this substrate holds one region, so iterating
// every group it has *is* the region. The tags are ANDed, matching the SDK's
// filter semantics — a group missing any one of them is not returned.
//
// # The empty-tag refusal is here because the SDK adapter has it
//
// An earlier revision returned **every group** for an empty tag set while the SDK
// adapter refused the call. That divergence runs the wrong way: a test passes
// against this substrate by matching everything, and the same code is rejected
// outright in production. And the general point is worse than this instance —
// **whichever way a fake diverges from its substrate, the fake is the thing that
// gets tested**, so the divergence decides what the suite can discover.
//
// So the refusal is duplicated rather than left to the adapter, and there is a
// test asserting the two seams agree on it rather than trusting that they do.
func (c *MemoryEndpointEC2) FindSecurityGroups(_ context.Context, tags map[string]string) ([]EndpointSecurityGroupRecord, error) {
	if err := c.take(); err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("%w: no tags were given, and an unfiltered search would return "+
			"every security group in the region", compute.ErrInvalidSpec)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []EndpointSecurityGroupRecord
	for _, key := range sortedGroupKeys(c.groups) {
		g := c.groups[key]
		matched := true
		for k, v := range tags {
			if g.rec.Tags[k] != v {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, *copySecurityGroup(&g.rec))
		}
	}
	return out, nil
}

// UpdateSecurityGroupRuleDescriptions implements [EndpointEC2API]. A rule identifier this
// group does not hold is ignored, which is what EC2 does.
func (c *MemoryEndpointEC2) UpdateSecurityGroupRuleDescriptions(_ context.Context, id string, rules []EndpointSecurityGroupRule) error {
	return c.withGroup(id, func(g *memoryEndpointSecurityGroup) error {
		want := make(map[string]string, len(rules))
		for _, r := range rules {
			want[r.ID] = r.Description
		}
		for i := range g.rules {
			if desc, ok := want[g.rules[i].ID]; ok {
				g.rules[i].Description = desc
			}
		}
		return nil
	})
}

// tagRule applies tags to one rule by identifier, reporting absence so the caller
// can fall through to treating the identifier as a group's.
func (c *MemoryEndpointEC2) tagRule(ruleID string, tags map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		for i := range g.rules {
			if g.rules[i].ID != ruleID {
				continue
			}
			if g.rules[i].Tags == nil {
				g.rules[i].Tags = map[string]string{}
			}
			for k, v := range tags {
				g.rules[i].Tags[k] = v
			}
			return nil
		}
	}
	return fmt.Errorf("%w: security group rule %q", ErrNoSuchResource, ruleID)
}

// PutRuleWithTags adds a rule to a group carrying exactly the tags given, so a test
// can construct the state a previous version of this package left behind — an owned
// rule with no [tagPeer]. There is no other way to reach it: the current write path
// always records the peer kind, which is precisely why the migration path needed a
// deliberately-constructed witness rather than one that arises by accident.
func (c *MemoryEndpointEC2) PutRuleWithTags(groupID string, rule EndpointSecurityGroupRule, tags map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		if g.rec.ID != groupID {
			continue
		}
		c.nextID++
		rule.ID = fmt.Sprintf("sgr-placeholder-%d", c.nextID)
		rule.Tags = copyTags(tags)
		g.rules = append(g.rules, rule)
		sort.Slice(g.rules, func(i, j int) bool { return endpointRuleKey(g.rules[i]) < endpointRuleKey(g.rules[j]) })
	}
}

// sortedGroupKeys is for a deterministic FindSecurityGroups and Dump.
func sortedGroupKeys(m map[string]*memoryEndpointSecurityGroup) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DescribeSecurityGroupRules implements [EndpointEC2API].
func (c *MemoryEndpointEC2) DescribeSecurityGroupRules(_ context.Context, id string) ([]EndpointSecurityGroupRule, error) {
	if err := c.take(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		if g.rec.ID != id {
			continue
		}
		out := make([]EndpointSecurityGroupRule, 0, len(g.rules))
		for _, r := range g.rules {
			r.Tags = copyTags(r.Tags)
			out = append(out, r)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
}

// PutUntaggedRule adds a rule to a group without any tags, which is what a rule
// an operator created out of band looks like. It exists so a test can drive the
// half of the ownership rule that must *not* revoke.
func (c *MemoryEndpointEC2) PutUntaggedRule(id string, rule EndpointSecurityGroupRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		if g.rec.ID != id {
			continue
		}
		c.nextID++
		rule.ID = fmt.Sprintf("sgr-placeholder-%d", c.nextID)
		rule.Tags = nil
		g.rules = append(g.rules, rule)
	}
}

// CreateSecurityGroup implements [EndpointEC2API].
func (c *MemoryEndpointEC2) CreateSecurityGroup(_ context.Context, in EndpointCreateSecurityGroupRequest) (*EndpointSecurityGroupRecord, error) {
	if err := c.take(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := groupKey(in.VpcID, in.Name)
	if _, ok := c.groups[key]; ok {
		return nil, fmt.Errorf("%w: security group %q in %q", ErrAlreadyExists, in.Name, in.VpcID)
	}
	c.nextID++
	g := &memoryEndpointSecurityGroup{rec: EndpointSecurityGroupRecord{
		ID:    fmt.Sprintf("sg-placeholder-%d", c.nextID),
		Name:  in.Name,
		VpcID: in.VpcID,
		Tags:  copyTags(in.Tags),
	}}
	if g.rec.Tags == nil {
		g.rec.Tags = map[string]string{}
	}
	c.groups[key] = g
	return copySecurityGroup(&g.rec), nil
}

// FailNextDelete makes the next DeleteSecurityGroup fail, until the returned
// function is called.
//
// Narrower than [failNext.FailNext] on purpose. The behaviour worth reproducing
// is EC2's, and EC2 refuses *this one call* while a load balancer's network
// interfaces are still attached — everything else on the path keeps working. A
// substrate-wide injector would fail the describes as well, so a teardown test
// built on it would be exercising an error path AWS does not produce and would
// not notice a teardown that returned success while leaving the group behind.
func (c *MemoryEndpointEC2) FailNextDelete(err error) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failDelete = err
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.failDelete = nil
	}
}

// DeleteSecurityGroup implements [EndpointEC2API].
func (c *MemoryEndpointEC2) DeleteSecurityGroup(_ context.Context, id string) error {
	if err := c.take(); err != nil {
		return err
	}
	c.mu.Lock()
	if err := c.failDelete; err != nil {
		c.failDelete = nil
		c.mu.Unlock()
		return fmt.Errorf("%w: security group %q is still in use", err, id)
	}
	c.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, g := range c.groups {
		if g.rec.ID == id {
			delete(c.groups, key)
			return nil
		}
	}
	return fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
}

// AuthorizeSecurityGroupIngress implements [EndpointEC2API]. A duplicate rule is
// [ErrAlreadyExists], which EC2 also reports and which is what makes an
// unconditional re-authorise a real defect rather than a harmless one.
func (c *MemoryEndpointEC2) AuthorizeSecurityGroupIngress(_ context.Context, id string, rules []EndpointSecurityGroupRule, tags map[string]string) error {
	return c.withGroup(id, func(g *memoryEndpointSecurityGroup) error {
		for _, r := range rules {
			for _, have := range g.rules {
				if endpointRuleKey(have) == endpointRuleKey(r) {
					return fmt.Errorf("%w: an ingress rule %s on %q",
						ErrAlreadyExists, endpointRuleKey(r), id)
				}
			}
			c.nextID++
			r.ID = fmt.Sprintf("sgr-placeholder-%d", c.nextID)
			// One TagSpecification per call, applied to every rule it created,
			// which is the granularity EC2 has.
			r.Tags = copyTags(tags)
			g.rules = append(g.rules, r)
		}
		sort.Slice(g.rules, func(i, j int) bool {
			return endpointRuleKey(g.rules[i]) < endpointRuleKey(g.rules[j])
		})
		return nil
	})
}

// RevokeSecurityGroupIngress implements [EndpointEC2API].
func (c *MemoryEndpointEC2) RevokeSecurityGroupIngress(_ context.Context, id string, ruleIDs []string) error {
	return c.withGroup(id, func(g *memoryEndpointSecurityGroup) error {
		drop := make(map[string]struct{}, len(ruleIDs))
		for _, r := range ruleIDs {
			drop[r] = struct{}{}
		}
		keep := g.rules[:0]
		for _, have := range g.rules {
			if _, ok := drop[have.ID]; ok {
				continue
			}
			keep = append(keep, have)
		}
		g.rules = keep
		return nil
	})
}

// CreateTags implements [EndpointEC2API].
func (c *MemoryEndpointEC2) CreateTags(_ context.Context, resourceID string, tags map[string]string) error {
	// A rule identifier as well as a group identifier. EC2's CreateTags takes any
	// taggable resource, and `security-group-rule` is one — which is what makes
	// retagging a rule that predates [tagPeer] possible without a new API. A
	// substrate that only accepted group identifiers here would have made the
	// migration path look impossible.
	if err := c.tagRule(resourceID, tags); err == nil {
		return nil
	}
	return c.withGroup(resourceID, func(g *memoryEndpointSecurityGroup) error {
		for k, v := range tags {
			g.rec.Tags[k] = v
		}
		return nil
	})
}

// DeleteTags implements [EndpointEC2API].
func (c *MemoryEndpointEC2) DeleteTags(_ context.Context, resourceID string, keys []string) error {
	return c.withGroup(resourceID, func(g *memoryEndpointSecurityGroup) error {
		for _, k := range keys {
			delete(g.rec.Tags, k)
		}
		return nil
	})
}

func (c *MemoryEndpointEC2) withGroup(id string, apply func(*memoryEndpointSecurityGroup) error) error {
	if err := c.take(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		if g.rec.ID == id {
			return apply(g)
		}
	}
	return fmt.Errorf("%w: security group %q", ErrNoSuchResource, id)
}

// DescribeSubnets implements [EndpointEC2API]. An unknown identifier is
// [ErrNoSuchResource] rather than an omission, so the provider's count check has
// a partial answer to catch as well as a missing one.
func (c *MemoryEndpointEC2) DescribeSubnets(_ context.Context, ids []string) ([]EndpointSubnetRecord, error) {
	if err := c.take(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]EndpointSubnetRecord, 0, len(ids))
	for _, id := range ids {
		sn, ok := c.subnets[id]
		if !ok {
			return nil, fmt.Errorf("%w: subnet %q", ErrNoSuchResource, id)
		}
		out = append(out, sn)
	}
	return out, nil
}

// Dump renders every security group with its rule set.
//
// The rules are rendered as protocol/port/peer, so that a rule removed from a
// spec is observably gone rather than merely reported gone — which is the half
// of the declarative contract an authorise-only implementation fails.
func (c *MemoryEndpointEC2) Dump() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.groups))
	for k := range c.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		g := c.groups[k]
		fields := []string{"vpc=" + g.rec.VpcID, "ingress=" + endpointRenderRules(g.rules)}
		if pairs := sortedPairs(g.rec.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("SecurityGroup %s: %s", g.rec.Name, strings.Join(fields, " ")))
	}
	return out
}

func copySecurityGroup(in *EndpointSecurityGroupRecord) *EndpointSecurityGroupRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	return &out
}

// emitInto records a marker for a channel. See [Harness.EmitInto].
func (b *RecordingBuilder) emitInto(channel, marker string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.emissions == nil {
		b.emissions = map[string]string{}
	}
	b.emissions[channel] = marker
}

// emission returns the marker for a channel, prefixed with a space, or empty.
func (b *RecordingBuilder) emission(channel string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m := b.emissions[channel]; m != "" {
		return " " + m
	}
	return ""
}

// --- object storage ---------------------------------------------------------

// memoryBucket is one general-purpose bucket's state.
type memoryBucket struct {
	region     string
	tags       map[string]string
	blocked    bool
	encryption string
	// versions is every object version and delete marker the bucket holds, in
	// the order they were written. Nothing in this package writes objects, so it
	// is only ever set by [MemoryS3.PutObject] and [MemoryS3.PutObjectVersions]
	// from a test that needs a non-empty bucket.
	versions []memoryVersion
	// nextVersion numbers the versions [MemoryS3.PutObjectVersions] writes, so
	// every version ID in a bucket is distinct.
	nextVersion int
}

// memoryVersion is one object version or delete marker.
type memoryVersion struct {
	ObjectVersion
	// visible reports a current object that is not a delete marker: what a
	// plain object listing, and therefore IsEmpty, sees. A noncurrent version
	// and a delete marker are invisible to it and still stop S3 deleting the
	// bucket, which is the difference EmptyBucket exists to close.
	visible bool
}

// MemoryS3 is an in-memory general-purpose object store.
//
// It models the three things about S3 that the provider has to get right and
// that a looser fake would let pass: a bucket name is global, so a create can
// collide with a bucket the caller cannot see; tagging replaces the whole set;
// and "no tag set" is a distinct answer from "no such bucket".
type MemoryS3 struct {
	failNext
	mu      sync.Mutex
	buckets map[string]*memoryBucket
	// trace records every operation called, in order, so a test can derive the
	// set of calls an operation makes instead of listing them.
	trace []string
	// failNth holds occurrence-targeted failures: fail the nth call of an
	// operation rather than the next one or every one.
	failNth map[string]nthFailure
	// failOp holds operation-targeted failures, keyed by method name. Separate
	// from failNext because the two answer different questions: failNext is
	// "the next call, whatever it is" and this is "this call, whenever it comes".
	failOp map[string]error
	// foreign holds names that exist in another account, mapped to how HeadBucket
	// answers for them: true for ErrDenied, false for ErrNoSuchResource.
	//
	// Both, because S3's HeadBucket documentation says an inaccessible bucket
	// comes back 400, 403 or 404 and does not say when -- so a provider meets
	// either, and a fixture that modelled one would leave the other's path
	// undriven. CreateBucket reports [ErrNameTaken] for these whichever answer
	// the HEAD gave: the create is the call that can tell, and it is the same
	// call in both cases.
	foreign map[string]bool
}

// NewMemoryS3 returns an empty object store.
func NewMemoryS3() *MemoryS3 {
	return &MemoryS3{buckets: map[string]*memoryBucket{}, foreign: map[string]bool{}}
}

// FailOn makes one named operation fail, until the returned function runs.
//
// # Why the existing injectors cannot express this
//
// [failNext.FailNext] fails the *next* call and [failNext.FailUntilStopped] fails
// *every* call, and both therefore fail the FIRST call an operation makes. For a
// converge that reads before it writes, that is HeadBucket -- so an armed failure
// aborts the Ensure before it creates anything, and a test claiming to exercise a
// failure *between* the create and the tagging never enters that window at all.
//
// Two such tests were written and both passed vacuously: removing the code they
// were meant to guard changed nothing, because the guarded path was never reached.
// The tell was a control reporting DID NOT FIRE.
//
// So this targets an operation by name. It is a string rather than a typed enum
// because the operations are this type's own method names and the test reads better
// naming them -- and a name that matches no method is fatal rather than silent, for
// the usual reason.
func (s *MemoryS3) FailOn(op string, err error) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failOp == nil {
		s.failOp = map[string]error{}
	}
	s.failOp[op] = err
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.failOp, op)
	}
}

// KnownOperations names every operation FailOn accepts.
//
// Derived from nothing -- it is a list -- but its omissions are fatal: FailOn's
// caller checks against it, so a name that is not an operation stops the test
// rather than arming a failure that can never fire. A misspelt operation name is
// otherwise indistinguishable from an operation that is never called, which is the
// same silence this whole mechanism exists to break.
func (s *MemoryS3) KnownOperations() []string {
	return []string{
		"HeadBucket", "CreateBucket", "DeleteBucket", "IsEmpty", "ListObjectVersions",
		"DeleteObjectVersions", "GetBucketLocation", "PutPublicAccessBlock", "GetPublicAccessBlock", "PutBucketEncryption",
		"GetBucketEncryption", "GetBucketTagging", "PutBucketTagging",
	}
}

// FailOnNth makes the nth call of one operation fail, counting from 1.
//
// # Why an occurrence index and not just a name
//
// [MemoryS3.FailOn] targets an operation by name, and a converge calls some
// operations more than once. Every subtest derived from a trace with a repeated
// operation therefore failed the FIRST occurrence — so three occurrences of
// GetBucketTagging produced three subtests that all exercised the same one, and a
// deliberate strand at the second was invisible while the suite reported three
// green cells. **The occurrence index is an axis that cannot traverse when the
// injector only knows the name**, and a trace is a sequence rather than a set.
func (s *MemoryS3) FailOnNth(op string, nth int, err error) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNth == nil {
		s.failNth = map[string]nthFailure{}
	}
	s.failNth[op] = nthFailure{want: nth, err: err}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.failNth, op)
	}
}

// nthFailure is an occurrence-targeted failure and its progress.
type nthFailure struct {
	want int
	seen int
	err  error
	// fired records that this arming was actually consumed -- the nth call
	// happened and the injected error was returned.
	//
	// Separate from seen: seen counts calls, which reaches want and passes it, so
	// "seen >= want" is not the same claim once an arming is left in place across
	// further calls. Only a test reads this. See [MemoryS3.NthInjectionFired].
	fired bool
}

// takeOp records that op was called and reports an operation-targeted failure, if
// one is armed for it.
//
// It records as well as intercepts because every method already calls it, which
// makes it the one place a complete trace can be taken without a second list of
// call sites to keep in step. A trace assembled anywhere else would be a
// hand-maintained restatement of this function's callers.
func (s *MemoryS3) takeOp(op string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trace = append(s.trace, op)
	if n, ok := s.failNth[op]; ok {
		n.seen++
		s.failNth[op] = n
		if n.seen == n.want {
			n.fired = true
			s.failNth[op] = n
			return n.err
		}
	}
	return s.failOp[op]
}

// NthInjectionFired reports whether the occurrence-targeted arming for op was
// consumed: the nth call happened and the injected error was returned.
//
// # Why an error coming back is not the same observation
//
// A test that arms an injection and asserts the call failed is asserting that
// SOMETHING failed. That is the right control while the injection is the only
// thing that can fail, and it stops being the right control the moment another
// failure path is added to the code under test -- at which point the cell passes,
// measures nothing, and says nothing about it. The cell's own name goes on
// claiming the injection was exercised.
//
// This is the shape USOSS-19 hit from the other side: a collision cell that
// "passed cleanly" because the path it was written for did not exist in its
// fixture. Their remedy generalises -- every cell carries a positive control that
// fails immediately when the cell asserts nothing -- and the control has to be on
// the mechanism the cell is about, not on a consequence that other causes share.
//
// [failNext.injectionFired] is the equivalent for the name-targeted and sticky
// armings; this one is separate because [MemoryS3.FailOnNth] keeps its state in
// its own map rather than in the embedded injector.
func (s *MemoryS3) NthInjectionFired(op string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failNth[op].fired
}

// Operations returns the operations called on this substrate, in order.
//
// It exists so a test can DERIVE the set of calls an operation makes rather than
// typing one. The strand test's population was a hand literal beneath a name
// promising "every operation": adding a real fifth call inside the create window
// left it green, and adding that call to the literal by hand made it red. **A test
// called "every operation" whose operations are typed by hand is a list wearing a
// derivation's name.**
func (s *MemoryS3) Operations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.trace...)
}

// ResetOperations clears the trace, so a test can scope it to one call.
func (s *MemoryS3) ResetOperations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trace = nil
}

// PutUnowned creates a bucket without apphub's ownership tags, so an Ensure has
// a collision to refuse.
func (s *MemoryS3) PutUnowned(name, region string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[name] = &memoryBucket{
		region: region,
		tags:   map[string]string{"created-by": "somebody-else"},
	}
}

// PutForeign marks a name as taken by another account, with HeadBucket answering
// as denied -- S3's 403, the common answer for a bucket another account owns.
//
// An Ensure against one of these gets as far as the HEAD and no further, so what
// it reports is a denial with no way to know a collision caused it. That is the
// ambiguous half of the case and [objectStore.EnsureBucket] says so rather than
// guessing; [MemoryS3.PutForeignAbsent] is the half where the create answers.
func (s *MemoryS3) PutForeign(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.foreign[name] = true
}

// PutForeignAbsent marks a name as taken by another account, with HeadBucket
// answering as not-found -- S3's 404, the other answer its documentation allows
// for a bucket the caller cannot access.
//
// This is the half a provider can resolve: the Ensure reads "absent", tries the
// create, and the create is refused with [ErrNameTaken]. Modelled because it is
// the only path on which a collision is reported as a collision.
func (s *MemoryS3) PutForeignAbsent(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.foreign[name] = false
}

// PutObject makes a bucket non-empty, so a delete has something to refuse over.
//
// The object is unversioned: its version ID is "null", which is what S3 reports
// for an object in a bucket that has never had versioning enabled.
func (s *MemoryS3) PutObject(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[name]; ok {
		b.nextVersion++
		b.versions = append(b.versions, memoryVersion{
			ObjectVersion: ObjectVersion{Key: fmt.Sprintf("object-%d", b.nextVersion), VersionID: "null"},
			visible:       true,
		})
	}
}

// PutObjectVersions writes n versions of key to a versioned bucket and, when
// deleted is true, a delete marker on top of them.
//
// With deleted set, the bucket holds data that a plain object listing cannot
// see: [MemoryS3.IsEmpty] answers true, and [MemoryS3.DeleteBucket] still
// refuses, exactly as S3 does. That is the shape of a versioned bucket whose
// objects were "deleted" by an application, and it is the case a version-blind
// EmptyBucket would leave undeletable.
func (s *MemoryS3) PutObjectVersions(name, key string, n int, deleted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[name]
	if !ok {
		return
	}
	for i := range n {
		b.nextVersion++
		b.versions = append(b.versions, memoryVersion{
			ObjectVersion: ObjectVersion{Key: key, VersionID: fmt.Sprintf("v%d", b.nextVersion)},
			visible:       i == n-1 && !deleted,
		})
	}
	if deleted {
		b.nextVersion++
		b.versions = append(b.versions, memoryVersion{
			ObjectVersion: ObjectVersion{Key: key, VersionID: fmt.Sprintf("v%d", b.nextVersion)},
		})
	}
}

// withBucket runs fn against one bucket, or reports why it cannot.
func (s *MemoryS3) withBucket(name string, fn func(*memoryBucket) error) error {
	if err := s.take(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if denied, ok := s.foreign[name]; ok {
		if denied {
			return fmt.Errorf("%w: bucket %q is in another account", ErrDenied, name)
		}
		return fmt.Errorf("%w: bucket %q", ErrNoSuchResource, name)
	}
	b, ok := s.buckets[name]
	if !ok {
		return fmt.Errorf("%w: bucket %q", ErrNoSuchResource, name)
	}
	return fn(b)
}

// HeadBucket implements [S3API].
func (s *MemoryS3) HeadBucket(_ context.Context, name string) error {
	if err := s.takeOp("HeadBucket"); err != nil {
		return err
	}
	return s.withBucket(name, func(*memoryBucket) error { return nil })
}

// CreateBucket implements [S3API].
func (s *MemoryS3) CreateBucket(_ context.Context, name, region string) error {
	if err := s.takeOp("CreateBucket"); err != nil {
		return err
	}
	if err := s.take(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.foreign[name]; ok {
		// A globally unique namespace: the name is taken and by whom is not
		// something the caller is allowed to learn. ErrNameTaken rather than
		// ErrDenied, because a create is the one call S3 answers precisely --
		// BucketAlreadyExists for another account's name against
		// BucketAlreadyOwnedByYou for this one -- and a substrate that reported
		// a denial here would throw away the only unambiguous answer there is.
		return fmt.Errorf("%w: bucket %q is in another account", ErrNameTaken, name)
	}
	if _, ok := s.buckets[name]; ok {
		return fmt.Errorf("%w: bucket %q", ErrAlreadyExists, name)
	}
	s.buckets[name] = &memoryBucket{region: region, tags: map[string]string{}}
	return nil
}

// DeleteBucket implements [S3API].
func (s *MemoryS3) DeleteBucket(_ context.Context, name string) error {
	if err := s.takeOp("DeleteBucket"); err != nil {
		return err
	}
	if err := s.take(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[name]
	if !ok {
		return fmt.Errorf("%w: bucket %q", ErrNoSuchResource, name)
	}
	if len(b.versions) > 0 {
		// S3 refuses this too, for noncurrent versions and delete markers as
		// well as for objects a listing can see. The provider refuses it earlier and with a
		// better message, and this is the backstop that proves it does.
		return fmt.Errorf("bucket %q is not empty", name)
	}
	delete(s.buckets, name)
	return nil
}

// IsEmpty implements [S3API].
func (s *MemoryS3) IsEmpty(_ context.Context, name string) (bool, error) {
	if err := s.takeOp("IsEmpty"); err != nil {
		return false, err
	}
	empty := false
	err := s.withBucket(name, func(b *memoryBucket) error {
		empty = !slices.ContainsFunc(b.versions, func(v memoryVersion) bool { return v.visible })
		return nil
	})
	return empty, err
}

// ListObjectVersions implements [S3API].
func (s *MemoryS3) ListObjectVersions(_ context.Context, name string) ([]ObjectVersion, error) {
	if err := s.takeOp("ListObjectVersions"); err != nil {
		return nil, err
	}
	var page []ObjectVersion
	err := s.withBucket(name, func(b *memoryBucket) error {
		page = make([]ObjectVersion, 0, min(len(b.versions), s3MaxKeys))
		for _, v := range b.versions[:min(len(b.versions), s3MaxKeys)] {
			page = append(page, v.ObjectVersion)
		}
		return nil
	})
	return page, err
}

// DeleteObjectVersions implements [S3API].
func (s *MemoryS3) DeleteObjectVersions(_ context.Context, name string, versions []ObjectVersion) error {
	if err := s.takeOp("DeleteObjectVersions"); err != nil {
		return err
	}
	if len(versions) > s3MaxKeys {
		return fmt.Errorf("%w: %d versions in one batch delete, and S3 accepts at most %d",
			ErrMalformed, len(versions), s3MaxKeys)
	}
	doomed := make(map[ObjectVersion]bool, len(versions))
	for _, v := range versions {
		doomed[v] = true
	}
	return s.withBucket(name, func(b *memoryBucket) error {
		b.versions = slices.DeleteFunc(b.versions, func(v memoryVersion) bool {
			return doomed[v.ObjectVersion]
		})
		return nil
	})
}

// GetBucketLocation implements [S3API].
func (s *MemoryS3) GetBucketLocation(_ context.Context, name string) (string, error) {
	if err := s.takeOp("GetBucketLocation"); err != nil {
		return "", err
	}
	var region string
	err := s.withBucket(name, func(b *memoryBucket) error {
		region = b.region
		return nil
	})
	return region, err
}

// PutPublicAccessBlock implements [S3API].
func (s *MemoryS3) PutPublicAccessBlock(_ context.Context, name string) error {
	if err := s.takeOp("PutPublicAccessBlock"); err != nil {
		return err
	}
	return s.withBucket(name, func(b *memoryBucket) error { b.blocked = true; return nil })
}

// GetPublicAccessBlock implements [S3API].
func (s *MemoryS3) GetPublicAccessBlock(_ context.Context, name string) (bool, error) {
	if err := s.takeOp("GetPublicAccessBlock"); err != nil {
		return false, err
	}
	var blocked bool
	err := s.withBucket(name, func(b *memoryBucket) error { blocked = b.blocked; return nil })
	return blocked, err
}

// PutBucketEncryption implements [S3API].
func (s *MemoryS3) PutBucketEncryption(_ context.Context, name, algorithm string) error {
	if err := s.takeOp("PutBucketEncryption"); err != nil {
		return err
	}
	return s.withBucket(name, func(b *memoryBucket) error { b.encryption = algorithm; return nil })
}

// GetBucketEncryption implements [S3API].
func (s *MemoryS3) GetBucketEncryption(_ context.Context, name string) (string, error) {
	if err := s.takeOp("GetBucketEncryption"); err != nil {
		return "", err
	}
	var alg string
	err := s.withBucket(name, func(b *memoryBucket) error { alg = b.encryption; return nil })
	return alg, err
}

// GetBucketTagging implements [S3API].
func (s *MemoryS3) GetBucketTagging(_ context.Context, name string) (map[string]string, error) {
	if err := s.takeOp("GetBucketTagging"); err != nil {
		return nil, err
	}
	var tags map[string]string
	err := s.withBucket(name, func(b *memoryBucket) error { tags = copyTags(b.tags); return nil })
	return tags, err
}

// PutBucketTagging implements [S3API], replacing the whole set.
//
// Whole-set replacement is modelled deliberately rather than merged here,
// because it is what S3 does and because a fake that merged would hide the
// defect this is the substrate for: sending only the tags this provider owns
// deletes an operator's cost and compliance tags and reports success.
func (s *MemoryS3) PutBucketTagging(_ context.Context, name string, tags map[string]string) error {
	if err := s.takeOp("PutBucketTagging"); err != nil {
		return err
	}
	return s.withBucket(name, func(b *memoryBucket) error {
		b.tags = copyTags(tags)
		return nil
	})
}

// Dump reports every bucket, for the Rendered hook.
func (s *MemoryS3) Dump() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.buckets))
	for name := range s.buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		b := s.buckets[name]
		fields := []string{
			"region=" + b.region,
			"public-access-blocked=" + strconv.FormatBool(b.blocked),
			"encryption=" + b.encryption,
		}
		if pairs := sortedPairs(b.tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("Bucket %s: %s", name, strings.Join(fields, " ")))
	}
	return out
}

var _ S3API = (*MemoryS3)(nil)

// --- table and vector buckets -----------------------------------------------

// MemoryS3Tables is an in-memory table-bucket service.
type MemoryS3Tables struct {
	failNext
	mu      sync.Mutex
	buckets map[string]*TableBucketRecord
}

// NewMemoryS3Tables returns an empty table-bucket service.
func NewMemoryS3Tables() *MemoryS3Tables {
	return &MemoryS3Tables{buckets: map[string]*TableBucketRecord{}}
}

// tableBucketARN is how this substrate answers "what is this table bucket's ARN".
func tableBucketARN(name string) string {
	return "arn:aws:s3tables:" + MemoryRegion + ":" + MemoryAccount + ":bucket/" + name
}

// PutUnowned creates a table bucket without apphub's ownership tags.
func (m *MemoryS3Tables) PutUnowned(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buckets[name] = &TableBucketRecord{
		Name: name, ARN: tableBucketARN(name),
		Tags: map[string]string{"created-by": "somebody-else"},
	}
}

// GetTableBucket implements [S3TablesAPI].
func (m *MemoryS3Tables) GetTableBucket(_ context.Context, name string) (*TableBucketRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.buckets[name]
	if !ok {
		return nil, fmt.Errorf("%w: table bucket %q", ErrNoSuchResource, name)
	}
	out := *rec
	out.Tags = copyTags(rec.Tags)
	return &out, nil
}

// CreateTableBucket implements [S3TablesAPI].
func (m *MemoryS3Tables) CreateTableBucket(_ context.Context, name string, tags map[string]string) (*TableBucketRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.buckets[name]; ok {
		return nil, fmt.Errorf("%w: table bucket %q", ErrAlreadyExists, name)
	}
	rec := &TableBucketRecord{Name: name, ARN: tableBucketARN(name), Tags: copyTags(tags)}
	m.buckets[name] = rec
	out := *rec
	out.Tags = copyTags(rec.Tags)
	return &out, nil
}

// DeleteTableBucket implements [S3TablesAPI], by ARN as the service does.
func (m *MemoryS3Tables) DeleteTableBucket(_ context.Context, arn string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, rec := range m.buckets {
		if rec.ARN == arn {
			delete(m.buckets, name)
			return nil
		}
	}
	return fmt.Errorf("%w: table bucket %q", ErrNoSuchResource, arn)
}

// Dump reports every table bucket, for the Rendered hook.
func (m *MemoryS3Tables) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.buckets))
	for name := range m.buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, fmt.Sprintf("TableBucket %s: %s", name, sortedPairs(m.buckets[name].Tags)))
	}
	return out
}

// MemoryS3Vectors is an in-memory vector-bucket service.
type MemoryS3Vectors struct {
	failNext
	mu      sync.Mutex
	buckets map[string]*VectorBucketRecord
}

// vectorBucketARN is how this substrate answers "what is this vector bucket's ARN".
func vectorBucketARN(name string) string {
	return "arn:aws:s3vectors:" + MemoryRegion + ":" + MemoryAccount + ":bucket/" + name
}

// NewMemoryS3Vectors returns an empty vector-bucket service.
func NewMemoryS3Vectors() *MemoryS3Vectors {
	return &MemoryS3Vectors{buckets: map[string]*VectorBucketRecord{}}
}

// PutUnowned creates a vector bucket without apphub's ownership tags.
func (m *MemoryS3Vectors) PutUnowned(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buckets[name] = &VectorBucketRecord{
		Name: name, ARN: vectorBucketARN(name),
		Tags: map[string]string{"created-by": "somebody-else"},
	}
}

// GetVectorBucket implements [S3VectorsAPI].
func (m *MemoryS3Vectors) GetVectorBucket(_ context.Context, name string) (*VectorBucketRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.buckets[name]
	if !ok {
		return nil, fmt.Errorf("%w: vector bucket %q", ErrNoSuchResource, name)
	}
	out := *rec
	out.Tags = copyTags(rec.Tags)
	return &out, nil
}

// CreateVectorBucket implements [S3VectorsAPI].
func (m *MemoryS3Vectors) CreateVectorBucket(_ context.Context, name string, tags map[string]string) (*VectorBucketRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.buckets[name]; ok {
		return nil, fmt.Errorf("%w: vector bucket %q", ErrAlreadyExists, name)
	}
	rec := &VectorBucketRecord{Name: name, ARN: vectorBucketARN(name), Tags: copyTags(tags)}
	m.buckets[name] = rec
	out := *rec
	out.Tags = copyTags(rec.Tags)
	return &out, nil
}

// DeleteVectorBucket implements [S3VectorsAPI], by name: s3vectors reports no ARN.
func (m *MemoryS3Vectors) DeleteVectorBucket(_ context.Context, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.buckets[name]; !ok {
		return fmt.Errorf("%w: vector bucket %q", ErrNoSuchResource, name)
	}
	delete(m.buckets, name)
	return nil
}

// Dump reports every vector bucket, for the Rendered hook.
func (m *MemoryS3Vectors) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.buckets))
	for name := range m.buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, fmt.Sprintf("VectorBucket %s: %s", name, sortedPairs(m.buckets[name].Tags)))
	}
	return out
}

var (
	_ S3TablesAPI  = (*MemoryS3Tables)(nil)
	_ S3VectorsAPI = (*MemoryS3Vectors)(nil)
)
