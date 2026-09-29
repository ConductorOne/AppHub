// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// registryHost is the fake registry's hostname. It uses the reserved .invalid
// TLD so that a test which accidentally tries to reach it fails immediately
// rather than resolving something real.
const registryHost = "registry.invalid"

// imageRegistry implements [compute.ImageRegistry]. It is a synchronous port:
// the source system creates a repository with no polling loop
// (build.go:282-348), and a repository is usable the moment it exists.
type imageRegistry struct{ p *Provider }

// EnsureRepository implements [compute.ImageRegistry].
func (r imageRegistry) EnsureRepository(_ context.Context, spec compute.RepositorySpec) (*compute.Repository, error) {
	if err := r.p.validateName("image repository", spec.Name); err != nil {
		return nil, err
	}
	if spec.Retention.KeepLast < 0 || spec.Retention.MaxAge < 0 {
		return nil, fmt.Errorf("fake: repository %q has a negative retention rule: %w",
			spec.Name, compute.ErrInvalidSpec)
	}

	// Retention is re-applied on every call, so an existing repository picks up
	// a changed rule. That is why ensureRecord replaces the spec rather than
	// merging it.
	rec, _, err := ensureRecord(r.p, r.p.store.repos, compute.KindImageRepository, spec.Name, spec, false, nil)
	if err != nil {
		return nil, err
	}
	return r.repository(rec), nil
}

// DeleteRepository implements [compute.ImageRegistry].
func (r imageRegistry) DeleteRepository(_ context.Context, ref compute.Ref) error {
	id, err := r.p.resolve(ref, compute.KindImageRepository)
	if err != nil {
		return err
	}
	r.p.store.mu.Lock()
	rec, ok := r.p.store.repos[id]
	if ok {
		prefix := r.prefixLocked(rec)
		for img := range r.p.store.images {
			if strings.HasPrefix(string(img), prefix+":") {
				delete(r.p.store.images, img)
			}
		}
	}
	r.p.store.mu.Unlock()
	return deleteSync(r.p, r.p.store.repos, ref, compute.KindImageRepository)
}

// DescribeRepository implements [compute.ImageRegistry]. It was a fake-only
// method while the port had no read-back; the interface now has one.
func (r imageRegistry) DescribeRepository(_ context.Context, ref compute.Ref) (*compute.Repository, error) {
	rec, err := lookup(r.p, r.p.store.repos, ref, compute.KindImageRepository)
	if err != nil {
		return nil, err
	}
	return r.repository(rec), nil
}

func (r imageRegistry) repository(rec *record[compute.RepositorySpec]) *compute.Repository {
	r.p.store.mu.Lock()
	defer r.p.store.mu.Unlock()
	return &compute.Repository{Ref: rec.ref, Prefix: r.prefixLocked(rec), Spec: deepCopy(rec.spec)}
}

func (r imageRegistry) prefixLocked(rec *record[compute.RepositorySpec]) string {
	return registryHost + "/" + r.p.cfg.Name + "/" + rec.name
}

// This port requires no Grant: most registries cannot authorise a pull by
// workload identity, so it is a capability rather than a method — see
// [compute.ImageRegistry].
//
// What every provider owes is the obligation, and the fake discharges it the
// same way a real one must: at workload creation, scoped to the repository the
// workload's own image names. The first version granted every workload access to
// every repository, which passed the obligation as written and was a
// least-privilege regression; the obligation is narrower now and so is this.
func (r imageRegistry) ensurePullAccess(image compute.ImageRef, identity compute.Ref) {
	name, ok := r.repositoryFor(image)
	if !ok {
		return
	}
	r.p.store.mu.Lock()
	defer r.p.store.mu.Unlock()
	r.p.store.grants[grantKey{resource: r.p.ref(compute.KindImageRepository, name).ID,
		subject: identity.ID}] = compute.AccessRead
}

// repositoryFor reports which repository this provider issued an image from, if
// any. An image from somewhere else is not this provider's to make pullable.
func (r imageRegistry) repositoryFor(image compute.ImageRef) (string, bool) {
	ref := string(image)
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	prefix := registryHost + "/" + r.p.cfg.Name + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(ref, prefix)
	r.p.store.mu.Lock()
	defer r.p.store.mu.Unlock()
	if _, ok := r.p.store.repos[r.p.ref(compute.KindImageRepository, name).ID]; !ok {
		return "", false
	}
	return name, true
}

// GrantPull implements [compute.ImagePullGranter].
//
// The fake advertises [compute.CapImagePullGrants] by default because a
// reference provider should exercise the path a real substrate can offer — a
// Kubernetes kubelet credential provider carrying a pod-bound ServiceAccount
// token is the concrete case. A configuration that drops the capability refuses
// here, which is what the conformance suite checks.
func (r imageRegistry) GrantPull(ctx context.Context, repository compute.Ref, identity compute.Ref) error {
	if r.p.broken(DefectPullGrantNotIdempotent) {
		// The SECOND grant is the one that fails, as a provider that treats a
		// grant as a create does. The first version of this failed the first
		// call, which meant the fixture never reached a second grant at all: a
		// defect that fires on call one cannot show that a check observes call
		// two, so the control was not testing what its name claimed. Found in
		// review.
		if r.p.granted(repository, identity) {
			return fmt.Errorf("fake: %s may already pull from %s: %w",
				identity, repository, compute.ErrFailed)
		}
		return r.granter().Grant(ctx, repository, identity, compute.AccessRead)
	}
	if !r.p.caps.Has(compute.CapImagePullGrants) && !r.p.broken(DefectPullGrantWithoutCapability) {
		return &compute.UnsupportedError{
			Provider:   r.p.cfg.Name,
			Capability: compute.CapImagePullGrants,
			Detail:     "this registry cannot authorise a pull by workload identity",
		}
	}
	return r.granter().Grant(ctx, repository, identity, compute.AccessRead)
}

// RevokePull implements [compute.ImagePullGranter].
func (r imageRegistry) RevokePull(ctx context.Context, repository compute.Ref, identity compute.Ref) error {
	return r.granter().Revoke(ctx, repository, identity)
}

func (r imageRegistry) granter() granter {
	return granter{p: r.p, kind: compute.KindImageRepository, exists: func(id string) bool {
		r.p.store.mu.Lock()
		defer r.p.store.mu.Unlock()
		_, ok := r.p.store.repos[id]
		return ok
	}}
}

var (
	_ compute.ImageRegistry    = imageRegistry{}
	_ compute.ImagePullGranter = imageRegistry{}
)

// imageBuilder implements [compute.ImageBuilder].
//
// It reads the build context from disk and writes nothing outside the store,
// which keeps it hermetic: no daemon, no network, no subprocess. What it does
// preserve is the checks that are security properties rather than kaniko
// details — the Dockerfile must resolve inside the context directory, and the
// build never sees a credential.
type imageBuilder struct{ p *Provider }

// Build implements [compute.ImageBuilder].
//
// It is a thin wrapper so that a hostile build-error emission decorates
// **whatever** error the build returns rather than one particular failure route.
// The channel the conformance suite names is "the error a build returns", and the
// first version of this consulted the emission only after the destination check
// had passed — so the suite's own fixture, which fails a build by naming a
// destination in no repository, established nothing and the check it stood on
// went red. A hook that emits on one route out of several is the same false
// declaration the marker mechanism exists to rule out; it just refuses less
// honestly.
func (b imageBuilder) Build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	res, err := b.build(ctx, req)
	if err != nil && b.p.broken(DefectBuildCredentialInError) {
		// A failing build whose error quotes what it was authenticating with. It
		// decorates whatever error occurred rather than manufacturing one, so a
		// legal build still succeeds: a defect that failed every build would trip
		// half the build port's checks for an unrelated reason, and a fixture that
		// fails a check by accident does not show the check works.
		err = fmt.Errorf("%w (authenticating with %s)", err, b.p.buildCredential())
	}
	m := b.p.emission(ChannelBuildError)
	if m == "" {
		return res, err
	}
	if err == nil {
		return nil, fmt.Errorf("fake: build failed%s: %w", m, compute.ErrFailed)
	}
	return nil, fmt.Errorf("%w%s", err, m)
}

func (b imageBuilder) build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	// Before any state is touched, and before the context is read: a build that
	// failed at its substrate did not read the repository's source.
	if err := b.p.injected(OpBuild, compute.KindImageRepository); err != nil {
		return nil, err
	}
	if len(req.Destinations) == 0 && !b.p.broken(DefectBuildWithoutDestination) {
		return nil, fmt.Errorf("fake: a build needs at least one destination: %w", compute.ErrInvalidSpec)
	}
	if req.Source.ContextDir == "" {
		return nil, fmt.Errorf("fake: a build needs a context directory: %w", compute.ErrInvalidSpec)
	}

	dockerfile, err := resolveInContext(req.Source.ContextDir, req.Source.Dockerfile)
	if err != nil {
		return nil, err
	}
	recipe, err := os.ReadFile(dockerfile) //nolint:gosec // the path is confined to the context directory by resolveInContext.
	if err != nil {
		return nil, fmt.Errorf("fake: reading %s: %w", req.Source.Dockerfile, err)
	}

	// A destination must live in a repository this provider hosts. A builder
	// that pushed anywhere would let a test believe an image is pullable when
	// nothing published it.
	for _, dest := range req.Destinations {
		if err := b.checkDestination(dest); err != nil {
			if b.p.broken(DefectBuildOutputInError) {
				// The source system's shape: the failure carries a tail of what
				// the builder read, which is repository-authored content, and
				// the caller persists it onto a job record.
				return nil, fmt.Errorf("fake: build failed: %w\nbuilder output:\n%s", err, recipe)
			}
			return nil, err
		}
	}

	if req.Logs != nil {
		if m := b.p.emission(ChannelBuildLog); m != "" {
			_, _ = fmt.Fprintf(req.Logs, "fake:%s\n", m)
		}
	}
	if req.Logs != nil && !b.p.broken(DefectSilentBuild) {
		// A real builder's log is the progress signal, so there is one. The
		// caller owns any bounding of it.
		_, _ = fmt.Fprintf(req.Logs, "fake: building from %s\n", req.Source.ContextDir)
		if b.p.broken(DefectBuildCredentialInLogs) {
			// What a builder that inherits an ambient credential looks like from
			// outside: the credential it was given, in the stream its caller
			// persists a tail of. This is what a Dockerfile RUN printing the
			// executor's environment produces.
			_, _ = fmt.Fprintf(req.Logs, "fake: authenticating with %s\n", b.p.buildCredential())
		}
		// Repository-authored content, echoed the way a builder echoes the
		// recipe it is executing. Legitimate here: Logs is documented as
		// receiving the builder's output. It must not reach an error.
		_, _ = fmt.Fprintf(req.Logs, "fake: recipe:\n%s", recipe)
		for _, dest := range req.Destinations {
			_, _ = fmt.Fprintf(req.Logs, "fake: pushing %s\n", dest)
		}
	}
	if b.p.broken(DefectBuildFailsAfterEmitting) && req.Logs != nil {
		// The material is already out of the door; the call then fails. A check
		// that only reads a successful build's output sees nothing here.
		//
		// Logs is optional and the nil guard is not cosmetic: the credential check
		// now drives a build with no log sink while reading the error and result
		// channels, and this line panicked on it.
		_, _ = fmt.Fprintf(req.Logs, "fake: authenticating with %s\n", b.p.buildCredential())
		return nil, fmt.Errorf("fake: the builder failed after starting: %w", compute.ErrFailed)
	}

	sum := sha256.Sum256(recipe)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if b.p.broken(DefectBuildCredentialInResult) {
		// The result channel. Digest is opaque to the caller, which is precisely
		// why material riding there is not noticed.
		digest += "+" + b.p.buildCredential()
	}

	// Metadata records what a puller of the image can read back: the caller's
	// non-secret build arguments, rendered the way a real registry's
	// image-inspect output renders them. Legitimate here -- BuildArgs is
	// documented non-secret -- unlike the defect below, which is this
	// provider's own scoped push credential rather than anything the caller
	// supplied.
	meta := renderMetadata(req.BuildArgs)
	if b.p.broken(DefectBuildCredentialInImageMetadata) {
		// A builder that authenticates a private base-image pull by handing
		// its own scoped credential to the build as an ordinary build
		// argument. Docker and kaniko both record every ARG a build consumed
		// in the image's build history, so this is baked in and published,
		// not merely logged.
		meta += "credential=" + b.p.buildCredential() + "\n"
	}
	meta += b.p.emission(ChannelImageMetadata)

	b.p.store.mu.Lock()
	for _, dest := range req.Destinations {
		b.p.store.images[dest] = digest
		b.p.store.imageMetadata[dest] = meta
	}
	b.p.store.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fake: build cancelled: %w", err)
	}
	// The digest is documented as optional and opaque, so a marker can ride there
	// without violating anything a caller may rely on.
	return &compute.BuildResult{
		Images: req.Destinations,
		Digest: digest + b.p.emission(ChannelBuildResult),
	}, nil
}

func (b imageBuilder) checkDestination(dest compute.ImageRef) error {
	prefix, _, ok := strings.Cut(string(dest), ":")
	if !ok || prefix == "" {
		return fmt.Errorf("fake: destination %q has no tag: %w", dest, compute.ErrInvalidSpec)
	}
	b.p.store.mu.Lock()
	defer b.p.store.mu.Unlock()
	for _, rec := range b.p.store.repos {
		if registryHost+"/"+b.p.cfg.Name+"/"+rec.name == prefix {
			return nil
		}
	}
	return fmt.Errorf("fake: no repository hosts %q; ensure it before pushing to it: %w",
		dest, compute.ErrNotFound)
}

// resolveInContext confines a Dockerfile path to the build context.
//
// The source system checks this (build.go:462-467) and losing it would
// reintroduce a path-traversal escape: a repository that ships
// "../../etc/something" as its Dockerfile path would have the builder read a
// file from the platform's own filesystem.
func resolveInContext(contextDir, dockerfile string) (string, error) {
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if filepath.IsAbs(dockerfile) {
		return "", fmt.Errorf("fake: Dockerfile path %q is absolute and so escapes the build context: %w",
			dockerfile, compute.ErrInvalidSpec)
	}
	root, err := filepath.Abs(contextDir)
	if err != nil {
		return "", fmt.Errorf("fake: resolving the build context: %w", err)
	}
	joined := filepath.Join(root, dockerfile)
	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fake: Dockerfile path %q resolves outside the build context: %w",
			dockerfile, compute.ErrInvalidSpec)
	}
	return joined, nil
}

// PulledDigest reports the digest recorded for an image, and whether anything
// published it. Test helper; not part of the interface.
func (s *Store) PulledDigest(img compute.ImageRef) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.images[img]
	return d, ok
}

// ImageMetadata reports the metadata recorded for an image, and whether a
// build recorded any. Test helper; not part of the interface -- the same gap
// [compute.BuildResult] leaves that [Harness.ImageMetadata] exists to close.
func (s *Store) ImageMetadata(img compute.ImageRef) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.imageMetadata[img]
	return m, ok
}

// renderMetadata deterministically renders a build's non-secret arguments the
// way an image's own metadata records them: sorted, so two builds of the same
// request produce comparable output.
func renderMetadata(args map[string]string) string {
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, args[name])
	}
	return b.String()
}

var _ compute.ImageBuilder = imageBuilder{}
