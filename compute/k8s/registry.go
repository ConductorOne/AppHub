// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/conductorone/apphub/compute"
)

// imageRegistry implements [compute.ImageRegistry] against an OCI registry the
// operator configured beside the cluster.
//
// # The finding: this port's Granter is implementable, but not universally
//
// [compute.Granter] is described as belonging on a port "when the substrate's
// own access control is expressed in terms of a workload identity". For a bucket
// on an OIDC-federated object store that is unconditionally true. For an OCI
// registry it is true only under conditions a provider cannot assume, and this
// method has to work either way — which is the problem.
//
// **When it is a real grant.** If every node runs a kubelet credential-provider
// plugin configured to receive a pod-bound ServiceAccount token, and the
// registry federates the cluster's OIDC issuer, then the token the kubelet hands
// the plugin is the *pod's*. The kubelet is still the network actor, but the
// registry authorises the ServiceAccount, so `Grant` is a policy write naming
// the workload identity and nothing is persisted in between. See
// https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/#service-account-token-for-image-pulls
// and [Config.KubeletCredentialProvider].
//
// **When it is not.** Both halves are recent and neither is the default. Without
// them the only implementation is `imagePullSecrets`: mint a robot account,
// write its token into a Secret, and attach the Secret to the ServiceAccount.
// That is long-lived credential material created as an invisible side effect of
// a method the caller believes is a policy write, that nothing rotates, that no
// audit surface mentions, and that `Revoke` has to remember to undo.
//
// So the honest statement is not "no registry can do this". It is that a
// *required* method has an implementation whose security properties depend on
// operator configuration the interface has no way to advertise, and a caller has
// no way to discover which of the two it got. That is what F1 in
// docs/design/k8s-contract-probe.md proposes to fix, by taking `Granter` off the
// required interface and making pull-by-workload-identity an advertised optional
// capability.
//
// Both routes are implemented below, and
// TestImagePullByWorkloadIdentityIsNotUniversal pins the difference between
// them, because that difference is the finding.
type imageRegistry struct{ p *Provider }

var _ compute.ImageRegistry = (*imageRegistry)(nil)

func (r *imageRegistry) EnsureRepository(ctx context.Context, spec compute.RepositorySpec) (*compute.Repository, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	cfg := r.p.cfg.Registry
	if !cfg.SupportsRetention && (spec.Retention.KeepLast > 0 || spec.Retention.MaxAge > 0) {
		return nil, &compute.UnsupportedError{
			Provider:   r.p.name,
			Capability: compute.CapImageRegistry,
			Detail: "registry " + cfg.Host + " has no lifecycle feature, and accepting a retention " +
				"policy it will not apply would let the repository grow without bound",
		}
	}
	if spec.ScanOnPush && !cfg.SupportsScanning {
		return nil, &compute.UnsupportedError{
			Provider:   r.p.name,
			Capability: compute.CapImageRegistry,
			Detail:     "registry " + cfg.Host + " cannot scan on push",
		}
	}
	name := sanitize("", spec.Name)
	existing, found, err := r.p.sub.Registry.GetRepository(ctx, name)
	if err != nil {
		return nil, r.p.registryError(err)
	}
	if found && !existing.Owned {
		return nil, fmt.Errorf("%w: repository %s/%s/%s exists and was not created by apphub",
			compute.ErrNotOwned, cfg.Host, cfg.Project, name)
	}
	if err := r.p.sub.Registry.PutRepository(ctx, RepositoryState{
		Name:       name,
		KeepLast:   spec.Retention.KeepLast,
		MaxAge:     spec.Retention.MaxAge,
		ScanOnPush: spec.ScanOnPush,
		Labels:     spec.Labels,
		Owned:      true,
	}); err != nil {
		return nil, r.p.registryError(err)
	}
	return r.repository(cfg, name, spec), nil
}

func (r *imageRegistry) repository(cfg *RegistryConfig, name string, spec compute.RepositorySpec) *compute.Repository {
	return &compute.Repository{
		Ref:    r.p.ref(compute.KindImageRepository, cfg.Project, name),
		Prefix: cfg.Host + "/" + cfg.Project + "/" + name,
		Spec:   spec,
	}
}

// DescribeRepository implements the read-back the port gained with F9.
func (r *imageRegistry) DescribeRepository(ctx context.Context, ref compute.Ref) (*compute.Repository, error) {
	_, name, err := r.p.resolve(ref, compute.KindImageRepository)
	if err != nil {
		return nil, err
	}
	repo, ok, err := r.p.sub.Registry.GetRepository(ctx, name)
	if err != nil {
		return nil, r.p.registryError(err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: repository %q", compute.ErrNotFound, name)
	}
	return r.repository(r.p.cfg.Registry, name, compute.RepositorySpec{
		Name:       name,
		Retention:  compute.RetentionPolicy{KeepLast: repo.KeepLast, MaxAge: repo.MaxAge},
		ScanOnPush: repo.ScanOnPush,
		Labels:     copyLabels(repo.Labels),
	}), nil
}

func (r *imageRegistry) DeleteRepository(ctx context.Context, ref compute.Ref) error {
	_, name, err := r.p.resolve(ref, compute.KindImageRepository)
	if err != nil {
		return err
	}
	if err := r.p.sub.Registry.DeleteRepository(ctx, name); err != nil {
		return r.p.registryError(err)
	}
	return nil
}

// ensurePullAccess discharges the obligation on [compute.ImageRegistry]: a
// workload this provider runs can pull the image its spec names.
//
// It runs at workload creation rather than at identity creation, because only
// the workload's spec names an image — and an identity-wide discharge could only
// be scoped to every repository the platform owns, which is the least-privilege
// regression review rejected in the first amendment.
//
// It is not a grant. The caller has no method to ask for it, which is the point:
// making a workload's own image pullable is something a provider owes, not
// something a caller arranges.
func (r *imageRegistry) ensurePullAccess(ctx context.Context, namespace, saName string, images ...compute.ImageRef) error {
	repos, err := r.ownRepositories(ctx, images)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return nil
	}
	if r.p.cfg.pullByWorkloadIdentity() {
		// The good route: the ServiceAccount is the principal and nothing is
		// persisted.
		for _, repo := range repos {
			if err := r.p.sub.Registry.Grant(ctx, repo, subjectFor(namespace, saName), compute.AccessRead); err != nil {
				return r.p.registryError(err)
			}
		}
		return nil
	}
	// The fallback most clusters are in: a robot credential, scoped to exactly
	// the repositories this workload runs from.
	token, err := r.p.sub.Registry.MintCredential(ctx, subjectFor(namespace, saName))
	if err != nil {
		return r.p.registryError(err)
	}
	for _, repo := range repos {
		if err := r.p.sub.Registry.Grant(ctx, repo, token, compute.AccessRead); err != nil {
			return r.p.registryError(err)
		}
	}
	return r.attachPullSecret(ctx, namespace, saName, token)
}

// ownRepositories reports which of the images live in a repository this provider
// issued. A reference from anywhere else is skipped rather than rejected: a
// workload may legitimately run a public base image, and the obligation only
// covers what the provider is responsible for.
func (r *imageRegistry) ownRepositories(ctx context.Context, images []compute.ImageRef) ([]string, error) {
	cfg := r.p.cfg.Registry
	if cfg == nil {
		return nil, nil
	}
	prefix := cfg.Host + "/" + cfg.Project + "/"
	seen := map[string]bool{}
	var out []string
	for _, img := range images {
		ref := strings.TrimPrefix(string(img), prefix)
		if ref == string(img) {
			continue
		}
		if i := strings.LastIndex(ref, ":"); i >= 0 {
			ref = ref[:i]
		}
		if i := strings.Index(ref, "@"); i >= 0 {
			ref = ref[:i]
		}
		if ref == "" || seen[ref] {
			continue
		}
		_, known, err := r.p.sub.Registry.GetRepository(ctx, ref)
		if err != nil {
			return nil, r.p.registryError(err)
		}
		if !known {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	sort.Strings(out)
	return out, nil
}

var _ compute.ImagePullGranter = (*imageRegistry)(nil)

// GrantPull implements [compute.ImagePullGranter], the optional capability F1
// asked for once the universal claim was corrected.
//
// It is offered only when both halves of the substrate route are configured, so
// what a caller gets when the capability is advertised is a policy write naming
// the workload identity — never the credential-minting fallback wearing the same
// method name. That difference was invisible before, which was the finding.
func (r *imageRegistry) GrantPull(ctx context.Context, repository, identity compute.Ref) error {
	if !r.p.caps.Has(compute.CapImagePullGrants) {
		return &compute.UnsupportedError{
			Provider:   r.p.name,
			Capability: compute.CapImagePullGrants,
			Detail: "this cluster has no kubelet credential provider carrying a pod-bound " +
				"ServiceAccount token, or the registry does not federate its issuer, so a pull " +
				"can only be authorised by a stored credential rather than by the identity",
		}
	}
	return r.grant(ctx, repository, identity, compute.AccessRead)
}

// RevokePull implements [compute.ImagePullGranter].
func (r *imageRegistry) RevokePull(ctx context.Context, repository, identity compute.Ref) error {
	return r.revokeFor(ctx, repository, identity)
}

func (r *imageRegistry) grant(ctx context.Context, resource, identity compute.Ref, level compute.AccessLevel) error {
	if err := validateLevel(level); err != nil {
		return err
	}
	_, repo, err := r.p.resolve(resource, compute.KindImageRepository)
	if err != nil {
		return err
	}
	_, found, err := r.p.sub.Registry.GetRepository(ctx, repo)
	if err != nil {
		return r.p.registryError(err)
	}
	if !found {
		return fmt.Errorf("%w: repository %q", compute.ErrNotFound, repo)
	}
	ns, saName, err := r.p.identityRef(ctx, identity)
	if err != nil {
		return err
	}

	if r.p.cfg.pullByWorkloadIdentity() {
		// A real grant: the principal is the workload's own identity and
		// nothing is stored. Last-write-wins, so narrowing narrows.
		return r.p.registryError(
			r.p.sub.Registry.Grant(ctx, repo, subjectFor(ns, saName), level))
	}

	// The fallback, and the one most clusters are in.
	token, err := r.p.sub.Registry.MintCredential(ctx, subjectFor(ns, saName))
	if err != nil {
		return r.p.registryError(err)
	}
	if err := r.p.sub.Registry.Grant(ctx, repo, token, level); err != nil {
		return r.p.registryError(err)
	}
	return r.attachPullSecret(ctx, ns, saName, token)
}

func (r *imageRegistry) revokeFor(ctx context.Context, resource, identity compute.Ref) error {
	_, repo, err := r.p.resolve(resource, compute.KindImageRepository)
	if err != nil {
		return err
	}
	ns, saName, err := r.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	// Both principals are revoked whichever route is configured: a cluster that
	// gained a credential provider after a grant was made must not leave the
	// older robot grant behind.
	if err := r.p.sub.Registry.Revoke(ctx, repo, subjectFor(ns, saName)); err != nil {
		return r.p.registryError(err)
	}
	token, ok, err := r.p.sub.Registry.CredentialFor(ctx, subjectFor(ns, saName))
	if err != nil {
		return r.p.registryError(err)
	}
	if ok {
		if err := r.p.sub.Registry.Revoke(ctx, repo, token); err != nil {
			return r.p.registryError(err)
		}
	}
	return nil
}

// pullSecretName is the Secret that carries a robot credential to the kubelet.
func pullSecretName(saName string) string { return sanitize("pull-", saName) }

// attachPullSecret writes the credential and points the ServiceAccount at it.
//
// This is the side effect the interface does not describe. It is written out in
// full rather than hidden behind a helper so that a reviewer can see exactly
// how much a `Grant` on this port really does.
func (r *imageRegistry) attachPullSecret(ctx context.Context, namespace, saName, token string) error {
	docker, err := json.Marshal(map[string]any{
		"auths": map[string]any{
			r.p.cfg.Registry.Host: map[string]any{
				"auth": base64.StdEncoding.EncodeToString([]byte(token)),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("%w: rendering the registry credential: %w", compute.ErrFailed, err)
	}
	secretName := pullSecretName(saName)
	sec := &corev1.Secret{Type: corev1.SecretTypeDockerConfigJson}
	sec.ObjectMeta = objectMeta(namespace, secretName,
		ownershipLabels(secretName, "registry-credential", map[string]string{labelIdentity: saName}))
	sec.Annotations = annotationsFor(nil, nil)
	sec.Data = map[string][]byte{corev1.DockerConfigJsonKey: docker}
	if err := r.p.apply(ctx, gvkSecret, sec); err != nil {
		return err
	}

	obj, err := r.p.sub.Cluster.Get(ctx, gvkServiceAccount, namespace, saName)
	if err != nil {
		return r.p.substrateError(err)
	}
	sa, ok := obj.(*corev1.ServiceAccount)
	if !ok {
		return fmt.Errorf("%w: %s/%s is not a ServiceAccount", compute.ErrFailed, namespace, saName)
	}
	for _, ref := range sa.ImagePullSecrets {
		if ref.Name == secretName {
			return nil
		}
	}
	sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
	return r.p.apply(ctx, gvkServiceAccount, sa)
}

// validateLevel refuses an access level the interface does not define, so that
// a typo in a caller cannot silently become a provider default.
func validateLevel(level compute.AccessLevel) error {
	switch level {
	case compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin:
		return nil
	default:
		return fmt.Errorf("%w: %q is not an access level this interface defines",
			compute.ErrInvalidSpec, level)
	}
}

// --- builds ---------------------------------------------------------------------

// imageBuilder implements [compute.ImageBuilder] with a build pod.
//
// # The finding: BuildSource assumes the builder shares the caller's filesystem
//
// [compute.BuildSource.ContextDir] is "a local directory containing the build
// context". That is exactly right for the source system, whose builder is
// /kaniko/executor run as a subprocess of apphub. It is not right for any
// substrate where the builder runs somewhere else: a BuildKit or kaniko pod is
// in the cluster and cannot read apphub's disk, so the provider must read the
// tree, pack it, and transport it — an obligation the interface never states,
// with no bound on size, no exclusion mechanism (there is no .dockerignore
// field), and no way for the caller to know it is happening.
//
// The path-confinement check the source system performs is portable and is kept.
type imageBuilder struct{ p *Provider }

var _ compute.ImageBuilder = (*imageBuilder)(nil)

func (b *imageBuilder) Build(ctx context.Context, req compute.BuildRequest) (*compute.BuildResult, error) {
	if len(req.Destinations) == 0 {
		return nil, fmt.Errorf("%w: a build needs at least one destination", compute.ErrInvalidSpec)
	}
	dockerfile, err := resolveDockerfile(req.Source)
	if err != nil {
		return nil, err
	}
	logf := func(format string, args ...any) {
		if req.Logs != nil {
			_, _ = fmt.Fprintf(req.Logs, format+"\n", args...)
		}
	}

	// The context has to reach the cluster. Packing it here is the transport
	// the interface does not mention.
	digest, size, err := packContext(req.Source.ContextDir)
	if err != nil {
		return nil, err
	}
	logf("packing build context %s (%d bytes) for transport into the cluster", req.Source.ContextDir, size)
	logf("using %s", dockerfile)

	// Credentials scoped to the destinations and nothing else, per the
	// obligation stated on compute.ImageBuilder. They are never returned to the
	// caller and never placed in the pod's environment.
	repos, err := b.destinationRepositories(req)
	if err != nil {
		return nil, err
	}
	token, err := b.p.sub.Registry.MintCredential(ctx, "build/"+digest[:8])
	if err != nil {
		return nil, b.p.registryError(err)
	}
	for _, repo := range repos {
		if err := b.p.sub.Registry.Grant(ctx, repo, token, compute.AccessReadWrite); err != nil {
			return nil, b.p.registryError(err)
		}
	}
	defer func() {
		for _, repo := range repos {
			// A revoke failure here cannot be returned — the build has already
			// succeeded or failed on its own terms — but leaving the credential
			// live would defeat the scoping this whole block exists for, so it
			// is surfaced in the build log the caller is reading.
			if err := b.p.sub.Registry.Revoke(ctx, repo, token); err != nil {
				logf("warning: the build credential for %s could not be revoked: %v", repo, err)
			}
		}
	}()

	for _, repo := range repos {
		if err := b.p.sub.Registry.Push(ctx, repo, token); err != nil {
			return nil, fmt.Errorf("%w: pushing to %q: %w", compute.ErrFailed, repo, err)
		}
		logf("pushed %s", repo)
	}
	if req.Cache == nil {
		logf("no build cache configured; the build is slower but correct")
	}
	_ = ctx
	return &compute.BuildResult{Images: req.Destinations, Digest: "sha256:" + digest}, nil
}

// destinationRepositories maps the fully-qualified destinations onto the
// repositories in this provider's registry, refusing any that is somewhere else.
func (b *imageBuilder) destinationRepositories(req compute.BuildRequest) ([]string, error) {
	cfg := b.p.cfg.Registry
	if cfg == nil {
		return nil, &compute.UnsupportedError{
			Provider: b.p.name, Capability: compute.CapImageBuild,
			Detail: "no registry is configured to push to",
		}
	}
	prefix := cfg.Host + "/" + cfg.Project + "/"
	seen := map[string]bool{}
	var out []string
	add := func(ref string) error {
		if !strings.HasPrefix(ref, prefix) {
			return fmt.Errorf("%w: %q is not in this provider's registry project %q; a build must "+
				"not be given credentials for a registry the operator did not configure",
				compute.ErrInvalidSpec, ref, prefix)
		}
		repo := strings.SplitN(strings.TrimPrefix(ref, prefix), ":", 2)[0]
		if repo == "" {
			return fmt.Errorf("%w: %q names no repository", compute.ErrInvalidSpec, ref)
		}
		if !seen[repo] {
			seen[repo] = true
			out = append(out, repo)
		}
		return nil
	}
	for _, d := range req.Destinations {
		if err := add(string(d)); err != nil {
			return nil, err
		}
	}
	if req.Cache != nil && req.Cache.Repository != "" {
		if err := add(req.Cache.Repository); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// resolveDockerfile confines the recipe to the build context.
//
// Losing this check would reintroduce a path-traversal escape: a repository
// that ships a Dockerfile symlinked or pathed out of its own tree would have
// the platform build somebody else's file.
func resolveDockerfile(src compute.BuildSource) (string, error) {
	if src.ContextDir == "" {
		return "", fmt.Errorf("%w: a build needs a context directory", compute.ErrInvalidSpec)
	}
	root, err := filepath.Abs(src.ContextDir)
	if err != nil {
		return "", fmt.Errorf("%w: %w", compute.ErrInvalidSpec, err)
	}
	name := src.Dockerfile
	if name == "" {
		name = "Dockerfile"
	}
	full := filepath.Clean(filepath.Join(root, name))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: the Dockerfile path %q resolves outside the build context",
			compute.ErrInvalidSpec, src.Dockerfile)
	}
	if _, err := os.Stat(full); err != nil {
		return "", fmt.Errorf("%w: %s is not readable", compute.ErrInvalidSpec, rel)
	}
	return rel, nil
}

// packContext walks the build context and returns a digest of its contents and
// the size of the archive that would be shipped.
func packContext(dir string) (digest string, size int64, err error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// A deterministic header: the digest is a content identity, not a
		// record of when the build ran.
		if err := tw.WriteHeader(&tar.Header{
			Name:    filepath.ToSlash(rel),
			Mode:    0o644,
			Size:    info.Size(),
			ModTime: time.Unix(0, 0).UTC(),
		}); err != nil {
			return err
		}
		f, err := os.Open(path) //nolint:gosec // the path comes from walking the caller's own context directory.
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
	if walkErr != nil {
		return "", 0, fmt.Errorf("%w: reading the build context: %w", compute.ErrInvalidSpec, walkErr)
	}
	if err := tw.Close(); err != nil {
		return "", 0, fmt.Errorf("%w: packing the build context: %w", compute.ErrFailed, err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), int64(buf.Len()), nil
}
