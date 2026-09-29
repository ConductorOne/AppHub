// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/conductorone/apphub/compute"
)

// runtimeObject is a local alias so this file does not have to name the runtime
// package in every signature.
type runtimeObject = runtime.Object

// Harness is the substrate operations the [compute] interface deliberately does
// not expose, supplied so the conformance suite's hooks have something to call.
//
// Every method here is a place the contract talks about a behaviour it gives no
// portable way to observe. Two of them are worth pointing at specifically:
//
//   - [Harness.Read] and [Harness.Write] on an image repository have to go
//     through the *credential* the provider minted, because a ServiceAccount
//     cannot authenticate to a registry. Writing this harness is what turned
//     the [imageRegistry] finding from an argument into a demonstration: the
//     test cannot even ask the question the invariant asks without reaching for
//     a Secret the interface never mentions.
//   - [Harness.CanExecInto] answers from RBAC, which authorises the *caller*.
//     It returns false for a workload's own identity even against a workload
//     with ExecEnabled — which is the post-PR-#3 contract, and is what
//     Kubernetes does anyway.
type Harness struct{ p *Provider }

// Harness returns the substrate hooks for this provider.
func (p *Provider) Harness() *Harness { return &Harness{p: p} }

// FailNextApply makes every call to every substrate fail with err until the
// returned function is called.
//
// It exists for the conformance suite's retry gate. A stale-read conflict is
// this substrate's most common retryable failure, and the check is whether the
// provider's mapping reaches [compute.ErrTransient] rather than
// [compute.ErrFailed] — telling a caller its spec has to change when the write
// would have succeeded on a second attempt.
//
// # Why it is not "the next apply"
//
// The name is kept for the conformance hook it is wired to, but the behaviour is
// wider than it was, in two directions, and both changes came from a measurement
// rather than a hunch. USOSS-32's rework of that gate reports, per method, what
// the hook did not reach; against this provider it named nine unexercised
// methods on the full-cluster configuration, because failing only cluster
// *applies* leaves every read-back, every delete, and both non-cluster
// substrates untouched. So this now arms:
//
//   - every cluster verb, not only Apply ([MemoryCluster.FailEvery]);
//   - the in-memory registry and object store, so the error mapping for the two
//     substrates that are not the cluster is exercised too.
//
// A substrate that is not the in-memory implementation is skipped rather than
// refused: a real API server cannot be told to fail, and the suite's gate treats
// a hook that cannot arrange a failure as "not verified" rather than as a
// failure — which is the honest answer.
func (h *Harness) FailNextApply(err error) func() {
	var undo []func()
	if mc, ok := h.p.sub.Cluster.(*MemoryCluster); ok {
		undo = append(undo, mc.FailEvery(err))
	}
	// The two non-cluster substrates are armed with the failure translated into
	// *their* vocabulary. This matters and is easy to get wrong: the caller's err
	// is a cluster error — the suite passes ErrOptimisticConcurrency, which is a
	// stale resourceVersion — and Provider.backingError has no reason to know
	// what an API-server 409 is. Arming the registry with it unchanged would map
	// it to compute.ErrFailed, so the gate would be checking that a retryable
	// registry failure is reported as terminal: green, and backwards.
	transient := fmt.Errorf("%w: %w", ErrBackingTransient, err)
	if reg, ok := h.p.sub.Registry.(*MemoryRegistry); ok {
		undo = append(undo, reg.FailEvery(transient))
	}
	if obj, ok := h.p.sub.Objects.(*MemoryObjectStore); ok {
		undo = append(undo, obj.FailEvery(transient))
	}
	return func() {
		for _, f := range undo {
			f()
		}
	}
}

// InduceDenial makes the next substrate call behind kind fail the way the
// substrate that stands behind it spells an authorization failure, so that the
// mapping onto [compute.ErrNotPermitted] is exercised rather than asserted.
//
// # Why this hook not existing was the whole defect
//
// Until it did, the suite's Options.InduceDenial was nil here, so
// `provider/an-authorization-failure-is-ErrNotPermitted` recorded a clean skip
// against both configurations of this provider — and behind the skip, a
// Kubernetes 403 reached a caller as [compute.ErrFailed]. That is the
// load-bearing-skip shape: an inert gate and a correct mapping are
// indistinguishable from outside, and here the gate was inert and the mapping
// was wrong. Closing it needed both halves — [ErrClusterDenied] and its arms in
// [Provider.substrateError] and [Provider.backingError] are the mapping, and
// this is what drives them.
//
// # Per kind, and per substrate, unlike [Harness.FailNextApply]
//
// FailNextApply arms all three substrates at once because it is not told which
// port the suite is about to drive. This hook is, so it arms exactly the
// substrate that stands behind that port and nothing else — which is what makes
// the suite's per-port count mean something. Arming all three would report ten
// ports driven while proving only that whichever substrate answered first was
// mapped, and this provider's three substrates have three unrelated mappings:
// [Provider.substrateError] for the cluster, [Provider.backingError] for the
// registry and the object store.
//
// Each is armed in its own vocabulary for the same reason FailNextApply
// translates: handing the object store a cluster error would exercise the
// default arm of a mapping instead of its denial arm, and pass while proving the
// opposite.
//
// # It is sticky, not one-shot
//
// [MemoryCluster.FailEvery] refuses every verb until the returned stop runs, so
// whichever call the port makes first is the one denied. A one-shot arm would
// have to guess how many calls into an Ensure the interesting one is, and the
// failure mode of guessing wrong is quiet in the worst direction: the shot is
// spent on a call the port converges rather than propagates, the Ensure reports
// success, and the suite can only read that as "this provider does not surface
// denials at all" — the message would name the wrong defect.
//
// A kind with no substrate behind it is an error rather than a silent success:
// the suite records that port as undrivable by name and drives the others.
func (h *Harness) InduceDenial(_ context.Context, kind compute.Kind) (func(), error) {
	// "induced" is in each message because a denial that reaches a human should
	// say where it came from; the sentinel is what the mapping keys on.
	switch kind {
	case compute.KindImageRepository:
		reg, ok := h.p.sub.Registry.(*MemoryRegistry)
		if !ok {
			return func() {}, errors.New("k8s: inducing a denial on the registry needs the " +
				"in-memory registry; a real one cannot be told to refuse a credential")
		}
		return reg.FailEvery(fmt.Errorf("%w: induced by the conformance harness",
			ErrRegistryDenied)), nil

	case compute.KindBucket:
		obj, ok := h.p.sub.Objects.(*MemoryObjectStore)
		if !ok {
			return func() {}, errors.New("k8s: inducing a denial on the object store needs the " +
				"in-memory store; a real one cannot be told to refuse a request")
		}
		return obj.FailEvery(fmt.Errorf("%w: induced by the conformance harness",
			ErrObjectStoreDenied)), nil

	default:
		// Every other port this provider vends is an object in the API server,
		// and which object is [Provider.clusterGVK]'s answer rather than a
		// second list here. A kind it refuses -- a key-value table, say -- is a
		// kind with no substrate to deny, which is exactly what the caller is
		// asking about.
		if _, err := h.p.clusterGVK(kind); err != nil {
			return func() {}, err
		}
		mc, ok := h.p.sub.Cluster.(*MemoryCluster)
		if !ok {
			return func() {}, errors.New("k8s: inducing a denial on the cluster needs the " +
				"in-memory cluster; a real API server cannot be told to refuse RBAC")
		}
		return mc.FailEvery(fmt.Errorf("%w: induced by the conformance harness",
			ErrClusterDenied)), nil
	}
}

// Stall makes a resource stop converging.
func (h *Harness) Stall(ctx context.Context, ref compute.Ref) error {
	mc, ok := h.p.sub.Cluster.(*MemoryCluster)
	if !ok {
		return errors.New("k8s: Stall needs the in-memory cluster")
	}
	gvk, ns, name, err := h.p.locate(ref)
	if err != nil {
		return err
	}
	_ = ctx
	return mc.stall(gvk, ns, name)
}

// CreateUnowned puts a resource where ref points without apphub's ownership
// marker, so that an Ensure has a collision to refuse.
func (h *Harness) CreateUnowned(ctx context.Context, ref compute.Ref) error {
	switch ref.Kind {
	case compute.KindImageRepository:
		_, name, err := h.p.resolve(ref, compute.KindImageRepository)
		if err != nil {
			return err
		}
		return h.p.sub.Registry.PutRepository(ctx, RepositoryState{Name: name, Owned: false})
	case compute.KindBucket:
		_, name, err := h.p.resolve(ref, compute.KindBucket)
		if err != nil {
			return err
		}
		return h.p.sub.Objects.PutBucket(ctx, BucketState{
			// ClaimForeign rather than ClaimUnclaimed: the conformance suite asks
			// for a bucket somebody ELSE manages, and an unclaimed bucket is
			// claimable by design, so seeding that would assert the opposite of
			// what CreateUnowned means.
			Name: name, Class: compute.ObjectClassStandard, Claim: ClaimForeign,
		})
	}

	mc, ok := h.p.sub.Cluster.(*MemoryCluster)
	if !ok {
		return errors.New("k8s: CreateUnowned needs the in-memory cluster")
	}
	gvk, ns, name, err := h.p.locate(ref)
	if err != nil {
		return err
	}
	obj, err := emptyObject(gvk, ns, name)
	if err != nil {
		return err
	}
	_ = ctx
	return mc.putUnowned(gvk, obj)
}

// Read performs a data-plane read of resource as identity.
func (h *Harness) Read(ctx context.Context, resource, identity compute.Ref) error {
	return h.access(ctx, resource, identity, false)
}

// Write performs a data-plane write of resource as identity.
func (h *Harness) Write(ctx context.Context, resource, identity compute.Ref) error {
	return h.access(ctx, resource, identity, true)
}

func (h *Harness) access(ctx context.Context, resource, identity compute.Ref, write bool) error {
	idNS, idName, err := h.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	switch resource.Kind {
	case compute.KindBucket:
		_, bucket, err := h.p.resolve(resource, compute.KindBucket)
		if err != nil {
			return err
		}
		// The workload presents its projected token; the store resolves it to
		// this subject. No intermediate credential exists.
		subject := subjectFor(idNS, idName)
		if write {
			return h.p.sub.Objects.Write(ctx, bucket, subject)
		}
		return h.p.sub.Objects.Read(ctx, bucket, subject)

	case compute.KindImageRepository:
		_, repo, err := h.p.resolve(resource, compute.KindImageRepository)
		if err != nil {
			return err
		}
		// Which principal the question has to be asked as is the finding.
		// On a cluster with a credential provider that forwards a pod-bound
		// ServiceAccount token, it is the identity itself. Without one, the
		// only way to ask "may this identity pull" is to find the credential
		// the provider had to mint and present that. See [imageRegistry].
		principal := subjectFor(idNS, idName)
		if !h.p.cfg.pullByWorkloadIdentity() {
			principal, err = h.pullToken(ctx, idNS, idName)
			if err != nil {
				return err
			}
		}
		if write {
			return h.p.sub.Registry.Push(ctx, repo, principal)
		}
		return h.p.sub.Registry.Pull(ctx, repo, principal)

	default:
		return fmt.Errorf("k8s: the harness has no data plane for a %q", resource.Kind)
	}
}

// pullToken recovers the robot token from the imagePullSecret the provider
// attached to the identity's ServiceAccount.
func (h *Harness) pullToken(ctx context.Context, namespace, saName string) (string, error) {
	obj, err := h.p.sub.Cluster.Get(ctx, gvkSecret, namespace, pullSecretName(saName))
	if err != nil {
		return "", fmt.Errorf("k8s: identity %s/%s holds no registry credential: %w",
			namespace, saName, err)
	}
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return "", errors.New("k8s: the pull secret is not a Secret")
	}
	return decodeDockerToken(sec.Data[corev1.DockerConfigJsonKey], h.p.cfg.Registry.Host)
}

// AnonymousRead attempts an unauthenticated read of a bucket.
func (h *Harness) AnonymousRead(ctx context.Context, bucket compute.Ref) error {
	_, name, err := h.p.resolve(bucket, compute.KindBucket)
	if err != nil {
		return err
	}
	return h.p.sub.Objects.AnonymousRead(ctx, name)
}

// Login authenticates against a relational endpoint, which is how "a re-Ensure
// does not rotate the admin password" is checked.
func (h *Harness) Login(ctx context.Context, ref compute.Ref, username string, password compute.SecretValue) error {
	ns, name, err := h.p.resolve(ref, compute.KindRelational)
	if err != nil {
		return err
	}
	obj, err := h.p.sub.Cluster.Get(ctx, gvkSecret, ns, adminSecretName(name))
	if err != nil {
		return fmt.Errorf("k8s: the endpoint has no admin credential: %w", err)
	}
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return errors.New("k8s: the admin credential is not a Secret")
	}
	if string(sec.Data[corev1.BasicAuthUsernameKey]) != username ||
		string(sec.Data[corev1.BasicAuthPasswordKey]) != compute.RevealSecret(password) {
		// Deliberately says nothing about what was presented.
		return errors.New("k8s: authentication failed")
	}
	return nil
}

// CanExecInto reports whether a workload identity may open an interactive
// session against a workload.
//
// The answer is always no, and it is no for a reason rather than by fiat: RBAC
// on pods/exec authorises the caller, this provider creates no Role or
// RoleBinding granting it, and [compute.ServiceSpec.ExecEnabled] is a statement
// about the target. A provider that "implemented" exec by binding the pods/exec
// verb to the workload's own ServiceAccount would let the workload exec into
// pods and would still not let an operator exec into the workload — the
// inversion PR #3 removed.
func (h *Harness) CanExecInto(ctx context.Context, identity, target compute.Ref) (bool, error) {
	if _, _, err := h.p.resolve(identity, compute.KindWorkloadIdentity); err != nil {
		return false, err
	}
	if _, _, err := h.p.resolve(target, compute.KindService); err != nil {
		return false, err
	}
	// The check is real: if the provider ever grew a RoleBinding for the
	// workload's own ServiceAccount, this would find it.
	bindings, err := h.p.sub.Cluster.List(ctx, gvkRoleBinding, "", nil)
	if err != nil {
		return false, err
	}
	return len(bindings) > 0, nil
}

// Rendered dumps everything the provider wrote, across all three substrates.
func (h *Harness) Rendered(ctx context.Context) ([]string, error) {
	mc, ok := h.p.sub.Cluster.(*MemoryCluster)
	if !ok {
		return nil, errors.New("k8s: Rendered needs the in-memory cluster")
	}
	out := mc.dump()
	if h.p.cfg.Registry != nil && h.p.sub.Registry != nil {
		lines, err := h.p.sub.Registry.Describe(ctx, h.p.cfg.Registry.Host, h.p.cfg.Registry.Project)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	if h.p.cfg.ObjectStore != nil && h.p.sub.Objects != nil {
		lines, err := h.p.sub.Objects.Describe(ctx, h.p.cfg.ObjectStore.URIScheme)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	return out, nil
}

// locate maps a [compute.Ref] onto the primary cluster object behind it.
//
// It lives on [Provider] rather than on [Harness] because two callers need it
// and only one of them is a test hook: a wait has to know which object to watch,
// and the mapping from a compute Kind to the cluster object that carries its
// status is the same mapping either way. Keeping one copy is the point — a second
// switch over the same Kinds would be a restatement, and the shape this project
// has been bitten by is a restatement drifting from what it restates.
func (p *Provider) locate(ref compute.Ref) (schemaGVK, string, string, error) {
	gvk, err := p.clusterGVK(ref.Kind)
	if err != nil {
		return schemaGVK{}, "", "", err
	}
	ns, name, err := p.resolve(ref, ref.Kind)
	return gvk, ns, name, err
}

// clusterGVK reports which cluster object carries a kind, or an error for a kind
// no cluster object stands behind.
//
// It is the kind-to-object half of [Provider.locate], split out because
// [Harness.InduceDenial] has to ask the same question — "is this port backed by
// the API server, and if so by what?" — and a second switch over the same kinds
// would be the restatement the note on locate is about. The two callers want
// different things from the answer (one watches the object, one arms the
// substrate holding it), and neither should be the one that knows a Gateway is
// what a function endpoint is.
func (p *Provider) clusterGVK(kind compute.Kind) (schemaGVK, error) {
	var gvk schemaGVK
	switch kind {
	case compute.KindWorkloadIdentity:
		gvk = gvkServiceAccount
	case compute.KindSecret:
		gvk = gvkSecret
	case compute.KindService, compute.KindFunction:
		gvk = gvkDeployment
	case compute.KindScheduledJob:
		gvk = gvkCronJob
	case compute.KindFunctionEndpoint:
		gvk = gvkGateway
	case compute.KindRelational:
		if p.cfg.PostgresOperator == nil {
			return gvk, errors.New("k8s: no Postgres operator is configured")
		}
		group, version, _ := parseAPIVersion(p.cfg.PostgresOperator.APIVersion)
		gvk = schemaGVK{Group: group, Version: version, Kind: p.cfg.PostgresOperator.Kind}
	default:
		return gvk, fmt.Errorf("k8s: no cluster object stands behind a %q", kind)
	}
	return gvk, nil
}

// emptyObject builds the bare object CreateUnowned puts in the cluster: the
// right kind under the right name, with none of this platform's labels.
func emptyObject(gvk schemaGVK, namespace, name string) (runtimeObject, error) {
	meta := objectMeta(namespace, name, map[string]string{"created-by": "somebody-else"})
	switch gvk {
	case gvkServiceAccount:
		return &corev1.ServiceAccount{ObjectMeta: meta}, nil
	case gvkSecret:
		return &corev1.Secret{ObjectMeta: meta, Type: corev1.SecretTypeOpaque}, nil
	case gvkDeployment:
		return &appsv1.Deployment{ObjectMeta: meta}, nil
	case gvkCronJob:
		return &batchv1.CronJob{ObjectMeta: meta, Spec: batchv1.CronJobSpec{Schedule: "0 0 * * *"}}, nil
	}
	// Everything else in this provider is a custom resource, and an unstructured
	// object is exactly what an operator's own client would have created.
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
		"spec":       map[string]any{},
	}}
	u.SetNamespace(namespace)
	u.SetName(name)
	u.SetLabels(map[string]string{"created-by": "somebody-else"})
	return u, nil
}

// decodeDockerToken recovers the token from a dockerconfigjson Secret.
func decodeDockerToken(data []byte, host string) (string, error) {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("k8s: the pull secret is not a docker config: %w", err)
	}
	entry, ok := cfg.Auths[host]
	if !ok {
		return "", fmt.Errorf("k8s: the pull secret has no entry for %q", host)
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Auth)
	if err != nil {
		return "", fmt.Errorf("k8s: the pull secret's auth is not base64: %w", err)
	}
	return string(raw), nil
}
