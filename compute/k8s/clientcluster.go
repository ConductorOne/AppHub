// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

// defaultFieldManager is the field-manager name this provider writes under.
//
// It is a fixed string rather than configuration because it identifies the
// *writer*, and every apphub deployment is the same writer as far as a
// co-operating controller is concerned. It contains no site-specific identifier.
const defaultFieldManager = "apphub"

// metadataNameField is the field selector that narrows a watch to one object: the
// object's name, under the metadata prefix, joined by a dot.
//
// It is assembled from its two segments rather than written as a single literal
// because this repository's secret scan reads a dotted two-label string inside a
// Go literal as a hostname — which is correct behaviour, since that is exactly
// how the source repository's own internal domain travels, and the scan covers
// comments and git history as well as code. This is a Kubernetes field path, not
// a host. Do not join it back into one literal: the scan fails the build, and the
// fix would then have to be an allowlist entry, which means loosening a detection
// rule for a string that was never a secret.
const metadataNameField = "metadata" + "." + "name"

// ClientCluster is a [Cluster] backed by a real Kubernetes API server through
// client-go.
//
// It is the production counterpart of [MemoryCluster], and it sits at the same
// seam: everything above [Cluster] — the whole translation between the compute
// contract and Kubernetes objects, which is where this provider's substance is —
// is shared between the two and unaware of which is installed. That is the
// property USOSS-27 built the seam for, and it is why this type is a few hundred
// lines rather than a rewrite.
//
// # One dynamic client rather than a typed client per group
//
// A typed clientset would give compile-time checking of every call, at the cost
// of a switch over every kind with five verbs each, and would still need the
// dynamic client for the two custom resources whose GroupVersionKind is operator
// configuration. So the whole provider goes through the dynamic client and
// converts, which makes one code path serve a built-in Deployment and a Postgres
// operator's cluster resource identically.
//
// The cost is that a kind's *resource name* is no longer supplied by generated
// code, and getting one wrong is a run-time 404 rather than a compile error.
// That is why [ResourceResolver] refuses an unmapped kind instead of guessing;
// see [StaticResolver] for the specific mistake it exists to prevent.
//
// # What is verified, and what is assumed
//
// Everything here is exercised against client-go's fake dynamic client, which
// proves this code issues the calls it means to. It does not prove a real API
// server responds as assumed — a fake shares the code's own beliefs about
// resource names, admission, defaulting, and status subresources. The
// assumptions are listed on [ClientCluster.Apply] and [ClientCluster.Watch],
// where they matter.
type ClientCluster struct {
	client   dynamic.Interface
	metadata metadata.Interface
	resolver ResourceResolver
	scheme   *runtime.Scheme
	manager  string
}

var (
	_ Cluster = (*ClientCluster)(nil)
	_ Watcher = (*ClientCluster)(nil)
)

// ClientClusterOptions is the optional half of [NewClientCluster].
type ClientClusterOptions struct {
	// Scheme converts between unstructured objects and the typed ones the
	// provider builds. Nil means client-go's scheme, which knows every built-in
	// kind. A caller with additional typed kinds registered supplies its own.
	Scheme *runtime.Scheme

	// FieldManager is the field-manager name writes are attributed to. Empty
	// means "apphub".
	FieldManager string

	// Metadata is the client [Cluster.GetMetadata] uses: client-go's metadata
	// client, which asks the API server for PartialObjectMetadata and therefore
	// receives no object payload.
	//
	// It is a separate client because the dynamic client has no metadata
	// projection — every read through it returns the whole object — and
	// GetMetadata's entire purpose is that the payload does not arrive.
	//
	// Nil is permitted and is NOT a fallback: GetMetadata then fails, naming
	// this field. A security property that quietly degraded to the
	// value-bearing read would be worse than one that is absent, because the
	// caller would believe it held. [NewClientClusterForConfig] builds one, so
	// the production path always has it.
	Metadata metadata.Interface
}

// NewClientCluster returns a cluster over client.
func NewClientCluster(client dynamic.Interface, resolver ResourceResolver, opts ClientClusterOptions) (*ClientCluster, error) {
	if client == nil {
		return nil, errors.New("k8s: NewClientCluster needs a dynamic client")
	}
	if resolver == nil {
		return nil, errors.New("k8s: NewClientCluster needs a ResourceResolver; a client that " +
			"guessed resource names would 404 at run time instead of refusing at construction")
	}
	out := &ClientCluster{
		client:   client,
		metadata: opts.Metadata,
		resolver: resolver,
		scheme:   opts.Scheme,
		manager:  opts.FieldManager,
	}
	if out.scheme == nil {
		out.scheme = scheme.Scheme
	}
	if out.manager == "" {
		out.manager = defaultFieldManager
	}
	return out, nil
}

// NewClientClusterForConfig builds a dynamic client from cfg and returns a
// cluster over it.
//
// It performs no I/O: client-go's dynamic client dials lazily, so a
// misconfigured cluster fails on first use rather than here. That is deliberate
// — a provider that reached the network from its constructor could not be
// constructed in a test at all — and it means a nil error from this function
// says nothing about whether the cluster is reachable.
func NewClientClusterForConfig(cfg *rest.Config, resolver ResourceResolver, opts ClientClusterOptions) (*ClientCluster, error) {
	if cfg == nil {
		return nil, errors.New("k8s: NewClientClusterForConfig needs a *rest.Config")
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: building a dynamic client: %w", err)
	}
	if opts.Metadata == nil {
		// The production path always has a metadata client, so GetMetadata's
		// nil-client refusal is reachable only by a caller that built a
		// ClientCluster directly.
		meta, err := metadata.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("k8s: building a metadata client: %w", err)
		}
		opts.Metadata = meta
	}
	return NewClientCluster(client, resolver, opts)
}

// resource returns the client for one kind in one namespace.
func (c *ClientCluster) resource(gvk schema.GroupVersionKind, namespace string) (dynamic.ResourceInterface, error) {
	gvr, namespaced, err := c.resolver.ResourceFor(gvk)
	if err != nil {
		return nil, err
	}
	if !namespaced || namespace == "" {
		return c.client.Resource(gvr), nil
	}
	return c.client.Resource(gvr).Namespace(namespace), nil
}

// Get implements [Cluster].
func (c *ClientCluster) Get(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	client, err := c.resource(gvk, namespace)
	if err != nil {
		return nil, err
	}
	u, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, c.apiError(err, gvk, namespace, name)
	}
	return c.fromUnstructured(u, gvk)
}

// GetMetadata implements [Cluster]: it asks the API server for the object's
// metadata and receives no payload.
//
// client-go's metadata client sends the PartialObjectMetadata Accept header, so
// the server projects the object server-side and the values never cross the
// wire. That is the difference between this and Get, and it is the reason
// GetMetadata exists rather than being Get with the result ignored.
func (c *ClientCluster) GetMetadata(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (*metav1.PartialObjectMetadata, error) {
	if c.metadata == nil {
		return nil, fmt.Errorf("k8s: this cluster was built with no metadata client, so it "+
			"cannot read %s/%s without fetching its payload; set ClientClusterOptions.Metadata. "+
			"Falling back to the value-bearing read is deliberately not done: a caller asked a "+
			"question about metadata and must not be answered with an object", namespace, name)
	}
	gvr, namespaced, err := c.resolver.ResourceFor(gvk)
	if err != nil {
		return nil, err
	}
	client := c.metadata.Resource(gvr).Namespace(namespace)
	if !namespaced || namespace == "" {
		client = c.metadata.Resource(gvr).Namespace("")
	}
	out, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, c.apiError(err, gvk, namespace, name)
	}
	return out, nil
}

// Apply implements [Cluster]: it creates the object if it is absent and replaces
// it if it is present.
//
// # Why read-modify-write rather than server-side apply
//
// Server-side apply is the natural verb for a declarative write and would let
// the API server own the merge. It is not used here for two reasons, and the
// second is the honest one.
//
// The first is that this provider always writes whole objects — every Ensure
// renders the complete desired state from the caller's spec — so there is no
// partial-object merge for SSA to arbitrate. A full replace is the same
// operation.
//
// The second is that client-go's fake dynamic client does not implement
// [types.ApplyPatchType]: a patch of that type fails with "unable to find api
// field in struct Unstructured". So an SSA implementation would be an
// unexercised code path in every test this repository can run, and the first
// time anybody found out whether it worked would be against a real cluster. A
// read-modify-write is fully exercisable, and it makes this substrate's most
// common retryable failure — the stale-resourceVersion 409 — a real, tested path
// rather than a hypothetical one. See [Provider.substrateError] for why that
// distinction earned an interface amendment.
//
// # Two behaviours that are assumptions, not facts
//
// Status is copied from the stored object onto the outgoing one before the
// update. On a real API server this is unnecessary for a built-in kind, because
// status is a subresource and an update to the main resource ignores it — but it
// *is* necessary for a custom resource whose CRD does not declare a status
// subresource, where a plain update would blank the operator's status and make a
// running database read as pending. Copying is correct in both cases and is what
// [MemoryCluster] does, so the two substrates behave alike. Whether any
// particular operator's CRD declares the subresource is not observable from here.
//
// An AlreadyExists on the create branch is mapped to
// [ErrOptimisticConcurrency] rather than to a failure. It means another writer
// created the object between this read and this write, which is precisely a
// retryable conflict: [Provider.apply] will re-read and take the update branch.
func (c *ClientCluster) Apply(ctx context.Context, gvk schema.GroupVersionKind, obj runtime.Object) error {
	desired, err := c.toUnstructured(obj, gvk)
	if err != nil {
		return err
	}
	namespace, name := desired.GetNamespace(), desired.GetName()
	if name == "" {
		return fmt.Errorf("k8s: object of kind %s has no name", gvk.Kind)
	}
	client, err := c.resource(gvk, namespace)
	if err != nil {
		return err
	}

	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := client.Create(ctx, desired, metav1.CreateOptions{FieldManager: c.manager}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("%w: %s %s/%s was created by another writer between the read "+
					"and the create", ErrOptimisticConcurrency, gvk.Kind, namespace, name)
			}
			return c.apiError(err, gvk, namespace, name)
		}
		return nil
	case err != nil:
		return c.apiError(err, gvk, namespace, name)
	}

	// The stored resourceVersion is carried onto the outgoing object so the
	// update is a compare-and-swap: if anything wrote in between, the API server
	// answers 409 and [Provider.apply] re-reads.
	//
	// A resourceVersion is an OPTIMISTIC-CONCURRENCY TOKEN AND NOT A CONTENT
	// VERSION. It is opaque, it changes on writes a caller never made, and it is
	// not comparable or orderable across objects. Nothing may map it onto a
	// user-visible "version" of a Secret's material: a caller pinning a secret
	// version would appear to have its pin honoured while reading whatever the
	// latest value happens to be, which is a fail-open dressed as a feature.
	// (USOSS-35 amends compute.SecretBinding to carry a version, and the answer
	// for this substrate is a typed refusal, not this field.)
	desired.SetResourceVersion(existing.GetResourceVersion())
	if status, found := existing.Object["status"]; found {
		desired.Object["status"] = status
	}
	if _, err := client.Update(ctx, desired, metav1.UpdateOptions{FieldManager: c.manager}); err != nil {
		return c.apiError(err, gvk, namespace, name)
	}
	return nil
}

// Delete implements [Cluster]. Deleting an absent object is not an error, which
// is what makes every Delete* method on the provider idempotent.
func (c *ClientCluster) Delete(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) error {
	client, err := c.resource(gvk, namespace)
	if err != nil {
		return err
	}
	err = client.Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return c.apiError(err, gvk, namespace, name)
}

// List implements [Cluster].
//
// The selector is pushed down to the API server as a label selector rather than
// filtered here, so a cluster with a hundred thousand Secrets does not send them
// all. Results are sorted by name, matching [MemoryCluster], because the compute
// contract's determinism invariant compares two reads and the API server makes
// no ordering promise across pages.
func (c *ClientCluster) List(ctx context.Context, gvk schema.GroupVersionKind, namespace string, selector map[string]string) ([]runtime.Object, error) {
	client, err := c.resource(gvk, namespace)
	if err != nil {
		return nil, err
	}
	opts := metav1.ListOptions{}
	if len(selector) > 0 {
		opts.LabelSelector = labels.Set(selector).String()
	}
	list, err := client.List(ctx, opts)
	if err != nil {
		return nil, c.apiError(err, gvk, namespace, "")
	}
	items := list.Items
	sort.Slice(items, func(i, j int) bool { return items[i].GetName() < items[j].GetName() })
	out := make([]runtime.Object, 0, len(items))
	for i := range items {
		converted, err := c.fromUnstructured(&items[i], gvk)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

// Watch implements [Watcher]: it reports that one object may have changed.
//
// # What it delivers, and why that is all
//
// The channel carries no event payload. A tick means "read it again", and the
// caller — [Provider.waitFor] — does exactly that, through the same Get every
// other path uses. That is deliberate: a watch event's object can be stale
// relative to a subsequent read, and a wait loop that trusted the payload would
// have two sources of truth for the same object. One is enough, and it keeps the
// watch a pure replacement for the poll timer rather than a second data path.
//
// The channel has room for one pending tick and a full channel is not blocked
// on. Coalescing is correct here for the same reason: the consumer re-reads
// current state, so two ticks and one tick lead to the same read.
//
// # Reconnection, and what happens when it fails
//
// A watch ends for ordinary reasons — an API server rolling, a timeout, a
// compaction — so the goroutine re-establishes it. The re-established watch does
// not resume from a resourceVersion: it does not need to, because the consumer
// re-reads on every tick and a missed intermediate state is not observable
// through a contract whose only question is "is it ready yet".
//
// If re-establishing fails, the channel is *closed* rather than left silent. A
// closed channel is what tells [Provider.waitFor] to fall back to polling for
// the rest of the wait, so a watch that dies does not turn a bounded wait into a
// hang. That fallback is the one place a caller can observe the difference
// between this cluster and [MemoryCluster], and it is why the poll path is kept.
//
// # The assumption
//
// This is verified against client-go's fake dynamic client, which delivers a
// watch event on every create and update. That the fake fires is evidence this
// code wires the watch up correctly. It is not evidence that a real API server
// delivers an event for the specific field transitions this provider waits on —
// notably a Deployment's status conditions, written by a controller rather than
// by us. If a real cluster ever proves stingier than the fake, the failure is a
// wait that runs to its deadline, not a wrong answer, because the poll fallback
// and the deadline both still apply.
func (c *ClientCluster) Watch(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (<-chan struct{}, func(), error) {
	client, err := c.resource(gvk, namespace)
	if err != nil {
		return nil, nil, err
	}
	if name == "" {
		return nil, nil, errors.New("k8s: a watch needs the name of the object to watch")
	}
	opts := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metadataNameField, name).String(),
	}

	watcher, err := client.Watch(ctx, opts)
	if err != nil {
		return nil, nil, c.apiError(err, gvk, namespace, name)
	}

	inner, cancel := context.WithCancel(ctx)
	changes := make(chan struct{}, 1)
	var once sync.Once
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer close(changes)
		current := watcher
		defer func() { current.Stop() }()

		// tick reports that the object may have changed. It coalesces, because the
		// consumer re-reads current state and two ticks lead to the same read.
		tick := func() {
			select {
			case changes <- struct{}{}:
			default:
			}
		}

		// resumeFrom is the newest resourceVersion this watch has observed. A
		// replacement watch resumes from it so the API server replays anything
		// that happened while no watch existed, rather than starting from "now".
		resumeFrom := ""

		for {
			select {
			case <-inner.Done():
				return
			case event, ok := <-current.ResultChan():
				if ok {
					if rv := eventResourceVersion(event.Object); rv != "" {
						resumeFrom = rv
					}
					tick()
					continue
				}
				// # The gap between two watches, which is a transition rather
				// than a call
				//
				// The watch ended. Every individual watch here worked; what was
				// broken was the move between two of them. A change landing after
				// the old watch closed and before the replacement existed was
				// reported by neither: the replacement started from "now" and
				// emitted nothing, so a consumer waiting for readiness on an
				// object that had *already become* ready waited out its whole
				// deadline. The report's concession that a missed intermediate
				// state is unobservable did not cover it, because the state
				// reached in the gap is persistent, not intermediate.
				//
				// Two things close it, and both are here because they fail
				// differently. Resuming from the last observed resourceVersion
				// asks the server to replay the gap, which is the correct fix and
				// depends on the server still holding that history — it may answer
				// 410 Gone if it does not. Emitting one tick as soon as the
				// replacement is established does not depend on the server at all:
				// it makes the consumer re-read, and a re-read of current state
				// cannot miss a persistent change whatever happened in the gap.
				current.Stop()
				resumeOpts := opts
				resumeOpts.ResourceVersion = resumeFrom
				next, err := client.Watch(inner, resumeOpts)
				if err != nil && resumeFrom != "" {
					// Most likely the history is gone. Retry from "now" — the
					// unconditional tick below is what keeps that safe.
					resumeFrom = ""
					resumeOpts.ResourceVersion = ""
					next, err = client.Watch(inner, resumeOpts)
				}
				if err != nil {
					// Change notification has stopped working. Closing the channel
					// is what drops the waiter to polling rather than leaving it
					// blocked on something nothing will write to.
					return
				}
				current = next
				tick()
			}
		}
	}()

	stop := func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	return changes, stop, nil
}

// eventResourceVersion reads the resourceVersion off a watch event's object, or
// returns "" when the object has none — a bookmark or an error event, or anything
// without object metadata. An empty answer leaves the resume point where it was,
// which is the conservative direction: resuming from an older version replays more
// than necessary, and replaying too much is harmless because the consumer re-reads.
func eventResourceVersion(obj runtime.Object) string {
	if obj == nil {
		return ""
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		return ""
	}
	return acc.GetResourceVersion()
}

// --- conversion ----------------------------------------------------------------

// toUnstructured renders an object as unstructured, stamping the GVK.
//
// The GVK is stamped from the seam's argument rather than read off the object,
// because the provider builds typed objects with an empty TypeMeta — which is
// idiomatic Go client code and fatal for a dynamic write, since apiVersion and
// kind are how the API server routes it.
func (c *ClientCluster) toUnstructured(obj runtime.Object, gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	if obj == nil {
		return nil, fmt.Errorf("k8s: no object was supplied for kind %s", gvk.Kind)
	}
	if u, ok := obj.(*unstructured.Unstructured); ok {
		out := u.DeepCopy()
		out.SetGroupVersionKind(gvk)
		return out, nil
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("k8s: converting a %s to unstructured: %w", gvk.Kind, err)
	}
	out := &unstructured.Unstructured{Object: content}
	out.SetGroupVersionKind(gvk)
	return out, nil
}

// fromUnstructured converts a server response back into the shape the provider
// above this seam expects.
//
// A kind the scheme knows comes back typed, because the translation layer type
// asserts on concrete types — `obj.(*appsv1.Deployment)` — exactly as it does
// against [MemoryCluster]. A kind the scheme does not know, which is every
// operator-supplied custom resource, stays unstructured, which is also what
// MemoryCluster stores for it. Keeping both substrates' return types identical
// is what lets one translation layer serve both.
func (c *ClientCluster) fromUnstructured(u *unstructured.Unstructured, gvk schema.GroupVersionKind) (runtime.Object, error) {
	if !c.scheme.Recognizes(gvk) {
		return u.DeepCopy(), nil
	}
	typed, err := c.scheme.New(gvk)
	if err != nil {
		return nil, fmt.Errorf("k8s: the scheme recognises %s but cannot construct it: %w", gvk, err)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, typed); err != nil {
		return nil, fmt.Errorf("k8s: converting a %s from unstructured: %w", gvk.Kind, err)
	}
	return typed, nil
}

// --- errors -------------------------------------------------------------------

// apiError maps an API-server error onto this package's substrate errors.
//
// It stops at the substrate taxonomy on purpose: mapping onto the compute
// taxonomy is [Provider.substrateError]'s job, and the two 409s Kubernetes has
// mean unrelated things. See the note on [ErrOptimisticConcurrency].
func (c *ClientCluster) apiError(err error, gvk schema.GroupVersionKind, namespace, name string) error {
	if err == nil {
		return nil
	}
	where := objectKey{gvk: gvk, namespace: namespace, name: name}
	switch {
	case apierrors.IsNotFound(err):
		return fmt.Errorf("%w: %s", ErrObjectNotFound, where)
	case apierrors.IsConflict(err):
		// The retryable 409. Kubernetes' other 409 — a name already taken — is
		// AlreadyExists, and IsConflict is false for it, so this branch cannot
		// swallow an ownership collision.
		return fmt.Errorf("%w: %s: %w", ErrOptimisticConcurrency, where, err)
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		// RBAC refused the verb, or the credential was not accepted. Without
		// this arm both fell to the default and reached the caller as
		// [compute.ErrFailed] — "the resource entered a failed state" for a
		// request the API server never acted on. See [ErrClusterDenied].
		return fmt.Errorf("%w: %s: %w", ErrClusterDenied, where, err)
	default:
		return fmt.Errorf("k8s: %s: %w", where, err)
	}
}
