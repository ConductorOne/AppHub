// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Errors the substrate returns. They are deliberately substrate-shaped rather
// than compute-shaped: mapping them onto the [compute] taxonomy is the
// provider's job, and one of this probe's findings is that the mapping is not
// onto. See doc.go, "the 409 problem".
var (
	// ErrObjectNotFound is the API server's 404.
	ErrObjectNotFound = errors.New("k8s: object not found")

	// ErrOptimisticConcurrency is the API server's 409 Conflict on a stale
	// resourceVersion. It is the canonical *retryable* Kubernetes error, and
	// [compute.ErrNotOwned] means something entirely different, so a provider
	// must never surface it as one.
	ErrOptimisticConcurrency = errors.New("k8s: the object was modified; please apply your changes to the latest version")

	// ErrClusterDenied is the API server's 403 and its 401: RBAC refused the
	// verb, or the credential this platform presented was not accepted at all.
	//
	// It is the cluster's member of a set of three. Each substrate behind this
	// provider spells a denial in its own vocabulary and each has its own
	// sentinel — [ErrRegistryDenied] for the registry, [ErrObjectStoreDenied] for
	// the object store — and [Provider.substrateError] and
	// [Provider.backingError] are where all three become
	// [compute.ErrNotPermitted]. The cluster's was the one missing, which is why
	// a Kubernetes RBAC rejection surfaced as [compute.ErrFailed]: not because
	// the mapping chose wrong, but because nothing named the input.
	//
	// A 401 is here with the 403 on purpose, following the sentinel it maps onto:
	// [compute.ErrNotPermitted] takes both, because the question the taxonomy
	// asks is who can fix it and whether the same request could ever succeed, and
	// the answer for a rejected credential is the same as for a refused verb. The
	// wrapped API-server error still says which.
	ErrClusterDenied = errors.New("k8s: the API server refused the credential")
)

// Cluster is the subset of a Kubernetes API server this provider uses.
//
// It exists so the whole translation above it — every place the [compute]
// interface and the Kubernetes API disagree, which is where this provider's
// substance is — is written once and serves two substrates. There are two:
// [MemoryCluster], which runs the conformance suite with no cluster and no
// network, and [ClientCluster], which is client-go against a real API server.
// USOSS-27 built the seam and the first; USOSS-19 added the second, and the
// prediction that it would be one implementation of four methods rather than a
// rewrite held.
//
// A cluster that can report changes also implements [Watcher], which is what
// lets a wait block on a change instead of re-reading on a timer.
type Cluster interface {
	// Get returns a deep copy of the object, or [ErrObjectNotFound].
	Get(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error)

	// GetMetadata returns an object's metadata WITHOUT its payload, or
	// [ErrObjectNotFound].
	//
	// It is a separate verb from Get and it is required rather than optional,
	// which is the whole point. A caller that only needs to know whether an
	// object exists must be able to ask without the object's contents entering
	// this process — and for a Secret that is not a nicety, it is the difference
	// between a metadata read and a read-back.
	//
	// Review found this the hard way: [compute.SecretStore.Describe] was
	// implemented over Get and never looked at Secret.Data, which made it
	// metadata-only in intent and not in effect. The whole corev1.Secret,
	// values included, had already been fetched and deserialized. *Not looking
	// at material you have fetched is not the same as not fetching it.*
	//
	// It is required, and not an optional interface like [Watcher], because a
	// substrate that could not do it would make Describe fall back to Get — and
	// a security property with a fallback is a security property with a bypass.
	// A substrate that genuinely cannot must fail the call, not widen it.
	GetMetadata(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (*metav1.PartialObjectMetadata, error)

	// Apply creates or updates an object. It is the provider's only write verb,
	// which is what keeps every Ensure declarative: the object handed in is the
	// desired state and the substrate converges to it.
	Apply(ctx context.Context, gvk schema.GroupVersionKind, obj runtime.Object) error

	// Delete removes an object. Deleting an absent object returns nil.
	Delete(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) error

	// List returns every object of gvk in namespace whose labels are a superset
	// of selector.
	List(ctx context.Context, gvk schema.GroupVersionKind, namespace string, selector map[string]string) ([]runtime.Object, error)
}

// Watcher is the optional half of [Cluster]: a substrate that can tell a caller
// when one object has changed, instead of being asked again on a timer.
//
// It is a separate interface rather than a fifth method on [Cluster] for a
// reason that is not stylistic. [MemoryCluster] deliberately advances
// convergence *on observation* — a read is its clock, which is what keeps the
// hermetic suite free of timers — so it has nothing to report a change from: a
// watch on it would block forever waiting for a write that only a reader can
// cause. Making the capability optional lets the substrate that genuinely has
// it use it ([ClientCluster]) while the one that cannot say so by not
// implementing it, and [Provider.waitFor] reads that as "poll", which is the
// documented fallback rather than an accident.
//
// A Cluster that implements this must guarantee two things, because
// [Provider.waitFor] relies on both:
//
//   - a tick means "read the object again", not "here is its new value". No
//     payload crosses the channel, so there is only ever one source of truth for
//     an object's state.
//   - the channel is closed if change notification stops working. A silent
//     channel would turn a bounded wait into a hang; a closed one makes the
//     waiter fall back to polling for the remainder of its deadline.
type Watcher interface {
	// Watch reports changes to one object until stop is called or ctx is done.
	// The returned stop function is safe to call more than once and blocks until
	// the watch's own goroutine has finished, so a caller may tear down
	// whatever the watch touched as soon as it returns.
	Watch(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (changes <-chan struct{}, stop func(), err error)
}

// objectKey addresses one object.
type objectKey struct {
	gvk       schema.GroupVersionKind
	namespace string
	name      string
}

func (k objectKey) String() string {
	if k.namespace == "" {
		return k.gvk.Kind + "/" + k.name
	}
	return k.gvk.Kind + " " + k.namespace + "/" + k.name
}

// entry is one stored object plus the bookkeeping a controller needs.
type entry struct {
	object runtime.Object
	// generation increments when the spec changes, as it does on a real API
	// server. It is what a status's observedGeneration is compared against.
	generation int64
	// observations counts how many times a client has read the object. It
	// stands in for elapsed time: an in-memory cluster has no controllers of
	// its own, so convergence advances when somebody looks, which keeps the
	// whole suite free of sleeps.
	observations int
	// stalled makes the object stop converging, for the conformance suite's
	// Stall hook.
	stalled bool
	// unowned marks an object created outside the provider, for CreateUnowned.
	unowned bool
}

// MemoryCluster is an in-memory stand-in for an API server, including the part
// of kube-controller-manager (and of the operators the provider depends on)
// that writes status.
//
// It is not a mock of the provider's calls: it stores the objects the provider
// actually builds and answers reads from them, so a translation bug shows up as
// a wrong object rather than as an unmet expectation. What it deliberately does
// not simulate is admission, defaulting, finalizers, or scheduling — none of
// which the [compute] contract can observe.
type MemoryCluster struct {
	mu      sync.Mutex
	objects map[objectKey]*entry
	// seen records every kind any verb has been called with, whether or not the
	// object existed. It is the population TestEveryKindTheProviderWritesIsResolvable
	// checks a ResourceResolver against: the set of kinds a real client would
	// have to address is not something to write down by hand, because a kind
	// missing from the list is exactly the kind that 404s in production.
	seen map[schema.GroupVersionKind]struct{}
	// resourceVersion is cluster-wide and monotonic, as it is on a real server.
	resourceVersion int64
	// failEvery, when set, is returned from every verb — not only from Apply.
	// It exists so the conformance suite can make the substrate fail in a way a
	// retry would fix and check that the provider's error mapping reaches
	// ErrTransient.
	//
	// It covers reads and deletes as well as writes because USOSS-32 measured
	// what an apply-only injection leaves unexercised: with writes alone, every
	// read-back path and every delete path in this provider's error mapping is
	// unverified, and the suite reported nine such observations for this
	// provider. Failing every verb is also the contract the suite documents for
	// its InduceTransient hook — "fail every substrate call until stop", not
	// "fail the next one".
	failEvery error
}

// NewMemoryCluster returns an empty cluster.
func NewMemoryCluster() *MemoryCluster {
	return &MemoryCluster{
		objects: map[objectKey]*entry{},
		seen:    map[schema.GroupVersionKind]struct{}{},
	}
}

// SeenKinds returns every kind this cluster has been asked about, sorted.
//
// It exists so a test can derive the set of kinds the provider actually
// addresses by driving the provider, rather than restating it. A hand-written
// list of kinds is the shape this project has been bitten by repeatedly: the
// entry that is missing is the one nobody thought of, and for a resource-name
// table that means a run-time 404 rather than a build failure.
func (c *MemoryCluster) SeenKinds() []schema.GroupVersionKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]schema.GroupVersionKind, 0, len(c.seen))
	for gvk := range c.seen {
		out = append(out, gvk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// note records a kind, under the caller's lock.
func (c *MemoryCluster) note(gvk schema.GroupVersionKind) { c.seen[gvk] = struct{}{} }

var _ Cluster = (*MemoryCluster)(nil)

// Get reads an object, advancing the controllers that would be watching it.
func (c *MemoryCluster) Get(_ context.Context, gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note(gvk)
	if c.failEvery != nil {
		return nil, c.failEvery
	}
	e, ok := c.objects[objectKey{gvk, namespace, name}]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, objectKey{gvk, namespace, name})
	}
	c.observe(e)
	return e.object.DeepCopyObject(), nil
}

// GetMetadata implements [Cluster]: it returns the object's metadata and never
// its payload.
//
// The in-memory substrate necessarily already holds the object, so nothing here
// can stop material existing in this process. What it can do — and what the
// property is actually about — is not hand any out: the returned
// PartialObjectMetadata is built from the object's meta alone, so a caller that
// asks this question cannot receive an answer carrying a value. A control in
// the k8s suite asserts Describe reaches this and never Get.
func (c *MemoryCluster) GetMetadata(_ context.Context, gvk schema.GroupVersionKind, namespace, name string) (*metav1.PartialObjectMetadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note(gvk)
	if c.failEvery != nil {
		return nil, c.failEvery
	}
	e, ok := c.objects[objectKey{gvk, namespace, name}]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, objectKey{gvk, namespace, name})
	}
	c.observe(e)
	meta, err := meta.Accessor(e.object)
	if err != nil {
		return nil, fmt.Errorf("k8s: reading the metadata of %s: %w", objectKey{gvk, namespace, name}, err)
	}
	out := &metav1.PartialObjectMetadata{}
	out.SetGroupVersionKind(gvk)
	out.ObjectMeta = metav1.ObjectMeta{
		Name:        meta.GetName(),
		Namespace:   meta.GetNamespace(),
		Labels:      maps.Clone(meta.GetLabels()),
		Annotations: maps.Clone(meta.GetAnnotations()),
	}
	return out, nil
}

// Apply writes an object.
func (c *MemoryCluster) Apply(_ context.Context, gvk schema.GroupVersionKind, obj runtime.Object) error {
	c.mu.Lock()
	injected := c.failEvery
	c.mu.Unlock()
	if injected != nil {
		return injected
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("k8s: object of kind %s has no metadata: %w", gvk.Kind, err)
	}
	if acc.GetName() == "" {
		return fmt.Errorf("k8s: object of kind %s has no name", gvk.Kind)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note(gvk)
	key := objectKey{gvk, acc.GetNamespace(), acc.GetName()}
	c.resourceVersion++
	stored := obj.DeepCopyObject()
	storedAcc, err := meta.Accessor(stored)
	if err != nil {
		return fmt.Errorf("k8s: object of kind %s has no metadata: %w", gvk.Kind, err)
	}
	storedAcc.SetResourceVersion(fmt.Sprint(c.resourceVersion))

	if existing, ok := c.objects[key]; ok {
		// Status is a subresource: an update to spec does not clear it.
		copyStatus(stored, existing.object)
		gen := existing.generation
		changed := !specEqual(existing.object, stored)
		if changed {
			gen++
		}
		storedAcc.SetGeneration(gen)
		existing.object = stored
		existing.generation = gen
		if changed {
			// A spec change restarts convergence, which is what makes a
			// rollout observable as a rollout rather than as a no-op.
			existing.observations = 0
		}
		return nil
	}
	storedAcc.SetGeneration(1)
	c.objects[key] = &entry{object: stored, generation: 1}
	return nil
}

// Delete removes an object; deleting an absent one is not an error.
func (c *MemoryCluster) Delete(_ context.Context, gvk schema.GroupVersionKind, namespace, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note(gvk)
	if c.failEvery != nil {
		return c.failEvery
	}
	delete(c.objects, objectKey{gvk, namespace, name})
	return nil
}

// List returns matching objects, in name order so callers are deterministic.
func (c *MemoryCluster) List(_ context.Context, gvk schema.GroupVersionKind, namespace string, selector map[string]string) ([]runtime.Object, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.note(gvk)
	if c.failEvery != nil {
		return nil, c.failEvery
	}
	var keys []objectKey
	for k := range c.objects {
		if k.gvk != gvk || (namespace != "" && k.namespace != namespace) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	var out []runtime.Object
	for _, k := range keys {
		e := c.objects[k]
		acc, err := meta.Accessor(e.object)
		if err != nil {
			continue
		}
		if !labelsMatch(acc.GetLabels(), selector) {
			continue
		}
		c.observe(e)
		out = append(out, e.object.DeepCopyObject())
	}
	return out, nil
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// stall makes an object stop converging.
func (c *MemoryCluster) stall(gvk schema.GroupVersionKind, namespace, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.objects[objectKey{gvk, namespace, name}]
	if !ok {
		return fmt.Errorf("%w: %s", ErrObjectNotFound, objectKey{gvk, namespace, name})
	}
	e.stalled = true
	return nil
}

// putUnowned stores an object the provider did not create, so the ownership
// invariant has something to collide with.
func (c *MemoryCluster) putUnowned(gvk schema.GroupVersionKind, obj runtime.Object) error {
	if err := c.Apply(context.Background(), gvk, obj); err != nil {
		return err
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.objects[objectKey{gvk, acc.GetNamespace(), acc.GetName()}]; ok {
		e.unowned = true
	}
	return nil
}

// dump renders every object as one line, for the conformance suite's Rendered
// hook. Nothing that could be secret material is included; see renderObject.
func (c *MemoryCluster) dump() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var keys []objectKey
	for k := range c.objects {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, renderObject(k, c.objects[k].object))
	}
	return out
}

// specEqual compares the parts of two objects a generation bump is about. It
// is a deliberate approximation: the provider only ever writes whole objects,
// so comparing the rendered form catches every change it can make.
func specEqual(a, b runtime.Object) bool {
	return renderSpec(a) == renderSpec(b)
}

// metaLabels reads an object's labels, or nil.
func metaLabels(obj runtime.Object) map[string]string {
	acc, err := meta.Accessor(obj)
	if err != nil {
		return nil
	}
	return acc.GetLabels()
}

// metaAnnotations reads an object's annotations, or nil.
func metaAnnotations(obj runtime.Object) map[string]string {
	acc, err := meta.Accessor(obj)
	if err != nil {
		return nil
	}
	return acc.GetAnnotations()
}

// objectMeta builds the metadata every object this provider creates carries.
//
// The ownership marker is a label rather than an annotation because a label can
// be selected on, and teardown by scope needs that.
func objectMeta(namespace, name string, labels map[string]string) metav1.ObjectMeta {
	out := map[string]string{}
	for k, v := range labels {
		out[k] = v
	}
	return metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: out}
}

// sortedPairs renders a map as "k=v k=v", sorted, for the Rendered hook.
func sortedPairs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}

// FailEvery makes every verb — Get, Apply, Delete and List — return err until
// the returned function is called.
//
// Used by the conformance suite's retry gate: only a provider knows how to make
// its own substrate fail in a way a retry would fix, so the suite asks for it
// rather than trying to arrange one.
//
// It covers every verb rather than only Apply because an apply-only injection
// leaves the read and delete halves of [Provider.substrateError] unexercised —
// measured, not assumed: USOSS-32's gate reported nine such observations for this
// provider on the full-cluster configuration. Widening the injection is the
// cheap half of closing them.
func (c *MemoryCluster) FailEvery(err error) func() {
	c.mu.Lock()
	c.failEvery = err
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.failEvery = nil
		c.mu.Unlock()
	}
}
