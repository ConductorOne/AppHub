// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// ErrAccessDenied is what the fake substrate's data plane returns when an
// identity has no grant covering the operation.
//
// It is not one of the [compute] sentinels because it is not an interface error:
// it is the substrate refusing a runtime operation, which is exactly the thing a
// grant is supposed to change. The conformance suite only requires that it be
// non-nil.
var ErrAccessDenied = errors.New("fake: the workload identity has no grant permitting this")

// Harness exposes the substrate operations a conformance suite needs and the
// [compute.Provider] interface deliberately does not have.
//
// Every method here answers a question the interface cannot: can this identity
// actually read that bucket, does an anonymous request get refused, does the
// original admin password still work, what did the provider render. Those are
// behavioural questions, and answering them is substrate-specific — which is why
// the conformance suite takes them as hooks rather than assuming a shape.
//
// Obtain one with [Provider.Harness]. Nothing in the provider's own code path
// consults it.
type Harness struct{ p *Provider }

// Harness returns the test hooks for this provider's substrate.
func (p *Provider) Harness() *Harness { return &Harness{p: p} }

// Stall makes a resource stop converging, so that a Wait against it has
// something to time out on. It is the hook behind the deadline invariant.
func (h *Harness) Stall(_ context.Context, ref compute.Ref) error {
	if ref.Provider != h.p.cfg.Name {
		return fmt.Errorf("fake: %s: %w", ref, compute.ErrForeignRef)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	a := h.asyncStateLocked(ref)
	if a == nil {
		return fmt.Errorf("fake: nothing asynchronous at %s to stall: %w", ref, compute.ErrNotFound)
	}
	a.stalled = true
	a.phase = compute.PhasePending
	a.observations = 0
	a.message = "stalled by the test harness"
	return nil
}

func (h *Harness) asyncStateLocked(ref compute.Ref) *asyncState {
	switch ref.Kind {
	case compute.KindService:
		if rec, ok := h.p.store.services[ref.ID]; ok {
			return rec.async
		}
	case compute.KindScheduledJob:
		if rec, ok := h.p.store.jobs[ref.ID]; ok {
			return rec.async
		}
	case compute.KindFunction:
		if rec, ok := h.p.store.functions[ref.ID]; ok {
			return rec.async
		}
	case compute.KindFunctionEndpoint:
		if rec, ok := h.p.store.endpoints[ref.ID]; ok {
			return rec.async
		}
	case compute.KindRelational:
		if rec, ok := h.p.store.relationals[ref.ID]; ok {
			return rec.async
		}
	case compute.KindKeyValueTable:
		if rec, ok := h.p.store.tables[ref.ID]; ok {
			return rec.async
		}
	}
	return nil
}

// CreateUnowned puts a resource into the substrate under the reference a spec
// would claim, without this platform's ownership marker.
//
// It is the hook behind the ownership invariant: an Ensure that finds such a
// resource must return [compute.ErrNotOwned] rather than adopt it, because the
// names these resources carry derive from mutable application names and
// reconciling a stranger's infrastructure is not a recoverable mistake.
func (h *Harness) CreateUnowned(_ context.Context, ref compute.Ref) error {
	if ref.Provider != h.p.cfg.Name {
		return fmt.Errorf("fake: %s: %w", ref, compute.ErrForeignRef)
	}
	name := strings.TrimPrefix(ref.ID, string(ref.Kind)+"/")

	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()

	switch ref.Kind {
	case compute.KindWorkloadIdentity:
		putUnowned(h.p.store.identities, ref, name, compute.WorkloadIdentitySpec{Name: name}, false, h.p)
	case compute.KindImageRepository:
		putUnowned(h.p.store.repos, ref, name, compute.RepositorySpec{Name: name}, false, h.p)
	case compute.KindBucket:
		putUnowned(h.p.store.buckets, ref, name, compute.BucketSpec{Name: name}, false, h.p)
	case compute.KindSecret:
		putUnowned(h.p.store.secrets, ref, name, compute.SecretSpec{Name: name}, false, h.p)
	case compute.KindService:
		putUnowned(h.p.store.services, ref, name, compute.ServiceSpec{Name: name}, true, h.p)
	case compute.KindScheduledJob:
		putUnowned(h.p.store.jobs, ref, name, compute.ScheduledJobSpec{Name: name}, true, h.p)
	case compute.KindFunction:
		putUnowned(h.p.store.functions, ref, name, compute.FunctionSpec{Name: name}, true, h.p)
	case compute.KindFunctionEndpoint:
		putUnowned(h.p.store.endpoints, ref, name, compute.EndpointSpec{Name: name}, true, h.p)
	case compute.KindRelational:
		putUnowned(h.p.store.relationals, ref, name, relationalState{}, true, h.p)
	case compute.KindKeyValueTable:
		putUnowned(h.p.store.tables, ref, name, compute.KeyValueSpec{Name: name}, true, h.p)
	default:
		return fmt.Errorf("fake: no substrate table for kind %q: %w", ref.Kind, compute.ErrInvalidSpec)
	}
	return nil
}

func putUnowned[S any](table map[string]*record[S], ref compute.Ref, name string, spec S, async bool, p *Provider) {
	rec := &record[S]{
		ref:       ref,
		name:      name,
		spec:      spec,
		owned:     false,
		revision:  revisionOf(spec),
		updatedAt: p.store.now(),
	}
	if async {
		rec.async = &asyncState{phase: compute.PhaseReady, toReady: 1}
	}
	table[ref.ID] = rec
}

// Read performs a data-plane read on resource as identity. It returns
// [ErrAccessDenied] when no grant covers it.
//
// This is what makes a grant testable as behaviour — "after AccessRead, a read
// succeeds and a write fails" — instead of by inspecting a policy document,
// which would only ever test one substrate's policy language.
func (h *Harness) Read(_ context.Context, resource compute.Ref, identity compute.Ref) error {
	return h.access(resource, identity, false)
}

// Write performs a data-plane write on resource as identity.
func (h *Harness) Write(_ context.Context, resource compute.Ref, identity compute.Ref) error {
	return h.access(resource, identity, true)
}

func (h *Harness) access(resource compute.Ref, identity compute.Ref, write bool) error {
	if resource.Provider != h.p.cfg.Name || identity.Provider != h.p.cfg.Name {
		return fmt.Errorf("fake: %s or %s: %w", resource, identity, compute.ErrForeignRef)
	}
	if identity.Kind != compute.KindWorkloadIdentity {
		return fmt.Errorf("fake: %s is not a workload identity: %w", identity, compute.ErrInvalidSpec)
	}
	if !h.exists(resource) {
		return fmt.Errorf("fake: no %s %s: %w", resource.Kind, resource, compute.ErrNotFound)
	}
	if !h.p.store.permits(resource.ID, identity.ID, write) {
		op := "read"
		if write {
			op = "write"
		}
		return fmt.Errorf("fake: %s cannot %s %s: %w", identity, op, resource, ErrAccessDenied)
	}

	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	switch resource.Kind {
	case compute.KindBucket:
		return dataPlane(h.p.store.objects, resource.ID, "conformance/probe", write)
	case compute.KindKeyValueTable:
		return dataPlane(h.p.store.items, resource.ID, "conformance-probe", write)
	default:
		// An image repository has no data plane in this fake; the grant check
		// above is the whole of the operation.
		return nil
	}
}

func dataPlane(store map[string]map[string][]byte, id, key string, write bool) error {
	bucket, ok := store[id]
	if !ok {
		return fmt.Errorf("fake: %s has no data plane: %w", id, compute.ErrNotFound)
	}
	if write {
		bucket[key] = []byte("probe")
		return nil
	}
	if _, ok := bucket[key]; !ok {
		// A read of an absent object is still an authorised read: the grant
		// check is what the suite is asking about, not whether data exists.
		return nil
	}
	return nil
}

func (h *Harness) exists(ref compute.Ref) bool {
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	switch ref.Kind {
	case compute.KindBucket:
		_, ok := h.p.store.buckets[ref.ID]
		return ok
	case compute.KindKeyValueTable:
		rec, ok := h.p.store.tables[ref.ID]
		return ok && !rec.async.deleted
	case compute.KindImageRepository:
		_, ok := h.p.store.repos[ref.ID]
		return ok
	default:
		return false
	}
}

// AnonymousRead attempts an unauthenticated read of a bucket. It must fail for a
// bucket created with PublicAccess false.
func (h *Harness) AnonymousRead(_ context.Context, bucket compute.Ref) error {
	if bucket.Provider != h.p.cfg.Name {
		return fmt.Errorf("fake: %s: %w", bucket, compute.ErrForeignRef)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	rec, ok := h.p.store.buckets[bucket.ID]
	if !ok {
		return fmt.Errorf("fake: no bucket %s: %w", bucket, compute.ErrNotFound)
	}
	if rec.spec.PublicAccess || h.p.broken(DefectPublicByDefault) {
		return nil
	}
	return fmt.Errorf("fake: anonymous read of %s: %w", bucket, ErrAccessDenied)
}

// Login authenticates against a relational endpoint. It is the hook behind the
// invariant that a re-Ensure must not rotate the admin password: the caller's
// stored copy has to keep working.
func (h *Harness) Login(_ context.Context, ref compute.Ref, username string, password compute.SecretValue) error {
	rec, err := lookup(h.p, h.p.store.relationals, ref, compute.KindRelational)
	if err != nil {
		return err
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	if rec.spec.Spec.AdminUsername != username || rec.spec.AdminDigest != digest(password) {
		// The message names neither the expected user nor anything derived from
		// the password: an authentication failure that says which half was wrong
		// is an oracle.
		return fmt.Errorf("fake: authentication failed for %s: %w", ref, ErrAccessDenied)
	}
	return nil
}

// CanExecInto reports whether a workload identity is able to open an interactive
// session against a workload.
//
// The correct answer is always no, and that is the point. Exec authorises the
// *operator's* principal; making a workload reachable must not grant the
// workload's own identity anything. The first draft of the interface modelled
// exec as a workload capability, which on Kubernetes would have let a workload
// exec into pods while still leaving operators unable to exec into the workload.
func (h *Harness) CanExecInto(_ context.Context, identity compute.Ref, target compute.Ref) (bool, error) {
	if identity.Provider != h.p.cfg.Name || target.Provider != h.p.cfg.Name {
		return false, fmt.Errorf("fake: %s or %s: %w", identity, target, compute.ErrForeignRef)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	if _, ok := h.p.store.identities[identity.ID]; !ok {
		return false, fmt.Errorf("fake: no workload identity %s: %w", identity, compute.ErrNotFound)
	}
	rec, ok := h.p.store.services[target.ID]
	if !ok {
		return false, fmt.Errorf("fake: no service %s: %w", target, compute.ErrNotFound)
	}
	if h.p.broken(DefectExecWidensIdentity) {
		return rec.spec.ExecEnabled, nil
	}
	return false, nil
}

// ExternalGrants returns every cross-domain grant standing on resource, keyed by
// principal identifier, as an independent copy of the stored record.
//
// # Why this exists
//
// [ext.ExternalAccessGranter.GrantExternal] must refuse a principal with no
// constraints **without mutating anything** -- an error return that also changes a
// grant is a worse contract than either half. Nothing could assert that, because
// nothing outside this package could see whether a grant survived a refused call:
// the compute interface deliberately offers no read-back for an external grant,
// which is the same reason every other method on this type exists.
//
// An unobservable contract is an unasserted contract.
//
// # Why the value is the record and not a rendering
//
// It was a %+v rendering, on the argument that a rendering covers a field added
// later without anybody remembering. The argument was right and the
// implementation was not: **%+v joins a []string with spaces, so a constraint
// containing a space is indistinguishable from two constraints.**
//
//	["tenant one"]      renders  [tenant one]
//	["tenant", "one"]   renders  [tenant one]      <- identical
//
// A mutation that split one constraint into two passed the comparison. And these
// are opaque caller-supplied strings, so whitespace is legal input rather than a
// pathological case.
//
// Quoting the elements would not fix it. A renderer whose losslessness depends on
// the data not containing its delimiter is the same defect with a longer
// delimiter -- the collision moves, it does not close. **The evidence and the
// comparison were the same artefact, so any two states the renderer conflated
// were equal by construction.**
//
// So the value is the record itself, compared structurally with
// [reflect.DeepEqual]. That keeps the property the rendering was chosen for -- a
// field added later is included with nothing named -- and cannot collide, because
// DeepEqual compares a slice's length and its elements rather than their
// concatenation.
//
// # The copy is deep, and that is load-bearing
//
// A snapshot sharing a slice with the live store is not a snapshot: an in-place
// mutation would change the "before" as well, and the comparison would pass for
// the same reason a snapshot taken before the setup does. See
// [copyExternalGrant].
//
// # It distinguishes "nothing there" from "I could not look"
//
// A resolve failure is an error, not an empty map. Those two answers are
// identical under len and range, and a test that cannot tell them apart passes
// when it is silently addressing the wrong resource. internal/reachable takes the
// same disposition.
func (h *Harness) ExternalGrants(resource compute.Ref) (map[string]any, error) {
	id, err := h.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return nil, fmt.Errorf("fake: ExternalGrants could not resolve %s: %w", resource, err)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	out := map[string]any{}
	for key, grant := range h.p.store.external {
		if key.resource != id {
			continue
		}
		out[key.subject] = copyExternalGrant(grant)
	}
	return out, nil
}

// CreateUnownedExternalGrant plants a cross-domain grant this platform did not
// create, on a bucket it did.
//
// It is the hook behind the ownership half of the external-grant contract, and it
// exists because that half was previously unreachable. Both
// [ext.ExternalAccessGranter.GrantExternal] and RevokeExternal must refuse a
// grant they did not create, with [compute.ErrNotOwned], and this package had no
// way to produce one -- so both refusals were branches nothing could enter. A
// guard that cannot be exercised is a guard nobody has checked.
//
// [Harness.CreateUnowned] cannot serve. It plants an unowned RESOURCE, and this
// is an unowned EDGE on a resource that is ours: the collision the contract warns
// about is a stranger's trust statement landing on a bucket whose name this
// platform derived from a mutable application name, which is not the same event
// as the bucket itself being somebody else's.
//
// The constraint is present and arbitrary. A foreign grant is not this platform's
// to describe beyond what it can see, but an EMPTY constraint list would make the
// fixture indistinguishable from the unconstrained grant GrantExternal refuses to
// create -- so a test could not tell "refused because foreign" from "refused
// because unconstrained".
func (h *Harness) CreateUnownedExternalGrant(resource compute.Ref, principalID string) error {
	id, err := h.p.resolve(resource, compute.KindBucket)
	if err != nil {
		return fmt.Errorf("fake: CreateUnownedExternalGrant could not resolve %s: %w", resource, err)
	}
	if principalID == "" {
		return fmt.Errorf("fake: an external principal needs an identifier: %w", compute.ErrInvalidSpec)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	if _, ok := h.p.store.buckets[id]; !ok {
		return fmt.Errorf("fake: no bucket %s: %w", resource, compute.ErrNotFound)
	}
	h.p.store.external[grantKey{resource: id, subject: principalID}] = externalGrant{
		level:       compute.AccessRead,
		constraints: []string{"a-stranger-s-correlation-value"},
		owned:       false,
	}
	return nil
}

// copyExternalGrant returns a grant that shares nothing with the stored one.
//
// Every reference-typed field has to be copied here or a snapshot aliases live
// state. TestTheExternalGrantCopyHandlesEveryReferenceField derives the field set
// and fails if one is added that this function does not name, so the obligation is
// enforced rather than remembered.
func copyExternalGrant(g externalGrant) externalGrant {
	out := g
	out.constraints = append([]string(nil), g.constraints...)
	return out
}

// ExternalGrantReferenceFields names the fields [copyExternalGrant] deep-copies.
//
// Exported so the check lives with the other assertions rather than inside the
// package it constrains. It is a list, deliberately and with a fatal default: the
// test below fails on a reference-typed field that is NOT here, so the list cannot
// silently fall behind the struct -- which is the only property that matters for a
// list.
func ExternalGrantReferenceFields() map[string]string {
	return map[string]string{
		"constraints": "copied with append in copyExternalGrant",
	}
}

// Rendered returns everything this provider has rendered into its substrate:
// one entry per workload definition, in the shape the substrate stores.
//
// It is the hook behind the invariant that secret material never reaches a
// non-secret channel. A real provider's equivalent is its task definition, its
// pod spec, or its build log — the artefacts an operator, a support engineer, or
// an audit log can see. Secrets appear here only as references.
//
// It is an *enumeration*, and [RenderedRef] exists because an enumeration can
// be incomplete in a way an aggregate scan of it cannot detect: every render
// call below shares its logic with RenderedRef's per-kind lookup, so
// [DefectDropsRenderedArtefact] has to be honoured in exactly one place to
// affect both.
func (h *Harness) Rendered(context.Context) ([]string, error) {
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()

	var out []string
	for _, id := range keys(h.p.store.services) {
		out = append(out, h.renderService(h.p.store.services[id]))
	}
	for _, id := range keys(h.p.store.jobs) {
		out = append(out, h.renderJob(h.p.store.jobs[id]))
	}
	for _, id := range keys(h.p.store.functions) {
		out = append(out, h.renderFunction(h.p.store.functions[id]))
	}
	for _, id := range keys(h.p.store.endpoints) {
		out = append(out, h.renderEndpoint(h.p.store.endpoints[id]))
	}
	for _, id := range keys(h.p.store.relationals) {
		out = append(out, h.renderRelational(h.p.store.relationals[id]))
	}
	for _, id := range keys(h.p.store.repos) {
		out = append(out, h.renderRepository(h.p.store.repos[id]))
	}
	for _, id := range keys(h.p.store.buckets) {
		out = append(out, h.renderBucket(h.p.store.buckets[id]))
	}
	for _, id := range keys(h.p.store.tables) {
		out = append(out, h.renderKeyValue(h.p.store.tables[id]))
	}
	for _, id := range keys(h.p.store.secrets) {
		// DefectDropsRenderedArtefact is the PARTIAL emptying
		// checkEveryPlantedResourceIsRendered exists to catch (USOSS-48): every
		// other kind above still renders, only the secret store's own listing
		// silently disappears from the enumeration.
		if h.p.broken(DefectDropsRenderedArtefact) {
			continue
		}
		out = append(out, h.renderSecret(h.p.store.secrets[id]))
	}
	for _, id := range keys(h.p.store.identities) {
		out = append(out, h.renderIdentity(h.p.store.identities[id]))
	}
	return out, nil
}

// RenderedRef returns the rendered artefact for one resource by reference, so
// a check can verify per-resource correspondence rather than trusting
// [Rendered]'s enumeration to be complete (USOSS-48).
//
// It shares its per-kind rendering with Rendered rather than re-deriving it,
// so the two can never disagree about what one record renders as — and it
// shares [DefectDropsRenderedArtefact]'s check for the same reason: a
// provider that answered found=true here for a Ref it silently drops from
// Rendered would defeat the property this hook exists to let a check observe.
func (h *Harness) RenderedRef(_ context.Context, ref compute.Ref) (string, bool, error) {
	if ref.Provider != h.p.cfg.Name {
		return "", false, fmt.Errorf("fake: %s: %w", ref, compute.ErrForeignRef)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()

	switch ref.Kind {
	case compute.KindService:
		rec, ok := h.p.store.services[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderService(rec), true, nil
	case compute.KindScheduledJob:
		rec, ok := h.p.store.jobs[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderJob(rec), true, nil
	case compute.KindFunction:
		rec, ok := h.p.store.functions[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderFunction(rec), true, nil
	case compute.KindFunctionEndpoint:
		rec, ok := h.p.store.endpoints[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderEndpoint(rec), true, nil
	case compute.KindRelational:
		rec, ok := h.p.store.relationals[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderRelational(rec), true, nil
	case compute.KindImageRepository:
		rec, ok := h.p.store.repos[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderRepository(rec), true, nil
	case compute.KindBucket:
		rec, ok := h.p.store.buckets[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderBucket(rec), true, nil
	case compute.KindKeyValueTable:
		rec, ok := h.p.store.tables[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderKeyValue(rec), true, nil
	case compute.KindSecret:
		rec, ok := h.p.store.secrets[ref.ID]
		if !ok || h.p.broken(DefectDropsRenderedArtefact) {
			return "", false, nil
		}
		return h.renderSecret(rec), true, nil
	case compute.KindWorkloadIdentity:
		rec, ok := h.p.store.identities[ref.ID]
		if !ok {
			return "", false, nil
		}
		return h.renderIdentity(rec), true, nil
	default:
		return "", false, fmt.Errorf("fake: %s: unrecognised kind", ref)
	}
}

func (h *Harness) renderService(rec *record[compute.ServiceSpec]) string {
	s := rec.spec
	return fmt.Sprintf("service %s: image=%s placement=%s cpu=%dm memory=%dMiB replicas=%d "+
		"exec=%t identity=%s capabilities=%v ports=%s env=%s secrets=%s ingress=%s routes=%s labels=%s",
		rec.name, s.Image, s.Placement.Name, s.Resources.CPUMillicores, s.Resources.MemoryMiB,
		s.Replicas, s.ExecEnabled, s.Identity.ID, s.Capabilities, renderPorts(s.Ports),
		renderEnv(s.Env), h.renderSecrets(s.Secrets), renderIngress(s.Ingress),
		renderRoutes(s.Routes), renderLabels(s.Labels))
}

func (h *Harness) renderJob(rec *record[compute.ScheduledJobSpec]) string {
	s := rec.spec
	return fmt.Sprintf("scheduled-job %s: image=%s schedule=%q timezone=%s paused=%t placement=%s "+
		"identity=%s env=%s secrets=%s ingress=%s labels=%s",
		rec.name, s.Image, s.Schedule.Expression, s.Schedule.Timezone, s.Schedule.Paused,
		s.Placement.Name, s.Identity.ID, renderEnv(s.Env), h.renderSecrets(s.Secrets),
		renderIngress(s.Ingress), renderLabels(s.Labels))
}

func (h *Harness) renderFunction(rec *record[compute.FunctionSpec]) string {
	s := rec.spec
	return fmt.Sprintf("function %s: runtime=%s handler=%s arch=%s memory=%dMiB timeout=%s "+
		"placement=%s identity=%s capabilities=%v env=%s secrets=%s labels=%s bundle-bytes=%d",
		rec.name, s.Runtime, s.Handler, s.Architecture, s.Resources.MemoryMiB, s.Timeout, s.Placement.Name,
		s.Identity.ID, s.Capabilities, renderEnv(s.Env), h.renderSecrets(s.Secrets),
		renderLabels(s.Labels), len(s.Code.Inline))
}

func (h *Harness) renderEndpoint(rec *record[compute.EndpointSpec]) string {
	var listeners []string
	for _, l := range rec.spec.Listeners {
		if l.TLS == nil {
			listeners = append(listeners, fmt.Sprintf("%d/plaintext", l.Port))
			continue
		}
		// A TLS listener names its certificate. A rendered listener with
		// tls=yes and an empty certificate is the source system's defect, and
		// printing it is what lets the suite see it.
		listeners = append(listeners, fmt.Sprintf("%d/tls certificate=%q", l.Port, l.TLS.CertificateRef))
	}
	return fmt.Sprintf("function-endpoint %s: target=%s placement=%s listeners=[%s] ingress=%s labels=%s",
		rec.name, rec.spec.Target.ID, rec.spec.Placement.Name, strings.Join(listeners, " "),
		renderIngress(rec.spec.Ingress), renderLabels(rec.spec.Labels))
}

func (h *Harness) renderRelational(rec *record[relationalState]) string {
	s := rec.spec.Spec
	return fmt.Sprintf("relational %s: engine=%s/%s database=%s admin=%s "+
		"capacity=%v-%v placement=%s ingress=%s",
		rec.name, s.Engine, s.EngineVersion, s.DatabaseName,
		s.AdminUsername, s.Capacity.MinUnits, s.Capacity.MaxUnits,
		s.Placement.Name, renderIngress(s.Ingress))
}

func (h *Harness) renderRepository(rec *record[compute.RepositorySpec]) string {
	s := rec.spec
	return fmt.Sprintf("image-repository %s: keep-last=%d max-age=%s scan-on-push=%t labels=%s",
		rec.name, s.Retention.KeepLast, s.Retention.MaxAge, s.ScanOnPush, renderLabels(s.Labels))
}

func (h *Harness) renderBucket(rec *record[compute.BucketSpec]) string {
	s := rec.spec
	return fmt.Sprintf("bucket %s: class=%s zone=%s public=%t labels=%s",
		rec.name, s.Class, s.Zone, s.PublicAccess, renderLabels(s.Labels))
}

func (h *Harness) renderKeyValue(rec *record[compute.KeyValueSpec]) string {
	s := rec.spec
	return fmt.Sprintf("key-value %s: partition=%s sort=%s placement=%s labels=%s",
		rec.name, s.PartitionKey, s.SortKey, s.Placement.Name, renderLabels(s.Labels))
}

// renderSecret is a secret store's own listing entry, which names a secret
// rather than printing it -- unless [DefectSecretValueInStoreListing] is set,
// the leak a provider whose only material-carrying port is its secret store
// can have.
func (h *Harness) renderSecret(rec *record[compute.SecretSpec]) string {
	s := rec.spec
	if h.p.broken(DefectSecretValueInStoreListing) {
		return fmt.Sprintf("secret %s: scope=%s value=%s labels=%s",
			s.Name, s.Scope, compute.RevealSecret(s.Value), renderLabels(s.Labels))
	}
	return fmt.Sprintf("secret %s: scope=%s labels=%s", s.Name, s.Scope, renderLabels(s.Labels))
}

func (h *Harness) renderIdentity(rec *record[compute.WorkloadIdentitySpec]) string {
	s := rec.spec
	return fmt.Sprintf("identity %s: runs-on=%s labels=%s", rec.name, s.RunsOn, renderLabels(s.Labels))
}

// renderSecrets prints bindings by reference. A provider that resolved a value
// into a workload definition would put every application secret through its own
// memory and into an artefact anyone with read access to the substrate can see.
func (h *Harness) renderSecrets(bindings []compute.SecretBinding) string {
	var parts []string
	for _, b := range bindings {
		if h.p.broken(DefectSecretInRendered) {
			rec, ok := h.p.store.secrets[b.Secret.ID]
			if ok {
				parts = append(parts, b.EnvName+"="+compute.RevealSecret(rec.spec.Value))
				continue
			}
		}
		// The reference, and the revision it is pinned to when it is pinned. The
		// version is here so that "the pin was honoured" is observable above the
		// interface at all: a binding is resolved by the runtime at launch, so
		// the rendered specification is the only place a caller — or the
		// conformance suite — can see which revision a workload was wired to.
		rendered := b.EnvName + "->" + b.Secret.String()
		if b.Version != "" && !h.p.broken(DefectIgnoresSecretVersion) {
			rendered += "@" + b.Version
		}
		parts = append(parts, rendered)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func renderEnv(env []compute.EnvVar) string {
	parts := make([]string, 0, len(env))
	for _, e := range env {
		parts = append(parts, e.Name+"="+e.Value)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func renderPorts(ports []compute.PortSpec) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d/%s", p.Number, orTCP(p.Protocol)))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func renderIngress(rules []compute.IngressRule) string {
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		peer := string(r.From.Kind)
		if r.From.Kind == compute.PeerWorkload {
			peer += "(" + r.From.Workload.ID + ")"
		}
		parts = append(parts, fmt.Sprintf("%s->%d/%s", peer, r.Port, orTCP(r.Protocol)))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func renderRoutes(routes []compute.Route) string {
	parts := make([]string, 0, len(routes))
	for _, r := range routes {
		parts = append(parts, fmt.Sprintf("%s->%d auth=%t paths=%v public=%v",
			r.Host, r.TargetPort, r.RequireAuth, r.PathPrefixes, r.PublicPaths))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func renderLabels(labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}

func orTCP(p compute.Protocol) compute.Protocol {
	if p == "" {
		return compute.ProtocolTCP
	}
	return p
}

// --- failure injection -----------------------------------------------------

// Op names a provider operation for [Harness.FailNext].
//
// The source system's own tests inject AWS-shaped errors into narrow per-call
// interfaces — a fake IAM client that can be told to fail GetRole, a smithy
// APIError with a chosen code (bucket_c1_role_test.go, build_container_port_test.go).
// Those fakes do not port, because they mock AWS API calls rather than the need
// behind them, but the capability does: nothing here is transactional, so a
// deploy that provisions a bucket, a database, and a service can fail in the
// middle and leave two of the three, and the only way to test that path is to
// make one call fail on purpose.
type Op string

// The operations a failure can be injected into. They cover the shared paths
// every port routes through; a provider method that does something unusual is
// not interceptable and the test has to arrange its failure another way.
const (
	// OpEnsure is any Ensure or Put, checked before the resource is touched.
	OpEnsure Op = "ensure"
	// OpDescribe is any read-back, including a secret Get.
	OpDescribe Op = "describe"
	// OpDelete is any delete.
	OpDelete Op = "delete"
	// OpGrant is [compute.Granter.Grant].
	OpGrant Op = "grant"
	// OpRevoke is [compute.Granter.Revoke].
	OpRevoke Op = "revoke"
	// OpBuild is [compute.ImageBuilder.Build].
	//
	// Added by USOSS-39, because the builder consulted no injection point at
	// all: FailNext could not reach it and its substrate-error mapping was
	// untestable. That is the third instance of one shape in this package — a
	// path that does not route through the shared body and therefore skips the
	// gate — after identityService.DeleteWorkloadIdentity and, in compute/k8s,
	// every delete.
	OpBuild Op = "build"
)

type failureKey struct {
	op   Op
	kind compute.Kind
}

// FailNext makes the next matching operation return err, once.
//
// Errors are queued, so two calls to FailNext with the same op and kind fail the
// next two operations in order. An injected error is returned before the
// operation touches any state, which is what makes it usable for testing a
// half-finished deploy: the resources ensured before the failure exist and the
// ones after it do not.
//
// Wrap a [compute] sentinel in err when the caller under test branches on one.
func (h *Harness) FailNext(op Op, kind compute.Kind, err error) {
	if err == nil {
		panic("fake: FailNext needs an error; injecting nil would assert nothing")
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	if h.p.store.failures == nil {
		h.p.store.failures = map[failureKey][]error{}
	}
	key := failureKey{op: op, kind: kind}
	h.p.store.failures[key] = append(h.p.store.failures[key], err)
}

// FailEvery makes every intercepted operation return err until the returned
// function is called.
//
// [Harness.FailNext] queues one error per operation and kind, which is the right
// shape for testing a half-finished deploy. It is the wrong shape for the
// conformance suite's retry gate: that drives every method of every port,
// because the mapping from a substrate's errors onto the compute taxonomy is
// written per service and a provider can get its registry right and its identity
// service wrong. A hook that armed a single call would leave every other mapping
// unexercised while the gate went green.
//
// Wrap a [compute] sentinel in err, as FailNext's callers do.
func (h *Harness) FailEvery(err error) func() {
	if err == nil {
		panic("fake: FailEvery needs an error; injecting nil would assert nothing")
	}
	armed := &stickyFailure{err: err}
	h.p.store.mu.Lock()
	h.p.store.sticky = armed
	h.p.store.mu.Unlock()
	return func() {
		h.p.store.mu.Lock()
		defer h.p.store.mu.Unlock()
		if h.p.store.sticky == armed {
			h.p.store.sticky = nil
		}
	}
}

// PendingFailures reports how many injected failures have not been consumed. A
// test that injected one and finished with it unconsumed did not exercise the
// path it thought it did.
func (h *Harness) PendingFailures() int {
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	n := 0
	for _, errs := range h.p.store.failures {
		n += len(errs)
	}
	return n
}

// injected pops an injected failure for op and kind, if one is queued, or
// returns the sticky one armed by [Harness.FailEvery].
func (p *Provider) injected(op Op, kind compute.Kind) error {
	p.store.mu.Lock()
	key := failureKey{op: op, kind: kind}
	queue := p.store.failures[key]
	var err error
	switch {
	case len(queue) > 0:
		err = queue[0]
		if len(queue) == 1 {
			delete(p.store.failures, key)
		} else {
			p.store.failures[key] = queue[1:]
		}
	case p.store.sticky != nil:
		err = p.store.sticky.err
	}
	p.store.mu.Unlock()
	return p.classify(err)
}

// classify is the provider's substrate-error mapping, and the one place
// [DefectTransientIsTerminal] lives.
//
// A real provider maps its substrate's vocabulary onto the compute taxonomy in a
// switch with twenty arms, once per service; this stands in for that. Reporting
// a retryable failure as [compute.ErrFailed] is the conservative-in-the-wrong-
// direction mistake: ErrFailed is documented as not retryable without a spec
// change, so a caller that believes it abandons a deploy that would have worked.
func (p *Provider) classify(err error) error {
	if err == nil {
		return err
	}
	// Two defects, one choke point, guarded on the sentinel in the injected
	// error so they cannot mask each other: DefectTransientIsTerminal fires only
	// on ErrTransient and DefectDenialIsTerminal only on ErrNotPermitted. Both
	// collapse into ErrFailed, which is where each of those mappings was before
	// its sentinel existed.
	switch {
	case p.broken(DefectTransientIsTerminal) && errors.Is(err, compute.ErrTransient):
		return fmt.Errorf("fake: the substrate refused this call: %w", compute.ErrFailed)
	case p.broken(DefectDenialIsTerminal) && errors.Is(err, compute.ErrNotPermitted):
		// %v and not %w on the cause, deliberately: dropping the chain is the
		// defect. Wrapping would leave errors.Is(err, ErrNotPermitted) true, the
		// conformance check would pass, and a defect that wrapped would not be
		// one.
		//nolint:errorlint // Collapsing the chain is what this defect simulates.
		return fmt.Errorf("%w: fake: the substrate refused this call: %v", compute.ErrFailed, err)
	}
	return err
}

// BuildCredentials reports the material this provider's builds are given.
//
// A real provider mints a scoped, short-lived credential and never shows it to
// the caller — that obligation is why [compute.ImageBuilder] has no
// MintPushCredentials method. So the only way to check that it appears in
// nothing a build emits is for the provider to report it to a test, which is
// what this is for.
func (h *Harness) BuildCredentials(context.Context) ([]string, error) {
	return []string{h.p.buildCredential()}, nil
}

// ImageMetadata reports the metadata this provider recorded for image, and
// whether a build recorded any.
//
// Nothing in [compute.BuildResult] exposes it, which is exactly the gap
// [compute.BuildRequest.BuildArgs] documents and this method exists to close:
// the suite reads it back to confirm that neither a caller's non-secret build
// arguments nor -- under [DefectBuildCredentialInImageMetadata] -- this
// provider's own push credential go unaccounted for.
func (h *Harness) ImageMetadata(image compute.ImageRef) (string, bool) {
	return h.p.store.ImageMetadata(image)
}

// BuildCacheDefaultMaxAge reports the age at which this provider expires a
// cached build layer when a caller leaves [compute.BuildCache.MaxAge] at
// zero. See [DefectBuildCacheDefaultIsForever].
func (h *Harness) BuildCacheDefaultMaxAge(context.Context) (time.Duration, error) {
	return h.p.buildCacheDefaultMaxAge(), nil
}

// ExternalGrantShape returns a zero stored grant, so a test can derive its field
// set with reflection.
//
// The precondition it exists to check has changed with the comparison. When
// [Harness.ExternalGrants] returned a %+v rendering, the requirement was that
// every field render deterministically. Now that it returns the record and the
// comparison is [reflect.DeepEqual], determinism is free -- DeepEqual handles maps
// -- and the live obligation is different: every reference-typed field must be
// deep-copied, or a snapshot aliases the store it is supposed to be independent
// of. Same reflection, different question.
func ExternalGrantShape() any { return externalGrant{} }

// The channels [Harness.EmitInto] can put a marker into.
//
// They are plain strings rather than the conformance suite's Channel type,
// because a provider must not depend on the suite that tests it: the caller maps
// its own vocabulary onto these. The set is closed, and an unknown channel is a
// refusal rather than a silent success — a hook that accepts a channel it does
// not implement is exactly the false declaration the marker mechanism exists to
// rule out.
const (
	ChannelBuildLog      = "build-log"
	ChannelBuildError    = "build-error"
	ChannelBuildResult   = "build-result"
	ChannelStatusMessage = "status-message"
	ChannelCallError     = "call-error"
	ChannelImageMetadata = "image-metadata"
)

// ErrChannelNotHostile reports that this provider cannot emit into a channel.
var ErrChannelNotHostile = errors.New("fake: no emission path for this channel")

// EmitInto makes this provider put marker into the named channel, until it is
// asked again.
//
// It is the hostile mode USOSS-61 requires. The point of a marker rather than a
// declaration is that the suite verifies the arrival by looking, so this cannot
// be satisfied by reporting success: the emission has to actually reach the
// channel the check reads.
func (h *Harness) EmitInto(_ context.Context, channel, marker string) error {
	switch channel {
	case ChannelBuildLog, ChannelBuildError, ChannelBuildResult, ChannelStatusMessage, ChannelCallError,
		ChannelImageMetadata:
	default:
		return fmt.Errorf("%w: %q", ErrChannelNotHostile, channel)
	}
	h.p.store.mu.Lock()
	defer h.p.store.mu.Unlock()
	if h.p.store.emissions == nil {
		h.p.store.emissions = map[string]string{}
	}
	// An empty marker clears. The suite clears between establishing a channel and
	// scanning it, because a persistent emission poisons the real run: an armed
	// build-error would make every later build fail and turn the material scan
	// into a skip.
	if marker == "" {
		delete(h.p.store.emissions, channel)
		return nil
	}
	h.p.store.emissions[channel] = marker
	return nil
}

// emission returns what a test asked this provider to emit into channel, as a
// string safe to append to whatever the channel carries. Empty when nothing was
// asked for, so the ordinary path is unchanged.
func (p *Provider) emission(channel string) string {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	if m := p.store.emissions[channel]; m != "" {
		return " " + m
	}
	return ""
}
