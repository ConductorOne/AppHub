// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"fmt"
	"time"

	"github.com/conductorone/apphub/compute"
)

// blockingEnsureDelay is how long a [DefectBlockingEnsure] provider spends inside
// Ensure. It is short enough that the suite's self-test stays fast and long
// enough that a small Options.EnsureBudget catches it.
const blockingEnsureDelay = 150 * time.Millisecond

// ensureRecord is the shared Ensure body: create the resource if it is absent,
// converge it onto spec if it is present, and refuse it if something this
// platform does not own already holds the name.
//
// merge, when non-nil, is applied to an existing record's spec before the new
// one replaces it. It exists only so [DefectCreateOrAdd] can be expressed:
// correct behaviour is to replace, and a provider that merges is the failure the
// convergence invariant hunts for.
func ensureRecord[S any](
	p *Provider,
	table map[string]*record[S],
	kind compute.Kind,
	name string,
	spec S,
	async bool,
	merge func(old, updated S) S,
) (*record[S], bool, error) {
	if err := p.injected(OpEnsure, kind); err != nil {
		return nil, false, err
	}
	ref := p.ref(kind, name)

	p.store.mu.Lock()
	defer p.store.mu.Unlock()

	existing, found := table[ref.ID]
	if found && !existing.owned {
		if !p.broken(DefectAdoptsUnowned) {
			return nil, false, fmt.Errorf(
				"fake: a %s named %q already exists and is not managed by this platform, so "+
					"reconciling it would mutate somebody else's infrastructure: %w",
				kind, name, compute.ErrNotOwned)
		}
		existing.owned = true
	}

	// A copy on the way in as well as on the way out. A caller that keeps its
	// spec and mutates a map in it must not be editing what the provider stored,
	// which is the same aliasing bug from the other direction.
	effective := deepCopy(spec)
	if found && merge != nil && p.broken(DefectCreateOrAdd) {
		effective = deepCopy(merge(existing.spec, spec))
	}

	if async && p.broken(DefectBlockingEnsure) {
		// Blocks inside Ensure until the resource is ready, which is what every
		// provisioning path in the source system does: up to ten minutes for an
		// Aurora cluster, inside a synchronous deploy request, with a hardcoded
		// timeout the caller cannot shorten.
		time.Sleep(blockingEnsureDelay)
	}

	if !found {
		rec := &record[S]{
			ref:       ref,
			name:      name,
			spec:      effective,
			owned:     true,
			revision:  revisionOf(effective),
			updatedAt: p.store.now(),
		}
		if async {
			rec.async = &asyncState{
				phase:   compute.PhasePending,
				toReady: p.cfg.ObservationsToReady,
				message: "accepted; converging",
			}
			if p.broken(DefectBlockingEnsure) {
				rec.async.phase = compute.PhaseReady
				rec.async.message = "waited inline until ready"
			}
		}
		table[ref.ID] = rec
		return rec, true, nil
	}

	existing.spec = effective
	existing.updatedAt = p.store.now()
	newRevision := revisionOf(effective)
	if newRevision != existing.revision {
		existing.revision = newRevision
		if existing.async != nil {
			// A configuration change restarts convergence, which is what makes
			// a redeploy observable as a rollout rather than a no-op.
			existing.async.phase = compute.PhasePending
			existing.async.observations = 0
			existing.async.deleted = false
			existing.async.message = "accepted; converging"
		}
	}
	if existing.async != nil && existing.async.deleted {
		// Re-ensuring after a delete recreates.
		existing.async.deleted = false
		existing.async.phase = compute.PhasePending
		existing.async.observations = 0
	}
	return existing, false, nil
}

// lookup finds a record by reference, validating the reference first.
func lookup[S any](p *Provider, table map[string]*record[S], ref compute.Ref, kind compute.Kind) (*record[S], error) {
	id, err := p.resolve(ref, kind)
	if err != nil {
		return nil, err
	}
	if err := p.injected(OpDescribe, kind); err != nil {
		return nil, err
	}
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	rec, ok := table[id]
	if !ok {
		return nil, fmt.Errorf("fake: no %s %s: %w", kind, ref, compute.ErrNotFound)
	}
	return rec, nil
}

// statusOf renders an asynchronous record's status, advancing its convergence by
// one observation. Describe is the observation: a fake that converged on a wall
// clock would make every test that waits either slow or flaky.
func statusOf[S any](p *Provider, rec *record[S]) compute.Status {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	phase := rec.async.observe()
	rec.updatedAt = p.store.now()
	message := rec.async.message
	if m := p.store.emissions[ChannelStatusMessage]; m != "" {
		message += " " + m
	}
	return compute.Status{
		Ref:       rec.ref,
		Phase:     phase,
		Message:   message,
		UpdatedAt: rec.updatedAt,
	}
}

// goneStatus is what Describe reports for an asynchronous resource that was
// never created or has been deleted. It is not an error: teardown and
// reconciliation must be re-runnable without distinguishing the two.
func goneStatus(ref compute.Ref) compute.Status {
	return compute.Status{
		Ref:       ref,
		Phase:     compute.PhaseGone,
		UpdatedAt: epoch,
	}
}

// describeAsync is the shared Describe body for an asynchronous port.
func describeAsync[S any](p *Provider, table map[string]*record[S], ref compute.Ref, kind compute.Kind) (*record[S], compute.Status, error) {
	id, err := p.resolve(ref, kind)
	if err != nil {
		return nil, compute.Status{}, err
	}
	if err := p.injected(OpDescribe, kind); err != nil {
		return nil, compute.Status{}, err
	}
	p.store.mu.Lock()
	rec, ok := table[id]
	p.store.mu.Unlock()
	if !ok {
		if p.broken(DefectDescribeErrorAfterDelete) {
			return nil, compute.Status{}, fmt.Errorf("fake: no %s %s: %w", kind, ref, compute.ErrNotFound)
		}
		return nil, goneStatus(ref), nil
	}
	if rec.async.deleted && p.broken(DefectDescribeErrorAfterDelete) {
		return nil, compute.Status{}, fmt.Errorf("fake: %s %s was deleted: %w", kind, ref, compute.ErrNotFound)
	}
	return rec, statusOf(p, rec), nil
}

// deleteAsync is the shared Delete body for an asynchronous port. Deleting an
// absent resource returns nil.
func deleteAsync[S any](p *Provider, table map[string]*record[S], ref compute.Ref, kind compute.Kind) error {
	id, err := p.resolve(ref, kind)
	if err != nil {
		return err
	}
	if err := p.injected(OpDelete, kind); err != nil {
		return err
	}
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	rec, ok := table[id]
	if !ok {
		if p.broken(DefectDeleteNotIdempotent) {
			return fmt.Errorf("fake: no %s %s to delete: %w", kind, ref, compute.ErrNotFound)
		}
		return nil
	}
	if rec.async.deleted && p.broken(DefectDeleteNotIdempotent) {
		return fmt.Errorf("fake: %s %s is already deleted: %w", kind, ref, compute.ErrNotFound)
	}
	rec.async.deleted = true
	rec.async.phase = compute.PhaseGone
	rec.updatedAt = p.store.now()
	p.revokeAllLocked(id)
	return nil
}

// deleteSync is the shared Delete body for a synchronous port.
func deleteSync[S any](p *Provider, table map[string]*record[S], ref compute.Ref, kind compute.Kind) error {
	id, err := p.resolve(ref, kind)
	if err != nil {
		return err
	}
	if err := p.injected(OpDelete, kind); err != nil {
		return err
	}
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	if _, ok := table[id]; !ok {
		if p.broken(DefectDeleteNotIdempotent) {
			return fmt.Errorf("fake: no %s %s to delete: %w", kind, ref, compute.ErrNotFound)
		}
		return nil
	}
	delete(table, id)
	p.revokeAllLocked(id)
	return nil
}

// revokeAllLocked drops every grant on a resource that is going away. Callers
// hold the store lock.
func (p *Provider) revokeAllLocked(resourceID string) {
	for k := range p.store.grants {
		if k.resource == resourceID {
			delete(p.store.grants, k)
		}
	}
	for k := range p.store.external {
		if k.resource == resourceID {
			delete(p.store.external, k)
		}
	}
	delete(p.store.objects, resourceID)
	delete(p.store.items, resourceID)
}
