// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"strconv"

	"github.com/conductorone/apphub/compute"
)

// secretStore implements [compute.SecretStore].
//
// A secret store is a synchronous port: Put returns a usable reference or an
// error, with no third state. The material lives in the record and is reachable
// only through Get; nothing else in this package reads it, which is the property
// the conformance suite's secret checks assert.
type secretStore struct{ p *Provider }

// Put implements [compute.SecretStore].
func (s secretStore) Put(_ context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	if err := s.p.validateName("secret", spec.Name); err != nil {
		// The scope is named because the name is the field being refused, so the
		// name cannot identify what failed. An error that identifies neither half
		// of a secret's identity is one a reader cannot place, and it is not
		// evidence for security/secret-material-does-not-appear-in-errors either:
		// that check searches this refusal for the value the spec carried, and a
		// refusal composed from none of the spec is clean either way.
		return compute.StoredSecret{}, fmt.Errorf("fake: in scope %q: %w", spec.Scope, err)
	}
	if spec.Scope == "" {
		if s.p.broken(DefectSecretInError) {
			return compute.StoredSecret{}, fmt.Errorf("fake: secret %q (value %q) has no scope: %w",
				spec.Name, compute.RevealSecret(spec.Value), compute.ErrInvalidSpec)
		}
		return compute.StoredSecret{}, fmt.Errorf("fake: secret %q has no scope, so teardown could "+
			"not enumerate it: %w", spec.Name, compute.ErrInvalidSpec)
	}
	for k, v := range spec.Labels {
		// Labels are expected to appear in listings and logs, so a provider that
		// let material in here would leak it through a channel the caller was
		// told was safe.
		if v == compute.RevealSecret(spec.Value) && compute.RevealSecret(spec.Value) != "" {
			return compute.StoredSecret{}, fmt.Errorf("fake: secret %q label %q repeats the secret "+
				"value: %w", spec.Name, k, compute.ErrInvalidSpec)
		}
	}

	placement, err := s.p.resolvePlacement(spec.Placement)
	if err != nil {
		return compute.StoredSecret{}, fmt.Errorf("fake: secret %q: %w", spec.Name, err)
	}
	effective := spec
	effective.Placement = compute.Placement{Name: placement}

	// The placement is part of the key for the same reason it is on the
	// identity: a secret belongs to one, and a binding across placements is
	// ErrInvalidSpec rather than something a provider quietly copies.
	rec, _, err := ensureRecord(s.p, s.p.store.secrets, compute.KindSecret,
		placement+"/"+spec.Scope+"/"+spec.Name, effective, false, nil)
	if err != nil {
		return compute.StoredSecret{}, err
	}
	return compute.StoredSecret{Ref: rec.ref, Version: s.recordRevision(rec.ref.ID, spec.Value)}, nil
}

// recordRevision appends value to a secret's history and returns the version
// that now names it.
//
// A repeat write of the same value returns the existing version rather than
// creating a new one, which matches what a versioned store does and matters for
// the idempotence invariant: two identical Puts must be indistinguishable, and a
// store that minted a revision per call would make a redeploy that changed
// nothing look like a rotation.
func (s secretStore) recordRevision(id string, value compute.SecretValue) string {
	s.p.store.mu.Lock()
	defer s.p.store.mu.Unlock()
	history := s.p.store.secretRevisions[id]
	if n := len(history); n > 0 && compute.RevealSecret(history[n-1]) == compute.RevealSecret(value) {
		return strconv.Itoa(n)
	}
	history = append(history, value)
	s.p.store.secretRevisions[id] = history
	return strconv.Itoa(len(history))
}

// Get implements [compute.SecretStore].
func (s secretStore) Get(_ context.Context, ref compute.Ref) (compute.SecretValue, error) {
	rec, err := lookup(s.p, s.p.store.secrets, ref, compute.KindSecret)
	if err != nil {
		return compute.SecretValue{}, err
	}
	s.p.store.mu.Lock()
	defer s.p.store.mu.Unlock()
	return rec.spec.Value, nil
}

// Describe implements [compute.SecretStore]. It returns the locator and the
// location and never the value.
func (s secretStore) Describe(_ context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	rec, err := lookup(s.p, s.p.store.secrets, ref, compute.KindSecret)
	if err != nil {
		return nil, err
	}
	s.p.store.mu.Lock()
	defer s.p.store.mu.Unlock()
	info := &compute.SecretInfo{
		Ref: rec.ref,
		// Scoped: this provider keys a secret by placement, so a workload
		// elsewhere genuinely cannot bind it.
		PlacementScope: compute.SecretPlacementScoped,
		Placement:      rec.spec.Placement,
	}
	if s.p.broken(DefectSecretValueInDescribe) {
		// A metadata read that returns the value through a field named for
		// something else. This is the whole reason Describe is permitted to
		// exist without being a read-back, so it is the defect the suite has to
		// be able to catch.
		info.Placement = compute.Placement{Name: compute.RevealSecret(rec.spec.Value)}
	}
	return info, nil
}

// Delete implements [compute.SecretStore].
func (s secretStore) Delete(_ context.Context, ref compute.Ref) error {
	return deleteSync(s.p, s.p.store.secrets, ref, compute.KindSecret)
}

// DeleteScope implements [compute.SecretStore].
func (s secretStore) DeleteScope(_ context.Context, scope string) error {
	if scope == "" {
		return fmt.Errorf("fake: DeleteScope needs a scope; an empty one would delete every "+
			"secret this provider holds: %w", compute.ErrInvalidSpec)
	}
	s.p.store.mu.Lock()
	defer s.p.store.mu.Unlock()
	for id, rec := range s.p.store.secrets {
		if rec.spec.Scope == scope {
			delete(s.p.store.secrets, id)
		}
	}
	return nil
}

var _ compute.SecretStore = secretStore{}
