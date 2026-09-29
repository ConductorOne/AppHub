// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// relationalState is what the substrate keeps for a relational endpoint.
//
// The password is kept as a salted digest rather than as material. A fake
// substrate has to be able to authenticate a login — that is the only way the
// "do not rotate the admin password" invariant can be checked behaviourally —
// but it does not have to retain the plaintext to do it, and retaining it would
// put material somewhere the interface says it must not be.
type relationalState struct {
	Spec compute.RelationalSpec
	// AdminDigest is excluded from the revision hash: a password is not part of
	// the effective configuration, and a provider must not rotate it.
	AdminDigest string `json:"-"`
}

// relationalProvisioner implements [compute.RelationalProvisioner].
//
// It has no [compute.Granter], and that absence is the design decision this port
// exists to demonstrate: access to a relational database is granted by creating
// a SQL role, which is ordinary SQL above this interface, and no substrate
// workload identity maps generically onto a SQL principal.
type relationalProvisioner struct{ p *Provider }

// defaultMaxUnits is this provider's capacity ceiling when a spec names none.
// It is finite on purpose: an unbounded default is a billing incident.
const defaultMaxUnits = 8.0

// EnsureRelational implements [compute.RelationalProvisioner].
func (r relationalProvisioner) EnsureRelational(_ context.Context, spec compute.RelationalSpec) (*compute.RelationalStatus, error) {
	if err := r.p.validateName("relational endpoint", spec.Name); err != nil {
		return nil, err
	}
	placement, err := r.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if err := r.validateEngine(spec); err != nil {
		if r.p.broken(DefectSecretInError) {
			// Interpolating the spec it could not satisfy is how a provider leaks
			// material: the password was never the reason the call failed.
			return nil, fmt.Errorf("fake: relational endpoint %q (admin password %q): %w",
				spec.Name, compute.RevealSecret(spec.AdminPassword), err)
		}
		return nil, fmt.Errorf("fake: relational endpoint %q: %w", spec.Name, err)
	}
	if spec.DatabaseName == "" || spec.AdminUsername == "" {
		return nil, fmt.Errorf("fake: relational endpoint %q needs a database name and an admin "+
			"username: %w", spec.Name, compute.ErrInvalidSpec)
	}
	if spec.AdminPassword.IsZero() {
		if r.p.broken(DefectSecretInError) {
			return nil, fmt.Errorf("fake: relational endpoint %q: empty admin password %q: %w",
				spec.Name, compute.RevealSecret(spec.AdminPassword), compute.ErrInvalidSpec)
		}
		return nil, fmt.Errorf("fake: relational endpoint %q has no admin password: %w",
			spec.Name, compute.ErrInvalidSpec)
	}
	capacity, err := normaliseCapacity(spec.Capacity)
	if err != nil {
		return nil, fmt.Errorf("fake: relational endpoint %q: %w", spec.Name, err)
	}
	if err := r.p.validateIngress(spec.Ingress); err != nil {
		return nil, fmt.Errorf("fake: relational endpoint %q: %w", spec.Name, err)
	}

	effective := spec
	effective.Capacity = capacity
	effective.Placement = compute.Placement{Name: placement}
	// The provider is handed the password to create the endpoint with and must
	// not retain it. What is retained is a digest, which cannot be handed back.
	effective.AdminPassword = compute.SecretValue{}

	state := relationalState{Spec: effective, AdminDigest: digest(spec.AdminPassword)}

	ref := r.p.ref(compute.KindRelational, spec.Name)
	r.p.store.mu.Lock()
	existing, found := r.p.store.relationals[ref.ID]
	r.p.store.mu.Unlock()
	if found && existing.owned {
		// Never rotate the admin password on a re-Ensure. The caller's stored
		// copy would silently become wrong and the next deploy's role
		// provisioning would fail with an authentication error far from the
		// change that caused it. The source system guards this by checking for
		// an existing cluster before generating a password at all
		// (container.go:288-300).
		if !r.p.broken(DefectRotatesAdminPassword) {
			state.AdminDigest = existing.spec.AdminDigest
		}
		if r.p.broken(DefectSubstitutesImmutableField) {
			// Converge what is easy and quietly keep the rest. The call still
			// reports success, so the caller reads an effective spec that is not
			// the spec it sent.
			state.Spec.DatabaseName = existing.spec.Spec.DatabaseName
			state.Spec.AdminUsername = existing.spec.Spec.AdminUsername
		}
	}

	rec, _, err := ensureRecord(r.p, r.p.store.relationals, compute.KindRelational, spec.Name, state, true, nil)
	if err != nil {
		return nil, err
	}
	return r.status(rec, statusOf(r.p, rec)), nil
}

func (r relationalProvisioner) validateEngine(spec compute.RelationalSpec) error {
	versions, ok := r.p.cfg.EngineVersions[spec.Engine]
	if !ok {
		have := make([]string, 0, len(r.p.cfg.EngineVersions))
		for e := range r.p.cfg.EngineVersions {
			have = append(have, string(e))
		}
		return fmt.Errorf("engine %q is not one this provider offers (have %s): %w",
			spec.Engine, strings.Join(have, ", "), compute.ErrInvalidSpec)
	}
	if spec.EngineVersion == "" {
		return fmt.Errorf("no engine version named; this provider offers %s: %w",
			strings.Join(versions, ", "), compute.ErrInvalidSpec)
	}
	for _, v := range versions {
		if v == spec.EngineVersion {
			return nil
		}
	}
	// Substituting a version the caller did not ask for is not an option: the
	// major version is pinned deliberately and a different one may not run the
	// application's schema.
	return fmt.Errorf("engine version %q is not one this provider offers (have %s): %w",
		spec.EngineVersion, strings.Join(versions, ", "), compute.ErrInvalidSpec)
}

func normaliseCapacity(c compute.CapacityRange) (compute.CapacityRange, error) {
	if c.MinUnits < 0 || c.MaxUnits < 0 {
		return c, fmt.Errorf("capacity range %v-%v is negative: %w", c.MinUnits, c.MaxUnits, compute.ErrInvalidSpec)
	}
	out := c
	if out.MaxUnits == 0 {
		out.MaxUnits = defaultMaxUnits
	}
	if out.MinUnits > out.MaxUnits {
		return c, fmt.Errorf("capacity floor %v exceeds ceiling %v: %w",
			out.MinUnits, out.MaxUnits, compute.ErrInvalidSpec)
	}
	return out, nil
}

// DescribeRelational implements [compute.RelationalProvisioner].
func (r relationalProvisioner) DescribeRelational(_ context.Context, ref compute.Ref) (*compute.RelationalStatus, error) {
	rec, st, err := describeAsync(r.p, r.p.store.relationals, ref, compute.KindRelational)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &compute.RelationalStatus{Status: st}, nil
	}
	return r.status(rec, st), nil
}

// WaitForRelational implements [compute.RelationalProvisioner].
func (r relationalProvisioner) WaitForRelational(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.RelationalStatus, error) {
	var out *compute.RelationalStatus
	_, err := waitFor(ctx, r.p, "relational endpoint", ref, opts,
		func() (compute.Status, error) {
			st, err := r.DescribeRelational(ctx, ref)
			if err != nil {
				return compute.Status{}, err
			}
			out = st
			return st.Status, nil
		},
		func(st compute.Status) bool { return st.Phase == compute.PhaseReady },
	)
	return out, err
}

// DeleteRelational implements [compute.RelationalProvisioner].
func (r relationalProvisioner) DeleteRelational(_ context.Context, ref compute.Ref) error {
	return deleteAsync(r.p, r.p.store.relationals, ref, compute.KindRelational)
}

func (r relationalProvisioner) status(rec *record[relationalState], st compute.Status) *compute.RelationalStatus {
	r.p.store.mu.Lock()
	defer r.p.store.mu.Unlock()
	// The admin password is zeroed: a read-back that handed material back would
	// defeat the point of never letting a caller read one.
	effective := deepCopy(rec.spec.Spec)
	effective.AdminPassword = compute.SecretValue{}
	out := &compute.RelationalStatus{Status: st, Spec: effective}
	if st.Phase == compute.PhaseReady {
		// The endpoint is populated once ready; before that the host may be
		// empty, which is what the interface says and what a caller must handle.
		out.Endpoint = compute.SQLEndpoint{
			Host:         rec.name + ".db." + r.p.cfg.Name + ".invalid",
			Port:         5432,
			DatabaseName: rec.spec.Spec.DatabaseName,
			RequireTLS:   true,
		}
	}
	return out
}

var _ compute.RelationalProvisioner = relationalProvisioner{}

// digest is how the fake substrate remembers a password without holding it.
func digest(v compute.SecretValue) string {
	// A fixed salt is enough here: this is a fake substrate's password check,
	// not a credential store, and the digest never leaves the process.
	sum := sha256.Sum256([]byte("fake-relational-v1:" + compute.RevealSecret(v)))
	return hex.EncodeToString(sum[:])
}

// keyValueProvisioner implements [compute.KeyValueProvisioner].
//
// It does embed [compute.Granter], because this kind of store authorises by
// substrate identity and has no notion of a database-internal principal.
type keyValueProvisioner struct{ p *Provider }

// EnsureKeyValueTable implements [compute.KeyValueProvisioner].
func (k keyValueProvisioner) EnsureKeyValueTable(_ context.Context, spec compute.KeyValueSpec) (*compute.KeyValueStatus, error) {
	if err := k.p.validateName("key-value table", spec.Name); err != nil {
		return nil, err
	}
	placement, err := k.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if spec.PartitionKey == "" {
		return nil, fmt.Errorf("fake: key-value table %q has no partition key: %w",
			spec.Name, compute.ErrInvalidSpec)
	}
	if spec.SortKey != "" && spec.SortKey == spec.PartitionKey {
		return nil, fmt.Errorf("fake: key-value table %q uses %q as both partition and sort key: %w",
			spec.Name, spec.SortKey, compute.ErrInvalidSpec)
	}

	effective := spec
	effective.Placement = compute.Placement{Name: placement}

	rec, _, err := ensureRecord(k.p, k.p.store.tables, compute.KindKeyValueTable, spec.Name, effective, true, nil)
	if err != nil {
		return nil, err
	}
	k.p.store.mu.Lock()
	if _, ok := k.p.store.items[rec.ref.ID]; !ok {
		k.p.store.items[rec.ref.ID] = map[string][]byte{}
	}
	k.p.store.mu.Unlock()
	return k.status(rec, statusOf(k.p, rec)), nil
}

// DescribeKeyValueTable implements [compute.KeyValueProvisioner].
func (k keyValueProvisioner) DescribeKeyValueTable(_ context.Context, ref compute.Ref) (*compute.KeyValueStatus, error) {
	rec, st, err := describeAsync(k.p, k.p.store.tables, ref, compute.KindKeyValueTable)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &compute.KeyValueStatus{Status: st}, nil
	}
	return k.status(rec, st), nil
}

// WaitForKeyValueTable implements [compute.KeyValueProvisioner].
func (k keyValueProvisioner) WaitForKeyValueTable(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.KeyValueStatus, error) {
	var out *compute.KeyValueStatus
	_, err := waitFor(ctx, k.p, "key-value table", ref, opts,
		func() (compute.Status, error) {
			st, err := k.DescribeKeyValueTable(ctx, ref)
			if err != nil {
				return compute.Status{}, err
			}
			out = st
			return st.Status, nil
		},
		func(st compute.Status) bool { return st.Phase == compute.PhaseReady },
	)
	return out, err
}

// DeleteKeyValueTable implements [compute.KeyValueProvisioner].
func (k keyValueProvisioner) DeleteKeyValueTable(_ context.Context, ref compute.Ref) error {
	return deleteAsync(k.p, k.p.store.tables, ref, compute.KindKeyValueTable)
}

func (k keyValueProvisioner) status(rec *record[compute.KeyValueSpec], st compute.Status) *compute.KeyValueStatus {
	k.p.store.mu.Lock()
	defer k.p.store.mu.Unlock()
	return &compute.KeyValueStatus{Status: st, Spec: deepCopy(rec.spec), Name: k.p.cfg.Name + "-" + rec.name}
}

// Grant implements [compute.Granter].
func (k keyValueProvisioner) Grant(ctx context.Context, resource compute.Ref, identity compute.Ref, level compute.AccessLevel) error {
	return k.granter().Grant(ctx, resource, identity, level)
}

// Revoke implements [compute.Granter].
func (k keyValueProvisioner) Revoke(ctx context.Context, resource compute.Ref, identity compute.Ref) error {
	return k.granter().Revoke(ctx, resource, identity)
}

// DescribeGrant implements [compute.Granter].
func (k keyValueProvisioner) DescribeGrant(ctx context.Context, resource compute.Ref, identity compute.Ref) (*compute.GrantInfo, error) {
	return k.granter().DescribeGrant(ctx, resource, identity)
}

func (k keyValueProvisioner) granter() granter {
	return granter{p: k.p, kind: compute.KindKeyValueTable, exists: func(id string) bool {
		k.p.store.mu.Lock()
		defer k.p.store.mu.Unlock()
		rec, ok := k.p.store.tables[id]
		return ok && !rec.async.deleted
	}}
}

var _ compute.KeyValueProvisioner = keyValueProvisioner{}
