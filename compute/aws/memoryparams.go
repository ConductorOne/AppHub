// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/conductorone/apphub/compute"
)

// MemoryParameters is an in-process [ParameterStore].
//
// It enforces the behaviours the provider's error mapping depends on rather than
// accepting everything: a create-only collision, the tier's value limit, the
// per-resource tag limit, and a version that increments on every write. A fake
// that said yes to all of those would let the provider's mapping of them go
// permanently untested, which is how a conformance suite ends up green against
// a provider that would fail on contact with the real service.
//
// Every method is safe for concurrent use, because the conformance suite runs
// its checks as parallel subtests against one substrate.
type MemoryParameters struct {
	mu     sync.Mutex
	params map[string]*memParameter

	// failErr, when set, is returned by the (failAfter+1)-th subsequent call to
	// any method, and then cleared. It exists so a test can drive the provider's
	// handling of a substrate failure — a throttle, a tagging call that fails
	// after the value has already been written — without a network.
	failErr   error
	failAfter int
	sticky    bool
	// fired records that an armed injection was actually consumed, so a gate can
	// tell "the method handled the failure" from "the failure never reached it".
	// USOSS-60's acceptance criterion; the same silence otherwise.
	fired bool
}

type memParameter struct {
	value   compute.SecretValue
	keyID   string
	tier    ParameterTier
	version int64
	tags    map[string]string

	// history is every value this parameter has held, oldest first, so that a
	// version-pinned read resolves to the value that revision actually had.
	history []compute.SecretValue
}

// NewMemoryParameters returns an empty in-memory parameter store.
func NewMemoryParameters() *MemoryParameters {
	return &MemoryParameters{params: map[string]*memParameter{}}
}

var _ ParameterStore = (*MemoryParameters)(nil)

// FailNext makes the NEXT call to any method return err, once, until the returned
// function is called. Passing nil clears it.
//
// One-shot, matching [failNext.FailNext] on the other in-memory services. The
// signatures match on purpose: a store with a differently-shaped injector is a
// store the harness ends up special-casing, and a special case is where a service
// gets left unarmed.
func (m *MemoryParameters) FailNext(err error) func() {
	return m.arm(err, 0, false)
}

// FailUntilStopped makes EVERY call return err until the returned function is
// called.
//
// The distinction from [MemoryParameters.FailNext] is USOSS-60's, and it is not
// cosmetic: a gate that drives many methods inside one armed window has the
// one-shot form consumed by whichever call happens to come first, and every
// method after it is scored as unexercised rather than as unarmed.
func (m *MemoryParameters) FailUntilStopped(err error) func() {
	return m.arm(err, 0, true)
}

func (m *MemoryParameters) arm(err error, skip int, sticky bool) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failErr, m.failAfter, m.sticky, m.fired = err, skip, sticky && err != nil, false
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.failErr, m.failAfter, m.sticky = nil, 0, false
	}
}

// injectionFired reports whether an armed injection was actually consumed. It is
// unexported and reached through the interface [Harness.InjectionFired] asserts,
// which is what lets a new in-memory service join without the harness changing.
func (m *MemoryParameters) injectionFired() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fired
}

// FailAfter makes the call `skip` calls from now return err, once.
//
// The offset is what makes the interesting case reachable: a Put that succeeds
// followed by a tagging call that does not, which is the sequence the source
// system got wrong by discarding the second call's error (container.go:320).
func (m *MemoryParameters) FailAfter(skip int, err error) { m.arm(err, skip, false) }

// Fail is [MemoryParameters.FailUntilStopped] without the stop function, kept for
// the tests that arm and clear explicitly.
func (m *MemoryParameters) Fail(err error) { m.arm(err, 0, err != nil) }

// PutUnowned writes a parameter with no tags at all, as some other tool would
// have created it. It is how the conformance suite's CreateUnowned hook
// manufactures the ownership collision a mutable application name can cause.
func (m *MemoryParameters) PutUnowned(name string, value compute.SecretValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.params[name] = &memParameter{
		value:   value,
		tier:    TierStandard,
		version: 1,
		tags:    map[string]string{"created-by": "somebody-else"},
		history: []compute.SecretValue{value},
	}
}

// arnOf is the ARN this store reports for a parameter, standing in for the
// service that would return one.
//
// Composed HERE and nowhere else. An earlier version let the provider install a
// composer so that a store handed to a provider reported ARNs in that provider's
// partition, region and account -- which meant the provider knew how to compose
// an SSM ARN, and a provider that can compose one will eventually compose one on
// a path that should have read it back. The in-memory store is the only place a
// fake ARN is legitimate, so this is the only place that makes one, and it uses
// the same deliberately-unreal account and region as every other memory store
// here: an ARN from this file cannot be mistaken for one from a service.
//
// Note there is no separator between "parameter" and the name: an SSM parameter
// name already begins with a slash, and inserting one produces an ARN that
// matches nothing while appending anything produces one that matches too much.
func (m *MemoryParameters) arnOf(name string) string {
	return "arn:aws:ssm:" + MemoryRegion + ":" + MemoryAccount + ":parameter" + name
}

// Names returns every parameter name currently held, sorted. Test support.
func (m *MemoryParameters) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.params))
	for name := range m.params {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Dump describes every parameter in the operator-facing form the conformance
// suite's Rendered hook consumes.
//
// A parameter's *value* never appears, and that is the invariant this method
// exists to be checked against: Parameter Store is where the material lives, so
// a dump of it that included values would be the one artefact in the system
// that legitimately contains a secret — and then the suite's "no material in
// anything the provider renders" check would have to be weakened to accommodate
// it. Rendering metadata and tags instead keeps the check strict.
func (m *MemoryParameters) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.params))
	for _, name := range sortedKeys(m.params) {
		p := m.params[name]
		// Nothing derived from the value appears, not even its length: a length
		// is not material, but it narrows a brute force, and an operator
		// debugging a tier limit already knows how big their own value is.
		fields := []string{
			"type=SecureString",
			"tier=" + string(p.tier),
			fmt.Sprintf("version=%d", p.version),
		}
		if p.keyID != "" {
			fields = append(fields, "keyId="+p.keyID)
		}
		if labels := labelsFromTags(p.tags); len(labels) > 0 {
			fields = append(fields, sortedPairs(labels))
		}
		fields = append(fields, "managedBy="+p.tags[tagManagedBy])
		out = append(out, name+": "+strings.Join(fields, " "))
	}
	return out
}

func (m *MemoryParameters) take() error {
	if m.failErr == nil {
		return nil
	}
	if m.failAfter > 0 {
		m.failAfter--
		return nil
	}
	err := m.failErr
	m.fired = true
	if !m.sticky {
		m.failErr = nil
	}
	return err
}

// Put implements [ParameterStore].
func (m *MemoryParameters) Put(_ context.Context, in PutParameterInput) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return 0, err
	}
	limit := in.Tier.MaxValueBytes()
	if limit == 0 {
		return 0, fmt.Errorf("aws: unknown parameter tier %q", in.Tier)
	}
	// The length, never the value.
	if len(compute.RevealSecret(in.Value)) > limit {
		return 0, fmt.Errorf("%w: the %s tier allows %d bytes", ErrParameterTooLarge, in.Tier, limit)
	}
	existing, ok := m.params[in.Name]
	if ok && !in.Overwrite {
		return 0, fmt.Errorf("%w: %s", ErrParameterExists, in.Name)
	}
	if !ok {
		if len(in.Tags) > maxTagsPerResource {
			return 0, fmt.Errorf("aws: %d tags exceeds the %d AWS allows on a parameter",
				len(in.Tags), maxTagsPerResource)
		}
		tags := make(map[string]string, len(in.Tags))
		for k, v := range in.Tags {
			tags[k] = v
		}
		m.params[in.Name] = &memParameter{
			value:   in.Value,
			keyID:   in.KeyID,
			tier:    in.Tier,
			version: 1,
			tags:    tags,
			history: []compute.SecretValue{in.Value},
		}
		return 1, nil
	}
	// A repeat write of the same value does not mint a revision. That is what the
	// idempotence invariant needs -- two identical Puts must be
	// indistinguishable, and a store that versioned every call would make a
	// redeploy that changed nothing look like a rotation.
	//
	// DOC-DERIVED, AND THE CONFORMANCE SUITE TURNS IT INTO A HARD FAILURE. The
	// claim that this is also what real SSM does comes from documentation, not
	// from an observed PutParameter against a live account -- the same standing
	// as the IAM/ARN-grammar claim in docs/design/aws-secret-store.md, which is
	// caveated there and this was not. It is worth naming here because the suite
	// does not treat it as a detail of this substrate: for any provider declaring
	// Options.HonoursSecretVersions, a second identical Put reporting a
	// DIFFERENT version is a conformance FAILURE (checks_security.go, the
	// "a repeat write is not a rotation" arm). So if real SSM increments on every
	// PutParameter regardless of the value, compute/aws fails conformance the
	// first time it is run against a live account -- and the fix would be in the
	// invariant, not here.
	//
	// Worth one confirmation against a live account before production, alongside
	// the ARN-grammar one.
	if compute.RevealSecret(existing.value) == compute.RevealSecret(in.Value) {
		existing.keyID, existing.tier = in.KeyID, in.Tier
		return existing.version, nil
	}
	existing.value = in.Value
	existing.keyID = in.KeyID
	existing.tier = in.Tier
	existing.version++
	existing.history = append(existing.history, in.Value)
	return existing.version, nil
}

// RevisionValue returns the value a parameter held at a version, standing in for
// SSM's own parameter history.
//
// A real history rather than a counter: honouring a pinned binding means
// resolving to the value that revision held, and a store that only remembered
// the number would resolve every pin to the latest value while reporting the
// number the caller asked for -- which is the exact failure
// compute.SecretBinding.Version was added to close, so the fake must not be able
// to exhibit it.
func (m *MemoryParameters) RevisionValue(name string, version int64) (compute.SecretValue, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.params[name]
	if !ok || version < 1 || version > int64(len(p.history)) {
		return compute.SecretValue{}, false
	}
	return p.history[version-1], true
}

// Get implements [ParameterStore].
func (m *MemoryParameters) Get(_ context.Context, name string) (compute.SecretValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return compute.SecretValue{}, err
	}
	p, ok := m.params[name]
	if !ok {
		return compute.SecretValue{}, fmt.Errorf("%w: %s", ErrParameterNotFound, name)
	}
	return p.value, nil
}

// Describe implements [ParameterStore].
func (m *MemoryParameters) Describe(_ context.Context, name string) (ParameterMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return ParameterMetadata{}, err
	}
	p, ok := m.params[name]
	if !ok {
		return ParameterMetadata{}, fmt.Errorf("%w: %s", ErrParameterNotFound, name)
	}
	return ParameterMetadata{
		Name: name, ARN: m.arnOf(name), Tier: p.tier, Version: p.version, KeyID: p.keyID,
	}, nil
}

// DescribeByPath implements [ParameterStore].
func (m *MemoryParameters) DescribeByPath(_ context.Context, path string) ([]ParameterMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return nil, err
	}
	// The trailing slash is what makes this a path match rather than a prefix
	// match. Without it "/p/apps/app-1" would enumerate "/p/apps/app-10/..."
	// too, and DeleteScope would delete another application's secrets.
	prefix := strings.TrimSuffix(path, "/") + "/"
	var out []ParameterMetadata
	for _, name := range sortedKeys(m.params) {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		p := m.params[name]
		out = append(out, ParameterMetadata{
			Name: name, ARN: m.arnOf(name), Tier: p.tier, Version: p.version, KeyID: p.keyID,
		})
	}
	return out, nil
}

// Tags implements [ParameterStore].
func (m *MemoryParameters) Tags(_ context.Context, name string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return nil, err
	}
	p, ok := m.params[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrParameterNotFound, name)
	}
	out := make(map[string]string, len(p.tags))
	for k, v := range p.tags {
		out[k] = v
	}
	return out, nil
}

// SetTags implements [ParameterStore].
func (m *MemoryParameters) SetTags(_ context.Context, name string, add map[string]string, remove []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return err
	}
	p, ok := m.params[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrParameterNotFound, name)
	}
	for k, v := range add {
		p.tags[k] = v
	}
	for _, k := range remove {
		delete(p.tags, k)
	}
	if len(p.tags) > maxTagsPerResource {
		return fmt.Errorf("aws: %d tags exceeds the %d AWS allows on a parameter",
			len(p.tags), maxTagsPerResource)
	}
	return nil
}

// Delete implements [ParameterStore].
func (m *MemoryParameters) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.take(); err != nil {
		return err
	}
	if _, ok := m.params[name]; !ok {
		return fmt.Errorf("%w: %s", ErrParameterNotFound, name)
	}
	delete(m.params, name)
	return nil
}
