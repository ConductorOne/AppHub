// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package matrix_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/matrix"
)

// This file's fixtures are written out rather than borrowed from compute/fake,
// and that is deliberate twice over.
//
// It keeps this package's dependencies to compute alone, which is the right shape
// for something whose whole job is to reflect over compute.Provider — and it is
// what the import boundary requires, since every real provider can reach
// compute/ext and this package has no business being allowed to.
//
// It also makes the fixtures better evidence. Each of the four answers the matrix
// can give is produced here by a provider constructed to give exactly that answer,
// so a test that expects "stub" is reading a port that was written to be one
// rather than hoping a general-purpose fake happens to behave that way.

// fixture is a provider whose every answer is dictated by its configuration.
type fixture struct {
	name string
	caps compute.CapabilitySet
	// stubKeyValues hands out a KeyValueProvisioner whose every method refuses,
	// which is the defect the matrix exists to expose.
	stubKeyValues bool
	// nilSecrets returns a nil port with a nil error, which is the other way a
	// provider can be broken rather than merely limited.
	nilSecrets bool
	// evasiveKeyValues hands out a port that refuses every realistic call but
	// answers ErrInvalidSpec to the zero-argument one a probe makes. It is the
	// adversary a reviewer used to falsify this package's original claim.
	evasiveKeyValues bool
}

var _ compute.Provider = (*fixture)(nil)

func newFixture(name string, stub, nilPort bool, caps ...compute.Capability) *fixture {
	return &fixture{
		name:          name,
		caps:          compute.NewCapabilitySet(caps...),
		stubKeyValues: stub,
		nilSecrets:    nilPort,
	}
}

// fullFixture advertises everything and implements the two ports these tests
// need, so nothing is declined for want of a capability.
func fullFixture() *fixture {
	return newFixture("fixture-full", false, false, compute.AllCapabilities()...)
}

// narrowFixture advertises two capabilities, so most ports are declined.
func narrowFixture() *fixture {
	return newFixture("fixture-narrow", false, false,
		compute.CapContainerService, compute.CapSecretStore)
}

func (f *fixture) Name() string                        { return f.name }
func (f *fixture) Capabilities() compute.CapabilitySet { return f.caps }
func (f *fixture) Identities() compute.IdentityService { return nil }

func (f *fixture) refuse(c compute.Capability) error {
	return &compute.UnsupportedError{
		Provider:   f.name,
		Capability: c,
		Detail:     "this fixture is configured without " + string(c),
	}
}

// Every accessor below declines unless the capability is advertised, which is the
// agreement compute.Provider documents. The ports that are handed out are the two
// this file needs: a working SecretStore and a KeyValueProvisioner that is either
// working or a stub.

func (f *fixture) Registry() (compute.ImageRegistry, error) {
	return nil, f.refuse(compute.CapImageRegistry)
}

func (f *fixture) Builder() (compute.ImageBuilder, error) {
	return nil, f.refuse(compute.CapImageBuild)
}

func (f *fixture) Containers() (compute.ContainerRuntime, error) {
	return nil, f.refuse(compute.CapContainerService)
}

func (f *fixture) Functions() (compute.FunctionRuntime, error) {
	return nil, f.refuse(compute.CapFunction)
}

func (f *fixture) ObjectStores() (compute.ObjectStore, error) {
	return nil, f.refuse(compute.CapObjectStore)
}

func (f *fixture) Relational() (compute.RelationalProvisioner, error) {
	return nil, f.refuse(compute.CapRelationalDatabase)
}

func (f *fixture) KeyValues() (compute.KeyValueProvisioner, error) {
	if !f.caps.Has(compute.CapKeyValueTable) {
		return nil, f.refuse(compute.CapKeyValueTable)
	}
	return keyValues{
		provider:         f.name,
		refuseEverything: f.stubKeyValues,
		evasive:          f.evasiveKeyValues,
	}, nil
}

func (f *fixture) Secrets() (compute.SecretStore, error) {
	if f.nilSecrets {
		// A nil port with a nil error: the failure compute.Provider's
		// documentation calls out by name, where "the first caller to forget a
		// nil check gets a panic instead of a diagnosis".
		return nil, nil
	}
	if !f.caps.Has(compute.CapSecretStore) {
		return nil, f.refuse(compute.CapSecretStore)
	}
	return secretStore{}, nil
}

// secretStore is a working port: its methods reject their input, which is what a
// real port does with a zero specification, and none of them refuses the
// capability.
type secretStore struct{}

var _ compute.SecretStore = secretStore{}

func (secretStore) Put(context.Context, compute.SecretSpec) (compute.StoredSecret, error) {
	return compute.StoredSecret{}, compute.ErrInvalidSpec
}

func (secretStore) Describe(context.Context, compute.Ref) (*compute.SecretInfo, error) {
	return nil, compute.ErrInvalidSpec
}

func (secretStore) Get(context.Context, compute.Ref) (compute.SecretValue, error) {
	return compute.SecretValue{}, compute.ErrInvalidSpec
}

func (secretStore) Delete(context.Context, compute.Ref) error { return compute.ErrInvalidSpec }
func (secretStore) DeleteScope(context.Context, string) error { return compute.ErrInvalidSpec }

// keyValues is either a working port or a stub, on one flag, so the two can be
// compared without changing anything else about the provider.
type keyValues struct {
	provider         string
	refuseEverything bool
	// evasive makes only EnsureKeyValueTable behave, and only for the zero spec.
	// Every other method, and every realistic Ensure, refuses.
	evasive bool
}

var _ compute.KeyValueProvisioner = keyValues{}

func (k keyValues) answer() error {
	if k.refuseEverything || k.evasive {
		return &compute.UnsupportedError{
			Provider:   k.provider,
			Capability: compute.CapKeyValueTable,
			Detail:     "this fixture is a stub on purpose",
		}
	}
	return compute.ErrInvalidSpec
}

func (k keyValues) EnsureKeyValueTable(_ context.Context, spec compute.KeyValueSpec) (*compute.KeyValueStatus, error) {
	if k.evasive {
		// The evasion: validate the input a zero-argument probe supplies, and
		// refuse anything a caller would actually send.
		if spec.Name == "" {
			return nil, compute.ErrInvalidSpec
		}
		return nil, &compute.UnsupportedError{
			Provider:   k.provider,
			Capability: compute.CapKeyValueTable,
			Detail:     "this fixture refuses every realistic call on purpose",
		}
	}
	return nil, k.answer()
}

func (k keyValues) DescribeKeyValueTable(context.Context, compute.Ref) (*compute.KeyValueStatus, error) {
	return nil, k.answer()
}

func (k keyValues) WaitForKeyValueTable(context.Context, compute.Ref, compute.WaitOptions) (*compute.KeyValueStatus, error) {
	return nil, k.answer()
}

func (k keyValues) DeleteKeyValueTable(context.Context, compute.Ref) error { return k.answer() }

func (k keyValues) Grant(context.Context, compute.Ref, compute.Ref, compute.AccessLevel) error {
	return k.answer()
}

func (k keyValues) Revoke(context.Context, compute.Ref, compute.Ref) error { return k.answer() }

func (k keyValues) DescribeGrant(context.Context, compute.Ref, compute.Ref) (*compute.GrantInfo, error) {
	return nil, k.answer()
}

// TestTheFixturesAreWhatTheyClaim guards the fixtures themselves, before
// anything is asserted through them.
//
// USOSS-27's third review round found an evidence row naming a test that a later
// edit had deleted: the claim outlived its subject. A fixture that stopped
// refusing, or a "working" port that started refusing, would make every test
// below pass for the wrong reason and look exactly the same from outside.
func TestTheFixturesAreWhatTheyClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stub, err := newFixture("f", true, false, compute.CapKeyValueTable).KeyValues()
	if err != nil {
		t.Fatalf("the stub fixture declined at acquisition, so it is not a stub: %v", err)
	}
	if err := stub.DeleteKeyValueTable(ctx, compute.Ref{}); !errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("the stub fixture no longer refuses: %v", err)
	}

	working, err := newFixture("f", false, false, compute.CapKeyValueTable).KeyValues()
	if err != nil {
		t.Fatalf("the working fixture declined at acquisition: %v", err)
	}
	if err := working.DeleteKeyValueTable(ctx, compute.Ref{}); errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("the working fixture refuses like a stub, so the control half of "+
			"TestAStubPortCannotHide proves nothing: %v", err)
	}

	secrets, err := fullFixture().Secrets()
	if err != nil || secrets == nil {
		t.Fatalf("the working SecretStore fixture is not usable: %v", err)
	}
	if err := secrets.Delete(ctx, compute.Ref{}); errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("the working SecretStore refuses like a stub: %v", err)
	}
}

// TestAccessorsAreDerivedNotListed is the emptiness gate on the reflection.
//
// A derivation that returns nothing satisfies every assertion written over it,
// and the accessor set here is read out of an interface type rather than
// written down. So this test names the ports that exist today and requires all
// of them: if the reflection rule ever stops matching — a signature changes, the
// reflected type is wrong — the failure is loud rather than an empty table.
//
// It deliberately does not require the set to be *exactly* these eight. Adding a
// port to compute.Provider should add a row without editing this package, which
// is the property the derivation exists for; what must not happen is a row going
// missing.
func TestAccessorsAreDerivedNotListed(t *testing.T) {
	t.Parallel()

	m, err := matrix.Derive(context.Background(), fullFixture(), matrix.Options{})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(m.Ports) == 0 {
		t.Fatal("the derived port set is empty; every check over this matrix would be vacuous")
	}

	got := map[string]matrix.Port{}
	for _, p := range m.Ports {
		got[p.Accessor] = p
	}
	for accessor, iface := range map[string]string{
		"Registry":     "compute.ImageRegistry",
		"Builder":      "compute.ImageBuilder",
		"Containers":   "compute.ContainerRuntime",
		"Functions":    "compute.FunctionRuntime",
		"ObjectStores": "compute.ObjectStore",
		"Relational":   "compute.RelationalProvisioner",
		"KeyValues":    "compute.KeyValueProvisioner",
		"Secrets":      "compute.SecretStore",
	} {
		row, ok := got[accessor]
		if !ok {
			t.Errorf("no matrix row for compute.Provider.%s; the reflection rule stopped "+
				"matching it", accessor)
			continue
		}
		if row.Interface != iface {
			t.Errorf("%s's port renders as %q, want %q", accessor, row.Interface, iface)
		}
	}

	// Identities is documented as never refused and returns one value, so it is
	// not a capability-gated accessor and must not appear as a row. Name and
	// Capabilities are not ports at all.
	for _, notAPort := range []string{"Identities", "Name", "Capabilities"} {
		if _, ok := got[notAPort]; ok {
			t.Errorf("compute.Provider.%s appears as a port row; the rule is matching "+
				"methods it should not", notAPort)
		}
	}
}

// TestEveryCapabilityGetsARow pins that the capability axis covers the whole
// population rather than only what the provider has. An absent capability is the
// fact a support matrix is mostly read for.
func TestEveryCapabilityGetsARow(t *testing.T) {
	t.Parallel()

	m, err := matrix.Derive(context.Background(), narrowFixture(), matrix.Options{})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	all := compute.AllCapabilities()
	if len(m.Capabilities) != len(all) {
		t.Fatalf("the matrix has %d capability rows, want %d — one per compute.AllCapabilities()",
			len(m.Capabilities), len(all))
	}
	present, absent := 0, 0
	for i, row := range m.Capabilities {
		if row.Capability != all[i] {
			t.Errorf("row %d is %q, want %q: the order must follow compute.AllCapabilities()",
				i, row.Capability, all[i])
		}
		if row.Present {
			present++
		} else {
			absent++
		}
	}
	// Both halves non-empty, so a matrix that answered "yes" or "no" to
	// everything — the two ways this could be uniformly wrong — fails here.
	if present == 0 || absent == 0 {
		t.Fatalf("a narrow provider produced %d present and %d absent capabilities; both "+
			"halves should be non-empty", present, absent)
	}
}

// TestDeclinedPortsCarryTheirCapability checks the discoverability criterion:
// a refusal happens at acquisition and names the capability, so a caller can act
// on it without calling anything.
func TestDeclinedPortsCarryTheirCapability(t *testing.T) {
	t.Parallel()

	m, err := matrix.Derive(context.Background(), narrowFixture(), matrix.Options{})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	declined, available := 0, 0
	for _, p := range m.Ports {
		switch p.Support {
		case matrix.SupportDeclined:
			declined++
			if p.Capability == "" {
				t.Errorf("%s was declined but the refusal named no capability, so a caller "+
					"cannot tell an operator what to configure", p.Accessor)
			}
			if p.Detail == "" {
				t.Errorf("%s was declined with no explanation", p.Accessor)
			}
		case matrix.SupportUnknown:
			t.Errorf("%s is %q: %s", p.Accessor, p.Support, p.Detail)
		case matrix.SupportStub:
			t.Errorf("%s reported as a stub without probing, which should be impossible",
				p.Accessor)
		case matrix.SupportAvailable:
			available++
		}
	}
	// Both halves, so a matrix that declined or allowed everything fails here.
	if declined == 0 || available == 0 {
		t.Fatalf("the narrow provider produced %d declined and %d available ports; both "+
			"halves should be non-empty", declined, available)
	}
}

// TestABrokenAccessorIsNotReportedAsWorking covers the fourth answer: an
// accessor that returns a nil port and a nil error.
//
// compute.Provider's own documentation names this as the failure its
// (port, error) shape exists to prevent — "the first caller to forget a nil check
// gets a panic instead of a diagnosis". A matrix that reported it as available
// would publish a working port where there is none.
func TestABrokenAccessorIsNotReportedAsWorking(t *testing.T) {
	t.Parallel()

	p := newFixture("fixture-broken", false, true, compute.AllCapabilities()...)
	m, err := matrix.Derive(context.Background(), p, matrix.Options{ProbePorts: true})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	got := row(t, m, "Secrets")
	if got.Support != matrix.SupportUnknown {
		t.Fatalf("an accessor returning (nil, nil) reads as %q, want %q", got.Support,
			matrix.SupportUnknown)
	}
	if got.Detail == "" {
		t.Error("the broken accessor was reported with no explanation")
	}
}

// TestAStubPortCannotHide is the test the brief asked for: a port that exists
// but is unimplemented must not read as available.
//
// The fixture is a provider with one accessor replaced by a port whose every
// method refuses. Without probing it is indistinguishable from a working port,
// and this test pins both halves of that — which is the point, because "the
// matrix says available" means "probed and not a stub" only when Matrix.Probed
// is true.
func TestAStubPortCannotHide(t *testing.T) {
	t.Parallel()

	p := newFixture("fixture-stub", true, false, compute.AllCapabilities()...)

	unprobed, err := matrix.Derive(context.Background(), p, matrix.Options{})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if unprobed.Probed {
		t.Error("Matrix.Probed is true without Options.ProbePorts")
	}
	if got := row(t, unprobed, "KeyValues").Support; got != matrix.SupportAvailable {
		t.Errorf("without probing, the stub reads as %q; want %q — a caller cannot tell, "+
			"which is why probing exists", got, matrix.SupportAvailable)
	}

	probed, err := matrix.Derive(context.Background(), p, matrix.Options{ProbePorts: true})
	if err != nil {
		t.Fatalf("Derive with probing: %v", err)
	}
	if !probed.Probed {
		t.Error("Matrix.Probed is false with Options.ProbePorts set")
	}
	stub := row(t, probed, "KeyValues")
	if stub.Support != matrix.SupportStub {
		t.Fatalf("the stub port reads as %q, want %q (detail: %s)",
			stub.Support, matrix.SupportStub, stub.Detail)
	}
	if len(stub.Methods) == 0 {
		t.Fatal("the stub port was probed but no methods were recorded, so the classification " +
			"rests on an empty set")
	}
	for _, m := range stub.Methods {
		if !m.Refuses {
			t.Errorf("stub method %s did not refuse: %s", m.Name, m.Err)
		}
	}

	// The control: a port that is genuinely implemented must not be swept up by
	// the same probe. Both halves matter — a stub detector that fires on
	// everything is as useless as one that fires on nothing.
	working := row(t, probed, "Secrets")
	if working.Support != matrix.SupportAvailable {
		t.Fatalf("a working SecretStore reads as %q, want %q (detail: %s)",
			working.Support, matrix.SupportAvailable, working.Detail)
	}
	if len(working.Methods) == 0 {
		t.Fatal("the working port recorded no probed methods")
	}
	for _, m := range working.Methods {
		if m.Refuses {
			t.Errorf("working method %s refused: %s", m.Name, m.Err)
		}
	}
}

// TestDeriveRefusesToProduceNothing pins the emptiness contract: Derive errors
// rather than handing back a matrix that renders as "supports nothing".
func TestDeriveRefusesToProduceNothing(t *testing.T) {
	t.Parallel()
	if _, err := matrix.Derive(context.Background(), nil, matrix.Options{}); err == nil {
		t.Fatal("Derive(nil) returned no error")
	}
}

// TestMarkdownRefusesEmptyInput is the same contract on the renderer, which is
// the surface the public documentation actually calls.
func TestMarkdownRefusesEmptyInput(t *testing.T) {
	t.Parallel()

	if _, err := matrix.Markdown(); err == nil {
		t.Error("Markdown() with no matrices returned no error")
	}
	if _, err := matrix.Markdown(nil); err == nil {
		t.Error("Markdown(nil) returned no error")
	}
	if _, err := matrix.Markdown(&matrix.Matrix{Provider: "x"}); err == nil {
		t.Error("Markdown of a matrix with no rows returned no error")
	}

	m, err := matrix.Derive(context.Background(), fullFixture(), matrix.Options{})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if _, err := matrix.Markdown(m, m); err == nil {
		t.Error("Markdown with two matrices naming the same provider returned no error; one " +
			"column would have silently overwritten the other")
	}
}

// TestMarkdownRendersEveryRow checks the rendered table against the matrices it
// came from, rather than against a golden file: a golden file is a restatement
// and would drift.
func TestMarkdownRendersEveryRow(t *testing.T) {
	t.Parallel()

	full, err := matrix.Derive(context.Background(), fullFixture(), matrix.Options{ProbePorts: true})
	if err != nil {
		t.Fatalf("Derive full: %v", err)
	}
	narrow, err := matrix.Derive(context.Background(), narrowFixture(), matrix.Options{ProbePorts: true})
	if err != nil {
		t.Fatalf("Derive narrow: %v", err)
	}

	out, err := matrix.Markdown(full, narrow)
	if err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	for _, want := range []string{"fixture-full", "fixture-narrow", "### Capabilities", "### Ports"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendered table does not mention %q", want)
		}
	}
	for _, c := range compute.AllCapabilities() {
		if !strings.Contains(out, "`"+string(c)+"`") {
			t.Errorf("capability %q has no row in the rendered table", c)
		}
	}
	for _, p := range full.Ports {
		if !strings.Contains(out, "`"+p.Accessor+"`") {
			t.Errorf("accessor %q has no row in the rendered table", p.Accessor)
		}
	}
	// Every data row must have the same column count as the header, or a reader
	// silently reads a provider's answer out of the wrong column.
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "|") {
			rows = append(rows, line)
		}
	}
	if len(rows) == 0 {
		t.Fatal("the rendered table has no rows")
	}
	widths := map[int]int{}
	for _, r := range rows {
		widths[strings.Count(r, "|")]++
	}
	// Two widths exactly: the capability table (1 label + 2 providers) and the
	// port table (2 labels + 2 providers).
	if len(widths) != 2 {
		t.Errorf("the rendered table has %d distinct row widths (%v); want exactly two, one "+
			"per section", len(widths), widths)
	}
}

// row finds one accessor's row, failing if it is absent.
func row(t *testing.T, m *matrix.Matrix, accessor string) matrix.Port {
	t.Helper()
	for _, p := range m.Ports {
		if p.Accessor == accessor {
			return p
		}
	}
	t.Fatalf("no row for accessor %q", accessor)
	return matrix.Port{}
}

// TestAnEvasiveStubIsNotPublishedAsAvailable is the regression for a claim of
// this package's that a reviewer falsified.
//
// The original claim was that a port which exists but is unimplemented cannot
// hide. The counter-example: refuse every realistic call, but answer
// compute.ErrInvalidSpec to the single zero-argument call the probe makes. Five of
// six methods refusing, and the matrix published it as `available` — which
// USOSS-20's documentation consumes as a capability claim.
//
// The fix is not a cleverer probe, because there is not one: a zero-argument probe
// can only ever construct the input a well-written port rejects on validation
// grounds. It is a third answer. `partial` names the refusing methods and is
// rendered distinctly, so nothing publishes it as working.
func TestAnEvasiveStubIsNotPublishedAsAvailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	p := &fixture{
		name:             "fixture-evasive",
		caps:             compute.NewCapabilitySet(compute.AllCapabilities()...),
		evasiveKeyValues: true,
	}

	// First, the fixture really is evasive: the zero spec validates, a realistic
	// one refuses. Without this the test could pass for the wrong reason.
	port, err := p.KeyValues()
	if err != nil {
		t.Fatalf("the evasive fixture declined at acquisition, so it is not the adversary: %v", err)
	}
	if _, err := port.EnsureKeyValueTable(ctx, compute.KeyValueSpec{}); errors.Is(err, compute.ErrUnsupported) {
		t.Fatal("the evasive fixture refuses the zero spec, so it would be caught as an " +
			"ordinary stub and this test would prove nothing")
	}
	if _, err := port.EnsureKeyValueTable(ctx, compute.KeyValueSpec{Name: "real"}); !errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("the evasive fixture accepts a realistic spec, so it is not a stub at all: %v", err)
	}

	m, err := matrix.Derive(ctx, p, matrix.Options{ProbePorts: true})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	got := row(t, m, "KeyValues")
	if got.Support == matrix.SupportAvailable {
		t.Fatalf("the evasive port is published as %q. USOSS-20's documentation consumes this "+
			"as a capability claim, and the port can do nothing on a valid request.", got.Support)
	}
	if got.Support != matrix.SupportPartial {
		t.Fatalf("the evasive port reads as %q, want %q", got.Support, matrix.SupportPartial)
	}
	// The refusing methods must be named, or an operator cannot act on it.
	for _, want := range []string{"DeleteKeyValueTable", "Grant", "Revoke"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the partial classification does not name %s among the refusing methods: %s",
				want, got.Detail)
		}
	}

	// The control, and it is the half that makes `partial` useful rather than
	// merely cautious: a genuinely working port must NOT be swept up.
	working := row(t, m, "Secrets")
	if working.Support != matrix.SupportAvailable {
		t.Errorf("a working SecretStore reads as %q; a classifier that calls everything partial "+
			"is as useless as one that calls everything available", working.Support)
	}
}
