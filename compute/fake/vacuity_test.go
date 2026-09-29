// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/conformance"
	"github.com/conductorone/apphub/compute/fake"
)

// These are the USOSS-32 fixtures: one per way the two checks it is about could
// report a pass without having checked anything.
//
// The repository's standing rule is that a check needs a fixture that fails
// before the change and passes after, and that the bypass is reproduced first.
// Every test here was run against the suite as it stood at 2d538dd and the
// result is recorded above it, because "this now passes" is not evidence about a
// gate unless the same assertion failed before.
//
// The two defects they inject are also entries in
// TestConformanceSuiteCatchesNonConformance, against a provider with every
// capability. That is deliberate: there the question is whether the suite
// notices the defect at all, and here it is whether it still notices when the
// provider's capability set moves outside the condition the check used to test.

const (
	retryGate    = "provider/a-retryable-failure-is-ErrTransient"
	renderedGate = "security/secret-material-does-not-appear-in-rendered-artefacts"
	// correspondenceGate is the USOSS-48 remedy: it asks the provider about
	// one Ref rather than trusting renderedGate's aggregate scan to be
	// complete.
	correspondenceGate = "security/every-planted-resource-has-a-rendered-artefact"
)

// noSecretStoreCaps is USOSS-10's shape: an image registry, a builder and the
// workload identities it needs, and no secret store. Five of the six AWS ports
// are in this position, which is what made the skip expensive rather than
// merely untidy.
func noSecretStoreCaps() []compute.Capability {
	return []compute.Capability{
		compute.CapImageRegistry,
		compute.CapImageBuild,
		compute.CapObjectStore,
	}
}

// result returns one check's result, or fails the test if the suite did not run
// it. A check that has stopped being scheduled is the failure mode a fixture
// asserting only "did not fail" would miss.
func result(t *testing.T, rep *conformance.Report, check string) conformance.Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.Check == check {
			return r
		}
	}
	t.Fatalf("the suite has no result for %q, so this fixture is asserting nothing:\n%s", check, rep)
	return conformance.Result{}
}

// TestTheRetryGateRunsWithoutASecretStore is the reproduction from
// INTERFACE-FRICTION.md §3, pinned.
//
// Before USOSS-32 the retry gate skipped unless the provider advertised
// CapSecretStore, "because a secret Put is the cheapest write on any provider".
// Verified against 2d538dd: this provider maps a retryable substrate failure
// onto compute.ErrFailed, and the suite reported it as NOT VERIFIED and passed
// the run — the defect was invisible. The same defect against a provider *with*
// a secret store failed there, which is what makes the capability condition,
// rather than the defect, the thing this fixture is about.
func TestTheRetryGateRunsWithoutASecretStore(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-no-secrets-terminal",
		Capabilities: noSecretStoreCaps(),
		Defects:      []fake.Defect{fake.DefectTransientIsTerminal},
	})
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, retryGate)
	if got.Skipped {
		t.Errorf("%s reported as unverified against a provider with no secret store, so the "+
			"substrate-error mapping five of the six AWS ports are writing goes unchecked. "+
			"Every provider has a workload-identity port and this one also has a registry and "+
			"an object store: skipping is reachable only by omitting a capability from a "+
			"hand-maintained condition.\n%s", retryGate, rep)
	}
	if !got.Failed() {
		t.Errorf("%s passed against a provider that maps a retryable substrate failure onto "+
			"compute.ErrFailed:\n%s", retryGate, rep)
	}
}

// TestTheRetryGateFailsWhenTheHookInducesNothing is the anti-vacuity assertion
// itself.
//
// Verified against 2d538dd: with a hook that arms nothing the gate drove its one
// Put, the Put succeeded, and the check treated that as "the provider absorbed
// it, which the contract allows" and passed. So a provider whose hook does not
// work was indistinguishable from one whose mapping is right — a check that
// cannot tell those apart is counted as coverage while proving nothing, which is
// the whole defect class this ticket is in.
func TestTheRetryGateFailsWhenTheHookInducesNothing(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{ExtPorts: true})
	opts.InduceTransient = func(context.Context, compute.Provider, compute.Kind) (func(), error) {
		return func() {}, nil
	}
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, retryGate)
	if !got.Failed() {
		t.Errorf("%s did not fail against a hook that induces nothing. Either it passed — in "+
			"which case an inert hook reads exactly like a correct mapping — or it skipped, which "+
			"is the same claim in a quieter voice:\n%s", retryGate, rep)
	}
	if !strings.Contains(strings.Join(got.Messages, " "), "surfaced") {
		t.Errorf("the failure does not say that nothing surfaced, so a provider author cannot "+
			"tell the hook is the problem: %v", got.Messages)
	}
}

// TestTheRetryGateNamesAPortItCannotDrive is USOSS-42's fixture: since
// Options.InduceTransient takes the kind the suite is about to drive, a hook
// that cannot arrange a failure for one of them says so by returning an error
// for that kind alone, and the gate has to record that one port by name while
// still driving -- and passing over -- the rest, the same contract
// Options.InduceDenial already has.
//
// Before the kind parameter existed a hook could only accept or refuse a
// failure for the whole provider in one shot; there was no way to say "not this
// one port". This pins that a single refused kind is reported as an
// observation naming the port rather than failing the whole check or silently
// dropping the port's own tally.
func TestTheRetryGateNamesAPortItCannotDrive(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{ExtPorts: true})
	inner := opts.InduceTransient
	opts.InduceTransient = func(ctx context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
		if kind == compute.KindBucket {
			return nil, errors.New("fake: this harness cannot throttle the object store")
		}
		return inner(ctx, p, kind)
	}
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, retryGate)
	if got.Skipped || got.Failed() {
		t.Errorf("%s reported skipped or failed because one kind (bucket) refused to be armed, "+
			"even though every other port armed and verified cleanly:\n%s", retryGate, rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "bucket") {
		t.Errorf("no note names the bucket port as undrivable, so a reader cannot tell its "+
			"mapping went unverified: %v", rep.Notes)
	}
}

// TestTheRetryGateDrivesEveryPortRatherThanOne is the "gets ECR right and IAM
// wrong" case, which is why one call site was never enough.
//
// The provider is the reference implementation with one port's mapping replaced:
// its identity service reports a retryable failure as compute.ErrFailed and
// every other port is correct. Verified against 2d538dd: the gate drove a secret
// Put, the secret store's mapping was right, and the run passed. A per-service
// mapping cannot be checked at one call site, and there are six of these being
// written independently.
func TestTheRetryGateDrivesEveryPortRatherThanOne(t *testing.T) {
	t.Parallel()

	store := fake.NewStore()
	cfg := fake.Config{ExtPorts: true}
	factory := func(conformance.TB) compute.Provider {
		return terminalIdentities{fake.New(store, cfg)}
	}
	opts := conformanceOptions(cfg)
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, retryGate)
	if !got.Failed() {
		t.Errorf("%s passed against a provider whose identity service maps a retryable failure "+
			"onto compute.ErrFailed while every other port maps it correctly:\n%s", retryGate, rep)
	}
	if !strings.Contains(strings.Join(got.Messages, " "), "EnsureWorkloadIdentity") {
		t.Errorf("the failure does not name the method that got it wrong, so the enumeration is "+
			"not reporting per method: %v", got.Messages)
	}
}

// TestTheRenderedGateSaysSoWhenNothingCarriesMaterial is the reproduction from
// INTERFACE-FRICTION.md §4.
//
// This provider has no port that can be handed secret material: no secret store
// to hold any, no relational admin password, and nothing to bind. Verified
// against 2d538dd: the check scanned the rendered artefacts for a sentinel
// nobody had stored, found none, and reported a pass — counted as coverage of an
// invariant it had not touched. It must report as unverified instead, and say
// why.
//
// USOSS-26 corrected the other half of this ticket's premise and is right: the
// check does have teeth the moment CapSecretStore is present, because the secret
// port's own lifecycle checks store the sentinel. TestTheRenderedGateHasTeeth
// WithASecretStoreAlone pins that so it cannot be lost while fixing this.
func TestTheRenderedGateSaysSoWhenNothingCarriesMaterial(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-no-material",
		Capabilities: noSecretStoreCaps(),
	})
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, renderedGate)
	if got.Failed() {
		t.Fatalf("%s failed against a provider that holds no material at all, which is a suite "+
			"bug rather than a provider one:\n%s", renderedGate, rep)
	}
	if !got.Skipped {
		t.Fatalf("%s passed against a provider with no port that can be handed secret material. "+
			"It planted nothing, so the pass says only that a sentinel nobody stored was absent "+
			"— and it is counted as coverage of a security invariant:\n%s", renderedGate, rep)
	}
	joined := strings.Join(got.Messages, " ")
	for _, want := range []string{"NOT VERIFIED", "no port that can be handed secret material"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the unverified report does not contain %q, so a reader cannot tell what was "+
				"not checked: %v", want, got.Messages)
		}
	}
}

// TestTheRenderedGateHasTeethWithASecretStoreAlone pins USOSS-26's correction.
//
// The claim this ticket inherited was that the check plants only for
// CapSecretStore+CapContainerService or CapRelationalDatabase and therefore
// proves nothing otherwise. The first half is true of the planting branch; the
// conclusion is not, because the secret port's own Ensure stores secrets whose
// value is the sentinel and the substrate is shared across the run. So a
// provider whose only material-carrying port is its secret store is genuinely
// covered.
//
// Verified against 2d538dd: this fails there too. It is here so that the fix for
// the vacuous case cannot quietly remove the coverage that already existed.
func TestTheRenderedGateHasTeethWithASecretStoreAlone(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-secrets-only",
		Capabilities: []compute.Capability{compute.CapSecretStore},
		Defects:      []fake.Defect{fake.DefectSecretValueInStoreListing},
	})
	rep := conformance.Verify(t, factory, opts)

	if got := result(t, rep, renderedGate); !got.Failed() {
		t.Errorf("%s passed against a provider whose only material-carrying port is its secret "+
			"store and whose substrate listing prints the values:\n%s", renderedGate, rep)
	}
}

// TestTheRenderedGateFailsWhenTheSubstrateShowsNothing closes the other way the
// scan could look at nothing: a hook that returns artefacts which do not reflect
// what was planted.
//
// Verified against 2d538dd: with an empty Rendered the check reported as
// unverified, which is defensible, but it did so *without* having planted
// anything, and the same report came back for a provider that had material in
// play. Now the planting is deliberate, so a Rendered that does not move is a
// failure: the scan below it would pass whatever the provider did with the
// material.
func TestTheRenderedGateFailsWhenTheSubstrateShowsNothing(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{ExtPorts: true})
	opts.Rendered = func(context.Context, compute.Provider) ([]string, error) { return nil, nil }
	rep := conformance.Verify(t, factory, opts)

	if got := result(t, rep, renderedGate); !got.Failed() {
		t.Errorf("%s did not fail against a provider that renders nothing after material was "+
			"planted through every port that carries it:\n%s", renderedGate, rep)
	}
}

// TestThePartialArtefactDropDefeatsTheAggregateCheckButNotCorrespondence is
// USOSS-48's reproduction, measured against a live leak rather than reasoned
// about: the ticket's first version described a TOTAL emptying, which
// TestTheRenderedGateFailsWhenTheSubstrateShowsNothing above already shows the
// aggregate gate catches. The real gap is PARTIAL: one resource's artefact
// dropped from the enumeration while everything else renders.
//
// DefectSecretValueInStoreListing puts the sentinel in exactly the artefact
// DefectDropsRenderedArtefact drops, which reproduces PR #25's shape: a List
// call whose per-item read failed and was swallowed, so one resource is
// missing from what the substrate reports and the rest renders fine.
//
// renderedGate is still fooled by this, on the current tree, because its
// non-emptiness argument is entirely aggregate: Options.Rendered grows (the
// planted service is fresh), so "the provider rendered something new" holds,
// and the sentinel is in none of it because the one artefact that carried it
// was never a member of the list the scan searched. That is not a defect in
// this test; it is the vacuous pass USOSS-48 is about, still true of
// renderedGate alone and asserted here so a future change cannot silently
// depend on renderedGate to catch this shape.
//
// correspondenceGate is not fooled: it asked the provider about the exact Ref
// planted through the secret port, independent of the aggregate's size, and
// the provider reported no artefact for it.
func TestThePartialArtefactDropDefeatsTheAggregateCheckButNotCorrespondence(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		ExtPorts: true,
		Defects:  []fake.Defect{fake.DefectDropsRenderedArtefact, fake.DefectSecretValueInStoreListing},
	})
	rep := conformance.Verify(t, factory, opts)

	if got := result(t, rep, renderedGate); got.Failed() {
		t.Errorf("%s failed against a partially-emptied artefact set. It is not expected to see "+
			"this shape at all -- it only knows whether the aggregate is non-empty and fresh, "+
			"not which member of it corresponds to which resource:\n%s", renderedGate, rep)
	}
	if got := result(t, rep, correspondenceGate); !got.Failed() {
		t.Errorf("%s passed against a provider that dropped one resource's artefact from "+
			"Options.Rendered while everything else rendered fine:\n%s", correspondenceGate, rep)
	}
}

// TestTheCorrespondenceGateSaysSoWhenNothingCarriesMaterial is
// correspondenceGate's half of TestTheRenderedGateSaysSoWhenNothingCarriesMaterial:
// the legitimate-empty case still has to be named as unverified rather than
// passed, for the same reason. A provider that holds no material has no Ref
// for this check to demand correspondence for either.
func TestTheCorrespondenceGateSaysSoWhenNothingCarriesMaterial(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-no-material",
		Capabilities: noSecretStoreCaps(),
	})
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, correspondenceGate)
	if got.Failed() {
		t.Fatalf("%s failed against a provider that holds no material at all, which is a suite "+
			"bug rather than a provider one:\n%s", correspondenceGate, rep)
	}
	if !got.Skipped {
		t.Fatalf("%s passed against a provider with no port that can be handed secret material, "+
			"which planted nothing and therefore verified nothing:\n%s", correspondenceGate, rep)
	}
}

// TestTheCorrespondenceGateHasTeethWithASecretStoreAlone is
// TestTheRenderedGateHasTeethWithASecretStoreAlone's counterpart: a provider
// whose only material-carrying port is its secret store is still genuinely
// covered by the per-resource check, not just the aggregate one.
func TestTheCorrespondenceGateHasTeethWithASecretStoreAlone(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-secrets-only",
		Capabilities: []compute.Capability{compute.CapSecretStore},
		Defects:      []fake.Defect{fake.DefectDropsRenderedArtefact},
	})
	rep := conformance.Verify(t, factory, opts)

	if got := result(t, rep, correspondenceGate); !got.Failed() {
		t.Errorf("%s passed against a provider whose only material-carrying port is its secret "+
			"store and which drops that secret's own rendered artefact:\n%s", correspondenceGate, rep)
	}
}

// --- the one-wrong-port provider -------------------------------------------

// terminalIdentities is the reference provider with a single port's error
// mapping replaced.
//
// It is a wrapper rather than a fake.Defect because the point is that *one* port
// is wrong while the rest are right, and a defect flag on the provider would be
// a property of all of them. This is the shape INTERFACE-FRICTION.md §3
// describes: a provider that reached ErrTransient from its registry and
// ErrFailed from its identity service.
type terminalIdentities struct{ *fake.Provider }

func (p terminalIdentities) Identities() compute.IdentityService {
	return terminalIdentityService{p.Provider.Identities()}
}

// underlying reaches the substrate hooks through the wrapper. See harness().
func (p terminalIdentities) underlying() *fake.Provider { return p.Provider }

type terminalIdentityService struct{ compute.IdentityService }

func (s terminalIdentityService) EnsureWorkloadIdentity(
	ctx context.Context, spec compute.WorkloadIdentitySpec,
) (*compute.WorkloadIdentity, error) {
	id, err := s.IdentityService.EnsureWorkloadIdentity(ctx, spec)
	if errors.Is(err, compute.ErrTransient) {
		return nil, fmt.Errorf("fake: the identity service refused this call: %w", compute.ErrFailed)
	}
	return id, err
}

// --- the provider whose refusals say nothing (USOSS-66) ---------------------

const errGate = "security/secret-material-does-not-appear-in-errors"

// bareRefusals is the reference provider with every refusal from the three ports
// the error gate drives reduced to a context-free sentinel: no name, no scope,
// nothing else the caller supplied. leak makes those same refusals carry the
// value the spec was holding, which is the one thing they must never do.
//
// It is a wrapper rather than a fake.Defect for the reason terminalIdentities is:
// terseness is a property of how a provider words its errors, not a defect it
// has, and an honest provider is entitled to it. What it is not entitled to is a
// green — the point of the fixture is that a suite scanning five strings the
// provider composed from nothing has measured nothing.
type bareRefusals struct {
	*fake.Provider
	leak bool
}

// underlying reaches the substrate hooks through the wrapper. See harness().
func (p bareRefusals) underlying() *fake.Provider { return p.Provider }

// bare is the whole fixture: an ErrInvalidSpec refusal with the spec discarded,
// optionally with the material the call was holding put back in.
func (p bareRefusals) bare(err error, value compute.SecretValue) error {
	if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
		return err
	}
	if p.leak {
		return fmt.Errorf("%w: %s", compute.ErrInvalidSpec, compute.RevealSecret(value))
	}
	return compute.ErrInvalidSpec
}

func (p bareRefusals) Secrets() (compute.SecretStore, error) {
	s, err := p.Provider.Secrets()
	if err != nil {
		return nil, err
	}
	return bareSecrets{s, p}, nil
}

type bareSecrets struct {
	compute.SecretStore
	p bareRefusals
}

func (s bareSecrets) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	out, err := s.SecretStore.Put(ctx, spec)
	return out, s.p.bare(err, spec.Value)
}

func (p bareRefusals) Relational() (compute.RelationalProvisioner, error) {
	r, err := p.Provider.Relational()
	if err != nil {
		return nil, err
	}
	return bareRelational{r, p}, nil
}

type bareRelational struct {
	compute.RelationalProvisioner
	p bareRefusals
}

func (r bareRelational) EnsureRelational(
	ctx context.Context, spec compute.RelationalSpec,
) (*compute.RelationalStatus, error) {
	out, err := r.RelationalProvisioner.EnsureRelational(ctx, spec)
	return out, r.p.bare(err, spec.AdminPassword)
}

func (p bareRefusals) Containers() (compute.ContainerRuntime, error) {
	c, err := p.Provider.Containers()
	if err != nil {
		return nil, err
	}
	return bareContainers{c, p}, nil
}

type bareContainers struct {
	compute.ContainerRuntime
	p bareRefusals
}

func (c bareContainers) EnsureService(
	ctx context.Context, spec compute.ServiceSpec,
) (*compute.ServiceStatus, error) {
	out, err := c.ContainerRuntime.EnsureService(ctx, spec)
	return out, c.p.bare(err, compute.SecretValue{})
}

// bareSuite is newSuite with every refusal the error gate reads stripped of the
// spec that produced it.
func bareSuite(t *testing.T, leak bool) (conformance.Factory, conformance.Options) {
	t.Helper()
	factory, opts := newSuite(fake.Config{ExtPorts: true})
	return func(tb conformance.TB) compute.Provider {
		p, ok := factory(tb).(*fake.Provider)
		if !ok {
			t.Fatal("newSuite stopped returning *fake.Provider, so this fixture wraps nothing")
		}
		return bareRefusals{p, leak}
	}, opts
}

// TestTheErrorGateSaysSoWhenEveryRefusalIsBare is USOSS-66's reproduction,
// pinned.
//
// The guard this replaced was `checked == 0 -> skip`, where checked counted
// calls that FAILED. Verified against 279ed4b: this provider fails all five of
// them, so checked reached five, the loop searched five context-free sentinels,
// found nothing, and the suite reported "secret material appears in no error
// message and no Status field" as VERIFIED — failed=false, skipped=false, no
// messages at all. Five refusals composed from none of the spec are clean
// whatever the provider does with the material it is holding, which is the same
// clean a correct provider produces.
//
// The scanChannels call that stood alongside it did not save the run: it
// established and scanned the foreign-ref refusal, which is a different error
// from the five, and which had never been handed any material to leak.
func TestTheErrorGateSaysSoWhenEveryRefusalIsBare(t *testing.T) {
	t.Parallel()

	factory, opts := bareSuite(t, false)
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, errGate)
	if got.Failed() {
		t.Fatalf("%s failed against a provider that is merely terse, which is a suite bug rather "+
			"than a provider one — an honest provider is entitled to word its errors how it "+
			"likes:\n%s", errGate, rep)
	}
	if !got.Skipped {
		t.Fatalf("%s reported verified against a provider whose every refusal discards the spec. "+
			"Nothing it scanned could have carried the value that came with the call, so the "+
			"green says only that five context-free sentinels do not contain a secret:\n%s",
			errGate, rep)
	}
	joined := strings.Join(got.Messages, " ")
	for _, want := range []string{"NOT VERIFIED", "naming any part of the spec it refused"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the unverified report does not contain %q, so a reader cannot tell what was "+
				"not checked: %v", want, got.Messages)
		}
	}
}

// TestTheErrorGateStillCatchesALeakInABareRefusal is the other half, and the one
// that stops the new guard becoming an escape hatch.
//
// Requiring an observation before believing a clean scan must not turn into
// skipping the scan when the observation is absent: a refusal that names none of
// the spec and still carries the value is the worst case of all, and it has to
// be a failure rather than a NOT VERIFIED. So the material search runs over every
// failed call and only the verdict turns on observation.
func TestTheErrorGateStillCatchesALeakInABareRefusal(t *testing.T) {
	t.Parallel()

	factory, opts := bareSuite(t, true)
	rep := conformance.Verify(t, factory, opts)

	got := result(t, rep, errGate)
	if got.Skipped {
		t.Fatalf("%s reported NOT VERIFIED against a provider that puts the secret value into a "+
			"refusal. The guard is meant to withhold belief in a clean scan, not to skip the "+
			"scan:\n%s", errGate, rep)
	}
	if !got.Failed() {
		t.Fatalf("%s did not fail against a provider whose refusals carry the material they were "+
			"handed:\n%s", errGate, rep)
	}
}

// acceptingSecrets is the reference provider with a secret store that refuses
// nothing, including the specs this suite hands it precisely to be refused.
type acceptingSecrets struct{ *fake.Provider }

// underlying reaches the substrate hooks through the wrapper. See harness().
func (p acceptingSecrets) underlying() *fake.Provider { return p.Provider }

func (p acceptingSecrets) Secrets() (compute.SecretStore, error) {
	s, err := p.Provider.Secrets()
	if err != nil {
		return nil, err
	}
	return acceptingStore{s}, nil
}

type acceptingStore struct{ compute.SecretStore }

func (s acceptingStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	out, err := s.SecretStore.Put(ctx, spec)
	if errors.Is(err, compute.ErrInvalidSpec) {
		return out, nil
	}
	return out, err
}

// TestTheErrorGateSaysSoWhenNothingIsRefused keeps the branch the old guard's
// `checked == 0` covered, now that counting failures is no longer the guard.
//
// A provider is entitled to accept a spec this suite expected it to reject. What
// it must not do is turn that into a pass: if nothing was refused there is no
// error to search, and a run that searched no error has not measured the
// invariant. Only errGate is asserted here — a store that accepts an unnamed
// secret is wrong in other ways too, and those are other checks' business.
func TestTheErrorGateSaysSoWhenNothingIsRefused(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		Name:         "fake-accepts-everything",
		Capabilities: []compute.Capability{compute.CapSecretStore},
	})
	wrapped := func(tb conformance.TB) compute.Provider {
		p, ok := factory(tb).(*fake.Provider)
		if !ok {
			t.Fatal("newSuite stopped returning *fake.Provider, so this fixture wraps nothing")
		}
		return acceptingSecrets{p}
	}
	rep := conformance.Verify(t, wrapped, opts)

	got := result(t, rep, errGate)
	if !got.Skipped {
		t.Fatalf("%s reported verified against a store that refused none of the specs it was "+
			"given to refuse, so no error was searched at all:\n%s", errGate, rep)
	}
	joined := strings.Join(got.Messages, " ")
	if !strings.Contains(joined, "no error to search") {
		t.Errorf("the unverified report does not say that nothing was refused, so a reader "+
			"cannot tell this from a provider whose errors were merely terse: %v", got.Messages)
	}
}
