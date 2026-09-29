// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/compute/conformance"
)

// A green gate proves nothing until somebody tries to defeat it.
//
// Every test in this file breaks this provider's secret store in one specific,
// plausible way and asserts that the conformance suite fails the one invariant
// that break violates — not merely that it fails something. Without this, "the
// AWS secret store passes conformance" is an assertion about a suite nobody has
// shown to be capable of failing on this port.
//
// The two DeleteScope invariants are new in this change, so their fixtures are
// the ones that matter most: they fail against the defect and pass against the
// real store, which is the evidence that the check does work rather than merely
// running.

// brokenProvider is the real provider with one port swapped out.
type brokenProvider struct {
	compute.Provider
	store compute.SecretStore
}

func (b brokenProvider) Secrets() (compute.SecretStore, error) { return b.store, nil }

// brokenStore delegates everything and lets one method be replaced.
type brokenStore struct {
	compute.SecretStore
	inner       compute.SecretStore
	put         func(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error)
	get         func(ctx context.Context, ref compute.Ref) (compute.SecretValue, error)
	del         func(ctx context.Context, ref compute.Ref) error
	deleteScope func(ctx context.Context, scope string) error
}

func (b brokenStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	if b.put != nil {
		return b.put(ctx, spec)
	}
	return b.inner.Put(ctx, spec)
}

func (b brokenStore) Get(ctx context.Context, ref compute.Ref) (compute.SecretValue, error) {
	if b.get != nil {
		return b.get(ctx, ref)
	}
	return b.inner.Get(ctx, ref)
}

func (b brokenStore) Delete(ctx context.Context, ref compute.Ref) error {
	if b.del != nil {
		return b.del(ctx, ref)
	}
	return b.inner.Delete(ctx, ref)
}

func (b brokenStore) DeleteScope(ctx context.Context, scope string) error {
	if b.deleteScope != nil {
		return b.deleteScope(ctx, scope)
	}
	return b.inner.DeleteScope(ctx, scope)
}

// verifyDefect runs the suite against a provider whose secret store has been
// broken by mutate, and returns the report.
func verifyDefect(t *testing.T, mutate func(inner compute.SecretStore, sub *aws.Substrate) brokenStore) *conformance.Report {
	t.Helper()
	sub := aws.NewMemorySubstrate()
	factory := func(tb conformance.TB) compute.Provider {
		p, err := aws.New(sub, secretStoreConfig())
		if err != nil {
			tb.Fatalf("aws.New: %v", err)
		}
		inner, err := p.Secrets()
		if err != nil {
			tb.Fatalf("Secrets(): %v", err)
		}
		broken := mutate(inner, sub)
		broken.inner = inner
		broken.SecretStore = inner
		return brokenProvider{Provider: p, store: broken}
	}
	opts := conformance.Options{
		// "default", not "primary": fullConfig configures "default" and
		// "secondary", and a placement name that is configured nowhere is a
		// fixture naming a thing that does not exist. It was harmless only
		// because every secret check that reaches Config.placement did so with an
		// EMPTY Placement, which falls back to the default -- so this option was
		// read only on paths these fixtures skip. USOSS-11's container port names
		// the placement on every EnsureService and it became nineteen failures at
		// once. Found by them, fixed here rather than carried on their branch.
		Placement: "default",
		// Required because secretStoreConfig is the full account, which since
		// USOSS-14 advertises CapRelationalDatabase: the suite refuses to run
		// against a provider advertising it with no engine named. These fixtures
		// are about the secret store, so the values are just the declared ones
		// -- see conformanceOptions for why the version cannot be invented.
		Engine:        compute.EnginePostgres,
		EngineVersion: "16",
		// Required for the same reason: secretStoreConfig also advertises
		// function and function-endpoint since USOSS-12, and the suite refuses
		// to run against a provider advertising them with neither declared.
		FunctionRuntime: testRuntime,
		CertificateRef:  testCertificateRef,
		// The provider under test is compute/aws, which honours a pin: see
		// conformanceOptions.
		HonoursSecretVersions: true,
		ImplementsExt:         implementsExt(true), // secretStoreConfig is fullConfig, which configures ObjectStore
		InduceTransient: func(ctx context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
			bp, ok := p.(brokenProvider)
			if !ok {
				return nil, errors.New("aws_test: unexpected provider")
			}
			return bp.Provider.(*aws.Provider).Harness().InduceTransientKind(ctx, kind, aws.ErrThrottled)
		},
		CreateUnowned: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			bp, ok := p.(brokenProvider)
			if !ok {
				return errors.New("aws_test: unexpected provider")
			}
			return bp.Provider.(*aws.Provider).Harness().CreateUnowned(ctx, ref)
		},
		Rendered: func(ctx context.Context, p compute.Provider) ([]string, error) {
			bp, ok := p.(brokenProvider)
			if !ok {
				return nil, errors.New("aws_test: unexpected provider")
			}
			return bp.Provider.(*aws.Provider).Harness().Rendered(ctx)
		},
	}
	return conformance.Verify(t, factory, opts)
}

// requireOnly asserts that the named check failed and that nothing else did.
//
// The second half is what makes the fixture evidence rather than noise: a defect
// that fails half the suite tells you the suite reacts, not that the invariant
// you meant to violate is the one being enforced.
// destroyed records the resources a defect fixture actually destroyed, so a
// cascade can be identified BY CAUSE rather than by name.
//
// USOSS-11 found the previous version wrong by two. It derived WHETHER a cascade
// applies -- from CapContainerService, correctly -- and then HAND-LISTED WHICH
// checks were in it. Same split that has cost this project all night, one level
// further in: the gate derived, the membership two names somebody wrote down, and
// already wrong when written. Two container-service scale checks also Ensure a
// service binding the deleted secret.
//
// Adding the two names would be correct today and drift tomorrow, because the
// real membership is "every check that Ensures a service binding a secret this
// defect destroyed" -- a property of the SUITE, which grows whenever a check is
// added. Scheduled jobs will bind secrets too.
//
// So membership is computed from the causal chain: the fixture's broken store
// records what it deleted, and an additional failure whose message names one of
// those resources is the cascade. Nothing to keep in step, and nothing that can
// be wrong by two.
//
// # What this trades, stated because it is a real loss
//
// A predicate cannot assert that a declared member MUST fail, which was the
// property that made the previous list a declaration rather than an exemption.
// It is not needed here, and that is the point rather than a consolation: a
// member exists only because it actually failed naming a resource this defect
// actually destroyed, so there is no declaration to go stale. The named
// invariant keeps its two-direction assertion.
//
// The residual risk is an unrelated failure that happens to mention the same
// parameter path being absorbed. Against that, every absorbed failure is LOGGED
// by name -- silently absorbing failures is the thing to avoid; absorbing them
// visibly is not.
type destroyed struct {
	mu    sync.Mutex
	names []string
}

func (d *destroyed) record(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.names = append(d.names, name)
}

func (d *destroyed) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.names...)
}

// requireOnlyCausedBy is requireOnly plus a cause-derived cascade.
//
// want keeps the two-direction assertion: each named check must fail, and
// nothing may fail that is neither named nor caused by what the defect destroyed.
func requireOnlyCausedBy(t *testing.T, rep *conformance.Report, d *destroyed, want ...string) {
	t.Helper()
	wanted := map[string]bool{}
	for _, name := range want {
		wanted[name] = true
		if !rep.FailedCheck(name) {
			t.Errorf("the defect did not fail %q; that invariant is not enforced:\n%s", name, rep)
		}
	}
	gone := d.list()
	if len(gone) == 0 {
		t.Error("the fixture recorded nothing destroyed, so a cascade could not be identified by " +
			"cause and any additional failure would be reported as a loss of isolation")
	}
	for _, r := range rep.Failures() {
		if wanted[r.Check] {
			continue
		}
		msg := strings.Join(r.Messages, "\n")
		var because string
		for _, name := range gone {
			if strings.Contains(msg, name) {
				because = name
				break
			}
		}
		if because == "" {
			t.Errorf("the defect also failed %q, and its message names none of the %d resources "+
				"the defect destroyed, so it is a loss of isolation rather than a cascade:\n%s",
				r.Check, len(gone), msg)
			continue
		}
		// Absorbed, and named. A cascade nobody can see is an exemption.
		t.Logf("declared cascade: %q also failed, caused by the destruction of %s", r.Check, because)
	}
}

func requireOnly(t *testing.T, rep *conformance.Report, want ...string) {
	t.Helper()
	wanted := map[string]bool{}
	for _, name := range want {
		wanted[name] = true
		if !rep.FailedCheck(name) {
			t.Errorf("the defect did not fail %q; that invariant is not enforced:\n%s", name, rep)
		}
	}
	for _, r := range rep.Failures() {
		if !wanted[r.Check] {
			t.Errorf("the defect also failed %q, so the fixture does not isolate one invariant:\n%s",
				r.Check, strings.Join(r.Messages, "\n"))
		}
	}
}

// TestDefectDeleteScopeDeletesOnlyTheFirst is the pagination and loop-exit bug:
// a teardown that stops after one secret and reports success.
func TestDefectDeleteScopeDeletesOnlyTheFirst(t *testing.T) {
	t.Parallel()
	rep := verifyDefect(t, func(inner compute.SecretStore, sub *aws.Substrate) brokenStore {
		params, ok := sub.Parameters.(*aws.MemoryParameters)
		if !ok {
			t.Fatal("expected the in-memory parameter store")
		}
		return brokenStore{deleteScope: func(ctx context.Context, scope string) error {
			if scope == "" {
				return inner.DeleteScope(ctx, scope)
			}
			found, err := params.DescribeByPath(ctx, "/apphub/conformance/apps")
			if err != nil {
				return err
			}
			for _, meta := range found {
				if strings.Contains(meta.Name, scope) {
					return params.Delete(ctx, meta.Name)
				}
			}
			return nil
		}}
	})
	requireOnly(t, rep, "port/secret/delete-scope-removes-the-scope-and-nothing-else")
}

// TestDefectDeleteScopeIsPrefixMatched is the hierarchy bug: a scope treated as
// a string prefix reaches a neighbouring application whose name merely starts
// the same way.
func TestDefectDeleteScopeIsPrefixMatched(t *testing.T) {
	t.Parallel()
	gone := &destroyed{}
	rep := verifyDefect(t, func(inner compute.SecretStore, sub *aws.Substrate) brokenStore {
		params, ok := sub.Parameters.(*aws.MemoryParameters)
		if !ok {
			t.Fatal("expected the in-memory parameter store")
		}
		return brokenStore{deleteScope: func(ctx context.Context, scope string) error {
			if scope == "" {
				return inner.DeleteScope(ctx, scope)
			}
			// Every parameter under the apps tree, which is what a prefix match
			// on a truncated scope amounts to.
			found, err := params.DescribeByPath(ctx, "/apphub/conformance/apps")
			if err != nil {
				return err
			}
			for _, meta := range found {
				if err := params.Delete(ctx, meta.Name); err != nil {
					return err
				}
				gone.record(meta.Name)
			}
			return nil
		}}
	})
	// The cascade is identified BY CAUSE -- see destroyed.
	requireOnlyCausedBy(t, rep, gone, "port/secret/delete-scope-removes-the-scope-and-nothing-else")
}

// TestDefectDeleteScopeAcceptsAnEmptyScope is the fail-open case the new check
// exists for: a caller bug that deletes a whole deployment's credentials.
func TestDefectDeleteScopeAcceptsAnEmptyScope(t *testing.T) {
	t.Parallel()
	gone := &destroyed{}
	rep := verifyDefect(t, func(_ compute.SecretStore, sub *aws.Substrate) brokenStore {
		params, ok := sub.Parameters.(*aws.MemoryParameters)
		if !ok {
			t.Fatal("expected the in-memory parameter store")
		}
		return brokenStore{deleteScope: func(ctx context.Context, scope string) error {
			// An empty scope read as "everything under the prefix", which is
			// what a path-prefix implementation does by doing nothing special.
			found, err := params.DescribeByPath(ctx, "/apphub/conformance/apps/"+scope)
			if err != nil {
				return err
			}
			for _, meta := range found {
				if err := params.Delete(ctx, meta.Name); err != nil {
					return err
				}
				gone.record(meta.Name)
			}
			return nil
		}}
	})
	// The cascade is identified BY CAUSE -- see destroyed.
	requireOnlyCausedBy(t, rep, gone, "port/secret/delete-scope-refuses-an-empty-scope")
}

// TestDefectPutAdoptsAnUnownedParameter is the ownership check removed.
func TestDefectPutAdoptsAnUnownedParameter(t *testing.T) {
	t.Parallel()
	rep := verifyDefect(t, func(inner compute.SecretStore, sub *aws.Substrate) brokenStore {
		params, ok := sub.Parameters.(*aws.MemoryParameters)
		if !ok {
			t.Fatal("expected the in-memory parameter store")
		}
		return brokenStore{put: func(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
			ref, err := inner.Put(ctx, spec)
			if !errors.Is(err, compute.ErrNotOwned) {
				// Everything else, including the substrate-error mapping, is the
				// real store's. Only the refusal is removed, so the fixture is
				// evidence about the ownership check and nothing else.
				return ref, err
			}
			// Overwrite whatever is there, which is what PutParameter with
			// Overwrite=true does when nobody checks first.
			name := "/apphub/conformance/apps/" + spec.Scope + "/" + spec.Name
			version, err := params.Put(ctx, aws.PutParameterInput{
				Name: name, Value: spec.Value, Tier: aws.TierStandard, Overwrite: true,
				Tags: map[string]string{"apphub.dev/managed-by": "apphub"},
			})
			if err != nil {
				return compute.StoredSecret{}, err
			}
			return compute.StoredSecret{
				Ref:     compute.Ref{Provider: "aws", Kind: compute.KindSecret, ID: name},
				Version: strconv.FormatInt(version, 10),
			}, nil
		}}
	})
	requireOnly(t, rep, "port/secret/refuses-a-resource-it-does-not-own")
}

// TestDefectErrorCarriesTheMaterial is the leak this whole ticket is about: an
// error path that interpolates the spec it could not satisfy.
func TestDefectErrorCarriesTheMaterial(t *testing.T) {
	t.Parallel()
	rep := verifyDefect(t, func(inner compute.SecretStore, _ *aws.Substrate) brokenStore {
		return brokenStore{put: func(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
			ref, err := inner.Put(ctx, spec)
			if err != nil {
				// Wrapped, so every sentinel the real store set survives. A
				// fixture that replaced the error would break every check that
				// branches on one, and would then be evidence about those
				// checks rather than about this one.
				return ref, fmt.Errorf("aws: could not store %s: %w", compute.RevealSecret(spec.Value), err)
			}
			return ref, nil
		}}
	})
	requireOnly(t, rep, "security/secret-material-does-not-appear-in-errors")
}

// TestDefectDeletedSecretStillReads is the read-back invariant: a caller cannot
// tell a deleted secret from a broken provider.
func TestDefectDeletedSecretStillReads(t *testing.T) {
	t.Parallel()
	rep := verifyDefect(t, func(inner compute.SecretStore, _ *aws.Substrate) brokenStore {
		return brokenStore{del: func(ctx context.Context, ref compute.Ref) error {
			// Narrowed to a well-formed reference of this provider's own, which
			// is the bug being modelled: the reference resolves and the API call
			// is never made. A Delete that returned nil for everything would
			// also defeat the foreign-reference and wrong-kind checks, and the
			// fixture would then be evidence about those instead.
			if ref.Provider != "aws" || ref.Kind != compute.KindSecret {
				return inner.Delete(ctx, ref)
			}
			return nil
		}}
	})
	// Two invariants, and both are genuinely violated by this one bug rather
	// than by an over-broad fixture. A Delete that never reaches the API leaves
	// the parameter there, so a caller cannot tell a deleted secret from a
	// broken provider through EITHER read: the value still comes back, and the
	// metadata read still says it exists.
	//
	// The second entry arrived with compute.SecretStore.Describe (USOSS-15). It
	// is listed rather than narrowed away because narrowing here would mean
	// making the fixture violate only one of two things one bug really does
	// break, which is a fixture describing something other than the bug.
	requireOnly(t, rep,
		"port/secret/sync/read-back-after-delete-is-not-found",
		"security/secret-metadata-read-returns-no-material",
	)
}

// TestDefectForeignReferenceReportsNotFound is the mis-mapping that makes a
// caller recreate somebody else's secret.
func TestDefectForeignReferenceReportsNotFound(t *testing.T) {
	t.Parallel()
	rep := verifyDefect(t, func(inner compute.SecretStore, _ *aws.Substrate) brokenStore {
		// Only a foreign reference, which is the defect being modelled. Mapping
		// EVERY Get error onto ErrNotFound also turns a retryable failure into a
		// terminal one, so the fixture violated a second invariant and stopped
		// being evidence about this one. Caught by USOSS-32's strengthened retry
		// gate, which drives Get under an induced throttle -- the fixture was
		// wrong, not the gate.
		notFound := func(err error) error {
			if errors.Is(err, compute.ErrForeignRef) {
				return compute.ErrNotFound
			}
			return err
		}
		return brokenStore{
			get: func(ctx context.Context, ref compute.Ref) (compute.SecretValue, error) {
				v, err := inner.Get(ctx, ref)
				return v, notFound(err)
			},
			del: func(ctx context.Context, ref compute.Ref) error {
				if ref.Provider != "aws" {
					return compute.ErrNotFound
				}
				return inner.Delete(ctx, ref)
			},
		}
	})
	requireOnly(t, rep, "port/secret/foreign-refs-are-refused")
}

// TestDefectRenderedArtefactsCarryTheMaterial is the fixture that answers a
// question two other tickets got wrong in the pessimistic direction.
//
// USOSS-10 reported security/secret-material-does-not-appear-in-rendered-artefacts
// as passing vacuously, on the grounds that checkSecretsNotInRendered plants its
// sentinel only for a provider with CapSecretStore *and* CapContainerService.
// That is true of the planting branch and it was the right conclusion for a
// provider with no secret store — but it is not true here, and the difference is
// worth pinning rather than arguing: the secret port's own lifecycle checks store
// parameters whose value IS the sentinel, they run before the security checks,
// and the store is shared, so the sentinel is genuinely in play by the time the
// artefacts are scanned.
//
// So this fixture makes the operator-facing dump include values and asserts the
// check notices. It is the difference between "the suite is green" and "the suite
// would have caught it".
func TestDefectRenderedArtefactsCarryTheMaterial(t *testing.T) {
	t.Parallel()
	sub := aws.NewMemorySubstrate()
	factory := func(tb conformance.TB) compute.Provider {
		p, err := aws.New(sub, secretStoreConfig())
		if err != nil {
			tb.Fatalf("aws.New: %v", err)
		}
		return p
	}
	opts := conformance.Options{
		// "default", not "primary": fullConfig configures "default" and
		// "secondary", and a placement name that is configured nowhere is a
		// fixture naming a thing that does not exist. It was harmless only
		// because every secret check that reaches Config.placement did so with an
		// EMPTY Placement, which falls back to the default -- so this option was
		// read only on paths these fixtures skip. USOSS-11's container port names
		// the placement on every EnsureService and it became nineteen failures at
		// once. Found by them, fixed here rather than carried on their branch.
		Placement: "default",
		// Required because secretStoreConfig is the full account, which since
		// USOSS-14 advertises CapRelationalDatabase: the suite refuses to run
		// against a provider advertising it with no engine named. These fixtures
		// are about the secret store, so the values are just the declared ones
		// -- see conformanceOptions for why the version cannot be invented.
		Engine:        compute.EnginePostgres,
		EngineVersion: "16",
		// Required for the same reason: secretStoreConfig also advertises
		// function and function-endpoint since USOSS-12, and the suite refuses
		// to run against a provider advertising them with neither declared.
		FunctionRuntime: testRuntime,
		CertificateRef:  testCertificateRef,
		// The provider under test is compute/aws, which honours a pin: see
		// conformanceOptions.
		HonoursSecretVersions: true,
		ImplementsExt:         implementsExt(true), // secretStoreConfig is fullConfig, which configures ObjectStore
		CreateUnowned: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			return harness(p).CreateUnowned(ctx, ref)
		},
		// A Rendered hook that dumps values rather than metadata, which is the
		// one mistake this hook can make.
		Rendered: func(ctx context.Context, p compute.Provider) ([]string, error) {
			artefacts, err := harness(p).Rendered(ctx)
			if err != nil {
				return nil, err
			}
			params, ok := sub.Parameters.(*aws.MemoryParameters)
			if !ok {
				return nil, errors.New("aws_test: expected the in-memory parameter store")
			}
			for _, name := range params.Names() {
				v, err := params.Get(ctx, name)
				if err != nil {
					return nil, err
				}
				artefacts = append(artefacts, fmt.Sprintf("%s: value=%s", name, compute.RevealSecret(v)))
			}
			return artefacts, nil
		},
	}
	rep := conformance.Verify(t, factory, opts)
	if !rep.FailedCheck("security/secret-material-does-not-appear-in-rendered-artefacts") {
		t.Errorf("a Rendered hook that dumps parameter values was not caught, so that invariant "+
			"is not enforced for a provider whose only capability is the secret store:\n%s", rep)
	}
	// The convergence check reads the same artefacts, so it is expected
	// collateral rather than a second finding.
	for _, r := range rep.Failures() {
		switch r.Check {
		case "security/secret-material-does-not-appear-in-rendered-artefacts",
			"port/secret/ensure-converges-rather-than-accumulating":
		default:
			t.Errorf("the defect also failed %q, so the fixture does not isolate the invariant:\n%s",
				r.Check, strings.Join(r.Messages, "\n"))
		}
	}
}

// TestTheRealStorePassesEveryCheckTheseFixturesBreak closes the loop. Each
// fixture above shows a check failing; this shows the same checks passing against
// the store as shipped, so a fixture cannot be passing because the check is
// broken for everybody.
func TestTheRealStorePassesEveryCheckTheseFixturesBreak(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(t, secretStoreConfig())
	rep := conformance.Verify(t, factory, opts)
	for _, name := range []string{
		"port/secret/delete-scope-removes-the-scope-and-nothing-else",
		"port/secret/delete-scope-refuses-an-empty-scope",
		"port/secret/refuses-a-resource-it-does-not-own",
		"port/secret/sync/read-back-after-delete-is-not-found",
		"port/secret/foreign-refs-are-refused",
		"security/secret-material-does-not-appear-in-errors",
		"security/secret-material-does-not-appear-in-rendered-artefacts",
	} {
		if rep.FailedCheck(name) {
			t.Errorf("the store as shipped fails %q:\n%s", name, rep)
		}
	}
	// And a check that never runs is not a check that passes.
	ran := map[string]bool{}
	for _, r := range rep.Results {
		if !r.Skipped {
			ran[r.Check] = true
		}
	}
	for _, name := range []string{
		"port/secret/delete-scope-removes-the-scope-and-nothing-else",
		"port/secret/delete-scope-refuses-an-empty-scope",
		"security/secret-material-does-not-appear-in-errors",
		"security/secret-material-does-not-appear-in-rendered-artefacts",
	} {
		if !ran[name] {
			t.Errorf("%q did not run, so its passing says nothing", name)
		}
	}
	if len(rep.Failures()) > 0 {
		t.Errorf("the store as shipped fails %d check(s):\n%s", len(rep.Failures()), rep)
	}
}
