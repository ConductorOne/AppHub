// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// TestEveryCoveredByClaimIsBoundToAnExecutedCall establishes by EXECUTION what the
// AST binding could only establish by spelling.
//
// # Why the AST binding was not enough
//
// [TestEveryCoveredByClaimIsBoundToACall] resolves a CoveredBy claim to the
// function registered for it and requires that function's body to contain a call
// to the method. **A selector inside an uninvoked closure satisfies that search.**
// Both real revokes were replaced with `func() { granter.RevokeExternal(...) }`,
// never called: compile, that test, the full suite and the fake conformance run all
// passed, while the documentation said the call was "really made".
//
// That is spelling-versus-denotation in the reachability direction — the same
// failure as matching an error-code string instead of a typed exception, or
// validating a name's shape and never resolving it. **An identifier is not an
// invocation.**
//
// # What this does instead
//
// It runs each named check against instrumented ports that record every call, and
// requires the claimed method to appear in the record. No assertion about what the
// check asserts — that would be asserting on assertions, which has no floor. The
// floor is that the call happens, which is the thing the claim says and the thing
// the AST cannot see.
//
// # Why the AST binding stays, measured rather than assumed
//
// The obvious reading is that execution subsumes syntax and the older test is now
// redundant. **It is not, and both halves were measured.** Two mutations, each
// caught by exactly one:
//
//   - the call moved into an uninvoked closure — the AST binding passes, this one
//     fails;
//   - the call deleted from the check while the BINDING makes it instead — this one
//     passes, the AST binding fails.
//
// The AST binding asserts about the check's source and cannot be satisfied by
// anything the binding does; this one asserts about a run and cannot be satisfied
// by an unreachable identifier. Neither implies the other, so keeping both is not
// belt-and-braces.
//
// # The population is derived, not listed
//
// The first version of this test named GrantExternal and RevokeExternal in a
// literal. That is the defect one layer in: a hand-typed population that happens to
// match today's claims and silently covers nothing when a third arrives. So the
// claims come from [undrivenPortMethods] and the binding is looked up by check name
// — **a CoveredBy claim with no execution binding is fatal here**, which is what
// makes this mechanism extend rather than decay. [executionBindings] carries the
// other direction: a binding no claim names is also fatal.
func TestEveryCoveredByClaimIsBoundToAnExecutedCall(t *testing.T) {
	t.Parallel()

	bindings := executionBindings()
	// One run per check family, however many claims name it. Each element is one
	// check's observed calls -- NOT the union.
	//
	// Unioning was the first form and it was weaker than the AST binding, which
	// requires every check a pattern matches to call the method. With a union, one
	// family member calling it covered for a sibling that had stopped: the
	// uninvoked-closure mutation applied to the second delete-scope check passed,
	// because the first still called it. **A claim over a family is a claim about
	// each member, and an aggregate cannot see a member go quiet.**
	calls := map[string][][]string{}
	used := map[string]bool{}

	claims := 0
	for iface, methods := range undrivenPortMethods() {
		for method, x := range methods {
			if x.CoveredBy == "" {
				continue
			}
			claimed := strings.Fields(x.CoveredBy)[0]
			if _, exempt := unresolvableCoveredBy[exemptionKey{iface, method, claimed}]; exempt {
				// The exemption is for a check that does not exist yet, so there
				// is nothing to execute. The AST test records the exemption; this
				// one inherits it rather than restating the reason.
				continue
			}
			claims++

			run, ok := bindings[claimed]
			if !ok {
				t.Errorf("%s.%s claims coverage by %q and no execution binding exists for that "+
					"check, so nothing here establishes the call is ever MADE. The AST binding "+
					"only requires the method's name to appear in the check's source, which an "+
					"identifier in an unreachable position satisfies. Add an entry to "+
					"executionBindings that runs the check against instrumented ports and "+
					"returns the calls it observed", iface, method, claimed)
				continue
			}
			used[claimed] = true
			if _, done := calls[claimed]; !done {
				calls[claimed] = run(t)
			}
			runs := calls[claimed]
			if len(runs) == 0 {
				t.Errorf("%s.%s claims coverage by %q and its execution binding ran no check, so "+
					"the assertion below is over an empty set", iface, method, claimed)
				continue
			}
			for i, run := range runs {
				if !slices.Contains(run, method) {
					t.Errorf("%s.%s claims coverage by %q, and check %d of %d in that family "+
						"invoked %v -- not %s. The claim names a call the check does not make. A "+
						"selector in the check's source is not an invocation: it survives being "+
						"moved into a closure nobody runs, into a branch nothing reaches, or "+
						"behind a condition that is never true",
						iface, method, claimed, i+1, len(runs), run, method)
				}
			}
		}
	}
	if claims == 0 {
		t.Error("no resolvable CoveredBy claims were found, so every assertion above ran zero " +
			"times. There is at least one claim in undrivenPortMethods; a derivation returning " +
			"nothing here is this test failing to look, not a clean bill")
	}

	// The other direction: a binding for a check nothing claims. Left standing, it
	// is a fixture maintained for a claim that has been deleted or retargeted --
	// the same rot as a stale exemption, and equally invisible while it passes.
	for name := range bindings {
		if !used[name] {
			t.Errorf("executionBindings has an entry for %q and no CoveredBy claim names that "+
				"check, so the binding runs a check nothing depends on it running. Delete the "+
				"entry, or restore the claim it was written for", name)
		}
	}
}

// executionBindings maps a check name to a function that runs that check against
// instrumented ports and returns the method names the check actually invoked.
//
// A hand-maintained map, and that is safe here for one reason: **both directions
// are checked.** A claim with no entry fails, and an entry no claim names fails. A
// list is only dangerous when falling behind is silent.
//
// # The residual boundary, which is one class and not one case
//
// Each function must return the calls it OBSERVED. Nothing here can tell that it
// did — **the binding is the instrument, and this test does not check its own
// instrument.** Enumerated rather than gestured at, the ways a binding can pass
// while the check never invokes the method are:
//
//  1. returning a literal instead of the record (measured: undetectable);
//  2. making the call itself, before or after invoking the check, so the record is
//     the binding's own activity;
//  3. instrumenting a port the check does not use, and calling the method on it.
//
// All three are the same thing — a binding that reports what it wants rather than
// what happened — and none is detectable from here, because a test that checked
// them would need an instrument of its own. That regress is why the line is drawn
// at the instrument rather than one step further in, and why it is written down: a
// reader must not take a passing run as evidence about a binding they have not
// read. Three properties keep the class small: a binding is short, it is reviewed
// with the claim that requires it, and both directions of the map are enforced, so
// one cannot sit here unattached to a claim.
func executionBindings() map[string]func(*testing.T) [][]string {
	return map[string]func(*testing.T) [][]string{
		"grants/bucket/an-external-grant-is-constrained-and-reads-back": runExternalGrantCheck,
		"port/secret/delete-scope-*":                                    runDeleteScopeChecks,
		// Bound on its exact name rather than through the family pattern: the
		// Get claim names this one check, and the map is looked up by the
		// claimed name verbatim. Its sibling refuses an empty scope and never
		// reads, so the family pattern could not carry a Get claim -- the
		// per-member assertion would (rightly) fail on it.
		"port/secret/delete-scope-removes-the-scope-and-nothing-else": runCheckDeleteScope,
		// USOSS-44: the ext.TableBucketProvisioner / ext.VectorBucketProvisioner
		// entries in undrivenPortMethods claim these four checks. Each runs
		// against ledgerStore, which now also implements both ext ports and
		// records every call, exactly as it already did for ExternalAccessGranter.
		"ext/table-bucket/ensure-table-bucket-and-delete-table-bucket-round-trip":    runTableBucketLifecycleCheck,
		"ext/table-bucket/table-bucket-grant-then-table-bucket-revoke":               runTableBucketGrantCheck,
		"ext/vector-bucket/ensure-vector-bucket-and-delete-vector-bucket-round-trip": runVectorBucketLifecycleCheck,
		"ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke":            runVectorBucketGrantCheck,
	}
}

// runTableBucketLifecycleCheck runs checkTableBucketLifecycle against a
// ledgerStore that also implements ext.TableBucketProvisioner and records every
// call, and returns what it recorded.
func runTableBucketLifecycleCheck(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{
			Placement:     "default",
			ImplementsExt: map[string]bool{"ext.TableBucketProvisioner": true},
		})
	rec.run(func() { checkTableBucketLifecycle(rec, env) })
	if rec.failures > 0 {
		t.Errorf("the check reported %d failure(s) against a conforming table-bucket provisioner, "+
			"so the calls it made may be error handling rather than the drive: %v",
			rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// runTableBucketGrantCheck runs checkTableBucketGrant the same way.
func runTableBucketGrantCheck(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{
			Placement:     "default",
			ImplementsExt: map[string]bool{"ext.TableBucketProvisioner": true},
		})
	rec.run(func() { checkTableBucketGrant(rec, env) })
	if rec.failures > 0 {
		t.Errorf("the check reported %d failure(s) against a conforming table-bucket provisioner, "+
			"so the calls it made may be error handling rather than the drive: %v",
			rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// runVectorBucketLifecycleCheck runs checkVectorBucketLifecycle the same way.
func runVectorBucketLifecycleCheck(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{
			Placement:     "default",
			ImplementsExt: map[string]bool{"ext.VectorBucketProvisioner": true},
		})
	rec.run(func() { checkVectorBucketLifecycle(rec, env) })
	if rec.failures > 0 {
		t.Errorf("the check reported %d failure(s) against a conforming vector-bucket provisioner, "+
			"so the calls it made may be error handling rather than the drive: %v",
			rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// runVectorBucketGrantCheck runs checkVectorBucketGrant the same way.
func runVectorBucketGrantCheck(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{
			Placement:     "default",
			ImplementsExt: map[string]bool{"ext.VectorBucketProvisioner": true},
		})
	rec.run(func() { checkVectorBucketGrant(rec, env) })
	if rec.failures > 0 {
		t.Errorf("the check reported %d failure(s) against a conforming vector-bucket provisioner, "+
			"so the calls it made may be error handling rather than the drive: %v",
			rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// runExternalGrantCheck runs the external-grant constraint check against a granter
// that records every call, and returns what it recorded.
func runExternalGrantCheck(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{
			Placement:     "default",
			ImplementsExt: map[string]bool{"ext.ExternalAccessGranter": true},
		})

	rec.run(func() { checkExternalGrantConstraints(rec, env) })

	// A check that failed against a conforming granter may have made its calls on
	// an error path rather than by driving the port, so the record would not mean
	// what this test reads it as.
	if rec.failures > 0 {
		t.Errorf("the check reported %d failure(s) against a conforming granter, so the calls it "+
			"made may be error handling rather than the drive: %v", rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// callLedger records every port call made through the instrumented ports.
type callLedger struct {
	mu    sync.Mutex
	calls []string
}

// record appends one call. Locked because a check may drive a port concurrently.
func (l *callLedger) record(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, name)
}

// ledgerStore is an ObjectStore whose grant methods conform and are recorded.
//
// The external-grant state is a real record rather than a constraint list,
// because the check under test reads it back: it asserts the stored level, the
// stored constraint set and the ownership flag, so a stub that kept only
// constraints could not satisfy a conforming run and this test would report the
// check as broken. Keeping it genuinely conforming is the whole basis for reading
// its call record as "the check drove the port" rather than "the check errored".
type ledgerStore struct {
	ledger  *callLedger
	buckets map[string]bool
	grants  map[string]ext.ExternalGrant
	// extBuckets remembers the ref issued for a table/vector bucket name, so a
	// second Ensure of the same spec adopts the same ref rather than minting a
	// new one -- checkTableBucketLifecycle and checkVectorBucketLifecycle both
	// assert on that.
	extBuckets map[string]string
	// pairGrants is the core Granter's state, keyed on the (resource, identity)
	// pair the interface is keyed on.
	pairGrants map[ledgerPair]compute.AccessLevel
}

// ledgerPair is a (resource, identity) grant key.
type ledgerPair struct{ resource, identity string }

func (s *ledgerStore) EnsureBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if s.buckets == nil {
		s.buckets = map[string]bool{}
	}
	s.buckets[spec.Name] = true
	return &compute.Bucket{
		Ref:  compute.Ref{Provider: "ledger", Kind: compute.KindBucket, ID: "bucket/" + spec.Name},
		Name: spec.Name, Class: compute.ObjectClassStandard, URI: "ledger://" + spec.Name, Spec: spec,
	}, nil
}

func (s *ledgerStore) DescribeBucket(_ context.Context, _ compute.Ref) (*compute.Bucket, error) {
	return nil, fmt.Errorf("%w: ledger", compute.ErrNotFound)
}
func (s *ledgerStore) DeleteBucket(context.Context, compute.Ref) error { return nil }
func (s *ledgerStore) EmptyBucket(context.Context, compute.Ref) error  { return nil }

// Grant, Revoke and DescribeGrant keep real per-pair state, and record.
//
// They were no-ops returning nil, with an unconditional ErrNotFound from the
// read-back, which was adequate while nothing drove them through this store:
// this fixture exists for the ext ports, and the core grant checks run against
// the real providers. USOSS-44 changed that by driving Grant and Revoke on the
// ext bucket ports here, and USOSS-73 added a read-back to those ports -- so a
// stub now produces a failure that is the FIXTURE's rather than a provider's,
// and this file's whole premise is that a failing check means the recorded
// calls may be error handling instead of a drive.
//
// Keyed on the pair, because that is what compute.Granter is keyed on. Keyed on
// the identity alone, this fixture would exhibit
// fake.DefectGrantClobbersOtherResources.
func (s *ledgerStore) Grant(_ context.Context, resource, identity compute.Ref,
	level compute.AccessLevel) error {
	s.ledger.record("Grant")
	if s.pairGrants == nil {
		s.pairGrants = map[ledgerPair]compute.AccessLevel{}
	}
	// Assignment, not accumulation: last write wins on the level.
	s.pairGrants[ledgerPair{resource: resource.ID, identity: identity.ID}] = level
	return nil
}

func (s *ledgerStore) Revoke(_ context.Context, resource, identity compute.Ref) error {
	s.ledger.record("Revoke")
	delete(s.pairGrants, ledgerPair{resource: resource.ID, identity: identity.ID})
	return nil
}

// EnsureTableBucket implements [ext.TableBucketProvisioner] and records the
// call. Class other than standard is refused, mirroring compute/aws and
// compute/fake: neither S3 Tables nor S3 Vectors has a storage class.
func (s *ledgerStore) EnsureTableBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	s.ledger.record("EnsureTableBucket")
	return s.ensureExtBucket(spec, "table")
}

// DeleteTableBucket implements [ext.TableBucketProvisioner] and records the call.
func (s *ledgerStore) DeleteTableBucket(ctx context.Context, ref compute.Ref) error {
	s.ledger.record("DeleteTableBucket")
	return s.DeleteBucket(ctx, ref)
}

// EnsureVectorBucket implements [ext.VectorBucketProvisioner] and records the
// call.
func (s *ledgerStore) EnsureVectorBucket(_ context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	s.ledger.record("EnsureVectorBucket")
	return s.ensureExtBucket(spec, "vector")
}

// DeleteVectorBucket implements [ext.VectorBucketProvisioner] and records the
// call.
func (s *ledgerStore) DeleteVectorBucket(ctx context.Context, ref compute.Ref) error {
	s.ledger.record("DeleteVectorBucket")
	return s.DeleteBucket(ctx, ref)
}

// ensureExtBucket is the shared body of EnsureTableBucket and
// EnsureVectorBucket -- not called "Ensure" and not shared through an
// interface, so it carries no method name of its own for the AST binding to
// find; the two exported methods above are what the coverage tooling reads.
func (s *ledgerStore) ensureExtBucket(spec compute.BucketSpec, kind string) (*compute.Bucket, error) {
	if spec.Class != "" && spec.Class != compute.ObjectClassStandard {
		return nil, fmt.Errorf("ledger: a %s bucket has no storage class, and %q was named: %w",
			kind, spec.Class, compute.ErrInvalidSpec)
	}
	if s.buckets == nil {
		s.buckets = map[string]bool{}
	}
	id, adopted := s.extBuckets[spec.Name]
	if !adopted {
		if s.extBuckets == nil {
			s.extBuckets = map[string]string{}
		}
		id = kind + "-bucket/" + spec.Name
		s.extBuckets[spec.Name] = id
	}
	s.buckets[spec.Name] = true
	return &compute.Bucket{
		Ref:   compute.Ref{Provider: "ledger", Kind: compute.KindBucket, ID: id},
		Name:  spec.Name,
		Class: compute.ObjectClassStandard,
		URI:   "ledger://" + kind + "/" + spec.Name,
		Spec:  compute.BucketSpec{Name: spec.Name, Class: compute.ObjectClassStandard},
	}, nil
}

var (
	_ ext.TableBucketProvisioner  = (*ledgerStore)(nil)
	_ ext.VectorBucketProvisioner = (*ledgerStore)(nil)
)

// DescribeGrant is not driven by the check under test -- it is a core Granter
// method and this fixture exists for the ext port -- so it reports the absence
// the contract specifies rather than inventing a grant.
func (s *ledgerStore) DescribeGrant(_ context.Context, resource,
	identity compute.Ref) (*compute.GrantInfo, error) {
	s.ledger.record("DescribeGrant")
	level, ok := s.pairGrants[ledgerPair{resource: resource.ID, identity: identity.ID}]
	if !ok {
		return nil, fmt.Errorf("%w: ledger: no grant on %s for %s", compute.ErrNotFound,
			resource, identity)
	}
	return &compute.GrantInfo{Resource: resource, Identity: identity, Level: level}, nil
}

// GrantExternal conforms to the contract and records that it was called.
func (s *ledgerStore) GrantExternal(_ context.Context, _ compute.Ref,
	principal ext.ExternalPrincipal, level compute.AccessLevel) error {
	s.ledger.record("GrantExternal")
	if principal.ID == "" {
		return fmt.Errorf("%w: ledger: no principal", compute.ErrInvalidSpec)
	}
	if len(principal.Constraints) == 0 {
		return fmt.Errorf("%w: ledger: no constraints", compute.ErrInvalidSpec)
	}
	if s.grants == nil {
		s.grants = map[string]ext.ExternalGrant{}
	}
	// Assignment, not append: a repeated grant to one principal replaces the
	// previous one, which is what the contract says and what the check now reads
	// back.
	s.grants[principal.ID] = ext.ExternalGrant{
		Principal: ext.ExternalPrincipal{
			ID:          principal.ID,
			Constraints: append([]string(nil), principal.Constraints...),
		},
		Level:   level,
		Managed: true,
	}
	return nil
}

// RevokeExternal conforms and records.
func (s *ledgerStore) RevokeExternal(_ context.Context, _ compute.Ref,
	principal ext.ExternalPrincipal) error {
	s.ledger.record("RevokeExternal")
	delete(s.grants, principal.ID)
	return nil
}

// ExternalGrants conforms and records.
//
// Ordered, and empty-not-nil for a resource with no grants, because both are
// things the contract states and the check under test asserts.
func (s *ledgerStore) ExternalGrants(_ context.Context, _ compute.Ref) ([]ext.ExternalGrant, error) {
	s.ledger.record("ExternalGrants")
	out := make([]ext.ExternalGrant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b ext.ExternalGrant) int {
		return strings.Compare(a.Principal.ID, b.Principal.ID)
	})
	return out, nil
}

// ledgerProvider is the smallest provider that reaches the check under test.
type ledgerProvider struct{ ledger *callLedger }

func (p *ledgerProvider) Name() string { return "ledger" }
func (p *ledgerProvider) Capabilities() compute.CapabilitySet {
	caps := compute.NewCapabilitySet()
	caps[compute.CapObjectStore] = struct{}{}
	caps[compute.CapSecretStore] = struct{}{}
	// Needed by checkTableBucketGrant / checkVectorBucketGrant (USOSS-44), which
	// skip without it. Harmless to the other bindings sharing this provider:
	// none of them asserts on its absence.
	caps[compute.CapWorkloadGrants] = struct{}{}
	return caps
}
func (p *ledgerProvider) ObjectStores() (compute.ObjectStore, error) {
	return &ledgerStore{ledger: p.ledger}, nil
}

func (p *ledgerProvider) Identities() compute.IdentityService { return &ledgerIdentities{} }

// ledgerIdentities is the smallest IdentityService that satisfies
// [Env.ContainerIdentity]: it mints a stable ref per name and never fails.
// checkTableBucketGrant / checkVectorBucketGrant (USOSS-44) are the only
// bindings that reach it.
type ledgerIdentities struct{}

func (ledgerIdentities) EnsureWorkloadIdentity(_ context.Context, spec compute.WorkloadIdentitySpec) (*compute.WorkloadIdentity, error) {
	return &compute.WorkloadIdentity{
		Ref: compute.Ref{Provider: "ledger", Kind: compute.KindWorkloadIdentity, ID: "identity/" + spec.Name},
	}, nil
}

func (ledgerIdentities) DescribeWorkloadIdentity(_ context.Context, ref compute.Ref) (*compute.WorkloadIdentity, error) {
	return &compute.WorkloadIdentity{Ref: ref}, nil
}

func (ledgerIdentities) DeleteWorkloadIdentity(context.Context, compute.Ref) error { return nil }
func (p *ledgerProvider) Registry() (compute.ImageRegistry, error) {
	return nil, compute.Unsupported("ledger", compute.CapImageRegistry)
}
func (p *ledgerProvider) Builder() (compute.ImageBuilder, error) {
	return nil, compute.Unsupported("ledger", compute.CapImageBuild)
}
func (p *ledgerProvider) Containers() (compute.ContainerRuntime, error) {
	return nil, compute.Unsupported("ledger", compute.CapContainerService)
}
func (p *ledgerProvider) Functions() (compute.FunctionRuntime, error) {
	return nil, compute.Unsupported("ledger", compute.CapFunction)
}
func (p *ledgerProvider) Relational() (compute.RelationalProvisioner, error) {
	return nil, compute.Unsupported("ledger", compute.CapRelationalDatabase)
}
func (p *ledgerProvider) KeyValues() (compute.KeyValueProvisioner, error) {
	return nil, compute.Unsupported("ledger", compute.CapKeyValueTable)
}
func (p *ledgerProvider) Secrets() (compute.SecretStore, error) {
	return &ledgerSecrets{ledger: p.ledger}, nil
}

// recordingTB captures what a check reports instead of failing the outer test.
//
// Fatalf and Skipf STOP, the way the real ones do. A shim that recorded them and
// returned would let a check run past a point a real run could never reach, so the
// call record would include calls no real execution makes — an instrument that
// reports more than happened, in a test whose whole subject is instruments that
// report more than happened. The check bound here today uses only Errorf, so
// nothing depends on this yet; the next binding would have inherited it silently.
type recordingTB struct {
	*testing.T
	failures int
	messages []string
}

// stopped is what Fatalf and Skipf panic with, recovered by [recordingTB.run].
type stopped struct{ why string }

// run invokes fn and returns when it completes or stops.
func (r *recordingTB) run(fn func()) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		if _, ok := v.(stopped); ok {
			return
		}
		panic(v)
	}()
	fn()
}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.failures++
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	panic(stopped{why: "Fatalf"})
}

func (r *recordingTB) Skipf(format string, args ...any) {
	r.messages = append(r.messages, "SKIP: "+fmt.Sprintf(format, args...))
	panic(stopped{why: "Skipf"})
}

// --- the secret store's delete-scope family -----------------------------------

// runCheckDeleteScope runs the one delete-scope check that reads, against a
// recording secret store, and returns what it called. The Get claim on the
// undriven-method table names this check by its exact name, so the binding runs
// exactly it -- running the sibling too would report calls the claim did not
// name, and running neither would be an empty assertion.
func runCheckDeleteScope(t *testing.T) [][]string {
	t.Helper()
	ledger := &callLedger{}
	rec := &recordingTB{T: t}
	env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
		Options{Placement: "default", ImplementsExt: map[string]bool{}})
	rec.run(func() { checkDeleteScope(rec, env) })
	if rec.failures > 0 {
		t.Errorf("the delete-scope check reported %d failure(s) against a conforming secret "+
			"store, so the calls it made may be error handling rather than the drive: %v",
			rec.failures, rec.messages)
	}
	return [][]string{ledger.calls}
}

// runDeleteScopeChecks runs both delete-scope checks against a recording secret
// store and returns what they called.
//
// A wildcard claim names a family, so its execution binding runs the WHOLE family
// and unions the calls. Running one and reporting the pattern covered would be the
// binding asserting less than the claim.
func runDeleteScopeChecks(t *testing.T) [][]string {
	t.Helper()
	var calls [][]string
	for _, fn := range []func(TB, *Env){checkDeleteScope, checkDeleteScopeRefusesEmpty} {
		ledger := &callLedger{}
		rec := &recordingTB{T: t}
		env := newEnv(rec, func(TB) compute.Provider { return &ledgerProvider{ledger: ledger} },
			Options{Placement: "default", ImplementsExt: map[string]bool{}})
		rec.run(func() { fn(rec, env) })
		if rec.failures > 0 {
			t.Errorf("a delete-scope check reported %d failure(s) against a conforming secret "+
				"store, so the calls it made may be error handling rather than the drive: %v",
				rec.failures, rec.messages)
		}
		calls = append(calls, ledger.calls)
	}
	return calls
}

// ledgerSecrets is a conforming SecretStore that records every call.
//
// Conforming matters: a stub that refused everything would drive the checks down
// their error paths, and the calls recorded would be the ones a failing provider
// provokes rather than the ones the check makes when the port works.
type ledgerSecrets struct {
	ledger *callLedger
	mu     sync.Mutex
	// stored maps a scope to the secrets in it, by name.
	stored map[string]map[string]string
}

func (s *ledgerSecrets) Put(_ context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	s.ledger.record("Put")
	if spec.Scope == "" || spec.Name == "" {
		return compute.StoredSecret{}, fmt.Errorf("%w: ledger: a secret needs a scope and a name",
			compute.ErrInvalidSpec)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stored == nil {
		s.stored = map[string]map[string]string{}
	}
	if s.stored[spec.Scope] == nil {
		s.stored[spec.Scope] = map[string]string{}
	}
	s.stored[spec.Scope][spec.Name] = compute.RevealSecret(spec.Value)
	return compute.StoredSecret{
		Ref: compute.Ref{
			Provider: "ledger", Kind: compute.KindSecret,
			ID: "parameter/" + spec.Scope + "/" + spec.Name,
		},
		// This double keeps no history, so it declares no revision rather than
		// claiming "1": an empty version is "current", which is the truth here.
		Version: "",
	}, nil
}

func (s *ledgerSecrets) Get(_ context.Context, ref compute.Ref) (compute.SecretValue, error) {
	s.ledger.record("Get")
	scope, name, ok := splitLedgerSecretRef(ref)
	if !ok {
		return compute.SecretValue{}, fmt.Errorf("%w: ledger: %s", compute.ErrForeignRef, ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, present := s.stored[scope][name]
	if !present {
		return compute.SecretValue{}, fmt.Errorf("%w: ledger: %s", compute.ErrNotFound, ref)
	}
	return compute.NewSecretValue(v), nil
}

func (s *ledgerSecrets) Describe(_ context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	s.ledger.record("Describe")
	scope, name, ok := splitLedgerSecretRef(ref)
	if !ok {
		return nil, fmt.Errorf("%w: ledger: %s", compute.ErrForeignRef, ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, present := s.stored[scope][name]; !present {
		return nil, fmt.Errorf("%w: ledger: %s", compute.ErrNotFound, ref)
	}
	// Global: this store keys a secret by scope and name only, so any workload
	// can bind any secret it holds. It never returns the value — Describe is
	// the metadata read, and the ledger exists to prove a check uses it that
	// way.
	return &compute.SecretInfo{Ref: ref, PlacementScope: compute.SecretPlacementGlobal}, nil
}

func (s *ledgerSecrets) Delete(_ context.Context, ref compute.Ref) error {
	s.ledger.record("Delete")
	scope, name, ok := splitLedgerSecretRef(ref)
	if !ok {
		return fmt.Errorf("%w: ledger: %s", compute.ErrForeignRef, ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.stored[scope], name)
	return nil
}

func (s *ledgerSecrets) DeleteScope(_ context.Context, scope string) error {
	s.ledger.record("DeleteScope")
	if scope == "" {
		// Fails CLOSED, which is the invariant the second check is about: an empty
		// scope is not "everything".
		return fmt.Errorf("%w: ledger: an empty scope names no scope", compute.ErrInvalidSpec)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.stored, scope)
	return nil
}

// splitLedgerSecretRef undoes the ID this store issues.
func splitLedgerSecretRef(ref compute.Ref) (scope, name string, ok bool) {
	if ref.Provider != "ledger" || ref.Kind != compute.KindSecret {
		return "", "", false
	}
	rest, ok := strings.CutPrefix(ref.ID, "parameter/")
	if !ok {
		return "", "", false
	}
	scope, name, ok = strings.Cut(rest, "/")
	return scope, name, ok
}
