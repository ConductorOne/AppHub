// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/conformance"
	"github.com/conductorone/apphub/compute/fake"
)

// A conformance suite nobody has tried to defeat is an assertion, not a gate.
//
// The repository's standing rule — added after an independent reviewer defeated
// three of the CI gates on the first pull request with working fixtures — is that
// a check needs a fixture that fails before the check exists and passes after.
// This file is that fixture for the conformance suite: for every invariant the
// suite claims to enforce there is a deliberately non-conformant provider, and
// the test asserts that the *named* invariant is the one that fails. Asserting
// only "something failed" would pass for a suite whose checks all crash.

// fullCaps is the capability set for a provider that can do everything.
func fullCaps() []compute.Capability { return fake.AllCapabilities() }

// withoutCaps returns every capability except those named, for the configurations
// whose whole point is that a capability is missing.
func withoutCaps(drop ...compute.Capability) []compute.Capability {
	dropped := map[compute.Capability]bool{}
	for _, c := range drop {
		dropped[c] = true
	}
	var out []compute.Capability
	for _, c := range fullCaps() {
		if !dropped[c] {
			out = append(out, c)
		}
	}
	return out
}

func TestConformanceSuiteCatchesNonConformance(t *testing.T) {
	t.Parallel()

	cases := []struct {
		// what the defect is, in the reader's terms.
		what string
		cfg  fake.Config
		// ensureBudget overrides the suite's prompt-return budget. Only the
		// blocking-Ensure case needs it: a tight budget everywhere else would turn
		// a loaded machine into a flaky failure rather than a real one.
		ensureBudget time.Duration
		// expect names the checks that must fail. Every one of them, not just one
		// of them: a defect that trips a different invariant than the one it
		// violates would mean the suite's diagnosis is wrong even though its
		// verdict is right.
		expect []string
	}{
		{
			// The entry USOSS-32 found the retry gate did not have. A check that
			// has never been shown to fail is an assertion; adding a sentinel
			// without one would leave every provider free to keep mapping
			// denials to ErrFailed, which is where they all were.
			what: "collapses an authorization failure into ErrFailed",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectDenialIsTerminal}},
			expect: []string{
				"provider/an-authorization-failure-is-ErrNotPermitted",
			},
		},
		{
			what: "advertises a capability whose accessor still refuses",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectCapabilityLie}},
			expect: []string{
				"provider/capability-accessor-agreement",
			},
		},
		{
			what: "refuses an absent capability with an error that does not wrap ErrUnsupported",
			cfg: fake.Config{
				Capabilities: withoutCaps(compute.CapKeyValueTable, compute.CapFunction),
				Defects:      []fake.Defect{fake.DefectUntypedRefusal},
			},
			expect: []string{
				"provider/refusals-are-typed-and-named",
			},
		},
		{
			what: "reports a foreign Ref as ErrNotFound",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectForeignRefIsNotFound}},
			expect: []string{
				"port/container-service/foreign-refs-are-refused",
				"port/bucket/foreign-refs-are-refused",
				"port/secret/foreign-refs-are-refused",
				// The pull-grant surface, added by USOSS-39: naming it here is
				// what makes this entry a claim about a class — every reference
				// this provider did not issue — rather than about three ports.
				"grants/image-repository/pull-grants-refuse-a-foreign-ref",
			},
		},
		{
			what: "derives a different physical resource from the same logical name each time",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectNonDeterministicNames}},
			expect: []string{
				"port/container-service/ensure-is-idempotent",
				"port/container-service/name-is-deterministic-across-instances",
				"port/bucket/ensure-is-idempotent",
			},
		},
		{
			what: "implements Ensure additively, so a removed element survives",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectCreateOrAdd}},
			expect: []string{
				"port/container-service/ensure-converges-rather-than-accumulating",
				"port/scheduled-job/ensure-converges-rather-than-accumulating",
				"port/function/ensure-converges-rather-than-accumulating",
			},
		},
		{
			what: "blocks inside an asynchronous Ensure until the resource is ready",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBlockingEnsure}},
			// The defect waits 150ms inline; 50ms is over budget by enough that a
			// scheduling hiccup cannot explain it.
			ensureBudget: 50 * time.Millisecond,
			expect: []string{
				"port/container-service/async/ensure-does-not-block",
				"port/relational-database/async/ensure-does-not-block",
			},
		},
		{
			what: "fails when asked to delete something that is already gone",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectDeleteNotIdempotent}},
			expect: []string{
				"port/container-service/delete-is-idempotent",
				"port/bucket/delete-is-idempotent",
				"port/workload-identity/delete-is-idempotent",
			},
		},
		{
			what: "reports a deleted asynchronous resource as an error instead of PhaseGone",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectDescribeErrorAfterDelete}},
			expect: []string{
				"port/container-service/async/describe-after-delete-is-gone",
				"port/key-value-table/async/describe-after-delete-is-gone",
			},
		},
		{
			what: "waits well past its deadline",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectWaitIgnoresDeadline}},
			expect: []string{
				"port/container-service/async/wait-honours-its-deadline",
			},
		},
		{
			what: "waits instead of refusing when given neither a timeout nor a context deadline",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectWaitWithoutDeadline}},
			expect: []string{
				"port/container-service/async/wait-requires-a-deadline",
			},
		},
		{
			what: "never reports progress",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectNoProgress}},
			expect: []string{
				"port/container-service/async/wait-reports-progress",
				"port/function/async/wait-reports-progress",
			},
		},
		{
			what: "adopts a resource this platform does not own",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectAdoptsUnowned}},
			expect: []string{
				"port/container-service/refuses-a-resource-it-does-not-own",
				"port/bucket/refuses-a-resource-it-does-not-own",
			},
		},
		{
			what: "adds a second grant instead of narrowing the level",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectGrantIsAdditive}},
			expect: []string{
				"grants/bucket/access-level-decides-what-succeeds",
				"grants/key-value-table/access-level-decides-what-succeeds",
				// USOSS-73. The read-back sees the stored level, so the two
				// checks that could previously only observe this through the
				// data plane now observe it through the interface -- which is
				// what makes it catchable on a provider that supplies no
				// data-plane hooks. The idempotence check is the pointed one:
				// it is named for last-write-wins and used to emit a note
				// saying it could not assert it.
				"grants/bucket/the-read-back-reports-what-stands",
				"grants/key-value-table/the-read-back-reports-what-stands",
				"grants/bucket/grant-is-idempotent-and-last-write-wins",
				"grants/key-value-table/grant-is-idempotent-and-last-write-wins",
			},
		},
		{
			what: "keys its grants on the identity alone, so a grant on one resource destroys another's",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectGrantClobbersOtherResources}},
			expect: []string{
				"grants/bucket/a-grant-names-one-resource",
				"grants/key-value-table/a-grant-names-one-resource",
				// USOSS-73, and the reason the read-back check is not redundant
				// with the one above it: that one needs Options.Read, and this
				// defect is available to any substrate with a per-identity
				// container for permissions -- which is most of them.
				"grants/bucket/the-read-back-is-keyed-on-the-pair",
				"grants/key-value-table/the-read-back-is-keyed-on-the-pair",
			},
		},
		{
			// The defect USOSS-73 was opened over. Before the read-back, the only
			// check that could see this was the behavioural one, so a provider
			// with no data-plane hooks and a revoke that did nothing passed every
			// grant invariant there was.
			//
			// TestTheReadBackCatchesANoOpRevokeWithNoDataPlaneHooks is the half of
			// that claim this entry cannot make: here the fake supplies Read and
			// Write, so several checks fire and none of them is isolated.
			what: "returns nil from every Revoke and removes no grant",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectRevokeDoesNothing}},
			expect: []string{
				"grants/bucket/the-read-back-reports-what-stands",
				"grants/key-value-table/the-read-back-reports-what-stands",
				"grants/bucket/the-read-back-is-keyed-on-the-pair",
				"grants/key-value-table/the-read-back-is-keyed-on-the-pair",
				// The two ext bucket ports too, and those are the pointed ones:
				// USOSS-44's obligation entry for them said in as many words
				// that "a provider whose Grant and Revoke both return nil and do
				// nothing would satisfy" their check, because no Options hook
				// performs a data-plane operation through a table or vector
				// bucket on any provider. The read-back needs no such hook, so
				// that sentence is now false and this row is what says so.
				"ext/table-bucket/table-bucket-grant-then-table-bucket-revoke",
				"ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke",
			},
		},
		{
			// The ticket's literal example: "a provider whose RevokeExternal does
			// nothing at all passed the full conformance suite and the entire fake
			// package -- measured, not hypothesised." One check catches it, and
			// every assertion that check makes about stored state is a read-back
			// that did not exist when that sentence was written.
			what: "returns nil from RevokeExternal and leaves the cross-domain grant standing",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectRevokeExternalDoesNothing}},
			expect: []string{
				"grants/bucket/an-external-grant-is-constrained-and-reads-back",
			},
		},
		{
			what: "fails when revoking a grant that was never made",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectRevokeAbsentFails}},
			expect: []string{
				"grants/bucket/revoking-an-absent-grant-is-nil",
				// And on the pull-grant surface, added by USOSS-39. Teardown
				// re-runnability is a property of every revoke this provider has,
				// not of the bucket port, and naming both is what says so.
				"grants/image-repository/revoking-an-absent-pull-grant-is-nil",
			},
		},
		{
			what: "interpolates secret material into an error message",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSecretInError}},
			expect: []string{
				"security/secret-material-does-not-appear-in-errors",
			},
		},
		{
			what: "resolves a secret value into a rendered workload definition",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSecretInRendered}},
			expect: []string{
				"security/secret-material-does-not-appear-in-rendered-artefacts",
			},
		},
		{
			what: "rotates the relational admin password on a re-Ensure",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectRotatesAdminPassword}},
			expect: []string{
				"security/relational-admin-password-is-not-rotated",
			},
		},
		{
			what: "keeps the live database name and admin username on a re-Ensure that changed them",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSubstitutesImmutableField}},
			expect: []string{
				"port/relational-database/an-immutable-field-is-not-silently-substituted",
			},
		},
		{
			what: "leaves anonymous read enabled on a bucket created with PublicAccess false",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectPublicByDefault}},
			expect: []string{
				"security/bucket-public-access-is-off-by-default",
			},
		},
		{
			what: "creates a TLS listener with no resolvable certificate",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectTLSWithoutCertificate}},
			expect: []string{
				"security/tls-listener-requires-a-resolvable-certificate",
			},
		},
		{
			what: "hands back a standard bucket when a zonal one was asked for",
			cfg: fake.Config{
				Capabilities: withoutCaps(compute.CapObjectStoreZonal),
				Defects:      []fake.Defect{fake.DefectSilentZonalFallback},
			},
			expect: []string{
				"capabilities/zonal-object-storage",
			},
		},
		{
			what: "accepts a workload capability it does not advertise and quietly drops it",
			cfg: fake.Config{
				Capabilities: withoutCaps(compute.CapModelInference),
				Defects:      []fake.Defect{fake.DefectSilentCapabilityDrop},
			},
			expect: []string{
				"capabilities/workload-capabilities-are-refused-when-absent",
			},
		},
		{
			what: "lets the workload's own identity open sessions against other workloads",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectExecWidensIdentity}},
			expect: []string{
				"security/exec-does-not-widen-the-workload-identity",
			},
		},
		{
			what: "serves an application's public hostname over HTTP without being asked to",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectPlaintextRoute}},
			expect: []string{
				"security/route-without-tls-is-refused",
			},
		},
		{
			what: "binds a secret from one placement into a workload in another",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectCopiesSecretAcrossPlacements}},
			expect: []string{
				"security/secrets-do-not-cross-placements",
			},
		},
		{
			what: "widens a platform-ingress rule to the internet when no proxy is configured",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectWidensIngressWithoutProxy}},
			expect: []string{
				"security/missing-ingress-proxy-is-an-error-not-an-open-port",
			},
		},
		{
			what: "demands a substrate network identifier as an interface input",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectRequiresNetworkIdentifier}},
			expect: []string{
				"abstraction/placement-is-an-operator-configured-name",
			},
		},
		{
			// The retry gate was the one check in the suite with no entry in this
			// table, so nothing had ever shown it could fail. USOSS-32.
			what: "maps a retryable substrate failure onto ErrFailed",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectTransientIsTerminal}},
			expect: []string{
				"provider/a-retryable-failure-is-ErrTransient",
			},
		},
		{
			// The defect that makes Describe reviewable. The operation is
			// permitted to exist because it returns a locator and a location
			// rather than material, so a suite that cannot catch a provider
			// returning material through it is not checking the property that
			// justified the operation. USOSS-15.
			what: "returns a stored secret's value through the metadata read",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSecretValueInDescribe}},
			expect: []string{
				"security/secret-metadata-read-returns-no-material",
			},
		},
		{
			// The leak a provider whose only material-carrying port is its secret
			// store can have. DefectSecretInRendered needs a workload to bind a
			// secret into, so it cannot exhibit this one. USOSS-32.
			what: "prints stored secret values in its own substrate listing",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSecretValueInStoreListing}},
			expect: []string{
				"security/secret-material-does-not-appear-in-rendered-artefacts",
			},
		},
		{
			// The partial-emptying shape USOSS-48 measured against a live leak:
			// one resource's artefact dropped from the enumeration while
			// everything else renders. checkSecretsNotInRendered's emptiness
			// gate cannot see this alone -- see
			// TestThePartialArtefactDropDefeatsTheAggregateCheckButNotCorrespondence
			// in vacuity_test.go for the side-by-side proof -- so only the
			// correspondence check is expected to fail here.
			what: "drops one resource's own rendered artefact while the rest of the substrate renders",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectDropsRenderedArtefact}},
			expect: []string{
				"security/every-planted-resource-has-a-rendered-artefact",
			},
		},
		// --- USOSS-39: the build port, the scale call, and the pull-grant
		// surface. All three were driven by no check at all before it, so none of
		// them had an entry here either — which is the same hole in the same
		// place, since a check with no fixture and a method with no check are the
		// same claim with different words.
		{
			what: "writes the build's own push credential into the build log",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildCredentialInLogs}},
			expect: []string{
				"security/build-credentials-do-not-appear-in-what-a-build-emits",
			},
		},
		{
			what: "returns a failing build whose error carries the push credential",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildCredentialInError}},
			expect: []string{
				"security/build-credentials-do-not-appear-in-what-a-build-emits",
			},
		},
		{
			what: "returns the push credential inside the build result's digest",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildCredentialInResult}},
			expect: []string{
				"security/build-credentials-do-not-appear-in-what-a-build-emits",
			},
		},
		{
			what: "puts what the builder read from the context into a failing build's error",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildOutputInError}},
			expect: []string{
				"security/build-output-does-not-appear-in-an-error",
			},
		},
		{
			// The PR #25 hazard, probed on this suite's own new checks: material
			// out, then a failure. A check that scanned only a successful build
			// would pass.
			what: "writes the build credential into the log and then fails",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildFailsAfterEmitting}},
			expect: []string{
				"security/build-credentials-do-not-appear-in-what-a-build-emits",
				// And this one, because the defect genuinely fails a build of a
				// legal context as well as leaking. Both are named because the
				// rule for this table is every check the defect violates, not
				// one of them: a fixture that trips two invariants and documents
				// one leaves the second undocumented, and a later change that
				// stopped it noticing would look like an unrelated improvement.
				"port/image-build/logs-receive-the-builder-output",
			},
		},
		{
			what: "writes nothing to the Logs writer a build was given",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectSilentBuild}},
			expect: []string{
				"port/image-build/logs-receive-the-builder-output",
			},
		},
		{
			what: "accepts a build with no destination and reports success",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildWithoutDestination}},
			expect: []string{
				"port/image-build/a-build-with-no-destination-is-refused",
			},
		},
		{
			// USOSS-39 named this channel and did not build it; USOSS-49 did.
			what: "folds the build's own push credential into the pushed image's metadata",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildCredentialInImageMetadata}},
			expect: []string{
				"security/build-credentials-do-not-appear-in-image-metadata",
			},
		},
		{
			// USOSS-39 named this obligation and did not build a check for it;
			// USOSS-49 did.
			what: "reports a zero (forever) default MaxAge for its build cache",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectBuildCacheDefaultIsForever}},
			expect: []string{
				"port/image-build/build-cache-default-is-not-forever",
			},
		},
		{
			what: "treats a scale to zero instances as a removal rather than a pause",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectScaleToZeroDeletes}},
			expect: []string{
				"port/container-service/scale-to-zero-pauses-rather-than-deletes",
			},
		},
		{
			what: "rewrites the spec when asked only to change the instance count",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectScaleRewritesTheSpec}},
			expect: []string{
				"port/container-service/scale-changes-only-the-instance-count",
			},
		},
		{
			what: "fails the second grant of a pull that is already granted",
			cfg:  fake.Config{Defects: []fake.Defect{fake.DefectPullGrantNotIdempotent}},
			expect: []string{
				"grants/image-repository/pull-grant-is-idempotent",
			},
		},
		{
			// The capability-negative one, so it needs a provider that does not
			// advertise the capability it is about.
			what: "accepts a pull grant without advertising the capability for it",
			cfg: fake.Config{
				Capabilities: withoutCaps(compute.CapImagePullGrants),
				Defects:      []fake.Defect{fake.DefectPullGrantWithoutCapability},
			},
			expect: []string{
				"grants/image-repository/pull-grants-refused-without-the-capability",
			},
		},
	}

	cases = append(cases, struct {
		what         string
		cfg          fake.Config
		ensureBudget time.Duration
		expect       []string
	}{
		what: "accepts a version-pinned secret binding and binds the current value anyway",
		cfg:  fake.Config{Defects: []fake.Defect{fake.DefectIgnoresSecretVersion}},
		expect: []string{
			"security/secret-version-pin-is-honoured-or-refused",
		},
	})

	for _, tc := range cases {
		tc := tc
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			cfg.ExtPorts = true
			factory, opts := newSuite(cfg)
			if tc.ensureBudget > 0 {
				opts.EnsureBudget = tc.ensureBudget
			}

			rep := conformance.Verify(t, factory, opts)
			for _, want := range tc.expect {
				if !rep.FailedCheck(want) {
					t.Errorf("a provider that %s passed %q.\n%s", tc.what, want, rep)
				}
			}
			if len(rep.Failures()) == 0 {
				t.Errorf("a provider that %s passed the whole suite", tc.what)
			}
		})
	}
}

// TestConformanceSuiteBaseline asserts that the provider the defect cases are
// derived from passes cleanly, so a failure above is evidence about the defect
// rather than about the suite.
//
// It also reports how many invariants went unverified. That number is the honest
// measure of the suite: the fake supplies every hook, so anything skipped here is
// an invariant the *interface* does not let a suite reach, not one this provider
// declined to be tested on.
func TestConformanceSuiteBaseline(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fake.Config{ExtPorts: true})
	rep := conformance.Verify(t, factory, opts)

	if failures := rep.Failures(); len(failures) > 0 {
		t.Errorf("the reference provider failed %d check(s):\n%s", len(failures), rep)
	}
	skipped := rep.Skipped()
	t.Logf("conformance baseline: %d checks, %d not verified", len(rep.Results), len(skipped))
	for _, s := range skipped {
		t.Logf("  not verified: %s", s.Check)
	}
	// The fake supplies every hook, so the only legitimate skips are invariants
	// the interface itself cannot express — today the two ports with no read-back
	// or no Wait, and the capability negatives that need a provider lacking the
	// capability. If this grows, something has quietly stopped being checked.
	const maxSkipped = 8
	if len(skipped) > maxSkipped {
		t.Errorf("%d checks went unverified against the reference provider, which supplies every "+
			"hook; at most %d are expected and the rest means an invariant has quietly stopped "+
			"being checked:\n%s", len(skipped), maxSkipped, rep)
	}
	// This asserted the opposite until the USOSS-2 amendment landed: the suite
	// used to record six contract observations against the reference provider,
	// one per gap it could not check through the interface. Every one of them is
	// closed now — each read-back carries its effective spec, the image registry
	// has a Describe, scheduled jobs are synchronous rather than asynchronous
	// with no Wait, and a certificate-less HTTPS listener is representable — so
	// a note here means a gap has reopened.
	//
	// Notes remain the right mechanism, and a provider that supplies fewer hooks
	// than the fake will still produce them. Zero is only the expectation for the
	// reference provider with the full harness.
	if len(rep.Notes) != 0 {
		t.Errorf("the suite recorded %d contract observation(s) against the reference provider, "+
			"which supplies every hook. Each one is an invariant the interface cannot express, "+
			"and the amendment that closed the previous six is meant to have left none:\n%s",
			len(rep.Notes), rep)
	}
}

// TestConformanceReportNamesThePortAndTheInvariant is the requirement that makes
// the suite usable by the six implementations that follow: a failure has to say
// which port, which invariant, and what happened. "assertion failed" would be
// useless to them.
func TestConformanceReportNamesThePortAndTheInvariant(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fake.Config{
		ExtPorts: true,
		Defects:  []fake.Defect{fake.DefectCreateOrAdd},
	})
	rep := conformance.Verify(t, factory, opts)

	const check = "port/container-service/ensure-converges-rather-than-accumulating"
	var found bool
	for _, r := range rep.Results {
		if r.Check != check {
			continue
		}
		found = true
		if !r.Failed() {
			t.Fatalf("%s passed against a provider that implements Ensure additively", check)
		}
		if r.Invariant == "" {
			t.Error("the result carries no invariant sentence")
		}
		joined := strings.Join(r.Messages, "\n")
		for _, want := range []string{"container-service", "violates", "converged"} {
			if !strings.Contains(joined, want) {
				t.Errorf("the failure message does not contain %q:\n%s", want, joined)
			}
		}
	}
	if !found {
		t.Fatalf("the report has no result for %q", check)
	}
}

// TestConvergenceIsNotVerifiedWithoutASubstrateObserver is the reviewer's
// lying-provider fixture, kept.
//
// The claim under review was that the effective-spec read-back closed the
// convergence gap and made Options.Rendered optional. It did not. A provider
// that reports the new spec from Describe/Wait/Status while leaving the old
// object in place satisfies every interface-level check, because every
// interface-level check asks the provider about itself. The reviewer built that
// wrapper and the named convergence check passed.
//
// The fix is not a cleverer interface check — there is no such thing, since the
// interface only ever returns what the provider says. It is that convergence is
// *not verified* without a substrate observer, and the report says so instead of
// going green.
func TestConvergenceIsNotVerifiedWithoutASubstrateObserver(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{})
	opts.Rendered = nil

	rep := conformance.Verify(t, factory, opts)

	const check = "port/container-service/ensure-converges-rather-than-accumulating"
	var found bool
	for _, r := range rep.Skipped() {
		if r.Check == check {
			found = true
			if !strings.Contains(strings.Join(r.Messages, " "), "Options.Rendered") {
				t.Errorf("the skip reason does not name what is missing: %v", r.Messages)
			}
		}
	}
	if !found {
		t.Errorf("%s did not report as unverified with no substrate observer. Either it passed — "+
			"in which case a provider that lies in its read-back is conformant, which is the "+
			"defect — or it is no longer scheduled:\n%s", check, rep)
	}
	if rep.FailedCheck(check) {
		t.Errorf("%s failed rather than reporting as unverified; a provider that supplies no "+
			"observer has not demonstrated non-convergence either", check)
	}
}

// --- the declining half of the version-pinning invariant --------------------

// noVersionProvider is a provider whose secret store reports no revisions — the
// shape compute/k8s has — wrapped around a fake that nonetheless accepts a
// pinned binding.
//
// It exists because the two halves of the pinning invariant are different
// failures and a fixture for one is not a fixture for the other. The case above
// covers an honourer that ignores the pin. This covers the worse one: a provider
// with nothing to pin to that accepts the pin anyway, so the caller believes it
// pinned a revision, the workload follows the latest value, and nothing said so.
//
// It is a wrapper rather than a new Defect on purpose. "Report no version" is not
// a way of being non-conformant — it is the correct behaviour for a substrate
// without revisions — so it does not belong in the shipped defect taxonomy. What
// is non-conformant is reporting no version and then accepting a pin, which is
// this wrapper plus the existing defect.
type noVersionProvider struct {
	compute.Provider
	inner *fake.Provider
	store compute.SecretStore
}

func (n noVersionProvider) Secrets() (compute.SecretStore, error) { return n.store, nil }

// underlying lets this file's harness helper reach the substrate hooks through
// the wrapper. The name is USOSS-32's; we independently added the same escape
// hatch within an hour of each other and theirs landed first, so this converges
// on it rather than adding a second spelling. See harness in fake_test.go.
func (n noVersionProvider) underlying() *fake.Provider { return n.inner }

type noVersionStore struct{ compute.SecretStore }

func (n noVersionStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	stored, err := n.SecretStore.Put(ctx, spec)
	stored.Version = ""
	return stored, err
}

func TestConformanceSuiteCatchesAPinAcceptedByAStoreWithNoRevisions(t *testing.T) {
	t.Parallel()
	inner, opts := newSuite(fake.Config{
		ExtPorts: true,
		Defects:  []fake.Defect{fake.DefectIgnoresSecretVersion},
	})
	// The declaration is the whole difference: this provider says its store has
	// no revisions, which is what makes accepting a pin a violation rather than
	// the honouring path.
	opts.HonoursSecretVersions = false
	factory := func(tb conformance.TB) compute.Provider {
		p := inner(tb)
		f, ok := p.(*fake.Provider)
		if !ok {
			tb.Fatalf("fake_test: expected a *fake.Provider")
		}
		store, err := p.Secrets()
		if err != nil {
			tb.Fatalf("Secrets(): %v", err)
		}
		return noVersionProvider{Provider: p, inner: f, store: noVersionStore{store}}
	}

	rep := conformance.Verify(t, factory, opts)
	const want = "security/secret-version-pin-is-honoured-or-refused"
	if !rep.FailedCheck(want) {
		t.Errorf("a store with no revisions that accepted a pinned binding passed %q; then the "+
			"typed refusal is not enforced and compute.SecretBinding.Version reintroduces the "+
			"silent degradation it was added to close.\n%s", want, rep)
	}
}

// TestTheReadBackCatchesANoOpRevokeWithNoDataPlaneHooks is the measurement
// USOSS-73 turns on, made where the claim actually lives.
//
// # The claim
//
// "A provider whose revoke does nothing at all passed the full conformance
// suite." That was true, and the table above cannot show why: the fake supplies
// Options.Read and Options.Write, so [fake.DefectRevokeDoesNothing] trips the
// behavioural checks there and the read-back looks like one more failure among
// several.
//
// The provider that got away with it is the one with no data-plane harness. Those
// hooks have to perform a real operation as a workload identity, which is the
// hardest thing a provider author has to build, and the checks that need them
// SKIP without them -- so the invariant was not weakly asserted, it was not
// asserted.
//
// # What this asserts, in both directions
//
// With Read and Write removed and the defect armed:
//
//   - the behavioural checks skip, which is the "before" state -- they are the
//     ones that used to be the only witness;
//   - the read-back checks fail, which is the "after".
//
// Both halves are needed. Asserting only the failure would leave a reader unable
// to tell a new capability from a duplicate of an existing one, and asserting
// only the skip would prove the old gap without proving it closed.
func TestTheReadBackCatchesANoOpRevokeWithNoDataPlaneHooks(t *testing.T) {
	t.Parallel()

	factory, opts := newSuite(fake.Config{
		ExtPorts: true,
		Defects:  []fake.Defect{fake.DefectRevokeDoesNothing},
	})
	// The provider under test is one that supplied no data-plane harness. This is
	// the whole point of the fixture, so it is done by clearing the hooks rather
	// than by configuring a second provider: the substrate is identical and the
	// only variable is what the suite can observe with.
	opts.Read = nil
	opts.Write = nil

	rep := conformance.Verify(t, factory, opts)

	skipped := map[string]bool{}
	for _, r := range rep.Skipped() {
		skipped[r.Check] = true
	}
	for _, name := range []string{
		"grants/bucket/access-level-decides-what-succeeds",
		"grants/key-value-table/access-level-decides-what-succeeds",
		"grants/bucket/a-grant-names-one-resource",
		"grants/key-value-table/a-grant-names-one-resource",
	} {
		if !skipped[name] {
			t.Errorf("%q did not skip without Options.Read and Options.Write. If it can now run "+
				"without them, this fixture no longer describes the provider the gap existed for "+
				"and the argument below needs rewriting rather than the assertion relaxing", name)
		}
	}

	for _, name := range []string{
		"grants/bucket/the-read-back-reports-what-stands",
		"grants/key-value-table/the-read-back-reports-what-stands",
		"grants/bucket/the-read-back-is-keyed-on-the-pair",
		"grants/key-value-table/the-read-back-is-keyed-on-the-pair",
	} {
		if !rep.FailedCheck(name) {
			t.Errorf("a provider whose Revoke removes nothing passed %q with no data-plane hooks. "+
				"That is the exact configuration the read-back was added for, so this is the "+
				"assertion that says the gap is closed.\n%s", name, rep)
		}
	}
}
