// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/apphub/compute"
)

// DefaultName is the [compute.Provider.Name] a fake provider reports unless
// [Config.Name] overrides it. It is deliberately not "aws" or "kubernetes": a
// test that accidentally persists a Ref issued here should be obvious about
// where it came from.
const DefaultName = "fake"

// AllCapabilities returns every capability the fake can implement, which is all
// of them. A provider configured with a subset is the interesting case — see
// [Config.Capabilities].
func AllCapabilities() []compute.Capability {
	return []compute.Capability{
		compute.CapImageRegistry,
		compute.CapImageBuild,
		compute.CapContainerService,
		compute.CapScheduledJob,
		compute.CapWorkloadExec,
		compute.CapFunction,
		compute.CapFunctionEndpoint,
		compute.CapObjectStore,
		compute.CapObjectStoreZonal,
		compute.CapRelationalDatabase,
		compute.CapKeyValueTable,
		compute.CapSecretStore,
		compute.CapModelInference,
		compute.CapPlatformIngress,
		compute.CapIngressAuth,
		compute.CapMCPAuth,
		compute.CapWorkloadGrants,
		compute.CapImagePullGrants,
	}
}

// Config is the operator-supplied configuration of a fake provider.
//
// It exists for the same reason a real provider's constructor does: everything
// site-specific is supplied here rather than compiled in. What a [Placement]
// name means, which function runtimes are legal, which certificates can be
// resolved, and whether an ingress proxy exists at all are all configuration,
// and a conformance suite that could not vary them could not test refusal.
type Config struct {
	// Name overrides [DefaultName]. Two fakes with different names are useful
	// for testing that a foreign [compute.Ref] is refused.
	Name string

	// Capabilities is the advertised capability set. Nil means
	// [AllCapabilities]; an explicitly empty slice means a provider that can
	// only manage workload identities.
	//
	// A subset is the configuration worth testing: the conformance suite's
	// capability-negative checks have nothing to bite on against a provider
	// that advertises everything.
	Capabilities []compute.Capability

	// Placements are the operator-configured placement names. Nil means a
	// single placement called "default". The first entry is the default, which
	// an empty [compute.Placement.Name] selects; a name not in this list is
	// [compute.ErrInvalidSpec], because a provider must not guess where to put
	// something.
	Placements []string

	// NoIngressProxy configures a provider with no platform ingress proxy. Such
	// a provider must reject a [compute.PeerPlatformIngress] rule rather than
	// widen it to the internet, which is the fail-closed behaviour change
	// USOSS-2 accepted (design doc §4.2).
	NoIngressProxy bool

	// FunctionRuntimes are the runtime identifiers this provider accepts. Nil
	// means a small default set. Anything else is [compute.ErrInvalidSpec] with
	// the legal set named.
	FunctionRuntimes []string

	// Zones are the zone identifiers legal for [compute.ObjectClassZonal]. Nil
	// means one zone called "zone-a".
	Zones []string

	// Certificates are the certificate references this provider can resolve.
	// Nil means one called "cert-default". A listener naming anything else is
	// [compute.ErrInvalidSpec]: a provider may not invent a certificate.
	Certificates []string

	// ExtPorts makes this provider implement the non-portable ports in
	// compute/ext — table buckets, vector buckets, and cross-trust-domain
	// grants.
	//
	// It is off by default, which is the honest default for something that is
	// not AWS: those ports exist because one substrate has a feature nothing
	// else does, so a fake that always implemented them would let a test believe
	// the feature is portable. Turn it on to exercise a caller's table-bucket
	// path; leave it off to exercise the refusal, which is the branch an
	// operator actually meets.
	ExtPorts bool

	// EngineVersions are the relational engine versions on offer, by engine.
	// Nil means Postgres 16 and 17.
	EngineVersions map[compute.SQLEngine][]string

	// ObservationsToReady is how many observations an asynchronous resource
	// takes to converge. Zero means two, which is the interesting default: an
	// Ensure returns [compute.PhasePending] and a Wait has something to
	// actually wait for, so [compute.WaitOptions.OnUpdate] has more than one
	// state to report.
	ObservationsToReady int

	// BuildCredential is the material this provider makes available to a build,
	// standing in for the scoped short-lived push credential a real provider
	// mints. Empty means [DefaultBuildCredential].
	//
	// It exists so the conformance suite can assert the material appears in
	// nothing a build emits. A real provider never shows it to a caller — that
	// is the whole point of the obligation on [compute.ImageBuilder] — so the
	// only way to check the obligation is for the provider to report it to a
	// test.
	BuildCredential string

	// BuildCacheMaxAge is the age at which this provider expires a cached
	// build layer when a caller leaves [compute.BuildCache.MaxAge] at zero.
	// Empty means [DefaultBuildCacheMaxAge].
	BuildCacheMaxAge time.Duration

	// Defects makes the provider deliberately non-conformant. See [Defect].
	Defects []Defect
}

// Defect names a way of being non-conformant.
//
// A fake that only ever behaves correctly cannot show that the conformance
// suite would catch a provider that does not. The repository's standing rule is
// that a green gate proves nothing until somebody tries to defeat it, and the
// suite is a gate: for every invariant it claims to enforce there is a defect
// here that violates it and a self-test asserting the suite fails. Injecting a
// defect is a test-only act — nothing in the provider's normal path reads this
// field except the checks named below.
type Defect string

// The defects the fake can be configured with. Each one corresponds to a
// conformance invariant, and compute/conformance's self-test asserts the suite
// catches it.
const (
	// DefectCapabilityLie advertises a capability whose accessor still refuses,
	// breaking the capability/accessor agreement (§7.1).
	DefectCapabilityLie Defect = "capability-lie"
	// DefectUntypedRefusal refuses an absent capability with an error that does
	// not wrap [compute.ErrUnsupported] (§7.2).
	DefectUntypedRefusal Defect = "untyped-refusal"
	// DefectForeignRefIsNotFound reports a foreign [compute.Ref] as
	// [compute.ErrNotFound], letting a caller conclude the resource was deleted
	// (§7.4).
	DefectForeignRefIsNotFound Defect = "foreign-ref-is-not-found"
	// DefectNonDeterministicNames derives a different physical resource from the
	// same logical name on each call, so teardown cannot find what a deploy
	// created (§7.6, §7.14).
	DefectNonDeterministicNames Defect = "non-deterministic-names"
	// DefectCreateOrAdd implements Ensure additively: an element present in the
	// first spec and absent from the second survives (§7.7).
	DefectCreateOrAdd Defect = "create-or-add"
	// DefectBlockingEnsure blocks inside an asynchronous Ensure until the
	// resource is ready (§7.8).
	DefectBlockingEnsure Defect = "blocking-ensure"
	// DefectDeleteNotIdempotent fails when asked to delete an absent resource
	// (§7.9).
	DefectDeleteNotIdempotent Defect = "delete-not-idempotent"
	// DefectDescribeErrorAfterDelete reports a deleted asynchronous resource as
	// an error instead of [compute.PhaseGone] (§7.10).
	DefectDescribeErrorAfterDelete Defect = "describe-error-after-delete"
	// DefectWaitIgnoresDeadline waits past its deadline (§7.11).
	DefectWaitIgnoresDeadline Defect = "wait-ignores-deadline"
	// DefectWaitWithoutDeadline waits forever when given neither a timeout nor
	// a context deadline (§7.12).
	DefectWaitWithoutDeadline Defect = "wait-without-deadline"
	// DefectNoProgress never calls [compute.WaitOptions.OnUpdate] (§7.13).
	DefectNoProgress Defect = "no-progress"
	// DefectAdoptsUnowned adopts a resource this platform does not own instead
	// of returning [compute.ErrNotOwned] (§7.15).
	DefectAdoptsUnowned Defect = "adopts-unowned"
	// DefectGrantIsAdditive leaves the wider grant in place when a narrower one
	// is applied (§7.17).
	DefectGrantIsAdditive Defect = "grant-is-additive"
	// DefectRevokeAbsentFails fails when revoking a grant that was never made
	// (§7.18).
	DefectRevokeAbsentFails Defect = "revoke-absent-fails"
	// DefectGrantClobbersOtherResources keys the grant store on the identity
	// alone, so a grant or revoke on one resource silently destroys the same
	// identity's grant on every other resource -- and returns nil either way.
	//
	// It is the defect USOSS-14's review found in the AWS key-value port, which
	// wrote every grant under one provider-wide inline IAM policy name. Nothing
	// caught it: [compute.Granter] states it is keyed on the (resource,
	// identity) pair, and the suite drove one resource at a time, so a provider
	// keyed on the identity alone passed every grant check there was.
	//
	// The direction of the failure is under-grant rather than over-grant, which
	// is why it is worth a fixture rather than a comment: it breaks an
	// application at runtime, well after the deploy that reported success.
	DefectGrantClobbersOtherResources Defect = "grant-clobbers-other-resources"
	// DefectRevokeDoesNothing returns nil from every Revoke and removes no
	// grant.
	//
	// It is the defect USOSS-73 was opened over, in its plainest form. Before
	// [compute.Granter.DescribeGrant] existed, the only check that could see it
	// was the behavioural one, which needs Options.Read and Options.Write and
	// skips without them -- so a provider that supplied no data-plane hooks and
	// whose revoke did nothing at all passed every grant invariant the suite had.
	// That was measured rather than assumed, and it is what the read-back
	// invariants exist to make impossible.
	//
	// The direction is over-grant, which is the opposite of
	// [DefectGrantClobbersOtherResources] and worse: an under-grant breaks the
	// application and somebody notices, while an access that was reported revoked
	// and was not survives the audit that went looking for it.
	DefectRevokeDoesNothing Defect = "revoke-does-nothing"
	// DefectRevokeExternalDoesNothing returns nil from
	// [ext.ExternalAccessGranter.RevokeExternal] and leaves the grant standing.
	//
	// The cross-domain twin of [DefectRevokeDoesNothing], and the one the ticket
	// names: "a provider whose RevokeExternal does nothing at all passed the full
	// conformance suite and the entire fake package". It is a fixture rather than
	// a sentence so that the claim stays checkable -- and so that the check which
	// now catches it can be shown to catch it.
	//
	// Worse than the core case in blast radius, because the principal left with
	// access is outside this platform's trust domain: revoking it is the whole
	// mechanism by which a partnership ends.
	DefectRevokeExternalDoesNothing Defect = "revoke-external-does-nothing"
	// DefectSecretInError puts secret material into an error message (§7.19).
	DefectSecretInError Defect = "secret-in-error"
	// DefectSecretInRendered writes a resolved secret value into a rendered
	// artefact instead of binding it by reference (§7.20).
	DefectSecretInRendered Defect = "secret-in-rendered"
	// DefectRotatesAdminPassword rotates the relational admin password on a
	// re-Ensure, invalidating the caller's stored copy (§7.21).
	DefectRotatesAdminPassword Defect = "rotates-admin-password"
	// DefectSubstitutesImmutableField converges the mutable half of a relational
	// re-Ensure and silently keeps the live database name and admin username,
	// reporting success and an effective spec carrying the old values.
	//
	// It is the defect USOSS-14's review found in the AWS relational port, whose
	// existing-cluster arm converged capacity, security groups and tags and
	// compared none of the fields RDS fixes at creation.
	// [compute.RelationalProvisioner] forbids exactly this for the engine
	// version -- "reject a spec whose version it cannot supply rather than
	// substitute a different one" -- and the admin username is the field where
	// it costs the most, being half of the credential the caller stored before
	// provisioning.
	DefectSubstitutesImmutableField Defect = "substitutes-immutable-field"
	// DefectDenialIsTerminal collapses an authorization failure into
	// [compute.ErrFailed], which is where every provider's denials landed before
	// [compute.ErrNotPermitted] existed and where they stay unless something
	// checks (USOSS-40).
	DefectDenialIsTerminal Defect = "denial-is-terminal"
	// DefectPublicByDefault leaves anonymous read enabled on a bucket created
	// with PublicAccess false (§7.22).
	DefectPublicByDefault Defect = "public-by-default"
	// DefectTLSWithoutCertificate accepts a TLS listener with no resolvable
	// certificate, reproducing the source system's certificate-less HTTPS
	// listener (§7.23).
	DefectTLSWithoutCertificate Defect = "tls-without-certificate"
	// DefectSilentZonalFallback hands back a standard bucket when a zonal one
	// was asked for and the capability is absent (§7.24).
	DefectSilentZonalFallback Defect = "silent-zonal-fallback"
	// DefectSilentCapabilityDrop accepts a workload capability the provider does
	// not advertise and quietly does not grant it (§7.24).
	DefectSilentCapabilityDrop Defect = "silent-capability-drop"
	// DefectExecWidensIdentity grants the workload's own identity the ability to
	// open sessions against other workloads — the principal inversion USOSS-2
	// corrected (§7.25).
	DefectExecWidensIdentity Defect = "exec-widens-identity"
	// DefectWidensIngressWithoutProxy widens a
	// [compute.PeerPlatformIngress] rule to the internet when no ingress proxy
	// is configured, which is the source system's fail-open behaviour
	// (design doc §4.2).
	DefectWidensIngressWithoutProxy Defect = "widens-ingress-without-proxy"
	// DefectIgnoresSecretVersion accepts a [compute.SecretBinding.Version] and
	// binds the current value anyway, which is the defect
	// [compute.ErrVersionPinningUnsupported] exists to prevent: the caller
	// believes it pinned a revision and got the latest one, and nothing said so.
	DefectIgnoresSecretVersion Defect = "ignores-secret-version"

	// DefectPlaintextRoute serves an application's own public hostname over
	// HTTP when the route names no certificate and does not allow plaintext.
	// The fail-open half of the choice compute.Route.AllowPlaintext exists to
	// make explicit.
	DefectPlaintextRoute Defect = "plaintext-route"

	// DefectCopiesSecretAcrossPlacements satisfies a binding whose secret is in
	// a different placement from the workload, which a real provider could only
	// do by copying the material into a second namespace — doubling the places
	// an audit has to look for material apphub is never supposed to read.
	DefectCopiesSecretAcrossPlacements Defect = "copies-secret-across-placements"
	// DefectRequiresNetworkIdentifier demands a substrate network identifier as
	// an interface input, by rejecting a [compute.Placement] that carries only a
	// logical name.
	DefectRequiresNetworkIdentifier Defect = "requires-network-identifier"

	// DefectTransientIsTerminal maps a retryable substrate failure onto
	// [compute.ErrFailed] instead of [compute.ErrTransient] — the conservative
	// mistake that turns an outage into a failed deploy, since ErrFailed tells
	// the caller its spec has to change.
	//
	// It is the defect USOSS-32 needed and the suite did not have. The retry
	// gate had no fixture at all: it was the one check with no entry in this
	// list, so nothing had ever shown it could fail. It also skipped for any
	// provider without a secret store, which is why the same defect is injected
	// twice in the self-test, once with a secret store and once without.
	DefectTransientIsTerminal Defect = "transient-is-terminal"

	// DefectBuildCredentialInLogs writes the build's own push credential into
	// [compute.BuildRequest.Logs].
	//
	// This is the live defect PR #18's review found in the first provider to
	// implement the port, and the reason the obligation on
	// [compute.ImageBuilder] is stated in capitals: a build's output is
	// persisted by its caller, and a Dockerfile RUN is repository-authored code
	// that can read the executor's own environment.
	//nolint:gosec // G101: the value is a defect's name, not a credential.
	DefectBuildCredentialInLogs Defect = "build-credential-in-logs"

	// DefectBuildOutputInError puts what the builder read from the build context
	// into a failing build's error.
	//
	// The source system does exactly this (build.go:566-572): a failing build's
	// error carries a tail of kaniko's output and is persisted onto a job record
	// and rendered in an interface. The content is repository-authored.
	DefectBuildOutputInError Defect = "build-output-in-error"

	// DefectBuildFailsAfterEmitting writes the build's own credential into the
	// log and *then* fails.
	//
	// It exists for a hazard found on PR #25 rather than here: an S3 object store
	// silently continued past a tag-read error, so Describe returned an empty
	// artefact set, Harness.Rendered reported nothing, and every security check
	// scanning those artefacts passed by omission. That is the vacuous-pass class
	// arriving by a route nobody had enumerated — not a skip and not an absent
	// sentinel, but a swallowed error emptying the thing the check reads.
	//
	// The build checks scan four channels, so the question is whether a failure
	// partway through empties any of them. This defect is the probe: the material
	// is out, and the call then fails. A check that scans only a successful
	// build's output would pass here, and an adversarial builder would never
	// produce that case on its own, because a hostile builder emits rather than
	// erroring.
	DefectBuildFailsAfterEmitting Defect = "build-fails-after-emitting"

	// DefectBuildCredentialInError returns a failing build whose error carries the
	// push credential.
	//
	// It exists because the credential check's claim is that the material appears
	// in **no log, error or result**, and until USOSS-61 only the log half of that
	// was pinned: both credential defects wrote to Logs, so deleting the error and
	// result channels from the check's scan would have kept the self-test green
	// while the check went on claiming all three. A claim covering three channels
	// needs three fixtures — otherwise the coverage is asserted in a name rather
	// than demonstrated, which is the vacuity this suite is built to refuse.
	//
	// The shape is a real one: an error message that quotes the arguments or
	// environment it was invoked with, which is how compute/aws's redacting writer
	// came to exist.
	//nolint:gosec // G101: the value is a defect's name, not a credential.
	DefectBuildCredentialInError Defect = "build-credential-in-error"

	// DefectBuildCredentialInResult returns the push credential inside
	// [compute.BuildResult.Digest].
	//
	// The result is the third channel the credential check reads, and the least
	// obvious of the three: a caller persists a BuildResult onto whatever record
	// describes the build, so an opaque field is exactly where material rides out
	// unnoticed. Same reason as [DefectBuildCredentialInError] — the check claims
	// this channel, so something has to be able to fail it.
	//nolint:gosec // G101: the value is a defect's name, not a credential.
	DefectBuildCredentialInResult Defect = "build-credential-in-result"

	// DefectSilentBuild writes nothing to the Logs writer it was given, which
	// deprives the caller of a build's only progress signal — and passes every
	// check that scans a build's output for material it should not contain.
	DefectSilentBuild Defect = "silent-build"

	// DefectBuildWithoutDestination accepts a build with no destinations and
	// reports success, so the caller cannot tell that nothing was published.
	DefectBuildWithoutDestination Defect = "build-without-destination"

	// DefectBuildCredentialInImageMetadata folds the build's own push
	// credential into the pushed image's metadata, standing in for a builder
	// that authenticates a private base-image pull by handing its scoped
	// credential to the build as an ordinary build argument.
	//
	// It is the fourth credential-egress channel USOSS-39 named and did not
	// build (USOSS-49): docker and kaniko both record every ARG a build
	// consumed in the image's build history, so a credential smuggled in this
	// way is not merely logged, it is published -- baked into metadata every
	// puller of the image can read, for as long as the image exists.
	//nolint:gosec // G101: the value is a defect's name, not a credential.
	DefectBuildCredentialInImageMetadata Defect = "build-credential-in-image-metadata"

	// DefectBuildCacheDefaultIsForever reports a zero default MaxAge for a
	// build cache, standing in for a provider whose cache never expires a
	// layer on its own.
	//
	// [compute.BuildCache.MaxAge] documents that zero defers to "the
	// provider's default, which must not be 'forever'" -- an obligation
	// USOSS-39 named and did not build a check for (USOSS-49). A cached
	// package-install layer keeps serving whatever it captured, so a default
	// that never expires means an upstream security fix never reaches a
	// rebuild of an unchanged recipe.
	DefectBuildCacheDefaultIsForever Defect = "build-cache-default-is-forever"

	// DefectScaleToZeroDeletes treats a scale to zero instances as a removal
	// rather than a pause, so a paused service reports PhaseGone and its caller
	// concludes it was deleted.
	DefectScaleToZeroDeletes Defect = "scale-to-zero-deletes"

	// DefectScaleRewritesTheSpec implements a scale as an Ensure of a spec the
	// scale path carries, losing every declarative element it does not — the
	// create-or-add mistake from the other direction, and silent because the
	// caller asked only for a different instance count.
	DefectScaleRewritesTheSpec Defect = "scale-rewrites-the-spec"

	// DefectPullGrantNotIdempotent fails the second GrantPull for a pair that is
	// already granted. A caller reconciles rather than remembering, so it grants
	// pull on every deploy, and this turns a no-op into a failed deploy.
	DefectPullGrantNotIdempotent Defect = "pull-grant-not-idempotent"

	// DefectPullGrantWithoutCapability accepts a pull grant on a provider that
	// does not advertise [compute.CapImagePullGrants], making the grant a silent
	// no-op: the caller records an authorisation that does not exist and the
	// workload's failure to pull surfaces at launch instead.
	DefectPullGrantWithoutCapability Defect = "pull-grant-without-capability"

	// DefectSecretValueInDescribe returns a stored secret's value through the
	// metadata read that is documented never to return one.
	//
	// It is the defect that makes compute.SecretStore.Describe reviewable: the
	// operation is permitted to exist precisely because it returns a locator
	// and a location rather than material, so a suite that cannot catch a
	// provider returning material through it is not checking the property that
	// justified the operation.
	DefectSecretValueInDescribe Defect = "secret-value-in-describe"
	// DefectSecretValueInStoreListing prints stored secret values in the
	// substrate listing [Harness.Rendered] returns, rather than naming the
	// secrets.
	//
	// It is the leak a provider whose only material-carrying port is the secret
	// store can have: DefectSecretInRendered needs a workload to bind a secret
	// into, so it cannot be exhibited by a provider with no container runtime,
	// and a check that only looked for that shape would report such a provider
	// as clean.
	DefectSecretValueInStoreListing Defect = "secret-value-in-store-listing"

	// DefectDropsRenderedArtefact makes [Harness.Rendered] and
	// [Harness.RenderedRef] silently omit every secret's own listing entry,
	// while every other resource still renders. Everything else the substrate
	// holds -- services, buckets, functions, whatever else is in play --
	// renders exactly as it would without the defect.
	//
	// This is the PARTIAL emptying [checkEveryPlantedResourceIsRendered] exists
	// to catch (USOSS-48), and it is deliberately not a total one:
	// [checkSecretsNotInRendered] already fails a Rendered that returns nothing
	// at all, so a total-emptying fixture would prove nothing new. Combined
	// with [DefectSecretValueInStoreListing] -- which puts the material in
	// exactly the artefact this defect drops -- it reproduces the PR #25 shape
	// measured against a live leak: the aggregate list stays non-empty and
	// grows (a planted service still renders fresh), the sentinel is nowhere
	// in it because the one artefact that carried it was never a member of the
	// list the scan searched, and checkSecretsNotInRendered reports a clean
	// scan of a set the leak was silently excluded from.
	DefectDropsRenderedArtefact Defect = "drops-rendered-artefact"
)

// stickyFailure is armed by [Harness.FailEvery]. It is a pointer so that a stop
// function only clears the arming it made: two overlapping FailEvery calls
// cannot disarm each other.
type stickyFailure struct{ err error }

// Provider is an in-memory [compute.Provider].
//
// It is a working implementation, not a set of stubs: a resource ensured
// through it can be described, waited on, granted to, read and written as a
// workload identity, and deleted, and the state persists in the [Store] it was
// constructed with. That is what lets a module test assert on behaviour instead
// of on which methods were called.
type Provider struct {
	store *Store
	cfg   Config
	caps  compute.CapabilitySet
	// defects is Config.Defects as a set, for cheap lookup on hot paths.
	defects map[Defect]struct{}
}

// New returns a provider backed by store.
//
// Two providers constructed over the same [Store] address the same substrate,
// which is what the conformance suite's determinism invariant needs: the same
// logical name must resolve to the same physical resource from a different
// provider instance.
func New(store *Store, cfg Config) *Provider {
	if store == nil {
		panic("fake: New requires a Store; call fake.NewStore()")
	}
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Capabilities == nil {
		cfg.Capabilities = AllCapabilities()
	}
	if cfg.Placements == nil {
		// Two, not one. Placement scoping for identities and secrets is only
		// observable with a second placement to be in the wrong one of.
		cfg.Placements = []string{"default", "secondary"}
	}
	if cfg.FunctionRuntimes == nil {
		cfg.FunctionRuntimes = []string{"nodejs20.x", "python3.12", "provided.al2023"}
	}
	if cfg.Zones == nil {
		cfg.Zones = []string{"zone-a"}
	}
	if cfg.Certificates == nil {
		cfg.Certificates = []string{"cert-default"}
	}
	if cfg.EngineVersions == nil {
		cfg.EngineVersions = map[compute.SQLEngine][]string{
			compute.EnginePostgres: {"16", "17"},
		}
	}
	if cfg.ObservationsToReady == 0 {
		cfg.ObservationsToReady = 2
	}
	defects := make(map[Defect]struct{}, len(cfg.Defects))
	for _, d := range cfg.Defects {
		defects[d] = struct{}{}
	}
	caps := compute.NewCapabilitySet(cfg.Capabilities...)
	// A configuration-derived capability has to follow the configuration, or the
	// capability/accessor agreement invariant is a lie: a provider told it has no
	// ingress proxy must not advertise CapPlatformIngress just because the
	// default capability list mentions it.
	if cfg.NoIngressProxy {
		delete(caps, compute.CapPlatformIngress)
		delete(caps, compute.CapIngressAuth)
	}
	return &Provider{
		store:   store,
		cfg:     cfg,
		caps:    caps,
		defects: defects,
	}
}

// Name implements [compute.Provider].
func (p *Provider) Name() string { return p.cfg.Name }

// Capabilities implements [compute.Provider].
func (p *Provider) Capabilities() compute.CapabilitySet { return p.caps }

// Store returns the state this provider reads and writes. Test helpers use it;
// nothing in the [compute.Provider] contract exposes it.
func (p *Provider) Store() *Store { return p.store }

func (p *Provider) broken(d Defect) bool {
	_, ok := p.defects[d]
	return ok
}

// require gates a port accessor on a capability.
func (p *Provider) require(c compute.Capability) error {
	if p.caps.Has(c) && !p.broken(DefectCapabilityLie) {
		return nil
	}
	if p.broken(DefectUntypedRefusal) {
		// A refusal a caller cannot recognise: no ErrUnsupported anywhere in the
		// chain, so an existing branch on the sentinel silently misses it.
		return fmt.Errorf("fake: no %s here", c)
	}
	return compute.Unsupported(p.cfg.Name, c)
}

// Identities implements [compute.Provider].
func (p *Provider) Identities() compute.IdentityService { return identityService{p} }

// Registry implements [compute.Provider].
func (p *Provider) Registry() (compute.ImageRegistry, error) {
	if err := p.require(compute.CapImageRegistry); err != nil {
		return nil, err
	}
	return imageRegistry{p}, nil
}

// Builder implements [compute.Provider].
func (p *Provider) Builder() (compute.ImageBuilder, error) {
	if err := p.require(compute.CapImageBuild); err != nil {
		return nil, err
	}
	return imageBuilder{p}, nil
}

// Containers implements [compute.Provider].
func (p *Provider) Containers() (compute.ContainerRuntime, error) {
	if err := p.require(compute.CapContainerService); err != nil {
		return nil, err
	}
	return containerRuntime{p}, nil
}

// Functions implements [compute.Provider].
func (p *Provider) Functions() (compute.FunctionRuntime, error) {
	if err := p.require(compute.CapFunction); err != nil {
		return nil, err
	}
	return functionRuntime{p}, nil
}

// ObjectStores implements [compute.Provider].
func (p *Provider) ObjectStores() (compute.ObjectStore, error) {
	if err := p.require(compute.CapObjectStore); err != nil {
		return nil, err
	}
	if p.cfg.ExtPorts {
		return extObjectStore{objectStore{p}}, nil
	}
	return objectStore{p}, nil
}

// Relational implements [compute.Provider].
func (p *Provider) Relational() (compute.RelationalProvisioner, error) {
	if err := p.require(compute.CapRelationalDatabase); err != nil {
		return nil, err
	}
	return relationalProvisioner{p}, nil
}

// KeyValues implements [compute.Provider].
func (p *Provider) KeyValues() (compute.KeyValueProvisioner, error) {
	if err := p.require(compute.CapKeyValueTable); err != nil {
		return nil, err
	}
	return keyValueProvisioner{p}, nil
}

// Secrets implements [compute.Provider].
func (p *Provider) Secrets() (compute.SecretStore, error) {
	if err := p.require(compute.CapSecretStore); err != nil {
		return nil, err
	}
	return secretStore{p}, nil
}

var _ compute.Provider = (*Provider)(nil)

// --- reference handling ----------------------------------------------------

// ref builds a deterministic reference for a logical name.
//
// Determinism is a contract, not a convenience: teardown has to reconstruct a
// reference for a resource whose provisioned identifier may never have been
// persisted, so the same logical name must always produce the same physical
// resource — from a different provider instance and after a restart.
func (p *Provider) ref(kind compute.Kind, name string) compute.Ref {
	id := string(kind) + "/" + name
	if p.broken(DefectNonDeterministicNames) {
		id = fmt.Sprintf("%s/%s-%d", kind, name, p.store.tick())
	}
	return compute.Ref{Provider: p.cfg.Name, Kind: kind, ID: id}
}

// resolve validates a reference and returns its identifier.
//
// The order matters. A foreign reference is checked first and refused with
// [compute.ErrForeignRef], because reporting it as not-found would let a caller
// conclude the resource had been deleted and move on to recreate it somewhere
// it does not belong.
func (p *Provider) resolve(ref compute.Ref, want compute.Kind) (string, error) {
	if ref.Provider != p.cfg.Name {
		if p.broken(DefectForeignRefIsNotFound) {
			return "", fmt.Errorf("fake: %s: %w", ref, compute.ErrNotFound)
		}
		return "", fmt.Errorf("fake: provider %q was handed a reference issued by %q%s: %w",
			p.cfg.Name, ref.Provider, p.emission(ChannelCallError), compute.ErrForeignRef)
	}
	if ref.Kind != want {
		return "", fmt.Errorf("fake: reference %s is a %q, but this call takes a %q: %w",
			ref, ref.Kind, want, compute.ErrInvalidSpec)
	}
	if ref.ID == "" {
		return "", fmt.Errorf("fake: reference %s has no identifier: %w", ref, compute.ErrInvalidSpec)
	}
	return ref.ID, nil
}

// --- shared spec validation ------------------------------------------------

func (p *Provider) validateName(what, name string) error {
	if name == "" {
		return fmt.Errorf("fake: %s needs a name: %w", what, compute.ErrInvalidSpec)
	}
	// A substrate limit, present so that "a name too long for the substrate" is
	// a real refusal a caller can hit rather than a documented possibility.
	const maxName = 63
	if len(name) > maxName {
		return fmt.Errorf("fake: %s name %q is %d characters; this provider allows %d: %w",
			what, name, len(name), maxName, compute.ErrInvalidSpec)
	}
	if strings.ContainsAny(name, "/ \t\n") {
		return fmt.Errorf("fake: %s name %q contains a character this provider cannot use: %w",
			what, name, compute.ErrInvalidSpec)
	}
	return nil
}

// resolvePlacement maps a logical placement name onto this provider's
// configuration. It carries no network identifier in either direction, which is
// the whole point of Placement being a name: see design doc §4.2.
func (p *Provider) resolvePlacement(pl compute.Placement) (string, error) {
	if p.broken(DefectRequiresNetworkIdentifier) {
		return "", fmt.Errorf("fake: placement %q has no subnet identifiers; pass them on the spec: %w",
			pl.Name, compute.ErrInvalidSpec)
	}
	if pl.Name == "" {
		if len(p.cfg.Placements) == 0 {
			return "", fmt.Errorf("fake: this provider has no default placement, so one must be named: %w",
				compute.ErrInvalidSpec)
		}
		return p.cfg.Placements[0], nil
	}
	for _, cand := range p.cfg.Placements {
		if cand == pl.Name {
			return cand, nil
		}
	}
	return "", fmt.Errorf("fake: no placement named %q is configured (have %v): %w",
		pl.Name, p.cfg.Placements, compute.ErrInvalidSpec)
}

// validateIngress checks a reachability rule set.
//
// The refusal that matters is [compute.PeerPlatformIngress] against a provider
// with no ingress proxy configured. The source system silently widens that to
// 0.0.0.0/0 when TRAEFIK_SECURITY_GROUP_ID is unset (build.go:836-848) — a
// missing environment variable turns a proxy-only port into an internet-facing
// one. Here it is an error.
func (p *Provider) validateIngress(rules []compute.IngressRule) error {
	for i, r := range rules {
		if r.Port <= 0 || r.Port > 65535 {
			return fmt.Errorf("fake: ingress rule %d names port %d: %w", i, r.Port, compute.ErrInvalidSpec)
		}
		switch r.Protocol {
		case "", compute.ProtocolTCP, compute.ProtocolUDP:
		default:
			return fmt.Errorf("fake: ingress rule %d names protocol %q: %w", i, r.Protocol, compute.ErrInvalidSpec)
		}
		switch r.From.Kind {
		case compute.PeerWorkload:
			if r.From.Workload.IsZero() {
				return fmt.Errorf("fake: ingress rule %d names a workload peer with no reference: %w",
					i, compute.ErrInvalidSpec)
			}
			if r.From.Workload.Provider != p.cfg.Name {
				return fmt.Errorf("fake: ingress rule %d names a workload issued by %q: %w",
					i, r.From.Workload.Provider, compute.ErrForeignRef)
			}
		case compute.PeerPlatformIngress:
			if !r.From.Workload.IsZero() {
				return fmt.Errorf("fake: ingress rule %d sets a workload reference on a %q peer: %w",
					i, r.From.Kind, compute.ErrInvalidSpec)
			}
			// Discoverable in advance since F7: the capability and the
			// behaviour have to agree, or checking it before deploying tells a
			// caller nothing.
			if !p.caps.Has(compute.CapPlatformIngress) && !p.broken(DefectWidensIngressWithoutProxy) {
				return fmt.Errorf("fake: ingress rule %d names the platform ingress proxy, but this "+
					"provider is configured without one; widening the rule to the internet instead "+
					"would expose port %d: %w", i, r.Port, compute.ErrInvalidSpec)
			}
		case compute.PeerInternet, compute.PeerControlPlane:
			if !r.From.Workload.IsZero() {
				return fmt.Errorf("fake: ingress rule %d sets a workload reference on a %q peer: %w",
					i, r.From.Kind, compute.ErrInvalidSpec)
			}
		default:
			return fmt.Errorf("fake: ingress rule %d names peer kind %q: %w", i, r.From.Kind, compute.ErrInvalidSpec)
		}
	}
	return nil
}

// validateWorkloadCapabilities refuses a capability the provider does not
// advertise, rather than accepting the spec and quietly not granting it. A
// workload that believes it can call an inference API and cannot is an
// authorization error at runtime, far from the deploy that caused it.
func (p *Provider) validateWorkloadCapabilities(caps []compute.WorkloadCapability) error {
	if p.broken(DefectSilentCapabilityDrop) {
		return nil
	}
	for _, c := range caps {
		switch c {
		case compute.WorkloadCapabilityModelInference:
			if !p.caps.Has(compute.CapModelInference) {
				return fmt.Errorf("fake: workload capability %q requires %q: %w",
					c, compute.CapModelInference, compute.ErrUnsupported)
			}
		default:
			return fmt.Errorf("fake: unknown workload capability %q: %w", c, compute.ErrInvalidSpec)
		}
	}
	return nil
}

// requireIdentity checks that a spec's identity exists and can be assumed by
// the runtime it is being attached to.
func (p *Provider) requireIdentity(ref compute.Ref, runsOn compute.RuntimeKind) error {
	id, err := p.resolve(ref, compute.KindWorkloadIdentity)
	if err != nil {
		return err
	}
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	rec, ok := p.store.identities[id]
	if !ok {
		return fmt.Errorf("fake: no workload identity %s: %w", ref, compute.ErrNotFound)
	}
	if rec.spec.RunsOn != runsOn {
		return fmt.Errorf("fake: workload identity %s runs on %q and cannot be assumed by a %q workload: %w",
			ref, rec.spec.RunsOn, runsOn, compute.ErrInvalidSpec)
	}
	return nil
}

// validateSecretBindings checks that every bound secret came from this
// provider's own store. A runtime can only resolve a reference to a store it
// natively understands, so a foreign reference is refused rather than
// half-honoured.
func (p *Provider) validateSecretBindings(placement string, bindings []compute.SecretBinding) error {
	for i, b := range bindings {
		if b.EnvName == "" {
			return fmt.Errorf("fake: secret binding %d has no environment variable name: %w",
				i, compute.ErrInvalidSpec)
		}
		id, err := p.resolve(b.Secret, compute.KindSecret)
		if err != nil {
			return fmt.Errorf("fake: secret binding %d for %s: %w", i, b.EnvName, err)
		}
		p.store.mu.Lock()
		rec, ok := p.store.secrets[id]
		p.store.mu.Unlock()
		if !ok {
			return fmt.Errorf("fake: secret binding %d refers to %s, which does not exist: %w",
				i, b.Secret, compute.ErrNotFound)
		}
		// A binding across placements is ErrInvalidSpec, and a provider must not
		// copy material to satisfy one — the rule compute.SecretBinding states.
		if rec.spec.Placement.Name != placement && !p.broken(DefectCopiesSecretAcrossPlacements) {
			return fmt.Errorf("fake: secret binding %d refers to a secret in placement %q and the "+
				"workload is in %q; copying the material across is not an option a provider has: %w",
				i, rec.spec.Placement.Name, placement, compute.ErrInvalidSpec)
		}
		if err := p.resolveSecretVersion(id, b); err != nil {
			return fmt.Errorf("fake: secret binding %d for %s: %w", i, b.EnvName, err)
		}
	}
	return nil
}

// resolveSecretVersion checks that a pinned binding names a revision this store
// actually holds.
//
// This provider honours pinning, so an unknown revision is a caller error rather
// than something to fall back from. Falling back to the current value is the
// defect [compute.ErrVersionPinningUnsupported] exists to prevent, and
// [DefectIgnoresSecretVersion] is that fallback made explicit so the conformance
// suite can be shown to catch it.
func (p *Provider) resolveSecretVersion(id string, b compute.SecretBinding) error {
	if b.Version == "" {
		return nil
	}
	if p.broken(DefectIgnoresSecretVersion) {
		return nil
	}
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	if _, ok := revisionValue(p.store.secretRevisions[id], b.Version); !ok {
		return fmt.Errorf("secret %s has no revision %q: %w", b.Secret, b.Version, compute.ErrNotFound)
	}
	return nil
}

// revisionValue resolves a version string against a value history.
func revisionValue(history []compute.SecretValue, version string) (compute.SecretValue, bool) {
	n, err := strconv.Atoi(version)
	if err != nil || n < 1 || n > len(history) {
		return compute.SecretValue{}, false
	}
	return history[n-1], true
}

// --- revision --------------------------------------------------------------

// revisionOf hashes the effective spec, so [compute.ServiceStatus.Revision]
// changes exactly when the configuration does and is stable when it does not.
// A caller uses that to tell a real rollout from a no-op Ensure.
//
// A [compute.SecretValue] marshals to its redaction, so an admin password
// change does not appear here — which is correct twice over: the password is
// not part of the effective configuration, and a provider must not rotate it.
func revisionOf(spec any) string {
	b, err := json.Marshal(spec)
	if err != nil {
		// Every spec in this package is plain data; an error here is a
		// programming mistake, not a runtime condition.
		panic("fake: spec is not marshalable: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return "rev-" + hex.EncodeToString(sum[:8])
}

// --- store -----------------------------------------------------------------

// Store is the substrate the fake provisions into.
//
// It is separate from [Provider] so that two providers can address the same
// substrate — the conformance suite's determinism invariant requires a second
// instance to find what the first one created — and so a module test can hold
// one across several providers.
//
// Every method is safe for concurrent use.
type Store struct {
	mu sync.Mutex

	identities  map[string]*record[compute.WorkloadIdentitySpec]
	repos       map[string]*record[compute.RepositorySpec]
	services    map[string]*record[compute.ServiceSpec]
	jobs        map[string]*record[compute.ScheduledJobSpec]
	functions   map[string]*record[compute.FunctionSpec]
	endpoints   map[string]*record[compute.EndpointSpec]
	buckets     map[string]*record[compute.BucketSpec]
	relationals map[string]*record[relationalState]
	tables      map[string]*record[compute.KeyValueSpec]
	secrets     map[string]*record[compute.SecretSpec]

	// secretRevisions is the value history of each secret, oldest first, keyed
	// by the secret's Ref.ID. A version is the 1-based index into it, rendered
	// as a decimal string.
	//
	// A real history rather than a counter, because that is what honouring
	// [compute.SecretBinding.Version] requires: a pinned binding has to resolve
	// to the value that revision held, and a store that only remembered the
	// number would resolve every pin to the latest value while reporting the
	// number the caller asked for. That is precisely the failure the field was
	// added to close, so the reference implementation must not be able to
	// exhibit it by accident.
	secretRevisions map[string][]compute.SecretValue

	// grants is the substrate's access control: resource identifier and
	// identity identifier to level. One entry per pair, so a narrower grant
	// replaces a wider one instead of adding to it.
	grants map[grantKey]compute.AccessLevel
	// external holds cross-trust-domain grants, keyed by resource and the
	// caller-supplied principal identifier.
	external map[grantKey]externalGrant

	// objects and items are the data planes, so that a grant can be tested by
	// reading and writing rather than by inspecting a policy document.
	objects map[string]map[string][]byte
	items   map[string]map[string][]byte

	// images records what a build pushed, so a runtime can refuse to run an
	// image nobody published.
	images map[compute.ImageRef]string

	// imageMetadata records the metadata a build attached to a pushed image --
	// the non-secret build arguments a caller supplied, and, under
	// [DefectBuildCredentialInImageMetadata], the provider's own push
	// credential. Nothing in [compute.BuildResult] exposes this; it exists
	// purely so [Harness.ImageMetadata] can read it back.
	imageMetadata map[compute.ImageRef]string

	// failures are errors queued by [Harness.FailNext], keyed by operation and
	// resource kind. Nothing populates this except a test.
	failures map[failureKey][]error

	// emissions are markers a test asked this provider to put into a named
	// channel, keyed by channel name. See [Harness.EmitInto].
	emissions map[string]string

	// sticky is the error every intercepted operation returns until it is
	// cleared, armed by [Harness.FailEvery]. The conformance suite's retry gate
	// drives every method of every port, so a hook that armed one call would
	// leave every other mapping unexercised.
	sticky *stickyFailure

	// clock is a logical clock. A fake substrate with a real clock makes
	// timestamps in test output vary for no reason; this one advances by a
	// second on every observation.
	clock int64
}

type grantKey struct {
	resource string
	subject  string
}

type externalGrant struct {
	level       compute.AccessLevel
	constraints []string
	// owned records that this platform created the grant. Revoking a grant it
	// did not create is refused: the names these live on derive from mutable
	// application names, so a collision is possible and deleting a stranger's
	// trust relationship is not recoverable.
	owned bool
}

// NewStore returns an empty substrate.
func NewStore() *Store {
	return &Store{
		identities:  map[string]*record[compute.WorkloadIdentitySpec]{},
		repos:       map[string]*record[compute.RepositorySpec]{},
		services:    map[string]*record[compute.ServiceSpec]{},
		jobs:        map[string]*record[compute.ScheduledJobSpec]{},
		functions:   map[string]*record[compute.FunctionSpec]{},
		endpoints:   map[string]*record[compute.EndpointSpec]{},
		buckets:     map[string]*record[compute.BucketSpec]{},
		relationals: map[string]*record[relationalState]{},
		tables:      map[string]*record[compute.KeyValueSpec]{},
		secrets:     map[string]*record[compute.SecretSpec]{},

		secretRevisions: map[string][]compute.SecretValue{},
		grants:          map[grantKey]compute.AccessLevel{},
		external:        map[grantKey]externalGrant{},
		objects:         map[string]map[string][]byte{},
		items:           map[string]map[string][]byte{},
		images:          map[compute.ImageRef]string{},
		imageMetadata:   map[compute.ImageRef]string{},
		clock:           0,
	}
}

// epoch is the logical clock's origin. A fixed instant keeps test output stable.
var epoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

func (s *Store) tick() int64 {
	s.clock++
	return s.clock
}

// now advances and reads the logical clock. Callers hold s.mu.
func (s *Store) now() time.Time {
	return epoch.Add(time.Duration(s.tick()) * time.Second)
}

// record is one provisioned resource.
type record[S any] struct {
	ref  compute.Ref
	name string
	spec S

	// owned reports that this platform created the resource. An Ensure that
	// finds an unowned resource under the name it would claim returns
	// [compute.ErrNotOwned] rather than adopting it.
	owned bool

	// async is the convergence state of an asynchronous-class resource, and nil
	// for a synchronous-class one. The two classes are a real distinction in
	// the interface (see compute.Status), and modelling it here rather than
	// giving everything a phase is what lets the fake demonstrate both.
	async *asyncState

	revision  string
	updatedAt time.Time
}

type asyncState struct {
	phase        compute.Phase
	observations int
	toReady      int
	// stalled resources never converge, so a Wait against one has something to
	// time out on.
	stalled bool
	message string
	// deleted records that teardown has run: a Describe then reports
	// [compute.PhaseGone] rather than an error.
	deleted bool
}

// observe advances convergence and returns the current phase. Callers hold the
// store lock.
func (a *asyncState) observe() compute.Phase {
	if a.deleted {
		a.phase = compute.PhaseGone
		return a.phase
	}
	if a.phase == compute.PhaseReady || a.phase == compute.PhaseFailed {
		return a.phase
	}
	a.observations++
	if !a.stalled && a.observations >= a.toReady {
		a.phase = compute.PhaseReady
		a.message = ""
	}
	return a.phase
}

// keys returns a map's keys sorted, for stable messages.
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultBuildCredential is the material [Config.BuildCredential] defaults to.
// It is distinctive so that finding it in a log, an error or a result is
// unambiguous.
//
// gosec flags it, and it is right to: this is a credential-shaped literal in
// non-test code. It stays a literal rather than being assembled from fragments,
// because a value spelled to evade a detection rule is worse than one that trips
// it and says why — and the thing it stands for is a *fake* substrate's push
// credential, which authorises nothing anywhere.
//
//nolint:gosec // G101: deliberately credential-shaped, and it authorises nothing.
const DefaultBuildCredential = "fake-build-push-credential-a71c3e5d"

// buildCredential returns the material this provider's builds are given.
func (p *Provider) buildCredential() string {
	if p.cfg.BuildCredential != "" {
		return p.cfg.BuildCredential
	}
	return DefaultBuildCredential
}

// DefaultBuildCacheMaxAge is the age [Config.BuildCacheMaxAge] defaults to: a
// believable production retention, chosen to be neither zero nor implausibly
// long, so a defect that reports zero cannot be mistaken for a rounding
// artefact of a real default.
const DefaultBuildCacheMaxAge = 14 * 24 * time.Hour

// buildCacheDefaultMaxAge returns the age at which this provider expires a
// cached build layer when a caller leaves [compute.BuildCache.MaxAge] at
// zero. See [DefectBuildCacheDefaultIsForever].
func (p *Provider) buildCacheDefaultMaxAge() time.Duration {
	if p.broken(DefectBuildCacheDefaultIsForever) {
		return 0
	}
	if p.cfg.BuildCacheMaxAge > 0 {
		return p.cfg.BuildCacheMaxAge
	}
	return DefaultBuildCacheMaxAge
}
