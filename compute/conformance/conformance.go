// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
)

// TB is the part of [testing.TB] the suite uses.
//
// It is an interface rather than *testing.T so that the suite can be run by
// something that records outcomes instead of failing a test — which is how the
// suite tests itself. A conformance suite that has never been shown to fail
// against a non-conformant provider is an assertion, not a gate.
type TB interface {
	Helper()
	Name() string
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
	Cleanup(func())
	Failed() bool
}

// Factory constructs a provider to test.
//
// It is called more than once and every call must return a provider addressing
// the same substrate. Two of the invariants need that: one ensures a resource
// through one instance and looks for it through another, and one checks that a
// provider configured differently refuses what this one accepts.
type Factory func(tb TB) compute.Provider

// Class is one of the two port classes the interface defines. See the package
// documentation for why the distinction is load-bearing.
type Class string

// The port classes.
const (
	// Async is a port whose Ensure returns a [compute.Status] promptly and whose
	// readiness is a separate Wait.
	Async Class = "asynchronous"
	// Sync is a port whose Ensure returns a usable resource or an error, with no
	// phase and no Wait.
	Sync Class = "synchronous"
)

// Options carries the substrate facts the suite cannot invent and the hooks for
// the invariants the interface cannot express.
//
// Everything here is either operator configuration the provider was constructed
// with (a placement name, a legal function runtime) or a substrate operation the
// contract talks about but does not expose (perform a read as this identity).
// Nothing here is a knob for switching an invariant off.
type Options struct {
	// Placement is a placement name the provider was configured with. Empty
	// means "use the provider's default", which is legal only for a provider
	// that has one.
	Placement string

	// SecondPlacement is a second configured placement name, empty when the
	// provider under test has only one.
	//
	// It exists because placement scoping is only observable with two: an
	// identity and a secret are namespace-scoped on some substrates, so a
	// workload in a second placement can use neither unless both were placed
	// with it. A provider that never configures two never exercises the rule.
	SecondPlacement string

	// UnknownPlacement is a placement name the provider was *not* configured
	// with, used to check that a provider refuses rather than guesses. Empty
	// means a generated name unlikely to collide.
	UnknownPlacement string

	// Zone is a zone identifier legal for [compute.ObjectClassZonal]. Required
	// if the provider advertises [compute.CapObjectStoreZonal].
	Zone string

	// FunctionRuntime is a runtime identifier the provider accepts. Required if
	// the provider advertises [compute.CapFunction].
	FunctionRuntime string

	// RejectedFunctionRuntime is a runtime identifier the provider does not
	// accept. Empty means a generated one.
	RejectedFunctionRuntime string

	// CertificateRef is a certificate the provider can resolve. Required if the
	// provider advertises [compute.CapFunctionEndpoint].
	CertificateRef string

	// Engine and EngineVersion name a relational engine the provider offers.
	// Required if the provider advertises [compute.CapRelationalDatabase].
	Engine        compute.SQLEngine
	EngineVersion string

	// RouteHost is a hostname the provider's ingress may be asked to route.
	// Empty means a generated name under the reserved .invalid TLD.
	RouteHost string

	// HonoursSecretVersions declares that this provider's secret store has
	// revisions and honours [compute.SecretBinding.Version].
	//
	// A declaration rather than a capability, and false by default, because the
	// two outcomes are both correct and the suite has to know which one it is
	// looking at. A provider that honours pinning and forgets to declare it fails
	// the check rather than skipping it, which is the direction that gets noticed.
	//
	// Pinning is not capability-gated on the interface: a capability is a whole
	// port or a class of behaviour a substrate may structurally lack, and this is
	// one field on one spec whose refusal arrives from the call that could not be
	// satisfied.
	HonoursSecretVersions bool

	// ImplementsExt declares, per compute/ext port name, whether this provider
	// documents that it implements it. The suite checks the lookup helpers agree:
	// a provider that implements a port must be reachable through it, and one
	// that does not must produce a typed refusal rather than a skipped resource.
	//
	// Keys are the port names as [ext.ErrNotImplemented] reports them:
	// "ext.TableBucketProvisioner", "ext.VectorBucketProvisioner",
	// "ext.ExternalAccessGranter". A missing key means false.
	ImplementsExt map[string]bool

	// WithoutIngressProxy, when set, returns a provider configured with no
	// platform ingress proxy. It exists for one invariant: such a provider must
	// reject a [compute.PeerPlatformIngress] rule rather than widen it to the
	// internet. That is a behaviour change USOSS-2 accepted deliberately, and it
	// is the kind of fail-closed property that regresses silently.
	WithoutIngressProxy Factory

	// EnsureBudget bounds how long an asynchronous Ensure may take before it
	// counts as blocking. Zero means two seconds.
	EnsureBudget time.Duration

	// WaitTimeout is the deliberately short deadline used against a resource
	// that will not converge. Zero means 100ms.
	WaitTimeout time.Duration

	// WaitMargin is how far past its deadline a Wait may return. Zero means one
	// second.
	WaitMargin time.Duration

	// --- hooks ------------------------------------------------------------
	//
	// Each of these makes one invariant checkable. A nil hook skips its checks
	// with a message naming what was not verified; it never converts an
	// invariant into a silent pass.

	// Stall makes a resource stop converging, so a Wait against it has something
	// to time out on.
	Stall func(ctx context.Context, p compute.Provider, ref compute.Ref) error

	// CreateUnowned puts a resource at ref into the substrate without this
	// platform's ownership marker. An Ensure that finds one must return
	// [compute.ErrNotOwned].
	CreateUnowned func(ctx context.Context, p compute.Provider, ref compute.Ref) error

	// InduceTransient makes the provider's substrate fail in a way that would
	// succeed if retried — a throttle, a reset connection, a stale-read conflict
	// on an optimistic-concurrency update. It returns a function that stops
	// inducing it.
	//
	// It must be **sticky**: every substrate call fails until the returned
	// function is called. A one-shot hook — arm the next call, consume it, go
	// quiet — is not what this asks for. The gate drives every method of every
	// port the provider has, because the mapping from a substrate's errors onto
	// this taxonomy is written per service: a hook that armed one call, or one
	// service, would pass on a provider that gets its registry right and its
	// identity service wrong.
	//
	// A one-shot hook does not *fail* the gate, and that is deliberate rather
	// than lenient. Whether a provider can throttle its own reads is a fact
	// about its substrate, not a conformance question, so the gate reports the
	// methods it could not reach as contract observations naming each one. The
	// consequence is worth being blunt about: a run whose observations list most
	// of the provider's methods has verified the mapping for the few that are
	// missing from that list, and nothing else.
	//
	// This hook exists because [compute.ErrTransient] is otherwise a sentinel
	// with no gate. Six AWS providers are about to write six independent
	// mappings from a substrate's errors onto this taxonomy, and the one that
	// maps a throttle to [compute.ErrFailed] tells its caller the spec has to
	// change when the deploy would have succeeded on a retry. Nothing else in
	// the suite catches that, and it is not the kind of mistake a reviewer
	// reliably spots in a switch statement with twenty arms.
	//
	// It is substrate-specific by nature — only the provider knows how to make
	// its own API throttle — which is why it is a hook rather than something the
	// suite can do for itself.
	//
	// It takes the kind, same as [Options.InduceDenial] and for the same reason:
	// pinned to one fixed write it can only ever say something about the port
	// behind that write, and a secret Put -- "the cheapest write on any
	// provider" -- does not exist on five of the six AWS providers, so the only
	// gate on their error mapping did not run at all (USOSS-10, then USOSS-42
	// when the fix landed). Passing the kind lets [checkTransientIsNotTerminal]
	// drive whichever port the provider actually advertises for it, so the
	// check runs everywhere instead of nowhere for want of a secret store.
	//
	// Returning an error means "I cannot induce a transient failure for this
	// kind", not "the harness is broken" -- the same contract
	// [Options.InduceDenial] has. A hook that cannot reach one port says so and
	// the suite records that port as unverified by name, then carries on with
	// the others.
	InduceTransient func(ctx context.Context, p compute.Provider, kind compute.Kind) (stop func(), err error)

	// InduceDenial makes the provider's substrate refuse the next operation on
	// kind for authorization reasons -- an IAM AccessDenied, an RBAC rejection, a
	// resource policy. It returns a function that stops inducing it.
	//
	// # Returning an error means "I cannot induce a denial for this kind"
	//
	// Not "the harness is broken". A hook that cannot reach one port says so and
	// the suite records that port as unverified *by name*, then carries on with
	// the others -- because the alternative is worse than it looks. An inert hook
	// makes the provider's Ensure succeed, which is indistinguishable from a
	// provider that maps denials correctly unless somebody says which ports were
	// actually driven. USOSS-26 reported that from the other side: the value of
	// the equivalent transient gate was not the extra coverage, it was that a
	// method the hook could not reach came back as a named observation instead of
	// silence.
	//
	// So the suite reports what it drove and what it could not, and fails rather
	// than passing if it could drive nothing.
	//
	// It takes the kind, which is what lets [checkDenialIsNotAResourceFailure]
	// drive whichever port the provider actually has, so the check runs
	// everywhere rather than being pinned to one fixed write. USOSS-42 gave
	// [Options.InduceTransient] the same treatment for the same reason: it used
	// to be pinned to a secret Put "because a secret Put is the cheapest write on
	// any provider" -- true of a provider that has one, and five of the six AWS
	// providers did not, so the single gate on their error mapping did not run
	// at all (reported by USOSS-10).
	InduceDenial func(ctx context.Context, p compute.Provider, kind compute.Kind) (stop func(), err error)

	// Read and Write perform a data-plane operation as a workload identity, so
	// that a grant is checked by behaviour rather than by inspecting a policy
	// document. They return a non-nil error when the substrate refuses.
	Read  func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error
	Write func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error

	// AnonymousRead attempts an unauthenticated read of a bucket. It must fail
	// for a bucket created with PublicAccess false.
	//
	// Its error, and the errors from [Options.Read], [Options.Write] and
	// [Options.CanExecInto], report whether the substrate refused -- and must NOT
	// be routed through the provider's [compute] error mapping. A refusal here is
	// the *desired* outcome of a fail-closed check, so surfacing it as
	// [compute.ErrNotPermitted] would tell an operator to widen a policy in order
	// to make a security check fail. USOSS-19 caught that while wiring a
	// Kubernetes provider's denial mapping and excluded this path by hand; it is
	// written down here so the next provider does not have to catch it.
	AnonymousRead func(ctx context.Context, p compute.Provider, bucket compute.Ref) error

	// RelationalLogin authenticates against a relational endpoint. It is how the
	// "a re-Ensure must not rotate the admin password" invariant is checked.
	RelationalLogin func(ctx context.Context, p compute.Provider, ref compute.Ref, username string, password compute.SecretValue) error

	// CanExecInto reports whether a workload identity can open an interactive
	// session against a workload. The answer must be no even for a workload with
	// ExecEnabled: exec authorises the operator's principal, not the workload's.
	CanExecInto func(ctx context.Context, p compute.Provider, identity, target compute.Ref) (bool, error)

	// BuildCredentials reports the material this provider makes available to a
	// build — the scoped, short-lived push credential [compute.ImageBuilder]
	// obliges it to mint, in whatever form the substrate uses.
	//
	// It is a hook because the suite cannot know it and must not be able to:
	// the obligation exists precisely so that a minted credential is never
	// visible to the caller, and putting a MintPushCredentials method on the
	// interface was rejected for that reason. So the provider reports it here,
	// to a test, so the test can assert it appears nowhere a build can emit it.
	//
	// A nil hook leaves that invariant unverified and says so. Returning an
	// empty slice is a failure rather than a pass: a scan for nothing finds
	// nothing.
	BuildCredentials func(ctx context.Context, p compute.Provider) ([]string, error)

	// EmitInto makes the provider put marker into the named channel, so that a
	// check which scans that channel for material can first establish the channel
	// carries anything at all.
	//
	// It is the hostile mode USOSS-61 requires, and the marker is the reason it is
	// this shape rather than a capability a provider declares. A declaration is a
	// claim, and a claim a provider can make falsely reproduces the vacuity one
	// level out. Even "emit, then tell me you emitted" is a claim about the
	// fixture: a runner can be asked to emit, report that it did, and write
	// somewhere the check never reads. **"Here is a string only I know; make it
	// appear where a leak would appear" is a claim about the channel**, and the
	// suite settles it by looking.
	//
	// Return an error wrapping [ErrChannelNotHostile] for a channel this provider
	// cannot emit into. That is a refusal, not a failure: whether a substrate's
	// builder can be made to print is a fact about the substrate rather than a
	// conformance question, and the check that wanted the channel reports NOT
	// VERIFIED. What it must never do is accept the request and not carry the
	// marker — a hook that reports success without wiring the channel buys a green
	// for every scan standing on it, which is worse than one that refuses.
	//
	// A nil hook leaves every material scan in [channels] unverified.
	EmitInto func(ctx context.Context, p compute.Provider, channel Channel, marker string) error

	// Rendered returns the artefacts the provider wrote into its substrate — a
	// task definition, a pod spec, a build log — as inspectable strings. It
	// carries two invariants: that secret material never appears in one, and
	// that a declarative element removed from a spec is actually gone.
	Rendered func(ctx context.Context, p compute.Provider) ([]string, error)

	// RenderedRef reports whether one specific resource the suite created has a
	// corresponding entry in what [Options.Rendered] enumerates, and returns
	// that entry when it does (USOSS-48).
	//
	// [Options.Rendered] is a provider-*composed* enumeration, not a channel the
	// suite owns: nothing stops a provider dropping exactly one artefact from it
	// while every other resource renders fine. That leaves the aggregate list
	// non-empty and a scan over it clean, because the scan is searching a set
	// the dropped artefact was never in -- an emptiness gate cannot see a
	// PARTIAL emptying, only a total one. The measured case: a List call whose
	// per-item metadata read failed and was swallowed, so one resource is
	// missing from the enumeration and the rest render fine.
	//
	// The suite can name the exact [compute.Ref] it just created; only the
	// provider can say which artefact, if any, corresponds to it -- so
	// completeness has to be asked per-resource rather than inferred from the
	// aggregate's size or freshness. found=false means the provider has nothing
	// to show for ref, whatever the reason; a provider that answers true for a
	// ref it silently dropped from Rendered defeats the one property this hook
	// exists to observe, so an honest implementation must derive both answers
	// from the same state. Returning found=true with an empty artefact is not a
	// legitimate way to say "nothing here" -- use found=false.
	//
	// A nil hook leaves per-resource correspondence unverified and says so; it
	// does not fall back to searching the aggregate list, because the aggregate
	// list is the thing under test.
	RenderedRef func(ctx context.Context, p compute.Provider, ref compute.Ref) (artefact string, found bool, err error)
	// ImageMetadata reads back the metadata this provider recorded for a
	// pushed image -- labels, build history, whatever the substrate exposes on
	// inspection.
	//
	// It exists because [compute.BuildResult] carries none, so
	// [ChannelImageMetadata] cannot be read the way the other three
	// credential-egress channels are: those come straight back from a call to
	// [compute.ImageBuilder.Build], and this is provider state Build never
	// returns. USOSS-39 claimed the channel and did not build it; `rg
	// BuildArgs compute/conformance compute/fake` found no planting, no
	// read-back hook, no provider storage and no defect, which is what an
	// unbuilt claim looks like from the outside.
	//
	// A nil hook leaves that channel's invariant unverified.
	ImageMetadata func(ctx context.Context, p compute.Provider, image compute.ImageRef) (string, error)

	// BuildCacheDefaultMaxAge reports the age at which this provider expires a
	// cached build layer when a caller leaves [compute.BuildCache.MaxAge] at
	// zero -- the provider's own default, which that field documents as "must
	// not be 'forever'".
	//
	// It is a hook rather than something the suite reads back from a spec
	// because [compute.BuildCache] is an input with no corresponding output:
	// [compute.ImageBuilder.Build] returns no cache policy, so the effective
	// retention a provider actually applies is not observable through the
	// interface at all.
	//
	// A nil hook leaves the invariant unverified.
	BuildCacheDefaultMaxAge func(ctx context.Context, p compute.Provider) (time.Duration, error)
}

func (o *Options) applyDefaults() {
	if o.UnknownPlacement == "" {
		o.UnknownPlacement = "conformance-no-such-placement"
	}
	if o.RejectedFunctionRuntime == "" {
		o.RejectedFunctionRuntime = "conformance-no-such-runtime1.0"
	}
	if o.RouteHost == "" {
		o.RouteHost = "conformance.invalid"
	}
	if o.EnsureBudget == 0 {
		o.EnsureBudget = 2 * time.Second
	}
	if o.WaitTimeout == 0 {
		o.WaitTimeout = 100 * time.Millisecond
	}
	if o.WaitMargin == 0 {
		o.WaitMargin = time.Second
	}
}

// requiredFor reports the options a provider's advertised capabilities make
// mandatory. Missing one is a caller error, not a reason to skip: the suite
// cannot invent a legal function runtime, and pretending the check ran would be
// worse than failing loudly here.
func (o *Options) requiredFor(caps compute.CapabilitySet) []string {
	var missing []string
	if caps.Has(compute.CapObjectStoreZonal) && o.Zone == "" {
		missing = append(missing, "Zone (the provider advertises "+string(compute.CapObjectStoreZonal)+")")
	}
	if caps.Has(compute.CapFunction) && o.FunctionRuntime == "" {
		missing = append(missing, "FunctionRuntime (the provider advertises "+string(compute.CapFunction)+")")
	}
	if caps.Has(compute.CapFunctionEndpoint) && o.CertificateRef == "" {
		missing = append(missing, "CertificateRef (the provider advertises "+string(compute.CapFunctionEndpoint)+")")
	}
	if caps.Has(compute.CapRelationalDatabase) {
		if o.Engine == "" {
			missing = append(missing, "Engine (the provider advertises "+string(compute.CapRelationalDatabase)+")")
		}
		if o.EngineVersion == "" {
			missing = append(missing, "EngineVersion (the provider advertises "+string(compute.CapRelationalDatabase)+")")
		}
	}
	return missing
}

// Env is what a check is handed: the provider under test, the options, and the
// fixtures a spec needs before it can be valid.
type Env struct {
	// Provider is the instance under test.
	Provider compute.Provider
	// Options is the configuration and hooks.
	Options Options
	// Factory makes another provider over the same substrate.
	Factory Factory

	ctx context.Context

	mu        sync.Mutex
	counter   int
	fixtures  map[string]compute.Ref
	notes     []string
	skipNames []string
}

func newEnv(tb TB, factory Factory, opts Options) *Env {
	opts.applyDefaults()
	p := factory(tb)
	if p == nil {
		tb.Fatalf("conformance: the factory returned a nil provider")
	}
	if missing := opts.requiredFor(p.Capabilities()); len(missing) > 0 {
		tb.Fatalf("conformance: provider %q cannot be tested with these Options; set: %s",
			p.Name(), strings.Join(missing, "; "))
	}
	// The context deliberately has no deadline: one invariant is that a Wait
	// given neither a timeout nor a context deadline refuses instead of blocking
	// forever, and a suite-wide deadline would hide it.
	return &Env{
		Provider: p,
		Options:  opts,
		Factory:  factory,
		ctx:      context.Background(),
		fixtures: map[string]compute.Ref{},
	}
}

// Context returns the suite's context. It has no deadline on purpose.
func (e *Env) Context() context.Context { return e.ctx }

// Name returns a fresh logical name with the given stem.
//
// Names are unique per suite run so that one check cannot disturb another, and
// short enough to survive a substrate's naming rules.
func (e *Env) Name(stem string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counter++
	return fmt.Sprintf("cf-%s-%d", stem, e.counter)
}

// note records something the suite observed about the contract itself, as
// opposed to about the provider — most often that an invariant could not be
// checked because the interface exposes no way to observe it. These are printed
// at the end of a run and are direct input to the interface's open items.
func (e *Env) note(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	for _, existing := range e.notes {
		if existing == msg {
			return
		}
	}
	e.notes = append(e.notes, msg)
}

// Notes returns what the suite recorded about the contract during a run.
func (e *Env) Notes() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.notes...)
}

// Check is one invariant.
type Check struct {
	// Name is the check's identifier, and is built so a failure names the port,
	// the class or capability, and the invariant. A conformance failure reading
	// only "assertion failed" is useless to the implementations that follow.
	Name string
	// Port is the port the check exercises, empty for a provider-level check.
	Port string
	// Class is the port class the check applies to, empty when it applies to
	// both.
	Class Class
	// Invariant is the sentence the check enforces, quoted in failures.
	Invariant string
	// Fn runs the check.
	Fn func(tb TB, e *Env)
}

// skip reports that an invariant could not be checked, naming what is missing.
// It never passes silently: a caller reading the output sees the invariant it
// did not get.
func skip(tb TB, e *Env, invariant, missing string) {
	tb.Helper()
	e.mu.Lock()
	e.skipNames = append(e.skipNames, tb.Name())
	e.mu.Unlock()
	tb.Skipf("conformance: NOT VERIFIED — %s. This provider's Options do not supply %s, "+
		"so the invariant was not exercised.", invariant, missing)
}

// skipBecause is skip for an invariant that could not be checked for a reason
// that is not a missing Option — a provider that genuinely has no port the check
// can drive.
//
// It is deliberately the same mechanism as skip rather than a quieter one. The
// rule USOSS-32 landed is that an unverified invariant is reported as
// unverified: a check may legitimately have nothing to drive, and when that
// happens it says so in the same place every other unverified invariant is
// counted. What it must never do is report the same outcome as a check that
// drove something and found nothing wrong.
func skipBecause(tb TB, e *Env, invariant, because string) {
	tb.Helper()
	e.mu.Lock()
	e.skipNames = append(e.skipNames, tb.Name())
	e.mu.Unlock()
	tb.Skipf("conformance: NOT VERIFIED — %s. %s.", invariant, because)
}

// Run executes the whole suite against the provider the factory produces.
//
// Each check is a subtest, so a failure names the port and the invariant in the
// test name as well as in the message.
func Run(t *testing.T, factory Factory, opts Options) {
	t.Helper()
	e := newEnv(t, factory, opts)
	checks := allChecks(e)
	for _, c := range checks {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			c.Fn(t, e)
		})
	}
	if notes := e.Notes(); len(notes) > 0 {
		t.Logf("conformance: %d contract observation(s) for provider %q — these are gaps in what "+
			"the interface lets a suite check, not provider failures:\n  %s",
			len(notes), e.Provider.Name(), strings.Join(notes, "\n  "))
	}
}

// Report is the outcome of a [Verify] run.
type Report struct {
	// Results is one entry per check, in the order they ran.
	Results []Result
	// Notes is what the suite recorded about the contract itself.
	Notes []string
}

// Result is one check's outcome.
type Result struct {
	// Check is the check's name.
	Check string
	// Invariant is the sentence it enforces.
	Invariant string
	// Skipped reports that the check could not run.
	Skipped bool
	// Messages are everything the check reported.
	Messages []string
}

// Failed reports whether the check failed.
func (r Result) Failed() bool { return !r.Skipped && len(r.Messages) > 0 }

// Failures returns the checks that failed.
func (rep *Report) Failures() []Result {
	var out []Result
	for _, r := range rep.Results {
		if r.Failed() {
			out = append(out, r)
		}
	}
	return out
}

// Skipped returns the checks that could not run.
func (rep *Report) Skipped() []Result {
	var out []Result
	for _, r := range rep.Results {
		if r.Skipped {
			out = append(out, r)
		}
	}
	return out
}

// FailedCheck reports whether the named check failed. Used by the suite's own
// tests, which assert that a deliberately broken provider fails a specific
// invariant rather than merely failing something.
func (rep *Report) FailedCheck(name string) bool {
	for _, r := range rep.Results {
		if r.Check == name && r.Failed() {
			return true
		}
	}
	return false
}

func (rep *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d checks, %d failed, %d not verified\n",
		len(rep.Results), len(rep.Failures()), len(rep.Skipped()))
	for _, r := range rep.Failures() {
		fmt.Fprintf(&b, "FAIL %s\n", r.Check)
		for _, m := range r.Messages {
			fmt.Fprintf(&b, "     %s\n", m)
		}
	}
	for _, r := range rep.Skipped() {
		fmt.Fprintf(&b, "SKIP %s\n", r.Check)
	}
	return b.String()
}

// Verify runs the suite without a [testing.T] and returns what happened.
//
// It exists so the suite can be tested: compute/conformance's own tests drive a
// deliberately non-conformant provider through it and assert that the specific
// invariant it violates is the one that fails. Prefer [Run] in a provider's
// tests.
func Verify(tb TB, factory Factory, opts Options) *Report {
	e := newEnv(tb, factory, opts)
	rep := &Report{}
	for _, c := range allChecks(e) {
		rec := &recorder{name: c.Name, parent: tb}
		runCheck(c, rec, e)
		rep.Results = append(rep.Results, Result{
			Check:     c.Name,
			Invariant: c.Invariant,
			Skipped:   rec.skipped,
			Messages:  rec.messages,
		})
	}
	rep.Notes = e.Notes()
	return rep
}

// runCheck invokes one check against a recorder, converting the recorder's
// Fatalf into a return rather than a process-wide exit.
func runCheck(c Check, rec *recorder, e *Env) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(abort); !ok {
				panic(r)
			}
		}
		for _, fn := range rec.cleanups {
			fn()
		}
	}()
	c.Fn(rec, e)
}

// abort is what a recorder's Fatalf panics with.
type abort struct{}

// recorder is a [TB] that records instead of failing.
type recorder struct {
	name     string
	parent   TB
	messages []string
	skipped  bool
	cleanups []func()
}

func (r *recorder) Helper()      {}
func (r *recorder) Name() string { return r.name }
func (r *recorder) Logf(format string, args ...any) {
	if r.parent != nil {
		r.parent.Logf(format, args...)
	}
}
func (r *recorder) Errorf(format string, args ...any) {
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
	panic(abort{})
}
func (r *recorder) Skipf(format string, args ...any) {
	// The reason is kept: a skip is not a failure, and Result.Failed says so, but
	// a report that did not say what went unverified would be the silent gap this
	// whole mechanism exists to avoid.
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
	r.skipped = true
	panic(abort{})
}
func (r *recorder) Cleanup(fn func()) { r.cleanups = append(r.cleanups, fn) }

// Failed mirrors [Result.Failed]: a skip records its reason as a message but is
// not a failure.
func (r *recorder) Failed() bool { return !r.skipped && len(r.messages) > 0 }

var _ TB = (*recorder)(nil)

// allChecks assembles the suite for one provider.
//
// The order is provider-level first, then per-port lifecycle, then grants, then
// security, then the capability negatives — cheapest and most fundamental first,
// so that a provider that is lying about its own capabilities fails before a
// hundred downstream checks fail for the same reason.
func allChecks(e *Env) []Check {
	var out []Check
	out = append(out, providerChecks(e)...)
	out = append(out, lifecycleChecks(e)...)
	out = append(out, grantChecks(e)...)
	out = append(out, securityChecks(e)...)
	out = append(out, buildChecks(e)...)
	out = append(out, scaleChecks(e)...)
	out = append(out, pullGrantChecks(e)...)
	out = append(out, negativeChecks(e)...)
	out = append(out, extPositiveChecks(e)...)

	seen := map[string]bool{}
	for _, c := range out {
		if seen[c.Name] {
			panic("conformance: duplicate check name " + c.Name)
		}
		seen[c.Name] = true
	}
	return out
}

// sortedCaps is for stable messages.
func sortedCaps(s compute.CapabilitySet) []string {
	out := make([]string, 0, len(s))
	for _, c := range s.List() {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}
