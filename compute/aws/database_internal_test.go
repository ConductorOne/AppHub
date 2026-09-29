// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
)

// TestASecurityGroupAppHubOwnsAsSomethingElseIsNotAdopted is the half of the
// ownership property that needs the physical name.
//
// It lives in an internal test rather than beside the others because planting the
// decoy needs the name this provider *would* create, and exporting a
// name-rendering method for a test to call would put a test seam on the
// production type. The property is the same one: an IAM role, a security group
// and a cluster are all resources apphub legitimately owns, and adopting one as
// another silently repurposes a trust relationship or a network hole. This is
// USOSS-13's finding, and it matters here because this port creates a security
// group in the same namespace every other AWS port's groups live in.
func TestASecurityGroupAppHubOwnsAsSomethingElseIsNotAdopted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := Config{
		Region:           MemoryRegion,
		DefaultPlacement: "default",
		Placements: map[string]PlacementConfig{"default": {
			VPC:                        MemoryVPC,
			Subnets:                    []string{"apphub-test-subnet-one", "apphub-test-subnet-two"},
			ControlPlaneSecurityGroups: []string{"apphub-test-control-plane-sg"},
		}},
		Identity: IdentityConfig{NamePrefix: "apphub-"},
		Relational: &RelationalConfig{
			NamePrefix:     "apphub-",
			EngineVersions: map[compute.SQLEngine][]string{compute.EnginePostgres: {"16"}},
		},
	}
	sub := NewMemorySubstrate()
	p, err := New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}

	names, err := p.relationalNames("adopt")
	if err != nil {
		t.Fatalf("rendering the names: %v", err)
	}
	mem, ok := sub.EC2.(*MemoryEC2)
	if !ok {
		t.Fatal("the fixture is not using the in-memory EC2")
	}
	// AppHub's own ownership tag, and a component that is not this port's.
	mem.PutOwnedAs(names.SecurityGroup, MemoryVPC, componentIdentity)

	rp, err := p.Relational()
	if err != nil {
		t.Fatalf("acquiring the relational port: %v", err)
	}
	_, err = rp.EnsureRelational(ctx, compute.RelationalSpec{
		Name:          "adopt",
		Engine:        compute.EnginePostgres,
		EngineVersion: "16",
		DatabaseName:  "appdb",
		AdminUsername: "appuser",
		AdminPassword: compute.NewSecretValue("irrelevant-to-this-assertion"),
		Capacity:      compute.CapacityRange{MinUnits: 0.25, MaxUnits: 2},
		Ingress: []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: postgresPort},
		},
	})
	if err == nil {
		t.Fatal("Ensure adopted a security group apphub created as a workload identity's group; " +
			"both tags have to match, because the ownership tag alone makes every resource this " +
			"platform owns interchangeable by name")
	}
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("refused with %v, want compute.ErrNotOwned", err)
	}
}

// TestOnlyTheAdapterFilesImportAnAWSSDK derives the claim awssdk.go used to make
// in a comment.
//
// The comment said "this file is the only one in the package that imports an AWS
// SDK", and USOSS-14 falsified it by adding a second adapter. A comment stating a
// property of a file set is the artefact-drifts-from-code defect in its cheapest
// form, so the property is now derived from the package's own source and the
// allowed set is small enough to read.
//
// The property is worth holding rather than merely recording: everything above
// [Substrate] is the same code whether it runs against an account or against
// memory, and that is only true while the SDK cannot be reached from anywhere
// else in the package.
func TestOnlyTheAdapterFilesImportAnAWSSDK(t *testing.T) {
	t.Parallel()

	// The files permitted to name an AWS SDK: each adapter and its tests. A
	// port that lands a new substrate adapter adds it here, which is the point
	// -- the addition is the moment a reviewer is asked whether another file may
	// reach the SDK.
	allowed := map[string]bool{
		"awssdk.go":          true,
		"awssdkdb.go":        true,
		"endpointawssdk.go":  true,
		"ssmclient.go":       true,
		"ecsclient.go":       true,
		"schedulerclient.go": true,
		// The build-task adapter, which is the substrate half of the hosted
		// BuildRunner: RunTask, DescribeTasks, StopTask and one log read, each
		// a translation of one API call. It is also the only adapter that
		// constructs its own clients, because the composition root is not
		// permitted the SDK and so cannot build an argument for it -- see
		// NewSDKBuildTaskRunner.
		"buildtaskclient.go":         true,
		"awssdk_internal_test.go":    true,
		"ecsclient_internal_test.go": true,
		"awssdkobj_test.go":          true,
		"awssdkdb_internal_test.go":  true,
		"ssmclient_internal_test.go": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	var offenders, scanned []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		scanned = append(scanned, e.Name())
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(path, "github.com/aws/") {
				continue
			}
			if !allowed[e.Name()] {
				offenders = append(offenders, e.Name()+" imports "+path)
			}
		}
	}
	// A walk that found nothing passes every assertion over it.
	if len(scanned) < 10 {
		t.Fatalf("only %d Go files found in the package directory; the walk is not working: %v",
			len(scanned), scanned)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("an AWS SDK is imported outside the adapter files:\n  %s\n"+
			"Everything above Substrate has to be the same code against an account and against "+
			"memory, which stops being true the moment the SDK is reachable from the port logic.",
			strings.Join(offenders, "\n  "))
	}
	// And the adapters really do import one, so the allowlist is not a list of
	// files that happen to be clean.
	for _, name := range []string{"awssdk.go", "awssdkdb.go", "ssmclient.go", "ecsclient.go"} {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		var found bool
		for _, imp := range f.Imports {
			if strings.HasPrefix(strings.Trim(imp.Path.Value, `"`), "github.com/aws/") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is on the adapter allowlist and imports no AWS SDK; the allowlist has "+
				"gone stale", name)
		}
	}
}

// TestReconcilingIngressToleratesAStaleRead is USOSS-11's finding, and it is the
// kind that passes two test suites separately and breaks on merge.
//
// The removal set is computed from a *read* of the security group and the
// substrate call happens after it. So the case to exercise is not "the rules were
// already gone when the read happened" — reconciliation computes no removal then
// — but "the read said the rule was there and by the time the revoke ran it was
// not". A concurrent teardown is the plausible cause, and failing an Ensure for
// it turns a race into a broken deploy when the desired state was reached anyway.
//
// It is an internal test because the stale read has to be *constructed*: driving
// EnsureRelational and then removing rules out of band produces the other
// scenario, which computes no removal and passes whether the tolerance is there
// or not. That is exactly the trap — the first version of this test did that and
// passed with the tolerance deleted.
//
// The mirror case is the same shape on the authorise side: a read that missed a
// rule somebody else added, so the provider tries to add it again.
//
// The tolerance is at this call site rather than in the substrate: [EC2API]
// reports what EC2 reports, so a provider revoking a rule it never wrote stays a
// visible mistake everywhere else.
func TestReconcilingIngressToleratesAStaleRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	rule := func(source string) SecurityGroupRule {
		r := singlePort("tcp", postgresPort, "")
		r.SourceGroup = source
		return r
	}
	newGroup := func(t *testing.T) (*Provider, *MemoryEC2, *SecurityGroupRecord) {
		t.Helper()
		sub := NewMemorySubstrate()
		p := &Provider{sub: sub, cfg: Config{Region: MemoryRegion}, name: DefaultName}
		mem, ok := sub.EC2.(*MemoryEC2)
		if !ok {
			t.Fatal("the fixture is not using the in-memory EC2")
		}
		g, err := mem.CreateSecurityGroup(ctx, CreateSecurityGroupRequest{
			Name: "apphub-stale", VPC: MemoryVPC, Description: "test",
		})
		if err != nil {
			t.Fatalf("creating the group: %v", err)
		}
		return p, mem, g
	}

	t.Run("a revoke of a rule that has already gone", func(t *testing.T) {
		t.Parallel()
		p, mem, g := newGroup(t)
		// The read claims a rule the substrate does not have, which is what a
		// read taken a moment before a concurrent teardown looks like.
		stale := copyGroup(g)
		stale.Ingress = []SecurityGroupRule{rule("apphub-test-cp-one")}

		if err := p.reconcileIngress(ctx, stale, nil); err != nil {
			t.Errorf("reconciling from a stale read failed with %v; the rule the removal set was "+
				"computed from is already gone, the desired state is reached, and failing here "+
				"means a concurrent teardown breaks a deploy", err)
		}
		// And the group really is empty afterwards, so the tolerance did not
		// hide a revoke that should have happened.
		got, err := mem.DescribeSecurityGroupByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("reading the group back: %v", err)
		}
		if len(got.Ingress) != 0 {
			t.Errorf("the group holds %v after reconciling to an empty rule set", got.Ingress)
		}
	})

	t.Run("an authorise of a rule that is already there", func(t *testing.T) {
		t.Parallel()
		p, mem, g := newGroup(t)
		want := rule("apphub-test-cp-one")
		// Somebody else added it after the read was taken.
		if err := mem.AuthorizeIngress(ctx, g.ID, []SecurityGroupRule{want}); err != nil {
			t.Fatalf("adding the rule out of band: %v", err)
		}
		// The read predates that, so it shows an empty group.
		stale := copyGroup(g)
		stale.Ingress = nil

		if err := p.reconcileIngress(ctx, stale, []SecurityGroupRule{want}); err != nil {
			t.Errorf("reconciling from a stale read failed with %v; the rule this call was about "+
				"to add is already there and the desired state is reached", err)
		}
		got, err := mem.DescribeSecurityGroupByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("reading the group back: %v", err)
		}
		if len(got.Ingress) != 1 || got.Ingress[0] != want {
			t.Errorf("the group holds %v, want exactly the one desired rule", got.Ingress)
		}
	})

	t.Run("a substrate failure that is not a race still fails", func(t *testing.T) {
		t.Parallel()
		p, mem, g := newGroup(t)
		// The tolerance must not swallow a real failure. A throttle is the one
		// that matters most: it has to reach the caller as compute.ErrTransient.
		stop := mem.FailNext(ErrThrottled)
		defer stop()
		err := p.reconcileIngress(ctx, copyGroup(g), []SecurityGroupRule{rule("apphub-test-cp-one")})
		if err == nil {
			t.Fatal("a throttled reconcile reported success; the tolerance for a race must not " +
				"swallow every failure")
		}
		if !errors.Is(err, compute.ErrTransient) {
			t.Errorf("a throttled reconcile surfaced as %v, want compute.ErrTransient", err)
		}
	})
}

// TestEveryProviderStatusIsEitherMappedOrFatal is CONTRACT rule 9 for the two
// state gates, tested over the whole enumerated set plus the outside of it.
//
// The first version of these gates had a tolerant default returning
// PhasePending, and review demonstrated it: one unrecognised value through each
// mapper came back as a normal transitional state. That is the third outcome a
// gate must not have — it turns a new *terminal* provider status into polling
// until the caller's deadline expires, which deletes the diagnosis and teaches
// the caller to retry something that will never become usable.
//
// The population is the map itself, so it grows with the enumeration, plus a set
// of strings from outside it including the shapes a careless normalisation would
// admit.
func TestEveryProviderStatusIsEitherMappedOrFatal(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		known map[string]compute.Phase
		mapFn func(string) (compute.Phase, error)
		// unknown are strings outside the enumeration.
		unknown []string
	}{
		"RDS": {
			known: relationalClusterPhases,
			mapFn: relationalPhase,
			unknown: []string{
				"", " ", "quantum-superposition", "available-ish",
				// A status AWS could plausibly add, which is the case this is
				// really about.
				"storage-throughput-optimization",
				// Shapes a normalisation would wrongly admit. Case and
				// surrounding space ARE normalised deliberately (RDS is
				// inconsistent about them), so they are not here; these are not.
				"available,", "available available", "AVAILABLE-",
			},
		},
		"DynamoDB": {
			known: keyValueTablePhases,
			mapFn: keyValuePhase,
			unknown: []string{
				"", " ", "RESTORING", "ACTIVE_PENDING", "CREATED",
				"REPLICA_NOT_AUTHORIZED", "ACTIVE,", "ACTIVE ACTIVE",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(tc.known) == 0 {
				t.Fatal("the enumeration is empty, so this derivation is about nothing")
			}
			// Every enumerated status maps, and to the phase the map says.
			for status, want := range tc.known {
				got, err := tc.mapFn(status)
				if err != nil {
					t.Errorf("the enumerated status %q was refused: %v", status, err)
					continue
				}
				if got != want {
					t.Errorf("status %q mapped to %q, want %q", status, got, want)
				}
			}
			// Case and surrounding whitespace are normalised, deliberately: the
			// APIs are not consistent about them and a case difference is not a
			// new status. Asserted so the normalisation is a decision rather
			// than an accident.
			for status := range tc.known {
				for _, variant := range []string{
					strings.ToUpper(status), strings.ToLower(status), " " + status + " ",
				} {
					if _, err := tc.mapFn(variant); err != nil {
						t.Errorf("the case/space variant %q of the enumerated status %q was "+
							"refused; normalising those two is deliberate", variant, status)
					}
				}
			}
			// And everything outside is fatal, naming the status.
			for _, status := range tc.unknown {
				got, err := tc.mapFn(status)
				if err == nil {
					t.Errorf("the unrecognised status %q was accepted as %q. An unrecognised "+
						"status may be terminal, and treating it as converging turns a "+
						"diagnosable failure into a wait that never ends", status, got)
					continue
				}
				if !errors.Is(err, compute.ErrFailed) {
					t.Errorf("the unrecognised status %q was refused with %v, which does not "+
						"match compute.ErrFailed", status, err)
				}
				if status != "" && status != " " && !strings.Contains(err.Error(), status) {
					t.Errorf("the refusal for %q does not name the status, so an operator cannot "+
						"tell which one to add: %v", status, err)
				}
			}
		})
	}
}

// TestTheWaitLoopSleepsTheConfiguredInterval is review's B3 and then their B1 on
// the fix for it.
//
// # What the first version measured, and why it was wrong
//
// It counted successful reads inside a wall-clock window and asserted the count
// was small. Review built the load and demonstrated the consequence: with
// GOMAXPROCS(1) and 64 runnable goroutines, the **correct** implementation failed
// five times out of five — 4, 3, 3, 3, 4 reads — while the idle control passed a
// hundred out of a hundred.
//
// **A count over a duration is a measurement of the scheduler, not of the code.**
// Lowering the threshold does not fix that; it makes the threshold luckier. The
// author of #25 hit the same thing and went from ten reads to three, which this
// result shows is still a threshold.
//
// # What this measures instead
//
// The sleep the loop **requests**, through a substituted [waiter]. That is the
// property the interval actually governs, it is exact, and load cannot perturb it:
// a loop asking for 5s and a loop asking for 1ms differ with no reference to
// elapsed time. The clock is substituted too, so "remaining deadline" is a
// number this test chooses rather than one the machine supplies.
//
// There is no wall-clock assertion anywhere below, and no count-over-duration.
func TestTheWaitLoopSleepsTheConfiguredInterval(t *testing.T) {
	t.Parallel()

	// A fake clock that only moves when the loop sleeps, so the whole run is
	// deterministic and takes no real time.
	type run struct {
		sleeps []time.Duration
		reads  int
		// order records reads and sleeps interleaved, so the alternation the
		// loop must produce is checkable rather than assumed.
		order []string
	}
	drive := func(interval, timeout time.Duration, readsBeforeReady int) (*run, error) {
		r := &run{}
		clock := time.Unix(0, 0)
		w := waiter{
			sleep: func(d time.Duration) {
				r.sleeps = append(r.sleeps, d)
				r.order = append(r.order, "sleep")
				clock = clock.Add(d)
			},
			now: func() time.Time { return clock },
		}
		_, err := w.waitFor(context.Background(), interval,
			compute.WaitOptions{Timeout: timeout},
			func() (compute.Status, bool, error) {
				r.reads++
				r.order = append(r.order, "read")
				phase := compute.PhasePending
				done := readsBeforeReady > 0 && r.reads >= readsBeforeReady
				if done {
					phase = compute.PhaseReady
				}
				return compute.Status{Ref: compute.Ref{ID: "x"}, Phase: phase}, done, nil
			})
		return r, err
	}

	t.Run("each sleep is exactly the configured interval", func(t *testing.T) {
		t.Parallel()
		// A deadline far longer than three intervals, so nothing is truncated
		// and every sleep is the interval itself.
		const interval = 50 * time.Millisecond
		r, err := drive(interval, time.Hour, 3)
		if err != nil {
			t.Fatalf("the wait failed: %v", err)
		}
		if r.reads != 3 {
			t.Fatalf("the loop read %d times, want 3", r.reads)
		}
		// Two sleeps between three reads, each the full interval. This is the
		// assertion the old count-in-a-window one was reaching for, stated
		// exactly.
		want := []time.Duration{interval, interval}
		if !slices.Equal(r.sleeps, want) {
			t.Errorf("the loop requested sleeps of %v, want %v. The retry machinery bounds "+
				"failures rather than throughput, so the wait loop's own interval is the only "+
				"thing keeping a multi-minute Aurora creation from being read a thousand times a "+
				"second", r.sleeps, want)
		}
		// And they alternate, which is what makes "one sleep per read" a
		// property rather than an arithmetic coincidence.
		if !slices.Equal(r.order, []string{"read", "sleep", "read", "sleep", "read"}) {
			t.Errorf("reads and sleeps did not alternate: %v", r.order)
		}
	})

	t.Run("an unconfigured provider sleeps its default", func(t *testing.T) {
		t.Parallel()
		r, err := drive((&Config{}).pollInterval(), time.Hour, 2)
		if err != nil {
			t.Fatalf("the wait failed: %v", err)
		}
		if len(r.sleeps) != 1 || r.sleeps[0] != DefaultPollInterval {
			t.Errorf("an unconfigured provider requested sleeps of %v; the default is %s",
				r.sleeps, DefaultPollInterval)
		}
	})

	t.Run("the default itself is production-safe", func(t *testing.T) {
		t.Parallel()
		// Separate from the subtest above, and the separation is the point.
		//
		// That one asserts the loop *uses* DefaultPollInterval, comparing against
		// the constant — so it passes whatever the constant is. Setting the
		// default back to a millisecond, which is the defect B3 was raised for,
		// left it green. A self-referential assertion: it cannot fail for the
		// reason it exists.
		//
		// Found by reproducing the defect against the new test rather than by
		// reading it, which is the only way that shape shows up. So the claim
		// about the *value* is made here, against an absolute bound rather than
		// against itself.
		const floor = time.Second
		if DefaultPollInterval < floor {
			t.Errorf("DefaultPollInterval is %s. The SDK's retry machinery bounds failures rather "+
				"than throughput, so nothing but this constant stops a multi-minute Aurora "+
				"creation being read hundreds of times a second until AWS throttles it — at which "+
				"point the port reports ErrTransient instead of continuing the caller's Wait. "+
				"Anything under %s is a test-speed number in a production default; configure a "+
				"fast one through Config.PollInterval instead", DefaultPollInterval, floor)
		}
		if MinPollInterval >= floor {
			t.Errorf("MinPollInterval is %s, which is not below the production floor of %s; a "+
				"hermetic suite then cannot configure a fast interval and the floor is doing two "+
				"jobs", MinPollInterval, floor)
		}
	})

	t.Run("a sleep is truncated to the remaining deadline, never past it", func(t *testing.T) {
		t.Parallel()
		// The interval is far longer than the deadline, so the one sleep must be
		// the deadline rather than the interval: a production interval must not
		// overshoot a caller's short Wait.
		r, err := drive(time.Hour, 120*time.Millisecond, 0)
		if !errors.Is(err, compute.ErrTimeout) {
			t.Fatalf("the wait returned %v, want compute.ErrTimeout", err)
		}
		for i, d := range r.sleeps {
			if d > 120*time.Millisecond {
				t.Errorf("sleep %d was %s, longer than the caller's whole deadline; the caller "+
					"chose the deadline and the interval is this provider's business", i, d)
			}
		}
		if len(r.sleeps) != 1 {
			t.Errorf("the loop requested %d sleeps against a deadline shorter than one interval, "+
				"want 1: %v", len(r.sleeps), r.sleeps)
		}
	})

	t.Run("interval resolution", func(t *testing.T) {
		t.Parallel()
		for name, tc := range map[string]struct {
			in   time.Duration
			want time.Duration
		}{
			"unset means the default":    {0, DefaultPollInterval},
			"negative means the default": {-time.Second, DefaultPollInterval},
			"below the floor is raised":  {time.Nanosecond, MinPollInterval},
			"a configured value stands":  {time.Millisecond, time.Millisecond},
		} {
			if got := (&Config{PollInterval: tc.in}).pollInterval(); got != tc.want {
				t.Errorf("%s: %s resolved to %s, want %s", name, tc.in, got, tc.want)
			}
		}
	})
}

// failingEC2 wraps an [EC2API] and fails one method, so a test can make exactly
// one observation fail while every other call behaves.
//
// Wrapping rather than a whole fake: the point is that the *cluster* read
// succeeds and the *group* read does not, which is the shape review used, and a
// fake that failed everything would not distinguish "could not observe the
// network policy" from "could not observe anything".
type failingEC2 struct {
	EC2API
	failByID error
}

func (f failingEC2) DescribeSecurityGroupByID(ctx context.Context, id string) (*SecurityGroupRecord, error) {
	if f.failByID != nil {
		return nil, f.failByID
	}
	return f.EC2API.DescribeSecurityGroupByID(ctx, id)
}

// TestAFailedIngressObservationIsFatalNotEmpty is review's B4.
//
// The defect: every DescribeSecurityGroupByID error was swallowed and whatever
// subset had been read was returned as the effective declarative ingress set. A
// throttled or denied EC2 read therefore said *there are no rules* about a group
// that still had one — and "no ingress rules" reads as safe, so anything scanning
// the effective spec passes on a population it never obtained. An empty
// declarative set cannot mean both "observed empty" and "could not observe".
//
// Three cases, and the positive control is what makes the other two mean
// something: a genuinely empty group must still report an empty set with no
// error, or the fix would just be "always fail".
func TestAFailedIngressObservationIsFatalNotEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	build := func(t *testing.T) (*Provider, *Substrate) {
		t.Helper()
		cfg := Config{
			Region:           MemoryRegion,
			DefaultPlacement: "default",
			PollInterval:     time.Millisecond,
			Placements: map[string]PlacementConfig{"default": {
				VPC:                        MemoryVPC,
				Subnets:                    []string{"apphub-test-subnet-one", "apphub-test-subnet-two"},
				ControlPlaneSecurityGroups: []string{"apphub-test-control-plane-sg"},
			}},
			Identity: IdentityConfig{NamePrefix: "apphub-"},
			Relational: &RelationalConfig{
				NamePrefix:     "apphub-",
				EngineVersions: map[compute.SQLEngine][]string{compute.EnginePostgres: {"16"}},
			},
		}
		sub := NewMemorySubstrate()
		p, err := New(sub, cfg)
		if err != nil {
			t.Fatalf("constructing the provider: %v", err)
		}
		return p, sub
	}
	spec := func(name string, rules []compute.IngressRule) compute.RelationalSpec {
		return compute.RelationalSpec{
			Name: name, Engine: compute.EnginePostgres, EngineVersion: "16",
			DatabaseName: "appdb", AdminUsername: "appuser",
			AdminPassword: compute.NewSecretValue("irrelevant-to-this-assertion"),
			Capacity:      compute.CapacityRange{MinUnits: 0.25, MaxUnits: 2},
			Ingress:       rules,
		}
	}

	t.Run("a genuinely empty group reports an empty set", func(t *testing.T) {
		t.Parallel()
		p, _ := build(t)
		rp, err := p.Relational()
		if err != nil {
			t.Fatalf("Relational: %v", err)
		}
		st, err := rp.EnsureRelational(ctx, spec("empty", nil))
		if err != nil {
			t.Fatalf("EnsureRelational: %v", err)
		}
		got, err := rp.DescribeRelational(ctx, st.Ref)
		if err != nil {
			t.Fatalf("DescribeRelational: %v", err)
		}
		if len(got.Spec.Ingress) != 0 {
			t.Errorf("an endpoint provisioned with no ingress reported %v", got.Spec.Ingress)
		}
	})

	// The table carries the expected sentinel rather than deriving it below,
	// because the denial arm MOVED: #39 (USOSS-55) remapped [ErrDenied] from
	// compute.ErrFailed to [compute.ErrNotPermitted], and this assertion pinned
	// the old answer. It merged clean into this branch and the gate is what
	// caught it. Keeping the expectation beside the injected error is what makes
	// the next such move a one-line edit at the place a reader is already
	// looking.
	for name, tc := range map[string]struct {
		injected error
		want     error
	}{
		"a throttled read": {ErrThrottled, compute.ErrTransient},
		"a denied read":    {ErrDenied, compute.ErrNotPermitted},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, sub := build(t)
			rp, err := p.Relational()
			if err != nil {
				t.Fatalf("Relational: %v", err)
			}
			// One real rule, so there is something for a swallowed error to
			// hide.
			st, err := rp.EnsureRelational(ctx, spec("hidden", []compute.IngressRule{
				{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: postgresPort},
			}))
			if err != nil {
				t.Fatalf("EnsureRelational: %v", err)
			}
			// Confirm the rule is really there, so the assertion below is not
			// about an endpoint that never had one.
			before, err := rp.DescribeRelational(ctx, st.Ref)
			if err != nil {
				t.Fatalf("the first DescribeRelational: %v", err)
			}
			if len(before.Spec.Ingress) == 0 {
				t.Fatal("the endpoint has no ingress rules, so a swallowed error would hide " +
					"nothing and this test is about nothing")
			}

			// Now fail only the group read.
			sub.EC2 = failingEC2{EC2API: sub.EC2, failByID: tc.injected}
			got, err := rp.DescribeRelational(ctx, st.Ref)
			if err == nil {
				t.Fatalf("DescribeRelational succeeded with a failed security-group read and "+
					"reported %d ingress rule(s). An empty or partial declarative set cannot "+
					"mean both 'observed empty' and 'could not observe', and 'no ingress rules' "+
					"reads as safe", len(got.Spec.Ingress))
			}
			// Classified, so a caller can tell a throttle from a denial.
			if !errors.Is(err, tc.want) {
				t.Errorf("the failure surfaced as %v, want %v: the EC2 error has to reach the "+
					"caller through the compute taxonomy, not as an opaque read failure",
					err, tc.want)
			}
			// And distinguishable, which is the point of classifying at all: a
			// throttle says wait, a denial says fix an IAM policy, and a caller
			// that cannot tell them apart will retry one of them forever.
			for _, wrong := range []error{compute.ErrTransient, compute.ErrNotPermitted} {
				if !errors.Is(tc.want, wrong) && errors.Is(err, wrong) {
					t.Errorf("the failure matches both %v and %v, so a caller branching on "+
						"either is sent to the wrong remedy: %v", tc.want, wrong, err)
				}
			}
		})
	}

	t.Run("a group the cluster references and EC2 does not have is an observation", func(t *testing.T) {
		t.Parallel()
		p, sub := build(t)
		rp, err := p.Relational()
		if err != nil {
			t.Fatalf("Relational: %v", err)
		}
		st, err := rp.EnsureRelational(ctx, spec("absent", []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: postgresPort},
		}))
		if err != nil {
			t.Fatalf("EnsureRelational: %v", err)
		}
		// Absence is the one thing that is knowledge rather than failure: the
		// group contributes no rules and the next Ensure recreates it.
		sub.EC2 = failingEC2{EC2API: sub.EC2, failByID: ErrNoSuchResource}
		got, err := rp.DescribeRelational(ctx, st.Ref)
		if err != nil {
			t.Fatalf("a describe whose security group is gone failed with %v; an absent group is "+
				"an observation, and teardown and reconciliation have to be re-runnable", err)
		}
		if len(got.Spec.Ingress) != 0 {
			t.Errorf("an absent group contributed %v", got.Spec.Ingress)
		}
	})
}

// renderingEC2 is an in-memory EC2 that renders through the SDK adapter's own
// [ipPermissions] before mutating, and classifies a refusal the way the adapter
// does.
//
// It exists because USOSS-11 could not reproduce the port-range defect against
// [MemoryEC2] at all: MemoryEC2 matches rules by equality on the record, so it
// removed a rule the real adapter could not even describe, and end to end
// everything looked correct. **The fake accepted what the real adapter refuses.**
//
// So the fake is made to share the one step where the loss happened. Anything
// asserted through this type is asserted against the production rendering; a
// green against MemoryEC2 alone would mean nothing here.
type renderingEC2 struct {
	EC2API
	// refusalAs, when set, is wrapped around a rendering refusal — used to
	// reproduce the defect by re-classifying the refusal as the substrate
	// sentinel the reconciler tolerates.
	refusalAs error
}

func (r renderingEC2) render(rules []SecurityGroupRule) error {
	if _, err := ipPermissions(rules); err != nil {
		if r.refusalAs != nil {
			return fmt.Errorf("%w: %w", r.refusalAs, err)
		}
		return err
	}
	return nil
}

func (r renderingEC2) AuthorizeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error {
	if err := r.render(rules); err != nil {
		return err
	}
	return r.EC2API.AuthorizeIngress(ctx, id, rules)
}

func (r renderingEC2) RevokeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error {
	if err := r.render(rules); err != nil {
		return err
	}
	return r.EC2API.RevokeIngress(ctx, id, rules)
}

// TestAWidePortRangeIsRevocable is the end-to-end half of the port-range fix.
//
// A group fronting a database holds 1024-65535 from 0.0.0.0/0 — the rule that
// survived a reported-successful revoke on USOSS-11's container port. Two things
// have to be true, and before the fix neither was:
//
//  1. reconciliation removes it, because it is not a rule this provider asked
//     for;
//  2. and if it *cannot* be removed, the reconcile says so rather than returning
//     nil.
//
// The second is what the tolerance on [ErrNoSuchResource] makes fragile, and it
// is checked by re-classifying a rendering refusal as that sentinel — the exact
// shape of the original defect.
func TestAWidePortRangeIsRevocable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	wide := SecurityGroupRule{
		Protocol: "tcp", FromPort: Port(1024), ToPort: Port(65535), SourceCIDR: "0.0.0.0/0",
	}
	desired := singlePort("tcp", postgresPort, "apphub control plane")
	desired.SourceGroup = "apphub-test-control-plane-sg"

	build := func(t *testing.T, ec2 func(EC2API) EC2API) (*Provider, *MemoryEC2, *SecurityGroupRecord) {
		t.Helper()
		sub := NewMemorySubstrate()
		mem, ok := sub.EC2.(*MemoryEC2)
		if !ok {
			t.Fatal("the fixture is not using the in-memory EC2")
		}
		group, err := mem.CreateSecurityGroup(ctx, CreateSecurityGroupRequest{
			Name: "apphub-test-db-sg", Description: "test", VPC: MemoryVPC,
		})
		if err != nil {
			t.Fatalf("creating the group: %v", err)
		}
		// Authorised straight onto the fake, the way an operator or another
		// system would have: it is in the group without this provider's help.
		if err := mem.AuthorizeIngress(ctx, group.ID, []SecurityGroupRule{wide}); err != nil {
			t.Fatalf("seeding the wide rule: %v", err)
		}
		sub.EC2 = ec2(sub.EC2)
		return &Provider{sub: sub, cfg: Config{Region: MemoryRegion}, name: DefaultName}, mem, group
	}
	stillThere := func(t *testing.T, mem *MemoryEC2, id string) bool {
		t.Helper()
		for _, g := range mem.Groups() {
			if g.ID != id {
				continue
			}
			for _, r := range g.Ingress {
				if r == wide {
					return true
				}
			}
		}
		return false
	}

	t.Run("it is revoked, through the production rendering", func(t *testing.T) {
		t.Parallel()
		p, mem, group := build(t, func(api EC2API) EC2API { return renderingEC2{EC2API: api} })
		read, err := p.sub.EC2.DescribeSecurityGroupByID(ctx, group.ID)
		if err != nil {
			t.Fatalf("reading the group back: %v", err)
		}
		if err := p.reconcileIngress(ctx, read, []SecurityGroupRule{desired}); err != nil {
			t.Fatalf("reconciling: %v. A range read off a group has to be expressible, or the "+
				"provider can neither keep it nor remove it", err)
		}
		if stillThere(t, mem, group.ID) {
			t.Error("1024-65535 from 0.0.0.0/0 is still authorised after a reconcile that " +
				"reported success")
		}
	})

	t.Run("and a refusal it cannot express is never reported as success", func(t *testing.T) {
		t.Parallel()
		// The original defect, reconstructed: the rendering refuses, and the
		// refusal is classified as the sentinel the reconciler tolerates.
		p, mem, group := build(t, func(api EC2API) EC2API {
			return renderingEC2{EC2API: refusingRenderEC2{EC2API: api}, refusalAs: ErrNoSuchResource}
		})
		read, err := p.sub.EC2.DescribeSecurityGroupByID(ctx, group.ID)
		if err != nil {
			t.Fatalf("reading the group back: %v", err)
		}
		err = p.reconcileIngress(ctx, read, []SecurityGroupRule{desired})
		if err == nil && stillThere(t, mem, group.ID) {
			t.Error("reconcileIngress returned nil while 1024-65535 from 0.0.0.0/0 was still " +
				"authorised. That is the defect: a rendering refusal classified as absence is " +
				"read as the rule already being gone, so a caller is told a wide rule was " +
				"removed that is still in force")
		}
	})
}

// refusingRenderEC2 makes every rule unrenderable, so that renderingEC2's
// refusal path is the one exercised rather than the happy path.
type refusingRenderEC2 struct{ EC2API }

func (r refusingRenderEC2) RevokeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error {
	// The rules are made unrenderable here rather than in the fixture, so the
	// group really does hold a legitimate range and only the revoke's rendering
	// fails -- which is the asymmetry the defect needed.
	broken := make([]SecurityGroupRule, 0, len(rules))
	for _, rule := range rules {
		rule.FromPort, rule.ToPort = Port(-2), Port(-2)
		broken = append(broken, rule)
	}
	if _, err := ipPermissions(broken); err != nil {
		return err
	}
	return r.EC2API.RevokeIngress(ctx, id, rules)
}
