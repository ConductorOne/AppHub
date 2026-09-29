// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/conductorone/apphub/compute"
)

// The port table is the whole of the suite's per-class scoping: which invariants
// apply where is decided by [Port.Class] and [Port.HasGranter] and by nothing
// else. So the table itself is worth pinning. An earlier draft of the design
// document claimed the phase and Wait rules applied to "every port", which would
// have produced a suite asserting a PhaseGone on a type with no phase and, worse,
// six AWS implementations built against a contract that cannot be satisfied.

// TestPortListMatchesTheGranterAudit ties the suite's grant scoping to the
// interface's own audit, so the two cannot drift.
//
// compute.WorkloadGrantPorts is the audited list of interfaces embedding
// Granter, pinned there by a reflect test. This asserts the suite drives grant
// invariants at exactly those ports and no others — which is what stopped
// working when ImageRegistry kept a Granter nobody could implement.
func TestPortListMatchesTheGranterAudit(t *testing.T) {
	t.Parallel()

	// The audit names interfaces; the suite names ports. One mapping, spelled
	// out, so that adding a port with a Granter forces a decision here.
	portForInterface := map[string]string{
		"ObjectStore":         "bucket",
		"KeyValueProvisioner": "key-value-table",
	}

	want := map[string]bool{}
	for _, iface := range compute.WorkloadGrantPorts() {
		port, ok := portForInterface[iface]
		if !ok {
			t.Fatalf("compute.WorkloadGrantPorts names %q, which this suite has no port for; a "+
				"port that can be granted on and is not exercised is untested grant semantics",
				iface)
		}
		want[port] = true
	}

	for _, p := range ports() {
		if p.HasGranter != want[p.Name] {
			t.Errorf("port %q has HasGranter=%t but the interface audit says %t; the suite and "+
				"compute.WorkloadGrantPorts disagree about which substrates authorise by "+
				"workload identity", p.Name, p.HasGranter, want[p.Name])
		}
	}
}

func TestPortClassificationMatchesTheInterface(t *testing.T) {
	t.Parallel()

	want := map[string]struct {
		kind       compute.Kind
		class      Class
		capability compute.Capability
		granter    bool
	}{
		// Synchronous: Ensure returns a usable resource, there is no phase and no
		// Wait. The source system creates all of these with no polling loop.
		"workload-identity": {compute.KindWorkloadIdentity, Sync, "", false},
		// No granter since F1: no registry authorises a workload identity, and
		// the only implementation minted a credential behind the caller's back.
		"image-repository": {compute.KindImageRepository, Sync, compute.CapImageRegistry, false},
		"secret":           {compute.KindSecret, Sync, compute.CapSecretStore, false},
		"bucket":           {compute.KindBucket, Sync, compute.CapObjectStore, true},
		// Synchronous since F8: a cron entry is live on acceptance, so the port
		// has nothing to wait for and Describe reports ErrNotFound after delete.
		"scheduled-job": {compute.KindScheduledJob, Sync, compute.CapScheduledJob, false},

		// Asynchronous: Ensure returns a Status promptly, Describe reports
		// PhaseGone after a delete, and readiness is a separate Wait.
		"container-service":   {compute.KindService, Async, compute.CapContainerService, false},
		"function":            {compute.KindFunction, Async, compute.CapFunction, false},
		"function-endpoint":   {compute.KindFunctionEndpoint, Async, compute.CapFunctionEndpoint, false},
		"relational-database": {compute.KindRelational, Async, compute.CapRelationalDatabase, false},
		"key-value-table":     {compute.KindKeyValueTable, Async, compute.CapKeyValueTable, true},
	}

	got := ports()
	if len(got) != len(want) {
		t.Fatalf("the suite knows %d ports and the interface has %d; a port with no entry here is "+
			"a port nothing checks", len(got), len(want))
	}
	seenName := map[string]bool{}
	seenKind := map[compute.Kind]bool{}
	for _, p := range got {
		exp, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected port %q", p.Name)
			continue
		}
		if seenName[p.Name] {
			t.Errorf("two ports are both named %q", p.Name)
		}
		seenName[p.Name] = true
		if seenKind[p.Kind] {
			t.Errorf("two ports both issue Refs of kind %q", p.Kind)
		}
		seenKind[p.Kind] = true

		if p.Kind != exp.kind {
			t.Errorf("port %q issues kind %q, want %q", p.Name, p.Kind, exp.kind)
		}
		if p.Class != exp.class {
			t.Errorf("port %q is classified %q, want %q; the class decides whether the phase and "+
				"Wait invariants apply, so getting it wrong either asserts a phase on a type that "+
				"has none or silently drops the invariants for a port that does",
				p.Name, p.Class, exp.class)
		}
		if p.Capability != exp.capability {
			t.Errorf("port %q is gated on %q, want %q", p.Name, p.Capability, exp.capability)
		}
		if p.HasGranter != exp.granter {
			t.Errorf("port %q has HasGranter=%t, want %t", p.Name, p.HasGranter, exp.granter)
		}
		if p.ops == nil {
			t.Errorf("port %q has no operations", p.Name)
		}
	}
}

// TestRelationalPortIsNotDrivenThroughGrantChecks pins the decision that came out
// of the Kubernetes falsification exercise: relational access control is SQL,
// above this interface, so the relational port has no Granter and the suite must
// not try to drive one at it. Doing so would be a suite bug reported as a
// provider bug.
func TestRelationalPortIsNotDrivenThroughGrantChecks(t *testing.T) {
	t.Parallel()
	for _, p := range ports() {
		if p.Kind == compute.KindRelational && p.HasGranter {
			t.Error("the suite believes the relational port implements Granter. There is no general " +
				"mapping from a substrate workload identity to a SQL principal: an IAM role maps to " +
				"a Postgres role only with rds-iam enabled, and a Kubernetes ServiceAccount has no " +
				"Postgres meaning at all")
		}
		if p.Kind == compute.KindKeyValueTable && !p.HasGranter {
			t.Error("the suite believes the key-value port has no Granter. Every substrate with " +
				"this product authorises it by workload identity, and the source system grants the " +
				"application's task role eight actions on the table")
		}
	}
}

func TestPortAvailabilityFollowsTheCapabilitySet(t *testing.T) {
	t.Parallel()
	empty := compute.NewCapabilitySet()
	full := compute.NewCapabilitySet(compute.CapObjectStore)

	for _, p := range ports() {
		if p.Capability == "" {
			if !p.Available(empty) {
				t.Errorf("port %q requires no capability but reported itself unavailable", p.Name)
			}
			continue
		}
		if p.Available(empty) {
			t.Errorf("port %q reported itself available to a provider with no capabilities", p.Name)
		}
	}
	bucket := ports()[3]
	if bucket.Name != "bucket" {
		t.Fatalf("the port order changed; this test indexes it: got %q", bucket.Name)
	}
	if !bucket.Available(full) {
		t.Error("the bucket port is unavailable to a provider advertising object storage")
	}
}

func TestOptionsDefaultsAreSafe(t *testing.T) {
	t.Parallel()
	var o Options
	o.applyDefaults()

	if o.UnknownPlacement == "" || o.RejectedFunctionRuntime == "" || o.RouteHost == "" {
		t.Errorf("applyDefaults left a generated value empty: %+v", o)
	}
	if o.EnsureBudget <= 0 || o.WaitTimeout <= 0 || o.WaitMargin <= 0 {
		t.Errorf("applyDefaults left a duration unset: %+v", o)
	}
	// A margin at or below the timeout would make the deadline assertion sharp
	// enough to fail on a loaded machine rather than on a real overrun.
	if o.WaitMargin < o.WaitTimeout {
		t.Errorf("the wait margin (%s) is smaller than the wait timeout (%s), which invites a "+
			"flaky failure rather than a real one", o.WaitMargin, o.WaitTimeout)
	}
	if o.RouteHost != "" && !strings.HasSuffix(o.RouteHost, ".invalid") {
		t.Errorf("the default route host %q is not under the reserved .invalid TLD; a suite that "+
			"names a real hostname could have a provider route traffic somewhere real", o.RouteHost)
	}

	// A caller-supplied value is never overwritten.
	set := Options{
		UnknownPlacement: "mine",
		EnsureBudget:     time.Second,
		WaitTimeout:      2 * time.Second,
		WaitMargin:       3 * time.Second,
		RouteHost:        "chosen.invalid",
	}
	set.applyDefaults()
	if set.UnknownPlacement != "mine" || set.EnsureBudget != time.Second ||
		set.WaitTimeout != 2*time.Second || set.WaitMargin != 3*time.Second ||
		set.RouteHost != "chosen.invalid" {
		t.Errorf("applyDefaults overwrote caller-supplied options: %+v", set)
	}
}

func TestRequiredOptionsFollowTheCapabilities(t *testing.T) {
	t.Parallel()
	// A provider that advertises these cannot be tested without the substrate
	// facts the suite has no way to invent, so the run must fail loudly rather
	// than skip and look green.
	caps := compute.NewCapabilitySet(
		compute.CapObjectStoreZonal, compute.CapFunction,
		compute.CapFunctionEndpoint, compute.CapRelationalDatabase,
	)
	var o Options
	missing := o.requiredFor(caps)
	for _, want := range []string{"Zone", "FunctionRuntime", "CertificateRef", "Engine", "EngineVersion"} {
		var found bool
		for _, m := range missing {
			if strings.Contains(m, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("requiredFor did not ask for %q: %v", want, missing)
		}
	}
	full := Options{
		Zone: "z", FunctionRuntime: "r", CertificateRef: "c",
		Engine: compute.EnginePostgres, EngineVersion: "16",
	}
	if got := full.requiredFor(caps); len(got) != 0 {
		t.Errorf("requiredFor still wants %v with every option supplied", got)
	}
	if got := (&Options{}).requiredFor(compute.NewCapabilitySet()); len(got) != 0 {
		t.Errorf("requiredFor wants %v from a provider that advertises nothing", got)
	}
}

func TestReportDistinguishesFailuresFromSkips(t *testing.T) {
	t.Parallel()
	rep := &Report{Results: []Result{
		{Check: "a/passed", Invariant: "x"},
		{Check: "b/failed", Invariant: "y", Messages: []string{"broke"}},
		{Check: "c/skipped", Invariant: "z", Skipped: true},
		// A skipped check that also recorded a message is still a skip: the
		// message is the explanation, not a failure.
		{Check: "d/skipped-with-note", Skipped: true, Messages: []string{"why"}},
	}}
	if got := len(rep.Failures()); got != 1 {
		t.Errorf("Failures() returned %d results, want 1: %v", got, rep.Failures())
	}
	if got := len(rep.Skipped()); got != 2 {
		t.Errorf("Skipped() returned %d results, want 2", got)
	}
	if !rep.FailedCheck("b/failed") {
		t.Error("FailedCheck did not find the failing check")
	}
	for _, name := range []string{"a/passed", "c/skipped", "d/skipped-with-note", "e/absent"} {
		if rep.FailedCheck(name) {
			t.Errorf("FailedCheck(%q) reported a failure", name)
		}
	}
	s := rep.String()
	for _, want := range []string{"b/failed", "broke", "c/skipped", "1 failed", "2 not verified"} {
		if !strings.Contains(s, want) {
			t.Errorf("Report.String() is missing %q:\n%s", want, s)
		}
	}
}

// TestRecorderTurnsFatalIntoAReturn covers the mechanism the suite's self-test
// depends on: a check that calls Fatalf must stop, and the runner must carry on
// to the next check rather than exiting the process.
func TestRecorderTurnsFatalIntoAReturn(t *testing.T) {
	t.Parallel()
	reached := false
	rec := &recorder{name: "x"}
	runCheck(Check{Name: "x", Fn: func(tb TB, _ *Env) {
		tb.Fatalf("stop here")
		// Reached only if Fatalf returned, which it must not.
		reached = true
	}}, rec, nil)

	if reached {
		t.Error("Fatalf returned to its caller; a check that has established it cannot continue would " +
			"go on to panic on the nil it was complaining about")
	}
	if !rec.Failed() || len(rec.messages) != 1 {
		t.Errorf("the recorder did not record the fatal message: %v", rec.messages)
	}

	// A cleanup registered before the fatal still runs.
	ran := false
	rec2 := &recorder{name: "y"}
	runCheck(Check{Name: "y", Fn: func(tb TB, _ *Env) {
		tb.Cleanup(func() { ran = true })
		tb.Fatalf("stop")
	}}, rec2, nil)
	if !ran {
		t.Error("a cleanup registered before Fatalf did not run")
	}

	// A skip is not a failure.
	rec3 := &recorder{name: "z"}
	runCheck(Check{Name: "z", Fn: func(tb TB, _ *Env) { tb.Skipf("not verified") }}, rec3, nil)
	if !rec3.skipped || rec3.Failed() {
		t.Errorf("a skip was recorded as skipped=%t failed=%t", rec3.skipped, rec3.Failed())
	}
}

// TestPanicsAreNotSwallowed makes sure the recover in runCheck only catches the
// recorder's own abort. A genuine panic in a provider is a defect the suite must
// surface, not absorb.
func TestPanicsAreNotSwallowed(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("runCheck swallowed a genuine panic")
		}
	}()
	runCheck(Check{Name: "boom", Fn: func(TB, *Env) { panic("provider blew up") }},
		&recorder{name: "boom"}, nil)
}

// The two tests below are the generative half of the USOSS-32 fix. The defect
// they exist for is not a wrong entry in a table — it is a table that stopped
// describing the thing it was a table of, while every check over it went green.
// Both derive their expectation from the interfaces in compute and compare the
// suite's restatement against it in both directions, so a method added, renamed,
// or removed there fails here rather than going quietly undriven.

// TestEveryPortMethodIsDrivenOrNamed asserts that every method of every port
// interface is either driven by the transient gate or named, with a reason, as
// one this suite does not drive.
//
// The gate used to drive one method of one port chosen by a hand-written
// capability condition. The condition was a restatement of "what can I write
// with" and it drifted; the single call could not see a per-service mapping at
// all. This is what stops both from recurring: the port interfaces come from
// compute.Provider's own accessors, the method set comes from each interface,
// and anything the suite does not drive has to say why.
func TestEveryPortMethodIsDrivenOrNamed(t *testing.T) {
	t.Parallel()

	ifaces := allPortInterfaces()
	// A derivation returning nothing passes every check over it.
	if len(ifaces) == 0 {
		t.Fatal("allPortInterfaces derived no port interfaces, so every assertion below would " +
			"hold vacuously")
	}

	// Which ports view which interface, and which methods they drive.
	driven := map[string]map[string]string{} // interface -> method -> port
	for _, pt := range ports() {
		if pt.Iface == nil {
			t.Errorf("port %q names no Iface, so nothing can enumerate its methods", pt.Name)
			continue
		}
		if len(pt.Methods) == 0 {
			t.Errorf("port %q names no methods, so a failure against it cannot say which "+
				"interface method a provider author has to look at", pt.Name)
			continue
		}
		for op, method := range pt.Methods {
			owner := opOwner(op, pt)
			ownerReal := map[string]bool{}
			for _, m := range methodNames(owner) {
				ownerReal[m] = true
			}
			if !ownerReal[method] {
				t.Errorf("port %q maps %s onto %s.%s, which is not a method of that interface; "+
					"either the method was renamed or the table was guessed",
					pt.Name, op, owner.Name(), method)
				continue
			}
			if driven[owner.Name()] == nil {
				driven[owner.Name()] = map[string]string{}
			}
			driven[owner.Name()][method] = pt.Name
		}
	}

	// Methods driven outside the port table, by portlessCalls.
	for ifaceName, methods := range portlessDriven() {
		if driven[ifaceName] == nil {
			driven[ifaceName] = map[string]string{}
		}
		for _, m := range methods {
			driven[ifaceName][m] = "portless"
		}
	}

	undriven := undrivenPortMethods()
	for _, iface := range ifaces {
		name := iface.Name()
		methods := methodNames(iface)
		if len(methods) == 0 {
			t.Errorf("%s has no methods, which cannot be right for a port", name)
		}
		for _, m := range methods {
			if _, ok := driven[name][m]; ok {
				continue
			}
			if x, ok := undriven[name][m]; ok {
				if x.Reason == "" {
					t.Errorf("%s.%s is named as undriven with no reason; an undriven method is a "+
						"gap this suite is choosing and the choice has to be readable", name, m)
				}
				// An exclusion with no expiry is where an obligation goes to be
				// forgotten. The three USOSS-32 entries had no expiry and all
				// three turned out to be holes rather than legitimate.
				// S1: Legitimate and CoveredBy were declared and never read, so a
				// new hole could set neither and pass while the decision record
				// claimed the distinction was enforced. A dead classification
				// field is a worse artefact than no field, because it reads as
				// enforcement.
				//
				// The rule: an exclusion is either legitimate — nothing can drive
				// it — or covered by a check that does. The third state, a hole
				// that nothing covers and that something could drive, is what
				// this table is for naming and is not allowed to be silent: it
				// has to be driven, not excused.
				switch {
				case x.Legitimate && x.CoveredBy != "":
					t.Errorf("%s.%s is named as legitimate (nothing can drive it) and also as "+
						"covered by %q. If something exercises it, something can drive it, so "+
						"one of the two claims is false", name, m, x.CoveredBy)
				case !x.Legitimate && x.CoveredBy == "":
					t.Errorf("%s.%s is excused as neither legitimate nor covered. That is a hole "+
						"nothing observes and something could drive: either drive it, or say "+
						"what makes it undrivable, or name the check that covers it", name, m)
				case x.CoveredBy != "" && !plausibleCheckName(x.CoveredBy):
					t.Errorf("%s.%s claims to be covered by %q, which does not name a check this "+
						"suite could schedule: the first segment has to be one of the check "+
						"families and a port segment has to be a port in the table", name, m,
						x.CoveredBy)
				}
				if x.Expires == "" {
					t.Errorf("%s.%s is named as undriven with no expiry condition. Name the event "+
						"after which this entry is wrong -- a ticket, a pull request, a capability "+
						"appearing -- so it cannot outlive its reason", name, m)
				}
				continue
			}
			t.Errorf("%s.%s is neither driven by the transient gate nor named in "+
				"undrivenPortMethods. A provider's mapping for it is unverified, which is the "+
				"defect USOSS-32 fixed: add it to a port's Methods, or name it with the reason "+
				"it cannot be driven", name, m)
		}
	}

	// The other direction. A stale entry left behind by a rename is how a list
	// like this stops describing anything while still looking maintained.
	byName := map[string]reflect.Type{}
	for _, iface := range ifaces {
		byName[iface.Name()] = iface
	}
	for ifaceName, methods := range undriven {
		iface, ok := byName[ifaceName]
		if !ok {
			t.Errorf("undrivenPortMethods names interface %q, which is not a port interface the "+
				"suite knows of; the entry is stale", ifaceName)
			continue
		}
		declared := map[string]bool{}
		for _, m := range methodNames(iface) {
			declared[m] = true
		}
		for m := range methods {
			if !declared[m] {
				t.Errorf("undrivenPortMethods excuses %s.%s, which is not a method of that "+
					"interface; the entry is stale and is excusing nothing", ifaceName, m)
			}
			if _, alsoDriven := driven[ifaceName][m]; alsoDriven {
				t.Errorf("%s.%s is both driven and named as undriven; one of the two is wrong",
					ifaceName, m)
			}
		}
	}
}

// TestMaterialPortsFollowTheInterfaces asserts that which ports the
// rendered-artefact check plants secret material through is derived from the
// interfaces rather than restated.
//
// checkSecretsNotInRendered planted only for CapSecretStore+CapContainerService
// or CapRelationalDatabase. That condition was a hand-maintained answer to "what
// can be handed material", and for a provider outside it the check scanned for a
// sentinel nobody had stored and passed. The derivation is now
// compute.SecretValue or compute.SecretBinding appearing in a method argument;
// this pins the suite's Port.PlantsSecretMaterial column against it, in both
// directions.
func TestMaterialPortsFollowTheInterfaces(t *testing.T) {
	t.Parallel()

	unplanted := unplantedMaterialPorts()
	carriers := 0
	for _, pt := range ports() {
		if pt.Iface == nil {
			continue // reported by the test above
		}
		direct, byRef, err := materialReach(pt)
		if err != nil {
			t.Errorf("materialReach(%q): %v", pt.Name, err)
			continue
		}
		carries := direct || byRef
		if carries {
			carriers++
		}
		reason, excused := unplanted[pt.Name]
		switch {
		case pt.PlantsSecretMaterial && !carries:
			t.Errorf("port %q claims to plant secret material but no method of %s takes a "+
				"compute.SecretValue or a compute.SecretBinding, so there is no material to "+
				"plant", pt.Name, pt.Iface.Name())
		case pt.PlantsSecretMaterial && excused:
			t.Errorf("port %q both plants secret material and is excused from planting it; one "+
				"of the two is wrong", pt.Name)
		case carries && !pt.PlantsSecretMaterial && !excused:
			t.Errorf("%s can be handed secret material and port %q neither plants it nor appears "+
				"in unplantedMaterialPorts. That is the vacuum USOSS-32 closed: the check would "+
				"scan this provider's artefacts for a sentinel it never stored. Plant it, or name "+
				"the reason it cannot be planted", pt.Iface.Name(), pt.Name)
		case !carries && excused:
			t.Errorf("unplantedMaterialPorts excuses port %q, whose interface %s cannot carry "+
				"secret material at all; the entry is stale", pt.Name, pt.Iface.Name())
		case excused && reason == "":
			t.Errorf("port %q is excused from planting material with no reason given", pt.Name)
		}
	}
	// A method no port drives is the other half of the same question: if it can
	// be handed material, its mapping is unverified in a way no port-level
	// derivation can see. It is already required to be named as undriven; this
	// says so where it matters.
	driven := map[string]map[string]bool{}
	for _, pt := range ports() {
		if pt.Iface == nil {
			continue
		}
		if driven[pt.Iface.Name()] == nil {
			driven[pt.Iface.Name()] = map[string]bool{}
		}
		for op, m := range pt.Methods {
			owner := opOwner(op, pt)
			if driven[owner.Name()] == nil {
				driven[owner.Name()] = map[string]bool{}
			}
			driven[owner.Name()][m] = true
		}
	}
	undriven := undrivenPortMethods()
	for _, iface := range allPortInterfaces() {
		for _, m := range methodNames(iface) {
			if driven[iface.Name()][m] {
				continue
			}
			d, r, err := methodMaterialReach(iface, m)
			if err != nil {
				t.Errorf("methodMaterialReach(%s.%s): %v", iface.Name(), m, err)
				continue
			}
			if !d && !r {
				continue
			}
			if _, named := undriven[iface.Name()][m]; !named {
				t.Errorf("%s.%s can be handed secret material and no port drives it, so nothing "+
					"observes what the provider does with it; name it in undrivenPortMethods "+
					"with the reason, or drive it", iface.Name(), m)
			}
		}
	}

	// Non-emptiness, at both resolutions: a reflect walk that found no carriers
	// would satisfy every case above and leave the check planting nothing.
	if carriers == 0 {
		t.Fatal("no port interface was found to carry secret material, so the derivation behind " +
			"checkSecretsNotInRendered found nothing to plant and every case above held vacuously")
	}
	planted := 0
	for _, pt := range ports() {
		if pt.PlantsSecretMaterial {
			planted++
		}
	}
	if planted == 0 {
		t.Fatal("no port plants secret material, so checkSecretsNotInRendered can never scan " +
			"for material that is genuinely in play")
	}
}

// plausibleCheckName reports whether s begins with a check name this suite could
// produce.
//
// It validates the addressable part — the family, and the port segment against
// the derived port table — and deliberately not the rest: a check's full name
// depends on which capabilities the provider under test advertises, so there is
// no single set to compare against here. That limit is the reason this is named
// "plausible": it catches a family or port that does not exist, and it does not
// catch a well-formed name for a check nobody wrote.
func plausibleCheckName(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return false
	}
	switch parts[0] {
	case "provider", "security", "capabilities", "abstraction", "ext":
		return true
	case "port", "grants":
		for _, pt := range ports() {
			if pt.Name == parts[1] {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// TestEveryUnverifiedObligationIsAccountedFor requires each recorded gap to say
// what it is, what closing it would need, and where it is tracked.
//
// An unchecked obligation with nowhere to be picked up is the same artefact as an
// undocumented one. This is the table that replaced a false claim of coverage, so
// it is worth more than the claim only if it stays specific.
func TestEveryUnverifiedObligationIsAccountedFor(t *testing.T) {
	t.Parallel()

	obligations := unverifiedObligations()
	if len(obligations) == 0 {
		t.Fatal("no unverified obligations are recorded. That would mean this suite checks every " +
			"documented requirement in compute, which is not true of any conformance suite; an " +
			"empty table here is a derivation returning nothing rather than a clean bill")
	}
	seen := map[string]bool{}
	for _, o := range obligations {
		switch {
		case o.Where == "":
			t.Errorf("an obligation names no interface member: %+v", o)
		case o.Requirement == "":
			t.Errorf("%s records no requirement, so a reader cannot tell what is unchecked", o.Where)
		case o.Needs == "":
			t.Errorf("%s records no missing observation. Saying an obligation is unchecked "+
				"without saying what checking it would take is how a gap becomes permanent",
				o.Where)
		case o.TrackedBy == "":
			t.Errorf("%s is unchecked and untracked; name the ticket", o.Where)
		}
		if seen[o.Where] {
			t.Errorf("%s is recorded twice", o.Where)
		}
		seen[o.Where] = true
		// Locatable in one of the packages this suite covers -- DERIVED from the
		// ports, not listed.
		//
		// It required "compute." alone until the first obligation in compute/ext
		// arrived, and was then widened to the pair {"compute.", "ext."}. That
		// second form is the same defect as the first, one element later: a
		// hand-maintained population that happens to match today's members and
		// silently rejects the first obligation from a third package the suite
		// grows into. Widening a list in response to a counterexample fixes the
		// counterexample; deriving it fixes the class.
		//
		// So the prefixes come from where the port interfaces actually live.
		// allPortInterfaces is the authority the rest of this file already makes
		// its coverage claims against, which is what makes "the packages this
		// suite accounts for" a fact about the suite rather than a sentence about
		// it.
		prefixes := obligationPrefixes()
		if len(prefixes) == 0 {
			t.Fatal("no package prefixes were derived from the port interfaces, so every " +
				"obligation below would be unlocatable -- or, had the sense been inverted, " +
				"every one trivially fine")
		}
		locatable := false
		for _, pkg := range prefixes {
			if strings.HasPrefix(o.Where, pkg) {
				locatable = true
				break
			}
		}
		if !locatable {
			t.Errorf("%s names no member of %v, so it cannot be located. Those are the packages "+
				"the suite's port interfaces live in; an obligation outside them is either "+
				"misfiled or evidence the suite's scope has grown -- and if it is the latter, "+
				"the fix is a port in that package, not an entry in a list here", o.Where, prefixes)
		}
	}
}

// TestNoExclusionOutlivesItsRetirementCondition evaluates what Expires only
// states.
//
// The correction that produced this test is the reason for it. An exclusion's
// Expires read "USOSS-26's lifecycle checks growing an error-mapping case", which
// was ambiguous: one such case existed and the one the entry was about did not, so
// an auditor could conclude the condition met or unmet from the same sentence.
// Making the sentence unambiguous was the obvious fix and it was not enough —
// **replacing an Expires with "banana" left every audit in this file green.**
//
//	Requiring a field to be PRESENT is not requiring it to be EVALUABLE.
//
// The field went from ambiguous prose to unambiguous prose, and the gate still
// could not distinguish either from a fruit. So the diagnosis was right and the
// remedy was in the same register as the defect — a sentence a careful reader can
// evaluate, in a table nothing but a careful reader reads.
//
// RetiredWhen is the evaluable half: a fragment of a check name. This test fails
// once any check registered in this package has a name containing it, so an entry
// deletes itself by turning red the moment it stops being necessary, and the merge
// order of two unrelated pull requests stops mattering.
//
// The shape is PR #35's (USOSS-37), whose exemption table reached it first for a
// different subject — that gate resolves CoveredBy claims and never reads Expires,
// and its own entry retires on the fragment "delete-scope". Two details from it
// are load-bearing and both are borrowed deliberately: a **fragment** rather than a
// whole name, because port check names are computed and no literal of the whole
// name exists; and a **floor**, because a collector that finds nothing retires
// nothing and reports the same green as one that found everything.
func TestNoExclusionOutlivesItsRetirementCondition(t *testing.T) {
	t.Parallel()

	names := registeredCheckNameFragments(t)
	// The floor. Non-emptiness proves a derivation found something, never that it
	// looked everywhere — but zero proves it looked nowhere, and that is the case
	// that silently retires nothing.
	if len(names) < 100 {
		t.Fatalf("collected %d check-name literals from this package, which cannot be right for a "+
			"suite of ~168 checks; a collector that finds nothing retires no exclusion and reports "+
			"the same green as one that found everything", len(names))
	}

	seen := 0
	for iface, methods := range undrivenPortMethods() {
		for method, x := range methods {
			seen++
			where := iface + "." + method
			if x.RetiredWhen == "" {
				t.Errorf("%s has no RetiredWhen, so nothing can ever retire it. Expires says when "+
					"the entry becomes wrong and nothing evaluates it; this is the half that does",
					where)
				continue
			}
			if err := validRetirementFragment(method, x.RetiredWhen); err != nil {
				t.Errorf("%s has an unusable RetiredWhen %q: %v", where, x.RetiredWhen, err)
				continue
			}
			for _, n := range names {
				if strings.Contains(n, x.RetiredWhen) {
					t.Errorf("%s is retired: a check named %q contains %q, so the method this "+
						"entry excuses is now covered and the entry excuses nothing. Delete it and "+
						"let the driven-or-named audit decide, which will then either pass or be a "+
						"real finding", where, n, x.RetiredWhen)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("undrivenPortMethods is empty, so every assertion above holds vacuously")
	}
}

// validRetirementFragment reports whether a fragment is something a machine can
// evaluate against a check name, rather than a sentence.
//
// The rule ties the fragment to its own subject: it has to contain the kebab-case
// form of the method the entry excludes. That is what rules out "banana" without a
// hand-maintained list of acceptable strings — a list which would itself be a
// population somebody typed.
//
// What this deliberately does NOT rule out is a fragment too COARSE for its entry.
// "delete-scope" is a valid fragment by every rule here, and it is the wrong one
// for SecretStore.DeleteScope, because USOSS-26's two checks contain it and
// neither drives the method under an induced failure: it would retire the entry on
// the wrong event. Retiring early and never retiring are the same defect wearing
// different clothes, but the distinction is per-entry judgement rather than a law,
// so it is recorded at the entry and not pretended to be enforced here.
func validRetirementFragment(method, frag string) error {
	for _, r := range frag {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '-' && r != '/' {
			return fmt.Errorf("a check-name fragment is lower-case kebab (and may contain %q); "+
				"%q is not, so it cannot match a name this suite generates", "/", frag)
		}
	}
	want := kebab(method)
	if !strings.Contains(frag, want) {
		return fmt.Errorf("it does not contain %q, the kebab-case form of the method it excludes, "+
			"so nothing ties it to its own subject and any string at all would pass", want)
	}
	return nil
}

// kebab renders a Go method name the way this suite names checks after it.
func kebab(name string) string {
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// registeredCheckNameFragments collects every string literal appearing in a
// Check's Name in this package, including the literal parts of a concatenation.
//
// The literal parts are what makes a computed name matchable: "port/" + pt.Name +
// "/ensure-is-idempotent" yields two literals and the distinguishing one is the
// suffix. It is a syntax walk rather than a type-checked one on purpose — the
// question is which strings appear, not what anything means.
//
// PR #35 (USOSS-37) grows a checkNameLiterals with the same job for its own gate.
// Whichever of the two lands second should collapse them; two collectors over one
// population is exactly the drift this file exists to catch, and saying so here is
// cheaper than discovering it later.
func registeredCheckNameFragments(t *testing.T) []string {
	t.Helper()

	// Every .go file in the directory, parsed one by one, rather than
	// parser.ParseDir: that helper is deprecated, and the reason it is deprecated
	// is the reason not to want it here either -- it associates files with
	// packages without considering build tags. A check name behind a build
	// constraint is still a registered check name, and a collector that cannot see
	// it retires nothing while reporting the same green. USOSS-28 reached the same
	// conclusion about the import graph from the other end.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading this package's directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no .go files found in this package's directory, so nothing was collected")
	}
	var out []string
	collect := func(e ast.Expr) {
		ast.Inspect(e, func(n ast.Node) bool {
			if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if v, err := strconv.Unquote(b.Value); err == nil {
					out = append(out, v)
				}
			}
			return true
		})
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Name" {
					collect(kv.Value)
				}
			}
			return true
		})
	}
	return out
}

// TestRetirementFragmentsAreEvaluable is the banana control.
//
// It exists because the defect this whole entry came from was a gate that could
// not tell a meaningful condition from a meaningless one. A test that only
// exercises the good case would inherit exactly that blindness: it would pass with
// the validator returning nil unconditionally.
func TestRetirementFragmentsAreEvaluable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		method, frag string
		want         bool
	}{
		{"DeleteScope", "delete-scope-under-an-induced-failure", true},
		{"DeleteScope", "delete-scope", true},
		{"Grant", "table-bucket-grant", true},
		{"GrantExternal", "grant-external", true},

		// The finding, as a case: prose and fruit are the same thing to a gate
		// that only checks presence.
		{"DeleteScope", "banana", false},
		{"DeleteScope", "USOSS-26's lifecycle checks growing an induced-failure case", false},
		{"DeleteScope", "", false},
		// Ties to the wrong subject, which is how a fragment ends up unable to
		// retire the entry it is written on.
		{"DeleteScope", "ensure-is-idempotent", false},
		// Not a shape any generated name can contain.
		{"DeleteScope", "DeleteScope", false},
	} {
		err := validRetirementFragment(tc.method, tc.frag)
		if got := err == nil; got != tc.want {
			t.Errorf("validRetirementFragment(%q, %q) accepted=%v, want %v (err: %v)",
				tc.method, tc.frag, got, tc.want, err)
		}
	}
}

// obligationPrefixes is the set of "<package>." prefixes an obligation may name,
// derived from the packages the suite's port interfaces are declared in.
//
// A port interface's reflect.Type carries its declaring package's import path, and
// the prefix an obligation uses is that path's last element -- "compute." for
// github.com/conductorone/apphub/compute, "ext." for .../compute/ext. So the set of
// acceptable prefixes is a consequence of which ports exist, and adding a port in a
// new package widens it without anybody editing a list.
func obligationPrefixes() []string {
	seen := map[string]bool{}
	var out []string
	for _, iface := range allPortInterfaces() {
		path := iface.PkgPath()
		if path == "" {
			// An unnamed interface type has no package. None of the ports is one,
			// and if that changes this is not the place to decide what it means.
			continue
		}
		base := path[strings.LastIndex(path, "/")+1:] + "."
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryUnsettleableCheckExists binds unverifiableByMarker to the checks it
// names, by deriving the scheduled names rather than pattern-matching them.
//
// The first version of this audit called plausibleCheckName, which accepts any
// well-formed two-segment name — so a reviewer replaced a real key with
// "security/not-a-real-check" and it passed. **Validating that a name is
// well-formed is not validating that it denotes the thing it claims**: syntax
// where semantics was needed, which is the same defect as an AST gate recognising
// a callee spelled int32 while a type alias walks through it.
//
// The companion table this test used to check no longer exists. The channels each
// check establishes are no longer stated separately from the channels it scans —
// scanChannels takes one map and uses it for both — so there is nothing left to
// drift and nothing to audit. That is the stronger remedy: the reviewer's
// deleted-channel mutation is now unrepresentable rather than caught.
func TestEveryUnsettleableCheckExists(t *testing.T) {
	t.Parallel()

	// Derived, not restated. securityChecks ignores its Env, so the real names
	// are available here; the per-port ones come from the same ports() the
	// entries are generated from.
	scheduled := map[string]bool{}
	for _, c := range securityChecks(nil) {
		scheduled[c.Name] = true
	}
	for _, pt := range ports() {
		scheduled["port/"+pt.Name+"/ensure-converges-rather-than-accumulating"] = true
	}
	if len(scheduled) == 0 {
		t.Fatal("no check names were derived, so every assertion below holds vacuously")
	}

	unsettleable := unverifiableByMarker()
	if len(unsettleable) == 0 {
		t.Fatal("unverifiableByMarker is empty; the USOSS-61 derivation counted 12 checks that " +
			"read Options.Rendered and cannot be settled by a marker")
	}
	for name, why := range unsettleable {
		if !scheduled[name] {
			t.Errorf("unverifiableByMarker names %q, which is not a check this suite schedules. "+
				"A fabricated name in this table is worse than an absent one: it reads as a "+
				"limitation somebody considered", name)
		}
		if why == "" {
			t.Errorf("%q is listed as unsettleable with no reason; the point of this table is "+
				"that the limit is stated rather than implied", name)
		}
	}

	// Every channel the mechanism offers has to be reachable, or a check could
	// ask for one no provider can ever be asked for.
	if len(channels()) == 0 {
		t.Fatal("channels() is empty")
	}
	seen := map[Channel]bool{}
	for _, c := range channels() {
		if c == "" {
			t.Error("channels() contains the empty channel")
		}
		if seen[c] {
			t.Errorf("channels() lists %q twice", c)
		}
		seen[c] = true
	}
}
