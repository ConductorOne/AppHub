// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// The tests here are the ones the conformance suite cannot run, and each of them
// exists because the suite is either silent about the property or passes on it
// vacuously.
//
// Two of the friction document's findings are why:
//
//   - §3: the ErrTransient gate skips unless the provider advertises
//     CapSecretStore, so the single check guarding the substrate-error mapping
//     does not run for this provider either. USOSS-14 adds two ports and two
//     services to that mapping.
//   - §4: the "secret material does not appear in rendered artefacts" check
//     plants its sentinel only for some capabilities. It *does* run here, because
//     the relational port is one of them — but the sentinel it plants is a
//     password, and a green suite still says nothing about a password reaching an
//     error, a Describe, or a substrate record.
//
// Every property below is stated as a property and quantified over a derived set
// where there is one, because on this project a test that named cases has twice
// passed while the class it was about was broken.

// --- fixtures ---------------------------------------------------------------

func relationalSpec(name string) compute.RelationalSpec {
	return compute.RelationalSpec{
		Name:          name,
		Engine:        compute.EnginePostgres,
		EngineVersion: "16",
		DatabaseName:  "appdb",
		AdminUsername: "appuser",
		AdminPassword: compute.NewSecretValue(testPassword),
		Capacity:      compute.CapacityRange{MinUnits: 0.25, MaxUnits: 2},
		Placement:     compute.Placement{Name: "default"},
		Ingress: []compute.IngressRule{{
			From: compute.Peer{Kind: compute.PeerControlPlane},
			Port: 5432,
		}},
		Labels: map[string]string{"owner": "tests"},
	}
}

// testPassword is the material every test in this file plants and then hunts
// for. It is a sentinel rather than a realistic password precisely so that a
// substring search for it is meaningful.
const testPassword = "apphub-test-admin-password-sentinel"

func keyValueSpec(name string) compute.KeyValueSpec {
	return compute.KeyValueSpec{
		Name:         name,
		PartitionKey: "pk",
		SortKey:      "sk",
		Placement:    compute.Placement{Name: "default"},
		Labels:       map[string]string{"owner": "tests"},
	}
}

func mustRelational(t *testing.T, p *aws.Provider) compute.RelationalProvisioner {
	t.Helper()
	rp, err := p.Relational()
	if err != nil {
		t.Fatalf("acquiring the relational port: %v", err)
	}
	return rp
}

func mustKeyValues(t *testing.T, p *aws.Provider) compute.KeyValueProvisioner {
	t.Helper()
	kv, err := p.KeyValues()
	if err != nil {
		t.Fatalf("acquiring the key-value port: %v", err)
	}
	return kv
}

func mustIdentity(t *testing.T, p *aws.Provider, name string) compute.Ref {
	t.Helper()
	id, err := p.Identities().EnsureWorkloadIdentity(context.Background(),
		compute.WorkloadIdentitySpec{Name: name, Placement: compute.Placement{Name: "default"}})
	if err != nil {
		t.Fatalf("ensuring the workload identity: %v", err)
	}
	return id.Ref
}

// --- the transient mapping, over every method of every port -----------------

// TestARetryableDatabaseSubstrateFailureIsErrTransient is the friction
// document's §3, applied to the two ports USOSS-14 adds.
//
// The conformance suite's own gate for this skips unless the provider advertises
// CapSecretStore, so nothing in the suite exercises the mapping for RDS, EC2 or
// DynamoDB. And the mapping is *per service*: an implementation that reached
// compute.ErrTransient from DynamoDB and compute.ErrFailed from RDS would pass a
// one-call check and still tell a caller to abandon a deploy that would have
// worked on a retry. So this enumerates every method of every port rather than
// one call site, and [TestEveryDatabasePortMethodHasATransientProbe] fails if the
// enumeration falls behind the interface.
func TestARetryableDatabaseSubstrateFailureIsErrTransient(t *testing.T) {
	t.Parallel()
	for name, probe := range databaseProbes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			p, _ := newProvider(t, nil)
			fixture := probe.setup(t, p)

			stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
			if err != nil {
				t.Fatalf("arming the throttle: %v", err)
			}
			defer stop()

			err = probe.call(t, p, fixture)
			switch {
			case err == nil:
				t.Fatal("the throttled call succeeded, so this case checks nothing")
			case errors.Is(err, compute.ErrTransient):
			case errors.Is(err, compute.ErrFailed):
				t.Errorf("a throttled call surfaced as compute.ErrFailed, which is documented as "+
					"not retryable without changing the spec; a caller that believes that "+
					"abandons a deploy that would have worked: %v", err)
			default:
				t.Errorf("a throttled call surfaced as %v, which matches no sentinel that would "+
					"make sense for it", err)
			}
		})
	}
}

type dbProbe struct {
	setup func(*testing.T, *aws.Provider) any
	call  func(*testing.T, *aws.Provider, any) error
}

// databaseProbes is one probe per method of the two ports this ticket adds,
// including the Granter both halves of.
//
// The setup and the call are separate for the reason USOSS-10's equivalent gives:
// with the fixture creation inside the call, the injected throttle lands on the
// setup and the test proves nothing about the method it names.
func databaseProbes() map[string]dbProbe {
	ctx := context.Background()
	relRef := func(t *testing.T, p *aws.Provider) any {
		t.Helper()
		st, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec("app"))
		if err != nil {
			t.Fatalf("ensuring the relational endpoint: %v", err)
		}
		return st.Ref
	}
	tableRef := func(t *testing.T, p *aws.Provider) any {
		t.Helper()
		st, err := mustKeyValues(t, p).EnsureKeyValueTable(ctx, keyValueSpec("app"))
		if err != nil {
			t.Fatalf("ensuring the table: %v", err)
		}
		return st.Ref
	}
	type grantFixture struct {
		table    compute.Ref
		identity compute.Ref
	}
	grantSetup := func(t *testing.T, p *aws.Provider) any {
		t.Helper()
		return grantFixture{table: tableRef(t, p).(compute.Ref), identity: mustIdentity(t, p, "app")}
	}

	return map[string]dbProbe{
		"Relational.EnsureRelational": {
			setup: func(*testing.T, *aws.Provider) any { return nil },
			call: func(t *testing.T, p *aws.Provider, _ any) error {
				_, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec("app"))
				return err
			},
		},
		"Relational.DescribeRelational": {
			setup: relRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				_, err := mustRelational(t, p).DescribeRelational(ctx, f.(compute.Ref))
				return err
			},
		},
		"Relational.WaitForRelational": {
			setup: relRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				_, err := mustRelational(t, p).WaitForRelational(ctx, f.(compute.Ref),
					compute.WaitOptions{Timeout: waitProbeTimeout})
				return err
			},
		},
		"Relational.DeleteRelational": {
			setup: relRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				return mustRelational(t, p).DeleteRelational(ctx, f.(compute.Ref))
			},
		},
		"KeyValues.EnsureKeyValueTable": {
			setup: func(*testing.T, *aws.Provider) any { return nil },
			call: func(t *testing.T, p *aws.Provider, _ any) error {
				_, err := mustKeyValues(t, p).EnsureKeyValueTable(ctx, keyValueSpec("app"))
				return err
			},
		},
		"KeyValues.DescribeKeyValueTable": {
			setup: tableRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				_, err := mustKeyValues(t, p).DescribeKeyValueTable(ctx, f.(compute.Ref))
				return err
			},
		},
		"KeyValues.WaitForKeyValueTable": {
			setup: tableRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				_, err := mustKeyValues(t, p).WaitForKeyValueTable(ctx, f.(compute.Ref),
					compute.WaitOptions{Timeout: waitProbeTimeout})
				return err
			},
		},
		"KeyValues.DeleteKeyValueTable": {
			setup: tableRef,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				return mustKeyValues(t, p).DeleteKeyValueTable(ctx, f.(compute.Ref))
			},
		},
		"KeyValues.Grant": {
			setup: grantSetup,
			call: func(t *testing.T, p *aws.Provider, f any) error {
				g := f.(grantFixture)
				return mustKeyValues(t, p).Grant(ctx, g.table, g.identity, compute.AccessRead)
			},
		},
		"KeyValues.Revoke": {
			setup: func(t *testing.T, p *aws.Provider) any {
				t.Helper()
				g := grantSetup(t, p).(grantFixture)
				if err := mustKeyValues(t, p).Grant(ctx, g.table, g.identity,
					compute.AccessRead); err != nil {
					t.Fatalf("granting before the revoke probe: %v", err)
				}
				return g
			},
			call: func(t *testing.T, p *aws.Provider, f any) error {
				g := f.(grantFixture)
				return mustKeyValues(t, p).Revoke(ctx, g.table, g.identity)
			},
		},
		"KeyValues.DescribeGrant": {
			// Granted first, as the revoke probe is: the probe checks how a
			// throttled substrate call is classified, and a read that returned
			// ErrNotFound before reaching IAM would classify nothing.
			setup: func(t *testing.T, p *aws.Provider) any {
				t.Helper()
				g := grantSetup(t, p).(grantFixture)
				if err := mustKeyValues(t, p).Grant(ctx, g.table, g.identity,
					compute.AccessRead); err != nil {
					t.Fatalf("granting before the describe-grant probe: %v", err)
				}
				return g
			},
			call: func(t *testing.T, p *aws.Provider, f any) error {
				g := f.(grantFixture)
				_, err := mustKeyValues(t, p).DescribeGrant(ctx, g.table, g.identity)
				return err
			},
		},
	}
}

// waitProbeTimeout is short: a Wait probe is checking the error the *first*
// substrate call returns, and a long deadline would let the retry the induced
// failure permits succeed before the deadline expired.
const waitProbeTimeout = 1

// TestEveryDatabasePortMethodHasATransientProbe derives the population the test
// above quantifies over, instead of trusting a hand-written map.
//
// This project's lesson is that a hand-maintained restatement of a set drifts
// from the set, and the specific instance was a Granter port list that missed a
// port carrying a Granter. So the set of methods comes from the interface types
// by reflection, and a method added to compute.RelationalProvisioner or
// compute.KeyValueProvisioner tomorrow turns this red rather than silently
// escaping the mapping check.
func TestEveryDatabasePortMethodHasATransientProbe(t *testing.T) {
	t.Parallel()
	probes := databaseProbes()

	type port struct {
		accessor string
		typ      reflect.Type
	}
	ports := []port{
		{"Relational", reflect.TypeOf((*compute.RelationalProvisioner)(nil)).Elem()},
		{"KeyValues", reflect.TypeOf((*compute.KeyValueProvisioner)(nil)).Elem()},
	}
	var want []string
	for _, pt := range ports {
		if pt.typ.NumMethod() == 0 {
			t.Fatalf("%s reports no methods, so this derivation is about nothing", pt.accessor)
		}
		for i := range pt.typ.NumMethod() {
			want = append(want, pt.accessor+"."+pt.typ.Method(i).Name)
		}
	}
	sort.Strings(want)
	if len(want) < 8 {
		t.Fatalf("derived only %d methods across both ports, which cannot be right: %v",
			len(want), want)
	}
	for _, name := range want {
		if _, ok := probes[name]; !ok {
			t.Errorf("%s is a method of a port this ticket implements and has no transient probe; "+
				"the substrate-error mapping is per service, so an unprobed method is a service "+
				"whose throttle may be surfacing as compute.ErrFailed", name)
		}
	}
	for name := range probes {
		if !contains(want, name) {
			t.Errorf("the probe map has an entry %q that is not a method of either port; a stale "+
				"probe is a case nobody is checking", name)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// --- the credential path ----------------------------------------------------

// TestTheAdminPasswordReachesNothingObservable is the property the friction
// document's §4 says a green conformance run does not establish.
//
// The suite plants a sentinel and searches rendered artefacts. That is one of
// four places a password escapes, and this covers all four: an error from a call
// that was *holding* the material when it failed, the effective spec a Describe
// hands back, the status message, and every substrate record.
//
// It is a class rather than a case: the error half enumerates several ways the
// same call can fail while holding the password, because "the error path" is not
// one path.
func TestTheAdminPasswordReachesNothingObservable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rp := mustRelational(t, p)

	// Every one of these is a call handed real material and then made to fail,
	// because an error path is where a provider interpolates the spec it could
	// not satisfy.
	failing := map[string]compute.RelationalSpec{
		"an engine version this provider does not offer": func() compute.RelationalSpec {
			s := relationalSpec("bad-version")
			s.EngineVersion = "conformance-no-such-version"
			return s
		}(),
		"an engine this provider does not offer": func() compute.RelationalSpec {
			s := relationalSpec("bad-engine")
			s.Engine = compute.EngineMySQL
			return s
		}(),
		"an impossible capacity range": func() compute.RelationalSpec {
			s := relationalSpec("bad-capacity")
			s.Capacity = compute.CapacityRange{MinUnits: 8, MaxUnits: 1}
			return s
		}(),
		"a capacity that does not land on an ACU step": func() compute.RelationalSpec {
			s := relationalSpec("bad-step")
			s.Capacity = compute.CapacityRange{MinUnits: 0.3, MaxUnits: 2}
			return s
		}(),
		"an unconfigured placement": func() compute.RelationalSpec {
			s := relationalSpec("bad-placement")
			s.Placement = compute.Placement{Name: "no-such-placement"}
			return s
		}(),
		"no database name": func() compute.RelationalSpec {
			s := relationalSpec("bad-dbname")
			s.DatabaseName = ""
			return s
		}(),
		"an ingress rule this provider will not write": func() compute.RelationalSpec {
			s := relationalSpec("bad-ingress")
			s.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 5432}}
			return s
		}(),
		"a label an AWS tag cannot hold": func() compute.RelationalSpec {
			s := relationalSpec("bad-label")
			s.Labels = map[string]string{"owner": strings.Repeat("x", 1000)}
			return s
		}(),
	}
	checked := 0
	for what, spec := range failing {
		_, err := rp.EnsureRelational(ctx, spec)
		if err == nil {
			t.Errorf("EnsureRelational with %s succeeded, so that error path was not searched", what)
			continue
		}
		checked++
		if strings.Contains(err.Error(), testPassword) {
			// Deliberately does not print the error.
			t.Errorf("the error from EnsureRelational with %s contains the admin password; an "+
				"error is logged, returned to an API caller, and usually persisted onto a job "+
				"record", what)
		}
	}
	if checked != len(failing) {
		t.Fatalf("only %d of %d error paths were exercised", checked, len(failing))
	}

	// The success path: the read-back and the substrate.
	st, err := rp.EnsureRelational(ctx, relationalSpec("good"))
	if err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	if !st.Spec.AdminPassword.IsZero() {
		t.Error("the effective spec from Ensure carries the admin password; a read-back must not " +
			"hand material back, and this one is returned to whatever called the deploy")
	}
	if strings.Contains(st.Message, testPassword) {
		t.Error("Status.Message contains the admin password")
	}
	described, err := rp.DescribeRelational(ctx, st.Ref)
	if err != nil {
		t.Fatalf("DescribeRelational: %v", err)
	}
	if !described.Spec.AdminPassword.IsZero() {
		t.Error("the effective spec from Describe carries the admin password")
	}
	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if len(rendered) == 0 {
		t.Fatal("the substrate rendered nothing, so this half of the assertion is about nothing")
	}
	for i, artefact := range rendered {
		if strings.Contains(artefact, testPassword) {
			t.Errorf("substrate record %d contains the admin password; an operator, a support "+
				"engineer and an audit log can all read it", i)
		}
	}
}

// TestNoSubstrateMethodCanChangeAMasterPassword is the construction behind the
// no-rotation rule, asserted rather than described.
//
// compute.RelationalSpec forbids rotating the admin password on a re-Ensure, and
// the conformance suite checks the behaviour. This checks the *shape*: RDSAPI has
// exactly one method that takes a credential, and it is the create. A general
// modify would put the provider one edit away from rotating a password the caller
// has stored, and a rule that holds because no method can express the violation
// is worth more than one that holds because nobody wrote the call.
func TestNoSubstrateMethodCanChangeAMasterPassword(t *testing.T) {
	t.Parallel()
	rds := reflect.TypeOf((*aws.RDSAPI)(nil)).Elem()
	if rds.NumMethod() == 0 {
		t.Fatal("RDSAPI reports no methods, so this derivation is about nothing")
	}
	carriers := map[string]bool{}
	for i := range rds.NumMethod() {
		m := rds.Method(i)
		for j := range m.Type.NumIn() {
			if typeCarriesASecret(m.Type.In(j)) {
				carriers[m.Name] = true
			}
		}
	}
	want := map[string]bool{"CreateCluster": true}
	if !reflect.DeepEqual(carriers, want) {
		t.Errorf("the RDS substrate methods carrying credential material are %v, want %v. A "+
			"second one is a second place a stored password can be rotated out from under the "+
			"caller, which compute.RelationalSpec.AdminPassword forbids", keysOf(carriers),
			keysOf(want))
	}
}

// typeCarriesASecret reports whether a type is, or contains, credential
// material.
//
// It looks for the redacting types by name rather than by identity so that it
// keeps working if a request grows a nested struct. That is deliberately blunt:
// the question is "could material be in here", and a false positive is a test
// failure a reader can dismiss while a false negative is the defect.
func typeCarriesASecret(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct:
		if isSecretType(t) {
			return true
		}
		for i := range t.NumField() {
			if typeCarriesASecret(t.Field(i).Type) {
				return true
			}
		}
		return false
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return typeCarriesASecret(t.Elem())
	default:
		return isSecretType(t)
	}
}

func isSecretType(t reflect.Type) bool {
	return t.Name() == "Secret" || t.Name() == "SecretValue" || t.Name() == "PushCredentials"
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAChangedImmutableFieldIsRefusedRatherThanSubstituted covers the arm that
// converges an existing cluster.
//
// That arm converges capacity, security groups and tags, and used to compare
// none of the four fields Aurora fixes at creation -- so a re-Ensure asking for a
// different engine version, database name or admin username returned nil and an
// effective spec reporting the live values. For the engine version that is the
// substitution [compute.RelationalProvisioner] forbids in as many words. For the
// admin username it is worse than a wrong report: it is half of the credential
// the caller stored before provisioning, so a green deploy leaves that copy
// naming an account which does not exist.
//
// The conformance suite carries the port-neutral half of this
// (port/relational-database/an-immutable-field-is-not-silently-substituted); it
// cannot drive the engine version, because it is given exactly one and asking for
// another would only prove the provider refuses a version it does not offer. This
// configuration offers two, so the version case is checked here.
//
// The last case is the one that keeps the check honest: an unchanged re-Ensure
// must still succeed. A refusal keyed on "the cluster exists" rather than on
// "the spec differs" would pass every case above and break every redeploy.
func TestAChangedImmutableFieldIsRefusedRatherThanSubstituted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for what, change := range map[string]func(*compute.RelationalSpec){
		"a different engine version": func(s *compute.RelationalSpec) { s.EngineVersion = "15" },
		"a different database name":  func(s *compute.RelationalSpec) { s.DatabaseName = "seconddb" },
		"a different admin username": func(s *compute.RelationalSpec) { s.AdminUsername = "seconduser" },
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			rp := mustRelational(t, p)
			if _, err := rp.EnsureRelational(ctx, relationalSpec("app")); err != nil {
				t.Fatalf("the first EnsureRelational: %v", err)
			}
			second := relationalSpec("app")
			change(&second)

			st, err := rp.EnsureRelational(ctx, second)
			if err == nil {
				t.Fatalf("re-Ensuring with %s succeeded; the effective spec reports engine "+
					"version %q, database %q and admin username %q, and the spec asked for %q, "+
					"%q and %q. None of these can change on an existing Aurora cluster, so "+
					"reporting success substitutes the live values for the ones asked for",
					what, st.Spec.EngineVersion, st.Spec.DatabaseName, st.Spec.AdminUsername,
					second.EngineVersion, second.DatabaseName, second.AdminUsername)
			}
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Errorf("re-Ensuring with %s was refused with %v, which does not match "+
					"compute.ErrInvalidSpec; the spec is what has to change", what, err)
			}
			// The refusal says what the caller has to decide, rather than only
			// that the call failed.
			if !strings.Contains(err.Error(), "reconcile") {
				t.Errorf("the refusal is %q, which does not say that this is a new endpoint "+
					"rather than a reconcile -- the thing the caller has to decide", err)
			}
		})
	}

	t.Run("an unchanged re-Ensure still converges", func(t *testing.T) {
		t.Parallel()
		p, _ := newProvider(t, nil)
		rp := mustRelational(t, p)
		if _, err := rp.EnsureRelational(ctx, relationalSpec("app")); err != nil {
			t.Fatalf("the first EnsureRelational: %v", err)
		}
		// Capacity changes, which is a field RDS *can* modify. It must still
		// converge: the refusal above is keyed on the spec differing in an
		// immutable field, not on the cluster existing.
		converging := relationalSpec("app")
		converging.Capacity = compute.CapacityRange{MinUnits: 0.5, MaxUnits: 4}
		st, err := rp.EnsureRelational(ctx, converging)
		if err != nil {
			t.Fatalf("re-Ensuring with only a changed capacity failed with %v; the mutable "+
				"fields still have to converge", err)
		}
		if st.Spec.Capacity.MaxUnits != 4 {
			t.Errorf("the effective spec reports MaxUnits %g after converging to 4",
				st.Spec.Capacity.MaxUnits)
		}
	})
}

// TestRelationalCapacityCeilingRefusesCreateAndModify verifies that a caller
// bypassing the control plane cannot write a capacity above the operator limit.
func TestRelationalCapacityCeilingRefusesCreateAndModify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	rp := mustRelational(t, p)

	oversized := relationalSpec("denied")
	oversized.Capacity = compute.CapacityRange{MinUnits: 128, MaxUnits: 128}
	if _, err := rp.EnsureRelational(ctx, oversized); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("oversized create = %v; want invalid spec", err)
	}
	if _, err := sub.RDS.DescribeCluster(ctx, "apphub-denied"); !errors.Is(err, aws.ErrNoSuchResource) {
		t.Fatalf("oversized create wrote a cluster: %v", err)
	}

	allowed := relationalSpec("bounded")
	st, err := rp.EnsureRelational(ctx, allowed)
	if err != nil {
		t.Fatalf("allowed create: %v", err)
	}
	for _, capacity := range []compute.CapacityRange{
		{MinUnits: 128, MaxUnits: 0},
		{MinUnits: 0.25, MaxUnits: 128},
	} {
		oversized = allowed
		oversized.Capacity = capacity
		if _, err := rp.EnsureRelational(ctx, oversized); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("oversized modify (%+v) = %v; want invalid spec", capacity, err)
		}
		cluster, err := sub.RDS.DescribeCluster(ctx, "apphub-bounded")
		if err != nil {
			t.Fatal(err)
		}
		if cluster.MinCapacity != 0.5 || cluster.MaxCapacity != 4 {
			t.Errorf("oversized modify wrote capacity %g–%g ACUs", cluster.MinCapacity, cluster.MaxCapacity)
		}
	}
	if st.Spec.Capacity.MaxUnits != 2 {
		t.Fatalf("allowed create returned capacity %+v", st.Spec.Capacity)
	}

	custom, _ := newProvider(t, func(c *aws.Config) {
		c.Relational.MaxCapacityUnits = 4
	})
	customSpec := relationalSpec("custom")
	customSpec.Capacity.MaxUnits = 4
	if _, err := mustRelational(t, custom).EnsureRelational(ctx, customSpec); err != nil {
		t.Fatalf("operator-approved 4-unit create: %v", err)
	}
	customSpec.Capacity.MaxUnits = 4.25
	if _, err := mustRelational(t, custom).EnsureRelational(ctx, customSpec); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("overriding the custom limit = %v; want invalid spec", err)
	}
}

func TestRelationalCapacityConfigRespectsUnitsAndDefaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, func(c *aws.Config) {
		c.Relational.MaxCapacityUnits = 1
	})
	spec := relationalSpec("small")
	spec.Capacity = compute.CapacityRange{}
	st, err := mustRelational(t, p).EnsureRelational(ctx, spec)
	if err != nil {
		t.Fatalf("omitted capacity under a smaller operator ceiling: %v", err)
	}
	if st.Spec.Capacity.MinUnits != 0.25 || st.Spec.Capacity.MaxUnits != 1 {
		t.Fatalf("effective capacity = %+v; want 0.25–1 units", st.Spec.Capacity)
	}

	p, _ = newProvider(t, func(c *aws.Config) {
		c.Relational.ACUsPerUnit = 1
		c.Relational.MaxCapacityUnits = 4
	})
	spec = relationalSpec("mapping")
	spec.Capacity = compute.CapacityRange{MinUnits: 0.5, MaxUnits: 4}
	st, err = mustRelational(t, p).EnsureRelational(ctx, spec)
	if err != nil {
		t.Fatalf("4 abstract units at 1 ACU per unit: %v", err)
	}
	if st.Spec.Capacity.MaxUnits != 4 {
		t.Fatalf("capacity units were treated as ACUs: %+v", st.Spec.Capacity)
	}
}

func TestRelationalCapacityConfigRejectsInvalidCeilings(t *testing.T) {
	t.Parallel()
	for _, limit := range []float64{-1, math.NaN(), math.Inf(1), 129} {
		cfg := fullConfig()
		cfg.Relational.MaxCapacityUnits = limit
		if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
			t.Errorf("MaxCapacityUnits %g was accepted; want a finite Aurora-compatible ceiling", limit)
		}
	}
	cfg := fullConfig()
	cfg.Relational.MaxCapacityUnits = 1
	cfg.Relational.DefaultMaxUnits = 2
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Error("explicit default above operator ceiling was accepted")
	}
}

// --- grants -----------------------------------------------------------------

// TestAKeyValueGrantIsLeastPrivilege checks the property the source system does
// not have.
//
// The source attaches eight DynamoDB actions whenever an application has a table
// (database.go:117-126), so a read-only consumer gets PutItem, UpdateItem,
// DeleteItem and BatchWriteItem. compute.AccessRead here has to grant reads and
// only reads, and the assertion is over the policy document rather than over the
// behavioural hook, because "a write fails" and "no write action is granted" are
// different claims and the second is the one about privilege.
func TestAKeyValueGrantIsLeastPrivilege(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	kv := mustKeyValues(t, p)

	st, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("app"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	role := strings.TrimPrefix(identity.ID, "role/")
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("the fixture is not using the in-memory IAM")
	}

	if err := kv.Grant(ctx, st.Ref, identity, compute.AccessRead); err != nil {
		t.Fatalf("Grant(AccessRead): %v", err)
	}
	policies := iam.Policies(role)
	if len(policies) == 0 {
		t.Fatal("Grant wrote no inline policy, so nothing was granted and every assertion below " +
			"is about nothing")
	}
	docs := strings.Join(valuesOf(policies), "\n")
	for _, write := range []string{"PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem"} {
		if strings.Contains(docs, write) {
			t.Errorf("a read grant permits dynamodb:%s; read access that permits writing is not "+
				"read access, and this is the narrowing the source system does not do", write)
		}
	}
	for _, read := range []string{"GetItem", "Query", "Scan", "BatchGetItem"} {
		if !strings.Contains(docs, read) {
			t.Errorf("a read grant does not permit dynamodb:%s, so the consumer cannot find the "+
				"data it may read", read)
		}
	}
	// The resource is the table's ARN as the substrate reported it, and nothing
	// wider. A policy naming "*" would satisfy every behavioural check and grant
	// access to every table in the account.
	if strings.Contains(docs, `"*"`) {
		t.Error("the grant names a wildcard resource, which authorises every table in the account")
	}

	// Narrowing replaces rather than accumulates. This is the case an
	// implementation gets wrong by adding a second statement.
	if err := kv.Grant(ctx, st.Ref, identity, compute.AccessReadWrite); err != nil {
		t.Fatalf("Grant(AccessReadWrite): %v", err)
	}
	if err := kv.Grant(ctx, st.Ref, identity, compute.AccessRead); err != nil {
		t.Fatalf("re-granting AccessRead: %v", err)
	}
	narrowed := strings.Join(valuesOf(iam.Policies(role)), "\n")
	if strings.Contains(narrowed, "PutItem") {
		t.Error("narrowing from read-write to read left a write action in force; the grant " +
			"accumulated instead of being replaced")
	}
	if got := len(iam.Policies(role)); got != 1 {
		t.Errorf("the role carries %d inline policies after three grants, want 1; a grant that "+
			"adds a policy per call cannot be narrowed or revoked", got)
	}

	// And the role carries nothing else. USOSS-10 pins that a role *it* creates
	// has no permissions; this pins that this port adds exactly one policy and
	// removes it again.
	if err := kv.Revoke(ctx, st.Ref, identity); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := len(iam.Policies(role)); got != 0 {
		t.Errorf("the role carries %d inline policies after Revoke, want 0", got)
	}
}

// TestTeardownDeletesAWorkloadIdentityWithAKeyValueGrant pins the teardown bug
// this file's Grant test does not cover: DeleteWorkloadIdentity has to succeed
// on a role a key-value Grant put an inline policy on.
//
// [keyValueProvisioner.Grant] writes that policy with PutRolePolicy
// (keyvalue.go), and teardown does not call Revoke — [compute.IdentityService]
// asks a provider to release the grants made to an identity it deletes, and on
// AWS that promise is kept by removing the role's inline policies as part of
// deleting the role, not by revoking each grant separately. Before
// [identityService.DeleteWorkloadIdentity] did that, it called IAM.DeleteRole
// directly against a role still carrying the grant's policy, which real IAM
// refuses with DeleteConflictException. [MemoryIAM.DeleteRole] now models that
// refusal instead of quietly dropping the policies for free, so this exercises
// the real failure mode rather than passing against a fixture looser than AWS.
func TestTeardownDeletesAWorkloadIdentityWithAKeyValueGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	kv := mustKeyValues(t, p)

	st, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("app"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	if err := kv.Grant(ctx, st.Ref, identity, compute.AccessReadWrite); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	role := strings.TrimPrefix(identity.ID, "role/")
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("the fixture is not using the in-memory IAM")
	}
	if got := len(iam.Policies(role)); got == 0 {
		t.Fatal("Grant wrote no inline policy, so this test proves nothing about deleting one")
	}

	if err := p.Identities().DeleteWorkloadIdentity(ctx, identity); err != nil {
		t.Fatalf("DeleteWorkloadIdentity on a role with a key-value grant: %v", err)
	}
	if _, err := sub.IAM.GetRole(ctx, role); !errors.Is(err, aws.ErrNoSuchResource) {
		t.Errorf("GetRole after DeleteWorkloadIdentity: got %v, want %v", err, aws.ErrNoSuchResource)
	}
}

// TestAKeyValueGrantIsScopedToTheTableItNames pins the pair-scoping at the level
// where the defect lived: the inline IAM policy name.
//
// The conformance suite now carries this invariant behaviourally
// (grants/key-value-table/a-grant-names-one-resource). This test is the
// substrate-level statement of the same thing, because the mechanism is what got
// it wrong: PutRolePolicy replaces the whole document under the name it is given
// and DeleteRolePolicy removes it, so a provider-wide policy name made the *role*
// the unit of replacement instead of the (table, role) pair compute.Granter is
// keyed on. Two tables on one role held one grant between them; a grant on the
// second silently destroyed the first, a revoke of either removed both, and every
// call returned nil.
//
// Asserting on the policy names as well as the documents is deliberate. A
// behavioural check tells you access was lost; the names tell you why, and they
// are the thing a later change to the naming would break.
func TestAKeyValueGrantIsScopedToTheTableItNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	kv := mustKeyValues(t, p)

	alpha, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("alpha"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable(alpha): %v", err)
	}
	beta, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("beta"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable(beta): %v", err)
	}
	identity := mustIdentity(t, p, "app")
	role := strings.TrimPrefix(identity.ID, "role/")
	iam, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatal("the fixture is not using the in-memory IAM")
	}
	// One table's ARN, so "the grant on alpha survives" is a claim about alpha
	// rather than about the number of policies.
	alphaTable, ok := strings.CutPrefix(alpha.Ref.ID, "table/")
	if !ok {
		t.Fatalf("the alpha reference %s does not carry a table name", alpha.Ref)
	}
	ddb, ok := sub.DynamoDB.(*aws.MemoryDynamoDB)
	if !ok {
		t.Fatal("the fixture is not using the in-memory DynamoDB")
	}
	alphaARN, ok := ddb.TableARN(alphaTable)
	if !ok {
		t.Fatalf("the in-memory DynamoDB has no ARN for %q", alphaTable)
	}
	grantsAlpha := func() bool {
		return strings.Contains(strings.Join(valuesOf(iam.Policies(role)), "\n"), alphaARN)
	}

	if err := kv.Grant(ctx, alpha.Ref, identity, compute.AccessReadWrite); err != nil {
		t.Fatalf("Grant(alpha): %v", err)
	}
	if !grantsAlpha() {
		t.Fatal("the role has no grant on alpha immediately after being granted one; the rest of " +
			"this test would be vacuous")
	}

	// The Grant half.
	if err := kv.Grant(ctx, beta.Ref, identity, compute.AccessRead); err != nil {
		t.Fatalf("Grant(beta): %v", err)
	}
	if !grantsAlpha() {
		t.Error("granting on beta destroyed the role's grant on alpha, and returned nil doing " +
			"it; compute.Granter is keyed on the (resource, identity) pair, so one inline policy " +
			"name per provider makes the role the unit of replacement")
	}
	if got := len(iam.Policies(role)); got != 2 {
		t.Errorf("the role carries %d inline policies after grants on two tables, want 2 (one "+
			"per table): %v", got, keysOfString(iam.Policies(role)))
	}

	// The Revoke half. Revoke's resource argument is load-bearing; it was once
	// resolved only to be discarded.
	if err := kv.Revoke(ctx, beta.Ref, identity); err != nil {
		t.Fatalf("Revoke(beta): %v", err)
	}
	if !grantsAlpha() {
		t.Error("revoking beta removed the role's grant on alpha; tearing down one table must " +
			"not take an unrelated table's access with it")
	}
	if got := len(iam.Policies(role)); got != 1 {
		t.Errorf("the role carries %d inline policies after revoking one of two, want 1", got)
	}
	if err := kv.Revoke(ctx, alpha.Ref, identity); err != nil {
		t.Fatalf("Revoke(alpha): %v", err)
	}
	if got := len(iam.Policies(role)); got != 0 {
		t.Errorf("the role carries %d inline policies after both grants were revoked, want 0", got)
	}
}

// tableNameFromRef recovers the DynamoDB table name a key-value ref carries,
// the same way [TestAKeyValueGrantIsScopedToTheTableItNames] does.
func tableNameFromRef(t *testing.T, ref compute.Ref) string {
	t.Helper()
	name, ok := strings.CutPrefix(ref.ID, "table/")
	if !ok {
		t.Fatalf("the reference %s does not carry a table name", ref)
	}
	return name
}

// TestWaitForKeyValueTableToleratesATransientNotFoundAfterCreate is the
// regression test for the deploy failure this fix addresses. CloudTrail showed
// CreateTable succeed and the DescribeTable and ListTagsOfResource calls right
// behind it answer ResourceNotFoundException, because DynamoDB's control plane
// is not immediately read-consistent with itself.
// [keyValueProvisioner.WaitForKeyValueTable] used to map that straight to
// compute.ErrNotFound ("the resource was deleted while waiting for it") for a
// table CreateTable had just reported as created.
//
// This test fails without the fix: with keyValueNotFoundGrace removed (or the
// tolerance dropped), the single injected not-found below reaches waitFor as
// [compute.PhaseGone] on the first poll and the wait aborts immediately instead
// of reaching compute.PhaseReady.
func TestWaitForKeyValueTableToleratesATransientNotFoundAfterCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	kv := mustKeyValues(t, p)

	st, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("app"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable: %v", err)
	}
	ddb, ok := sub.DynamoDB.(*aws.MemoryDynamoDB)
	if !ok {
		t.Fatal("the fixture is not using the in-memory DynamoDB")
	}
	name := tableNameFromRef(t, st.Ref)

	// One not-found read, exactly what CloudTrail showed: CreateTable
	// succeeded and the DescribeTable right behind it did not see it yet.
	// One-shot ([failNext.FailNext]), not sticky, because the real fault is
	// transient: the very next read finds the table.
	ddb.FailNext(fmt.Errorf("%w: table %q", aws.ErrNoSuchResource, name))

	got, err := kv.WaitForKeyValueTable(ctx, st.Ref, compute.WaitOptions{Timeout: time.Second})
	if err != nil {
		t.Fatalf("WaitForKeyValueTable: %v", err)
	}
	if got.Phase != compute.PhaseReady {
		t.Errorf("phase = %v, want %v", got.Phase, compute.PhaseReady)
	}
}

// TestWaitForKeyValueTableFailsWhenNotFoundOutlastsTheGracePeriod is the other
// half of the same property: a table that is genuinely gone -- not merely slow
// to propagate -- must still be reported gone, not waited on until the caller's
// deadline expires for an unrelated reason.
func TestWaitForKeyValueTableFailsWhenNotFoundOutlastsTheGracePeriod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	kv := mustKeyValues(t, p)

	st, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("app"))
	if err != nil {
		t.Fatalf("EnsureKeyValueTable: %v", err)
	}
	ddb, ok := sub.DynamoDB.(*aws.MemoryDynamoDB)
	if !ok {
		t.Fatal("the fixture is not using the in-memory DynamoDB")
	}
	name := tableNameFromRef(t, st.Ref)

	// Every DynamoDB read not-found from here on, as if the table were
	// actually deleted mid-wait -- which the grace period must not mask
	// forever.
	defer ddb.FailUntilStopped(fmt.Errorf("%w: table %q", aws.ErrNoSuchResource, name))()

	_, err = kv.WaitForKeyValueTable(ctx, st.Ref, compute.WaitOptions{Timeout: time.Second})
	if !errors.Is(err, compute.ErrNotFound) {
		t.Fatalf("WaitForKeyValueTable = %v, want an error matching compute.ErrNotFound", err)
	}
}

// TestAGrantPolicyPrefixThatLeavesNoRoomIsRefusedAtConstruction pins where the
// misconfiguration is caught.
//
// The grant policy name is a prefix plus a table, bounded by IAM's 128
// characters. A prefix that fills the ceiling cannot render a name for any
// table, and the choice is between learning that at aws.New and learning it at
// the Grant in the middle of a deploy. This project prefers the first, and the
// test is here so a later refactor that moves the check into Grant has to argue
// with something.
func TestAGrantPolicyPrefixThatLeavesNoRoomIsRefusedAtConstruction(t *testing.T) {
	t.Parallel()
	cfg := fullConfig()
	kv := *cfg.KeyValue
	kv.GrantPolicyName = strings.Repeat("x", 128)
	cfg.KeyValue = &kv
	_, err := aws.New(aws.NewMemorySubstrate(), cfg)
	if err == nil {
		t.Fatal("aws.New accepted a grant policy prefix that leaves no room for a table name; " +
			"every Grant this provider makes would be refused, and the operator would learn it " +
			"from a failing deploy rather than from the configuration")
	}
	if !strings.Contains(err.Error(), "GrantPolicyName") {
		t.Errorf("the refusal is %q, which does not name the field to change", err)
	}
}

// keysOfString is [keysOf] for a map whose values are strings, for a failure
// message that names the policies rather than counting them.
func keysOfString(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// TestWorkloadGrantsMatchesEveryGranterPortVended is the derived cross-check the
// capability's own contract asks for.
//
// compute.CapWorkloadGrants says a provider advertising it must be able to grant
// on *every* Granter port it vends, and one that can grant on some but not others
// must advertise nothing. Config.capabilities derives the capability from one
// expression, and that expression becomes wrong the moment another Granter port
// lands here (USOSS-13's object store carries one). So the set of Granter ports
// is derived from the interface types and each one is actually driven.
func TestWorkloadGrantsMatchesEveryGranterPortVended(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	if !p.Capabilities().Has(compute.CapWorkloadGrants) {
		t.Fatal("the full configuration does not advertise CapWorkloadGrants, so this test is " +
			"about nothing")
	}

	// Every accessor on compute.Provider whose port embeds Granter. Derived,
	// because a hand-maintained list of Granter ports is exactly the artefact
	// that missed one on this project before.
	granter := reflect.TypeOf((*compute.Granter)(nil)).Elem()
	provider := reflect.TypeOf((*compute.Provider)(nil)).Elem()
	var vended []string
	for i := range provider.NumMethod() {
		m := provider.Method(i)
		if m.Type.NumOut() == 0 {
			continue
		}
		out := m.Type.Out(0)
		if out.Kind() != reflect.Interface || !out.Implements(granter) {
			continue
		}
		vended = append(vended, m.Name)
	}
	sort.Strings(vended)
	if len(vended) == 0 {
		t.Fatal("derived no Granter-carrying ports from compute.Provider, so this check is about " +
			"nothing")
	}

	value := reflect.ValueOf(p)
	for _, accessor := range vended {
		results := value.MethodByName(accessor).Call(nil)
		if err, _ := results[1].Interface().(error); err != nil {
			// A port this provider does not vend at all is not a problem: the
			// capability is about the ports it *does* vend.
			continue
		}
		port, ok := results[0].Interface().(compute.Granter)
		if !ok {
			t.Errorf("%s returned something that is not a Granter", accessor)
			continue
		}
		// Driven, not inspected. The claim is "can grant", and the only way to
		// check it is to grant.
		err := port.Grant(ctx, compute.Ref{}, compute.Ref{}, compute.AccessRead)
		if errors.Is(err, compute.ErrUnsupported) {
			t.Errorf("this provider advertises %s but %s.Grant refuses as unsupported. The "+
				"capability's contract is that it must hold for every Granter port vended, so "+
				"either the port can grant or the capability must not be advertised — a caller "+
				"told grants work and then finding they work on one port is worse off than one "+
				"told nothing works", compute.CapWorkloadGrants, accessor)
		}
		// Any other error is fine and expected: the zero Refs above are not
		// resources. What is being checked is that the refusal is not
		// "unsupported".
		_ = err
	}
}

// TestGrantIsRefusedWhenTheCapabilityIsAbsent is the negative half, and it names
// the capability the operator has to change.
func TestGrantIsRefusedWhenTheCapabilityIsAbsent(t *testing.T) {
	t.Parallel()
	// A provider with the key-value port and no grants is not expressible
	// through Config today — the capability is derived from the same field — so
	// this drives the refusal through the only other provider the fixtures
	// build: one with no key-value port at all, where the accessor itself
	// refuses. The property being pinned is that the refusal is typed and names
	// a capability, whichever one it is.
	p, err := aws.New(aws.NewMemorySubstrate(), registrylessConfig())
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	if _, err := p.KeyValues(); !errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("KeyValues() on a provider with no key-value configuration returned %v, want "+
			"compute.ErrUnsupported", err)
	}
	var unsupported *compute.UnsupportedError
	if _, err := p.Relational(); !errors.As(err, &unsupported) {
		t.Errorf("Relational() returned %v, which is not a typed *compute.UnsupportedError; an "+
			"operator needs the provider and the capability named", err)
	} else if unsupported.Capability != compute.CapRelationalDatabase {
		t.Errorf("the refusal names capability %q, want %q", unsupported.Capability,
			compute.CapRelationalDatabase)
	}
}

// --- ingress ----------------------------------------------------------------

// TestIngressFailsClosed enumerates every peer kind the interface defines and
// pins what this port does with it.
//
// It is written over compute.PeerKind's whole vocabulary rather than over the two
// cases that matter, because the failure mode being guarded is a *default*: a
// switch whose default branch produces a rule is a switch that opens a port
// nobody asked for. The source system's equivalent widens to 0.0.0.0/0 when it
// has no security group to name, which is the behaviour the interface's
// fail-closed rule was written to reverse.
func TestIngressFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		rule compute.IngressRule
		// accepted says whether this provider will write a rule for it.
		accepted bool
		// notFound says the refusal must be compute.ErrNotFound: the rule is
		// well formed and names a workload that does not exist.
		notFound bool
	}{
		{
			name:     "the control plane, which is how role provisioning connects",
			rule:     compute.IngressRule{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 5432},
			accepted: true,
		},
		{
			name: "a workload that does not exist, which has no group to name",
			rule: compute.IngressRule{
				From: compute.Peer{Kind: compute.PeerWorkload, Workload: compute.Ref{
					Provider: aws.DefaultName, Kind: compute.KindService, ID: "service/app"}},
				Port: 5432,
			},
			notFound: true,
		},
		{
			name: "the internet, which would publish a database",
			rule: compute.IngressRule{From: compute.Peer{Kind: compute.PeerInternet}, Port: 5432},
		},
		{
			name: "the platform ingress proxy, which speaks HTTP",
			rule: compute.IngressRule{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 5432},
		},
		{
			name: "a peer kind the interface does not define",
			rule: compute.IngressRule{From: compute.Peer{Kind: compute.PeerKind("everyone")}, Port: 5432},
		},
		{
			name: "a workload peer with no reference",
			rule: compute.IngressRule{From: compute.Peer{Kind: compute.PeerWorkload}, Port: 5432},
		},
		{
			name: "no peer kind at all, which is the zero value",
			rule: compute.IngressRule{Port: 5432},
		},
		{
			name: "a port outside the legal range",
			rule: compute.IngressRule{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 70000},
		},
		{
			name: "a protocol the interface does not define",
			rule: compute.IngressRule{
				From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 5432,
				Protocol: compute.Protocol("sctp"),
			},
		},
		{
			name: "a workload reference set on a peer kind that ignores it",
			rule: compute.IngressRule{
				From: compute.Peer{Kind: compute.PeerControlPlane, Workload: compute.Ref{
					Provider: aws.DefaultName, Kind: compute.KindService, ID: "service/app"}},
				Port: 5432,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			spec := relationalSpec("ingress")
			spec.Ingress = []compute.IngressRule{tc.rule}
			_, err := mustRelational(t, p).EnsureRelational(ctx, spec)
			switch {
			case tc.accepted:
				if err != nil {
					t.Errorf("a rule this provider should write was refused: %v", err)
				}
			case err == nil:
				t.Error("the rule was accepted; a peer this provider cannot resolve must not " +
					"become a rule, and must not become a wider one")
			case tc.notFound:
				if !errors.Is(err, compute.ErrNotFound) {
					t.Errorf("refused with %v, want compute.ErrNotFound", err)
				}
			default:
				if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrForeignRef) {
					t.Errorf("refused with %v, which matches neither compute.ErrInvalidSpec nor "+
						"compute.ErrForeignRef", err)
				}
			}
		})
	}
}

// TestAMissingControlPlaneGroupIsARefusalNotAWidening is the fail-closed case
// with the most consequence, so it is checked on the substrate as well as on the
// error.
//
// Without a control-plane rule, deploy-time role and extension provisioning
// connects from the control plane and the packets are silently dropped — which the
// source system documents having hit (database.go:200-205). The two wrong answers
// are to leave the port shut and to open it to everything, and the assertion is
// that neither happened: the call failed *and* no security group was written.
func TestAMissingControlPlaneGroupIsARefusalNotAWidening(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, func(cfg *aws.Config) {
		pc := cfg.Placements["default"]
		pc.ControlPlaneSecurityGroups = nil
		cfg.Placements["default"] = pc
	})
	_, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec("no-control-plane"))
	if err == nil {
		t.Fatal("a control-plane rule was accepted on a provider that was never told where the " +
			"control plane is")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}
	rendered, _ := p.Harness().Rendered(ctx)
	for _, artefact := range rendered {
		if strings.Contains(artefact, "0.0.0.0/0") || strings.Contains(artefact, "::/0") {
			t.Errorf("the substrate holds an open ingress rule after the refusal: %s", artefact)
		}
	}
}

// TestIngressConvergesInTheSubstrate is the removal half, observed where it has
// to be observed.
//
// The provider's own read-back is the weaker half of a convergence claim — a
// provider that reported the new spec while leaving the old rule in place would
// satisfy it — so this reads the substrate. The source system has no revoke on
// this path at all, so a rule it wrote outlives the spec that asked for it: "I
// removed that rule" silently means "I stopped asking for it".
func TestIngressConvergesInTheSubstrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, func(cfg *aws.Config) {
		pc := cfg.Placements["default"]
		pc.ControlPlaneSecurityGroups = []string{"apphub-test-cp-one", "apphub-test-cp-two"}
		cfg.Placements["default"] = pc
	})
	rp := mustRelational(t, p)

	if _, err := rp.EnsureRelational(ctx, relationalSpec("converge")); err != nil {
		t.Fatalf("the first Ensure: %v", err)
	}
	before, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if !anyContains(before, "apphub-test-cp-two") {
		t.Fatal("the first Ensure did not write a rule for the second control-plane group, so " +
			"the removal below is about nothing")
	}

	// Narrow the configuration, which is how an operator removes a
	// control-plane group, and re-Ensure the same spec through a second provider
	// over the *same* substrate. Two providers rather than one because the
	// removal is a configuration change, and reconfiguring is what an operator
	// does — the resource is the same one either way, which is exactly what the
	// determinism contract buys.
	p2 := newProviderOver(t, sub, func(cfg *aws.Config) {
		c := cfg.Placements["default"]
		c.ControlPlaneSecurityGroups = []string{"apphub-test-cp-one"}
		cfg.Placements["default"] = c
	})
	if _, err := mustRelational(t, p2).EnsureRelational(ctx, relationalSpec("converge")); err != nil {
		t.Fatalf("the second Ensure: %v", err)
	}
	after, err := p2.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if anyContains(after, "apphub-test-cp-two") {
		t.Error("the removed control-plane group still has an ingress rule in the substrate; " +
			"Ensure added rather than converged, and a security control that only ever " +
			"accumulates is one that fails open")
	}
	if !anyContains(after, "apphub-test-cp-one") {
		t.Error("the remaining control-plane group lost its rule, so provisioning can no longer " +
			"connect")
	}
}

func anyContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// --- capacity, encryption, engines ------------------------------------------

// TestCapacityIsRefusedRatherThanRounded states the property as a property.
//
// Three ports in this package already refuse rather than round — ECR retention
// (USOSS-10), SSM parameter tiers (USOSS-26) — and the reason generalises: both
// roundings are a lie the caller cannot see. Rounding a floor down can put it
// below what the workload needs to start; rounding a ceiling up bills for
// capacity nobody asked for.
func TestCapacityIsRefusedRatherThanRounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rp := mustRelational(t, p)

	// Anything that does not land on Aurora's half-ACU step is refused. With
	// the default two ACUs per unit, a quarter-unit step is representable and a
	// tenth is not.
	for _, c := range []compute.CapacityRange{
		{MinUnits: 0.1, MaxUnits: 2},
		{MinUnits: 0.25, MaxUnits: 2.1},
		{MinUnits: 0.05, MaxUnits: 0.05},
		{MinUnits: 0, MaxUnits: 0.1},
		{MinUnits: 1, MaxUnits: 1000},
		{MinUnits: -1, MaxUnits: 2},
		{MinUnits: 4, MaxUnits: 1},
	} {
		spec := relationalSpec(fmt.Sprintf("cap-%g-%g", c.MinUnits, c.MaxUnits))
		spec.Capacity = c
		if _, err := rp.EnsureRelational(ctx, spec); err == nil {
			t.Errorf("capacity %v was accepted; it does not land on an Aurora Serverless v2 step "+
				"or is out of range, so accepting it means silently provisioning something else", c)
		} else if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("capacity %v was refused with %v, want compute.ErrInvalidSpec", c, err)
		}
	}

	// A zero ceiling gets the provider's finite default rather than nothing.
	// compute.CapacityRange is explicit that an unbounded default is a billing
	// incident.
	spec := relationalSpec("cap-default")
	spec.Capacity = compute.CapacityRange{}
	st, err := rp.EnsureRelational(ctx, spec)
	if err != nil {
		t.Fatalf("a spec with no capacity range was refused: %v", err)
	}
	if st.Spec.Capacity.MaxUnits <= 0 {
		t.Errorf("the effective ceiling is %g; a default ceiling has to be finite and positive",
			st.Spec.Capacity.MaxUnits)
	}
}

// TestStorageIsAlwaysEncrypted pins that there is no configuration for it.
//
// The source system sets StorageEncrypted (database.go:311). This provider does
// too and offers no knob, because an unencrypted managed database is not a
// trade-off worth exposing — and the check is on the substrate record rather than
// on the call, so a provider that stopped passing the flag would fail here even
// though every other assertion still held.
func TestStorageIsAlwaysEncrypted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	if _, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec("encrypted")); err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if !anyContains(rendered, "encrypted=true") {
		t.Errorf("no cluster in the substrate reports encrypted storage: %v", rendered)
	}
	if anyContains(rendered, "encrypted=false") {
		t.Error("a cluster in the substrate has unencrypted storage")
	}
}

// TestEngineAndVersionRefusals covers what the provider will not provision.
func TestEngineAndVersionRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rp := mustRelational(t, p)

	// MySQL. Aurora has a MySQL engine and this provider deliberately does not
	// offer it: nothing in the source system provisions one, so there is no call
	// site to validate a mapping against.
	spec := relationalSpec("mysql")
	spec.Engine = compute.EngineMySQL
	if _, err := rp.EnsureRelational(ctx, spec); !errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("EngineMySQL was refused with %v, want compute.ErrUnsupported: it is an engine "+
			"this provider does not offer rather than an invalid spec", err)
	}

	// A version the configuration does not declare. Substituting is what the
	// interface forbids.
	for _, v := range []string{"", "17", "16.4", "latest"} {
		spec := relationalSpec("version-" + v)
		spec.EngineVersion = v
		if _, err := rp.EnsureRelational(ctx, spec); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("engine version %q was refused with %v, want compute.ErrInvalidSpec", v, err)
		}
	}

	// A minor version in the *configuration* is refused at construction, so an
	// operator learns from here rather than from RDS on the day it is retired.
	cfg := fullConfig()
	cfg.Relational.EngineVersions = map[compute.SQLEngine][]string{compute.EnginePostgres: {"16.4"}}
	if _, err := aws.New(aws.NewMemorySubstrate(), cfg); err == nil {
		t.Error("a pinned minor version in Config.Relational.EngineVersions was accepted")
	}
}

// TestNewRefusesADatabaseConfigItCannotServe enumerates the construction-time
// refusals, because a provider that cannot work is better discovered by the
// operator who configured it than by the deploy that needed it.
func TestNewRefusesADatabaseConfigItCannotServe(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*aws.Config, *aws.Substrate){
		"a relational config with no RDS substrate": func(_ *aws.Config, sub *aws.Substrate) {
			sub.RDS = nil
		},
		"a relational config with no EC2 substrate": func(_ *aws.Config, sub *aws.Substrate) {
			sub.EC2 = nil
		},
		"a key-value config with no DynamoDB substrate": func(_ *aws.Config, sub *aws.Substrate) {
			sub.DynamoDB = nil
		},
		"no engine versions": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.EngineVersions = nil
		},
		"an engine with no versions": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.EngineVersions = map[compute.SQLEngine][]string{compute.EnginePostgres: {}}
		},
		"an engine this provider does not offer": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.EngineVersions = map[compute.SQLEngine][]string{compute.EngineMySQL: {"8"}}
		},
		"a name prefix that cannot begin an RDS identifier": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.NamePrefix = "9-"
		},
		"an empty name prefix, which leaves the leading-letter rule unmet": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.NamePrefix = ""
		},
		"a name prefix with a character RDS forbids": func(cfg *aws.Config, _ *aws.Substrate) {
			cfg.Relational.NamePrefix = "apphub_"
		},
		"no placement that can hold a database": func(cfg *aws.Config, _ *aws.Substrate) {
			for name, pc := range cfg.Placements {
				pc.Subnets = nil
				cfg.Placements[name] = pc
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := fullConfig()
			sub := aws.NewMemorySubstrate()
			mutate(&cfg, sub)
			if _, err := aws.New(sub, cfg); err == nil {
				t.Error("New accepted a configuration it cannot serve; the provider would " +
					"advertise a capability that fails at the first deploy that needed it")
			}
		})
	}
}

// --- ownership --------------------------------------------------------------

// TestOwnershipRequiresBothTagsOnEveryDatabaseResource is USOSS-13's finding,
// applied to the resources this port creates.
//
// The security group's half of this property is in
// TestASecurityGroupAppHubOwnsAsSomethingElseIsNotAdopted, which lives in an
// internal test file because planting the decoy needs the physical name and
// exporting a name-rendering method for a test to call would put a test seam on
// the production type.
//
// Checking only the ownership tag makes every resource apphub owns
// interchangeable by name, and these are not interchangeable: a security group
// and a database cluster are different objects with different consequences, and
// adopting one as the other is how a trust relationship or a network hole gets
// silently repurposed. The property is checked per resource kind rather than
// once, because a provider that got the cluster right and the security group
// wrong would pass a single check.
func TestOwnershipRequiresBothTagsOnEveryDatabaseResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Each case plants a resource carrying apphub's ownership tag but a
	// *different* component, which is the case the ownership tag alone cannot
	// catch.
	for _, tc := range []struct {
		name string
		// plant writes the decoy and returns the logical name to Ensure.
		plant func(*testing.T, *aws.Provider, *aws.Substrate) string
		call  func(*testing.T, *aws.Provider, string) error
	}{
		{
			name: "a cluster apphub owns as something else",
			plant: func(t *testing.T, p *aws.Provider, _ *aws.Substrate) string {
				t.Helper()
				rp := mustRelational(t, p)
				st, err := rp.EnsureRelational(ctx, relationalSpec("adopt"))
				if err != nil {
					t.Fatalf("Ensure: %v", err)
				}
				if err := rp.DeleteRelational(ctx, st.Ref); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				if err := p.Harness().CreateUnowned(ctx, st.Ref); err != nil {
					t.Fatalf("CreateUnowned: %v", err)
				}
				return "adopt"
			},
			call: func(t *testing.T, p *aws.Provider, name string) error {
				t.Helper()
				_, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec(name))
				return err
			},
		},
		{
			name: "a table apphub owns as something else",
			plant: func(t *testing.T, p *aws.Provider, _ *aws.Substrate) string {
				t.Helper()
				kv := mustKeyValues(t, p)
				st, err := kv.EnsureKeyValueTable(ctx, keyValueSpec("adopt"))
				if err != nil {
					t.Fatalf("Ensure: %v", err)
				}
				if err := kv.DeleteKeyValueTable(ctx, st.Ref); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				if err := p.Harness().CreateUnowned(ctx, st.Ref); err != nil {
					t.Fatalf("CreateUnowned: %v", err)
				}
				return "adopt"
			},
			call: func(t *testing.T, p *aws.Provider, name string) error {
				t.Helper()
				_, err := mustKeyValues(t, p).EnsureKeyValueTable(ctx, keyValueSpec(name))
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, sub := newProvider(t, nil)
			name := tc.plant(t, p, sub)
			err := tc.call(t, p, name)
			if err == nil {
				t.Fatal("Ensure adopted a resource this platform did not create as this kind of " +
					"resource; both the ownership tag and the component tag have to match")
			}
			if !errors.Is(err, compute.ErrNotOwned) {
				t.Errorf("refused with %v, which does not match compute.ErrNotOwned; a caller "+
					"cannot tell 'that name is taken' from an ordinary failure", err)
			}
		})
	}
}

// --- teardown ---------------------------------------------------------------

// TestDeleteRemovesEverythingEnsureCreated is the property the source system's
// teardown does not have.
//
// The source stores three RDS identifiers on the application row to find them
// again (container.go:263-268), so a failed deploy that never wrote that row
// strands them. Here every physical name is derived from the logical one, and
// this checks that the derivation is actually used: after Delete, the substrate
// holds nothing.
func TestDeleteRemovesEverythingEnsureCreated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)
	rp := mustRelational(t, p)

	st, err := rp.EnsureRelational(ctx, relationalSpec("teardown"))
	if err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	before, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	// Every resource kind the port creates has to be visible first, or the
	// assertion below is about a subset.
	for _, kind := range []string{"Cluster ", "Instance ", "SubnetGroup ", "SecurityGroup "} {
		if !anyContains(before, kind) {
			t.Fatalf("the substrate holds no %s after Ensure, so this teardown assertion is "+
				"incomplete: %v", strings.TrimSpace(kind), before)
		}
	}

	if err := rp.DeleteRelational(ctx, st.Ref); err != nil {
		t.Fatalf("DeleteRelational: %v", err)
	}
	after, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	for _, artefact := range after {
		for _, kind := range []string{"Cluster ", "Instance ", "SubnetGroup ", "SecurityGroup "} {
			if strings.HasPrefix(artefact, kind) {
				t.Errorf("teardown left %s behind; a resource nothing addresses is a resource "+
					"nothing will ever delete, and a security group is one that keeps a network "+
					"hole open", artefact)
			}
		}
	}
	// And it is re-runnable.
	if err := rp.DeleteRelational(ctx, st.Ref); err != nil {
		t.Errorf("the second DeleteRelational returned %v; a failed deploy leaves a partial set "+
			"and the retry deletes the ones that are already gone", err)
	}
}

// TestADatabaseAndItsServiceShareALogicalName pins the pairing the deploy module
// always produces: one logical name for both an application's database and its
// service, under the same prefix.
//
// The database's security group was once named exactly what the service's group
// is named, so the service step found the database's group, refused it as not
// owned, and every deploy with a database failed after the database existed.
// Teardown of either must also leave the other's group alone.
func TestADatabaseAndItsServiceShareALogicalName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	db, err := mustRelational(t, p).EnsureRelational(ctx, relationalSpec(spec.Name))
	if err != nil {
		t.Fatalf("ensuring the database: %v", err)
	}
	rt := containers(t, p)
	svc, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensuring a service named like its database: %v", err)
	}
	if _, err := p.WorkloadSecurityGroupID(ctx, svc.Ref); err != nil {
		t.Fatalf("the service's own security group: %v", err)
	}
	if err := mustRelational(t, p).DeleteRelational(ctx, db.Ref); err != nil {
		t.Fatalf("deleting the database: %v", err)
	}
	if _, err := p.WorkloadSecurityGroupID(ctx, svc.Ref); err != nil {
		t.Errorf("deleting the database took the service's security group with it: %v", err)
	}
}

// TestADatabaseAdmitsItsWorkload pins the deploy module's second Ensure: once
// the service exists, the database's ingress names the service's own security
// group, and a deploy with a database no longer fails at database-ingress.
func TestADatabaseAdmitsItsWorkload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	svc, err := containers(t, p).EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("ensuring the service: %v", err)
	}
	groupID, err := p.WorkloadSecurityGroupID(ctx, svc.Ref)
	if err != nil {
		t.Fatalf("the service's own security group: %v", err)
	}
	db := relationalSpec(spec.Name)
	db.Ingress = append(db.Ingress, compute.IngressRule{
		From: compute.Peer{Kind: compute.PeerWorkload, Workload: svc.Ref},
		Port: 5432,
	})
	if _, err := mustRelational(t, p).EnsureRelational(ctx, db); err != nil {
		t.Fatalf("a database refused its own application as a peer: %v", err)
	}
	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if !anyContains(rendered, groupID) {
		t.Errorf("no rendered rule names the service's group %s: %v", groupID, rendered)
	}
}

// TestARuleDescriptionEC2WouldRejectIsRefused pins the ingress compiler to
// EC2's description charset. An apostrophe reached AuthorizeSecurityGroupIngress
// and failed the deploy at database-ingress with no word about which input.
func TestARuleDescriptionEC2WouldRejectIsRefused(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		description string
		wantErr     bool
	}{
		"apostrophe":         {"the application's own workload, and nothing else", true},
		"non-ascii":          {"workload — only", true},
		"too long":           {strings.Repeat("a", 256), true},
		"every allowed rune": {"aZ09 ._-:/()#,@[]+=&;{}!$*", false},
		"empty":              {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			p, _, spec := serviceFixture(t, nil)
			svc, err := containers(t, p).EnsureService(ctx, spec)
			if err != nil {
				t.Fatalf("ensuring the service: %v", err)
			}
			db := relationalSpec(spec.Name)
			db.Ingress = append(db.Ingress, compute.IngressRule{
				From:        compute.Peer{Kind: compute.PeerWorkload, Workload: svc.Ref},
				Port:        5432,
				Description: tc.description,
			})
			_, err = mustRelational(t, p).EnsureRelational(ctx, db)
			if tc.wantErr && !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("description %q = %v, want compute.ErrInvalidSpec", tc.description, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("description %q was refused: %v", tc.description, err)
			}
		})
	}
}

// TestATableGrantSurvivesEnsuringItsService pins the order a deploy runs in: the
// table is granted to the workload identity, then the service is ensured on that
// identity. The service's capability reconcile used to prune every "apphub-"
// inline policy it had not written, which removed the table grant and left the
// application with AccessDenied on its own table.
func TestATableGrantSurvivesEnsuringItsService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, spec := serviceFixture(t, nil)
	kv := mustKeyValues(t, p)
	table, err := kv.EnsureKeyValueTable(ctx, keyValueSpec(spec.Name))
	if err != nil {
		t.Fatalf("ensuring the table: %v", err)
	}
	if err := kv.Grant(ctx, table.Ref, spec.Identity, compute.AccessReadWrite); err != nil {
		t.Fatalf("granting the table: %v", err)
	}
	spec.ExecEnabled = true
	for _, pass := range []string{"create", "redeploy"} {
		if _, err := containers(t, p).EnsureService(ctx, spec); err != nil {
			t.Fatalf("%s: ensuring the service: %v", pass, err)
		}
		info, err := kv.DescribeGrant(ctx, table.Ref, spec.Identity)
		if err != nil {
			t.Fatalf("%s: the table grant is gone after ensuring the service: %v", pass, err)
		}
		if info.Level != compute.AccessReadWrite {
			t.Errorf("%s: table grant level = %q, want %q", pass, info.Level, compute.AccessReadWrite)
		}
	}
}
