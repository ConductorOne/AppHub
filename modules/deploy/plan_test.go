// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// planFor is newPlan with the test configuration, failing the test on refusal.
func planFor(t *testing.T, app *Application) *Plan {
	t.Helper()
	p, err := newPlan(testConfig(), app, planFixtureProvider)
	if err != nil {
		t.Fatalf("newPlan: %v", err)
	}
	return p
}

// render is a Plan rendered as a value: every pointer followed, so two plans
// built from equal inputs render identically.
//
// Written as a reflective walk rather than as a format string over the fields
// this test knows about, and that is the point rather than the convenience: a
// pointer field printed as an address makes every plan differ from every other,
// which turns every case below into a pass. Two rounds of this test were
// defective for exactly that reason — first Plan's own pointers, then a pointer
// nested inside a specification the format string had reached only as %+v — and
// both were invisible because a difference is what the test is looking for.
// There is a stability gate in the test as well, because a construction and its
// check fail independently.
func render(p *Plan) string {
	return deepRender(reflect.ValueOf(struct {
		Plan    *Plan
		Build   compute.BuildRequest
		Service compute.ServiceSpec
		// The completed workload specifications are part of the rendering, not
		// only the static half: Resources, Replicas, Schedule and Capabilities
		// reach a deploy through these and through nothing else, so a rendering
		// without them would report those fields as unread.
		Job compute.ScheduledJobSpec
	}{
		Plan:    p,
		Build:   p.Build("/context", []compute.ImageRef{"registry/x:tag"}),
		Service: p.Service(resolved{}),
		Job:     p.ScheduledJob(resolved{}),
	}))
}

// deepRender prints a value with every pointer followed and every map key
// sorted, so the result is a function of the value and of nothing else.
//
// Unexported fields are skipped: the Plan keeps its inputs privately, and
// including them would make every mutation differ trivially. io.Writer and
// other interface fields are printed by type, since an address is all a value
// like that has.
func deepRender(v reflect.Value) string { return deepRenderAt(v, 0) }

// deepRenderMaxDepth bounds the walk. Nothing rendered here is cyclic, and the
// bound is here so that a type added later which is cannot hang a test run.
const deepRenderMaxDepth = 32

func deepRenderAt(v reflect.Value, depth int) string {
	if depth > deepRenderMaxDepth {
		return "<too deep>"
	}
	deepRender := func(v reflect.Value) string { return deepRenderAt(v, depth+1) }
	switch v.Kind() {
	case reflect.Invalid:
		return "<invalid>"
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		// The only thing such a value has is an address, and an address is not
		// a function of the value.
		return "<" + v.Kind().String() + ">"
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return "<nil>"
		}
		// An interface is followed rather than named by its type. Naming the
		// type was this walk's second defect: a map[string]any full of strings
		// rendered as "<string> <string>", so a scan of it for credential
		// material could never have found any.
		return deepRender(v.Elem())
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return "<nil>"
		}
		parts := make([]string, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts = append(parts, deepRender(v.Index(i)))
		}
		return "[" + strings.Join(parts, " ") + "]"
	case reflect.Map:
		if v.IsNil() {
			return "<nil>"
		}
		parts := make([]string, 0, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			parts = append(parts, deepRender(iter.Key())+":"+deepRender(iter.Value()))
		}
		sort.Strings(parts)
		return "{" + strings.Join(parts, " ") + "}"
	case reflect.Struct:
		var parts []string
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			parts = append(parts, f.Name+"="+deepRender(v.Field(i)))
		}
		return "{" + strings.Join(parts, " ") + "}"
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}

// applicationFieldsNotReadByThePlan are the fields of [Application] a plan is
// not a function of, each with the reason.
//
// It is an exclusion list and it is the judgement in this test, which is why it
// carries reasons rather than names. Everything NOT on it must change the plan
// or be refused when it is taken away; a field that is neither is a field the
// record carries and the deploy ignores.
var applicationFieldsNotReadByThePlan = map[string]string{
	// Variant fields. They must be ZERO on the baseline this test uses, so
	// removing one cannot change anything here — which is the applicability
	// rule doing its job rather than a field going unread. They are driven from
	// both sides by TestEveryInputFieldIsClassified and
	// TestAVariantFieldSetOutsideItsVariantIsRefused, which is where a reader
	// should look before deleting either.
	"Schedule": "a variant field: zero unless the application is scheduled",
	// Read by run rather than the plan: it replaces the build step, and the
	// plan describes what is converged, which is the same with or without it.
	"PinnedImage": "consumed by run: it skips the build, and the plan is the same either way",
	"Runtime":     "a variant field: zero unless the application is a function, which is refused",
	"Handler":     "a variant field: zero unless the application is a function, which is refused",
	// Outputs. A redeploy legitimately carries the previous deploy's values, so
	// they are unconstrained and are not inputs at all.
	"Status":         "output: where the last deploy got to",
	"DeployStep":     "output: the current deployment intent/checkpoint",
	"FailedStep":     "output: where the last deploy stopped",
	"FailureClass":   "output: how the last deploy failed",
	"LastDeployedAt": "output: when the last deploy finished",
	"Artifacts":      "output: what the last deploy created",
}

// reachBaseline is the application the reach test mutates.
//
// It carries a secret binding, which testApplication does not: a binding needs
// a provider-issued reference, and the provider only holds one for a secret
// somebody stored. Planning does not need it to exist -- it checks the
// reference's provider, kind and target -- so a synthetic one is enough here
// and is what makes Application.Secrets observable in this test at all.
func reachBaseline() *Application {
	app := testApplication()
	app.Secrets = []SecretBinding{{
		EnvName: "API_TOKEN",
		Secret:  compute.Ref{Provider: planFixtureProvider, Kind: compute.KindSecret, ID: "api-token"},
	}}
	app.EnvSecrets = []string{"STRIPE_KEY"}
	return app
}

// TestEveryApplicationFieldReachesThePlanOrIsExcludedOnPurpose derives its
// population from the [Application] type rather than from a list of fields
// somebody wrote down, so a field added to the record and never wired into the
// plan fails here instead of being silently carried and ignored.
//
// The mutation is "take the field away". A field whose removal changes nothing
// and is not excluded is a field the deploy does not read.
func TestEveryApplicationFieldReachesThePlanOrIsExcludedOnPurpose(t *testing.T) {
	t.Parallel()
	rt := reflect.TypeOf(Application{})
	if rt.NumField() == 0 {
		t.Fatal("Application has no fields, so this test asserts nothing")
	}

	baseline := render(planFor(t, reachBaseline()))
	// The comparison below is only meaningful if the rendering is a function of
	// the plan. A pointer printed as an address makes every plan differ from
	// every other, and then every field looks read.
	if again := render(planFor(t, reachBaseline())); again != baseline {
		t.Fatalf("rendering the same plan twice differs, so no comparison below means "+
			"anything:\n%s\n%s", baseline, again)
	}
	var checked int
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		checked++
		reason, excluded := applicationFieldsNotReadByThePlan[field.Name]

		app := reachBaseline()
		v := reflect.ValueOf(app).Elem().Field(i)
		v.Set(reflect.Zero(field.Type))

		mutated, err := newPlan(testConfig(), app, planFixtureProvider)
		switch {
		case err != nil:
			if excluded {
				t.Errorf("%s is excluded as %q, but removing it is refused: %v",
					field.Name, reason, err)
			}
		case render(mutated) != baseline:
			if excluded {
				t.Errorf("%s is excluded as %q, but removing it changes the plan", field.Name, reason)
			}
		default:
			if !excluded {
				t.Errorf("removing %s neither changes the plan nor is refused: the record carries "+
					"it and the deploy does not read it. Wire it in, or add it to "+
					"applicationFieldsNotReadByThePlan with the reason", field.Name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no exported fields were checked")
	}
	// The exclusion list must not outlive its fields either: a stale entry is a
	// field somebody deleted and an exemption nobody removed.
	for name := range applicationFieldsNotReadByThePlan {
		if _, ok := rt.FieldByName(name); !ok {
			t.Errorf("applicationFieldsNotReadByThePlan excludes %q, which Application no longer has",
				name)
		}
	}
	t.Logf("checked %d exported field(s) of Application, %d excluded on purpose",
		checked, len(applicationFieldsNotReadByThePlan))
}

// TestEveryWorkloadCapabilityBecomesAProviderRequirement quantifies over the
// closed set the compute package publishes, not over the one capability that
// exists today. A capability added there and not handled here fails this.
func TestEveryWorkloadCapabilityBecomesAProviderRequirement(t *testing.T) {
	t.Parallel()
	all := compute.WorkloadCapabilities()
	if len(all) == 0 {
		t.Fatal("compute publishes no workload capabilities, so this test asserts nothing")
	}
	for _, c := range all {
		t.Run(string(c), func(t *testing.T) {
			t.Parallel()
			required := c.Requires()
			if required == "" {
				t.Fatalf("%q reports no required capability, which compute documents as "+
					"unrecognised; it should not be in WorkloadCapabilities()", c)
			}

			bare := testApplication()
			bare.Capabilities = nil
			without := planFor(t, bare)
			if contains(without.Required, required) {
				t.Fatalf("%q is required by an application that did not ask for %q, so the "+
					"positive case below cannot distinguish anything", required, c)
			}

			app := testApplication()
			app.Capabilities = []compute.WorkloadCapability{c}
			with := planFor(t, app)
			if !contains(with.Required, required) {
				t.Errorf("an application asking for %q does not require %q of its provider, so "+
					"it would deploy onto one that cannot grant it and fail at runtime", c, required)
			}
		})
	}

	// And the negative: a capability the compute package does not define is
	// refused rather than passed through to a provider that will not know it.
	app := testApplication()
	app.Capabilities = []compute.WorkloadCapability{"invented-capability"}
	if _, err := newPlan(testConfig(), app, planFixtureProvider); !errors.Is(err, ErrInvalidApplication) {
		t.Errorf("an unrecognised workload capability was accepted: %v", err)
	}
}

func contains[T comparable](haystack []T, needle T) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestNoApplicationCanPlanAPublicBucket. There is no field on the record that
// reaches PublicAccess, and this is the assertion that says so: the property is
// over every bucket an application record can ask for, not over the one this
// test happens to construct.
func TestNoApplicationCanPlanAPublicBucket(t *testing.T) {
	t.Parallel()
	kinds := []BucketKind{BucketStandard, BucketZonal}
	levels := []compute.AccessLevel{"", compute.AccessRead, compute.AccessReadWrite}
	var planned int
	for _, kind := range kinds {
		for _, level := range levels {
			app := testApplication()
			app.Bucket = Bucket{Kind: kind, Access: level}
			if kind == BucketZonal {
				app.Bucket.Zone = "zone-a"
			}
			p, err := newPlan(testConfig(), app, planFixtureProvider)
			if err != nil {
				t.Errorf("bucket kind %q level %q was refused: %v", kind, level, err)
				continue
			}
			if p.Bucket == nil {
				t.Errorf("bucket kind %q planned no bucket", kind)
				continue
			}
			planned++
			if p.Bucket.PublicAccess {
				t.Errorf("bucket kind %q level %q planned a publicly readable bucket", kind, level)
			}
			if p.BucketAccess == compute.AccessAdmin {
				t.Errorf("bucket kind %q level %q granted the workload administrative access",
					kind, level)
			}
		}
	}
	if planned != len(kinds)*len(levels) {
		t.Fatalf("planned %d of %d bucket configurations, so the property ran over a smaller "+
			"population than it claims", planned, len(kinds)*len(levels))
	}
	// The other direction: an application asking for administrative access is
	// refused rather than quietly downgraded, so this is a rule somebody has to
	// argue with rather than one they can drift past.
	app := testApplication()
	app.Bucket = Bucket{Kind: BucketStandard, Access: compute.AccessAdmin}
	if _, err := newPlan(testConfig(), app, planFixtureProvider); !errors.Is(err, ErrInvalidApplication) {
		t.Errorf("an application asking for administrative bucket access was accepted: %v", err)
	}
}

// TestARouteIsNeverPublishedOnAHostnameNobodyReserved.
func TestARouteIsNeverPublishedOnAHostnameNobodyReserved(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		route Route
	}{
		{"no hostname at all", Route{}},
		{"only whitespace", Route{Hostname: "   "}},
		{"a hostname carrying its own domain", Route{Hostname: "reports.elsewhere.test"}},
		{"a hostname with a path separator", Route{Hostname: "reports/v2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := testApplication()
			app.Routes = []Route{tc.route}
			p, err := newPlan(testConfig(), app, planFixtureProvider)
			if err == nil {
				t.Fatalf("published %+v", p.Routes)
			}
			if !errors.Is(err, ErrInvalidApplication) {
				t.Errorf("refusal is not an invalid-application failure: %v", err)
			}
		})
	}

	// Both directions: a hostname that is a single label is published, under
	// the configured domain and nowhere else.
	p := planFor(t, testApplication())
	if len(p.Routes) != 1 {
		t.Fatalf("planned %d routes, want 1", len(p.Routes))
	}
	if p.Routes[0].Host != "reports.apps.example.test" {
		t.Errorf("host = %q", p.Routes[0].Host)
	}
	if p.Routes[0].TLS == nil || p.Routes[0].TLS.CertificateRef == "" {
		t.Error("a route that did not ask for plaintext was planned without a certificate")
	}
}

// TestARouteWithoutACertificateIsRefusedRatherThanServedInTheClear.
func TestARouteWithoutACertificateIsRefusedRatherThanServedInTheClear(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.RouteCertificate = ""
	if _, err := newPlan(cfg, testApplication(), planFixtureProvider); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a route was planned with no certificate configured: %v", err)
	}
	// And the escape hatch is explicit, on the route, by somebody who meant it.
	app := testApplication()
	app.Routes[0].AllowPlaintext = true
	p, err := newPlan(cfg, app, planFixtureProvider)
	if err != nil {
		t.Fatalf("a route that explicitly allows plaintext was refused: %v", err)
	}
	if p.Routes[0].TLS != nil {
		t.Error("a plaintext route was given a certificate")
	}
}

// TestTheDatabaseAcceptsOnlyTheApplicationsOwnWorkload.
func TestTheDatabaseAcceptsOnlyTheApplicationsOwnWorkload(t *testing.T) {
	t.Parallel()
	p := planFor(t, testApplication())
	if p.Relational == nil {
		t.Fatal("no database planned")
	}
	if len(p.Relational.Ingress) != 0 {
		t.Errorf("a database was planned reachable before the workload it is for exists: %v",
			p.Relational.Ingress)
	}
	rules, err := p.RelationalIngress(compute.Ref{Provider: "fake-store", Kind: compute.KindService, ID: "x"})
	if err != nil {
		t.Fatalf("RelationalIngress: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("planned %d ingress rules, want exactly one", len(rules))
	}
	if rules[0].From.Kind != compute.PeerWorkload {
		t.Errorf("the database accepts %q as well as its own workload", rules[0].From.Kind)
	}
	if rules[0].Port != 5432 {
		t.Errorf("port = %d, want the engine's own", rules[0].Port)
	}

	// An engine with no known default port is refused, not guessed at.
	app := testApplication()
	app.Database.Engine = "cockroach"
	if _, err := newPlan(testConfig(), app, planFixtureProvider); err == nil {
		t.Error("an engine this module knows no port for was planned anyway")
	}
}

// TestExecIsOffOnEveryServiceThePlanProduces pins a negative. The source turned
// an interactive shell on for every service it created; if somebody widens that
// again, this fails and they have to say why.
func TestExecIsOffOnEveryServiceThePlanProduces(t *testing.T) {
	t.Parallel()
	p := planFor(t, testApplication())
	spec := p.Service(resolved{})
	if spec.ExecEnabled {
		t.Error("exec is enabled on a service this module planned")
	}
}

// TestTheRequiredCapabilitySetIsSortedAndDeduplicated keeps the failure message
// stable, which matters because it is what an operator reads when a provider
// cannot run their application.
func TestTheRequiredCapabilitySetIsSortedAndDeduplicated(t *testing.T) {
	t.Parallel()
	p := planFor(t, testApplication())
	if len(p.Required) == 0 {
		t.Fatal("the plan requires nothing of its provider")
	}
	if !sort.SliceIsSorted(p.Required, func(i, j int) bool { return p.Required[i] < p.Required[j] }) {
		t.Errorf("required capabilities are unsorted: %v", p.Required)
	}
	seen := map[compute.Capability]bool{}
	for _, c := range p.Required {
		if seen[c] {
			t.Errorf("%q is required twice", c)
		}
		seen[c] = true
	}
}

// TestApplicationLabelsCannotDisplaceTheOnesOperatorsSearchBy.
func TestApplicationLabelsCannotDisplaceTheOnesOperatorsSearchBy(t *testing.T) {
	t.Parallel()
	app := testApplication()
	app.Labels = map[string]string{LabelApplication: "some-other-application"}
	p := planFor(t, app)
	if got := p.Labels[LabelApplication]; got != app.ID {
		t.Errorf("a record's own labels overwrote the identifying label: %q", got)
	}
}

// TestTheSecretLabelSetCarriesNoRequesterSuppliedText. Labels are expected in
// listings and logs, and a secret's are the ones worth being careful about.
func TestTheSecretLabelSetCarriesNoRequesterSuppliedText(t *testing.T) {
	t.Parallel()
	app := testApplication()
	app.Name = "a display name somebody typed"
	app.Labels = map[string]string{"note": "and a label they typed"}
	labels := secretLabels(app)
	for k, v := range labels {
		if strings.Contains(v, "typed") {
			t.Errorf("secret label %q carries requester-supplied text %q", k, v)
		}
	}
	if labels[LabelApplication] != app.ID {
		t.Errorf("a stored secret carries no application label, so a teardown cannot find it")
	}
}

// TestAnOutOfRangePortIsRefusedRatherThanClamped. The source replaced anything
// outside 1-65535 with 80 (container.go:104-106), which produces a workload
// listening on a port nothing reaches and a record that says otherwise.
func TestAnOutOfRangePortIsRefusedRatherThanClamped(t *testing.T) {
	t.Parallel()
	for _, port := range []int{0, -1, 65536, 1 << 20} {
		app := testApplication()
		app.Port = port
		p, err := newPlan(testConfig(), app, planFixtureProvider)
		if err == nil {
			t.Errorf("port %d was accepted and planned as %d", port, p.Service(resolved{}).Ports[0].Number)
			continue
		}
		if !errors.Is(err, ErrInvalidApplication) {
			t.Errorf("port %d refused as something else: %v", port, err)
		}
	}
	// Both ends of the legal range, so the refusal is about the range and not
	// about ports.
	for _, port := range []int{1, 80, 8080, 65535} {
		app := testApplication()
		app.Port = port
		if _, err := newPlan(testConfig(), app, planFixtureProvider); err != nil {
			t.Errorf("legal port %d was refused: %v", port, err)
		}
	}
}

func TestPlanRefusesInvalidDatabaseExtensionsAndMissingOperatorCA(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.PostgresRootCertPath = "/operator/aurora-ca.pem"
	cases := []struct {
		name     string
		database Database
	}{
		{"unsupported", Database{Kind: DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{"dblink"}}},
		{"non-exact", Database{Kind: DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{"Vector"}}},
		{"duplicate", Database{Kind: DatabaseRelational, Engine: compute.EnginePostgres, Extensions: []string{"vector", "vector"}}},
		{"mysql", Database{Kind: DatabaseRelational, Engine: compute.EngineMySQL, Extensions: []string{"vector"}}},
		{"key-value", Database{Kind: DatabaseKeyValue, PartitionKey: "pk", Extensions: []string{"vector"}}},
		{"none", Database{Extensions: []string{"vector"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := testApplication()
			app.Database = tc.database
			if _, err := newPlan(cfg, app, planFixtureProvider); !errors.Is(err, ErrInvalidApplication) {
				t.Fatalf("invalid extensions accepted or returned the wrong error: %v", err)
			}
		})
	}
	app := testApplication()
	app.Database.Extensions = []string{"vector", "pg_trgm"}
	if _, err := newPlan(cfg, app, planFixtureProvider); err != nil {
		t.Fatalf("allowed PostgreSQL extensions refused: %v", err)
	}
	cfg.PostgresRootCertPath = ""
	if _, err := newPlan(cfg, app, planFixtureProvider); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("extensions without operator CA were not refused before deployment: %v", err)
	}
}
