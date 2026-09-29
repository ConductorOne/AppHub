// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

// The consequence of assumption A4 being false, asserted rather than described.
//
// This provider declares credentials.Capabilities{RecoverCreate: false} because
// ConductorOne's create request has no idempotency key and no operation resolves a
// creation by one, so a vend whose response is lost leaves a live credential that
// cannot be found again. Everywhere that fact is written down -- the package
// comment, docs/design/credential-vending.md §2.4, the decision record -- it is
// followed by the claim that lifecycle.CheckIssuable then refuses managed issuance
// unless an operator explicitly accepts it.
//
// That was a claim about another package's behaviour made from this one's
// documentation, which is the shape this project keeps paying for: a comment that
// was true of something and got attached to the wrong thing.
//
// # Why this file quantifies rather than enumerates
//
// Its first version tested *single-field* relaxations of a permissive policy.
// Review defeated that with a **two-field** bypass -- DefaultTTL together with
// MaxTTL -- which is unreachable from a population that changes one field at a
// time. The production code was fine; the fixture was weaker than the property it
// claimed to hold.
//
// So the property is now stated over the whole policy space: the Cartesian product
// of every field's values, with the opt-in withheld. And the field set is
// **derived from the struct by reflection** with a driver-or-exemption
// cross-check, so a policy field added later fails this test rather than being
// quantified over vacuously. Enumerating the fields by hand is what produced the
// gap, so the fix is to stop enumerating them.
//
// The import direction is the safe one: credentials/lifecycle does not import
// credentials/c1 and cannot, so this adds no cycle and no boundary exposure.

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

// policyAxis is the set of values one ProviderPolicy field takes in the generated
// population, or the reason it takes none.
type policyAxis struct {
	Why    string
	Values []func(*lifecycle.ProviderPolicy)
}

// everyType is every credential type the axes talk about, including shapes the
// enum does not name.
func everyType() []credentials.CredentialType {
	return []credentials.CredentialType{
		credentials.CredentialTypeDynamic,
		credentials.CredentialTypeStatic,
		"",
		"something-new",
	}
}

// policyAxes is the value set for each ProviderPolicy field, keyed by the struct
// field name so it can be cross-checked against reflection in both directions.
func policyAxes() map[string]policyAxis {
	ttls := []time.Duration{0, time.Nanosecond, time.Hour, 180 * 24 * time.Hour, 100 * 365 * 24 * time.Hour}

	// Every TTL-map shape: nil, empty, each duration under each type, and one that
	// names every type at once -- which is what a permissive operator writes, and
	// is the half of the two-field bypass that mattered.
	ttlMaps := []map[credentials.CredentialType]time.Duration{nil, {}}
	for _, ct := range everyType() {
		for _, d := range ttls {
			ttlMaps = append(ttlMaps, map[credentials.CredentialType]time.Duration{ct: d})
		}
	}
	all := map[credentials.CredentialType]time.Duration{}
	for _, ct := range everyType() {
		all[ct] = time.Hour
	}
	ttlMaps = append(ttlMaps, all)

	typeLists := [][]credentials.CredentialType{nil, {}}
	for _, ct := range everyType() {
		typeLists = append(typeLists, []credentials.CredentialType{ct})
	}
	typeLists = append(typeLists, everyType())

	var defaults, maxes []func(*lifecycle.ProviderPolicy)
	for _, m := range ttlMaps {
		m := m
		defaults = append(defaults, func(p *lifecycle.ProviderPolicy) { p.DefaultTTL = m })
		maxes = append(maxes, func(p *lifecycle.ProviderPolicy) { p.MaxTTL = m })
	}
	var allowed []func(*lifecycle.ProviderPolicy)
	for _, l := range typeLists {
		l := l
		allowed = append(allowed, func(p *lifecycle.ProviderPolicy) { p.AllowedTypes = l })
	}

	return map[string]policyAxis{
		"Enabled": {Values: []func(*lifecycle.ProviderPolicy){
			func(p *lifecycle.ProviderPolicy) { p.Enabled = false },
			func(p *lifecycle.ProviderPolicy) { p.Enabled = true },
		}},
		"AllowedTypes": {Values: allowed},
		"DefaultTTL":   {Values: defaults},
		"MaxTTL":       {Values: maxes},
		"AllowUnrecoverableIssuance": {
			Why: "it is the field under test; the caller fixes it and the population " +
				"holds it, so varying it here would collapse the property into a tautology",
		},
	}
}

// generatePolicies returns the Cartesian product of the axes, with the opt-in set
// as given.
//
// The product is over *combinations*, which is the whole point: a bypass needing
// two fields at once is unreachable from a population that changes one at a time,
// and that is exactly what review found.
func generatePolicies(optIn bool) []lifecycle.ProviderPolicy {
	axes := policyAxes()
	names := make([]string, 0, len(axes))
	for name, axis := range axes {
		if len(axis.Values) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names) // deterministic, so a failure is reproducible

	out := []lifecycle.ProviderPolicy{{AllowUnrecoverableIssuance: optIn}}
	for _, name := range names {
		axis := axes[name]
		next := make([]lifecycle.ProviderPolicy, 0, len(out)*len(axis.Values))
		for _, base := range out {
			for _, set := range axis.Values {
				p := base
				set(&p)
				next = append(next, p)
			}
		}
		out = next
	}
	return out
}

func TestThePolicyPopulationCoversEveryField(t *testing.T) {
	// The cross-check that makes the population a derivation rather than a list. A
	// field added to ProviderPolicy has no axis and no exemption, so this fails
	// before the properties below can quantify over it vacuously.
	declared := map[string]bool{}
	rt := reflect.TypeOf(lifecycle.ProviderPolicy{})
	for i := range rt.NumField() {
		if f := rt.Field(i); f.IsExported() {
			declared[f.Name] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("reflection found no exported ProviderPolicy fields; the derivation is empty")
	}

	axes := policyAxes()
	for name := range declared {
		axis, ok := axes[name]
		if !ok {
			t.Errorf("ProviderPolicy.%s has no axis and no exemption: vary it in policyAxes, or say why it cannot affect issuability", name)
			continue
		}
		if len(axis.Values) == 0 && axis.Why == "" {
			t.Errorf("ProviderPolicy.%s has an axis with neither values nor a reason", name)
		}
	}
	// The other direction: an axis naming no field covers nothing, which is what a
	// rename produces.
	for name := range axes {
		if !declared[name] {
			t.Errorf("policyAxes names %q, which is not an exported ProviderPolicy field", name)
		}
	}

	varied, exempt := 0, 0
	for _, axis := range axes {
		if len(axis.Values) > 0 {
			varied++
		} else {
			exempt++
		}
	}
	t.Logf("%d exported policy fields: %d varied, %d exempt; %d policies generated",
		len(declared), varied, exempt, len(generatePolicies(false)))
}

func TestNoPolicyWithoutTheOptInAdmitsIssuance(t *testing.T) {
	// The property over the whole generated policy space rather than over
	// one-field changes: with AllowUnrecoverableIssuance false, nothing admits
	// issuance through this provider, for any credential type.
	provider := providerOver(t, script{}.transport())
	policies := generatePolicies(false)
	if len(policies) == 0 {
		t.Fatal("empty policy population")
	}

	admitted, checked := 0, 0
	for _, policy := range policies {
		for _, ct := range everyType() {
			if err := lifecycle.CheckIssuable(provider, policy, ct); err == nil {
				admitted++
				if admitted <= 3 { // enough to diagnose, not enough to drown the log
					t.Errorf("issuance admitted without the opt-in: type=%q enabled=%t allowed=%v defaultTTL=%v maxTTL=%v",
						ct, policy.Enabled, policy.AllowedTypes, policy.DefaultTTL, policy.MaxTTL)
				}
			}
			checked++
		}
	}
	if admitted != 0 {
		t.Fatalf("%d of %d (policy, type) combinations admitted issuance with the opt-in withheld", admitted, checked)
	}
	t.Logf("%d (policy, type) combinations, none admitted", checked)
}

func TestTheOptInIsWhatChangesTheAnswer(t *testing.T) {
	// The other direction. Without it, the property above would be satisfied by a
	// provider nothing can ever issue through, and the refusal would be measuring
	// something other than the opt-in.
	provider := providerOver(t, script{}.transport())

	admitted := 0
	for _, policy := range generatePolicies(true) {
		for _, ct := range everyType() {
			if err := lifecycle.CheckIssuable(provider, policy, ct); err == nil {
				admitted++
			}
		}
	}
	if admitted == 0 {
		t.Fatal("with the opt-in set, no policy in the whole population admits issuance; the refusal is not about the opt-in")
	}

	// And withholding the opt-in from an otherwise-admitting policy refuses for the
	// stated reason rather than an incidental neighbour.
	control := lifecycle.ProviderPolicy{
		Enabled:                    true,
		AllowedTypes:               []credentials.CredentialType{credentials.CredentialTypeDynamic},
		AllowUnrecoverableIssuance: true,
	}
	if err := lifecycle.CheckIssuable(provider, control, credentials.CredentialTypeDynamic); err != nil {
		t.Fatalf("the control policy does not admit: %v", err)
	}
	control.AllowUnrecoverableIssuance = false
	if err := lifecycle.CheckIssuable(provider, control, credentials.CredentialTypeDynamic); !errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
		t.Errorf("err = %v, want ErrUnrecoverableIssuance", err)
	}
	t.Logf("%d (policy, type) combinations admitted with the opt-in set", admitted)
}

func TestTheTypeRefusalIsReachableAndIsAboutTheType(t *testing.T) {
	// Review's second finding: the earlier version withheld the opt-in, so the
	// recovery refusal fired first and the type refusal was unreachable. Mutating
	// the type check green left the test green -- it was measuring the recovery
	// refusal and reporting it as the type refusal.
	//
	// A test whose subject is masked by an earlier guard is measuring the earlier
	// guard. Setting the opt-in is the only way past the recovery refusal, so it is
	// the only way to reach the subject at all.
	provider := providerOver(t, script{}.transport())
	policy := lifecycle.ProviderPolicy{
		Enabled:                    true,
		AllowedTypes:               everyType(), // permit every type at the policy layer
		AllowUnrecoverableIssuance: true,
	}

	var admitted []credentials.CredentialType
	for _, ct := range everyType() {
		err := lifecycle.CheckIssuable(provider, policy, ct)
		if err == nil {
			admitted = append(admitted, ct)
			continue
		}
		// The refusal must be about the type and not about recovery, which is the
		// masking this test exists to detect.
		if errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
			t.Errorf("type %q was refused for recovery reasons with the opt-in set; the subject is masked", ct)
		}
	}
	if len(admitted) != 1 || admitted[0] != credentials.CredentialTypeDynamic {
		t.Fatalf("admitted types = %v, want exactly [dynamic]", admitted)
	}
}

func TestAStaticCredentialIsRefusedEvenWithTheOptIn(t *testing.T) {
	// The opt-in accepts one specific risk -- an unresolvable ambiguous vend -- and
	// must not become a general override. ConductorOne cannot vend a static
	// credential at all, because its create request requires a strictly positive
	// lifetime, so Capabilities{Static: false} is a fact and no policy should be
	// able to talk the lifecycle layer past it.
	provider := providerOver(t, script{}.transport())
	policy := lifecycle.ProviderPolicy{
		Enabled:                    true,
		AllowedTypes:               everyType(),
		AllowUnrecoverableIssuance: true,
	}

	err := lifecycle.CheckIssuable(provider, policy, credentials.CredentialTypeStatic)
	if err == nil {
		t.Fatal("CheckIssuable admitted a static credential through a provider that cannot vend one")
	}
	if errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
		t.Errorf("the refusal was about recovery rather than about the type: %v", err)
	}
	// The dynamic case passes under the same policy, so this is not a test that
	// would pass against a provider refused for everything.
	if err := lifecycle.CheckIssuable(provider, policy, credentials.CredentialTypeDynamic); err != nil {
		t.Fatalf("the same policy refused a dynamic credential too: %v", err)
	}
}

func TestTheDeclaredCapabilitiesAreWhatLifecycleActuallyReads(t *testing.T) {
	// CapabilitiesOf clears RecoverCreate for a provider that does not implement
	// credentials.CreateRecoverer, so a provider could declare the bit and be
	// masked. This asserts the two agree, which is what makes the refusals above
	// properties of the provider rather than of the masking.
	provider := providerOver(t, script{}.transport())
	declared := provider.Capabilities()
	effective := credentials.CapabilitiesOf(provider)
	if declared != effective {
		t.Fatalf("declared %+v but lifecycle sees %+v", declared, effective)
	}
	if effective.RecoverCreate {
		t.Error("RecoverCreate is set; ConductorOne has no idempotency key to resolve a vend by")
	}
	if effective.Static {
		t.Error("Static is set; ConductorOne's create request requires a positive lifetime")
	}
	if !effective.Revoke {
		t.Error("Revoke is clear; ConductorOne can revoke by identifier and this provider does")
	}
}
