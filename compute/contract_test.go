// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
)

// These tests pin decisions that review found wrong the first time. An
// interface package cannot be tested by exercising behaviour, but each of these
// properties is checkable and each one, if it regressed, would regress silently
// — a parallel type definition still compiles, an embedded interface still
// compiles, a capability constant still compiles. That is exactly the class of
// mistake worth a test.

// --- Shared workload-identity vocabulary -----------------------------------
//
// compute and credentials each defined a type called Attestation, meaning two
// different things, with two spellings of the same AWS scheme. The contract
// resolves it by giving credentials/workload sole ownership. These tests fail
// if compute grows a parallel definition again, or if the scheme identifiers
// drift apart.

func TestWorkloadIdentityUsesTheSharedExpectedAttestation(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(compute.WorkloadIdentity{}).FieldByName("Attestation")
	if !ok {
		t.Fatal("WorkloadIdentity has no Attestation field")
	}

	want := reflect.TypeOf(workload.ExpectedAttestation{})
	if field.Type != want {
		t.Fatalf("WorkloadIdentity.Attestation is %s, want %s — the vocabulary is owned by "+
			"credentials/workload and compute must not define a parallel type", field.Type, want)
	}

	// The type is the stored policy, not the runtime proof. If it ever acquires
	// a field that could carry material, the two concepts have been merged
	// again.
	for i := range want.NumField() {
		f := want.Field(i)
		if f.Type.Kind() != reflect.String {
			t.Errorf("ExpectedAttestation.%s is %s; the expected-attestation policy holds "+
				"only plain identifiers, and anything else suggests proof material has leaked in",
				f.Name, f.Type)
		}
	}
}

func TestAttestationSchemeIdentifiersMatchTheContract(t *testing.T) {
	t.Parallel()

	// Spelled out rather than referenced, so that changing the constant does
	// not change the test with it. These literals are the contract.
	cases := map[workload.Method]string{
		workload.MethodAWSSTSCallerIdentity: "aws-sts-caller-identity",
		workload.MethodK8sServiceAccount:    "k8s-service-account",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("scheme identifier is %q, want %q — a verifier registry keyed on one "+
				"spelling silently fails to select a verifier registered under another",
				string(got), want)
		}
	}

	// "aws-sts" was one half of the original mismatch. It must not come back.
	if string(workload.MethodAWSSTSCallerIdentity) == "aws-sts" {
		t.Error("the retired short scheme name is back")
	}
}

// --- Relational provisioning must not require identity-based granting -------

// relationalOnly is the minimal provider a substrate with managed Postgres and
// nothing else would write. It exists to prove such a provider can be written:
// if RelationalProvisioner regrows an embedded Granter, this stops compiling.
type relationalOnly struct{}

func (relationalOnly) EnsureRelational(context.Context, compute.RelationalSpec) (*compute.RelationalStatus, error) {
	return nil, nil
}
func (relationalOnly) DescribeRelational(context.Context, compute.Ref) (*compute.RelationalStatus, error) {
	return nil, nil
}
func (relationalOnly) WaitForRelational(context.Context, compute.Ref, compute.WaitOptions) (*compute.RelationalStatus, error) {
	return nil, nil
}
func (relationalOnly) DeleteRelational(context.Context, compute.Ref) error { return nil }

var _ compute.RelationalProvisioner = relationalOnly{}

// reflectedPorts is the reflect view of the package's exported interfaces.
//
// It is a hand-written list and that is now safe, because it is no longer the
// authority on anything: granteraudit_test.go derives the real set from source
// and fails if this list and the package disagree in either direction. What it
// buys is type-system truth — reflect.Implements answers "does this actually
// satisfy Granter" in a way an AST walk over method names approximates.
//
// It was the authority once, which is how a reviewer added an exported port
// carrying Granter and watched the audit pass.
func reflectedPorts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"ImageRegistry":         reflect.TypeOf((*compute.ImageRegistry)(nil)).Elem(),
		"ImagePullGranter":      reflect.TypeOf((*compute.ImagePullGranter)(nil)).Elem(),
		"ImageBuilder":          reflect.TypeOf((*compute.ImageBuilder)(nil)).Elem(),
		"ContainerRuntime":      reflect.TypeOf((*compute.ContainerRuntime)(nil)).Elem(),
		"FunctionRuntime":       reflect.TypeOf((*compute.FunctionRuntime)(nil)).Elem(),
		"ObjectStore":           reflect.TypeOf((*compute.ObjectStore)(nil)).Elem(),
		"RelationalProvisioner": reflect.TypeOf((*compute.RelationalProvisioner)(nil)).Elem(),
		"KeyValueProvisioner":   reflect.TypeOf((*compute.KeyValueProvisioner)(nil)).Elem(),
		"SecretStore":           reflect.TypeOf((*compute.SecretStore)(nil)).Elem(),
		"IdentityService":       reflect.TypeOf((*compute.IdentityService)(nil)).Elem(),
		"Provider":              reflect.TypeOf((*compute.Provider)(nil)).Elem(),
	}
}

// TestGranterIsOnlyOnAuditedPorts checks the audited list against the type
// system. Completeness of the candidate set is granteraudit_test.go's job; this
// is the half that knows what an interface really satisfies.
func TestGranterIsOnlyOnAuditedPorts(t *testing.T) {
	t.Parallel()

	granter := reflect.TypeOf((*compute.Granter)(nil)).Elem()

	audited := map[string]bool{}
	for _, name := range compute.WorkloadGrantPorts() {
		audited[name] = true
	}

	for name, rt := range reflectedPorts() {
		has := rt.Implements(granter)
		switch {
		case has && !audited[name]:
			t.Errorf("%s satisfies Granter but is not in WorkloadGrantPorts. Either its substrate "+
				"authorises by workload identity — in which case audit it and add it — or it does "+
				"not, and a provider will be forced to invent a principal or mint a credential to "+
				"implement Grant. That has happened three times: RelationalProvisioner, "+
				"ImageRegistry, and whichever port this is.", name)
		case !has && audited[name]:
			t.Errorf("%s is listed in WorkloadGrantPorts but does not satisfy Granter; the audit "+
				"and the interface disagree", name)
		}
	}
}

// TestImageRegistryHasNoGranter names the specific removal, so that reinstating
// it fails with the reason rather than with a set mismatch.
func TestImageRegistryHasNoGranter(t *testing.T) {
	t.Parallel()

	granter := reflect.TypeOf((*compute.Granter)(nil)).Elem()
	if reflect.TypeOf((*compute.ImageRegistry)(nil)).Elem().Implements(granter) {
		t.Error("ImageRegistry embeds Granter. No OCI registry federates a workload identity " +
			"provider, so the only implementation mints a credential the caller cannot see or " +
			"rotate; and the principal that pulls an image is the node or the execution role, " +
			"not the workload the grant names. Pull access is an obligation on the provider, " +
			"documented on ImageRegistry.")
	}
}

// TestWorkloadCapabilityRequiresIsTotal keeps the capability requirement as data
// rather than prose, which is what lets the conformance suite enumerate it.
func TestWorkloadCapabilityRequiresIsTotal(t *testing.T) {
	t.Parallel()

	for _, wc := range compute.WorkloadCapabilities() {
		if wc.Requires() == "" {
			t.Errorf("WorkloadCapability %q has no Requires() mapping, so a conformance suite "+
				"enumerating capabilities cannot tell which provider capability gates it", wc)
		}
	}
	if compute.WorkloadCapability("not-a-capability").Requires() != "" {
		t.Error("Requires() invented a capability for an unrecognised value; a provider must be " +
			"able to tell an unknown capability from an ungated one")
	}
}

func TestRelationalProvisionerDoesNotRequireGranter(t *testing.T) {
	t.Parallel()

	granter := reflect.TypeOf((*compute.Granter)(nil)).Elem()
	relational := reflect.TypeOf((*compute.RelationalProvisioner)(nil)).Elem()

	if relational.Implements(granter) {
		t.Error("RelationalProvisioner embeds Granter: a provider offering only operator-managed " +
			"Postgres would have to implement Grant(resource, workloadIdentity, level), which no " +
			"substrate identity generically maps to. Returning unsupported from a required method " +
			"is the stub-interface problem Provider exists to avoid.")
	}

	// The key-value port keeps it, because that substrate really does authorise
	// by workload identity. Asserting both directions stops the fix from being
	// applied by deleting Granter everywhere.
	keyValue := reflect.TypeOf((*compute.KeyValueProvisioner)(nil)).Elem()
	if !keyValue.Implements(granter) {
		t.Error("KeyValueProvisioner no longer embeds Granter, but a key-value table is granted " +
			"to a workload identity")
	}
}

func TestProviderVendsTheTwoDatabasePortsSeparately(t *testing.T) {
	t.Parallel()

	provider := reflect.TypeOf((*compute.Provider)(nil)).Elem()
	for _, name := range []string{"Relational", "KeyValues"} {
		if _, ok := provider.MethodByName(name); !ok {
			t.Errorf("Provider has no %s accessor", name)
		}
	}
	// A single accessor gated on "either capability" is what forced the two
	// ports together in the first place.
	if _, ok := provider.MethodByName("Databases"); ok {
		t.Error("Provider.Databases is back; it hands a relational-only provider an interface " +
			"it can only half implement")
	}
}

// --- Exec is not a workload-identity capability -----------------------------

func TestExecIsNotAWorkloadCapability(t *testing.T) {
	t.Parallel()

	for _, c := range compute.WorkloadCapabilities() {
		if strings.Contains(string(c), "exec") {
			t.Errorf("WorkloadCapabilities contains %q. Exec authorises the operator opening the "+
				"session, not the workload receiving it: on Kubernetes, granting pods/exec to the "+
				"target Pod's own ServiceAccount lets the workload exec into pods and still does "+
				"not let an operator in.", c)
		}
	}

	// Model inference stays, because there the calling principal really is the
	// workload.
	found := false
	for _, c := range compute.WorkloadCapabilities() {
		if c == compute.WorkloadCapabilityModelInference {
			found = true
		}
	}
	if !found {
		t.Error("WorkloadCapabilities no longer lists model inference, which is a genuine " +
			"workload-identity capability")
	}
}

func TestExecIsRuntimeOperabilityOnTheServiceSpec(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(compute.ServiceSpec{}).FieldByName("ExecEnabled")
	if !ok {
		t.Fatal("ServiceSpec has no ExecEnabled field; exec has to be modelled somewhere, and " +
			"the workload's identity is the wrong place")
	}
	if field.Type.Kind() != reflect.Bool {
		t.Errorf("ServiceSpec.ExecEnabled is %s, want bool: it states whether the target is "+
			"reachable, not who may reach it", field.Type)
	}
}

// --- Asynchronous ports all carry a Status ----------------------------------

func TestAsynchronousPortStatusesEmbedStatus(t *testing.T) {
	t.Parallel()

	// Every type an asynchronous port's Ensure/Describe/Wait can return. The
	// key-value table was the gap: it had a Wait but no phase, so a caller
	// could not tell "created" from "usable" for a resource whose creation is
	// genuinely asynchronous.
	statuses := []any{
		compute.ServiceStatus{},
		compute.FunctionStatus{},
		compute.EndpointStatus{},
		compute.RelationalStatus{},
		compute.KeyValueStatus{},
	}

	want := reflect.TypeOf(compute.Status{})
	for _, s := range statuses {
		rt := reflect.TypeOf(s)
		field, ok := rt.FieldByName("Status")
		if !ok || field.Type != want || !field.Anonymous {
			t.Errorf("%s does not embed compute.Status; the async contract (prompt return, "+
				"PhaseGone after delete, Wait with a deadline) cannot be stated for it", rt.Name())
		}
	}

	// Scheduled jobs went the other way: the port had a phase-bearing status and
	// no Wait, which is the combination the class split exists to forbid. It is
	// synchronous now, so a phase here would be claiming a contract the port
	// does not offer.
	if _, ok := reflect.TypeOf(compute.ScheduledJobStatus{}).FieldByName("Status"); ok {
		t.Error("ScheduledJobStatus embeds compute.Status again. A cron entry is live on " +
			"acceptance on every substrate named so far, so either the port has gained a " +
			"WaitForScheduledJob or it is advertising an asynchronous contract it cannot honour.")
	}
}

// TestEveryPortReadBackCarriesItsSpec pins the field that makes declarative
// convergence checkable by somebody other than the provider.
//
// Without it the strongest conformance invariant — an element present in the
// first spec and absent from the second is gone, not merely not-added — can only
// be tested through a provider-supplied hook, which a provider is free not to
// supply.
func TestEveryPortReadBackCarriesItsSpec(t *testing.T) {
	t.Parallel()

	// Read-back type -> the spec type it must carry. SecretStore is absent on
	// purpose: a secret's declarative state is its value, Get already returns
	// it, and a descriptor echoing it would add a place material can leak from.
	want := map[reflect.Type]reflect.Type{
		reflect.TypeOf(compute.ServiceStatus{}):      reflect.TypeOf(compute.ServiceSpec{}),
		reflect.TypeOf(compute.ScheduledJobStatus{}): reflect.TypeOf(compute.ScheduledJobSpec{}),
		reflect.TypeOf(compute.FunctionStatus{}):     reflect.TypeOf(compute.FunctionSpec{}),
		reflect.TypeOf(compute.EndpointStatus{}):     reflect.TypeOf(compute.EndpointSpec{}),
		reflect.TypeOf(compute.RelationalStatus{}):   reflect.TypeOf(compute.RelationalSpec{}),
		reflect.TypeOf(compute.KeyValueStatus{}):     reflect.TypeOf(compute.KeyValueSpec{}),
		reflect.TypeOf(compute.Bucket{}):             reflect.TypeOf(compute.BucketSpec{}),
		reflect.TypeOf(compute.Repository{}):         reflect.TypeOf(compute.RepositorySpec{}),
		reflect.TypeOf(compute.WorkloadIdentity{}):   reflect.TypeOf(compute.WorkloadIdentitySpec{}),
	}

	for rt, spec := range want {
		field, ok := rt.FieldByName("Spec")
		if !ok {
			t.Errorf("%s has no Spec field, so a caller cannot verify that a removed element is "+
				"gone rather than merely not-added", rt.Name())
			continue
		}
		if field.Type != spec {
			t.Errorf("%s.Spec is %s, want %s", rt.Name(), field.Type, spec)
		}
	}
}

// TestPlacementScopedSpecsCarryPlacement covers the amendment that made identity
// and secrets usable outside the default placement.
func TestPlacementScopedSpecsCarryPlacement(t *testing.T) {
	t.Parallel()

	placement := reflect.TypeOf(compute.Placement{})
	for _, spec := range []any{compute.WorkloadIdentitySpec{}, compute.SecretSpec{}} {
		rt := reflect.TypeOf(spec)
		field, ok := rt.FieldByName("Placement")
		if !ok || field.Type != placement {
			t.Errorf("%s carries no Placement. Both become namespace-scoped objects on "+
				"Kubernetes — a pod may only run as a ServiceAccount in its own namespace and "+
				"may only resolve a secretKeyRef in its own — so a workload in any placement but "+
				"the provider's default can use neither.", rt.Name())
		}
	}
}

// TestRouteCanBeServedEncrypted covers the last fail-open default: an
// application's own public hostname.
func TestRouteCanBeServedEncrypted(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeOf(compute.Route{})
	tls, ok := rt.FieldByName("TLS")
	if !ok || tls.Type != reflect.TypeOf((*compute.TLSConfig)(nil)) {
		t.Error("Route has no *TLSConfig. A ListenerSpec must carry a certificate to serve TLS, " +
			"but the hostname every deployed application actually gets could only be plaintext, " +
			"provider-invented, or refused.")
	}
	if plain, ok := rt.FieldByName("AllowPlaintext"); !ok || plain.Type.Kind() != reflect.Bool {
		t.Error("Route has no AllowPlaintext. Serving an application over HTTP has to be a " +
			"decision somebody wrote down, not the consequence of leaving a field nil.")
	}
}

// TestListenerCanExpressACertificatelessHTTPSSpec makes the invariant the design
// doc asserts actually reachable.
func TestListenerCanExpressACertificatelessHTTPSSpec(t *testing.T) {
	t.Parallel()

	// The point is that this value can be constructed at all. With nil TLS
	// meaning plaintext and no protocol field, the defect the source system
	// shipped was unrepresentable, so no provider could be tested for refusing
	// it.
	bad := compute.ListenerSpec{Port: 8443, Protocol: compute.ListenerHTTPS}
	if bad.TLS != nil {
		t.Fatal("test built the wrong value")
	}
	if compute.ListenerHTTPS == compute.ListenerHTTP {
		t.Error("the two listener protocols are indistinguishable")
	}
}

// sentinels is the taxonomy, by name, with the value each name refers to.
//
// It is a hand-written map and it is *cross-checked against its source*, which is
// the point: [TestEveryDeclaredErrorIsClassified] type-checks the whole package --
// every non-test file in the directory, whatever they happen to be called -- and
// requires every exported error the package declares to be in **exactly one** of
// this map and [nonTaxonomy]. An error in neither fails; so does one in both, and
// so does a name in either that the package no longer declares.
//
// It is not "this map carries every exported error": [nonTaxonomy] explains why
// that stopped being true and what decides which side a candidate falls on. What
// survives from the older, simpler rule is the part that matters -- a list of
// errors written out in a test is exactly the kind of restatement that drifts from
// the thing it restates, this repository has shipped that twice, and the
// properties below are only worth anything if the set they run over is *decided*
// rather than whatever somebody remembered to add.
//
// Values as well as names, because the properties are about the values: Go cannot
// enumerate a package's variables at runtime, so the names come from the source
// and the values come from here.
func sentinels() map[string]error {
	return map[string]error{
		"ErrUnsupported":  compute.ErrUnsupported,
		"ErrNotFound":     compute.ErrNotFound,
		"ErrNotOwned":     compute.ErrNotOwned,
		"ErrNotPermitted": compute.ErrNotPermitted,
		"ErrTransient":    compute.ErrTransient,
		"ErrInvalidSpec":  compute.ErrInvalidSpec,
		"ErrTimeout":      compute.ErrTimeout,
		"ErrFailed":       compute.ErrFailed,
		"ErrForeignRef":   compute.ErrForeignRef,
		// A port-operation outcome intended for caller action, so it belongs
		// here rather than in nonTaxonomy(): a caller that pinned a revision and
		// gets this picks another provider or stops pinning. It is the first
		// member that specialises another -- see hierarchy().
		"ErrVersionPinningUnsupported": compute.ErrVersionPinningUnsupported,
	}
}

// nonTaxonomy names the exported error values this package declares that are
// deliberately **not** part of the taxonomy, each with the reason.
//
// # Why an exception list exists at all, and why it is not a bypass
//
// [errorPopulation] derives every exported package-scope variable assignable
// to error. That is a *type* question, and "is this part of the taxonomy" is a
// *semantic* one. Until compute.ErrSecretSerialize they had the same answer, and
// the first time they diverged the derivation reported a real divergence as a
// defect.
//
// Nothing in the package distinguishes the two, so this cannot be derived; it has
// to be decided and written down. What keeps that from being a hole is the shape
// of the check rather than the goodwill of whoever edits this map: a declared
// error in **neither** map is fatal, a name in **both** is fatal, and a name in
// either that the package no longer declares is fatal. So the next new error
// stops the build until somebody classifies it, which is the only property that
// matters here.
//
// # The criterion, so the next call is decided rather than pattern-matched
//
// A taxonomy sentinel is **a provider port-operation outcome intended for caller
// action** -- retry, pick another provider, fix the spec, give up. Ask of a
// candidate: is it returned from a port operation, and is it *meant* to be the
// thing a caller branches on?
//
// The rule is deliberately about intent rather than about observed use, and the
// earlier evidential form -- "does a caller errors.Is it to choose an action" --
// was withdrawn on review because it is **false of every member**. An exact
// search outside providers and the conformance suite finds no business caller
// branching on any of the nine, which is what a pre-1.0 library looks like: the
// callers do not exist yet. Widening "caller" until the claim became true would
// have swallowed the conformance suite, and the conformance suite also exercises
// the one error this map excludes -- so the evidential form would have erased the
// distinction it exists to draw.
//
// Intent survives the first real caller appearing; a usage census does not.
//
// Being here excludes an error from the taxonomy's *properties*, not from
// scrutiny. The population is still derived, so
// [TestTheSentinelHierarchyMatchesTheImplementation] still sees an excluded error
// that wraps a real sentinel — verified by mutation: declaring
// ErrSecretSerialize as fmt.Errorf("%w: ...", ErrInvalidSpec) fails that test with
// "hierarchy() does not say so", exception or no exception. That is the case that
// would matter, because an excluded error wrapping ErrInvalidSpec is
// indistinguishable from ErrInvalidSpec to a caller.
func nonTaxonomy() map[string]string {
	return map[string]string{
		"ErrSecretSerialize": "a refusal by SecretValue to serialise credential material. No " +
			"provider returns it and it is not the outcome of a port operation: it is what the " +
			"encoding paths of a value type return instead of writing a secret out. A caller " +
			"matches it to assert that the refusal happened, never to decide what to do about a " +
			"resource, so the taxonomy's properties would say nothing about it and its presence " +
			"in that map would make the map mean 'the exported errors' rather than 'the taxonomy'",
	}
}

// hierarchy is the *intended* specialisation relation: sentinel -> the sentinels
// it deliberately wraps.
//
// # Why this is hand-written when the set above is derived
//
// It looks like the restatement this file spent an amendment removing, and it is
// the opposite, for a reason worth stating because it inverts the usual rule.
// [declaredErrors] reads the *implementation* out of the package. For the set
// of sentinels that is exactly right -- the declarations are the truth, and a
// hand-written list of them can only drift. For the hierarchy it is circular: if
// somebody replaces
//
//	ErrFoo = fmt.Errorf("%w: ...", ErrUnsupported)
//
// with
//
//	ErrFoo = errors.New("...")
//
// then the derivation happily reports that ErrFoo wraps nothing, and every caller
// branching on ErrUnsupported silently stops handling ErrFoo. A derivation from
// the implementation cannot catch the implementation changing. Declared intent
// can, which is USOSS-35's point and their own regression fixture.
//
// So both exist and are cross-checked against each other in both directions, the
// same idiom this file already uses for the set -- one level down.
//
// # The one entry, and how it got here
//
// This map was empty, and the emptiness was itself the assertion: no sentinel in
// compute wrapped another. USOSS-35 enumerated all 72 ordered pairs to establish
// that and found exactly one match -- ErrVersionPinningUnsupported, which was
// then on a branch. The comment that stood here said that when it landed the
// resolver would "either add one line here or get a failure naming the sentinel
// and the parent it was found to wrap".
//
// That is exactly what happened, and it is worth recording rather than editing
// away. Rebasing USOSS-35 onto this file produced three failures before this line
// existed: the population check reported a declared error in neither map, and
// both directions of the hierarchy check reported errors.go declaring
// ErrVersionPinningUnsupported as wrapping ErrUnsupported with the map silent
// about it. The pre-specified work was one line, and nothing had to be
// remembered for it to be demanded.
//
// So the map is no longer empty and the assertion is now positive: this is the
// complete set of intended specialisations, and both directions still hold. A
// second sentinel wrapping something, or this one quietly stopping, fails.
func hierarchy() map[string][]string {
	return map[string][]string{
		// ErrVersionPinningUnsupported wraps ErrUnsupported deliberately: a
		// caller that already branches on "this provider cannot do that" handles
		// a pinning refusal with no change, while a caller that wants to tell
		// "cannot pin" from "has no such port" still can. Declaring it here is
		// what catches the specialisation being re-declared with errors.New,
		// which no derivation from the implementation could see.
		"ErrVersionPinningUnsupported": {"ErrUnsupported"},
	}
}

// errorDecl is one exported error as the package declares it.
//
// An error, not a sentinel: this layer runs *before* the classification, so
// everything it describes is a candidate. It was errorDecl's predecessor that
// held the conflation this change exists to retire -- a type named for sentinels
// holding a declared non-sentinel -- and the word is now reserved for [sentinels]
// and [hierarchy], where the decision has already been made.
type errorDecl struct {
	// name is the identifier.
	name string
	// file is where it was declared, for a message that names it.
	file string
	// wraps is the sentinel this one specialises, empty for a root.
	wraps string
}

// The population of exported errors, and why it is derived with go/types rather
// than go/ast.
//
// Errors, not sentinels: this runs before the classification, so the population
// is candidates. Only [sentinels] holds things the taxonomy has accepted.
//
// # Two reproduced bypasses, and the shape they share
//
// The first version of this walked the AST of compute/errors.go looking for
// errors.New and fmt.Errorf calls. Review defeated it twice:
//
//   - "var ErrReviewAlias = ErrUnsupported" -- a bare identifier, not a call, so
//     the walk skipped it. An alias is two names for one value, so errors.Is
//     cannot tell them apart and every distinctness property was vacuous for it.
//   - an exported errors.New error in a different compute/*.go file -- the walk
//     only opened errors.go.
//
// Neither was a careless mistake in the walk; both are the same structural
// mistake in what a syntax walk can be. The population was defined by the forms
// and files the walk happened to recognise, so every property over it was
// complete with respect to a set the walk itself chose. That is why it looked
// finished: everything inside the population was accounted for. It is the third
// instance of this shape on this project -- an errhygiene check derived 33 of 37
// exported callables, a port-method tally derived 39 of 54 -- and every one was
// go/ast plus a hardcoded set of recognised forms.
//
// # The fix, in two halves
//
// The *population* comes from the type checker, over the whole package: every
// exported package-level variable whose type is assignable to error, in whatever
// file and by whatever expression. A name cannot hide from that by being declared
// in a form nobody enumerated, because nothing is enumerated.
//
// The *form* still needs the syntax tree, because "what does this wrap" is not a
// type-level fact. But it is now fail-closed: a name in the population whose
// declaration this file cannot classify is a failure, not an absence. So an
// unrecognised form stops the build with a message instead of quietly leaving the
// error outside every property.

// errorPopulation type-checks the package and returns every exported
// package-level variable of error type, with the files it parsed.
func errorPopulation(tb testing.TB) ([]string, []*ast.File, *token.FileSet) {
	tb.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		tb.Fatalf("reading the package directory: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			tb.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		tb.Fatal("no non-test Go files found; a derivation that returns nothing passes every " +
			"check over it")
	}

	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("github.com/conductorone/apphub/compute", fset, files, nil)
	if err != nil {
		tb.Fatalf("type-checking the package: %v", err)
	}
	errIface := types.Universe.Lookup("error").Type()
	var out []string
	for _, name := range pkg.Scope().Names() {
		v, ok := pkg.Scope().Lookup(name).(*types.Var)
		if !ok || !v.Exported() {
			continue
		}
		if types.AssignableTo(v.Type(), errIface) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	if len(out) < 2 {
		tb.Fatalf("the type checker found %d exported error variables, which cannot be right", len(out))
	}
	return out, files, fset
}

// declaredErrors returns the population with each one's declaration form,
//
// Named for errors rather than sentinels because that is what it returns: every
// exported error the package declares, whether or not it is in the taxonomy.
// Calling them all sentinels is the conflation this change exists to undo, and a
// helper that asserts it in its own name would put the mistake back one layer
// down.
// failing rather than skipping anything it cannot classify.
func declaredErrors(tb testing.TB) []errorDecl {
	tb.Helper()
	population, files, fset := errorPopulation(tb)
	wanted := map[string]bool{}
	for _, n := range population {
		wanted[n] = true
	}

	found := map[string]errorDecl{}
	for _, file := range files {
		where := filepath.Base(fset.Position(file.Pos()).Filename)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if !wanted[ident.Name] || i >= len(value.Values) {
						continue
					}
					d, err := classifyError(ident.Name, where, value.Values[i])
					if err != nil {
						tb.Errorf("%v", err)
						continue
					}
					found[ident.Name] = d
				}
			}
		}
	}

	// Fail-closed: every name the type checker reported must have been
	// classified. An absence here is the bug the go/ast version had.
	var out []errorDecl
	for _, name := range population {
		d, ok := found[name]
		if !ok {
			tb.Errorf("the type checker reports %s as an exported error variable and this file "+
				"could not find or classify its declaration, so it would sit outside every "+
				"property asserted over the taxonomy", name)
			continue
		}
		out = append(out, d)
	}
	return out
}

// classifyError decides what a declaration's right-hand side is.
//
// It refuses two things rather than ignoring them: an alias, and any form it does
// not recognise. Both refusals are the point -- the previous version's silence on
// exactly these is what review defeated.
func classifyError(name, file string, value ast.Expr) (errorDecl, error) {
	switch v := value.(type) {
	case *ast.Ident:
		// "var ErrA = ErrB". Two names for one value: errors.Is is true in both
		// directions, so a caller branching on either catches the other and no
		// property over the set can separate them. If the intent is a narrower
		// sentinel, wrap it; if the intent is a rename, rename it.
		return errorDecl{}, fmt.Errorf("%s in %s is declared as an alias of %s. An alias is two "+
			"names for one value, so errors.Is cannot tell them apart in either direction and a "+
			"caller branching on one catches the other. Wrap it with fmt.Errorf(\"%%w: ...\", %s) "+
			"to make it a narrower sentinel, or rename rather than aliasing", name, file, v.Name, v.Name)
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			break
		}
		switch {
		case pkg.Name == "errors" && sel.Sel.Name == "New":
			return errorDecl{name: name, file: file}, nil
		case pkg.Name == "fmt" && sel.Sel.Name == "Errorf":
			return errorDecl{name: name, file: file, wraps: wrappedIdent(v)}, nil
		}
	}
	return errorDecl{}, fmt.Errorf("%s in %s is an error variable declared in a form this "+
		"file does not recognise, so its relationship to the taxonomy cannot be checked. "+
		"Either declare it with errors.New or fmt.Errorf, or teach classifyError the new form -- "+
		"do not leave it unclassified, because an unclassified error silently sits outside every "+
		"property here", name, file)
}

// wrappedIdent returns the name of the first bare identifier passed to a
// fmt.Errorf call, which for a sentinel declaration is the sentinel it
// specialises. Empty when there is none.
func wrappedIdent(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

// TestEveryDeclaredErrorIsClassified is the generative half of the cross-check.
//
// It was TestTheSentinelMapMatchesTheSource, and the name asserted the rule this
// change replaced: the map no longer matches the source on its own, it is one of
// two destinations that between them account for it. A test name is a claim, and
// it is the claim CI prints.
//
// It reads the population out of the package rather than trusting the map, so a
// sentinel added without being *classified* -- into [sentinels] or [nonTaxonomy]
// -- fails here instead of quietly sitting outside every property the map is used
// for. Classified, not "added to the map": the two destinations are the whole
// point, and requiring membership in this one is the rule this test used to
// enforce and no longer does.
func TestEveryDeclaredErrorIsClassified(t *testing.T) {
	t.Parallel()

	declared := declaredErrors(t)
	if len(declared) < 2 {
		t.Fatalf("derived %d exported errors from the package, which cannot be right; a derivation that "+
			"returns nothing passes every check over it", len(declared))
	}
	known := sentinels()
	excused := nonTaxonomy()
	declaredNames := make([]string, 0, len(declared))
	for _, d := range declared {
		declaredNames = append(declaredNames, d.name)
	}

	// Every declared error lands in exactly one of the two maps. "Neither" is
	// the case this test exists for; "both" is the one that would let an error
	// carry the taxonomy's properties while also being excused from them.
	for _, name := range declaredNames {
		_, isSentinel := known[name]
		reason, isExcused := excused[name]
		switch {
		case !isSentinel && !isExcused:
			t.Errorf("the package declares the exported error %s and neither sentinels() nor "+
				"nonTaxonomy() carries it, so every property asserted over the taxonomy silently "+
				"excludes it. Decide which it is: see nonTaxonomy() for the criterion. Adding it to "+
				"sentinels() to make this pass, without deciding, is how that map stops describing "+
				"anything", name)
		case isSentinel && isExcused:
			t.Errorf("%s is in both sentinels() and nonTaxonomy(); it cannot be both part of the "+
				"taxonomy and excused from it. nonTaxonomy() gives the reason %q", name, reason)
		case isExcused && strings.TrimSpace(reason) == "":
			t.Errorf("nonTaxonomy() excuses %s with an empty reason. An exception with no reason is "+
				"an exception nobody can review", name)
		}
	}

	// And neither map outlives what it described.
	for name := range known {
		if !slices.Contains(declaredNames, name) {
			t.Errorf("sentinels() carries %s and the package does not declare it; the map has "+
				"outlived what it described", name)
		}
	}
	for name := range excused {
		if !slices.Contains(declaredNames, name) {
			t.Errorf("nonTaxonomy() excuses %s and the package does not declare it. A stale "+
				"exception is worse than none: it is a standing permission for a name somebody "+
				"may reintroduce meaning something else", name)
		}
	}
}

// hierarchyProblems reports every way the declared hierarchy and the implemented
// one disagree, as sentences.
//
// A pure function over its inputs, deliberately: it is the only way to hand the
// three assertions a synthetic violation. The antisymmetry one cannot be
// provoked by editing compute/errors.go -- see
// TestTheHierarchyAssertionsCatchASyntheticViolation -- so a property that could
// only be driven from the real package would be a property with no failing
// fixture, which on this project means an assertion rather than a gate.
func hierarchyProblems(all map[string]error, intended map[string][]string, decls []errorDecl) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// 1. Intended => actual. Catches a specialisation quietly losing its
	//    wrapping, which stops every caller branching on the parent from handling
	//    it -- and which a derivation from the implementation cannot see, because
	//    it would simply derive the new, wrong implementation.
	for child, parents := range intended {
		childErr, ok := all[child]
		if !ok {
			add("hierarchy() names %s, which is not a sentinel; the map has outlived what it "+
				"described", child)
			continue
		}
		for _, parent := range parents {
			parentErr, ok := all[parent]
			if !ok {
				add("hierarchy() says %s wraps %s, which is not a sentinel", child, parent)
				continue
			}
			if !errors.Is(childErr, parentErr) {
				add("hierarchy() says %s wraps %s and it does not. Every caller branching on %s "+
					"has silently stopped handling %s -- which is what happens when a "+
					"specialisation is re-declared with errors.New instead of wrapping",
					child, parent, parent, child)
			}
		}
	}

	// 2. Actual => intended. Catches a specialisation nobody declared, which
	//    makes two sentinels indistinguishable to a caller.
	for _, d := range decls {
		if d.wraps == "" {
			continue
		}
		if !slices.Contains(intended[d.name], d.wraps) {
			add("%s declares %s as wrapping %s and hierarchy() does not say so. Either the "+
				"specialisation is deliberate and belongs in that map, or it is accidental and "+
				"makes %s indistinguishable from %s to a caller",
				d.file, d.name, d.wraps, d.name, d.wraps)
		}
	}

	// 3. Antisymmetry: a parent never matches its child.
	//
	//    This is a gate, and establishing that took two goes. It looked
	//    unreachable, because the wrapping route is an initialization cycle --
	//    "var a = fmt.Errorf("%w", b)" alongside "var b = fmt.Errorf("%w", a)"
	//    does not compile. But errors.Is has a second route: it consults an
	//    Is(error) bool method, and a method body is not part of the
	//    initialization dependency graph. So a sentinel implemented as a type
	//    with an Is method can match its own specialisation, with no cycle, and
	//    it compiles and runs. USOSS-35 produced the counterexample after I had
	//    concluded the compiler was the gate; it is reproduced in the fixture
	//    below.
	//
	//    Without this, an edit making a general sentinel match a narrower one
	//    would make every use of the general one read as the narrow one, and
	//    assertions 1 and 2 would both still pass.
	for child, parents := range intended {
		for _, parent := range parents {
			if all[child] == nil || all[parent] == nil {
				continue
			}
			if errors.Is(all[parent], all[child]) {
				add("%s matches its own specialisation %s, so every use of the general sentinel "+
					"reads as the narrow one. errors.Is consults an Is(error) bool method as well "+
					"as the wrapping chain, so this is reachable without an initialization cycle",
					parent, child)
			}
		}
	}
	return problems
}

// TestTheSentinelHierarchyMatchesTheImplementation, in both directions, plus
// antisymmetry. See [hierarchyProblems] for what each assertion catches and why
// none of the three subsumes another.
func TestTheSentinelHierarchyMatchesTheImplementation(t *testing.T) {
	t.Parallel()
	for _, problem := range hierarchyProblems(sentinels(), hierarchy(), declaredErrors(t)) {
		t.Error(problem)
	}
}

// claiming is an error whose Is method claims to be something else. It exists for
// the fixture below and models an ordinary thing to reach for -- "this error means
// any of these three" -- rather than a contrivance.
type claiming struct {
	msg    string
	claims error
}

func (c *claiming) Error() string        { return c.msg }
func (c *claiming) Is(target error) bool { return target == c.claims }

// TestTheHierarchyAssertionsCatchASyntheticViolation gives all three assertions a
// failing fixture.
//
// The first two can be provoked by editing compute/errors.go and were verified
// that way. The third cannot: making a real sentinel match its own specialisation
// through the wrapping chain is an initialization cycle. It is reachable through
// the Is-method route, which is why the property takes its inputs as arguments --
// so the violation can be constructed here instead of shipped in the package.
func TestTheHierarchyAssertionsCatchASyntheticViolation(t *testing.T) {
	t.Parallel()

	root := errors.New("synthetic: root")
	child := fmt.Errorf("%w: child", root)

	cases := []struct {
		what     string
		all      map[string]error
		intended map[string][]string
		decls    []errorDecl
		wantPart string
	}{
		{
			what:     "intent without the wrapping",
			all:      map[string]error{"Root": root, "Child": errors.New("synthetic: unwrapped")},
			intended: map[string][]string{"Child": {"Root"}},
			wantPart: "silently stopped handling",
		},
		{
			what:     "a wrapping nobody declared",
			all:      map[string]error{"Root": root, "Child": child},
			intended: map[string][]string{},
			decls:    []errorDecl{{name: "Child", file: "synthetic.go", wraps: "Root"}},
			wantPart: "hierarchy() does not say so",
		},
		{
			what: "a parent that matches its own specialisation",
			// The Is-method route. No initialization cycle: the parent's Is
			// method names the child, and a method body is not part of the
			// initialization dependency graph.
			all: func() map[string]error {
				var parent *claiming
				kid := fmt.Errorf("%w: child", errors.New("synthetic: base"))
				parent = &claiming{msg: "synthetic: parent", claims: kid}
				return map[string]error{"Parent": parent, "Child": kid}
			}(),
			intended: map[string][]string{"Child": {"Parent"}},
			wantPart: "matches its own specialisation",
		},
	}
	for _, c := range cases {
		problems := hierarchyProblems(c.all, c.intended, c.decls)
		found := false
		for _, p := range problems {
			if strings.Contains(p, c.wantPart) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the hierarchy assertions reported %v, none of them containing %q; an "+
				"assertion with no failing fixture is not a gate", c.what, problems, c.wantPart)
		}
	}

	// And the real hierarchy must be clean, or the fixture above is the only
	// thing this test is exercising.
	if problems := hierarchyProblems(sentinels(), hierarchy(), declaredErrors(t)); len(problems) > 0 {
		t.Errorf("the real sentinels report %v; the fixture cases above are meaningless if the "+
			"honest case does not pass", problems)
	}
}

// TestExactlyOneSentinelSaysTryAgain, over the classified taxonomy set.
//
// [compute.ErrTransient] is documented as "the only sentinel here that says 'try
// again'; every other one is terminal for the call that produced it". That is a
// property of the set, so it is asserted over the set rather than over the six
// members somebody remembered -- which is what this test used to do, and which
// would have silently excluded [compute.ErrNotPermitted] the day it was added.
func TestExactlyOneSentinelSaysTryAgain(t *testing.T) {
	t.Parallel()

	all := sentinels()
	roots := 0
	for name, err := range all {
		if !errors.Is(err, compute.ErrTransient) {
			continue
		}
		switch {
		case name == "ErrTransient":
			roots++
		case slices.Contains(hierarchy()[name], "ErrTransient"):
			// A declared specialisation of ErrTransient legitimately says "try
			// again"; it is the same statement, narrower. Permitted because it
			// was declared, not because it was listed here.
		default:
			t.Errorf("%s matches ErrTransient without declaring that it wraps it, so a caller "+
				"retries something that cannot succeed and the one sentinel meaning \"try again\" "+
				"stops meaning anything", name)
		}
	}
	if roots != 1 {
		t.Errorf("%d root sentinels match ErrTransient, want exactly ErrTransient itself", roots)
	}
}

// TestEverySentinelIsDistinguishableFromEveryOther.
//
// Every pair, both directions, over the classified taxonomy set. A caller branches on these
// and nothing else, so two that match each other are two the caller cannot tell
// apart -- and the pairs that matter are not obvious in advance. ErrTransient
// against ErrNotOwned was the one that had a test, because a Kubernetes 409 means
// both; ErrNotPermitted against ErrFailed and ErrInvalidSpec is the pair
// USOSS-40 exists for, and it would not have occurred to anybody to write that
// test before the sentinel existed. Asserting the property over all pairs is what
// makes the next one free.
func TestEverySentinelIsDistinguishableFromEveryOther(t *testing.T) {
	t.Parallel()

	all := sentinels()
	intended := hierarchy()
	names := slices.Sorted(maps.Keys(all))
	if len(names) < 2 {
		t.Fatal("fewer than two sentinels; there are no pairs to check")
	}
	pairs := 0
	for _, a := range names {
		// Permitted by declared *intent*, not by what the implementation happens
		// to do -- otherwise an accidental wrapping would license itself.
		permitted := intended[a]
		for _, b := range names {
			if a == b {
				continue
			}
			pairs++
			if errors.Is(all[a], all[b]) && !slices.Contains(permitted, b) {
				t.Errorf("errors.Is(%s, %s) is true and %s does not declare that it wraps %s, so a "+
					"caller branching on %s cannot tell it from %s", a, b, a, b, b, a)
			}
		}
	}
	if want := len(names) * (len(names) - 1); pairs != want {
		t.Errorf("checked %d ordered pairs, want %d; the loop is not covering the set", pairs, want)
	}
}

// TestAWrappedSentinelMatchesItselfAndNothingElse, over the classified taxonomy set.
//
// The pairwise test above compares the sentinel *values*, which is the structural
// property. This is the one a caller actually experiences: nobody ever holds a
// bare sentinel. A provider returns fmt.Errorf("%w: op: %w", sentinel, cause), and
// what has to be true of that is that it matches the sentinel it wrapped and no
// other -- so a caller branching on ErrFailed does not catch a denial, and a
// caller branching on ErrNotPermitted does catch one however deeply the provider
// nested its cause.
//
// The shape is USOSS-35's, from hitting SA1032 on a bare-sentinel comparison and
// concluding the wrapped form was not merely a way around the linter but the more
// realistic assertion. Generalised here from their one sentinel to the whole
// classified taxonomy set, so the next sentinel inherits it.
func TestAWrappedSentinelMatchesItselfAndNothingElse(t *testing.T) {
	t.Parallel()

	all := sentinels()
	intended := hierarchy()
	names := slices.Sorted(maps.Keys(all))
	if len(names) < 2 {
		t.Fatal("fewer than two sentinels; there is nothing to distinguish")
	}
	for _, name := range names {
		permitted := intended[name]
		// Two layers, because a provider often wraps a substrate error inside its
		// own message and a single layer would not exercise the chain.
		cause := errors.New("the substrate said no")
		wrapped := fmt.Errorf("%w: compute/example: doing the thing: %w", all[name], cause)

		if !errors.Is(wrapped, all[name]) {
			t.Errorf("a provider-shaped error wrapping %s does not match %s, so a caller cannot "+
				"branch on the sentinel the provider chose", name, name)
		}
		if !errors.Is(wrapped, cause) {
			t.Errorf("wrapping %s lost the underlying cause, which is what a log needs", name)
		}
		for _, other := range names {
			if other == name {
				continue
			}
			if errors.Is(wrapped, all[other]) && !slices.Contains(permitted, other) {
				t.Errorf("a provider-shaped error wrapping %s also matches %s, which %s does not "+
					"declare that it wraps; a caller branching on %s catches something that is "+
					"not one", name, other, name, other)
			}
		}
	}
}

// TestADenialIsNotAResourceFailureOrACallerError is the pair USOSS-40 exists for,
// named on its own because the reason is behavioural rather than structural.
//
// The properties above already prove they do not match. This one records *why it
// matters*, which a generic property cannot: the three sentinels send a reader to
// three different people. ErrInvalidSpec sends them to the request, ErrFailed to
// the resource, and ErrNotPermitted to whoever administers the platform's own
// permissions. Collapsing any two means somebody debugs the wrong thing.
//
// Asserted against a wrapped error rather than the bare sentinel, for the reason
// on TestAWrappedSentinelMatchesItselfAndNothingElse: it is what a caller holds,
// and it expresses both directions without the argument order that is normally a
// mistake.
func TestADenialIsNotAResourceFailureOrACallerError(t *testing.T) {
	t.Parallel()

	denial := fmt.Errorf("%w: compute/example: s3:HeadBucket was denied: %w",
		compute.ErrNotPermitted, errors.New("AccessDenied"))

	for _, other := range []struct {
		name string
		err  error
		who  string
	}{
		{"ErrFailed", compute.ErrFailed, "the resource, which never reached a phase"},
		{"ErrInvalidSpec", compute.ErrInvalidSpec, "the caller's request, which is not wrong"},
		{"ErrTransient", compute.ErrTransient, "a retry, which cannot succeed unchanged"},
	} {
		if errors.Is(denial, other.err) {
			t.Errorf("a denial as a provider would return it also matches %s, so a caller "+
				"branching on that is sent to %s", other.name, other.who)
		}
		// And the reverse: an error of the other kind must not read as a denial,
		// or an operator is paged for an application's problem.
		wrongWay := fmt.Errorf("%w: compute/example: something else", other.err)
		if errors.Is(wrongWay, compute.ErrNotPermitted) {
			t.Errorf("an error wrapping %s matches ErrNotPermitted, so %s would be reported as a "+
				"permission problem", other.name, other.name)
		}
	}
	if !errors.Is(denial, compute.ErrNotPermitted) {
		t.Error("the denial does not match ErrNotPermitted, so this test is asserting nothing")
	}
}
