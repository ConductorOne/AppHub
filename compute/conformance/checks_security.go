// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// securityChecks are the properties that matter because this repository is going
// public: secret material stays out of every channel that is not a secret store,
// a redeploy does not lock the platform out of its own database, and the two
// fail-closed behaviour changes USOSS-2 accepted stay closed.
func securityChecks(_ *Env) []Check {
	return []Check{
		{
			Name:      "security/secret-bindings-travel-by-reference",
			Invariant: "a workload's secrets move by reference and the compute layer never reads a value",
			Fn:        checkSecretsByReference,
		},
		{
			Name:      "security/secret-material-does-not-appear-in-errors",
			Invariant: "secret material appears in no error message and no Status field",
			Fn:        checkSecretsNotInErrors,
		},
		{
			Name:      "security/secret-metadata-read-returns-no-material",
			Port:      "secret",
			Invariant: "SecretStore.Describe reports where a secret is and never what it is",
			Fn:        checkDescribeReturnsNoMaterial,
		},
		{
			Name:      "security/secret-material-does-not-appear-in-rendered-artefacts",
			Invariant: "secret material appears in nothing the provider renders",
			Fn:        checkSecretsNotInRendered,
		},
		{
			Name:      "security/every-planted-resource-has-a-rendered-artefact",
			Invariant: "every resource this suite creates through a material-carrying port corresponds to an artefact the provider renders, or the provider says why not",
			Fn:        checkEveryPlantedResourceIsRendered,
		},
		{
			Name:      "security/relational-admin-password-is-not-rotated",
			Port:      "relational-database",
			Class:     Async,
			Invariant: "a re-Ensure does not rotate the admin password",
			Fn:        checkAdminPasswordNotRotated,
		},
		{
			Name:      "security/bucket-public-access-is-off-by-default",
			Port:      "bucket",
			Class:     Sync,
			Invariant: "a bucket created with PublicAccess false refuses an anonymous read",
			Fn:        checkBucketNotPublic,
		},
		{
			Name:      "security/tls-listener-requires-a-resolvable-certificate",
			Port:      "function-endpoint",
			Class:     Async,
			Invariant: "a listener that asks for TLS with no resolvable certificate is ErrInvalidSpec",
			Fn:        checkTLSRequiresCertificate,
		},
		{
			Name:      "security/missing-ingress-proxy-is-an-error-not-an-open-port",
			Port:      "container-service",
			Class:     Async,
			Invariant: "a provider with no ingress proxy rejects a platform-ingress rule rather than widening it to the internet",
			Fn:        checkIngressProxyFailsClosed,
		},
		{
			Name:      "security/route-without-tls-is-refused",
			Port:      "container-service",
			Class:     Async,
			Invariant: "a route with no certificate and no AllowPlaintext is refused rather than served over HTTP",
			Fn:        checkRouteFailsClosedWithoutTLS,
		},
		{
			Name:      "security/secret-version-pin-is-honoured-or-refused",
			Port:      "secret",
			Class:     Sync,
			Invariant: "a version-pinned secret binding is honoured or typed-refused, never silently unpinned",
			Fn:        checkSecretVersionPinning,
		},
		{
			Name:      "security/secrets-do-not-cross-placements",
			Port:      "container-service",
			Class:     Async,
			Invariant: "a secret binding across placements is refused rather than satisfied by copying material",
			Fn:        checkSecretsDoNotCrossPlacements,
		},
		{
			Name:      "security/exec-does-not-widen-the-workload-identity",
			Port:      "container-service",
			Class:     Async,
			Invariant: "making a workload reachable for interactive sessions grants its own identity nothing",
			Fn:        checkExecDoesNotWidenIdentity,
		},
	}
}

// checkSecretsByReference pins the shape of the binding as well as the
// behaviour. A [compute.SecretBinding] that could carry a value would put every
// application secret through apphub's own memory and into whatever the provider
// renders, which is the property the ECS ValueFrom mechanism and a Kubernetes
// secretKeyRef both exist to avoid.
func checkSecretsByReference(tb TB, e *Env) {
	const inv = "a workload's secrets move by reference and the compute layer never reads a value"
	rt := reflect.TypeOf(compute.SecretBinding{})
	secretValue := reflect.TypeOf(compute.SecretValue{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		if f.Type == secretValue {
			fail(tb, "secret", inv, "compute.SecretBinding.%s is a SecretValue; a binding must "+
				"name a secret, not carry one", f.Name)
		}
		if f.Type.Kind() == reflect.String && strings.Contains(strings.ToLower(f.Name), "value") {
			fail(tb, "secret", inv, "compute.SecretBinding.%s is a string named for a value; a "+
				"binding must name a secret, not carry one", f.Name)
		}
	}

	if !e.Provider.Capabilities().Has(compute.CapContainerService) ||
		!e.Provider.Capabilities().Has(compute.CapSecretStore) {
		skip(tb, e, inv, "both "+string(compute.CapContainerService)+" and "+
			string(compute.CapSecretStore)+", without which no workload can be given a bound secret")
		return
	}
	rtPort, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)
	bindings := e.SecretBindings(tb, e.Provider)
	if len(bindings) == 0 {
		skip(tb, e, inv, "a secret fixture")
		return
	}
	if _, err := rtPort.EnsureService(e.ctx,
		e.ServiceSpec(e.Name("secret-binding"), Base, identity, bindings)); err != nil {
		fail(tb, "container-service", inv, "a service with a secret bound by reference was refused: "+
			"%v; the binding is the only supported way to get a secret into a workload", redact(err))
		return
	}
	// The Status.Message scan had no non-emptiness guard at all: a provider whose
	// Message is always empty passed it trivially. Folded in as the construction
	// rather than a length check, because "the field is non-empty" and "the field
	// carries what the provider puts there" are different claims and only the
	// second makes the scan evidence.
	e.scanChannels(tb, "container-service", inv, []string{secretSentinel},
		map[Channel]func() string{
			ChannelStatusMessage: func() string {
				probe, err := rtPort.EnsureService(e.ctx,
					e.ServiceSpec(e.Name("message-probe"), Base, identity, bindings))
				if err != nil || probe == nil {
					return ""
				}
				return probe.Message
			},
		})

	// A binding whose reference this provider did not issue must be refused
	// rather than half-honoured: a runtime can only resolve a reference to a
	// store it natively understands.
	foreign := []compute.SecretBinding{{
		EnvName: "CONFORMANCE_FOREIGN",
		Secret:  compute.Ref{Provider: foreignProvider, Kind: compute.KindSecret, ID: "elsewhere"},
	}}
	_, err = rtPort.EnsureService(e.ctx, e.ServiceSpec(e.Name("foreign-secret"), Base, identity, foreign))
	if err == nil {
		fail(tb, "container-service", inv, "a service bound to a secret held by another provider "+
			"was accepted; the runtime cannot resolve it, so the workload would start without the "+
			"value or not at all")
	} else if !errors.Is(err, compute.ErrForeignRef) {
		fail(tb, "container-service", inv, "a foreign secret binding was refused with %v, which "+
			"does not match compute.ErrForeignRef; that sentinel is the backstop for a mistaken "+
			"conversion in the deploy layer's adapter", redact(err))
	}
}

// checkDescribeReturnsNoMaterial is the check that justifies Describe existing.
//
// A metadata read is permitted on a secret store only because it returns a
// locator and a location rather than a value. That is a claim about every
// provider, and a claim nothing checks is a claim enforced by whoever reads the
// comment — so this drives a real secret through Describe and searches
// everything it returns, structurally and by content.
//
// The structural half matters as much as the content half: a field of type
// [compute.SecretValue] on [compute.SecretInfo] would make the operation a
// read-back whatever any individual provider chose to put in it.
func checkDescribeReturnsNoMaterial(tb TB, e *Env) {
	const inv = "SecretStore.Describe reports where a secret is and never what it is"

	// Structural, and it holds whether or not this provider has a secret store:
	// the type is the interface's, not the provider's.
	rt := reflect.TypeOf(compute.SecretInfo{})
	secretValue := reflect.TypeOf(compute.SecretValue{})
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type == secretValue {
			fail(tb, "secret", inv, "compute.SecretInfo.%s is a SecretValue; a metadata read "+
				"that can carry material is a read-back with a different name", rt.Field(i).Name)
		}
	}

	if !e.Provider.Capabilities().Has(compute.CapSecretStore) {
		skip(tb, e, inv, string(compute.CapSecretStore))
		return
	}
	store, err := e.Provider.Secrets()
	if err != nil {
		fatal(tb, "secret", inv, "Secrets() refused: %v", err)
	}
	stored, err := store.Put(e.ctx, compute.SecretSpec{
		Name:  e.Name("describe-no-material"),
		Scope: "conformance",
		Value: compute.NewSecretValue(secretSentinel),
	})
	if err != nil {
		fatal(tb, "secret", inv, "Put: %v", redact(err))
	}
	ref := stored.Ref
	info, err := store.Describe(e.ctx, ref)
	if err != nil {
		fatal(tb, "secret", inv, "Describe of a secret just stored: %v", redact(err))
	}
	if info == nil {
		fail(tb, "secret", inv, "Describe returned no information and no error")
		return
	}
	// Every field, rendered, so a provider that puts the value in one this
	// check does not name is caught by construction rather than by enumeration.
	rendered := fmt.Sprintf("%+v", *info)
	if strings.Contains(rendered, secretSentinel) {
		fail(tb, "secret", inv, "Describe returned the secret's material through a field of "+
			"compute.SecretInfo; the operation exists on the understanding that it cannot")
	}
	if info.Ref != ref {
		fail(tb, "secret", inv, "Describe reported reference %s for %s", info.Ref, ref)
	}

	// The placement answer has to be one of the two the interface defines, and
	// has to be consistent with the placement field. A store that reported a
	// placement it does not have is not a hypothetical: the AWS store resolved
	// its DEFAULT placement and returned that, so a secret stored elsewhere was
	// described as living somewhere it did not, and a caller comparing the two
	// would refuse a valid deployment.
	switch info.PlacementScope {
	case compute.SecretPlacementScoped:
		if info.Placement.Name == "" {
			fail(tb, "secret", inv, "Describe reported placement scope %q and no placement; a "+
				"caller cannot compare a binding against nothing", info.PlacementScope)
		}
	case compute.SecretPlacementGlobal:
		if info.Placement.Name != "" {
			fail(tb, "secret", inv, "Describe reported placement scope %q and placement %q; if "+
				"placement does not constrain binding then naming one is an answer to a "+
				"question this store cannot be asked", info.PlacementScope, info.Placement.Name)
		}
	default:
		fail(tb, "secret", inv, "Describe reported placement scope %q, which is not one this "+
			"interface defines; a caller cannot tell whether the binding is placed correctly",
			info.PlacementScope)
	}

	// And for a scoped store, what Describe says has to be what Put was told.
	// Driven over every placement the provider offers, because a store that
	// always answered its default would pass a single-placement check.
	if info.PlacementScope == compute.SecretPlacementScoped {
		// Every placement the provider was configured with, not just the
		// default: a store that always answered its default would pass a
		// single-placement check, which is exactly how the defect that
		// motivated this got through.
		for _, placement := range []string{e.Options.Placement, e.Options.SecondPlacement} {
			if placement == "" {
				continue
			}
			placed, err := store.Put(e.ctx, compute.SecretSpec{
				Name:      e.Name("describe-placement"),
				Scope:     "conformance",
				Placement: compute.Placement{Name: placement},
				Value:     compute.NewSecretValue(secretSentinel),
			})
			if err != nil {
				fail(tb, "secret", inv, "Put into configured placement %q was refused: %v",
					placement, redact(err))
				continue
			}
			got, err := store.Describe(e.ctx, placed.Ref)
			if err != nil {
				fail(tb, "secret", inv, "Describe of a secret in placement %q: %v",
					placement, redact(err))
				continue
			}
			if got.Placement.Name != placement {
				fail(tb, "secret", inv, "Put accepted placement %q and Describe reported %q; a "+
					"caller comparing a binding's placement against a workload's would refuse "+
					"a valid deployment", placement, got.Placement.Name)
			}
		}
	}

	// And the other half of what it is for: a reference to a secret that is
	// gone reports ErrNotFound rather than describing something.
	if err := store.Delete(e.ctx, ref); err != nil {
		fatal(tb, "secret", inv, "Delete: %v", redact(err))
	}
	if _, err := store.Describe(e.ctx, ref); !errors.Is(err, compute.ErrNotFound) {
		fail(tb, "secret", inv, "Describe of a deleted secret answered %v, want ErrNotFound; a "+
			"caller cannot preflight a binding against a store that says a missing secret is "+
			"fine", redact(err))
	}
}

// checkSecretsNotInErrors drives calls that are holding real secret material
// into failure and searches what comes back.
//
// # The guard, and why counting failures was not one
//
// A clean scan of an error is evidence only if the error said something. The
// guard this replaces counted calls that FAILED -- `checked == 0` was the only
// way out -- which establishes that a call was attempted and refused, not that
// its refusal was composed from the spec it refused. A provider whose every
// refusal is a bare sentinel satisfied it with five failures and nothing read,
// and the suite reported "secret material appears in no error message" as
// verified on the strength of five strings that could not have contained
// anything. The guard proved an attempt where an observation was needed
// (USOSS-66).
//
// So every call below plants a marker of the suite's own choosing in a field of
// the spec that is NOT secret -- the resource's own name, or its scope where the
// name is the field being made invalid, both of which [Env.Name] already makes
// unique per run -- and an error counts as observed only when it carries that
// marker back. An error that names what it refused is an error
// composed from the spec it was handed, and composing from the spec is how the
// value travelling alongside would get out. An error that names nothing is not
// clean, it is unread, and it is reported that way instead of counted.
//
// The material scan still runs over every failed call, observed or not: a
// sentinel found in a terse error is a leak whatever else is true of it. Only
// the verdict turns on observation, because only the verdict makes a claim about
// the provider.
//
// # Why the marker is planted rather than asked for
//
// [Env.scanChannels] is the general form of this construction, and USOSS-61
// built it. It is not what this check uses, for one reason: the marker has to
// arrive in the error the check actually reads. [Options.EmitInto]'s
// [ChannelCallError] is wired in both reference providers to the
// foreign-[compute.Ref] refusal, and no call below goes through it -- so establishing that channel
// would establish an error this check never scans, while the errors it does scan
// stayed unestablished. That is the "scanned three, established one" defect
// [Env.scanChannels] exists to close, and it was live here: the version this
// replaces established the foreign-ref error and then scanned that same error
// for material it had never been handed, next to five errors that had.
//
// Planting into the spec needs no hostile mode and settles each error
// individually, which is what the shape of this check requires.
func checkSecretsNotInErrors(tb TB, e *Env) {
	const inv = "secret material appears in no error message and no Status field"
	caps := e.Provider.Capabilities()

	// errorPath is one call handed real secret material and made to fail. marker
	// is what the suite planted in field, which is never the field holding the
	// material.
	type errorPath struct {
		what   string
		field  string
		marker string
		err    error
	}
	var paths []errorPath

	// Every one of these is a call that is handed real material and then made to
	// fail, because an error path is where a provider is most likely to
	// interpolate the spec it could not satisfy.
	if caps.Has(compute.CapSecretStore) {
		store, err := e.Provider.Secrets()
		if err != nil {
			fatal(tb, "secret", inv, "Secrets() refused: %v", err)
		}
		// The name is the field being made invalid here, so it cannot also carry
		// the marker; the scope does.
		scope := e.Name("errpath-scope")
		_, err = store.Put(e.ctx, compute.SecretSpec{
			Name:  "", // invalid on purpose
			Scope: scope,
			Value: compute.NewSecretValue(secretSentinel),
		})
		paths = append(paths, errorPath{"SecretStore.Put with an invalid name", "the scope", scope, err})

		name := e.Name("errpath-name")
		_, err = store.Put(e.ctx, compute.SecretSpec{
			Name:  name,
			Scope: "", // invalid on purpose
			Value: compute.NewSecretValue(secretSentinel),
		})
		paths = append(paths, errorPath{"SecretStore.Put with no scope", "the name", name, err})
	}
	if caps.Has(compute.CapRelationalDatabase) {
		rp, err := e.Provider.Relational()
		if err != nil {
			fatal(tb, "relational-database", inv, "Relational() refused: %v", err)
		}
		engineName := e.Name("errpath-engine")
		spec := e.RelationalSpec(engineName, Base, e.AdminPassword())
		spec.EngineVersion = "conformance-no-such-version"
		_, err = rp.EnsureRelational(e.ctx, spec)
		paths = append(paths, errorPath{
			"EnsureRelational with an unsupported engine version", "the name", engineName, err})

		capacityName := e.Name("errpath-capacity")
		spec = e.RelationalSpec(capacityName, Base, e.AdminPassword())
		spec.Capacity = compute.CapacityRange{MinUnits: 8, MaxUnits: 1}
		_, err = rp.EnsureRelational(e.ctx, spec)
		paths = append(paths, errorPath{
			"EnsureRelational with an impossible capacity range", "the name", capacityName, err})
	}
	if caps.Has(compute.CapContainerService) && caps.Has(compute.CapSecretStore) {
		rt, err := e.Provider.Containers()
		if err != nil {
			fatal(tb, "container-service", inv, "Containers() refused: %v", err)
		}
		bindings := e.SecretBindings(tb, e.Provider)
		serviceName := e.Name("errpath-service")
		spec := e.ServiceSpec(serviceName, Base, e.ContainerIdentity(tb, e.Provider), bindings)
		spec.Resources = compute.Resources{} // invalid on purpose
		_, err = rt.EnsureService(e.ctx, spec)
		paths = append(paths, errorPath{
			"EnsureService with an invalid resource request", "the name", serviceName, err})
	}

	if len(paths) == 0 {
		skip(tb, e, inv, "any port that takes secret material")
		return
	}

	failed, observed := 0, 0
	for _, p := range paths {
		if p.err == nil {
			// A provider is entitled to accept a spec this suite expected it to
			// reject; it just means this particular error path was not exercised.
			e.note("the %s call succeeded, so that error path was not searched for secret material", p.what)
			continue
		}
		failed++
		text := p.err.Error()
		// Searched whether or not the marker arrived: material in a terse error
		// is still material in an error. Only the verdict below turns on
		// observation.
		if strings.Contains(text, secretSentinel) {
			// Deliberately does not print the error.
			fail(tb, "secret", inv, "the error from %s contains the secret material; an error is "+
				"logged, returned to an API caller, and often persisted", p.what)
			continue
		}
		if !strings.Contains(text, p.marker) {
			e.note("the %s call failed with an error that does not name %s it was handed, so a "+
				"clean scan of that error is not evidence: an error the provider composed from "+
				"none of the spec could not have carried the value that came with it", p.what, p.field)
			continue
		}
		observed++
	}

	if tb.Failed() {
		// The loop above already found material in an error and reported it. A
		// skip below this point exists only to say "not verified" when nothing
		// was found, and recorder.Skipf sets skipped unconditionally -- so
		// running it after a real failure would erase that failure from the
		// report rather than add to it.
		return
	}
	if failed == 0 {
		// Nothing was refused, so there is no error to have observed. This is the
		// case the old guard's `checked == 0` covered, and it is still a skip.
		skipBecause(tb, e, inv, fmt.Sprintf("this provider accepted all %d spec(s) this suite "+
			"expected it to refuse, so no call failed while holding secret material and there was "+
			"no error to search", len(paths)))
		return
	}
	if observed == 0 {
		skipBecause(tb, e, inv, fmt.Sprintf("none of the %d call(s) this suite drove into failure "+
			"came back with an error naming any part of the spec it refused. Every scan above was "+
			"of a string composed from nothing the caller supplied, and such a string is clean "+
			"whatever the provider does with the material it was holding -- the same clean a "+
			"correct provider produces", failed))
		return
	}
}

func checkSecretsNotInRendered(tb TB, e *Env) {
	const inv = "secret material appears in nothing the provider renders"
	if e.Options.Rendered == nil {
		skip(tb, e, inv, "Options.Rendered, which has to dump the artefacts the provider wrote "+
			"into its substrate — a task definition, a pod spec, a build log")
		return
	}

	plantable, err := materialPorts(e)
	if err != nil {
		// A suite bug, and it has to be loud. The derivation deciding what can
		// be handed material is the whole of this check's non-emptiness
		// argument; if it cannot answer, the check has nothing to stand on.
		fatal(tb, "secret", inv, "%v", err)
	}
	if len(plantable) == 0 {
		// The legitimate case, and it stays legitimate — but it is named, and it
		// is not a pass. A provider that holds no material cannot leak any;
		// what it cannot do is stand as evidence that this invariant holds.
		skipBecause(tb, e, inv, fmt.Sprintf("provider %q has no port that can be handed secret "+
			"material: of the ports it advertises, none takes a compute.SecretValue in a spec "+
			"this suite applies, and a binding needs %s to have something to point at. Nothing "+
			"was planted, so the scan would only have shown that a sentinel nobody stored was "+
			"absent — which is what it used to report as a pass",
			e.Provider.Name(), compute.CapSecretStore))
		return
	}

	// Captured before planting so that "the provider rendered nothing new" is
	// distinguishable from "the provider renders nothing at all". The scan is
	// only evidence about the planted material if the planting reached the
	// artefacts being scanned.
	before := map[string]bool{}
	for _, a := range e.rendered(tb) {
		before[a] = true
	}

	planted := 0
	for _, pt := range plantable {
		o, err := pt.ops(tb, e, e.Provider)
		if err != nil {
			fatal(tb, pt.Name, inv, "the provider advertises %q but the port could not be "+
				"acquired: %v", pt.Capability, err)
		}
		if _, _, err := o.Ensure(e.Name("rendered-"+pt.Name), Base); err != nil {
			fail(tb, pt.Name, inv, "the material-carrying spec this check plants was refused, so "+
				"nothing it renders was searched: %v", redact(err))
			continue
		}
		planted++
	}
	if planted == 0 {
		fail(tb, "secret", inv, "every one of the %d material-carrying port(s) refused the spec "+
			"that plants the sentinel, so nothing was searched", len(plantable))
		return
	}

	rendered := e.rendered(tb)
	if len(rendered) == 0 {
		fail(tb, "secret", inv, "material was planted through %d port(s) and Options.Rendered "+
			"returned no artefacts, so there was nothing to search; passing here would report "+
			"only that the check looked at nothing", planted)
		return
	}
	fresh := 0
	for _, a := range rendered {
		if !before[a] {
			fresh++
		}
	}
	if fresh == 0 {
		fail(tb, "secret", inv, "material was planted through %d port(s) and Options.Rendered "+
			"returned the same %d artefact(s) as before, so nothing it renders reflects what was "+
			"planted; the scan below would pass whatever the provider did with the material",
			planted, len(rendered))
		return
	}

	for i, artefact := range rendered {
		if strings.Contains(artefact, secretSentinel) {
			// The artefact is not printed: it contains the material.
			fail(tb, "secret", inv, "rendered artefact %d contains secret material; a secret must "+
				"reach a workload as a reference the runtime resolves at launch, not as a value "+
				"written into something an operator, a support engineer, or an audit log can read", i)
			return
		}
	}
}

// checkEveryPlantedResourceIsRendered is the harness-side remedy USOSS-48
// found necessary: checkSecretsNotInRendered's emptiness gate is the wrong
// instrument for a PARTIAL leak. A provider that lets one Describe or List
// call swallow an error can drop exactly the artefact that would have failed
// the scan while everything else renders -- Options.Rendered stays non-empty,
// the planted material still shows up as "fresh" through the ports that did
// not drop anything, and the aggregate scan finds no sentinel because it is
// searching a set the leaking artefact was never a member of.
// checkSecretsNotInRendered cannot see that: it only knows the aggregate
// grew, not which member of it corresponds to which Ref.
//
// So this check asks a narrower question the suite can answer completely: for
// each Ref it just created through a material-carrying port, does the
// provider say there is a rendered artefact for it? Only the provider can
// answer that -- the suite holds the Ref, the provider holds the enumeration
// -- which is why it needs Options.RenderedRef rather than a second pass over
// the aggregate list.
func checkEveryPlantedResourceIsRendered(tb TB, e *Env) {
	const inv = "every resource this suite creates through a material-carrying port corresponds " +
		"to an artefact the provider renders, or the provider says why not"
	if e.Options.RenderedRef == nil {
		skip(tb, e, inv, "Options.RenderedRef, which looks up the rendered artefact for one "+
			"resource by reference -- without it a resource silently dropped from "+
			"Options.Rendered is indistinguishable from one that was never asked about")
		return
	}

	plantable, err := materialPorts(e)
	if err != nil {
		// A suite bug, and it has to be loud: the derivation deciding what can
		// be handed material is the whole of this check's non-emptiness
		// argument.
		fatal(tb, "secret", inv, "%v", err)
	}
	if len(plantable) == 0 {
		// The legitimate case, unchanged by this check: a provider that holds
		// no material has nothing this check needs to see rendered, and
		// asking it to would be inventing coverage rather than reporting it.
		skipBecause(tb, e, inv, fmt.Sprintf("provider %q has no port that can be handed secret "+
			"material, so there is no Ref for this check to demand correspondence for",
			e.Provider.Name()))
		return
	}

	checked := 0
	for _, pt := range plantable {
		o, err := pt.ops(tb, e, e.Provider)
		if err != nil {
			fatal(tb, pt.Name, inv, "the provider advertises %q but the port could not be "+
				"acquired: %v", pt.Capability, err)
		}
		ref, _, err := o.Ensure(e.Name("correspondence-"+pt.Name), Base)
		if err != nil {
			fail(tb, pt.Name, inv, "the material-carrying spec this check plants was refused, so "+
				"there is no Ref to check correspondence for: %v", redact(err))
			continue
		}
		artefact, found, err := e.Options.RenderedRef(e.ctx, e.Provider, ref)
		if err != nil {
			fatal(tb, pt.Name, inv, "Options.RenderedRef failed for %s: %v", ref, err)
		}
		if !found {
			fail(tb, pt.Name, inv, "%s was just created through Ensure and the provider reports "+
				"no rendered artefact for it -- a resource this suite created is not visible in "+
				"what the provider renders. This is exactly the shape a partially-emptied "+
				"artefact set has: Options.Rendered can stay non-empty, and grow, while this one "+
				"Ref is silently missing from it", ref)
			continue
		}
		if artefact == "" {
			fail(tb, pt.Name, inv, "%s was reported found with an empty artefact; an empty "+
				"string is not a legitimate way to report \"nothing here\" -- return found=false "+
				"instead", ref)
			continue
		}
		checked++
	}
	if checked == 0 {
		fail(tb, "secret", inv, "every one of the %d material-carrying port(s) refused the spec "+
			"this check plants, so no correspondence was verified", len(plantable))
	}
}

func checkAdminPasswordNotRotated(tb TB, e *Env) {
	const inv = "a re-Ensure does not rotate the admin password"
	if !e.Provider.Capabilities().Has(compute.CapRelationalDatabase) {
		skip(tb, e, inv, "the "+string(compute.CapRelationalDatabase)+" capability")
		return
	}
	if e.Options.RelationalLogin == nil {
		skip(tb, e, inv, "Options.RelationalLogin, which has to authenticate against the endpoint "+
			"— the only way to tell whether the caller's stored password still works")
		return
	}
	rp, err := e.Provider.Relational()
	if err != nil {
		fatal(tb, "relational-database", inv, "Relational() refused: %v", err)
	}
	original := e.AdminPassword()
	rotated := compute.NewSecretValue(secretSentinel + "-rotated")
	name := e.Name("password")

	st, err := rp.EnsureRelational(e.ctx, e.RelationalSpec(name, Base, original))
	if err != nil {
		fatal(tb, "relational-database", inv, "the first EnsureRelational failed: %v", redact(err))
	}
	ref := st.Ref
	if _, err := rp.EnsureRelational(e.ctx, e.RelationalSpec(name, Base, rotated)); err != nil {
		fatal(tb, "relational-database", inv, "re-Ensuring with a different password failed with "+
			"%v; the call must succeed and leave the existing password alone", redact(err))
	}

	if err := e.Options.RelationalLogin(e.ctx, e.Provider, ref, "conformance_admin", original); err != nil {
		fail(tb, "relational-database", inv, "the original admin password no longer authenticates "+
			"after a re-Ensure passed a different one; the caller's stored copy has silently become "+
			"wrong, and the next deploy's role provisioning fails with an authentication error far "+
			"from the change that caused it")
	}
	if err := e.Options.RelationalLogin(e.ctx, e.Provider, ref, "conformance_admin", rotated); err == nil {
		fail(tb, "relational-database", inv, "the password passed to the second Ensure now "+
			"authenticates, which means the provider rotated it")
	}
}

func checkBucketNotPublic(tb TB, e *Env) {
	const inv = "a bucket created with PublicAccess false refuses an anonymous read"
	if !e.Provider.Capabilities().Has(compute.CapObjectStore) {
		skip(tb, e, inv, "the "+string(compute.CapObjectStore)+" capability")
		return
	}
	if e.Options.AnonymousRead == nil {
		skip(tb, e, inv, "Options.AnonymousRead, which has to attempt an unauthenticated read")
		return
	}
	store, err := e.Provider.ObjectStores()
	if err != nil {
		fatal(tb, "bucket", inv, "ObjectStores() refused: %v", err)
	}
	// PublicAccess is left at its zero value on purpose: the invariant is about
	// the default, and a provider that only blocks access when asked is not
	// secure by default.
	b, err := store.EnsureBucket(e.ctx, compute.BucketSpec{
		Name:   e.Name("private"),
		Labels: map[string]string{"owner": "conformance"},
	})
	if err != nil {
		fatal(tb, "bucket", inv, "EnsureBucket failed: %v", err)
	}
	if err := e.Options.AnonymousRead(e.ctx, e.Provider, b.Ref); err == nil {
		fail(tb, "bucket", inv, "an anonymous read of a bucket created with PublicAccess false "+
			"succeeded; a provider must apply whatever blocks its substrate offers to make false "+
			"actually mean it, and merely omitting a public policy is not equivalent")
	}
}

func checkTLSRequiresCertificate(tb TB, e *Env) {
	const inv = "a listener that asks for TLS with no resolvable certificate is ErrInvalidSpec"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapFunctionEndpoint) {
		skip(tb, e, inv, "the "+string(compute.CapFunctionEndpoint)+" capability")
		return
	}
	rt, err := e.Provider.Functions()
	if err != nil {
		fatal(tb, "function-endpoint", inv, "Functions() refused: %v", err)
	}
	target := e.EndpointTarget(tb, e.Provider)

	// The literal form of the source system's defect — an HTTPS listener with no
	// TLSConfig at all — is representable since ListenerSpec gained a protocol,
	// so it is the first case here rather than a note explaining why it could not
	// be checked.
	cases := []struct {
		what     string
		protocol compute.ListenerProtocol
		tls      *compute.TLSConfig
	}{
		{"no certificate at all", compute.ListenerHTTPS, nil},
		{"an empty certificate reference", compute.ListenerHTTPS, &compute.TLSConfig{}},
		{"a certificate reference the provider cannot resolve", compute.ListenerHTTPS,
			&compute.TLSConfig{CertificateRef: "conformance-no-such-certificate"}},
		{"a certificate on a plaintext listener", compute.ListenerHTTP,
			&compute.TLSConfig{CertificateRef: "conformance-certificate"}},
	}
	for _, c := range cases {
		_, err := rt.EnsureEndpoint(e.ctx, compute.EndpointSpec{
			Name:      e.Name("tls"),
			Target:    target,
			Listeners: []compute.ListenerSpec{{Port: 8443, Protocol: c.protocol, TLS: c.tls}},
			Placement: compute.Placement{Name: e.Options.Placement},
			Ingress:   []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8443}},
		})
		if err == nil {
			fail(tb, "function-endpoint", inv, "a TLS listener with %s was accepted; the source "+
				"system creates HTTPS listeners with no certificate at all, and encoding the "+
				"requirement here is what turns that into a deploy-time failure instead of a "+
				"listener that does not work", c.what)
			continue
		}
		if !errors.Is(err, compute.ErrInvalidSpec) {
			fail(tb, "function-endpoint", inv, "a TLS listener with %s was refused with %v, which "+
				"does not match compute.ErrInvalidSpec", c.what, err)
		}
	}

	// A provider must also not quietly turn a plaintext listener into a
	// certificate-less TLS one, which is what choosing the protocol from the port
	// number does.
	if e.Options.Rendered == nil {
		e.note("without Options.Rendered the suite cannot check that a plaintext listener was not " +
			"silently rendered as a certificate-less TLS listener, which is how the source " +
			"system's defect arises (it selects HTTPS for any port other than 80)")
		return
	}
	if _, err := rt.EnsureEndpoint(e.ctx, compute.EndpointSpec{
		Name:      e.Name("plaintext"),
		Target:    target,
		Listeners: []compute.ListenerSpec{{Port: 8080}},
		Placement: compute.Placement{Name: e.Options.Placement},
		Ingress:   []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080}},
	}); err != nil {
		fail(tb, "function-endpoint", inv, "a plaintext listener on a port other than 80 was "+
			"refused: %v", err)
		return
	}
	for _, artefact := range e.rendered(tb) {
		if strings.Contains(artefact, `certificate=""`) {
			fail(tb, "function-endpoint", inv, "the provider rendered a TLS listener with an empty "+
				"certificate: %s", artefact)
		}
	}
}

func checkIngressProxyFailsClosed(tb TB, e *Env) {
	const inv = "a provider with no ingress proxy rejects a platform-ingress rule rather than widening it to the internet"
	if !e.Provider.Capabilities().Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability")
		return
	}

	// First, against the provider under test: a platform-ingress rule is either
	// accepted or refused with a typed error. What it must never be is accepted
	// and then widened, which the second half of this check covers.
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)
	spec := e.ServiceSpec(e.Name("proxy"), Base, identity, nil)
	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 8080,
			Description: "the platform's reverse proxy may reach this app"},
	}
	if _, err := rt.EnsureService(e.ctx, spec); err != nil {
		if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrUnsupported) {
			fail(tb, "container-service", inv, "a platform-ingress rule was refused with %v; a "+
				"provider that has no ingress proxy configured must say so as ErrInvalidSpec or "+
				"ErrUnsupported, so the operator learns what to configure", err)
		}
		// Discoverable in advance now (F7): a refusal is only correct from a
		// provider that says it has no ingress proxy.
		if e.Provider.Capabilities().Has(compute.CapPlatformIngress) {
			fail(tb, "container-service", inv, "the provider advertises %s and then refused a "+
				"platform-ingress rule with %v; a capability a caller checks before deploying has "+
				"to mean the spec will be accepted", compute.CapPlatformIngress, err)
		}
	} else if !e.Provider.Capabilities().Has(compute.CapPlatformIngress) {
		fail(tb, "container-service", inv, "the provider accepted a platform-ingress rule without "+
			"advertising %s; either it has an ingress proxy and should say so, or it widened the "+
			"rule to something else, which is the source system's fail-open defect",
			compute.CapPlatformIngress)
	}

	if e.Options.WithoutIngressProxy == nil {
		skip(tb, e, inv, "Options.WithoutIngressProxy, which has to return a provider configured "+
			"with no platform ingress proxy — the configuration where the source system silently "+
			"widens the rule to 0.0.0.0/0")
		return
	}
	bare := e.Options.WithoutIngressProxy(tb)
	bareRT, err := bare.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "the proxy-less provider refused Containers(): %v", err)
	}
	bareIdentity := e.identity(tb, bare, compute.RuntimeContainer)
	bareSpec := e.ServiceSpec(e.Name("no-proxy"), Base, bareIdentity, nil)
	bareSpec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerPlatformIngress}, Port: 8080},
	}
	_, err = bareRT.EnsureService(e.ctx, bareSpec)
	if err == nil {
		fail(tb, "container-service", inv, "a provider configured with no ingress proxy accepted a "+
			"platform-ingress rule; in the source system a missing TRAEFIK_SECURITY_GROUP_ID turns "+
			"a proxy-only port into an internet-facing one, and the interface requires a provider "+
			"to reject the rule instead")
		return
	}
	if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrUnsupported) {
		fail(tb, "container-service", inv, "the proxy-less provider refused with %v, which matches "+
			"neither compute.ErrInvalidSpec nor compute.ErrUnsupported", err)
	}
}

func checkExecDoesNotWidenIdentity(tb TB, e *Env) {
	const inv = "making a workload reachable for interactive sessions grants its own identity nothing"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability")
		return
	}
	if !caps.Has(compute.CapWorkloadExec) {
		skip(tb, e, inv, "the "+string(compute.CapWorkloadExec)+" capability")
		return
	}
	if e.Options.CanExecInto == nil {
		skip(tb, e, inv, "Options.CanExecInto, which has to answer whether a workload identity can "+
			"open a session against a workload")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)

	execSpec := e.ServiceSpec(e.Name("exec"), Base, identity, nil)
	execSpec.ExecEnabled = true
	execSvc, err := rt.EnsureService(e.ctx, execSpec)
	if err != nil {
		fatal(tb, "container-service", inv, "a service with ExecEnabled was refused although the "+
			"provider advertises %q: %v", compute.CapWorkloadExec, err)
	}
	other, err := rt.EnsureService(e.ctx, e.ServiceSpec(e.Name("exec-neighbour"), Base, identity, nil))
	if err != nil {
		fatal(tb, "container-service", inv, "EnsureService for the neighbour failed: %v", err)
	}

	for _, target := range []struct {
		what string
		ref  compute.Ref
	}{
		{"the workload it was enabled on", execSvc.Ref},
		{"another workload entirely", other.Ref},
	} {
		can, err := e.Options.CanExecInto(e.ctx, e.Provider, identity, target.ref)
		if err != nil {
			fail(tb, "container-service", inv, "the CanExecInto hook failed for %s: %v", target.what, err)
			continue
		}
		if can {
			fail(tb, "container-service", inv, "the workload's own identity can open an interactive "+
				"session against %s. ExecEnabled expresses only the target half — make this workload "+
				"available for sessions — and the principal that opens one is the operator. Granting "+
				"it to the workload's identity is the inversion USOSS-2 corrected: on Kubernetes it "+
				"would let the workload exec into pods while still leaving operators unable to exec "+
				"into the workload", target.what)
		}
	}
}

// redact keeps a failure message from becoming the leak it is checking for.
func redact(err error) string {
	if err == nil {
		return "<nil>"
	}
	msg := err.Error()
	if strings.Contains(msg, secretSentinel) {
		return fmt.Sprintf("<an error containing secret material, %d bytes, withheld>", len(msg))
	}
	return msg
}

// checkRouteFailsClosedWithoutTLS is the last fail-open default the interface
// carried: an application's own public hostname.
//
// ListenerSpec has required a certificate since the first draft. Route did not
// carry one at all, so a provider's only options were plaintext (fail-open),
// inventing a certificate (forbidden), or refusing every route. Route.TLS and
// Route.AllowPlaintext make the choice the caller's and the refusal the
// interface's.
func checkRouteFailsClosedWithoutTLS(tb TB, e *Env) {
	const inv = "a route with no certificate and no AllowPlaintext is refused rather than served over HTTP"
	if !e.Provider.Capabilities().Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)

	spec := e.ServiceSpec(e.Name("plainroute"), Base, identity, nil)
	spec.Routes = []compute.Route{{Host: e.Name("app") + ".conformance.invalid", TargetPort: 8080}}
	if _, err := rt.EnsureService(e.ctx, spec); err == nil {
		fail(tb, "container-service", inv, "a route with no TLS and no AllowPlaintext was "+
			"accepted; publishing an application over HTTP has to be something somebody asked "+
			"for, and this is the same defect as the source system's certificate-less HTTPS "+
			"listener one layer down")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "container-service", inv, "the refusal was %v, which does not match "+
			"compute.ErrInvalidSpec", err)
	}

	// The explicit opt-out must work, or a platform that terminates TLS at an
	// edge the interface cannot see could not deploy anything.
	allowed := e.ServiceSpec(e.Name("allowplain"), Base, identity, nil)
	allowed.Routes = []compute.Route{{
		Host: e.Name("open") + ".conformance.invalid", TargetPort: 8080, AllowPlaintext: true,
	}}
	if _, err := rt.EnsureService(e.ctx, allowed); err != nil {
		fail(tb, "container-service", inv, "a route that explicitly allows plaintext was refused "+
			"with %v; the field exists so that serving HTTP is a decision somebody wrote down, "+
			"not something no provider will do", err)
	}

	// And a certificate the provider cannot resolve is refused rather than
	// substituted, the same rule as a listener's.
	unresolvable := e.ServiceSpec(e.Name("badcert"), Base, identity, nil)
	unresolvable.Routes = []compute.Route{{
		Host: e.Name("bad") + ".conformance.invalid", TargetPort: 8080,
		TLS: &compute.TLSConfig{CertificateRef: "conformance-no-such-certificate"},
	}}
	if _, err := rt.EnsureService(e.ctx, unresolvable); err == nil {
		fail(tb, "container-service", inv, "a route naming an unresolvable certificate was "+
			"accepted; a provider must not invent one")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "container-service", inv, "the refusal for an unresolvable route certificate was "+
			"%v, which does not match compute.ErrInvalidSpec", err)
	}
}

// checkSecretsDoNotCrossPlacements covers the amendment that made identities and
// secrets placement-scoped.
//
// A binding across placements is ErrInvalidSpec, and a provider must not copy
// secret material to satisfy one — copying doubles the places an audit has to
// look for material the interface is otherwise careful never to let apphub
// read.
// checkSecretVersionPinning is the gate on [compute.SecretBinding.Version].
//
// The invariant has two halves and a provider is on exactly one side of it, so
// the check needs both sides driven or it proves nothing. A check that only
// asserted "a decliner refuses" would pass against a provider that refuses
// everything; one that only asserted "an honourer pins" would never notice the
// silent-unpinning defect the field exists to close.
//
// What is observable where:
//
//   - The WRITE half needs only the secret store. An honouring provider reports
//     distinct [compute.StoredSecret.Version] values for two distinct values and
//     the same one for a repeat write; a declining provider reports none. Every
//     provider with the capability exercises this.
//   - The BIND half needs a runtime, because a binding is resolved at launch and
//     [compute.SecretStore] has no method that consumes one. Where there is no
//     container service the check says so rather than passing.
func checkSecretVersionPinning(tb TB, e *Env) {
	const inv = "a version-pinned secret binding is honoured or typed-refused, never silently unpinned"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapSecretStore) {
		skip(tb, e, inv, "the "+string(compute.CapSecretStore)+" capability")
		return
	}
	store, err := e.Provider.Secrets()
	if err != nil {
		fatal(tb, "secret", inv, "Secrets() refused: %v", err)
	}
	spec := func(value string) compute.SecretSpec {
		return compute.SecretSpec{
			Name:      "cf-pinned",
			Scope:     "conformance-pinning",
			Value:     compute.NewSecretValue(value),
			Placement: compute.Placement{Name: e.Options.Placement},
			Labels:    map[string]string{"owner": "conformance"},
		}
	}
	first, err := store.Put(e.ctx, spec(secretSentinel))
	if err != nil {
		fatal(tb, "secret", inv, "the first Put failed: %v", redact(err))
	}
	again, err := store.Put(e.ctx, spec(secretSentinel))
	if err != nil {
		fatal(tb, "secret", inv, "a repeat Put of the same value failed: %v", redact(err))
	}
	second, err := store.Put(e.ctx, spec(secretSentinel+"-rotated"))
	if err != nil {
		fatal(tb, "secret", inv, "a Put of a new value failed: %v", redact(err))
	}
	for _, s := range []compute.StoredSecret{first, again, second} {
		if s.Ref != first.Ref {
			fail(tb, "secret", inv, "Put returned a different Ref for the same logical secret "+
				"(%s then %s); a Ref is the resource's identity and a new value is not a new "+
				"resource", first.Ref, s.Ref)
			return
		}
	}

	if !e.Options.HonoursSecretVersions {
		if first.Version != "" {
			fail(tb, "secret", inv, "the provider does not declare Options.HonoursSecretVersions "+
				"but Put reported version %q; either it honours pinning and should declare it, or "+
				"it is reporting a version a caller cannot pin to", first.Version)
		}
	} else {
		switch {
		case first.Version == "":
			fail(tb, "secret", inv, "the provider declares it honours pinning but Put reported no "+
				"version; then nothing can fill compute.SecretBinding.Version and the pin is "+
				"unreachable from the write path")
			return
		case again.Version != first.Version:
			fail(tb, "secret", inv, "a repeat Put of an identical value minted a new version "+
				"(%q then %q); a redeploy that changed nothing would look like a rotation",
				first.Version, again.Version)
		case second.Version == first.Version:
			fail(tb, "secret", inv, "a Put of a different value reported the same version %q, so "+
				"a pin to it does not name one revision", first.Version)
			return
		}
	}

	// The bind half.
	if !caps.Has(compute.CapContainerService) {
		e.note("port secret: compute.SecretStore has no method that consumes a binding, so whether " +
			"a version pin is honoured or refused is only observable through a runtime; this " +
			"provider has no container service, so only the write half of the pinning invariant " +
			"was exercised")
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability, without which no "+
			"binding is ever resolved")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)
	pinned := []compute.SecretBinding{{
		EnvName: "CONFORMANCE_PINNED",
		Secret:  first.Ref,
		Version: first.Version,
	}}
	if !e.Options.HonoursSecretVersions {
		// A decliner has no version to offer, so the suite supplies one. That is
		// the case that matters: a caller converting a credentials.SecretRef has a
		// version string from the credential layer and no way to know this
		// substrate cannot use it.
		pinned[0].Version = "1"
	}
	svcSpec := e.ServiceSpec(e.Name("pinned"), Base, identity, pinned)
	_, err = rt.EnsureService(e.ctx, svcSpec)

	if !e.Options.HonoursSecretVersions {
		switch {
		case err == nil:
			fail(tb, "container-service", inv, "a workload bound to a pinned revision was accepted "+
				"by a provider whose store has no revisions; the caller believes it pinned one and "+
				"the workload will follow the latest value, which is the silent degradation "+
				"compute.SecretBinding.Version exists to close")
		case !errors.Is(err, compute.ErrVersionPinningUnsupported):
			fail(tb, "container-service", inv, "a pinned binding was refused with %v, which does "+
				"not match compute.ErrVersionPinningUnsupported; a caller cannot tell 'this "+
				"substrate has no versions' from an ordinary rejection", redact(err))
		}
		return
	}

	if err != nil {
		fail(tb, "container-service", inv, "a workload bound to a revision this provider reported "+
			"was refused: %v", redact(err))
		return
	}
	// An unknown revision must not be accepted either: an honouring provider that
	// fell back to the current value on a version it did not recognise would be
	// the same defect as ignoring the field.
	unknown := []compute.SecretBinding{{
		EnvName: "CONFORMANCE_PINNED",
		Secret:  first.Ref,
		Version: first.Version + "-no-such-revision",
	}}
	if _, err := rt.EnsureService(e.ctx,
		e.ServiceSpec(e.Name("pinned-unknown"), Base, identity, unknown)); err == nil {
		fail(tb, "container-service", inv, "a binding to a revision that does not exist was "+
			"accepted; a provider that falls back to the current value has silently unpinned the "+
			"workload, which is what the field was added to prevent")
	}

	// And the pin has to be visible in what the provider renders, where it can
	// show its work: a binding is resolved at launch, so a rendered specification
	// is the only place a caller can confirm which revision a workload was wired
	// to.
	if e.Options.Rendered == nil {
		e.note("port secret: Options.Rendered is not supplied, so the suite could not check that a " +
			"honoured version pin is visible in what the provider rendered")
		return
	}

	// A CONTROL, not a substring search.
	//
	// "the version appears somewhere in the rendered service" is an assertion
	// that cannot fail. A revision is a short decimal string -- "1" for the
	// first write of any secret -- and a rendered container specification is
	// full of incidental digits: replicas, ports, CPU and memory, the image
	// tag, the generated name's own counter. Removing a provider's version
	// render entirely still left this check green, which makes it a comment
	// rather than a gate.
	//
	// So the pin is observed as a DIFFERENCE. The same binding is rendered
	// twice, once pinned and once not, over the same secret and the same
	// environment variable, and the only difference between the two specs is
	// the field under test. A provider that drops the version renders the two
	// identically and fails here; the digits that happen to be in both cancel.
	unpinned := []compute.SecretBinding{{EnvName: "CONFORMANCE_PINNED", Secret: first.Ref}}
	controlSpec := e.ServiceSpec(e.Name("unpinned"), Base, identity, unpinned)
	if _, err := rt.EnsureService(e.ctx, controlSpec); err != nil {
		fail(tb, "container-service", inv, "an UNPINNED binding to the same secret was refused "+
			"with %v, so there is nothing to compare the pinned render against and whether the "+
			"pin was rendered cannot be established", redact(err))
		return
	}
	all := e.rendered(tb)
	pinnedText := renderedBody(all, svcSpec.Name)
	controlText := renderedBody(all, controlSpec.Name)
	if pinnedText == "" || controlText == "" {
		e.note("port secret: nothing the provider rendered names both the pinned and the unpinned " +
			"workload, so the pin could not be confirmed in a rendered artefact")
		return
	}
	if pinnedText == controlText {
		fail(tb, "container-service", inv, "the provider rendered a binding pinned to revision %q "+
			"and an unpinned binding to the same secret IDENTICALLY, so nothing above the "+
			"interface can tell which revision the workload was wired to; a pin that is not "+
			"observable is not distinguishable from a pin that was dropped", first.Version)
		return
	}
	if !strings.Contains(pinnedText, first.Version) {
		fail(tb, "container-service", inv, "the workload's rendered specification differs from the "+
			"unpinned one but does not mention revision %q, so what it records is that a pin was "+
			"set rather than which revision was honoured", first.Version)
	}
}

// renderedBody joins the artefacts describing one resource with that resource's
// own name replaced, so two renders of the same spec under different generated
// names compare equal.
//
// Without the substitution every comparison between two rendered specifications
// differs in the name and nothing else can be concluded from a difference.
func renderedBody(all []string, name string) string {
	got := renderedFor(all, name)
	if len(got) == 0 {
		return ""
	}
	joined := strings.Join(got, "\n")
	return strings.ReplaceAll(joined, name, "<resource>")
}

func checkSecretsDoNotCrossPlacements(tb TB, e *Env) {
	const inv = "a secret binding across placements is refused rather than satisfied by copying material"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapContainerService) || !caps.Has(compute.CapSecretStore) {
		skip(tb, e, inv, "the container-service and secret-store capabilities")
		return
	}
	if e.Options.SecondPlacement == "" {
		skip(tb, e, inv, "Options.SecondPlacement, which has to name a second configured "+
			"placement — the configuration where namespace-scoped identities and secrets bite")
		return
	}
	store, err := e.Provider.Secrets()
	if err != nil {
		fatal(tb, "secret", inv, "Secrets() refused: %v", err)
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}

	// A secret in the default placement, a workload in the second one.
	stored, err := store.Put(e.ctx, compute.SecretSpec{
		Name:      e.Name("crossing"),
		Scope:     e.Name("scope"),
		Value:     compute.NewSecretValue(secretSentinel),
		Placement: compute.Placement{Name: e.Options.Placement},
	})
	if err != nil {
		fatal(tb, "secret", inv, "Put failed: %v", err)
	}
	identity, err := e.Provider.Identities().EnsureWorkloadIdentity(e.ctx, compute.WorkloadIdentitySpec{
		Name:      e.Name("crossing"),
		RunsOn:    compute.RuntimeContainer,
		Placement: compute.Placement{Name: e.Options.SecondPlacement},
	})
	if err != nil {
		fatal(tb, "workload-identity", inv, "EnsureWorkloadIdentity in the second placement "+
			"failed: %v; an identity has to be placeable, or a workload outside the default "+
			"placement can run as nothing", err)
	}
	spec := e.ServiceSpec(e.Name("crossing"), Base, identity.Ref, nil)
	spec.Placement = compute.Placement{Name: e.Options.SecondPlacement}
	spec.Secrets = []compute.SecretBinding{{EnvName: "CROSSING", Secret: stored.Ref}}
	if _, err := rt.EnsureService(e.ctx, spec); err == nil {
		fail(tb, "container-service", inv, "a workload in one placement bound a secret from "+
			"another; either the provider copied the material, which it must not, or the binding "+
			"resolves to nothing at launch")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "container-service", inv, "the refusal was %v, which does not match "+
			"compute.ErrInvalidSpec", err)
	}
}
