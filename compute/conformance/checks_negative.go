// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// workloadCapabilityGate maps a [compute.WorkloadCapability] onto the provider
// capability it requires.
//
// The pairing is not expressed anywhere in the interface — the requirement lives
// in a doc comment — so the suite has to carry it. The consequence is handled
// rather than ignored: [checkWorkloadCapabilityNegatives] enumerates
// [compute.WorkloadCapabilities] and fails loudly if it meets one this table does
// not know about, so a capability added later is covered by a red build instead
// of being silently untested.
func workloadCapabilityGate() map[compute.WorkloadCapability]compute.Capability {
	return map[compute.WorkloadCapability]compute.Capability{
		compute.WorkloadCapabilityModelInference: compute.CapModelInference,
	}
}

func negativeChecks(_ *Env) []Check {
	checks := []Check{
		{
			Name:      "capabilities/workload-capabilities-are-refused-when-absent",
			Invariant: "a spec requesting a capability the provider does not advertise fails loudly",
			Fn:        checkWorkloadCapabilityNegatives,
		},
		{
			Name:      "capabilities/zonal-object-storage",
			Port:      "bucket",
			Class:     Sync,
			Invariant: "a zonal bucket is provisioned when the capability is advertised and refused with ErrUnsupported when it is not",
			Fn:        checkZonalCapability,
		},
		{
			Name:      "capabilities/scheduled-jobs",
			Port:      "scheduled-job",
			Class:     Sync,
			Invariant: "a scheduled job is refused with ErrUnsupported when the capability is absent",
			Fn:        checkScheduledJobCapability,
		},
		{
			Name:      "capabilities/function-endpoints",
			Port:      "function-endpoint",
			Class:     Async,
			Invariant: "an endpoint is refused with ErrUnsupported when the capability is absent",
			Fn:        checkFunctionEndpointCapability,
		},
		{
			Name:      "capabilities/workload-exec",
			Port:      "container-service",
			Class:     Async,
			Invariant: "ExecEnabled is refused with ErrUnsupported when the capability is absent",
			Fn:        checkWorkloadExecCapability,
		},
		{
			Name:      "abstraction/placement-is-an-operator-configured-name",
			Invariant: "Placement is a logical name; an unconfigured one is refused rather than guessed",
			Fn:        checkPlacementIsLogical,
		},
		{
			Name:      "abstraction/reachability-is-expressed-between-roles",
			Port:      "container-service",
			Class:     Async,
			Invariant: "inbound reachability is stated between roles in the system, not between network objects",
			Fn:        checkReachabilityBetweenRoles,
		},
		{
			Name:      "abstraction/no-substrate-network-identifier-is-required",
			Invariant: "no substrate network identifier is required as an interface input",
			Fn:        checkNoNetworkIdentifierRequired,
		},
	}

	checks = append(checks, Check{
		Name:      "grants/bucket/an-external-grant-is-constrained-and-reads-back",
		Invariant: "a cross-domain grant with no correlation value is refused, and revoking an absent one is nil",
		Fn:        checkExternalGrantConstraints,
	})

	for _, port := range []string{
		"ext.TableBucketProvisioner",
		"ext.VectorBucketProvisioner",
		"ext.ExternalAccessGranter",
	} {
		port := port
		checks = append(checks, Check{
			Name:      "ext/" + port + "/lookup-matches-what-the-provider-documents",
			Invariant: "an ext lookup succeeds exactly when the provider implements the port, and otherwise returns a typed refusal that wraps ErrUnsupported",
			Fn:        checkExtLookup(port),
		})
	}
	return checks
}

func checkWorkloadCapabilityNegatives(tb TB, e *Env) {
	const inv = "a spec requesting a capability the provider does not advertise fails loudly"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability, through which a "+
			"workload capability is requested")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)
	gate := workloadCapabilityGate()

	// Enumerated rather than hardcoded, so that a capability added to the
	// interface later is covered without editing this loop.
	for _, wc := range compute.WorkloadCapabilities() {
		required, known := gate[wc]
		if !known {
			fail(tb, "container-service", inv, "compute.WorkloadCapabilities() includes %q, and the "+
				"conformance suite does not know which provider capability it requires. The pairing "+
				"is only stated in a doc comment, so it cannot be discovered at runtime: add %q to "+
				"conformance.workloadCapabilityGate", wc, wc)
			continue
		}
		spec := e.ServiceSpec(e.Name("wcap"), Base, identity, nil)
		spec.Capabilities = []compute.WorkloadCapability{wc}
		_, err := rt.EnsureService(e.ctx, spec)

		if caps.Has(required) {
			if err != nil {
				fail(tb, "container-service", inv, "the provider advertises %q but a service "+
					"requesting workload capability %q was refused: %v", required, wc, err)
			}
			continue
		}
		if err == nil {
			fail(tb, "container-service", inv, "a service requesting workload capability %q was "+
				"accepted although the provider does not advertise %q; the workload will believe it "+
				"has the access and get an authorization error at runtime, far from the deploy that "+
				"caused it", wc, required)
			continue
		}
		if !errors.Is(err, compute.ErrUnsupported) {
			fail(tb, "container-service", inv, "workload capability %q was refused with %v, which "+
				"does not match compute.ErrUnsupported; retrying cannot help, and a caller that "+
				"treats it as transient has misread the error", wc, err)
		}
	}
}

func checkZonalCapability(tb TB, e *Env) {
	const inv = "a zonal bucket is provisioned when the capability is advertised and refused with ErrUnsupported when it is not"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapObjectStore) {
		skip(tb, e, inv, "the "+string(compute.CapObjectStore)+" capability")
		return
	}
	store, err := e.Provider.ObjectStores()
	if err != nil {
		fatal(tb, "bucket", inv, "ObjectStores() refused: %v", err)
	}
	spec := compute.BucketSpec{
		Name:   e.Name("zonal"),
		Class:  compute.ObjectClassZonal,
		Zone:   e.Options.Zone,
		Labels: map[string]string{"owner": "conformance"},
	}
	b, err := store.EnsureBucket(e.ctx, spec)

	if !caps.Has(compute.CapObjectStoreZonal) {
		switch {
		case err == nil && b != nil && b.Class == compute.ObjectClassStandard:
			fail(tb, "bucket", inv, "a zonal bucket request was quietly satisfied with a %q bucket; "+
				"the caller asked for a latency property, and handing them a standard bucket "+
				"satisfies the type signature while breaking the reason they asked", b.Class)
		case err == nil:
			fail(tb, "bucket", inv, "a zonal bucket was provisioned although the provider does not "+
				"advertise %q", compute.CapObjectStoreZonal)
		case !errors.Is(err, compute.ErrUnsupported):
			fail(tb, "bucket", inv, "a zonal bucket was refused with %v, which does not match "+
				"compute.ErrUnsupported", err)
		}
		return
	}

	if err != nil {
		fail(tb, "bucket", inv, "the provider advertises %q but a zonal bucket in zone %q was "+
			"refused: %v", compute.CapObjectStoreZonal, e.Options.Zone, err)
		return
	}
	if b.Class != compute.ObjectClassZonal {
		fail(tb, "bucket", inv, "a zonal bucket came back as class %q; the caller must be able to "+
			"tell what they got", b.Class)
	}
	// A zonal bucket with no zone cannot be placed, so it is a spec error rather
	// than a provider default.
	noZone := spec
	noZone.Name = e.Name("zonal-nozone")
	noZone.Zone = ""
	if _, err := store.EnsureBucket(e.ctx, noZone); err == nil {
		fail(tb, "bucket", inv, "a zonal bucket with no zone was accepted; the zone is required, "+
			"and a provider that picks one has made a latency decision the caller did not make")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "bucket", inv, "a zonal bucket with no zone was refused with %v, which does not "+
			"match compute.ErrInvalidSpec", err)
	}
}

func checkScheduledJobCapability(tb TB, e *Env) {
	const inv = "a scheduled job is refused with ErrUnsupported when the capability is absent"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability, through which "+
			"scheduled jobs are reached")
		return
	}
	if caps.Has(compute.CapScheduledJob) {
		skip(tb, e, inv, "a provider without "+string(compute.CapScheduledJob)+
			" (this one has it, so the refusal path does not exist here)")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "scheduled-job", inv, "Containers() refused: %v", err)
	}
	_, err = rt.EnsureScheduledJob(e.ctx, compute.ScheduledJobSpec{
		Name:      e.Name("job"),
		Schedule:  compute.Schedule{Expression: "*/5 * * * *"},
		Placement: compute.Placement{Name: e.Options.Placement},
		Image:     e.Image(),
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Identity:  e.ContainerIdentity(tb, e.Provider),
	})
	requireUnsupported(tb, e, "scheduled-job", inv, "EnsureScheduledJob", compute.CapScheduledJob, err)
}

func checkFunctionEndpointCapability(tb TB, e *Env) {
	const inv = "an endpoint is refused with ErrUnsupported when the capability is absent"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapFunction) {
		skip(tb, e, inv, "the "+string(compute.CapFunction)+" capability, through which endpoints "+
			"are reached")
		return
	}
	if caps.Has(compute.CapFunctionEndpoint) {
		skip(tb, e, inv, "a provider without "+string(compute.CapFunctionEndpoint))
		return
	}
	rt, err := e.Provider.Functions()
	if err != nil {
		fatal(tb, "function-endpoint", inv, "Functions() refused: %v", err)
	}
	st, err := rt.EnsureFunction(e.ctx, e.FunctionSpec(e.Name("endpointless"), Base,
		e.FunctionIdentity(tb, e.Provider)))
	if err != nil {
		fatal(tb, "function-endpoint", inv, "EnsureFunction failed: %v", err)
	}
	_, err = rt.EnsureEndpoint(e.ctx, compute.EndpointSpec{
		Name:      e.Name("endpoint"),
		Target:    st.Ref,
		Listeners: []compute.ListenerSpec{{Port: 80}},
		Placement: compute.Placement{Name: e.Options.Placement},
	})
	requireUnsupported(tb, e, "function-endpoint", inv, "EnsureEndpoint", compute.CapFunctionEndpoint, err)
}

func checkWorkloadExecCapability(tb TB, e *Env) {
	const inv = "ExecEnabled is refused with ErrUnsupported when the capability is absent"
	caps := e.Provider.Capabilities()
	if !caps.Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability")
		return
	}
	if caps.Has(compute.CapWorkloadExec) {
		skip(tb, e, inv, "a provider without "+string(compute.CapWorkloadExec))
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	spec := e.ServiceSpec(e.Name("exec-absent"), Base, e.ContainerIdentity(tb, e.Provider), nil)
	spec.ExecEnabled = true
	_, err = rt.EnsureService(e.ctx, spec)
	requireUnsupported(tb, e, "container-service", inv, "EnsureService with ExecEnabled",
		compute.CapWorkloadExec, err)
}

// requireUnsupported is the shared assertion for a capability the provider does
// not advertise: the call must fail, and the failure must be recognisable.
func requireUnsupported(tb TB, _ *Env, port, inv, call string, capability compute.Capability, err error) {
	tb.Helper()
	if err == nil {
		fail(tb, port, inv, "%s succeeded although the provider does not advertise %q; a capability "+
			"a substrate structurally lacks must be a fact the caller can discover and act on, not "+
			"a resource that silently does not work", call, capability)
		return
	}
	if !errors.Is(err, compute.ErrUnsupported) {
		fail(tb, port, inv, "%s was refused with %v, which does not match compute.ErrUnsupported",
			call, err)
	}
}

func checkExtLookup(port string) func(TB, *Env) {
	const inv = "an ext lookup succeeds exactly when the provider implements the port, and otherwise returns a typed refusal that wraps ErrUnsupported"
	return func(tb TB, e *Env) {
		if !e.Provider.Capabilities().Has(compute.CapObjectStore) {
			skip(tb, e, inv, "the "+string(compute.CapObjectStore)+" capability, which the ext "+
				"lookups take a port of")
			return
		}
		store, err := e.Provider.ObjectStores()
		if err != nil {
			fatal(tb, port, inv, "ObjectStores() refused: %v", err)
		}

		var lookupErr error
		switch port {
		case "ext.TableBucketProvisioner":
			_, lookupErr = ext.TableBuckets(e.Provider.Name(), store)
		case "ext.VectorBucketProvisioner":
			_, lookupErr = ext.VectorBuckets(e.Provider.Name(), store)
		case "ext.ExternalAccessGranter":
			_, lookupErr = ext.ExternalAccess(e.Provider.Name(), store)
		default:
			fatal(tb, port, inv, "the suite does not know how to look up %q", port)
		}

		documented := e.Options.ImplementsExt[port]
		if documented {
			if lookupErr != nil {
				fail(tb, port, inv, "Options.ImplementsExt says this provider implements %s, but "+
					"the lookup refused it: %v", port, lookupErr)
			}
			return
		}
		if lookupErr == nil {
			fail(tb, port, inv, "the lookup found %s on a provider that does not document it; a "+
				"caller would use a non-portable port the provider never promised, and an operator "+
				"would learn the resource is substrate-specific only when something else broke", port)
			return
		}
		// The refusal has to be usable: an operator should learn a table bucket
		// is substrate-specific when they pick it, not when the deploy fails.
		if !errors.Is(lookupErr, compute.ErrUnsupported) {
			fail(tb, port, inv, "the refusal %v does not match compute.ErrUnsupported, so a caller "+
				"that already branches on that sentinel needs a second case", lookupErr)
		}
		var typed *ext.ErrNotImplemented
		if !errors.As(lookupErr, &typed) {
			fail(tb, port, inv, "the refusal %v is not an *ext.ErrNotImplemented", lookupErr)
			return
		}
		if typed.Provider != e.Provider.Name() || typed.Port != port {
			fail(tb, port, inv, "the refusal names provider %q and port %q, want %q and %q",
				typed.Provider, typed.Port, e.Provider.Name(), port)
		}
	}
}

func checkPlacementIsLogical(tb TB, e *Env) {
	const inv = "Placement is a logical name; an unconfigured one is refused rather than guessed"
	caps := e.Provider.Capabilities()

	// Any port that takes a Placement will do; a service is the richest.
	switch {
	case caps.Has(compute.CapContainerService):
		rt, err := e.Provider.Containers()
		if err != nil {
			fatal(tb, "container-service", inv, "Containers() refused: %v", err)
		}
		identity := e.ContainerIdentity(tb, e.Provider)

		// The configured name works, and it is the only network input the spec
		// carries.
		if _, err := rt.EnsureService(e.ctx,
			e.ServiceSpec(e.Name("placement-ok"), Base, identity, nil)); err != nil {
			fail(tb, "container-service", inv, "a service placed in the configured placement %q was "+
				"refused: %v", e.Options.Placement, err)
		}

		spec := e.ServiceSpec(e.Name("placement-bad"), Base, identity, nil)
		spec.Placement = compute.Placement{Name: e.Options.UnknownPlacement}
		if _, err := rt.EnsureService(e.ctx, spec); err == nil {
			fail(tb, "container-service", inv, "a service naming placement %q, which this provider "+
				"is not configured with, was accepted; a provider that guesses where to run "+
				"something can strand a resource somewhere nothing addresses — which is what the "+
				"source system does when it degrades an unusable region to a logged warning and a "+
				"silent fallback", e.Options.UnknownPlacement)
		} else if !errors.Is(err, compute.ErrInvalidSpec) {
			fail(tb, "container-service", inv, "an unconfigured placement was refused with %v, "+
				"which does not match compute.ErrInvalidSpec", err)
		}
	case caps.Has(compute.CapObjectStore):
		skip(tb, e, inv, "a port that takes a Placement (this provider has no container service, "+
			"and compute.BucketSpec carries no Placement field)")
	default:
		skip(tb, e, inv, "a port that takes a Placement")
	}
}

func checkReachabilityBetweenRoles(tb TB, e *Env) {
	const inv = "inbound reachability is stated between roles in the system, not between network objects"
	if !e.Provider.Capabilities().Has(compute.CapContainerService) {
		skip(tb, e, inv, "the "+string(compute.CapContainerService)+" capability")
		return
	}
	rt, err := e.Provider.Containers()
	if err != nil {
		fatal(tb, "container-service", inv, "Containers() refused: %v", err)
	}
	identity := e.ContainerIdentity(tb, e.Provider)

	peerSvc, err := rt.EnsureService(e.ctx, e.ServiceSpec(e.Name("peer"), Base, identity, nil))
	if err != nil {
		fatal(tb, "container-service", inv, "EnsureService for the peer workload failed: %v", err)
	}

	// A workload peer is named by its Ref — the replacement for the
	// security-group-to-security-group pattern.
	spec := e.ServiceSpec(e.Name("reachability"), Base, identity, nil)
	spec.Ingress = []compute.IngressRule{
		{From: compute.Peer{Kind: compute.PeerWorkload, Workload: peerSvc.Ref}, Port: 8080},
		{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: 8080},
	}
	if _, err := rt.EnsureService(e.ctx, spec); err != nil {
		fail(tb, "container-service", inv, "a rule naming another workload by reference and one "+
			"naming the control plane were refused: %v", err)
	}

	// A workload peer with no reference names nothing.
	bad := e.ServiceSpec(e.Name("reachability-bad"), Base, identity, nil)
	bad.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerWorkload}, Port: 8080}}
	if _, err := rt.EnsureService(e.ctx, bad); err == nil {
		fail(tb, "container-service", inv, "a workload peer with no reference was accepted; there "+
			"is no workload for the rule to be about")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "container-service", inv, "a workload peer with no reference was refused with %v, "+
			"which does not match compute.ErrInvalidSpec", err)
	}

	// A workload peer from another substrate cannot be resolved.
	foreign := e.ServiceSpec(e.Name("reachability-foreign"), Base, identity, nil)
	foreign.Ingress = []compute.IngressRule{{
		From: compute.Peer{Kind: compute.PeerWorkload, Workload: compute.Ref{
			Provider: foreignProvider, Kind: compute.KindService, ID: "elsewhere"}},
		Port: 8080,
	}}
	if _, err := rt.EnsureService(e.ctx, foreign); err == nil {
		fail(tb, "container-service", inv, "a rule naming a workload issued by %q was accepted",
			foreignProvider)
	} else if !errors.Is(err, compute.ErrForeignRef) && !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, "container-service", inv, "a foreign workload peer was refused with %v, which "+
			"matches neither compute.ErrForeignRef nor compute.ErrInvalidSpec", err)
	}

	// An unknown peer kind must not be treated as a default.
	unknown := e.ServiceSpec(e.Name("reachability-unknown"), Base, identity, nil)
	unknown.Ingress = []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerKind("everyone")}, Port: 8080}}
	if _, err := rt.EnsureService(e.ctx, unknown); err == nil {
		fail(tb, "container-service", inv, "a rule naming peer kind %q was accepted; an unknown "+
			"role must not fall back to any particular one", "everyone")
	}
}

// networkIdentifierWords are the substrate identifiers that must not be an input
// to this interface. "zone" is deliberately absent: [compute.BucketSpec.Zone] is
// an opaque, operator-supplied string and the design doc records it as a
// concession rather than a leak.
var networkIdentifierWords = []string{
	"subnet", "vpc", "securitygroup", "accountid", "arn", "cidr",
	"loadbalancer", "targetgroup", "clusterid", "clusterarn", "instanceid",
	"ipaddress", "ipv4", "ipv6", "parameterstore",
}

// checkNoNetworkIdentifierRequired asserts the property the whole network model
// exists for: a caller can provision everything while knowing no substrate
// network identifier.
//
// It is checked two ways. Structurally, no spec type reachable from this
// interface has a field whose name is one of those identifiers — a conformance
// test that only passed when handed a subnet ID would prove the abstraction was
// fake, so the assertion is the opposite. Behaviourally, every other check in
// this suite has already provisioned every port using nothing but a placement
// name, role-based reachability, and caller-composed hostnames.
func checkNoNetworkIdentifierRequired(tb TB, e *Env) {
	const inv = "no substrate network identifier is required as an interface input"
	seen := map[reflect.Type]bool{}
	specs := []any{
		compute.ServiceSpec{}, compute.ScheduledJobSpec{}, compute.FunctionSpec{},
		compute.EndpointSpec{}, compute.BucketSpec{}, compute.RelationalSpec{},
		compute.KeyValueSpec{}, compute.RepositorySpec{}, compute.WorkloadIdentitySpec{},
		compute.SecretSpec{}, compute.BuildRequest{}, compute.Placement{},
		compute.IngressRule{}, compute.Route{},
	}
	for _, s := range specs {
		scanForIdentifiers(tb, reflect.TypeOf(s), reflect.TypeOf(s).Name(), seen, inv)
	}

	// And the positive half, stated so the check is not purely structural: if the
	// provider could only be driven with a substrate identifier, none of the
	// port checks above could have passed, because the suite never has one to
	// give.
	tb.Logf("conformance: every port was provisioned with a logical placement name, reachability "+
		"between roles, and caller-composed hostnames; the suite holds no subnet, security group, "+
		"cluster, load balancer, or account identifier to give provider %q", e.Provider.Name())
}

func scanForIdentifiers(tb TB, t reflect.Type, path string, seen map[reflect.Type]bool, inv string) {
	tb.Helper()
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := range t.NumField() {
		f := t.Field(i)
		lower := strings.ToLower(f.Name)
		for _, word := range networkIdentifierWords {
			if strings.Contains(lower, word) {
				fail(tb, "interface", inv, "%s.%s names a substrate identifier (%q). A caller would "+
					"have to know a network object's identity to use this interface, which is the "+
					"fake abstraction the network model exists to avoid: Placement{Subnets []string} "+
					"keeps every AWS network ID in the interface and gives a Kubernetes provider a "+
					"field it must ignore", path, f.Name, word)
			}
		}
		scanForIdentifiers(tb, f.Type, path+"."+f.Name, seen, inv)
	}
}

// checkExternalGrantConstraints drives ext.ExternalAccessGranter's two methods.
//
// # Why this exists
//
// [undrivenPortMethods] excused GrantExternal and RevokeExternal as
// "no provider implements this port". compute/fake does, so the exclusion was
// false and — once corrected to Legitimate false — became the third state the
// table forbids: a hole nothing observes that something could drive. The table's
// own rule is *drive it, do not excuse it*, so this drives it.
//
// # What it asserts
//
// The contract is that a grant carrying no constraints is refused, that the
// refusal mutates nothing, that a repeated grant replaces rather than
// accumulates, and that a revoke removes.
//
// This used to assert only the first of those, and said so at length: observing
// whether a call changed stored state needed a read-back the interface did not
// offer, so compute/fake asserted the rest against its own private store and this
// check established the error classifications and nothing behind them. That
// boundary was recorded as an unverified obligation with seven numbered gaps, and
// a provider whose RevokeExternal did nothing at all passed the whole suite —
// measured, not hypothesised.
//
// [ext.ExternalAccessGranter.ExternalGrants] closed it. Each assertion below is
// labelled with the gap it now covers, because the point of the enumeration was
// that a reader must not count partial coverage as the whole contract, and the
// same applies in reverse now that it is not partial.
//
// # The half that is still not this check's
//
// That a grant *authorises* anything outside the trust domain. Nothing in this
// repository can perform a cross-account access, so "the grant is recorded as
// asked" is the ceiling here — the same division of labour the core grant checks
// have between the read-back and Options.Read.
func checkExternalGrantConstraints(tb TB, e *Env) {
	const inv = "a cross-domain grant with no correlation value is refused and mutates nothing; a repeated grant replaces; a revoke removes"
	const port = "ext.ExternalAccessGranter"

	if !e.Options.ImplementsExt[port] {
		skip(tb, e, inv, "a provider documenting "+port+"; the lookup check covers the refusal "+
			"for providers that do not")
		return
	}
	if !e.Provider.Capabilities().Has(compute.CapObjectStore) {
		fail(tb, port, inv, "Options.ImplementsExt claims %s and the provider does not advertise "+
			"%s, so there is no object store to reach the port through", port, compute.CapObjectStore)
		return
	}
	store, err := e.Provider.ObjectStores()
	if err != nil {
		fatal(tb, port, inv, "ObjectStores() refused: %v", err)
		return
	}
	granter, err := ext.ExternalAccess(e.Provider.Name(), store)
	if err != nil {
		fatal(tb, port, inv, "Options.ImplementsExt claims %s and the lookup refused: %v", port, err)
		return
	}
	bucket, err := store.EnsureBucket(e.ctx, compute.BucketSpec{Name: e.Name("ext-grant")})
	if err != nil {
		fatal(tb, port, inv, "EnsureBucket: %v", err)
		return
	}

	const id = "caller-supplied-principal"

	// A bucket nobody has granted anything on. Empty, not an error: "nothing
	// outside the trust domain can reach this" is the answer a reconciler acts on.
	if grants, err := granter.ExternalGrants(e.ctx, bucket.Ref); err != nil {
		fail(tb, port, inv, "ExternalGrants on a bucket with no external grants returned %v, want "+
			"an empty slice and no error; a read that cannot report the absence of access cannot "+
			"be used to audit access", err)
	} else if len(grants) != 0 {
		fail(tb, port, inv, "ExternalGrants reports %d grant(s) on a bucket nothing has been "+
			"granted on: %v. Every assertion below is vacuous if the read-back invents grants",
			len(grants), grants)
	}

	// No constraints: refused. A grant constrained only by the principal admits
	// every other tenant reachable through that principal.
	if err := granter.GrantExternal(e.ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id}, compute.AccessRead); !errors.Is(err, compute.ErrInvalidSpec) {
		fail(tb, port, inv, "GrantExternal with no constraints returned %v, want ErrInvalidSpec. An "+
			"unconstrained cross-domain grant admits every tenant reachable through the principal, "+
			"which is the failure the source system's own comment warns about", err)
	}

	// Gap (7): the refusal mutated nothing. An error return that also created a
	// grant is a worse contract than either half of it, and this is the assertion
	// that was impossible before the read-back existed.
	if grants, err := granter.ExternalGrants(e.ctx, bucket.Ref); err != nil {
		fail(tb, port, inv, "ExternalGrants after the refused grant: %v", err)
	} else if len(grants) != 0 {
		fail(tb, port, inv, "a GrantExternal that was refused for having no constraints left %d "+
			"grant(s) behind: %v. The refusal is the check, and a refusal that half-applies leaves "+
			"exactly the unconstrained grant it was refusing to make", len(grants), grants)
	}

	// Two constraints, not one: the field is plural and a provider that kept only
	// the first would satisfy every single-element fixture.
	principal := ext.ExternalPrincipal{ID: id, Constraints: []string{"tenant one", "tenant two"}}
	if err := granter.GrantExternal(e.ctx, bucket.Ref, principal, compute.AccessRead); err != nil {
		fail(tb, port, inv, "GrantExternal with two constraints: %v", err)
		return
	}

	// Gaps (1) and (4): the grant exists, and every constraint survived. A count
	// would not catch a provider storing two copies of the first, which is why the
	// set is compared element by element.
	one := requireOneExternalGrant(tb, e, granter, bucket.Ref, inv)
	if one != nil {
		if one.Level != compute.AccessRead {
			fail(tb, port, inv, "the stored grant reports level %q and %q was granted",
				one.Level, compute.AccessRead)
		}
		if !one.Managed {
			fail(tb, port, inv, "the stored grant reports Managed false for a grant this platform "+
				"just created; RevokeExternal refuses a grant it did not create, so a provider that "+
				"disowns its own grants can never remove them")
		}
		if !slices.Equal(one.Principal.Constraints, principal.Constraints) {
			fail(tb, port, inv, "the stored constraints are %v and %v were granted. Every "+
				"correlation value has to survive: one tenant's value silently replaced by another's "+
				"admits the wrong tenant, and a provider that stored two copies of the first would "+
				"pass any check that only counted them",
				one.Principal.Constraints, principal.Constraints)
		}
	}

	// Gaps (3) and (5): a repeated grant to one principal replaces rather than
	// accumulates, and the level is last-write-wins.
	widened := ext.ExternalPrincipal{ID: id, Constraints: []string{"tenant one"}}
	if err := granter.GrantExternal(e.ctx, bucket.Ref, widened, compute.AccessReadWrite); err != nil {
		fail(tb, port, inv, "a repeated GrantExternal returned %v; the method is documented "+
			"idempotent and replaces any previous grant to the same principal", err)
	}
	if two := requireOneExternalGrant(tb, e, granter, bucket.Ref, inv); two != nil {
		if two.Level != compute.AccessReadWrite {
			fail(tb, port, inv, "after re-granting at %s the stored level is %q; a repeated grant "+
				"to one principal is last-write-wins on level",
				compute.AccessReadWrite, two.Level)
		}
		if !slices.Equal(two.Principal.Constraints, widened.Constraints) {
			fail(tb, port, inv, "after re-granting with %v the stored constraints are %v. A "+
				"re-grant replaces the previous grant to that principal, so a constraint the new "+
				"call does not name is a tenant that keeps access nobody intended -- which is the "+
				"configuration-edit path the port's own documentation calls out",
				widened.Constraints, two.Principal.Constraints)
		}
	}

	// Gap (2): a revoke removes something.
	if err := granter.RevokeExternal(e.ctx, bucket.Ref, principal); err != nil {
		fail(tb, port, inv, "RevokeExternal: %v", err)
	}
	if grants, err := granter.ExternalGrants(e.ctx, bucket.Ref); err != nil {
		fail(tb, port, inv, "ExternalGrants after RevokeExternal: %v", err)
	} else if len(grants) != 0 {
		fail(tb, port, inv, "RevokeExternal returned nil and left %d grant(s) standing: %v. A "+
			"revoke that reports success and removes nothing is a security control failing open, "+
			"and a provider whose RevokeExternal did exactly that passed this suite before the "+
			"read-back existed", len(grants), grants)
	}
	if err := granter.RevokeExternal(e.ctx, bucket.Ref, principal); err != nil {
		fail(tb, port, inv, "RevokeExternal on an absent grant returned %v, want nil; teardown has "+
			"to be re-runnable", err)
	}
}

// requireOneExternalGrant reads the grants on resource and returns the only one,
// or nil after reporting why there is not exactly one.
//
// Exactly one, because every assertion the caller makes about "the stored grant"
// is meaningless if a provider accumulated a second: the accumulation IS the
// defect in gap (3), and reading grants[0] out of a two-element slice would let
// it through while the level and constraint assertions passed on the newer entry.
func requireOneExternalGrant(tb TB, e *Env, granter ext.ExternalAccessGranter,
	resource compute.Ref, inv string) *ext.ExternalGrant {
	const port = "ext.ExternalAccessGranter"
	grants, err := granter.ExternalGrants(e.ctx, resource)
	if err != nil {
		fail(tb, port, inv, "ExternalGrants: %v", err)
		return nil
	}
	if len(grants) != 1 {
		fail(tb, port, inv, "ExternalGrants reports %d grant(s) where one principal has been "+
			"granted: %v. More than one means the provider accumulated rather than replaced; none "+
			"means a grant that returned nil never reached the substrate", len(grants), grants)
		return nil
	}
	return &grants[0]
}
