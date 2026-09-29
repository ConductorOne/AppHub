// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/conformance"
	"github.com/conductorone/apphub/compute/k8s"
)

// gatewayGVK is the Gateway API's Gateway, which this provider writes for a
// function endpoint.
var gatewayGVK = schema.GroupVersionKind{
	Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway",
}

// TestGuessingTheResourceNameIsWrongForAKindThisProviderWrites is the reason
// [k8s.StaticResolver] exists.
//
// apimachinery ships meta.UnsafeGuessKindToResource, and using it would have
// removed a table nobody wants to maintain. It is wrong for a kind this provider
// actually writes: it pluralises Gateway as "gatewaies", because it applies an
// English "-y" → "-ies" rule to a word ending in "-ay". The real resource is
// "gateways".
//
// The instance is a curiosity. The failure mode is the finding: a wrong resource
// name produces a 404 from the API server, which is indistinguishable from "the
// object does not exist", so a provider built on the guess would create a new
// Gateway on every reconcile and never converge — and every fake-client test
// would pass, because a fake is addressed by whatever resource the code asks for
// and therefore agrees with the mistake. This is the sharpest example on this
// branch of a class of defect a hermetic test cannot catch, and the answer is not
// a better test but a construction that refuses to guess.
func TestGuessingTheResourceNameIsWrongForAKindThisProviderWrites(t *testing.T) {
	t.Parallel()

	guessed, _ := meta.UnsafeGuessKindToResource(gatewayGVK)
	if guessed.Resource == "gateways" {
		t.Fatalf("meta.UnsafeGuessKindToResource now returns %q for a Gateway. If apimachinery "+
			"fixed its pluralisation, this test has served its purpose and the reasoning on "+
			"k8s.StaticResolver should be re-checked rather than the guess adopted: the argument "+
			"is that a wrong resource name is a silent 404, and that is unchanged.",
			guessed.Resource)
	}

	resolver, err := k8s.NewStaticResolver(nil)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	gvr, namespaced, err := resolver.ResourceFor(gatewayGVK)
	if err != nil {
		t.Fatalf("resolving a Gateway: %v", err)
	}
	if gvr.Resource != "gateways" {
		t.Errorf("the resolver maps a Gateway to %q, want %q", gvr.Resource, "gateways")
	}
	if !namespaced {
		t.Error("a Gateway resolved as cluster-scoped; a request would be addressed without a " +
			"namespace and read across every namespace")
	}
	if gvr.Resource == guessed.Resource {
		t.Error("the resolver agrees with the guess, so this test is no longer distinguishing " +
			"anything")
	}
}

// TestStaticResolverRefusesAnUnmappedKind pins the fail-closed half.
//
// An operator's custom resource cannot be in the built-in table — its resource
// name is whatever the CRD author chose — so the interesting behaviour is what
// happens before somebody configures it. A resolver that guessed would send a
// request to a path nobody serves; this one refuses and names the kind.
func TestStaticResolverRefusesAnUnmappedKind(t *testing.T) {
	t.Parallel()

	cfg := fullConfig()
	pg := schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster"}

	bare, err := k8s.NewStaticResolver(nil)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	if _, _, err := bare.ResourceFor(pg); !errors.Is(err, k8s.ErrUnmappedKind) {
		t.Fatalf("resolving an unconfigured custom resource returned %v, want ErrUnmappedKind", err)
	}

	mapping, err := k8s.PostgresResource(cfg.PostgresOperator, "clusters")
	if err != nil {
		t.Fatalf("PostgresResource: %v", err)
	}
	configured, err := k8s.NewStaticResolver(mapping)
	if err != nil {
		t.Fatalf("NewStaticResolver with the operator's resource: %v", err)
	}
	gvr, namespaced, err := configured.ResourceFor(pg)
	if err != nil {
		t.Fatalf("resolving a configured custom resource: %v", err)
	}
	if gvr.Resource != "clusters" || gvr.Group != "postgresql.cnpg.io" || !namespaced {
		t.Errorf("the operator's resource resolved to %s (namespaced=%v)", gvr, namespaced)
	}

	// An override of a built-in is allowed, because a cluster may serve a kind
	// at a name this table does not know. It has to actually take effect.
	overridden, err := k8s.NewStaticResolver(map[schema.GroupVersionKind]k8s.APIResource{
		gatewayGVK: {Resource: "gatewayclasses-but-not-really", Namespaced: true},
	})
	if err != nil {
		t.Fatalf("NewStaticResolver with an override: %v", err)
	}
	if gvr, _, err := overridden.ResourceFor(gatewayGVK); err != nil ||
		gvr.Resource != "gatewayclasses-but-not-really" {
		t.Errorf("an override of a built-in did not take effect: %s, %v", gvr, err)
	}
}

// TestStaticResolverRefusesAMalformedMapping checks the constructor, because a
// mapping with no resource name would resolve to a URL with an empty path
// segment and fail at run time instead of at configuration time.
func TestStaticResolverRefusesAMalformedMapping(t *testing.T) {
	t.Parallel()

	for name, extra := range map[string]map[schema.GroupVersionKind]k8s.APIResource{
		"no kind": {
			{Group: "g", Version: "v1"}: {Resource: "things", Namespaced: true},
		},
		"no version": {
			{Group: "g", Kind: "Thing"}: {Resource: "things", Namespaced: true},
		},
		"no resource": {
			{Group: "g", Version: "v1", Kind: "Thing"}: {Namespaced: true},
		},
	} {
		if _, err := k8s.NewStaticResolver(extra); err == nil {
			t.Errorf("NewStaticResolver accepted a mapping with %s", name)
		}
	}

	if _, err := k8s.PostgresResource(nil, "clusters"); err == nil {
		t.Error("PostgresResource accepted a nil operator config")
	}
	if _, err := k8s.PostgresResource(fullConfig().PostgresOperator, ""); err == nil {
		t.Error("PostgresResource accepted an empty resource name; the plural is the CRD " +
			"author's choice and this provider must not guess it")
	}
	bad := *fullConfig().PostgresOperator
	bad.APIVersion = "not/a/valid/apiVersion"
	if _, err := k8s.PostgresResource(&bad, "clusters"); err == nil {
		t.Error("PostgresResource accepted a malformed apiVersion")
	}
}

// TestEveryKindTheProviderWritesIsResolvable is the completeness half, and it is
// derived rather than restated.
//
// A resource table is only as good as its coverage, and a hand-written list of
// "the kinds this provider writes" would be exactly the shape this project has
// been bitten by: the entry that is missing is the one nobody thought of, and for
// a resource name that means a silent 404 in production rather than a red build.
//
// So the population is obtained by driving the provider. The conformance suite is
// the most complete exerciser of this provider that exists, so it is run against
// an in-memory cluster that records every kind any verb was called with, and the
// resolver must be able to address all of them. The suite runs at both
// configuration scopes because the plain-cluster configuration reaches a
// different set of kinds — no Gateway, no HTTPRoute, no Postgres cluster — and
// the union is what a real deployment might address.
//
// Two emptiness gates, because a derivation that finds nothing passes every
// assertion over it: the recorded kind set must be non-empty, and it must contain
// the kinds that cannot possibly be absent if the suite really ran.
func TestEveryKindTheProviderWritesIsResolvable(t *testing.T) {
	t.Parallel()

	cluster := k8s.NewMemoryCluster()
	postgres := ""

	for name, cfg := range map[string]k8s.Config{
		"full":  fullConfig(),
		"plain": ingressOnlyConfig(),
	} {
		if cfg.PostgresOperator != nil {
			postgres = "clusters"
		}
		registry := k8s.NewMemoryRegistry()
		if cfg.Registry != nil {
			registry.SetFederatesClusterOIDC(cfg.Registry.FederatesClusterOIDC)
		}
		sub := &k8s.Substrate{
			Cluster:  cluster,
			Registry: registry,
			Objects:  k8s.NewMemoryObjectStore(),
		}
		opts := conformanceOptions(cfg)
		proxyless := cfg
		proxyless.IngressProxy = k8s.PodSelector{}
		opts.WithoutIngressProxy = func(conformance.TB) compute.Provider {
			return k8s.New(sub, proxyless)
		}
		t.Run("drive/"+name, func(t *testing.T) {
			conformance.Run(t, func(conformance.TB) compute.Provider { return k8s.New(sub, cfg) }, opts)
		})
	}

	kinds := cluster.SeenKinds()
	if len(kinds) == 0 {
		t.Fatal("the conformance runs addressed no kinds at all, so this check would pass " +
			"vacuously; the recording cluster is not wired into the providers under test")
	}
	// The floor: if the suite genuinely ran, these were touched. A recording
	// that lost them is a recording that cannot be trusted for the rest.
	for _, must := range []string{"ServiceAccount", "Secret", "Deployment"} {
		found := false
		for _, gvk := range kinds {
			if gvk.Kind == must {
				found = true
			}
		}
		if !found {
			t.Fatalf("no %s was addressed across either conformance run; the recorded kind set "+
				"(%v) is incomplete and the coverage claim below rests on it", must, kinds)
		}
	}

	extra := map[schema.GroupVersionKind]k8s.APIResource{}
	if postgres != "" {
		mapping, err := k8s.PostgresResource(fullConfig().PostgresOperator, postgres)
		if err != nil {
			t.Fatalf("PostgresResource: %v", err)
		}
		for gvk, res := range mapping {
			extra[gvk] = res
		}
	}
	resolver, err := k8s.NewStaticResolver(extra)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}

	for _, gvk := range kinds {
		gvr, namespaced, err := resolver.ResourceFor(gvk)
		if err != nil {
			t.Errorf("the provider addressed %s, which a client-go cluster cannot resolve: %v\n"+
				"Every kind the provider touches needs an entry in k8s.BuiltinResources or in "+
				"the operator-supplied overrides, or a real cluster answers 404 and the provider "+
				"reads that as 'absent'.", gvk, err)
			continue
		}
		if gvr.Resource == "" {
			t.Errorf("%s resolved to an empty resource name", gvk)
		}
		if !namespaced {
			t.Errorf("%s resolved as cluster-scoped; every object this provider writes is "+
				"placed in a namespace", gvk)
		}
	}
	t.Logf("resolved %d kinds addressed across both conformance configurations", len(kinds))
}
