// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/conformance"
	"github.com/conductorone/apphub/compute/k8s"
)

// harness reaches the substrate hooks. A provider this file did not construct
// has no business being handed to these options.
func harness(p compute.Provider) *k8s.Harness {
	k, ok := p.(*k8s.Provider)
	if !ok {
		panic("k8s_test: the conformance suite was handed a provider this test did not construct")
	}
	return k.Harness()
}

// fullConfig is a cluster with everything beside it that a Kubernetes provider
// needs in order to offer more than containers and secrets: a registry, a
// builder, an object store that federates the cluster's OIDC issuer, a Postgres
// operator, runtime images for functions, and the Gateway API.
//
// Every value is site-specific configuration under a reserved TLD. Nothing here
// is compiled into the provider, and there is no network identifier of any kind
// — that is the property USOSS-27 was asked to confirm, and this struct is the
// evidence: it is the complete set of things an operator must supply.
func fullConfig() k8s.Config {
	return k8s.Config{
		Placements: map[string]k8s.PlacementConfig{
			"default": {
				Namespace:        "apphub-apps",
				NodeSelector:     map[string]string{"apphub.dev/pool": "apps"},
				StorageClass:     "fast-ssd",
				IngressClassName: "platform",
			},
			"secondary": {Namespace: "apphub-apps-2", StorageClass: "fast-ssd", IngressClassName: "platform"},
		},
		DefaultPlacement: "default",
		IngressAddress:   "ingress.cluster.invalid",
		OIDCIssuer:       "https://oidc.cluster.invalid",
		OIDCAudience:     "apphub",
		IngressProxy:     k8s.PodSelector{Namespace: "platform-ingress", Labels: map[string]string{"app": "gateway"}},
		ControlPlane:     k8s.PodSelector{Namespace: "apphub-system", Labels: map[string]string{"app": "apphub"}},
		EndpointDomain:   "endpoints.invalid",
		GatewayAPI:       true,
		Certificates:     map[string]string{"cert-default": "cert-default-tls"},
		// Deliberately not "python3.12": the runtime vocabulary belongs to the
		// operator, and a Kubernetes provider that adopted AWS's spelling would
		// be evidence that the field is not really provider-owned.
		FunctionRuntimes: map[string]string{"python-3.12": "registry.invalid/apphub/runtime-python:3.12"},
		Registry: &k8s.RegistryConfig{
			Host: "registry.invalid", Project: "apphub",
			SupportsRetention: true, SupportsScanning: true,
			FederatesClusterOIDC: true,
		},
		ObjectStore: &k8s.ObjectStoreConfig{
			Endpoint: "https://objects.invalid", URIScheme: "s3", TrustsClusterOIDC: true,
		},
		PostgresOperator: &k8s.PostgresOperatorConfig{
			APIVersion: "postgresql.cnpg.io/v1", Kind: "Cluster",
			Versions:                  []string{"16", "17"},
			InstanceMillicoresPerUnit: 1000,
			InstanceMiBPerUnit:        4096,
		},
		BuildKit: true,
		// The cluster forwards a pod-bound ServiceAccount token to a
		// credential-provider plugin, so an image-pull grant names the workload
		// identity rather than a stored credential. Off in most clusters; the
		// difference is finding F1, and newLegacyPullSuite covers the other side.
		KubeletCredentialProvider: true,
	}
}

// ingressOnlyConfig is the same cluster without the Gateway API, without a
// registry, and without an object store or a Postgres operator: a plain
// Kubernetes cluster and nothing else. It is what most clusters actually are,
// and it is the configuration in which the capability refusals are real.
func ingressOnlyConfig() k8s.Config {
	cfg := fullConfig()
	cfg.Name = "kubernetes-plain"
	cfg.GatewayAPI = false
	cfg.Registry = nil
	cfg.BuildKit = false
	cfg.ObjectStore = nil
	cfg.PostgresOperator = nil
	cfg.FunctionRuntimes = nil
	return cfg
}

func conformanceOptions(cfg k8s.Config) conformance.Options {
	opts := conformance.Options{
		Placement: "default",
		// Two placements is what makes namespace scoping observable: an identity
		// and a secret are namespace-scoped here, so a workload in the second
		// placement can use neither unless both were placed with it.
		SecondPlacement: "secondary",
		// A stale-read conflict the provider cannot absorb, which is this
		// substrate's most common retryable failure and the one F2 was about.
		//
		// USOSS-42 gave this hook a kind parameter, the same treatment
		// InduceDenial below already had. It is accepted and not branched on:
		// this provider has only three substrates and FailNextApply already arms
		// all of them sticky, in each one's own vocabulary, so there is no
		// narrower arm to make -- unlike compute/aws, nothing here goes unarmed
		// for want of a kind.
		InduceTransient: func(_ context.Context, p compute.Provider, _ compute.Kind) (func(), error) {
			return harness(p).FailNextApply(k8s.ErrOptimisticConcurrency), nil
		},
		// A denial on whichever substrate stands behind the port the suite is
		// about to drive. Supplying it is what makes
		// provider/an-authorization-failure-is-ErrNotPermitted run here at all:
		// with the hook nil the check skipped, and behind the skip a 403 was
		// reported as compute.ErrFailed.
		InduceDenial: func(ctx context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
			return harness(p).InduceDenial(ctx, kind)
		},
		// Every ext port is AWS-shaped and this provider implements none of
		// them, which is the outcome compute/ext exists to make explicit.
		ImplementsExt: map[string]bool{},
		Stall: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			return harness(p).Stall(ctx, ref)
		},
		CreateUnowned: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			return harness(p).CreateUnowned(ctx, ref)
		},
		Read: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			return harness(p).Read(ctx, resource, identity)
		},
		Write: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			return harness(p).Write(ctx, resource, identity)
		},
		AnonymousRead: func(ctx context.Context, p compute.Provider, bucket compute.Ref) error {
			return harness(p).AnonymousRead(ctx, bucket)
		},
		RelationalLogin: func(ctx context.Context, p compute.Provider, ref compute.Ref, user string, password compute.SecretValue) error {
			return harness(p).Login(ctx, ref, user, password)
		},
		CanExecInto: func(ctx context.Context, p compute.Provider, identity, target compute.Ref) (bool, error) {
			return harness(p).CanExecInto(ctx, identity, target)
		},
		Rendered: func(ctx context.Context, p compute.Provider) ([]string, error) {
			return harness(p).Rendered(ctx)
		},
	}
	if len(cfg.FunctionRuntimes) > 0 {
		for name := range cfg.FunctionRuntimes {
			opts.FunctionRuntime = name
		}
	}
	if cfg.GatewayAPI {
		opts.CertificateRef = "cert-default"
	}
	if cfg.PostgresOperator != nil {
		opts.Engine = compute.EnginePostgres
		opts.EngineVersion = cfg.PostgresOperator.Versions[0]
	}
	return opts
}

// newSuite returns a factory and options over one substrate. Every provider the
// factory hands back addresses the same cluster, registry, and object store,
// which is what the determinism invariant needs.
func newSuite(cfg k8s.Config) (conformance.Factory, conformance.Options) {
	sub := newSubstrate(cfg)
	factory := func(conformance.TB) compute.Provider { return k8s.New(sub, cfg) }
	opts := conformanceOptions(cfg)
	proxyless := cfg
	proxyless.IngressProxy = k8s.PodSelector{}
	opts.WithoutIngressProxy = func(conformance.TB) compute.Provider {
		return k8s.New(sub, proxyless)
	}
	return factory, opts
}

// newSubstrate builds the substrate a config describes. The registry's
// federation is a fact about the registry rather than about the provider, so it
// is configured here and not derived inside New.
//
// The in-memory backing stores are constructed by name rather than through
// k8s.NewSubstrate, because Substrate.Registry and Substrate.Objects are seams
// now and SetFederatesClusterOIDC is a property of this implementation of one:
// a real registry federates the cluster or does not, and nothing can tell it to
// start. Naming the type is the price of the seam and it is the right way round —
// the test knows it wants the in-memory one.
func newSubstrate(cfg k8s.Config) *k8s.Substrate {
	registry := k8s.NewMemoryRegistry()
	if cfg.Registry != nil {
		registry.SetFederatesClusterOIDC(cfg.Registry.FederatesClusterOIDC)
	}
	return &k8s.Substrate{
		Cluster:  k8s.NewMemoryCluster(),
		Registry: registry,
		Objects:  k8s.NewMemoryObjectStore(),
	}
}

// TestConformanceFullCluster runs the suite against a cluster with every
// supporting system configured.
func TestConformanceFullCluster(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fullConfig())
	conformance.Run(t, factory, opts)
}

// TestConformancePlainCluster runs the suite against a bare cluster.
//
// This is the run that exercises the refusals: no registry, no builder, no
// object store, no Postgres operator, no functions, no endpoints. A suite only
// ever run against the full configuration would never show that a Kubernetes
// provider's inability is typed, named, and loud.
func TestConformancePlainCluster(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(ingressOnlyConfig())
	conformance.Run(t, factory, opts)
}
