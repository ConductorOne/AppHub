// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// This file is the evidence behind docs/design/k8s-contract-probe.md.
//
// Each test pins one thing writing a Kubernetes provider found out about the
// Compute interface. They are deliberately narrow and deliberately not part of
// the conformance suite: the suite checks that a provider obeys the contract,
// and these check what obeying it costs.

func newProvider(t *testing.T, cfg k8s.Config) (*k8s.Provider, *k8s.Substrate) {
	t.Helper()
	sub := newSubstrate(cfg)
	return k8s.New(sub, cfg), sub
}

// legacyPullConfig is a cluster with no kubelet credential provider and a
// registry that does not federate it: the configuration most clusters are in,
// and the one where an image-pull grant has to become a stored credential.
func legacyPullConfig() k8s.Config {
	cfg := fullConfig()
	cfg.Name = "kubernetes-legacy-pull"
	cfg.KubeletCredentialProvider = false
	registry := *cfg.Registry
	registry.FederatesClusterOIDC = false
	cfg.Registry = &registry
	return cfg
}

func mustIdentity(t *testing.T, p *k8s.Provider, name string) compute.Ref {
	t.Helper()
	id, err := p.Identities().EnsureWorkloadIdentity(context.Background(), compute.WorkloadIdentitySpec{
		Name: name, RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(%q): %v", name, err)
	}
	return id.Ref
}

func rendered(t *testing.T, p *k8s.Provider) []string {
	t.Helper()
	out, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	return out
}

func findRendered(t *testing.T, p *k8s.Provider, substr string) string {
	t.Helper()
	for _, line := range rendered(t, p) {
		if strings.Contains(line, substr) {
			return line
		}
	}
	t.Fatalf("no rendered artefact contains %q; got:\n  %s", substr, strings.Join(rendered(t, p), "\n  "))
	return ""
}

// regGranter reaches this provider's image-pull grant path.
//
// compute.ImageRegistry no longer requires compute.Granter — that is the
// amendment F1 asked for, and it landed — so a test that exercises the grant
// reaches compute.ImagePullGranter, which is offered only when the substrate
// route is configured.
func regGranter(t *testing.T, p *k8s.Provider, reg compute.ImageRegistry) compute.ImagePullGranter {
	t.Helper()
	g, err := compute.ImagePullGrants(p, reg)
	if err != nil {
		t.Fatalf("ImagePullGrants: %v", err)
	}
	return g
}

// --- Finding 1 -------------------------------------------------------------------

// TestImagePullByWorkloadIdentityIsNotUniversal is the corrected F1, after the
// amendment it asked for.
//
// The claim: whether a registry can authorise a pull from a workload identity
// depends on operator configuration, and before the amendment a caller could not
// tell which of the two it had. An earlier version of the finding said no
// registry could — false as a universal, since a kubelet credential-provider
// plugin can be configured to receive a pod-bound ServiceAccount token.
// https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/#service-account-token-for-image-pulls
//
// So it is a capability now. This asserts the difference is visible, which is
// the whole content of the finding.
func TestImagePullByWorkloadIdentityIsNotUniversal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Wired for it: the capability is advertised, the grant is a policy write
	// naming the identity, and nothing is persisted.
	p, _ := newProvider(t, fullConfig())
	if !p.Capabilities().Has(compute.CapImagePullGrants) {
		t.Fatal("a cluster with a credential provider and a federating registry should advertise " +
			"CapImagePullGrants")
	}
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	if err := regGranter(t, p, reg).GrantPull(ctx, repo.Ref, identity); err != nil {
		t.Fatalf("GrantPull: %v", err)
	}
	if sa := findRendered(t, p, "ServiceAccount apphub-apps/app:"); strings.Contains(sa, "imagePullSecrets") {
		t.Errorf("a real grant should persist no credential; got %s", sa)
	}
	if err := p.Harness().Read(ctx, repo.Ref, identity); err != nil {
		t.Errorf("a pull as the granted identity should succeed: %v", err)
	}
	if err := regGranter(t, p, reg).RevokePull(ctx, repo.Ref, identity); err != nil {
		t.Errorf("RevokePull: %v", err)
	}
	if err := regGranter(t, p, reg).RevokePull(ctx, repo.Ref, identity); err != nil {
		t.Errorf("revoking an absent pull grant should be nil, got %v", err)
	}

	// Not wired for it — the ordinary cluster. The capability is absent and the
	// refusal names it, so a caller learns before it plans around the feature
	// rather than getting a credential-minting method wearing the same name.
	legacy, _ := newProvider(t, legacyPullConfig())
	if legacy.Capabilities().Has(compute.CapImagePullGrants) {
		t.Fatal("a cluster with no credential provider must not advertise CapImagePullGrants")
	}
	legacyReg, err := legacy.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	_, err = compute.ImagePullGrants(legacy, legacyReg)
	if !errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("the refusal should wrap ErrUnsupported, got %v", err)
	}
	var unsupported *compute.UnsupportedError
	if errors.As(err, &unsupported) && unsupported.Capability != compute.CapImagePullGrants {
		t.Errorf("the refusal names %q rather than the missing capability", unsupported.Capability)
	}
}

// TestLegacyPullObligationIsScopedToTheWorkloadsOwnImage is the other half.
//
// A cluster with no credential-provider route still gets the obligation: a
// workload can pull the image its spec names. The provider mints a credential to
// do it, because that is all the substrate offers — but scoped to the
// repositories that workload runs from, not to the whole project. An earlier
// version of the amendment granted project-wide, which is a least-privilege
// regression introduced by a least-privilege fix.
func TestLegacyPullObligationIsScopedToTheWorkloadsOwnImage(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, legacyPullConfig())
	ctx := context.Background()
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	mine, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	other, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "unrelated"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	identity := mustIdentity(t, p, "app")

	// Nothing is granted until a workload names an image.
	if err := p.Harness().Read(ctx, mine.Ref, identity); err == nil {
		t.Error("an identity with no workload can already pull")
	}

	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "api",
		Image:     compute.ImageRef(mine.Prefix + ":v1"),
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Identity:  identity,
	}); err != nil {
		t.Fatalf("EnsureService: %v", err)
	}

	if err := p.Harness().Read(ctx, mine.Ref, identity); err != nil {
		t.Errorf("a workload cannot pull the image its own spec names, which is the obligation "+
			"compute.ImageRegistry states: %v", err)
	}
	if err := p.Harness().Read(ctx, other.Ref, identity); err == nil {
		t.Error("the workload can pull a repository its spec does not name. That is the " +
			"project-wide grant review rejected: a fix for a least-privilege problem must not " +
			"introduce one.")
	}
	if err := p.Harness().Write(ctx, mine.Ref, identity); err == nil {
		t.Error("a workload identity can push; the obligation is pull")
	}
	// The credential is real, and still invisible to the caller.
	findRendered(t, p, "Secret apphub-apps/pull-app:")
}

// TestPullGrantsHaveNoAccessLevel is F24, closed.
//
// A repository has two verbs. compute.AccessLevel has three, so a provider had
// to alias the third or refuse it — a decision the caller could not see.
// compute.ImagePullGranter has no level at all: GrantPull and RevokePull say
// what they do, and push belongs to the builder's scoped credential rather than
// to a running workload.
func TestPullGrantsHaveNoAccessLevel(t *testing.T) {
	t.Parallel()
	granter := reflect.TypeOf((*compute.ImagePullGranter)(nil)).Elem()
	level := reflect.TypeOf(compute.AccessLevel(""))
	for i := range granter.NumMethod() {
		m := granter.Method(i)
		for j := range m.Type.NumIn() {
			if m.Type.In(j) == level {
				t.Errorf("ImagePullGranter.%s takes a compute.AccessLevel. A repository has two "+
					"verbs and the level has three, so the third would have to be aliased or "+
					"refused — which is the finding this port's shape exists to avoid.", m.Name)
			}
		}
	}
	// And a granted pull does not carry push with it.
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	if err := regGranter(t, p, reg).GrantPull(ctx, repo.Ref, identity); err != nil {
		t.Fatalf("GrantPull: %v", err)
	}
	if err := p.Harness().Write(ctx, repo.Ref, identity); err == nil {
		t.Error("a pull grant conferred push")
	}
}

// --- Finding 2 -------------------------------------------------------------------

// conflictOnce is a Cluster that fails one Apply with the substrate's
// optimistic-concurrency error, which is Kubernetes' other 409.
type conflictOnce struct {
	k8s.Cluster
	fired bool
}

func (c *conflictOnce) Apply(ctx context.Context, gvk schema.GroupVersionKind, obj runtime.Object) error {
	if !c.fired {
		c.fired = true
		return k8s.ErrOptimisticConcurrency
	}
	return c.Cluster.Apply(ctx, gvk, obj)
}

// TestOptimisticConcurrencyIsTransient is F2 after the amendment.
//
// Kubernetes returns 409 for two unrelated things: "that name is taken", which
// is compute.ErrNotOwned, and "your copy is stale, read it again", which is the
// most common retryable failure on the substrate. The taxonomy had nowhere for
// the second, so the provider swallowed it on a budget the caller could neither
// see nor bound — and the sentinel's old name (ErrConflict) invited an
// implementer to map the retryable one onto it.
func TestOptimisticConcurrencyIsTransient(t *testing.T) {
	t.Parallel()
	sub := k8s.NewSubstrate()
	sub.Cluster = &conflictOnce{Cluster: sub.Cluster}
	p := k8s.New(sub, fullConfig())

	// Still absorbed when it can be, which the contract allows and this
	// substrate needs.
	if _, err := p.Identities().EnsureWorkloadIdentity(context.Background(),
		compute.WorkloadIdentitySpec{Name: "app", RunsOn: compute.RuntimeContainer}); err != nil {
		t.Fatalf("an optimistic-concurrency conflict should be retried internally: %v", err)
	}

	// What changed: when the budget runs out the caller is told it may retry,
	// not that its spec has to change.
	always := k8s.NewSubstrate()
	always.Cluster = &alwaysConflict{Cluster: always.Cluster}
	q := k8s.New(always, fullConfig())
	_, err := q.Identities().EnsureWorkloadIdentity(context.Background(),
		compute.WorkloadIdentitySpec{Name: "app", RunsOn: compute.RuntimeContainer})
	if !errors.Is(err, compute.ErrTransient) {
		t.Errorf("a conflict the provider could not absorb surfaced as %v, want ErrTransient", err)
	}
	if errors.Is(err, compute.ErrNotOwned) {
		t.Error("a stale-read conflict matched ErrNotOwned, which would tell the caller its " +
			"deploy collided with somebody else's infrastructure")
	}
	if errors.Is(err, compute.ErrFailed) {
		t.Error("a stale-read conflict matched ErrFailed, which is documented as not retryable")
	}
}

// alwaysConflict never lets an apply through, so the provider exhausts its
// budget and has to surface the failure.
type alwaysConflict struct{ k8s.Cluster }

func (c *alwaysConflict) Apply(context.Context, schema.GroupVersionKind, runtime.Object) error {
	return k8s.ErrOptimisticConcurrency
}

// --- Finding 3 -------------------------------------------------------------------

// TestIdentityAndSecretCannotCrossAPlacement shows the consequence of
// WorkloadIdentitySpec and SecretSpec carrying no Placement.
//
// Both become namespace-scoped Kubernetes objects. A pod may only run as a
// ServiceAccount in its own namespace and may only resolve a secretKeyRef in
// its own namespace, so a workload placed anywhere but the provider's default
// placement cannot use either. The provider refuses rather than copying secret
// material into a second namespace.
func TestIdentityAndSecretCannotCrossAPlacement(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	identity := mustIdentity(t, p, "app")

	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	secret, err := store.Put(ctx, compute.SecretSpec{
		Name: "db-password", Scope: "app-1", Value: compute.NewSecretValue("s3cret"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	spec := compute.ServiceSpec{
		Name:      "api",
		Placement: compute.Placement{Name: "secondary"},
		Image:     "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
		Replicas:  1,
		Identity:  identity,
		Secrets:   []compute.SecretBinding{{EnvName: "DB_PASSWORD", Secret: secret.Ref}},
	}
	_, err = rt.EnsureService(ctx, spec)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("a workload in another placement should be refused with ErrInvalidSpec, got %v", err)
	}
	if !strings.Contains(err.Error(), "namespace") {
		t.Errorf("the refusal should say why: %v", err)
	}
}

// --- Finding 4 and 7 --------------------------------------------------------------

// TestRouteFailsClosedWithoutOperatorTLSAndAuth checks the TLS and ingress
// authentication boundaries independently. Route TLS must resolve to a
// certificate (or explicitly allow plaintext). Kubernetes Ingress alone cannot
// enforce Route.RequireAuth: neither a configured ingress class nor the
// presence of an ingress proxy turns provider-owned annotations into a
// controller-enforced authentication mechanism.
func TestRouteFailsClosedWithoutOperatorTLSAndAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	base := func(cfg k8s.Config, route compute.Route) error {
		p, _ := newProvider(t, cfg)
		identity := mustIdentity(t, p, "app")
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers: %v", err)
		}
		_, err = rt.EnsureService(ctx, compute.ServiceSpec{
			Name:      "api",
			Image:     "registry.invalid/apphub/app:v1",
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  1,
			Ports:     []compute.PortSpec{{Number: 8080}},
			Identity:  identity,
			Routes:    []compute.Route{route},
		})
		if err != nil {
			for _, line := range rendered(t, p) {
				if strings.HasPrefix(line, "Ingress ") {
					t.Errorf("refused route published an Ingress: %s", line)
				}
			}
		}
		return err
	}

	// A route that names no certificate and does not allow plaintext fails
	// closed. Before F4 this refusal came from operator configuration, because
	// Route had no certificate field and refusing was the only alternative to
	// serving an application over HTTP; it is the interface's rule now.
	err := base(fullConfig(), compute.Route{Host: "app.invalid", TargetPort: 8080})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a route with no certificate and no AllowPlaintext should fail closed, got %v", err)
	}
	err = base(fullConfig(), compute.Route{Host: "app.invalid", TargetPort: 8080,
		TLS: &compute.TLSConfig{CertificateRef: "no-such-certificate"}})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("an unresolvable route certificate should be refused, got %v", err)
	}
	if err := base(fullConfig(), compute.Route{
		Host: "app.invalid", TargetPort: 8080, AllowPlaintext: true,
	}); err != nil {
		t.Errorf("a route that explicitly allows plaintext should be accepted: %v", err)
	}

	withoutIngress := fullConfig()
	withoutIngress.IngressProxy = k8s.PodSelector{}
	placement := withoutIngress.Placements["default"]
	placement.IngressClassName = ""
	withoutIngress.Placements["default"] = placement
	for _, cfg := range []k8s.Config{fullConfig(), withoutIngress} {
		p, _ := newProvider(t, cfg)
		if p.Capabilities().Has(compute.CapIngressAuth) {
			t.Errorf("provider %q advertises authentication without controller-enforced auth", p.Name())
		}
		for _, route := range []compute.Route{
			{Host: "app.invalid", TargetPort: 8080, RequireAuth: true, TLS: &compute.TLSConfig{CertificateRef: "cert-default"}},
			{Host: "app.invalid", TargetPort: 8080, RequireAuth: true, PublicPaths: []string{"/healthz"}, TLS: &compute.TLSConfig{CertificateRef: "cert-default"}},
		} {
			err := base(cfg, route)
			var unsupported *compute.UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Capability != compute.CapIngressAuth {
				t.Errorf("RequireAuth route (public paths %v) should be refused for CapIngressAuth, got %v", route.PublicPaths, err)
			}
		}
	}
	if err := base(fullConfig(), compute.Route{Host: "app.invalid", TargetPort: 8080,
		PublicPaths: []string{"/healthz"}, TLS: &compute.TLSConfig{CertificateRef: "cert-default"}}); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("PublicPaths without RequireAuth should be invalid, got %v", err)
	}
}

// An internal route must never share the public Ingress, including when it
// appears after a valid public route or updates an existing service.
func TestInternalRoutesCannotPublishOrMutateService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	public := compute.Route{Host: "public.invalid", TargetPort: 8080, AllowPlaintext: true}
	internal := compute.Route{Host: "private.invalid", TargetPort: 8080, AllowPlaintext: true, Internal: true}

	for _, tc := range []struct {
		name     string
		routes   []compute.Route
		existing bool
	}{
		{name: "internal alone", routes: []compute.Route{internal}},
		{name: "public then internal", routes: []compute.Route{public, internal}},
		{name: "internal then public", routes: []compute.Route{internal, public}},
		{name: "existing public service", routes: []compute.Route{public, internal}, existing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newProvider(t, fullConfig())
			identity := mustIdentity(t, p, "app")
			rt, err := p.Containers()
			if err != nil {
				t.Fatalf("Containers: %v", err)
			}
			spec := compute.ServiceSpec{
				Name: "api", Image: "registry.invalid/apphub/app:v1",
				Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
				Replicas:  1, Ports: []compute.PortSpec{{Number: 8080}},
				Identity: identity, Routes: []compute.Route{public},
			}
			if tc.existing {
				if _, err := rt.EnsureService(ctx, spec); err != nil {
					t.Fatalf("public route should be accepted: %v", err)
				}
				findRendered(t, p, "Ingress apphub-apps/svc-api:")
			}
			before := rendered(t, p)
			spec.Routes = tc.routes
			spec.Image = "registry.invalid/apphub/app:v2"
			if _, err := rt.EnsureService(ctx, spec); !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("internal route should be refused with ErrInvalidSpec, got %v", err)
			}
			if after := rendered(t, p); !reflect.DeepEqual(after, before) {
				t.Errorf("refused route mutated resources:\nbefore: %v\nafter: %v", before, after)
			}
		})
	}

	t.Run("public route", func(t *testing.T) {
		p, _ := newProvider(t, fullConfig())
		identity := mustIdentity(t, p, "app")
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers: %v", err)
		}
		_, err = rt.EnsureService(ctx, compute.ServiceSpec{
			Name: "api", Image: "registry.invalid/apphub/app:v1",
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  1, Ports: []compute.PortSpec{{Number: 8080}},
			Identity: identity, Routes: []compute.Route{public},
		})
		if err != nil {
			t.Fatalf("public route should be accepted: %v", err)
		}
		line := findRendered(t, p, "Ingress apphub-apps/svc-api:")
		if !strings.Contains(line, public.Host) {
			t.Errorf("public host %q missing from Ingress: %s", public.Host, line)
		}
	})
}

// --- Finding 5 and 8 --------------------------------------------------------------

// TestPlainClusterDeclinesFunctionEndpoints shows what ListenerSpec costs.
//
// A listener is a port plus an optional certificate. networking.k8s.io/v1
// Ingress can express neither: it is served on whatever ports the controller
// listens on, and its TLS section is keyed by hostname. So a provider with only
// an Ingress controller must decline the capability outright — and the Gateway
// API, which can express it, has the protocol field compute.ListenerSpec lacks.
func TestPlainClusterDeclinesFunctionEndpoints(t *testing.T) {
	t.Parallel()
	cfg := ingressOnlyConfig()
	cfg.FunctionRuntimes = fullConfig().FunctionRuntimes // functions, but no Gateway API
	p, _ := newProvider(t, cfg)

	if p.Capabilities().Has(compute.CapFunctionEndpoint) {
		t.Fatal("a cluster with no Gateway API must not advertise function endpoints")
	}
	fns, err := p.Functions()
	if err != nil {
		t.Fatalf("Functions: %v", err)
	}
	_, err = fns.EnsureEndpoint(context.Background(), compute.EndpointSpec{
		Name:      "api",
		Target:    compute.Ref{Provider: p.Name(), Kind: compute.KindFunction, ID: "functions/apphub-apps/fn-api"},
		Listeners: []compute.ListenerSpec{{Port: 8443, Protocol: compute.ListenerHTTPS, TLS: &compute.TLSConfig{CertificateRef: "cert-default"}}},
	})
	if !errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("the refusal should be ErrUnsupported, got %v", err)
	}
}

// --- Finding 8 --------------------------------------------------------------------

// TestScheduledJobIsLiveOnAcceptance is the evidence for reclassifying the port.
//
// compute.ScheduledJobStatus embeds compute.Status, which puts the port in the
// asynchronous class, but compute.ContainerRuntime has no WaitForScheduledJob.
// On this substrate that is not an omission to fill: a CronJob is live the
// moment the API server accepts it, there is no readiness condition, and a Wait
// would have nothing to wait for.
func TestScheduledJobIsLiveOnAcceptance(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	st, err := rt.EnsureScheduledJob(ctx, compute.ScheduledJobSpec{
		Name:      "nightly",
		Schedule:  compute.Schedule{Expression: "0 3 * * *", Timezone: "UTC"},
		Image:     "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 250, MemoryMiB: 256},
		Identity:  mustIdentity(t, p, "app"),
	})
	if err != nil {
		t.Fatalf("EnsureScheduledJob: %v", err)
	}
	if st.Ref.IsZero() {
		t.Fatal("EnsureScheduledJob returned no reference")
	}
	// A descriptor, not a phase: the port is synchronous since F8 landed, so
	// the resource is usable when the call returns and there is nothing to poll.
	if st.Schedule.Expression != "0 3 * * *" {
		t.Errorf("the effective schedule is %q, want the one that was asked for",
			st.Schedule.Expression)
	}
	if st.Spec.Name != "nightly" {
		t.Errorf("the descriptor carries no effective spec: %+v", st.Spec)
	}
	if err := rt.DeleteScheduledJob(ctx, st.Ref); err != nil {
		t.Fatalf("DeleteScheduledJob: %v", err)
	}
	if _, err := rt.DescribeScheduledJob(ctx, st.Ref); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("describing a deleted scheduled job returned %v, want compute.ErrNotFound", err)
	}
}

// TestRateSchedulesConvertExactlyOrAreRefused pins the one place the schedule
// grammar is a real translation.
func TestRateSchedulesConvertExactlyOrAreRefused(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	job := func(name, expr string) error {
		_, err := rt.EnsureScheduledJob(ctx, compute.ScheduledJobSpec{
			Name:      name,
			Schedule:  compute.Schedule{Expression: expr},
			Image:     "registry.invalid/apphub/app:v1",
			Resources: compute.Resources{CPUMillicores: 250, MemoryMiB: 256},
			Identity:  identity,
		})
		return err
	}
	if err := job("every-15", "rate(15 minutes)"); err != nil {
		t.Errorf("rate(15 minutes) divides an hour exactly and should convert: %v", err)
	}
	findRendered(t, p, "schedule=*/15 * * * *")
	if err := job("every-7", "rate(7 minutes)"); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("rate(7 minutes) has no exact cron equivalent and must be refused, got %v", err)
	}
}

// --- Finding 11 and 12 ------------------------------------------------------------

// TestFunctionReachabilityIsSplitAcrossTwoCalls shows what FunctionSpec's
// missing Ingress field costs.
//
// Every other workload spec carries reachability. A function does not, which is
// right for Lambda and wrong for a pod: with no NetworkPolicy a function pod is
// reachable by everything in the cluster. So the provider writes a default-deny
// policy from the function spec, and EnsureEndpoint's documented "grants the
// endpoint permission to invoke it" has to be a *second* policy — because if the
// two shared an object the next EnsureFunction would reconcile the invoke rule
// away, and the function spec has no way to declare it.
func TestFunctionReachabilityIsSplitAcrossTwoCalls(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	fns, err := p.Functions()
	if err != nil {
		t.Fatalf("Functions: %v", err)
	}
	fn, err := fns.EnsureFunction(ctx, compute.FunctionSpec{
		Name: "api", Runtime: "python-3.12", Handler: "index.handler",
		Code: compute.CodeSource{Inline: []byte("bundle")}, Resources: compute.Resources{MemoryMiB: 512}, Timeout: 30 * time.Second,
		Identity: mustIdentity(t, p, "app"),
	})
	if err != nil {
		t.Fatalf("EnsureFunction: %v", err)
	}
	// Default-deny: a policy with no ingress rules at all.
	line := findRendered(t, p, "NetworkPolicy apphub-apps/fn-api:")
	if !strings.Contains(line, "ingressFrom= ") && !strings.HasSuffix(line, "ingressFrom=") {
		t.Errorf("a function's own policy should be default-deny, got %s", line)
	}

	ep, err := fns.EnsureEndpoint(ctx, compute.EndpointSpec{
		Name: "api", Target: fn.Ref,
		Listeners: []compute.ListenerSpec{{Port: 443, Protocol: compute.ListenerHTTPS, TLS: &compute.TLSConfig{CertificateRef: "cert-default"}}},
		Ingress:   []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 443}},
	})
	if err != nil {
		t.Fatalf("EnsureEndpoint: %v", err)
	}
	// The invoke permission is a separate object, named for the endpoint.
	findRendered(t, p, "NetworkPolicy apphub-apps/ep-api:")

	// Re-ensuring the function must not remove it, which is only true because
	// the two live in different objects.
	if _, err := fns.EnsureFunction(ctx, compute.FunctionSpec{
		Name: "api", Runtime: "python-3.12", Handler: "index.handler",
		Code: compute.CodeSource{Inline: []byte("bundle-2")}, Resources: compute.Resources{MemoryMiB: 512}, Timeout: 30 * time.Second,
		Identity: mustIdentity(t, p, "app"),
	}); err != nil {
		t.Fatalf("second EnsureFunction: %v", err)
	}
	findRendered(t, p, "NetworkPolicy apphub-apps/ep-api:")
	_ = ep
}

// TestNoWorkloadPolicyRestrictsEgress records that the interface models none.
//
// A NetworkPolicy that named policyTypes [Ingress, Egress] with no egress rules
// would be deny-all outbound and would cut every application off from its own
// database. The interface has no egress vocabulary, so the provider must leave
// egress entirely to whatever the cluster does by default — which means that in
// a default-deny-egress cluster, the interface's inputs are not sufficient to
// make an application reach the database it was just given.
func TestNoWorkloadPolicyRestrictsEgress(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name: "api", Image: "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512}, Replicas: 1,
		Ports:    []compute.PortSpec{{Number: 8080}},
		Identity: mustIdentity(t, p, "app"),
		Ingress:  []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080}},
	}); err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	line := findRendered(t, p, "NetworkPolicy apphub-apps/svc-api:")
	if !strings.Contains(line, "policyTypes=Ingress ") {
		t.Errorf("the policy should carry Ingress only, got %s", line)
	}
	if strings.Contains(line, "Egress") {
		t.Errorf("the interface models no egress, so the provider must not write an egress "+
			"section: %s", line)
	}
}

// --- Finding 13 and 15 ------------------------------------------------------------

// TestResourcesBecomeBothRequestsAndLimits records the collapse.
//
// compute.Resources is one number per dimension. Kubernetes has two — a request,
// which is what the scheduler reserves, and a limit, which is what the kernel
// enforces — and the gap between them is the difference between Burstable and
// Guaranteed QoS. A provider given one number has to set both, which makes every
// apphub workload Guaranteed: a scheduling and cost decision the caller never
// made.
func TestResourcesBecomeBothRequestsAndLimits(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name: "api", Image: "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512}, Replicas: 1,
		Identity: mustIdentity(t, p, "app"),
	}); err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	line := findRendered(t, p, "Deployment apphub-apps/svc-api:")
	if !strings.Contains(line, "cpuRequest=500m") || !strings.Contains(line, "memRequest=512Mi") {
		t.Errorf("the allocation should reach the pod exactly, got %s", line)
	}
}

// TestCapacityRangeIsATranslationAndSaysSo pins the direction of the loss.
//
// The design document says CapacityRange is a translation rather than an
// equivalence. What it does not say is which way the loss goes: the operators
// surveyed take fixed requests and limits, not a range, so nothing scales
// between the two numbers. The provider reports that in Status.Message, which is
// the only channel the interface offers.
func TestCapacityRangeIsATranslationAndSaysSo(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rp, err := p.Relational()
	if err != nil {
		t.Fatalf("Relational: %v", err)
	}
	st, err := rp.EnsureRelational(ctx, compute.RelationalSpec{
		Name: "app", Engine: compute.EnginePostgres, EngineVersion: "16",
		DatabaseName: "app", AdminUsername: "admin",
		AdminPassword: compute.NewSecretValue("hunter2"),
		Capacity:      compute.CapacityRange{MinUnits: 0.5, MaxUnits: 4},
	})
	if err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	if !strings.Contains(st.Message, "does not scale") {
		t.Errorf("the status should say the range was translated to fixed sizing, got %q", st.Message)
	}
	line := findRendered(t, p, "Cluster apphub-apps/db-app:")
	for _, want := range []string{"request.cpu=500m", "limit.cpu=4000m", "capacity=0.5-4"} {
		if !strings.Contains(line, want) {
			t.Errorf("rendered cluster missing %q: %s", want, line)
		}
	}
}

// --- Finding 17 -------------------------------------------------------------------

// TestRunsOnHasNoMeaningOnThisSubstrate records the aliasing.
//
// RunsOn exists because an AWS role trusted by ecs-tasks.amazonaws.com cannot be
// assumed by Lambda. A ServiceAccount has no such restriction, so a Kubernetes
// provider either invents a distinction by encoding RunsOn into the object name
// or ignores it and lets two logically distinct identities alias. This one
// ignores it, and the aliasing is visible here rather than only in production.
func TestRunsOnHasNoMeaningOnThisSubstrate(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	container, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(container): %v", err)
	}
	fn, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: compute.RuntimeFunction,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(function): %v", err)
	}
	if container.Ref != fn.Ref {
		t.Fatalf("this provider is expected to ignore RunsOn, but produced %s and %s",
			container.Ref, fn.Ref)
	}
	if container.Attestation.Subject != "system:serviceaccount:apphub-apps:app" {
		t.Errorf("unexpected subject %q", container.Attestation.Subject)
	}
}

// --- Finding 20 -------------------------------------------------------------------

// TestBuildContextIsReadLocallyAndConfined records the transport obligation and
// keeps the source system's path-confinement check.
func TestBuildContextIsReadLocallyAndConfined(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder: %v", err)
	}

	var logs strings.Builder
	if _, err := builder.Build(ctx, compute.BuildRequest{
		Source: compute.BuildSource{ContextDir: dir},
	}); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a build with no destination should be refused, got %v", err)
	}

	res, err := builder.Build(ctx, compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir},
		Destinations: []compute.ImageRef{compute.ImageRef(repo.Prefix + ":v1")},
		Logs:         &logs,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Digest == "" {
		t.Error("the build should report a content digest")
	}
	if !strings.Contains(logs.String(), "packing build context") {
		t.Errorf("the provider has to transport the context into the cluster and should say so: %q",
			logs.String())
	}

	// The escape the source system guards against.
	_, err = builder.Build(ctx, compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir, Dockerfile: "../Dockerfile"},
		Destinations: []compute.ImageRef{compute.ImageRef(repo.Prefix + ":v1")},
	})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a Dockerfile outside the context should be refused, got %v", err)
	}

	// And a destination in somebody else's registry must not get credentials.
	_, err = builder.Build(ctx, compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir},
		Destinations: []compute.ImageRef{"elsewhere.invalid/someone/app:v1"},
	})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a destination outside the configured registry should be refused, got %v", err)
	}
}

// --- Finding 25 -------------------------------------------------------------------

// TestExecEnabledIsOneWayOnThisSubstrate records the asymmetry.
//
// compute.ServiceSpec.ExecEnabled is a bool, so it has two states, and
// compute.CapWorkloadExec makes the true state discoverable. Only one of the two
// is enforceable here: a pod is exec-able whenever the *caller's* RBAC permits
// it, and there is nothing a provider can put on a Deployment to make it not be.
// So ExecEnabled: false is silently a no-op, and a provider that advertises the
// capability is telling the truth about true and nothing at all about false.
//
// Both halves are asserted, because the second is the one that makes the first
// a finding rather than an implementation detail.
func TestExecEnabledIsOneWayOnThisSubstrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Half one: the flag changes nothing the provider writes. If a future
	// implementation ever made it do something, this goes red and the finding
	// needs revisiting.
	render := func(exec bool) string {
		p, _ := newProvider(t, fullConfig())
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers: %v", err)
		}
		if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
			Name: "api", Image: "registry.invalid/apphub/app:v1",
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512}, Replicas: 1,
			Identity: mustIdentity(t, p, "app"), ExecEnabled: exec,
		}); err != nil {
			t.Fatalf("EnsureService(exec=%t): %v", exec, err)
		}
		return findRendered(t, p, "Deployment apphub-apps/svc-api:")
	}
	if on, off := render(true), render(false); on != off {
		t.Errorf("ExecEnabled appears to do something on this substrate, which contradicts the "+
			"report:\n  true:  %s\n  false: %s", on, off)
	}

	// Half two: and here is why it cannot. Exec is authorised by RBAC on the
	// principal opening the session, which this provider does not own and the
	// interface deliberately places outside itself. Bind pods/exec to a
	// principal and it reaches a workload whose ExecEnabled is false -- so
	// `false` is not a statement a caller can rely on.
	p, sub := newProvider(t, fullConfig())
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	identity := mustIdentity(t, p, "app")
	closed, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name: "closed", Image: "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512}, Replicas: 1,
		Identity: identity, ExecEnabled: false,
	})
	if err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	if can, err := p.Harness().CanExecInto(ctx, identity, closed.Ref); err != nil {
		t.Fatalf("CanExecInto: %v", err)
	} else if can {
		t.Fatal("nothing has been granted pods/exec yet, so nothing should be able to open a session")
	}

	// An operator's RoleBinding, which no compute spec describes and no provider
	// method writes.
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apphub-apps", Name: "operators-may-exec"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "apphub-operator"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "platform-operators"}},
	}
	gvk := schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}
	if err := sub.Cluster.Apply(ctx, gvk, binding); err != nil {
		t.Fatalf("applying the operator RoleBinding: %v", err)
	}
	can, err := p.Harness().CanExecInto(ctx, identity, closed.Ref)
	if err != nil {
		t.Fatalf("CanExecInto: %v", err)
	}
	if !can {
		t.Error("a pods/exec binding should make the workload reachable for a session even " +
			"though its ExecEnabled is false; if it does not, this substrate can enforce the " +
			"false state after all and F25 should be struck")
	}
}

// --- Findings with a structural assertion ------------------------------------------
//
// These check a shape rather than a behaviour, because the finding is about
// something the interface does not have. Each fails once the corresponding
// amendment lands, which is deliberate: the failure message says so, and the
// finding should be struck from docs/design/k8s-contract-probe.md in the same
// change that turns the test red.

// --- Findings with a behavioural assertion ------------------------------------------

// TestLabelsBecomeAnAnnotationAndStopBeingSelectable is F16.
//
// A Kubernetes label value is at most 63 characters of [A-Za-z0-9._-]. The
// interface promises nothing of the sort, so a provider that copied caller
// labels across would reject specs the interface says are valid. Annotation keys
// have the same grammar as label keys, so one-annotation-each does not work
// either. Everything ends up escaped into a single annotation and stops being
// selectable, which is half of what "ownership tagging" means here.
func TestLabelsBecomeAnAnnotationAndStopBeingSelectable(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	long := strings.Repeat("x", 200)
	if _, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: compute.RuntimeContainer,
		// Legal per the interface; illegal as a Kubernetes label value and as an
		// annotation key respectively.
		Labels: map[string]string{"owner": long, "a/b/c": "yes"},
	}); err != nil {
		t.Fatalf("the interface permits these labels, so the provider must too: %v", err)
	}
	line := findRendered(t, p, "ServiceAccount apphub-apps/app:")
	if !strings.Contains(line, "a/b/c=yes") || !strings.Contains(line, "owner="+long) {
		t.Errorf("both labels should survive, escaped into one annotation: %s", line)
	}
}

// TestDeletingAnIdentityCascadesAcrossThreeSubstrates is F18.
//
// compute.IdentityService.DeleteWorkloadIdentity is documented as removing "an
// identity and every grant made to it". On AWS that is free: the grants are
// inline policies on the role. Here they are in the object store's policy
// document and in the registry, two systems the identity port does not own. This
// provider can reach all three, so it cascades — and the cascade is the finding.
func TestDeletingAnIdentityCascadesAcrossThreeSubstrates(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	identity := mustIdentity(t, p, "app")

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	if err := store.Grant(ctx, bucket.Ref, identity, compute.AccessReadWrite); err != nil {
		t.Fatalf("Grant(bucket): %v", err)
	}
	if err := regGranter(t, p, reg).GrantPull(ctx, repo.Ref, identity); err != nil {
		t.Fatalf("Grant(repository): %v", err)
	}
	if err := p.Harness().Read(ctx, bucket.Ref, identity); err != nil {
		t.Fatalf("the bucket grant should work before the delete: %v", err)
	}
	if err := p.Harness().Read(ctx, repo.Ref, identity); err != nil {
		t.Fatalf("the repository grant should work before the delete: %v", err)
	}

	if err := p.Identities().DeleteWorkloadIdentity(ctx, identity); err != nil {
		t.Fatalf("DeleteWorkloadIdentity: %v", err)
	}
	if err := p.Harness().Read(ctx, bucket.Ref, identity); err == nil {
		t.Error("the object-store grant outlived the identity")
	}
	if err := p.Harness().Read(ctx, repo.Ref, identity); err == nil {
		t.Error("the registry grant outlived the identity")
	}
}

// TestFunctionCarriesALambdaHandlerAndADerivedCPU is F19.
func TestFunctionCarriesALambdaHandlerAndADerivedCPU(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	fns, err := p.Functions()
	if err != nil {
		t.Fatalf("Functions: %v", err)
	}
	if _, err := fns.EnsureFunction(ctx, compute.FunctionSpec{
		Name: "api", Runtime: "python-3.12", Handler: "index.handler",
		Code: compute.CodeSource{Inline: []byte("bundle")}, Resources: compute.Resources{MemoryMiB: 1769},
		Timeout: 30 * time.Second, Identity: mustIdentity(t, p, "app"),
	}); err != nil {
		t.Fatalf("EnsureFunction: %v", err)
	}
	line := findRendered(t, p, "Deployment apphub-apps/fn-api:")
	// The handler survives only as an out-of-band convention with the image.
	if !strings.Contains(line, "APPHUB_FUNCTION_HANDLER=index.handler") {
		t.Errorf("the handler has nowhere to go but an environment variable: %s", line)
	}
	// 1769 MiB is one vCPU on Lambda, and resource.Quantity renders 1000m as
	// "1". FunctionSpec has no CPU field, so the provider reproduces that
	// ratio -- an AWS fact inside a Kubernetes pod spec.
	if !strings.Contains(line, "cpuRequest=1 ") {
		t.Errorf("the CPU allocation should be derived with Lambda's memory ratio: %s", line)
	}
}

// TestPeerInternetIsWiderHereThanASecurityGroup is F21.
func TestPeerInternetIsWiderHereThanASecurityGroup(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name: "api", Image: "registry.invalid/apphub/app:v1",
		Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512}, Replicas: 1,
		Ports: []compute.PortSpec{{Number: 8080}}, Identity: mustIdentity(t, p, "app"),
		Ingress: []compute.IngressRule{{From: compute.Peer{Kind: compute.PeerInternet}, Port: 8080}},
	}); err != nil {
		t.Fatalf("EnsureService: %v", err)
	}
	// A NetworkPolicy cannot say "from outside the cluster", so the rule the
	// caller meant as public also admits every pod in the cluster.
	line := findRendered(t, p, "NetworkPolicy apphub-apps/svc-api:")
	if !strings.Contains(line, "0.0.0.0/0") {
		t.Errorf("PeerInternet compiles to an ipBlock: %s", line)
	}
}

// TestOneProviderNameCoversFourSubstrates is F22.
func TestOneProviderNameCoversFourSubstrates(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	identity := mustIdentity(t, p, "app")

	// The bucket is in an object store, the repository is in a registry, and the
	// ServiceAccount is in the cluster. All three refs claim one provider, so a
	// Ref persisted today survives the operator swapping any one of them out.
	for _, ref := range []compute.Ref{bucket.Ref, repo.Ref, identity} {
		if ref.Provider != "kubernetes" {
			t.Errorf("%s does not claim the provider name", ref)
		}
	}
}

// --- The confirmation USOSS-27 was asked for ---------------------------------------

// awsNetworkWords are the identifiers that must not be needed to drive this
// interface, mirroring the conformance suite's structural check.
var awsNetworkWords = []string{
	"subnet", "vpc", "securitygroup", "accountid", "arn", "cidr",
	"loadbalancer", "targetgroup", "clusterarn", "instanceid", "parameterstore",
}

// configInventory is every leaf field an operator can set on [k8s.Config],
// pinned.
//
// This list is the actual confirmation that no substrate network identifier is
// required, and it is a pinned inventory rather than a name scan for a reason a
// reviewer found the hard way: a name scan passes for a field called `Network`.
// Matching names catches a field called `SubnetIDs` and nothing else, which
// makes it a regression heuristic and not a proof.
//
// What the inventory proves is narrower and actually true: this is the complete
// set of things an operator supplies to drive every Compute port on Kubernetes,
// it was reviewed field by field, and none of it is a network object identity.
// Adding a field fails this test, which forces the same review again. That is
// the strongest mechanical form the claim has, because "is this a network
// identifier" is a judgement rather than a predicate.
var configInventory = []string{
	"Config.BuildKit bool",
	"Config.Certificates map[string]string",
	"Config.ControlPlane.Labels map[string]string",
	"Config.ControlPlane.Namespace string",
	"Config.DefaultPlacement string",
	"Config.EndpointDomain string",
	"Config.FunctionRuntimes map[string]string",
	"Config.GatewayAPI bool",
	"Config.IngressAddress string",
	"Config.IngressProxy.Labels map[string]string",
	"Config.IngressProxy.Namespace string",
	"Config.KubeletCredentialProvider bool",
	"Config.MaxInlineBundleBytes int",
	"Config.Name string",
	"Config.OIDCAudience string",
	"Config.OIDCIssuer string",
	"Config.ObjectStore.Endpoint string",
	"Config.ObjectStore.TrustsClusterOIDC bool",
	"Config.ObjectStore.URIScheme string",
	"Config.Placements[].IngressClassName string",
	"Config.Placements[].Name string",
	"Config.Placements[].Namespace string",
	"Config.Placements[].NodeSelector map[string]string",
	"Config.Placements[].StorageClass string",
	"Config.PostgresOperator.APIVersion string",
	"Config.PostgresOperator.InstanceMiBPerUnit int",
	"Config.PostgresOperator.InstanceMillicoresPerUnit int",
	"Config.PostgresOperator.Kind string",
	"Config.PostgresOperator.Versions []string",
	"Config.Registry.FederatesClusterOIDC bool",
	"Config.Registry.Host string",
	"Config.Registry.Project string",
	"Config.Registry.SupportsRetention bool",
	"Config.Registry.SupportsScanning bool",
}

// TestConfigInventoryIsPinned is the complement to the conformance suite's scan
// over compute's spec types.
//
// The suite checks that no field a *caller* fills in names a network object.
// That is necessary but not sufficient: an interface could still be unusable
// without an identifier smuggled through a string. This checks the other
// direction — everything an *operator* must supply for a non-AWS provider to
// satisfy every port — and finds no network object identity there either.
//
// It fails when a field is added, removed, or renamed. That is the point: the
// judgement it encodes cannot be automated, so the test forces it to be made
// again by a human in a reviewable diff.
func TestConfigInventoryIsPinned(t *testing.T) {
	t.Parallel()
	got := inventory(reflect.TypeOf(k8s.Config{}), "Config", nil)
	sort.Strings(got)
	want := append([]string(nil), configInventory...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("k8s.Config's field inventory changed.\n  got:\n    %s\n  want:\n    %s\n\n"+
			"Every entry is something an operator must supply to drive a Compute port on "+
			"Kubernetes, and the claim USOSS-27 makes is that none of it is a substrate network "+
			"identifier. Re-make that judgement for the changed field, then update "+
			"configInventory and docs/design/k8s-contract-probe.md.",
			strings.Join(got, "\n    "), strings.Join(want, "\n    "))
	}
}

// inventory renders every leaf field of a struct type as "path type", descending
// through pointers, slices, and map values.
//
// stack is the chain of struct types currently being walked, and exists only to
// stop a recursive type from looping. It is deliberately not a global visited
// set: PodSelector appears twice in Config, under IngressProxy and under
// ControlPlane, and both occurrences are things an operator configures.
func inventory(typ reflect.Type, path string, stack []reflect.Type) []string {
	typ = deref(typ)
	if typ.Kind() != reflect.Struct || slices.Contains(stack, typ) {
		return nil
	}
	stack = append(stack, typ)
	var out []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		child := deref(f.Type)
		switch {
		case child.Kind() == reflect.Struct:
			out = append(out, inventory(child, path+"."+f.Name, stack)...)
		case child.Kind() == reflect.Map && deref(child.Elem()).Kind() == reflect.Struct:
			out = append(out, inventory(child.Elem(), path+"."+f.Name+"[]", stack)...)
		default:
			out = append(out, path+"."+f.Name+" "+f.Type.String())
		}
	}
	return out
}

func deref(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

// TestNoAWSNetworkIdentifierFieldName is a regression heuristic, and is labelled
// as one because it is not a proof.
//
// It catches a field called SubnetIDs. It does not catch a field called
// Network — a reviewer demonstrated exactly that against an earlier version of
// this file, and the conclusion it was cited for is carried by
// [TestConfigInventoryIsPinned] instead. It is kept because a name scan is still
// the cheapest way to catch the obvious mistake.
func TestNoAWSNetworkIdentifierFieldName(t *testing.T) {
	t.Parallel()
	seen := map[reflect.Type]bool{}
	scanFields(t, reflect.TypeOf(k8s.Config{}), "k8s.Config", seen)
}

func scanFields(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
		typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := range typ.NumField() {
		f := typ.Field(i)
		lower := strings.ToLower(f.Name)
		for _, word := range awsNetworkWords {
			if strings.Contains(lower, word) {
				t.Errorf("%s.%s names %q; a Kubernetes provider that needed an AWS network "+
					"identifier would mean the placement model is nominal", path, f.Name, word)
			}
		}
		scanFields(t, f.Type, path+"."+f.Name, seen)
	}
}

// TestTheAmendedInterfaceClosedTheseFindings replaces five tests that pinned
// gaps this amendment closed.
//
// Each of them said, in its own failure message, "if this fails the amendment
// has landed: strike the finding and delete this test". It landed. They are
// replaced rather than deleted so that the closure is pinned too: a revert would
// otherwise be silent.
func TestTheAmendedInterfaceClosedTheseFindings(t *testing.T) {
	t.Parallel()

	// F9: the registry has a read-back.
	if _, ok := reflect.TypeOf((*compute.ImageRegistry)(nil)).Elem().MethodByName("DescribeRepository"); !ok {
		t.Error("compute.ImageRegistry lost DescribeRepository; nothing above the interface can " +
			"ask whether a repository exists or whether a delete took effect")
	}

	// F6: every read-back carries the effective spec the provider is converging
	// to. It is the provider's own report — see compute.Status on what that does
	// and does not establish — but the interface exposing nothing at all was the
	// finding.
	specs := map[string]any{
		"ServiceStatus":      compute.ServiceStatus{},
		"ScheduledJobStatus": compute.ScheduledJobStatus{},
		"FunctionStatus":     compute.FunctionStatus{},
		"EndpointStatus":     compute.EndpointStatus{},
		"RelationalStatus":   compute.RelationalStatus{},
		"KeyValueStatus":     compute.KeyValueStatus{},
		"Bucket":             compute.Bucket{},
		"Repository":         compute.Repository{},
		"WorkloadIdentity":   compute.WorkloadIdentity{},
	}
	for name, v := range specs {
		if _, ok := reflect.TypeOf(v).FieldByName("Spec"); !ok {
			t.Errorf("%s no longer carries its effective spec", name)
		}
	}

	// F10, F13, F14: readiness, route addresses, and a caller-chosen endpoint
	// hostname.
	fields := []struct {
		typ        any
		field, why string
	}{
		{compute.ServiceSpec{}, "Readiness",
			`"serving" meant a different thing on every substrate`},
		{compute.ServiceStatus{}, "RouteAddresses",
			"a caller that cannot learn the address cannot delegate DNS either"},
		{compute.EndpointSpec{}, "Hostnames",
			"the caller chose the certificate and the provider chose the name it was served under"},
	}
	for _, f := range fields {
		rt := reflect.TypeOf(f.typ)
		if _, ok := rt.FieldByName(f.field); !ok {
			t.Errorf("%s.%s is gone: %s", rt.Name(), f.field, f.why)
		}
	}
}

// TestGrantRefusalNamesTheMissingCapability reproduces the reviewer's fixture
// for the conformance blocker.
//
// With the object store not federating the cluster's issuer the provider
// correctly omits CapWorkloadGrants — but the suite scheduled the positive grant
// checks from the port shape alone, so it demanded a Grant the provider had said
// it could not do, and the refusal named CapObjectStore (which the provider has)
// rather than the capability that was missing.
// TestTheGrantReadBackRefusesRatherThanReportingNoGrant is the read-back's half
// of the same rule, and the reason it is a separate test is that the tempting
// implementation is not a refusal at all.
//
// A store that does not federate the cluster's issuer holds no grants. So
// "return no grant" looks like a true answer, and it is the wrong one: it is
// indistinguishable from a store that was consulted and had none, and a caller
// reconciling on it keeps issuing grants nothing can express while being told
// each time that none stand. The refusal has to name CapWorkloadGrants for the
// same reason Grant's does.
func TestTheGrantReadBackRefusesRatherThanReportingNoGrant(t *testing.T) {
	t.Parallel()
	cfg := fullConfig()
	cfg.ObjectStore.TrustsClusterOIDC = false
	p, _ := newProvider(t, cfg)
	ctx := context.Background()

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	info, err := store.DescribeGrant(ctx, bucket.Ref, mustIdentity(t, p, "app"))
	if errors.Is(err, compute.ErrNotFound) {
		t.Fatalf("DescribeGrant reported compute.ErrNotFound. That says this pair has no grant, "+
			"when what is true is that this provider cannot hold one; got %v", err)
	}
	if !errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("DescribeGrant should refuse with ErrUnsupported, got (%v, %v)", info, err)
	}
	var unsupported *compute.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("the refusal should be an *UnsupportedError, got %v", err)
	}
	if unsupported.Capability != compute.CapWorkloadGrants {
		t.Errorf("the refusal names %q and has to name %q, as Grant's does",
			unsupported.Capability, compute.CapWorkloadGrants)
	}
}

// TestTheGrantReadBackRoundTripsThroughTheBucketPolicy is the positive case for
// this provider, where the grant is stored the opposite way round from AWS.
//
// A cross-check on the asymmetry compute.Granter.DescribeGrant documents: here
// the policy lives on the BUCKET keyed by OIDC subject, so the read is a bucket
// read rather than a role read. The pair is what both substrates hold directly,
// which is the argument for keying the method on it.
func TestTheGrantReadBackRoundTripsThroughTheBucketPolicy(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, fullConfig())
	ctx := context.Background()

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	identity := mustIdentity(t, p, "app")

	if _, err := store.DescribeGrant(ctx, bucket.Ref, identity); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("DescribeGrant before any Grant = %v, want compute.ErrNotFound", err)
	}
	for _, level := range []compute.AccessLevel{
		compute.AccessRead, compute.AccessReadWrite, compute.AccessRead,
	} {
		if err := store.Grant(ctx, bucket.Ref, identity, level); err != nil {
			t.Fatalf("Grant(%s): %v", level, err)
		}
		info, err := store.DescribeGrant(ctx, bucket.Ref, identity)
		if err != nil {
			t.Fatalf("DescribeGrant after Grant(%s): %v", level, err)
		}
		if info.Level != level {
			t.Errorf("Grant(%s) then DescribeGrant reports %q", level, info.Level)
		}
	}
	if err := store.Revoke(ctx, bucket.Ref, identity); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.DescribeGrant(ctx, bucket.Ref, identity); !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("DescribeGrant after Revoke = %v, want compute.ErrNotFound", err)
	}
}

func TestGrantRefusalNamesTheMissingCapability(t *testing.T) {
	t.Parallel()
	cfg := fullConfig()
	cfg.ObjectStore.TrustsClusterOIDC = false
	p, _ := newProvider(t, cfg)
	ctx := context.Background()

	if p.Capabilities().Has(compute.CapWorkloadGrants) {
		t.Fatal("a store that does not federate the cluster's issuer must not advertise " +
			"CapWorkloadGrants")
	}
	if !p.Capabilities().Has(compute.CapObjectStore) {
		t.Fatal("it should still advertise CapObjectStore; only the grant is unavailable")
	}

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	err = store.Grant(ctx, bucket.Ref, mustIdentity(t, p, "app"), compute.AccessRead)
	if !errors.Is(err, compute.ErrUnsupported) {
		t.Fatalf("Grant should refuse with ErrUnsupported, got %v", err)
	}
	var unsupported *compute.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("the refusal should be an *UnsupportedError, got %v", err)
	}
	if unsupported.Capability != compute.CapWorkloadGrants {
		t.Errorf("the refusal names %q; it has to name %q, the one that is missing, or an "+
			"operator reads the message and reconfigures the wrong thing",
			unsupported.Capability, compute.CapWorkloadGrants)
	}
}

// --- The map is a claim too ----------------------------------------------------

// findingsDocument is the report this package's tests are the evidence for.
const findingsDocument = "../../docs/design/k8s-contract-probe.md"

// TestFindingsDocumentNamesOnlyRealTests checks the evidence map against the
// package.
//
// # Why this exists
//
// The first revision of the findings document claimed all twenty-five findings
// had an executable assertion when fifteen tests existed. The fix was an
// evidence map naming, per finding, what backs it. Review then found that the
// map itself contained a false row: F25 named
// TestExecEnabledIsOneWayOnThisSubstrate, which an editing mistake had deleted
// from this file. The artefact built to stop an evidence overclaim contained an
// evidence overclaim, because a map from claims to evidence is itself a claim
// and nothing was checking it.
//
// So this is the construction rather than the check: a row cannot name a test
// that does not exist, because the build fails. It is the same move as the
// import-boundary checker — prefer a shape that cannot express the violation
// over a reviewer who might notice one.
//
// # What it does not cover, stated so this comment is not the next overclaim
//
// Three things.
//
//   - A row may name a test that exists and does not test the finding. Nothing
//     mechanical can close that; it is what review is for.
//   - Conformance evidence is named as a check identifier
//     ("security/tls-listener-requires-a-resolvable-certificate"), and those are
//     assembled at run time from a port name and an invariant, so there is no
//     static symbol to compare against.
//   - A test that exists and is named nowhere in the document is not reported.
//     That is deliberate: several tests back statements outside the findings
//     list, and requiring a citation for each would make the document harder to
//     edit without making it more true.
func TestFindingsDocumentNamesOnlyRealTests(t *testing.T) {
	t.Parallel()
	doc := readFindingsDocument(t)
	have := testFunctionsInPackage(t)

	// Every Test identifier the document names, anywhere in it -- the map, the
	// per-finding evidence lines, and the prose -- must exist.
	named := backtickedTestNames(doc)
	if len(named) == 0 {
		t.Fatal("the findings document names no tests at all, which means this check is not " +
			"looking at what it thinks it is")
	}
	for _, name := range named {
		if !have[name] {
			t.Errorf("%s names %s, and no such test function exists in this package. Either the "+
				"test was renamed or deleted and the document is now claiming evidence it does "+
				"not have, or the name is a typo.", findingsDocument, name)
		}
	}
}

// TestEvidenceMapCoversEveryFinding pins the map's shape and its headline count.
//
// The count in the document's opening paragraph is derived from the table here
// rather than typed, so the two cannot drift: that sentence is the summary a
// reader trusts, and it was wrong once already.
func TestEvidenceMapCoversEveryFinding(t *testing.T) {
	t.Parallel()
	doc := readFindingsDocument(t)
	have := testFunctionsInPackage(t)
	rows := evidenceMapRows(t, doc)

	// One row per finding, F1 through F25, in the order the summary lists them.
	if len(rows) != findingCount {
		t.Fatalf("the evidence map has %d rows, want one per finding (%d)", len(rows), findingCount)
	}
	for i, row := range rows {
		want := fmt.Sprintf("F%d", i+1)
		if row.id != want {
			t.Fatalf("evidence map row %d is %q, want %q; the map must list every finding once, "+
				"in order, or a finding can go missing without anything noticing", i+1, row.id, want)
		}
	}

	// A row is either backed by at least one real test, or it says analysis and
	// names none. There is no third state, because a third state is where an
	// unbacked claim would hide.
	executable := 0
	for _, row := range rows {
		names := backtickedTestNames(row.evidence)
		analysis := strings.Contains(strings.ToLower(row.kind), "analysis")
		switch {
		case analysis && len(names) > 0:
			t.Errorf("%s is marked analysis but names %v; pick one", row.id, names)
		case analysis:
			continue
		case len(names) == 0 && !strings.Contains(strings.ToLower(row.kind), "conformance"):
			t.Errorf("%s claims kind %q and names no test; a finding with no evidence must be "+
				"marked analysis and say why", row.id, row.kind)
		default:
			for _, n := range names {
				if !have[n] {
					t.Errorf("%s names %s, which does not exist", row.id, n)
				}
			}
			executable++
		}
	}

	// And the sentence a reader actually reads.
	want := fmt.Sprintf("**%d of the %d findings have an executable assertion**", executable, len(rows))
	if !strings.Contains(doc, want) {
		t.Errorf("the document's opening paragraph does not contain %q. That figure is the "+
			"summary a reader trusts and it must be derived from the evidence map, not typed: "+
			"%d of %d rows are backed.", want, executable, len(rows))
	}
}

// findingCount is the number of findings the document reports. It is a constant
// so that adding a finding without adding a map row is a failure rather than a
// silently shorter table.
const findingCount = 25

func readFindingsDocument(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(findingsDocument)
	if err != nil {
		t.Fatalf("reading the findings document: %v", err)
	}
	return string(b)
}

// backtickedTestNameRE matches a Go test identifier inside markdown backticks.
var backtickedTestNameRE = regexp.MustCompile("`(Test[A-Z][A-Za-z0-9_]*)`")

func backtickedTestNames(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range backtickedTestNameRE.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// verifierPackage is the package clause these verifier tests are compiled under,
// read out of the running binary rather than written down.
//
// It is discovered rather than hardcoded so that the binding cannot drift: if
// this file is ever moved into the implementation package, the name it looks for
// moves with it, and if somebody writes the wrong constant there is nothing to
// write.
func verifierPackage(t *testing.T) string {
	t.Helper()
	pc, _, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed, so the verifier cannot establish its own package")
	}
	full := goruntime.FuncForPC(pc).Name() // e.g. ".../compute/k8s_test.verifierPackage"
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		full = full[i+1:]
	}
	name, _, found := strings.Cut(full, ".")
	if !found || name == "" {
		t.Fatalf("cannot read a package name out of %q", goruntime.FuncForPC(pc).Name())
	}
	return name
}

// testFunctionsInPackage returns every Test function declared in the package
// these verifier tests are themselves compiled into.
//
// Two bindings, and the second was a review finding. Parsed rather than grepped,
// because a name inside a comment or a string is not a test and this check
// exists because a document said something the code did not. And filtered by
// *package clause* rather than by directory, because a Go directory holds two
// packages: verification round 4 showed that a file declaring `package k8s` with
// a Test function in it satisfied a map row, even though the findings tests are
// `package k8s_test` and `go test` would never run it. The set has to be the
// tests that actually run, not the files that happen to sit nearby.
func testFunctionsInPackage(t *testing.T) map[string]bool {
	t.Helper()
	want := verifierPackage(t)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		if file.Name.Name != want {
			continue
		}
		files++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	if files == 0 {
		t.Fatalf("no file in this directory declares package %q, so the verifier is looking at "+
			"nothing; if the package was renamed, verifierPackage should have followed it", want)
	}
	return out
}

// evidenceRow is one line of the evidence map.
type evidenceRow struct {
	id       string
	kind     string
	evidence string
}

// evidenceMapRowRE matches a table row whose first cell is a finding id.
var evidenceMapRowRE = regexp.MustCompile(`(?m)^\|\s*(F\d+)\s*\|([^|]*)\|(.*)\|\s*$`)

func evidenceMapRows(t *testing.T, doc string) []evidenceRow {
	t.Helper()
	const heading = "## Evidence map"
	start := strings.Index(doc, heading)
	if start < 0 {
		t.Fatalf("%s has no %q section", findingsDocument, heading)
	}
	section := doc[start:]
	if end := strings.Index(section[len(heading):], "\n## "); end >= 0 {
		section = section[:len(heading)+end]
	}
	var rows []evidenceRow
	for _, m := range evidenceMapRowRE.FindAllStringSubmatch(section, -1) {
		rows = append(rows, evidenceRow{
			id:       m[1],
			kind:     strings.TrimSpace(m[2]),
			evidence: m[3],
		})
	}
	return rows
}

// TestFindingEvidenceIsBoundToItsRow ties each finding's prose to its map row.
//
// # Why this exists
//
// Verification round 4 found the seam left by round 3. The map's rows were being
// checked, and every test name in the document was being checked for existence,
// but the two checks were not joined: a finding could be marked `analysis` in the
// table while its own section cited a real test in prose. The document would then
// claim executable evidence for a finding the map says has none — the same drift
// the map exists to prevent, relocated from the table into the text beside it.
//
// So the binding is per finding, not per document. A finding's section may cite
// only evidence its row records, and a row marked analysis must have a section
// that cites none. The test-name scan stays global, because a stale name
// anywhere is still a stale name; this adds the part that says *whose* evidence
// it is.
func TestFindingEvidenceIsBoundToItsRow(t *testing.T) {
	t.Parallel()
	doc := readFindingsDocument(t)
	rows := evidenceMapRows(t, doc)
	sections := findingSections(t, doc)

	for _, row := range rows {
		body, ok := sections[row.id]
		if !ok {
			t.Errorf("the evidence map has a row for %s and the document has no %q section for "+
				"it; a row that describes nothing cannot be checked against anything", row.id, row.id)
			continue
		}
		rowNames := backtickedTestNames(row.evidence)
		inRow := map[string]bool{}
		for _, n := range rowNames {
			inRow[n] = true
		}
		sectionNames := backtickedTestNames(body)
		analysis := strings.Contains(strings.ToLower(row.kind), "analysis")

		if analysis && len(sectionNames) > 0 {
			t.Errorf("the evidence map marks %s as analysis, but its section cites %v. Either the "+
				"finding has executable evidence and the row is wrong, or the prose is claiming "+
				"evidence the map does not record.", row.id, sectionNames)
			continue
		}
		for _, n := range sectionNames {
			if !inRow[n] {
				t.Errorf("%s's section cites %s and its evidence-map row does not (%v). The map is "+
					"the record of what backs a finding; prose must not add to it silently.",
					row.id, n, rowNames)
			}
		}
	}

	// And the other direction, so a section cannot go missing while its row
	// stays: every section must have a row.
	byID := map[string]bool{}
	for _, row := range rows {
		byID[row.id] = true
	}
	for id := range sections {
		if !byID[id] {
			t.Errorf("the document has an %q section with no evidence-map row; every finding is "+
				"listed in the map, so this one is either new and unmapped or renumbered", id)
		}
	}
}

// findingSectionRE matches a finding's heading and captures its identifier.
var findingSectionRE = regexp.MustCompile(`(?m)^### (F\d+) `)

// findingSections splits the document into one body per finding, from its
// heading to the next heading of any level.
func findingSections(t *testing.T, doc string) map[string]string {
	t.Helper()
	locs := findingSectionRE.FindAllStringSubmatchIndex(doc, -1)
	out := make(map[string]string, len(locs))
	for _, loc := range locs {
		id := doc[loc[2]:loc[3]]
		body := doc[loc[1]:]
		// A finding's section ends at the next heading, whatever its level.
		if end := regexp.MustCompile(`(?m)^#{2,3} `).FindStringIndex(body); end != nil {
			body = body[:end[0]]
		}
		if _, dup := out[id]; dup {
			t.Errorf("the document has two %q sections; a finding must be described once", id)
		}
		out[id] = body
	}
	return out
}
