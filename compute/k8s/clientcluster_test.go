// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// The kinds these tests address.
var (
	deploymentGVK = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	secretGVK     = schema.GroupVersionKind{Version: "v1", Kind: "Secret"}
	postgresGVK   = schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster"}
)

// newClientCluster returns a cluster over client-go's fake dynamic client,
// together with the fake so a test can inspect the actions that were issued.
//
// # The boundary this fixture sits on, stated once
//
// The fake implements the API server's *contract as client-go understands it*:
// it stores objects, answers Get/List/Watch/Create/Update/Delete, honours a
// label selector, and returns real apierrors. That makes it evidence for "this
// code issues the calls it means to, and handles the answers it is given".
//
// It is not evidence about Kubernetes. A fake is addressed by whatever resource
// name the code under test asks for, so it agrees with a mapping mistake; it runs
// no admission, no defaulting, no controllers, and no finalizers; and it does not
// enforce resourceVersion, so the 409 path has to be injected by a reactor rather
// than provoked. Each of those is called out where it matters. Nothing here
// should be read as "a real cluster behaves this way".
func newClientCluster(t *testing.T) (*k8s.ClientCluster, *dynamicfake.FakeDynamicClient) {
	t.Helper()

	mapping, err := k8s.PostgresResource(fullConfig().PostgresOperator, "clusters")
	if err != nil {
		t.Fatalf("PostgresResource: %v", err)
	}
	resolver, err := k8s.NewStaticResolver(mapping)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}

	// The fake's own scheme is deliberately empty and every list kind is declared
	// explicitly. Handing it client-go's scheme makes its tracker build a typed
	// DeploymentList and then fail to append unstructured items to it — the fake's
	// scheme governs its storage, not the conversion this package does, which uses
	// client-go's scheme inside ClientCluster.
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			{Group: "apps", Version: "v1", Resource: "deployments"}:            "DeploymentList",
			{Version: "v1", Resource: "secrets"}:                               "SecretList",
			{Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}: "ClusterList",
		})

	cluster, err := k8s.NewClientCluster(client, resolver, k8s.ClientClusterOptions{})
	if err != nil {
		t.Fatalf("NewClientCluster: %v", err)
	}
	return cluster, client
}

func deployment(namespace, name string, replicas int32, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
	}
}

// TestNewClientClusterRefusesAnIncompleteConstruction pins the fail-closed
// constructor. A cluster with no resolver would have to guess resource names,
// which is the mistake StaticResolver exists to prevent.
func TestNewClientClusterRefusesAnIncompleteConstruction(t *testing.T) {
	t.Parallel()

	resolver, err := k8s.NewStaticResolver(nil)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	if _, err := k8s.NewClientCluster(nil, resolver, k8s.ClientClusterOptions{}); err == nil {
		t.Error("NewClientCluster accepted a nil dynamic client")
	}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	if _, err := k8s.NewClientCluster(client, nil, k8s.ClientClusterOptions{}); err == nil {
		t.Error("NewClientCluster accepted a nil resolver")
	}
	if _, err := k8s.NewClientClusterForConfig(nil, resolver, k8s.ClientClusterOptions{}); err == nil {
		t.Error("NewClientClusterForConfig accepted a nil *rest.Config")
	}
}

// TestClientClusterRoundTripsATypedObject is the property the whole seam rests
// on: an object written through the client comes back as the *same concrete Go
// type* the provider wrote, because every line of translation above the seam type
// asserts on concrete types and would panic-or-refuse on an unstructured one.
//
// It is stated as a property rather than as a field comparison — write it, read
// it, and the round trip must preserve type and content — because "the replicas
// survived" is a case and "the object survives" is the class.
func TestClientClusterRoundTripsATypedObject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	want := deployment("apps", "web", 3, map[string]string{"app": "web"})
	if err := cluster.Apply(ctx, deploymentGVK, want); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := cluster.Get(ctx, deploymentGVK, "apps", "web")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dep, ok := got.(*appsv1.Deployment)
	if !ok {
		t.Fatalf("Get returned a %T; the translation layer above this seam type asserts on "+
			"*appsv1.Deployment and every path through it would break", got)
	}
	if dep.Namespace != "apps" || dep.Name != "web" {
		t.Errorf("Get returned %s/%s", dep.Namespace, dep.Name)
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Errorf("the replica count did not survive the round trip: %v", dep.Spec.Replicas)
	}
	if dep.Labels["app"] != "web" {
		t.Errorf("labels did not survive the round trip: %v", dep.Labels)
	}

	// A Secret's data is []byte, which unstructured conversion carries as base64.
	// Round-tripping it is worth its own assertion because getting it wrong would
	// corrupt credential material rather than fail.
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "db"},
		Type:       corev1.SecretTypeBasicAuth,
		Data:       map[string][]byte{corev1.BasicAuthPasswordKey: []byte("s3cr3t-not-a-real-value")},
	}
	if err := cluster.Apply(ctx, secretGVK, sec); err != nil {
		t.Fatalf("Apply a Secret: %v", err)
	}
	readBack, err := cluster.Get(ctx, secretGVK, "apps", "db")
	if err != nil {
		t.Fatalf("Get a Secret: %v", err)
	}
	stored, ok := readBack.(*corev1.Secret)
	if !ok {
		t.Fatalf("Get returned a %T for a Secret", readBack)
	}
	if string(stored.Data[corev1.BasicAuthPasswordKey]) != "s3cr3t-not-a-real-value" {
		t.Errorf("a Secret's byte data did not survive the round trip: %q",
			stored.Data[corev1.BasicAuthPasswordKey])
	}
	if stored.Type != corev1.SecretTypeBasicAuth {
		t.Errorf("a Secret's type did not survive the round trip: %q", stored.Type)
	}
}

// TestClientClusterRoundTripsACustomResource is the other half: a kind the
// scheme does not know must come back unstructured, which is what MemoryCluster
// stores for it and what the provider's database and endpoint paths read.
func TestClientClusterRoundTripsACustomResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	u := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"instances": int64(2)},
	}}
	u.SetGroupVersionKind(postgresGVK)
	u.SetNamespace("apps")
	u.SetName("db")

	if err := cluster.Apply(ctx, postgresGVK, u); err != nil {
		t.Fatalf("Apply a custom resource: %v", err)
	}
	got, err := cluster.Get(ctx, postgresGVK, "apps", "db")
	if err != nil {
		t.Fatalf("Get a custom resource: %v", err)
	}
	back, ok := got.(*unstructured.Unstructured)
	if !ok {
		t.Fatalf("Get returned a %T for a custom resource; the provider reads it with "+
			"unstructured.NestedInt64 and would break", got)
	}
	instances, found, err := unstructured.NestedInt64(back.Object, "spec", "instances")
	if err != nil || !found || instances != 2 {
		t.Errorf("spec.instances round-tripped as (%d, %v, %v)", instances, found, err)
	}
	if back.GetKind() != postgresGVK.Kind {
		t.Errorf("the custom resource came back with kind %q", back.GetKind())
	}
}

// TestApplyStampsTheGroupVersionKind is a small thing with a large failure.
//
// The provider builds typed objects with an empty TypeMeta, which is idiomatic
// for a typed client and fatal for a dynamic one: apiVersion and kind are how the
// request is routed and how the stored object identifies itself. If the seam did
// not stamp them from its own argument, every write would go out kindless.
func TestApplyStampsTheGroupVersionKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, client := newClientCluster(t)

	bare := deployment("apps", "web", 1, nil)
	if bare.APIVersion != "" || bare.Kind != "" {
		t.Fatal("this fixture is supposed to start with an empty TypeMeta; the test is not " +
			"exercising what it claims")
	}
	if err := cluster.Apply(ctx, deploymentGVK, bare); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, action := range client.Actions() {
		create, ok := action.(k8stesting.CreateAction)
		if !ok || action.GetVerb() != "create" {
			continue
		}
		u, ok := create.GetObject().(*unstructured.Unstructured)
		if !ok {
			t.Fatalf("the create carried a %T", create.GetObject())
		}
		if u.GetAPIVersion() != "apps/v1" || u.GetKind() != "Deployment" {
			t.Errorf("the create went out as apiVersion=%q kind=%q", u.GetAPIVersion(), u.GetKind())
		}
		return
	}
	t.Fatal("no create action was issued")
}

// TestApplyReplacesRatherThanAccumulating pins the declarative contract at the
// seam. The compute interface's Ensure methods converge; if Apply merged instead
// of replacing, a removed field would survive and the conformance suite's
// convergence checks would be lying about what reaches the substrate.
func TestApplyReplacesRatherThanAccumulating(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	first := deployment("apps", "web", 3, map[string]string{"app": "web", "temporary": "yes"})
	if err := cluster.Apply(ctx, deploymentGVK, first); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	second := deployment("apps", "web", 1, map[string]string{"app": "web"})
	if err := cluster.Apply(ctx, deploymentGVK, second); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	got, err := cluster.Get(ctx, deploymentGVK, "apps", "web")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	dep := got.(*appsv1.Deployment)
	if *dep.Spec.Replicas != 1 {
		t.Errorf("replicas is %d after the second apply, want 1", *dep.Spec.Replicas)
	}
	if _, still := dep.Labels["temporary"]; still {
		t.Error("a label the second apply omitted survived it; Apply accumulated instead of " +
			"replacing, which is the defect the convergence invariant exists to catch")
	}
}

// TestApplyPreservesStatusAcrossAnUpdate is the assumption stated on
// ClientCluster.Apply, made observable.
//
// A controller owns status; the provider owns spec. An update that carried an
// empty status would blank a Postgres operator's phase and make a running
// database read as pending on the next Describe — and the fake, which has no
// status subresource, is exactly the substrate where that would happen. The
// stored status must survive.
//
// Boundary, honestly: this proves the copy happens. On a real API server a
// built-in kind would not have needed it, because status is a subresource there.
// What the fake cannot tell us is whether a given operator's CRD declares that
// subresource — which is why the copy is unconditional.
func TestApplyPreservesStatusAcrossAnUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, client := newClientCluster(t)

	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"instances": int64(1)}}}
	u.SetGroupVersionKind(postgresGVK)
	u.SetNamespace("apps")
	u.SetName("db")
	if err := cluster.Apply(ctx, postgresGVK, u); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The operator writes status, as an operator does.
	gvr := schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}
	stored, err := client.Resource(gvr).Namespace("apps").Get(ctx, "db", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}
	stored.Object["status"] = map[string]any{"phase": "Cluster in healthy state"}
	if _, err := client.Resource(gvr).Namespace("apps").Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("writing status as the operator would: %v", err)
	}

	// The provider re-reconciles with a changed spec.
	next := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"instances": int64(3)}}}
	next.SetGroupVersionKind(postgresGVK)
	next.SetNamespace("apps")
	next.SetName("db")
	if err := cluster.Apply(ctx, postgresGVK, next); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	got, err := cluster.Get(ctx, postgresGVK, "apps", "db")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	phase, found, err := unstructured.NestedString(got.(*unstructured.Unstructured).Object, "status", "phase")
	if err != nil || !found {
		t.Fatalf("the operator's status did not survive a spec update (found=%v, err=%v); a "+
			"running database would read as pending after every reconcile", found, err)
	}
	if phase != "Cluster in healthy state" {
		t.Errorf("status.phase is %q after the update", phase)
	}
	instances, _, _ := unstructured.NestedInt64(got.(*unstructured.Unstructured).Object, "spec", "instances")
	if instances != 3 {
		t.Errorf("the spec update did not take effect: instances=%d", instances)
	}
}

// TestApplyMapsAStaleWriteToARetryableError is the 409 path — the substrate's
// most common failure and the one that earned an interface amendment (F2).
//
// The fake does not enforce resourceVersion, so the conflict is injected with a
// reactor. That is a real limit of the fixture and it is stated rather than
// papered over: what is verified is the *mapping*, not that a real API server
// produces a conflict in this scenario. The mapping is what matters, because
// getting it wrong tells a caller its spec has to change when a retry would have
// worked.
func TestApplyMapsAStaleWriteToARetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, client := newClientCluster(t)

	if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 1, nil)); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	client.PrependReactor("update", "deployments",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "apps", Resource: "deployments"}, "web", errors.New("stale"))
		})

	err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 2, nil))
	if !errors.Is(err, k8s.ErrOptimisticConcurrency) {
		t.Fatalf("a 409 on update mapped to %v, want ErrOptimisticConcurrency", err)
	}
	// And the substrate error must NOT be the other 409. Conflating them tells a
	// caller its resource belongs to somebody else.
	if errors.Is(err, compute.ErrNotOwned) {
		t.Error("a stale-write conflict surfaced as compute.ErrNotOwned")
	}
}

// TestApplyMapsALostCreateRaceToARetryableError covers the create branch of the
// same race: two writers, both saw the object absent, one created it first.
//
// AlreadyExists is retryable — the retry re-reads and takes the update branch —
// so mapping it to a terminal failure would abandon a deploy that was about to
// succeed.
func TestApplyMapsALostCreateRaceToARetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, client := newClientCluster(t)

	client.PrependReactor("create", "deployments",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewAlreadyExists(
				schema.GroupResource{Group: "apps", Resource: "deployments"}, "web")
		})

	err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 1, nil))
	if !errors.Is(err, k8s.ErrOptimisticConcurrency) {
		t.Fatalf("a lost create race mapped to %v, want ErrOptimisticConcurrency", err)
	}
}

// TestAnRBACRejectionMapsToTheDenialSentinel is the 403 path, and unlike the
// 409 above it is the failure a real cluster produces with no help at all: the
// ClusterRole this platform runs under does not carry the verb.
//
// It is asserted here rather than only in the conformance suite because the
// suite drives [MemoryCluster], which returns this package's own sentinels
// directly. Nothing in it can establish that a *client-go* rejection becomes one
// — that translation is [ClientCluster.apiError]'s alone, and it is the only
// copy of it that ever runs against a real API server. A missing arm there is
// invisible from the suite and total in production.
//
// The 401 is here with the 403 for the reason [k8s.ErrClusterDenied] gives: a
// refused credential and a refused verb are the same answer to the two questions
// the taxonomy asks — who fixes it, and could this request ever succeed as
// written.
func TestAnRBACRejectionMapsToTheDenialSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deployments := schema.GroupResource{Group: "apps", Resource: "deployments"}
	cases := map[string]error{
		"403 Forbidden": apierrors.NewForbidden(deployments, "web",
			errors.New("deployments.apps is forbidden: User \"system:serviceaccount:apphub-system:apphub\" cannot get resource")),
		"401 Unauthorized": apierrors.NewUnauthorized("Unauthorized"),
	}
	for name, injected := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cluster, client := newClientCluster(t)
			client.PrependReactor("*", "deployments",
				func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, injected })

			_, err := cluster.Get(ctx, deploymentGVK, "apps", "web")
			if !errors.Is(err, k8s.ErrClusterDenied) {
				t.Fatalf("a read refusal mapped to %v, want ErrClusterDenied", err)
			}
			// Not the other two substrate sentinels. A denial read as
			// ErrObjectNotFound is the worst of the three: Provider.claim treats
			// that as "the name is free", so an under-privileged platform would
			// conclude every resource is absent and try to create it.
			if errors.Is(err, k8s.ErrObjectNotFound) {
				t.Error("a refusal surfaced as ErrObjectNotFound, which the ownership check reads " +
					"as \"this name is free\"")
			}
			if errors.Is(err, k8s.ErrOptimisticConcurrency) {
				t.Error("a refusal surfaced as ErrOptimisticConcurrency, so the provider would " +
					"retry it five times and fail anyway")
			}

			if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 1, nil)); !errors.Is(err, k8s.ErrClusterDenied) {
				t.Fatalf("a write refusal mapped to %v, want ErrClusterDenied", err)
			}
		})
	}
}

// TestAProviderOverARealClientReportsARefusalAsNotPermitted joins the two halves
// of the denial path that no other test sees together: client-go's error becomes
// [k8s.ErrClusterDenied] in [ClientCluster.apiError], and that becomes
// [compute.ErrNotPermitted] in Provider.substrateError.
//
// The conformance suite exercises the second half over the in-memory cluster and
// the tests above exercise the first, so both were true separately while the
// composition was what a caller actually gets. This drives a provider over the
// fake client and asserts on the sentinel a caller branches on.
func TestAProviderOverARealClientReportsARefusalAsNotPermitted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cluster, client := newClientCluster(t)
	client.PrependReactor("*", "serviceaccounts",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "serviceaccounts"}, "api",
				errors.New("serviceaccounts is forbidden"))
		})

	p := k8s.New(&k8s.Substrate{
		Cluster:  cluster,
		Registry: k8s.NewMemoryRegistry(),
		Objects:  k8s.NewMemoryObjectStore(),
	}, fullConfig())

	_, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "api", RunsOn: compute.RuntimeContainer,
	})
	if !errors.Is(err, compute.ErrNotPermitted) {
		t.Fatalf("an RBAC refusal reached the caller as %v, want compute.ErrNotPermitted", err)
	}
	// The three the sentinel exists to be distinguishable from. ErrFailed is
	// where this landed before the mapping arm existed, and it sends an operator
	// looking for a broken resource instead of a missing permission.
	for _, wrong := range []struct {
		err  error
		name string
	}{
		{compute.ErrFailed, "compute.ErrFailed"},
		{compute.ErrInvalidSpec, "compute.ErrInvalidSpec"},
		{compute.ErrTransient, "compute.ErrTransient"},
	} {
		if errors.Is(err, wrong.err) {
			t.Errorf("the refusal also matches %s, so a caller branching on it is sent to the "+
				"wrong place: %v", wrong.name, err)
		}
	}
}

// TestGetMapsNotFoundToTheSubstrateSentinel matters because the provider's
// ownership check reads exactly this: claim() treats ErrObjectNotFound as "the
// name is free" and anything else as a failure. A 404 that arrived as a generic
// error would make every first Ensure fail.
func TestGetMapsNotFoundToTheSubstrateSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	_, err := cluster.Get(ctx, deploymentGVK, "apps", "absent")
	if !errors.Is(err, k8s.ErrObjectNotFound) {
		t.Fatalf("Get of an absent object returned %v, want ErrObjectNotFound", err)
	}
}

// TestGetRefusesAnUnmappedKind is the fail-closed path reaching the caller: a
// kind nobody configured must be refused by name rather than sent to a URL that
// 404s and read as "absent".
func TestGetRefusesAnUnmappedKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	resolver, err := k8s.NewStaticResolver(nil) // no Postgres mapping
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	cluster, err := k8s.NewClientCluster(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		resolver, k8s.ClientClusterOptions{})
	if err != nil {
		t.Fatalf("NewClientCluster: %v", err)
	}

	_, err = cluster.Get(ctx, postgresGVK, "apps", "db")
	if !errors.Is(err, k8s.ErrUnmappedKind) {
		t.Fatalf("Get of an unmapped kind returned %v, want ErrUnmappedKind", err)
	}
	if errors.Is(err, k8s.ErrObjectNotFound) {
		t.Fatal("an unmapped kind was reported as an absent object, which is the exact " +
			"confusion the resolver exists to prevent: the provider would create a new object " +
			"on every reconcile and never converge")
	}
}

// TestDeleteIsIdempotent pins what makes every Delete* method on the provider
// idempotent, which the conformance suite requires.
func TestDeleteIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 1, nil)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i := range 3 {
		if err := cluster.Delete(ctx, deploymentGVK, "apps", "web"); err != nil {
			t.Fatalf("Delete %d returned %v; deleting an absent object must not be an error", i, err)
		}
	}
}

// TestListPushesTheSelectorToTheServer verifies at the resolution the failure
// lives at.
//
// A List that fetched everything and filtered locally would return the right
// answer and be a production defect: a namespace with a hundred thousand Secrets
// would be pulled over the wire on every reconcile. Asserting on the returned
// objects cannot observe that, so this asserts on the request that was issued.
func TestListPushesTheSelectorToTheServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, client := newClientCluster(t)

	for _, spec := range []struct {
		name   string
		labels map[string]string
	}{
		{"zeta", map[string]string{"app.kubernetes.io/managed-by": "apphub"}},
		{"alpha", map[string]string{"app.kubernetes.io/managed-by": "apphub"}},
		{"other", map[string]string{"app.kubernetes.io/managed-by": "somebody-else"}},
	} {
		if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", spec.name, 1, spec.labels)); err != nil {
			t.Fatalf("Apply %s: %v", spec.name, err)
		}
	}

	client.ClearActions()
	got, err := cluster.List(ctx, deploymentGVK, "apps",
		map[string]string{"app.kubernetes.io/managed-by": "apphub"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d objects, want 2", len(got))
	}

	// Sorted by name, matching MemoryCluster, because the determinism invariant
	// compares two reads and the API server promises no ordering.
	if got[0].(*appsv1.Deployment).Name != "alpha" || got[1].(*appsv1.Deployment).Name != "zeta" {
		t.Errorf("List is not sorted by name: %s, %s",
			got[0].(*appsv1.Deployment).Name, got[1].(*appsv1.Deployment).Name)
	}

	found := false
	for _, action := range client.Actions() {
		list, ok := action.(k8stesting.ListAction)
		if !ok {
			continue
		}
		found = true
		selector := list.GetListRestrictions().Labels
		if selector == nil || selector.Empty() {
			t.Error("the List went out with no label selector, so the whole namespace would " +
				"have been fetched and filtered locally")
			continue
		}
		if !selector.Matches(labels.Set{"app.kubernetes.io/managed-by": "apphub"}) {
			t.Errorf("the pushed-down selector %q does not match the labels asked for",
				selector.String())
		}
		if selector.Matches(labels.Set{"app.kubernetes.io/managed-by": "somebody-else"}) {
			t.Errorf("the pushed-down selector %q also matches somebody else's objects",
				selector.String())
		}
	}
	if !found {
		t.Fatal("no list action was issued")
	}
}

// TestWatchDeliversAChangeAndStopsCleanly is the watch path's own test.
//
// What it proves: this code establishes a watch scoped to one object, forwards a
// change as a tick, and its stop function is idempotent and does not leak the
// goroutine (the race detector and the second Stop between them would catch a
// double-close or a send on a closed channel).
//
// What it does not prove: that a real API server delivers an event for the
// transitions this provider waits on. The fake fires on every create and update;
// a real cluster's Deployment status is written by a controller, and this fixture
// has no controllers. That is the assumption, and the reason the poll fallback
// and the caller's deadline both still apply on the watched path.
func TestWatchDeliversAChangeAndStopsCleanly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	changes, stop, err := cluster.Watch(ctx, deploymentGVK, "apps", "web")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Cleanup(stop)

	if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 1, nil)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("no change was reported within five seconds of the object being created")
	}

	// A second write must also be reported, so the watch is not one-shot.
	if err := cluster.Apply(ctx, deploymentGVK, deployment("apps", "web", 2, nil)); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("no change was reported for the second write")
	}

	stop()
	stop() // idempotent by contract
}

// TestWatchRefusesWhatItCannotWatch keeps the failure modes typed rather than
// silent, because Provider.watchChanges reads an error here as "poll instead".
func TestWatchRefusesWhatItCannotWatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cluster, _ := newClientCluster(t)

	if _, _, err := cluster.Watch(ctx, deploymentGVK, "apps", ""); err == nil {
		t.Error("Watch accepted an empty object name; it would have watched the whole namespace")
	}

	resolver, err := k8s.NewStaticResolver(nil)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	unmapped, err := k8s.NewClientCluster(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		resolver, k8s.ClientClusterOptions{})
	if err != nil {
		t.Fatalf("NewClientCluster: %v", err)
	}
	if _, _, err := unmapped.Watch(ctx, postgresGVK, "apps", "db"); !errors.Is(err, k8s.ErrUnmappedKind) {
		t.Errorf("watching an unmapped kind returned %v, want ErrUnmappedKind", err)
	}
}

// TestClientClusterSatisfiesBothSeams is a compile-time claim made observable:
// the production cluster is a Cluster *and* a Watcher, and the in-memory one is
// deliberately only a Cluster.
//
// The second half is the load-bearing one. MemoryCluster's clock is the read —
// convergence advances on observation — so a watch on it would block forever
// waiting for a write only a reader can cause. If it ever gained a Watch method,
// Provider.waitFor would silently stop polling against it and the hermetic suite
// would hang. This test is the tripwire for that.
func TestClientClusterSatisfiesBothSeams(t *testing.T) {
	t.Parallel()
	cluster, _ := newClientCluster(t)

	var _ k8s.Cluster = cluster
	if _, ok := any(cluster).(k8s.Watcher); !ok {
		t.Error("ClientCluster does not implement k8s.Watcher, so every production wait would poll")
	}
	if _, ok := any(k8s.NewMemoryCluster()).(k8s.Watcher); ok {
		t.Error("MemoryCluster now implements k8s.Watcher. Its convergence advances on " +
			"observation, so a wait that blocked on a watch of it would wait for a write only a " +
			"reader can cause — the hermetic suite would hang rather than fail. Either give it " +
			"a real change notification or take the method away.")
	}
}

// TestWatchReconnectionDoesNotMissAPersistentChange is the B3 regression, and the
// shape of the defect is worth naming: it was a **transition, not a call**. Every
// individual watch worked; the move between two of them did not.
//
// A change landing after the old watch closed and before the replacement existed
// was reported by neither — the replacement started from "now" and emitted
// nothing. So a consumer waiting for readiness on an object that had *already
// become* ready waited out its whole deadline. The earlier concession that "a
// missed intermediate state is not observable" did not cover it, because the state
// reached in the gap is persistent rather than intermediate.
//
// The test drives the gap directly: the first watch is closed, and the object is
// changed while no watch exists. The replacement is a watcher that never emits
// anything, so the *only* way a tick can arrive is the unconditional one the
// reconnect now sends.
func TestWatchReconnectionDoesNotMissAPersistentChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cluster, client := newClientCluster(t)

	first := watch.NewFake()
	second := watch.NewFake() // established, and deliberately silent
	var handedOut int
	var mu sync.Mutex

	client.PrependWatchReactor("deployments",
		func(k8stesting.Action) (bool, watch.Interface, error) {
			mu.Lock()
			defer mu.Unlock()
			handedOut++
			if handedOut == 1 {
				return true, first, nil
			}
			return true, second, nil
		})

	changes, stop, err := cluster.Watch(ctx, deploymentGVK, "apps", "web")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Cleanup(stop)

	// Close the first watch. The object becomes ready in the gap that follows,
	// which nothing will report unless the reconnect reports it.
	first.Stop()

	select {
	case _, ok := <-changes:
		if !ok {
			t.Fatal("the change channel closed instead of reconnecting; the waiter would drop " +
				"to polling rather than being told to re-read")
		}
		// A tick arrived after the reconnect, which is the fix: the consumer
		// re-reads current state, and a re-read cannot miss a persistent change
		// whatever happened while no watch existed.
	case <-time.After(5 * time.Second):
		t.Fatal("the watch reconnected without reporting a change. A ready update in the gap " +
			"between two watches would leave WaitFor blocked until its deadline on an object " +
			"that is already ready.")
	}

	mu.Lock()
	got := handedOut
	mu.Unlock()
	if got < 2 {
		t.Errorf("the watch was established %d times; the reconnect did not happen, so the "+
			"tick above came from somewhere else and this test is not checking the reconnect",
			got)
	}
}

// TestWatchResumesFromTheLastObservedResourceVersion pins the other half of the
// B3 fix, which fails differently from the tick and is therefore worth having as
// well rather than instead.
//
// The tick makes the consumer re-read and depends on nothing. Resuming from the
// last observed resourceVersion asks the API server to replay what happened in the
// gap, which is the more precise answer and depends on the server still holding
// that history. This asserts the replacement watch actually carries the version.
func TestWatchResumesFromTheLastObservedResourceVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cluster, client := newClientCluster(t)

	first := watch.NewFake()
	second := watch.NewFake()
	var mu sync.Mutex
	var resumeVersions []string
	var handedOut int

	client.PrependWatchReactor("deployments",
		func(action k8stesting.Action) (bool, watch.Interface, error) {
			mu.Lock()
			defer mu.Unlock()
			handedOut++
			if w, ok := action.(k8stesting.WatchActionImpl); ok {
				resumeVersions = append(resumeVersions, w.WatchRestrictions.ResourceVersion)
			}
			if handedOut == 1 {
				return true, first, nil
			}
			return true, second, nil
		})

	changes, stop, err := cluster.Watch(ctx, deploymentGVK, "apps", "web")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Cleanup(stop)

	// An event carrying a resourceVersion, which the watch must remember.
	dep := deployment("apps", "web", 1, nil)
	dep.ResourceVersion = "4242"
	first.Modify(dep)
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("no tick for the first event")
	}

	first.Stop()
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("no tick after the reconnect")
	}

	mu.Lock()
	got := append([]string(nil), resumeVersions...)
	mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("the watch was established %d times, want at least 2", len(got))
	}
	if got[0] != "" {
		t.Errorf("the first watch resumed from %q; it should start from the current state", got[0])
	}
	if got[1] != "4242" {
		t.Errorf("the replacement watch resumed from %q, want %q — without it the server does "+
			"not replay what happened while no watch existed", got[1], "4242")
	}
}
