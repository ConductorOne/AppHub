// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// readVerbRecorder records which read verb a caller reached for, and whether the
// value-bearing one handed back a payload.
//
// The control is written against the SUBSTRATE rather than against
// secretStore.Describe, and that is the whole point. The first version of
// Describe called Cluster.Get and then did not inspect Secret.Data — which reads
// as metadata-only and is not: the object, values included, had already been
// fetched and deserialized. A control that only checked what Describe *returned*
// would have passed. This one fails if Get is reached at all.
type readVerbRecorder struct {
	k8s.Cluster
	gets         int
	getsWithData int
	metadataGets int
}

func (c *readVerbRecorder) Get(ctx context.Context, gvk schema.GroupVersionKind, ns, name string) (runtime.Object, error) {
	obj, err := c.Cluster.Get(ctx, gvk, ns, name)
	c.gets++
	if sec, ok := obj.(*corev1.Secret); ok && len(sec.Data) > 0 {
		c.getsWithData++
	}
	return obj, err
}

func (c *readVerbRecorder) GetMetadata(ctx context.Context, gvk schema.GroupVersionKind, ns, name string) (*metav1.PartialObjectMetadata, error) {
	c.metadataGets++
	return c.Cluster.GetMetadata(ctx, gvk, ns, name)
}

// TestDescribeNeverReachesTheValueBearingRead is the reproduction from round
// three of review on PR #42, kept.
//
// It stores a secret with real material, resets the observation, and calls
// Describe. The assertions are about the substrate calls, not about the result:
// zero Gets, at least one GetMetadata.
func TestDescribeNeverReachesTheValueBearingRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	watched := &readVerbRecorder{Cluster: k8s.NewMemoryCluster()}
	sub := &k8s.Substrate{
		Cluster:  watched,
		Registry: k8s.NewMemoryRegistry(),
		Objects:  k8s.NewMemoryObjectStore(),
	}
	p := k8s.New(sub, fullConfig())
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}

	const material = "correct-horse-battery-staple"
	stored, err := store.Put(ctx, compute.SecretSpec{
		Name:  "describe-metadata-only",
		Scope: "control",
		Value: compute.NewSecretValue(material),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref

	// Establish that the instrument can see a payload at all: without this the
	// assertion below passes on a wrapper that never observes anything.
	if _, err := store.Get(ctx, ref); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if watched.getsWithData == 0 {
		t.Fatal("the control never observed a payload through Get, so it cannot tell a " +
			"metadata read from a value-bearing one and every assertion below is vacuous")
	}

	watched.gets, watched.getsWithData, watched.metadataGets = 0, 0, 0

	info, err := store.Describe(ctx, ref)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if watched.gets != 0 {
		t.Errorf("Describe reached the value-bearing Cluster.Get %d time(s), returning a payload "+
			"%d time(s). Not inspecting material you have fetched is not the same as not "+
			"fetching it", watched.gets, watched.getsWithData)
	}
	if watched.metadataGets == 0 {
		t.Error("Describe reached no metadata read either, so it established nothing about " +
			"whether the secret exists")
	}
	if info == nil {
		t.Fatal("Describe returned nothing and no error")
	}
	if info.PlacementScope != compute.SecretPlacementScoped {
		t.Errorf("placement scope = %q, want %q: a Kubernetes secretKeyRef resolves only within "+
			"the pod's own namespace, so a secret here genuinely is somewhere",
			info.PlacementScope, compute.SecretPlacementScoped)
	}
	if info.Placement.Name == "" {
		t.Error("a scoped store reported no placement")
	}
}

// TestAClusterWithNoMetadataClientRefusesRatherThanFallingBack pins the
// fail-closed half.
//
// A ClientCluster built without a metadata client cannot answer the question,
// and the one thing it must not do is answer a different one. A fallback to the
// value-bearing read would make the security property hold or not depending on
// how somebody constructed the client, which is the shape of every bypass this
// repository has found.
func TestAClusterWithNoMetadataClientRefusesRatherThanFallingBack(t *testing.T) {
	t.Parallel()
	resolver, err := k8s.NewStaticResolver(nil)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	// A nil dynamic client would be refused at construction; the metadata
	// client is the one deliberately absent.
	c, err := k8s.NewClientCluster(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		resolver, k8s.ClientClusterOptions{})
	if err != nil {
		t.Fatalf("NewClientCluster: %v", err)
	}
	_, err = c.GetMetadata(context.Background(), schema.GroupVersionKind{Version: "v1", Kind: "Secret"},
		"default", "anything")
	if err == nil {
		t.Fatal("a cluster with no metadata client answered a metadata question")
	}
	if !strings.Contains(err.Error(), "Metadata") {
		t.Errorf("the refusal does not name what to supply: %v", err)
	}
}
