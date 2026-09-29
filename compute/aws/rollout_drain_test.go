// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0
package aws_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

type drainingRevisionECS struct {
	aws.ECSAPI
	draining bool
}

func (e *drainingRevisionECS) DescribeService(ctx context.Context, cluster, name string) (*aws.ServiceRecord, error) {
	record, err := e.ECSAPI.DescribeService(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	snapshot := *record
	if e.draining {
		snapshot.RunningCount++
		snapshot.RolloutState = "IN_PROGRESS"
	}
	return &snapshot, nil
}

func TestFullReplicaWaitDoesNotReleaseOldIngressBeforeDrain(t *testing.T) {
	ctx := context.Background()
	p, sub, spec := serviceFixture(t, nil)
	spec.Replicas = 2
	first, err := containers(t, p).EnsureService(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	sub.ECS.(*aws.MemoryECS).Advance(aws.MemoryCluster, "apphub-billing")
	ecs := &drainingRevisionECS{ECSAPI: sub.ECS, draining: true}
	sub.ECS = ecs
	runtime := containers(t, newProviderOver(t, sub, nil))
	status, err := runtime.DescribeService(ctx, first.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if status.ReadyReplicas != 2 || status.Phase != compute.PhasePending {
		t.Fatalf("new tasks wrongly prove old ingress retired: %+v", status)
	}
	if _, err := runtime.WaitForService(ctx, first.Ref, 2, compute.WaitOptions{Timeout: 20 * time.Millisecond}); !errors.Is(err, compute.ErrTimeout) {
		t.Fatalf("full wait passed before old tasks drained: %v", err)
	}
	ecs.draining = false
	if _, err := runtime.WaitForService(ctx, first.Ref, 2, compute.WaitOptions{Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
}
