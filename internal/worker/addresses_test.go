// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"slices"
	"testing"

	"github.com/conductorone/apphub/compute"
)

// bareHostProvider reports route addresses the way the AWS provider does: the
// route's host with no scheme. Every method it does not override panics.
type bareHostProvider struct {
	compute.Provider
	runtime *bareHostRuntime
}

func (p bareHostProvider) Containers() (compute.ContainerRuntime, error) { return p.runtime, nil }

type bareHostRuntime struct {
	compute.ContainerRuntime
	replicas int
	hosts    []string
}

func (r *bareHostRuntime) status() *compute.ServiceStatus {
	return &compute.ServiceStatus{ReadyReplicas: r.replicas, DesiredReplicas: r.replicas, RouteAddresses: r.hosts}
}

func (r *bareHostRuntime) WaitForService(_ context.Context, _ compute.Ref, _ int, _ compute.WaitOptions) (*compute.ServiceStatus, error) {
	return r.status(), nil
}

func (r *bareHostRuntime) DescribeService(_ context.Context, _ compute.Ref) (*compute.ServiceStatus, error) {
	return r.status(), nil
}

func TestVerifyServiceKeepsTheDeployModulesAddresses(t *testing.T) {
	f := newWorkerFixture(t)
	s, ctx := f.claim(t)
	if err := s.prepare(ctx, fixtureCommit); err != nil {
		t.Fatal(err)
	}
	published := []string{"https://notes.apps.example"}
	s.prepared.Artifacts.Workload = compute.Ref{Provider: "test", Kind: "service", ID: "notes"}
	s.prepared.Artifacts.Addresses = slices.Clone(published)

	provider := bareHostProvider{runtime: &bareHostRuntime{replicas: f.app.Application.Replicas, hosts: []string{"notes.apps.example"}}}
	target := f.d.targets[f.app.TargetID]
	if err := f.d.verifyService(ctx, s, f.app.ID, provider, target); err != nil {
		t.Fatalf("verifyService: %v", err)
	}
	if got := s.prepared.Artifacts.Addresses; !slices.Equal(got, published) {
		t.Fatalf("addresses = %v; want %v", got, published)
	}
	if s.prepared.DeployStep != "complete" {
		t.Fatalf("deploy step = %q; want complete", s.prepared.DeployStep)
	}
}
