// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// TestDescribeServiceDistinguishesAbsentFromMalformedSpec is
// TestDecodeSpecDistinguishesAbsentFromMalformed for the caller-visible
// contract: decodeSpec (compute/k8s/names.go) used to discard its unmarshal
// error at every one of its call sites, so an annotation that was never
// written and one that was written and then corrupted produced the identical
// zero-value spec -- indistinguishable to any caller, including this test's
// predecessor, which had no way to tell them apart because neither one was
// ever an error.
//
// DescribeService is one of six Describe* methods that read the
// annotationSpec-bearing object's effective spec via decodeSpec (the other
// five: DescribeScheduledJob, DescribeFunction, DescribeEndpoint,
// DescribeWorkloadIdentity, DescribeRelational). This test exercises it as
// the representative case; each of the other five call sites now returns an
// error wrapping compute.ErrFailed under the same condition, by the same
// reasoning documented at each call site.
func TestDescribeServiceDistinguishesAbsentFromMalformedSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	newService := func(t *testing.T) (compute.ContainerRuntime, *k8s.Substrate, compute.Ref) {
		t.Helper()
		cfg := fullConfig()
		sub := newSubstrate(cfg)
		p := k8s.New(sub, cfg)
		rt, err := p.Containers()
		if err != nil {
			t.Fatalf("Containers: %v", err)
		}
		svc, err := rt.EnsureService(ctx, compute.ServiceSpec{
			Name:      "api",
			Image:     compute.ImageRef("registry.invalid/apphub/api:v1"),
			Resources: compute.Resources{CPUMillicores: 500, MemoryMiB: 512},
			Replicas:  1,
			Ports:     []compute.PortSpec{{Number: 8080}},
			Identity:  mustIdentity(t, p, "api"),
		})
		if err != nil {
			t.Fatalf("EnsureService: %v", err)
		}
		return rt, sub, svc.Ref
	}

	t.Run("absent is not an error", func(t *testing.T) {
		t.Parallel()
		rt, sub, ref := newService(t)
		if err := corruptEffectiveSpec(ctx, sub, ""); err != nil {
			t.Fatalf("removing the annotation: %v", err)
		}
		st, err := rt.DescribeService(ctx, ref)
		if err != nil {
			t.Fatalf("DescribeService with an absent effective-spec annotation returned %v, "+
				"want nil: an object this provider has not (yet) rendered an annotation for is "+
				"not a defect", err)
		}
		if st.Spec.Replicas != 0 {
			t.Errorf("DescribeService with an absent annotation reported Spec.Replicas=%d, "+
				"want the zero spec", st.Spec.Replicas)
		}
	})

	t.Run("malformed IS an error, and a different one", func(t *testing.T) {
		t.Parallel()
		rt, sub, ref := newService(t)
		if err := corruptEffectiveSpec(ctx, sub, `{"Replicas":`); err != nil {
			t.Fatalf("corrupting the annotation: %v", err)
		}
		_, err := rt.DescribeService(ctx, ref)
		if err == nil {
			t.Fatal("DescribeService with a malformed effective-spec annotation returned nil, " +
				"want an error: this is the exact bug USOSS-69 reports -- a present-but-garbled " +
				"annotation was silently treated the same as an absent one")
		}
		if !errors.Is(err, compute.ErrFailed) {
			t.Errorf("DescribeService with a malformed annotation returned %v, want an error "+
				"wrapping compute.ErrFailed", err)
		}
	})
}
