// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

// The object-store adapter's own test file, and it is separate from
// objectstore_test.go for the reason TestOnlyTheAdapterFilesImportAnAWSSDK
// exists: everything above Substrate has to be the same code against an account
// and against memory, which is only true while the SDK cannot be reached from
// anywhere but an adapter and the tests of one. This test's subject IS the
// adapter's constructor -- whether a caller outside the package can wire an
// SDK-backed object store from the exported surface -- so it needs the SDK, and
// keeping it in the file that also tests the port logic would have licensed that
// whole file to reach for it.

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	"github.com/aws/aws-sdk-go-v2/service/s3vectors"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/compute/ext"
)

// TestAProviderIsConstructibleFromTheExportedSurfaceAlone is the test whose
// absence was the defect.
//
// Every other test in this package builds its provider with
// [aws.NewMemorySubstrate], so none of them ever asked whether a *caller* could
// build one. The answer was no: `NewSDKSubstrate` took three clients and never
// populated S3, and the concrete adapters are unexported, so `ObjectStores()`
// refused on every real substrate. **A port with full conformance coverage and no
// path to instantiate it** — which is the widest possible version of testing at a
// lower seam than the thing being claimed.
//
// So this constructs the way a composition root does: exported identifiers only,
// no reach into the package's internals, and it asserts the ports come back
// rather than asserting anything about what they then do. No network: a client
// with no credentials is a perfectly good client until it is asked to make a
// call, and reachability is decided before that.
func TestAProviderIsConstructibleFromTheExportedSurfaceAlone(t *testing.T) {
	t.Parallel()

	// The clients a composition root would hand over. Constructed from an empty
	// config on purpose -- where credentials come from is not this package's
	// decision, and this test must not depend on any being present.
	base := awssdk.Config{Region: "us-east-1"}
	sub := aws.NewSDKSubstrateFrom(aws.SDKClients{
		ECR:       ecr.NewFromConfig(base),
		IAM:       iam.NewFromConfig(base),
		STS:       sts.NewFromConfig(base),
		S3:        s3.NewFromConfig(base),
		S3Tables:  s3tables.NewFromConfig(base),
		S3Vectors: s3vectors.NewFromConfig(base),
	})

	// Each field must actually be populated. Asserted individually because a
	// substrate with five of six wired is the defect this test exists for, and
	// "the constructor returned something" does not distinguish the two.
	for name, got := range map[string]bool{
		"ECR": sub.ECR != nil, "IAM": sub.IAM != nil, "STS": sub.STS != nil,
		"S3": sub.S3 != nil, "S3Tables": sub.S3Tables != nil, "S3Vectors": sub.S3Vectors != nil,
	} {
		if !got {
			t.Errorf("NewSDKSubstrate left Substrate.%s nil, so a provider configured for it "+
				"cannot serve the port and aws.New refuses", name)
		}
	}

	p, err := aws.New(sub, aws.Config{
		Region:           "us-east-1",
		DefaultPlacement: "default",
		Placements:       map[string]aws.PlacementConfig{"default": {}},
		Identity:         aws.IdentityConfig{PathPrefix: "/apphub/", NamePrefix: "apphub-"},
		ObjectStore: &aws.ObjectStoreConfig{
			NamePrefix: "apphub-", TableBuckets: true, VectorBuckets: true,
		},
	})
	if err != nil {
		t.Fatalf("aws.New with an SDK substrate and an object store: %v", err)
	}

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores() on an SDK-backed provider: %v — the port is unreachable in "+
			"production even though the conformance suite passes against memory", err)
	}
	if !p.Capabilities().Has(compute.CapObjectStore) {
		t.Error("the provider serves ObjectStores() and does not advertise CapObjectStore")
	}

	// And the two ext ports, which are reached by lookup rather than by an
	// accessor -- so nothing else in this package would notice them missing.
	if _, err := ext.TableBuckets(p.Name(), store); err != nil {
		t.Errorf("ext.TableBuckets on an SDK-backed provider with TableBuckets enabled: %v", err)
	}
	if _, err := ext.VectorBuckets(p.Name(), store); err != nil {
		t.Errorf("ext.VectorBuckets on an SDK-backed provider with VectorBuckets enabled: %v", err)
	}
}
