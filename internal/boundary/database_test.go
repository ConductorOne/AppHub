// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"strings"
	"testing"
)

// USOSS-14 changed two gates, and this file is the fixture obligation that comes
// with doing that: a check that is modified without a fixture that fails before
// and passes after is a check nobody has tried to defeat.
//
// The two changes:
//
//   - `dynamodb-fenced` gained one allowed prefix, compute/aws, because
//     provisioning a table for a deployed application is the other side of the
//     port that fence guards. Its idiom half gained one allowed *file*.
//   - `aws-sdk-confined` is new: the AWS SDK is denied to every package except
//     the AWS provider and the persistence fence.
//
// Each test below asks whether the change let something through that should not
// have got through, rather than whether the change works.

// TestTheDynamoDBFenceStillBitesAfterTheProviderWasAllowed is the question a
// reviewer will ask about the widening, asked in code.
//
// The whole risk of adding an allowed prefix is that prefix matching is more
// generous than it looks, or that the entry was written where it accidentally
// covers a parent. So the fixture puts an SDK import in four places: the two that
// are allowed, one package *next to* the allowed one, and one nowhere near it.
func TestTheDynamoDBFenceStillBitesAfterTheProviderWasAllowed(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		// Allowed: the persistence fence, and the compute provider that
		// provisions a table for a deployed application.
		apphub("/store"):       {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
		apphub("/compute/aws"): {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
		// Denied: a sibling of the allowed package, which is what a prefix
		// written one segment too short would let through.
		apphub("/compute/k8s"): {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
		// Denied: the parent of the allowed package. If the entry had been
		// "compute" rather than "compute/aws", this would pass and the fence
		// would be off for every provider.
		apphub("/compute"): {"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"},
		// Denied: ordinary business logic, the case the fence was written for.
		apphub("/modules/deploy"): {"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"},
	}), "linux")

	denied := map[string]bool{}
	for _, v := range got {
		if v.RuleName == "dynamodb-fenced" {
			denied[v.Package] = true
		}
	}
	for _, want := range []string{"/compute/k8s", "/compute", "/modules/deploy"} {
		if !denied[apphub(want)] {
			t.Errorf("%s imports the DynamoDB SDK and was not flagged by dynamodb-fenced; the "+
				"widening for the compute provider has taken the fence off more than one package",
				apphub(want))
		}
	}
	for _, allowed := range []string{"/store", "/compute/aws"} {
		if denied[apphub(allowed)] {
			t.Errorf("%s is on the allowlist and was flagged anyway", apphub(allowed))
		}
	}
	if len(denied) != 3 {
		t.Errorf("dynamodb-fenced flagged %d packages, want exactly 3: %v", len(denied), denied)
	}
}

// TestAWSSDKIsConfinedToTheProviderAndTheFence exercises the new rule the same
// way: on what it must deny, not on what it must allow.
//
// The rule denies the SDK by module prefix rather than by service package, which
// is the property that keeps it from going stale — a service released tomorrow is
// denied without anybody editing a list. The fixture therefore includes a service
// nothing in this repository uses.
func TestAWSSDKIsConfinedToTheProviderAndTheFence(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/compute/aws"): {"github.com/aws/aws-sdk-go-v2/service/rds"},
		apphub("/store"):       {"github.com/aws/aws-sdk-go-v2/service/dynamodb"},
		// The acceptance criterion for USOSS-14, as a graph assertion: the
		// package that provisions roles and extensions must not be able to reach
		// an AWS SDK at all. The source system's equivalent file imports one
		// solely to pass a config through to a Parameter Store lookup.
		apphub("/postgres"): {"github.com/aws/aws-sdk-go-v2/service/ssm"},
		// A service this repository does not use, to show the rule is over the
		// module rather than over an enumeration of services. It is also the
		// parent of an allowed package: credentials/aws may reach the SDK and
		// credentials itself may not, which is the entry written one segment too
		// short. postgres/ depends on the root package, so this is the
		// acceptance criterion's other end.
		apphub("/credentials"): {"github.com/aws/aws-sdk-go-v2/service/kms"},
		// Allowed: an AWS credential provider cannot be written without the
		// SDK's signer and STS. USOSS-9 landed this package on main after the
		// rule had gone green, and the composition -- not either half -- would
		// have turned main red.
		apphub("/credentials/aws"): {"github.com/aws/aws-sdk-go-v2/service/sts"},
		// smithy is the SDK's own runtime and is denied with it: a package that
		// reads a smithy.APIError is branching on an AWS error shape, which is
		// the coupling the compute taxonomy exists to remove.
		apphub("/modules/deploy"): {"github.com/aws/smithy-go"},
	}), "linux")

	denied := map[string]bool{}
	for _, v := range got {
		if v.RuleName == "aws-sdk-confined" {
			denied[v.Package] = true
		}
	}
	for _, want := range []string{"/postgres", "/credentials", "/modules/deploy"} {
		if !denied[apphub(want)] {
			t.Errorf("%s reaches an AWS SDK and aws-sdk-confined did not flag it", apphub(want))
		}
	}
	for _, allowed := range []string{"/compute/aws", "/store", "/credentials/aws"} {
		if denied[apphub(allowed)] {
			t.Errorf("%s is on the allowlist and was flagged anyway", apphub(allowed))
		}
	}
}

// TestAWSSDKConfinementCatchesATransitiveReach is the bypass worth checking,
// because it is the one that has actually happened on this project: a wrapper
// package that imports the forbidden thing and a caller that imports the
// wrapper.
func TestAWSSDKConfinementCatchesATransitiveReach(t *testing.T) {
	t.Parallel()
	got := DefaultConfig().CheckGraph(graph(map[string][]string{
		apphub("/postgres"):            {apphub("/internal/awswrapper")},
		apphub("/internal/awswrapper"): {"github.com/aws/aws-sdk-go-v2/service/ssm"},
	}), "linux")
	var forPostgres bool
	for _, v := range got {
		if v.RuleName == "aws-sdk-confined" && v.Package == apphub("/postgres") {
			forPostgres = true
		}
	}
	if !forPostgres {
		t.Fatalf("a package reaching the SDK through a wrapper was not flagged, so the "+
			"confinement can be defeated by adding one indirection: %v", got)
	}
}

// TestTheIdiomExemptionIsTwoAdapterFilesNotThePackage is the fixture for the
// other half of the fence.
//
// The exemption is two paths rather than a package, and the reason is that
// compute/aws is thousands of lines under active extension by six tickets. If the
// entry were the package, a `dynamodbav` tag anywhere in it would pass — which is
// exactly the leak the idiom rule exists to catch and exactly what a provisioning
// adapter has no reason to contain.
//
// The two are the SDK adapter and the adapter's own test. The test is named
// because it has to reference the exception types whose classification it checks;
// the case below proves that a *different* test file in the same package is still
// refused, which is the property that keeps this two files rather than a
// convention.
func TestTheIdiomExemptionIsTwoAdapterFilesNotThePackage(t *testing.T) {
	t.Parallel()
	rule := DefaultDynamoDBIdiomRule()

	// The two exempt files. The adapter names a request field because
	// CreateTable has to; its test names an exception type.
	for _, exempt := range []SourceFile{
		{
			Path: "compute/aws/awssdkdb.go",
			Content: []byte(`package aws

func create() any { return struct{ BillingMode string }{} }
`),
		},
		{
			Path: "compute/aws/awssdkdb_internal_test.go",
			Content: []byte(`package aws

var throttle = "ProvisionedThroughputExceededException"
`),
		},
	} {
		if leaks := rule.Check([]SourceFile{exempt}); len(leaks) != 0 {
			t.Errorf("%s is exempt and was flagged anyway: %v", exempt.Path, leaks)
		}
	}

	// Every other file in the same package is still checked, including for the
	// same needle and for the needles that really are persistence idiom.
	for _, f := range []SourceFile{
		{
			// A different test file in the same package. This is the case that
			// keeps the exemption two files rather than "the adapter and
			// anything that looks like its test".
			Path: "compute/aws/database_internal_test.go",
			Content: []byte(`package aws

var throttle = "ProvisionedThroughputExceededException"
`),
		},
		{
			Path: "compute/aws/keyvalue.go",
			Content: []byte(`package aws

func create() any { return struct{ BillingMode string }{} }
`),
		},
		{
			Path: "compute/aws/database.go",
			Content: []byte(`package aws

type row struct {
	ID string ` + "`dynamodbav:\"ID\"`" + `
}
`),
		},
		{
			// A file whose name merely starts with the exempt one's, which is
			// what a naive prefix match would let through. hasPathPrefix is
			// segment-aware, so it must not.
			Path: "compute/aws/awssdkdb.go.helper.go",
			Content: []byte(`package aws

const q = "PK = :pk AND begins_with(SK, :sk)"
`),
		},
	} {
		if leaks := rule.Check([]SourceFile{f}); len(leaks) == 0 {
			t.Errorf("%s carries DynamoDB idiom and was not flagged; the exemption covers more "+
				"than the one file it names", f.Path)
		}
	}
}

// TestThePostgresPackageHasNoAWSImportInTheRealTree is the acceptance criterion
// asserted against the repository rather than against a fixture.
//
// The criterion USOSS-14 was given is "database_extensions.go has no AWS import
// after the port". A structural check over the whole package is the strongest
// available form of it, and the graph check above proves the rule would catch a
// violation; this proves there is not one today. Both are needed: a rule that
// works on fixtures and a tree that satisfies it are different claims.
func TestThePostgresPackageHasNoAWSImportInTheRealTree(t *testing.T) {
	t.Parallel()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}
	// Through the same scan the real gate uses, so this cannot pass over a file
	// set the gate would never see.
	scanned, err := ScanFiles(root, DefaultModulePrefix)
	if err != nil {
		t.Fatalf("scanning %s: %v", root, err)
	}
	all, err := SourcesFrom(root, scanned)
	if err != nil {
		t.Fatalf("reading sources under %s: %v", root, err)
	}
	var files []SourceFile
	for _, f := range all {
		if hasPathPrefix(f.Path, "postgres") {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		// A derivation that returns nothing passes every check over it.
		t.Fatal("no files found under postgres/, so this assertion is about nothing")
	}
	for _, f := range files {
		for _, line := range strings.Split(string(f.Content), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				// A comment may discuss the constraint; explaining one must not
				// be what violates it.
				continue
			}
			if strings.Contains(trimmed, `"github.com/aws/`) {
				t.Errorf("%s imports an AWS SDK: %s. The whole point of this package is that the "+
					"master-password lookup goes through compute.SecretStore, so a Postgres "+
					"provisioner can run against any substrate", f.Path, trimmed)
			}
		}
	}
}
