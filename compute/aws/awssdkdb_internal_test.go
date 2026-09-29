// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/compute"
)

// This file names an AWS SDK type, which is why it is on
// TestOnlyTheAdapterFilesImportAnAWSSDK's allowlist: it tests an adapter's error
// classification, and the errors are the SDK's.
//
// That allowlist caught the first draft of this test, which lived in
// database_internal_test.go. The right response was to move the test to the file
// the allowlist already names for this reason, not to add another name to the
// allowlist — a control widened to make something pass is a control that stops
// meaning anything.

// TestADynamoDBThrottleIsTransient closes a gap this ticket created rather than
// found.
//
// The shared throttle list drops `ProvisionedThroughputExceededException`
// because the string was unnameable while DynamoDB was fenced into store/ — the
// boundary checker refused it, correctly. This ticket widens that fence for
// compute/aws and adds a port that makes real DynamoDB calls, so the omission
// stopped being theoretical: a throttled call would have been classified
// terminal, telling a caller its spec has to change when waiting would have
// worked.
//
// It is the class of regression the overlap analysis cannot see — nothing in this
// ticket edited the throttle list, and the behaviour it depends on moved
// underneath it.
//
// Driven through the adapter rather than through the predicate, because what
// matters is the answer a caller gets.
func TestADynamoDBThrottleIsTransient(t *testing.T) {
	t.Parallel()
	adapter := &sdkDynamoDB{}
	p := &Provider{name: DefaultName}

	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"a provisioned-throughput throttle": {
			err:  &dynamodbtypes.ProvisionedThroughputExceededException{},
			want: compute.ErrTransient,
		},
		"a request-limit throttle": {
			err:  &dynamodbtypes.RequestLimitExceeded{},
			want: compute.ErrTransient,
		},
		// The controls. A throttle test that also claimed these would be
		// widening rather than classifying.
		"a missing table": {
			err:  &dynamodbtypes.ResourceNotFoundException{},
			want: compute.ErrNotFound,
		},
		"a table already in use": {
			err:  &dynamodbtypes.ResourceInUseException{},
			want: compute.ErrTransient,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := p.substrateError(adapter.err(tc.err))
			if !errors.Is(got, tc.want) {
				t.Errorf("classified as %v, want %v. A throttle reported terminal tells a caller "+
					"to change a spec that was correct", got, tc.want)
			}
		})
	}

	// And a cancelled context still wins, which is the ordering claim the
	// throttle-first check rests on.
	if got := adapter.err(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Errorf("a cancelled context classified as %v; the throttle test must not claim it", got)
	}
}

// TestEveryEC2CodeIsPlacedInExactlyOneClass is the audit review asked for, as a
// test rather than as a table in a comment.
//
// The ruling was to name the class rather than remove one entry: malformed,
// already-there and absent are three answers, and the not-found set conflated
// two of them. So this asserts the partition — every code in exactly one class,
// no code in two — and then asserts what each class *classifies as*, because a
// partition with the wrong destinations is still wrong.
//
// The load-bearing assertion is the last one: **nothing outside the absent set
// may classify as ErrNoSuchResource.** Absence is the answer that produces an
// empty read, so that is the direction the port must never guess in.
// TestTheEC2CodeSetsArePartitionedAndPlacedByName checks the placement of the
// codes this package lists, and deliberately does not claim to know EC2's
// vocabulary.
//
// # What the old name got wrong
//
// It was TestEveryEC2CodeIsPlacedInExactlyOneClass, and review demonstrated the
// problem the honest way: **that test passed the exact malformed→absent
// reversion it existed to catch.** It could not do otherwise. It read the three
// sets, checked they were disjoint, and then asked the provider what each set
// classified as — so moving a code from one set to another moved it in the
// expectation at the same time. Every assertion was the sets validating
// themselves.
//
// "Every" is a claim about a population, and this population is a list somebody
// typed: EC2 has no generated typed exceptions, so there is nothing to derive it
// from. A test whose name asserts completeness over a hand-maintained list stops
// the next reader from asking the question the name has already answered.
//
// # The oracle that is not the sets
//
// AWS's error codes carry their class in their name, and that convention is
// independent of how this package has sorted them:
//
//	suffix ".NotFound"      absence
//	suffix ".Duplicate"     the thing is already there
//	contains "Malformed"    the input could not be parsed
//
// So the placement can be adjudicated without consulting the classification.
// This is what fails on the reversion: `InvalidGroupId.Malformed` contains
// "Malformed", so it may not sit in the absent set no matter what the absent set
// says it means.
//
// Codes whose name carries no convention are enumerated, because a carve-out
// that grows silently is the same defect one level up. There is exactly **one**
// today — `InvalidParameterValue` — and it is placed by judgement, which is
// stated rather than hidden.
//
// What still is not verified here: that these are the codes EC2 sends. Nothing
// inside this package can establish that. The construction that makes the gap
// safe is the fail-closed default, and it has its own test —
// [TestAnUnlistedEC2CodeIsNeverReadAsAbsence].
func TestTheEC2CodeSetsArePartitionedAndPlacedByName(t *testing.T) {
	t.Parallel()
	adapter := &sdkEC2{}
	p := &Provider{name: DefaultName}

	classes := map[string][]string{
		"absent":    ec2AbsentCodes,
		"exists":    ec2ExistsCodes,
		"malformed": ec2MalformedCodes,
	}
	// The partition. A code in two classes means one of them is unreachable,
	// and which one depends on evaluation order rather than on meaning.
	seen := map[string]string{}
	total := 0
	for class, codes := range classes {
		if len(codes) == 0 {
			t.Fatalf("the %q class is empty, so the assertions over it are about nothing", class)
		}
		for _, code := range codes {
			total++
			if other, dup := seen[code]; dup {
				t.Errorf("%q is in both the %q and %q classes; which one wins is then a matter "+
					"of evaluation order rather than of what the code means", code, other, class)
			}
			seen[code] = class
		}
	}
	// The count is asserted exactly, and against the sets rather than against a
	// number typed here, because review was right that a bare `total < 8` is a
	// denominator nobody can maintain: eight was the size of one audit, not a
	// population, and a threshold that must be edited by hand to stay true is the
	// same defect this test's rename was about. What the assertion is for is that
	// the three classes are the whole partition -- a fourth set added without
	// being registered above would leave its codes unchecked.
	if want := len(ec2AbsentCodes) + len(ec2ExistsCodes) + len(ec2MalformedCodes); total != want {
		t.Fatalf("walked %d codes across the registered classes and the three sets hold %d; a "+
			"class this test does not know about has codes nothing here checks", total, want)
	}

	// Placement adjudicated by AWS's naming convention rather than by this
	// package's own sorting. This is the assertion the previous version lacked,
	// and the one that fails on a code moved between classes.
	byName := []struct {
		class string
		holds func(string) bool
		why   string
	}{
		{"absent", func(c string) bool { return strings.HasSuffix(c, ".NotFound") },
			`a ".NotFound" suffix is AWS saying the thing is not there`},
		{"exists", func(c string) bool { return strings.HasSuffix(c, ".Duplicate") },
			`a ".Duplicate" suffix is AWS saying the thing is already there`},
		{"malformed", func(c string) bool { return strings.Contains(c, "Malformed") },
			`"Malformed" is AWS saying it could not parse the input`},
	}
	// Placed by judgement because the name carries no convention. Enumerated so
	// that a second one cannot appear without this list being edited.
	const conventionFree = "InvalidParameterValue"
	freeCount := 0
	for _, code := range append(append(append([]string{},
		ec2AbsentCodes...), ec2ExistsCodes...), ec2MalformedCodes...) {
		if code == conventionFree {
			freeCount++
			if seen[code] != "malformed" {
				t.Errorf("%q is placed in %q; it is the one code here whose name carries no "+
					"convention, and the judgement recorded for it is that an unusable parameter "+
					"is an unparseable input", code, seen[code])
			}
			continue
		}
		matched := ""
		for _, rule := range byName {
			if rule.holds(code) {
				if matched != "" {
					t.Errorf("%q matches the naming convention for both %q and %q, so the "+
						"convention cannot adjudicate it and it belongs in the enumerated "+
						"exceptions", code, matched, rule.class)
				}
				matched = rule.class
				if seen[code] != rule.class {
					t.Errorf("%q is in the %q class, but %s, so it belongs in %q. This is the "+
						"assertion the sets cannot make about themselves: it reads the code's "+
						"name, not this package's opinion of it", code, seen[code], rule.why,
						rule.class)
				}
			}
		}
		if matched == "" {
			t.Errorf("%q matches no naming convention and is not in the enumerated exceptions, "+
				"so nothing outside the sets adjudicates its placement; either it follows a "+
				"convention this test does not know, or it is a second judgement call and has "+
				"to be recorded as one", code)
		}
	}
	if freeCount != 1 {
		t.Errorf("%d convention-free code(s) in the sets, want exactly 1 (%q). The count is "+
			"asserted because a carve-out list that grows quietly is the same defect as a "+
			"population list that does", freeCount, conventionFree)
	}

	// What each class classifies as, through the provider's own mapping. This is
	// the self-referential half — kept, because a correctly placed code with a
	// broken mapping is a real failure — and it is no longer the only half.
	for class, want := range map[string]error{
		"absent":    compute.ErrNotFound,
		"exists":    compute.ErrTransient,
		"malformed": compute.ErrInvalidSpec,
	} {
		for _, code := range classes[class] {
			got := p.substrateError(adapter.err(&smithy.GenericAPIError{Code: code}))
			if !errors.Is(got, want) {
				t.Errorf("%q is classified %q and surfaced as %v, want %v", code, class, got, want)
			}
		}
	}
}

// TestAnUnlistedEC2CodeIsNeverReadAsAbsence pins the construction that carries
// every code the hand-maintained sets do not name.
//
// The sets cannot be complete, so completeness is not what makes them safe. What
// makes them safe is that **absence is the one answer that produces an empty
// read** — a caller told nothing may reach its database — and that no code
// outside the absent set can reach it, including codes this package has never
// heard of.
func TestAnUnlistedEC2CodeIsNeverReadAsAbsence(t *testing.T) {
	t.Parallel()
	adapter := &sdkEC2{}
	p := &Provider{name: DefaultName}

	unlisted := []string{
		// Real EC2 codes deliberately not in any set.
		"InvalidGroup.InUse", "DependencyViolation", "RequestExpired",
		"UnauthorizedOperation", "RulesPerSecurityGroupLimitExceeded",
		// And the case the sets can never cover.
		"SomeCodeAWSAddedLater",
	}
	// Everything outside the absent set, listed or not.
	corpus := append([]string{}, unlisted...)
	corpus = append(corpus, ec2ExistsCodes...)
	corpus = append(corpus, ec2MalformedCodes...)
	for _, code := range corpus {
		got := p.substrateError(adapter.err(&smithy.GenericAPIError{Code: code}))
		if errors.Is(got, compute.ErrNotFound) {
			t.Errorf("%q classified as compute.ErrNotFound. Absence is the one answer that "+
				"produces an empty read, so a code this package cannot confidently call absent "+
				"must not be treated as absent", code)
		}
	}
}

// TestAMalformedSecurityGroupIDDoesNotReadBackAsEmptyIngress is review's A1,
// driven through the public path they used rather than through the classifier.
//
// The classifier test above proves the mapping; this proves the *consequence* is
// gone. They are different claims: a correct mapping consumed by a caller that
// treats ErrInvalidSpec as "continue" would still produce the empty read.
func TestAMalformedSecurityGroupIDDoesNotReadBackAsEmptyIngress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := Config{
		Region:           MemoryRegion,
		DefaultPlacement: "default",
		PollInterval:     time.Millisecond,
		Placements: map[string]PlacementConfig{"default": {
			VPC:                        MemoryVPC,
			Subnets:                    []string{"apphub-test-subnet-one", "apphub-test-subnet-two"},
			ControlPlaneSecurityGroups: []string{"apphub-test-control-plane-sg"},
		}},
		Identity: IdentityConfig{NamePrefix: "apphub-"},
		Relational: &RelationalConfig{
			NamePrefix:     "apphub-",
			EngineVersions: map[compute.SQLEngine][]string{compute.EnginePostgres: {"16"}},
		},
	}
	sub := NewMemorySubstrate()
	p, err := New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	rp, err := p.Relational()
	if err != nil {
		t.Fatalf("Relational: %v", err)
	}
	st, err := rp.EnsureRelational(ctx, compute.RelationalSpec{
		Name: "malformed", Engine: compute.EnginePostgres, EngineVersion: "16",
		DatabaseName: "appdb", AdminUsername: "appuser",
		AdminPassword: compute.NewSecretValue("irrelevant-to-this-assertion"),
		Capacity:      compute.CapacityRange{MinUnits: 0.25, MaxUnits: 2},
		Ingress: []compute.IngressRule{
			{From: compute.Peer{Kind: compute.PeerControlPlane}, Port: postgresPort},
		},
	})
	if err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	// The rule really is there, so an empty answer below would be hiding it.
	before, err := rp.DescribeRelational(ctx, st.Ref)
	if err != nil {
		t.Fatalf("the first DescribeRelational: %v", err)
	}
	if len(before.Spec.Ingress) == 0 {
		t.Fatal("the endpoint has no ingress rules, so this test is about nothing")
	}

	// The SDK-shaped error EC2 returns for an identifier it cannot parse,
	// through the real adapter mapping rather than an injected sentinel.
	malformed := (&sdkEC2{}).err(&smithy.GenericAPIError{
		Code: "InvalidGroupId.Malformed", Message: "Invalid id: \"sg-not-an-id\"",
	})
	sub.EC2 = failingEC2{EC2API: sub.EC2, failByID: malformed}

	got, err := rp.DescribeRelational(ctx, st.Ref)
	if err == nil {
		t.Fatalf("DescribeRelational succeeded with a malformed security-group identifier and "+
			"reported %d ingress rule(s). A malformed input is not an absent resource: the first "+
			"is a spec error the caller must fix, the second is a state the caller may create, "+
			"and treating one as the other says nothing may reach a database because of a typo",
			len(got.Spec.Ingress))
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("the failure surfaced as %v, want compute.ErrInvalidSpec: a caller can act on a "+
			"malformed identifier, and what they must do is fix an input", err)
	}
}

// TestAPortRangeSurvivesTheRoundTripAndStaysRevocable is the regression for a
// security defect USOSS-11's reviewer found on the EC2API shape all three
// database/container tickets share.
//
// # The defect
//
// A rule read off a group used to carry one port, and a range was reported as
// Port: -1 — a value no desired rule can equal, so a range always landed in the
// removal set. That reasoning was right. The representation defeated it: to
// revoke, the rule has to be rendered back into an EC2 permission, and -1 is not
// a port. What EC2 answers to a revoke of port -1 is not knowable from here, and
// the two plausible answers are not equally bad. InvalidParameterValue fails the
// reconcile; InvalidPermission.NotFound is [ErrNoSuchResource], which
// [Provider.reconcileIngress] tolerates as a concurrent teardown — and then the
// reconcile returns nil while a wide rule is still authorised. On the container
// port the surviving rule was 1024-65535 from 0.0.0.0/0.
//
// # Why the assertion is a round trip and not a reconcile
//
// USOSS-11 reported that their in-memory EC2 did not reproduce it: the fake
// matched the sentinel rule by equality and removed it, so end to end it looked
// correct. The fake accepts what the real adapter cannot render. So this asserts
// on the rendering itself — [securityGroupRecord] then [ipPermissions], both of
// them the production path — where the loss actually happens. A representation
// that cannot round-trip a rule cannot revoke it, whatever the fake says.
func TestAPortRangeSurvivesTheRoundTripAndStaysRevocable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		from, to int32
	}{
		{"the wide range that survived a revoke on the container port", 1024, 65535},
		{"a narrow range", 5432, 5433},
		{"a single port, which must not grow a span", 5432, 5432},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := ec2types.IpPermission{
				IpProtocol: awssdk.String("tcp"),
				FromPort:   awssdk.Int32(tc.from),
				ToPort:     awssdk.Int32(tc.to),
				IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
			}
			rec, err := securityGroupRecord(&ec2types.SecurityGroup{
				GroupId:       awssdk.String("sg-round-trip"),
				IpPermissions: []ec2types.IpPermission{original},
			})
			if err != nil {
				t.Fatalf("reading a permission back: %v", err)
			}
			if len(rec.Ingress) != 1 {
				t.Fatalf("one permission read back as %d rule(s)", len(rec.Ingress))
			}
			back, err := ipPermissions(rec.Ingress)
			if err != nil {
				t.Fatalf("a rule read straight off a group could not be rendered back: %v. "+
					"Anything the substrate can hold has to be expressible, or it cannot be "+
					"revoked", err)
			}
			if len(back) != 1 {
				t.Fatalf("one rule rendered as %d permission(s)", len(back))
			}
			gotFrom := awssdk.ToInt32(back[0].FromPort)
			gotTo := awssdk.ToInt32(back[0].ToPort)
			if gotFrom != tc.from || gotTo != tc.to {
				t.Errorf("ports %d-%d read back and re-rendered as %d-%d. A revoke is built from "+
					"this permission, so a rule that does not survive the round trip is a rule "+
					"this provider cannot remove — and reporting success for a revoke that "+
					"removed nothing leaves the rule authorised", tc.from, tc.to, gotFrom, gotTo)
			}
		})
	}
}

// TestARangeIsStillNotSomethingThisProviderAsksFor keeps the property the
// sentinel was introduced to provide, now that the sentinel is gone.
//
// Removing the marker value must not make a range look desired. It does not,
// because a range has FromPort != ToPort and every rule this provider builds
// goes through [singlePort], so no desired rule can equal one.
func TestARangeIsStillNotSomethingThisProviderAsksFor(t *testing.T) {
	t.Parallel()

	desired := singlePort("tcp", 5432, "apphub control plane")
	if desired.FromPort != desired.ToPort {
		t.Fatalf("singlePort built a range: %v-%v", desired.FromPort, desired.ToPort)
	}
	rec, err := securityGroupRecord(&ec2types.SecurityGroup{
		GroupId: awssdk.String("sg-wide"),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: awssdk.String("tcp"),
			FromPort:   awssdk.Int32(1024),
			ToPort:     awssdk.Int32(65535),
			IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
		}},
	})
	if err != nil {
		t.Fatalf("reading the wide permission back: %v", err)
	}
	for _, observed := range rec.Ingress {
		if observed == desired {
			t.Errorf("a 1024-65535 range compared equal to the single port this provider asks "+
				"for, so reconciliation would leave it in place: %+v", observed)
		}
		if observed.FromPort == observed.ToPort {
			t.Errorf("a range read back as a single port %v, which is the loss this struct's "+
				"second field exists to prevent", observed.FromPort)
		}
	}
}

// TestARenderingRefusalIsNotReadAsAbsence is the second half of the port-range
// fix, and it is the half that matters even after the first one.
//
// [Provider.reconcileIngress] tolerates [ErrNoSuchResource] on a revoke, which is
// correct: the removal set is computed from a read that may be a moment stale, so
// a rule the service says is already gone is a benign concurrent teardown. The
// tolerance is therefore a channel through which a *different* failure can be
// read as the desired state. Nothing this package refuses on its own may travel
// down it.
//
// Asserted at both levels, because either alone is satisfiable by the wrong fix:
// the refusal itself carries no substrate sentinel, and a reconcile driven
// through an EC2 that renders the way the SDK adapter does fails rather than
// reporting success.
func TestARenderingRefusalIsNotReadAsAbsence(t *testing.T) {
	t.Parallel()

	unrenderable := map[string]SecurityGroupRule{
		"no source at all": {Protocol: "tcp", FromPort: Port(5432), ToPort: Port(5432)},
		"a port above the SDK's range": {
			Protocol: "tcp", FromPort: Port(70000), ToPort: Port(70000), SourceCIDR: "0.0.0.0/0",
		},
		"a port below it": {
			Protocol: "tcp", FromPort: Port(-2), ToPort: Port(-2), SourceCIDR: "0.0.0.0/0",
		},
	}
	for name, rule := range unrenderable {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ipPermissions([]SecurityGroupRule{rule})
			if err == nil {
				t.Fatalf("%+v rendered into a permission; a permission that does not describe "+
					"the rule is worse than no call, because the service then answers about the "+
					"permission it was handed", rule)
			}
			// The whole point. Any of these would let the reconciler's tolerance
			// swallow the refusal and report a revoke that removed nothing.
			for _, sentinel := range []error{
				ErrNoSuchResource, ErrAlreadyExists, ErrMalformed, ErrThrottled, ErrDenied,
			} {
				if errors.Is(err, sentinel) {
					t.Errorf("the refusal carries %v. A caller cannot then tell \"I cannot "+
						"describe your rule\" from the service's own answer, and on the revoke "+
						"path ErrNoSuchResource is tolerated -- so the reconcile would report "+
						"success while the rule stood: %v", sentinel, err)
				}
			}
		})
	}
}

// TestEveryEC2IngressShapeStaysRepresentable is the round-four blocker, and the
// population is taken from the SDK type rather than from the shapes this
// provider has met.
//
// # Why the previous fix was not enough
//
// Round three fixed a reported witness — tcp/1024-65535 — by giving the rule two
// port numbers instead of one. The invariant claimed was much broader: anything
// EC2 can return must stay expressible so that reconciliation can revoke it. It
// was not. `types.IpPermission` has seven fields, and the fix addressed one axis:
//
//	IpProtocol        a string, and it changes what the ports MEAN
//	FromPort, ToPort  *int32 -- OPTIONAL, and -1 is a legal ICMP wildcard
//	IpRanges          IPv4 sources
//	Ipv6Ranges        IPv6 sources
//	PrefixListIds     managed-prefix-list sources     <- had no field at all
//	UserIdGroupPairs  group sources, with an owner    <- owner was dropped
//
// Review found three consequences, and the first is worse than the defect round
// three fixed:
//
//  1. a permission whose only source was a prefix list produced **zero rules**,
//     so it could never enter the removal set and stayed authorised with nothing
//     pointing at it. A strange value in a read-back is an anomaly somebody may
//     notice; zero rules is indistinguishable from an empty group. Silent
//     omission is the fail-open with the evidence removed.
//  2. an all-protocol permission omits both ports, and nil became a non-nil zero
//     on the way back, so the revoke was not built from the permission EC2
//     returned.
//  3. ICMP's documented -1/-1 wildcard was refused, because the bound written for
//     TCP ports rejected every negative value. That is a **false refusal
//     introduced by the fix for a silent one** — both from the same missing axis,
//     since -1 was a sentinel in this package and a real value in the SDK at the
//     same time.
//
// # What this asserts
//
// Every shape below round-trips through the production path — `securityGroupRecord`
// then `ipPermissions` — back to the permission EC2 gave, field for field
// including the nil-ness of the ports. A shape that cannot round-trip cannot be
// revoked, and any shape this package cannot express must be an **error at the
// read** rather than a rule it silently drops.
func TestEveryEC2IngressShapeStaysRepresentable(t *testing.T) {
	t.Parallel()

	i32 := func(v int32) *int32 { return &v }
	for _, tc := range []struct {
		name string
		perm ec2types.IpPermission
	}{
		{"the reported TCP range", ec2types.IpPermission{
			IpProtocol: awssdk.String("tcp"), FromPort: i32(1024), ToPort: i32(65535),
			IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
		}},
		{"a prefix-list source, which used to read back as no rules at all",
			ec2types.IpPermission{
				IpProtocol: awssdk.String("tcp"), FromPort: i32(5432), ToPort: i32(5432),
				PrefixListIds: []ec2types.PrefixListId{{
					PrefixListId: awssdk.String("pl-0abc123"),
					Description:  awssdk.String("a managed prefix list"),
				}},
			}},
		{"all protocols with the ports omitted, which must stay omitted",
			ec2types.IpPermission{
				IpProtocol: awssdk.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8")}},
			}},
		{"the ICMP wildcard, which is -1/-1 and legal", ec2types.IpPermission{
			IpProtocol: awssdk.String("icmp"), FromPort: i32(-1), ToPort: i32(-1),
			IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8")}},
		}},
		{"an ICMP type with a wildcard code", ec2types.IpPermission{
			IpProtocol: awssdk.String("icmpv6"), FromPort: i32(128), ToPort: i32(-1),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}},
		}},
		{"a cross-account group pair, whose owner is part of the rule",
			ec2types.IpPermission{
				IpProtocol: awssdk.String("tcp"), FromPort: i32(5432), ToPort: i32(5432),
				UserIdGroupPairs: []ec2types.UserIdGroupPair{{
					GroupId: awssdk.String("sg-0abc123"),
					UserId:  awssdk.String("apphub-test-account-placeholder"),
				}},
			}},
		{"a source with NO description, which must not become an empty one",
			ec2types.IpPermission{
				IpProtocol: awssdk.String("tcp"), FromPort: i32(5432), ToPort: i32(5432),
				IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("10.0.0.0/8")}},
			}},
		{"a source with an EMPTY description, which is a different permission",
			ec2types.IpPermission{
				IpProtocol: awssdk.String("tcp"), FromPort: i32(5432), ToPort: i32(5432),
				IpRanges: []ec2types.IpRange{{
					CidrIp: awssdk.String("10.0.0.0/8"), Description: awssdk.String(""),
				}},
			}},
		{"an IPv6 range", ec2types.IpPermission{
			IpProtocol: awssdk.String("tcp"), FromPort: i32(5432), ToPort: i32(5432),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("2001:db8::/32")}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, err := securityGroupRecord(&ec2types.SecurityGroup{
				GroupId:       awssdk.String("sg-grammar"),
				IpPermissions: []ec2types.IpPermission{tc.perm},
			})
			if err != nil {
				t.Fatalf("reading the permission back: %v", err)
			}
			if len(rec.Ingress) != 1 {
				t.Fatalf("one permission read back as %d rule(s). Zero means the rule is "+
					"invisible to reconciliation and stays authorised with nothing pointing "+
					"at it", len(rec.Ingress))
			}
			back, err := ipPermissions(rec.Ingress)
			if err != nil {
				t.Fatalf("a permission read straight off a group could not be rendered back: "+
					"%v. Anything the substrate can hold has to be expressible, or it cannot "+
					"be revoked", err)
			}
			if len(back) != 1 {
				t.Fatalf("one rule rendered as %d permission(s)", len(back))
			}
			assertPermissionsMatch(t, tc.perm, back[0])
		})
	}
}

// assertPermissionsMatch compares a rendered permission with the one EC2 gave,
// on every axis the revoke is matched by.
//
// The port comparison is on the POINTERS' nil-ness as well as their values,
// because that is precisely what round three got wrong: an omitted port became a
// non-nil zero, and a permission with 0/0 is not a permission with no span.
func assertPermissionsMatch(t *testing.T, want, got ec2types.IpPermission) {
	t.Helper()
	if awssdk.ToString(want.IpProtocol) != awssdk.ToString(got.IpProtocol) {
		t.Errorf("protocol %q rendered as %q",
			awssdk.ToString(want.IpProtocol), awssdk.ToString(got.IpProtocol))
	}
	for _, p := range []struct {
		field     string
		want, got *int32
	}{
		{"FromPort", want.FromPort, got.FromPort},
		{"ToPort", want.ToPort, got.ToPort},
	} {
		switch {
		case p.want == nil && p.got != nil:
			t.Errorf("%s was omitted and rendered as a pointer to %d. An all-protocol "+
				"permission states no span, and a non-nil zero is a different permission",
				p.field, *p.got)
		case p.want != nil && p.got == nil:
			t.Errorf("%s was %d and rendered as omitted", p.field, *p.want)
		case p.want != nil && *p.want != *p.got:
			t.Errorf("%s %d rendered as %d", p.field, *p.want, *p.got)
		}
	}
	for _, arm := range []struct {
		name      string
		want, got []string
	}{
		{"IpRanges", cidrs(want.IpRanges), cidrs(got.IpRanges)},
		{"Ipv6Ranges", cidrs6(want.Ipv6Ranges), cidrs6(got.Ipv6Ranges)},
		{"PrefixListIds", prefixLists(want.PrefixListIds), prefixLists(got.PrefixListIds)},
		{"UserIdGroupPairs", pairs(want.UserIdGroupPairs), pairs(got.UserIdGroupPairs)},
	} {
		if !slices.Equal(arm.want, arm.got) {
			t.Errorf("%s was %v and rendered as %v", arm.name, arm.want, arm.got)
		}
	}
}

func cidrs(in []ec2types.IpRange) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, awssdk.ToString(r.CidrIp)+"|"+describe(r.Description))
	}
	return out
}

// describe renders a description for comparison, distinguishing absent from
// empty.
//
// EC2 returning no description and EC2 returning an empty one are different
// permissions, and the description is carried into the revoke -- so comparing
// them through ToString would hide exactly the defect this distinguishes. Found
// by USOSS-11's generated cross product, which failed 241 of 288 cells without
// it.
func describe(d *string) string {
	if d == nil {
		return "<absent>"
	}
	return "<empty-or-set:" + *d + ">"
}

func cidrs6(in []ec2types.Ipv6Range) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, awssdk.ToString(r.CidrIpv6)+"|"+describe(r.Description))
	}
	return out
}

func prefixLists(in []ec2types.PrefixListId) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, awssdk.ToString(r.PrefixListId)+"|"+describe(r.Description))
	}
	return out
}

func pairs(in []ec2types.UserIdGroupPair) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, awssdk.ToString(r.UserId)+"/"+awssdk.ToString(r.GroupId)+"|"+describe(r.Description))
	}
	return out
}

// TestAPermissionWithNoSourceIsAnErrorNotZeroRules is the tripwire for the shape
// this package cannot express.
//
// The grammar is closed over every source arm the SDK declares, so the only
// permission left that produces no rule is one with no source at all. That must
// be loud. "This permission cannot be represented" is an acceptable answer;
// "zero rules" is not, because zero rules is indistinguishable from an empty
// group and leaves whatever EC2 was describing authorised.
func TestAPermissionWithNoSourceIsAnErrorNotZeroRules(t *testing.T) {
	t.Parallel()
	_, err := securityGroupRecord(&ec2types.SecurityGroup{
		GroupId: awssdk.String("sg-sourceless"),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: awssdk.String("tcp"),
			FromPort:   awssdk.Int32(5432),
			ToPort:     awssdk.Int32(5432),
		}},
	})
	if err == nil {
		t.Fatal("a permission with no source of any kind was read without error, so it " +
			"contributed no rule and nothing said so")
	}
	// Same rule as a rendering refusal: it must not be readable as absence.
	for _, sentinel := range []error{ErrNoSuchResource, ErrAlreadyExists, ErrMalformed} {
		if errors.Is(err, sentinel) {
			t.Errorf("the read refusal carries %v, which a caller could read as the group or "+
				"the rule being absent: %v", sentinel, err)
		}
	}
}

// TestTeardownStateFaultsAreTransient pins the classification a retrying teardown
// depends on: every refusal RDS and EC2 give while a deletion is still settling
// reaches the caller as [compute.ErrTransient].
//
// Driven through the real adapters' err and then [Provider.substrateError],
// because what matters is the answer a caller gets. The instance fault is the
// one a code-string list would miss: its code is "InvalidDBInstanceState", with
// no "Fault" suffix.
//
// The control is an unrelated fault through each adapter. Without it, a mapping
// that made every RDS or EC2 error transient would pass, and a spec error would
// be retried until the caller's budget ran out.
func TestTeardownStateFaultsAreTransient(t *testing.T) {
	t.Parallel()
	p := &Provider{name: DefaultName}
	rdsErr := (&sdkRDS{}).err
	ec2Err := (&sdkEC2{}).err

	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"a cluster whose instance is still deleting": {
			err: rdsErr(&rdstypes.InvalidDBClusterStateFault{}), want: compute.ErrTransient,
		},
		"an instance that is already deleting": {
			err: rdsErr(&rdstypes.InvalidDBInstanceStateFault{}), want: compute.ErrTransient,
		},
		"a subnet group still held by its cluster": {
			err: rdsErr(&rdstypes.InvalidDBSubnetGroupStateFault{}), want: compute.ErrTransient,
		},
		"a security group whose interfaces linger": {
			err: ec2Err(&smithy.GenericAPIError{Code: "DependencyViolation"}), want: compute.ErrTransient,
		},
		"a security group still in use": {
			err: ec2Err(&smithy.GenericAPIError{Code: "ResourceInUse"}), want: compute.ErrTransient,
		},
		"control: an unrelated RDS fault": {
			err: rdsErr(&smithy.GenericAPIError{Code: "InvalidParameterCombination"}), want: compute.ErrFailed,
		},
		"control: an unrelated EC2 fault": {
			err: ec2Err(&smithy.GenericAPIError{Code: "InvalidGroup.Reserved"}), want: compute.ErrFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := p.substrateError(tc.err)
			if !errors.Is(got, tc.want) {
				t.Errorf("classified as %v, want %v", got, tc.want)
			}
		})
	}
}

// settlingRDS refuses DeleteCluster while the instance deletion it follows is
// still settling, the way RDS does: once, with the adapter's own classification
// of InvalidDBClusterStateFault.
type settlingRDS struct {
	RDSAPI
	mu      sync.Mutex
	refuses int
}

func (s *settlingRDS) DeleteCluster(ctx context.Context, id string) error {
	s.mu.Lock()
	refuse := s.refuses > 0
	if refuse {
		s.refuses--
	}
	s.mu.Unlock()
	if refuse {
		return (&sdkRDS{}).err(&rdstypes.InvalidDBClusterStateFault{Message: awssdk.String(
			"Cluster cannot be deleted, it still contains DB instances in non-deleting state.")})
	}
	return s.RDSAPI.DeleteCluster(ctx, id)
}

// lingeringEC2 refuses DeleteSecurityGroup while RDS's network interfaces are
// still attached, with the adapter's own classification of DependencyViolation.
type lingeringEC2 struct {
	EC2API
	mu      sync.Mutex
	refuses int
}

func (l *lingeringEC2) DeleteSecurityGroup(ctx context.Context, id string) error {
	l.mu.Lock()
	refuse := l.refuses > 0
	if refuse {
		l.refuses--
	}
	l.mu.Unlock()
	if refuse {
		return (&sdkEC2{}).err(&smithy.GenericAPIError{Code: "DependencyViolation",
			Message: "resource sg-x has a dependent object"})
	}
	return l.EC2API.DeleteSecurityGroup(ctx, id)
}

// TestDeleteRelationalConvergesUnderRetry is the teardown a live database really
// gets: the first pass is refused at the cluster, the second at the security
// group, and the third finishes -- with every step the earlier passes completed
// treated as already done rather than as a failure.
//
// Each pass has to answer ErrTransient for a retrying caller to reach the next
// one. The final assertions read the substrate rather than the port, because an
// idempotent Delete that returned nil having deleted nothing would satisfy a
// port-level check.
func TestDeleteRelationalConvergesUnderRetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := Config{
		Region:           MemoryRegion,
		DefaultPlacement: "default",
		PollInterval:     time.Millisecond,
		Placements: map[string]PlacementConfig{"default": {
			VPC:                        MemoryVPC,
			Subnets:                    []string{"apphub-test-subnet-one", "apphub-test-subnet-two"},
			ControlPlaneSecurityGroups: []string{"apphub-test-control-plane-sg"},
		}},
		Identity: IdentityConfig{NamePrefix: "apphub-"},
		Relational: &RelationalConfig{
			NamePrefix:     "apphub-",
			EngineVersions: map[compute.SQLEngine][]string{compute.EnginePostgres: {"16"}},
		},
	}
	sub := NewMemorySubstrate()
	p, err := New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	rp, err := p.Relational()
	if err != nil {
		t.Fatalf("Relational: %v", err)
	}
	st, err := rp.EnsureRelational(ctx, compute.RelationalSpec{
		Name: "teardown", Engine: compute.EnginePostgres, EngineVersion: "16",
		DatabaseName: "appdb", AdminUsername: "appuser",
		AdminPassword: compute.NewSecretValue("irrelevant-to-this-assertion"),
		Capacity:      compute.CapacityRange{MinUnits: 0.25, MaxUnits: 2},
	})
	if err != nil {
		t.Fatalf("EnsureRelational: %v", err)
	}
	id, err := p.resolve(st.Ref, compute.KindRelational)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	names, err := p.relationalNamesFor(id)
	if err != nil {
		t.Fatalf("relationalNamesFor: %v", err)
	}
	if _, err := sub.EC2.DescribeSecurityGroupByName(ctx, names.SecurityGroup, MemoryVPC); err != nil {
		t.Fatalf("the endpoint has no security group, so the EC2 half of this test is about "+
			"nothing: %v", err)
	}

	settling := &settlingRDS{RDSAPI: sub.RDS, refuses: 1}
	lingering := &lingeringEC2{EC2API: sub.EC2, refuses: 1}
	sub.RDS, sub.EC2 = settling, lingering

	for pass, refusedAt := range []string{"the cluster", "the security group"} {
		if err := rp.DeleteRelational(ctx, st.Ref); !errors.Is(err, compute.ErrTransient) {
			t.Fatalf("pass %d, refused at %s, = %v, want compute.ErrTransient; a teardown loop "+
				"that retries only ErrTransient stops here", pass+1, refusedAt, err)
		}
	}
	if err := rp.DeleteRelational(ctx, st.Ref); err != nil {
		t.Fatalf("the third pass, with nothing left settling, = %v, want nil", err)
	}
	if settling.refuses != 0 || lingering.refuses != 0 {
		t.Fatalf("an armed refusal was never reached (cluster %d, security group %d left), so "+
			"the transient passes above were about something else", settling.refuses, lingering.refuses)
	}

	if _, err := sub.RDS.DescribeInstance(ctx, names.Instance); !errors.Is(err, ErrNoSuchResource) {
		t.Errorf("the instance survived teardown: %v", err)
	}
	if _, err := sub.RDS.DescribeCluster(ctx, names.Cluster); !errors.Is(err, ErrNoSuchResource) {
		t.Errorf("the cluster survived teardown: %v", err)
	}
	if _, err := sub.RDS.DescribeSubnetGroup(ctx, names.SubnetGroup); !errors.Is(err, ErrNoSuchResource) {
		t.Errorf("the subnet group survived teardown: %v", err)
	}
	if _, err := sub.EC2.DescribeSecurityGroupByName(ctx, names.SecurityGroup, MemoryVPC); !errors.Is(err, ErrNoSuchResource) {
		t.Errorf("the security group survived teardown: %v", err)
	}
}

// TestASubnetGroupReadsBackWithItsTags pins the adapter against RDS's own
// shape: DescribeDBSubnetGroups returns no tags, so a describe that stopped
// there read every group this platform created as unowned, and every deploy
// retry after the first failed at relational-database.
func TestASubnetGroupReadsBackWithItsTags(t *testing.T) {
	t.Parallel()
	const arn = "arn:aws:rds:us-west-2:account:subgrp:apphub-app"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing the request: %v", err)
		}
		w.Header().Set("Content-Type", "text/xml")
		var body string
		switch action := r.Form.Get("Action"); action {
		case "DescribeDBSubnetGroups":
			body = fmt.Sprintf(`<DescribeDBSubnetGroupsResponse><DescribeDBSubnetGroupsResult>`+
				`<DBSubnetGroups><DBSubnetGroup><DBSubnetGroupName>apphub-app</DBSubnetGroupName>`+
				`<DBSubnetGroupArn>%s</DBSubnetGroupArn><Subnets><Subnet>`+
				`<SubnetIdentifier>subnet-1</SubnetIdentifier></Subnet></Subnets>`+
				`</DBSubnetGroup></DBSubnetGroups></DescribeDBSubnetGroupsResult>`+
				`</DescribeDBSubnetGroupsResponse>`, arn)
		case "ListTagsForResource":
			if got := r.Form.Get("ResourceName"); got != arn {
				t.Errorf("listed tags for %q, want %q", got, arn)
			}
			body = `<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>` +
				`<Tag><Key>apphub:managed-by</Key><Value>apphub</Value></Tag>` +
				`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`
		default:
			t.Errorf("unexpected RDS action %q", action)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("writing the response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client := rds.New(rds.Options{
		Region:       "us-west-2",
		BaseEndpoint: awssdk.String(srv.URL),
		Credentials:  awssdk.AnonymousCredentials{},
	})
	rec, err := (&sdkRDS{c: client}).DescribeSubnetGroup(context.Background(), "apphub-app")
	if err != nil {
		t.Fatalf("DescribeSubnetGroup: %v", err)
	}
	if got := rec.Tags[tagManagedBy]; got != managedByValue {
		t.Errorf("the group read back with %s=%q, want %q; its ownership is invisible",
			tagManagedBy, got, managedByValue)
	}
	if !slices.Equal(rec.SubnetIDs, []string{"subnet-1"}) {
		t.Errorf("subnets read back as %v", rec.SubnetIDs)
	}
}

// TestATableReadsBackWithItsTags pins the adapter against DynamoDB's own shape:
// DescribeTable returns no tags, so a describe that stopped there read every
// table this platform created as unowned, and every redeploy after the first
// failed at key-value-table.
func TestATableReadsBackWithItsTags(t *testing.T) {
	t.Parallel()
	const arn = "arn:aws:dynamodb:us-west-2:account:table/apphub-app"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request: %v", err)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		var out string
		switch target := r.Header.Get("X-Amz-Target"); target {
		case "DynamoDB_20120810.DescribeTable":
			out = fmt.Sprintf(`{"Table":{"TableName":"apphub-app","TableArn":%q,`+
				`"TableStatus":"ACTIVE","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}]}}`, arn)
		case "DynamoDB_20120810.ListTagsOfResource":
			if !strings.Contains(string(body), arn) {
				t.Errorf("listed tags with %s, want the table ARN %q", body, arn)
			}
			out = `{"Tags":[{"Key":"apphub:managed-by","Value":"apphub"}]}`
		default:
			t.Errorf("unexpected DynamoDB target %q", target)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := io.WriteString(w, out); err != nil {
			t.Errorf("writing the response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	client := dynamodb.New(dynamodb.Options{
		Region:       "us-west-2",
		BaseEndpoint: awssdk.String(srv.URL),
		Credentials:  awssdk.AnonymousCredentials{},
	})
	rec, err := (&sdkDynamoDB{c: client}).DescribeTable(context.Background(), "apphub-app")
	if err != nil {
		t.Fatalf("DescribeTable: %v", err)
	}
	if got := rec.Tags[tagManagedBy]; got != managedByValue {
		t.Errorf("the table read back with %s=%q, want %q; its ownership is invisible",
			tagManagedBy, got, managedByValue)
	}
	if rec.PartitionKey != "pk" {
		t.Errorf("partition key read back as %q", rec.PartitionKey)
	}
}
