// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/compute/ext"
)

// newObjectStore returns a provider with object storage and the substrate behind
// it, so a test can plant an unowned resource.
func newObjectStore(t *testing.T) (*aws.Provider, *aws.Substrate, compute.ObjectStore) {
	t.Helper()
	sub := aws.NewMemorySubstrate()
	p, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("aws.New(): %v", err)
	}
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	return p, sub, store
}

func TestZonalObjectStoreIsAContractRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, store := newObjectStore(t)
	s3 := sub.S3.(*aws.MemoryS3)

	if p.Capabilities().Has(compute.CapObjectStoreZonal) {
		t.Fatalf("the AWS provider advertises %q, but S3 Express One Zone has no safe "+
			"ownership check for this port", compute.CapObjectStoreZonal)
	}

	for _, tc := range []struct {
		name string
		spec compute.BucketSpec
		want error
	}{
		{
			name: "zonal class",
			spec: compute.BucketSpec{Name: "zonal", Class: compute.ObjectClassZonal, Zone: "use1-az1"},
			want: compute.ErrUnsupported,
		},
		{
			name: "standard bucket with zone",
			spec: compute.BucketSpec{Name: "standard-with-zone", Zone: "use1-az1"},
			want: compute.ErrInvalidSpec,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s3.ResetOperations()

			got, err := store.EnsureBucket(ctx, tc.spec)
			if !errors.Is(err, tc.want) {
				t.Fatalf("EnsureBucket(%+v) = (%+v, %v), want error matching %v",
					tc.spec, got, err, tc.want)
			}
			if ops := s3.Operations(); len(ops) != 0 {
				t.Fatalf("EnsureBucket(%+v) touched S3 before refusing: %v", tc.spec, ops)
			}
			if buckets := s3.Dump(); len(buckets) != 0 {
				t.Fatalf("EnsureBucket(%+v) left buckets behind: %v", tc.spec, buckets)
			}
		})
	}
}

// TestDescribeBucketRefusesABucketItDoesNotOwn is the case the ownership table
// records for DescribeBucket.
//
// A read-back is not exempt. Reporting somebody else's bucket as this platform's
// is a lie a caller acts on: it will grant access to it, write to it, and delete
// it on teardown.
func TestDescribeBucketRefusesABucketItDoesNotOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, store := newObjectStore(t)

	owned, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "mine"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	// The same physical name, re-planted without the ownership tags.
	sub.S3.(*aws.MemoryS3).PutUnowned(owned.Name, aws.MemoryRegion)

	if _, err := store.DescribeBucket(ctx, owned.Ref); !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("DescribeBucket on an unowned bucket = %v, want compute.ErrNotOwned", err)
	}
	_ = p
}

// TestBucketOwnershipIsCheckedOnEveryPath drives every ref-taking method on the
// port against a bucket this platform did not create.
//
// One table over the methods rather than a test each, because the property is
// about the *set*: a method added later that reads a ref and skips the check is
// the defect, and a per-method test cannot notice one that does not exist yet.
// TestEveryPortMethodThatTakesARefIsCoveredByAnOwnershipCase is the other half —
// it fails if a method appears with no case recorded here.
func TestBucketOwnershipIsCheckedOnEveryPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		call func(store compute.ObjectStore, bucket, identity compute.Ref) error
	}{
		{"DeleteBucket", func(s compute.ObjectStore, b, _ compute.Ref) error {
			return s.DeleteBucket(ctx, b)
		}},
		{"EmptyBucket", func(s compute.ObjectStore, b, _ compute.Ref) error {
			return s.EmptyBucket(ctx, b)
		}},
		{"Grant", func(s compute.ObjectStore, b, id compute.Ref) error {
			return s.Grant(ctx, b, id, compute.AccessRead)
		}},
		{"Revoke", func(s compute.ObjectStore, b, id compute.Ref) error {
			return s.Revoke(ctx, b, id)
		}},
		// A read is in this table for the reason the ownership class states: the
		// invariant is about acting on the strength of a resource, not only about
		// mutating it, and reporting a stranger's bucket as carrying this
		// platform's grant is a lie a caller acts on. It is also the direction
		// that fails open -- a read-back that answered here would tell a
		// reconciler an unowned bucket has no grants, and the reconciler would
		// then write one.
		{"DescribeGrant", func(s compute.ObjectStore, b, id compute.Ref) error {
			_, err := s.DescribeGrant(ctx, b, id)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, sub, store := newObjectStore(t)

			// Establish the state first, then take it away. A fixture planted
			// before the resource exists tests the wrong thing, and a snapshot
			// taken before the setup reports the setup as the mutation.
			bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
			if err != nil {
				t.Fatalf("EnsureBucket(): %v", err)
			}
			identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
				Name: "reader", RunsOn: compute.RuntimeContainer,
			})
			if err != nil {
				t.Fatalf("EnsureWorkloadIdentity(): %v", err)
			}
			sub.S3.(*aws.MemoryS3).PutUnowned(bucket.Name, aws.MemoryRegion)

			if err := tc.call(store, bucket.Ref, identity.Ref); !errors.Is(err, compute.ErrNotOwned) {
				t.Errorf("%s against an unowned bucket = %v, want compute.ErrNotOwned", tc.name, err)
			}
		})
	}
}

// TestAGrantOnOneFlavourDoesNotReachAnother is the property the bucket flavour in
// the Ref exists for.
//
// Three services provision something this interface calls a bucket, and
// compute.KindBucket is the only kind for all three. Without the flavour in the
// Ref's ID, a grant on a table bucket would read the general-purpose bucket of
// the same name — a different resource — and both would contend for one inline
// policy name, so granting on one would silently overwrite the grant on the
// other.
func TestAGrantOnOneFlavourDoesNotReachAnother(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newObjectStore(t)

	tables, err := ext.TableBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.TableBuckets(): %v", err)
	}

	// The same logical name in both services.
	const logical = "analytics"
	plain, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: logical})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	table, err := tables.EnsureTableBucket(ctx, compute.BucketSpec{Name: logical})
	if err != nil {
		t.Fatalf("EnsureTableBucket(): %v", err)
	}
	if plain.Ref == table.Ref {
		t.Fatal("a general-purpose bucket and a table bucket of the same logical name share a Ref, " +
			"so no Grant can tell which service to check")
	}

	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "reader", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	if err := store.Grant(ctx, plain.Ref, identity.Ref, compute.AccessRead); err != nil {
		t.Fatalf("Grant on the general-purpose bucket: %v", err)
	}
	if err := tables.Grant(ctx, table.Ref, identity.Ref, compute.AccessReadWrite); err != nil {
		t.Fatalf("Grant on the table bucket: %v", err)
	}

	// Two grants, not one overwritten.
	grants, err := p.Harness().Grants(ctx, identity.Ref)
	if err != nil {
		t.Fatalf("Harness().Grants(): %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("after granting on two flavours of %q the role holds %d policies (%v); want 2 — "+
			"one overwrote the other, which is what a flavour-blind policy name does",
			logical, len(grants), grants)
	}

	// And revoking one leaves the other. Teardown of one resource must not
	// silently remove access to a different one.
	if err := store.Revoke(ctx, plain.Ref, identity.Ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	after, err := p.Harness().Grants(ctx, identity.Ref)
	if err != nil {
		t.Fatalf("Harness().Grants() after revoke: %v", err)
	}
	if len(after) != 1 {
		t.Errorf("after revoking one flavour the role holds %d policies (%v); want 1", len(after), after)
	}
}

// TestAccessReadGrantsNothingThatMutates reads back the policy this provider
// actually wrote and asserts the actions rather than the intent.
//
// Asserting the document rather than the level is the point: "AccessRead maps to
// a read-only action set" is a claim about a table in policy.go, and a claim about
// a table is satisfied by the table agreeing with itself. What a caller
// experiences is the document.
func TestAccessReadGrantsNothingThatMutates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, store := newObjectStore(t)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "reader", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	if err := store.Grant(ctx, bucket.Ref, identity.Ref, compute.AccessRead); err != nil {
		t.Fatalf("Grant(): %v", err)
	}

	role := strings.TrimPrefix(identity.Ref.ID, "role/")
	names, err := sub.IAM.ListRolePolicyNames(ctx, role)
	if err != nil {
		t.Fatalf("ListRolePolicies(): %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("one grant produced %d policies: %v", len(names), names)
	}
	doc, err := sub.IAM.GetRolePolicy(ctx, role, names[0])
	if err != nil {
		t.Fatalf("GetRolePolicy(): %v", err)
	}

	var parsed struct {
		Statement []struct {
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource any      `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("the stored policy is not valid JSON: %v", err)
	}

	// Every verb a read grant must not carry. Matched as a substring of the
	// action, because "s3:PutObject" and "s3:PutBucketPolicy" are both Put and
	// neither belongs in a read.
	forbidden := []string{"Put", "Delete", "Create", "Write", "Abort", "Restore", "Replicate", "*"}
	for _, st := range parsed.Statement {
		if st.Effect != "Allow" {
			t.Errorf("a grant produced a %q statement; this provider writes only Allow, and a Deny "+
				"here would be invisible to the least-privilege reading of the Action list", st.Effect)
		}
		for _, action := range st.Action {
			for _, bad := range forbidden {
				if strings.Contains(action, bad) {
					t.Errorf("AccessRead granted %q, which contains %q. A read grant that can "+
						"mutate is the escalation this level exists to prevent, and it is invisible "+
						"to a caller who asked for read", action, bad)
				}
			}
		}
	}
}

// TestNoPolicyThisProviderWritesCanDelegateAccess is the escalation gate.
//
// A workload holding a resource-policy write can grant a third party access to
// its own bucket, which turns any level into an unbounded one. The actions are
// excluded from every level in every flavour, so this asserts over all of them
// rather than over the one that seemed risky.
func TestNoPolicyThisProviderWritesCanDelegateAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, store := newObjectStore(t)

	tables, err := ext.TableBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.TableBuckets(): %v", err)
	}
	vectors, err := ext.VectorBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.VectorBuckets(): %v", err)
	}

	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "worker", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	role := strings.TrimPrefix(identity.Ref.ID, "role/")

	// Every flavour, at every level it offers. AccessAdmin is refused on a plain
	// bucket and offered on the other two, so a refusal is a legal outcome here
	// and only a *granted* forbidden action is a failure.
	plain, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "plain"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	table, err := tables.EnsureTableBucket(ctx, compute.BucketSpec{Name: "tbl"})
	if err != nil {
		t.Fatalf("EnsureTableBucket(): %v", err)
	}
	vector, err := vectors.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "vec"})
	if err != nil {
		t.Fatalf("EnsureVectorBucket(): %v", err)
	}

	granted := 0
	for _, resource := range []compute.Ref{plain.Ref, table.Ref, vector.Ref} {
		for _, level := range []compute.AccessLevel{
			compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin,
		} {
			if err := store.Grant(ctx, resource, identity.Ref, level); err != nil {
				continue // a refused level grants nothing
			}
			granted++
			names, lerr := sub.IAM.ListRolePolicyNames(ctx, role)
			if lerr != nil {
				t.Fatalf("ListRolePolicies(): %v", lerr)
			}
			for _, name := range names {
				doc, gerr := sub.IAM.GetRolePolicy(ctx, role, name)
				if gerr != nil {
					t.Fatalf("GetRolePolicy(): %v", gerr)
				}
				for _, bad := range []string{
					"PutBucketPolicy", "PutTableBucketPolicy", "PutTablePolicy",
					"PutVectorBucketPolicy", "PutBucketAcl", "PutPublicAccessBlock",
					"PutBucketEncryption", "DeletePublicAccessBlock", "PutAccessPointPolicy",
				} {
					if strings.Contains(doc, bad) {
						t.Errorf("%s at %s granted %s: a workload that can write a resource policy "+
							"can delegate access to anyone, which makes every level unbounded",
							resource.ID, level, bad)
					}
				}
			}
		}
	}
	if granted == 0 {
		t.Fatal("no level was granted on any flavour, so this check exercised nothing")
	}
}

// TestNoIdentifierBelongingToADeploymentIsCompiledIn is the disclosure gate.
//
// The source system hardcodes three real AWS account identifiers as IAM role ARN
// constants (bucket.go:508-513). Every deployment-specific identifier in this
// package is configuration with no default, and this asserts that mechanically
// over the package's own source — including its test files, because a fixture is
// as public as a constant once the repository is.
//
// It scans for the *shape* rather than for any value, so nothing this test
// contains is itself a disclosure. That is the same reason .gitleaks.toml's
// twelve-digit rule has an empty allowlist: a detection rule that names the thing
// it detects publishes it.
func TestNoIdentifierBelongingToADeploymentIsCompiledIn(t *testing.T) {
	t.Parallel()

	// A standalone run of exactly twelve digits: an AWS account identifier's
	// shape. Bounded on both sides so a longer number -- a timestamp, a size --
	// does not match, and so a shorter one does not either.
	accountShape := regexp.MustCompile(`(^|[^0-9])[0-9]{12}([^0-9]|$)`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the package: %v", err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d Go files in this package, which cannot be right; a scan that reads "+
			"nothing passes", len(files))
	}
	scanned := 0
	for _, name := range files {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(body), "\n") {
			if accountShape.MatchString(line) {
				t.Errorf("%s:%d matches the shape of an AWS account identifier. Every "+
					"deployment-specific identifier in this package is configuration with no "+
					"default; if this is a fixture, use a word instead -- a test file is as "+
					"public as a constant. Line: %q", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	t.Logf("scanned %d files in this package", scanned)
}

// TestTheIdentifierScanCanFail is the negative fixture for the gate above.
//
// A scan that reports nothing is indistinguishable from a scan that reads
// nothing, and the gate's own guard against reading nothing is a file count --
// which does not prove the pattern works. This proves the pattern.
func TestTheIdentifierScanCanFail(t *testing.T) {
	t.Parallel()

	shape := regexp.MustCompile(`(^|[^0-9])[0-9]{12}([^0-9]|$)`)

	// The fixtures are BUILT rather than written, and that is not fastidiousness:
	// the first version of this test spelled twelve-digit runs as literals, and
	// the gate above -- which scans this file too -- failed on them. Correctly. A
	// negative fixture for a disclosure check cannot contain the thing it
	// detects, or the check has to exempt its own test file, and an exemption is
	// the hole. So digits() composes a run of any length at runtime and no
	// literal of the forbidden shape exists in this package's source.
	digits := func(n int) string { return strings.Repeat("1234567890", (n/10)+1)[:n] }

	for _, tc := range []struct {
		line string
		want bool
	}{
		{`arn:aws:iam::` + digits(12) + `:role/x`, true},
		{`Account: "` + digits(12) + `",`, true},
		{`arn:aws:iam::` + aws.MemoryAccount + `:role/x`, false},
		// Boundaries: eleven and thirteen digits are not this shape.
		{`n := ` + digits(11), false},
		{`n := ` + digits(13), false},
		// A twelve-digit run inside a longer one is not a standalone match.
		{`sha := ` + digits(28), false},
	} {
		if got := shape.MatchString(tc.line); got != tc.want {
			t.Errorf("the account-shape pattern matched %q = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestTheExtPortsRefuseWhatTheyCannotApply is the read-back invariant on the two
// lookup-only ports.
//
// Both used to accept `Class=zonal` and `PublicAccess=true`, apply neither, and
// **return them in the effective spec** — so a caller reading the result back was
// told the substrate held configuration it does not have. That is not a gap in
// coverage; it is the read-back reporting a request as a fact.
//
// The table is over (port × field) rather than a case each, because the property
// is about the set: a third field, or a third lookup-only port, is the defect this
// cannot otherwise notice.
func TestTheExtPortsRefuseWhatTheyCannotApply(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newObjectStore(t)

	tables, err := ext.TableBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.TableBuckets(): %v", err)
	}
	vectors, err := ext.VectorBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.VectorBuckets(): %v", err)
	}

	ports := map[string]func(compute.BucketSpec) (*compute.Bucket, error){
		"table":  func(s compute.BucketSpec) (*compute.Bucket, error) { return tables.EnsureTableBucket(ctx, s) },
		"vector": func(s compute.BucketSpec) (*compute.Bucket, error) { return vectors.EnsureVectorBucket(ctx, s) },
	}
	unapplicable := map[string]compute.BucketSpec{
		"zonal class":   {Name: "a", Class: compute.ObjectClassZonal},
		"a zone":        {Name: "b", Zone: "use1-az1"},
		"public access": {Name: "c", PublicAccess: true},
	}

	for portName, ensure := range ports {
		for field, spec := range unapplicable {
			t.Run(portName+"/"+field, func(t *testing.T) {
				t.Parallel()
				got, err := ensure(spec)
				if err == nil {
					t.Fatalf("Ensure accepted %s and returned effective spec %+v; it applies "+
						"nothing for that field, so accepting it reports a request as a fact",
						field, got.Spec)
				}
				if !errors.Is(err, compute.ErrInvalidSpec) && !errors.Is(err, compute.ErrUnsupported) {
					t.Errorf("Ensure refused %s with %v; a refusal has to be typed so a caller can "+
						"tell it from a substrate failure", field, err)
				}
			})
		}
	}

	// And the accepted path reports the effective class rather than the empty
	// request, because "" means "the provider's default" and the read-back is
	// supposed to say what that resolved to.
	got, err := tables.EnsureTableBucket(ctx, compute.BucketSpec{Name: "plain"})
	if err != nil {
		t.Fatalf("EnsureTableBucket on an applicable spec: %v", err)
	}
	if got.Spec.Class != compute.ObjectClassStandard {
		t.Errorf("the effective spec reports Class %q; an empty request means the provider's "+
			"default and the read-back should name it", got.Spec.Class)
	}
}

// TestExtBucketOwnershipIsCheckedOnEveryPath is the ext half of the ownership
// matrix.
//
// It exists because the ownership-coverage derivation could not see these four
// methods until it took the concrete type rather than the accessor's interface:
// the ext ports are reached by a lookup helper, so they appear on no interface
// compute.Provider returns. Deleting the check inside DeleteTableBucket compiled
// and the whole package stayed green.
//
// Each flavour plants its unowned fixture in its own service, which is the point
// of the flavour existing: a table bucket's ownership lives in S3 Tables' tags and
// nowhere else.
func TestExtBucketOwnershipIsCheckedOnEveryPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		plant func(*aws.Substrate, string)
		// prepare creates the resource so there is something to un-own, and
		// returns its physical name and Ref. Establishing the state before
		// taking it away is deliberate: a fixture planted first tests a
		// different thing, and a snapshot taken first reports the setup as the
		// mutation.
		prepare func(compute.ObjectStore, *aws.Provider) (*compute.Bucket, error)
		call    func(compute.ObjectStore, *aws.Provider, compute.Ref) error
	}{
		{
			name:  "EnsureTableBucket",
			plant: func(s *aws.Substrate, n string) { s.S3Tables.(*aws.MemoryS3Tables).PutUnowned(n) },
			prepare: func(st compute.ObjectStore, p *aws.Provider) (*compute.Bucket, error) {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "tbl"})
			},
			call: func(st compute.ObjectStore, p *aws.Provider, _ compute.Ref) error {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				_, err = tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "tbl"})
				return err
			},
		},
		{
			name:  "DeleteTableBucket",
			plant: func(s *aws.Substrate, n string) { s.S3Tables.(*aws.MemoryS3Tables).PutUnowned(n) },
			prepare: func(st compute.ObjectStore, p *aws.Provider) (*compute.Bucket, error) {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "tbl"})
			},
			call: func(st compute.ObjectStore, p *aws.Provider, ref compute.Ref) error {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				return tb.DeleteTableBucket(ctx, ref)
			},
		},
		{
			name:  "EnsureVectorBucket",
			plant: func(s *aws.Substrate, n string) { s.S3Vectors.(*aws.MemoryS3Vectors).PutUnowned(n) },
			prepare: func(st compute.ObjectStore, p *aws.Provider) (*compute.Bucket, error) {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "vec"})
			},
			call: func(st compute.ObjectStore, p *aws.Provider, _ compute.Ref) error {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				_, err = vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "vec"})
				return err
			},
		},
		{
			name:  "DeleteVectorBucket",
			plant: func(s *aws.Substrate, n string) { s.S3Vectors.(*aws.MemoryS3Vectors).PutUnowned(n) },
			prepare: func(st compute.ObjectStore, p *aws.Provider) (*compute.Bucket, error) {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "vec"})
			},
			call: func(st compute.ObjectStore, p *aws.Provider, ref compute.Ref) error {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				return vb.DeleteVectorBucket(ctx, ref)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, sub, store := newObjectStore(t)

			got, err := tc.prepare(store, p)
			if err != nil {
				t.Fatalf("preparing the resource: %v", err)
			}
			tc.plant(sub, got.Name)

			if err := tc.call(store, p, got.Ref); !errors.Is(err, compute.ErrNotOwned) {
				t.Errorf("%s against an unowned resource = %v, want compute.ErrNotOwned", tc.name, err)
			}
		})
	}
}

// TestAFailureAfterCreateDoesNotStrandTheBucket is the blocker this port shipped.
//
// S3's CreateBucket takes no tags — unlike CreateTableBucket and
// CreateVectorBucket, which is why only this flavour has the problem. So between
// the create and the ownership tagging the bucket exists with no marker, and **an
// untagged bucket is refused by every subsequent reconcile as ErrNotOwned, because
// it is indistinguishable from one this platform did not create.** The resource was
// stranded permanently, by the ownership check working exactly as designed.
//
// # Three versions of this test, and what each one missed
//
//  1. It armed FailNext / FailUntilStopped, which fail the FIRST substrate call —
//     HeadBucket. So the Ensure aborted before creating anything and **the window
//     under test was never entered.** Removing the unwind changed nothing.
//  2. It targeted operations by name, which reached the window — and **the names
//     were a hand literal beneath a subtest named for "every operation".** Adding a
//     real fifth call inside the window left it green; adding that call to the
//     literal made it red. A test called "every operation" whose operations are
//     typed by hand is a list wearing a derivation's name.
//  3. This one. The window is DERIVED from a trace of what EnsureBucket actually
//     calls, so a call added inside it joins the population by being made.
//
// # And the trace alone is not enough, which is the refinement
//
// A trace is a *behaviour* derivation, so it is blind to any operation the traced
// scenario never reaches. [aws.MemoryS3.KnownOperations] is the *declaration* side.
// Comparing the two would be two hand lists with extra steps, so instead every
// declared operation must have a recorded **decision** — traced-and-therefore-tested,
// or classified below with a reason — and an operation with neither is fatal. The
// declaration side is a cross-check, not a second population.
// strandFixtureBucket is the one bucket name the strand test both traces and
// drives. One constant rather than two literals, so the population and the fixture
// it is driven in cannot drift apart.
const strandFixtureBucket = "stranded"

func TestAFailureAfterCreateDoesNotStrandTheBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Derive the window: run a clean create and record what it called.
	_, probeSub, probeStore := newObjectStore(t)
	probeMem, ok := probeSub.S3.(*aws.MemoryS3)
	if !ok {
		t.Fatalf("the substrate's object store is a %T", probeSub.S3)
	}
	probeMem.ResetOperations()
	// The same spec the cells drive, not a different one. The window is a
	// population derived in one fixture and driven in another, and two different
	// names are two different fixtures: anything in the converge that varies with
	// the name -- a sanitisation branch, a digest suffix, a length limit --
	// derives a window the cells cannot reach. Nothing does today; deriving and
	// driving the same spec means nothing has to.
	if _, err := probeStore.EnsureBucket(ctx, compute.BucketSpec{Name: strandFixtureBucket}); err != nil {
		t.Fatalf("the tracing Ensure failed: %v", err)
	}
	trace := probeMem.Operations()

	// Everything after CreateBucket is inside the window. Before it, a failure
	// leaves nothing behind and there is nothing to strand.
	createAt := slices.Index(trace, "CreateBucket")
	if createAt < 0 {
		t.Fatalf("the traced Ensure never called CreateBucket, so there is no window to derive: %v",
			trace)
	}
	window := trace[createAt+1:]
	if len(window) == 0 {
		t.Fatalf("the traced Ensure made no call after CreateBucket, so this test has nothing to "+
			"drive; trace was %v", trace)
	}
	t.Logf("window derived from the trace: %v", window)

	// The window is a SEQUENCE, so each cell is an (operation, occurrence) pair
	// counted over the whole trace. Driving by name alone made every repeat of an
	// operation exercise its first occurrence: three GetBucketTagging calls
	// produced three subtests that all failed call one, so a strand at call two
	// was invisible behind three green cells. **A trace is a sequence and a set of
	// names is not.**
	type cell struct {
		op  string
		nth int
	}
	counts := map[string]int{}
	for _, op := range trace[:createAt+1] {
		counts[op]++ // occurrences before the window still count toward nth
	}
	var cells []cell
	for _, op := range window {
		counts[op]++
		cells = append(cells, cell{op: op, nth: counts[op]})
	}

	// State the axis's cardinality rather than leaving it to be inferred from the
	// subtest count. The occurrence index exists because a converge can call one
	// operation more than once; TODAY'S converge does not, so every cell is
	// occurrence 1 and **this test does not traverse the occurrence axis at all.**
	// Four green cells would otherwise read as though it did.
	//
	// Not a failure: the absence of repeats is a property of the converge, not a
	// defect in it. It is logged because the alternative is a reader counting
	// coverage this test does not have -- and if a repeat is ever added, the cells
	// for it appear here automatically and this line stops printing. What keeps
	// FailOnNth itself honest meanwhile is TestFailOnNthTargetsTheNthOccurrence,
	// which drives nth > 1 directly.
	repeats := 0
	for _, c := range cells {
		if c.nth > 1 {
			repeats++
		}
	}
	if repeats == 0 {
		t.Logf("every one of the %d cells is occurrence 1: no operation repeats in this converge, "+
			"so the occurrence axis is not traversed here. TestFailOnNthTargetsTheNthOccurrence "+
			"is what covers nth > 1.", len(cells))
	} else {
		t.Logf("%d of %d cells target a repeated occurrence", repeats, len(cells))
	}

	for _, c := range cells {
		name := c.op
		if c.nth > 1 {
			name = fmt.Sprintf("%s#%d", c.op, c.nth)
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem, ok := sub.S3.(*aws.MemoryS3)
			if !ok {
				t.Fatalf("the substrate's object store is a %T", sub.S3)
			}
			op := c.op

			stop := mem.FailOnNth(op, c.nth, aws.ErrThrottled)
			_, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: strandFixtureBucket})
			fired := mem.NthInjectionFired(op)
			stop()

			// POSITIVE CONTROL, on the mechanism rather than on a consequence.
			//
			// The first version asserted only that the Ensure failed. That is a
			// control on SOMETHING failing, which the injection shares with every
			// other failure path the converge might grow -- and a cell that fails
			// for another reason passes it, measures nothing, and keeps a name
			// claiming the occurrence was exercised. USOSS-19 hit the same shape
			// from the other side: a cell that passed cleanly because the path it
			// was written for did not exist in its fixture.
			//
			// So the control is that THIS arming was consumed. A cell derived from
			// the trace but unreachable in the fixture it runs in now says so.
			if !fired {
				t.Fatalf("the arming for occurrence %d of %s was never consumed, so this cell "+
					"asserts nothing about it. Either the operation is not reached that many "+
					"times in this fixture -- in which case the window derivation and the drive "+
					"disagree -- or the Ensure stopped before it. err was %v", c.nth, op, err)
			}
			if err == nil {
				t.Fatalf("EnsureBucket succeeded with occurrence %d of %s failing, so the error "+
					"was swallowed and this subtest proves nothing", c.nth, op)
			}

			// The property: whatever happened, a retry must converge. Either the
			// bucket is gone and gets recreated, or it is present and correctly
			// tagged. What must not happen is a bucket that exists and can never
			// be adopted.
			got, rerr := store.EnsureBucket(ctx, compute.BucketSpec{Name: "stranded"})
			if rerr != nil {
				t.Fatalf("a retry after a failure at %s could not converge: %v\n"+
					"This is the strand: the bucket exists carrying no ownership tag, so every "+
					"reconcile refuses it as not-owned and there is no path back through this "+
					"interface", op, rerr)
			}
			if _, derr := store.DescribeBucket(ctx, got.Ref); derr != nil {
				t.Errorf("the converged bucket cannot be described: %v", derr)
			}
		})
	}

	// The declaration cross-check. Every operation the substrate declares must
	// have a decision: inside the window and therefore driven above, or named here
	// with the reason it is not. Neither is fatal — which is what stops the trace's
	// blindness to unreached operations from becoming this test's blindness.
	t.Run("every declared operation has a decision", func(t *testing.T) {
		t.Parallel()
		notInTheCreateWindow := map[string]string{
			"HeadBucket":   "runs before CreateBucket; a failure there leaves nothing behind",
			"CreateBucket": "is the create itself; a failure means no bucket exists to strand",
			"DeleteBucket": "teardown, and the unwind's own call — covered by " +
				"TestAFailureConfiguringAnADOPTEDBucketDoesNotDeleteIt",
			"IsEmpty":              "DeleteBucket's precondition, not part of Ensure",
			"ListObjectVersions":   "EmptyBucket only",
			"DeleteObjectVersions": "EmptyBucket only",
			"GetBucketLocation":    "DescribeBucket only",
			"GetPublicAccessBlock": "the AnonymousRead hook and DescribeBucket, not Ensure",
			"GetBucketEncryption":  "not called by Ensure; harden writes without reading",
		}
		for _, op := range probeMem.KnownOperations() {
			if slices.Contains(window, op) {
				if _, alsoExcluded := notInTheCreateWindow[op]; alsoExcluded {
					t.Errorf("%s is both traced inside the create window and named as outside it; "+
						"one of the two claims is false", op)
				}
				continue
			}
			if _, ok := notInTheCreateWindow[op]; !ok {
				t.Errorf("the substrate declares %s and it is neither traced inside the create "+
					"window nor named as outside it. A trace is a behaviour derivation and is "+
					"blind to what the traced scenario does not reach, so an operation with no "+
					"recorded decision is a hole: either it belongs in the window and the trace "+
					"is not reaching it, or it does not and that should be written down", op)
			}
		}
		for op := range notInTheCreateWindow {
			if !slices.Contains(probeMem.KnownOperations(), op) {
				t.Errorf("notInTheCreateWindow names %s and the substrate does not declare it; the "+
					"list has outlived what it described", op)
			}
		}
	})
}

// TestAFailureConfiguringAnADOPTEDBucketDoesNotDeleteIt is the other half of the
// unwind, and it is the half that would destroy data.
//
// The unwind removes a bucket THIS call created. Applying it to an adopted bucket
// would delete a bucket that predates the call, because a configuration failure on
// an existing resource is not licence to remove the resource. The two cases are
// indistinguishable afterwards, which is why `created` is threaded through from the
// branch that made it rather than inferred.
//
// # Why the empty case is the one that detects the over-fix
//
// The first version used a bucket with an object in it, on the reasoning that a
// deletion would then be unmistakably destructive. It could not detect anything:
// DeleteBucket refuses a non-empty bucket, so **the object that was supposed to
// make the mutation visible was what prevented it.** Removing the `created` guard
// changed nothing and the control reported DID NOT FIRE.
//
// So both cases run. The empty one is where an ignored guard actually deletes, and
// the non-empty one is the second line: even if the guard were ignored, the
// substrate itself refuses.
func TestAFailureConfiguringAnADOPTEDBucketDoesNotDeleteIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		objects int
	}{
		{"empty adopted bucket", 0},
		{"adopted bucket holding an object", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem, ok := sub.S3.(*aws.MemoryS3)
			if !ok {
				t.Fatalf("the substrate's object store is a %T", sub.S3)
			}

			owned, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "adopted"})
			if err != nil {
				t.Fatalf("EnsureBucket(): %v", err)
			}
			for range tc.objects {
				mem.PutObject(owned.Name)
			}

			// Targeted inside the configuration step: a blanket failure aborts at
			// HeadBucket, the unwind is never reached, and the test proves nothing.
			stop := mem.FailOn("PutBucketEncryption", aws.ErrThrottled)
			_, err = store.EnsureBucket(ctx, compute.BucketSpec{Name: "adopted"})
			stop()
			if err == nil {
				t.Fatal("the re-Ensure succeeded against a failing substrate, so this proves nothing")
			}

			// The bucket must still be there, checked through the port because
			// that is what a caller sees.
			if _, derr := store.DescribeBucket(ctx, owned.Ref); derr != nil {
				t.Errorf("after a failed re-Ensure the adopted bucket is gone or unreadable: %v\n"+
					"A configuration failure on a resource this call did not create is not licence "+
					"to delete it", derr)
			}
			if tc.objects > 0 {
				empty, ierr := mem.IsEmpty(ctx, owned.Name)
				if ierr != nil {
					t.Fatalf("IsEmpty(): %v", ierr)
				}
				if empty {
					t.Error("the adopted bucket's object is gone after a failed re-Ensure")
				}
			}
		})
	}
}

// TestAnExtBucketIsOwnedByTheCallThatCreatedIt catches a create that does not tag.
//
// Both ext services take Tags in the create request, so a created bucket is
// marked atomically. If a create dropped the tags the bucket would exist unowned,
// and — exactly as with the S3 strand — every later reconcile would refuse it.
//
// The ownership tests cannot see this: they plant an unowned resource deliberately
// and assert the refusal, so a create that produced an unowned resource by
// accident satisfies them. **The property that distinguishes the two is
// idempotence**: a second Ensure of the same name must adopt what the first
// created, which is only possible if the first tagged it.
func TestAnExtBucketIsOwnedByTheCallThatCreatedIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newObjectStore(t)

	for _, tc := range []struct {
		name   string
		ensure func() (*compute.Bucket, error)
	}{
		{"table", func() (*compute.Bucket, error) {
			tb, err := ext.TableBuckets(p.Name(), store)
			if err != nil {
				return nil, err
			}
			return tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "owned-by-create"})
		}},
		{"vector", func() (*compute.Bucket, error) {
			vb, err := ext.VectorBuckets(p.Name(), store)
			if err != nil {
				return nil, err
			}
			return vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "owned-by-create"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			first, err := tc.ensure()
			if err != nil {
				t.Fatalf("the first Ensure: %v", err)
			}
			second, err := tc.ensure()
			if err != nil {
				t.Fatalf("the second Ensure could not adopt what the first created: %v\n"+
					"That means the create did not tag it, so the bucket exists unowned and every "+
					"reconcile will refuse it — the same strand as an untagged S3 bucket, in a "+
					"service whose API takes the tags in the create request", err)
			}
			if first.Ref != second.Ref {
				t.Errorf("two Ensures of one name produced %s and %s", first.Ref, second.Ref)
			}
		})
	}
}

// TestFailOnNthTargetsTheNthOccurrence pins the injector the strand test depends
// on.
//
// The strand test derives its window from a trace, and a trace is a **sequence**:
// an operation can appear more than once, and the occurrences are different events.
// Driving by name alone made every subtest for a repeated operation exercise the
// first occurrence, so three appearances produced three cells that all tested one —
// the occurrence axis could not traverse, and three green cells hid a strand at the
// second call.
//
// This asserts the mechanism directly rather than through an Ensure, because
// through an Ensure the retry converges and the error text is gone: **the end-to-end
// observation cannot distinguish "occurrence 2 failed and was recovered" from
// "occurrence 1 failed and was recovered"**, which is the same reason the defect
// was invisible in the first place. So the mechanism is pinned where the difference
// is observable.
func TestFailOnNthTargetsTheNthOccurrence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, sub, store := newObjectStore(t)
	_ = sub
	_ = store

	for _, target := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("occurrence-%d", target), func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem, ok := sub.S3.(*aws.MemoryS3)
			if !ok {
				t.Fatalf("the substrate's object store is a %T", sub.S3)
			}
			b, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "nth"})
			if err != nil {
				t.Fatalf("EnsureBucket(): %v", err)
			}

			stop := mem.FailOnNth("GetBucketTagging", target, aws.ErrThrottled)
			defer stop()
			var failedAt int
			for i := 1; i <= 3; i++ {
				if _, err := mem.GetBucketTagging(ctx, b.Name); err != nil {
					if failedAt != 0 {
						t.Errorf("call %d also failed; an nth-occurrence injection must fire once", i)
					}
					failedAt = i
				}
			}
			if failedAt != target {
				t.Errorf("armed occurrence %d and call %d failed. Every call but the nth must "+
					"succeed, or a subtest derived for occurrence n is exercising a different "+
					"event than the one it names", target, failedAt)
			}
		})
	}
}

// TestTheInjectionObserverAndArmingCoverEveryService is the protection this PR
// added in round two and then lost in round two.
//
// The production fix — deriving both the arming and the observing from Substrate's
// fields — was correct and survived. **Its test did not: it was deleted while the
// strand test above was being rewritten, and reverting InjectionFired to its
// original ECR/IAM/STS hand list then left `go test ./compute/aws -count=1`
// green.** The two derived helpers were left unused.
//
// That is a protection lost in a refactor for an unrelated finding, and the way it
// escaped notice is worth recording: after removing an accidentally duplicated
// block I checked that no duplicate remained and that the test count was what I
// expected. **Neither of those observes whether a particular named test survived** —
// a count is preserved by deleting one test and adding another.
//
// # It arms and observes rather than comparing helpers
//
// An earlier version asked InjectionObservableServices which services were
// observable, and that function derives its answer the way InjectionFired derives
// its own — so reverting InjectionFired left it green. **Helper-to-helper equality
// is the vacuity, not the check.** So each subtest plants a real failure on one
// service, makes a call that consumes it, and asks InjectionFired.
func TestTheInjectionObserverAndArmingCoverEveryService(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		service string
		arm     func(*aws.Substrate, error) func()
		touch   func(context.Context, *aws.Provider, compute.ObjectStore) error
	}{
		{"S3", func(s *aws.Substrate, e error) func() { return s.S3.(*aws.MemoryS3).FailUntilStopped(e) },
			func(ctx context.Context, _ *aws.Provider, st compute.ObjectStore) error {
				_, err := st.EnsureBucket(ctx, compute.BucketSpec{Name: "probe"})
				return err
			}},
		{"S3Tables", func(s *aws.Substrate, e error) func() {
			return s.S3Tables.(*aws.MemoryS3Tables).FailUntilStopped(e)
		},
			func(ctx context.Context, p *aws.Provider, st compute.ObjectStore) error {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				_, err = tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "probe"})
				return err
			}},
		{"S3Vectors", func(s *aws.Substrate, e error) func() {
			return s.S3Vectors.(*aws.MemoryS3Vectors).FailUntilStopped(e)
		},
			func(ctx context.Context, p *aws.Provider, st compute.ObjectStore) error {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return err
				}
				_, err = vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "probe"})
				return err
			}},
	} {
		t.Run(tc.service, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			p, sub, store := newObjectStore(t)

			if p.Harness().InjectionFired() {
				t.Fatal("InjectionFired is true before anything was armed, so it proves nothing")
			}
			stop := tc.arm(sub, aws.ErrThrottled)
			defer stop()
			if err := tc.touch(ctx, p, store); err == nil {
				t.Fatalf("the call against a failing %s succeeded, so no injection was consumed "+
					"and this subtest cannot distinguish an unobserved service from an unreached "+
					"one", tc.service)
			}
			if !p.Harness().InjectionFired() {
				t.Errorf("a failure was armed on Substrate.%s, a call consumed it, and "+
					"InjectionFired reports false. Every coverage claim made with that observer "+
					"silently excludes %s", tc.service, tc.service)
			}
		})
	}

	// And InduceTransient itself must arm every service it claims to. Comparing
	// the two helpers cannot see this: both derive, so reverting only the arming's
	// body left them agreeing. This drives the real hook and then asks each
	// service whether its injection fired.
	t.Run("InduceTransient arms every service it reports", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p, sub, store := newObjectStore(t)
		armable, _ := p.Harness().InjectionArmableServices()
		if len(armable) < 4 {
			t.Fatalf("only %v can be armed on a fully configured provider; the object store's "+
				"three services should be among them", armable)
		}

		stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
		if err != nil {
			t.Fatalf("InduceTransient: %v", err)
		}
		defer stop()

		// One call per storage service, each of which must now fail. A service
		// InduceTransient did not arm answers successfully, which is the defect.
		for name, call := range map[string]func() error{
			"S3": func() error {
				_, e := store.EnsureBucket(ctx, compute.BucketSpec{Name: "armed"})
				return e
			},
			// Reached here rather than pointed at. USOSS-26 added the secret
			// store, so this provider now has a fourth armable service and this
			// test can drive it -- which is better than naming the file that
			// does, because a reference is only as good as whoever keeps it.
			"Parameters": func() error {
				secrets, e := p.Secrets()
				if e != nil {
					return e
				}
				// Put rather than Get: a Get against a parameter that does not
				// exist can fail for the absence rather than for the injection,
				// and a cell that cannot distinguish those is not evidence the
				// arming worked. A Put reaches the substrate on its first call.
				_, e = secrets.Put(ctx, compute.SecretSpec{
					Scope: "armed", Name: "armed",
					Placement: compute.Placement{Name: "default"},
					Value:     compute.NewSecretValue("v"),
				})
				return e
			},
			"S3Tables": func() error {
				tb, e := ext.TableBuckets(p.Name(), store)
				if e != nil {
					return e
				}
				_, e = tb.EnsureTableBucket(ctx, compute.BucketSpec{Name: "armed"})
				return e
			},
			"S3Vectors": func() error {
				vb, e := ext.VectorBuckets(p.Name(), store)
				if e != nil {
					return e
				}
				_, e = vb.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "armed"})
				return e
			},
		} {
			if !slices.Contains(armable, name) {
				t.Errorf("Substrate.%s is configured and InjectionArmableServices does not report "+
					"it", name)
				continue
			}
			if err := call(); err == nil {
				t.Errorf("InduceTransient reports Substrate.%s as armable and a call against it "+
					"succeeded, so the hook did not actually arm it. The transient gate would "+
					"score every method behind %s as unexercised while reporting the port driven",
					name, name)
			}
		}
		_ = sub
	})

	// The arming and the observing must derive the SAME set. They did not once:
	// the observer derived and the arming was a literal, so two services were
	// observed and never stimulated — a general observation over a stimulus that
	// is not measures the intersection while reporting the union.
	t.Run("the armable and observable sets agree", func(t *testing.T) {
		t.Parallel()
		p, _, _ := newObjectStore(t)
		armable, unarmable := p.Harness().InjectionArmableServices()
		observable, unobservable := p.Harness().InjectionObservableServices()
		slices.Sort(armable)
		slices.Sort(observable)
		if !slices.Equal(armable, observable) {
			t.Errorf("InduceTransient can arm %v and InjectionFired can observe %v. A service in "+
				"one set and not the other is either stimulated and unwatched or watched and "+
				"never stimulated; both report coverage that does not exist", armable, observable)
		}
		probed := []string{"S3", "S3Tables", "S3Vectors", "Parameters"}
		elsewhere := map[string]string{
			"ECR":     "failinjection_test.go, the image-repository cells",
			"IAM":     "failinjection_test.go, the workload-identity cells",
			"STS":     "failinjection_test.go, via the build path",
			"Builder": "failinjection_test.go, the image-build cells",
			// USOSS-41's push phase, driven by buildsplit_test.go's
			// TestARetryableSubstrateFailureFromThePusherIsErrTransient. It is
			// its own service rather than part of the builder because it is its
			// own process: that is the whole of USOSS-41.
			"Pusher": "buildsplit_test.go, TestARetryableSubstrateFailureFromThePusherIsErrTransient",
			// USOSS-14's three, driven by database_test.go's
			// TestARetryableDatabaseSubstrateFailureIsErrTransient, which arms
			// InduceTransient across every method of both database ports. EC2 is
			// reached through the security group EnsureRelational creates, which
			// is the only thing in this package placed on a network.
			"RDS":      "database_test.go, the relational transient probes",
			"EC2":      "database_test.go, the relational probes, via the security group",
			"DynamoDB": "database_test.go, the key-value transient probes",
			// USOSS-11's container port (#23), driven by container_test.go's
			// TestARetryableSubstrateFailureIsErrTransientOnEveryMethod.
			"ECS":       "container_test.go, the container-service transient probes",
			"Scheduler": "container_test.go, the scheduled-job transient probes",
			// USOSS-12's function and function-endpoint ports, driven by
			// function_test.go's
			// TestEveryFunctionPortMethodMapsATransientFailureToErrTransient, which
			// arms InduceTransient and drives all eight methods across both ports.
			// EndpointEC2 is reached through the security group EnsureEndpoint
			// creates, the only thing on this port placed on a network.
			"Lambda":      "function_test.go, TestEveryFunctionPortMethodMapsATransientFailureToErrTransient",
			"ELBv2":       "function_test.go, TestEveryFunctionPortMethodMapsATransientFailureToErrTransient",
			"EndpointEC2": "function_test.go, TestEveryFunctionPortMethodMapsATransientFailureToErrTransient, via the endpoint's security group",
		}
		for _, svc := range observable {
			if slices.Contains(probed, svc) {
				continue
			}
			if _, ok := elsewhere[svc]; !ok {
				t.Errorf("Substrate.%s can be observed for an injection and nothing arms one on "+
					"it — not here, and not named as covered elsewhere", svc)
			}
		}
		if len(unarmable) > 0 || len(unobservable) > 0 {
			t.Logf("not armable: %v; not observable: %v — outside every InjectionFired-based "+
				"coverage claim", unarmable, unobservable)
		}
	})
}

// TestTheUnwindReportsTheCausesOwnSentinel is the test for a converge that could
// not stop.
//
// # The loop
//
// The unwind used to wrap every cause in compute.ErrTransient, on the reasoning
// that the bucket had been removed so the Ensure could be retried from scratch.
// That reasoning is about the BUCKET and the sentinel is about the ERROR. With an
// IAM role missing s3:PutPublicAccessBlock, every attempt created a bucket, was
// denied, deleted it, and answered "try again" -- and the one thing that ends
// that loop is compute.ErrNotPermitted sending somebody to the role.
//
// # What it asserts, and why it is exactly one thing
//
// compute.ErrTransient is documented as the only sentinel that says "try again";
// every other one is terminal for the call that produced it. So an error matching
// two of them is not merely imprecise -- two callers branching on the taxonomy
// reach opposite conclusions from the same value, and which one is right depends
// on the order they happened to check in. Each cell therefore requires the
// cause's sentinel AND the absence of every other, rather than only the presence
// of the right one, which the old behaviour would also have passed.
func TestTheUnwindReportsTheCausesOwnSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Every sentinel the substrate can route a cause to, so a cell cannot assert
	// its own sentinel and be silent about the rest.
	taxonomy := map[string]error{
		"ErrTransient":    compute.ErrTransient,
		"ErrNotPermitted": compute.ErrNotPermitted,
		"ErrFailed":       compute.ErrFailed,
		"ErrNotOwned":     compute.ErrNotOwned,
		"ErrNotFound":     compute.ErrNotFound,
	}

	for _, tc := range []struct {
		name string
		// op is the call inside the create window that fails. Both hardening
		// calls, because the denial that produced the loop was on the first and
		// nothing structural distinguishes the second.
		op    string
		cause error
		want  string
	}{
		{
			name:  "a denial on the public-access block",
			op:    "PutPublicAccessBlock",
			cause: aws.ErrDenied,
			want:  "ErrNotPermitted",
		},
		{
			name:  "a denial on the encryption default",
			op:    "PutBucketEncryption",
			cause: aws.ErrDenied,
			want:  "ErrNotPermitted",
		},
		{
			// The control in the other direction. A cause that really is
			// retryable must still come back retryable -- a fix that made the
			// unwind terminal for everything would pass every cell above and be
			// just as wrong, in the direction that abandons a deploy which would
			// have worked.
			name:  "a throttle on the public-access block",
			op:    "PutPublicAccessBlock",
			cause: aws.ErrThrottled,
			want:  "ErrTransient",
		},
		{
			// An unclassified substrate failure. Terminal, and terminal alone:
			// this is the cell that used to report ErrTransient and ErrFailed at
			// once, which is the taxonomy contradicting itself in one value.
			name:  "an unclassified failure on the encryption default",
			op:    "PutBucketEncryption",
			cause: errors.New("the service said something new"),
			want:  "ErrFailed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem, ok := sub.S3.(*aws.MemoryS3)
			if !ok {
				t.Fatalf("the substrate's object store is a %T", sub.S3)
			}

			stop := mem.FailOn(tc.op, tc.cause)
			_, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "unwound"})
			stop()

			if err == nil {
				t.Fatalf("EnsureBucket succeeded with %s failing, so this cell asserts nothing",
					tc.op)
			}
			for name, sentinel := range taxonomy {
				matched := errors.Is(err, sentinel)
				switch {
				case name == tc.want && !matched:
					t.Errorf("the error does not match compute.%s, which is the cause's own "+
						"classification: %v", name, err)
				case name != tc.want && matched:
					t.Errorf("the error matches compute.%s as well as compute.%s. Two sentinels "+
						"is two answers: a caller branching on one retries and a caller branching "+
						"on the other gives up, from the same value. err was %v",
						name, tc.want, err)
				}
			}

			// The loop, stated as the property rather than as a sentinel. A
			// denial is terminal, so a caller that retries only on ErrTransient
			// stops -- which is what the missing IAM permission needed somebody
			// to do.
			if tc.want != "ErrTransient" && errors.Is(err, compute.ErrTransient) {
				t.Error("a terminal cause came back as retryable, so a caller loops on a " +
					"failure that cannot resolve without somebody changing the IAM role")
			}
		})
	}
}

// TestANameHeldByAnotherAccountIsRefusedAsACollision drives the case S3's global
// namespace creates, on both of the answers S3 gives for it.
//
// # Two answers, one condition
//
// HeadBucket's own documentation says a bucket the caller cannot access comes
// back as 400, 403 or 404 and declines to say which -- deliberately, since an
// answer that separated "absent" from "somebody else's" would make a HEAD an
// enumeration tool for a namespace shared by every AWS account. So a provider
// meets the same collision through two different doors and has to be right at
// both.
//
// The 404 door is the one where the truth is recoverable: the Ensure reads
// "absent", tries the create, and S3 answers BucketAlreadyExists -- which it
// returns ONLY for another account's name, since this account's own bucket is
// BucketAlreadyOwnedByYou. That is compute.ErrNotOwned, and it used to be
// compute.ErrTransient: "try again" for a name that will never be free.
//
// The 403 door is the one where it is not. The provider reports the denial it
// was given and names the second reading in the message rather than guessing at
// a sentinel S3 refused to license -- guessing compute.ErrNotOwned there would be
// wrong every time a role is simply missing s3:ListBucket.
//
// MemoryS3.PutForeign existed to model this and had no callers at all, which is
// how three documented paragraphs about a hazard came to sit above code that did
// not implement it.
func TestANameHeldByAnotherAccountIsRefusedAsACollision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// plant chooses which of S3's two answers the HEAD gives.
		plant func(*aws.MemoryS3, string)
		want  error
		// notWant is the taxonomy this must NOT reach. Both cells refuse
		// ErrTransient, because a name in another account never becomes free and
		// a caller that retries does so forever.
		notWant []error
	}{
		{
			name:    "S3 answers the HEAD as absent, so the create discovers it",
			plant:   func(m *aws.MemoryS3, n string) { m.PutForeignAbsent(n) },
			want:    compute.ErrNotOwned,
			notWant: []error{compute.ErrTransient, compute.ErrFailed, compute.ErrNotFound},
		},
		{
			name:    "S3 answers the HEAD as denied, so the collision is unprovable",
			plant:   func(m *aws.MemoryS3, n string) { m.PutForeign(n) },
			want:    compute.ErrNotPermitted,
			notWant: []error{compute.ErrTransient, compute.ErrFailed},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, sub, store := newObjectStore(t)
			mem, ok := sub.S3.(*aws.MemoryS3)
			if !ok {
				t.Fatalf("the substrate's object store is a %T", sub.S3)
			}

			// The physical name, derived the way the provider derives it: a
			// fixture that planted the logical name would plant a name the
			// Ensure never asks about, and pass by never colliding at all.
			created, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "assets"})
			if err != nil {
				t.Fatalf("the probe Ensure that derives the physical name failed: %v", err)
			}
			physical := created.Name
			if derr := store.DeleteBucket(ctx, created.Ref); derr != nil {
				t.Fatalf("removing the probe bucket: %v", derr)
			}

			tc.plant(mem, physical)
			_, err = store.EnsureBucket(ctx, compute.BucketSpec{Name: "assets"})
			if err == nil {
				t.Fatal("EnsureBucket succeeded against a name another account holds, so this " +
					"provider believes it owns somebody else's bucket")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want it to match %v", err, tc.want)
			}
			for _, no := range tc.notWant {
				if errors.Is(err, no) {
					t.Errorf("the error also matches %v: %v", no, err)
				}
			}
			// The message has to carry the half the sentinel cannot. Both cells
			// name the field an operator changes, because on this path the name
			// is the fix and no permission is.
			if !strings.Contains(err.Error(), "NamePrefix") {
				t.Errorf("the refusal does not name Config.ObjectStore.NamePrefix, which is what "+
					"an operator changes to resolve a collision: %v", err)
			}
		})
	}
}

// TestEveryBucketCarriesDefaultEncryption is the assertion USOSS-13's acceptance
// criteria asked for and the port shipped without.
//
// "Buckets are private + encrypted by default; A TEST ASSERTS THIS (a regression
// here is a data-exposure bug, not a style issue)." Private was asserted, by a
// conformance check that fires under mutation. Encrypted was not asserted
// anywhere: setting encryptionAlgorithm to a value S3 has never heard of left the
// entire repository green, because nothing read the setting back. The tests that
// DID go red when the call was deleted were about something else -- two failure
// injections losing their stimulus and a trace losing a decision -- and none of
// them named the invariant or looked at what was applied.
//
// # Why the legal set is spelled again here
//
// The check is that the algorithm on the bucket is one S3 accepts, and the
// vocabulary is S3's rather than this package's. A fixture that read the
// provider's own constant back would agree with any value the provider chose,
// including the garbage that started this, which is the whole failure being
// closed.
func TestEveryBucketCarriesDefaultEncryption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// S3's ServerSideEncryptionConfiguration vocabulary, read off the API
	// reference rather than off compute/aws.
	acceptedByS3 := map[string]bool{"AES256": true, "aws:kms": true, "aws:kms:dsse": true}

	t.Run("a created bucket has it", func(t *testing.T) {
		t.Parallel()
		_, sub, store := newObjectStore(t)
		mem, ok := sub.S3.(*aws.MemoryS3)
		if !ok {
			t.Fatalf("the substrate's object store is a %T", sub.S3)
		}
		b, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "encrypted"})
		if err != nil {
			t.Fatalf("EnsureBucket: %v", err)
		}
		got, err := mem.GetBucketEncryption(ctx, b.Name)
		if err != nil {
			t.Fatalf("reading the bucket's default encryption back: %v", err)
		}
		if got == "" {
			t.Fatal("the bucket has no default encryption at all, so every object written to it " +
				"is stored unencrypted unless its writer remembers to ask")
		}
		if !acceptedByS3[got] {
			t.Errorf("the bucket's default encryption is %q, which is not an SSE algorithm S3 "+
				"accepts -- so on a real account the setting was rejected and the bucket has "+
				"none", got)
		}
	})

	t.Run("an adopted bucket is re-hardened", func(t *testing.T) {
		t.Parallel()
		_, sub, store := newObjectStore(t)
		mem, ok := sub.S3.(*aws.MemoryS3)
		if !ok {
			t.Fatalf("the substrate's object store is a %T", sub.S3)
		}
		if _, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "encrypted"}); err != nil {
			t.Fatalf("the first EnsureBucket: %v", err)
		}
		// The second Ensure's calls alone. The property is that hardening is not
		// conditional on having just created the bucket: a default cleared out of
		// band is restored by the next reconcile rather than reported as
		// converged.
		mem.ResetOperations()
		if _, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "encrypted"}); err != nil {
			t.Fatalf("the second EnsureBucket: %v", err)
		}
		if !slices.Contains(mem.Operations(), "PutBucketEncryption") {
			t.Errorf("the adopt path did not set the encryption default: %v. A bucket whose "+
				"default was turned off out of band would stay off, and the Ensure would report "+
				"it converged", mem.Operations())
		}
	})
}

// TestAnExtEnsureReportsTheLabelsTheSubstrateHolds is the read-back invariant
// refuseUnapplicableSpec was written to protect, one field over.
//
// Both ext Ensures returned the effective spec by copying the request and
// normalising Class, under a comment saying "the fields that could have differed
// were refused above, so nothing here can be an echo". Labels could differ and
// were not refused -- and neither ext Ensure reconciles tags on the adopt path,
// unlike the general-purpose one. So a caller who changed a label and re-Ensured
// was told the new label was effective while the bucket still carried the old.
//
// refuseUnapplicableSpec's own doc calls that shape the worst of the three
// options: **echoing it back as effective is what turns a gap into a lie.** The
// gap is real and stays -- neither S3TablesAPI nor S3VectorsAPI has a tagging
// call, so this provider genuinely cannot converge a label after create. What it
// can do is report what is there, so a caller can find out.
func TestAnExtEnsureReportsTheLabelsTheSubstrateHolds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		ensure func(*aws.Provider, compute.ObjectStore, compute.BucketSpec) (*compute.Bucket, error)
		tags   func(*aws.Substrate, string) map[string]string
	}{
		{
			name: "table bucket",
			ensure: func(p *aws.Provider, st compute.ObjectStore, spec compute.BucketSpec) (*compute.Bucket, error) {
				tb, err := ext.TableBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return tb.EnsureTableBucket(ctx, spec)
			},
			tags: func(s *aws.Substrate, n string) map[string]string {
				rec, err := s.S3Tables.GetTableBucket(ctx, n)
				if err != nil {
					return nil
				}
				return rec.Tags
			},
		},
		{
			name: "vector bucket",
			ensure: func(p *aws.Provider, st compute.ObjectStore, spec compute.BucketSpec) (*compute.Bucket, error) {
				vb, err := ext.VectorBuckets(p.Name(), st)
				if err != nil {
					return nil, err
				}
				return vb.EnsureVectorBucket(ctx, spec)
			},
			tags: func(s *aws.Substrate, n string) map[string]string {
				rec, err := s.S3Vectors.GetVectorBucket(ctx, n)
				if err != nil {
					return nil
				}
				return rec.Tags
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, sub, store := newObjectStore(t)

			first, err := tc.ensure(p, store, compute.BucketSpec{
				Name:   "labelled",
				Labels: map[string]string{"team": "alpha"},
			})
			if err != nil {
				t.Fatalf("the first Ensure: %v", err)
			}
			if got := first.Spec.Labels["team"]; got != "alpha" {
				t.Fatalf("the create path reported team=%q, and it applied alpha", got)
			}

			// The re-Ensure with a changed label: the request the provider cannot
			// apply, because neither service exposes a tagging call.
			second, err := tc.ensure(p, store, compute.BucketSpec{
				Name:   "labelled",
				Labels: map[string]string{"team": "beta"},
			})
			if err != nil {
				t.Fatalf("the re-Ensure: %v", err)
			}

			substrate := labelsOf(tc.tags(sub, second.Name))
			if !maps.Equal(second.Spec.Labels, substrate) {
				t.Errorf("the Ensure reported labels %v as effective and the substrate holds %v. "+
					"The effective spec is what the substrate has: a caller who reads back the "+
					"label it asked for has no way to discover the tag was never written",
					second.Spec.Labels, substrate)
			}
		})
	}
}

// labelsOf recovers the caller-visible labels from a resource's tags, spelling
// the prefix rather than importing it: a fixture that shared the production
// constant would agree with a change to it, and the prefix is part of what a
// label means to anything reading these tags from outside.
func labelsOf(tags map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		if label, ok := strings.CutPrefix(k, "apphub:label/"); ok {
			out[label] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// TestTheGrantReadBackRecoversTheLevelFromTheStoredPolicy is the property
// USOSS-73's read-back rests on for this provider.
//
// This package holds no record of a grant it made. The level is recovered by
// asking which level would render the policy that stands, so the read-back is a
// statement about IAM's contents rather than about this process's memory — and
// that is the whole reason the method is worth having. A provider that echoed the
// level it was last asked for would satisfy every round-trip check in the
// conformance suite while a grant that never reached the substrate looked
// present.
//
// It runs across all three bucket flavours because one method serves all three,
// and the table and vector documents are rendered against an ARN read back from
// the service rather than composed — so a read-back that composed one would
// report every ext grant as unrecognisable.
func TestTheGrantReadBackRecoversTheLevelFromTheStoredPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newObjectStore(t)

	tables, err := ext.TableBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.TableBuckets(): %v", err)
	}
	vectors, err := ext.VectorBuckets(p.Name(), store)
	if err != nil {
		t.Fatalf("ext.VectorBuckets(): %v", err)
	}

	plain, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "plain"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	table, err := tables.EnsureTableBucket(ctx, compute.BucketSpec{Name: "tabular"})
	if err != nil {
		t.Fatalf("EnsureTableBucket(): %v", err)
	}
	vector, err := vectors.EnsureVectorBucket(ctx, compute.BucketSpec{Name: "vectored"})
	if err != nil {
		t.Fatalf("EnsureVectorBucket(): %v", err)
	}
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}

	for _, tc := range []struct {
		flavour string
		ref     compute.Ref
		// levels this flavour offers. A plain bucket refuses AccessAdmin, and
		// the read-back has to cope with a level that cannot be rendered rather
		// than treat the refusal as a failed comparison.
		levels []compute.AccessLevel
	}{
		{"bucket", plain.Ref, []compute.AccessLevel{compute.AccessRead, compute.AccessReadWrite}},
		{"table-bucket", table.Ref, []compute.AccessLevel{
			compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin}},
		{"vector-bucket", vector.Ref, []compute.AccessLevel{
			compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin}},
	} {
		t.Run(tc.flavour, func(t *testing.T) {
			// Not parallel: the subtests share one identity's role, and the
			// policy names are per bucket rather than per level, so ordering
			// within a flavour is what the narrowing assertion depends on.
			for _, level := range tc.levels {
				if err := store.Grant(ctx, tc.ref, identity.Ref, level); err != nil {
					t.Fatalf("Grant(%s): %v", level, err)
				}
				info, err := store.DescribeGrant(ctx, tc.ref, identity.Ref)
				if err != nil {
					t.Fatalf("DescribeGrant() after Grant(%s): %v", level, err)
				}
				if info.Level != level {
					t.Errorf("Grant(%s) then DescribeGrant() reports %q; the level is recovered "+
						"from the stored policy, so a mismatch means the forward and backward "+
						"paths disagree about what that level renders", level, info.Level)
				}
			}
			if err := store.Revoke(ctx, tc.ref, identity.Ref); err != nil {
				t.Fatalf("Revoke(): %v", err)
			}
			if _, err := store.DescribeGrant(ctx, tc.ref, identity.Ref); !errors.Is(err, compute.ErrNotFound) {
				t.Errorf("DescribeGrant() after Revoke() = %v, want compute.ErrNotFound", err)
			}
		})
	}
}

// TestTheGrantReadBackRefusesAPolicyItDidNotWrite is the case the level inverse
// exists to fail on rather than guess at.
//
// An inline policy standing under the name this provider uses, whose document is
// not one it would render for any level it defines, has been written or edited
// outside this platform. Both available answers are wrong: reported low, an
// access review passes a workload that can in fact write; reported high, an
// operator revokes and re-grants something that was never there. So neither is
// reported.
func TestTheGrantReadBackRefusesAPolicyItDidNotWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub, store := newObjectStore(t)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "data"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	if err := store.Grant(ctx, bucket.Ref, identity.Ref, compute.AccessRead); err != nil {
		t.Fatalf("Grant(): %v", err)
	}

	// Rewrite the standing document out of band, keeping the policy name. This is
	// the shape of the real event: somebody widens a role's permissions by hand,
	// or another tool claims the same policy name.
	role := strings.TrimPrefix(identity.Ref.ID, "role/")
	names, err := sub.IAM.ListRolePolicyNames(ctx, role)
	if err != nil {
		t.Fatalf("ListRolePolicyNames(): %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("one grant produced %d policies: %v", len(names), names)
	}
	if err := sub.IAM.PutRolePolicy(ctx, role, names[0],
		`{"Version":"2012-10-17","Statement":[{"Sid":"Hand","Effect":"Allow",`+
			`"Action":["s3:*"],"Resource":["*"]}]}`); err != nil {
		t.Fatalf("PutRolePolicy(): %v", err)
	}

	info, err := store.DescribeGrant(ctx, bucket.Ref, identity.Ref)
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("DescribeGrant() over a hand-edited policy = (%v, %v), want an error wrapping "+
			"compute.ErrFailed. Guessing a level here is worse than failing: the document grants "+
			"s3:* on everything, and reporting it as %q would tell an access review the workload "+
			"has read access", info, err, compute.AccessRead)
	}
	// And specifically not "there is no grant": something is standing there.
	if errors.Is(err, compute.ErrNotFound) {
		t.Error("DescribeGrant() reported compute.ErrNotFound for a policy that exists. A caller " +
			"reconciling on that answer would grant again and leave the hand-written statement in " +
			"force alongside its own")
	}
}
