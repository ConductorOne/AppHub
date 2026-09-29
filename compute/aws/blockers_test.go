// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/credentials"
)

// The five blockers from the PR #18 review, as regression tests.
//
// They are grouped by the class the review named rather than one per symptom,
// because the classes are what the fixes are shaped around: an ownership check
// that guards one entry point, an Ensure that merges instead of reconciling, a
// contract on a component that is assumed to honour it, and a retry decision
// made twice by two different functions.

// --- Class A: ownership is a property of access, not a step each method remembers --

// TestOwnershipIsRequiredByEveryPortMethodThatUsesAResource.
//
// EnsureRepository checked the ownership tags; Build and both Delete methods did
// not, so the boundary guarded one entry point and the others walked past it.
//
// The Delete half is the nastier one: a Ref this provider issued is not a
// capability. The resource behind it can be deleted and replaced by somebody
// else's under the same physical name, so ownership has to be re-established at
// use rather than inherited from issuance.
//
// The fixture takes that route deliberately: provision through the port, delete,
// put an unowned resource at the same name, then call the public method with the
// Ref that used to be valid. Nothing here guesses a Ref format.
func TestOwnershipIsRequiredByEveryPortMethodThatUsesAResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Every refused call is checked against the WHOLE rendered substrate rather
	// than against the object the case is about. USOSS-13's framing, and it is
	// stronger for a reason worth keeping: a refusal that happens after a write
	// to some other object is the same defect one step removed, and a per-object
	// assertion cannot see it.
	rendered := func(t *testing.T, p *aws.Provider) string {
		t.Helper()
		out, err := p.Harness().Rendered(ctx)
		if err != nil {
			t.Fatalf("Rendered: %v", err)
		}
		sort.Strings(out)
		return strings.Join(out, "\n")
	}

	t.Run("Build refuses an unowned destination before minting", func(t *testing.T) {
		t.Parallel()
		p, sub := newProvider(t, nil)
		reg, err := p.Registry()
		if err != nil {
			t.Fatalf("Registry(): %v", err)
		}
		repo := mustEnsureRepo(t, p, "app")
		if err := reg.DeleteRepository(ctx, repo.Ref); err != nil {
			t.Fatalf("DeleteRepository: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, repo.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}

		builder, err := p.Builder()
		if err != nil {
			t.Fatalf("Builder(): %v", err)
		}
		before := rendered(t, p)
		_, err = builder.Build(ctx, compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(repo.Prefix + ":latest")},
		})
		if err == nil {
			t.Error("Build accepted a destination this platform does not own; a scoped push " +
				"credential was minted against somebody else's repository")
		} else if !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("Build refused an unowned destination with %v, want compute.ErrNotOwned", err)
		}

		sts, ok := sub.STS.(*aws.MemorySTS)
		if !ok {
			t.Fatalf("the substrate's token service is a %T", sub.STS)
		}
		if n := len(sts.Requests()); n != 0 {
			t.Errorf("%d credential(s) were minted for an unowned repository; the ownership "+
				"check must come before the mint, not after it", n)
		}
		if after := rendered(t, p); after != before {
			t.Errorf("the refused build changed the substrate:\n before: %s\n  after: %s",
				before, after)
		}
	})

	t.Run("DeleteRepository refuses a replacement it does not own", func(t *testing.T) {
		t.Parallel()
		p, sub := newProvider(t, nil)
		reg, err := p.Registry()
		if err != nil {
			t.Fatalf("Registry(): %v", err)
		}
		repo := mustEnsureRepo(t, p, "app")
		if err := reg.DeleteRepository(ctx, repo.Ref); err != nil {
			t.Fatalf("the first DeleteRepository: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, repo.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}

		before := rendered(t, p)
		err = reg.DeleteRepository(ctx, repo.Ref)
		if err == nil {
			t.Error("DeleteRepository destroyed a repository this platform does not own, using a " +
				"Ref that was valid before the name was reused")
		} else if !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("DeleteRepository refused with %v, want compute.ErrNotOwned", err)
		}
		if after := rendered(t, p); after != before {
			t.Errorf("the refused delete changed the substrate:\n before: %s\n  after: %s",
				before, after)
		}
		_ = sub
	})

	t.Run("DeleteWorkloadIdentity refuses a replacement it does not own", func(t *testing.T) {
		t.Parallel()
		p, sub := newProvider(t, nil)
		id := mustEnsureIdentity(t, p, "app")
		if err := p.Identities().DeleteWorkloadIdentity(ctx, id.Ref); err != nil {
			t.Fatalf("the first DeleteWorkloadIdentity: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, id.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}

		before := rendered(t, p)
		err := p.Identities().DeleteWorkloadIdentity(ctx, id.Ref)
		if err == nil {
			t.Error("DeleteWorkloadIdentity destroyed an IAM role this platform does not own")
		} else if !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("DeleteWorkloadIdentity refused with %v, want compute.ErrNotOwned", err)
		}
		if after := rendered(t, p); after != before {
			t.Errorf("the refused delete changed the substrate:\n before: %s\n  after: %s",
				before, after)
		}
		_ = sub
	})
}

// --- Class B: Ensure reconciles the whole resource, it does not merge ------------

// TestEnsureConvergesTheWholeTrustPolicy.
//
// The reconciliation compared only the runtime it could read back out of the
// policy, so an owned role could retain any amount of extra trust and Ensure
// would report success. A wildcard AWS principal on a role is "anyone in this
// partition may assume this", so converging the set is the security property and
// not tidiness.
//
// Stated as a property over a population of junk rather than as the one witness
// the review supplied, because a check for AWS:"*" closes that witness and
// leaves extra Service principals, extra actions and conditions live.
func TestEnsureConvergesTheWholeTrustPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	junk := map[string]string{
		"a wildcard AWS principal": `{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["sts:AssumeRole"]}`,
		"another service principal": `{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},` +
			`"Action":["sts:AssumeRole"]}`,
		"a federated principal": `{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},` +
			`"Action":["sts:AssumeRoleWithWebIdentity"]}`,
		"an extra action on the expected principal": `{"Effect":"Allow",` +
			`"Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}`,
	}

	for name, statement := range junk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, sub := newProvider(t, nil)
			mem, ok := sub.IAM.(*aws.MemoryIAM)
			if !ok {
				t.Fatalf("the substrate's identity service is a %T", sub.IAM)
			}
			spec := compute.WorkloadIdentitySpec{Name: "app", RunsOn: compute.RuntimeContainer}
			if _, err := p.Identities().EnsureWorkloadIdentity(ctx, spec); err != nil {
				t.Fatalf("EnsureWorkloadIdentity: %v", err)
			}
			role, err := mem.GetRole(ctx, "apphub-app")
			if err != nil {
				t.Fatalf("GetRole: %v", err)
			}
			intended := role.AssumeRolePolicy

			// Somebody widens the trust policy out of band.
			widened, err := addStatement(role.AssumeRolePolicy, statement)
			if err != nil {
				t.Fatalf("widening the trust policy: %v", err)
			}
			if err := mem.UpdateAssumeRolePolicy(ctx, "apphub-app", widened); err != nil {
				t.Fatalf("UpdateAssumeRolePolicy: %v", err)
			}

			// A redeploy with the unchanged spec must put it back.
			if _, err := p.Identities().EnsureWorkloadIdentity(ctx, spec); err != nil {
				t.Fatalf("re-EnsureWorkloadIdentity: %v", err)
			}
			after, err := mem.GetRole(ctx, "apphub-app")
			if err != nil {
				t.Fatalf("GetRole: %v", err)
			}
			if !samePolicy(t, after.AssumeRolePolicy, intended) {
				t.Errorf("Ensure left the widened trust policy in place.\n  after: %s\n  want:  %s",
					after.AssumeRolePolicy, intended)
			}
		})
	}
}

func addStatement(policy, statement string) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return "", err
	}
	var extra any
	if err := json.Unmarshal([]byte(statement), &extra); err != nil {
		return "", err
	}
	list, _ := doc["Statement"].([]any)
	doc["Statement"] = append(list, extra)
	out, err := json.Marshal(doc)
	return string(out), err
}

// samePolicy compares two policy documents by meaning rather than by bytes, so
// the test does not depend on the order the provider happens to emit.
func samePolicy(t *testing.T, a, b string) bool {
	t.Helper()
	norm := func(s string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatalf("policy is not JSON: %v", err)
		}
		list, _ := doc["Statement"].([]any)
		rendered := make([]string, 0, len(list))
		for _, st := range list {
			b, _ := json.Marshal(st)
			rendered = append(rendered, string(b))
		}
		sort.Strings(rendered)
		return strings.Join(rendered, "\n")
	}
	return norm(a) == norm(b)
}

// --- Class C: the credential must not reach a surface the caller keeps ----------

// hostilePusher is a pusher that actively tries to emit the credential through
// every channel [aws.PushCommand] gives it.
//
// It replaces the benign recorder the earliest version of this test used, which
// is the reason that test named a surface it could not exercise: a fake that
// cannot express the failure is a test that names a case. It was a hostile
// *runner* until USOSS-41; the credential is not reachable from a
// [aws.BuildCommand] any more — the type has no field for it — so the hostility
// moved to the phase that really does hold material.
type hostilePusher struct{ inner aws.ImagePusher }

func (h hostilePusher) Push(ctx context.Context, cmd aws.PushCommand) error {
	material := []string{
		credentials.Reveal(cmd.Credentials.AccessKeyID),
		credentials.Reveal(cmd.Credentials.SecretAccessKey),
		credentials.Reveal(cmd.Credentials.SessionToken),
	}
	if cmd.Output != nil {
		// Whole, and split across writes, because a redactor that scans one
		// Write at a time misses the second.
		for _, m := range material {
			_, _ = cmd.Output.Write([]byte("leak: " + m + "\n"))
			for i := range m {
				_, _ = cmd.Output.Write([]byte{m[i]})
			}
			_, _ = cmd.Output.Write([]byte("\n"))
		}
	}
	if h.inner != nil {
		_ = h.inner.Push(ctx, cmd)
	}
	// And through the error, which the pusher's own obligation forbids.
	return errors.New("push failed: " + strings.Join(material, " "))
}

// TestNoBuildSurfaceCarriesTheCredentialEvenWhenThePusherIsHostile.
//
// The obligation on ImagePusher not to put its output in an error is a contract
// on a component this package does not control. This asserts the property that
// has to hold when the contract is broken.
//
// It is a weaker threat than the one this test was written for — that one was a
// Dockerfile RUN line reading the executor's own environment, and the answer to
// it is now that there is nothing there to read — but it is not a hypothetical
// one: the pusher's environment is where the credential is, and a tool that
// prints its environment when a registry call fails is ordinary.
func TestNoBuildSurfaceCarriesTheCredentialEvenWhenThePusherIsHostile(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	prefix := ensureRepo(t, p, "app")
	sub.Pusher = hostilePusher{inner: aws.NewRecordingPusher()}
	p, err := aws.New(sub, fullConfig())
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}

	var logs strings.Builder
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
		Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		Logs:         &logs,
	})
	if err == nil {
		t.Fatal("the hostile pusher's build succeeded, so this test checks nothing")
	}

	for surface, text := range map[string]string{
		"the caller's log writer": logs.String(),
		"the returned error":      err.Error(),
	} {
		for _, material := range credentialMaterial() {
			if strings.Contains(text, material) {
				t.Errorf("the push credential reached %s. Moving output out of the error does "+
					"not stop it becoming a durable record, and the pusher cannot be assumed to "+
					"honour its obligation", surface)
			}
		}
	}
	if !errors.Is(err, compute.ErrFailed) {
		t.Errorf("the redacted error matches no compute sentinel: %v", err)
	}
}

// TestEveryPortMethodThatTakesARefIsCoveredByAnOwnershipCase.
//
// The three ownership cases above are cases. This is the class: it derives the
// set of methods from the interfaces themselves and fails if one is not covered,
// so the fourth method — the one review predicted would forget — cannot be added
// without either a case or a deliberate exemption.
//
// Derived rather than restated, because a hand-maintained list of methods drifts
// from the interface, and this project has paid for that shape more than once. A
// derivation returning nothing passes every check over it, so the count is
// asserted too.
func TestEveryPortMethodThatTakesARefIsCoveredByAnOwnershipCase(t *testing.T) {
	t.Parallel()

	// The invariant, stated the way USOSS-13 states it because their framing is
	// better than mine: *every method that addresses an existing resource
	// refuses when the resource it would mutate — or would act on the strength
	// of — is not this platform's.* Framing it around mutation is what turns a
	// read-back from an exception into an instance: DescribeRepository does not
	// mutate, and reporting somebody else's repository as this platform's is
	// still a lie a caller acts on.
	//
	// The methods an ownership case exists for. Every method on the two ports
	// must appear exactly once.
	covered := map[string]string{
		"DeleteRepository":         "TestOwnershipIsRequiredByEveryPortMethodThatUsesAResource",
		"DescribeRepository":       "resolves through imageRegistry.owned",
		"EnsureRepository":         "TestAnUnownedRepositoryIsRefusedBeforeAnythingIsWritten",
		"DeleteWorkloadIdentity":   "TestOwnershipIsRequiredByEveryPortMethodThatUsesAResource",
		"DescribeWorkloadIdentity": "resolves through identityService.owned",
		"EnsureWorkloadIdentity":   "conformance port/workload-identity/refuses-a-resource-it-does-not-own",
		"EnsureBucket":             "conformance port/bucket/refuses-a-resource-it-does-not-own",
		"DescribeBucket":           "TestDescribeBucketRefusesABucketItDoesNotOwn",
		"DeleteBucket":             "TestBucketOwnershipIsCheckedOnEveryPath",
		"EmptyBucket":              "TestBucketOwnershipIsCheckedOnEveryPath",
		"Grant":                    "TestBucketOwnershipIsCheckedOnEveryPath",
		"Revoke":                   "TestBucketOwnershipIsCheckedOnEveryPath",
		"DescribeGrant":            "TestBucketOwnershipIsCheckedOnEveryPath",
		// Found by deriving the port list rather than listing it: the case
		// existed and was not recorded, because ImageBuilder was not one of the
		// two ports the literal named.
		"Build": "TestNoCredentialIsMintedForADestinationThisProviderDidNotIssue",
		// The four the accessor-shaped derivation could not see at all: the ext
		// ports are reached by a lookup helper, so they are on no interface
		// compute.Provider returns. Visible now because the population is the
		// concrete type behind each port.
		"EnsureTableBucket":  "TestExtBucketOwnershipIsCheckedOnEveryPath",
		"DeleteTableBucket":  "TestExtBucketOwnershipIsCheckedOnEveryPath",
		"EnsureVectorBucket": "TestExtBucketOwnershipIsCheckedOnEveryPath",
		"DeleteVectorBucket": "TestExtBucketOwnershipIsCheckedOnEveryPath",
		// USOSS-26's secret store, visible here for the first time because this
		// branch and that one only met on this rebase. Two of its five methods
		// have a case; three do NOT CHECK OWNERSHIP AT ALL.
		//
		// Put and DeleteScope refuse an unowned parameter and their own tests
		// prove it. Get returns an unowned parameter's material, Describe reports
		// it as this store's, and Delete destroys it and returns nil -- all at a
		// valid path
		// inside the store's own prefix, and both reproduced on plain main with
		// none of this branch's code present. Their tests cover a FOREIGN ref and
		// an OUT-OF-PREFIX ref, which are different resources: a foreign ref
		// names another provider's resource, and this is this provider's path
		// holding somebody else's parameter.
		//
		// Not fixed here. Get's correct refusal is a design question with two
		// defensible answers -- ErrNotOwned tells a caller that another tool's
		// parameter exists at that path, ErrNotFound hides it -- and choosing
		// belongs to that port's author, not to a rebase. Recorded, reported, and
		// pinned by a test that FAILS WHEN THE DEFECT IS FIXED so this entry
		// cannot outlive it.
		// USOSS-14's relational and key-value ports, visible for the first time
		// here for the same reason the secret store's methods were: the port list
		// is derived from what compute.Provider vends, so a port merged on
		// another branch is inside this check the moment the two trees meet.
		// Their Ensures are covered; their Describes and Deletes are the SAME
		// HOLE the secret store has, and DeleteRelational's is the worst instance
		// of it in this package -- see
		// TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete.
		"EnsureRelational":      "conformance port/relational/refuses-a-resource-it-does-not-own",
		"EnsureKeyValueTable":   "conformance port/key-value/refuses-a-resource-it-does-not-own",
		"DescribeRelational":    "TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete",
		"DeleteRelational":      "TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete",
		"DescribeKeyValueTable": "TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete",
		"DeleteKeyValueTable":   "TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete",
		// The Waits poll their own Describe rather than reading the substrate, so
		// they have exactly the ownership behaviour it has and cannot have a
		// separate one. Recorded rather than left out: "inherits" is a decision
		// and an omission is not.
		"WaitForRelational":    "polls DescribeRelational, so it inherits its ownership behaviour",
		"WaitForKeyValueTable": "polls DescribeKeyValueTable, so it inherits its ownership behaviour",
		// USOSS-11's container port (#23). Its four ref-taking service methods do
		// check ownership -- containerRuntime routes them through
		// Provider.checkServiceOwned -- so unlike the two ports above these are
		// ordinary entries rather than a record of a hole. Read from the code and
		// cited to the test that drives each.
		"EnsureService":   "TestEnsureConvergesWhatItOwnsAndLeavesWhatItDoesNot",
		"DescribeService": "resolves through Provider.checkServiceOwned",
		"DeleteService":   "resolves through Provider.checkServiceOwned",
		"ScaleService":    "resolves through Provider.checkServiceOwned",
		"WaitForService":  "polls DescribeService, so it inherits its ownership behaviour",
		// USOSS-33's scheduled-job port. Each method checks schedule-group
		// ownership before mutating or reporting an EventBridge Scheduler backed
		// job; Wait polls DescribeScheduledJob, so it inherits that read-side
		// ownership behaviour.
		"EnsureScheduledJob":   "TestEnsureConvergesWhatItOwnsAndLeavesWhatItDoesNot",
		"DescribeScheduledJob": "TestScheduledJobCreatesSchedulerRoleAndScopedPolicy",
		"DeleteScheduledJob":   "TestEnsureConvergesWhatItOwnsAndLeavesWhatItDoesNot",
		"Put":                  "TestPutExistingUnownedIsConflict",
		"DeleteScope":          "TestDeleteScopeLeavesForeignParametersAndSaysSo",
		"Get":                  "TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete",
		"Delete":               "TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete",
		// Arrived with USOSS-15's SecretStore.Describe (#42) and has the same
		// hole as its two siblings, which is why it is on the same record rather
		// than on an exemption of its own.
		"Describe": "TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete",
		// USOSS-12's function and function-endpoint ports, visible for the first
		// time here for the same reason USOSS-11's and USOSS-14's were: the port
		// list is derived from what compute.Provider vends, so a port merged on
		// another branch is inside this check the moment the two trees meet.
		//
		// Unlike the relational/key-value/secret-store holes above, all eight
		// methods here check ownership. Ensure and Delete always have
		// (functionRuntime.EnsureFunction/DeleteFunction and .EnsureEndpoint/
		// .DeleteEndpoint call checkOwned on the Lambda function and, for the
		// endpoint, the load balancer and target group records). Describe and
		// Wait did NOT before this rebase -- the exact shape of the hole this
		// check exists to find, discovered by deriving the port list rather than
		// trusting that "Ensure and Delete check, so the port is fine" -- and are
		// fixed in the same pass: DescribeFunction/WaitForFunction and
		// DescribeEndpoint/WaitForEndpoint now re-check ownership on every read,
		// because a Ref that resolved to this platform's resource a poll ago is
		// not a capability either.
		"EnsureFunction":   "functionRuntime.EnsureFunction calls checkOwned on the Lambda function",
		"DeleteFunction":   "functionRuntime.DeleteFunction calls checkOwned on the Lambda function",
		"DescribeFunction": "functionRuntime.DescribeFunction calls checkOwned on the Lambda function",
		"WaitForFunction":  "functionRuntime.WaitForFunction calls checkOwned on every poll",
		"EnsureEndpoint":   "functionRuntime.EnsureEndpoint calls checkOwned on the load balancer, target group and Lambda function",
		"DeleteEndpoint":   "functionRuntime.DeleteEndpoint calls checkOwned on the load balancer and target group",
		"DescribeEndpoint": "functionRuntime.DescribeEndpoint calls checkOwned on the load balancer",
		"WaitForEndpoint":  "functionRuntime.WaitForEndpoint calls checkOwned on every poll",
	}

	// Every name recorded above must resolve to a test that exists, or be prose
	// that says so.
	//
	// The same hole USOSS-37 closed one layer out: a name validated for nothing
	// is a restatement nothing compares against its source. An entry naming a
	// test that was renamed or deleted goes on satisfying this table forever.
	// Entries that are deliberately prose -- "resolves through X.owned",
	// "conformance <check name>" -- are recognised by not starting with "Test".
	testsInPackage := testFunctionsHere(t)
	for method, by := range covered {
		if !strings.HasPrefix(by, "Test") {
			continue
		}
		if !testsInPackage[by] {
			t.Errorf("%s is recorded as covered by %q and no test function of that name exists in "+
				"this package. A coverage claim that names nothing is worse than an empty entry: "+
				"it reads as covered and cannot be resolved", method, by)
		}
	}

	// The ports are DERIVED from compute.Provider, not listed.
	//
	// They used to be listed, as the two this package then implemented. The
	// methods were derived and the *ports* were not, so USOSS-13's object store
	// arrived with five ref-taking methods and sat entirely outside this check
	// while it passed. That is the same defect this test exists to prevent, one
	// level up: a hand-picked population verifies the cases somebody thought of.
	//
	// So this reflects over compute.Provider for every accessor returning a port
	// interface, and requires coverage for every port THIS provider actually
	// vends. A port it refuses has no methods to own anything.
	ports := advertisedPorts(t, newProviderForPortScan(t))
	if len(ports) < 2 {
		t.Fatalf("derived %d ports from compute.Provider, which cannot be right", len(ports))
	}
	// A SET of method names, not a count of methods.
	//
	// covered is keyed by name, and two ports can declare the same one: Granter
	// is embedded in both the object store and USOSS-14's key-value port, so
	// Grant and Revoke are each declared twice. Counting occurrences made the
	// tally disagree with a complete table by exactly the number of shared names
	// -- a red check with nothing to add, which is the kind that gets silenced by
	// padding the table rather than by reading it. The population is the set of
	// names the table has to answer for.
	seen := map[string]bool{}
	for portName, typ := range ports {
		if typ.NumMethod() == 0 {
			t.Fatalf("%s reflects zero methods, so this check proves nothing", portName)
		}
		for i := range typ.NumMethod() {
			name := typ.Method(i).Name
			seen[name] = true
			if _, ok := covered[name]; !ok {
				t.Errorf("%s.%s has no ownership case. Every method that turns a Ref or a name "+
					"into something it acts on must go through the resolve step that reads the "+
					"ownership tags — a Ref that was valid once is not a capability, because the "+
					"resource behind it can be replaced. Add a case to "+
					"TestOwnershipIsRequiredByEveryPortMethodThatUsesAResource, or record why "+
					"this method needs none.", portName, name)
			}
		}
	}
	if len(seen) != len(covered) {
		// Both directions. A name in the table that no port declares is the same
		// drift as a method with no entry, and it is the one nothing above
		// catches: an entry for a method that was renamed or removed goes on
		// excusing something that is not there.
		for name := range covered {
			if !seen[name] {
				t.Errorf("the table records %q and no port this provider vends declares it; the "+
					"entry has outlived the method it described", name)
			}
		}
		t.Errorf("the %d ports this provider vends declare %d distinct method names and %d are "+
			"recorded here; the table has drifted from the interfaces",
			len(ports), len(seen), len(covered))
	}
}

// testFunctionsHere is the set of test function names declared in this package.
//
// Source-level, deliberately: the point is to resolve a NAME somebody wrote in a
// table, and a name that does not resolve is the defect. It cannot tell whether
// the named test asserts what the entry claims -- that is the boundary, and it is
// the same one USOSS-37 drew: this binds a name to a declaration, not a claim to
// an assertion.
func testFunctionsHere(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		files++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	if files == 0 || len(out) == 0 {
		t.Fatalf("found %d test files and %d test functions; a derivation that reads nothing "+
			"resolves every name put to it", files, len(out))
	}
	return out
}

// TestDescribeRefusesAResourceItDoesNotOwn is the half the table above records
// as "resolves through owned" — asserted rather than asserted-by-comment.
func TestDescribeRefusesAResourceItDoesNotOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("repository", func(t *testing.T) {
		t.Parallel()
		p, _ := newProvider(t, nil)
		reg, err := p.Registry()
		if err != nil {
			t.Fatalf("Registry(): %v", err)
		}
		repo := mustEnsureRepo(t, p, "app")
		if err := reg.DeleteRepository(ctx, repo.Ref); err != nil {
			t.Fatalf("DeleteRepository: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, repo.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}
		if _, err := reg.DescribeRepository(ctx, repo.Ref); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("DescribeRepository reported an unowned repository as this platform's: %v", err)
		}
	})

	t.Run("role", func(t *testing.T) {
		t.Parallel()
		p, _ := newProvider(t, nil)
		id := mustEnsureIdentity(t, p, "app")
		if err := p.Identities().DeleteWorkloadIdentity(ctx, id.Ref); err != nil {
			t.Fatalf("DeleteWorkloadIdentity: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, id.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}
		if _, err := p.Identities().DescribeWorkloadIdentity(ctx, id.Ref); !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("DescribeWorkloadIdentity reported an unowned role as this platform's: %v", err)
		}
	})
}

// TestTheLifecyclePolicyOfAnOwnedRepositoryConvergesToTheSpec.
//
// This replaces three tests that asserted two mechanisms which no longer exist —
// a read-merge-write, and a claim tag gating a refusal. Between them those
// produced five findings, and the machinery was solving a problem this substrate
// does not have: nothing in AWS applies a lifecycle policy to a repository on
// your behalf, so the S3-tagging analogy that motivated it does not hold here.
//
// What is asserted now is the whole contract: on a repository this provider
// owns, the lifecycle policy is the one the spec describes, across every
// transition including the ones with nothing on either side.
func TestTheLifecyclePolicyOfAnOwnedRepositoryConvergesToTheSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}

	// Every transition, including none-to-none and none-after-none, because the
	// remove path used to be where the state machine went wrong.
	for _, want := range []compute.RetentionPolicy{
		{},
		{KeepLast: 20},
		{KeepLast: 5},
		{},
		{},
		{MaxAge: 14 * 24 * time.Hour},
		{},
		{KeepLast: 3},
	} {
		if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
			Name: "app", Retention: want,
		}); err != nil {
			t.Fatalf("EnsureRepository(%+v): %v", want, err)
		}
		got, err := reg.DescribeRepository(ctx, repo.Ref)
		if err != nil {
			t.Fatalf("DescribeRepository: %v", err)
		}
		if got.Spec.Retention != want {
			t.Errorf("after asking for %+v the effective retention is %+v", want, got.Spec.Retention)
		}
		_, policyErr := mem.GetLifecyclePolicy(ctx, "apphub/app")
		hasPolicy := policyErr == nil
		wantPolicy := want.KeepLast > 0 || want.MaxAge > 0
		if hasPolicy != wantPolicy {
			t.Errorf("after asking for %+v the repository %s a lifecycle policy",
				want, map[bool]string{true: "has", false: "has no"}[hasPolicy])
		}
	}
}

// TestARepositoryThisProviderDoesNotOwnIsNeverReached.
//
// The lifecycle policy is written unconditionally on a repository this provider
// owns, so the *only* thing standing between an operator's repository and being
// rewritten is the ownership check — and that check runs before anything else.
// This asserts the protection is where the code says it is, since removing the
// claim tag removed the second line of defence.
func TestARepositoryThisProviderDoesNotOwnIsNeverReached(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, sub := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}

	// Somebody else's repository, with a lifecycle policy of their own, under
	// the name this provider would use.
	mem.PutUnowned("apphub/app")
	operatorPolicy := `{"rules":[{"rulePriority":1,"description":"theirs",` +
		`"selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days",` +
		`"countNumber":1},"action":{"type":"expire"}}]}`
	if err := mem.PutLifecyclePolicy(ctx, "apphub/app", operatorPolicy); err != nil {
		t.Fatalf("PutLifecyclePolicy: %v", err)
	}

	for _, retention := range []compute.RetentionPolicy{{}, {KeepLast: 5}} {
		_, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app", Retention: retention})
		if !errors.Is(err, compute.ErrNotOwned) {
			t.Errorf("retention %+v: refused with %v, want compute.ErrNotOwned", retention, err)
		}
		after, err := mem.GetLifecyclePolicy(ctx, "apphub/app")
		if err != nil {
			t.Fatalf("GetLifecyclePolicy: %v", err)
		}
		if after != operatorPolicy {
			t.Errorf("retention %+v: the operator's lifecycle policy was changed:\n%s",
				retention, after)
		}
	}
}

// TestEveryLifecyclePolicyThisProviderRendersIsValidForECR.
//
// The merged documents violated ECR's unique-priority invariant, which the
// service rejects outright — so a spec a caller was entitled to write produced a
// call that could never succeed. The merge is gone, and the renderer is checked
// against the invariants directly rather than through it.
func TestEveryLifecyclePolicyThisProviderRendersIsValidForECR(t *testing.T) {
	t.Parallel()
	// Both shapes this provider can render, separately. The combination is
	// refused rather than rendered — see the subtest below — because ECR permits
	// one rule that applies to every image and both shapes are that.
	for _, retention := range []compute.RetentionPolicy{
		{KeepLast: 20},
		{KeepLast: 1},
		{MaxAge: 14 * 24 * time.Hour},
		{MaxAge: 24 * time.Hour},
	} {
		p, sub := newProvider(t, nil)
		reg, err := p.Registry()
		if err != nil {
			t.Fatalf("Registry(): %v", err)
		}
		if _, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{
			Name: "app", Retention: retention,
		}); err != nil {
			t.Fatalf("EnsureRepository(%+v): %v", retention, err)
		}
		mem, ok := sub.ECR.(*aws.MemoryECR)
		if !ok {
			t.Fatalf("the substrate's registry is a %T", sub.ECR)
		}

		policy, err := mem.GetLifecyclePolicy(context.Background(), "apphub/app")
		if err != nil {
			t.Fatalf("GetLifecyclePolicy: %v", err)
		}
		var parsed struct {
			Rules []struct {
				RulePriority int    `json:"rulePriority"`
				Description  string `json:"description"`
				Selection    struct {
					TagStatus string `json:"tagStatus"`
				} `json:"selection"`
			} `json:"rules"`
		}
		if err := json.Unmarshal([]byte(policy), &parsed); err != nil {
			t.Fatalf("the rendered policy is not JSON: %v", err)
		}
		if len(parsed.Rules) == 0 {
			t.Fatalf("retention %+v rendered no rules", retention)
		}
		seen := map[int]bool{}
		lastAny := -1
		for i, rule := range parsed.Rules {
			if rule.RulePriority < 1 {
				t.Errorf("retention %+v rendered rulePriority %d; ECR requires a positive integer",
					retention, rule.RulePriority)
			}
			if seen[rule.RulePriority] {
				t.Errorf("retention %+v rendered a duplicate rulePriority %d; ECR rejects the "+
					"document", retention, rule.RulePriority)
			}
			seen[rule.RulePriority] = true
			if rule.Selection.TagStatus == "any" {
				lastAny = i
			}
		}
		// ECR requires a tagStatus=any rule to be the last rule, and permits
		// only one. Both rules this provider writes are tagStatus=any, so with
		// two of them the document is invalid however they are numbered — which
		// is a real limit on RetentionPolicy and is reported as one.
		anyCount := 0
		for _, rule := range parsed.Rules {
			if rule.Selection.TagStatus == "any" {
				anyCount++
			}
		}
		if anyCount > 1 {
			t.Errorf("retention %+v rendered %d rules with tagStatus=any; ECR permits one and "+
				"requires it last, so this document is rejected by the service", retention, anyCount)
		}
		if lastAny >= 0 && lastAny != len(parsed.Rules)-1 {
			t.Errorf("retention %+v put a tagStatus=any rule at index %d of %d; ECR requires it "+
				"last", retention, lastAny, len(parsed.Rules))
		}
	}
}

// TestRetentionShapesECRCannotCombineAreRefused.
//
// Found by the validity test above rather than by review, and it is the half of
// review's blocker 2 that removing the merge did not close: ECR permits exactly
// one lifecycle rule with tagStatus "any" and requires it last, and both shapes
// this provider renders are tagStatus "any". So a RetentionPolicy the interface
// documents as legal produced a document the service rejects outright.
//
// Refusing keeps the failure at the spec, where a caller can act on it, rather
// than at the deploy as a validation error about policy syntax.
func TestRetentionShapesECRCannotCombineAreRefused(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	_, err = reg.EnsureRepository(context.Background(), compute.RepositorySpec{
		Name:      "app",
		Retention: compute.RetentionPolicy{KeepLast: 5, MaxAge: 7 * 24 * time.Hour},
	})
	if err == nil {
		t.Fatal("a retention policy asking for both shapes was accepted; ECR rejects the " +
			"document it renders")
	}
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "KeepLast") || !strings.Contains(err.Error(), "MaxAge") {
		t.Errorf("the refusal does not name both fields, so a caller cannot tell which to "+
			"drop: %v", err)
	}
}

// TestARefusedEnsureChangesNothing.
//
// The ownership tests assert this for the three methods review found walking
// past the ownership check. This is the same property for the *validation*
// paths, which nobody has found a defect in — and that is why it is worth
// pinning rather than skipping.
//
// Every case here is refused before anything is written, so the test passes
// today by construction. It stops passing the moment a validation moves below a
// write, which is a natural thing for a later edit to do — putting the retention
// check next to the code that renders retention, say, which is after the
// repository has been created. The failure would be a repository left behind by
// a call that reported an error, and nothing else in the suite would see it.
//
// The comparison is against everything the substrate renders, not the resource
// the case is about, for the reason review gave: a write to some *other* object
// is the same defect one step removed.
func TestARefusedEnsureChangesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	specs := map[string]compute.RepositorySpec{
		"a name that cannot be sanitised":                {Name: "   "},
		"a label key in the reserved aws namespace":      {Name: "app", Labels: map[string]string{"aws:x": "y"}},
		"a label value longer than a tag":                {Name: "app", Labels: map[string]string{"k": strings.Repeat("v", 300)}},
		"a label key with a character a tag cannot hold": {Name: "app", Labels: map[string]string{"k\x01": "v"}},
		"a negative KeepLast":                            {Name: "app", Retention: compute.RetentionPolicy{KeepLast: -1}},
		"a MaxAge ECR cannot express":                    {Name: "app", Retention: compute.RetentionPolicy{MaxAge: time.Hour}},
		"both retention shapes at once":                  {Name: "app", Retention: compute.RetentionPolicy{KeepLast: 1, MaxAge: 24 * time.Hour}},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			reg, err := p.Registry()
			if err != nil {
				t.Fatalf("Registry(): %v", err)
			}
			before, err := p.Harness().Rendered(ctx)
			if err != nil {
				t.Fatalf("Rendered: %v", err)
			}
			sort.Strings(before)

			if _, err := reg.EnsureRepository(ctx, spec); err == nil {
				t.Fatalf("the spec %+v was accepted", spec)
			} else if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Errorf("refused with %v, want compute.ErrInvalidSpec", err)
			}

			after, err := p.Harness().Rendered(ctx)
			if err != nil {
				t.Fatalf("Rendered: %v", err)
			}
			sort.Strings(after)
			if strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Errorf("a refused Ensure left something behind:\n before: %v\n  after: %v",
					before, after)
			}
		})
	}
}

// newProviderForPortScan builds a provider with every capability this package can
// offer, so the derived port set is the widest one rather than whatever the
// default fixture happened to configure.
func newProviderForPortScan(t *testing.T) *aws.Provider {
	t.Helper()
	p, err := aws.New(aws.NewMemorySubstrate(), fullConfig())
	if err != nil {
		t.Fatalf("constructing a provider for the port scan: %v", err)
	}
	return p
}

// advertisedPorts returns the method set to require ownership cases for.
//
// # Why the authority is the CONCRETE type, not the interface
//
// The first version reflected over `compute.Provider` and took each accessor's
// returned **interface** type. That derived the ports instead of listing them,
// which was the fix -- and it was a derivation over the wrong authority. The two
// compute/ext ports are reached by a *lookup helper* rather than by an accessor,
// so they appear on no interface `compute.Provider` returns, and their methods sat
// outside the check exactly as the listed version's omissions had. Deleting
// DeleteTableBucket's ownership check compiled and the suite stayed green.
//
// That is the same defect one layer in: accessors are not the population, they are
// one route to it. So this takes the **concrete type behind each port** and
// enumerates its exported methods. `objectStore` implements the core ObjectStore
// *and* both ext provisioners, so all of them arrive from one reflection with
// nothing named -- and a fourth ext port on the same type would too.
//
// An exported method that is genuinely not a port method is not a problem: the
// covered map takes a reason as its value, and "records why this method needs
// none" is a legitimate entry.
//
// # Unclassifiable accessors are fatal
//
// An accessor this cannot classify used to be skipped. A derivation that shrugs is
// a bypass, and this package has now found that shape in five separate gates. If
// compute.Provider grows an accessor shaped differently, this stops the build
// rather than quietly shrinking its own population.
func advertisedPorts(t *testing.T, p compute.Provider) map[string]reflect.Type {
	t.Helper()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	provider := reflect.TypeOf(&p).Elem()
	value := reflect.ValueOf(&p).Elem()

	// Accessors that answer something other than a port. Named, so that a new
	// one is a build failure rather than a silent skip.
	notAPort := map[string]string{
		"Name":         "the provider's name, not a port",
		"Capabilities": "the capability set, not a port",
	}

	out := map[string]reflect.Type{}
	for i := range provider.NumMethod() {
		m := provider.Method(i)
		if reason, ok := notAPort[m.Name]; ok {
			_ = reason
			continue
		}
		ft := m.Type
		if ft.NumIn() != 0 || ft.NumOut() == 0 || ft.NumOut() > 2 ||
			(ft.NumOut() == 2 && ft.Out(1) != errType) || ft.Out(0).Kind() != reflect.Interface {
			t.Fatalf("compute.Provider.%s is shaped in a way this derivation does not recognise "+
				"(%s). It is fatal rather than skipped: a derivation that silently drops what it "+
				"cannot classify shrinks its own population, and every gate in this repository "+
				"that skipped instead of failing has been found to have a bypass. Either teach "+
				"this function the shape or add %s to notAPort with a reason.",
				m.Name, ft, m.Name)
		}
		res := value.Method(i).Call(nil)
		// A refused accessor has no port, and a port that does not exist owns
		// nothing. Recorded as absent rather than as an error: a provider
		// legitimately refuses what it is not configured for.
		if (len(res) == 2 && !res[1].IsNil()) || res[0].IsNil() {
			continue
		}
		// The CONCRETE type, so methods reachable only through an ext lookup are
		// in the population too.
		concrete := reflect.TypeOf(res[0].Interface())
		out[ft.Out(0).Name()] = concrete
	}
	return out
}

// TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete RECORDS A DEFECT. It is
// not an endorsement, and it fails when the defect is fixed.
//
// # The defect
//
// [compute.SecretStore] obliges a provider to refuse a resource it does not own.
// This provider's secret store (USOSS-26) honours that on Put and DeleteScope and
// not on Get, Describe or Delete:
//
//   - Get returns the material of a parameter at a valid path inside the store's
//     own prefix that this platform did not create — another tool's secret, read
//     out through apphub's API;
//   - Describe reports such a parameter as this store's, which is the same lie
//     without the material: a caller that branches on a successful Describe goes
//     on to Get or Delete it;
//   - Delete removes such a parameter and returns nil — another tool's secret,
//     destroyed irreversibly, with a success reported to the caller.
//
// Reproduced on plain main at 6d2d86f with none of USOSS-13's code present, so it
// is not an artefact of the rebase that surfaced it.
//
// Describe joined the list without anybody touching this file. USOSS-15 (#42)
// added it to [compute.SecretStore], the derivation below found a twenty-first
// method with no ownership case, and the method turned out to share the hole its
// two siblings already had — which is the derived population doing the job a
// hand-written list could not. It was verified here rather than assumed: the
// assertion was written to fail if Describe refused, and it did not.
//
// # Why it was invisible
//
// The port's own tests cover a FOREIGN ref (another provider's) and an
// OUT-OF-PREFIX ref (a differently-configured provider's tree). Both are refused.
// Neither is this case: this provider's own prefix, holding somebody else's
// parameter. **Two of the three ways a reference can be wrong were tested, and the
// third is the one where the resource is real and reachable.**
//
// It surfaced here because TestEveryPortMethodThatTakesARefIsCoveredByAnOwnershipCase
// derives its population from the ports the provider vends rather than listing
// them, so a port arriving from another branch is inside the check the moment the
// two trees meet.
//
// # Why this branch records it instead of fixing it
//
// Get's correct refusal is a design question with two defensible answers, and they
// differ in what they disclose: ErrNotOwned tells the caller that another tool's
// parameter exists at that path, while ErrNotFound hides it. That choice belongs
// to the port's author. A rebase is the wrong place to decide it, and a silent fix
// inside an unrelated pull request is the wrong way to land it.
//
// # Why it is a test and not a comment
//
// So the record cannot outlive the defect. A prose note in the coverage table
// would go on excusing two methods after somebody fixed them, and nothing would
// say so — the exact rot USOSS-37 found in its own exemption table. This fails the
// moment either method starts refusing, which forces the table entry to be
// updated in the same change as the fix.
func TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, params, store := newStore(t, nil)
	_ = p

	// A parameter at a path this store issued, then re-planted without the
	// ownership tags — which is what an operator or another tool writing into the
	// same prefix produces.
	// Put reports a [compute.StoredSecret] since USOSS-35; the Ref inside it is
	// what every other method here takes.
	stored, err := store.Put(ctx, compute.SecretSpec{
		Scope: "app", Name: "THEIRS", Placement: compute.Placement{Name: "default"},
		Value: compute.NewSecretValue("placeholder"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ref := stored.Ref
	name := paramOf(t, ref)
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete of our own parameter: %v", err)
	}
	params.PutUnowned(name, compute.NewSecretValue("somebody-elses-material"))

	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Errorf("Get now refuses an unowned parameter (%v). THE DEFECT THIS TEST RECORDS IS "+
			"FIXED: delete this test and change the Get entry in the ownership coverage table to "+
			"name the test that proves the refusal", err)
	} else if compute.RevealSecret(got) != "somebody-elses-material" {
		t.Errorf("Get returned %q, which is neither a refusal nor the planted material; the "+
			"behaviour has changed in some third way and this record no longer describes it",
			compute.RevealSecret(got))
	}

	// Describe before Delete, because Delete destroys the fixture.
	if _, derr := store.Describe(ctx, ref); derr != nil {
		t.Errorf("Describe now refuses an unowned parameter (%v). THE DEFECT THIS TEST RECORDS IS "+
			"FIXED for Describe: update the table entry", derr)
	}

	if err := store.Delete(ctx, ref); err != nil {
		t.Errorf("Delete now refuses an unowned parameter (%v). THE DEFECT THIS TEST RECORDS IS "+
			"FIXED for Delete: update the table entry", err)
	} else if _, gerr := params.Get(ctx, name); gerr == nil {
		t.Error("Delete returned nil and the unowned parameter survives; the behaviour has " +
			"changed in some third way and this record no longer describes it")
	}
}

// TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete RECORDS A DEFECT, on
// the same terms as [TestTheSecretStoreDoesNotCheckOwnershipOnGetDescribeOrDelete]
// and for the same reason. It is not an endorsement, and it fails when the defect
// is fixed.
//
// # The defect
//
// USOSS-14's relational and key-value ports check ownership on their Ensures --
// the conformance suite drives that -- and on nothing else:
//
//   - DescribeRelational and DescribeKeyValueTable report a resource this
//     platform did not create as this platform's, which is a lie a caller acts
//     on: it will grant on it, write to it, and tear it down;
//   - DeleteKeyValueTable destroys an unowned table and returns nil;
//   - **DeleteRelational destroys an unowned DB cluster, its instance and its
//     subnet group, and returns nil.** That is somebody else's database, deleted
//     irreversibly, reported as a successful teardown.
//
// DeleteRelational is not uniformly blind, which is what makes it worth writing
// down rather than summarising: it *does* check the security group's ownership
// before removing it (database.go, "Only if it is ours, and ours as a database
// network"). So the argument was made, in that function, for the cheapest of the
// four resources it deletes -- and the cluster went unchecked.
//
// # Why this branch records it instead of fixing it
//
// Same reasoning as the secret store's, and it has held up twice now. The
// correct refusal is a disclosure choice -- ErrNotOwned tells the caller another
// tool's cluster exists under that name, ErrNotFound hides it -- and it belongs
// to that port's author. A rebase is the wrong place to decide it and somebody
// else's pull request is the wrong place to land it. The record is a test so it
// cannot outlive the defect.
//
// # How it surfaced
//
// [TestEveryPortMethodThatTakesARefIsCoveredByAnOwnershipCase] derives its
// population from the ports the provider vends. USOSS-14 merged its two ports
// against a version of that check which named ImageRegistry and IdentityService
// by hand, so eight methods entered main outside a check that would have seen
// them. The derived form found them on the first rebase that put the two trees
// together -- which is the third time on this branch that replacing a list with
// a derivation has found something, after ImageBuilder.Build and the secret
// store.
func TestTheDatabasePortsDoNotCheckOwnershipOnDescribeOrDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := newProvider(t, nil)

	t.Run("relational", func(t *testing.T) {
		rel, err := p.Relational()
		if err != nil {
			t.Fatalf("Relational(): %v", err)
		}
		st, err := rel.EnsureRelational(ctx, compute.RelationalSpec{
			Name: "recorded", Engine: compute.EnginePostgres, EngineVersion: "16",
			DatabaseName: "app", AdminUsername: "admin",
			AdminPassword: compute.NewSecretValue("not-the-material-under-test"),
		})
		if err != nil {
			t.Fatalf("EnsureRelational: %v", err)
		}
		// Provision, remove, then re-plant unowned at the same name: the case is
		// this provider's own path holding somebody else's resource, which is
		// what a foreign ref and an out-of-prefix ref are both NOT.
		if err := rel.DeleteRelational(ctx, st.Ref); err != nil {
			t.Fatalf("DeleteRelational of our own cluster: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, st.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}

		if _, err := rel.DescribeRelational(ctx, st.Ref); err != nil {
			t.Errorf("DescribeRelational now refuses an unowned cluster (%v). THE DEFECT THIS "+
				"TEST RECORDS IS FIXED: change the DescribeRelational entry in the ownership "+
				"coverage table to name the test that proves the refusal", err)
		}
		if err := rel.DeleteRelational(ctx, st.Ref); err != nil {
			t.Errorf("DeleteRelational now refuses an unowned cluster (%v). THE DEFECT THIS TEST "+
				"RECORDS IS FIXED for DeleteRelational: update the table entry", err)
		}
	})

	t.Run("key-value", func(t *testing.T) {
		kv, err := p.KeyValues()
		if err != nil {
			t.Fatalf("KeyValues(): %v", err)
		}
		st, err := kv.EnsureKeyValueTable(ctx, compute.KeyValueSpec{
			Name: "recorded", PartitionKey: "pk",
		})
		if err != nil {
			t.Fatalf("EnsureKeyValueTable: %v", err)
		}
		if err := kv.DeleteKeyValueTable(ctx, st.Ref); err != nil {
			t.Fatalf("DeleteKeyValueTable of our own table: %v", err)
		}
		if err := p.Harness().CreateUnowned(ctx, st.Ref); err != nil {
			t.Fatalf("CreateUnowned: %v", err)
		}

		if _, err := kv.DescribeKeyValueTable(ctx, st.Ref); err != nil {
			t.Errorf("DescribeKeyValueTable now refuses an unowned table (%v). THE DEFECT THIS "+
				"TEST RECORDS IS FIXED: update the table entry", err)
		}
		if err := kv.DeleteKeyValueTable(ctx, st.Ref); err != nil {
			t.Errorf("DeleteKeyValueTable now refuses an unowned table (%v). THE DEFECT THIS "+
				"TEST RECORDS IS FIXED for DeleteKeyValueTable: update the table entry", err)
		}
	})
}
