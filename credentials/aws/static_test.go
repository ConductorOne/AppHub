// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/credentials"
)

// TestTheFakeIAMBehavesLikeIAM checks the fixture before anything relies on it.
//
// A stateful fake that mutates what it is asked to report makes every failure
// read as a real defect, and this repository has already paid for that once: four
// confident failures in an enumeration turned out to be a stub computing state
// from an empty request body. So the three behaviours the tests below depend on
// are asserted here, on the fake, first.
func TestTheFakeIAMBehavesLikeIAM(t *testing.T) {
	t.Parallel()
	f := newFakeIAM()
	ctx := context.Background()
	h := newHarness(t, fullConfig())
	h.iam = f
	h.p.iam = f

	if _, err := h.p.CreateCredential(ctx, staticRequest()); err != nil {
		t.Fatalf("create: %v", err)
	}
	name := onlyUser(t, f)

	// One: a second user under the same name is refused, not adopted.
	if _, err := h.p.CreateCredential(ctx, staticRequest()); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("a duplicate create returned %v, want ErrNotOwned", err)
	}

	// Two: DeleteUser refuses while anything hangs off the user.
	if _, err := f.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awssdk.String(name)}); !isDeleteConflict(err) {
		t.Fatalf("DeleteUser on a populated user returned %v, want a conflict", err)
	}

	// Three: a read does not mutate. Reading the tags twice must return the same
	// thing, and must not change what a subsequent delete sees.
	before, err := h.p.ownsUser(ctx, name)
	if err != nil || !before {
		t.Fatalf("ownsUser = %v, %v", before, err)
	}
	after, err := h.p.ownsUser(ctx, name)
	if err != nil || !after {
		t.Fatalf("ownsUser on a second read = %v, %v", after, err)
	}
	if _, err := f.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awssdk.String(name)}); !isDeleteConflict(err) {
		t.Fatalf("reading the tags changed what DeleteUser sees: %v", err)
	}
}

func onlyUser(t *testing.T, f *fakeIAM) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.users) != 1 {
		t.Fatalf("want exactly one IAM user, have %d", len(f.users))
	}
	for name := range f.users {
		return name
	}
	return ""
}

func userNames(f *fakeIAM) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.users))
	for name := range f.users {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func TestStaticCreateProducesABoundedTaggedUser(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	res, err := h.p.CreateCredential(context.Background(), staticRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	name := onlyUser(t, h.iam)
	h.iam.mu.Lock()
	u := h.iam.users[name]
	h.iam.mu.Unlock()

	if u.path != testUserPath {
		t.Fatalf("path = %q, want %q", u.path, testUserPath)
	}
	// The boundary is on the create call, so there is no window in which the user
	// exists unbounded. The source made it optional metadata, so the common path
	// had no boundary at all.
	if u.boundary != testBoundaryARN {
		t.Fatalf("permissions boundary = %q, want %q", u.boundary, testBoundaryARN)
	}
	for key, want := range map[string]string{
		tagManagedBy: managedByValue,
		tagComponent: componentCredentialUser,
		tagName:      name,
	} {
		if got := u.tags[key]; got != want {
			t.Fatalf("tag %s = %q, want %q", key, got, want)
		}
	}
	if len(u.attached) != 1 || u.attached[0] != testPolicyARN {
		t.Fatalf("attached policies = %v, want exactly the configured one", u.attached)
	}
	if len(u.sscs) != 1 || u.sscs[0].service != bedrockServiceName {
		t.Fatalf("service credentials = %+v, want one for %s", u.sscs, bedrockServiceName)
	}

	// The handle names the user and the credential, and nothing has to be
	// re-derived to act on it later.
	gotUser, gotCred, err := parseStaticHandle(res.PlatformKeyID)
	if err != nil {
		t.Fatalf("the handle this provider minted does not parse: %v", err)
	}
	if gotUser != name || gotCred != u.sscs[0].id {
		t.Fatalf("handle = %q/%q, want %q/%q", gotUser, gotCred, name, u.sscs[0].id)
	}
	if credentials.Reveal(res.APIKey) != h.iam.credSecret {
		t.Fatal("the material handed back is not what IAM returned")
	}
	// The expiry is IAM's, computed from the days this provider sent, and never a
	// local time.Now()+TTL.
	if res.ExpiresAt == nil {
		t.Fatal("no expiry was reported")
	}
	wantExp := time.Unix(0, 0).UTC().Add(7 * dayHours * time.Hour)
	if !res.ExpiresAt.Equal(wantExp) {
		t.Fatalf("ExpiresAt = %v, want IAM's %v", res.ExpiresAt, wantExp)
	}
	want := []string{testPolicyARN, testBoundaryARN, bedrockServiceName}
	if strings.Join(res.GrantedScope, "|") != strings.Join(want, "|") {
		t.Fatalf("GrantedScope = %v, want %v", res.GrantedScope, want)
	}
}

// TestAlwaysSendsAnExpiry is the one-line version of a defect worth its own test.
//
// AWS documents an absent CredentialAgeDays as "the credential will not expire",
// and the source omitted it whenever no TTL was supplied. A vend that produces a
// permanent credential by default is not a shorter lifetime, it is an unbounded
// one.
func TestAlwaysSendsAnExpiry(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	if _, err := h.p.CreateCredential(context.Background(), staticRequest()); err != nil {
		t.Fatalf("create: %v", err)
	}
	name := onlyUser(t, h.iam)
	h.iam.mu.Lock()
	defer h.iam.mu.Unlock()
	if h.iam.users[name].sscs[0].expires == nil {
		t.Fatal("the credential was created with no expiry")
	}
}

// TestAFailedCreateLeavesNothingUntracked enumerates the failure at every step of
// the create, with the population derived rather than listed.
//
// The population is the ordered set of IAM calls a successful create makes, read
// off a recording fake. A call added to createStatic later joins this enumeration
// without anybody remembering to add it -- which is the difference between this
// and a table of three method names.
func TestAFailedCreateLeavesNothingUntracked(t *testing.T) {
	t.Parallel()

	// Derive the population.
	probe := newHarness(t, fullConfig())
	if _, err := probe.p.CreateCredential(context.Background(), staticRequest()); err != nil {
		t.Fatalf("the probing create failed: %v", err)
	}
	steps := distinct(probe.iam.called())
	if len(steps) == 0 {
		t.Fatal("derived no create steps; a derivation that finds nothing passes every check over it")
	}
	t.Logf("create calls IAM %d ways: %v", len(steps), steps)

	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.fail = func(method string, _ int) error {
				if method == step {
					return withStatus(500, apiError{code: "InternalFailure"})
				}
				return nil
			}
			res, err := h.p.CreateCredential(context.Background(), staticRequest())
			if err == nil {
				t.Fatalf("failing %s still produced %+v", step, res)
			}
			left := userNames(h.iam)
			if len(left) == 0 {
				return
			}
			// Something is left behind. That is permitted only when the error says
			// so, because an operator has to know to go and remove it.
			if !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("failing %s left %v behind and the error does not say so: %v", step, left, err)
			}
		})
	}
}

// TestACreateThatCannotHandOverTheMaterialKeepsTheHandle is the one create
// failure that deliberately leaves the credential in place.
//
// Tearing it down here would be the provider deciding how to compensate for a
// half-completed vend, which is the lifecycle layer's decision. So the handle
// travels in a credentials.CreateNotDeliveredError, which carries it without
// rendering it.
func TestACreateThatCannotHandOverTheMaterialKeepsTheHandle(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.iam.credSecret = ""
	_, err := h.p.CreateCredential(context.Background(), staticRequest())
	if !errors.Is(err, credentials.ErrCreateNotDelivered) {
		t.Fatalf("want ErrCreateNotDelivered, got %v", err)
	}
	var nd *credentials.CreateNotDeliveredError
	if !errors.As(err, &nd) {
		t.Fatalf("the error does not carry a handle: %v", err)
	}
	if len(userNames(h.iam)) != 1 {
		t.Fatal("the undelivered credential was torn down; that is the lifecycle's call")
	}
	// The handle does not render, so an error that quotes the error does not quote
	// a name IAM chose.
	if strings.Contains(err.Error(), "sscred-") {
		t.Fatalf("the handle rendered into the error: %v", err)
	}
	// And it is recoverable deliberately: the caller asks for it.
	if credentials.RevealForeign(nd.PlatformKeyID()) == "" {
		t.Fatal("the handle is empty")
	}
}

func TestACreateWithNoCredentialIdentifierTearsDown(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.iam.omitCredID = true
	if _, err := h.p.CreateCredential(context.Background(), staticRequest()); err == nil {
		t.Fatal("want an error")
	}
	// Nothing could ever have named it, so leaving it would leave a credential
	// that cannot be revoked. That is the one case where tearing down is right.
	if left := userNames(h.iam); len(left) != 0 {
		t.Fatalf("an unnameable credential was left behind: %v", left)
	}
}

// TestRevokeAndStatusOverEveryPriorState is the enumeration this ticket's
// riskiest code needs.
//
// Every individual operation in teardown is correct on a user this platform
// created. What is not settled by testing calls is what happens from a state
// nothing in this package produced: the user deleted out from under the record,
// or replaced by somebody else's user of the same name. So the population is the
// prior states, crossed with the two operations that act on one.
func TestRevokeAndStatusOverEveryPriorState(t *testing.T) {
	t.Parallel()

	const userName = "example-bedrock-example-app"
	const credID = "sscred-1"
	handle := staticHandle(userName, credID)

	ourTags := map[string]string{
		tagManagedBy: managedByValue,
		tagName:      userName,
		tagComponent: componentCredentialUser,
	}
	otherComponent := map[string]string{
		tagManagedBy: managedByValue,
		tagName:      userName,
		tagComponent: "something-else",
	}
	untagged := map[string]string{}

	states := []struct {
		name string
		// setup installs the prior state.
		setup func(f *fakeIAM)
		// wantRevokeErr is the sentinel revoke must report, or nil for success.
		wantRevokeErr error
		// wantUserGone says the user must not exist after a successful revoke.
		wantUserGone bool
		// wantStatus is what GetCredentialStatus must report.
		wantStatus credentials.CredentialStatus
	}{
		{
			name:         "absent",
			setup:        func(*fakeIAM) {},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusRevoked,
		},
		{
			name: "ours, holding the credential",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{tags: ourTags, sscs: []fakeSSC{
					{id: credID, service: bedrockServiceName, status: iamtypes.StatusTypeActive},
				}}
			},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusActive,
		},
		{
			name: "ours, credential already gone",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{tags: ourTags}
			},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusRevoked,
		},
		{
			name: "ours, credential deactivated",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{tags: ourTags, sscs: []fakeSSC{
					{id: credID, service: bedrockServiceName, status: iamtypes.StatusTypeInactive},
				}}
			},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusRevoked,
		},
		{
			name: "ours, credential past its stated expiry",
			setup: func(f *fakeIAM) {
				past := fixedNow.Add(-time.Hour)
				f.users[userName] = &fakeUser{tags: ourTags, sscs: []fakeSSC{
					{id: credID, service: bedrockServiceName, status: iamtypes.StatusTypeActive, expires: &past},
				}}
			},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusExpired,
		},
		{
			name: "untagged: somebody else's user under our name",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{tags: untagged, sscs: []fakeSSC{
					{id: credID, service: bedrockServiceName, status: iamtypes.StatusTypeActive},
				}}
			},
			wantRevokeErr: ErrNotOwned,
			wantStatus:    credentials.CredentialStatusRevoked,
		},
		{
			name: "ours, but created as something else",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{tags: otherComponent}
			},
			wantRevokeErr: ErrNotOwned,
			wantStatus:    credentials.CredentialStatusRevoked,
		},
		{
			name: "ours, with children spread over several pages",
			setup: func(f *fakeIAM) {
				f.users[userName] = &fakeUser{
					tags:     ourTags,
					attached: []string{testPolicyARN, "arn:aws:iam::aws:policy/ExampleSecond", "arn:aws:iam::aws:policy/ExampleThird"},
					inline:   []string{"inline-one", "inline-two"},
					keys:     []string{"key-one", "key-two", "key-three"},
					sscs: []fakeSSC{
						{id: credID, service: bedrockServiceName, status: iamtypes.StatusTypeActive},
						{id: "sscred-2", service: "codecommit.amazonaws.com", status: iamtypes.StatusTypeActive},
					},
				}
			},
			wantUserGone: true,
			wantStatus:   credentials.CredentialStatusActive,
		},
	}

	for _, st := range states {
		t.Run("revoke/"+st.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.mu.Lock()
			st.setup(h.iam)
			h.iam.mu.Unlock()

			err := h.p.RevokeCredential(context.Background(), handle, nil)
			switch {
			case st.wantRevokeErr != nil:
				if !errors.Is(err, st.wantRevokeErr) {
					t.Fatalf("want %v, got %v", st.wantRevokeErr, err)
				}
				// A refusal must not have deleted anything on its way to refusing.
				if len(userNames(h.iam)) != 1 {
					t.Fatal("a refused revoke deleted the user anyway")
				}
			default:
				if err != nil {
					t.Fatalf("revoke: %v", err)
				}
				if st.wantUserGone && len(userNames(h.iam)) != 0 {
					t.Fatalf("revoke reported success and the user is still there: %v", userNames(h.iam))
				}
			}
		})

		t.Run("status/"+st.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.mu.Lock()
			st.setup(h.iam)
			h.iam.mu.Unlock()

			got, err := h.p.GetCredentialStatus(context.Background(), handle, nil)
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if got != st.wantStatus {
				t.Fatalf("status = %q, want %q", got, st.wantStatus)
			}
			// A status check never mutates. The source's status path was read-only
			// too, but nothing said so, and a fixture that mutates on read is how
			// this repository lost an hour to four confident false failures.
			for _, c := range h.iam.called() {
				switch c {
				case "DeleteUser", "DeleteAccessKey", "DeleteUserPolicy",
					"DeleteServiceSpecificCredential", "DetachUserPolicy", "CreateUser",
					"AttachUserPolicy", "CreateServiceSpecificCredential":
					t.Fatalf("a status check called %s", c)
				}
			}
		})
	}
}

// TestTeardownEnumeratesEveryPage is the transition the source's teardown could
// not survive.
//
// The source read one page of each list. A user with more children than a page
// therefore kept some, and DeleteUser then failed with a conflict -- an error
// that says the user has children and not which enumeration missed them. The fake
// paginates at one item per page by default, so this is the ordinary path here
// rather than an exotic one.
func TestTeardownEnumeratesEveryPage(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-example-app"
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.users[userName] = &fakeUser{
		tags: map[string]string{
			tagManagedBy: managedByValue,
			tagName:      userName,
			tagComponent: componentCredentialUser,
		},
		attached: []string{"arn:aws:iam::aws:policy/ExampleOne", "arn:aws:iam::aws:policy/ExampleTwo", "arn:aws:iam::aws:policy/ExampleThree"},
		inline:   []string{"a", "b", "c", "d"},
		keys:     []string{"k1", "k2", "k3"},
		sscs: []fakeSSC{
			{id: "sscred-1", service: bedrockServiceName},
			{id: "sscred-2", service: bedrockServiceName},
			{id: "sscred-3", service: "codecommit.amazonaws.com"},
		},
	}
	h.iam.mu.Unlock()

	if err := h.p.teardownUser(context.Background(), userName); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if left := userNames(h.iam); len(left) != 0 {
		t.Fatalf("teardown left %v", left)
	}
	// The counts are the evidence that pagination happened rather than that one
	// page happened to hold everything: three attached policies detached, four
	// inline deleted, three keys, three service credentials.
	for method, want := range map[string]int{
		"DetachUserPolicy":                3,
		"DeleteUserPolicy":                4,
		"DeleteAccessKey":                 3,
		"DeleteServiceSpecificCredential": 3,
	} {
		if got := h.iam.countOf(method); got != want {
			t.Fatalf("%s called %d times, want %d", method, got, want)
		}
	}
}

// TestATruncatedPageWithNoMarkerIsRefused closes a skip path.
//
// A response claiming truncation and supplying no marker is not a last page and
// not one this code can follow. Treating it as the end would silently shorten an
// enumeration teardown depends on being complete.
func TestATruncatedPageWithNoMarkerIsRefused(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-example-app"
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.truncateWithoutMarker = true
	h.iam.users[userName] = &fakeUser{
		tags: map[string]string{
			tagManagedBy: managedByValue,
			tagName:      userName,
			tagComponent: componentCredentialUser,
		},
		attached: []string{"arn:aws:iam::aws:policy/ExampleOne", "arn:aws:iam::aws:policy/ExampleTwo"},
	}
	h.iam.mu.Unlock()

	err := h.p.teardownUser(context.Background(), userName)
	if !errors.Is(err, ErrPaginationExhausted) {
		t.Fatalf("want ErrPaginationExhausted, got %v", err)
	}
	if len(userNames(h.iam)) != 1 {
		t.Fatal("a teardown that could not enumerate the user's children deleted it anyway")
	}
}

// TestRevokeReportsAFailedCredentialDelete is the error the source discarded.
//
// It ignored DeleteServiceSpecificCredential's error entirely and went on to
// delete the user, so a revoke that could not remove the credential reported
// whatever DeleteUser said -- pointing the diagnosis at the wrong call.
func TestRevokeReportsAFailedCredentialDelete(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-example-app"
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.users[userName] = &fakeUser{
		tags: map[string]string{
			tagManagedBy: managedByValue,
			tagName:      userName,
			tagComponent: componentCredentialUser,
		},
		sscs: []fakeSSC{{id: "sscred-1", service: bedrockServiceName}},
	}
	h.iam.fail = func(method string, _ int) error {
		if method == "DeleteServiceSpecificCredential" {
			return withStatus(403, apiError{code: "AccessDenied"})
		}
		return nil
	}
	h.iam.mu.Unlock()

	err := h.p.RevokeCredential(context.Background(), staticHandle(userName, "sscred-1"), nil)
	if err == nil {
		t.Fatal("a revoke that could not delete the credential reported success")
	}
	if h.iam.countOf("DeleteUser") != 0 {
		t.Fatal("the revoke went on to delete the user after failing to delete the credential")
	}
}

// TestEveryTeardownFailureIsReported enumerates the teardown steps the same way
// the create test enumerates the create steps, deriving the population from a
// successful run.
func TestEveryTeardownFailureIsReported(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-example-app"

	populate := func(f *fakeIAM) {
		f.users[userName] = &fakeUser{
			tags: map[string]string{
				tagManagedBy: managedByValue,
				tagName:      userName,
				tagComponent: componentCredentialUser,
			},
			attached: []string{"arn:aws:iam::aws:policy/ExampleOne"},
			inline:   []string{"inline-one"},
			keys:     []string{"key-one"},
			sscs:     []fakeSSC{{id: "sscred-1", service: bedrockServiceName}},
		}
	}

	probe := newHarness(t, fullConfig())
	probe.iam.mu.Lock()
	populate(probe.iam)
	probe.iam.mu.Unlock()
	if err := probe.p.teardownUser(context.Background(), userName); err != nil {
		t.Fatalf("the probing teardown failed: %v", err)
	}
	steps := distinct(probe.iam.called())
	if len(steps) == 0 {
		t.Fatal("derived no teardown steps")
	}
	t.Logf("teardown calls IAM %d ways: %v", len(steps), steps)

	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.mu.Lock()
			populate(h.iam)
			h.iam.fail = func(method string, _ int) error {
				if method == step {
					return withStatus(500, apiError{code: "InternalFailure"})
				}
				return nil
			}
			h.iam.mu.Unlock()

			err := h.p.teardownUser(context.Background(), userName)
			if err == nil {
				t.Fatalf("failing %s was reported as a successful teardown", step)
			}
			if len(userNames(h.iam)) != 1 {
				t.Fatalf("a failed teardown deleted the user anyway (failing %s)", step)
			}
		})
	}
}

// TestATransientFailureIsMarked pins the classification a reconciler acts on, in
// both directions.
func TestATransientFailureIsMarked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{"a 500", withStatus(500, apiError{code: "InternalFailure"}), true},
		{"a 429", withStatus(429, apiError{code: "TooManyRequestsException"}), true},
		{"a throttle at 400", withStatus(400, apiError{code: "Throttling", fault: smithy.FaultClient}), true},
		{"a server fault with no status", apiError{code: "InternalFailure", fault: smithy.FaultServer}, true},
		{"a transport failure", operationError(errors.New("connection reset")), true},
		{"access denied", withStatus(403, apiError{code: "AccessDenied", fault: smithy.FaultClient}), false},
		{"a malformed request", withStatus(400, apiError{code: "ValidationError", fault: smithy.FaultClient}), false},
		{"no such entity", withStatus(404, &iamtypes.NoSuchEntityException{}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.fail = func(method string, _ int) error {
				if method == "CreateUser" {
					return tc.err
				}
				return nil
			}
			_, err := h.p.CreateCredential(context.Background(), staticRequest())
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errors.Is(err, credentials.ErrTransient); got != tc.transient {
				t.Fatalf("ErrTransient = %v, want %v (for %v)", got, tc.transient, err)
			}
		})
	}
}

// TestNamesAreOnlyEverReadFromTheHandle is the property that makes a non-injective
// sanitisation harmless.
//
// Two distinct credential names can sanitize to one IAM user name. That is safe
// only because nothing re-derives a name in order to act on an existing user: the
// name travels in the platform key ID. Asserting it behaviourally, from the other
// end than the structural check in identifiers_test.go, because two checks over
// one claim from one direction is one check.
func TestNamesAreOnlyEverReadFromTheHandle(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	ctx := context.Background()

	// Two names that fold to the same IAM name. The first create wins; the second
	// is refused rather than adopting it.
	first := staticRequest()
	first.Name = "a b"
	second := staticRequest()
	second.Name = "a/b"

	res, err := h.p.CreateCredential(ctx, first)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.p.CreateCredential(ctx, second); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("the colliding name was not refused: %v", err)
	}

	// A third user exists under a different name. Revoking the first handle must
	// touch only the user the handle names, whatever any request said.
	const other = "example-bedrock-untouched"
	h.iam.mu.Lock()
	h.iam.users[other] = &fakeUser{tags: map[string]string{
		tagManagedBy: managedByValue,
		tagName:      other,
		tagComponent: componentCredentialUser,
	}}
	h.iam.mu.Unlock()

	if err := h.p.RevokeCredential(ctx, res.PlatformKeyID, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if left := userNames(h.iam); len(left) != 1 || left[0] != other {
		t.Fatalf("users after revoke = %v, want only %q", left, other)
	}
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// TestTeardownRefusesAUserItDoesNotOwn drives the ownership check in teardownUser
// directly, and it exists because a mutation removing that check survived the
// whole suite.
//
// The reason it survived is worth recording: revokeStatic checks ownership too, so
// every path the suite drove refused before teardown was reached. The two checks
// are deliberately redundant -- ownership is established at the write and not only
// at the read, which is compute/aws/identity.go:105-110's finding -- and a
// defence-in-depth layer with no test of its own is a layer somebody deletes as
// duplication.
//
// So: this test protects teardownUser's check, and
// TestRevokeAndStatusOverEveryPriorState protects revokeStatic's. Neither covers
// the other.
func TestTeardownRefusesAUserItDoesNotOwn(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-not-ours"
	cases := []struct {
		name string
		tags map[string]string
	}{
		{"no tags at all", map[string]string{}},
		{"a different platform's marker", map[string]string{tagManagedBy: "something-else"}},
		{"our marker, another component", map[string]string{
			tagManagedBy: managedByValue, tagComponent: "image-repository",
		}},
		{"our component, no marker", map[string]string{tagComponent: componentCredentialUser}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig())
			h.iam.mu.Lock()
			h.iam.users[userName] = &fakeUser{tags: tc.tags, attached: []string{testPolicyARN}}
			h.iam.mu.Unlock()

			if err := h.p.teardownUser(context.Background(), userName); !errors.Is(err, ErrNotOwned) {
				t.Fatalf("want ErrNotOwned, got %v", err)
			}
			if len(userNames(h.iam)) != 1 {
				t.Fatal("teardown deleted a user it does not own")
			}
			// And nothing was detached or deleted on the way to refusing: a
			// teardown that refuses after mutating is not a refusal.
			for _, c := range h.iam.called() {
				switch c {
				case "DetachUserPolicy", "DeleteUserPolicy", "DeleteAccessKey",
					"DeleteServiceSpecificCredential", "DeleteUser":
					t.Fatalf("teardown called %s on a user it refused", c)
				}
			}
		})
	}
	// The control: the same call on a user that IS ours removes it, so the test
	// above is distinguishable from a teardown that refuses everything.
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.users[userName] = &fakeUser{tags: map[string]string{
		tagManagedBy: managedByValue,
		tagName:      userName,
		tagComponent: componentCredentialUser,
	}, attached: []string{testPolicyARN}}
	h.iam.mu.Unlock()
	if err := h.p.teardownUser(context.Background(), userName); err != nil {
		t.Fatalf("teardown of a user we own: %v", err)
	}
	if len(userNames(h.iam)) != 0 {
		t.Fatal("teardown left a user it owns")
	}
}

// TestStatusFindsACredentialOnALaterPage is the case every other status test
// missed.
//
// TestRevokeAndStatusOverEveryPriorState has a multi-page state, and in it the
// credential being looked for is the first item -- so page one always answered and
// the pagination in findServiceCredential was never on the path. A mutation that
// reduced that read to a single page survived the whole suite.
//
// The diagnostic that would have caught it earlier: does every member of my
// population take the same branch? Every one did.
func TestStatusFindsACredentialOnALaterPage(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-paged"
	const target = "sscred-last"
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.users[userName] = &fakeUser{
		tags: map[string]string{
			tagManagedBy: managedByValue,
			tagName:      userName,
			tagComponent: componentCredentialUser,
		},
		sscs: []fakeSSC{
			{id: "sscred-1", service: bedrockServiceName, status: iamtypes.StatusTypeActive},
			{id: "sscred-2", service: bedrockServiceName, status: iamtypes.StatusTypeActive},
			{id: "sscred-3", service: bedrockServiceName, status: iamtypes.StatusTypeActive},
			{id: target, service: bedrockServiceName, status: iamtypes.StatusTypeActive},
		},
	}
	h.iam.mu.Unlock()

	got, err := h.p.GetCredentialStatus(context.Background(), staticHandle(userName, target), nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got != credentials.CredentialStatusActive {
		t.Fatalf("status = %q, want active for a credential on the fourth page", got)
	}
	// The evidence that pagination happened: the fake serves one item per page, so
	// finding the fourth took four reads.
	if n := h.iam.countOf("ListServiceSpecificCredentials"); n < 4 {
		t.Fatalf("ListServiceSpecificCredentials called %d times; the later pages were not read", n)
	}
	// And the other direction: a credential that is genuinely absent is still
	// reported revoked after every page has been read, rather than the read
	// running away.
	got, err = h.p.GetCredentialStatus(context.Background(), staticHandle(userName, "sscred-absent"), nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got != credentials.CredentialStatusRevoked {
		t.Fatalf("status = %q, want revoked", got)
	}
}

// TestATruncatedStatusReadIsRefused covers the same skip path in the status read
// that TestATruncatedPageWithNoMarkerIsRefused covers in teardown. Two callers of
// nextMarker, two tests: the first was written when only one existed.
func TestATruncatedStatusReadIsRefused(t *testing.T) {
	t.Parallel()
	const userName = "example-bedrock-paged"
	h := newHarness(t, fullConfig())
	h.iam.mu.Lock()
	h.iam.truncateWithoutMarker = true
	h.iam.users[userName] = &fakeUser{
		tags: map[string]string{
			tagManagedBy: managedByValue,
			tagName:      userName,
			tagComponent: componentCredentialUser,
		},
		sscs: []fakeSSC{
			{id: "sscred-1", service: bedrockServiceName, status: iamtypes.StatusTypeActive},
			{id: "sscred-2", service: bedrockServiceName, status: iamtypes.StatusTypeActive},
		},
	}
	h.iam.mu.Unlock()

	got, err := h.p.GetCredentialStatus(context.Background(), staticHandle(userName, "sscred-2"), nil)
	if !errors.Is(err, ErrPaginationExhausted) {
		t.Fatalf("want ErrPaginationExhausted, got %v", err)
	}
	if got != credentials.CredentialStatusUnknown {
		t.Fatalf("status = %q, want unknown: an unreadable enumeration is not evidence of absence", got)
	}
}
