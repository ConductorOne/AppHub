// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/conductorone/apphub/compute"
)

// The SDK-backed store is a translation layer, and the two things worth testing
// about a translation layer are that it says the right thing to the service and
// that it understands what the service says back. Neither needs a network: the
// requests are inspected as values and the responses, including the failures,
// are the SDK's own types.

// fakeSSM records requests and replays canned responses.
type fakeSSM struct {
	puts      []*ssm.PutParameterInput
	gets      []*ssm.GetParameterInput
	describes []*ssm.DescribeParametersInput
	addTags   []*ssm.AddTagsToResourceInput
	removeTag []*ssm.RemoveTagsFromResourceInput
	deletes   []*ssm.DeleteParameterInput

	// describePages is returned one page per DescribeParameters call.
	describePages []*ssm.DescribeParametersOutput
	getOut        *ssm.GetParameterOutput
	tagsOut       *ssm.ListTagsForResourceOutput
	err           error
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.puts = append(f.puts, in)
	return &ssm.PutParameterOutput{}, f.err
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.gets = append(f.gets, in)
	if f.err != nil {
		return nil, f.err
	}
	return f.getOut, nil
}

func (f *fakeSSM) DescribeParameters(_ context.Context, in *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	f.describes = append(f.describes, in)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.describePages) == 0 {
		return &ssm.DescribeParametersOutput{}, nil
	}
	page := f.describePages[0]
	f.describePages = f.describePages[1:]
	return page, nil
}

func (f *fakeSSM) ListTagsForResource(_ context.Context, _ *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tagsOut, nil
}

func (f *fakeSSM) AddTagsToResource(_ context.Context, in *ssm.AddTagsToResourceInput, _ ...func(*ssm.Options)) (*ssm.AddTagsToResourceOutput, error) {
	f.addTags = append(f.addTags, in)
	return &ssm.AddTagsToResourceOutput{}, f.err
}

func (f *fakeSSM) RemoveTagsFromResource(_ context.Context, in *ssm.RemoveTagsFromResourceInput, _ ...func(*ssm.Options)) (*ssm.RemoveTagsFromResourceOutput, error) {
	f.removeTag = append(f.removeTag, in)
	return &ssm.RemoveTagsFromResourceOutput{}, f.err
}

func (f *fakeSSM) DeleteParameter(_ context.Context, in *ssm.DeleteParameterInput, _ ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error) {
	f.deletes = append(f.deletes, in)
	return &ssm.DeleteParameterOutput{}, f.err
}

var _ SSMAPI = (*fakeSSM)(nil)

// TestPutSendsSecureStringAndOnlyTagsOnCreate covers the two request-shape
// decisions that matter. SecureString has no configuration behind it, and Tags
// on an overwriting Put is rejected by the service — the constraint that made the
// source system tag in a separate, error-discarding call.
func TestPutSendsSecureStringAndOnlyTagsOnCreate(t *testing.T) {
	t.Parallel()
	f := &fakeSSM{}
	store := NewSSMParameterStore(f)
	ctx := context.Background()
	in := PutParameterInput{
		Name:  "/apphub/apps/a/TOKEN",
		Value: compute.NewSecretValue("material"),
		KeyID: "alias/k",
		Tier:  TierStandard,
		Tags:  map[string]string{"apphub.dev/managed-by": "apphub"},
	}
	if _, err := store.Put(ctx, in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	in.Overwrite = true
	if _, err := store.Put(ctx, in); err != nil {
		t.Fatalf("Put(overwrite): %v", err)
	}
	if len(f.puts) != 2 {
		t.Fatalf("%d PutParameter calls", len(f.puts))
	}
	create, overwrite := f.puts[0], f.puts[1]
	for i, req := range f.puts {
		if req.Type != ssmtypes.ParameterTypeSecureString {
			t.Fatalf("call %d sent type %q; a String parameter is stored in plaintext", i, req.Type)
		}
		if req.Tier != ssmtypes.ParameterTierStandard {
			t.Fatalf("call %d sent tier %q; an empty tier makes the service apply the account's "+
				"default, which may be Intelligent-Tiering and then the documented value limit is "+
				"not the one in force", i, req.Tier)
		}
		if awssdk.ToString(req.KeyId) != "alias/k" {
			t.Fatalf("call %d did not pass the configured key", i)
		}
	}
	if len(create.Tags) != 1 {
		t.Fatalf("the create-only Put sent %d tags; a parameter created untagged is "+
			"indistinguishable from somebody else's", len(create.Tags))
	}
	if awssdk.ToBool(create.Overwrite) {
		t.Fatal("the create-only Put set Overwrite")
	}
	if len(overwrite.Tags) != 0 {
		t.Fatal("the overwriting Put sent tags, which SSM rejects")
	}
	if !awssdk.ToBool(overwrite.Overwrite) {
		t.Fatal("the overwriting Put did not set Overwrite")
	}
}

// TestGetAsksForDecryption: a SecureString read without WithDecryption comes back
// as ciphertext, which would be injected into a workload as a credential that
// does not work.
func TestGetAsksForDecryption(t *testing.T) {
	t.Parallel()
	f := &fakeSSM{getOut: &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: awssdk.String("material")},
	}}
	got, err := NewSSMParameterStore(f).Get(context.Background(), "/p/TOKEN")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if compute.RevealSecret(got) != "material" {
		t.Fatal("Get did not return the value")
	}
	if !awssdk.ToBool(f.gets[0].WithDecryption) {
		t.Fatal("Get did not ask for decryption")
	}
}

// TestGetWithNoValueIsNotFound: an empty secret is worse than an error, because
// it would be injected into a workload as an empty credential.
func TestGetWithNoValueIsNotFound(t *testing.T) {
	t.Parallel()
	for _, out := range []*ssm.GetParameterOutput{
		{},
		{Parameter: &ssmtypes.Parameter{}},
	} {
		_, err := NewSSMParameterStore(&fakeSSM{getOut: out}).Get(context.Background(), "/p/TOKEN")
		if !errors.Is(err, ErrParameterNotFound) {
			t.Fatalf("Get with no value returned %v, want ErrParameterNotFound", err)
		}
	}
}

// TestDescribeByPathEnumeratesEveryPageAndNeverAsksForValues.
//
// The pagination half is the one that fails quietly: a teardown that stopped at
// the first page would leave credentials behind and report success. The other
// half is the operation choice — DescribeParameters returns metadata,
// GetParametersByPath returns values, and only one of those can leak.
func TestDescribeByPathEnumeratesEveryPageAndNeverAsksForValues(t *testing.T) {
	t.Parallel()
	f := &fakeSSM{describePages: []*ssm.DescribeParametersOutput{
		{
			Parameters: []ssmtypes.ParameterMetadata{
				{Name: awssdk.String("/p/apps/a/ONE"), Tier: ssmtypes.ParameterTierStandard, Version: 3},
			},
			NextToken: awssdk.String("more"),
		},
		{
			Parameters: []ssmtypes.ParameterMetadata{
				{Name: awssdk.String("/p/apps/a/TWO"), Tier: ssmtypes.ParameterTierAdvanced, Version: 1},
			},
		},
	}}
	got, err := NewSSMParameterStore(f).DescribeByPath(context.Background(), "/p/apps/a")
	if err != nil {
		t.Fatalf("DescribeByPath: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("DescribeByPath returned %d parameters across two pages, want 2; a listing that "+
			"stops at the first page is how a teardown leaves credentials behind", len(got))
	}
	if got[1].Tier != TierAdvanced || got[1].Version != 1 {
		t.Fatalf("metadata was not translated: %+v", got[1])
	}
	if len(f.describes) != 2 {
		t.Fatalf("%d DescribeParameters calls", len(f.describes))
	}
	if awssdk.ToString(f.describes[1].NextToken) != "more" {
		t.Fatal("the second call did not carry the continuation token")
	}
	filter := f.describes[0].ParameterFilters[0]
	if awssdk.ToString(filter.Key) != "Path" || awssdk.ToString(filter.Option) != "Recursive" {
		t.Fatalf("the listing filter is %s/%s, want Path/Recursive",
			awssdk.ToString(filter.Key), awssdk.ToString(filter.Option))
	}
	// And there is no code path that could have asked for a value: the
	// interface's return type has no value field.
	if strings.Contains(fmt.Sprintf("%+v", got), "material") {
		t.Fatal("a listing carried material")
	}
}

// TestSetTagsAddsBeforeRemoving: a failure between the two must not be the one
// that strips the ownership tag, because the next Put would then refuse to adopt
// this platform's own parameter.
func TestSetTagsAddsBeforeRemoving(t *testing.T) {
	t.Parallel()
	f := &fakeSSM{}
	store := NewSSMParameterStore(f)
	if err := store.SetTags(context.Background(), "/p/TOKEN",
		map[string]string{"a": "1"}, []string{"b"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	if len(f.addTags) != 1 || len(f.removeTag) != 1 {
		t.Fatalf("%d add and %d remove calls", len(f.addTags), len(f.removeTag))
	}
	// Nothing is sent when there is nothing to do, so a converged parameter
	// costs no API calls.
	f2 := &fakeSSM{}
	if err := NewSSMParameterStore(f2).SetTags(context.Background(), "/p/TOKEN", nil, nil); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	if len(f2.addTags) != 0 || len(f2.removeTag) != 0 {
		t.Fatal("an empty tag plan still called the service")
	}
}

// TestSSMErrorMapping is the part of the adapter that decides what a caller sees.
//
// It is a table over the SDK's own error types rather than over strings, because
// the source system matched on strings and error codes at the call sites and
// every one of those matches was a provider dependency hidden in a conditional.
func TestSSMErrorMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		what string
		err  error
		want error // nil means "no sentinel: deliberately unclassified"
	}{
		{"ParameterNotFound", &ssmtypes.ParameterNotFound{}, ErrParameterNotFound},
		{"InvalidResourceId", &ssmtypes.InvalidResourceId{}, ErrParameterNotFound},
		{"ParameterAlreadyExists", &ssmtypes.ParameterAlreadyExists{}, ErrParameterExists},
		{"TooManyUpdates", &ssmtypes.TooManyUpdates{}, ErrThrottled},
		{"ThrottlingException", &ssmtypes.ThrottlingException{}, ErrThrottled},
		{"InternalServerError", &ssmtypes.InternalServerError{}, ErrThrottled},
		{"ParameterLimitExceeded", &ssmtypes.ParameterLimitExceeded{}, nil},
		{"ParameterMaxVersionLimitExceeded", &ssmtypes.ParameterMaxVersionLimitExceeded{}, nil},
		{"something the SDK did not model", errors.New("connection reset"), nil},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			got := ssmError(tc.err, "/p/apps/a/TOKEN")
			if got == nil {
				t.Fatal("a non-nil SDK error mapped to nil")
			}
			if !errors.Is(got, tc.err) {
				t.Fatalf("the mapping dropped the underlying cause: %v", got)
			}
			if !strings.Contains(got.Error(), "/p/apps/a/TOKEN") {
				t.Fatalf("the mapping dropped the parameter name, so an operator cannot tell which "+
					"secret failed: %v", got)
			}
			for _, sentinel := range []error{
				ErrParameterNotFound, ErrParameterExists, ErrParameterTooLarge, ErrThrottled,
			} {
				matched := errors.Is(got, sentinel)
				want := tc.want != nil && errors.Is(sentinel, tc.want)
				if matched != want {
					t.Fatalf("%v matches %v = %t, want %t", got, sentinel, matched, want)
				}
			}
		})
	}
	if ssmError(nil, "x") != nil {
		t.Fatal("ssmError(nil) is not nil")
	}
}

// TestThrottlingIsTransientAndNeverTerminal is the invariant the interface's
// ErrTransient exists for, checked here as well as through the conformance
// suite's InduceTransient hook.
//
// The negative half is the one that matters. ErrFailed is documented as "not
// retryable without changing the spec", so a caller told that about a throttled
// call abandons a deploy that would have worked; and ErrNotOwned would tell it
// somebody else owns the name. Both are reachable one careless switch arm away.
func TestThrottlingIsTransientAndNeverTerminal(t *testing.T) {
	t.Parallel()
	params := NewMemoryParameters()
	iam := NewMemoryIAM()
	p, err := New(&Substrate{Parameters: params, IAM: iam}, Config{
		Region:           MemoryRegion,
		DefaultPlacement: "default",
		Placements:       map[string]PlacementConfig{"default": {}},
		Identity:         IdentityConfig{PathPrefix: "/apphub/", NamePrefix: "apphub-"},
		Secrets:          &SecretConfig{PathPrefix: "/apphub/test"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	spec := compute.SecretSpec{
		Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue("material"),
	}

	// Every call the port makes, not just the first: the mapping is per call
	// site, and a Put that classifies correctly says nothing about a Get.
	calls := map[string]func() error{
		"Put": func() error { _, e := store.Put(context.Background(), spec); return e },
		"Get": func() error {
			_, e := store.Get(context.Background(), p.ref(compute.KindSecret, "/apphub/test/apps/app-1/TOKEN"))
			return e
		},
		"Delete": func() error {
			return store.Delete(context.Background(), p.ref(compute.KindSecret, "/apphub/test/apps/app-1/TOKEN"))
		},
		"DeleteScope": func() error { return store.DeleteScope(context.Background(), "app-1") },
		"EnsureWorkloadIdentity": func() error {
			_, e := p.Identities().EnsureWorkloadIdentity(context.Background(),
				compute.WorkloadIdentitySpec{Name: "api", RunsOn: compute.RuntimeContainer})
			return e
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			throttled := fmt.Errorf("%w: rate exceeded", ErrThrottled)
			// FailUntilStopped on both, not FailNext: this table drives five
			// call sites inside one armed window, and the one-shot form is
			// consumed by whichever of them runs first -- leaving the rest
			// scored as unexercised rather than as unarmed. USOSS-60 measured
			// that as 2 of 6 on the sibling gate.
			stopParams := params.FailUntilStopped(throttled)
			stopIAM := iam.FailUntilStopped(throttled)
			defer func() {
				stopParams()
				stopIAM()
			}()
			err := call()
			if err == nil {
				t.Fatalf("%s succeeded against a throttled substrate", name)
			}
			if !errors.Is(err, compute.ErrTransient) {
				t.Fatalf("%s reported a throttled substrate as %v, want compute.ErrTransient", name, err)
			}
			for _, wrong := range []error{
				compute.ErrFailed, compute.ErrNotOwned, compute.ErrNotFound,
				compute.ErrInvalidSpec, compute.ErrUnsupported, compute.ErrForeignRef,
			} {
				if errors.Is(err, wrong) {
					t.Fatalf("%s reported a throttled substrate as %v as well; a caller branching "+
						"on that abandons a deploy that would have worked", name, wrong)
				}
			}
			// This table drives four SecretStore methods and one IdentityService
			// method. The identity case routes through Provider.substrateError,
			// which used to retain the foreign error in every arm -- the package
			// convention this store's wrap was copied from, on the ECR, IAM, STS
			// and Builder ports (USOSS-76). substrateError no longer retains, so
			// the exemption that used to live here is retired: all five call
			// sites are asserted the same way.
			assertForeignErrorNotRetained(t, name, err)
		})
	}
}

// assertForeignErrorNotRetained is the (a) fix's property, asserted from the
// package's own tests as well as from outside.
func assertForeignErrorNotRetained(t *testing.T, name string, err error) {
	t.Helper()
	// INVERTED, not deleted. This asserted that the store RETAINS the
	// substrate cause, which was true of the old wrap and was the (a)
	// defect: retaining the cause retains its TEXT, and on this port the
	// substrate handles credential material. The classification is what
	// a caller branches on; the cause is what could carry a value.
	if errors.Is(err, ErrThrottled) {
		t.Fatalf("%s retained the substrate error in its chain (%v). The classification "+
			"must survive and the foreign error must not: a caller-supplied "+
			"ParameterStore, or the SDK, writes that text and neither can be shown to "+
			"be free of material", name, err)
	}
	if strings.Contains(err.Error(), "rate exceeded") {
		t.Fatalf("%s carried the substrate's own message into its error: %v", name, err)
	}
}
