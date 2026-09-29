// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/conductorone/apphub/credentials"
)

// Test identifiers. None of them is a real one, and two properties keep them
// that way.
//
// An account number is built at run time rather than written down: the
// repository's own secret scan reports every standalone twelve-digit number as
// the shape of an AWS account ID, with an empty allowlist, and a fixture is not a
// good enough reason to add an entry to it or to write a number that has to be
// argued about. The policy ARNs name the AWS partition instead of an account, so
// they need no number at all.
const (
	testRegion      = "us-example-1"
	testPolicyARN   = "arn:aws:iam::aws:policy/ExampleBedrockAccess"
	testBoundaryARN = "arn:aws:iam::aws:policy/ExampleBoundary"
	testUserPath    = "/example-platform/"
	testUserPrefix  = "example-bedrock"
	testSessPrefix  = "example"
)

func testAccount() string { return strings.Repeat("9", 12) }

func testRoleARN() string { return "arn:aws:iam::" + testAccount() + ":role/example-vending-role" }

// fixedNow is the clock every test uses. A fixed clock is what lets an expiry
// assertion be an equality rather than a tolerance.
var fixedNow = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func fullConfig() Config {
	return Config{
		Region: testRegion,
		Dynamic: &DynamicConfig{
			RoleARN:           testRoleARN(),
			SessionNamePrefix: testSessPrefix,
		},
		Static: &StaticConfig{
			UserPath:               testUserPath,
			UserNamePrefix:         testUserPrefix,
			PolicyARN:              testPolicyARN,
			PermissionsBoundaryARN: testBoundaryARN,
		},
	}
}

// fakePresigner records what it was asked for and returns a synthetic URL.
type fakePresigner struct {
	url     string
	err     error
	region  string
	session sessionCredentials
	calls   int
	// applied captures the PresignOptions the caller supplied, so a test can
	// assert the expiry middleware was installed without running the real signer.
	optionFuncs int
}

func (f *fakePresigner) PresignGetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, optFns ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	f.calls++
	f.optionFuncs = len(optFns)
	if f.err != nil {
		return nil, f.err
	}
	url := f.url
	if url == "" {
		url = "https://sts." + testRegion + ".amazonaws.com/?Action=GetCallerIdentity&X-Amz-Signature=deadbeef"
	}
	return &v4.PresignedHTTPRequest{URL: url}, nil
}

// harness is one provider plus the fakes behind it.
type harness struct {
	p   *Provider
	iam *fakeIAM
	sts *fakeSTS
	pre *fakePresigner
	tok *fakeTokens
}

// newHarness builds a provider over the fakes, bypassing NewProvider's client
// arguments so a test can inject an interface.
//
// It sets every seam explicitly rather than relying on a zero value, because a
// seam left nil would reach the real AWS SDK and the test would stop being
// hermetic without saying so.
func newHarness(t *testing.T, cfg Config, opts ...Option) *harness {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test configuration is invalid: %v", err)
	}
	h := &harness{
		iam: newFakeIAM(),
		sts: newFakeSTS(fixedNow),
		pre: &fakePresigner{},
	}
	h.p = &Provider{cfg: cfg, sts: h.sts, iam: h.iam, now: func() time.Time { return fixedNow }}
	h.p.presign = func(region string, sess sessionCredentials) presignAPI {
		h.pre.region = region
		h.pre.session = sess
		return h.pre
	}
	for _, opt := range opts {
		opt(h.p)
	}
	return h
}

// withFakeTokens installs a web identity token source the test can inspect.
func (h *harness) withFakeTokens(token string) *harness {
	h.tok = &fakeTokens{token: token}
	h.p.tokens = h.tok
	return h
}

func dynamicRequest() credentials.CreateRequest {
	return credentials.CreateRequest{
		Name:           "example-app",
		CredentialType: credentials.CredentialTypeDynamic,
		TTL:            time.Hour,
		RequesterID:    "someone@example.com",
		RequesterType:  "user",
	}
}

func staticRequest() credentials.CreateRequest {
	return credentials.CreateRequest{
		Name:           "example-app",
		CredentialType: credentials.CredentialTypeStatic,
		TTL:            7 * dayHours * time.Hour,
		RequesterID:    "someone@example.com",
		RequesterType:  "user",
	}
}

func TestNewProviderRefusesAConfigurationItCannotActformOn(t *testing.T) {
	t.Parallel()
	// A configured credential type with no client would defer the failure to the
	// first vend, which is the least useful moment for it.
	if _, err := NewProvider(fullConfig(), nil, nil); !errors.Is(err, ErrMissingClient) {
		t.Fatalf("want ErrMissingClient, got %v", err)
	}
	if _, err := NewProvider(Config{Region: testRegion}, nil, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

// TestCapabilitiesFollowTheConfiguration runs the control in both directions.
//
// A table asserting only that a configured type is reported available cannot tell
// a correct provider from one that reports everything available, which is the
// direction that matters: lifecycle.CheckIssuable admits a vend on the strength
// of these bits.
func TestCapabilitiesFollowTheConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
		want credentials.Capabilities
	}{
		{
			name: "both",
			cfg:  fullConfig(),
			want: credentials.Capabilities{Dynamic: true, Static: true, Revoke: true, Status: true},
		},
		{
			name: "dynamic only",
			cfg:  Config{Region: testRegion, Dynamic: fullConfig().Dynamic},
			want: credentials.Capabilities{Dynamic: true},
		},
		{
			name: "static only",
			cfg:  Config{Region: testRegion, Static: fullConfig().Static},
			want: credentials.Capabilities{Static: true, Revoke: true, Status: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, tc.cfg)
			if got := h.p.Capabilities(); got != tc.want {
				t.Fatalf("Capabilities() = %+v, want %+v", got, tc.want)
			}
			if got := h.p.SupportsDynamic(); got != tc.want.Dynamic {
				t.Fatalf("SupportsDynamic() = %v, want %v", got, tc.want.Dynamic)
			}
			// CapabilitiesOf must agree: a declaration this package makes and the
			// contract's own reader disagreeing is how a provider gets admitted
			// for something it cannot do.
			if got := credentials.CapabilitiesOf(h.p); got != tc.want {
				t.Fatalf("CapabilitiesOf() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCreateCredentialRefusesWhatItCannotHonour(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     Config
		mutate  func(*credentials.CreateRequest)
		wantErr error
	}{
		{
			name:    "a requested scope",
			mutate:  func(r *credentials.CreateRequest) { r.RequestedScope = []string{"anthropic.claude"} },
			wantErr: credentials.ErrScopeNotSupported,
		},
		{
			name:   "no TTL",
			mutate: func(r *credentials.CreateRequest) { r.TTL = 0 },
		},
		{
			name:   "a negative TTL",
			mutate: func(r *credentials.CreateRequest) { r.TTL = -time.Hour },
		},
		{
			name:   "an unrecognised credential type",
			mutate: func(r *credentials.CreateRequest) { r.CredentialType = "permanent" },
		},
		{
			name:   "an empty credential type",
			mutate: func(r *credentials.CreateRequest) { r.CredentialType = "" },
		},
		{
			name:    "a dynamic TTL under STS's floor",
			mutate:  func(r *credentials.CreateRequest) { r.TTL = time.Minute },
			wantErr: ErrLimit,
		},
		{
			name:    "a dynamic TTL over STS's ceiling",
			mutate:  func(r *credentials.CreateRequest) { r.TTL = 13 * time.Hour },
			wantErr: ErrLimit,
		},
		{
			name:    "a dynamic vend this deployment did not configure",
			cfg:     Config{Region: testRegion, Static: fullConfig().Static},
			wantErr: ErrTypeNotConfigured,
		},
		{
			name: "a static vend this deployment did not configure",
			cfg:  Config{Region: testRegion, Dynamic: fullConfig().Dynamic},
			mutate: func(r *credentials.CreateRequest) {
				r.CredentialType = credentials.CredentialTypeStatic
				r.TTL = dayHours * time.Hour
			},
			wantErr: ErrTypeNotConfigured,
		},
		{
			name: "a static TTL that is not a whole number of days",
			mutate: func(r *credentials.CreateRequest) {
				r.CredentialType = credentials.CredentialTypeStatic
				r.TTL = 36 * time.Hour
			},
			wantErr: ErrLimit,
		},
		{
			name: "a static TTL shorter than a day",
			mutate: func(r *credentials.CreateRequest) {
				r.CredentialType = credentials.CredentialTypeStatic
				r.TTL = 12 * time.Hour
			},
			wantErr: ErrLimit,
		},
		{
			// The sentinel, not merely the presence of an error. prefixedName would
			// refuse this too, with ErrNameNotUsable, so asserting only that
			// something failed cannot tell the two refusals apart -- and a mutation
			// removing the explicit check survived exactly that gap.
			name:    "a dynamic vend with no requester",
			mutate:  func(r *credentials.CreateRequest) { r.RequesterID = "" },
			wantErr: ErrRequesterRequired,
		},
		{
			name:    "a dynamic vend with a whitespace-only requester",
			mutate:  func(r *credentials.CreateRequest) { r.RequesterID = "   " },
			wantErr: ErrNameNotUsable,
		},
		{
			name: "a name with no usable characters",
			mutate: func(r *credentials.CreateRequest) {
				r.CredentialType = credentials.CredentialTypeStatic
				r.TTL = dayHours * time.Hour
				r.Name = "  /  "
			},
			wantErr: ErrNameNotUsable,
		},
		{
			name: "a name too long to prefix",
			mutate: func(r *credentials.CreateRequest) {
				r.CredentialType = credentials.CredentialTypeStatic
				r.TTL = dayHours * time.Hour
				r.Name = strings.Repeat("a", maxIAMUserName)
			},
			wantErr: ErrNameNotUsable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			if cfg.Region == "" {
				cfg = fullConfig()
			}
			h := newHarness(t, cfg)
			req := dynamicRequest()
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			res, err := h.p.CreateCredential(context.Background(), req)
			if err == nil {
				t.Fatalf("want an error, got result %+v", res)
			}
			if res != nil {
				t.Fatalf("an error must not also return a result: %+v", res)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			// The control in the other direction: nothing reached AWS.
			if calls := h.iam.called(); len(calls) != 0 {
				t.Fatalf("a refused request called IAM: %v", calls)
			}
			if calls := h.sts.called(); len(calls) != 0 {
				t.Fatalf("a refused request called STS: %v", calls)
			}
		})
	}
}

// TestARefusedRequestIsNotTheOnlyOutcome is the control for the table above.
//
// Every case there asserts a refusal and asserts that AWS was never called. A
// provider that refused everything would pass all of them, so this test drives
// the same harness with a request that must succeed and asserts that AWS *was*
// called.
func TestARefusedRequestIsNotTheOnlyOutcome(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err != nil {
		t.Fatalf("the accepted request was refused: %v", err)
	}
	if got := h.sts.called(); len(got) == 0 {
		t.Fatal("the accepted request never reached STS")
	}
	h2 := newHarness(t, fullConfig())
	if _, err := h2.p.CreateCredential(context.Background(), staticRequest()); err != nil {
		t.Fatalf("the accepted static request was refused: %v", err)
	}
	if got := h2.iam.called(); len(got) == 0 {
		t.Fatal("the accepted static request never reached IAM")
	}
}

func TestUnrecognizedHandlesAreRefusedRatherThanReportedRevoked(t *testing.T) {
	t.Parallel()
	// The source returned nil from RevokeCredential for anything that did not
	// start with "{", so every one of these reported a successful revoke having
	// done nothing at all -- and the record was then finalized as revoked.
	handles := []string{
		"",
		"{}",
		`{"u":"x","c":"y"}`,
		"iam-user",
		"iam-user:",
		"iam-user:only-one-part",
		"iam-user::missing-user",
		"iam-user:user:",
		"iam-user:bad user:cred",
		"iam-user:user:cred:extra",
		"bedrock-token",
		"bedrock-token:session",
		"bedrock-token:session:not-a-number",
		"bedrock-token::1",
		"some-other-provider:handle",
	}
	h := newHarness(t, fullConfig())
	for _, handle := range handles {
		t.Run(handle, func(t *testing.T) {
			if err := h.p.RevokeCredential(context.Background(), handle, nil); err == nil {
				t.Fatal("RevokeCredential reported success on a handle it cannot act on")
			}
			status, err := h.p.GetCredentialStatus(context.Background(), handle, nil)
			if err == nil {
				t.Fatal("GetCredentialStatus reported no error on a handle it cannot read")
			}
			if status != credentials.CredentialStatusUnknown {
				t.Fatalf("status = %q, want unknown", status)
			}
		})
	}
}

func TestRevokingADynamicCredentialSaysItCannot(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	res, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	err = h.p.RevokeCredential(context.Background(), res.PlatformKeyID, nil)
	if !errors.Is(err, credentials.ErrRevokeNotSupported) {
		t.Fatalf("want ErrRevokeNotSupported, got %v", err)
	}
	// And nothing was attempted against AWS on the way to saying so.
	for _, c := range h.iam.called() {
		t.Fatalf("revoking a bearer token called IAM: %s", c)
	}
}

func TestDynamicStatusIsDerivedFromTheHandle(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	res, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	status, err := h.p.GetCredentialStatus(context.Background(), res.PlatformKeyID, nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != credentials.CredentialStatusActive {
		t.Fatalf("status = %q, want active", status)
	}

	// Past the stated expiry the answer changes, and it changes without asking
	// AWS anything -- which is the property Capabilities reports.
	h.p.now = func() time.Time { return fixedNow.Add(2 * time.Hour) }
	status, err = h.p.GetCredentialStatus(context.Background(), res.PlatformKeyID, nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != credentials.CredentialStatusExpired {
		t.Fatalf("status = %q, want expired", status)
	}
	if calls := h.iam.called(); len(calls) != 0 {
		t.Fatalf("a dynamic status check called IAM: %v", calls)
	}
}

// TestStaticHandlesAreRefusedWhenTheStaticPathIsGone pins a transition rather
// than a call: a deployment reconfigured to stop offering static credentials
// still holds records whose handles name IAM users.
//
// Reporting a successful revoke there would finalize a record for a credential
// that is still live, which is the same defect as an unrecognised handle
// returning nil.
func TestStaticHandlesAreRefusedWhenTheStaticPathIsGone(t *testing.T) {
	t.Parallel()
	h := newHarness(t, Config{Region: testRegion, Dynamic: fullConfig().Dynamic})
	handle := staticHandle("example-bedrock-example-app", "sscred-1")
	if err := h.p.RevokeCredential(context.Background(), handle, nil); !errors.Is(err, ErrTypeNotConfigured) {
		t.Fatalf("want ErrTypeNotConfigured, got %v", err)
	}
	status, err := h.p.GetCredentialStatus(context.Background(), handle, nil)
	if !errors.Is(err, ErrTypeNotConfigured) {
		t.Fatalf("want ErrTypeNotConfigured, got %v", err)
	}
	if status != credentials.CredentialStatusUnknown {
		t.Fatalf("status = %q, want unknown", status)
	}
}

func TestProviderIdentity(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	if h.p.ID() != ProviderID {
		t.Fatalf("ID() = %q, want %q", h.p.ID(), ProviderID)
	}
	if h.p.Name() == "" {
		t.Fatal("Name() is empty")
	}
	// The registry is the contract's own consumer of ID; registering twice must
	// fail, which is how a second provider under one key is caught.
	reg := credentials.NewProviderRegistry()
	if err := reg.Register(h.p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(h.p); err == nil {
		t.Fatal("the registry accepted the same provider ID twice")
	}
	got, ok := reg.Get(ProviderID)
	if !ok || got != credentials.CredentialProvider(h.p) {
		t.Fatalf("Get(%q) = %v, %v", ProviderID, got, ok)
	}
}
