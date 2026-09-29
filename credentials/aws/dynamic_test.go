// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithymw "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/conductorone/apphub/credentials"
)

// decodeToken takes a Bedrock bearer token apart, insisting on the whole
// documented format rather than on a prefix.
func decodeToken(t *testing.T, token credentials.Secret) *url.URL {
	t.Helper()
	raw := credentials.Reveal(token)
	body, ok := strings.CutPrefix(raw, bedrockTokenPrefix)
	if !ok {
		t.Fatalf("token does not begin with %q", bedrockTokenPrefix)
	}
	body, ok = strings.CutSuffix(body, bedrockTokenVersion)
	if !ok {
		t.Fatalf("token does not end with %q", bedrockTokenVersion)
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("the token body is not base64: %v", err)
	}
	u, err := url.Parse(string(decoded))
	if err != nil {
		t.Fatalf("the decoded token is not a URL: %v", err)
	}
	return u
}

// TestTheRealSignerProducesTheDocumentedToken drives the production presigner,
// not a double.
//
// It can, because presigning is a local signature computation: nothing here
// reaches AWS, so the one part of this package that the fakes cannot honestly
// stand in for is exercised for real. A double that returned a plausible URL
// would agree with whatever this package did, including a mistake.
func TestTheRealSignerProducesTheDocumentedToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.p.presign = newPresigner

	res, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	u := decodeToken(t, res.APIKey)

	if got, want := u.Host, "sts."+testRegion+".amazonaws.com"; got != want {
		t.Fatalf("token signs against host %q, want %q", got, want)
	}
	q := u.Query()
	for _, param := range []string{"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-Security-Token"} {
		if q.Get(param) == "" {
			t.Fatalf("the presigned URL carries no %s", param)
		}
	}
	if got := q.Get("Action"); got != "GetCallerIdentity" {
		t.Fatalf("Action = %q, want GetCallerIdentity", got)
	}
	// The signature was made with the session credentials, not with anything
	// ambient. The access key ID is not material and appears in the URL by
	// design; the secret does not.
	if !strings.Contains(q.Get("X-Amz-Credential"), "fake-access-key-id") {
		t.Fatalf("X-Amz-Credential = %q, want the session's access key", q.Get("X-Amz-Credential"))
	}
	if strings.Contains(u.String(), "fake-secret-access-key") {
		t.Fatal("the presigned URL contains the session's secret access key")
	}
	// The expiry is the session's remaining life in seconds, which for this
	// harness is exactly the requested TTL because the fake grants what is asked.
	if got, want := q.Get("X-Amz-Expires"), strconv.Itoa(int(time.Hour.Seconds())); got != want {
		t.Fatalf("X-Amz-Expires = %q, want %q", got, want)
	}
}

// refusingHTTPClient fails every request, loudly.
type refusingHTTPClient struct{ t *testing.T }

func (c refusingHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.t.Error("the presigner issued an HTTP request")
	return nil, errors.New("no requests are permitted in this test")
}

// TestPresignIssuesNoRequest establishes that the dynamic path's one
// locally-constructed AWS client makes no call.
//
// That claim is why newPresigner is exempt from this package's rule that clients
// arrive from the composition root: there is no retry behaviour, no endpoint call
// and no credential resolution for a caller to configure if nothing is sent. It
// is checked rather than asserted, against the production options.
//
// What it does not cover, stated rather than implied: it drives
// presignOptions plus sts.NewPresignClient, which is what newPresigner is, but it
// is not literally newPresigner -- there is no way to inject a transport through
// that signature. The composition is one line and is shared.
func TestPresignIssuesNoRequest(t *testing.T) {
	t.Parallel()
	opts := presignOptions(testRegion, sessionCredentials{
		accessKeyID:     "fake-access-key-id",
		secretAccessKey: credentials.NewSecret("fake-secret-access-key"),
		sessionToken:    credentials.NewSecret("fake-session-token"),
		expiresAt:       fixedNow.Add(time.Hour),
	})
	opts.HTTPClient = refusingHTTPClient{t: t}
	presigner := sts.NewPresignClient(sts.New(opts))

	out, err := presigner.PresignGetCallerIdentity(context.Background(),
		&sts.GetCallerIdentityInput{}, withExpires(900))
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	if out == nil || out.URL == "" {
		t.Fatal("presign produced no URL")
	}
	if got := mustQuery(t, out.URL).Get("X-Amz-Expires"); got != "900" {
		t.Fatalf("X-Amz-Expires = %q, want 900", got)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}

// TestExpiryComesFromSTSAndNotFromTheRequest is the divergence from the source
// that a reviewer should check hardest.
//
// The source computed both the reported expiry and the signature window from
// time.Now() plus what was asked for. When STS grants less -- which is exactly
// what a role with a lower MaxSessionDuration does -- that reports a credential
// as valid for longer than it is, and signs a URL that outlives the credentials
// signing it.
func TestExpiryComesFromSTSAndNotFromTheRequest(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.p.presign = newPresigner
	h.sts.grantedTTL = 30 * time.Minute // asked for an hour

	res, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExpiresAt == nil {
		t.Fatal("no expiry was reported")
	}
	if want := fixedNow.Add(30 * time.Minute); !res.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", res.ExpiresAt, want)
	}
	if got, want := mustQuery(t, decodeToken(t, res.APIKey).String()).Get("X-Amz-Expires"), "1800"; got != want {
		t.Fatalf("X-Amz-Expires = %q, want %q", got, want)
	}
	// The handle carries the same expiry, so a status check agrees with the
	// record. A handle and a result disagreeing is how a record outlives its
	// credential.
	expiry, err := parseDynamicHandle(res.PlatformKeyID)
	if err != nil {
		t.Fatalf("parse handle: %v", err)
	}
	if !expiry.Equal(*res.ExpiresAt) {
		t.Fatalf("handle expiry %v, result expiry %v", expiry, res.ExpiresAt)
	}
}

func TestASessionThatHasAlreadyExpiredIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.sts.expiresFrom = fixedNow.Add(-2 * time.Hour)
	_, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("want ErrLimit, got %v", err)
	}
	if h.pre.calls != 0 {
		t.Fatal("an expired session was still signed")
	}
}

// TestSTSCredentialFieldsAreAllRequired derives its population from the SDK type
// rather than from a list of field names.
//
// The source read three of the four through aws.ToString, which turns a nil
// pointer into an empty string, so a truncated STS response produced a signer
// configured with empty credentials and the failure arrived later as a signature
// error. Deriving the fields means a field AWS adds is a test failure here rather
// than a gap: the fake cannot omit a name it does not know, so the create
// succeeds and this test fails.
func TestSTSCredentialFieldsAreAllRequired(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(ststypes.Credentials{})
	var fields []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		fields = append(fields, f.Name)
	}
	if len(fields) == 0 {
		t.Fatal("derived no fields from ststypes.Credentials")
	}
	for _, name := range fields {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, fullConfig())
			h.sts.omit = name
			_, err := h.p.CreateCredential(context.Background(), dynamicRequest())
			if !errors.Is(err, errNoCredentials) {
				t.Fatalf("omitting %s: want errNoCredentials, got %v", name, err)
			}
		})
	}
	t.Run("nil credentials", func(t *testing.T) {
		h := newHarness(t, fullConfig())
		h.sts.nilCredentials = true
		_, err := h.p.CreateCredential(context.Background(), dynamicRequest())
		if !errors.Is(err, errNoCredentials) {
			t.Fatalf("want errNoCredentials, got %v", err)
		}
	})
	// The control: with nothing omitted the same harness succeeds, so the test
	// above is distinguishable from one that refuses everything.
	t.Run("nothing omitted", func(t *testing.T) {
		h := newHarness(t, fullConfig())
		if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err != nil {
			t.Fatalf("the complete response was refused: %v", err)
		}
	})
}

// TestWebIdentityAndAssumeRoleDoNotFallBackToEachOther pins the construction
// that replaced the source's preference chain.
//
// The source preferred AssumeRoleWithWebIdentity and fell back to AssumeRole when
// no OIDC provider was wired. The fallback was reachable only from a nil
// provider, so it was already a wiring decision spelled as a runtime branch --
// and a runtime branch is something a later reader can make reachable for a
// different reason. Here the decision is which constructor option was passed, and
// there is no path from either mode to the other.
func TestWebIdentityAndAssumeRoleDoNotFallBackToEachOther(t *testing.T) {
	t.Parallel()

	t.Run("federated, and a failure stays a failure", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, fullConfig()).withFakeTokens("fake-web-identity-token")
		h.sts.fail = func(method string, _ int) error {
			if method == "AssumeRoleWithWebIdentity" {
				return withStatus(http.StatusForbidden, apiError{code: "AccessDenied", fault: smithy.FaultClient})
			}
			return nil
		}
		if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err == nil {
			t.Fatal("want an error")
		}
		for _, c := range h.sts.called() {
			if c == "AssumeRole" {
				t.Fatal("a failed web identity assume fell back to a plain AssumeRole")
			}
		}
	})

	t.Run("not federated, and it never mints a token", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, fullConfig())
		if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err != nil {
			t.Fatalf("create: %v", err)
		}
		for _, c := range h.sts.called() {
			if c == "AssumeRoleWithWebIdentity" {
				t.Fatal("a provider with no token source used web identity federation")
			}
		}
	})

	t.Run("a nil token source is not a token source", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, fullConfig(), WithWebIdentity(nil))
		if h.p.tokens != nil {
			t.Fatal("WithWebIdentity(nil) installed something")
		}
	})
}

func TestATokenSourceFailureIsNotAFallback(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig()).withFakeTokens("")
	h.tok.err = errors.New("the signing key is unavailable: /keys/example-signing-key")

	_, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err == nil {
		t.Fatal("want an error")
	}
	if len(h.sts.called()) != 0 {
		t.Fatalf("STS was called after the token source failed: %v", h.sts.called())
	}
	// The token source is somebody else's implementation, so its diagnostics do
	// not travel: they can name a key path or quote the subject.
	if strings.Contains(err.Error(), "example-signing-key") {
		t.Fatalf("the token source's own error text reached the caller: %v", err)
	}
}

func TestAnEmptyMintedTokenIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig()).withFakeTokens("")
	if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err == nil {
		t.Fatal("an empty web identity token was presented to STS")
	}
	if len(h.sts.called()) != 0 {
		t.Fatalf("STS was called with an empty token: %v", h.sts.called())
	}
}

// TestTheWebIdentitySubjectIsWhateverTheCallerSaid pins the negative.
//
// This provider does not authenticate the requester: it mints a token asserting
// what the platform told it. A trust policy conditioning on the subject is
// therefore trusting the platform's authentication, and the platform's obligation
// is that RequesterType and RequesterID come from an authenticated session and
// never from a request body.
//
// Asserting it rather than documenting it means that if someone later makes this
// provider validate the requester, this test fails and they have to decide
// whether the stronger guarantee is real -- rather than silently inheriting a
// claim nothing checks.
func TestTheWebIdentitySubjectIsWhateverTheCallerSaid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind, id, want string
	}{
		{"user", "someone@example.com", "user:someone@example.com"},
		{"service-account", "deploy-bot", "service-account:deploy-bot"},
		{"user", "a b/c", "user:a-b-c"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, fullConfig()).withFakeTokens("fake-web-identity-token")
			req := dynamicRequest()
			req.RequesterType, req.RequesterID = tc.kind, tc.id
			if _, err := h.p.CreateCredential(context.Background(), req); err != nil {
				t.Fatalf("create: %v", err)
			}
			if len(h.tok.subjects) != 1 || h.tok.subjects[0] != tc.want {
				t.Fatalf("subjects = %v, want [%q]", h.tok.subjects, tc.want)
			}
			if h.tok.audience[0] != stsAudience {
				t.Fatalf("audience = %q, want %q", h.tok.audience[0], stsAudience)
			}
			if h.tok.ttls[0] != webIdentityTokenTTL {
				t.Fatalf("ttl = %v, want %v", h.tok.ttls[0], webIdentityTokenTTL)
			}
			if h.sts.lastWebIdentityToken != "fake-web-identity-token" {
				t.Fatalf("STS was presented %q", h.sts.lastWebIdentityToken)
			}
		})
	}
}

func TestAWebIdentityVendWithNoRequesterTypeIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig()).withFakeTokens("fake-web-identity-token")
	req := dynamicRequest()
	req.RequesterType = ""
	if _, err := h.p.CreateCredential(context.Background(), req); !errors.Is(err, ErrRequesterRequired) {
		t.Fatalf("want ErrRequesterRequired, got %v", err)
	}
	if len(h.tok.subjects) != 0 {
		t.Fatalf("a token was minted anyway, for %v", h.tok.subjects)
	}
}

func TestTheSessionNameIsPrefixedBoundedAndAttributed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	req := dynamicRequest()
	req.RequesterID = "Someone.Else+tag@example.com"
	if _, err := h.p.CreateCredential(context.Background(), req); err != nil {
		t.Fatalf("create: %v", err)
	}
	want := testSessPrefix + "-Someone.Else+tag@example.com"
	if h.sts.lastSessionName != want {
		t.Fatalf("session name = %q, want %q", h.sts.lastSessionName, want)
	}
	if len(h.sts.lastSessionName) > maxRoleSessionName {
		t.Fatalf("session name is %d bytes, over STS's %d", len(h.sts.lastSessionName), maxRoleSessionName)
	}
	if h.sts.lastRoleARN != testRoleARN() {
		t.Fatalf("assumed %q, want the configured role", h.sts.lastRoleARN)
	}
	if h.sts.lastDuration != int32(time.Hour.Seconds()) {
		t.Fatalf("duration = %d, want %d", h.sts.lastDuration, int32(time.Hour.Seconds()))
	}
}

func TestASessionNameTooLongIsRefusedRatherThanTruncated(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	req := dynamicRequest()
	req.RequesterID = strings.Repeat("x", maxRoleSessionName)
	_, err := h.p.CreateCredential(context.Background(), req)
	if !errors.Is(err, ErrNameNotUsable) {
		t.Fatalf("want ErrNameNotUsable, got %v", err)
	}
	if len(h.sts.called()) != 0 {
		t.Fatal("a truncated session name reached STS")
	}
}

func TestAPresignFailureIsReportedRatherThanSwallowed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.pre.err = fmt.Errorf("signing failed for %s", "fake-secret-access-key")
	res, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err == nil {
		t.Fatalf("want an error, got %+v", res)
	}
	if strings.Contains(err.Error(), "fake-secret-access-key") {
		t.Fatalf("the signer's error text reached the caller: %v", err)
	}
}

func TestAPresignerThatProducesNoURLIsAnError(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	h.p.presign = func(string, sessionCredentials) presignAPI { return emptyPresigner{} }
	if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err == nil {
		t.Fatal("an empty presigned URL became a token")
	}
}

type emptyPresigner struct{}

func (emptyPresigner) PresignGetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	return nil, nil
}

// TestTheExpiryMiddlewareRefusesARequestItCannotBound closes the skip path the
// source left open.
//
// The source's middleware returned next.HandleBuild for any request it could not
// type-assert to an HTTP request, so a presign whose expiry could not be set would
// have been emitted unbounded and reported as a success.
//
// This drives the build step directly, because a real presign always produces an
// HTTP request and therefore cannot reach the branch. It was written after a
// mutation that replaced the refusal with next.HandleBuild survived the entire
// suite -- the behavioural checks below are real and they cover the other branch.
func TestTheExpiryMiddlewareRefusesARequestItCannotBound(t *testing.T) {
	t.Parallel()

	reached := false
	next := smithymw.BuildHandlerFunc(func(context.Context, smithymw.BuildInput) (smithymw.BuildOutput, smithymw.Metadata, error) {
		reached = true
		return smithymw.BuildOutput{}, smithymw.Metadata{}, nil
	})

	// Not an HTTP request. The step must refuse rather than pass it along.
	_, _, err := boundExpires(900).HandleBuild(context.Background(),
		smithymw.BuildInput{Request: struct{ NotAnHTTPRequest bool }{}}, next)
	if err == nil {
		t.Fatal("the build step accepted a request it cannot bound")
	}
	if reached {
		t.Fatal("the build step passed an unrecognised request down the stack")
	}

	// The control, so the test above is distinguishable from a step that refuses
	// everything: a real HTTP request is bound and passed along.
	reached = false
	httpReq := smithyhttp.NewStackRequest().(*smithyhttp.Request)
	httpReq.URL = &url.URL{Scheme: "https", Host: "sts." + testRegion + ".amazonaws.com", Path: "/"}
	if _, _, err := boundExpires(1234).HandleBuild(context.Background(),
		smithymw.BuildInput{Request: httpReq}, next); err != nil {
		t.Fatalf("the build step refused a real HTTP request: %v", err)
	}
	if !reached {
		t.Fatal("the build step did not pass a recognised request down the stack")
	}
	if got := httpReq.URL.Query().Get("X-Amz-Expires"); got != "1234" {
		t.Fatalf("X-Amz-Expires = %q, want 1234", got)
	}
}

// TestTheExpiryReachesTheSignedURL is the behavioural half, and it is named
// alongside the structural one above so a later reader does not delete either
// believing the other covers it.
//
// This one sees the value on a real signature and cannot see the refusal; the one
// above sees the refusal and says nothing about a real signature.
func TestTheExpiryReachesTheSignedURL(t *testing.T) {
	t.Parallel()
	h := newHarness(t, fullConfig())
	if _, err := h.p.CreateCredential(context.Background(), dynamicRequest()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if h.pre.optionFuncs != 1 {
		t.Fatalf("the presigner was given %d option functions, want 1", h.pre.optionFuncs)
	}
	h2 := newHarness(t, fullConfig())
	h2.p.presign = newPresigner
	res, err := h2.p.CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if mustQuery(t, decodeToken(t, res.APIKey).String()).Get("X-Amz-Expires") == "" {
		t.Fatal("the signed URL has no expiry")
	}
}

// TestEveryWebIdentityFailureIsTransientAndDistinguishable replaces a test that
// asserted the opposite.
//
// The earlier version was TestAnExpiredWebIdentityTokenIsTransientAndARejectedOne
// IsNot, and its name was the claim: an expired token retryable, a rejected one
// terminal. Review falsified the second half. The SDK's own text for
// InvalidIdentityToken prescribes the retry -- "Get a new identity token from the
// identity provider and then retry the request" -- and IDPRejectedClaim can mean the
// claim expired. Both are fixed by a fresh mint, and this provider mints one per
// attempt.
//
// So all four web identity failures are transient, and the property that remains is
// that each error reaches its OWN sentinel: the three are not collapsed into one,
// and each of the three is reachable.
//
// This test does NOT detect a reordering of the switch cases, and an earlier version
// of this comment said it did. Review falsified that too -- a genuine reorder, each
// case moved with its body, passes this test and the whole suite. It has to: the
// predicates are disjoint, so the order cannot change which case an error reaches.
// TestTheTypedErrorPredicatesAreDisjoint is what establishes that, and it is the
// property the switch actually rests on.
//
// The retraction is recorded here because the claim had two members and only one was
// fixed. It was corrected in dynamic.go and config.go on the pull request that found
// it, and survived in this file -- so the lesson is the one about retractions: when
// you withdraw a claim, grep for it rather than fixing the instance you were shown.
//
// The control runs in the other direction: an error on the same call that is NOT a
// web identity failure must stay terminal, or a classifier that called everything
// on this path transient would pass the whole test.
func TestEveryWebIdentityFailureIsTransientAndDistinguishable(t *testing.T) {
	t.Parallel()
	// The sentinels, once, so the exclusion below is over the whole set rather than
	// over a per-case list somebody has to remember to extend.
	sentinels := []error{
		ErrWebIdentityTokenExpired,
		ErrWebIdentityTokenInvalid,
		ErrWebIdentityClaimRejected,
	}
	cases := []struct {
		name     string
		injected error
		want     int // index into sentinels
	}{
		{"expired", &ststypes.ExpiredTokenException{}, 0},
		{"could not be validated", &ststypes.InvalidIdentityTokenException{}, 1},
		{"claim rejected", &ststypes.IDPRejectedClaimException{}, 2},
	}
	if len(cases) != len(sentinels) {
		t.Fatalf("%d sentinels and %d cases; a sentinel with no case is unasserted",
			len(sentinels), len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := driveWebIdentityFailure(t, tc.injected)
			if !errors.Is(err, credentials.ErrTransient) {
				t.Fatalf("not transient: %v", err)
			}
			if !errors.Is(err, sentinels[tc.want]) {
				t.Fatalf("want %v, got %v", sentinels[tc.want], err)
			}
			// And it must not be reported as one of the OTHER two, which is what a
			// collapsed set of sentinels would do. NOT what a reordered switch would
			// do: the predicates are disjoint, so a reorder changes nothing and this
			// loop cannot see one. Indexed rather than compared: two sentinels are
			// values, and comparing errors with == is the habit errorlint exists to
			// break.
			for i, other := range sentinels {
				if i == tc.want {
					continue
				}
				if errors.Is(err, other) {
					t.Fatalf("also reported as %v; the branches are not distinguishable", other)
				}
			}
		})
	}

	t.Run("the identity provider being unreachable is transient too", func(t *testing.T) {
		t.Parallel()
		err := driveWebIdentityFailure(t, &ststypes.IDPCommunicationErrorException{})
		if !errors.Is(err, credentials.ErrTransient) {
			t.Fatalf("not transient: %v", err)
		}
	})

	// The control. RegionDisabled is on the same call and is a real configuration
	// fault: no number of fresh tokens fixes a region that is switched off.
	t.Run("control: a configuration fault on the same call stays terminal", func(t *testing.T) {
		t.Parallel()
		err := driveWebIdentityFailure(t, &ststypes.RegionDisabledException{})
		if errors.Is(err, credentials.ErrTransient) {
			t.Fatalf("a configuration fault was reported transient: %v", err)
		}
		for _, s := range []error{ErrWebIdentityTokenExpired, ErrWebIdentityTokenInvalid, ErrWebIdentityClaimRejected} {
			if errors.Is(err, s) {
				t.Fatalf("a configuration fault was reported as %v", s)
			}
		}
	})
}

// driveWebIdentityFailure runs one federated vend with err injected at the
// assume-role call and returns what the provider reported.
func driveWebIdentityFailure(t *testing.T, injected error) error {
	t.Helper()
	h := newHarness(t, fullConfig()).withFakeTokens("fake-web-identity-token")
	h.sts.fail = func(method string, _ int) error {
		if method == "AssumeRoleWithWebIdentity" {
			return injected
		}
		return nil
	}
	_, err := h.p.CreateCredential(context.Background(), dynamicRequest())
	if err == nil {
		t.Fatal("the injected failure produced no error")
	}
	return err
}
