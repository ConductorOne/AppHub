// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/internal/awscode"
)

// The SDK adapters are the one layer the conformance suite cannot reach: it
// drives the in-memory substrate, so nothing it does exercises the translation
// from a real AWS error into this package's vocabulary. That translation is
// where the taxonomy is actually decided, and it is checkable without a network
// because an SDK error is a value.
//
// The cases are named as a class rather than as instances: "the exception that
// means absence", "an error the SDK itself calls retryable", and so on, with
// the AWS spellings as the instances of each.

func TestTheSDKErrorTaxonomyReachesTheRightSentinel(t *testing.T) {
	t.Parallel()
	p := &Provider{name: "aws"}
	// A default-retryer classifier, which is what a client built from a default
	// config carries. Per-service, because the not-found and already-exists
	// exceptions are per-service types.
	def := classifier{}
	ecrError := func(err error) error { return def.classify(err, ecrNotFound, ecrExists) }
	iamError := func(err error) error { return def.classify(err, iamNotFound, iamExists) }
	// The adapter's own err rather than classify, because sdkS3 answers one case
	// before classify sees it: see [s3NameTaken].
	s3Error := (&sdkS3{classifier: def}).err

	cases := []struct {
		name    string
		err     error
		classfn func(error) error
		want    error
	}{
		{
			name:    "an ECR repository that does not exist is ErrNotFound",
			err:     &ecrtypes.RepositoryNotFoundException{},
			classfn: ecrError,
			want:    compute.ErrNotFound,
		},
		{
			name:    "a repository with no lifecycle policy is ErrNotFound",
			err:     &ecrtypes.LifecyclePolicyNotFoundException{},
			classfn: ecrError,
			want:    compute.ErrNotFound,
		},
		{
			name:    "an ECR repository that already exists is ErrTransient, not ErrNotOwned",
			err:     &ecrtypes.RepositoryAlreadyExistsException{},
			classfn: ecrError,
			want:    compute.ErrTransient,
		},
		{
			name:    "an IAM entity that does not exist is ErrNotFound",
			err:     &iamtypes.NoSuchEntityException{},
			classfn: iamError,
			want:    compute.ErrNotFound,
		},
		{
			name:    "an IAM entity that already exists is ErrTransient",
			err:     &iamtypes.EntityAlreadyExistsException{},
			classfn: iamError,
			want:    compute.ErrTransient,
		},
		{
			name:    "a throttled ECR call is ErrTransient",
			err:     &smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"},
			classfn: ecrError,
			want:    compute.ErrTransient,
		},
		{
			name:    "a throttled IAM call is ErrTransient",
			err:     &smithy.GenericAPIError{Code: "Throttling", Message: "slow down"},
			classfn: iamError,
			want:    compute.ErrTransient,
		},
		{
			name:    "a service fault is ErrTransient even unwrapped from its HTTP response",
			err:     &ecrtypes.ServerException{},
			classfn: ecrError,
			want:    compute.ErrTransient,
		},
		{
			name:    "an IAM service fault is ErrTransient",
			err:     &iamtypes.ServiceFailureException{},
			classfn: iamError,
			want:    compute.ErrTransient,
		},
		{
			name: "any other server fault is ErrTransient",
			err: &smithy.GenericAPIError{
				Code: "SomeFutureServiceException", Message: "sorry", Fault: smithy.FaultServer,
			},
			classfn: ecrError,
			want:    compute.ErrTransient,
		},
		{
			name: "a client fault is terminal",
			err: &smithy.GenericAPIError{
				Code: "SomeFutureValidationException", Message: "no", Fault: smithy.FaultClient,
			},
			classfn: ecrError,
			want:    compute.ErrFailed,
		},
		{
			// Terminal, but not a resource failure: the credentials this
			// provider runs with lack a permission, and no spec change helps.
			name:    "an authorization failure is not permitted",
			err:     &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no"},
			classfn: ecrError,
			want:    compute.ErrNotPermitted,
		},
		{
			// A 401 lands with the 403. Credential refresh happens below this
			// layer -- the SDK refreshes in the credential provider rather than
			// by retrying, and its standard retryer classifies an expired token
			// as not retryable -- so a call that reaches here with one has
			// already outlived the refresh. See [compute.ErrNotPermitted].
			//
			// The fixture is the SDK's own type and that is the point. An earlier
			// version built a smithy.GenericAPIError spelling "ExpiredToken",
			// which is the string the implementation checked for, so the test
			// could only pass: it asserted that the implementation agreed with
			// the fixture rather than with the SDK. The real type's ErrorCode()
			// is "ExpiredTokenException" and the witness was never covered.
			name:    "an expired credential is not permitted",
			err:     &ststypes.ExpiredTokenException{},
			classfn: func(err error) error { return def.classify(err, nil, nil) },
			want:    compute.ErrNotPermitted,
		},
		{
			// IAM's quota exhaustion is TERMINAL, and its absence from
			// throttleCodes is correct rather than a gap. A round of review was
			// spent "fixing" it: iamtypes.LimitExceededException reports the
			// code "LimitExceeded", which is in neither this package's list nor
			// the SDK's, and adding typed matching for it made a quota error
			// retryable. Pinned in this direction so the next reader does not
			// repeat it, and pinned with the SDK's own type so the pin is about
			// IAM's real witness rather than about a spelling.
			name:    "an IAM quota exhaustion is terminal",
			err:     &iamtypes.LimitExceededException{},
			classfn: func(err error) error { return def.classify(err, nil, nil) },
			want:    compute.ErrFailed,
		},
		{
			// ECR's quota exhaustion is transient, inherited from the SDK's own
			// throttle list, which carries this exact code and not IAM's. The two
			// are pinned side by side because the Go type names are identical and
			// only the codes differ -- which is what made the mistake above
			// available in the first place.
			name:    "an ECR quota exhaustion is transient, as the SDK classifies it",
			err:     &ecrtypes.LimitExceededException{},
			classfn: ecrError,
			want:    compute.ErrTransient,
		},
		{
			// The witness USOSS-63 was raised about, on the error IAM actually
			// sends when it throttles.
			//
			// The ticket's premise was that an IAM throttle reached this package
			// as ErrorCode() == "LimitExceeded", missed a set carrying only ECR's
			// longer spelling, and was reported terminal. The first half is a real
			// fact about a real type and the second half does not follow from it:
			// "LimitExceeded" is what iamtypes.LimitExceededException reports, and
			// that type is a QUOTA exhaustion, pinned terminal directly above.
			//
			// IAM's throttle is a different error entirely, and the SDK models no
			// type for it -- IAM is a query-protocol service, so its throttle
			// arrives as the common wire code "Throttling" with no Go type to
			// match on. That code is in the shared set and always was, in both
			// this package and credentials/aws, so an IAM throttle has been
			// transient throughout. Pinned here because the claim that it was not
			// is what the ticket asked to be resolved, and an answer nothing
			// checks is an answer that stops being true.
			//
			// A GenericAPIError rather than an SDK type is unavoidable and worth
			// flagging, given this file's own warning that a fixture you spelled
			// yourself tests the fixture: there IS no iamtypes throttle to use.
			// The mitigation is that the spelling is not this test's invention --
			// awscode's TestATypeNameIsNotAWireCode reads every iam type the SDK
			// declares and confirms none of them reports it.
			name: "an IAM throttle is transient, and it is not the quota exhaustion above",
			err: &smithy.GenericAPIError{
				Code: "Throttling", Message: "Rate exceeded", Fault: smithy.FaultClient,
			},
			classfn: iamError,
			want:    compute.ErrTransient,
		},
		{
			// The same collision as the IAM/ECR pair, running the other way, on a
			// service this package holds a client for.
			//
			// elbv2's PriorRequestNotCompleteException reports the code
			// "PriorRequestNotComplete", which IS in the shared set, so this is
			// transient -- correctly, since the remedy is to let the previous
			// request finish. Match on the TYPE name, as two reviewers did for
			// IAM, and it is in no set at all and classifies terminal: a caller
			// told its spec has to change while ELBv2 finishes the last call.
			//
			// It is pinned with the SDK's own type because the point is the gap
			// between that type's name and its code, which a hand-spelled fixture
			// would hide.
			name:    "an ELBv2 request that overtook its predecessor is transient",
			err:     &elbv2types.PriorRequestNotCompleteException{},
			classfn: func(err error) error { return def.classify(err, nil, nil) },
			want:    compute.ErrTransient,
		},
		{
			name:    "anything else is terminal",
			err:     &ecrtypes.InvalidParameterException{},
			classfn: ecrError,
			want:    compute.ErrFailed,
		},
		{
			name:    "an error that is not from AWS at all is terminal",
			err:     errors.New("the network is on fire"),
			classfn: ecrError,
			want:    compute.ErrFailed,
		},
		{
			// The bodyless 403, and the reason isAccessDenied grew a status arm.
			//
			// S3's HEAD operations carry no error body, so a HeadBucket refused
			// for authorization reaches this package as a status and nothing
			// else. Every arm of isAccessDenied was a CODE, and a response with
			// no code matched none of them: a denial arrived as
			// compute.ErrFailed, "the resource entered a failed state", for a
			// bucket that is somebody else's and perfectly healthy.
			//
			// This is the witness the code arms structurally cannot see, which is
			// why it is here rather than trusted to the AccessDenied case above.
			name: "a 403 with no error body is a denial",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{StatusCode: http.StatusForbidden},
				},
				Err: errors.New("api error : "),
			},
			classfn: s3Error,
			want:    compute.ErrNotPermitted,
		},
		{
			// The one call S3 answers precisely, and the half of it that used to
			// be a retry loop.
			//
			// BucketAlreadyExists is returned ONLY for a name live in another
			// account -- this account's own bucket is BucketAlreadyOwnedByYou --
			// so it is the definitive report of a namespace collision. It was
			// classified with the race as ErrAlreadyExists and came back
			// compute.ErrTransient: "try again" for a name that will never be
			// free, forever.
			name:    "a bucket name held by another account is not owned",
			err:     &s3types.BucketAlreadyExists{},
			classfn: s3Error,
			want:    compute.ErrNotOwned,
		},
		{
			// The control on the split: the sibling exception keeps the
			// retryable reading it should have. Two reconciles raced, the loser
			// re-reads and adopts. Side by side because collapsing them again is
			// the obvious simplification and this is what it would cost.
			name:    "this account racing its own create is still transient",
			err:     &s3types.BucketAlreadyOwnedByYou{},
			classfn: s3Error,
			want:    compute.ErrTransient,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := p.substrateError(tc.classfn(tc.err))
			if !errors.Is(got, tc.want) {
				t.Errorf("got %v, want it to match %v", got, tc.want)
			}
			// A retryable failure reported as terminal is the mapping mistake
			// that costs a deploy, so it is asserted in both directions.
			if errors.Is(tc.want, compute.ErrTransient) && errors.Is(got, compute.ErrFailed) {
				t.Error("a retryable failure also matches compute.ErrFailed, so a caller " +
					"branching on ErrFailed first gives up on it")
			}
			if errors.Is(tc.want, compute.ErrFailed) && errors.Is(got, compute.ErrTransient) {
				t.Error("a terminal failure also matches compute.ErrTransient, so a caller " +
					"retries something that can never succeed")
			}
		})
	}
}

// TestClassifyDoesNotKeepTheOriginalErrorReachable is INVERTED, not deleted
// (USOSS-76). This used to assert the opposite: that the AWS error stays
// reachable through errors.As so "an operator reading a log gets the
// service's own diagnosis". That was the defect. [ECRAPI] -- like every
// member of [Substrate] -- is an interface a caller can supply an adapter
// for, so the classified error's text is not this package's to show: a
// caller-supplied adapter's message cannot be shown to be free of material,
// exactly as [secretStore.wrap] established for the Parameters port in #19.
// [Provider.substrateError] answers with a fixed, taxonomy-only message and
// drops the chain, so neither errors.As nor errors.Unwrap can recover the
// original AWS error from the mapped one; the classification survives, which
// is what a caller branches on, and the AWS error's OWN text does not.
func TestClassifyDoesNotKeepTheOriginalErrorReachable(t *testing.T) {
	t.Parallel()
	original := &ecrtypes.RepositoryNotFoundException{}
	def := classifier{}
	wrapped := (&Provider{name: "aws"}).substrateError(def.classify(original, ecrNotFound, ecrExists))

	if !errors.Is(wrapped, compute.ErrNotFound) {
		t.Fatalf("the classification did not survive: got %v, want compute.ErrNotFound", wrapped)
	}
	var recovered *ecrtypes.RepositoryNotFoundException
	if errors.As(wrapped, &recovered) {
		t.Error("the AWS error is still reachable through errors.As; a caller-supplied ECRAPI's " +
			"error text must not survive the mapping")
	}
}

// TestASessionPolicyNamesNoPrincipal.
//
// AWS rejects a session policy carrying a Principal, and a provider that
// rendered one would fail every build with a message about policy syntax. The
// two documents this package renders are deliberately different types so the
// field cannot appear in the wrong one; this asserts the outcome, because the
// types could be merged by somebody who did not read why they are not.
func TestASessionPolicyNamesNoPrincipal(t *testing.T) {
	t.Parallel()
	policy, err := pushSessionPolicy([]string{"arn:aws:ecr:" + MemoryRegion + ":" +
		MemoryAccount + ":repository/apphub/app"})
	if err != nil {
		t.Fatalf("pushSessionPolicy: %v", err)
	}
	if want := "Principal"; strings.Contains(policy, want) {
		t.Errorf("the session policy contains %q; AWS rejects a session policy that names one", want)
	}

	trust, err := trustPolicyFor(compute.RuntimeContainer)
	if err != nil {
		t.Fatalf("trustPolicyFor: %v", err)
	}
	if !strings.Contains(trust, "Principal") {
		t.Error("the trust policy names no Principal, so nothing could assume the role")
	}
}

// TestAnEmptyScopeIsRefusedRatherThanWidened.
//
// A session policy with no resources is an empty intersection: every push
// fails, and the obvious fix is a wildcard. Refusing is how that fix never
// becomes tempting.
func TestAnEmptyScopeIsRefusedRatherThanWidened(t *testing.T) {
	t.Parallel()
	if _, err := pushSessionPolicy(nil); err == nil {
		t.Fatal("a session policy was rendered for no repositories")
	} else if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("an empty scope was refused with %v, want compute.ErrInvalidSpec", err)
	}
}

// TestTheSessionDurationCannotBeWidenedPastTheCeiling.
//
// The knob exists because fifteen minutes is a choice rather than a law. The
// ceiling exists because widening least-privilege machinery to make something
// work is the move this project has already had to catch once.
func TestTheSessionDurationCannotBeWidenedPastTheCeiling(t *testing.T) {
	t.Parallel()
	cfg := &BuildConfig{}
	if got := cfg.sessionDuration(); got != DefaultSessionDuration {
		t.Errorf("the default session duration is %s, want %s", got, DefaultSessionDuration)
	}
	cfg.SessionDuration = 99 * MaxSessionDuration
	if got := cfg.sessionDuration(); got != MaxSessionDuration {
		t.Errorf("a session duration of %s was accepted; the ceiling is %s",
			got, MaxSessionDuration)
	}
}

// TestTheSessionPolicyRefusesToOutgrowWhatSTSAccepts.
//
// The policy grows by one repository ARN per destination, and AWS caps an
// inline session policy at 2,048 characters. Without a bound here the failure
// arrives as a validation error about policy syntax from inside a credential
// mint, which is the least useful place to learn that a spec is too big — and
// the obvious way to make it fit is a wildcard resource, which would hand a
// repository-authored build push access to every repository in the account.
//
// The test finds the boundary rather than asserting a magic number, so it stays
// true if the policy's fixed overhead changes.
func TestTheSessionPolicyRefusesToOutgrowWhatSTSAccepts(t *testing.T) {
	t.Parallel()
	arn := func(i int) string {
		return fmt.Sprintf("arn:aws:ecr:%s:%s:repository/apphub/app-%03d", MemoryRegion, MemoryAccount, i)
	}

	limit := 0
	for n := 1; n <= 200; n++ {
		arns := make([]string, 0, n)
		for i := range n {
			arns = append(arns, arn(i))
		}
		policy, err := pushSessionPolicy(arns)
		if err == nil {
			if len(policy) > maxSessionPolicyBytes {
				t.Fatalf("%d repositories rendered a %d-character policy and was accepted; the "+
					"security token service accepts at most %d", n, len(policy), maxSessionPolicyBytes)
			}
			limit = n
			continue
		}
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Fatalf("%d repositories was refused with %v, want compute.ErrInvalidSpec", n, err)
		}
		// The refusal has to be actionable, and has to close off the wrong fix.
		msg := err.Error()
		for _, want := range []string{"destination repositories", "wildcard"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the refusal does not mention %q, so a caller is left to invent a fix "+
					"and the obvious one is the wrong one: %s", want, msg)
			}
		}
		if limit == 0 {
			t.Fatalf("even one repository was refused: %v", err)
		}
		t.Logf("the session policy holds %d repositories and refuses %d", limit, n)
		return
	}
	t.Fatalf("no number of repositories up to 200 was refused; the bound is not being applied")
}

// TestTheExtensionPathIsConfigAndNotTheClientsRetryer.
//
// This provider used to classify through the retryer of the client the error
// came from, so that an operator who extended a client with
// retry.AddWithErrorCodes got the same answer from both. That coupling is gone —
// see [classifier] — and this test pins both halves of what replaced it,
// including the half that costs the caller something.
//
// The cost is asserted deliberately. A documented consequence that no test
// touches is a documented consequence that quietly stops being true, and the one
// here is load-bearing for USOSS-11: extending a client no longer reaches this
// package, and the decision record now says so.
func TestTheExtensionPathIsConfigAndNotTheClientsRetryer(t *testing.T) {
	t.Parallel()
	const extendedCode = "DependencyViolation"
	fixture := &smithy.GenericAPIError{Code: extendedCode, Message: "still attached"}

	cfg := awssdk.Config{Region: MemoryRegion}
	cfg.Retryer = func() awssdk.Retryer {
		return retry.AddWithErrorCodes(retry.NewStandard(), extendedCode)
	}
	client := ecr.NewFromConfig(cfg)

	// The premise: this client really does retry the fixture, and a default one
	// really does not, so the two can disagree.
	if !client.Options().Retryer.IsErrorRetryable(fixture) {
		t.Fatalf("the fixture's client does not consider %q retryable, so this test proves nothing",
			extendedCode)
	}
	if retry.NewStandard().IsErrorRetryable(fixture) {
		t.Fatalf("a default retryer considers %q retryable; the fixture no longer distinguishes "+
			"an extended client from a default one", extendedCode)
	}

	sub := NewSDKSubstrateFrom(SDKClients{ECR: client})
	adapter, ok := sub.ECR.(*sdkECR)
	if !ok {
		t.Fatalf("the substrate's registry adapter is a %T", sub.ECR)
	}
	classified := adapter.classify(fixture, nil, nil)

	// The cost: the extended client is not consulted, so this is terminal.
	if got := (&Provider{name: "aws"}).substrateError(classified); errors.Is(got, compute.ErrTransient) {
		t.Errorf("an extended client reached this provider's classification (%v). Nothing here "+
			"reads a client's retryer any more, so either the coupling is back or "+
			"Config.IsRetryable has stopped being the documented extension path", got)
	}

	// And the remedy: the same widening, expressed on this package's surface.
	widened := &Provider{name: "aws", cfg: Config{IsRetryable: func(err error) bool {
		var api smithy.APIError
		return errors.As(err, &api) && api.ErrorCode() == extendedCode
	}}}
	if got := widened.substrateError(classified); !errors.Is(got, compute.ErrTransient) {
		t.Errorf("Config.IsRetryable did not widen %q to ErrTransient; got %v", extendedCode, got)
	}
}

// TestClassificationDoesNotDependOnHowTheClientIsConfigured.
//
// The property the coupling gave away. A retryer that classifies nothing
// retryable is a real construction — an earlier round built one to defeat a
// guard — and while this package classified through the client's retryer, an
// operator who installed it silently changed this provider's error vocabulary:
// every throttle became terminal, and a caller was told its spec had to change
// when waiting was the whole remedy.
//
// The operator asked for fewer attempts. They did not ask for a different error
// taxonomy. Same error, same answer, whatever the client is configured to do.
func TestClassificationDoesNotDependOnHowTheClientIsConfigured(t *testing.T) {
	t.Parallel()
	fixture := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"}

	never := awssdk.Config{Region: MemoryRegion}
	never.Retryer = func() awssdk.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) { o.Retryables = nil })
	}
	// The premise: the two clients really do disagree about this error.
	if retry.NewStandard(func(o *retry.StandardOptions) { o.Retryables = nil }).IsErrorRetryable(fixture) {
		t.Fatal("the never-retry client considers the fixture retryable; it no longer distinguishes " +
			"anything from a default client")
	}
	if !retry.NewStandard().IsErrorRetryable(fixture) {
		t.Fatal("a default retryer does not consider a ThrottlingException retryable")
	}

	for name, client := range map[string]*ecr.Client{
		"default":     ecr.NewFromConfig(awssdk.Config{Region: MemoryRegion}),
		"never-retry": ecr.NewFromConfig(never),
	} {
		adapter, ok := NewSDKSubstrateFrom(SDKClients{ECR: client}).ECR.(*sdkECR)
		if !ok {
			t.Fatalf("%s: the substrate's registry adapter is not an *sdkECR", name)
		}
		got := (&Provider{name: "aws"}).substrateError(adapter.classify(fixture, nil, nil))
		if !errors.Is(got, compute.ErrTransient) {
			t.Errorf("%s client: a throttle classified as %v, want compute.ErrTransient. A "+
				"client's retry configuration must not be able to change what this provider "+
				"calls a transient failure", name, got)
		}
	}
}

// TestTheRetryHookCanOnlyWiden.
//
// [Config.IsRetryable] is caller-supplied, which is the property that made the
// client's retryer the wrong thing to consult. It is safe here only because of
// the direction: consulted in addition and never instead, it can move a terminal
// error to ErrTransient and can do nothing else. A hook that returns false
// changes nothing, and no hook can reach a denial, a missing resource, or a
// cancelled context.
//
// Widening costs a caller a wasted retry. Narrowing costs it a deploy, and a
// configuration field must not be able to do the second.
func TestTheRetryHookCanOnlyWiden(t *testing.T) {
	t.Parallel()
	always := func(error) bool { return true }
	never := func(error) bool { return false }

	for _, tc := range []struct {
		name string
		err  error
		hook func(error) bool
		want error
	}{
		{"a throttle stays transient when the hook says no", fmt.Errorf("%w: x", ErrThrottled), never, compute.ErrTransient},
		{"a missing resource is not made retryable", fmt.Errorf("%w: x", ErrNoSuchResource), always, compute.ErrNotFound},
		{"a denial is not made retryable", fmt.Errorf("%w: x", ErrDenied), always, compute.ErrNotPermitted},
		{"a cancelled context is not made retryable", context.Canceled, always, context.Canceled},
		{"a terminal error is widened", errors.New("some api error"), always, compute.ErrTransient},
		{"and stays terminal without a hook", errors.New("some api error"), nil, compute.ErrFailed},
	} {
		got := (&Provider{name: "aws", cfg: Config{IsRetryable: tc.hook}}).substrateError(tc.err)
		if !errors.Is(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestASessionDurationTheTokenServiceWouldRejectIsRefused.
//
// The ceiling was checked and the floor was not, so a provider could be built
// with a one-second session duration and would send it. STS's documented minimum
// is fifteen minutes, so every build would fail with a validation error from
// inside a credential mint — the least useful place to learn about a
// configuration mistake.
//
// Refused rather than rounded up, for the same reason a MaxAge ECR cannot
// express is refused: silently issuing a credential that outlives what the
// operator asked for is a decision about a security bound, and it is theirs.
func TestASessionDurationTheTokenServiceWouldRejectIsRefused(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{time.Second, time.Minute, MinSessionDuration - time.Second} {
		cfg := &BuildConfig{SessionDuration: d}
		if err := cfg.validateSessionDuration(); err == nil {
			t.Errorf("a session duration of %s was accepted; the security token service will not "+
				"issue one shorter than %s", d, MinSessionDuration)
		}
	}
	for _, d := range []time.Duration{0, MinSessionDuration, DefaultSessionDuration, MaxSessionDuration} {
		cfg := &BuildConfig{SessionDuration: d}
		if err := cfg.validateSessionDuration(); err != nil {
			t.Errorf("a legal session duration of %s was refused: %v", d, err)
		}
	}
}

// TestAConcurrentReconcileOnOneRoleIsTransient is blocker 6.
//
// IAM's two "somebody else is changing this right now" exceptions are FaultClient
// and appear in none of the SDK's retryable or throttle code lists, so neither
// the client's retryer nor the fault check sees them. They reached the
// classifier's default and came back terminal — telling a caller its spec had to
// change because two of its own deploys overlapped.
//
// Every AWS port in this package creates roles through the shared identity
// service, so this was every port's. Consulting the client's own retryer does not
// close it, which is why the two types are named.
//
// The control is the point of the table: a probe that answered "not retryable"
// to everything would look identical to the defect, so a throttling error is
// asserted alongside them.
func TestAConcurrentReconcileOnOneRoleIsTransient(t *testing.T) {
	t.Parallel()
	p := &Provider{name: "aws"}
	def := classifier{}

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"two reconciles racing on one role", &iamtypes.ConcurrentModificationException{}, compute.ErrTransient},
		{"a role briefly unmodifiable", &iamtypes.EntityTemporarilyUnmodifiableException{}, compute.ErrTransient},
		// The control. Without it a classifier that called everything
		// retryable would pass the two cases above.
		{"a throttle (control: must still be transient)", &smithy.GenericAPIError{Code: "ThrottlingException"}, compute.ErrTransient},
		// The other control. Without it a classifier that called everything
		// retryable would also pass.
		{"a genuine spec error (control: must stay terminal)", &iamtypes.MalformedPolicyDocumentException{}, compute.ErrFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := p.substrateError(def.classify(tc.err, iamNotFound, iamExists))
			if !errors.Is(got, tc.want) {
				t.Errorf("got %v, want it to match %v", got, tc.want)
			}
			if errors.Is(tc.want, compute.ErrTransient) && errors.Is(got, compute.ErrFailed) {
				t.Error("a retryable failure also matches compute.ErrFailed, so a caller " +
					"branching on ErrFailed first abandons a deploy that would have worked")
			}
		})
	}
}

// TestADeleteConflictOnARoleIsTransientNotFailed pins the classification
// DeleteWorkloadIdentity's fix depends on: DeleteRole's DeleteConflictException
// -- raised while a role still carries an inline policy -- has to reach
// compute.ErrTransient, not fall through to the unclassified compute.ErrFailed
// default. Left unmapped, a caller reading ErrFailed is told its spec has to
// change; the true instruction is "remove what's still attached and retry",
// which is exactly what [ErrConflict] means.
//
// This drives [sdkIAM.err] rather than [classifier.classify] directly, because
// the conflict check sits in front of classify the same way [sdkEndpointEC2.err]
// keeps ec2InUse there — a case wired only into the shared classifier would not
// prove the adapter method every real call site uses actually reaches it.
func TestADeleteConflictOnARoleIsTransientNotFailed(t *testing.T) {
	t.Parallel()
	p := &Provider{name: "aws"}
	iamErr := (&sdkIAM{classifier: classifier{}}).err

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"a role with a remaining inline policy", &iamtypes.DeleteConflictException{}, compute.ErrTransient},
		// The control, so a classifier that answered ErrTransient to everything
		// could not pass this test.
		{"a genuine spec error (control: must stay terminal)", &iamtypes.MalformedPolicyDocumentException{}, compute.ErrFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := p.substrateError(iamErr(tc.err))
			if !errors.Is(got, tc.want) {
				t.Errorf("got %v, want it to match %v", got, tc.want)
			}
		})
	}
}

// TestTheThrottleStatusBackstop.
//
// Insurance rather than a live gap: every throttle a port here can receive today
// is already covered by a code the SDK knows. This is for the service that has
// not shipped its code yet, on a path where being wrong costs a deploy.
func TestTheThrottleStatusBackstop(t *testing.T) {
	t.Parallel()
	p := &Provider{name: "aws"}
	def := classifier{}

	unknown := &smithy.GenericAPIError{Code: "SomeFutureServiceQuotaException", Fault: smithy.FaultClient}
	// A client fault with a code nobody enumerated is terminal on its own,
	// which is the premise this backstop exists for.
	if got := p.substrateError(def.classify(unknown, nil, nil)); !errors.Is(got, compute.ErrFailed) {
		t.Fatalf("the premise no longer holds: an unenumerated client fault is %v", got)
	}
	// Under a 429 it is a throttle whatever it is called.
	throttled := &statusError{err: unknown, status: http.StatusTooManyRequests}
	if got := p.substrateError(def.classify(throttled, nil, nil)); !errors.Is(got, compute.ErrTransient) {
		t.Errorf("an HTTP 429 under an unenumerated code classified as %v", got)
	}
	// And a 400 is still terminal, so the backstop is a status test and not a
	// blanket.
	rejected := &statusError{err: unknown, status: http.StatusBadRequest}
	if got := p.substrateError(def.classify(rejected, nil, nil)); !errors.Is(got, compute.ErrFailed) {
		t.Errorf("an HTTP 400 classified as %v", got)
	}
}

// statusError stands in for the transport error the SDK wraps a response in.
type statusError struct {
	err    error
	status int
}

func (e *statusError) Error() string       { return e.err.Error() }
func (e *statusError) Unwrap() error       { return e.err }
func (e *statusError) HTTPStatusCode() int { return e.status }

// TestTheTrustPolicyDecodeDoesNotDependOnStayingEncoded.
//
// IAM returns AssumeRolePolicyDocument URL-encoded and this SDK does not decode
// it, so the adapter does. What that quietly assumed is that the document is
// *always* still encoded — and url.QueryUnescape turns "+" into a space. A "+"
// is legal in an IAM user name and therefore appears in principal ARNs, so
// decoding a document that arrived decoded would corrupt it silently, and the
// trust-policy comparison would then differ on every reconcile and rewrite the
// policy every time.
//
// Both directions are asserted, because the point is that the adapter no longer
// cares which it gets.
func TestTheTrustPolicyDecodeDoesNotDependOnStayingEncoded(t *testing.T) {
	t.Parallel()
	plain := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::acct:user/a+b"},"Action":["sts:AssumeRole"]}]}`

	for name, doc := range map[string]string{
		"encoded, which is what IAM sends today": url.QueryEscape(plain),
		"already decoded, in case that changes":  plain,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := roleRecord(&iamtypes.Role{
				RoleName:                 awssdk.String("app"),
				Arn:                      awssdk.String("arn:aws:iam::acct:role/app"),
				AssumeRolePolicyDocument: awssdk.String(doc),
			})
			if rec.AssumeRolePolicy != plain {
				t.Errorf("the adapter produced\n %s\nwant\n %s", rec.AssumeRolePolicy, plain)
			}
			if strings.Contains(rec.AssumeRolePolicy, "a b") {
				t.Error("a plus in a principal ARN became a space, so every reconcile would see " +
					"a different policy and rewrite it")
			}
		})
	}
}

// TestTwoDifferentTrustPoliciesNeverCanonicaliseTheSame.
//
// samePolicyDocument is what decides whether a trust policy has been widened, so
// a collision in it is blocker 2's class exactly: two different documents seen
// as equal means Ensure leaves a widened policy — a wildcard principal, an extra
// service, an added condition — in place and reports success.
//
// The suspicious part is canonicalValue's handling of lists: it renders each
// item to JSON and sorts the strings, so a list of strings and a string that
// *looks like* a rendered list are one substitution apart. Those pairs are here
// deliberately, along with the two shapes that must compare EQUAL because AWS
// treats them as the same document.
//
// Stated as pairs with an expected verdict rather than as "these are different",
// because a canonicaliser that returned a constant would pass a test that only
// checked inequality, and one that returned its input would pass a test that
// only checked equality. Both directions or neither.
func TestTwoDifferentTrustPoliciesNeverCanonicaliseTheSame(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{
			name:  "a scalar and a one-element list, which AWS treats as the same",
			a:     `{"Statement":[{"Action":"sts:AssumeRole"}]}`,
			b:     `{"Statement":[{"Action":["sts:AssumeRole"]}]}`,
			equal: true,
		},
		{
			name:  "statement order, which carries no meaning",
			a:     `{"Statement":[{"Action":"a"},{"Action":"b"}]}`,
			b:     `{"Statement":[{"Action":"b"},{"Action":"a"}]}`,
			equal: true,
		},
		{
			name:  "a list of strings against a string spelled like the rendered list",
			a:     `{"X":["a"]}`,
			b:     `{"X":"[\"a\"]"}`,
			equal: false,
		},
		{
			name:  "a nested list against a flat one holding its rendering",
			a:     `{"X":[["a"]]}`,
			b:     `{"X":["[\"a\"]"]}`,
			equal: false,
		},
		{
			name:  "a duplicated statement against a single one",
			a:     `{"Statement":[{"Action":"a"},{"Action":"a"}]}`,
			b:     `{"Statement":[{"Action":"a"}]}`,
			equal: false,
		},
		{
			name:  "a number against its decimal string",
			a:     `{"X":1}`,
			b:     `{"X":"1"}`,
			equal: false,
		},
		{
			name:  "a condition added, which this package does not model",
			a:     `{"Statement":[{"Action":"a"}]}`,
			b:     `{"Statement":[{"Action":"a","Condition":{"StringEquals":{"k":"v"}}}]}`,
			equal: false,
		},
		{
			name:  "a wildcard principal added beside the expected one",
			a:     `{"Statement":[{"Principal":{"Service":"ecs-tasks.amazonaws.com"}}]}`,
			b:     `{"Statement":[{"Principal":{"Service":"ecs-tasks.amazonaws.com","AWS":"*"}}]}`,
			equal: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			same, err := samePolicyDocument(tc.a, tc.b)
			if err != nil {
				t.Fatalf("samePolicyDocument: %v", err)
			}
			switch {
			case tc.equal && !same:
				t.Errorf("these compare as different and AWS treats them as the same document, "+
					"so every reconcile would rewrite an unchanged policy:\n  %s\n  %s", tc.a, tc.b)
			case !tc.equal && same:
				t.Errorf("COLLISION: two different documents canonicalise the same, so a widened "+
					"trust policy would be seen as unchanged and left in place:\n  %s\n  %s",
					tc.a, tc.b)
			}
		})
	}
}

// TestBothSubstrateSeamsRefuseAnUnfilteredSecurityGroupSearch exercises **both**
// implementations of the same refusal.
//
// The external test asserting "the two seams agree" called only the in-memory one,
// so disabling the SDK adapter's refusal left it green. That is the
// fake-versus-real class *inside* the fix for the fake-versus-real class: a test
// named for an agreement, trusting one side of it.
//
// The SDK side is reachable without credentials or network because the refusal is
// evaluated before any request is composed — which is itself worth pinning, since a
// guard that only fires after a round trip is a guard the caller pays for.
func TestBothSubstrateSeamsRefuseAnUnfilteredSecurityGroupSearch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// A client with no credentials and an endpoint that resolves nowhere. If the
	// refusal ever moves after the request is composed, this stops being a
	// refusal and starts being a network error, and the assertion below notices.
	client := ec2.New(ec2.Options{Region: MemoryRegion})

	for _, tc := range []struct {
		seam string
		api  EndpointEC2API
	}{
		{"in-memory", NewMemoryEndpointEC2()},
		{"sdk", &sdkEndpointEC2{c: client}},
	} {
		t.Run(tc.seam, func(t *testing.T) {
			t.Parallel()
			for _, tags := range []map[string]string{nil, {}} {
				_, err := tc.api.FindSecurityGroups(ctx, tags)
				if err == nil {
					t.Fatalf("%s: an unfiltered security group search was accepted. Unfiltered "+
						"means every group in the region, and the two seams must agree on "+
						"refusing it or whichever one a test happens to drive is the one that "+
						"gets tested", tc.seam)
				}
				if !errors.Is(err, compute.ErrInvalidSpec) {
					t.Errorf("%s: the refusal was %v; the seams must agree on the sentinel as "+
						"well as on refusing, or a caller cannot branch on it uniformly",
						tc.seam, err)
				}
			}
		})
	}
}

// TestTheSharedRetryableSetIsLoadBearingHere asserts that this package's classifier
// actually honours every code in [awscode.RetryableCodes].
//
// USOSS-63 replaced a throttleCodes map declared in this package with a shared
// declaration two packages away, and a shared declaration nothing here checks is
// worse than the duplicate it replaced: the duplicate was at least visible in the
// file whose behaviour it decided. This is the check that makes the shared set
// this package's business again -- delete a code from it, or stop consulting it,
// and this goes red.
//
// The fault is FaultClient deliberately. A server fault classifies transient on
// its own through [isServerFault], so a fixture carrying one would pass whether
// the code arm worked or not, and the whole population would be decoration.
func TestTheSharedRetryableSetIsLoadBearingHere(t *testing.T) {
	t.Parallel()

	codes := awscode.RetryableCodes()
	if len(codes) == 0 {
		t.Fatal("the shared set is empty; every assertion below would hold vacuously")
	}
	def := classifier{}
	p := &Provider{name: "aws"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			err := &smithy.GenericAPIError{Code: code, Message: "slow down", Fault: smithy.FaultClient}
			got := p.substrateError(def.classify(err, nil, nil))
			if !errors.Is(got, compute.ErrTransient) {
				t.Errorf("%s is in the shared retryable set and classifies as %v; a throttle "+
					"reported terminal tells a caller to give up when waiting was the remedy",
					code, got)
			}
			if errors.Is(got, compute.ErrFailed) {
				t.Errorf("%s also matches compute.ErrFailed, so a caller branching on it first "+
					"gives up", code)
			}
		})
	}

	// The control, in the other direction. Without it a classifier that answered
	// ErrTransient to everything would pass every assertion above.
	const notInTheSet = "SomeFutureValidationException"
	if awscode.IsRetryable(notInTheSet) {
		t.Fatalf("%s is in the shared set; this control no longer controls anything", notInTheSet)
	}
	control := &smithy.GenericAPIError{Code: notInTheSet, Message: "no", Fault: smithy.FaultClient}
	if got := p.substrateError(def.classify(control, nil, nil)); errors.Is(got, compute.ErrTransient) {
		t.Errorf("a code that is not in the shared set classified as transient: %v", got)
	}
}
