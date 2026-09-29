// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lambdaapi "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	s3tablestypes "github.com/aws/aws-sdk-go-v2/service/s3tables/types"
	"github.com/aws/aws-sdk-go-v2/service/s3vectors"
	s3vectorstypes "github.com/aws/aws-sdk-go-v2/service/s3vectors/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/awscode"
)

// The SDK adapter files are the only package files that import AWS SDK clients;
// TestOnlyTheAdapterFilesImportAnAWSSDK enforces that boundary. Port decisions
// above Substrate are identical against an account and against memory.

// NewSDKSubstrate wires the real clients.
//
// Clients are supplied for callers that already own their AWS configuration.
// Hosted composition uses NewFromConfig to load ambient operator credentials
// inside this provider boundary. A nil client disables its capability; New
// reports a mismatch when configuration enables a missing client.
//
// # Retry configuration is the composition root's, and this package does not touch it
//
// It tried to, four times, and the attempt is worth recording because the
// failure is structural rather than a run of bad luck.
//
// First as a guard, in four versions, each defeated by a different part of the
// retryer: an attempt budget that is a name for a budget; correct classification
// with a token bucket behind it; counting real attempts, which **spent the
// certified client's retry quota** — after fifty probes a client could make one
// attempt instead of three; and overriding the delay to make that probe fast,
// which changed the object being measured.
//
// Then as ownership: install this package's retryer and there is nothing left to
// guard. That lasted one round. `Options.RetryMaxAttempts` is re-applied *over*
// an installed retryer, so owning the retryer was not owning the behaviour — and
// then `APIOptions` survives the rebuild and runs after the SDK installs its
// retry middleware, so a caller can remove the middleware by ID and reduce every
// client to one attempt. That is a third disable path, and the fourth is
// whatever the SDK adds next.
//
// The lesson, and it is the same one the guards taught one level up:
// **owning a behaviour inside somebody else's extensible object is enumerating
// its disable paths.** The set is not closed, and it is not ours to close.
//
// So retry configuration belongs to whoever builds the clients, and the
// consequence is documented rather than defended:
//
//	A caller who disables retry on these clients gets a provider that does not
//	retry on their behalf, and makes one attempt instead of the SDK's default
//	three.
//
// That is the only thing disabling retry changes. It does not change how the
// one attempt this package does make is classified: throttling errors are
// still reported as [compute.ErrTransient], never terminal, because
// classification no longer asks the client anything — see the reversal below.
// A caller who wants fewer attempts still gets told to try again on a
// throttle; it is simply the caller, and not the SDK, doing the retrying.
//
// That is visible and diagnosable. It is also strictly better than what the
// ownership machinery produced, which was this package causing the same outcome
// by its own means.
//
// The same reversal has since taken the other half. Classification used to be
// derived from the client's own retryer — asking it whether an error was
// retryable — which looked exempt because it read the configuration rather
// than trying to own it. It was not exempt: a client's retryer is a
// caller-supplied function, so a client's retry configuration silently became
// this provider's error taxonomy, and a client configured never to retry made
// every throttle terminal. [classifier] now classifies from a fixed function of
// the error itself — a throttle code, an HTTP status, a server fault, and a
// short list of other signals, all reached with errors.As regardless of what
// any client is configured to do — and a caller who needs to widen this
// provider's idea of a transient failure says so through [Config.IsRetryable],
// on this package's own surface, never through the client.
func NewSDKSubstrate(
	ecrClient *ecr.Client,
	iamClient *iam.Client,
	stsClient *sts.Client,
	lambdaClient *lambdaapi.Client,
	elbClient *elbv2.Client,
	ec2Client *ec2.Client,
) *Substrate {
	// Delegates rather than duplicating the wiring. [SDKClients] is the shape
	// the other ports extend — a field per service, so that tickets adding a
	// client each do not have to change one signature — and two constructors
	// each doing their own wiring is how one of them silently stops attaching a
	// client's classifier.
	return NewSDKSubstrateFrom(SDKClients{
		ECR: ecrClient, IAM: iamClient, STS: stsClient,
		Lambda: lambdaClient, ELBv2: elbClient, EndpointEC2: ec2Client,
	})
}

// --- error classification ---------------------------------------------------------

// classifier answers "would this have worked if you tried again", from signals
// this package owns.
//
// # Three positions, and why the second looked like the answer
//
// A hand-maintained list of throttling codes drifts from the SDK's, in the
// direction that turns a retryable failure into one a caller is told to give up
// on. So the answer was derived from the SDK instead — first from a separately
// constructed default retryer, which disagreed with the client the error came
// from the moment an operator extended one, and then from *that client's own*
// retryer, which made the decision to retry and the decision to report the
// exhaustion retryable the same function.
//
// The second position looked exempt from the lesson that had just deleted the
// retry ownership above, because it read the caller's configuration rather than
// trying to own it. It was not exempt, and the reason is one line:
//
//	IsErrorRetryable is a caller-supplied function, so a client's configuration
//	silently became this provider's error taxonomy.
//
// A retryer that classifies nothing retryable is a real construction — review
// built one, in an earlier round, to defeat a guard that had asked the retryer
// for its attempt budget and not its opinion. Against a client configured that
// way, every throttle this package saw became [compute.ErrFailed]: a caller told
// its spec has to change when waiting was the whole remedy. The operator who
// turned retry down asked for fewer attempts. They did not ask for a different
// error vocabulary, and the coupling gave them one anyway.
//
// So it is the same failure as the two above it — **a construction built on a
// surface we do not own** — and it is the third on this branch. What changes is
// only which part of the surface: not the number of ways to disable a behaviour,
// but the fact that somebody else's function was answering a question this
// package's callers ask it.
//
// What this classifies from instead is a fixed function of the error: every
// signal below is reached with errors.As through whatever chain it arrives in,
// and each is an OR, so they can only move an error from terminal to retryable.
// The same error now gets the same answer whatever the clients were configured
// to do.
//
// The cost is real and is stated rather than hidden: **nothing in this package
// can see an AddWithErrorCodes on a client any more.** A caller who has extended
// the SDK's retryable codes — which is exactly what the decision record asks
// USOSS-11 to do for the EC2 teardown path — must also say so here, through
// [Config.IsRetryable]. That is a hook on this package's own surface, consulted
// in addition and never instead, which is the composition property USOSS-13
// argued for.
type classifier struct{}

// classify maps an AWS error onto this package's substrate vocabulary.
//
// notFound and alreadyExists are passed in because the two exceptions that mean
// them are per-service types; everything else is common.
func (c classifier) classify(err error, notFound, alreadyExists func(error) bool) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller asked to stop, and several signals below would otherwise
		// claim it: a context deadline reports Timeout() true. Returned as
		// itself so [Provider.substrateError] can keep its promise not to answer
		// "try again" to an instruction to stop.
		return err
	case notFound != nil && notFound(err):
		return fmt.Errorf("%w: %w", ErrNoSuchResource, err)
	case alreadyExists != nil && alreadyExists(err):
		return fmt.Errorf("%w: %w", ErrAlreadyExists, err)
	case isAccessDenied(err):
		return fmt.Errorf("%w: %w", ErrDenied, err)
	case isThrottleCode(err) || isServerFault(err) || isConsistencyRace(err) ||
		isThrottleStatus(err) || isTransportFailure(err):
		return fmt.Errorf("%w: %w", ErrThrottled, err)
	default:
		return err
	}
}

// isThrottleCode matches a throttling error code by name.
//
// This is the hand-maintained list the two retryer positions above existed to
// avoid, and it is back because the thing it was traded for turned out to depend
// on somebody else's wrapping. The trade is now explicit rather than assumed:
//
//   - The drift risk is real and in the dangerous direction. A throttling code
//     AWS ships after this list was written is classified terminal, and a caller
//     is told to change its spec when waiting would have worked.
//   - Three things bound it. Most throttles are also an HTTP 429 or a 5xx, which
//     [isThrottleStatus] and [isServerFault] catch without knowing any code; the
//     set is the SDK's own, so it is checkable against the SDK rather than
//     invented; and [Config.IsRetryable] lets an operator who meets a new one
//     close it without waiting for this package.
//
// # The list itself now lives in internal/awscode, and that is the third bound
//
// It used to be a throttleCodes map in this file, and credentials/aws held a
// character-for-character identical retryableCodes map in its own. Neither
// package could see the other, so "the two agree" was a coincidence rather than
// an invariant -- and the coincidence was already asymmetric: credentials/aws
// cross-checked its copy against retry.DefaultThrottleErrorCodes and
// retry.DefaultRetryableErrorCodes, and THIS copy was checked against nothing at
// all. The only way the two could drift was therefore the bad way round: a code
// the SDK added would have failed credentials/aws's test and silently gone
// missing here, which is precisely the "throttle classified terminal" failure the
// bullet above says the list must not be allowed to produce.
//
// [awscode.IsRetryable] is now the one declaration, credentials/aws's
// cross-check covers it, and the drift has nowhere left to happen. USOSS-63.
//
// # One entry is kept despite a tension worth naming
//
// "LimitExceededException" is ECR's *code* for a quota exhaustion, and no amount
// of retrying fixes one. It stays because the SDK's own throttle list contains
// that exact code, so this is the behaviour every previous round of this package
// had; changing it is a judgement about somebody's account and belongs in its own
// ticket.
//
// IAM is not the service in question, and its absence is correct rather than a
// gap. IAM's identically-named Go type *iamtypes.LimitExceededException reports
// the code "LimitExceeded", which is in neither the shared set nor the SDK's, so
// an IAM quota exhaustion is terminal -- the right answer for a quota, and the
// answer the SDK gives.
//
// An earlier comment here said IAM spelled it "LimitExceededException". That is
// the Go TYPE name rather than the code, and reading it as the code produced a
// "fix": typed matching for the IAM type, which made an IAM quota exhaustion
// retryable and diverged from the SDK in the dangerous direction, on exactly the
// judgement the paragraph above defers. Reverted. credentials/aws then inherited
// the same wrong sentence and re-derived the same reversal a ticket later.
//
// **The thing that looks like the identifier is not the identifier**, and a
// comment giving the wrong reason beside a correct classifier is how the next
// reader re-derives the bug. That is now a test rather than this paragraph:
// awscode's TestATypeNameIsNotAWireCode enumerates every SDK error type whose Go
// name and wire code disagree about membership of the set, across every service
// this module depends on and in both directions. IAM's is one of the two. The
// other is elbv2's PriorRequestNotCompleteException, whose code
// "PriorRequestNotComplete" IS in the set -- a trap running the opposite way,
// live in this package, that no reviewer had spotted because every argument about
// this bug had been about IAM.
func isThrottleCode(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	return awscode.IsRetryable(api.ErrorCode())
}

// isTransportFailure reports a connection that failed rather than a service that
// answered.
//
// The case: the request never got an answer — a reset connection, a dial
// failure, a read timeout. The SDK retries these internally, so this classifies
// what is left after it gave up, and giving up is a property of the client's
// configuration rather than of the error. Terminal is the wrong answer for a
// deploy: nothing about the caller's spec would change the outcome.
//
// Both interfaces rather than the concrete net types, for the same reason
// [isThrottleStatus] takes that shape: the concrete list goes stale, and
// errors.As finds either through any wrapper. Context cancellation reaches
// Timeout() true as well, which is why [classifier.classify] answers that first.
func isTransportFailure(err error) bool {
	var conn interface{ ConnectionError() bool }
	if errors.As(err, &conn) && conn.ConnectionError() {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// The signals, and why none folds into another.
//
// Each closes a case the others structurally cannot, and each is an `OR`, so
// they can only move an error from terminal to retryable. The reverse — a caller
// told its spec has to change when a retry would have worked — is the direction
// that costs a deploy, and nothing here can produce it.
//
// The simplification a later reader will reach for is deleting one because "the
// retryer covers it". It does not, and the case each is for is recorded on it.

// isServerFault reports whether the service blamed itself.
//
// The case: a typed exception arriving **without its transport wrapper**. The
// SDK's classifiers reach most 5xx responses through the HTTP status on the
// error that wraps them, so a bare ecrtypes.ServerException — or, as another
// port found, s3tablestypes.InternalServerErrorException — carries the fault and
// not the status and is classified terminal. A server fault is retryable by
// definition.
//
// Complementary to the code set rather than covered by it: a service that blames
// itself has said so in the fault whatever it called the code.
func isServerFault(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorFault() == smithy.FaultServer
}

// isConsistencyRace reports one of IAM's two "somebody else is changing this
// right now" exceptions.
//
// The case: **two concurrent reconciles touching one role**. Neither exception
// is in the SDK's throttle or retryable code lists, and both are FaultClient, so
// neither the retryer nor the fault check sees them. Verified with a probe that
// used a throttling error as a control, so a probe answering false to everything
// would have been visible:
//
//	ConcurrentModificationException          retryer=false serverFault=false
//	EntityTemporarilyUnmodifiableException   retryer=false serverFault=false
//	ThrottlingException (control)            retryer=true  serverFault=false
//
// They therefore reached the classifier's default, and a caller was told its
// spec had to change because two of its own deploys overlapped. This is the race
// the source system handles explicitly (bucket.go:799-816), and every AWS port
// here creates roles through the shared identity service, so all of them
// inherit it.
//
// Naming the two types is unavoidable: no code set, status or fault reaches
// them, and the SDK's own retryer did not know them either.
func isConsistencyRace(err error) bool {
	return isType[*iamtypes.ConcurrentModificationException](err) ||
		isType[*iamtypes.EntityTemporarilyUnmodifiableException](err)
}

// isThrottleStatus reports an HTTP 429 whatever the service called it.
//
// The case: a throttling code that is not in the shared set [isThrottleCode]
// reads. This is insurance
// rather than a live gap, and it is worth saying so rather than overstating it —
// every throttle a port in this package can currently receive is already
// covered, because s3tables and s3vectors spell theirs TooManyRequestsException,
// which is in the SDK's throttle list, and S3 uses SlowDown with a 503. Three
// lines on a path where being wrong costs a deploy.
//
// The interface rather than the concrete type, because both the AWS transport
// error and the smithy one implement it and enumerating them is the kind of list
// that goes stale.
func isThrottleStatus(err error) bool {
	var status interface{ HTTPStatusCode() int }
	return errors.As(err, &status) && status.HTTPStatusCode() == http.StatusTooManyRequests
}

// isAccessDenied matches the shape of an authorization failure rather than an
// enumeration of codes.
//
// It changes no outcome on its own — an authorization failure is terminal
// either way — and exists so the error a caller reads says which of the two
// terminal things happened. That the taxonomy cannot express "your platform's
// own IAM policy is what has to change" is a gap in [compute], tracked as
// USOSS-40, not something this function can close.
func isAccessDenied(err error) bool {
	// The typed exceptions first, because where the SDK ships a type, matching
	// its error-code *string* is a hand-maintained restatement of somebody
	// else's vocabulary -- and this function had exactly that defect. It checked
	// for "ExpiredToken"; the type is *ststypes.ExpiredTokenException and its
	// ErrorCode() is "ExpiredTokenException", so the real witness never matched
	// and an expired credential mapped to ErrFailed. sdkSTS.AssumeRole reaches
	// this path, so that was live.
	//
	// The test that was supposed to cover it built a smithy.GenericAPIError
	// carrying the spelling this function checked for, so it could only ever
	// pass: a fixture you spelled yourself tests the fixture. The pinning
	// fixtures are now the SDK's own types.
	if isType[*ststypes.ExpiredTokenException](err) {
		return true
	}
	// The bodyless 403, before the code check, because there is no code to check.
	//
	// Symmetric with [s3NotFound]'s bare 404 arm and there for the same reason:
	// S3's HEAD operations carry no error body, so a HeadBucket on a name another
	// account holds arrives as a status and nothing else. Without this arm nothing
	// bodyless could reach [ErrDenied] at all, and that collision -- the one
	// [ObjectStoreConfig.NamePrefix] exists for -- fell through to the default and
	// was reported as [compute.ErrFailed]: "the resource entered a failed state",
	// for a bucket that is somebody else's and perfectly healthy.
	//
	// Widening rather than narrowing, like every other signal in this file: it can
	// only move an error out of the terminal default into a more specific terminal
	// answer, and 403 has no second meaning in any service this package talks to.
	if isForbiddenStatus(err) {
		return true
	}
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	code := api.ErrorCode()
	// These four are genuine wire-level codes with no typed exception in any
	// service this package talks to -- checked against sts, iam and ecr's
	// errors.go, where none of them appears. A string is the only available
	// recogniser, and the producer is named so the enumeration can be rechecked:
	//
	//   AccessDenied*         every service, on an IAM authorization failure
	//   Unauthorized*         ECR's registry auth, and API Gateway fronted calls
	//   InvalidClientTokenId  STS and the SigV4 signer, on a bad access key
	//   ExpiredToken          the *wire* spelling some services use where STS
	//                         uses the typed exception above; retained because
	//                         it costs nothing, and it does NOT cover the STS
	//                         witness, which is what the type check is for
	return strings.HasPrefix(code, "AccessDenied") ||
		strings.HasPrefix(code, "Unauthorized") ||
		code == "InvalidClientTokenId" ||
		code == "ExpiredToken"
}

// isForbiddenStatus reports an HTTP 403 whatever the service called it, or did
// not call it: [isAccessDenied]'s code arms cannot see a response with no body.
//
// The interface rather than the concrete type, for the reason [isThrottleStatus]
// takes that shape: both the AWS transport error and the smithy one implement it,
// and enumerating them is the kind of list that goes stale.
func isForbiddenStatus(err error) bool {
	var status interface{ HTTPStatusCode() int }
	return errors.As(err, &status) && status.HTTPStatusCode() == http.StatusForbidden
}

func isType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// --- ECR ----------------------------------------------------------------------------

type sdkECR struct {
	c *ecr.Client
	classifier
}

var _ ECRAPI = (*sdkECR)(nil)

func ecrNotFound(err error) bool {
	return isType[*ecrtypes.RepositoryNotFoundException](err) ||
		isType[*ecrtypes.ImageNotFoundException](err) ||
		isType[*ecrtypes.LifecyclePolicyNotFoundException](err)
}

func ecrExists(err error) bool {
	return isType[*ecrtypes.RepositoryAlreadyExistsException](err)
}

func (s *sdkECR) err(err error) error { return s.classify(err, ecrNotFound, ecrExists) }

func (s *sdkECR) DescribeImage(ctx context.Context, repository, tag, digest string) (string, error) {
	id := ecrtypes.ImageIdentifier{}
	switch {
	case tag != "" && digest == "":
		id.ImageTag = awssdk.String(tag)
	case digest != "" && tag == "":
		id.ImageDigest = awssdk.String(digest)
	default:
		return "", fmt.Errorf("aws: DescribeImage needs a tag or a digest, not both and not neither")
	}
	out, err := s.c.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: awssdk.String(repository),
		ImageIds:       []ecrtypes.ImageIdentifier{id},
	})
	if err != nil {
		return "", s.err(err)
	}
	if len(out.ImageDetails) == 0 || out.ImageDetails[0].ImageDigest == nil {
		return "", fmt.Errorf("%w: image in %q", ErrNoSuchResource, repository)
	}
	return awssdk.ToString(out.ImageDetails[0].ImageDigest), nil
}

func (s *sdkECR) DescribeRepository(ctx context.Context, name string) (*RepositoryRecord, error) {
	out, err := s.c.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{name},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.Repositories) == 0 {
		// The API reports absence as an exception, so an empty list is a shape
		// the service does not produce. It is mapped rather than indexed into,
		// because a panic here would be a provider crash on a caller's read.
		return nil, fmt.Errorf("%w: repository %q", ErrNoSuchResource, name)
	}
	return repositoryRecord(&out.Repositories[0]), nil
}

func (s *sdkECR) CreateRepository(ctx context.Context, name string, scanOnPush, immutableTags bool, tags map[string]string) (*RepositoryRecord, error) {
	mutability := ecrtypes.ImageTagMutabilityMutable
	if immutableTags {
		mutability = ecrtypes.ImageTagMutabilityImmutable
	}
	out, err := s.c.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:             awssdk.String(name),
		ImageTagMutability:         mutability,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: scanOnPush},
		Tags:                       ecrTags(tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return repositoryRecord(out.Repository), nil
}

func (s *sdkECR) DeleteRepository(ctx context.Context, name string) error {
	// Force, because the port's contract is "removes a repository and its
	// images". Without it a repository that has ever been pushed to cannot be
	// deleted, and a teardown would leave the thing it was asked to remove.
	_, err := s.c.DeleteRepository(ctx, &ecr.DeleteRepositoryInput{
		RepositoryName: awssdk.String(name),
		Force:          true,
	})
	return s.err(err)
}

func (s *sdkECR) PutImageScanningConfiguration(ctx context.Context, name string, scanOnPush bool) error {
	_, err := s.c.PutImageScanningConfiguration(ctx, &ecr.PutImageScanningConfigurationInput{
		RepositoryName:             awssdk.String(name),
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: scanOnPush},
	})
	return s.err(err)
}

func (s *sdkECR) PutImageTagMutability(ctx context.Context, name string, immutableTags bool) error {
	mutability := ecrtypes.ImageTagMutabilityMutable
	if immutableTags {
		mutability = ecrtypes.ImageTagMutabilityImmutable
	}
	_, err := s.c.PutImageTagMutability(ctx, &ecr.PutImageTagMutabilityInput{
		RepositoryName:     awssdk.String(name),
		ImageTagMutability: mutability,
	})
	return s.err(err)
}

func (s *sdkECR) GetLifecyclePolicy(ctx context.Context, name string) (string, error) {
	out, err := s.c.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: awssdk.String(name),
	})
	if err != nil {
		return "", s.err(err)
	}
	return awssdk.ToString(out.LifecyclePolicyText), nil
}

func (s *sdkECR) PutLifecyclePolicy(ctx context.Context, name, policy string) error {
	_, err := s.c.PutLifecyclePolicy(ctx, &ecr.PutLifecyclePolicyInput{
		RepositoryName:      awssdk.String(name),
		LifecyclePolicyText: awssdk.String(policy),
	})
	return s.err(err)
}

func (s *sdkECR) DeleteLifecyclePolicy(ctx context.Context, name string) error {
	_, err := s.c.DeleteLifecyclePolicy(ctx, &ecr.DeleteLifecyclePolicyInput{
		RepositoryName: awssdk.String(name),
	})
	return s.err(err)
}

func (s *sdkECR) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{
		ResourceArn: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	tags := make(map[string]string, len(out.Tags))
	for _, t := range out.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags, nil
}

func (s *sdkECR) TagResource(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.TagResource(ctx, &ecr.TagResourceInput{
		ResourceArn: awssdk.String(arn),
		Tags:        ecrTags(tags),
	})
	return s.err(err)
}

func (s *sdkECR) UntagResource(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.UntagResource(ctx, &ecr.UntagResourceInput{
		ResourceArn: awssdk.String(arn),
		TagKeys:     keys,
	})
	return s.err(err)
}

func repositoryRecord(r *ecrtypes.Repository) *RepositoryRecord {
	if r == nil {
		return &RepositoryRecord{}
	}
	rec := &RepositoryRecord{
		Name:          awssdk.ToString(r.RepositoryName),
		ARN:           awssdk.ToString(r.RepositoryArn),
		URI:           awssdk.ToString(r.RepositoryUri),
		ImmutableTags: r.ImageTagMutability == ecrtypes.ImageTagMutabilityImmutable,
	}
	if r.ImageScanningConfiguration != nil {
		rec.ScanOnPush = r.ImageScanningConfiguration.ScanOnPush
	}
	return rec
}

func ecrTags(tags map[string]string) []ecrtypes.Tag {
	out := make([]ecrtypes.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, ecrtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// --- IAM ----------------------------------------------------------------------------

type sdkIAM struct {
	c *iam.Client
	classifier
}

var _ IAMAPI = (*sdkIAM)(nil)

func iamNotFound(err error) bool { return isType[*iamtypes.NoSuchEntityException](err) }
func iamExists(err error) bool   { return isType[*iamtypes.EntityAlreadyExistsException](err) }

// iamDeleteConflict reports DeleteRole's "this role still has something
// attached" exception.
//
// Handled here rather than folded into [classifier.classify], the same way
// [sdkEndpointEC2.err] keeps ec2InUse out of the shared path: it is an IAM-shaped
// fact -- DeleteConflictException is FaultClient and carries no code in the
// throttle or retryable sets, so unhandled it reaches the classifier's default
// and comes back terminal. [identityService.DeleteWorkloadIdentity] removes a
// role's inline policies before calling DeleteRole, so the ordinary case never
// raises this; it stays mapped in case something else is still attached (an
// unrelated caller's PutRolePolicy racing the delete, or a future managed-policy
// attachment), and [ErrConflict] is [compute.ErrTransient], not
// [compute.ErrFailed]: a caller told to change its spec over a dependency that
// clears on its own would abandon a teardown that a retry finishes.
func iamDeleteConflict(err error) bool { return isType[*iamtypes.DeleteConflictException](err) }

func (s *sdkIAM) err(err error) error {
	if iamDeleteConflict(err) {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return s.classify(err, iamNotFound, iamExists)
}

func (s *sdkIAM) GetRole(ctx context.Context, name string) (*RoleRecord, error) {
	out, err := s.c.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(name)})
	if err != nil {
		return nil, s.err(err)
	}
	return roleRecord(out.Role), nil
}

func (s *sdkIAM) CreateRole(ctx context.Context, in CreateRoleRequest) (*RoleRecord, error) {
	input := &iam.CreateRoleInput{
		RoleName:                 awssdk.String(in.Name),
		AssumeRolePolicyDocument: awssdk.String(in.AssumeRolePolicy),
		Tags:                     iamTags(in.Tags),
	}
	if in.Path != "" {
		input.Path = awssdk.String(in.Path)
	}
	if in.PermissionsBoundary != "" {
		input.PermissionsBoundary = awssdk.String(in.PermissionsBoundary)
	}
	out, err := s.c.CreateRole(ctx, input)
	if err != nil {
		return nil, s.err(err)
	}
	return roleRecord(out.Role), nil
}

func (s *sdkIAM) UpdateAssumeRolePolicy(ctx context.Context, name, policy string) error {
	_, err := s.c.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       awssdk.String(name),
		PolicyDocument: awssdk.String(policy),
	})
	return s.err(err)
}

func (s *sdkIAM) DeleteRole(ctx context.Context, name string) error {
	_, err := s.c.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: awssdk.String(name)})
	return s.err(err)
}

func (s *sdkIAM) TagRole(ctx context.Context, name string, tags map[string]string) error {
	_, err := s.c.TagRole(ctx, &iam.TagRoleInput{
		RoleName: awssdk.String(name),
		Tags:     iamTags(tags),
	})
	return s.err(err)
}

func (s *sdkIAM) UntagRole(ctx context.Context, name string, keys []string) error {
	_, err := s.c.UntagRole(ctx, &iam.UntagRoleInput{
		RoleName: awssdk.String(name),
		TagKeys:  keys,
	})
	return s.err(err)
}

func roleRecord(r *iamtypes.Role) *RoleRecord {
	if r == nil {
		return &RoleRecord{}
	}
	rec := &RoleRecord{
		Name: awssdk.ToString(r.RoleName),
		ARN:  awssdk.ToString(r.Arn),
		Tags: make(map[string]string, len(r.Tags)),
	}
	for _, t := range r.Tags {
		rec.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	// IAM returns a trust policy URL-encoded. Decoding it here rather than at
	// the reader is what keeps everything above [Substrate] free of a detail
	// that belongs to one API: an undecoded document parses as nothing, and a
	// provider comparing against one would rewrite the policy on every call.
	//
	// The decode is conditional on the document not already being JSON, and that
	// is not defensive clutter. url.QueryUnescape turns "+" into a space, and
	// "+" is legal in an IAM user name and therefore appears in principal ARNs —
	// so decoding a document that arrived decoded silently corrupts it. Today
	// this SDK does hand it back encoded; the condition costs one call and
	// removes a dependency on that staying true.
	if doc := awssdk.ToString(r.AssumeRolePolicyDocument); doc != "" {
		rec.AssumeRolePolicy = doc
		if !json.Valid([]byte(doc)) {
			if decoded, err := url.QueryUnescape(doc); err == nil {
				rec.AssumeRolePolicy = decoded
			}
		}
	}
	return rec
}

func iamTags(tags map[string]string) []iamtypes.Tag {
	out := make([]iamtypes.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, iamtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// --- STS ----------------------------------------------------------------------------

type sdkSTS struct {
	c *sts.Client
	classifier
}

var _ STSAPI = (*sdkSTS)(nil)

func (s *sdkSTS) AssumeRole(ctx context.Context, in AssumeRoleRequest) (PushCredentials, error) {
	// The duration is already bounded by BuildConfig.sessionDuration, and the
	// bound is restated here rather than assumed: this adapter is reachable
	// from anything that builds an AssumeRoleRequest, and a duration that
	// overflowed the field would silently become a different number of seconds.
	seconds := in.Duration / time.Second
	if seconds < 0 || seconds > MaxSessionDuration/time.Second {
		return PushCredentials{}, fmt.Errorf(
			"aws: a push credential was requested for %s, which is outside the range this "+
				"provider will ask for (up to %s)", in.Duration, MaxSessionDuration)
	}
	out, err := s.c.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         awssdk.String(in.RoleARN),
		RoleSessionName: awssdk.String(in.SessionName),
		Policy:          awssdk.String(in.Policy),
		DurationSeconds: awssdk.Int32(int32(seconds)),
	})
	if err != nil {
		return PushCredentials{}, s.classify(err, nil, nil)
	}
	if out.Credentials == nil {
		return PushCredentials{}, errors.New("aws: the security token service returned no credentials")
	}
	// The three fields cross into [credentials.Secret] here and are never
	// strings again until [withCredentials].
	return PushCredentials{
		AccessKeyID:     credentials.NewSecret(awssdk.ToString(out.Credentials.AccessKeyId)),
		SecretAccessKey: credentials.NewSecret(awssdk.ToString(out.Credentials.SecretAccessKey)),
		SessionToken:    credentials.NewSecret(awssdk.ToString(out.Credentials.SessionToken)),
		Expires:         awssdk.ToTime(out.Credentials.Expiration),
	}, nil
}

// --- object storage ---------------------------------------------------------

type sdkS3 struct {
	classifier
	c *s3.Client
}

// s3NotFound recognises the several ways S3 says a bucket is not there.
//
// Several, because the answer depends on the call: HeadBucket returns a bare 404
// with no typed body, GetBucketTagging returns NoSuchTagSet for a bucket that
// exists with no tags, and the typed NoSuchBucket only appears on some
// operations. Collapsing "no tag set" into "no such bucket" would be the source
// system's fail-open in reverse -- an untagged bucket would read as absent and an
// Ensure would try to create one that already exists.
func s3NotFound(err error) bool {
	if isType[*s3types.NoSuchBucket](err) || isType[*s3types.NotFound](err) {
		return true
	}
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	return false
}

// s3Exists is THIS account's create losing a race with itself.
//
// BucketAlreadyOwnedByYou and nothing else. BucketAlreadyExists used to be here
// too, and the two are opposites: one says the loser can adopt on the next pass,
// the other says the name is in another account and never will be free. Mapping
// both to [ErrAlreadyExists] made the second [compute.ErrTransient] -- "try
// again" for a bucket name nobody in this account can ever have.
func s3Exists(err error) bool {
	return isType[*s3types.BucketAlreadyOwnedByYou](err)
}

// s3NameTaken is the one place S3 answers the question a HEAD cannot.
//
// BucketAlreadyExists is returned only when the name is live in ANOTHER account:
// this account's own bucket comes back as BucketAlreadyOwnedByYou. So a create is
// how a namespace collision is discovered definitively, and [ErrNameTaken] is how
// it is reported. See [S3API.HeadBucket] for why the HEAD is not.
func s3NameTaken(err error) bool {
	return isType[*s3types.BucketAlreadyExists](err)
}

func (s *sdkS3) err(err error) error {
	// Before classify, because classify has three slots and this is a fourth
	// answer -- and because a collision must not fall through to the
	// already-exists slot, which is the retryable one.
	if s3NameTaken(err) {
		return fmt.Errorf("%w: %w", ErrNameTaken, err)
	}
	return s.classify(err, s3NotFound, s3Exists)
}

func (s *sdkS3) HeadBucket(ctx context.Context, name string) error {
	_, err := s.c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: awssdk.String(name)})
	return s.err(err)
}

func (s *sdkS3) CreateBucket(ctx context.Context, name, region string) error {
	in := &s3.CreateBucketInput{Bucket: awssdk.String(name)}
	// us-east-1 is the one region that must NOT be sent as a location
	// constraint: S3 rejects the request if it is. Every other region requires
	// it. This is the API's asymmetry, not a choice.
	if region != "us-east-1" {
		in.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(region),
		}
	}
	_, err := s.c.CreateBucket(ctx, in)
	return s.err(err)
}

func (s *sdkS3) DeleteBucket(ctx context.Context, name string) error {
	_, err := s.c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: awssdk.String(name)})
	return s.err(err)
}

func (s *sdkS3) IsEmpty(ctx context.Context, name string) (bool, error) {
	// One key is enough to answer the question, and asking for one rather than
	// the default thousand keeps the call cheap on a bucket with many objects.
	out, err := s.c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  awssdk.String(name),
		MaxKeys: awssdk.Int32(1),
	})
	if err != nil {
		return false, s.err(err)
	}
	return awssdk.ToInt32(out.KeyCount) == 0, nil
}

func (s *sdkS3) ListObjectVersions(ctx context.Context, name string) ([]ObjectVersion, error) {
	out, err := s.c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket:  awssdk.String(name),
		MaxKeys: awssdk.Int32(s3MaxKeys),
	})
	if err != nil {
		return nil, s.err(err)
	}
	versions := make([]ObjectVersion, 0, len(out.Versions)+len(out.DeleteMarkers))
	for _, v := range out.Versions {
		versions = append(versions, ObjectVersion{
			Key: awssdk.ToString(v.Key), VersionID: awssdk.ToString(v.VersionId),
		})
	}
	for _, m := range out.DeleteMarkers {
		versions = append(versions, ObjectVersion{
			Key: awssdk.ToString(m.Key), VersionID: awssdk.ToString(m.VersionId),
		})
	}
	return versions, nil
}

func (s *sdkS3) DeleteObjectVersions(ctx context.Context, name string, versions []ObjectVersion) error {
	if len(versions) > s3MaxKeys {
		return fmt.Errorf("%w: %d versions in one batch delete, and S3 accepts at most %d",
			ErrMalformed, len(versions), s3MaxKeys)
	}
	if len(versions) == 0 {
		return nil
	}
	ids := make([]s3types.ObjectIdentifier, 0, len(versions))
	for _, v := range versions {
		ids = append(ids, s3types.ObjectIdentifier{
			Key: awssdk.String(v.Key), VersionId: awssdk.String(v.VersionID),
		})
	}
	// Quiet, so the body carries only the failures: the successes are the
	// caller's own request echoed back, and a thousand of them say nothing.
	out, err := s.c.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: awssdk.String(name),
		Delete: &s3types.Delete{Objects: ids, Quiet: awssdk.Bool(true)},
	})
	if err != nil {
		return s.err(err)
	}
	if len(out.Errors) == 0 {
		return nil
	}
	// The per-key refusals arrive in a 200 OK body, not as an error the SDK
	// returns, so they are classified here the same way a request-level error
	// would be: the code carries the throttle or the denial, and a batch that
	// fails for SlowDown is as transient as a request that did.
	first := out.Errors[0]
	return fmt.Errorf("%d of %d versions in the batch were not deleted, the first %q version %q: %w",
		len(out.Errors), len(versions), awssdk.ToString(first.Key), awssdk.ToString(first.VersionId),
		s.err(&smithy.GenericAPIError{
			Code: awssdk.ToString(first.Code), Message: awssdk.ToString(first.Message),
		}))
}

func (s *sdkS3) GetBucketLocation(ctx context.Context, name string) (string, error) {
	out, err := s.c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(name)})
	if err != nil {
		return "", s.err(err)
	}
	// S3 reports us-east-1 as an empty constraint, for the same historical
	// reason CreateBucket refuses to be told it.
	if out.LocationConstraint == "" {
		return "us-east-1", nil
	}
	return string(out.LocationConstraint), nil
}

func (s *sdkS3) PutPublicAccessBlock(ctx context.Context, name string) error {
	_, err := s.c.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: awssdk.String(name),
		// All four. Three of four is not blocked: BlockPublicPolicy stops a new
		// public policy while IgnorePublicAcls is what neutralises one already
		// attached, and the source system sets all four for that reason
		// (bucket.go:245-253).
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       awssdk.Bool(true),
			IgnorePublicAcls:      awssdk.Bool(true),
			BlockPublicPolicy:     awssdk.Bool(true),
			RestrictPublicBuckets: awssdk.Bool(true),
		},
	})
	return s.err(err)
}

func (s *sdkS3) GetPublicAccessBlock(ctx context.Context, name string) (bool, error) {
	out, err := s.c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: awssdk.String(name),
	})
	if err != nil {
		if s3NoSuchConfiguration(err) {
			// No configuration at all means nothing is blocked, which is a
			// legitimate state to report rather than an error.
			return false, nil
		}
		return false, s.err(err)
	}
	c := out.PublicAccessBlockConfiguration
	if c == nil {
		return false, nil
	}
	// All four, for the reason PutPublicAccessBlock sets all four.
	return awssdk.ToBool(c.BlockPublicAcls) && awssdk.ToBool(c.IgnorePublicAcls) &&
		awssdk.ToBool(c.BlockPublicPolicy) && awssdk.ToBool(c.RestrictPublicBuckets), nil
}

func (s *sdkS3) PutBucketEncryption(ctx context.Context, name, algorithm string) error {
	_, err := s.c.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: awssdk.String(name),
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryption(algorithm),
				},
			}},
		},
	})
	return s.err(err)
}

func (s *sdkS3) GetBucketEncryption(ctx context.Context, name string) (string, error) {
	out, err := s.c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: awssdk.String(name),
	})
	if err != nil {
		if s3NoSuchConfiguration(err) {
			return "", nil
		}
		return "", s.err(err)
	}
	if out.ServerSideEncryptionConfiguration == nil {
		return "", nil
	}
	for _, r := range out.ServerSideEncryptionConfiguration.Rules {
		if r.ApplyServerSideEncryptionByDefault != nil {
			return string(r.ApplyServerSideEncryptionByDefault.SSEAlgorithm), nil
		}
	}
	return "", nil
}

func (s *sdkS3) GetBucketTagging(ctx context.Context, name string) (map[string]string, error) {
	out, err := s.c.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: awssdk.String(name)})
	if err != nil {
		if s3NoSuchTagSet(err) {
			// A bucket with no tags. Emphatically not a missing bucket: see
			// s3NotFound for why conflating the two inverts an Ensure.
			return map[string]string{}, nil
		}
		return nil, s.err(err)
	}
	tags := make(map[string]string, len(out.TagSet))
	for _, t := range out.TagSet {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags, nil
}

func (s *sdkS3) PutBucketTagging(ctx context.Context, name string, tags map[string]string) error {
	set := make([]s3types.Tag, 0, len(tags))
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		set = append(set, s3types.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	_, err := s.c.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket:  awssdk.String(name),
		Tagging: &s3types.Tagging{TagSet: set},
	})
	return s.err(err)
}

// s3NoSuchTagSet and s3NoSuchConfiguration match the by-code errors S3 uses for
// "this bucket has no such configuration", which have no typed shapes.
//
// Matched by code rather than by type because the SDK models neither: they arrive
// as smithy.GenericAPIError. That is a hand-maintained pair of strings, which is
// the drift risk the classifier's own comment discusses -- and the direction is
// safe here. A code that stops matching turns a "no configuration" answer into a
// terminal error, which fails closed and loudly rather than reporting a bucket as
// hardened when it is not.
//
//	NoSuchTagSet                                  GetBucketTagging, on a bucket
//	                                              with no tag set at all
//	NoSuchPublicAccessBlockConfiguration          GetPublicAccessBlock
//	ServerSideEncryptionConfigurationNotFoundError GetBucketEncryption
//
// Each producer is named so the enumeration can be re-checked against the API
// rather than trusted.
func s3NoSuchTagSet(err error) bool { return apiErrorCode(err) == "NoSuchTagSet" }

func s3NoSuchConfiguration(err error) bool {
	switch apiErrorCode(err) {
	case "NoSuchPublicAccessBlockConfiguration", "ServerSideEncryptionConfigurationNotFoundError":
		return true
	default:
		return false
	}
}

// apiErrorCode returns an AWS error's code, or "".
func apiErrorCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

type sdkS3Tables struct {
	classifier
	c *s3tables.Client
}

func (s *sdkS3Tables) err(err error) error {
	return s.classify(err,
		func(e error) bool { return isType[*s3tablestypes.NotFoundException](e) },
		func(e error) bool { return isType[*s3tablestypes.ConflictException](e) })
}

func (s *sdkS3Tables) GetTableBucket(ctx context.Context, name string) (*TableBucketRecord, error) {
	// s3tables addresses a bucket by ARN, and the only way to turn a name into
	// one is to list. A caller-composed ARN would need the account identifier
	// this package deliberately does not hold.
	var token *string
	for {
		out, err := s.c.ListTableBuckets(ctx, &s3tables.ListTableBucketsInput{ContinuationToken: token})
		if err != nil {
			return nil, s.err(err)
		}
		for _, b := range out.TableBuckets {
			if awssdk.ToString(b.Name) != name {
				continue
			}
			arn := awssdk.ToString(b.Arn)
			tags, terr := s.tags(ctx, arn)
			if terr != nil {
				return nil, terr
			}
			return &TableBucketRecord{Name: name, ARN: arn, Tags: tags}, nil
		}
		if out.ContinuationToken == nil || awssdk.ToString(out.ContinuationToken) == "" {
			return nil, fmt.Errorf("%w: table bucket %q", ErrNoSuchResource, name)
		}
		token = out.ContinuationToken
	}
}

func (s *sdkS3Tables) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTagsForResource(ctx, &s3tables.ListTagsForResourceInput{
		ResourceArn: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return out.Tags, nil
}

// CreateTableBucket creates a table bucket WITH its tags, in one call.
//
// The tags go in the create request because the API accepts them there. An
// earlier version created the bucket and then called TagResource, which opened a
// window in which the bucket existed carrying no ownership marker -- and an
// untagged bucket is refused by every subsequent reconcile as ErrNotOwned,
// because it is indistinguishable from one this platform did not create. A
// failure in that window stranded the resource permanently.
//
// Splitting an operation the substrate offers atomically is the avoidable half of
// that defect. S3 proper has no such option, which is why [sdkS3.CreateBucket]
// and objectStore.EnsureBucket have to carry a rollback instead; here the atomic
// call exists and is used.
func (s *sdkS3Tables) CreateTableBucket(ctx context.Context, name string, tags map[string]string) (*TableBucketRecord, error) {
	out, err := s.c.CreateTableBucket(ctx, &s3tables.CreateTableBucketInput{
		Name: awssdk.String(name),
		Tags: tags,
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &TableBucketRecord{Name: name, ARN: awssdk.ToString(out.Arn), Tags: copyTags(tags)}, nil
}

func (s *sdkS3Tables) DeleteTableBucket(ctx context.Context, arn string) error {
	_, err := s.c.DeleteTableBucket(ctx, &s3tables.DeleteTableBucketInput{
		TableBucketARN: awssdk.String(arn),
	})
	return s.err(err)
}

type sdkS3Vectors struct {
	classifier
	c *s3vectors.Client
}

func (s *sdkS3Vectors) err(err error) error {
	return s.classify(err,
		func(e error) bool { return isType[*s3vectorstypes.NotFoundException](e) },
		func(e error) bool { return isType[*s3vectorstypes.ConflictException](e) })
}

func (s *sdkS3Vectors) GetVectorBucket(ctx context.Context, name string) (*VectorBucketRecord, error) {
	out, err := s.c.GetVectorBucket(ctx, &s3vectors.GetVectorBucketInput{
		VectorBucketName: awssdk.String(name),
	})
	if err != nil {
		return nil, s.err(err)
	}
	tags, err := s.c.ListTagsForResource(ctx, &s3vectors.ListTagsForResourceInput{
		ResourceArn: out.VectorBucket.VectorBucketArn,
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &VectorBucketRecord{Name: name, ARN: awssdk.ToString(out.VectorBucket.VectorBucketArn), Tags: tags.Tags}, nil
}

// CreateVectorBucket creates a vector bucket WITH its tags, in one call.
//
// Same reasoning as [sdkS3Tables.CreateTableBucket]: the API takes Tags in the
// create request, so there is no window in which the bucket exists unmarked. The
// ARN is read back afterwards because s3vectors does not return one from the
// create -- a read, not a mutation, so a failure there leaves nothing stranded and
// the caller retries into an idempotent Ensure.
func (s *sdkS3Vectors) CreateVectorBucket(ctx context.Context, name string, tags map[string]string) (*VectorBucketRecord, error) {
	if _, err := s.c.CreateVectorBucket(ctx, &s3vectors.CreateVectorBucketInput{
		VectorBucketName: awssdk.String(name),
		Tags:             tags,
	}); err != nil {
		return nil, s.err(err)
	}
	got, err := s.c.GetVectorBucket(ctx, &s3vectors.GetVectorBucketInput{
		VectorBucketName: awssdk.String(name),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &VectorBucketRecord{Name: name, ARN: awssdk.ToString(got.VectorBucket.VectorBucketArn), Tags: copyTags(tags)}, nil
}

func (s *sdkS3Vectors) DeleteVectorBucket(ctx context.Context, name string) error {
	_, err := s.c.DeleteVectorBucket(ctx, &s3vectors.DeleteVectorBucketInput{
		VectorBucketName: awssdk.String(name),
	})
	return s.err(err)
}

var (
	_ S3API        = (*sdkS3)(nil)
	_ S3TablesAPI  = (*sdkS3Tables)(nil)
	_ S3VectorsAPI = (*sdkS3Vectors)(nil)
)
