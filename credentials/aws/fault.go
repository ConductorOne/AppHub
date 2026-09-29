// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/awscode"
)

// op names an AWS operation this package performs, for an error message.
//
// It is a defined unexported type for the reason internal/credhttp.Op is: it is
// the only detail that reaches an error alongside a status code, and a type
// nobody outside this package can construct makes "nothing built from a response
// or from a caller's input is passed here" a property of the type rather than a
// rule this comment asks the next author to remember.
type op string

const (
	opAssumeRole            op = "assuming the configured role"
	opAssumeRoleWebIdentity op = "assuming the configured role with a web identity"
	//nolint:gosec // G101 reads this constant's value as a hardcoded credential; it
	// is a clause in an error message, and the op type cannot be constructed outside
	// this package so no op value ever reaches AWS or a credential field.
	opWebIdentityToken     op = "minting a web identity token"
	opPresign              op = "presigning the Bedrock token request"
	opCreateUser           op = "creating the IAM user"
	opReadUserTags         op = "reading the IAM user's tags"
	opAttachPolicy         op = "attaching the configured policy"
	opDetachPolicy         op = "detaching a policy"
	opListAttachedPolicies op = "listing the user's attached policies"
	opListInlinePolicies   op = "listing the user's inline policies"
	opDeleteInlinePolicy   op = "deleting an inline policy"
	opListAccessKeys       op = "listing the user's access keys"
	opDeleteAccessKey      op = "deleting an access key"
	opCreateServiceCred    op = "creating the Bedrock service credential"
	opListServiceCreds     op = "listing the user's Bedrock service credentials"
	//nolint:gosec // G101, same reason as opWebIdentityToken above: this is prose.
	opDeleteServiceCred op = "deleting a Bedrock service credential"
	opDeleteUser        op = "deleting the IAM user"
)

// wrap turns an AWS failure into an error this package is willing to return.
//
// It carries the operation and an HTTP status code and nothing else, and the
// omission is deliberate rather than lazy. An AWS error message is text this
// process did not write: it echoes request parameters back -- an IAM user name,
// an ARN, a path -- and this package's sibling providers settled the same
// tradeoff the same way after a leak test rejected the alternative
// (credentials/datadog/datadog.go:444-458). The status code is a number, the
// operation is a constant here, and an operator who needs the service's own
// diagnostic reads it from CloudTrail, where it already is.
//
// Retryable failures are marked with credentials.ErrTransient so the reconciler
// can tell "come back later" from "this will never work".
func wrap(o op, err error) error {
	if err == nil {
		return nil
	}
	// A cancelled context is the caller asking to stop, and several signals below
	// would otherwise claim it as transient -- a deadline reports Timeout() true.
	// Returning it as itself keeps this function from answering "try again" to an
	// instruction to stop.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("aws: %s was stopped: %w", o, err)
	}
	if status, ok := httpStatus(err); ok {
		if isTransient(err) {
			return fmt.Errorf("aws: %s failed (%d): %w", o, status, credentials.ErrTransient)
		}
		return fmt.Errorf("aws: %s failed (%d)", o, status)
	}
	if isTransient(err) {
		return fmt.Errorf("aws: %s failed: %w", o, credentials.ErrTransient)
	}
	return fmt.Errorf("aws: %s failed", o)
}

// httpStatus recovers the status code the service answered with, if it answered.
//
// The interface is matched rather than the SDK's concrete transport error type:
// smithy wraps a response error per protocol, and every one of them carries this
// method. errors.As on an interface pointer finds whichever it is.
func httpStatus(err error) (int, bool) {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode(), true
	}
	return 0, false
}

// isTransient reports whether waiting could plausibly change the answer.
//
// Every signal is an OR and every one is a fixed function of the error, so the
// same error gets the same answer whatever the clients were configured to do.
// That is not a style choice: compute/aws/awssdk.go:95-141 records deriving this
// from the client's own retryer and finding that a caller-supplied
// IsErrorRetryable had silently become the provider's error taxonomy.
func isTransient(err error) bool {
	if status, ok := httpStatus(err); ok {
		if status == http.StatusTooManyRequests || status >= 500 {
			return true
		}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		if api.ErrorFault() == smithy.FaultServer {
			return true
		}
		if awscode.IsRetryable(api.ErrorCode()) {
			return true
		}
	}
	if isConsistencyRace(err) || isWebIdentityRetryable(err) {
		return true
	}
	// A request that never got an answer: a reset connection, a dial failure, a
	// read timeout. The SDK retries these itself, so what reaches here is what it
	// gave up on -- and giving up is a property of the client's configuration
	// rather than of the error. Nothing about the caller's request would change
	// the outcome, so terminal is the wrong answer.
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		if _, isAPI := httpStatus(err); !isAPI && !errors.As(err, &api) {
			return true
		}
	}
	return false
}

// isTransient's code arm reads the one shared retryable set, in internal/awscode.
//
// It used to read a retryableCodes map declared right here, and compute/aws held
// a character-for-character identical throttleCodes map in its own file. The
// comment that stood here said so, and said converging them was the right end
// state and not that pull request's to make. This is that convergence; USOSS-63.
//
// The asymmetry it removes is worth stating, because "two identical maps" makes
// the duplication sound harmless. Only this copy was cross-checked against
// retry.DefaultThrottleErrorCodes and retry.DefaultRetryableErrorCodes;
// compute/aws's was checked against nothing. So the two could only drift in the
// direction where a code AWS adds fails a test HERE and silently goes missing
// THERE -- a throttle classified terminal, which tells a caller to give up when
// waiting was the whole remedy. TestRetryableCodesMatchTheSDK now runs that
// cross-check against the shared set, so it covers both providers.
//
// # What that set is, precisely, because the first version of this comment was wrong
//
// It is the SDK's set of wire codes, and not the set of codes an IAM or STS client
// can return. Those are different, and the difference is worth stating rather than
// implying:
//
//   - Several entries are dead for these two clients. Neither IAM nor STS declares
//     an error reporting BandwidthLimitExceeded, EC2ThrottledException, SlowDown or
//     PriorRequestNotComplete.
//   - "LimitExceededException" is one of them, and the first version of this
//     comment said it was "how IAM spells a quota exhaustion". That is false. IAM's
//     LimitExceededException type reports the wire code "LimitExceeded"; the longer
//     string is the Go type name. The claim was inherited verbatim from
//     compute/aws, which was wrong in the same way -- and that inheritance is the
//     clearest argument for this ticket having converged the two: one wrong
//     sentence, copied, cost a review round in each package.
//
// Keeping the SDK's set anyway is deliberate: it is checkable against the SDK, so
// it cannot drift from it, and matching the SDK's own classification means a
// caller gets the same answer from this package that the client would have given
// itself. What it must not be read as is a list of what these services return.
//
// The type-name-is-not-the-code confusion behind both review rounds is now a test
// rather than a paragraph: awscode's TestATypeNameIsNotAWireCode enumerates every
// SDK error type whose Go name and wire code disagree about membership of the
// set, in both directions, across every AWS service this module depends on.
//
// TestEveryDeclaredSDKErrorIsClassified is the population that covers the gap this
// set structurally cannot: every error type iam and sts declare, each with a
// decided classification. It is what found isConsistencyRace missing.

// isConsistencyRace reports one of IAM's two "somebody else is changing this
// right now" exceptions.
//
// The case is two concurrent reconciles touching one IAM user: the lifecycle
// layer retries revokes, so two passes can overlap on the same user, and every
// mutating call in the static path can meet one of these.
//
// Neither is in the SDK's throttle or retryable code lists and both are
// FaultClient, so neither the code set nor the fault check sees them. Probed
// directly, with a throttle as the control so a probe answering false to
// everything would have been visible:
//
//	ConcurrentModification            fault=client inRetryableCodes=false isTransient=false
//	EntityTemporarilyUnmodifiable     fault=client inRetryableCodes=false isTransient=false
//	ThrottlingException (control)     fault=client inRetryableCodes=true  isTransient=true
//
// This is compute/aws/awssdk.go:280-292's finding rather than a new one, and the
// reason it had to be found twice is worth recording: that file was read while
// writing this one, and the reading stopped at the throttle-code list. Knowledge
// that is written down and does not cross a package boundary is the failure this
// repository has already paid for once.
//
// Matched with errors.As on the typed error rather than on the error code, which
// is not a style choice. IAM's wire codes are not its Go type names --
// ConcurrentModificationException reports "ConcurrentModification" -- so a
// code-string match here would be a second spelling of one grammar, which is
// exactly how a code accepted by one call site is rejected by another.
func isConsistencyRace(err error) bool {
	var cme *iamtypes.ConcurrentModificationException
	if errors.As(err, &cme) {
		return true
	}
	var etu *iamtypes.EntityTemporarilyUnmodifiableException
	return errors.As(err, &etu)
}

// isNoSuchEntity reports IAM saying the thing is not there.
//
// errors.As rather than a message match: the SDK models this as a typed error,
// and matching on message text would break on a wording change nobody would
// think to check (store/dynamo.go:127-136 settles the same question the same
// way).
func isNoSuchEntity(err error) bool {
	var nse *iamtypes.NoSuchEntityException
	return errors.As(err, &nse)
}

// isEntityAlreadyExists reports IAM refusing to create a second thing under one
// name.
func isEntityAlreadyExists(err error) bool {
	var eae *iamtypes.EntityAlreadyExistsException
	return errors.As(err, &eae)
}

// isDeleteConflict reports IAM refusing to delete something that still has
// children.
//
// It matters because teardown's whole job is to remove those children first, so
// this error means teardown's enumeration was incomplete -- which is what
// happens when a paginated list is read one page deep.
func isDeleteConflict(err error) bool {
	var dc *iamtypes.DeleteConflictException
	return errors.As(err, &dc)
}

// isWebIdentityRetryable reports a web identity failure that a fresh token could
// get past.
//
// # Why four errors the SDK does not call retryable are retryable here
//
// None of the four is in either of the SDK's code lists, and all four are
// FaultClient. Overriding a dependency's classification needs a better reason than
// "this package knows better", and the reason is not that:
//
//	the deciding information is not available to the dependency.
//
// Provider.assume mints a NEW token from the token source on every attempt
// (dynamic.go, the WebIdentityToken call). The SDK cannot know that -- a caller
// that holds one token and presents it repeatedly gets nothing from a retry, and
// that is the caller the SDK has to assume. So the classification differs because
// the callers differ, not because the classification is wrong.
//
// The consequence for anyone reusing this: a caller that does NOT re-mint per
// attempt must not inherit this. That is why the reasoning is here and in
// docs/decisions/ rather than only in the table.
//
// The four, with the SDK's own words:
//
//   - ExpiredToken. The token aged out between minting and use; webIdentityTokenTTL
//     is five minutes, so this means something stalled.
//   - InvalidIdentityToken: "The web identity token that was passed could not be
//     validated by Amazon Web Services. Get a new identity token from the identity
//     provider and then retry the request." The SDK's own documentation prescribes
//     the retry.
//   - IDPRejectedClaim: "If this error is returned for the AssumeRoleWithWebIdentity
//     operation, it can also mean that the claim has expired or has been explicitly
//     revoked." Expired is fixed by a fresh mint; revoked is not, and this provider
//     cannot tell which. Transient is the safe direction of that ambiguity, because
//     bounded retry ends and a terminal misclassification of an expiry does not.
//   - IDPCommunicationError. STS could not reach the identity provider at all.
//
// # What this costs, stated rather than implied
//
// A trust policy that is genuinely wrong, or a signing key that is genuinely
// unusable, now reports transient and is retried. That is deliberate: retry is
// bounded and owned by credentials/lifecycle, which gives up and finalizes the
// record, so a misconfiguration surfaces late rather than never. The opposite
// error -- calling a five-minute expiry terminal -- fails a vend that would have
// worked on the next attempt, every time.
func isWebIdentityRetryable(err error) bool {
	return isExpiredSTSToken(err) || isInvalidIdentityToken(err) ||
		isIdentityProviderRejectedClaim(err) || isIdentityProviderUnreachable(err)
}

// isIdentityProviderRejectedClaim reports the identity provider refusing the claim.
//
// See isWebIdentityRetryable for why this is transient and for the ambiguity it
// carries: the SDK documents this as possibly meaning the claim expired, which a
// fresh mint fixes, and possibly meaning it was revoked, which it does not.
func isIdentityProviderRejectedClaim(err error) bool {
	var irc *ststypes.IDPRejectedClaimException
	return errors.As(err, &irc)
}

// isInvalidIdentityToken reports STS rejecting the web identity token outright.
//
// It is separated from the generic path because it is about the token this package
// minted rather than about the request, and a caller reading "assuming the role
// failed (400)" would go looking in the wrong place. The token itself never
// appears in the error.
//
// It deliberately does NOT cover ExpiredTokenException, which an earlier version
// folded in here. Both are transient for this provider -- see
// isWebIdentityRetryable -- but they are different diagnoses and a caller lands in
// one branch or the other, so which one it is has to be observable. An earlier
// version also had them differing in transience, which was the wrong reason for the
// same separation.
func isInvalidIdentityToken(err error) bool {
	var iit *ststypes.InvalidIdentityTokenException
	return errors.As(err, &iit)
}

// isExpiredSTSToken reports the web identity token having expired before STS read
// it.
//
// webIdentityTokenTTL is five minutes and the token is presented immediately, so
// this means something stalled in between. See isWebIdentityRetryable.
func isExpiredSTSToken(err error) bool {
	var eit *ststypes.ExpiredTokenException
	return errors.As(err, &eit)
}

// isIdentityProviderUnreachable reports STS being unable to reach the identity
// provider that would verify the token.
//
// It is FaultClient and in neither of the SDK's code lists, so nothing else here
// sees it -- the same shape as the consistency race above, found by the same
// population (TestEveryDeclaredSDKErrorIsClassified). Nothing about the request
// would change the outcome, which is the definition of transient this package uses.
// See isWebIdentityRetryable.
func isIdentityProviderUnreachable(err error) bool {
	var ice *ststypes.IDPCommunicationErrorException
	return errors.As(err, &ice)
}
