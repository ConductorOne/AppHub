// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithymw "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/conductorone/apphub/credentials"
)

// The Bedrock bearer-token wire format.
//
// These are not configuration and deliberately so, although the ticket listed
// them alongside the identifiers. A prefix and a version marker are the format
// aws-bedrock-token-generator produces and Bedrock parses; an operator who could
// change them could only produce a token the service rejects, which is the
// opposite of the flexibility a knob suggests. They are protocol facts, and the
// identifiers this ticket is about are the ones that name somebody's account.
const (
	//nolint:gosec // G101 reads this as a hardcoded credential. It is the fixed
	// prefix every Bedrock bearer token begins with; the material is the presigned
	// URL after it, which is minted per request and lives in a credentials.Secret.
	bedrockTokenPrefix  = "bedrock-api-key-"
	bedrockTokenVersion = "&Version=1"
)

// The STS facts the dynamic path is bounded by.
const (
	// minSessionTTL and maxSessionTTL are STS's own window for
	// AssumeRoleWithWebIdentity. Outside it the request is refused here with the
	// limit named rather than clamped into range: a clamp silently hands back a
	// credential with a lifetime nobody asked for, in whichever direction the
	// clamp went.
	//
	// A third limit is not knowable from configuration and so is not enforced
	// here: a role's own MaxSessionDuration can be lower than 12 hours, and
	// nothing in this provider can see it. Such a request reaches STS and comes
	// back classified by fault.go. Guessing a lower ceiling would refuse requests
	// that would have worked.
	minSessionTTL = 15 * time.Minute
	maxSessionTTL = 12 * time.Hour

	// stsAudience is the audience AWS requires on a token presented to
	// AssumeRoleWithWebIdentity. It is a public AWS service name.
	stsAudience = "sts.amazonaws.com"

	// webIdentityTokenTTL is how long the minted OIDC token is valid. It has to
	// survive exactly one STS call, so it is short: a web identity token is a
	// bearer credential for whatever role trusts its issuer, and its useful life
	// is the only thing bounding a leaked one.
	webIdentityTokenTTL = 5 * time.Minute
)

// sessionCredentials is one set of temporary AWS credentials.
//
// The secret and the session token are credentials.Secret rather than strings
// because that is what they are. The source carried them as bare strings through
// two function boundaries and a config reload (claude.go:141-151).
type sessionCredentials struct {
	accessKeyID     string
	secretAccessKey credentials.Secret
	sessionToken    credentials.Secret
	expiresAt       time.Time
}

// presignerFor builds the local signer for one set of session credentials.
//
// It is a field on Provider rather than a package function so that a test can
// replace it, and it takes the credentials as an argument because that is the
// whole reason a presigner cannot be supplied at construction: the credentials
// it must sign with do not exist until STS answers.
type presignerFor func(region string, sess sessionCredentials) presignAPI

// newPresigner is the real implementation.
//
// It constructs a client from Options directly rather than from a loaded
// configuration, which is the one place in this package that builds an AWS client
// -- and it is exempt from the "clients are the composition root's" rule for a
// checkable reason rather than by exception: PresignGetCallerIdentity computes a
// signature locally and issues no request, so there is no retry behaviour, no
// endpoint call and no credential resolution for a caller to configure.
// TestPresignIssuesNoRequest holds that by giving the client a transport that
// fails any attempt to send anything.
func newPresigner(region string, sess sessionCredentials) presignAPI {
	return sts.NewPresignClient(sts.New(presignOptions(region, sess)))
}

// presignOptions is the client configuration newPresigner signs with.
//
// It is a separate function so that TestPresignIssuesNoRequest can drive the
// production options with a transport that fails any attempt to send anything.
// Reconstructing equivalent options in the test would have measured the test's
// own construction; this measures these.
func presignOptions(region string, sess sessionCredentials) sts.Options {
	return sts.Options{
		Region:      region,
		Credentials: sessionProvider{sess: sess},
	}
}

// sessionProvider hands the session credentials to the signer.
//
// It is a handful of lines rather than a call to the SDK's own
// NewStaticCredentialsProvider, for two reasons that both point the same way. The
// SDK's constructor takes the secret and the session token as plain strings and
// keeps them in a struct for the client's lifetime; this reveals them inside
// Retrieve, at the moment the signer needs them, and holds credentials.Secret
// everywhere else. And it means this package needs no direct dependency on
// aws-sdk-go-v2/credentials, so go.mod is unchanged by this port -- a smaller
// dependency graph for a public repository, decided the same way store/ decided
// not to expose its client.
//
// CanExpire is set from what STS actually granted, so the SDK refuses to sign with
// a session that has run out rather than producing a signature nothing will honor.
type sessionProvider struct{ sess sessionCredentials }

func (p sessionProvider) Retrieve(context.Context) (awssdk.Credentials, error) {
	return awssdk.Credentials{
		AccessKeyID:     p.sess.accessKeyID,
		SecretAccessKey: credentials.Reveal(p.sess.secretAccessKey),
		SessionToken:    credentials.Reveal(p.sess.sessionToken),
		Source:          ProviderID,
		CanExpire:       true,
		Expires:         p.sess.expiresAt,
	}, nil
}

// Compile-time proof that the SDK will accept it.
var _ awssdk.CredentialsProvider = sessionProvider{}

// createDynamic mints a Bedrock bearer token from the configured role.
func (p *Provider) createDynamic(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	dyn := p.cfg.Dynamic
	if req.TTL < minSessionTTL || req.TTL > maxSessionTTL {
		return nil, fmt.Errorf("aws: a dynamic TTL must be between %s and %s: %w",
			minSessionTTL, maxSessionTTL, ErrLimit)
	}
	if req.RequesterID == "" {
		// The session name is the only attribution a CloudTrail row will carry,
		// and the subject claim is what a role trust policy conditions on. The
		// source fell back to the credential's name when the requester was
		// unknown (claude.go:98-101), which makes an unattributable vend look
		// attributed.
		//
		// Deleting this branch does not stop the request being refused --
		// prefixedName rejects the empty session name on its own -- but it changes
		// the sentinel from ErrRequesterRequired to ErrNameNotUsable, which tells a
		// caller the wrong thing about what to fix. A mutation that removed it
		// survived the suite until the table asserted the sentinel rather than the
		// presence of an error.
		return nil, fmt.Errorf("%w: a requester ID is the only attribution a dynamic "+
			"credential carries", ErrRequesterRequired)
	}

	sessionName, err := prefixedName("the role session name", dyn.SessionNamePrefix,
		req.RequesterID, maxRoleSessionName)
	if err != nil {
		return nil, err
	}

	sess, err := p.assume(ctx, dyn.RoleARN, sessionName, req)
	if err != nil {
		return nil, err
	}

	// The presigned request cannot outlive the credentials that signed it, so its
	// validity is what STS actually granted rather than what was asked for. The
	// source used time.Now().Add(requested) for both the signature window and the
	// reported expiry (claude.go:154-164), which over-states both whenever STS
	// grants less than the request -- and a role with a lower MaxSessionDuration
	// is exactly that case.
	remaining := sess.expiresAt.Sub(p.now())
	if remaining <= 0 {
		return nil, fmt.Errorf("aws: the session AWS returned has already expired: %w", ErrLimit)
	}

	token, err := p.bedrockToken(ctx, sess, remaining)
	if err != nil {
		return nil, err
	}

	expiresAt := sess.expiresAt
	return &credentials.CreateResult{
		PlatformKeyID: dynamicHandle(sessionName, expiresAt),
		APIKey:        token,
		ExpiresAt:     &expiresAt,
		// What was granted is the role, which is the honest answer and is
		// narrower than the empty value the source returned. The contract reads an
		// empty GrantedScope as "the provider does not describe scope", and this
		// provider can.
		GrantedScope: []string{dyn.RoleARN},
	}, nil
}

// assume exchanges the platform's identity for the configured role's.
func (p *Provider) assume(ctx context.Context, roleARN, sessionName string, req credentials.CreateRequest) (sessionCredentials, error) {
	durationSecs := int32(req.TTL.Seconds())

	var creds *ststypes.Credentials
	if p.tokens != nil {
		subject, err := webIdentitySubject(req)
		if err != nil {
			return sessionCredentials{}, err
		}
		token, err := p.tokens.WebIdentityToken(ctx, subject, stsAudience, webIdentityTokenTTL)
		if err != nil {
			// The token source's own error text is not propagated: it is an
			// implementation this package does not own, and its diagnostics may
			// quote the subject or the key it failed to reach.
			return sessionCredentials{}, wrap(opWebIdentityToken, err)
		}
		if token.IsZero() {
			return sessionCredentials{}, fmt.Errorf("%s: the token source returned nothing", opWebIdentityToken)
		}
		out, err := p.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          awssdk.String(roleARN),
			RoleSessionName:  awssdk.String(sessionName),
			WebIdentityToken: awssdk.String(credentials.Reveal(token)),
			DurationSeconds:  awssdk.Int32(durationSecs),
		})
		if err != nil {
			// All three are transient, and each is a different diagnosis.
			//
			// The case ORDER is not load-bearing, and an earlier version of this
			// comment said it was. Review falsified that by swapping two cases: it
			// compiled and left every test green, including the one this comment
			// used to name. The order is irrelevant because the predicates are
			// disjoint over the errors STS returns -- one typed error per response,
			// so exactly one case can match.
			//
			// That disjointness is the property worth having, and it is now asserted
			// rather than assumed: TestTheTypedErrorPredicatesAreDisjoint checks it
			// over all 45 error types iam and sts declare. Reachability of each
			// branch is separately asserted by
			// TestEveryWebIdentityFailureIsTransientAndDistinguishable. Neither
			// covers the other and both are named here.
			//
			// The one case where order WOULD decide: errors.As walks a chain, so an
			// error wrapping two of these types matches two predicates. Nothing here
			// builds such a chain, and the disjointness test says plainly that it
			// cannot see one.
			//
			// Why a rejected token is retryable here at all is
			// isWebIdentityRetryable's comment, and it is the whole justification
			// for overriding the SDK: this provider mints a fresh token on every
			// attempt, which the SDK cannot know.
			switch {
			case isExpiredSTSToken(err):
				return sessionCredentials{}, fmt.Errorf("aws: %s failed: %w: %w",
					opAssumeRoleWebIdentity, ErrWebIdentityTokenExpired, credentials.ErrTransient)
			case isInvalidIdentityToken(err):
				return sessionCredentials{}, fmt.Errorf("aws: %s failed: %w: %w",
					opAssumeRoleWebIdentity, ErrWebIdentityTokenInvalid, credentials.ErrTransient)
			case isIdentityProviderRejectedClaim(err):
				return sessionCredentials{}, fmt.Errorf("aws: %s failed: %w: %w",
					opAssumeRoleWebIdentity, ErrWebIdentityClaimRejected, credentials.ErrTransient)
			}
			return sessionCredentials{}, wrap(opAssumeRoleWebIdentity, err)
		}
		creds = out.Credentials
	} else {
		out, err := p.sts.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         awssdk.String(roleARN),
			RoleSessionName: awssdk.String(sessionName),
			DurationSeconds: awssdk.Int32(durationSecs),
		})
		if err != nil {
			return sessionCredentials{}, wrap(opAssumeRole, err)
		}
		creds = out.Credentials
	}

	return sessionFromSTS(creds)
}

// sessionFromSTS converts what STS returned, refusing anything incomplete.
//
// Every field is checked. The source read three of them through aws.ToString
// (claude.go:143-147), which turns a nil pointer into an empty string -- so a
// truncated STS response produced a config carrying empty credentials and the
// failure arrived later, at the presign, as a signature error.
func sessionFromSTS(creds *ststypes.Credentials) (sessionCredentials, error) {
	if creds == nil {
		return sessionCredentials{}, errNoCredentials
	}
	id := awssdk.ToString(creds.AccessKeyId)
	secret := awssdk.ToString(creds.SecretAccessKey)
	token := awssdk.ToString(creds.SessionToken)
	if id == "" || secret == "" || token == "" || creds.Expiration == nil {
		return sessionCredentials{}, errNoCredentials
	}
	return sessionCredentials{
		accessKeyID:     id,
		secretAccessKey: credentials.NewSecret(secret),
		sessionToken:    credentials.NewSecret(token),
		expiresAt:       creds.Expiration.UTC(),
	}, nil
}

// webIdentitySubject builds the subject claim the role trust policy conditions
// on.
//
// # What this provider does and does not vouch for
//
// The claim is built from CreateRequest.RequesterType and RequesterID, which are
// the platform's own account of who is asking. This provider does not
// authenticate either: it mints a token asserting what it was told. So a trust
// policy that conditions on the subject is trusting the platform's
// authentication, and the platform's obligation is that these two fields come
// from an authenticated session and never from a request body. The source system
// states the same obligation about the same fields (honeytoken_aws.go:41-45).
//
// TestTheWebIdentitySubjectIsWhateverTheCallerSaid asserts that plainly, so a
// later reader finds the property in a test rather than only in this comment.
//
// Both fields are required. An empty type would render a subject beginning with
// the separator, and an empty requester is refused before this point.
func webIdentitySubject(req credentials.CreateRequest) (string, error) {
	kind := sanitize(req.RequesterType)
	if kind == "" || req.RequesterType == "" {
		return "", fmt.Errorf("%w: a requester type is required to build a web identity subject",
			ErrRequesterRequired)
	}
	id := sanitize(req.RequesterID)
	if id == "" {
		return "", fmt.Errorf("aws: the requester ID has no usable characters: %w", ErrNameNotUsable)
	}
	return kind + ":" + id, nil
}

// bedrockToken presigns an STS GetCallerIdentity request and encodes it as a
// Bedrock bearer token.
//
// The format is aws-bedrock-token-generator's:
//
//	bedrock-api-key-<base64(presigned URL)>&Version=1
//
// The presign itself is a local signature computation. Nothing here reaches the
// network, which is what makes this path testable against the real signer rather
// than against a double that agrees with it.
func (p *Provider) bedrockToken(ctx context.Context, sess sessionCredentials, valid time.Duration) (credentials.Secret, error) {
	expirySecs := int(valid.Seconds())
	if expirySecs <= 0 {
		return credentials.Secret{}, fmt.Errorf("aws: nothing is left of the session to sign for: %w", ErrLimit)
	}

	presigned, err := p.presign(p.cfg.Region, sess).PresignGetCallerIdentity(ctx,
		&sts.GetCallerIdentityInput{}, withExpires(expirySecs))
	if err != nil {
		return credentials.Secret{}, wrap(opPresign, err)
	}
	if presigned == nil || presigned.URL == "" {
		return credentials.Secret{}, fmt.Errorf("%s: the signer produced no URL", opPresign)
	}

	// The URL is a bearer credential: it carries a signature that anything
	// holding it can replay for as long as it is valid. It becomes a Secret here
	// and is never a string beyond this line.
	encoded := base64.StdEncoding.EncodeToString([]byte(presigned.URL))
	return credentials.NewSecret(bedrockTokenPrefix + encoded + bedrockTokenVersion), nil
}

// withExpires sets X-Amz-Expires on the presigned request.
//
// The SDK's presigner has no option for it, so the query parameter is set by a
// build-step middleware after the signer has run, which is what the source did
// (claude.go:178-194) and what aws-bedrock-token-generator does. It is kept as a
// separate function so the one interesting property -- that a request the
// middleware could not recognise is a failure rather than a silently unbounded
// signature -- is visible.
//
// The source returned next.HandleBuild for a request it could not type-assert
// (claude.go:183-188), so a signature with no expiry at all would have been
// emitted with no error. That is the shape of a skip path in a gate, and it is
// closed here.
func withExpires(seconds int) func(*sts.PresignOptions) {
	return func(po *sts.PresignOptions) {
		po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions, func(stack *smithymw.Stack) error {
				return stack.Build.Add(boundExpires(seconds), smithymw.After)
			})
		})
	}
}

// expiresMiddlewareID names the build step, for smithy's own stack listing.
const expiresMiddlewareID = "AppHubBedrockTokenExpires"

// boundExpires is the build step itself, extracted so it can be driven directly.
//
// Extracting it is the point rather than tidiness. The interesting property here
// is the refusal -- a request the step cannot recognise must be an error, not a
// signature emitted with no expiry -- and that is unreachable through a real
// presign, because a real presign always produces an HTTP request. A mutation that
// replaced the refusal with next.HandleBuild survived the whole suite.
// TestTheExpiryMiddlewareRefusesARequestItCannotBound now calls this with a
// request that is not one.
func boundExpires(seconds int) smithymw.BuildMiddleware {
	return smithymw.BuildMiddlewareFunc(expiresMiddlewareID,
		func(ctx context.Context, in smithymw.BuildInput, next smithymw.BuildHandler) (smithymw.BuildOutput, smithymw.Metadata, error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				// A skip path in a build step is a build step that does not run.
				// The source returned next.HandleBuild here (claude.go:183-188), so
				// a signature whose expiry could not be set would have been emitted
				// unbounded and reported as a success.
				return smithymw.BuildOutput{}, smithymw.Metadata{},
					errors.New("aws: the presigner did not produce an HTTP request to bound")
			}
			q := req.URL.Query()
			q.Set("X-Amz-Expires", strconv.Itoa(seconds))
			req.URL.RawQuery = q.Encode()
			return next.HandleBuild(ctx, in)
		},
	)
}
