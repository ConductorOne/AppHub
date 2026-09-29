// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/conductorone/apphub/credentials"
)

// bedrockServiceName is the service principal a Bedrock service-specific
// credential is scoped to. IAM enforces the scope: a credential created for this
// service can be used against this service and nothing else.
const bedrockServiceName = "bedrock.amazonaws.com"

// dayHours is the granularity IAM offers for a service-specific credential's
// lifetime. See createStatic for why a TTL that is not a whole number of these
// is refused rather than rounded.
const dayHours = 24

// maxListPages bounds every paginated read.
//
// It is a loop bound and not a limit on what AWS may hold: a paginated read whose
// marker stops advancing, or whose service keeps saying "truncated", would
// otherwise spin forever inside a revoke. Reaching it is an error rather than a
// short answer, because a short answer here means teardown believes it has
// removed everything hanging off a user when it has not.
const maxListPages = 100

// ErrPaginationExhausted means a paginated read did not terminate within
// maxListPages, so the enumeration it produced is incomplete.
var ErrPaginationExhausted = errors.New("aws: a paginated AWS read did not terminate")

// ErrCleanupIncomplete means a half-created credential could not be cleaned up,
// so an IAM user is still there.
//
// It is a distinct sentinel because it is the one failure in this package that
// leaves something behind for an operator to find, and a caller that cannot tell
// it apart from the failure that caused it cannot say so. The source discarded
// every teardown error (claude.go:360, 372, 384, 396), so this state was
// indistinguishable from a clean refusal.
var ErrCleanupIncomplete = errors.New("aws: an IAM user was left behind and needs removing")

// ErrNotOwned means an IAM user exists under a name this provider minted a
// handle for and does not carry this platform's ownership tags.
//
// It is refused rather than worked around. An IAM user name is account-global and
// this provider's names are derived from a caller-supplied credential name, so a
// name that belonged to a credential this platform minted can later belong to
// something an operator created by hand. Deleting that is worse than failing to
// revoke.
var ErrNotOwned = errors.New("aws: an IAM user under that name is not managed by apphub")

// createStatic creates a dedicated IAM user and a Bedrock service-specific
// credential on it.
func (p *Provider) createStatic(ctx context.Context, req credentials.CreateRequest) (*credentials.CreateResult, error) {
	st := p.cfg.Static

	// IAM expresses a service-specific credential's lifetime in whole days, and
	// the interface hands this provider a time.Duration. The source resolved the
	// mismatch by rounding -- int32(TTL.Hours()/24) with a floor of 1
	// (claude.go:255-261) -- which turns any TTL under a day into a credential
	// lasting a day. That is an extension of a lifetime the caller had already had
	// clamped by policy, in the one direction a credential lifetime must never
	// move. Refusing and naming the granularity is the rule this repository
	// settled on for a substrate that cannot express what the interface permits.
	if req.TTL%(dayHours*time.Hour) != 0 {
		return nil, fmt.Errorf("aws: IAM expresses a static credential's lifetime in whole days, "+
			"so a TTL must be a multiple of %dh: %w", dayHours, ErrLimit)
	}
	days := int64(req.TTL.Hours()) / dayHours
	if days < 1 || days > math.MaxInt32 {
		return nil, fmt.Errorf("aws: a static TTL must be between 1 and %d days: %w",
			int64(math.MaxInt32), ErrLimit)
	}

	userName, err := prefixedName("the IAM user name", st.UserNamePrefix, req.Name, maxIAMUserName)
	if err != nil {
		return nil, err
	}

	// Path, permissions boundary and ownership tags are all on the create call
	// rather than applied afterwards, and the ordering is the point. A user
	// created bare and tagged in a second call exists untagged in between -- and
	// teardown refuses to delete an untagged user, so a failure in that window
	// leaks a user nothing will ever clean up. A user created bare and bounded
	// afterwards is unbounded in the same window. One call has no window.
	if _, err := p.iam.CreateUser(ctx, &iam.CreateUserInput{
		UserName:            awssdk.String(userName),
		Path:                awssdk.String(st.UserPath),
		PermissionsBoundary: awssdk.String(st.PermissionsBoundaryARN),
		Tags:                ownershipTags(userName),
	}); err != nil {
		if isEntityAlreadyExists(err) {
			// Refused, never adopted. An existing user under this name may be an
			// operator's, and attaching a policy to it would be writing a grant
			// onto somebody else's identity. compute/aws/identity.go:33-37
			// records the same finding about roles.
			return nil, fmt.Errorf("aws: an IAM user already exists under the name this "+
				"credential would need: %w", ErrNotOwned)
		}
		return nil, wrap(opCreateUser, err)
	}

	if _, err := p.iam.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
		UserName:  awssdk.String(userName),
		PolicyArn: awssdk.String(st.PolicyARN),
	}); err != nil {
		return nil, p.compensate(ctx, userName, wrap(opAttachPolicy, err))
	}

	ageDays := int32(days)
	credOut, err := p.iam.CreateServiceSpecificCredential(ctx, &iam.CreateServiceSpecificCredentialInput{
		UserName:    awssdk.String(userName),
		ServiceName: awssdk.String(bedrockServiceName),
		// Always set. AWS documents an absent CredentialAgeDays as "the
		// credential will not expire", and the source omitted it whenever no TTL
		// was supplied (claude.go:255-261) -- so the default outcome of the
		// default request was a permanent credential.
		CredentialAgeDays: awssdk.Int32(ageDays),
	})
	if err != nil {
		return nil, p.compensate(ctx, userName, wrap(opCreateServiceCred, err))
	}
	ssc := credOut.ServiceSpecificCredential
	if ssc == nil {
		return nil, p.compensate(ctx, userName,
			fmt.Errorf("%s: IAM returned success and no credential", opCreateServiceCred))
	}
	credentialID := awssdk.ToString(ssc.ServiceSpecificCredentialId)
	if credentialID == "" {
		// Nothing to name it by, so nothing could revoke it later. Tearing the
		// user down takes the credential with it, which is the only disposition
		// that does not leave a credential nobody can find.
		return nil, p.compensate(ctx, userName,
			fmt.Errorf("%s: IAM returned a credential with no identifier", opCreateServiceCred))
	}

	handle := staticHandle(userName, credentialID)
	secret := awssdk.ToString(ssc.ServiceCredentialSecret)
	if secret == "" {
		// The credential exists upstream and cannot be handed over. The handle has
		// to survive -- it is the only record anyone will have of something that
		// needs deleting -- and it must not be rendered, because it carries a name
		// IAM chose. Both hold at once only through a type; see
		// credentials.CreateNotDeliveredError.
		//
		// This provider does not tear down here, unlike the paths above. Above,
		// nothing usable exists and nothing outside this function knows about it.
		// Here the credential is real and named, so whether to compensate is the
		// lifecycle layer's decision, and a provider that quietly revoked on its
		// way out of an error would be making that decision where nobody can see
		// it. credentials/datadog/datadog.go:274-288 settles the identical case.
		return nil, credentials.NewCreateNotDelivered(ProviderID, handle)
	}

	result := &credentials.CreateResult{
		PlatformKeyID: handle,
		APIKey:        credentials.NewSecret(secret),
		// The grant is the operator's policy bounded by the operator's boundary,
		// and IAM scopes the credential itself to one service. All three are what
		// was actually granted, which is more than the source recorded -- it
		// returned nothing here, so a record said what was asked for and never
		// what was given.
		GrantedScope: []string{st.PolicyARN, st.PermissionsBoundaryARN, bedrockServiceName},
	}
	if ssc.ExpirationDate != nil {
		// IAM's own answer, preferred over a local computation. The source fell
		// back to time.Now().Add(TTL) when IAM did not say (claude.go:275-280),
		// which records a locally guessed time as a provider-stated expiry --
		// lifecycle.Record.ExpiryAuthoritative is derived from whether this field
		// is set, and a true there lets a record be finalized as expired.
		exp := ssc.ExpirationDate.UTC()
		result.ExpiresAt = &exp
	}
	return result, nil
}

// compensate tears down a half-created user and reports both outcomes.
//
// The original failure is what the caller asked about, so it is what errors.Is
// sees. A failure to clean up is appended rather than substituted: it leaves an
// IAM user behind, which an operator has to know about, and swallowing it is what
// the source did at every step of its teardown (claude.go:360, 372, 384, 396).
func (p *Provider) compensate(ctx context.Context, userName string, cause error) error {
	if err := p.teardownUser(ctx, userName); err != nil {
		return fmt.Errorf("%w: %w: %w", cause, ErrCleanupIncomplete, err)
	}
	return cause
}

// revokeStatic deletes the service-specific credential and the user that holds
// it.
func (p *Provider) revokeStatic(ctx context.Context, userName, credentialID string) error {
	owned, err := p.ownsUser(ctx, userName)
	switch {
	case errors.Is(err, ErrNotOwned):
		return err
	case err != nil:
		return err
	case !owned:
		// The user is gone, so the credential is too: IAM will not delete a user
		// that still has one. A revoke exists to make the material stop working,
		// and it has. Returning an error here would leave the reconciler retrying
		// forever against something nobody can find -- the same reading
		// credentials/datadog gives a 404 (datadog.go:307-311).
		return nil
	}

	if _, err := p.iam.DeleteServiceSpecificCredential(ctx, &iam.DeleteServiceSpecificCredentialInput{
		UserName:                    awssdk.String(userName),
		ServiceSpecificCredentialId: awssdk.String(credentialID),
	}); err != nil && !isNoSuchEntity(err) {
		// Reported, not discarded. The source ignored this error entirely
		// (claude.go:307-310) and went on to delete the user, so a revoke that
		// could not remove the credential reported whatever DeleteUser said --
		// and DeleteUser would then have failed with a conflict, making the
		// diagnosis point at the wrong call.
		return wrap(opDeleteServiceCred, err)
	}

	return p.teardownUser(ctx, userName)
}

// statusStatic asks IAM whether the credential is still there.
func (p *Provider) statusStatic(ctx context.Context, userName, credentialID string) (credentials.CredentialStatus, error) {
	owned, err := p.ownsUser(ctx, userName)
	switch {
	case errors.Is(err, ErrNotOwned):
		// A user exists under the name and is not ours, so the one this platform
		// created is gone and so is everything that hung off it. Revoked is the
		// truthful answer and it is safe: it can only make a caller retire a
		// record for a credential that no longer exists.
		return credentials.CredentialStatusRevoked, nil
	case err != nil:
		return credentials.CredentialStatusUnknown, err
	case !owned:
		return credentials.CredentialStatusRevoked, nil
	}

	found, expiry, active, err := p.findServiceCredential(ctx, userName, credentialID)
	if err != nil {
		return credentials.CredentialStatusUnknown, err
	}
	switch {
	case !found:
		return credentials.CredentialStatusRevoked, nil
	case expiry != nil && !p.now().Before(*expiry):
		// IAM still lists it and its stated expiry has passed. Expired rather
		// than active: the source had no expired branch at all (claude.go:346-351)
		// and would have reported such a credential active.
		return credentials.CredentialStatusExpired, nil
	case !active:
		// IAM models a credential that has been deactivated but not deleted. It
		// does not work, which is what revoked means to a caller.
		return credentials.CredentialStatusRevoked, nil
	default:
		return credentials.CredentialStatusActive, nil
	}
}

// findServiceCredential looks for one credential ID across every page IAM has.
//
// The pagination is the point. ListServiceSpecificCredentials takes a marker, and
// the source read one page (claude.go:335-351): a user holding more credentials
// than one page returns would have had a live credential reported revoked, which
// is the reading that makes a caller stop managing something that still works.
func (p *Provider) findServiceCredential(ctx context.Context, userName, credentialID string) (found bool, expiry *time.Time, active bool, err error) {
	var marker *string
	for page := 0; page < maxListPages; page++ {
		out, listErr := p.iam.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{
			UserName:    awssdk.String(userName),
			ServiceName: awssdk.String(bedrockServiceName),
			Marker:      marker,
		})
		if listErr != nil {
			if isNoSuchEntity(listErr) {
				return false, nil, false, nil
			}
			return false, nil, false, wrap(opListServiceCreds, listErr)
		}
		for _, c := range out.ServiceSpecificCredentials {
			if awssdk.ToString(c.ServiceSpecificCredentialId) != credentialID {
				continue
			}
			return true, c.ExpirationDate, c.Status == iamtypes.StatusTypeActive, nil
		}
		next, done, pageErr := nextMarker(out.IsTruncated, out.Marker, opListServiceCreds)
		if pageErr != nil {
			return false, nil, false, pageErr
		}
		if done {
			return false, nil, false, nil
		}
		marker = next
	}
	return false, nil, false, fmt.Errorf("%s: %w", opListServiceCreds, ErrPaginationExhausted)
}

// ownsUser reports whether an IAM user exists under this name and carries this
// platform's ownership tags.
//
// Three outcomes, and the middle one is why this is not a bool. The user is
// absent (false, nil); it is present and ours (true, nil); it is present and not
// ours (false, ErrNotOwned). Collapsing the third into either of the others is
// how a platform deletes something it did not create.
func (p *Provider) ownsUser(ctx context.Context, userName string) (bool, error) {
	tags := map[string]string{}
	var marker *string
	complete := false
	for page := 0; page < maxListPages && !complete; page++ {
		out, err := p.iam.ListUserTags(ctx, &iam.ListUserTagsInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			if isNoSuchEntity(err) {
				return false, nil
			}
			return false, wrap(opReadUserTags, err)
		}
		for _, t := range out.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
		next, done, pageErr := nextMarker(out.IsTruncated, out.Marker, opReadUserTags)
		if pageErr != nil {
			return false, pageErr
		}
		complete = done
		marker = next
	}
	if !complete {
		// The tag set is incomplete, so the ownership question is unanswered. An
		// unanswered ownership question must not read as "not ours" -- that is the
		// answer that leads to a refusal, which is safe -- nor as "ours", which
		// would authorise a delete. It is an error.
		return false, fmt.Errorf("%s: %w", opReadUserTags, ErrPaginationExhausted)
	}

	// Both tags have to agree, not one. The ownership tag says apphub created
	// it; the component tag says what apphub created it *as*. An IAM user this
	// platform created to hold a vended credential and an IAM user it created for
	// something else are the same kind of object in one account-global namespace,
	// and treating them as interchangeable by name is how a teardown reaches
	// something it has no business deleting. compute/aws/names.go:279-294 reached
	// this from the other end.
	if tags[tagManagedBy] != managedByValue || tags[tagComponent] != componentCredentialUser {
		return false, ErrNotOwned
	}
	return true, nil
}

// ownershipTags are the tags every IAM user this provider creates carries.
func ownershipTags(userName string) []iamtypes.Tag {
	return []iamtypes.Tag{
		{Key: awssdk.String(tagManagedBy), Value: awssdk.String(managedByValue)},
		{Key: awssdk.String(tagName), Value: awssdk.String(userName)},
		{Key: awssdk.String(tagComponent), Value: awssdk.String(componentCredentialUser)},
	}
}

// teardownUser removes everything hanging off an IAM user and then the user.
//
// # It checks ownership first, and that is a transition rather than a call
//
// Every individual operation below is correct on a user this platform created.
// What makes the check necessary is the move between two states nothing here
// performs: the user is deleted out from under the record, and a new user appears
// under the same name. A handle that was valid once is then a name for somebody
// else's identity. The source checked nothing and deleted whatever the handle
// named (claude.go:354-409).
//
// # Every list is paginated and every failure is reported
//
// The source read one page of each list and discarded every error on the way
// (claude.go:355-401), so the observable outcome of an incomplete teardown was
// DeleteUser failing with a conflict -- an error that says the user has children
// and not which enumeration missed them.
func (p *Provider) teardownUser(ctx context.Context, userName string) error {
	owned, err := p.ownsUser(ctx, userName)
	switch {
	case err != nil:
		return err
	case !owned:
		// Already gone. Nothing to do and nothing wrong.
		return nil
	}

	if err := p.detachAllPolicies(ctx, userName); err != nil {
		return err
	}
	if err := p.deleteAllInlinePolicies(ctx, userName); err != nil {
		return err
	}
	if err := p.deleteAllAccessKeys(ctx, userName); err != nil {
		return err
	}
	if err := p.deleteAllServiceCredentials(ctx, userName); err != nil {
		return err
	}

	if _, err := p.iam.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awssdk.String(userName)}); err != nil {
		if isNoSuchEntity(err) {
			return nil
		}
		if isDeleteConflict(err) {
			// The user still has something attached, which means one of the
			// enumerations above did not see everything. Saying so names the
			// defect; "delete failed (409)" would not.
			return fmt.Errorf("aws: %s failed: something is still attached to the user that "+
				"teardown did not enumerate", opDeleteUser)
		}
		return wrap(opDeleteUser, err)
	}
	return nil
}

// collectPage is one page of a paginated read: the items, whether more follow,
// and the marker to ask for them with.
type collectPage[T any] struct {
	Items     []T
	Truncated bool
	Marker    *string
}

// collectAll reads every page before anything is deleted.
//
// # Enumerating and deleting must not interleave, and a test found that out
//
// The first version of teardown deleted each page's items before asking for the
// next page, which is the obvious shape and is wrong. A marker is an offset into
// a list that the deletions are shortening, so the second page starts past items
// that have moved down -- and those items are then never seen. The fake models a
// marker that way deliberately, and TestTeardownEnumeratesEveryPage failed
// immediately: the user was left with children and DeleteUser reported a
// conflict.
//
// The real IAM's marker is opaque and its behaviour under concurrent mutation is
// unspecified, which is a weaker guarantee than the fake's and not a stronger
// one. So the rule is the same either way: read the whole enumeration, then act
// on it.
func collectAll[T any](ctx context.Context, o op, fetch func(context.Context, *string) (collectPage[T], error)) ([]T, error) {
	var out []T
	var marker *string
	for page := 0; page < maxListPages; page++ {
		got, err := fetch(ctx, marker)
		if err != nil {
			if isNoSuchEntity(err) {
				return nil, nil
			}
			return nil, wrap(o, err)
		}
		out = append(out, got.Items...)
		next, done, pageErr := nextMarker(got.Truncated, got.Marker, o)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return out, nil
		}
		marker = next
	}
	return nil, fmt.Errorf("%s: %w", o, ErrPaginationExhausted)
}

func (p *Provider) detachAllPolicies(ctx context.Context, userName string) error {
	arns, err := collectAll(ctx, opListAttachedPolicies, func(ctx context.Context, marker *string) (collectPage[string], error) {
		out, err := p.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			return collectPage[string]{}, err
		}
		page := collectPage[string]{Truncated: out.IsTruncated, Marker: out.Marker}
		for _, ap := range out.AttachedPolicies {
			page.Items = append(page.Items, awssdk.ToString(ap.PolicyArn))
		}
		return page, nil
	})
	if err != nil {
		return err
	}
	for _, arn := range arns {
		if _, err := p.iam.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			UserName:  awssdk.String(userName),
			PolicyArn: awssdk.String(arn),
		}); err != nil && !isNoSuchEntity(err) {
			return wrap(opDetachPolicy, err)
		}
	}
	return nil
}

func (p *Provider) deleteAllInlinePolicies(ctx context.Context, userName string) error {
	names, err := collectAll(ctx, opListInlinePolicies, func(ctx context.Context, marker *string) (collectPage[string], error) {
		out, err := p.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			return collectPage[string]{}, err
		}
		return collectPage[string]{Items: out.PolicyNames, Truncated: out.IsTruncated, Marker: out.Marker}, nil
	})
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err := p.iam.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   awssdk.String(userName),
			PolicyName: awssdk.String(name),
		}); err != nil && !isNoSuchEntity(err) {
			return wrap(opDeleteInlinePolicy, err)
		}
	}
	return nil
}

func (p *Provider) deleteAllAccessKeys(ctx context.Context, userName string) error {
	ids, err := collectAll(ctx, opListAccessKeys, func(ctx context.Context, marker *string) (collectPage[string], error) {
		out, err := p.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			return collectPage[string]{}, err
		}
		page := collectPage[string]{Truncated: out.IsTruncated, Marker: out.Marker}
		for _, k := range out.AccessKeyMetadata {
			page.Items = append(page.Items, awssdk.ToString(k.AccessKeyId))
		}
		return page, nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := p.iam.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			UserName:    awssdk.String(userName),
			AccessKeyId: awssdk.String(id),
		}); err != nil && !isNoSuchEntity(err) {
			return wrap(opDeleteAccessKey, err)
		}
	}
	return nil
}

// deleteAllServiceCredentials removes every service-specific credential on the
// user, for every service and not only Bedrock.
//
// The unfiltered list is deliberate: DeleteUser refuses while any of them
// remains, so filtering by the service this provider creates for would leave a
// user undeletable if anything ever created one for another service. The source
// listed unfiltered here (claude.go:367-369) and filtered in the status path,
// which is the right way round.
func (p *Provider) deleteAllServiceCredentials(ctx context.Context, userName string) error {
	ids, err := collectAll(ctx, opListServiceCreds, func(ctx context.Context, marker *string) (collectPage[string], error) {
		out, err := p.iam.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			return collectPage[string]{}, err
		}
		page := collectPage[string]{Truncated: out.IsTruncated, Marker: out.Marker}
		for _, c := range out.ServiceSpecificCredentials {
			page.Items = append(page.Items, awssdk.ToString(c.ServiceSpecificCredentialId))
		}
		return page, nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := p.iam.DeleteServiceSpecificCredential(ctx, &iam.DeleteServiceSpecificCredentialInput{
			UserName:                    awssdk.String(userName),
			ServiceSpecificCredentialId: awssdk.String(id),
		}); err != nil && !isNoSuchEntity(err) {
			return wrap(opDeleteServiceCred, err)
		}
	}
	return nil
}

// nextMarker decides whether a paginated read continues, and refuses to guess.
//
// A response that says it is truncated and supplies no marker is not a last page
// and not a page this code can follow. Treating it as the end would silently
// shorten an enumeration teardown depends on being complete, which is a skip path
// in exactly the place a skip path becomes a bypass. So it is an error.
func nextMarker(truncated bool, marker *string, o op) (next *string, done bool, err error) {
	if !truncated {
		return nil, true, nil
	}
	if marker == nil || *marker == "" {
		return nil, false, fmt.Errorf("aws: %s returned a truncated page with no marker: %w",
			o, ErrPaginationExhausted)
	}
	return marker, false, nil
}
