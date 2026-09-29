// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/conductorone/apphub/credentials"
)

// The fakes in this file are stateful, and that is a hazard as well as the point.
// A fixture that mutates what it is asked to report makes every failure read as a
// real defect, so the invariants the fake itself is supposed to hold are asserted
// in TestTheFakeIAMBehavesLikeIAM before anything relies on them.

// fakeUser is one IAM user as the fake models it.
type fakeUser struct {
	path     string
	boundary string
	tags     map[string]string
	attached []string
	inline   []string
	keys     []string
	sscs     []fakeSSC
}

type fakeSSC struct {
	id      string
	service string
	expires *time.Time
	status  iamtypes.StatusType
}

// fakeIAM is an in-memory IAM good enough to drive this package's every path.
//
// pageSize is deliberately settable and defaults to something small: every list
// operation the real IAM paginates is paginated here too, so the default test run
// exercises the multi-page path rather than only the happy single-page one that
// the source's teardown was written against.
type fakeIAM struct {
	mu    sync.Mutex
	users map[string]*fakeUser
	// calls records every method name, in order.
	calls []string
	// fail returns an error for the named method. A nil error means "no
	// injection"; the func is consulted on every call so a test can fail the
	// second attempt and not the first.
	fail func(method string, attempt int) error
	// attempts counts calls per method, for fail.
	attempts map[string]int
	// pageSize is how many items a list returns per page. Zero means one.
	pageSize int
	// nextCredID makes credential identifiers unique. Deliberately not shaped
	// like an AWS identifier: a literal that looked like one would be a finding
	// in the repository's own secret scan, and a fixture is not a good enough
	// reason to write one.
	nextCredID int
	// credSecret is what CreateServiceSpecificCredential hands back. Empty means
	// "IAM returned no secret", which is the not-delivered path.
	credSecret string
	// omitCredID drops the identifier from a create response.
	omitCredID bool
	// omitExpiry drops the expiry from a create response.
	omitExpiry bool
	// truncateWithoutMarker makes every list claim truncation and supply no
	// marker, which is the response a paginated read must refuse to interpret.
	truncateWithoutMarker bool
}

func newFakeIAM() *fakeIAM {
	return &fakeIAM{
		users:      map[string]*fakeUser{},
		attempts:   map[string]int{},
		pageSize:   1,
		credSecret: "fake-service-credential-secret",
	}
}

// enter records the call and applies any injected failure. It must be called
// with the lock held.
func (f *fakeIAM) enter(method string) error {
	f.calls = append(f.calls, method)
	f.attempts[method]++
	if f.fail == nil {
		return nil
	}
	return f.fail(method, f.attempts[method])
}

func (f *fakeIAM) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeIAM) countOf(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[method]
}

// page returns the slice of items for a marker plus the next marker.
//
// The marker is an offset rendered as a string, which is what makes a
// mis-advanced marker visible: a caller that failed to forward it would loop on
// page zero, and every list-driven test would hang rather than quietly pass.
func (f *fakeIAM) page(total int, marker *string) (from, to int, truncated bool, next *string, err error) {
	size := f.pageSize
	if size < 1 {
		size = 1
	}
	from = 0
	if marker != nil && *marker != "" {
		from, err = strconv.Atoi(*marker)
		if err != nil {
			return 0, 0, false, nil, fmt.Errorf("fake: unreadable marker")
		}
	}
	if from > total {
		return 0, 0, false, nil, fmt.Errorf("fake: marker past the end")
	}
	to = from + size
	if to >= total {
		if f.truncateWithoutMarker {
			return from, total, true, nil, nil
		}
		return from, total, false, nil, nil
	}
	if f.truncateWithoutMarker {
		return from, to, true, nil, nil
	}
	m := strconv.Itoa(to)
	return from, to, true, &m, nil
}

func (f *fakeIAM) user(name string) (*fakeUser, error) {
	u, ok := f.users[name]
	if !ok {
		return nil, &iamtypes.NoSuchEntityException{Message: awssdk.String("no such user")}
	}
	return u, nil
}

func (f *fakeIAM) CreateUser(_ context.Context, in *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateUser"); err != nil {
		return nil, err
	}
	name := awssdk.ToString(in.UserName)
	if _, exists := f.users[name]; exists {
		return nil, &iamtypes.EntityAlreadyExistsException{Message: awssdk.String("user exists")}
	}
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	f.users[name] = &fakeUser{
		path:     awssdk.ToString(in.Path),
		boundary: awssdk.ToString(in.PermissionsBoundary),
		tags:     tags,
	}
	return &iam.CreateUserOutput{}, nil
}

func (f *fakeIAM) ListUserTags(_ context.Context, in *iam.ListUserTagsInput, _ ...func(*iam.Options)) (*iam.ListUserTagsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListUserTags"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(u.tags))
	for k := range u.tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	from, to, truncated, next, err := f.page(len(keys), in.Marker)
	if err != nil {
		return nil, err
	}
	out := &iam.ListUserTagsOutput{IsTruncated: truncated, Marker: next}
	for _, k := range keys[from:to] {
		out.Tags = append(out.Tags, iamtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(u.tags[k])})
	}
	return out, nil
}

func (f *fakeIAM) AttachUserPolicy(_ context.Context, in *iam.AttachUserPolicyInput, _ ...func(*iam.Options)) (*iam.AttachUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("AttachUserPolicy"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	u.attached = append(u.attached, awssdk.ToString(in.PolicyArn))
	return &iam.AttachUserPolicyOutput{}, nil
}

func (f *fakeIAM) DetachUserPolicy(_ context.Context, in *iam.DetachUserPolicyInput, _ ...func(*iam.Options)) (*iam.DetachUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DetachUserPolicy"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	u.attached = remove(u.attached, awssdk.ToString(in.PolicyArn))
	return &iam.DetachUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListAttachedUserPolicies"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	from, to, truncated, next, err := f.page(len(u.attached), in.Marker)
	if err != nil {
		return nil, err
	}
	out := &iam.ListAttachedUserPoliciesOutput{IsTruncated: truncated, Marker: next}
	for _, arn := range u.attached[from:to] {
		out.AttachedPolicies = append(out.AttachedPolicies, iamtypes.AttachedPolicy{PolicyArn: awssdk.String(arn)})
	}
	return out, nil
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListUserPolicies"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	from, to, truncated, next, err := f.page(len(u.inline), in.Marker)
	if err != nil {
		return nil, err
	}
	return &iam.ListUserPoliciesOutput{
		PolicyNames: append([]string(nil), u.inline[from:to]...),
		IsTruncated: truncated,
		Marker:      next,
	}, nil
}

func (f *fakeIAM) DeleteUserPolicy(_ context.Context, in *iam.DeleteUserPolicyInput, _ ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteUserPolicy"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	u.inline = remove(u.inline, awssdk.ToString(in.PolicyName))
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListAccessKeys"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	from, to, truncated, next, err := f.page(len(u.keys), in.Marker)
	if err != nil {
		return nil, err
	}
	out := &iam.ListAccessKeysOutput{IsTruncated: truncated, Marker: next}
	for _, k := range u.keys[from:to] {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, iamtypes.AccessKeyMetadata{AccessKeyId: awssdk.String(k)})
	}
	return out, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteAccessKey"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	u.keys = remove(u.keys, awssdk.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (f *fakeIAM) CreateServiceSpecificCredential(_ context.Context, in *iam.CreateServiceSpecificCredentialInput, _ ...func(*iam.Options)) (*iam.CreateServiceSpecificCredentialOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateServiceSpecificCredential"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	f.nextCredID++
	id := "sscred-" + strconv.Itoa(f.nextCredID)
	rec := fakeSSC{id: id, service: awssdk.ToString(in.ServiceName), status: iamtypes.StatusTypeActive}
	if in.CredentialAgeDays != nil {
		exp := time.Unix(0, 0).UTC().Add(time.Duration(*in.CredentialAgeDays) * dayHours * time.Hour)
		rec.expires = &exp
	}
	u.sscs = append(u.sscs, rec)

	out := &iamtypes.ServiceSpecificCredential{
		ServiceName: in.ServiceName,
		UserName:    in.UserName,
		Status:      iamtypes.StatusTypeActive,
	}
	if !f.omitCredID {
		out.ServiceSpecificCredentialId = awssdk.String(id)
	}
	if f.credSecret != "" {
		out.ServiceCredentialSecret = awssdk.String(f.credSecret)
	}
	if rec.expires != nil && !f.omitExpiry {
		out.ExpirationDate = rec.expires
	}
	return &iam.CreateServiceSpecificCredentialOutput{ServiceSpecificCredential: out}, nil
}

func (f *fakeIAM) ListServiceSpecificCredentials(_ context.Context, in *iam.ListServiceSpecificCredentialsInput, _ ...func(*iam.Options)) (*iam.ListServiceSpecificCredentialsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListServiceSpecificCredentials"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	want := awssdk.ToString(in.ServiceName)
	var matching []fakeSSC
	for _, c := range u.sscs {
		if want == "" || c.service == want {
			matching = append(matching, c)
		}
	}
	from, to, truncated, next, err := f.page(len(matching), in.Marker)
	if err != nil {
		return nil, err
	}
	out := &iam.ListServiceSpecificCredentialsOutput{IsTruncated: truncated, Marker: next}
	for _, c := range matching[from:to] {
		out.ServiceSpecificCredentials = append(out.ServiceSpecificCredentials, iamtypes.ServiceSpecificCredentialMetadata{
			ServiceSpecificCredentialId: awssdk.String(c.id),
			ServiceName:                 awssdk.String(c.service),
			ExpirationDate:              c.expires,
			Status:                      c.status,
			UserName:                    in.UserName,
		})
	}
	return out, nil
}

func (f *fakeIAM) DeleteServiceSpecificCredential(_ context.Context, in *iam.DeleteServiceSpecificCredentialInput, _ ...func(*iam.Options)) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteServiceSpecificCredential"); err != nil {
		return nil, err
	}
	u, err := f.user(awssdk.ToString(in.UserName))
	if err != nil {
		return nil, err
	}
	id := awssdk.ToString(in.ServiceSpecificCredentialId)
	kept := u.sscs[:0]
	found := false
	for _, c := range u.sscs {
		if c.id == id {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	u.sscs = kept
	if !found {
		return nil, &iamtypes.NoSuchEntityException{Message: awssdk.String("no such credential")}
	}
	return &iam.DeleteServiceSpecificCredentialOutput{}, nil
}

func (f *fakeIAM) DeleteUser(_ context.Context, in *iam.DeleteUserInput, _ ...func(*iam.Options)) (*iam.DeleteUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteUser"); err != nil {
		return nil, err
	}
	name := awssdk.ToString(in.UserName)
	u, err := f.user(name)
	if err != nil {
		return nil, err
	}
	// IAM refuses while anything hangs off the user. Modelling that is what makes
	// an incomplete teardown a test failure instead of a silent pass.
	if len(u.attached)+len(u.inline)+len(u.keys)+len(u.sscs) > 0 {
		return nil, &iamtypes.DeleteConflictException{Message: awssdk.String("user still has children")}
	}
	delete(f.users, name)
	return &iam.DeleteUserOutput{}, nil
}

func remove(list []string, want string) []string {
	out := list[:0]
	for _, v := range list {
		if v != want {
			out = append(out, v)
		}
	}
	return out
}

// fakeSTS answers assume-role calls.
type fakeSTS struct {
	mu       sync.Mutex
	calls    []string
	attempts map[string]int
	fail     func(method string, attempt int) error
	// grantedTTL is how long a session lasts, from expiresFrom. Zero means
	// "whatever was asked for".
	grantedTTL  time.Duration
	expiresFrom time.Time
	// omit drops one field from the returned credentials, by name.
	omit string
	// nilCredentials returns success with no credentials at all.
	nilCredentials bool
	// lastWebIdentityToken is what the last web-identity call presented.
	lastWebIdentityToken string
	lastRoleARN          string
	lastSessionName      string
	lastDuration         int32
}

func newFakeSTS(now time.Time) *fakeSTS {
	return &fakeSTS{attempts: map[string]int{}, expiresFrom: now}
}

func (f *fakeSTS) enter(method string) error {
	f.calls = append(f.calls, method)
	f.attempts[method]++
	if f.fail == nil {
		return nil
	}
	return f.fail(method, f.attempts[method])
}

func (f *fakeSTS) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeSTS) credentials(requested int32) *ststypes.Credentials {
	if f.nilCredentials {
		return nil
	}
	ttl := f.grantedTTL
	if ttl == 0 {
		ttl = time.Duration(requested) * time.Second
	}
	exp := f.expiresFrom.Add(ttl)
	out := &ststypes.Credentials{
		AccessKeyId:     awssdk.String("fake-access-key-id"),
		SecretAccessKey: awssdk.String("fake-secret-access-key"),
		SessionToken:    awssdk.String("fake-session-token"),
		Expiration:      &exp,
	}
	switch f.omit {
	case "AccessKeyId":
		out.AccessKeyId = nil
	case "SecretAccessKey":
		out.SecretAccessKey = nil
	case "SessionToken":
		out.SessionToken = nil
	case "Expiration":
		out.Expiration = nil
	}
	return out
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("AssumeRole"); err != nil {
		return nil, err
	}
	f.lastRoleARN = awssdk.ToString(in.RoleArn)
	f.lastSessionName = awssdk.ToString(in.RoleSessionName)
	f.lastDuration = awssdk.ToInt32(in.DurationSeconds)
	return &sts.AssumeRoleOutput{Credentials: f.credentials(f.lastDuration)}, nil
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("AssumeRoleWithWebIdentity"); err != nil {
		return nil, err
	}
	f.lastRoleARN = awssdk.ToString(in.RoleArn)
	f.lastSessionName = awssdk.ToString(in.RoleSessionName)
	f.lastDuration = awssdk.ToInt32(in.DurationSeconds)
	f.lastWebIdentityToken = awssdk.ToString(in.WebIdentityToken)
	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: f.credentials(f.lastDuration)}, nil
}

// fakeTokens is a WebIdentityTokenSource.
type fakeTokens struct {
	token    string
	err      error
	subjects []string
	audience []string
	ttls     []time.Duration
}

func (f *fakeTokens) WebIdentityToken(_ context.Context, subject, audience string, ttl time.Duration) (credentials.Secret, error) {
	f.subjects = append(f.subjects, subject)
	f.audience = append(f.audience, audience)
	f.ttls = append(f.ttls, ttl)
	if f.err != nil {
		return credentials.Secret{}, f.err
	}
	return credentials.NewSecret(f.token), nil
}

// apiError is an AWS API error with a code and a fault, as smithy models one.
type apiError struct {
	code  string
	fault smithy.ErrorFault
}

func (e apiError) Error() string                 { return "fake api error: " + e.code }
func (e apiError) ErrorCode() string             { return e.code }
func (e apiError) ErrorMessage() string          { return "fake api error message" }
func (e apiError) ErrorFault() smithy.ErrorFault { return e.fault }

// withStatus wraps err the way the SDK's HTTP transport does, so that a test
// drives the real response-error shape rather than a stand-in that agrees with
// this package's probe by construction.
func withStatus(status int, err error) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      err,
		},
		RequestID: "fake-request-id",
	}
}

// operationError wraps err the way the SDK wraps a transport failure: an
// OperationError with no API error and no HTTP response underneath.
func operationError(err error) error {
	return &smithy.OperationError{
		ServiceID:     "STS",
		OperationName: "AssumeRole",
		Err:           err,
	}
}

// A note on the marker this fake hands out, because it is the fixture's one
// opinionated choice.
//
// It is an offset into the list as it stands when the page is served. So a caller
// that deletes items between pages sees the enumeration shift under it and misses
// what moved down -- which is exactly what happened to the first version of
// teardown, and is why teardown now reads every page before deleting anything.
//
// The real IAM's marker is opaque and its behaviour under concurrent mutation is
// unspecified, so this models a weaker guarantee than AWS gives rather than a
// stronger one. Making the fake tolerant here would have hidden a defect that
// reaches production as a user that cannot be deleted.
