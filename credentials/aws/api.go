// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// This file is the only place in the package that names an AWS SDK operation.
// Everything above it is the same code whether it is running against an account
// or against the in-package fake.
//
// # The interfaces are unexported, and that is the load-bearing half
//
// It is store/dynamo.go's fence applied to a second service pair, for the same
// reason: an exported interface over IAM would be an IAM abstraction with a
// different name, and the SDK types in its signatures would be back in whatever
// package accepted one. Unexported means the only implementations are the real
// clients and this package's own test double.
//
// # Retry configuration belongs to whoever builds the clients
//
// This package does not touch it, and the reason is compute/aws/awssdk.go:38-73
// rather than a preference: four attempts to own or to guard retry behaviour on
// an SDK client were each defeated by a different disable path, and the set of
// disable paths is neither closed nor ours to close. So the clients arrive built.
//
// The consequence, stated rather than defended: a caller who disables retry on
// these clients gets a provider that does not retry, and a throttling failure is
// still classified transient -- see fault.go, which classifies from the error and
// never from the client that produced it.

// stsAPI is the slice of STS this package calls for a session.
//
// PresignGetCallerIdentity is deliberately not here. A presign is a local
// signature computation against a specific set of session credentials, so it
// cannot come from a client built at construction time -- the credentials it must
// sign with do not exist until the assume-role call returns. See presign.go.
type stsAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// iamAPI is the slice of IAM this package calls.
//
// The list-and-delete operations are here because a static credential is an IAM
// user, and an IAM user cannot be deleted while anything hangs off it. Three of
// them are paginated in the real API, which the source's teardown did not
// account for -- see static.go.
type iamAPI interface {
	CreateUser(context.Context, *iam.CreateUserInput, ...func(*iam.Options)) (*iam.CreateUserOutput, error)
	ListUserTags(context.Context, *iam.ListUserTagsInput, ...func(*iam.Options)) (*iam.ListUserTagsOutput, error)
	AttachUserPolicy(context.Context, *iam.AttachUserPolicyInput, ...func(*iam.Options)) (*iam.AttachUserPolicyOutput, error)
	DetachUserPolicy(context.Context, *iam.DetachUserPolicyInput, ...func(*iam.Options)) (*iam.DetachUserPolicyOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	DeleteUserPolicy(context.Context, *iam.DeleteUserPolicyInput, ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
	CreateServiceSpecificCredential(context.Context, *iam.CreateServiceSpecificCredentialInput, ...func(*iam.Options)) (*iam.CreateServiceSpecificCredentialOutput, error)
	ListServiceSpecificCredentials(context.Context, *iam.ListServiceSpecificCredentialsInput, ...func(*iam.Options)) (*iam.ListServiceSpecificCredentialsOutput, error)
	DeleteServiceSpecificCredential(context.Context, *iam.DeleteServiceSpecificCredentialInput, ...func(*iam.Options)) (*iam.DeleteServiceSpecificCredentialOutput, error)
	DeleteUser(context.Context, *iam.DeleteUserInput, ...func(*iam.Options)) (*iam.DeleteUserOutput, error)
}

// presignAPI is the local signature computation that produces a Bedrock bearer
// token. It makes no network call.
type presignAPI interface {
	PresignGetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// Compile-time proof that the real clients satisfy the slices above. Without
// these the fake would be the only implementation the compiler ever checked, and
// a signature that drifted from the SDK would be discovered by a caller.
var (
	_ stsAPI     = (*sts.Client)(nil)
	_ iamAPI     = (*iam.Client)(nil)
	_ presignAPI = (*sts.PresignClient)(nil)
)
