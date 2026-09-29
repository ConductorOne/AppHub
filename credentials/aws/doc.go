// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package aws vends credentials using AWS-native STS and IAM.
//
// This is a fully supported, CI-tested credential path, not a reference
// example: it is what an adopter with nothing but an AWS account uses. Ported
// by USOSS-9, which also removes the hardcoded account identifiers present in
// the internal implementation.
//
// # What it vends
//
// Two credential types, and the operator chooses which of them exist by
// configuring them. Neither is offered by default, because a credential type
// nobody configured is a credential type nobody reviewed.
//
//   - A dynamic credential is a Bedrock bearer token: a presigned STS
//     GetCallerIdentity request, base64-encoded, in the format
//     aws-bedrock-token-generator produces. It is minted from a role this
//     provider assumes, so its privileges are the role's and not the platform's.
//   - A static credential is a dedicated IAM user carrying an operator-named
//     policy and an operator-named permissions boundary, plus a Bedrock
//     service-specific credential on that user.
//
// # Every identifier is configuration, and none has a default
//
// The internal implementation compiled in an IAM path naming the internal
// project, an AWS managed-policy ARN, a fallback resource-name prefix, and a
// fallback region. Each is now a required field on [Config] with no default, and
// an unset one is refused at construction rather than filled in. That is the
// whole point of the ticket: a default that happens to be right for one
// deployment is an identifier belonging to that deployment, compiled into a
// public repository.
//
// # Where it fails closed and the source failed open
//
// Every difference is listed on [Provider], with the source line it changes.
// The load-bearing one: the source presigned with the platform's own ambient
// credentials when no role was configured, so a requester received a Bedrock
// token carrying the platform's privileges. A role is now required.
package aws
