// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package workload is the boundary between compute and credentials for workload
// identity: how a deployed application proves who it is and gets a short-lived
// token it can use to ask for credentials.
//
// It exists because that concern is currently smeared across both layers. In the
// source system, deploying an application makes the compute layer inject a
// rotating signature and a token endpoint into the container
// (backend/internal/modules/deploy/container.go:696-712), and the running
// application then calls AWS STS GetCallerIdentity, presigns the request, and
// exchanges it plus that signature for a platform-issued OIDC JWT
// (backend/internal/services/workload.go:246-340). So a credential concern is
// wired into compute, and an AWS API call is a runtime dependency of every
// deployed app -- including apps that have nothing to do with AWS.
//
// The shapes in this package are normative. They implement
// /shared/apphub/contracts/workload-identity.md, a supervisor-owned contract
// written after this design and the parallel compute design were found not to
// compose: the same name meant "expected policy" on one side and "submitted
// evidence" on the other, the two packages coined different identifiers for the
// same AWS scheme, and the verifier could not receive what the other side stored.
// This package is the single home of the vocabulary and compute imports it. If
// something here looks wrong, raise it against that contract rather than
// improving it locally -- a unilateral improvement to a shared boundary is what
// caused the incompatibility.
//
// The split this package defines:
//
//   - The credential layer owns identity. It verifies an AttestationProof against
//     the ExpectedAttestation the deploy layer stored, and mints the token.
//     Verifier and TokenIssuer live here; their AWS implementations (STS replay,
//     KMS-backed signing) live in credentials/aws.
//
//   - The compute layer owns delivery, and nothing else. It calls Rotate then
//     Materials and injects the result: environment variables verbatim, secrets by
//     reference into whatever secret mechanism the platform has. It does not read
//     a secret's value, does not know what any of them mean, and never calls a
//     credential API. A compute provider with no AWS in it delivers AWS-shaped
//     materials without noticing.
//
//   - The deploy layer owns two things neither package may take: persisting a
//     workload's ExpectedAttestation, and converting a credentials.SecretRef into
//     the compute provider's own secret binding. Only the deploy layer knows which
//     compute provider is in play, so only it can validate that a named store
//     belongs to that provider.
//
// The contract in one sentence: compute moves opaque bytes into a workload's
// environment; credentials decides what those bytes are and what they are worth.
//
// Designed in USOSS-3; reconciled with USOSS-2 by the normative contract named
// above, which is authoritative over both.
package workload
