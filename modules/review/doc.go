// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package review implements the review module: an agent-driven scan that
// inspects a repository snapshot and reports security findings.
//
// Ported by USOSS-17 from the source repository's
// backend/internal/modules/security/agent_scan.go, alongside its sibling
// modules/fix.
//
// # What the module does and does not do
//
// [Module.Execute] is an orchestrator. It validates its parameters, marks the
// scan running, fetches a snapshot of the repository, hands the in-memory tree
// to a [Scanner], normalises what comes back, and writes the result to a
// [ResultStore]. It contains no detection logic of its own: which patterns
// count as a finding is entirely the [Scanner] implementation's business, and
// nothing in this package describes one. That is deliberate on two counts --
// it is what lets an adopter bring a different model provider, and a published
// detection heuristic is a published bypass guide. docs/decisions/ records
// both, under USOSS-17.
//
// # What this package will not accept
//
// No credential material crosses this boundary. The source module minted a
// GitHub installation token and passed it to the tarball download; here the
// [SourceFetcher] authenticates itself from the [Coordinates] it is given, so
// there is no token, header, or key for this package to hold, log, or leak.
// The obligation is met by construction rather than by care.
//
// Nothing here reaches a cloud SDK, a store, or a service layer. Persistence
// arrives as [ResultStore], the AI provider as [Scanner], and the repository as
// [SourceFetcher] -- three interfaces this package declares and whose
// implementations live with the caller. portability_test.go checks that by
// reading the tree rather than by convention.
package review
