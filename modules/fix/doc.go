// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package fix implements the fix module: an agent-driven remediation pass that
// acts on one finding produced by modules/review and, when it can, opens a
// draft pull request against the repository the finding came from.
//
// Ported by USOSS-17 from the source repository's
// backend/internal/modules/security/agent_fix.go, alongside its sibling
// modules/review.
//
// # The flow
//
// One execution is one attempt at one finding:
//
//  1. Read the completed scan and take the finding at the requested index.
//  2. Fetch the repository snapshot at the scan's revision, so the agent
//     validates against the same tree the scan saw and not a later one.
//  3. Ask the [Fixer] whether the finding is real. Anything other than
//     [VerdictReal] is terminal: the record is finalised and no pull request
//     is opened.
//  4. Ask the [Fixer] for a patch, then check it against [Limits] --
//     file count, line count, per-file bytes, encoded size, and the protected
//     paths -- before any write leaves this process.
//  5. Push it: resolve the base branch, read its commit's tree, create a blob
//     per file, a tree, a commit and a ref, then open the pull request as a
//     draft and label it.
//  6. Record the branch, commit and pull request on the record.
//
// # This package writes to other people's repositories
//
// That is the whole reason for the shape of [Limits] and for the protected
// paths in caps.go. Everything the [Fixer] returns was produced by a model
// reading a repository this process does not control, so it is untrusted input
// that is about to become a commit. Two things follow, and both are load
// bearing: every cap is checked before the first write, and the pull request
// is opened as a draft so a person is between the agent and the main branch.
//
// The pull request body is assembled from the same untrusted text, so every
// piece of it is written inside a fence sized to the content -- see
// writeFencedBlock in pr.go. A model that emits a mention, a task list or a
// fence of its own gets those rendered as the characters it wrote.
//
// # This package holds no credentials
//
// [GitClient] and modules/review's SourceFetcher authenticate themselves from
// the [review.Coordinates] they are handed. No token, header or key crosses
// this boundary, so there is none here to log, store or leak.
package fix
