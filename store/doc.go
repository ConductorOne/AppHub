// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package store is the single boundary between AppHub and its persistence
// layer.
//
// v1 ships on DynamoDB. That is a deliberate, documented limitation, not a
// cloud-agnostic storage abstraction: the general abstraction is deferred, and
// nothing in this repository should claim otherwise. What this package buys is
// containment — every DynamoDB call in the codebase is behind this fence, so
// the eventual second backend is a rewrite of one package rather than a hunt
// through all of them.
//
// No package outside store may import a DynamoDB client (USOSS-5).
//
// # What the fence actually forbids
//
// The import rule is the half a tool can check trivially, and it is not the
// interesting half. The rule that matters is: nothing outside this package may
// be able to tell which database is underneath. Concretely, none of the
// following may cross the boundary, whether or not the SDK is imported:
//
//   - `dynamodbav` struct tags. The storage shape is credentialItem, which is
//     unexported. lifecycle.Record has no tags and never will.
//   - Hand-written expression strings ("PK = :pk AND begins_with(SK, :sk)").
//     The source system had 1,963 DynamoDB references and not one use of the
//     SDK's expression builder; every query was a string. All of those strings
//     live in this package.
//   - Partition and sort keys, GSI names, GSI1PK/GSI1SK.
//   - Pagination cursors (ExclusiveStartKey, LastEvaluatedKey). A caller that
//     threads a cursor is implementing DynamoDB's paging model; the methods here
//     paginate internally and return whole results.
//
// # Persisted instants
//
// One invariant, stated once because three separate defects in this package were
// the same defect:
//
//	Every instant this package persists is stored in a form whose lexical order
//	is its temporal order.
//
// DynamoDB compares strings bytewise and has no idea they are times, so a range
// filter over timestamps is only correct if the encoding makes byte order
// chronological. It did not, three times: a variable-width fractional part, the
// same in a sort key, and an expiry written in a +14:00 zone that sorted a year
// above a UTC bound and so was never swept at all -- a credential that had
// expired and that the platform believed live indefinitely. The first two were
// patched case by case, which is exactly how the third survived.
//
// store/instant.go holds the encoding and the property test. Nothing here writes
// a timestamp any other way.
//   - The SDK's error types. A condition failure becomes lifecycle.ErrConflict
//     or lifecycle.ErrNotFound before it leaves.
//
// Both halves are enforced by `make boundary`: internal/boundary holds the
// import rules and the idiom rule, and each has fixtures that fail before the
// rule exists and pass after. The import half reads the dependency graph; the
// idiom half reads the source, because a struct tag needs no import to couple a
// type to DynamoDB. The idiom half matches computed values rather than source
// spelling -- literals unquoted, concatenations and constant fmt.Sprintf calls
// folded -- after review defeated the spelling-based version with an escaped tag
// and an assembled expression. See internal/boundary/idiom.go for what that
// still cannot reach.
//
// # What a v2 storage interface would have to replace
//
// The port to a second backend is not "implement an interface". It is:
//
//  1. Reimplement lifecycle.Records. That interface is the contract, and it is
//     declared by its consumer (credentials/lifecycle) rather than here, so it
//     names no DynamoDB concept. Nine behaviours, all pinned by the conformance
//     suite in credentials/lifecycle/lifecycletest — a second implementation is
//     checked for agreement, not merely for compilation.
//  2. Provide optimistic concurrency. Record.Revision is the whole mechanism
//     preventing a scheduler pass from overwriting an operator's revoke. Here it
//     is a conditional write; a backend without compare-and-set needs a
//     transaction or a row lock, and must still return ErrConflict rather than
//     silently winning.
//  3. Decide what ListExpiring scans. See the note on scanPages: three of these
//     queries are full-table Scans with filters, inherited from the source. A
//     relational backend would index status and expiry instead. Because
//     lifecycle.Records does not encode the Scan, that is this package's
//     business and nobody else's.
//
// What a v2 implementation would find awkward, stated plainly rather than
// discovered later: nothing in the interface promises transactions across
// records, so an implementation cannot be asked for them, but neither can a
// caller that eventually needs them get them without changing the port. The
// interface is per-record by construction, which is DynamoDB's shape.
//
// # DynamoDB constraints that leak into business logic
//
// These are places where the database's limits have shaped code outside this
// package. They are recorded here because the fence cannot contain them — a size
// limit is a fact about the storage that callers have to respect — and a v2
// backend would want to revisit each one.
//
//   - Item size, 400 KiB. In the source system this bounds an agent's patch
//     payload: modules/security/agent_fix.go:88-100 caps a fix at 350 KiB total
//     specifically so the JSON-encoded diff fits in one row's attribute after
//     escaping overhead, and the comment records that a larger cap previously
//     made the write fail silently. modules/fix is ported by USOSS-17, which
//     inherits the constraint and should carry the reason with it.
//   - No record stored by this package approaches that limit today: the
//     annotation allowlist bounds the only open-ended field on a credential
//     record (16 keys, 512 bytes each — see lifecycle.AnnotationRegistry).
package store
