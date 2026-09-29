// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package fake implements the Compute provider interface in memory.
//
// It exists so the deploy path can be tested with no cloud account, no
// credentials, and no network — the property CI depends on, and the property an
// outside contributor with no AWS account depends on more.
//
// # It is an implementation, not a set of stubs
//
// Every port works. A resource ensured through this provider can be described,
// waited on, granted to a workload identity, read and written as that identity,
// scaled, and deleted, and the state persists in the [Store] it was constructed
// with. That is the difference that matters: a module test can assert on what
// happened rather than on which methods were called, and a stubbed provider
// cannot tell you that your deploy path leaves a bucket behind.
//
// The three types a caller touches:
//
//   - [Store] is the substrate. Two providers over one store address the same
//     resources, which is how a test checks that a second provider instance
//     finds what the first one created.
//   - [Config] is the operator configuration a real provider's constructor
//     takes: which placement names exist, which function runtimes are legal,
//     which certificates resolve, whether there is a platform ingress proxy, and
//     which capabilities to advertise. A subset of [AllCapabilities] is the
//     interesting configuration — the refusal path is where the bugs are.
//   - [Harness] is the substrate operations the interface deliberately does not
//     have: read as an identity, attempt an anonymous read, authenticate with an
//     admin password, stall a resource, dump what the provider rendered.
//
// # Failure injection
//
// [Harness.FailNext] queues an error for the next matching operation. Nothing
// across this interface is transactional, so a deploy that provisions a bucket, a
// database, and a service can fail in the middle and leave two of the three, and
// a module test needs to be able to produce that state. The source system's own
// tests do the same thing one AWS client at a time; this is the portable version.
//
// # Deliberate non-conformance
//
// [Config.Defects] makes this provider violate the contract on purpose, one
// invariant at a time. It is there because a conformance suite nobody has tried
// to defeat is an assertion rather than a gate: compute/conformance's checks are
// each shown to fail against the defect that violates them, in
// defects_test.go. Nothing in the normal provider path reads that field.
//
// # What it is not
//
// It is not a simulator of any substrate. Where a real provider would have a
// legal-size table, an eventual-consistency window, or a naming rule, this one
// has whatever was needed to make the corresponding contract branch reachable.
// A test that depends on a detail of this provider's own behaviour — the exact
// physical name, the URI scheme, the rounding step — is testing the fake.
//
// Written for USOSS-16.
package fake
