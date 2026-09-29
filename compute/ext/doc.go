// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ext holds capability ports that are NOT portable.
//
// # Read this before adding anything here
//
// Everything in package compute is a promise: implement the interface and your
// substrate works. Everything in this package is the opposite — an interface
// that exists because exactly one substrate has the feature, and the
// application ecosystem being ported uses it. Nothing here promises that a
// second implementation is possible, and for some of it a second
// implementation is known not to be.
//
// The package exists because the alternative is worse. There are three ways to
// handle a feature only one cloud has:
//
//  1. Put it in the core interface. Then every provider must implement it, and
//     the ones that cannot return errors from a method the contract says they
//     support. "Multi-cloud" becomes a claim the type system makes and reality
//     does not.
//  2. Put it in compute/aws and let the deploy module import that package.
//     Then the module depends on a provider and the abstraction is decorative.
//  3. Put it in a provider-neutral package that says, in its name and in its
//     documentation, that it is not portable, and make consumption an explicit
//     type assertion that can fail.
//
// This is (3). A module may import this package; what it may not do is assume
// the assertion succeeds.
//
// # The rules
//
//   - **Who may import this package is an allowlist, not a convention.** The
//     "ext-is-optional" rule in internal/boundary fences it, so widening the
//     set of packages that can reach an AWS-shaped port is a build failure
//     until somebody edits that allowlist in a diff a reviewer sees. Prose
//     cannot stop a package from importing this one; the boundary checker can.
//   - **The ports are a closed, reviewed set**, and it is short on purpose:
//     [TableBucketProvisioner], [VectorBucketProvisioner], and
//     [ExternalAccessGranter]. Adding a fourth is a design decision with the
//     same weight as adding a capability to package compute, and it should
//     carry the same justification: which single substrate has the feature,
//     why the application-facing contract cannot be met portably, and what an
//     adopter loses by going without it.
//   - Core deploy logic must treat every port here as optional. Reaching one is
//     always a lookup that can fail, and the failure must surface to the
//     operator as "your provider cannot do this", not as a crash or a silent
//     skip.
//   - A provider implements a port here only if its substrate has the feature
//     natively. Emulating an S3 Tables bucket over a filesystem to make a test
//     pass is how a fake abstraction ships.
//   - No identifier belonging to any particular deployment appears here. Every
//     account, role, principal, and endpoint is a caller-supplied value with no
//     default.
//   - Nothing here is required for an application to deploy. An adopter running
//     apphub on a substrate that implements none of it gets a working system
//     with fewer optional features.
package ext
