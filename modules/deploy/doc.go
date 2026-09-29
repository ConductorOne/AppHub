// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package deploy implements the deploy module: it takes an application
// specification and realises it on a compute provider.
//
// # The claim this package exists to make
//
// The deploy module is the primary consumer of the Compute provider interface
// ([github.com/conductorone/apphub/compute]) and must not reach for a cloud SDK
// directly; every cloud call goes through a provider. That is not a convention
// held in review: `make boundary` fails the build if any package under
// modules/deploy acquires a dependency path — direct, transitive, in a test, or
// behind a build constraint no supported configuration selects — outside a
// short list of permitted prefixes.
//
// Two rules enforce it, and they are different claims rather than two
// spellings of one:
//
//   - "deploy-imports-are-an-allowlist" names everything this package may
//     reach — the compute interface, the credential vocabulary, the module
//     framework, and the standard library — and forbids the rest. It is the
//     one that is right about the next substrate as well as this one.
//   - "deploy-is-substrate-free" names github.com/aws, k8s.io and sigs.k8s.io
//     specifically, so that the most likely violation gets a message saying
//     what it is and why the interface exists.
//
// The allowlist exists because review defeated the denylist on its own: a
// compileable import of a cloud SDK from a fourth vendor passed, because a
// denylist is blind to a population that does not exist yet. Adding a fourth
// prefix would have closed that spelling and left the defect.
//
// Its membership test is the toolchain's, not a pattern: what counts as
// standard library comes from `go list std` over the supported platforms.
// Review defeated the pattern version too, with a locally replaced module named
// `cloud` — a module path may have no dot in its first element when nothing has
// to fetch it. See the "deploy-imports" rules in internal/boundary and
// internal/boundary/deployfence_test.go, which plants both.
//
// The fence is stated over substrates rather than over AWS on purpose. A deploy
// module that swapped one SDK for another would have failed the ticket just as
// thoroughly, and a rule that only named AWS would have said so too late.
//
// # A record is refused before anything is created
//
// [newPlan] performs every refusal an application record can provoke, and
// [Module.Execute] calls it — and preflights the application's secret bindings
// against the provider, which is a metadata read and never a value — before its
// first write and before its first mutating provider call. That ordering is the contract, not an implementation detail:
// a rejected plan that partially applies leaves real infrastructure nobody
// asked for and nothing recorded, and returns an error that does not describe
// what was created. See applicability.go for the rule that keeps it true as
// fields are added.
//
// # What is here and what is not
//
// This package holds orchestration and translation, and nothing else:
//
//   - [Application] is the deploy module's own view of an application record.
//     It is not a database row; [Store] is the port a caller implements over
//     whatever it keeps them in.
//   - [Plan] is the pure translation from an [Application] plus a [Config] to
//     the [github.com/conductorone/apphub/compute] specifications that realise it.
//     It performs no I/O, so the interesting half of this package is testable
//     without a provider at all.
//   - [Module] walks a [Plan] against an injected [github.com/conductorone/apphub/compute.Provider].
//
// Three source responsibilities remain deliberately elsewhere or absent:
//
//   - Fetching the application source. [SourceFetcher] is an interface this
//     package declares and does not implement: cloning a git repository means
//     process execution and version-control credentials, neither of which
//     belongs in a package whose whole point is that it talks to one
//     abstraction. [ValidateSourceURL] stays here, because refusing a source
//     location is a decision this module has to make before it hands one to
//     anybody.
//   - Creating Postgres roles and loading initial data remain application
//     responsibilities. Requested extensions are different: deployment must
//     install them before starting the workload. [ExtensionInstaller] crosses
//     the SQL seam after the Compute provider reports a ready endpoint, with
//     temporary control-plane ingress removed when installation completes.
//   - The ConductorOne cross-account datasource role. ConductorOne is optional
//     in this repository and only credentials/c1 may depend on it, so a
//     c1-specific grant cannot live in the deploy module. See the decision
//     record.
//
// # Configuration carries every identifier
//
// [Config] has no defaults for anything that names a deployment: the resource
// prefix, the DNS suffix routes are published under, and the source hosts a
// repository may be fetched from are all supplied by an operator and refused
// when absent. The code this was ported from compiled in an internal DNS
// suffix, three cross-account role identifiers, and a resource prefix; none of
// them are here, and none of them may come back.
package deploy
