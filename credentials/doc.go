// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package credentials defines the CredentialProvider interface and the
// registry that resolves a credential request to a provider.
//
// Providers live in subdirectories, and this package imports none of them.
// Four are planned for v1, and two of the four exist today:
//
//   - credentials/datadog (Datadog API keys, static only) and
//     credentials/github (GitHub App installation tokens, dynamic only) are
//     implemented and exercised by CI. Neither needs a ConductorOne account.
//   - credentials/aws (native STS/IAM vending) is a package comment and nothing
//     else at this commit; USOSS-9 implements it.
//   - credentials/c1 (ConductorOne-backed vending, dynamic only) is implemented
//     and exercised by CI against a stubbed transport. It is the only one that
//     requires a ConductorOne account, and the only one no test in this repository
//     has ever run against the real thing.
//
// "Planned for v1" is the claim being made here. An earlier version of this
// comment said all four were supported and CI-exercised, which was true of
// neither of the two that did not exist.
//
// This package is only the vending half of the contract: a provider mints
// material and forgets it. Everything about a credential afterwards -- what the
// platform remembers, when it expires, who revokes it -- is in
// credentials/lifecycle, and the boundary between compute and workload identity
// is in credentials/workload. The whole contract, including the ConductorOne
// wire protocol and the assumptions it rested on, is written down in
// docs/design/credential-vending.md, whose §9 records how each of those
// assumptions turned out once USOSS-8 checked them.
//
// This package must never import a provider that requires a ConductorOne
// account. An adopter with no ConductorOne account must be able to build and
// run AppHub, so the c1 provider is registered by the caller that wants it,
// not by this package.
//
// That requirement is unconditional, and since USOSS-28 the mechanical guard
// behind it is no longer an enumeration of build configurations: internal/boundary
// builds a union import graph, parsing every Go file with every build constraint
// ignored, so a boundary violation reachable under any tag set is reported with
// the transitive chain that reaches it. See the package comment in
// internal/boundary, and `make boundary`.
//
// Credential material must never be logged, never appear in an error message,
// and never be written to disk outside an explicit, documented secret store. The
// Secret type makes the accidental cases fail closed rather than fail open; read
// its doc comment for what that does and does not cover, because it is a
// guardrail and not a vault.
//
// Interface, registry and contract types landed by USOSS-3; the cloud-neutral
// providers by USOSS-7; the AWS ones by USOSS-9.
//
// Three of the source system's providers are deliberately absent, and the
// interface is wider than what remains on purpose. See
// docs/design/credential-vending.md section 10: excluding a provider must not
// narrow the contract, because narrowing it would make a whole category of
// provider unimplementable by anyone outside this repository.
package credentials
