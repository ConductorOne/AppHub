// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package compute defines the provider-agnostic interface that application
// modules use instead of a cloud SDK.
//
// # What this replaces
//
// In the source system every deploy function takes an `aws.Config` or a
// concrete AWS client. Those parameters are the seam. A module that wants to
// run a container reaches for ecs.RegisterTaskDefinition; a module that wants
// the container to talk to its database reaches for
// ec2.AuthorizeSecurityGroupIngress. The cloud's shape is the program's shape.
//
// Here a module asks for what an application needs — run this image as a
// service, expose it on a URL, give me an object store, give me a Postgres
// endpoint — and a provider decides how. IAM roles, trust policies, security
// groups, subnets, VPCs, parameter-store paths, ARNs, and task definitions are
// provider implementation details. None of them appear in this package, and a
// method named after one is a design failure.
//
// # Shape
//
// [Provider] is the root. It reports a [CapabilitySet] and vends one port per
// capability; asking for a capability a provider does not have returns an
// error that wraps [ErrUnsupported] rather than a nil interface. The ports are:
//
//   - [ImageRegistry] and [ImageBuilder] — publish and build container images.
//   - [ContainerRuntime] — run an image as a replicated service or on a schedule.
//   - [FunctionRuntime] — run a code bundle as a function, optionally behind a URL.
//   - [ObjectStore] — buckets.
//   - [RelationalProvisioner] — managed SQL endpoints.
//   - [KeyValueProvisioner] — managed key-value tables.
//   - [SecretStore] — named secret material, bindable into a workload.
//
// Provisioning calls are named Ensure* and are idempotent and declarative: the
// spec you pass is the desired state, and calling twice with the same spec
// converges rather than conflicts. For the asynchronous ports, Ensure* never
// blocks on the resource becoming ready — it returns a status whose [Phase] may
// be [PhasePending], and the caller decides whether to wait, with a timeout it
// chooses. [Status] says which ports those are and why the rest differ.
//
// # Deliberate non-goals
//
// This package does not abstract persistence (see store/), credential vending
// (see credentials/), log aggregation, metrics, DNS registration, or cost.
// It does not model network egress. It does not promise that two providers
// produce equivalent security postures for the same spec — see
// docs/design/compute-provider.md, "What this abstraction does not make
// portable", which is required reading before implementing a provider.
//
// # Rules for implementations
//
//   - Nothing in this package may import an implementation. Providers live in
//     compute/aws, compute/fake, compute/k8s and are wired only in cmd/.
//   - A [Ref] issued by one provider is meaningless to another; a provider that
//     is handed a foreign Ref must return [ErrForeignRef], not guess.
//   - Credential material crosses this boundary only as [SecretValue] or by
//     reference in a [SecretBinding]. No error, log line, or status field may
//     contain a secret.
//   - The workload-identity vocabulary is owned by credentials/workload and
//     imported here. This package must not define a parallel version of it; two
//     definitions is the specific failure the shared contract exists to prevent.
//     See [WorkloadIdentity].
//   - A capability that only one substrate can satisfy does not belong here.
//     It belongs in compute/ext, which promises nothing.
//
// Designed by USOSS-2.
package compute
