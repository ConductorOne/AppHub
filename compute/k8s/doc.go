// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package k8s implements the Compute provider interface on Kubernetes.
//
// # What this is
//
// A Kubernetes provider in two parts, built by two tickets, and it is worth
// knowing which is which.
//
// USOSS-27 built the translation: every place the compute contract and the
// Kubernetes API disagree, plus a narrow [Cluster] seam and an in-memory
// implementation of it. Its purpose was to falsify package compute while the
// interface was still cheap to change — a capability only AWS can satisfy is a
// design bug in compute, and writing a second implementation is how that shows
// up. It found twenty-five such places and five amendment rounds came out of it.
//
// USOSS-19 made it a provider you can point at a cluster: [ClientCluster], a
// client-go implementation of the seam; [Watcher], so a wait blocks on a change
// rather than re-reading on a timer; seams for the registry and the object store
// so the in-memory ones stop being the only implementation possible; and
// [S3ObjectStore], a real client for the one non-cluster substrate with a
// vendor-neutral API. What it deliberately did not build, and why, is in
// docs/DECISIONS.md.
//
// The in-memory implementations are kept rather than replaced. They are what run
// the conformance suite and every findings test with no cluster, no network and
// no port, and — more than that — [MemoryCluster] stores the objects the provider
// actually builds, so a translation bug shows up as a wrong object rather than as
// an unmet expectation on a mock.
//
// # Where a hermetic test stops being evidence
//
// Three things about this package are verified against a fake and are therefore
// assumptions about Kubernetes rather than facts about it. They are listed here
// because the distinction is worth more than a confident claim.
//
//   - **A fake cannot catch a resource-mapping error**, because it is addressed
//     by whatever resource name the code asks for and therefore agrees with the
//     mistake. That is why [StaticResolver] refuses an unmapped kind instead of
//     guessing one; see its documentation for the specific instance.
//   - **A fake watch firing is not a real API server firing.** client-go's fake
//     delivers an event on every write; a real cluster's Deployment status is
//     written by a controller this fixture does not run. If a real cluster is
//     stingier, the failure is a wait that runs to its deadline, not a wrong
//     answer — the poll fallback and the caller's deadline both still apply.
//   - **The object-store signer is not verified against a reference
//     implementation.** See [SigV4Signer].
//
// # What the provider is honest about
//
//   - It advertises [compute.CapWorkloadExec] while doing nothing for it, because
//     on this substrate a pod is exec-able whenever the caller's RBAC permits it.
//     That is an accurate answer for [compute.ServiceSpec.ExecEnabled] being
//     true and no answer at all for it being false; see the findings document.
//   - Its image-pull authorisation depends on operator configuration. With a
//     kubelet credential provider that forwards a pod-bound ServiceAccount token
//     and a registry that federates the cluster, a grant names the workload
//     identity and stores nothing; without them it has to mint and attach a
//     credential. Both routes are implemented, because the difference between
//     them is a finding rather than a detail.
//   - A "Kubernetes provider" that satisfies every port is four substrates, not
//     one: a cluster, an OCI registry, an S3-compatible object store, and a
//     Postgres operator. [Config] is the full list of what an operator supplies,
//     and it is worth reading as the answer to "what does this abstraction
//     actually require of a non-AWS platform".
//
// # What it declines, and why
//
// A refusal here is a whole capability, typed, named, and made at acquisition:
//
//   - [compute.CapKeyValueTable] — always. Nothing in or beside a cluster has
//     DynamoDB's consistency and capacity semantics, and a table backed by
//     something with different ones would corrupt data rather than fail.
//   - [compute.CapObjectStoreZonal] — always. No S3-compatible store surveyed
//     offers a single-zone class, and quietly returning a standard bucket would
//     satisfy the signature while breaking the latency guarantee.
//   - [compute.CapModelInference] — always. There is no cluster-native managed
//     foundation-model service for a ServiceAccount to be granted access to.
//   - [compute.CapFunction] — unless the operator configures runtime images.
//     Kubernetes has no function runtime; this provider takes the design
//     document's second option, a Deployment wrapping the bundle, and says so in
//     [compute.Status.Message] because cold-start and cost behave differently.
//   - [compute.CapFunctionEndpoint] — unless the cluster has the Gateway API. A
//     networking.k8s.io Ingress cannot serve a caller-chosen port with a
//     caller-chosen certificate, which is what [compute.ListenerSpec] describes.
//   - [compute.CapImageRegistry], [compute.CapImageBuild],
//     [compute.CapObjectStore], [compute.CapRelationalDatabase] — unless the
//     operator configures the system that provides each.
//
// None of the ports here contains a stub that returns "unsupported" from a
// method the interface required it to have. Where writing one was the only
// option, that is recorded as a finding about the interface rather than worked
// around — see [imageRegistry], which is the clearest example.
//
// # The capability matrix
//
// What this provider does and does not support, per configuration, is in
// docs/design/capability-matrix.md — generated from the providers themselves by
// compute/matrix rather than written down, because a table about code that
// nothing checks stops being true.
//
// # The findings
//
// docs/design/k8s-contract-probe.md is the full list, with a proposed amendment
// for each and an evidence map saying what backs each one by name: 24 of the 25
// have an assertion in compute/k8s/findings_test.go or a named check in the
// conformance run, and one (the unspecified clock behind
// [compute.Status.UpdatedAt]) is analysis, because "unspecified" has nothing to
// assert against. Where the evidence is a test, an amendment that lands turns it
// red rather than leaving a stale claim in a document.
package k8s
