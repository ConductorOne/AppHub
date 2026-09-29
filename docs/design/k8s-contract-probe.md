<!--
Copyright 2026 ConductorOne, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# The Kubernetes contract probe — findings against the Compute interface

**USOSS-27.** This document is the output of implementing every port of
`compute.Provider` on Kubernetes and running the USOSS-16 conformance suite
against it. The provider is in `compute/k8s`.

**24 of the 25 findings have an executable assertion**, in
`compute/k8s/findings_test.go` or as a named check in the conformance run; the
twenty-fifth (F23) is analysis. [Evidence map](#evidence-map) says which is
which, per finding, by name. Where the evidence is a test, an amendment that
lands turns it red rather than leaving a stale claim here.

**That count and that map are checked by the build**, by three tests in
`compute/k8s/findings_test.go`:

* `TestFindingsDocumentNamesOnlyRealTests` fails if anything in this document
  names a test function that does not exist in the package these verifier tests
  are themselves compiled into.
* `TestEvidenceMapCoversEveryFinding` pins the map's shape — one row per finding,
  F1 through F25, in order; every row either names a real test or is marked
  `analysis` and names none — and derives the figure in the sentence above from
  the table, so the two cannot disagree.
* `TestFindingEvidenceIsBoundToItsRow` ties each finding's *section* to its row:
  a section may cite only evidence its row records, and an `analysis` row must
  have a section that cites none.

All three state, in their own comments, the three things they cannot check.

That machinery exists because this document got it wrong repeatedly, in a
widening pattern worth recording rather than quietly repairing. Each artefact was
correct about the previous failure and had a seam one level out:

1. Revision 1 claimed all twenty-five findings had an executable assertion.
   Fifteen tests existed.
2. Revision 2 fixed that with the evidence map — and the map contained a false
   row. F25 named a test an editing mistake had deleted from the file. *The
   artefact built to stop an evidence overclaim contained an evidence overclaim*,
   because a map from claims to evidence is itself a claim and nothing was
   checking it against the package.
3. Revision 3 made the map checkable — and the checker had two seams of its own.
   It collected test functions from every `.go` file in the directory without
   reading the package clause, so a row could name a `package k8s` function while
   the findings tests are `package k8s_test` and `go test` would never run it.
   And the name scan was global rather than per-row, so a finding marked
   `analysis` could cite a real test in its own prose: the table and the text
   beside it disagreeing, which is the drift the map exists to prevent, moved one
   paragraph over.
4. Revision 4 binds both — to package identity, and to the row.

The lesson generalises past this document, and is the project's most-repeated
shape: the answer is **bind the thing to its subject**, not check harder. A
checker scoped to a directory rather than a package, or to a document rather than
a claim, will be defeated by whatever is in scope and not in subject.

Revision 1 also stated F1 more universally than its evidence supported. All of
it was caught in review of PR #11 and is corrected below. The corrections are
marked rather than folded in, because a claim stated more strongly than its
evidence is the defect class this probe exists to find in the interface, and it
is not more excusable for appearing in the probe.

The probe is a compile-and-conformance exercise, per the ticket: no cluster is
required, the only `Cluster` implementation shipped is in-memory, and everything
above that seam is production translation code. What is being tested is whether
the *shape* fits.

**Result: it mostly does, and there are 25 places where it does not.** Two of
those (F1, F2) are the same class of defect as the two the PR #3 reviewer's
thought experiment found, and both are cheap to fix now and expensive to fix
after USOSS-10..14 and USOSS-26 have shipped six implementations against them.

---

## Summary

Severity is what the probe judged when it found the thing. **Status** is what
happened to it afterwards, in the USOSS-2 amendment that this probe's findings
produced (PR #12); the section reference is to
[`compute-provider.md`](compute-provider.md) §9, which records each change and
what was deliberately left open.

The column exists because "Blocker" reads as *open* blocker. Marking only the
findings whose tests changed would have left the other twenty implying they are
still outstanding — a new overclaim created by a partial fix, and one no verifier
here would catch, since none of them parses this table.

| # | Finding | Severity | Status | Amendment touches |
| --- | --- | --- | --- | --- |
| F1 | `ImageRegistry` embeds `Granter`, but whether that is a grant or a stored credential turns on configuration the interface cannot advertise | **Blocker** | Closed — `Granter` off the required port; `ImagePullGranter` behind a capability (§9.1) | `compute/image.go`, `compute/capability.go` |
| F2 | No transient/retryable error, and `ErrConflict` collides with the substrate's retryable 409 | **Blocker** | Closed — `ErrTransient`; `ErrConflict` renamed `ErrNotOwned` (§9.2) | `compute/errors.go` |
| F3 | `WorkloadIdentitySpec` and `SecretSpec` carry no `Placement`, but both are namespace-scoped | **Blocker** | Closed — `Placement` on both specs (§9.3) | `compute/identity.go`, `compute/secret.go` |
| F4 | `Route` has no TLS, so an application's own public hostname cannot be served encrypted | **Blocker** | Closed — `Route.TLS` and `Route.AllowPlaintext` (§9.4) | `compute/network.go` |
| F5 | `ListenerSpec` has no `Protocol` — confirmed against the substrate that has one | Should-fix | Closed — `ListenerProtocol` (§9.7) | `compute/function.go` |
| F6 | No `Describe` returns effective declarative state; Kubernetes makes the omission worse | Should-fix | Closed — every read-back carries its effective spec (§9.5) | all status types |
| F7 | No capability for "an ingress proxy is configured", nor for "the ingress can authenticate" | Should-fix | Closed — `CapPlatformIngress`, `CapIngressAuth` (§9.8) | `compute/capability.go` |
| F8 | Scheduled jobs are in the asynchronous class with nothing to wait for | Should-fix | Closed — port reclassified synchronous (§9.6) | `compute/database.go` class doc, `compute/container.go` |
| F9 | `ImageRegistry` has no read-back at all | Should-fix | Closed — `DescribeRepository` (§9.8) | `compute/image.go` |
| F10 | `ServiceSpec` has no readiness model, so `WaitForService`'s "serving" is provider-defined | Should-fix | Closed — `ServiceSpec.Readiness` (§9.8) | `compute/container.go` |
| F11 | `FunctionSpec` has no reachability field, and the invoke permission has nowhere to live | Should-fix | Closed — `FunctionSpec.Ingress`, invoke-ownership rule (§9.8) | `compute/function.go` |
| F12 | No egress model has a concrete consequence on a default-deny cluster | Should-fix | Closed by obligation — a provider MUST NOT restrict egress; `EgressRule` deferred (§9.8, §9.9) | `compute/network.go` |
| F13 | `ServiceStatus` reports no address for its `Route`s | Should-fix | Closed — `ServiceStatus.RouteAddresses` (§9.8) | `compute/container.go` |
| F14 | `EndpointSpec` has no hostname, so the provider names the endpoint | Should-fix | Closed — `EndpointSpec.Hostnames` (§9.8) | `compute/function.go` |
| F15 | `Resources` collapses requests and limits | Nit + doc | Closed by documentation — concession recorded (§9.8) | `compute/container.go` |
| F16 | `Labels` cannot be Kubernetes labels, so they stop being selectable | Nit + doc | Closed by documentation (§9.8) | several |
| F17 | `WorkloadIdentitySpec.RunsOn` has no meaning on this substrate | Nit + doc | Closed by documentation — `RunsOn` is advisory (§9.8) | `compute/identity.go` |
| F18 | `DeleteWorkloadIdentity` obliges a cross-substrate cascade with no mechanism | Should-fix | Closed — cascade narrowed to this provider's own ports (§9.8) | `compute/identity.go` |
| F19 | `FunctionSpec` has a Lambda `Handler` and no CPU allocation | Nit + doc | Closed — `FunctionSpec.Resources` (§9.8) | `compute/function.go` |
| F20 | `BuildSource.ContextDir` assumes the builder shares the caller's filesystem | Should-fix | Closed by obligation — transport stated; `Context`/`Exclude` deferred (§9.8, §9.9) | `compute/image.go` |
| F21 | `PeerInternet` is *wider* on Kubernetes than on a security group | Doc only | Closed by documentation (§9.8) | `compute/network.go` |
| F22 | `Provider` assumes one substrate; a Kubernetes provider is four | Doc only | Closed by documentation (§9.8) | `compute/provider.go` |
| F23 | `Status.UpdatedAt` has no specified clock — confirmed, Kubernetes has no such field | Doc only | Closed by documentation — the clock is specified (§9.8) | `compute/status.go` |
| F24 | `AccessLevel` has no third meaning on a registry | Nit + doc | Closed — `ImagePullGranter` carries no `AccessLevel` (§9.1) | `compute/identity.go` |
| F25 | `ServiceSpec.ExecEnabled` is a two-state field with one enforceable state | Should-fix | Closed by documentation (§9.8) | `compute/container.go` |

Everything the interface got right is in [What held up](#what-held-up), which is
the other half of an honest probe.

---

## Evidence map

What backs each finding, by name. `test` is a function in
`compute/k8s/findings_test.go`; `conformance` is a named check or a recorded
contract observation from a `conformance.Run`; `analysis` means there is no
mechanical assertion and the finding rests on reading the interface.

| # | Kind | Evidence |
| --- | --- | --- |
| F1 | test | `TestImagePullByWorkloadIdentityIsNotUniversal`, `TestLegacyPullObligationIsScopedToTheWorkloadsOwnImage` |
| F2 | test | `TestOptimisticConcurrencyIsTransient` |
| F3 | test | `TestIdentityAndSecretCannotCrossAPlacement` |
| F4 | test | `TestRouteFailsClosedWithoutOperatorTLSAndAuth` |
| F5 | test + conformance | `TestPlainClusterDeclinesFunctionEndpoints`; `security/tls-listener-requires-a-resolvable-certificate`. **The observation is gone**: the amendment added `ListenerProtocol`, so the certificate-less HTTPS listener the check could only describe is now representable, and the check asserts it. |
| F6 | test + conformance | `TestTheAmendedInterfaceClosedTheseFindings`. **The observations are gone**: every read-back carries its effective spec, so the suite records none of the seven. What replaced them is narrower than the amendment first claimed — see the section. |
| F7 | test + conformance | `TestRouteFailsClosedWithoutOperatorTLSAndAuth` (the auth half); `security/missing-ingress-proxy-is-an-error-not-an-open-port` (the proxy half). **Its observation is gone**: `CapPlatformIngress` exists, so the refusal is discoverable and the check requires capability and behaviour to agree. |
| F8 | test + conformance | `TestScheduledJobIsLiveOnAcceptance`. **The observation and the three skips are gone**: the port is in the synchronous class now, so there are no `port/scheduled-job/async/wait-*` checks to skip. |
| F9 | test + conformance | `TestTheAmendedInterfaceClosedTheseFindings`. **The observation and the skip are gone**: `DescribeRepository` exists, so there is no `NoReadBack` to record and `port/image-repository/sync/read-back-after-delete-is-not-found` runs instead of skipping. |
| F10 | test | `TestTheAmendedInterfaceClosedTheseFindings` |
| F11 | test | `TestFunctionReachabilityIsSplitAcrossTwoCalls` |
| F12 | test | `TestNoWorkloadPolicyRestrictsEgress` |
| F13 | test | `TestTheAmendedInterfaceClosedTheseFindings` |
| F14 | test | `TestTheAmendedInterfaceClosedTheseFindings` |
| F15 | test | `TestResourcesBecomeBothRequestsAndLimits` |
| F16 | test | `TestLabelsBecomeAnAnnotationAndStopBeingSelectable` |
| F17 | test | `TestRunsOnHasNoMeaningOnThisSubstrate` |
| F18 | test | `TestDeletingAnIdentityCascadesAcrossThreeSubstrates` |
| F19 | test | `TestFunctionCarriesALambdaHandlerAndADerivedCPU` |
| F20 | test | `TestBuildContextIsReadLocallyAndConfined` |
| F21 | test | `TestPeerInternetIsWiderHereThanASecurityGroup` |
| F22 | test | `TestOneProviderNameCoversFourSubstrates` |
| F23 | **analysis** | None. `Status.UpdatedAt`'s clock source is unspecified, and "unspecified" has no assertion: this provider uses a logical clock, an AWS provider will use `time.Now`, and both satisfy every check the suite can write. The finding is that two providers will differ and nothing catches it. |
| F24 | test | `TestPullGrantsHaveNoAccessLevel` |
| F25 | test | `TestExecEnabledIsOneWayOnThisSubstrate` |

Every finding's section below ends with a **Proposed amendment**. All of them
landed, in PR #12; the Status column in [Summary](#summary) says how, per finding.
The proposals are left as written rather than rewritten into the past tense,
because what the probe proposed and what the amendment did are two different
claims and only the second is checkable here — the first is the record of what
this exercise was for. Where an amendment changed a finding's *evidence* rather
than only its resolution, the section says so in place.

Four further tests back statements outside the findings list:
`TestRateSchedulesConvertExactlyOrAreRefused` and
`TestCapacityRangeIsATranslationAndSaysSo` support two entries in
[What held up](#what-held-up), and `TestConfigInventoryIsPinned` plus
`TestNoAWSNetworkIdentifierFieldName` back the network-identifier confirmation
the ticket asked for.

---

## Blockers

### F1 — `ImageRegistry` embeds `Granter`, and whether that is a grant or a stored credential turns on configuration the interface cannot advertise

**Evidence:** `compute/image.go:67-68`; `compute/k8s/registry.go` (`imageRegistry`);
`TestImagePullByWorkloadIdentityIsNotUniversal`,
`TestLegacyPullObligationIsScopedToTheWorkloadsOwnImage`.

**Correction.** The first revision of this finding claimed that *no* OCI registry
can implement `Granter` as a grant, on the ground that the kubelet rather than
the workload is the pulling principal. **That is false as a universal**, and a
reviewer was right to reject it. Kubernetes' kubelet credential-provider
mechanism can be configured to pass a *pod-bound ServiceAccount token* to a
credential plugin, which exchanges it for registry credentials:
<https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/#service-account-token-for-image-pulls>.
The kubelet remains the network actor, but the token it presents is the pod's,
so the registry authorises the ServiceAccount. Workload identity *can* authorise
an image pull on Kubernetes.

The committed test in the first revision proved that *this implementation* mints
a robot credential. It did not prove that *the interface requires* one. Those are
different claims and the finding asserted the second. Both the provider and the
test have been changed so that the code models the credential-provider route and
the test proves the claim below and nothing wider.

**What is actually true**, and what the amendment rests on:

1. **Pull-by-workload-identity is not universally supported.** It needs a kubelet
   credential-provider plugin configured with token attributes on every node
   *and* a registry that federates the cluster's OIDC issuer. Both are recent,
   both are per-deployment, and neither is the default. A cluster missing either
   half cannot do it at all.
2. **The fallback creates credential material as an invisible side effect.**
   Without both halves, the only implementation of `Grant` is `imagePullSecrets`:
   mint a robot account, write its token into a Secret, attach the Secret to the
   ServiceAccount. That is long-lived material created by a method the caller
   believes is a policy write, that nothing rotates, that no audit surface
   mentions, and that `Revoke` has to remember to undo.
3. **A caller cannot tell which one it got.** Both configurations advertise
   exactly the same `CapabilitySet`, expose the same method with the same
   signature, and return the same nil error.
   `TestImagePullByWorkloadIdentityIsNotUniversal` asserts precisely that: same
   capabilities, same call, and one of the two persisted a credential.
4. **The AWS side does not need the surface at all.** An ECS application task
   role receives no ECR policy; image pulls use the separate execution role
   (`build.go:619-666`). That is evidence about the source call site and nothing
   more — it does not generalise to a universal claim about Kubernetes, and the
   first revision of this finding used it as though it did.

So the defect is not "this cannot be implemented". It is that a **required**
method has an implementation whose security properties are decided by operator
configuration the interface has no vocabulary for, with no way for a caller to
discover which it received. That is the same failure mode as a capability that
is really a configuration fact — which is what `Capability` exists to express.

**Proposed amendment.** Remove `Granter` from the required `ImageRegistry`
interface, as it was removed from `RelationalProvisioner`, and reintroduce it as
an *advertised optional capability* rather than a required method:

```go
// CapImagePullIdentity is the ability to authorise an image pull from the
// workload's own runtime identity, with no credential stored in between.
//
// It is a capability rather than a method because substrates differ and the
// difference is invisible otherwise: AWS ECS pulls with a separate execution
// role and gives an application task role no registry policy at all
// (build.go:619-666); a Kubernetes cluster can do it only where a kubelet
// credential provider forwards a pod-bound ServiceAccount token and the
// registry federates the cluster's issuer; a cluster using imagePullSecrets
// cannot, and a provider there must fall back to storing a credential.
CapImagePullIdentity Capability = "image-pull-identity"

// ImagePullGranter authorises a workload identity to pull from a repository.
// Requires [CapImagePullIdentity]; vended by [Provider.ImagePullGrants].
type ImagePullGranter interface{ Granter }
```

with `Provider.ImagePullGrants() (ImagePullGranter, error)` following the
existing capability-gated accessor pattern.

A provider without the capability still has to make the pull work, and the
obligation is deliberately scoped to a workload-to-repository edge rather than
the blanket one the first revision proposed — the reviewer was right that
"every workload can pull any repository the provider issued" is wider than least
privilege:

> A provider MUST arrange that a workload it runs can pull the image its own
> spec names, when that image is in a repository the same provider issued. Any
> credential it creates to do so MUST be scoped to those repositories, MUST NOT
> be exposed to the caller, and MUST be removed when the workload identity is
> deleted.

The provider knows both ends of that edge — `ServiceSpec.Image` and
`ServiceSpec.Identity` — so the scoping is expressible without a grant surface.

F24, below, is the same finding from the other side.

### F24 — `AccessLevel` has no third meaning on a registry

**Evidence:** `compute/identity.go:100-135`; `compute/k8s/registry.go`
(`imageRegistry.GrantPull`); `TestPullGrantsHaveNoAccessLevel`.

The other half of F1. A repository has two verbs: `AccessRead` is pull and
`AccessReadWrite` is push. `compute.AccessLevel` has three, and the interface
says nothing about what the third means on a substrate with two, so a provider
must alias `AccessAdmin` or refuse it. This one aliases it to push, which is a
decision the caller cannot see and did not make.

**Proposed amendment.** Fold into F1's: with `Granter` off the required
`ImageRegistry` interface there is no registry grant to give a level to. If the
optional `ImagePullGranter` keeps one, document that a provider whose substrate
has no admin verb must map `AccessAdmin` to its widest level and say so, rather
than silently narrowing.

### F2 — There is no transient error, and `ErrConflict` collides with the substrate's retryable 409

**Evidence:** `compute/errors.go:34-41, 57-59`; `compute/k8s/provider.go`
(`substrateError`, `apply`); `TestOptimisticConcurrencyIsTransient`.

Kubernetes returns HTTP 409 for two unrelated things:

* **AlreadyExists** on a create — which, combined with an ownership-label check,
  is what `compute.ErrConflict` means.
* **Conflict** on an update whose `resourceVersion` is stale — the single most
  common retryable error on the substrate. It happens whenever two reconciles
  overlap, which is the normal state of a cluster.

The taxonomy has nowhere to put the second. `ErrConflict` would tell the caller
"somebody else owns this name; give up". `ErrFailed` is documented as "not
retryable without changing the spec". `ErrTimeout` is about a `Wait` deadline.

So the provider absorbs it and retries internally. **The precise complaint,
narrowed after review:** the retry *is* bounded — `applyAttempts = 5`, and every
attempt is passed the caller's context, so a context deadline still cuts it
short. What the caller cannot do is **select or observe that budget**. Five
attempts is a number this provider chose, another provider will choose a
different one, and neither is visible. And when the budget is exhausted the
taxonomy still cannot say what happened: the only remaining sentinel is
`ErrFailed`, which is documented as terminal, so a genuinely retryable failure is
reported as one that will never succeed. An earlier revision of this document
said the retry "cannot be bounded", which overstated it.

This is USOSS-16's finding 7 with a substrate-specific edge: it is not just that
a retry invariant cannot be written, it is that the *name* `ErrConflict` will be
mis-mapped. An implementer porting a Kubernetes client will reach for
`ErrConflict` when they see a 409, and a caller that branches on it will conclude
its deploy collided with somebody else's infrastructure.

**Proposed amendment.**

```go
// ErrTransient reports a failure that may succeed if retried unchanged: a
// throttled API call, a stale-read conflict on an optimistic-concurrency
// update, a connection reset. Every other sentinel in this file is terminal
// for the call that produced it.
//
// A provider MAY retry internally, but MUST NOT retry past its caller's
// context deadline, and MUST return this rather than ErrFailed when it gives
// up on something that could still succeed.
ErrTransient = errors.New("compute: transient failure, may succeed if retried")
```

and a clarifying sentence on `ErrConflict`:

> A substrate's optimistic-concurrency conflict is **not** this error. This
> error means the name is taken by a resource the platform does not own.

Consider renaming `ErrConflict` to `ErrNotOwned` in the same change; the name is
what invites the mistake. Either way the conformance suite gains the retry
invariant USOSS-16 deliberately declined to invent.

### F3 — `WorkloadIdentitySpec` and `SecretSpec` carry no `Placement`, but both become namespace-scoped objects

**Evidence:** `compute/identity.go:22-33`, `compute/secret.go:82-96`;
`compute/k8s/secret.go` (`bindingFor`), `compute/k8s/container.go`
(`buildWorkload`); `TestIdentityAndSecretCannotCrossAPlacement`.

`ServiceSpec`, `ScheduledJobSpec`, `FunctionSpec`, `EndpointSpec`, `BucketSpec`
(via class/zone), `RelationalSpec`, and `KeyValueSpec` all take a `Placement`.
`WorkloadIdentitySpec` and `SecretSpec` do not — reasonably, because an IAM role
and an SSM parameter are account-global.

On Kubernetes both are namespace-scoped, and both are namespace-scoped in the
strong sense:

* a pod may only run as a ServiceAccount **in its own namespace**;
* a `secretKeyRef` resolves only **within the pod's own namespace**.

A `Placement` is a namespace. So a provider must put every identity and every
secret in one fixed namespace, and a workload placed anywhere else cannot use
either. The provider's options are to copy secret material into a second
namespace — doubling the number of places an audit has to look, for material the
interface is careful never to let apphub even read — or to refuse. This provider
refuses, with `ErrInvalidSpec` and an explanation.

This is not hypothetical: `Placement` is the documented answer to multi-region
(`compute/network.go:29-45`), so the moment a platform has two placements, an
application's secrets and its workload are in different ones.

**Proposed amendment.** Add `Placement Placement` to both specs, with the same
"empty means the provider's default; a provider with no default returns
`ErrInvalidSpec`" rule, and one sentence to `SecretBinding`:

> A binding whose secret is in a different placement from the workload is
> `ErrInvalidSpec`. A provider MUST NOT copy secret material between placements
> to satisfy one.

The AWS provider ignores the field, which is the correct outcome for a substrate
where these objects are global.

### F4 — `Route` has no TLS, so an application's public hostname cannot be served encrypted

**Evidence:** `compute/network.go:150-172` versus `compute/function.go:104-122`;
`compute/k8s/container.go` (`routeIngress`);
`TestRouteFailsClosedWithoutOperatorTLSAndAuth`.

`ListenerSpec` carries a `TLSConfig` and the interface is emphatic that a TLS
listener with no certificate is `ErrInvalidSpec`. `Route` — the hostname every
deployed application actually gets — carries no certificate at all.

A Kubernetes Ingress needs `spec.tls[].secretName` to serve HTTPS. With nothing
in the spec to supply it, a provider has three options and two are bad:

1. serve the route as plaintext — fail-open, and precisely the class of defect
   `compute` was written to remove (see the `0.0.0.0/0` and certificate-less
   listener notes in `docs/design/compute-provider.md`);
2. invent a certificate — which the interface forbids elsewhere in as many words
   ("no provider may invent a default", `compute/function.go:106-108`);
3. require the operator to configure one and refuse the route otherwise.

This provider takes the third (`Config.RouteTLSSecret`), which means a
misconfigured platform fails a deploy instead of publishing an application over
HTTP. That is a deliberate fail-closed behaviour and it should be the
interface's, not one provider's.

**Proposed amendment.**

```go
type Route struct {
    // ...
    // TLS is the certificate the platform's ingress serves for Host. Nil means
    // the route is served as plaintext, which a provider MUST refuse unless
    // AllowPlaintext is set: a public application hostname served over HTTP is
    // a fail-open default, and the source system's certificate-less listener
    // (lambda.go:696-708) is the same defect one layer down.
    TLS *TLSConfig
    // AllowPlaintext permits a plaintext route, for a platform that terminates
    // TLS somewhere the interface cannot see.
    AllowPlaintext bool
}
```

Making `TLSConfig` reusable here is free — it is already the right shape, an
operator-resolvable reference with no lifecycle attached.

---

## Should-fix

### F5 — `ListenerSpec` has no protocol, confirmed against the substrate that has one

**Evidence:** `compute/function.go:104-122`; `compute/k8s/function.go`
(`gatewayListeners`); `TestPlainClusterDeclinesFunctionEndpoints`.

USOSS-16 found that §7.23's "an HTTPS listener with no `TLSConfig` is
`ErrInvalidSpec`" is unrepresentable, because nil `TLS` is the only way to say
plaintext. The Kubernetes probe adds the corroborating evidence: the substrate
API that *can* express a `ListenerSpec` — a Gateway API `Listener` — has exactly
the field we are missing, alongside a name and a hostname:

```
Listener{ Name, Hostname, Port, Protocol (HTTP|HTTPS|TCP|TLS|UDP), TLS }
```

And a second consequence the interface did not anticipate: a
`networking.k8s.io/v1` Ingress **cannot** express a listener at all. An Ingress
is served on whatever ports the controller listens on, and its TLS section is
keyed by hostname rather than by port. So a Kubernetes provider backed only by an
ingress controller — which is most clusters — must decline
`CapFunctionEndpoint` outright rather than serve the caller's port. This one
does, and only advertises the capability when `Config.GatewayAPI` is set.

**Proposed amendment.** Add a protocol, and make the §7.23 invariant reachable:

```go
type ListenerProtocol string
const (
    ListenerHTTP  ListenerProtocol = "http"
    ListenerHTTPS ListenerProtocol = "https"
)

type ListenerSpec struct {
    Name     string           // optional; substrates that name listeners need one
    Port     int
    Protocol ListenerProtocol // empty means ListenerHTTP
    TLS      *TLSConfig       // required for ListenerHTTPS, ErrInvalidSpec otherwise
}
```

USOSS-12 can then read §7.23 literally, and USOSS-16's suite can drop the
workaround note it currently emits at runtime.

### F6 — No `Describe` returns effective declarative state, and this substrate makes that worse

**Evidence:** USOSS-16 finding 1; `TestTheAmendedInterfaceClosedTheseFindings`.

**The conformance evidence this finding was recorded with no longer exists, and
is not repointed.** It cited the seven "nothing the interface exposes reflects a
declarative change" observations the suite printed for this provider. The
amendment gave every read-back an effective spec, so the suite records none of
them. Repointing the test name and leaving that clause would have claimed
conformance evidence for a gap that had been closed — the evidence overclaim
these verifiers exist to stop, reintroduced by the fix for it.

**And the replacement is narrower than the amendment first claimed.** Its first
revision reported this as six observations going to zero and the gap closed. A
reviewer then wrapped the provider so that `Describe` and `Wait` reported the new
spec while the substrate kept the old object, and the named convergence check
passed: a spec read-back is the provider reporting on itself, and nothing a
provider says about itself can establish what it did. So the interface-level
check stands, the claim is narrowed, and convergence is reported *unverified*
without a substrate observer rather than green. See
[`compute-provider.md`](compute-provider.md) §9.5.

The ticket asked whether a Kubernetes provider makes this better or worse. It
makes it **worse**, and for an instructive reason: on Kubernetes the effective
spec is *right there*. Every object stores the desired state the provider wrote,
`kubectl get -o yaml` returns it, and a `Describe` could return it for free. The
interface throws away information the substrate is holding.

On AWS a `Describe` that returned the effective spec would mean assembling it
from several API calls, which is why the omission was defensible. Here it is pure
loss, and it means a reconciler above the interface still cannot verify its own
work against the substrate best able to tell it.

**Proposed amendment.** Add the effective spec to each status type:

```go
type ServiceStatus struct {
    Status
    // Spec is the effective desired state the provider is converging to, as it
    // understood it. A provider MUST populate it; it is what lets a caller
    // verify that an element removed from a spec is gone rather than merely
    // not-added, which no other field can show.
    Spec ServiceSpec
    DesiredReplicas int
    // ...
}
```

with `SecretSpec.Value` explicitly zeroed. This closes the strongest invariant in
the conformance suite (§7.7) without a provider-specific hook, and removes seven
runtime observations from every conformance run.

### F7 — Two undiscoverable ingress requirements, not one

**Evidence:** USOSS-16 finding 5; `compute/network.go:110-121`,
`compute/network.go:163-170`; `TestRouteFailsClosedWithoutOperatorTLSAndAuth`.

USOSS-16 recommended `CapPlatformIngress` because a caller cannot discover in
advance whether a `PeerPlatformIngress` rule will be accepted. The probe confirms
it and finds a second instance of the same shape: `Route.RequireAuth` asks the
platform's ingress to authenticate, and a provider whose ingress cannot is
required to fail the spec — with no capability a caller could have checked.

**Proposed amendment.** Two constants:

```go
// CapPlatformIngress is the ability to name the platform's reverse proxy as a
// reachability peer. A provider with no ingress proxy configured does not have
// it, and rejects a PeerPlatformIngress rule rather than widening it.
CapPlatformIngress Capability = "platform-ingress"

// CapIngressAuth is the ability of the platform's ingress to authenticate a
// request before forwarding it — Route.RequireAuth.
CapIngressAuth Capability = "ingress-auth"
```

`CapPlatformIngress` is configuration-derived. `CapIngressAuth` requires an
enforceable controller-specific auth integration, not just a configured
middleware name: the current Kubernetes provider does not advertise it and
refuses `Route.RequireAuth` until such an integration exists.

### F8 — Scheduled jobs: reclassify the port rather than adding a `Wait`

**Evidence:** USOSS-16 finding 3; `compute/k8s/container.go`
(`DescribeScheduledJob`); `TestScheduledJobIsLiveOnAcceptance`.

`ScheduledJobStatus` embeds `Status`, which puts the port in the asynchronous
class, but `ContainerRuntime` has no `WaitForScheduledJob`, so three invariants
are skipped. USOSS-16 offered "add the method or move the port".

The probe has an opinion: **move the port.** A CronJob is live the moment the API
server accepts it. There is no readiness condition, no controller writes one, and
a `Wait` would have nothing to wait for; this provider reports `PhaseReady` from
the first `Describe` because that is the truth. The AWS side agrees — the source
system creates its EventBridge schedule with no polling loop
(`container.go:1382-1490`), unlike every genuinely asynchronous path it has.

**Proposed amendment.** Move scheduled jobs to the synchronous class in
`compute/status.go`'s class list, replace `ScheduledJobStatus`'s embedded
`Status` with the descriptor fields it needs, and have `DescribeScheduledJob`
return `ErrNotFound` after a delete like the other synchronous ports. If the
`PhaseGone` ergonomics are worth keeping, the alternative is to add
`WaitForScheduledJob` and document that a substrate with nothing to wait for
returns immediately — but that is a method that exists to satisfy a taxonomy.

### F9 — `ImageRegistry` has no read-back

**Evidence:** USOSS-16 finding 2; `TestTheAmendedInterfaceClosedTheseFindings`.

**The conformance evidence is inverted rather than repointed.** This finding was
recorded against the suite's `NoReadBack` observation and the
`port/image-repository/sync/read-back-after-delete-is-not-found` skip. The
amendment added `DescribeRepository`, so there is no `NoReadBack` to record and
that check runs instead of skipping. Naming the observation now would assert
evidence for a gap that is gone.

Confirmed, and worth one extra sentence: the registries a Kubernetes platform
would use all have a read-back API (Harbor `GET /projects/{p}/repositories/{r}`,
GAR `projects.locations.repositories.get`, ECR `DescribeRepositories`). The gap
is the interface's, not any substrate's. Nothing above the interface can ask
whether a repository exists, what retention it has, or whether a delete took
effect.

**Proposed amendment.** `DescribeRepository(ctx, ref) (*Repository, error)`,
returning `ErrNotFound`, with `Repository` extended to carry the effective
`RetentionPolicy` and `ScanOnPush` per F6.

### F10 — `ServiceSpec` has no readiness model, so "serving" means different things

**Evidence:** `compute/container.go:196-198` (`WaitForService` "blocks until at
least minReady instances are serving"); `compute/k8s/controllers.go`;
`TestTheAmendedInterfaceClosedTheseFindings`, which is where the structural
assertion for this finding went when the amendment closed it.

`WaitForService` promises instances that are *serving*. On Kubernetes, "serving"
is `readyReplicas`, which is driven by the pod's readiness probe — and
`ServiceSpec` has no probe. With none configured, a pod is Ready as soon as its
container starts, so this provider's `WaitForService` means "started", while an
AWS provider's will mean "passing the target group's health check". A deploy that
waits for readiness and then flips traffic behaves differently on the two.

**Proposed amendment.**

```go
// HealthCheck is how the substrate decides an instance is serving.
type HealthCheck struct {
    Path                string        // HTTP GET path; empty means TCP connect
    Port                int
    InitialDelay        time.Duration
    Period              time.Duration
    Timeout             time.Duration
    FailureThreshold    int
}

type ServiceSpec struct {
    // ...
    // Readiness decides when an instance counts toward WaitForService's
    // minReady. Nil means the provider's default, which a provider MUST
    // document, because "serving" otherwise means a different thing on every
    // substrate.
    Readiness *HealthCheck
}
```

### F11 — `FunctionSpec` has no reachability, and the invoke permission has nowhere to live

**Evidence:** `compute/function.go:42-101` (no `Ingress` field) versus
`compute/container.go:126` and `compute/function.go:135`;
`compute/function.go:186-195` (`EnsureEndpoint` "grants the endpoint permission
to invoke it"); `TestFunctionReachabilityIsSplitAcrossTwoCalls`.

Every workload spec in the interface carries reachability except `FunctionSpec`.
That is right for Lambda — a function has no inbound network surface, it is
invoked through the control plane. It is wrong for any substrate that implements
a function as a workload: a pod with no NetworkPolicy is reachable by everything
in the cluster, and the spec gives the caller no way to say otherwise. This
provider writes a default-deny policy, which is a decision the caller did not
make and cannot see.

The second half is sharper. `EnsureEndpoint` is documented as granting the
endpoint permission to invoke its target, "because an endpoint that cannot invoke
its target is not a partially-working endpoint, it is a broken one" — which is
correct. On Kubernetes that permission is a NetworkPolicy **on the function**. So
`EnsureEndpoint` mutates the function's reachability, and the function's own
spec has no field that could declare it. A provider that put both in one object
would have the next `EnsureFunction` reconcile the invoke rule away — a
declarative-convergence trap created by the interface, not by the substrate.
This provider dodges it by using two objects, and the test above pins that.

**Proposed amendment.** Add `Ingress []IngressRule` to `FunctionSpec` for
symmetry, and add a sentence to `EnsureEndpoint`:

> The invoke permission is owned by the endpoint, not by the function. A
> provider MUST NOT express it in a way that a subsequent `EnsureFunction` with
> an unchanged spec would remove.

### F12 — No egress model, with a concrete consequence

**Evidence:** `compute/doc.go:56-58` ("It does not model network egress");
`compute/k8s/container.go` (`networkPolicy`); `TestNoWorkloadPolicyRestrictsEgress`.

The absence is documented as a non-goal, and for AWS it is harmless: a security
group allows all egress by default. On Kubernetes the consequence is asymmetric
and worth stating explicitly.

A NetworkPolicy that listed `policyTypes: [Ingress, Egress]` with no egress rules
would be deny-all outbound and would cut every application off from the database
it was just given. So a provider must write `policyTypes: [Ingress]` only, and
egress is left entirely to whatever the cluster does by default. **In a
default-deny-egress cluster — a common hardening baseline — the interface's
inputs are not sufficient to make an application reach its own database**, even
though the database's `Ingress` correctly names the application as a peer.
Reachability is a two-sided property and the interface only models one side.

**Proposed amendment.** Either state the operator precondition in
`compute/doc.go` and the design document —

> A provider MUST NOT restrict a workload's egress, because the interface gives
> a caller no way to declare what a workload needs to reach. A platform with a
> default-deny egress posture must permit apphub's workloads out of band.

— or add the symmetric type, which is cheap because the vocabulary already
exists:

```go
type EgressRule struct {
    To          Peer
    Port        int
    Protocol    Protocol
    Description string
}
```

The documented option is enough for v1; the undocumented status quo is not,
because it will be discovered by an operator whose cluster is hardened.

### F13 — `ServiceStatus` reports no address for its routes

**Evidence:** `compute/container.go:137-149` versus `compute/function.go:147-157`;
`TestTheAmendedInterfaceClosedTheseFindings`, which is where the structural
assertion for this finding went when the amendment closed it.

`EndpointStatus` reports a `Hostname`, so a caller learns where its function
endpoint answers. `ServiceStatus` reports nothing of the kind, even though
`ServiceSpec.Routes` asked the platform's ingress for hostnames. On Kubernetes an
Ingress does nothing until DNS points at the ingress controller's address, and
that address is in the Ingress's status — which the provider can read and has
nowhere to put. The interface says DNS is a non-goal, which is fine, but a caller
that cannot learn the address cannot delegate DNS either.

**Proposed amendment.** `ServiceStatus.RouteAddresses []string` — the addresses
the platform's ingress answers on for this service's routes, empty until known.

### F14 — `EndpointSpec` has no hostname

**Evidence:** `compute/function.go:124-140`; `compute/k8s/function.go`
(`hostname`); `TestTheAmendedInterfaceClosedTheseFindings`, which is where the
structural assertion for this finding went when the amendment closed it.

A `Route` names its own host. An `EndpointSpec` does not, so the provider
composes one from operator configuration (`Config.EndpointDomain`) and reports it
back. The consequence is that the *caller* chooses the certificate
(`TLSConfig.CertificateRef`) and the *provider* chooses the name it is served
under — two decisions that have to agree and that no single party makes.

**Proposed amendment.** `EndpointSpec.Hostnames []string`, empty meaning
"provider-assigned, reported in `EndpointStatus.Hostname`". A provider that
cannot honour a requested hostname returns `ErrInvalidSpec`.

### F15 — `Resources` collapses requests and limits

**Evidence:** `compute/container.go:19-30`; `compute/k8s/container.go`
(`buildWorkload`); `TestResourcesBecomeBothRequestsAndLimits`.

Kubernetes has two numbers per dimension: a request, which the scheduler
reserves, and a limit, which the kernel enforces. The gap between them is the
difference between Burstable and Guaranteed QoS, and it is a real cost and
density decision. `compute.Resources` has one number, so a provider must set both
to it, making every apphub workload Guaranteed — a decision the caller never
made.

The interface's "round up, never down" rule is right and this substrate needs no
rounding at all; millicores and mebibytes are Kubernetes' own units.

**Proposed amendment.** Cheapest version is documentation: state that a provider
sets both a reservation and a ceiling to the same value, and that a substrate
distinguishing them will be at its strictest setting. If it is worth a field:
`Resources{CPUMillicores, MemoryMiB, BurstCPUMillicores, BurstMemoryMiB}` with
zero meaning "same as the reservation".

### F16 — `Labels` cannot be Kubernetes labels

**Evidence:** `compute/k8s/names.go` (`annotationLabels`, `validateLabels`).

`Labels map[string]string` appears on nine spec types as "non-secret metadata for
ownership tagging". A Kubernetes label value must be at most 63 characters of
alphanumerics, dashes, underscores and dots, and a key must be a qualified name.
The interface promises neither, so a provider that copied them across would
reject specs the interface says are valid. Annotation *keys* have the same
grammar as label keys, so one-annotation-per-label does not work either.

This provider escapes them all into a single annotation. The cost is that they
stop being selectable — which is half of what "ownership tagging" means on this
substrate, and is why `DeleteScope` has to select on a provider-owned label
instead.

**Proposed amendment.** Documentation plus a stated bound:

> A provider MAY require label keys to be a qualified name and values to be at
> most 63 characters of `[A-Za-z0-9._-]`; a caller that exceeds that MUST accept
> that the metadata is preserved but may not be selectable.

### F17 — `RunsOn` has no meaning on this substrate

**Evidence:** `compute/identity.go:26-30`;
`TestRunsOnHasNoMeaningOnThisSubstrate`.

`RunsOn` exists because an AWS role trusted by `ecs-tasks.amazonaws.com` cannot
be assumed by Lambda. A ServiceAccount has no such restriction — the same one
attaches to a Deployment, a CronJob's pods, and a Knative Service. A Kubernetes
provider therefore has two options and both are slightly dishonest: encode
`RunsOn` into the object name, inventing a distinction the substrate does not
have and doubling the ServiceAccounts an application needs; or ignore it, and let
two logically distinct identities silently alias. This provider ignores it and
records the caller's value on the object.

**Proposed amendment.** Documentation on the field:

> `RunsOn` is advisory. A provider whose identities are interchangeable between
> runtimes MAY ignore it, in which case two identities that differ only in
> `RunsOn` are the same identity. A caller that needs two identities MUST give
> them two names.

### F18 — `DeleteWorkloadIdentity` obliges a cross-substrate cascade with no mechanism

**Evidence:** `compute/identity.go:176-178`; `compute/k8s/identity.go`
(`DeleteWorkloadIdentity`).

The method is documented as removing "an identity and every grant made to it". On
AWS that is free — the grants are inline policies on the role. Here the grants
live in the object store's policy document and in the registry's robot accounts:
two systems the identity port does not own, that a production provider may hold
different credentials for, and that it may not be able to enumerate. This
provider does cascade, because it can reach all three, and the cascade is the
finding: the interface imposes a cross-substrate guarantee it provides no
mechanism for and no way to report partial failure of.

**Proposed amendment.** Narrow the obligation and give the caller the tool:

> `DeleteWorkloadIdentity` removes the identity. A provider SHOULD remove grants
> made to it through this provider's own `Granter` ports, and MUST report
> `ErrFailed` if it cannot. Grants made on a substrate the provider does not
> administer are the caller's to revoke.

and add `Granter.RevokeAll(ctx, identity Ref) error`, so a teardown can do it
explicitly rather than relying on a cascade.

### F19 — `FunctionSpec` has a Lambda `Handler` and no CPU allocation

**Evidence:** `compute/function.go:55, 68`; `compute/k8s/function.go`
(`envHandler`, `cpuForMemory`).

Two smaller things in one place:

* `Handler` is "the entrypoint symbol within the bundle", which is a concept the
  AWS runtime shim implements. On a container-based runtime the only thing a
  provider can do is pass it to the image as an environment variable and hope the
  image implements the same convention — an out-of-band contract between the
  operator and the image that the interface cannot describe.
* There is no CPU field. `MemoryMiB` is there because Lambda charges by it and
  derives CPU from it. A pod needs an explicit CPU request, so this provider
  reproduces Lambda's memory-to-CPU derivation — an AWS fact reaching into a
  Kubernetes pod spec because the interface has nowhere else to put it.

**Proposed amendment.** Replace `MemoryMiB` with `Resources Resources`
(`CPUMillicores` may be zero, meaning "provider-derived"), and document `Handler`
as an opaque string the provider passes to its runtime, whose meaning is a
contract between the caller and the runtime rather than part of this interface.

### F20 — `BuildSource.ContextDir` assumes the builder shares the caller's filesystem

**Evidence:** `compute/image.go:82-92`; `compute/k8s/registry.go`
(`imageBuilder.Build`, `packContext`); `TestBuildContextIsReadLocallyAndConfined`.

`ContextDir` is "a local directory containing the build context", which is
exactly right for the source system: its builder is `/kaniko/executor` run as a
subprocess of apphub. It is wrong for every substrate where the builder runs
somewhere else. A BuildKit or kaniko pod is in the cluster and cannot read
apphub's disk, so the provider must read the tree, pack it, and transport it —
an obligation the interface never states, with no size bound, no exclusion
mechanism (there is no `.dockerignore` equivalent), and no way for a caller to
know it is happening or to stream it themselves.

The path-confinement rule the interface does state is portable and is kept
(`resolveDockerfile`); losing it would reintroduce the traversal escape the
source system guards at `build.go:462-467`.

**Proposed amendment.**

```go
type BuildSource struct {
    // ContextDir is a local directory containing the build context. Exactly
    // one of ContextDir and Context must be set.
    ContextDir string
    // Context is the build context as a filesystem, for a caller that already
    // has one in memory or wants to bound what is shipped.
    Context fs.FS
    // Exclude are path patterns the provider must not include in the context.
    Exclude []string
    Dockerfile string
}
```

plus a stated obligation:

> A provider whose builder does not share the caller's filesystem MUST transport
> the context, MUST apply Exclude before doing so, and MUST document its size
> limit.

### F25 — `ExecEnabled` is a two-state field with one enforceable state

**Evidence:** `compute/container.go:94-120`;
`TestExecEnabledIsOneWayOnThisSubstrate`.

The post-PR-#3 model is right and the probe confirms it: exec is target
operability, the operator's principal is authorised separately, and this
provider's `CanExecInto` correctly reports that a workload's own identity cannot
exec into anything (`compute/k8s/harness.go`). That part of the design is
vindicated.

The residue is that `ExecEnabled` is a `bool` and only `true` is meaningful here.
A pod is exec-able whenever the *caller's* RBAC permits it, and there is nothing
a provider can put on a Deployment to make it not be. So `ExecEnabled: false` is
silently a no-op, and a provider advertising `CapWorkloadExec` is telling the
truth about one state and nothing about the other. A caller that sets it false
believing it has closed something has not.

The test asserts both halves, because the first alone would only show that *this*
provider ignores the field. It renders a workload with the flag on and off and
requires the two to be identical; then it creates a workload with
`ExecEnabled: false`, applies an operator `RoleBinding` that no compute spec
describes and no provider method writes, and requires that the workload has
become reachable for a session anyway. If that second assertion ever fails, the
substrate can enforce the false state after all and this finding should be
struck.

**Proposed amendment.** Documentation is sufficient:

> `ExecEnabled` requests that the target be reachable for interactive sessions.
> It is not a guarantee that `false` prevents one: on some substrates a workload
> is always reachable to a sufficiently authorised operator. A provider MUST
> document which of the two states it can enforce.

---

## Doc-only observations

### F21 — `PeerInternet` is wider on Kubernetes than on a security group

`PeerInternet` compiles to a NetworkPolicy `ipBlock` of `0.0.0.0/0`, which admits
every pod in the cluster as well as the internet: a NetworkPolicy has no way to
say "not from inside". A rule the caller meant as "public" is therefore *wider*
here than the AWS security group it replaces. The design document's "does not
promise that two providers produce equivalent security postures" covers this in
principle; it is worth naming this instance, because it is the one where the
non-AWS provider is the *less* restrictive of the two.

### F22 — `Provider` assumes one substrate; a Kubernetes provider is four

`compute.Provider` is written as though one substrate vends every port. A
Kubernetes provider that satisfies all of them is a cluster, plus an OCI
registry, plus an S3-compatible object store, plus a Postgres operator — four
systems with four identity models and four failure modes, and
`Ref.Provider` records one name for resources living in all of them. If an
operator later swaps MinIO for Ceph, every persisted bucket `Ref` still says
`kubernetes` and its `ID` means nothing.

No amendment is proposed: splitting `Provider` would be a much larger change and
the composition is genuinely useful. But `Provider.Name` should say that a name
identifies a *provider configuration*, not a substrate, and that changing what
sits behind a port invalidates the `Ref`s issued for it.

### F23 — `Status.UpdatedAt` has no specified clock

USOSS-16 finding 10, confirmed from the other side: Kubernetes objects have no
"when the provider observed this" field at all. The nearest thing is a condition's
`lastTransitionTime`, which is when the *controller* wrote it, not when the
caller read it. `Status.UpdatedAt` is documented as "when the provider observed
this state", which points at the second; a provider reading a watch cache would
naturally report the first. Two providers will differ. One sentence fixes it.

---

## What held up

A probe that only reported problems would be as suspect as one that reported
none. These are the parts that were tried and were fine.

* **No AWS network identifier is required as an interface input.** Confirmed two
  ways, with one honest caveat about how.

  The conformance suite's structural check over `compute`'s spec types passes.
  And — the complement, which is the part that check cannot show — `k8s.Config`
  is the complete set of things a Kubernetes operator must supply to drive every
  port, it was reviewed field by field, and none of it is a network object
  identity. The whole suite provisioned every port with nothing but a placement
  name, reachability between roles, and caller-composed hostnames. The single
  CIDR in the provider is an *output*: `PeerInternet` compiles to `0.0.0.0/0`
  (`TestPeerInternetIsWiderHereThanASecurityGroup`).

  **The caveat, which a reviewer established with a working mutation:** the
  mechanical form of that second check is `TestConfigInventoryIsPinned`, which
  pins the exact inventory of `Config`'s leaf fields. It is not a semantic
  property. The earlier name-matching version passed with a field called
  `Network` added, which is correct behaviour for a name scan — it catches
  `SubnetIDs` and nothing else. "Is this a network identifier" is a judgement
  rather than a predicate, so the pinned inventory forces the judgement to be
  re-made in a reviewable diff whenever a field is added, removed, or renamed,
  instead of pretending to automate it. The name scan is retained as
  `TestNoAWSNetworkIdentifierFieldName` and is labelled in the source as the
  heuristic it is.
* **`Placement` as a bare name is the right call.** A placement maps cleanly onto
  a namespace plus a node selector, a storage class, and an ingress class. None of
  those is expressible as an AWS network object, which is what would have happened
  with `Placement{Subnets []string}`.
* **Role-based reachability is the strongest part of the interface.** Every
  `PeerKind` maps onto a NetworkPolicy peer, which is a namespace plus a label
  selector. `PeerWorkload` naming another workload by `Ref` is exactly the
  security-group-to-security-group pattern, portably.
* **The exec fix is correct.** `ServiceSpec.ExecEnabled` as target operability,
  with the operator's principal authorised outside the interface, is what
  Kubernetes does anyway. `CanExecInto` returns false for the workload's own
  identity without the provider having to do anything, because the provider
  creates no RoleBinding — which is the point.
* **`RelationalProvisioner` without `Granter` is implementable exactly as
  predicted.** Four natural operations against an operator's cluster resource, no
  ServiceAccount-to-SQL-principal mapping invented. Had `Granter` still been
  embedded, this port would have been a stub.
* **`KeyValueProvisioner` and `CapObjectStoreZonal` decline cleanly**, at
  acquisition and at the spec respectively, which is what the capability model
  exists for.
* **`SecretBinding` by reference is an exact match** for `secretKeyRef`, and the
  "compute never reads the value" property falls out rather than being enforced.
* **`ErrForeignRef` is valuable.** With four substrates behind one provider name,
  a reference from elsewhere is a real hazard, and the sentinel catches it at the
  method rather than at an unpredictable depth.
* **`compute/ext` stayed scoped.** This provider implements no ext port and needs
  none; the boundary rule's `compute/k8s` allowlist entry is unused, which is the
  intended state.
* **Fail-closed held everywhere it was tested**: a proxy-less provider rejects a
  platform-ingress rule instead of widening it, a TLS listener with an empty or
  unresolvable certificate is refused, a plaintext listener is never upgraded to a
  certificate-less TLS one, a bucket is not publicly readable by default, and a
  re-`Ensure` does not rotate a relational admin password.
* **`CapacityRange` as translation works**, with one caveat now recorded: the
  operators surveyed take fixed requests and limits, so nothing scales between the
  two numbers. The provider says so in `Status.Message`, which is the channel the
  interface provides for exactly this.
* **The opaque zone string never came up**, because the capability is declined.
  It remains untested by a second provider.
* **The schedule grammar is worth having.** Pinning five-field cron plus
  `rate(n unit)` meant the provider could convert what converts exactly and refuse
  `rate(7 minutes)` rather than run the job at a cadence the caller did not ask
  for.

## Recommended sequencing

F1, F2, F3, and F4 should land as USOSS-2 amendments before USOSS-10..14 and
USOSS-26 begin, which is the reason this ticket was moved earlier. F1 in
particular changes an interface every one of those tickets implements, and its
first half is the same surgery PR #3 already performed once on
`RelationalProvisioner` — with the difference that `Granter` does not simply
disappear here, it reappears as an optional capability, because
pull-by-workload-identity is real on some substrates and absent on others.

F5 through F14 are cheaper to fold in now than later but do not individually
block an implementation. F15 through F25 are documentation or small additive
changes and can follow.

## What USOSS-19 changed about this document's subject

This document describes what writing a Kubernetes provider found out about the
Compute interface. Every finding above still stands: they are about the shape of
`compute`, and the shape of `compute` is what five amendment rounds acted on.

Two statements *around* the findings went stale when USOSS-19 turned the probe
into a provider, and they are corrected here rather than edited in place, because
the drift is the more useful record.

**"No sleeps anywhere in the package" was not true.** `compute/k8s/wait.go`
polled with `time.Sleep` on a live, exercised path — the conformance suite's
wait checks each spent about a tenth of a second in it. USOSS-19 replaced that
with a watch and kept the poll as an explicitly documented fallback for a
substrate that cannot report changes, which the in-memory cluster deliberately
cannot: its convergence advances on observation, so a watch on it would wait
forever for a write that only a reader can cause. The claim is now narrower and
checkable — the *watched* path runs no timer — and a test holds it to that by
comparing read counts across the two paths rather than by measuring elapsed time.

**The conformance counts quoted in USOSS-27's own report (128 of 135) predate the
USOSS-2 amendment merge.** Re-derived at USOSS-19's head, the full-cluster
configuration is 137 PASS + 4 SKIP + 0 FAIL of 141 subtests and the plain-cluster
configuration is 62 PASS + 12 SKIP + 0 FAIL of 74. The amendment closed several of
the observation gaps this document records as closed, and the suite grew with it;
the difference is amendment-then-remeasure, not a disagreement. Counts on this
project have gone stale and survived a re-audit before, so re-derive them rather
than quoting these.

**One thing this document could not have known, and it matters for anyone writing
a client against a substrate.** The probe's argument for `MemoryCluster` was
hermeticity. USOSS-19 found a second, stronger one: a fake client is addressed by
whatever resource name the code under test asks for, so it *agrees with a mapping
mistake*. apimachinery's own kind-to-resource pluraliser turns `Gateway` into
`gatewaies`; a provider built on it would read the resulting 404 as "the object
does not exist", recreate the object on every reconcile, never converge, and pass
every fake-client test it had. There is a class of defect a hermetic test cannot
catch, and the answer to it is a construction that refuses to guess rather than a
better test.
