# Architecture

AppHub is organized around three boundaries: application modules, provider
interfaces, and persistence/lifecycle state. The direction is deliberate: modules
ask for application-level work, providers translate that work into a substrate,
and only the store layer knows the v1 database.

## Runtime

![AppHub architecture](guide/images/architecture.svg)

At runtime the layers below run in two long-lived processes. `apphub serve` is the API:
it serves the portal, the REST API, and MCP, and records deployments as queued
in the DynamoDB store. `apphub worker` claims queued deployments, fetches source
through the GitHub App, runs each build as an isolated Kaniko task on Fargate
with no task role, pushes the image to ECR, and provisions the application's
resources through `compute/aws`. Published applications sit behind Traefik and
oauth2-proxy. The worker holds the deploy target's IAM authority; the API does
not.

## Layers

| Layer | Main packages | Responsibility |
| --- | --- | --- |
| Modules | `modules/`, `modules/deploy`, `modules/review`, `modules/fix` | Publish user-facing capabilities through the `modules.Module` interface. |
| Provider interfaces | `compute/`, `credentials/`, `credentials/workload` | Define the ports modules can depend on without importing a cloud SDK or vendor client. |
| Provider implementations | `compute/aws`, `compute/fake`, `compute/k8s`, `credentials/*` | Translate the provider interfaces onto AWS, Kubernetes, memory-backed fakes, or external credential systems. |
| Lifecycle and persistence | `credentials/lifecycle`, `store/` | Remember issued credentials, drive expiry/revoke/recovery, and persist v1 state. |

A package above a boundary depends on the interface below it, not on the concrete
implementation. Composition roots, such as `cmd/apphub`, choose implementations
and register them explicitly.

## Modules

A module implements `modules.Module`: metadata (`ID`, `Name`, `Description`,
`Icon`, `Category`), a flat JSON-schema-like parameter contract, `Validate`, and
`Execute`. `Execute` returns both `*modules.Result` and `error`; callers must
inspect both because a partial execution can have useful state and a failure at
same time.

Dependencies are constructor-supplied. Current modules do not use late-bound
`Set*` dependency injection: a module that is missing a provider, store, fetcher,
or other collaborator refuses construction with `modules.ErrNotConfigured` rather
than registering and discovering the missing dependency on first use. This keeps a
registered module usable by construction and makes deployment wiring failures
operator errors, not requester validation errors.

## Compute provider interface

`compute.Provider` is the root compute interface. It reports a stable provider
name, a configuration-derived `CapabilitySet`, and accessor methods for ports
such as images, containers, functions, object stores, relational databases,
key-value tables, and secret stores.

Accessors return `(port, error)` instead of nil fields or no-op stubs. If a
provider does not offer a capability, the accessor refuses at acquisition with a
typed `compute.ErrUnsupported` error naming the capability. If it advertises a
capability, the matching accessor must hand out a real port; the conformance
suite and generated matrix exist to keep that agreement true.

Provider implementations are late-bound by wiring, not imported by modules:

- `compute/aws` is the production AWS implementation. It requires operator
  configuration for region, placements, identity, registry, build, network,
  database, and other site-specific values. It has no compiled-in account,
  network, role, repository, or host defaults.
- `compute/fake` is an in-memory implementation used by tests and examples.
- `compute/k8s` translates the same interface onto Kubernetes plus operator-
  supplied seams such as registry and object storage.

The generated compute capability matrix lives at
[`docs/design/capability-matrix.md`](design/capability-matrix.md). It answers
whether a provider configuration can offer a port at all; it does not claim that
every spec inside that port is portable.

## Credential provider interface

`credentials.CredentialProvider` vends credential material once, reports status,
and revokes when the upstream can do so. Its contract is intentionally not tied to
ConductorOne: `credentials/c1` is one optional implementation, and the registry
imports no providers itself.

The `ProviderRegistry` is explicit startup wiring. A binary creates a registry,
registers the providers it wants, and then resolves providers by ID. That is the
mechanism that keeps optional providers optional: an adopter that does not import
or register a provider does not carry that provider in its build graph.

Credential material is held in `credentials.Secret`, whose formatting,
serialization, and logging paths redact or refuse. Provider metadata and foreign
provider strings use redacting helper types where they may contain deployment
configuration or caller-controlled text. Providers must not put credential
material in errors, logs, metadata, annotations, or durable records.

## Lifecycle and store

Credential vending has three parts:

1. `credentials/` is stateless provider code: create, revoke, status, capability
   reporting, and recovery for ambiguous creates where supported.
2. `credentials/lifecycle/` is stateful orchestration: policy checks, TTL clamps,
   issue records, revoke requests, status reconciliation, and recovery after a
   create whose response was not delivered.
3. `store/` is the v1 persistence implementation for lifecycle records.

v1 persistence is DynamoDB-only. The fence is explicit: DynamoDB clients and
DynamoDB storage idioms belong in `store/`, not in modules or provider
interfaces. This is not a cloud-agnostic database abstraction; it is containment
so a future store can be a focused rewrite of one layer instead of a leak through
every caller.

## Composition root

`cmd/apphub` currently composes credential providers from environment and prints
what was registered. It is intentionally narrow. A future application service can
reuse the same boundaries: construct stores, providers, registries, and modules;
register only the provider implementations the deployment chooses; then dispatch
through the interfaces above.
