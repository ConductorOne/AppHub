# Compute provider authoring guide

A compute provider turns AppHub's application-facing `compute.Provider` ports
into one substrate. The interface is not an SDK wrapper: method names describe
what an application needs, and each implementation is responsible for translating
that request into its own control plane.

## 1. Implement `compute.Provider`

A provider must implement:

- `Name() string`: a stable provider-configuration name recorded in every
  `compute.Ref` the provider issues.
- `Capabilities() compute.CapabilitySet`: the whole-port or whole-behaviour
  capabilities this configured instance offers.
- `Identities() compute.IdentityService`: every provider vends workload
  identities; it is not capability-gated.
- Accessors for optional ports: `Registry`, `Builder`, `Containers`,
  `Functions`, `ObjectStores`, `Relational`, `KeyValues`, and `Secrets`.

Accessor behaviour is part of the contract. If a provider advertises a capability,
the matching accessor must return a real port. If it does not advertise the
capability, the accessor must refuse at acquisition with `compute.ErrUnsupported`
(or `*compute.UnsupportedError`) naming the provider and capability. Do not return
nil ports, do not return stubs whose methods all fail, and do not silently ignore
a field the substrate cannot honor.

## 2. Advertise capabilities from configuration

Capabilities are coarse. They answer questions like "can this provider run
containers at all?" or "can this provider provision a key-value table?" They are
not knobs on specs. A provider can advertise `compute.CapContainerService` and
still reject a particular CPU size, placement, route, runtime, or engine version
with `compute.ErrInvalidSpec` or a call-level `compute.ErrUnsupported`.

Derive capabilities from the configured instance, not from the implementation in
abstract. The same Kubernetes implementation can have an object store when an
operator supplies that seam and lack one when it does not. The same AWS provider
can advertise a scheduled-job capability only when its scheduler substrate is
present.

## 3. Build ports around application contracts

Each accessor returns a port interface in `compute/`:

| Accessor | Port shape |
| --- | --- |
| `Registry` | Container image repositories and image pull policy. |
| `Builder` | Source-to-image builds that push to a provider-issued destination. |
| `Containers` | Long-running services and scheduled jobs. |
| `Functions` | Invocable functions and, when supported, stable endpoints. |
| `ObjectStores` | Buckets plus object-store grants. |
| `Relational` | Managed SQL endpoints. |
| `KeyValues` | Managed key-value tables plus grants. |
| `Secrets` | Secret storage and workload bindings without exposing values at launch. |

A port should refuse a spec it cannot express. Examples: a placement the provider
was not configured with, an unsupported runtime, a version pin the secret store
cannot honor, or a route that asks for authentication when the ingress layer
cannot enforce it. Refusing is better than widening a request or reporting success
for work that did not happen.

## 4. Run the conformance suite

`compute/conformance` is the executable contract. A provider test supplies a
factory and options describing the configured substrate:

```go
func TestConformance(t *testing.T) {
    substrate := myprovider.NewMemorySubstrate()
    factory := func(tb conformance.TB) compute.Provider {
        p, err := myprovider.New(substrate, testConfig())
        if err != nil {
            tb.Fatalf("constructing provider: %v", err)
        }
        return p
    }

    conformance.Run(t, factory, conformance.Options{
        Placement:       "default",
        FunctionRuntime: "provided.al2023",
        EngineVersion:   "16",
        // Fill hooks for invariants the interface cannot express.
    })
}
```

The factory may be called more than once, and each returned provider must address
the same substrate so a second instance can find and delete what the first one
created. If the provider advertises a capability, provide the matching options and
hooks; the suite should fail loudly rather than silently skipping the very
behaviour the provider claims.

Useful hooks include: creating an unowned resource, inducing a transient error,
checking anonymous access, authenticating as a workload, emitting markers into
rendered artifacts, and dumping rendered provider state. If a substrate genuinely
cannot express an invariant, either do not advertise the capability or leave the
hook nil so the report names the invariant as unverified.

## 5. Unsupported capability behaviour

There are three compliant refusal points:

1. **Configuration time:** `New` rejects a provider that would advertise a
   capability it cannot serve, such as a configured registry with no registry
   client.
2. **Accessor time:** an unadvertised port returns `compute.ErrUnsupported` from
   its accessor.
3. **Call time:** a supported port rejects a particular unsupported spec with a
   typed error, usually `compute.ErrInvalidSpec` or `compute.ErrUnsupported` with
   specific detail.

There is no compliant no-op. A provider must not accept a request and then omit a
network rule, drop a secret version, fall back to a wider placement, or deploy a
workload that lacks a capability the spec requested.

## 6. Update the capability matrix

When a provider or provider configuration changes, update the generated matrix:

```sh
go test ./compute/k8s -run TestCapabilityMatrixDocument -update
go test ./compute/k8s -run 'TestCapabilityMatrixDocument|TestTheMatrixDocumentIsNotEmptyOrUniform'
```

The matrix includes only provider instances the repository can construct
hermetically and without crossing provider-boundary import fences. Add your
provider to the generator only when its memory/fake substrate can be imported
from the generator's package without making another provider package reach your
SDKs. Otherwise document support in the provider package and keep the generated
matrix scoped to the configurations it can prove.

## Worked example: AWS

The AWS provider is configured with an explicit `aws.Config` and an `aws.Substrate`.
A test or matrix provider uses `aws.NewMemorySubstrate()`; a real composition root
uses SDK-backed clients. The config supplies region, placements, identity naming,
registry, build, secret, object-store, database, function, endpoint, container,
and scheduler-related settings. None of those values has a public default because
they are deployment-specific.

AWS capabilities are derived from that configuration. For example:

- registry requires `Config.Registry` and an ECR substrate;
- image build requires both registry and build configuration plus builder, pusher,
  and token-minting seams;
- scheduled jobs require the container runtime and scheduler substrate;
- object-store zonal support is not advertised, because the provider cannot put
  the ownership marker required by the contract on that bucket class.

The provider refuses at construction when configuration would make a false
capability claim. It refuses at accessor time for absent ports. It refuses at call
time for specs AWS or the configured account cannot honor.

## Worked example: Kubernetes or fake

The fake provider is a useful starting point for callers and tests: it implements
all ports over `fake.Store`, can be configured to advertise only a subset of
capabilities, and exposes a harness for behaviours that are intentionally outside
`compute.Provider`.

The Kubernetes provider shows the other important pattern: a provider instance may
be a composition of several substrates. A Kubernetes cluster may run services and
jobs, but image registry, object storage, database, and ingress behaviour depend
on operator-supplied seams. Its capability set therefore describes the configured
instance, not Kubernetes as a universal platform.
