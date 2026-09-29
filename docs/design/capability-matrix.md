<!--
GENERATED FILE. Do not edit.

Produced by TestCapabilityMatrixDocument in compute/k8s/matrixdoc_test.go, which
derives every row from the providers themselves and fails if this file disagrees.
Regenerate with:

    go test ./compute/k8s -run TestCapabilityMatrixDocument -update
-->

# Compute provider capability matrix

Which capabilities each provider supports, and what each of its ports does. Every
row is derived from the provider at test time rather than written down, because a
table about code that nothing checks stops being true.

## How to read it

**Capabilities** are what `Provider.Capabilities()` reports. A capability is a whole port
or a whole class of behaviour a substrate may structurally lack; it is not a flag
for a knob on a spec.

**Ports** are the accessors on `compute.Provider`. Each is one of:

| Value | Meaning |
| --- | --- |
| `available` | The accessor succeeded and no probed method refused. **This is negative evidence, not positive**: a zero-argument probe can show that a port refuses and cannot show that a port works, because the one input it can construct is the input a well-written port rejects on validation grounds. Driving a port with real specifications is `compute/conformance`'s job, not this table's. |
| `declined (cap)` | The accessor refuses at acquisition with `compute.ErrUnsupported`, naming the capability. A caller discovers this **before** calling anything. |
| `stub` | The accessor returns a port whose every probed method refuses. This is a defect, not a configuration: the refusal has moved from acquisition to call time. Nothing should ever be published in this state. |
| `partial` | Some but not all of the port's probed methods refuse. Not necessarily a defect, but never a capability claim — the port is not usable as a whole. |
| `unknown` | The accessor returned neither a port nor a typed refusal. A provider bug. |

The Kubernetes provider appears twice on purpose. Almost every capability it has
is a fact about what an operator installed *beside* the cluster — a registry, a
builder, an object store, a Postgres operator, the Gateway API — so a single
column would describe one deployment and misrepresent the rest. **kubernetes** is
a cluster with all of them; **kubernetes-plain** is a cluster with none.

### Capabilities

| Capability | fake | kubernetes | kubernetes-plain |
| --- | --- | --- | --- |
| `container-service` | yes | yes | yes |
| `function` | yes | yes | no |
| `function-endpoint` | yes | yes | no |
| `image-build` | yes | yes | no |
| `image-pull-grants` | yes | yes | no |
| `image-registry` | yes | yes | no |
| `ingress-auth` | yes | no | no |
| `key-value-table` | yes | no | no |
| `mcp-auth` | yes | no | no |
| `model-inference` | yes | no | no |
| `object-store` | yes | yes | no |
| `object-store-zonal` | yes | no | no |
| `platform-ingress` | yes | yes | no |
| `relational-database` | yes | yes | no |
| `scheduled-job` | yes | yes | yes |
| `secret-store` | yes | yes | yes |
| `workload-exec` | yes | yes | yes |
| `workload-grants` | yes | yes | no |

### Ports

| Accessor | Port | fake | kubernetes | kubernetes-plain |
| --- | --- | --- | --- | --- |
| `Builder` | `compute.ImageBuilder` | available | available | declined (`image-build`) |
| `Containers` | `compute.ContainerRuntime` | available | available | available |
| `Functions` | `compute.FunctionRuntime` | available | available | declined (`function`) |
| `KeyValues` | `compute.KeyValueProvisioner` | available | declined (`key-value-table`) | declined (`key-value-table`) |
| `ObjectStores` | `compute.ObjectStore` | available | available | declined (`object-store`) |
| `Registry` | `compute.ImageRegistry` | available | available | declined (`image-registry`) |
| `Relational` | `compute.RelationalProvisioner` | available | available | declined (`relational-database`) |
| `Secrets` | `compute.SecretStore` | available | available | available |

### What "available" means for the Kubernetes columns

The Kubernetes columns are derived from a provider assembled over these
implementations:

| Seam | Implementation behind these columns |
| --- | --- |
| `Cluster` | `*k8s.MemoryCluster` |
| `Registry` | `*k8s.MemoryRegistry` |
| `ObjectStore` | `*k8s.MemoryObjectStore` |

Read `available` in those columns as **"the provider's translation for this port
is complete and conformant when an operator supplies a working implementation of
the seam behind it"** — not as "this repository contains a production assembly for
it". The distinction matters most for `Registry` and `Builder`: every obligation
`compute.ImageRegistry` has beyond pull and push is a vendor control-plane API,
four vendors express them four ways, and this repository deliberately ships no
client for any of them. An operator running Kubernetes supplies that seam, or those
two columns describe nothing they can deploy.

`ClientCluster` and `S3ObjectStore` are shipped, so the `Cluster` and
`ObjectStore` seams have real implementations available even though the table
above is generated over the in-memory ones — the in-memory substrate is what keeps
generating this document hermetic.

## Matrix scope

This table covers provider configurations that can be constructed without cloud
credentials or live infrastructure.

**Anything a capability does not cover.** A provider can support a capability and
still refuse a particular specification — an unknown engine version, a placement
it has no configuration for, a retention policy its registry cannot apply. Those
are `compute.ErrInvalidSpec` and `compute.ErrUnsupported` on the call, not entries here.
This table answers "can this provider do this at all", which is the question a
caller can act on before it starts.
