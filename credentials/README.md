# `credentials/`

The `CredentialProvider` interface, the registry that resolves a request to a
provider, and the providers themselves.

| Path                     | Role                                                     | Ticket   |
| ------------------------ | -------------------------------------------------------- | -------- |
| `credentials/`           | Interface + registry + contract types. Imports no provider. | USOSS-3 / USOSS-7 |
| `credentials/lifecycle/` | What is remembered about a vended credential, and who drives it to gone. | USOSS-3 / USOSS-7 |
| `credentials/workload/`  | The compute-versus-credentials boundary for workload identity. Implements the supervisor-owned normative contract; `compute` imports these types rather than defining its own. | USOSS-3 |
| `credentials/aws/`       | AWS-native STS/IAM vending: Bedrock bearer tokens through STS, and IAM-user credentials. First-class, not a reference example. Every identifier is required configuration with no default. | USOSS-9  |
| `credentials/c1/`        | ConductorOne-backed vending. Optional; dynamic only. Implemented against ConductorOne's service-principal credential API. Cannot recover an ambiguous vend (see its package comment). | USOSS-3 / USOSS-8 |
| `credentials/datadog/`   | Datadog API keys. Static only; cloud-neutral.            | USOSS-7  |
| `credentials/github/`    | GitHub App installation tokens. Dynamic only; cloud-neutral. | USOSS-7 |

The contract itself -- the wire protocol, the authentication model, the lifecycle,
failure semantics, the security properties, and the assumptions about ConductorOne
that are *not* verified -- is in
[`docs/design/credential-vending.md`](../docs/design/credential-vending.md).

**ConductorOne is optional.** An adopter with nothing but an AWS account must be
able to build and run AppHub. `credentials/c1` is therefore the only package
permitted to depend on ConductorOne, and callers register it explicitly rather
than the registry importing it. See `internal/boundary` and `make boundary`.
