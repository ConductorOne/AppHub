# `compute/`

The provider-agnostic compute interface and its implementations.

| Path            | Role                                                        | Ticket        |
| --------------- | ----------------------------------------------------------- | ------------- |
| `compute/`      | The interface. No implementation, no cloud SDK imports.       | USOSS-2       |
| `compute/ext/`  | Ports that are **not** portable. Optional; import-fenced.     | USOSS-2       |
| `compute/aws/`  | AWS: ECS, Lambda + ALB, S3, DynamoDB/Aurora, ECR image build. | USOSS-10..14  |
| `compute/fake/` | In-memory provider. Working, not stubbed. No network, no creds.| USOSS-16      |
| `compute/conformance/` | The contract as an executable suite every provider runs. | USOSS-16 |
| `compute/k8s/`  | Kubernetes. A real client-go cluster client beside the in-memory one that keeps the suite hermetic. | USOSS-27, USOSS-19 |
| `compute/matrix/` | Derives a provider's capability support matrix from the provider. Generates `docs/design/capability-matrix.md`. | USOSS-19 (for USOSS-20) |

The design, the call sites each capability replaces, and — importantly — the
list of things this abstraction does **not** make portable are in
[`docs/design/compute-provider.md`](../docs/design/compute-provider.md). Read
the "What this abstraction does not make portable" section before implementing
a provider.

`compute/k8s` was built in two halves. USOSS-27 wrote it to falsify the
interface, because an interface with one implementation is a hypothesis; what
that found — twenty-five places the contract is AWS-shaped, underspecified, or
fail-open on a non-AWS substrate, each with a proposed amendment and an evidence
map saying what backs it — is in
[`docs/design/k8s-contract-probe.md`](../docs/design/k8s-contract-probe.md).
**Read it before implementing `compute/aws`.** USOSS-19 then made it a provider
you can point at a cluster: a client-go `Cluster`, a watch in place of the poll,
and seams for the registry and object store so the in-memory ones are one
implementation rather than the only one. The in-memory implementations stay —
they are what makes the conformance suite need no cluster, no network and no
port. What USOSS-19 deliberately did not build, and why, is in
[`docs/DECISIONS.md`](../docs/DECISIONS.md).

Which capabilities each provider supports is in
[`docs/design/capability-matrix.md`](../docs/design/capability-matrix.md). It is
**generated** by `compute/matrix` from the providers themselves and checked byte
for byte on every test run, so it cannot drift from them; regenerate it with
`go test ./compute/k8s -run TestCapabilityMatrixDocument -update`.

The workload-identity vocabulary lives in
[`credentials/workload`](../credentials/workload), not here, and `compute`
imports it. That direction is fixed by a supervisor-owned contract; a parallel
definition in `compute` is a bug even if it is field-for-field identical.

The design rule that governs this directory: methods name what an *application*
needs, not what a cloud API is called. If a method is named after an AWS API
call, the abstraction has leaked and the fix belongs in `compute/`, not in the
caller.
