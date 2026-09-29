## USOSS-10 — the AWS provider composes no AWS identifier, it reads them back

Binding on USOSS-11 through USOSS-14 and USOSS-26, which share the `compute/aws`
package. Recorded here rather than in the package because it is a rule about
what the *next* five implementations may do, and a rule that lives only in the
code it already governs is one the sixth implementer never reads.

The security bar says no account ID, ARN, registry host, or infrastructure ID
may be committed. That is necessary and it is not sufficient, because it is a
rule about literals and the interesting failures are about *construction*. The
source system does not hardcode an account ID in its build path either; it
recovers one from a push destination with a regexp and rebuilds a repository ARN
from a template (`kaniko_creds.go:26-47`). No literal, same coupling, and the
template is what the least-privilege session policy depends on being correct.

So the rule for this package is stronger and structural:

> An AWS identifier is read back from the service that owns it. It is never
> composed, parsed out of caller input, or reconstructed from parts.

Concretely, and each of these is a place the obvious implementation is the wrong
one:

* A repository's ARN and its registry-qualified URI come from ECR's own
  response. The session policy is scoped to ARNs the registry reported.
* A role's ARN comes from IAM's response. It is the subject of the workload
  attestation the verifier compares against (`auth/sts_verify.go:21-52`), so
  composing it would mean this package holding an account identifier in order to
  produce the one string that must be exactly right.
* A build destination is *compared* against the URI the registry reported, not
  parsed. That comparison is what confines a build to the operator's own
  registry: a parse that took the repository name from after the first slash
  would find `app` in the configured registry for a destination naming somebody
  else's host.
* A `compute.Ref`'s ID is a resource name, not an ARN. Refs are persisted by the
  deploy layer, and an ARN would put an account identifier into every stored row
  and make a reference issued against one account silently meaningful against
  another. The source system stores bare ARNs and reconstructs them by template
  in a dozen places (`bucket.go:194-215`).

### The consequence for tests

No fixture in this package may contain a twelve-digit number, an ECR hostname,
or anything else shaped like a real identifier — not even a synthetic one. A
fixture that imitates the real shape is the place a real value eventually gets
pasted, and to every scanner and every reader a synthetic account ID is
indistinguishable from a live one. The in-memory substrate therefore reports
`arn:aws:ecr:test-region:apphub-test-account:repository/...` and a registry
host under `.invalid`, and nothing above the substrate parses either, which is
what lets the fixtures be honest about being fixtures.

The minted push credential follows the same shape: the in-memory token service
returns `apphub-test-access-key-id` rather than anything with an AWS key
prefix, because an `ASIA`-prefixed string in a public repository is a finding for
every scanner that reads it and a live-credential scare for every human.
