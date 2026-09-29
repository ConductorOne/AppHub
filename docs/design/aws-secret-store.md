# The AWS secret store: SSM Parameter Store behind `compute.SecretStore`

USOSS-26. This is the port that carries credential material, so almost every
decision in it is a security decision and is written down here rather than left
to be inferred from the code.

Source: `backend/internal/modules/deploy/container.go:301`, `:312`, `:1133`
(`ssm.PutParameter`, `ssm.AddTagsToResource`), `postgres_roles.go:157`, `:231`
(`GetParameter` / `PutParameter` for the database master password), and
`terraform/modules/ecs/iam.tf:30-50`, `:233-245` (the IAM policies that let a
task read those parameters).

## Where the material goes, and where it does not

```
{PathPrefix}/apps/{scope}/{name}      SecureString, one KMS key, tagged
```

* **Everything is a `SecureString`.** There is no configuration for it. A
  `String` parameter is stored in plaintext and readable by anything holding
  `ssm:GetParameter`; offering the choice would put the unsafe option one struct
  field away. The source system's own writes are already `SecureString`
  (`container.go:311`, `:1145`), so nothing is given up.
* **`Get` is the only operation that returns material**, and the interface names
  its one legitimate caller: the master database password, which apphub has to
  present to Postgres in order to create roles (`postgres_roles.go:154-165`).
  Injection into a workload never comes through it — that is a
  `compute.SecretBinding`, which the runtime resolves at launch.
* **The listing operation cannot return a value.** Teardown enumerates a scope
  with `DescribeParameters` under a recursive `Path` filter, not
  `GetParametersByPath`. The two enumerate the same set and only one of them
  returns values; `ParameterMetadata` has no value field, so there is no
  correct-looking code path that leaks one.
* **Nothing derived from a value appears in an error, a tag, a reference or the
  operator-facing dump** — not the value, and not its length either. A length is
  not material but it narrows a brute force, and a caller debugging a tier limit
  already knows how big its own value is.

## Getting from a `Ref` to something a runtime can reference

A `compute.Ref` carries the parameter *path*, never an ARN: a Ref is what a
caller persists, and an ARN carries the account, so putting one in a Ref would
spread the account identifier through every stored application record. A runtime
that has to reference a parameter — an ECS `valueFrom`, an IAM `Resource`
element — needs the ARN, so there is one supported way across:

```go
refs, err := p.SecretParameterARNs(ctx, spec.Secrets)   // []{EnvName, ARN}
doc,  err := p.SecretReadPolicy(refs)                   // the grant for those
```

The ARN is **read back** from the substrate rather than composed from a template.
That is the decision `docs/DECISIONS.md` records for repositories, for the same
reason: the source system stored bare ARNs and then reconstructed them by string
template in a dozen places (`bucket.go:194-215`, `container.go:1530-1537`), which
is the coupling `compute.Ref` exists to prevent. It has a second effect worth
having — a reference to a parameter that does not exist is `ErrNotFound` while a
runtime is still building a specification, instead of an opaque
container-launch failure minutes later.

## The least-privilege grant

`Provider.SecretReadPolicy` takes the *resolved* references rather than the
bindings or a scope, which means it cannot invent an ARN: every one it can emit
came back from the substrate.

```
Action:   ssm:GetParameter, ssm:GetParameters
Resource: the exact ARN of each bound parameter
```

* **No path wildcard, and no way to spell one.** The narrowest grant that works
  is the set of parameter ARNs the workload actually references, and the caller
  always has that set — it is building the task definition out of the same
  slice. A scope-shaped variant
  ("everything under this application's path") is deliberately not offered: it
  would be wider in every case, and an API that offers a wider grant beside a
  narrower one gets the wider one used.
* **No enumeration.** `ssm:GetParametersByPath` and `ssm:DescribeParameters` are
  excluded. A principal that can enumerate a hierarchy can discover and read
  everything under it, so granting either against a path turns a grant scoped to
  one application into a grant over all of them. That is what the source system
  does today: `iam.tf:43-46` grants reads on
  `…:parameter{ssm_prefix}/apps/*` — every application's secrets, to every
  application's tasks.
* **No writes.** A workload has no business writing to the store that feeds it.
* **`kms:Decrypt` only for a customer-managed key**, and then narrowed with a
  `kms:ViaService` condition so the key cannot be used on ciphertext the workload
  obtained elsewhere. Against the AWS-managed SSM key the grant is neither
  needed nor scopeable to one key, so emitting it would be strictly wider and buy
  nothing.
* **The document is typed, not templated.** A policy is the one artefact here
  where a formatting slip is a privilege escalation, and `"Resource": "%s"` and
  `"Resource": "%s*"` look equally plausible in a template. Nor is there a
  wildcard *input*: the character class `segment()` produces and the grammar
  `PathPrefix` is matched against both exclude `*`. Since the ARN now arrives
  from the substrate rather than from this package, "it cannot happen" stopped
  being a property a reader can see in this code, so the emitted resources are
  re-checked for a wildcard and the policy is refused if one appears.

Who attaches it is not this port's business. On AWS the principal that resolves
an ECS `valueFrom` is the task *execution* role and the principal that reads a
parameter from application code is the task role; which applies is a property of
the runtime. That is also why `compute.SecretStore` is not a `compute.Granter` —
the identity that reads a bound secret on AWS is not necessarily the workload's
own.

## Ownership, and the bug the source system has here

Every parameter carries `apphub.dev/managed-by=apphub`. A `Put` that finds a
parameter without it returns `compute.ErrNotOwned` rather than overwriting
somebody else's credential; parameter names derive from a caller-chosen scope
and name, and those derive from mutable application names, so the collision is
reachable without anyone doing anything strange.

That check only works if the create and the tagging are one operation, because a
parameter that exists untagged is indistinguishable from somebody else's. SSM
rejects a `PutParameter` carrying both `Tags` and `Overwrite=true`, so the source
system always writes with `Overwrite=true` and then tags in a second call — and
**none of the three call sites surfaces a failure of that second call**. By
`grep -rn AddTagsToResource --include='*.go'` over the source checkout, excluding
worktrees, there are exactly three:

| Site | Handling |
|---|---|
| `deploy/container.go:321` | `_, _ = ...` — discarded |
| `deploy/postgres_roles.go:240` | `_, _ = ...` — discarded |
| `workload/rotator.go:283-294` | logged, then `return nil` |

All three create with `Overwrite=true`, so in all three a parameter can exist
that this platform wrote and cannot recognise as its own. The rotator's comment
calls the tagging "best-effort", which it can afford to because nothing in the
source depends on the tag; an ownership check does.

This port creates with `Overwrite=false` and `Tags` in the same call, so a
created parameter is always tagged, and it only takes the two-call path once it
has established that the parameter is already its own. A tagging failure on that
path is returned, not swallowed.

### Caller labels are namespaced, and that is load-bearing

`compute.SecretSpec.Labels` become tags under `apphub.dev/label/`. Without the
prefix a caller could pass a label named exactly `apphub.dev/managed-by` and
forge the ownership marker — turning a refusal into an adoption. Namespacing
makes that unsayable rather than merely forbidden. Operator tags from
`Config.Tags` are refused if they are in the `apphub.dev/` namespace at all.

### Which tags are this provider's to remove

`Labels` is a declarative set, so a label present in one deploy's spec and absent
from the next has to be gone from the substrate. Deciding "is this tag mine to
remove?" from the *current* configuration cannot see a key that has been taken
out of it, so an operator tag dropped from `Config.Tags` would survive on every
existing resource forever. The set of keys this provider applied is therefore
recorded on the resource itself, in `apphub.dev/operator-tags`, rather than
restated anywhere. A tag somebody else put on the parameter is left alone.

## Naming is injective, and that is a privilege boundary

A scope and a secret name each become one path segment. A name that is already a
legal segment and short enough is used verbatim; anything else is slugged and
given `.` plus 16 hex characters of a SHA-256 digest **of the original input**.

The marker is a dot, and the verbatim character class deliberately excludes one.
That is the whole of what makes the mapping injective, and the obvious
alternative is not:

> with `-` as the separator, the derived form of a long name is itself a legal
> short name. A caller can simply *use* that string — no hash collision needed —
> and land on the same parameter. Both carry this platform's ownership tag, so
> the second `Put` adopts the first's and overwrites it.

Reserving a character a verbatim segment cannot contain makes the two families of
output disjoint by construction rather than by an argument about probability.
`TestSegmentIsInjective` pins the regression case and was confirmed red against
the `-` scheme before green against this one. (The same defect was found
independently in USOSS-10's `sanitize` on the same day, from a USOSS-13 finding;
two ports arriving at it separately is why it is written down here rather than
just fixed.)

Sixteen hex characters is 64 bits. Eight — the obvious choice, and what the
Kubernetes provider uses for a label value it has 63 characters for — is 32 bits,
and a 32-bit collision between two *scopes* is a cross-application secret read.

A scope containing `/`, `..`, whitespace or upper case cannot escape the
configured prefix or add a hierarchy level either, because the slug's character
class contains no separator.

## Ownership is three tags, not one

`ownedBy` requires `apphub.dev/managed-by=apphub`, a matching
`apphub.dev/component`, and a matching `apphub.dev/name`. The marker alone
would make every resource this provider creates interchangeable by name, which
matters most for an IAM role: a role is account-global, several AWS ports will
create roles, and a port adopting another port's role by name hands a workload
permissions meant for something else.

## Teardown matches the hierarchy

`DeleteScope("app-1")` does not reach `app-1x`.
`MemoryParameters.DescribeByPath` implements the hierarchy semantics explicitly
rather than with a prefix compare, because a fake more permissive than the
service would let this port pass its own tests and delete the wrong thing.

A parameter under a scope's path that this platform does not own is **not**
deleted, and its presence is reported as `compute.ErrNotOwned` once the owned
ones are gone. Deleting it would destroy somebody else's material; skipping it
silently would make a teardown that left credentials behind look like a clean
one.

## Documented behaviours, rather than whatever the SDK does

| Case | Behaviour |
|---|---|
| Parameter exists and this platform owns it | Value replaced, tags converge on the spec, same `Ref` |
| Parameter exists and it does not | `compute.ErrNotOwned`, nothing written |
| Value larger than the configured tier allows | `compute.ErrInvalidSpec`, decided before the value leaves the process; the limit and the tier are named, the size is not |
| Read of a reference that no longer exists | `compute.ErrNotFound` |
| Read of another provider's reference | `compute.ErrForeignRef`, never `ErrNotFound` — a caller told "not found" recreates the secret somewhere it does not belong |
| Read of a reference outside the configured prefix | `compute.ErrInvalidSpec` |
| Empty value | `compute.ErrInvalidSpec` — an empty `SecureString` would be injected as an empty credential |
| Existing parameter in the advanced tier, provider configured for standard | `compute.ErrInvalidSpec`, because SSM cannot downgrade a tier and the caller never set that constraint |
| Throttle, 5xx, `TooManyUpdates` | `compute.ErrTransient`, never `ErrFailed` |
| `DeleteScope` with an empty scope | `compute.ErrInvalidSpec` — never "every secret" |

**Intelligent-Tiering is not offered.** Its whole behaviour is to promote a
parameter when the value exceeds the standard limit, so the maximum size a
caller can rely on is not knowable from the configuration — and a port whose
"value too large" boundary moves on its own cannot have a documented, tested
behaviour for it. An operator who wants the advanced limit asks for it. The
tier is also always sent explicitly, because an empty `Tier` makes Parameter
Store apply the account's *default tier configuration*, which may be
Intelligent-Tiering, and then the limit this port documents is not the one in
force.

## Version pinning (USOSS-35)

`credentials.SecretRef` pins a revision, `compute.Ref` addresses the current
value, and before USOSS-35 the conversion between them dropped the pin silently.
`compute.SecretBinding.Version` closes it, and this port honours it — SSM keeps
parameter history and accepts a `name:version` selector on both `GetParameter`
and an ECS `valueFrom`.

Two boundaries are worth stating because getting either backwards is invisible
until a workload will not start:

* **The selector belongs to the reference, not to the grant.**
  `SecretParameterARNs` appends `:<version>` to the ARN a runtime references.
  `SecretReadPolicy` uses the **unversioned** ARN, because an IAM `Resource`
  element for an SSM parameter has no version component — a policy naming
  `…:parameter/x:3` matches nothing. That fails closed, which is the safe
  direction, but it fails closed on every deploy that pins anything. Established
  from the ARN grammar across two AWS documentation sources rather than from a
  quoted statement, so it is worth one confirmation against a live account before
  production.
* **A pin is validated, not trusted.** A binding naming a revision the parameter
  does not have is `ErrNotFound`, and one whose version is not a number is
  `ErrInvalidSpec`. Falling back to the current value on an unrecognised revision
  is the same defect as ignoring the field.

`Put` reports the revision it created, which is the half that makes the field
usable at all: `credentials.SecretRef.Version` is populated by a `SecretWriter`
over `SecretStore.Put`, so a `Put` that returned only a `Ref` would leave the pin
expressible at the binding and unreachable from the write path. A repeat write of
an identical value does not mint a revision — otherwise a redeploy that changed
nothing would look like a rotation, and the idempotence invariant would be
observing a difference that is not there.

That last sentence has the **same standing as the ARN-grammar claim above, and
needs the same confirmation**: that real SSM does not mint a revision for an
identical value is taken from documentation, not from an observed `PutParameter`
against a live account. It is worth calling out separately because the
conformance suite does not treat it as a detail of the in-memory substrate — for
any provider declaring `Options.HonoursSecretVersions`, a second identical `Put`
reporting a *different* version is a conformance **failure**. So if SSM does
increment on every write regardless of the value, `compute/aws` fails conformance
the first time it runs against a live account, and the correction belongs in the
invariant rather than in the provider.

## Placement

`compute.SecretSpec.Placement` exists for substrates that scope a secret to a
namespace. An SSM parameter is account-global, and the interface says an AWS
provider ignores the field — but ignoring a name the provider was never
configured with is fail-open: a caller that asks for `eu-central-1` and silently
gets whatever `Region` says has been handed a resource somewhere it did not ask
for. So this provider has exactly one placement, named by
`Config.PlacementName`, and a spec naming any other is `compute.ErrInvalidSpec`.
A multi-region deployment is two providers, not one that conflates them.

## What the conformance suite did not cover, and now does

`compute.SecretStore.DeleteScope` had **no** conformance coverage. It is the call
that stops a torn-down application's credentials from outliving it, and the
interface documents it as existing precisely because the caller does not
reliably know the set — the source system tracked it in a `SecretNames` slice on
the application row that any failed deploy could leave incomplete
(`container.go:1152`).

Two checks were added, along with the interface documentation they enforce
(re-runnability, and that an empty scope is `ErrInvalidSpec` rather than
"everything"). `compute/fake`, `compute/k8s` and `compute/aws` all pass them
unchanged; all three already had the behaviour and nothing said so. Six defect
fixtures in `compute/aws/defects_test.go` show each new check failing against a
broken store and passing against the real one, because a check that has never
been shown to fail is an assertion rather than a gate.

## Deliberately not ported

* **`services/ssm_cache.go`** — the admin-key resolution cache. It is a
  credential-layer concern (`credentials.Metadata` and the provider registry own
  it), it caches decrypted material in process memory with a TTL, and nothing in
  `compute.SecretStore` calls for a cache. Reproducing it here would put a
  credential cache inside the compute layer, which is the entanglement the
  compute/credentials split exists to undo.
* **A `Granter` on the secret store.** See the least-privilege section: the
  reading principal on AWS is not the workload's own identity, so the grant
  cannot be expressed as `Grant(resource, identity, level)`.
* **An IAM adapter for the identity port.** The identity port is here because
  `compute.Provider` requires one and because the policy builder needs a
  principal to name; the SDK-backed `RoleStore` belongs to the ticket that owns
  ECS roles. `New` refuses a `Substrate` with a nil member, so a production
  deployment cannot silently get the in-memory one.
