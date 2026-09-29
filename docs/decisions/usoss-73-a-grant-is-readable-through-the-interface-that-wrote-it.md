## USOSS-73 — a grant is readable through the interface that wrote it

`compute.Granter` gains one method, and so does each port in `compute/ext` that
grants anything:

```go
// compute.Granter, and the two ext bucket ports that mirror it
DescribeGrant(ctx context.Context, resource, identity Ref) (*GrantInfo, error)

// ext.ExternalAccessGranter
ExternalGrants(ctx context.Context, resource compute.Ref) ([]ExternalGrant, error)
```

`GrantInfo` carries the two references and the level. `ExternalGrant` carries the
principal with its constraints, the level, and whether this platform created it.
Neither carries anything a caller supplied and the provider did not read back.

### Why an interface change was the only thing that would do

The write-only shape had already cost two providers a non-portable harness
method, arrived at independently: `compute/aws`'s `Harness.Grants` and
`compute/fake`'s `Harness.ExternalGrants`. Each was added because a contract
nobody can observe is a contract nobody asserts, and each let one provider prove
its own compliance with its own instrument — which is not two providers being
checked against one contract.

The measured consequence, not the predicted one: **a provider whose
`RevokeExternal` did nothing at all passed the full conformance suite and the
entire `compute/fake` package.** The suite's grant invariants could only be
checked behaviourally, through the `Options.Read` and `Options.Write` data-plane
hooks — the hardest part of a provider's harness — and the checks that need them
*skip* when they are absent. So the invariant was not weakly asserted on a
provider without hooks. It was not asserted.

`fake.DefectRevokeDoesNothing` and `fake.DefectRevokeExternalDoesNothing` now
pin that, and `TestTheReadBackCatchesANoOpRevokeWithNoDataPlaneHooks` asserts
both halves of the claim: with the hooks removed the behavioural checks skip, and
the read-back checks fail.

### The two read-backs have different shapes, and the substrates decided that

The obvious design is one shape for both. It does not survive contact with where
a grant is actually stored:

* **The core `Granter` takes the pair.** `compute/aws` writes an inline IAM
  policy on the *identity's role* — a resource policy is one document per
  resource that two providers would contend for. `compute/k8s` writes a policy on
  the *bucket*, keyed by OIDC subject. Each substrate enumerates cheaply in one
  direction and by brute force in the other, and **the two directions are not the
  same one.** Enumerating a bucket's grants on AWS means reading every role in
  the account; enumerating an identity's on Kubernetes means reading every bucket.
  The pair is what both hold directly, and it is what `Grant` and `Revoke` are
  already documented and conformance-checked as being keyed on.
* **`ext.ExternalAccessGranter` enumerates.** A cross-domain grant *is* a
  resource policy — that is the stated reason `compute/aws` refuses the port
  entirely. So the resource is where the whole set lives. It also has to
  enumerate: the gap `GrantExternal`'s own comment describes is "a grant that was
  correctly pinned yesterday and that the configuration no longer names", and a
  per-principal call cannot see a principal that has vanished from a set it was
  never given.

`aws.Harness.Grants` therefore stays. It enumerates by identity, which
`DescribeGrant` structurally cannot replace, and "teardown left nothing behind"
needs the enumeration.

### The AWS level is recovered, never remembered

`DescribeGrant` on `compute/aws` reads the standing policy and asks which access
level would render it (`levelFromStoredPolicy`). It does not classify the action
list, because that would be a second table mapping actions back onto levels, and
`policy.go` says in as many words that it is "the only place an action string
appears" — forward and backward tables that disagreed would report the wrong
access rather than fail.

The comparison is over meaning, not bytes: IAM returns an inline policy
URL-encoded, and a substrate may re-serialise what it stored. `samePolicyDocument`
already existed for the trust-policy convergence check and is reused. Both paths
are tested directly, because `MemoryIAM` returns what it was given and so
exercises neither.

A document that no level would render is **refused with `ErrFailed`**, not
guessed at. Guessing low passes an access review over a workload that can in
fact write; guessing high sends an operator to revoke something that was never
there. `TestTheGrantReadBackRefusesAPolicyItDidNotWrite` plants `s3:*` on `*`
under the provider's own policy name and requires the refusal — and requires that
it is not `ErrNotFound`, since a caller told the pair has no grant writes a
second one beside the first.

### One ordering that is load-bearing

`compute/aws`'s key-value `DescribeGrant` reads DynamoDB before IAM. The first
version read IAM first and returned `ErrNotFound` for an absent policy —
correct in isolation, and wrong here. USOSS-42 had just landed, arming the
transient gate against the substrate belonging to the kind under test, which
for a key-value table is DynamoDB and not IAM. So a *throttled* DynamoDB
surfaced through this method as "this pair has no grant".

That is the fail-open direction and the suite caught it: a caller told a pair has
no grant grants again, and a reconciler told it during a throttling episode
concludes a whole deployment has lost its access. The table is the precondition
anyway — a grant naming a table that is gone authorises nothing — so the order
now matches `Grant`'s, and `DescribeGrant` is in the gate's verified list at both
grant ports.

### It also closed a gap USOSS-44 had just written down

USOSS-44 (#71) landed one commit before this and gave the two `compute/ext` bucket
ports their first positive conformance checks. Its own obligation entry for them
said, in as many words, that **"a provider whose Grant and Revoke both return nil
and do nothing would satisfy"** `checkTableBucketGrant` — because no `Options`
hook performs a data-plane read or write through a table or vector bucket on any
provider, so the enforcement half had nowhere to come from.

`DescribeGrant` needs no such hook. Both checks now assert that the level granted
is the level standing and that a `Revoke` removed it, `fake.DefectRevokeDoesNothing`
fails both of them, and that sentence is no longer true. The obligation entries
are narrowed to the authorisation half rather than left standing.

Their `undrivenPortMethods` entries carry `Legitimate: false`. The first draft of
this change said `true` — written against the tree before USOSS-44 existed, when
nothing could drive those ports — which is precisely the failure the
`ExternalAccessGranter` comment two entries below warns about: the sentence gets
corrected and the structured field is left behind, so tools and humans read
different answers and neither sees the conflict.

### What this closes, and the one thing it does not

The suite's unverified-obligation entry for `ext.ExternalAccessGranter`
enumerated seven properties. Six are now portable assertions: stored existence,
removal on revoke, replacement rather than accumulation, preservation of every
constraint through creation *and* replacement, last-write-wins on level, and no
mutation from a refused call.

The seventh — `ErrNotOwned` on a grant this platform did not create — is
observable through `ExternalGrant.Managed` and is **not** driven by the portable
suite, because planting a foreign grant needs a provider-specific hook and a
suite that demanded one would be demanding that every provider be able to forge a
stranger's trust statement. `compute/fake` drives it against
`Harness.CreateUnownedExternalGrant`, which also enters two `ErrNotOwned` guards
that had existed since the port was written and that nothing had ever been able
to reach.

What no read-back can establish is that a grant **authorises** anything. A
provider whose `Grant` writes only where `DescribeGrant` reads passes these
checks and fails `grants/<port>/access-level-decides-what-succeeds`. The two are
ordered rather than redundant: the behavioural check is the stronger statement
where it runs, and the read-back is the floor everywhere. The obligation entry
records the cross-domain residue, which has no in-repository hook at all — it
would need a second trust domain and a real principal in it.

### What it cost

Five `Granter` implementations (`compute/aws` × 2, `compute/k8s`, `compute/fake` ×
2, sharing one), one `ExternalAccessGranter` implementation, one substrate-seam
addition (`k8s.ObjectStore.GetPolicy`; AWS needed none — `RolePolicyAPI` already
carried `GetRolePolicy`, unused), two new conformance invariants per grant port,
and two existing checks that stopped declining to assert what they are named for.

`S3ObjectStore.GetPolicy` refuses, as its `SetPolicy` and `ClearPolicy` do. The
tempting shape there is `(level, false, nil)` — "there is no grant" — and it is
wrong for the same reason throughout this change: it is indistinguishable from
having looked, and a caller reconciling on it keeps writing grants nothing can
express while being told each time that none stand.

`compute.SecretStore` is untouched. USOSS-73's third write-only site was the
secret existence check, and it landed with USOSS-15 — see
`usoss-15-a-secret-store-answers-where-a-secret-is-without-answering-what-it-is.md`.
