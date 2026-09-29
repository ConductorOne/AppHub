## USOSS-19 — a production Kubernetes provider: a real cluster client beside the in-memory one, and a watch instead of a poll

USOSS-27 built `compute/k8s` to falsify the Compute interface, and it worked: five
amendment rounds came out of it. What it deliberately did not build was a provider
you could point at a cluster. One `Cluster` implementation existed — `MemoryCluster`,
in memory — `go.mod` had no `k8s.io/client-go` dependency at all, and `waitFor`
advanced by calling `time.Sleep(pollInterval)` in a loop. This entry records the
three decisions that turned that into a provider, and one it deliberately did not
make.

### `MemoryCluster` stays, and the real client is added beside it

`ClientCluster` implements the same four-method `Cluster` seam over client-go's
dynamic client. `MemoryCluster` is not replaced, and the reason is not sentiment:
it is what makes 141 conformance checks and 30-odd findings tests run with no
cluster, no network, and no port. Replacing it with a fake clientset would have
traded a substrate that *stores the objects the provider actually builds* — so a
translation bug shows up as a wrong object — for one that agrees with whatever the
code asks it for.

That difference is not abstract. `meta.UnsafeGuessKindToResource`, apimachinery's
own kind-to-resource pluraliser, turns `Gateway` into `gatewaies`; the real
resource is `gateways`. A provider built on the guess would get a 404 from the API
server, read it as "the object does not exist", create a new Gateway on every
reconcile, and never converge — **and every fake-client test would pass**, because
a fake is addressed by the same wrong resource name the code asks for. A fake
cannot catch a mapping error. So resource resolution does not guess: `StaticResolver`
holds an explicit table and returns `ErrUnmappedKind` for anything absent from it,
which turns the whole class from a silent 404 into a refusal that names the kind.
An operator's custom resource — the Postgres operator's cluster kind is already
configuration, because CloudNativePG, Zalando and Crunchy disagree — must be
supplied, and the completeness of the table is derived rather than restated: the
conformance suite is run against a cluster that records every kind any verb was
called with, and every one of them must resolve.

`Apply` is a read-modify-write with the stored `resourceVersion` carried onto the
outgoing object, not a server-side apply. Server-side apply is the natural verb for
a declarative write, and the honest reason it is not used is that client-go's fake
dynamic client does not implement `types.ApplyPatchType` — so an SSA implementation
would be an unexercised code path in every test this repository can run, and the
first time anybody learned whether it worked would be against a real cluster. The
read-modify-write is fully exercisable and makes this substrate's most common
retryable failure a tested path rather than a hypothetical one.

One trap is signposted in the code because it is the kind of thing a well-meaning
implementer adds as a courtesy: a `resourceVersion` is an **optimistic-concurrency
token, not a content version**. It is opaque, it changes on writes a caller never
made, and mapping it onto a user-visible secret version would look like honouring a
pin while silently following the latest value.

### Watching, with polling kept as the documented fallback

`waitFor` now blocks on whichever of three things happens first: the substrate
reporting that the object changed, the deadline elapsing, or the caller's context
being cancelled. The change notification is a bare tick with no payload, and the
loop re-reads through the same `Get` every other path uses — one source of truth
for an object's state, rather than two that can disagree.

Change notification is a *separate* interface, `Watcher`, rather than a fifth method
on `Cluster`, and that is load-bearing. `MemoryCluster`'s clock is the read:
convergence advances on observation, which is what keeps the hermetic suite free of
timers. A watch on it would block forever waiting for a write only a reader can
cause. Making the capability optional lets the substrate that has it use it and the
one that cannot say so by not implementing it — and the wait reads that as "poll",
which is a documented fallback rather than an accident. A `ClientCluster` whose
watch dies and cannot be re-established closes the channel, which drops that wait
to the poll path for the remainder: a slower wait is a much better failure than a
hang.

**A note on what landing this cost, kept because it is why the record now looks
like this.** Rebasing this branch twice, the union merge driver twice swallowed the
blank/`---`/blank block introducing this entry in the old single-file record and spliced
its heading onto the end of the previous entry. No conflict was reported either time,
because at line granularity there was nothing to conflict about. `make decisions` caught
both. Counting the occurrences made the shape clear — one per merge involving two
branches that both append — so it was deterministic rather than flaky, and that is what
justified splitting the record into one file per decision (#30) rather than continuing to
catch the glue failure. The same single file was also putting several pull requests at a
time into a conflicted state, which silently removes their CI, because GitHub's
mergeability computation ignores the `merge=union` attribute. This entry now lives in its
own file, so that class of damage is structurally impossible rather than linted for.

**The corrected claim.** USOSS-27's report said there were "no sleeps anywhere in
the package". That was not true when it was written — `wait.go` polled with
`time.Sleep` on a live, exercised path — and the replacement claim is narrower and
checkable: *the watched path runs no timer*. It is held to that by a test that runs
the same unsatisfiable wait twice over the same substrate, once against a cluster
that reports changes and once against one that cannot, and requires exactly one read
in the first case and many in the second. The assertion is the ratio, so there is no
threshold to tune.

### Seams for the two substrates that are not the cluster

USOSS-27 put an interface between the provider and the API server. It did not do the
same for the registry or the object store: `MemoryRegistry` and `MemoryObjectStore`
were reached as concrete types, so they were not *an* implementation, they were the
only one it was possible to have. Both are now interfaces, and every method takes a
context and returns an error. That shape is the whole point — an in-memory substrate
cannot fail and cannot be cancelled, so a seam derived from one silently makes both
unrepresentable, and a real client is a network call that needs a deadline it can be
held to and a failure it can report.

`S3ObjectStore` is the real client for one of them. The resource half of
`compute.ObjectStore` maps onto specified, vendor-neutral S3 calls and is
implemented: CreateBucket, DeleteBucket, ListBuckets, and the tagging and
public-access sub-resources, with ownership and the caller's labels carried as
bucket tags. Public access is settled *before* the ownership tag is written, and
every field of the public-access configuration is sent explicitly in both
directions, because an omitted field means "leave it as it was" and a pre-existing
public bucket would then stay public while this provider reported it private.

### Reconciling public access on a bucket took three attempts, and the third was found by enumeration

Worth recording because each attempt was wrong in a way the previous one's test
could not see.

A `PublicAccessBlock` configuration does not grant anything — it *rejects or
ignores* grants. S3 grants public read through a bucket policy, and a new bucket
is private. So there are two pieces of state, and reaching a desired pair from an
arbitrary current pair needs an order that is safe at every step.

1. **Clear the blocks and stop.** Grants nothing; the bucket stayed private while
   being reported public. The read-back compounded it by inferring `PublicRead`
   from `!BlockPublicPolicy` — *the absence of a block is not the presence of a
   grant*, and a describe that infers is a claim rather than an observation.
2. **Unblock, then grant.** Safe from a clean prior state and not otherwise. Going
   private blocks and then revokes, so a failed revoke leaves a latent grant behind
   the block; unblocking first re-exposed it, and a failing grant then returned an
   error with the bucket publicly readable.
3. **Grant, then unblock.** Safe when the bucket starts blocked. When it starts
   *unblocked with no grant*, the grant is live the moment it is written, and a
   failed unblock returns an error having made the bucket public.

What holds is to route every change through a blocked intermediate state — ensure
blocked, set the grant, unblock if public — so no step can expose anything and any
failure leaves the bucket blocked. Because that would otherwise make every
reconcile of a public bucket briefly unreadable, the current pair is read first and
nothing is written when it already matches.

**The invariant is "a failed call must not increase exposure", not "must not leave
it readable".** The stronger phrasing was tried first and flagged three cases where
a failed call on an already-public bucket changed nothing — which would have pushed
the fix toward blocking buckets it had no business touching. Getting the invariant
right mattered as much as getting the ordering right.

**Attempt three was found by enumeration, not by argument.** The test models the
two state variables and answers an unsigned read from them, then walks four prior
states by two desired states by a failure injected into each write — 24
interleavings. A reviewer's hand-built case found attempt two; the enumeration
found attempt three, because their fixture pinned the prior state to blocked. When
a defect is "safe only from some starting states", the test has to enumerate the
starting states.

A related fix in the same area: a 404 from `GetBucketTagging` means `NoSuchBucket`
*or* `NoSuchTagSet` — the bucket exists with no tags. Reading the status alone
reported an existing untagged bucket as absent, and `EnsureBucket` reads absent as
"the name is free", so it configured and stamped ownership on a bucket somebody
else created. Existence is now settled with `HeadBucket`, whose 403 also means
"exists, not ours", rather than by matching an error-code string that
S3-compatible stores spell inconsistently. `CreateBucket`'s 409 is likewise split:
`BucketAlreadyOwnedByYou` is idempotence, anything else is refused.

### The exposure invariant was right for three rounds and its population was not

The ordering above went through four wrong versions. The fifth was found by a
reviewer inside the construction written to prevent exactly this, and that is the
part worth recording.

The enumeration walked four prior states x two desired states x a failure injected
into each of *two* writes. The reconcile makes five. The two were the ones its
author had thought of, so a tagging failure after the unblock returned an error with
a formerly-private bucket public, and the enumeration reported "all 24
interleavings hold" while it did.

**A sound property over a population its own author chose is the same defect as a
hand-picked test case, wearing a proof.** The fix is not another axis; it is to stop
choosing. The enumeration now runs each cell once with nothing failing, records
every mutating request the stub actually received, and uses *that* as the failure
population for that cell. Add a write to the reconcile and the enumeration grows
with no edit anywhere. Two gates keep the derivation honest: the discovered set must
contain the writes the reconcile is known to make, and **every injected failure must
be observed to fire** — a cell whose injection was never reached is not evidence,
and counting it as a pass is how a construction reports coverage it does not have.

Five writes, twenty-five cells, twenty-five injections fired.

The ordering that survives is that **every write which cannot change exposure
happens before any write that can, and every write that can happens while
blocked**: create, confirm ownership, tag, then the access reconcile. Moving the tag
to the front also fixed a defect nobody reported — with the tag last, a failed
access write left a bucket created and untagged, which the next EnsureBucket read
as existing-but-not-ours and refused for ever. The provider could not converge on a
bucket it had created itself.

### Four routes into one bug, and the thing they had in common

The adoption bug was closed four times. Each fix reasoned about **which status code
the create returned**, and each left a code nobody had considered:

1. a 404 from `GetBucketTagging` read as "absent" — it also means `NoSuchTagSet`;
2. `BucketAlreadyOwnedByYou` read as idempotence — it means the *account* owns it;
3. an unnamed 409 assumed harmless;
4. and a **200**, because `CreateBucket` in `us-east-1` answers 200 for a bucket you
   already own. The success path — the one that appears to prove we just created the
   bucket — proves nothing.

Enumerating status codes is what kept producing new routes, so the enumeration is
gone. **No create outcome distinguishes "we created this" from "it was already
here"**, so none of them gates anything: every outcome that does not fail outright
falls through to the same marker read. The one exception is a diagnosis rather than
a gate — `BucketAlreadyExists` means a *different* account holds the name, so no
ownership read could succeed and refusing early gives the operator "bucket names are
global" instead of "no marker found".

### A concession: an untagged bucket is treated as unclaimed, and that gives up a protection

This is recorded as a concession rather than a design choice, because something that
was protected before is not protected now, and the next person to read this code
should find that written down rather than infer it.

**Why the concession was necessary.** Requiring the ownership marker made a bucket
this provider *created but could not mark* permanently unusable: if the tag write
failed after creation, the next Ensure read an existing untagged bucket, called it
not-ours, and refused it for ever. Moving the tag ahead of the access reconcile — the
round-three fix — could not reach this, because there is nothing to tag before the
bucket exists. That write cannot be moved earlier, so no ordering fixes it.

Ownership therefore has three answers rather than two: the marker present is **ours**,
tags present without the marker is **foreign**, and no tags at all is **unclaimed**
and claimable.

**What is no longer protected.** A same-account actor who creates a bucket this
provider wants, wins the race, and leaves it carrying no tags at all will have that
bucket **adopted** — reconfigured, tagged as ours, and thereafter treated as ours.
Round three claimed that case was refused. It is not refused any more. What is
still protected: a bucket held by a **different account** is refused
(`BucketAlreadyExists`, whose diagnosis says bucket names are global), and a
same-account bucket carrying a tag that is not this platform's marker is refused as
foreign.

**And one correction to that boundary, because the first version of this entry
overstated it.** "Tag your buckets with anything at all and this provider will not
touch them" is false for exactly one value: this platform's own ownership marker.
An actor who writes that marker is asserting *that it is this platform*, and
`classifyTags` believes it — necessarily, because the marker has to be a value the
provider can recompute in order to recognise buckets it created, so it is
reproducible by construction and no obscurity in its value changes that. The
protection this concession actually leaves is therefore:

> anything in this account that can tag a bucket can present itself as this
> platform.

That is a property of the account's own permission boundary, not something a tag
classifier can recover. It is stated here because the concession was approved on
the strength of the overstated version, and a concession is only safe if it is
legible.

**The limit is in the substrate, not in the implementation.** S3 has no conditional
bucket creation — no create-if-absent that fails when the name is taken by someone
whose identity we could then read. So no sequence of S3 calls distinguishes:

* a bucket we created a millisecond ago and failed to tag, from
* a bucket another actor in this account created a millisecond ago and has not tagged.

The interface would need that distinction to have both properties, and the substrate
cannot express it, so this says so at the limit instead of implying a guarantee it
cannot keep. What made the choice between the two is that they are not symmetric:
refusing every untagged bucket is a **liveness failure that fires every time** the
provider partially fails on a bucket it genuinely owns, while adopting one requires
another actor **inside the same account** to win a race and leave their bucket
untagged. The second is the smaller harm, and unlike the first it is
**operator-actionable**: tag your buckets with anything at all and this provider will
not touch them.

`TestDoesNotAdoptASameAccountCreateRace` was rewritten to assert what is now true
rather than adjusted until it passed, and `TestATaggedForeignBucketIsStillRefused`
holds the half that survives.

**One ownership authority, because there were two and the reachable one was
wrong.** The three-answer logic above lived in `PutBucket`, and `EnsureBucket` had
its own two-answer check that ran first — so the fix was correct, its test passed,
and the reported two-`Ensure` reproduction still failed. Both paths now read one
field (`BucketState.Claim`) from one classifier (`classifyTags`), and the
regression runs through `EnsureBucket` rather than through the seam beneath it.
The rule this produced: **a test written at a lower seam than the reproduction can
pass while the reproduction still fails**, so a fix for a reported defect is
verified through the entry point the report used.

### Syntax is not the population

The capability audit was defeated twice, by the same counter-example, and the second
failure is the instructive one. Version one matched `Name Capability = "literal"`
with `go/ast`. A reviewer defeated it with `CapX = CapImageRegistry + "-suffix"` —
semantically a `Capability`, type inferred from the operand, silently skipped.
Version two added the conversion form and made anything unrecognised fatal, **and
still missed the same constant**, because it carries no type *node*: the code
classified it as "not a Capability" rather than as "a Capability I cannot read". The
doc comment described the case the code did not catch, which is worse than either.

A constant's type is a semantic property and no pattern match over expression shapes
recovers it. The audit now typechecks the package with `go/types` and asks the type
checker, which is the only thing that knows. Computed constants are *evaluated*
rather than refused, so the counter-example is caught by inclusion — it appears in
the derived set and its absence from `AllCapabilities` is reported. Standard library
only, about a second.

### A derived population undone one line later

The exposure enumeration derives its failure population from the writes the reconcile
actually makes. It then **deduplicated by request key**, and `PutBucket` writes
`publicAccessBlock` twice on a public transition — the guard and the unblock. Only
the first was ever failed, so the unblock, which is the write that actually exposes
the bucket, was never independently injected.

Deriving a population and then collapsing it by key is a population fix undone one
line later. Injection is now per **occurrence**, and a gate requires at least one
cell to have injected into a repeated key, so the collapse cannot come back
unnoticed. 25 cells became 26.

### Two inputs, one closed

`reencodeSpec` refused an *absent* effective-spec annotation, which was right. It did
not refuse a **malformed** one: `decodeSpec` discards its unmarshal error and returns
the zero value, so garbled JSON fell through the absent check and the mutation was
applied to a zero spec — replacing a garbled read-back with a *fabricated* one. That
is worse than the defect it was fixing, because garbled state shows something is
wrong and an invented spec does not. Absent and unparseable are two inputs; refusing
one of them is a tolerant path in a gate. Both are refused now, with different
messages, because they send an operator to different places.

### The account boundary is not the ownership boundary

`BucketAlreadyOwnedByYou` was treated as idempotence. It means *this account* owns
the bucket, not that this provider created it — so another actor in the same account
taking the name between the existence check and the create was adopted, tagged and
configured. That was the third distinct route into the same adoption bug on this
branch: first a `NoSuchTagSet`/`NoSuchBucket` conflation, then a 409 that
short-circuited, then this.

A 409 now reports only "it was already there" and the ownership question goes to the
same marker read as any pre-existing bucket. The managed-by marker exists precisely
because account membership is not authorship, and any answer that skips it is
adoption by another name.

### A transition is not a call

The watch reconnect missed a change that landed after one watch closed and before
its replacement existed: every individual watch worked, and the move between two of
them did not. A consumer waiting on an object that had *already become* ready waited
out its whole deadline. The earlier concession that a missed intermediate state is
unobservable did not cover it, because the state reached in the gap is persistent.

Two fixes, kept together because they fail differently. Resuming from the last
observed `resourceVersion` asks the server to replay the gap, and depends on the
server still holding that history. Emitting one tick as soon as the replacement is
established depends on nothing: it makes the consumer re-read, and a re-read of
current state cannot miss a persistent change however it arose.

### Two claims narrowed, and a threshold that was a flake

"The watched path runs no timer" was false — it arms one for the caller's deadline,
as any wait that can give up must. The property the test establishes is narrower:
**no periodic poll timer.** The test was right both times; only the sentence above
it was wrong, because a measurement of reads was described as a claim about timers.

The capability audit recognised one declaration form and silently skipped the rest,
so a computed constant that is semantically a `Capability` was missed. It now
recognises the literal and conversion forms and **fatals on any third** rather than
skipping — the audit either enumerates the population or fails. It also carried a
const block's type forward whenever the type node was absent, which is not Go's
rule: a spec with an explicit value inherits nothing.

And one of this branch's own tests required ten reads in a fifty-millisecond window
to prove the poll path was polling. True on an idle machine, false on a shared one,
and it failed at nine. The count was never the property — "one read versus repeated
reads" is — so the floor is now three. A threshold tuned to a quiet machine is a
flake with a plausible-looking justification.

### What this deliberately did not build, and why

**No registry client.** Only two of `compute.ImageRegistry`'s obligations
correspond to anything in a vendor-neutral registry API: the OCI Distribution
specification covers pulling and pushing content and the token exchange that
authorises them. It has no notion of creating a repository, no retention policy, no
vulnerability scanning, no robot accounts, and no per-repository grants. Every one
of those is a *vendor control-plane* API, and Harbor's, GAR's, ECR's and Quay's are
four different ones with four different authentication models. So "a real registry
client" is not one thing a Kubernetes provider can have; it is a fifth substrate
choice on top of the four this provider already admits to. Writing one against an
API that cannot be verified from here would be unfalsifiable code shaped by
guesses, so the seam is shipped and the client is a ticket per vendor.

**No Granter half of the object store, either, and for the same shape of reason.**
Authorising a Kubernetes ServiceAccount against a bucket has no vendor-neutral
form: AWS does it with a role assumed through STS AssumeRoleWithWebIdentity, MinIO
with a policy claim inside the token, Ceph RGW with its own STS and policy dialect.
`SetPolicy` returns a typed error naming what would be needed. That composes rather
than breaking: an operator running such a store sets `TrustsClusterOIDC` false, the
provider then omits `CapWorkloadGrants`, and the port refuses at acquisition with a
message about the store.

**No relational client, because none is needed.** `RelationalProvisioner` writes the
Postgres operator's cluster resource through the `Cluster` seam, so it became real
the moment `ClientCluster` existed. Nothing was added for it.

**No end-to-end deploy.** `modules/deploy` is a one-line stub pending USOSS-15, for
every provider. USOSS-19's fourth acceptance criterion cannot be satisfied until
there is a caller of `compute.Provider` to demonstrate, and stubbing around that
would be a demonstration of the stub.

**The signer is the one surface where "the tests pass" carries least weight.**
`SigV4Signer` is verified for determinism, for sensitivity to every component the
algorithm covers, for the documented header shape, and for never emitting the
secret. It is not verified against a reference implementation, because there is
none here and a second implementation written from the same reading of the
specification would be circular. Signing is deliberately isolated behind a `Signer`
interface for that reason, and it is the safest place on this branch to be wrong: a
bad signature is a 403 on the first request, immediately and loudly.
