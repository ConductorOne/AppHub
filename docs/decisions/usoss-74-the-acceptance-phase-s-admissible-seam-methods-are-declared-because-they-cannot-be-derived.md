## USOSS-74 — the acceptance phase's admissible seam methods are declared, because they cannot be derived

Round nine of PR #25 found `buildWorkload` writing inside the acceptance phase
that had been extracted, one round earlier, specifically so that a refused spec
would change nothing. Round ten then found the ownership `claim` on the wrong side
of that same boundary. Both were correct code with the boundary in the wrong place,
and both were found by a person reading the ordering rather than by any check.

So the boundary should be structural: the acceptance phase receives a seam it
**cannot write through**, and a write during validation fails to compile. That
requires knowing which seam methods the phase may call — and this entry exists
because **that set cannot be derived. It has to be declared.**

### Why the set is declared rather than derived

Four derivation routes were tried. Each failed, and each failed differently.

| Route | Outcome |
| --- | --- |
| the method's **name** | wrong answer |
| **observing implementations** | no fact of the matter |
| an automated **mutation detector** | wrong in *both* directions |
| the existing **interface doc comments** | already false |

**Names.** `ObjectStore.ClearPolicy` reads as a clearing operation and is one: it
calls `s.clearPolicy(bucket, subject)` and mutates. A first pass classified it
read-only because the verb list held `Put`, `Delete`, `Grant`, `Revoke`, `Mint`,
`Apply`, `Set` and not `Clear`. A verb list is a spelling census.

**Observing implementations.** `ObjectStore.Write` **mutates** in
`MemoryObjectStore` — `b.objects[subject] = []byte("written")` — and **refuses** in
`S3ObjectStore`, returning `ErrObjectStoreControlPlane` because writing as a
subject requires a token exchange. Same seam method, opposite answers in two
implementations, so there is no behaviour to observe that settles it.

**An automated detector.** A pass looking for `delete(`, assignment into receiver
state, calls to known lower-case mutators and writing HTTP verbs got three answers
wrong, in both directions:

* **False negative** — `MemoryRegistry.Grant` reported read-only. It calls
  `r.grant(...)` and mutates. This is the method whose mutation the round-nine
  regression measures directly (`grants 0 -> 1`).
* **False positive** — `S3ObjectStore.GetBucket` reported mutating, matching
  `state.Labels[...] = tag.Value`: an assignment into a **local** struct building
  the return value. Populating a result is not a seam mutation.
* **A second false positive, found while checking this entry's own table** —
  `ClientCluster.List` flagged as mutating, on `labels.Set(selector)`. A
  package-qualified type conversion in the Kubernetes API library, matched by a
  pattern meant for receiver mutators. `List` reads, sorts and converts; it is
  read-only, hand-verified.

A detector with only false negatives leaves a floor to build on; one with only
false positives leaves a set to prune. **One with both leaves nothing** — every
entry needs independent verification, so it has saved no work while lending its
output the appearance of a result.

That third instance is the sharpest argument for this entry's method, because it
was found *by using the detector to check the declaration this entry writes*. The
instrument disagreed with the table, the table was right, and the only way to know
which was to read the method. If verifying a declaration requires reading every
method anyway, the declaration is the artefact and the detector is not a shortcut
to it.

**The existing doc comments.** This is the route that matters most, because it is
the one this entry was expected to formalise. The `Registry` interface says:

> Pull and Push attempt a data-plane operation as a principal. **They exist for the
> conformance harness**: the compute contract states that a workload can pull the
> image its own spec names, and nothing in the interface can observe whether that
> is true.

Derived from the source, one caller per method, production paths separated from the
test-support surface in `harness.go`:

| Probe | Callers |
| --- | --- |
| `Objects.Read` | `harness.go` only |
| `Objects.Write` | `harness.go` only |
| `Objects.AnonymousRead` | `harness.go` only |
| `Registry.Pull` | `harness.go` only |
| **`Registry.Push`** | `harness.go` **and `registry.go`, in `imageBuilder.Build`** |

The sentence is true for four of five and **false for `Push`**. And it was false when
it was written: `Build` already called `Registry.Push` at USOSS-27's `7fc723d`,
while `backing.go` — where the sentence lives — arrived with USOSS-19. Not drift.
Wrong on arrival.

> A declaration is only ground truth for someone who did not write it, and in a
> single-author package there is no such person.

### The method this entry therefore uses

Establish each method's contract from its **call sites and its implementations
together**, then *write* the declaration and make it checkable. Not read the
declaration and formalise it, which is the order that would have inherited the
`Push` error and given it a compiler's authority.

### The declaration

Derived from call sites, then decided. `Provider.apply` and `Provider.claim` wrap
`Cluster.Apply` and `Cluster.Get`; the categories below are about the seam.

**Read-only — admissible inside an acceptance phase.**

| Method | Reason |
| --- | --- |
| `Cluster.Get` | reads one object; `Provider.claim` is this plus an ownership comparison |
| `Cluster.List` | reads a collection |
| `Registry.GetRepository` | reads repository state |
| `Registry.CredentialFor` | reads an existing credential; does not mint |
| `Registry.RepositoryNames` | enumerates |
| `Registry.Pull` | a data-plane read as a principal; harness-only, no production caller |
| `Registry.Describe` | renders repository state; enumerates, does not mutate |
| `ObjectStore.GetBucket` | reads bucket state, including the ownership claim |
| `ObjectStore.BucketNames` | enumerates |
| `ObjectStore.Read` | a data-plane read as a subject; refuses in `S3ObjectStore` for the same missing token exchange as `Write`, but unlike `Write` it never mutates in any implementation, so the refusal doesn't move it into the category below |
| `ObjectStore.AnonymousRead` | an unauthenticated read; how "public access is off unless asked for" is verified |
| `ObjectStore.Describe` | renders bucket state; enumerates, does not mutate |

**Mutating — inadmissible.**

| Method | Reason |
| --- | --- |
| `Cluster.Apply`, `Cluster.Delete` | write or remove an object |
| `Registry.PutRepository`, `Registry.DeleteRepository` | write or remove a repository |
| `Registry.MintCredential` | creates a credential that outlives the call |
| `Registry.Grant`, `Registry.Revoke` | change authorization state |
| `Registry.Push` | a data-plane write, and a production one — see below |
| `ObjectStore.PutBucket`, `ObjectStore.DeleteBucket` | write or remove a bucket |
| `ObjectStore.SetPolicy`, `ObjectStore.ClearPolicy` | change authorization state |
| `ObjectStore.Write` | a data-plane write |

**Refused in this implementation — mutating in contract, and that is the category
that decides it.**

`S3ObjectStore` refuses `SetPolicy`, `ClearPolicy` and `Write` with
`ErrObjectStoreControlPlane`, because authorising an OIDC subject against a bucket
has three incompatible vendor forms (AWS via `AssumeRoleWithWebIdentity`, MinIO via
a policy claim inside the token, Ceph RGW via its own dialect). That is the fact a
third implementation needs, and it is why this is a contract statement rather than
an excuse.

**These three are the reason a two-way partition is wrong.** A behaviour-derived
partition would classify them as *safe*, because in `S3ObjectStore` they
demonstrably do not mutate — they return an error. It would then hand the
acceptance phase three methods that mutate in contract, with the compiler's
authority behind the mistake. **A wrong partition is worse than no partition: it
compiles and reads as enforcement.**

### `Registry.Push` is reclassified, and the doc comment is wrong rather than the code

`Push` is a mutating data-plane operation with a production caller. The interface
comment claiming it exists for the harness is corrected, not the call site:
`imageBuilder.Build` pushes built images, which is what a builder is for.

### What the completeness checks have to establish

A declared partition is a list, and a list rots. Three rules, each mirroring a
construction this package already relies on:

1. **Every seam method appears in exactly one category.** An unclassified
   twenty-fifth method is fatal, not skipped — the same rule as
   `AllCapabilities` and the narrowing gate. A derivation that finds nothing is
   not a pass, so an empty method set is fatal too.
2. **`refused-in-this-implementation` expires when it stops being true.** It is a
   per-implementation fact inside a per-interface partition, so an implementation
   that begins honouring `SetPolicy` must not silently move it. The check fails
   when the refusal no longer holds, rather than when someone remembers.
3. **A method documented as existing for one purpose only must have no caller
   outside that purpose.** This is the check that would have failed on the day
   the `Push` sentence was written, and it generalises past this entry: every
   *"this exists for X only"* doc claim is a checkable assertion about call sites,
   and nothing currently checks any of them.

### What this entry does not settle

The structural barrier itself — the read-only seam view, and threading it through
nine mutating methods — is not decided here. This entry fixes only the set of
methods such a barrier may admit, because that set was the part that could not be
derived and therefore had to be argued rather than computed.

And the barrier will not close the class on its own. An apply that fails *after* a
grant still leaves the grant made and the resource absent; that needs grant-last
or explicit compensation, and no ordering or type boundary reaches it.
