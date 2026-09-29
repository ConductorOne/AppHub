## USOSS-11 — the ECS port honours a secret version pin, because a valueFrom takes the selector and a grant cannot

*Recorded from the #22 × #23 collision that turned `main` red. Both PRs were
green in isolation and neither saw the other: USOSS-35 gave
[compute.SecretBinding] a Version and taught the SSM store to honour it, and
USOSS-11's container port shipped a seam type that dropped the field. The
conformance check USOSS-35 strengthened caught it on the merge.*

`security/secret-version-pin-is-honoured-or-refused` accepts a provider on either
side of its invariant: honour the pin, or refuse it with
[compute.ErrVersionPinningUnsupported]. What it does not accept is silence. This
records which side the ECS port is on and why the choice was not close.

### Honouring, because the substrate already does

An SSM parameter ARN takes a `:<revision>` selector, an ECS `valueFrom` takes
that ARN, and the store USOSS-35 landed already resolves and validates a revision
(`secretStore.revision` refuses one beyond `meta.Version` with
[compute.ErrNotFound]). Nothing about the container port made the pin
unsupportable. It was not declining — it was **discarding**: `SecretBindingRef`
flattens a binding for the caller-supplied resolver and had no Version field, so
the pin never reached the store that could honour it.

Refusing would have been the wrong answer to a defect that was one field wide,
and it would have been a worse kind of wrong: `ErrVersionPinningUnsupported`
means *this substrate has no revisions*, and SSM has revisions. A typed refusal
that says something false about the substrate is not the honest option, it is
just the quiet one.

### The two halves go to different places, and getting that backwards is invisible

This is the part worth recording, because both halves derive from the same
resolved reference and only one of them may carry the selector:

|  | Carries `:<revision>` | Why |
|---|---|---|
| ECS `valueFrom` | **yes** | it is the string that resolves the parameter at launch, and the only place a caller can confirm which revision the workload was wired to |
| IAM `Resource` | **no** | an IAM Resource element has no version component; a grant naming `…:parameter/x:3` authorises nothing |

The store establishes the split ([SecretParameterRef.baseARN] recovers the
unversioned ARN by trimming the recorded version, rather than by cutting at the
last colon — an ARN is full of colons). The container port is what **attaches**
the grant, so getting it backwards would bite here: the task definition would
look correct, the policy would look plausible, and the workload would fail to
start minutes later as a launch failure rather than at Ensure as a spec error.
[TestAVersionPinReachesTheTaskDefinitionAndNotTheGrant] asserts both directions,
including that the grant does *not* contain the versioned ARN.

### A pin the resolver did not honour is refused, not dropped

[SecretResolver] is caller-supplied, which is the whole reason the port validates
the foreign-provider, wrong-kind and placement questions itself rather than
delegating them. The pin joins that list: a resolver that accepts a pinned
binding and returns an address with no revision has reported success for work it
did not do, and trusting it would make this port silently unpin every workload it
resolved. A resolver that genuinely cannot pin has
[compute.ErrVersionPinningUnsupported] to say so.

The comparison is on **presence, not equality**. A store is entitled to normalise
a revision — the SSM one parses through `strconv` and emits the canonical form,
so `"007"` comes back as `"7"` — and requiring the string to round-trip unchanged
would refuse a correct normalisation. What cannot happen is a pinned binding
coming back with no pin at all.

### Why the check caught this and the port's own tests did not

The port had a secret-binding test, and it passed: it bound a secret and asserted
the ARN reached the task definition. It never set Version, so there was nothing to
drop. USOSS-35's check is a **differential control** — it renders the same binding
twice, pinned and unpinned over the same secret and the same variable, and
requires the pin to be the difference — and that is a shape a single-render
assertion cannot have. A test that renders one thing and looks for a needle in it
cannot distinguish "the pin was honoured" from "the pin was dropped and this
digit was already here".

### The rule

When two changes each add a field and a consumer, the field's own tests prove
nothing about the seam between them. The population that catches it is the one
that renders the *difference* the field is supposed to make — and if a provider
declines instead, it must decline in a way that names the substrate's limitation
rather than staying quiet.
