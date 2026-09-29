## USOSS-12 — Lambda serialises two mutations, so an Ensure that needs both is `ErrTransient`

Recorded because it is the one place this port cannot satisfy both halves of an
interface rule at once, and because "returns an error having applied part of the
spec" is the kind of behaviour a reviewer should find written down rather than
infer.

Lambda mutates a function's configuration and its code through two API calls and
refuses the second while the first is in flight. `compute.Status` forbids
blocking inside an asynchronous `Ensure`, in as many words: "a provider that
blocks inside such an Ensure is non-conformant". The source system's answer is to
block (`lambda.go:242-245`), with a hardcoded deadline the caller cannot choose.

So `EnsureFunction` does what it can without blocking:

* a function that does not exist is **created**, configuration and code in one
  call — no conflict is possible, and this is the ordinary first deploy;
* a function whose configuration changed and whose code did not gets **one**
  mutation — the ordinary redeploy of unchanged code, which is why the code
  digest is compared rather than the code always re-uploaded;
* a function whose code changed and whose configuration did not gets one;
* a function where **both** changed gets the configuration update, and the code
  update then fails as `ErrConflict` → `compute.ErrTransient`, with a message
  saying the configuration was applied and the spec needs re-Ensuring.

The ordering is deliberate: configuration carries the execution role, so
applying configuration first means new code never runs under an old role. The
other order can.

Two `Ensure` calls is the honest cost of a substrate that serialises the two
halves. `compute.ErrTransient` means precisely "retry", which is the correct
instruction, and `Ensure` is idempotent so the retry is safe. What this must not
do is block, and it must not report success with half the spec applied.

**The claim is driven, not asserted.** `MemoryLambda` reproduces the refusal —
a mutation leaves the function `InProgress` and a second mutation while it is
returns `ErrConflict`, exactly as Lambda does — and
`TestASpecChangingBothCodeAndConfigurationIsTransientRatherThanBlocking` drives
the both-changed path, checks the sentinel, checks the call did not block, **and
checks that the retry converges**. Without that last half the test would accept a
provider that returned `ErrTransient` forever.

One asymmetry to know about: for an object-store code source the digest cannot be
compared, because the caller's deploy flow overwrites the same key, so the
location is unchanged in exactly the case where the code changed. That path
always issues the code update, and therefore always takes the two-call route when
the configuration changed too. It is the safe direction to be wrong in.
