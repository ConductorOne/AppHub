## USOSS-59 — One recursive reachability walk, and a redacting type's surface is methods AND fields

*Recorded from the third and fourth defeats of a redacting type's gates in one
evening, both found by a reviewer mutating the finished construction rather than
reading it. Neither was a live leak; both were gates reporting success on exactly
the input they existed to reject.*

### The rule, two halves

**1. There is ONE recursive reachability walk, in `internal/reachable`, and every
leak and recombination check in the repository uses it.**

It recurses through structs, pointers, interfaces, slices, arrays and maps with
**no depth cap** — cycles are bounded by remembering visited addresses, because a
depth cap is a silent bound wearing the costume of a safety measure. A
`reflect.Kind` with no explicit case is a **fatal error, not a skip**: a walk that
shrugs at what it does not understand is the bypass. It asserts non-emptiness and
reports a visited count, so a walk that stops finding things fails rather than
passes. Locations reflection can see but cannot read — a func's captured
variables, a channel's contents — are reported as unreadable **with their paths**
rather than dropped, because "there was nothing there" and "I could not look" are
different facts and only one is safe to build an invariant on.

**2. A redacting type's exported surface is checked in two halves: a named
allowlist of methods, and an EMPTY set of exported fields.** Both derived from the
type — methods over the method *sets* of `T` and `*T` with promotions, fields via
`reflect.VisibleFields` so a promoted field counts.

### Why one walk, and not three careful ones

There were three, at three depths, and the shallowest was the one guarding actual
credential material:

| walk | bound | consequence |
|---|---|---|
| `RecombiningEveryReachableField` | depth 1; returned nil for a struct field | a key moved into an unexported one-field holder **inside** `Secret` was invisible; the suite stayed green while an outside probe recovered all 39 plaintext bytes |
| `recordFields` | depth-8 cap, depth-first while documenting breadth-first | a walk whose documentation described a different traversal than it ran |
| the leak probe | exhaustive over output paths, no reconstruction axis | exhaustive over the wrong axis, in the very PR whose report named that failure |

**And the name was the tell.** A test called *RecombiningEveryReachableField* that
visits depth one is worse than an absent test, because the next person reads the
name and stops looking. So a bounded walk states its bound in its name and its
doc, or it has no bound.

### Why the attack reimplements the derivation instead of calling ours

`internal/reachable` has its **own** `SHA-256(key||nonce||block)`. A recombination
test that calls the shipped keystream shares the shipped keystream's bugs: a
derivation that quietly stopped using its key would faithfully fail to reverse
anything and report a pass. The reviewer's recovery worked precisely because they
wrote the four lines out themselves.

The obvious objection is drift — an independent copy that falls behind attacks a
construction nobody ships and reports "not reversible" about the wrong thing. That
is answered by **asserting** the agreement rather than hoping for it: every caller
of the recovery first requires the two derivations to agree on a known key and
nonce, so a divergence is a loud failure instead of a silently disarmed attack.

### Why the field half exists

A reviewer added `Leak func() string` to `credentials.Secret`, populated with a
closure returning the material. The full suite **passed** and `{{call .Leak}}`
rendered every byte. A method-name allowlist cannot see that: nothing on the
method set changed.

`Secret`'s own documentation already said unexported fields were the design. It
had no test, so the invariant existed only as prose — which is the population
hazard landing inside the fix for the population hazard. Both halves now have a
control that must be flagged: an embedded type carrying an exported promoted
method *and* an exported promoted func field. Without the control, the emptiness
assertion passes just as well when the derivation reads the declared field list.

### Two more requirements, both from defeats of the walk itself

**Slices are read to CAPACITY, not to length.** Every byte in a backing array past
a slice's length is reachable — `reflect.Value.Slice(0, Cap())` works on a slice
obtained from an unexported field, no `unsafe` — so a `Len`-bounded walk is one
whose population is the bytes it chose to look at. A reviewer put a 32-byte key in
the capacity of a `len=1 cap=32` view and recovered 43 of 43 bytes while the walk
reported no 32-byte blob.

**The cycle identity carries the view's capacity.** A cycle guard exists to stop
infinite recursion; an identity that is too narrow does not stop recursion, it
**skips** a value it has not seen. With identity `(pointer, type)`, two slices over
one array were conflated, and walking `key[:1]` first meant declining to walk
`key[:]`. Guard on identity, and make sure the identity is the whole thing.

Length is deliberately *not* in the identity. It was, and a mutation showed it
carried nothing: the walk reads `[0, Cap)` regardless of `Len`, so two views with
the same capacity are read identically. An inert component of a security identity
looks exactly like coverage — which is why each half of a fix is reverted
separately rather than as a unit.

### Permanent fixtures

Five shapes have now defeated a reachability walk here, and each is a fixture of
`internal/reachable` rather than of either secret type — production has none of
them, and the point is that the walk would not have noticed if it did:

- the nested one-field holder struct;
- a func field nine levels down, with a same-name direct field at depth one as a
  decoy, so a depth-capped walk reports the decoy and looks like it worked;
- two views over one backing array, the short one **cap-clamped** (`key[:1:1]`) so
  that reading to capacity cannot substitute for the cycle identity;
- a key in the **capacity** of a one-byte view;
- two views of equal length and different capacity, the cap-clamped one first —
  found by mutating the identity's components separately, not by review, and the
  reason `cap` is in the identity and `len` is not.

The third of those began as `key[:1]` rather than `key[:1:1]`, and in that form it
passed with the cycle fix reverted, because the capacity read found the key from
the short view alone. **A fixture green for a mechanism it does not name is the
same defect as a gate green on the input it exists to reject.**

### `errors.Is` cannot express "nothing was added"

A related ruling from the same review, and it is a general point. An assertion of
the form `errors.Is(err, ErrSentinel)` is satisfied by **any** wrapper, so where the
claim is *the error carries nothing of the input*, `errors.Is` is structurally
incapable of detecting a violation. Review demonstrated it: the reached path was
mutated to `fmt.Errorf("%w: %c", ErrSecretUnmarshal, lastInputByte)` and the test
passed.

Where the claim is about an error's **identity** rather than its **class**, assert
identity: `err == ErrSecretUnmarshal`. That is also what a constant sentinel's
contract promises, and it makes a byte-by-byte search unnecessary rather than
merely redundant. The sentinel-matching idiom is right everywhere else and wrong
precisely here.

The same assertion also checked two named byte spellings, which is an enumeration
standing in for a property — the property being *no byte of the input appears*, and
a third byte defeats a list of two. Where a local search is still wanted, quantify
over the input's bytes.

### The evidence for putting these tests in the shared package

Twice now, a gate somebody else wrote — in a package the branch under review does
not own — has caught something the branch's own local assertion did not.
`internal/errhygiene`'s differential check failed on the `errors.Is` mutation above
while `go test ./credentials` stayed green; and `compute`'s
`TestSecretValueDoesNotLeak` caught a whole-file restore that reverted
`compute/secret.go` on an unrelated AWS branch.

That is the argument for adversarial tests on shared types living **in the shared
package** rather than in the owning branch, demonstrated rather than asserted: the
local claim is written by the person with the local model of the type, and it is
exactly as wide as that model.
