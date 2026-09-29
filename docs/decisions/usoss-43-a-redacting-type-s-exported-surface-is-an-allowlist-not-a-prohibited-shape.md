## USOSS-43 — A redacting type's exported surface is an allowlist, not a prohibited shape

*Recorded from the supervisor's round-two ruling on PR #28, which reversed the
remedy the reviewer proposed. The reviewer was right that the gate was defeated
and right about both bypasses; the fix they asked for would have been defeated
again by the next member of the same grammar.*

### The rule

**On a type whose job is to redact, the exported methods that may exist are
exactly the ones on a named list, over the method sets of `T` and `*T`,
promotions included. Anything not on the list is fatal — whatever its arity,
whatever it returns. No shape test, no result-type test, no recogniser.**

The list licenses a method's *existence*. It does not license its body: that
each listed method redacts is asserted separately, by the fmt verb table, the
slog and JSON paths, and the rendering probe. Neither half is sufficient, and
this ticket cost three review rounds because each round dropped one of them.

### What was tried first, and why enumerating the grammar loses

The first gate prohibited a shape: exported, no arguments, exactly one `string`
result, on the claim that this was "the only shape `text/template` can call by
name". Two counterexamples, both from `text/template`'s own documentation and
both reproduced against the finished type with every gate green:

```go
func (s SecretValue) Leak(_ string) string      { return RevealSecret(s) }      // {{.Leak "x"}}
func (s SecretValue) Leak() (string, error)     { return RevealSecret(s), nil } // {{.Leak}}
```

The proposed remedy was to widen the prohibition to "any arity returning
`string` or `(string, error)`". That loses too, and not because of carelessness:
`{{.M}}` renders whatever comes back through `fmt`, so a method returning
`[]byte`, or a named type whose own formatting reaches the material, leaks
identically. A denylist of leaky result shapes is a hand-maintained restatement
of somebody else's grammar, and the next member of that grammar is always
available.

The parallel USOSS-53 work put a number on the same argument from the other
direction: enumerating the `fmt` verb space found **462** leaking paths on an
unhardened redacting type where a hand-written probe had found five.

So the prohibition is inverted. Adding to the surface becomes an edit to a list
— a decision someone makes, in a diff a reviewer reads — rather than a signature
that happens to fall outside a recogniser.

### The surface is methods AND fields

**The method allowlist alone is insufficient, and a reviewer showed why within the
hour: an exported FIELD is template-reachable with no method involved.** They added
`Leak func() string` to the sibling redacting type, populated with a closure
returning the material, and the full suite passed while `{{call .Leak}}` rendered
every byte. Nothing on the method set changed, so nothing a method allowlist can
see changed.

So the rule has two halves: a named allowlist of methods, and an **empty** set of
exported fields — derived with `reflect.VisibleFields`, so a field promoted from an
embedded type counts. Both halves have a control that must be flagged; without one,
the emptiness assertion passes just as well when the derivation is reading the
declared field list instead of the visible one.

Worth naming plainly, because it is the same defect one level up: *the population
contained only the shapes that had already been seen*. That is the hazard this
whole record is about, and it landed inside the fix for it.

### Why the list must also be checked for staleness

An entry naming a method that no longer exists is a standing licence for
whatever is added under that name next. `String` and `GoString` were deleted
from this type; had they been listed rather than removed, the list would still
authorise reinstating them. So every entry must resolve to a real method, and an
entry with no stated reason is not a licence at all.

### Why the behavioural probe stays, with a narrower claim

The structural rule cannot see a body. The rendering probe can, and it caught
`LogValue` and `MarshalJSON` bodies mutated to return the material while both
names stayed on the list.

What the probe may no longer claim is coverage of the class. A template command
may pass arguments to its final method, and no probe can synthesise a meaningful
argument for an arbitrary signature — a plausible zero value is not a plausible
argument, and invented arguments produce panics rather than evidence. So the
probe renders the niladic subset, one result or two with an `error` second, and
says in its own text that the class is carried structurally. An "it rendered
nothing, so nothing leaks" line is not a result and no longer reads as one.

Two layers that look redundant are not. `fmt` handles `%p` **before** it
consults `fmt.Formatter`, so no method can redact a pointer verb — a type with a
`Format` method still renders `%!p(compute.SecretValue={...})`. Field masking
closes that; `Format` closes the verbs masking does not reach. Neither may be
dropped on the grounds that the other exists.

### The justification shape this retires

Three gates on this project have now been defeated at the same joint: a rule
stated over a population, where the population was derived from what the author
could imagine rather than from the grammar the attacker actually has. "The only
shape a template can call" joins "a generic dumper does not XOR field pairs" and
"unexported closes reflection" — each true about the readers the author pictured,
each false about the language. Where a construction can make the violation
unexpressible, prefer that to any rule about which violations are recognised.
