## USOSS-46 — a redacting type may not store its mask beside the material

`credentials.Secret` held its material XOR a mask, with the mask stored in the
adjacent field. The justification, recorded at the time, was that *"a generic
dumper does not XOR field pairs"*.

That is retired, and the reason generalises past this type: **it is a claim about
what readers do, not a property of the type.** Eleven lines of ordinary
reflection falsify it — walk the fields, XOR each reachable byte pair, compare —
and the reproduction needs no `unsafe`, no build tags and no unusual code.

It is the same shape as two other claims this project falsified within a day:

* *"unexported closes reflection"* — it closes `Value.Interface` and closes
  setting; it does not close `Value.String` or element-wise reads.
* *"a caller passes a constant provider ID"* — a claim about call sites, used to
  justify a type that could not enforce it.

The rule that follows, and the one that binds subsequent work: **a redacting
type's resistance must be a property of its shape, not an assumption about the
code that walks it.** Concretely, the term that reverses the masking may not be
reachable from the value. Every redacting type in this repository now derives its
keystream from a package-level key that no instance references —
`credentials.Foreign`, `compute.SecretValue` (USOSS-43), and now
`credentials.Secret`.

### The key must be load-bearing, and provably so

A construction that reads a process-wide key inside its own derivation cannot be
asked whether the key matters, because there is only one key in a process. Three
separate sound checks were each demonstrated blind to a derivation that quietly
stopped using the key: the freshness check passes because nonces still differ, a
reachable-field search passes because no field holds plaintext, and a
construction-aware search for a reachable key passes *by construction* because it
hunts for something no longer in the derivation.

So the derivation takes the key as a parameter, with a delegating form under the
process key, and both halves are asserted: two keys give different output, and
the delegating form agrees with the explicit one. A rewrite that ignores the key
fails one or the other, whichever function it lands in.

### An exported method is a template call — and so is an exported field

`text/template` calls exported methods by name and reads exported fields by name,
so either one is a live template reference into whatever type carries it.

**This section originally said the prohibited thing was a SHAPE — "exported, no
arguments, exactly one string result" — and called a whitelist "not an option".
Both claims were wrong, and each was falsified by a reviewer within the day.**

The shape claim: `text/template`'s own documentation says a command's final method
may take **arguments**, and a niladic method may return **two** results with an
`error` second. Both render the plaintext. Widening the recogniser to those two
shapes loses again, because `{{.M}}` renders whatever comes back through `fmt` —
a `[]byte` result, or a named type whose own formatting reaches the material,
leaks identically. Enumerating a grammar someone else owns is not a rule; it is a
list of the cases the author happened to think of.

The whitelist claim: the objection was *"this one is allowed because its body
redacts today"*, which is a claim about a method body. That objection is answered
rather than ignored — **the allowlist licenses a method's EXISTENCE, and separate
tests hold its BEHAVIOUR.** Each listed method's redaction is asserted over the
`fmt` verbs and the slog, JSON, text and gob paths. Neither half is sufficient
alone, and dropping either is what cost three review rounds on the sibling type.

So the rule is: over the method **sets** of `T` and `*T`, promotions included,
only the methods a named list gives a reason for may exist, and **the set of
exported fields must be empty** — derived with `reflect.VisibleFields`, so a
promoted field counts. A stale list entry is fatal too, because an entry naming a
method that no longer exists pre-authorises the next method to reuse that name.

The field half exists because a reviewer added `Leak func() string` to
`credentials.Secret`, populated with a closure, and `{{call .Leak}}` rendered
every byte while the full suite passed. A method allowlist cannot see a field.

`String()` and `GoString()` are removed from `credentials.Secret` and
`compute.SecretValue`. Both redacted; both were live template calls into a type
holding credential material, with bodies a future edit could change.
`fmt.Formatter` takes precedence over `Stringer` and `GoStringer` for every verb,
so neither was load-bearing for formatting — but `fmt` resolves `%p` **before** it
consults `fmt.Formatter`, so no method redacts that verb and the field masking is
what closes it. The two defences are not interchangeable.
