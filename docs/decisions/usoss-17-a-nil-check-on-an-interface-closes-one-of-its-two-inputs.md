## USOSS-17 — a nil check on an interface closes one of its two inputs

Both constructors in this port refused a missing dependency and accepted a
**typed nil** — an interface value holding a nil pointer, which is not `nil`
because the interface has a type in it. Both then returned a module that looked
wired, and both panicked on the first call. So the framework's promise, that a
constructed module is a wired module and an absent dependency returns
`modules.ErrNotConfigured`, held for one of the two ways a dependency can be
absent.

That is the exact failure the constructor convention was adopted to prevent,
arriving through the check written to prevent it.

### The remedy is a helper, because the mistake is not local

`modules.Absent` reports whether a value is unusable: an untyped nil, or an
interface holding a nil pointer, map, slice, func, channel or interface. Every
constructor in this tree uses it instead of `== nil`. It lives beside
`modules.Missing` because the two are halves of one convention, and putting the
reflection in one place is what stops the next module getting it right by
remembering.

### The test was the real defect

The guard was wrong; the test was wrong in a way that mattered more, because it
was the thing claiming the guard was right. It quantified over the
constructor's arguments — which was the right instinct, and is why this port
caught several other classes — but **its population contained only untyped
nils**. A population that contains only the shapes the implementation already
handles is a control that cannot fire.

Two changes, and the second is the one worth copying:

- **Every interface dependency is exercised with both nils.** The set of
  interface parameters is derived from the constructor's own type, and a
  constructor parameter with no typed-nil case is a test failure.
- **The field population is derived from the type, not written down.**
  `fix.New` takes a `Config`, and the test's mutation map was hand-maintained
  while its own comment claimed that a field added without a guard would fail
  it. A review added one and watched it pass. Reflection now enumerates
  `Config` and the nested `Limits`, **an unclassified field is fatal**, and a
  classification naming a field that no longer exists is fatal too — drift is
  refused in both directions.

**A test that claims a future guarantee has to derive its population from the
thing it is guaranteeing about.** Otherwise it guarantees the past.
