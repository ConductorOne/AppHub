## USOSS-75 — credentials/aws deletes its local reachability walk and calls internal/reachable directly

`credentials/aws/hygiene_test.go` carried its own reflection walk
(`reachableText`) instead of using `internal/reachable`, the walk USOSS-46
built to be the one answer to "what bytes can ordinary reflection get out of a
value?". Both walks answered the same question, and they had already
diverged: `reachableText` read a byte slice to its **Length**; `internal/reachable`
reads to its **Capacity**, specifically because a slice obtained from an
unexported field can be re-sliced to capacity with no `unsafe` at all. A
one-byte view (`len 1, cap N`) whose backing array held a sentinel past index 0
walked clean under the local instrument and would have been recovered by the
shared one. Found by #44's reviewer on the composed base; reported here as
USOSS-75.

### The two questions really are the same one

The local walk existed for a driving reason, not a reading one: this
package's client seam is unexported (`store/dynamo.go`'s pattern, applied
here so `CreateCredential` can be tested without a real STS call), and only
in-package code can build a provider over that seam. That justifies the
*fixture* — the drivers table, the render matrix, the surface accounting —
staying in-package. It does not justify a second reflection walk: `internal/
reachable.Walk(v any)` takes an `any` and returns bytes reachable from it
regardless of which package `v`'s type is defined in. There is no seam to
route around for reading, only for driving.

So the fix is deletion, not a local-delta wrapper: `reachableText` is gone,
`assertNoSentinel` calls `reachable.Walk` directly, and `TestTheHygieneFixtureCanFail`
now checks the shared walk's `Result.Blobs` instead of a local `map[string]string`.

### The control, and what it had to prove before it could count

Two instruments over one question, never compared, is how the divergence went
unnoticed. `TestTheHygieneFixtureCanFail` gained a third planted case: a
struct holding a `len 1` slice view whose backing array (`cap ==
len(sentinelMaterial)`) carries the sentinel past index 0 — the literal shape
of the missed leak. Before deleting `reachableText`, that same fixture was
run through it directly and confirmed to walk clean (`walked=map[(*root).view:S]`,
one byte, not a match); after switching `assertNoSentinel` and the control to
`reachable.Walk`, the same fixture is recovered in full. The control stays in
the tree pinned to the shared walk, so a future regression that swaps it back
out for a local, Length-bounded one fails this file directly rather than only
`internal/reachable`'s own suite three levels away.

`internal/reachable` itself needed no change: it already reads to capacity and
already has its own dedicated fixture for this exact shape
(`capacityHidden` in `internal/reachable/reachable_test.go`, from USOSS-46).
The defect was entirely in `credentials/aws` maintaining a second, weaker
instrument beside it.
