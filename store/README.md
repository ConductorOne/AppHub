# `store/`

The single boundary between AppHub and its persistence layer (USOSS-5).

v1 ships on DynamoDB, and says so. This is **not** a cloud-agnostic storage
abstraction — that is explicitly deferred — so no document, comment, or type
name in this repository should imply otherwise.

What the fence buys is containment: every DynamoDB call in the codebase lives
behind this package, so adding a second backend later is a rewrite of one
package rather than an archaeology project. No package outside `store/` may
import a DynamoDB client.

## The fence is not just imports

An import is a dependency; an idiom is a shape. A type carrying `dynamodbav`
tags, a function taking a `"PK = :pk AND begins_with(SK, :sk)"` string, a struct
field named `GSI1SK` — none of these need the SDK in scope, and all of them mean
business logic knows which database is underneath. The source system is the
evidence: 1,456 `dynamodbav` tags and 328 GSI1 references across 38 files,
because nothing ever said they should not be there.

So `make boundary` runs two rule sets from `internal/boundary`:

| Rule | Mechanism | Catches |
| --- | --- | --- |
| `dynamodb-fenced` | the transitive dependency closure, per build target | any package outside `store/` reaching the SDK, directly or through someone else |
| `dynamodb-idiom-fenced` | parse + constant-fold every `.go` file | tags, expression strings, key names, pagination cursors, SDK request fields |

The idiom rule matches what the compiler computes, not what the file says:
string literals are unquoted, `+` concatenations folded, and constant
`fmt.Sprintf` calls expanded. It has to be. The first version compared raw token
text, and review defeated it with ordinary Go — a tag written
`"\x64ynamodbav:\"PK\""` is the real tag as far as `reflect` is concerned, and
an expression assembled by `fmt.Sprintf` from escaped fragments is the real
expression as far as DynamoDB is concerned, yet neither spelling contains
anything to match.

Comments are never inspected, so documentation is free to explain the fence — a
check that fires on its own rationale gets suppressed, and a suppressed check is
worse than none.

The folder therefore evaluates a small language, and every unmodelled corner of
that language is a bypass — which is how indexed directives
(`fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute")`) got through a version
that assumed sequential operands. So fmt's argument-selection grammar is now
enumerated exhaustively (`%%`, flags, width, precision, `*`, `%[n]`, verbs) and
anything outside it **refuses** rather than guessing; a folder that returns a
confident wrong answer is worse than one that declines, because the wrong answer
is what gets matched. Refusing is safe because a conservative net still joins the
call's constant fragments in source order, which catches any *other* helper that
concatenates its arguments — `strings.Join`, or whatever is written next.

What the rule cannot do is follow a value that is not a constant: a string built
from runtime input will not be caught, and no lexical rule can catch it. Nor is
its file *selection* its own — that comes from `ScanFiles`, deliberately, because
restating the go command's directory rules has already been wrong twice in
opposite directions (`node_modules`, which Go builds; and every directory named
`vendor`, when Go only excludes descendants beneath a vendor segment). While that
shared predicate is wrong, this rule is blind in the same places, and that is the
better trade: one wrong answer fixed once beats two maintained separately.

Both bounds are stated in `internal/boundary/idiom.go` and pinned by tests. The
rule exists to stop the fence eroding by ordinary convenience — which is how the
source system reached 1,456 tags — not to beat an author determined to hide
something from it.

Both rules have fixtures in `internal/boundary/idiom_test.go` and
`boundary_test.go` that fail before the rule exists and pass after, including
the case that motivates the second rule: a `dynamodbav`-tagged struct in
`credentials/lifecycle` that compiles with no AWS dependency at all, which the
import rule reports as zero violations.

## What is in here

| Type | Implements | Ported from |
| --- | --- | --- |
| `Client` | the table handle | `internal/database/client.go` |
| `CredentialRecords` | `lifecycle.Records` | `internal/database/credential.go` |

`CredentialRecords` is checked against
`credentials/lifecycle/lifecycletest.RunConformance` — the same suite the
in-memory `credentials/lifecycle/fake` passes. That is what makes the fake
usable as a stand-in: not that both satisfy the interface, but that both satisfy
the same behaviour. All of it is hermetic; no test here needs a table, a
credential, or a network.

## Adding a store

1. Let the consumer declare the port, in the consumer's package. `lifecycle`
   owns `Records`; a deploy store's interface belongs to `modules/deploy`. A
   port declared here would be this package's idea of what callers need, which
   is how a storage layer ends up dictating domain types.
2. Implement it here, with the storage shape in an **unexported** struct.
3. Write a conformance suite for the port next to the port, and run both the
   real implementation and a fake through it.
4. Do not add an exported interface over the SDK. That is a DynamoDB
   abstraction with a different name, and its signatures put SDK types back into
   callers.

## The ordering invariant

> Every instant this package persists is stored in a form whose lexical order is
> its temporal order.

DynamoDB compares strings bytewise and does not know they are times, so a range
filter over timestamps is correct only if the encoding makes byte order
chronological. Three defects here were that not holding — a variable-width
fractional part, the same in a sort key, and an expiry written in a `+14:00` zone
that sorted a year above a UTC bound and was therefore **never swept**, leaving a
credential the platform believed live indefinitely.

The first two were patched case by case, which is how the third survived: each
gap sat one generalisation away from a test already written. So there is now one
encoding (`store/instant.go`), one type that carries it, and a property test over
the pair — `encodeInstant(a) < encodeInstant(b)` if and only if `a` is before `b`
— rather than a third patch.

**The reader is strict, and that is the honest position rather than the generous
one.** It briefly accepted any RFC 3339 string, so that a row written by an older
build would stay readable. That was false comfort: a reader sits *downstream of the
query*, and `ListExpiring` compares stored bytes, so an offset-spelled expiry is
excluded before any decode runs. The permissive path read such a row perfectly well
through `Get` while the sweep that actually matters could not see it — coverage
exactly where it was not needed and none where it was.

Nothing has ever written another encoding: this package was introduced with this
one and nothing is deployed. So a differently-spelled row is an out-of-band write
or a bug, and the reader says so loudly on every path except the filter that
excludes it first. If a migration ever becomes necessary the answer is a migration
pass, not a permanently widened scan bound — widening far enough to catch a
`+14:00` spelling means reading an extra day of records on every reconciler pass,
forever, to protect against data that does not exist.

## Known scaling limitation

Three of `CredentialRecords`'s queries are full-table `Scan`s with filter
expressions, inherited from the source (`ListByApplication`, `ListByStatus`,
`ListExpiring`). DynamoDB filters *after* reading, so their cost grows with the
table rather than with the answer. This is recorded rather than hidden and is
deliberately not fixed here: the fix is a GSI keyed by status and expiry, which
is a schema change. Because `lifecycle.Records` does not encode the scan, that
change stays inside this package.
