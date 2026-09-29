## USOSS-5 — persistence is DynamoDB, fenced, and says so

v1 ships on DynamoDB behind the single `store/` package. This is **not** a
cloud-agnostic storage abstraction — that is explicitly deferred — and no
document, comment, or type name in this repository should imply otherwise.

`make boundary` rejects a DynamoDB import from any package outside `store/`, on
the same mechanism as the c1 rule. What the fence buys is containment: a second
backend later is a rewrite of one package rather than an archaeology project.

### The fence has two halves, because imports are the easy half

An import is a dependency; an idiom is a shape. A `dynamodbav` struct tag, a
`"PK = :pk AND begins_with(SK, :sk)"` string, a field named `GSI1SK` — none of
these need the SDK in scope, and each one means business logic knows which
database is underneath. The source system shows what happens when only the first
is policed: 1,456 `dynamodbav` tags and 328 GSI1 references across 38 files.

So `internal/boundary` carries a second rule, `dynamodb-idiom-fenced`, which
inspects every `.go` file and fails the build on tags, expression strings, key
names, pagination cursors, and SDK request fields outside `store/`. The
motivating fixture is a `dynamodbav`-tagged struct in `credentials/lifecycle`
that compiles with no AWS dependency: the import rule reports zero violations
on it.

**It matches meaning, not spelling, and that distinction was earned.** The first
version compared needles against raw token text and review defeated it with
ordinary Go: a tag written `"\x64ynamodbav:\"PK\""` is the real tag to
`reflect`, and an expression assembled by `fmt.Sprintf` from escaped fragments is
the real expression to DynamoDB. Neither spelling contains a needle, both
compile, and the gate passed. It now parses rather than tokenises — string
literals unquoted, `+` concatenations folded, constant `fmt.Sprintf` calls
expanded — and comments are still never inspected, so this file can go on
describing the idiom it forbids.

That is the third time on this project that a lexical check matching source
spelling lost to a language feature: the import checker fell to build tags twice
and the secret gate to quoting twice.

**And a fourth time, from the same root.** Matching meaning means evaluating a
small language, and every unmodelled corner of that language is a bypass:
`fmt.Sprintf("%[2]s_%[1]s(PK)", "exists", "attribute")` produced the real
expression while the gate passed, because indexed directives are not sequential.
So fmt's argument-selection grammar is now enumerated exhaustively — `%%`, flags,
width, precision, `*` width and precision from operands, `%[n]`, and verbs — and
anything outside it **refuses** rather than guessing. A folder that returns a
confident wrong answer is worse than one that declines, because the wrong answer
is what gets matched against. Refusing is safe because a conservative net still
joins a call's constant fragments in source order, which catches any other helper
that concatenates its arguments — `strings.Join` was a live bypass found while
reproducing this one.

Two bounds are stated in the code and pinned by tests rather than left implied.

A string whose forbidden part exists only at runtime is not caught, and no lexical
rule can catch it.

And the rule's *file selection* is not its own. It comes from `ScanFiles`, which
USOSS-28 has rewired onto the single exported `PackageDirs`. This rule used to keep
its own walker, and that walker had the `node_modules` bypass — a directory the go
command compiles. Restating the go command's directory rules has now been wrong
twice in opposite directions across this repository, so the copy here was deleted
rather than corrected: one owner, one fix site, and this rule inherits it without
being touched. Verified by composition rather than assumed — the rule as written
here, unchanged, finds a needle in `node_modules/park/leak.go` when placed on
USOSS-28's branch.

The rule exists to stop the fence eroding by convenience, which is how the source
system reached 1,456 tags, not to beat an author determined to hide something from
it.

### One invariant for persisted instants

DynamoDB compares strings bytewise and does not know they are times, so a range
filter over timestamps is correct only if the encoding makes byte order
chronological. Three defects in `store/` were that not holding: a variable-width
fractional part, the same in a GSI sort key, and an expiry written in a `+14:00`
zone that sorted a year above a UTC bound and was therefore **never swept** — a
credential that had genuinely expired and that the platform believed live
indefinitely.

The first two were patched case by case, and that is precisely how the third
survived: each gap sat one generalisation away from a test already written. So the
rule is stated as a class, in `store/instant.go`, with a property test rather than
a third patch:

> Every instant the store persists is stored in a form whose lexical order is its
> temporal order.

One encoding, one type carrying it, and `encodeInstant(a) < encodeInstant(b)` if
and only if `a` is before `b`, over a corpus chosen for the things that broke.

The reader is strict for the same reason. It briefly accepted any RFC 3339 string
so older rows would stay readable, which was false comfort: a reader is downstream
of the query, and the filter compares stored bytes, so an offset-spelled expiry is
excluded before any decode runs — the permissive path read such a row fine through
`Get` while the sweep that matters could not see it. Nothing has ever written
another encoding, so the claim is withdrawn rather than half-honoured, and a
mis-encoded row now fails loudly on every path except the filter that excludes it.
A migration, if one is ever needed, is a migration pass and not a permanently
widened scan bound.

### What was ported, and what was not

The survey found 9 files (~8,800 lines) of `internal/database/` reachable from
the porting paths. This ticket ports **one** of them — `credential.go`, as
`store.CredentialRecords` implementing `lifecycle.Records` — and defers the rest
deliberately.

The reason is that a port needs a consumer. `lifecycle.Records` exists because
USOSS-3 declared it, so there is a contract to implement and a caller to satisfy.
The other eight files serve `modules/deploy` (USOSS-15) and
`modules/review`/`modules/fix` (USOSS-17), which are currently `doc.go` stubs
declaring no ports at all. Porting `ApplicationRepository` now would mean
inventing those ports on the consumers' behalf, from this side of the boundary —
which inverts the rule that makes the fence work, and would land ~8,000 lines of
code with no caller, against the no-dead-code bar.

What this ticket delivers instead is the seam and its enforcement, so USOSS-15
and USOSS-17 land their persistence behind an already-load-bearing fence rather
than needing a second cleanup pass. The `store/README.md` "Adding a store"
section is the procedure they follow.
