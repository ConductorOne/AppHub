## USOSS-36 — What the error-content invariant covers is the set of packages that drive it

*Recorded from extending the invariant to `credentials/lifecycle` and
`credentials/workload`, which USOSS-7 reported as an explicit out-of-scope gap
when it closed PR #5's error-invariant blocker. Not a regression: these sites were
never covered by the claim.*

### The claim, stated no wider than the derivation

**Every package holding the error-content invariant states it over itself, and the
covered set is exactly the packages with an `errhygiene_test.go` that calls
`errhygiene.Assert`.** As of this entry that is eight: `credentials`,
`credentials/c1`, `credentials/datadog`, `credentials/github`,
`credentials/lifecycle`, `credentials/workload`, `internal/credhttp` and
`internal/githubapp`.

There is deliberately no list anywhere in code that has to be kept in step with
this paragraph. Under USOSS-52 the covered set is a property of which packages
drive the check, so a package that stops driving it stops being covered visibly —
by deleting a test — rather than by falling off a list nobody re-reads. The
previous blocker on this invariant was precisely a claim broader than its
enforcement, and a paragraph is allowed to name today's members; it is not allowed
to be the mechanism.

### The ticket's count was wrong in the direction that matters

USOSS-36 named seven sites across two packages. There are **thirteen**:

| file | sites named by the ticket | sites actually rendering caller text |
|---|---|---|
| `credentials/lifecycle/annotations.go` | 4 | **8** |
| `credentials/lifecycle/issuance.go` | 0 | **2** |
| `credentials/lifecycle/issuer.go` | 1 | 1 |
| `credentials/workload/workload.go` | 2 | 2 |

The four extra in `annotations.go` sit five and forty lines from ones the ticket
did name; the two in `issuance.go` are in a file the ticket did not mention. This
is the third time on this project that a hand-counted site list has been short,
and it is the argument for the derivation rather than a finding about the ticket:
the fix was not to count more carefully, it was to make the derivation name the
class so that the count stops being an input.

### The fix at each site is `credentials.Foreign`, not a comment

A `Foreign` cannot be formatted into a message: every `fmt` verb, `Stringer`,
`GoStringer` and `slog.LogValuer` answers with a placeholder, and the encoders
refuse outright, so `fmt.Errorf("%q", x)` renders the placeholder rather than
leaking. Wrapping is the whole change. What survives is the shape of the message —
which field was refused, and how long it was — because a count is permitted by the
invariant and a length is often the whole of what an error needs to say.

One value is deliberately **not** wrapped: the TTL in
`lifecycle.CheckScope`'s out-of-scope refusal. It is a `time.Duration`, it cannot
carry text, and it is the one part of the request that tells an operator which
limit was exceeded.

### Verified at the resolution the failure lives at

Each of the thirteen sites was reverted individually and the extended invariant
run; all thirteen fail red, one argument at a time. Whole-string containment is
not what does the work: a one-byte leak (`string(m)[0]` in a refusal) is invisible
to containment and is caught by the differential comparison of two byte-disjoint
sentinels. A new exported input and a new error type were both added to these
packages and both fail the check, which is the requirement that an unhandled new
input fails rather than being silently skipped.

Two of the drivers written for this entry passed on the first attempt and were
wrong: the schema-key-count refusal and the over-long-annotation-value refusal
were never reached with a sentinel in the value they render, so reverting them
stayed green. Mutation found that, and the drivers were widened until every site
fired. A driver that never reaches the branch it exists for looks exactly like a
branch that does not leak.
