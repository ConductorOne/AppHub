## USOSS-6 — `userID` identifies the requester and obliges nothing further

Recorded because review found two successive wrong statements of it, and because
whichever way this lands, USOSS-15 and USOSS-17 inherit it.

`Execute`'s `userID` argument identifies the requester. **Authorisation happens
before dispatch**, and no module derives a permission from it — verified across
all nine ported implementations, none of which does. That much is a real
inherited property and the interface says so.

Beyond that, **this repository requires nothing**. In particular it does not
require a module to record `userID` on what it writes. The enumeration:

| What the module does with `userID` | Count | Where |
| --- | --- | --- |
| Records it on what it writes | 2 of 9 | `security/agent_scan.go:488`, `security/deepsec_scan.go:191` (both a `requestedBy` field) |
| Discards it explicitly | 1 of 9 | `security/agent_fix.go:692` (`_ = userID`) |
| Never references it | 6 of 9 | security scan, pentest, vendor review, both deploy modules, announce delivery |
| Derives authorisation from it | 0 of 9 | — |

It can also be **empty**: one of the five dispatch paths
(`cmd/job-runner/main.go:540`) has no requester and passes `""`. A module that
records it unconditionally would be recording an empty requester on that path.

So universal attribution is not available to state as inherited, and it is not
being introduced as a new requirement either. Introducing it would mean two of
the nine ports gaining recording behaviour that the source does not have and
that nothing in this repository needs yet — a migration performed by a comment,
which is the thing the entry below exists to prevent. If a later ticket decides
every module must record its requester, that is a decision with a conversion
attached, and it gets its own entry here.
