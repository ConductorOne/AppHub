## USOSS-17 — every file in the source's `security` package, ruled on

The survey spot-checked four of these. The ticket asked for all of them to be
explicitly in or out of scope, so here is the whole package, enumerated rather
than listed from memory.

The population is **8 files, 3,599 lines, all of them Go, no subdirectories**,
in the source tree at `b626d3497057955d222da805be5be81ba6109876`. Derived by,
from
`backend/internal/modules/security/`:

```
find . -maxdepth 1 -type f -print | sort          # 8
find . -type f | wc -l                            # 8  -- so no subdirectory holds anything
find . -mindepth 1 -type d | wc -l                # 0
find . -maxdepth 1 -type f -name '*.go' -print0 | sort -z | xargs -0 wc -l   # 3599 total
```

The two counts agreeing is the part that matters: a `-maxdepth 1` enumeration
that missed a subdirectory would look exactly like a complete one.

| File | Lines | Ruling |
| --- | --- | --- |
| `agent_fix.go` | 1,432 | **In.** Ported as `modules/fix`. |
| `agent_scan.go` | 781 | **In.** Ported as `modules/review`. |
| `agent_scan_test.go` | 360 | **In, rewritten.** Not ported as source; the ported packages carry their own hermetic suites. |
| `deepsec_scan.go` | 558 | **Out.** |
| `deepsec_sandbox_test.go` | 155 | **Out**, with `deepsec_sandbox.go`. |
| `deepsec_sandbox.go` | 113 | **Out.** |
| `scan.go` | 101 | **Out.** |
| `pentest.go` | 99 | **Out.** |

### `scan.go` and `pentest.go` — out, because they do not do anything

Both are complete `Module` implementations that implement nothing. `scan.go:38-41`
is a comment reading "In a real implementation, this would: 1. Trigger
appropriate scanner ... 2. Queue the scan job", followed by a return of
`{"status": "queued"}`. `pentest.go:38-41` is the same shape: "1. Create a pen
test request ticket", then `{"status": "pending_scoping"}`. Neither has a
collaborator, a store, or a side effect.

They are out of scope not because they are unfinished but because of what they
are unfinished *at*. A module in a security repository named "Run Security Scan"
that accepts a target, reports success, and does nothing is a false assurance,
and it is worse than the absence of the feature: absence is visible. Shipping
them would also import their validation, which type-asserts required parameters
without checking they are present (`scan.go:57-66`, `pentest.go:55-61`) — a
`params["target"].(string)` on an absent key panics in `Execute`, which is
reached because neither module calls its own `Validate` against undeclared keys.

### `deepsec_scan.go` and `deepsec_sandbox.go` — out, on four independent grounds

Any one of these would be enough.

1. **They are a third tool's integration, not this capability.** The module
   shells out to an external `deepsec` CLI resolved from a repository's own
   dependency set (`deepsec_scan.go:296-337`). That is a different capability
   from the one this ticket ports, and it belongs to whoever ships that CLI.
2. **They read the environment from library code**, four variables across the
   two files (`deepsec_sandbox.go:55`, `deepsec_scan.go:296,300,319`), which is
   the pattern the decision above removes.
3. **They carry internal detail in their comments.** `deepsec_sandbox.go`
   names an internal infrastructure path and two internal secret names in prose
   describing what the sandbox withholds.
4. **`deepsec_sandbox.go` documents a re-accepted residual vulnerability.** Its
   own comment records that the scan step must hold a model API key while
   running code resolved from the scanned repository's dependencies, and that a
   malicious dependency can therefore read it. The mitigation is real and
   carefully reasoned, and the residual is deliberately accepted — but
   publishing a component whose documentation is a precise account of how to
   reach a secret through it is a decision above this ticket. It is reported,
   not fixed, and not ported.

### `agent_scan_test.go` — in scope, not ported as source

Its 360 lines are worth reading and were read. They are not carried across
because they test the source's shape: setter wiring, the source's persister
interface, the source's AI types. The ported packages test their own, and test
more of it — see the security review entry below for what the new suites found
that these did not.
