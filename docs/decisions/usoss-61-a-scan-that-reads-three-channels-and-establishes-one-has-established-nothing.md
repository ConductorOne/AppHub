## USOSS-61 — A scan that reads three channels and establishes one has established nothing

*Recorded from the USOSS-61 construction in `compute/conformance`, and from the
review that took it apart. The ruling was that the suite must be able to **demand**
a hostile mode. Round one built the demand; the review showed the demand was
scoped narrower than the claim standing on it.*

### The defect the construction closes

Four checks scan a channel for material that only arrives if the provider puts it
there. Each reported the same green whether the provider was correct or the
channel was empty. USOSS-39 found it the hard way: the credential-egress check
passed against `compute/aws`, and bypassing that provider's redacting writer
entirely did not turn it red, because the in-memory build runner wrote its own
arguments and nothing else. Every signal individually honest, the whole thing
vacuous.

> A benign fixture and a correct implementation are indistinguishable. A check
> with an input it cannot receive reports the same green as a correct provider.

So a scan does not stand on its own. Before searching a channel, a check requires
the provider to carry a marker **of the suite's choosing** into **that channel**,
and verifies it arrived by looking.

### Why a marker and not a declaration

A capability a provider declares is a claim, and a claim a provider can make
falsely reproduces the vacuity one level out — the check would then verify the
declaration. Exercise-and-verify on the *fixture* is not enough either: that is
the `InjectionFired` shape, sufficient for an injector because consumption of an
arming **is** the failure, and insufficient here because a runner can be asked to
emit, report that it did, and write somewhere the check never reads.

A marker is neither a claim nor a report. "Here is a string only I know; make it
appear where a leak would appear" cannot be satisfied without wiring the channel
the check reads. It is a positive control for the **scan**, which this suite did
not have.

### What the review found, which is the entry's title

Round one had a gate a check called before scanning, plus a table naming which
channels each check established. Both fell in one sitting:

- The credential check scanned **three** channels — the build log, the build error
  and the build result — and gated **one**. With a hook that genuinely emitted into
  the log and silently accepted the error channel, the check **passed** while
  claiming credentials appear in no log, error or result.
- Nothing bound the table to the call sites. Replacing an entry with
  `security/not-a-real-check` passed. Deleting a channel from an entry passed.
  *They were not pinned. They were spell-checked.*

The second is the same defect as an AST gate recognising a callee spelled `int32`
while a type alias walks through it: **validating that a name is well-formed is
not validating that it denotes the thing it claims.**

### The remedy: make the drift unrepresentable, then pin the population

1. **One map, both halves.** `scanChannels` takes the channels as a single map and
   uses it to establish *and* to scan. The set established and the set scanned are
   the same set by construction, so a channel cannot be added to one without the
   other. `hostileChannels()` — the table — is deleted. The reviewer's
   deleted-channel mutation is now unrepresentable rather than caught.
2. **A defect per channel.** The claim covers three channels; until now only the
   log half was pinned, because both credential defects wrote to `Logs`. So
   `DefectBuildCredentialInError` and `DefectBuildCredentialInResult` join it.
   Measured: deleting each channel from the scan turns exactly the defect for that
   channel red, and nothing else. That is the pin — derived from the self-test
   population rather than asserted in a table.
3. **The table that remains is derived.** `unverifiableByMarker` is audited against
   the check names the suite actually schedules, not against a name pattern. The
   fabricated-name mutation now fails.

### Two smaller findings, both from writing the fixtures

**A hook that emits on one route out of several is a false declaration that just
refuses less honestly.** Both providers consulted the build-error emission at one
point mid-build, and the suite's own failing-build fixture — a destination in no
repository — fails *before* that point. So the emission is now applied to whatever
error a build returns, in both `compute/fake` and `compute/aws`.

**An emission established and left armed poisons the run it was meant to make
meaningful.** An armed build-error makes every later build fail, which turns the
material scan into a skip and hands back the vacuous green by another route. So
the marker is cleared between establishing a channel and scanning it, and an empty
marker is defined to clear.

And a consequence of the second: the credential check's error reader must fail the
build **for a reason of its own** — the marker is gone by scan time, so a reader
whose only source of failure was the marker would scan a nil error. Established,
then read empty, every time.

### What this cannot do, stated rather than papered over

It works for a channel the suite owns or is handed: a writer it supplied, an error
it received, a status field it read back. It does **not** work for a
provider-supplied *enumeration* — contract rule 9 — because a hostile mode can put
a marker into an artefact and nothing stops the provider omitting that artefact
from what it enumerates. The scan then sees a non-empty set, a marker that arrived
through another artefact, and the leaking item silently absent.

The split, derived: **4 checks read a channel the suite owns, 12 read
`Options.Rendered`.** The four are constructed; the twelve are recorded in
`unverifiableByMarker` with USOSS-48's per-resource correspondence hook named as
what closes them.

### The consequence for providers, which is not a regression

`compute/fake` and `compute/aws` supply the hostile mode. `compute/k8s` does not,
so three checks that used to report PASS there now report **NOT VERIFIED**. That
is the ticket's whole point rather than a loss: those passes were the vacuous kind,
and the set of checked invariants is unchanged. Wiring `compute/k8s`'s hostile mode
belongs to that provider's owner.
