## USOSS-21 — `modules/paved` is out of v1 scope

*Recorded from the USOSS-21 decision record, verbatim, except that the name of
the deciding individual has been replaced with the project.*

> ## Decision — `modules/paved` is OUT of v1 scope
>
> **Deferred to v2.** Resolved ahead of the porting work, per this ticket's own guidance to decide before the answer gets expensive.
>
> ### Rationale
>
> * The project description locks v1 at **deploy / review / fix / credentials**. `paved` is a fourth capability, and adding it widens the surface that must be ported, reviewed, conformance-tested, and — critically — **security-audited before publication** (USOSS-18).
> * `paved` (1,547 lines) uses the same `Module` interface as deploy and security. USOSS-6 ports that interface **unchanged**, so `paved` ports cleanly later through the same machinery. Deferring costs no rework — this is the cheap direction to be wrong in.
> * `paved` is AI agents that build, deploy, and tear down applications. **Teardown is a destructive capability**; shipping it in the first public release, before the Compute abstraction has been pressure-tested by a second provider (USOSS-19), is the wrong order of operations.
>
> ### What this means
>
> * No `paved` code lands in apphub this round.
> * USOSS-6 must keep the `Module` interface **general**, not narrowed to the three v1 modules — a v2 `paved` port must not require reopening the interface. Reviewers check this.
> * Re-evaluate for v2 once the Compute interface has two real implementations behind it.
