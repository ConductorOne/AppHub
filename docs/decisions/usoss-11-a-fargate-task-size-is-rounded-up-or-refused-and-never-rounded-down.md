## USOSS-11 — a Fargate task size is rounded up, or refused, and never rounded down

`compute.Resources` requires a provider that cannot honour an allocation exactly
to round **up** and say so in `Status.Message`, or refuse. The source system does
neither: it passes the caller's numbers into `RegisterTaskDefinition`
(`container.go:746-748`), so a combination Fargate does not offer is rejected by
the API — fail-closed, but with no adjustment and no report.

This port resolves a request to the smallest Fargate size at least as large in
**both** dimensions, reports the adjustment in `Status.Message`, and returns
`ErrInvalidSpec` for a request larger than the largest size on offer. Rounding
down is never reachable, including in the case that is easy to get wrong: a
memory request whose step-rounding would exceed its CPU tier's ceiling moves to
the next tier up rather than being clamped to the ceiling.
