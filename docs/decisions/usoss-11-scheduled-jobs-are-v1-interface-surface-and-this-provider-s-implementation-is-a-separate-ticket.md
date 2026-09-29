## USOSS-11 — scheduled jobs are v1 interface surface, and this provider's implementation is a separate ticket

The question the ticket asks — v1 surface or deferred — was already answered by
the interface, which is worth checking before proposing an amendment.
`compute.ContainerRuntime` declares `EnsureScheduledJob`, `DescribeScheduledJob`
and `DeleteScheduledJob` gated on `CapScheduledJob`; `compute.Schedule` pins a
grammar (five-field POSIX cron, or `rate(<n> <unit>)`) so a provider validates
and translates rather than forwarding an operator's string as the source system
does (`container.go:1434`); and `ScheduledJobStatus` is deliberately in the
synchronous class because a cron entry is live on acceptance. So: v1 surface, no
amendment needed.

What is deferred is this provider's implementation, to USOSS-33. EventBridge
Scheduler is a second substrate plus a second IAM role trusting
`scheduler.amazonaws.com` with an `ecs:RunTask` policy
(`container.go:1382-1560`), and bundling it into the largest port on the board
makes a change nobody can review carefully. The gap is discoverable rather than
silent: all three methods return a typed `*compute.UnsupportedError` naming the
capability and the ticket, and the provider does not advertise
`CapScheduledJob`, so a caller checking capabilities before deploying is not
misled.
