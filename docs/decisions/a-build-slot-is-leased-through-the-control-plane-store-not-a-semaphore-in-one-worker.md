## A build slot is leased through the control-plane store, not a semaphore in one worker

A build slot is a build task definition plus the share directory its EFS access
point confines that build to. The confinement keeps one application's source
and image out of another's build, and it holds only while one build at a time
uses a slot.

Each worker used to hand out slots from a channel in its own process.
Deployment claims were already fenced across workers, so the documentation
called several workers safe. They were not. Every worker saw every slot as
free, `prepareSlot` empties a slot without checking who is in it, and the runner
reads back whatever image the slot holds. Two workers could therefore wipe each
other's build context, or ship one application with another's image. The
startup validation build always used slot zero, so a worker starting up could
do this to a live build.

### What replaces it

* `compute/aws.SlotLeaser` is the port: `Acquire` a lease on one of the slots,
  `Confirm` it with the authority, observe `Lost`, then `Release`.
  `NewProcessSlotLeaser` is the single-process implementation, for tests and
  local runs only.
* `internal/worker.SlotLeases` implements it with one `BuildSlotLease` record
  per slot, keyed by a digest of the task definition. A worker takes a slot with
  a compare-and-swap that succeeds only when the record is absent or expired.
  It renews the lease every 15s, and a lease lives for 60s. Every acquisition
  writes a new lease ID, so a holder that lost its lease never mistakes the next
  holder's record for its own.
* The runner confirms its lease before emptying the slot, before reading the
  image back, and before cleaning up afterwards. A slot whose lease was lost now
  belongs to another build and is never touched. A lost lease cancels the build,
  which stops its task. The startup validation build leases a slot like any
  other build.
* A holder stops trusting its lease 15s before it expires. This tolerates up to
  15s of clock difference between workers.
