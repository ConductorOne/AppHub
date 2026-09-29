## USOSS-13 — a bucket Ref carries which service issued it

*Recorded from USOSS-13. Found by wiring the conformance suite rather than by
review: the grant check failed, and the reason turned out to be a distinction the
re-integration had dropped.*

Three AWS services provision something this interface calls a bucket — S3, S3
Tables and S3 Vectors — and `compute.KindBucket` is the only kind available for
all three. So `compute/aws` puts the flavour in the Ref's ID:
`bucket/name`, `tablebucket/name`, `vectorbucket/name`.

### Why it cannot be omitted

`ext.TableBucketProvisioner.Grant` has the **identical signature** to
`compute.Granter.Grant` and takes the same kind. One `Grant` implementation serves
both, so without the flavour it cannot know which service to check ownership
against. Two concrete consequences, both silent:

* **It would check the wrong resource.** Granting on a table bucket would read the
  *general-purpose* bucket of that name for its ownership tags — a different
  resource, possibly another account's, possibly absent.
* **Two grants would contend for one policy name.** The inline policy is named
  from the resource, so a general-purpose bucket and a table bucket sharing a
  logical name would share a policy name, and granting on one would **overwrite
  the grant on the other**. Revoking one would remove access to the other.

`TestAGrantOnOneFlavourDoesNotReachAnother` provisions both flavours under one
logical name, grants on each, and asserts the role holds two policies rather than
one — then revokes one and asserts the other survives. Making the policy name
flavour-blind fails it.

### How it was lost, and what found it

The original implementation of this port had the distinction. The re-integration
onto USOSS-10's spine adopted that spine's `ref`/`resolve`, which key the ID
prefix off `compute.Kind` alone — correct for one-service-per-kind resources, and
silently lossy for the three that share a kind.

**No review caught it and no test of mine caught it.** The conformance suite's
`grants/bucket/refused-without-the-capability` check failed on the capability, and
chasing that led to the flavour. Wiring a suite is a different act from writing
tests for one's own code: the suite asks questions the author did not think to.

### A flavour mismatch is ErrInvalidSpec, not ErrNotFound

`resolveFlavoured` refuses a Ref of the wrong flavour as `ErrInvalidSpec`. The
resource may well exist; the caller has reached the wrong port for it. Reporting
"not found" would send them looking for a missing bucket.
