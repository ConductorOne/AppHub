## USOSS-13 — the AWS provider does not offer zonal object storage

*Recorded from the USOSS-13 port of `deploy/bucket.go`. Binding on anything that
later wants an S3 Express One Zone bucket.*

`compute.CapObjectStoreZonal` and `compute.ObjectClassZonal` exist because the
source system provisions S3 Express One Zone directory buckets
(`bucket.go:290-336`). **`compute/aws` does not advertise the capability**, and
`EnsureBucket` refuses `ObjectClassZonal` with a typed
`*compute.UnsupportedError` naming it.

The reason is a property of the substrate, not the state of the work.
`compute.ErrNotOwned` requires that "every provider must implement an ownership
check; adopting an untagged resource is not permitted". On S3 that check is a
bucket tag — and the AWS API model, as generated into
`aws-sdk-go-v2/service/s3 v1.107.3`, documents `PutBucketTagging`,
`GetBucketTagging` **and** `PutPublicAccessBlock` each as "not supported for
directory buckets". So for a zonal bucket there is nothing to write and nothing
to read, and `CreateBucket`'s `BucketAlreadyOwnedByYou` says only that the
*account* holds the name — not that apphub created it, which is the question
the check asks, because the collision the interface is worried about is with
another resource in the same account.

Three alternatives were considered and rejected:

* **Adopt any account-owned directory bucket under the configured name prefix.**
  Prefix scoping is an argument, not a check: it lets a teardown delete a bucket
  a human created inside apphub's namespace. That is data loss.
* **Refuse to adopt at all, so only a bucket this call created is a success.**
  Breaks the idempotency every other part of the contract depends on.
* **Write a marker object inside the bucket.** Directory buckets do support
  object operations, but that is not an ownership mechanism: any principal with
  `s3:PutObject` or `s3:DeleteObject` on the data bucket can forge, replace, or
  remove the marker. The marker would also be caller-visible data in the bucket,
  so deleting or rewriting it during reconciliation would violate the port's
  ownership boundary.

Until AWS exposes a control-plane signal for directory-bucket ownership that
apphub can write, read, and distinguish from caller data, the AWS provider
permanently declines `compute.CapObjectStoreZonal`. The refusal is the
fail-closed answer and a supported state rather than a gap: "A provider without
it must not silently fall back to standard: the caller asked for a latency
guarantee."

**Two smaller refusals on the same port, for the same reason — the source's
behaviour is the floor, and new security-relevant functionality is not a port:**

* `BucketSpec.PublicAccess: true` is `compute.ErrUnsupported`. Nothing in the
  source system ever creates a publicly readable bucket — it sets all four
  public-access-block flags on every bucket it creates (`bucket.go:245-253`) — so
  implementing it would be new functionality, and the functionality in question
  is a public bucket.
* `compute.AccessAdmin` on a general-purpose bucket is `compute.ErrUnsupported`.
  A bucket has no schema, so the only thing "structural changes as well as data
  access" can mean is the bucket's own configuration — which includes
  `s3:PutBucketPolicy` and `s3:PutPublicAccessBlock`. Granting those to a
  workload would let it undo the hardening the provider applies on every
  `Ensure`. `AccessAdmin` **is** offered on a table or vector bucket, where a
  schema is a real thing and the security-control actions are excluded.
