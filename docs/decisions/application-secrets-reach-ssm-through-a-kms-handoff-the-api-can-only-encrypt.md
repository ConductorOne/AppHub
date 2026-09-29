## Application secrets reach SSM through a KMS handoff the API can only encrypt

An application owner sets secrets in the portal, and the workload receives them
as environment variables resolved from SSM SecureString parameters. The value
has to travel from a browser to the worker, which is the only process holding
the deploy credential that writes SSM and converges the per-service execution
role's exact-ARN read grant (USOSS-11). The API deliberately holds no cloud
deploy credential (README, "Give the API only its persistence permissions"), so
it cannot write the parameter itself.

### The handoff

* `serve` encrypts each value with a dedicated symmetric KMS key under an
  encryption context of `apphub:application`, `apphub:secret` and
  `apphub:deployment`, and stores only the ciphertext on the one deployment
  record that applies it. Its IAM allows `kms:Encrypt` with all three context
  keys present and explicitly denies `kms:Decrypt` on the key.
* `worker` decrypts with the same context (`kms:Decrypt` only), passes the
  value to the deploy module in memory through `deploy.SecretValueSource`, and
  the module writes it through the target's existing secret store — so the
  parameter carries the provider's ownership tags and the binding uses the
  reference the provider issued (USOSS-15), never a composed path.
* The ciphertext is cleared when the deployment finishes, is interrupted, or
  its interruption is resolved. The application record keeps names only.

A secret change reuses the image of the last successful deployment when that
deployment was of the current revision (`deploy.Application.PinnedImage`): the
worker fetches no source, the module builds nothing, and only the task
definition and service converge. Any other state builds first, so an image is
never run against a specification it was not built from.

Save and redeploy are one operation: there is no stored-but-undeployed value,
so nothing waits in the table for a deployment that may never come.

### Alternatives refused

* **The API writes SSM directly**, write-only like the GitHub App key. It would
  have to restate `compute/aws`'s parameter naming and ownership tags, and the
  worker would bind by a path it composed — both of which USOSS-15 refuses —
  and it would give `serve` a cloud permission over every application's
  parameters.
* **Plaintext, or a value hash, in the control-plane table.** The idempotency
  hash of a secret change covers names and actions only; a durable hash of a
  low-entropy value is an offline guessing oracle.

### Limits that follow from the transport

A value is at most 4096 bytes (SSM standard tier, and under KMS Encrypt's
4 KiB), one save carries at most 48 KiB of values so the sealed batch fits the
128 KiB checkpoint document limit, and an application holds at most 50 secrets.
