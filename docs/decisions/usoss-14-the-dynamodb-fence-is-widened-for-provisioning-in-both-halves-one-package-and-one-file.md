## USOSS-14 — the DynamoDB fence is widened for provisioning, in both halves, one package and one file

`store/` is apphub's own persistence and always will be. Provisioning a
DynamoDB table **for a deployed application**, through
`compute.KeyValueProvisioner`, is the other side of the port that fence guards:
swapping apphub's persistence to Postgres would not touch it, and swapping the
compute provider to Kubernetes makes the whole port decline. So the fence is
widened, and the widening is recorded here because it changes a gate USOSS-5
delivered.

The fence has two halves and they are separate checks. Widening one without the
other would have produced a change that did not work:

* **The import half** (`internal/boundary/boundary.go`, `dynamodb-fenced`) gains
  `github.com/conductorone/apphub/compute/aws` — the package, not a prefix above it.
* **The idiom half** (`internal/boundary/idiom.go`, `dynamodb-idiom-fenced`)
  gains two **files**: `compute/aws/awssdkdb.go` and its own test.
  `CreateTable` has to name a billing mode to get an on-demand table and
  `BillingMode` is a needle, so the first exemption is unavoidable; the test is
  named because it references the exception types whose classification it checks.
  Scoping both to the SDK adapter rather than to the package keeps the idiom
  check over the thousands of other lines that five other tickets are extending.

  The alternative to the second exemption was a fixture helper in the adapter's
  production file, which would have put a test seam in production code to satisfy
  a lint. The needle exists to stop *business logic* knowing DynamoDB's shapes,
  and an adapter's test is the adapter.

### A consequence of widening it that the fence itself created

The shared throttle-code list in `compute/aws/awssdk.go` **drops**
`ProvisionedThroughputExceededException`, and the note beside it says why: the
code is DynamoDB's, DynamoDB was fenced into `store/`, and the boundary checker
refused the string.

This decision changes that premise, and the omission stopped being theoretical
the moment a port that makes real DynamoDB calls landed: measured, a throttled
call classified as `compute.ErrFailed` — terminal — telling a caller its spec had
to change when waiting would have worked. It is now recognised in
`awssdkdb.go`, where the fence permits the name, by type rather than by string.

`TransactionInProgressException`, the SDK's other dropped DynamoDB entry, is
deliberately **not** added: it belongs to `TransactWriteItems`, and this port
issues only control-plane calls. Adding a code the port cannot receive would be
inventing coverage.

This is the class of regression a file-overlap analysis cannot see. Nothing in
this ticket edited the throttle list; the behaviour it depends on moved
underneath it.

Both are covered by fixtures that fail before the change and pass after
(`internal/boundary/database_test.go`), including the two bypasses that matter: a
prefix written one segment too short, which would take the fence off every
provider, and a file name that merely *starts* with the exempt one's.

### And a new rule, going the other way

`aws-sdk-confined` denies `github.com/aws/aws-sdk-go-v2` and
`github.com/aws/smithy-go` to every package except `compute/aws`, `store/`, and
the checker's own fixtures. It is denied by **module** prefix rather than by
service package, so a service released tomorrow is denied without anybody
editing a list.

It exists because USOSS-14's acceptance criterion was that
`database_extensions.go` has no AWS import after the port, and a structural
property of the import graph is the strongest available form of that: the whole
`postgres/` package now provably cannot reach an AWS SDK, checked by
`make boundary` on every commit rather than by reading imports. It was true
before this rule and is now enforced.
