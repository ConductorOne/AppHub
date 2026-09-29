## USOSS-11 — `EnsureC1DatasourceRole` is not ported, and the import graph does not enforce that

`EnsureC1DatasourceRole` (`bucket.go:683`) creates an IAM role with cross-account
trust to a named vendor's tenant accounts, keyed by external IDs, so that
vendor's product can register an application's S3 bucket as an external
datasource. It is not ported, for four reasons in descending order of weight.

**It is not a compute concept.** Neither `ContainerRuntime` nor `ObjectStore`
has vocabulary for "grant a third party cross-account read of this bucket", and
inventing some to hold one vendor's integration would put that vendor inside the
portable interface — a worse outcome than the coupling it was trying to avoid.

**It is a bucket concern, not a container one.** It lives in `bucket.go`, is
gated on `bucketType == BucketTypeGeneral`, and is merely invoked from the
container deploy path.

**Its blast radius deserves its own review.** The trust policy is built from
caller-supplied external IDs, and the source system's own rollback comment
observes that an untracked role has "live cross-account trust yet is invisible to
teardown". That should not arrive as a side effect of an ECS port.

**c1 is optional (decision 3).** An adopter with no ConductorOne account must be
able to build and run apphub.

**And the finding that makes this entry necessary rather than decorative:** the
`c1-optional` boundary rule is an *import-prefix* rule
(`internal/boundary/boundary.go:146-160`) — it denies imports of
`github.com/conductorone/*` and `github.com/conductorone/apphub/credentials/c1`. A
port of `EnsureC1DatasourceRole` takes only strings and an IAM client, so it
imports nothing c1-related. This was tested rather than assumed: a faithful
shape-of-the-port stand-in was placed in `compute/aws` and `make boundary`
**passed**, three rules held over 6,035 import edges from 1,395 files. So
nothing enforces this boundary by construction, and per lesson 1 a decision
record is the only thing holding it. If the capability is ever wanted, it belongs
in an optional package behind a narrow interface, so that the import graph makes
the optionality real instead of conventional — which is the only form of it the
checker can actually enforce.
