## USOSS-15 — what the deploy module deliberately does not port

The source's deploy package is 7,270 lines across twenty-one files. Most of the
bulk is AWS plumbing that now lives below the Compute interface. This entry
records what is left out for a reason other than "the provider does it now", so
that a reader can tell an omission from an oversight.

### Function workloads

The source deploys containers (`container.go`, 1,567 lines) and functions
(`lambda.go`, 1,029 lines). Only containers are ported, which is what USOSS-15
allows: *"containers can land first with function support following"*.

A function is not an image workload with a different accessor.
`compute.FunctionSpec` carries **code** — inline bytes or an object location —
and no image at all, so it needs a build-and-publish pipeline that shares nothing
with the container one, plus a `compute.EndpointSpec` to reach it through rather
than a route. An application configured as a function is refused with
`compute.ErrUnsupported` and told why, rather than deployed as something else.

`WorkloadType` keeps the value, so an application record can still express it and
the refusal can name the right thing. Everything else on the function branch was
removed rather than left dead: a branch no input reaches is a branch nobody
tests.

### Fetching the source

`SourceFetcher` is an interface this package declares and does not implement.
Cloning a repository means process execution and version-control credentials —
the source read a personal access token out of the process environment
(`container.go:167-170`) — and neither belongs in a package whose whole claim is
that it talks to one abstraction.

`ValidateSourceURL` stays, because refusing a source location is a decision this
module has to make before it hands one to anybody, and it is the one place an
untrusted value reaches this code. The host allowlist that was compiled in
(`build.go:96-98`) is configuration, and an empty allowlist refuses everything.

### Running SQL against the database

`database_extensions.go`, `postgres_roles.go` and `db_load.go` connect to a
provisioned Postgres and issue statements: `CREATE EXTENSION`, `CREATE ROLE`, and
a bulk load. No port in `compute` expresses "run SQL", and inventing one here
would be inventing an interface from one call site.

`db_load.go` is the file USOSS-15 asks to be audited because it was missing from
the original inventory. **Audited: it has no cloud SDK import at all.** Its
imports are `context`, `errors`, `fmt`, `net/url`, `strings`, `time`, and
`github.com/jackc/pgx/v5` with `pgconn`. It is a Postgres client and a
SQLSTATE sanitiser, and it is excluded for the same reason as the other two —
not because it is cloudy, but because nothing here provisions a SQL connection.

### The ConductorOne cross-account datasource role

`bucket.go`'s `EnsureC1DatasourceRole` and its lifecycle (roughly 500 lines
across `bucket.go` and three test files) create an IAM role a ConductorOne tenant
assumes to read the application's bucket. ConductorOne is optional in this
repository and only `credentials/c1` may depend on it, so a c1-specific grant
cannot live in the deploy module. The cross-domain grant port in `compute/ext`
is where it goes if it is ported.

Its constants are the three real AWS account identifiers this port must never
carry (`bucket.go:511-513`). They are not here, and no test fixture approximates
them.

### Analytic table buckets and vector buckets

The source offers five bucket types; two of them — S3 Tables and S3 Vectors —
are AWS-only, and not because the storage is hard: the *application* speaks those
APIs directly, using an ARN handed to it in an environment variable. Backing them
with something else produces an application that cannot connect. `compute/ext`
holds the ports and `BucketKind` refuses the kinds, naming the reason.

### Multi-container applications

The source reads components and builds one container definition from the first
one, warning in a log line that only the first component's credentials are
injected (`container.go:636`). `compute.ServiceSpec` describes one workload,
so this module deploys one workload per application and carries the part
components were actually used for — routing — as a first-class `Routes` list. A
genuinely multi-container application is not expressible here and is not
pretended to be.

### An end-to-end deploy against real AWS

USOSS-15's last acceptance criterion asks for one, with the results in the pull
request. **It is unmet, and it cannot be met from here**: this environment has no
AWS credentials and no network access to AWS. Every test in this package runs
against `compute/fake`. The criterion belongs to a human with an account, and is
recorded as outstanding rather than approximated with something that would read
like evidence.
