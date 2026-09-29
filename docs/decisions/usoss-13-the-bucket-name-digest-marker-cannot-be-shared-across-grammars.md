## USOSS-13 — the bucket-name digest marker cannot be shared across grammars

*Recorded from USOSS-13's re-integration onto USOSS-10's naming spine. The
injectivity property is USOSS-10's and unchanged; what changed is that the
separator it depends on became a parameter, because no one string is safe in
every grammar this package writes into.*

`sanitizeWith` renders a logical name as a physical one, injectively. The
argument for injectivity rests entirely on the digest marker being **unreachable
in a lossless name**: `notAllowed` replaces every run of non-alphanumerics with a
single hyphen, so a name that survives verbatim provably contains neither a full
stop nor a double hyphen. The marker therefore means "a digest follows" and can
mean nothing else.

That argument is per-grammar, and the grammars disagree.

| grammar | limit | `.` | `--` |
|---|---|---|---|
| ECR repository | 256 | legal | **illegal** |
| IAM role | 64 | legal | legal |
| STS session name | 64 | legal | legal |
| S3 bucket | 63 | legal **but harmful** | legal |

**Legality was never the test, and that is the part worth recording.** A dot is
legal in an S3 bucket name and it breaks the bucket: virtual-hosted-style
addressing puts the name in a hostname label, so a bucket with a dot cannot be
reached over HTTPS without failing certificate validation — the wildcard
certificate covers one label and a dot adds another. AWS's own guidance is not to
use them. Nothing rejects such a name; it is created successfully and fails later,
in a client, as a TLS error that does not mention the bucket name.

So `sanitizeWith` takes the marker and every call site names its own. One
implementation of the injective mapping, four callers that state their own
separator: **two implementations of one property is how the property drifts.**

### What made the fourth caller visible

Only the explicit per-call-site marker did. There were three known grammars when
this started; `builder.go` sanitises STS session names against `maxSessionName`,
and a package-level default would have let that fourth caller inherit a separator
nobody had checked against its grammar. Passing it explicitly turned an invisible
inheritance into four visible decisions.

### The property is quantified over the marker, and that is checked

`TestSanitizeIsInjective` runs over every marker the package uses, not the one
that happened to be first. Setting the bucket marker to a single hyphen — a string
`notAllowed` *can* produce, so reachable in a lossless name — makes the property
report a collision. Without that quantification a future marker chosen without the
unreachability argument would pass silently.

### Also refused, for the same "legal but harmful" reason

AWS reserves bucket-name affixes: the `xn--` punycode prefix, `sthree-`,
`amzn-s3-demo-`, and the `-s3alias` / `--ol-s3` / `--x-s3` suffixes. A name landing
on one is rejected by S3 with a message about the affix rather than about the
configured prefix that produced it, so `bucketName` refuses it where the caller
can see which half to change.
