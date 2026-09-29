## USOSS-47 — public disclosure audit

Public documentation and comments must not carry local build-host paths, private
source-system names, private repository URLs, private Squire links, AWS
account-shaped identifiers, AWS ARNs with account numbers, or URLs under
private-use DNS suffixes. The useful part of a source citation is the source
path and, when known, the enclosing symbol; the private repository name adds no
public evidence and is scrubbed.

Public and reserved-documentation URLs remain accepted: ConductorOne's published
sites, public vendor/API documentation, `example`/`invalid`/`test` fixtures, and
public source-control/module infrastructure. Link-local metadata endpoints that
appear only in tests or CI hardening are accepted as endpoint-class fixtures, not
as deployment identifiers.

The audit is not a tenant-isolation proof. USOSS-62 records AWS ownership tags as
an accepted account-scoped trust boundary: public docs must state that limitation
where operators configure AWS, but the limitation is not a publication disclosure.

The mechanical gate is `make disclosure`, backed by `go run
./hack/disclosurecheck`, and `make check` runs it. The gate scans repository
paths and text contents, fails closed on an empty traversal, and uses shape rules
for the classes that can be detected without publishing the real values.

### Audit performed

The audit walked the repository text files and path names, excluding only
`.git/`, `.tools/`, `.task-worktrees/`, `vendor/`, and `node_modules/` because
those are not published source files for this repository. The exact search set
was:

| Class | Search shape | origin/main content hits | origin/main path hits | post-scrub content hits | post-scrub path hits | Decision |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Build-host checkout path | absolute path assembled from `/`, `data/`, `squire/`, `src` | 1 | 0 | 0 | 0 | Scrub |
| Private source-system name | case-insensitive private source-system slug with dash or underscore separator | 60 | 0 | 0 | 0 | Scrub; use `source system` instead |
| Private source repository URL | `github.com/ductone/` repository path except this module | 1 | 0 | 0 | 0 | Scrub |
| Private Squire URL | HTTP(S) URL containing a Squire host/path marker | 0 | 0 | 0 | 0 | Gate |
| AWS account ARN | ARN with a twelve-digit account segment | 0 | 0 | 0 | 0 | Gate |
| AWS account-shaped number | standalone twelve-digit number | 1 | 0 | 0 | 0 | Scrub even in scanner prose |
| Private-use DNS URL | HTTP(S) URL under `.internal`, `.corp`, `.lan`, `.intranet`, or `.local` | 0 | 0 | 0 | 0 | Gate |

Baseline denominator: 664 text files, 183,288 lines. Post-scrub denominator:
667 text files, 183,715 lines. Baseline URL census: 140 HTTP(S)
occurrences across 47 parsed host strings; all were public, reserved-documentation,
fixture, or endpoint-class test values, and no private Squire URL was present.

### Baseline file:line hits

The values themselves are not reproduced here because the point of the decision
is not to re-publish them in the audit record.

#### Build-host checkout path — 1

- docs/design/credential-vending.md:19

#### Private source-system name — 60

- CONTRIBUTING.md:159
- CONTRIBUTING.md:178
- compute/aws/config.go:188
- compute/aws/configdb.go:77
- compute/aws/container_test.go:1713
- compute/aws/endpoint.go:155
- compute/aws/names.go:20
- compute/aws/names.go:734
- compute/aws/registry.go:116
- compute/aws/routes.go:24
- compute/aws/routes.go:75
- compute/aws/secret.go:111
- compute/capability.go:35
- compute/capability.go:41
- compute/capability.go:80
- compute/capability.go:85
- compute/capability.go:92
- compute/container.go:14
- compute/container.go:222
- compute/container.go:271
- compute/container.go:293
- compute/database.go:27
- compute/database.go:51
- compute/database.go:71
- compute/database.go:141
- compute/database.go:174
- compute/database.go:181
- compute/database.go:217
- compute/errors.go:86
- compute/fake/container.go:480
- compute/identity.go:78
- compute/identity.go:135
- compute/image.go:91
- compute/network.go:13
- compute/network.go:105
- compute/network.go:108
- compute/network.go:114
- compute/network.go:178
- compute/network.go:184
- compute/secret.go:32
- compute/secret.go:313
- compute/secret.go:406
- compute/secret.go:550
- compute/status.go:71
- compute/status.go:73
- compute/status.go:74
- compute/status.go:75
- compute/status.go:159
- docs/decisions/usoss-1-repo-name-licence-and-conductorone-dependency-posture.md:15
- docs/decisions/usoss-68-and-usoss-71-a-bare-citation-resolves-against-its-own-directory-and-one-external-sibling-proves-the-rest.md:16
- docs/decisions/usoss-68-and-usoss-71-a-bare-citation-resolves-against-its-own-directory-and-one-external-sibling-proves-the-rest.md:98
- docs/decisions/usoss-68-and-usoss-71-a-bare-citation-resolves-against-its-own-directory-and-one-external-sibling-proves-the-rest.md:100
- docs/design/aws-secret-store.md:121
- docs/design/credential-vending.md:19
- hack/astaudit/main.go:19
- internal/citations/citations.go:17
- internal/citations/citations.go:117
- internal/citations/citations_test.go:244
- modules/deploy/config.go:40
- modules/deploy/config.go:43

#### Private source repository URL — 1

- docs/decisions/usoss-1-repo-name-licence-and-conductorone-dependency-posture.md:15

#### AWS account-shaped number — 1

- .gitleaks.toml:37

### Consequences

A new occurrence of the scrubbed classes now fails in `make check` before it can
become review prose. Hostnames and broader secret classes continue to be covered
by `.gitleaks.toml`, `hack/check-secret-rules.sh`, and `hack/check-paths.sh`; the
new checker covers the publication-disclosure shapes that do not require the
external gitleaks binary and were not previously part of `make check`.
