## USOSS-14 — the Postgres extension allowlist is a privilege boundary, and its accepted language is exactly the list

`IsAllowedDatabaseExtension` (`database/application.go:85-89`) is ported as
`postgres.IsAllowedExtension` with its membership rule and its reasoning intact.
Two things about it are now written down, because both were implicit.

**It is a privilege boundary, not a compatibility list.** `CREATE EXTENSION`
executes the extension's own SQL script with the installing role's privileges,
and a managed database's admin account is a member of the instance's privileged
role. Several extensions ship functions that read the filesystem, execute code in
an untrusted language, or open network connections. An application that could
name any extension could therefore turn "install a search index" into arbitrary
execution inside the database.

**The check is exact, and that exactness is the control.** It is not
case-insensitive, it does not trim, and it does not normalise. Every one of those
would make the accepted language larger than the list, and a control whose
accepted language is larger than its allowlist has an unenumerated surface. The
test quantifies over the allowlist itself, mutated every way a normalising
implementation would forgive — case, whitespace, quoting, schema qualification,
appended statements, a Unicode look-alike — so the population grows with the
list rather than being a set of names somebody chose.

### One deliberate behaviour change

A name not on the allowlist **fails the whole call**, before any statement runs.
The source logs a warning and continues (`database_extensions.go:55-58`), which
ships a successful deploy of an application whose database is missing the type it
depends on; the failure then arrives at runtime as "type vector does not exist",
from a component nobody was changing. The source's own API layer refuses the same
set (`services/application.go:1187-1188`), so its two halves disagree — this
agrees with the half that fails closed.
