## USOSS-68 and USOSS-71 — a bare citation resolves against its own directory, and one external sibling proves the rest

USOSS-68 named three `file:line` citations that were never correct: one pointed
thirteen lines past the end of a 138-line `store/dynamo.go`; one
(`compute/aws/identity.go:99-104`) was in range but about the wrong thing, which
no lexical check can catch; one was off by two lines at its leading edge. All
three were already fixed by the time this work started — `credentials/aws`
carried a narrow, package-scoped `TestEveryCitationResolves` from USOSS-9 that
had already caught and corrected the out-of-range one and documented the other
two as its own blind spot. That test is superseded and removed here: everything
it checked, `make citations` (`internal/citations`, `hack/citationlint`) checks
over the whole repository, not one package's own files.

USOSS-71 re-scoped the population while re-investigating: not thirteen
citations in one file, but a hundred-plus line-range citations across the
`compute/` package, most of them citing the source system this
repository was ported from by that system's *bare* file name — `database.go`,
not `backend/internal/modules/deploy/database.go`. Ten of those bare names
happened to collide with a real sibling file in the citing comment's own
package (`compute/database.go`, `compute/container.go`) and resolved, in
range, to unrelated local code. A reader following one of those ten gets no
signal at all that they landed on the wrong file.

### The checker measures three classes and says so

A citation resolves to exactly one of [`Local`, `Dangling`,
`External`](../../internal/citations/citations.go). `Dangling` — a real local
file, an out-of-range line — is what `make citations` gates on; it is the only
class a lexical check can decide without also reading the sentence. The
package doc comment states outright what it cannot decide: a citation that
lands on real, in-range local code saying something other than what the
comment claims. That was USOSS-68's second defect, and nothing short of a
reader closes it. Claiming otherwise in the tool's own description would be
the same failure `internal/boundary`'s `reportSuccess` was written to close —
a gate that reads as covering more than it does.

### Why a bare citation resolves against its own directory, not a repo-wide search

The population this checker actually found breaks down as: most citations name
a file absent from this repository under any path (self-announcing — read the
citation, `fs.ReadFile` fails, done); a smaller set name a real local file, out
of range (`Dangling`, USOSS-68's class, mechanically decidable); and a
dangerous few name a real local file, in range, that is not what the comment
means (USOSS-71's silent ten). That third class only exists because a bare
name is ambiguous, and this checker resolves the ambiguity the way the bug
happens: against a same-named file in the *citing comment's own directory*.
That is not the most cautious reading available — a repository-wide search by
base name would find matches in `compute/`, `compute/aws/`, and `compute/fake/`
at once — but caution here is the wrong direction. The silent defect is a
reader's eye jumping to the sibling that happens to share a name; a checker
that resolved more carefully than that reader would stop catching what it
exists to catch. A citation with a directory component
(`compute/aws/identity.go:99-104`) is never ambiguous and is always checked at
that exact path.

### The group-membership signal

Citations rarely stand alone. `capability.go`'s `CapSecretStore` doc cites
`(container.go:301-334, :1138-1154, postgres_roles.go:230-248)` — three
citations in one parenthetical, joined by `, ` and the bare `:1138-1154`
continuation that inherits the previous member's file name. `postgres_roles.go`
exists nowhere in this repository, under any path, so it proves the whole
group is about the source system, including the two `container.go` members
that would otherwise resolve — one of them in range against
`compute/container.go` (silently, USOSS-71's dangerous class) and one of them
out of range against it (`Dangling`, and only *not* reported because of this
signal). This checker applies group membership on the same rule: citations
joined by nothing but `, ` or ` and ` share a verdict, and one provably-external
member is decisive for all of them. It is cheaper than parsing the sentence
and, for this shape of comment, exactly as reliable.

### What is out of scope, and why

- **Only `.go` comments and `.md` prose are scanned.** Every citation named by
  either ticket is one of these two. Extending to other text formats is
  straightforward if one turns up; nothing in the design assumes Go or
  Markdown beyond how each is tokenised into flowing text.
- **Only the exact shapes `path/file.go:N`, `path/file.go:N-M`, and the bare
  `, :N-M` continuation are recognised.** A looser pattern would also match
  version strings, struct tags, and host:port literals that are not citations,
  trading a citation nobody checks for a citation wrongly flagged. The former
  failure is silent and bounded; the latter breaks a build over prose.
- **A bare filename with no line number (`see database.go`) is not tracked.**
  There is no range to compare against, so there is nothing this checker could
  decide about it that reading the sentence would not decide better.
- **Symbol-based citations, considered and deferred.** USOSS-68 asked whether a
  citation should name a symbol instead of a line range wherever the compiler
  can check it. For a citation into *this* repository's own code, it already
  should — this codebase's prevailing idiom is a godoc `[Type.Method]` link,
  which `go vet`'s doc-link check and every refactoring tool that understands
  Go source keep honest across a rename in a way a line number never is. That
  idiom is not new here and needs no fixture. What is out of scope is teaching
  `internal/citations` itself to resolve `[Symbol]` links or to flag a bare
  line-range citation into this repository's own code as something that
  *should* have been a symbol reference — that needs the same `go/ast` symbol
  table this checker's citing side does not build today, and no citation this
  round named a case where it would have made a difference: every fix here
  targets the source tree, which is not a Go package this module can resolve a
  symbol against at all. The chosen replacement for a cross-repository citation
  is therefore textual — `source system @
  backend/internal/modules/deploy/build.go, func buildImage` — naming the
  enclosing function where it was already evident from the surrounding
  sentence, and the repository and path alone where it was not. Inventing a
  function name for source this module cannot read would be a citation with
  the same defect this checker exists to catch, one layer further from view.
