## USOSS-4 — Go code lives at the repository root, not under `backend/`

The source repository puts its Go module in `backend/`, alongside a frontend, a
`paved/` tree, and a top-level Makefile that drives all of them. None of those
neighbours are being extracted. AppHub is one Go module and nothing else, so
the directory exists only to add a path segment.

The cost of the extra level is not cosmetic. It lands in every import path an
adopter writes — `github.com/conductorone/apphub/backend/compute/aws` rather than
`github.com/conductorone/apphub/compute/aws` — and in `go install` and `go get`
lines, forever. It also breaks the convention that a repository root is a Go
module, which is what tooling, `pkg.go.dev`, and readers all assume by default.

Decided at bootstrap because moving a module root after fifteen ports have
landed on it is expensive and touches every file. If a non-Go component is ever
added, it goes in a sibling directory rather than pushing the module down a
level.
