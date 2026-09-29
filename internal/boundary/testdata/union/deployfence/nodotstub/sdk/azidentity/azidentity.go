// Package azidentity here belongs to a module whose path has NO DOT in its
// first element: `module cloud`, reached through a replace directive.
//
// It is the control for the import allowlist's membership test. That test used
// to be "does the first path element contain a dot" — the go command's rule for
// telling a module path from a standard-library path — and review defeated it
// with exactly this: a real, compileable, locally replaced module named `cloud`
// providing cloud/sdk/azidentity, waved through as standard library.
//
// The inference was sound while every rule was a denylist and unsound the moment
// one of them became an allowlist, because the complement decides admission
// rather than merely reporting. The membership test is now `go list std`.
package azidentity

// Symbol exists so an importer can reference something.
const Symbol = "nodot"
