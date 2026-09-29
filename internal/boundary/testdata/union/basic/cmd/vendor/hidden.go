//go:build ignore

// Package vendor is the reviewer's fixture for bypass seventeen. A directory
// *named* vendor is an ordinary package -- `go help packages` says so outright,
// and `go list ./cmd/vendor` lists it -- but the walker skipped every directory
// with that name. With the import also behind a constraint no compatibility
// target selects, nothing saw this file at all.
package vendor

import _ "example.com/unionwrapper/forbidden"
