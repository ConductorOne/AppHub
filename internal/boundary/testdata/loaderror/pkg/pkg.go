// Package pkg imports something no module provides, so `go list -e` reports a
// broken package instead of failing -- which is precisely the case that used to
// be discarded.
package pkg

import _ "example.com/no-such-module-exists-anywhere/pkg"
