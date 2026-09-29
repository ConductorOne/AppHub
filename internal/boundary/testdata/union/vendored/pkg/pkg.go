// Package pkg imports a vendored dependency. What matters is not this file but
// the vendor tree beside it: with one present, `go build` compiles the vendored
// copy while a module-cache resolver reads something else.
package pkg

import _ "example.com/x"
