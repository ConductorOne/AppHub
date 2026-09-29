// Package viaclean imports a dependency package whose *tests* import the denied
// package. `go test ./...` never compiles a dependency's tests, so this is not a
// path to it and must not be reported.
package viaclean

import _ "example.com/unionwrapper/clean"
