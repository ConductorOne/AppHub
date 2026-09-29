// Package vialocal reaches the denied dependency through a module that is
// present only because of a local replace directive. Its files are not in the
// module cache, so a resolver that built cache paths by hand would miss it.
package vialocal

import _ "example.com/unionlocal"
