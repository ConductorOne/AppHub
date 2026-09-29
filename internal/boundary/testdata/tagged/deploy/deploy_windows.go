//go:build windows

package deploy

// The forbidden import lives behind a platform constraint, so `go list` on
// Linux never reports it.
import _ "example.com/tagged/forbidden"
