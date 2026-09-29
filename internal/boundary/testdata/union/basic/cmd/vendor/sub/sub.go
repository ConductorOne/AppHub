// Package sub sits *beneath* a vendor element, which `go list ./...` from the
// module root does not reach -- but `go list ./cmd/vendor/...` does, and so does an
// import. The walker enumerates it rather than reasoning about which pattern
// somebody will use, because under-approximating here has now cost two bypasses.
package sub

import _ "example.com/unionwrapper/forbidden"
