package winonly

// A Windows-only file is invisible to `go list` on Linux, which is how the
// second bypass worked.
import _ "example.com/unionwrapper"
