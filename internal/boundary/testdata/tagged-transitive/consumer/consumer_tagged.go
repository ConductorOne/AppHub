//go:build customtag

package consumer

// The seam between the two original fixes: the file view is shallow and sees
// only an innocuous wrapper, and the closure enumerates GOOS values and never
// enables a tag somebody invented.
import _ "example.com/tagwrapper"
