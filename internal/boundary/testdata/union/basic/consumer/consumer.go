// Package consumer reaches the same wrapper the allowed provider does, and is
// not itself allowed to. The exception belongs to the root being judged, not to
// the wrapper, so this is a violation and provider/ is not.
package consumer

import _ "example.com/unionwrapper"
