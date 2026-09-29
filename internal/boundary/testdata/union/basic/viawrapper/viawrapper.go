// Package viawrapper declares no denied import of its own. It reaches one
// through a third-party wrapper, which is how a direct-imports check gets
// defeated.
package viawrapper

import _ "example.com/unionwrapper"
