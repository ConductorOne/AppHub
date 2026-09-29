// Package consumer declares no forbidden import of its own. It reaches one
// through a third-party wrapper, which is exactly how a direct-imports check
// gets defeated.
package consumer

import _ "example.com/wrapper"
