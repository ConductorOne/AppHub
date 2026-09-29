// Package UnionMixedCase has an uppercase module path, which the module cache
// escapes. A resolver that reconstructed cache paths by hand would look in the
// wrong directory and see nothing.
package UnionMixedCase

import _ "example.com/unionwrapper/forbidden"
