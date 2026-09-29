// Package unionwrapper is the innocuous-looking middleman: nothing in the main
// module names the denied package, and importing this reaches it anyway.
package unionwrapper

import _ "example.com/unionwrapper/forbidden"
