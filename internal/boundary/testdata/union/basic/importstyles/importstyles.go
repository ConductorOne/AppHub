// Package importstyles declares a denied import four ways. A checker that reads
// only one of the forms would be a checker somebody rewrites their import to get
// past.
package importstyles

import (
	aliased "example.com/unionwrapper/forbidden/aliased"
	_ "example.com/unionwrapper/forbidden/blank"
	"example.com/unionwrapper/forbidden/direct"
	. "example.com/unionwrapper/forbidden/dotted"
)

// Marker uses the named imports so this is ordinary Go rather than a shape only
// a parser would accept.
var Marker = direct.Marker + aliased.Marker + Dotted
