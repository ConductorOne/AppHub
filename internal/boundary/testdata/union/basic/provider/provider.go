// Package provider stands in for credentials/c1: the one root allowed to reach
// the denied dependency, directly and through anything else.
package provider

import (
	_ "example.com/unionwrapper"
	_ "example.com/unionwrapper/forbidden"
)
