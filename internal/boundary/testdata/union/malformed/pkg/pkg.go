//go:build linux &&

// Package pkg carries a build constraint that does not parse. A checker that
// treated an unreadable constraint as "skip this file" would have a hiding
// place; this one fails instead.
package pkg

import _ "example.com/unionwrapper/forbidden"
