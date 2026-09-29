// Package pkg imports something no module in the build list provides. The union
// graph cannot follow it, so it cannot know what lies beyond -- which has to be
// an error rather than a gap.
package pkg

import _ "example.com/no-such-module-exists-anywhere/pkg"
