//go:build arm64

package probe

// arm64 is Graviton and Apple Silicon. A file constrained to it is ordinary
// code, and it was invisible to a checker that ran three operating systems on
// one architecture.
import _ "example.com/archwrapper"
