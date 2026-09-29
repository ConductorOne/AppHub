// Package review is a sibling module that is deliberately NOT a subject of the
// fence. It imports a substrate SDK, and the fence must stay silent about it --
// a rule that fired here would be a rule about the whole tree wearing a subject
// set, and the control for "it catches things" is worthless without one for
// "it catches only what it is aimed at".
package review

import "github.com/aws/aws-sdk-go-v2/direct"

// Symbol exists so the import is used.
const Symbol = direct.Symbol
