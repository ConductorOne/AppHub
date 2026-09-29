// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

import "fmt"

// IncompleteError is the only way this package reports failure. Every one of its
// messages names what was incomplete rather than what went wrong, because the
// class of defect the tool exists for is a run that produced a plausible answer
// from a population it had not established.
type IncompleteError struct {
	Msg string
}

func (e *IncompleteError) Error() string { return "audit: incomplete: " + e.Msg }

// fail aborts the derivation in progress. It panics with an *IncompleteError,
// which [Run] recovers and returns; any other panic is re-panicked untouched, so
// a genuine bug is never disguised as an audit finding.
//
// The derivations below read as straight-line code because of this: a count that
// cannot be established is not a value to thread through twenty call sites, it
// is the end of the run. go/parser uses the same idiom for the same reason. The
// panic never crosses the package boundary.
func fail(format string, a ...any) {
	panic(&IncompleteError{Msg: fmt.Sprintf(format, a...)})
}

// recoverFail converts a fail panic into an error and lets everything else
// through. Callers use it in a deferred closure over a named error result.
func recoverFail(err *error) {
	r := recover()
	if r == nil {
		return
	}
	if ie, ok := r.(*IncompleteError); ok {
		*err = ie
		return
	}
	panic(r)
}
