// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules

import "context"

// ProgressFunc receives a module's progress reports. progress is a percentage
// in [0, 100] and message is a human-readable status line.
//
// The range is a convention, not an invariant. Of the 69 ReportProgress calls in
// the code this was ported from, 62 pass an integer literal and every one of
// those is inside the range; the remaining 7 pass something computed -- 2 an
// arithmetic expression, 5 a variable -- so for those the range is not knowable
// by reading the call. Nothing checks it, and [ReportProgress] deliberately does
// not clamp: rewriting a module's own report would be worse than passing it on.
//
// The reporter is called synchronously from the module's caller-visible
// goroutine, so an implementation that blocks stalls the module.
//
// It must also be safe for concurrent use, so that a module which fans work out
// can report from several goroutines. That requirement is added here rather than
// inherited, and the checkable form of why is that there is no `go` statement
// anywhere under the source's module tree -- so nothing there ever exercised it.
// Requiring it now is cheaper than discovering later that the reporters already
// in the field cannot take it.
type ProgressFunc func(ctx context.Context, progress int, message string)

// progressKeyType is an unexported empty struct so no other package can
// construct the key and collide with this one.
type progressKeyType struct{}

var progressKey = progressKeyType{}

// WithProgress returns a copy of ctx carrying fn as its progress reporter.
//
// Progress travels in the context rather than in Execute's signature because it
// is optional and because it has to reach code the module calls, several layers
// down, without every function between growing a parameter for it.
func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey, fn)
}

// ReportProgress reports progress to the reporter in ctx, if there is one.
//
// Reporting is best-effort by design: a module calls this wherever it has
// something to say, and no reporter — or a nil one — is a no-op rather than an
// error. Nothing a module needs to do depends on the report arriving, so a
// caller that did not ask for progress does not have to be handled by every
// module separately.
func ReportProgress(ctx context.Context, progress int, message string) {
	if fn, ok := ctx.Value(progressKey).(ProgressFunc); ok && fn != nil {
		fn(ctx, progress, message)
	}
}
