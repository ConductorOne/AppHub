// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrNotConfigured is the sentinel every "this module is missing a dependency"
// failure wraps, so a caller can recognise the class without knowing which
// module or which dependency:
//
//	if errors.Is(err, modules.ErrNotConfigured) {
//		// a deployment problem, not a bad request: do not retry, and do not
//		// report it to the user as their mistake
//	}
//
// Telling this apart from a validation failure is the point. A missing
// dependency is the operator's problem and is not fixed by the caller sending
// different parameters, so it must not be reported as if it were.
//
// This sentinel is new here rather than ported, because nothing in the code
// this was ported from could make the distinction. It has five dispatch paths
// that call a module, and none of the five inspects the kind of error it gets
// back: two discard the result outright and log, three branch on the error and
// map it to a single outcome -- one HTTP 500, one failed-job row, one sanitised
// failure report.
var ErrNotConfigured = errors.New("module dependency not configured")

// MissingError names a dependency a module cannot run without. Build one with
// [Missing].
type MissingError struct {
	// Module is the ID of the module that needs the dependency.
	Module string
	// Dependency is the name of what is absent, as a contributor would say it:
	// "findings store", "compute provider", "GitHub token source".
	Dependency string
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("module %q is not configured: %s is required but was not supplied",
		e.Module, e.Dependency)
}

// Unwrap makes every MissingError match [ErrNotConfigured] under errors.Is.
func (e *MissingError) Unwrap() error { return ErrNotConfigured }

// Missing reports that a module cannot be constructed because a dependency was
// not supplied. It is the fail-closed half of the constructor-injection
// convention described in the package doc: a constructor that finds a nil
// dependency returns this instead of a module that will fail later.
//
//	func NewExampleModule(store FindingsWriter) (*ExampleModule, error) {
//		if store == nil {
//			return nil, modules.Missing(ModuleID, "findings store")
//		}
//		...
//	}
//
// dependency is the *name* of a collaborator, and nothing else. It is written to
// logs and returned to callers, so it must never carry a token, a key, a
// connection string, or any other value — naming what is absent is the whole
// job, and the value that is absent is not needed to describe it.
func Missing(moduleID, dependency string) error {
	return &MissingError{Module: moduleID, Dependency: dependency}
}

// Absent reports whether v is a dependency a module cannot use.
//
// It exists because `dep == nil` does not answer that question for an
// interface. An interface value holding a nil pointer is not nil -- the
// interface has a type -- so a constructor comparing its parameter to nil
// accepts it, returns a module that looks wired, and the module panics on its
// first call. That is precisely the failure the constructor convention exists
// to prevent, arriving through the check meant to prevent it, and it was found
// in review against the first two modules built on this framework: both
// refused an untyped nil and accepted a typed one, so of two inputs one was
// closed.
//
// Absent is true for an untyped nil, and for an interface holding a nil value
// of any kind that can be nil -- pointer, map, slice, func, channel, or
// another interface. It is false for everything else, including a zero struct,
// which is a usable value rather than an absent one.
//
//	func NewExampleModule(store FindingsWriter) (*ExampleModule, error) {
//		if modules.Absent(store) {
//			return nil, modules.Missing(ModuleID, "findings store")
//		}
//		...
//	}
//
// A module with more than one dependency should quantify its tests over typed
// nils for every one of them rather than checking the one that prompted this,
// because the population is what makes the guard a rule instead of a case.
func Absent(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}
