// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

// The three readers below are exported because modules/fix takes the same
// parameter map shape and would otherwise restate them. A second copy of a
// rule is a second thing to keep in step, and these have already been wrong
// once in the source: the integer readers exist at all because a parameter map
// decoded from JSON carries float64 where a programmatic caller passes int, so
// a plain type assertion silently rejects half its real callers.

// StringParam returns the string at key, and whether it was present, of that
// type, and non-empty. An empty string is reported absent: no parameter in
// either module distinguishes "" from unset, and treating them apart would be
// a distinction only the reader knew about.
func StringParam(params map[string]any, key string) (string, bool) {
	s, ok := params[key].(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// PositiveIntParam returns the integer at key when it is present and strictly
// positive.
//
// float64 is accepted because that is what encoding/json produces, and only
// when it holds an exact integer: 1.5 is not a positive integer that happened
// to arrive as a float, it is a caller error, and rounding it would invent a
// value nobody sent.
func PositiveIntParam(params map[string]any, key string) (int64, bool) {
	v, ok := intParam(params, key)
	if !ok || v <= 0 {
		return 0, false
	}
	return v, true
}

// NonNegativeIntParam is [PositiveIntParam] admitting zero, for the parameters
// that are indices rather than counts.
func NonNegativeIntParam(params map[string]any, key string) (int64, bool) {
	v, ok := intParam(params, key)
	if !ok || v < 0 {
		return 0, false
	}
	return v, true
}

func intParam(params map[string]any, key string) (int64, bool) {
	switch v := params[key].(type) {
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	default:
		return 0, false
	}
}
