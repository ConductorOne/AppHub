// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import "reflect"

// deepCopy returns a copy of a spec that shares no mutable state with it.
//
// # Why this exists
//
// A reviewer mutated the Labels map on a returned Repository.Spec and the next
// Describe reported the mutation, with no Ensure in between. The fake was
// handing out the map it stored.
//
// That is a small bug in the fake and a large one in what the fake is for. Six
// AWS providers will be developed against it, and a reference implementation
// that aliases its own state teaches every one of them that aliasing is fine:
// a module holding a returned spec and adjusting a label would silently rewrite
// what the provider believes it deployed, and the test that should have caught
// it would be running against the fake that does the same thing. A fake is a
// specification of behaviour, and its behaviour here was wrong.
//
// # How
//
// Start from a shallow copy — plain assignment, which copies unexported fields
// like [compute.SecretValue]'s material that reflect cannot set — then walk the
// settable fields replacing every map, slice and pointer with a fresh one.
//
// Unexported fields in these specs are left shallow, which is safe because they
// are immutable once constructed rather than because they are scalars: a
// [compute.SecretValue] holds its material in two byte slices, so a shallow
// copy aliases those slices. Nothing writes to them after NewSecretValue, so
// the alias is unobservable. A spec that ever gains a mutable unexported field
// breaks this and cloneInto cannot fix it, because reflect refuses to set one.
//
// A JSON round trip would be shorter and wrong: it would blank every
// SecretValue, because SecretValue marshals to its redaction.
func deepCopy[S any](in S) S {
	out := in
	cloneInto(reflect.ValueOf(&out).Elem())
	return out
}

// cloneInto replaces the mutable parts of v with copies, in place.
func cloneInto(v reflect.Value) {
	if !v.CanSet() {
		// An unexported field. Its shallow copy is independent enough for every
		// type this package puts in one: see deepCopy on why immutability, not
		// scalarness, is what makes that true.
		return
	}
	switch v.Kind() {
	case reflect.Map:
		if v.IsNil() {
			return
		}
		dst := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(iter.Value())
			cloneInto(elem)
			dst.SetMapIndex(iter.Key(), elem)
		}
		v.Set(dst)
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		dst := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(dst, v)
		for i := range dst.Len() {
			cloneInto(dst.Index(i))
		}
		v.Set(dst)
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		dst := reflect.New(v.Type().Elem())
		dst.Elem().Set(v.Elem())
		cloneInto(dst.Elem())
		v.Set(dst)
	case reflect.Struct:
		for i := range v.NumField() {
			cloneInto(v.Field(i))
		}
	default:
	}
}
