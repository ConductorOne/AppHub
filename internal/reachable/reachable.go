// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package reachable answers one question for the redacting types in this
// repository: what bytes can ordinary reflection get out of a value?
//
// It exists because that question was being answered three times, in three
// places, at three different depths — and the shallowest answer was the one
// guarding actual credential material:
//
//   - credentials' recombination fixture walked only the immediate fields of a
//     Secret. A reviewer moved the key into an unexported one-field holder struct
//     inside the type, used it for real, and the whole suite stayed green.
//   - a field recorder documented a breadth-first walk and ran depth-first under
//     a depth cap.
//   - a leak probe was exhaustive over output paths and had no reconstruction
//     axis at all.
//   - and then this package's own first version was defeated twice more: once by
//     two slice views sharing a backing array, which a (pointer, type) cycle
//     identity conflated into one; and once by a key hidden in the CAPACITY of a
//     one-byte view, which a Len-bounded read never saw. Both recovered every
//     byte through ordinary reflection while this walk reported nothing.
//
// Three copies of "what is reachable" drift, and the shallowest one scores a
// real leak clean. So there is one walk, it is derived rather than enumerated,
// and its bounds are in its name and its documentation rather than left to be
// discovered.
//
// # What it guarantees
//
// Every reflect.Kind is handled by an explicit case. A kind with no case is a
// FATAL error rather than a skip, because a walk that shrugs at something it does
// not understand is the bypass — that is how a struct field defeated the fixture
// this package replaces.
//
// Recursion runs through structs, pointers, interfaces, slices, arrays and maps
// with NO DEPTH CAP. Cycles are bounded by remembering visited values, not by
// giving up at a depth, because a depth cap is a silent bound that looks like a
// safety measure — and the identity remembered includes the view's capacity,
// because a too-narrow identity turns the guard itself into a skip.
//
// Slices are read to CAPACITY. Bytes past a slice's length are reachable to
// anyone holding the slice and invisible to a walk bounded by Len, which is the
// same asymmetry: the population was the bytes the walk chose to look at.
//
// # What it cannot do, stated rather than implied
//
// A func value's captured variables are not reachable through reflect, and
// neither are a channel's contents. Those are reported as [Unreadable] entries
// with their paths rather than dropped, so a caller can assert that a type it
// cares about has none — an unreadable field on a redacting type is a place
// material can sit where this walk cannot follow.
//
// It does not use unsafe, and that is the threat model: the adversary is a
// generic dumper, a logger, a template, or a curious reader with a debugger
// session and no particular motive. Anything willing to use unsafe has the
// material regardless, and every type here says so in its own documentation.
package reachable

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

// Blob is a byte sequence reachable from a value, with the path that reached it.
type Blob struct {
	// Path is the accessor chain, e.g. ".holder.key" or "[3].masked".
	Path string
	// Bytes is what was read there.
	Bytes []byte
	// Kind describes how the bytes were formed, for a failure message that tells
	// the reader what to look at.
	Kind string
}

// Unreadable is a location reflection can see but cannot read the contents of.
type Unreadable struct {
	Path string
	Kind reflect.Kind
}

// Result is everything one walk found.
type Result struct {
	Blobs      []Blob
	Unreadable []Unreadable
	// Visited counts the values examined, including the ones that produced no
	// bytes. A caller asserts on it so that a walk which silently stops
	// descending fails instead of passing.
	Visited int
}

// Bytes returns just the byte sequences, in walk order.
func (r Result) Bytes() [][]byte {
	out := make([][]byte, 0, len(r.Blobs))
	for _, b := range r.Blobs {
		out = append(out, b.Bytes)
	}
	return out
}

// Walk collects every byte sequence reachable from v by ordinary reflection.
//
// It returns an error rather than panicking or skipping when it meets a kind it
// has no case for, so that adding a kind to the language, or pointing this at
// something nobody anticipated, is a test failure and not a quiet gap.
func Walk(v any) (Result, error) {
	w := &walker{seen: map[visit]bool{}}
	if err := w.walk(reflect.ValueOf(v), ""); err != nil {
		return Result{}, err
	}
	return Result{Blobs: w.blobs, Unreadable: w.unreadable, Visited: w.visited}, nil
}

// visit identifies a value for the cycle guard.
//
// It carries the view BOUNDS as well as the pointer and the type, and that is a
// correctness requirement rather than precision for its own sake.
//
// A cycle guard exists to stop infinite recursion. A guard whose identity is too
// narrow does not stop recursion -- it SKIPS a value it has not seen, which is
// the same failure wearing the costume of a safety measure. Two slices sharing a
// backing array have the same Pointer and the same Type and are different views:
// with identity (ptr, typ), walking key[:1] first meant declining to walk key[:],
// and a reviewer used exactly that to hide a 32-byte key behind a one-byte
// prefix. Both suites stayed green while ordinary reflection read the full view
// and recovered every byte.
//
// So: guard on identity, and make sure the identity is the whole thing.
type visit struct {
	ptr uintptr
	typ reflect.Type
	// cap is the view's capacity, and it is the whole of the bounds this needs.
	// Zero for a pointer or a map, where the pointer alone identifies the value.
	//
	// LENGTH IS DELIBERATELY ABSENT. It was here, and a mutation showed it was
	// carrying nothing: [walker.sequence] reads [0, Cap) regardless of Len, so two
	// views over one array with the same capacity are read identically and
	// deduping one against the other loses no bytes. Capacity is what changes what
	// gets read, so capacity is what belongs in the identity.
	//
	// Shipping it anyway would have been an inert component of a security
	// identity, which looks exactly like coverage — the same defect as an inert
	// hook, and the reason each half of this fix is reverted separately rather
	// than as a unit.
	cap int
}

type walker struct {
	blobs      []Blob
	unreadable []Unreadable
	seen       map[visit]bool
	visited    int
}

func (w *walker) add(path, kind string, b []byte) {
	if len(b) > 0 {
		w.blobs = append(w.blobs, Blob{Path: path, Bytes: b, Kind: kind})
	}
}

// walk descends v, appending every blob it can form, and returns the bytes this
// value contributes to its parent's concatenation.
//
// The concatenation is the second half of the job and the reason this returns
// bytes rather than nothing: material split across two adjacent fields is not
// found by looking at either field, and that shape is one edit away from every
// masked type here. So each container also emits the ordered concatenation of
// everything beneath it.
func (w *walker) walk(v reflect.Value, path string) error {
	if path == "" {
		path = "."
	}
	w.visited++
	if !v.IsValid() {
		// The zero reflect.Value: a nil interface element. Nothing to read, and
		// not an error — but recorded, because "nothing was there" and "the walk
		// stopped" must not look the same.
		w.unreadable = append(w.unreadable, Unreadable{Path: path, Kind: reflect.Invalid})
		return nil
	}

	switch v.Kind() {
	case reflect.String:
		b := []byte(v.String())
		w.add(path, "string", b)
		return nil

	case reflect.Bool:
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// The two's-complement bit pattern, which is what the bytes of a signed
		// field actually are. #nosec G115 -- a wrapping conversion is the
		// intent here, not an accident: this reads a field's bytes, it does not
		// compute with the value.
		b := binary.LittleEndian.AppendUint64(nil, uint64(v.Int())) //nolint:gosec // reading bytes, not arithmetic
		w.add(path, "int", trimTrailingZeros(b))
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		b := binary.LittleEndian.AppendUint64(nil, v.Uint())
		w.add(path, "uint", trimTrailingZeros(b))
		return nil

	case reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		// No case for reading a float as material: nothing in this repository
		// stores credential bytes in one, and inventing an encoding here would
		// produce candidate blobs that mean nothing. Recorded so the absence is
		// visible rather than assumed.
		w.unreadable = append(w.unreadable, Unreadable{Path: path, Kind: v.Kind()})
		return nil

	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		// Reflection can see these and cannot read what they hold. A func's
		// captured variables are the interesting case: material can sit in a
		// closure where this walk cannot follow it.
		w.unreadable = append(w.unreadable, Unreadable{Path: path, Kind: v.Kind()})
		return nil

	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		if v.Kind() == reflect.Pointer {
			key := visit{ptr: v.Pointer(), typ: v.Type()}
			if w.seen[key] {
				return nil
			}
			w.seen[key] = true
		}
		return w.walk(v.Elem(), path)

	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		key := visit{ptr: v.Pointer(), typ: v.Type(), cap: v.Cap()}
		if w.seen[key] {
			return nil
		}
		w.seen[key] = true
		return w.sequence(v, path, "slice")

	case reflect.Array:
		return w.sequence(v, path, "array")

	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		key := visit{ptr: v.Pointer(), typ: v.Type()}
		if w.seen[key] {
			return nil
		}
		w.seen[key] = true
		iter := v.MapRange()
		for iter.Next() {
			if err := w.walk(iter.Key(), path+"[key]"); err != nil {
				return err
			}
			if err := w.walk(iter.Value(), path+"[value]"); err != nil {
				return err
			}
		}
		return nil

	case reflect.Struct:
		var concat []byte
		for i := range v.NumField() {
			f := v.Type().Field(i)
			before := len(w.blobs)
			if err := w.walk(v.Field(i), path+"."+f.Name); err != nil {
				return err
			}
			for _, b := range w.blobs[before:] {
				concat = append(concat, b.Bytes...)
			}
		}
		if v.NumField() > 1 {
			w.add(path, "struct-concat", concat)
		}
		return nil

	default:
		// Deliberately fatal. A kind with no case above is a hole, and a hole in
		// this walk is what the fixture it replaces had.
		return fmt.Errorf("reachable: no case for kind %s at %s; a walk that skips what it does "+
			"not understand is the bypass, so this is an error rather than a silent omission",
			v.Kind(), path)
	}
}

// sequence handles a slice or an array. A byte-shaped one yields its bytes
// directly; anything else is descended element by element and concatenated.
//
// It reads to CAPACITY, not to length. Every byte in a slice's backing array
// past its length is reachable by ordinary reflection -- Value.Slice(0, Cap())
// works on a slice obtained from an unexported field -- so a walk bounded by Len
// is a walk whose population is the bytes it chose to look at. A reviewer put a
// 32-byte key in the backing array of a view with len=1 cap=32, used
// holder.key[:32] to read it, and recovered 43 of 43 bytes while this walk
// reported no 32-byte blob at all.
//
// Note the two defeats needed one fix between them and not two: widening the
// cycle identity to include Len would have closed the aliased-views case and
// left this one open, because the hidden bytes were never in any view's length.
func (w *walker) sequence(v reflect.Value, path, kind string) error {
	full, label := v, kind
	if v.Kind() == reflect.Slice && v.Cap() > v.Len() {
		// Re-slicing to capacity is the adversary's own move, and it needs no
		// unsafe and no addressability: Slice on a slice Value is legal even when
		// the Value came from an unexported field.
		full = v.Slice(0, v.Cap())
		label = kind + "-to-cap"
	}
	if full.Type().Elem().Kind() == reflect.Uint8 {
		b := make([]byte, full.Len())
		for i := range b {
			// Element-wise rather than Value.Bytes: Bytes panics on an
			// unaddressable byte ARRAY, and skipping arrays for that reason is
			// exactly the sort of accidental bound this package exists to remove.
			// Uint() on a uint8 element cannot exceed 255, so the narrowing is
			// exact; the element kind was checked above.
			b[i] = byte(full.Index(i).Uint()) //nolint:gosec // element kind is uint8, checked above
		}
		w.add(path, label+"-of-byte", b)
		return nil
	}
	var concat []byte
	for i := range full.Len() {
		before := len(w.blobs)
		if err := w.walk(full.Index(i), path+"["+strconv.Itoa(i)+"]"); err != nil {
			return err
		}
		for _, b := range w.blobs[before:] {
			concat = append(concat, b.Bytes...)
		}
	}
	w.add(path, label+"-concat", concat)
	return nil
}

// trimTrailingZeros shortens a fixed-width integer encoding to its significant
// bytes, so that a uint8 field contributes one candidate byte and not eight.
// The full-width form is not lost: it is the leading portion of what remains.
func trimTrailingZeros(b []byte) []byte {
	n := len(b)
	for n > 1 && b[n-1] == 0 {
		n--
	}
	return b[:n]
}
