// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package errhygiene

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"text/template"
)

// The two sentinels. They share no byte, at any position, on purpose.
//
// The first version of this file used a shared readable prefix ("SENTINEL") plus a
// varying tail, so that a leak of the whole string could be caught by containment
// and a leak of any part by comparing the two renderings. It passed while
// Secret.UnmarshalJSON was still forwarding encoding/json's error -- because that
// error quotes exactly one byte of the input, the first one, and the first byte was
// the byte the two sentinels had in common. The check could not see a defect that
// lived below its resolution, which is the failure this project has now paid for
// three times.
//
// So every byte differs, and the differential check below can observe a leak of any
// single byte at any position. Containment is kept as well, because it produces a
// far more legible failure when text leaks whole, and it costs nothing.
//
// They are the same length. A count is permitted by the invariant, so "key name is
// 45 bytes (max 32)" must not read as a difference; equal lengths make every count
// agree and leave content as the only thing that can differ. Both are unreserved
// URL characters and need no JSON escaping, so neither is re-encoded to a different
// length on the way through a URL or a request body.
const (
	sentinelA = "Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3"
	sentinelB = "Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8"
)

func init() {
	if len(sentinelA) != len(sentinelB) || len(sentinelA) == 0 {
		panic("errhygiene: the sentinels must be the same non-zero length")
	}
	for i := range len(sentinelA) {
		if sentinelA[i] == sentinelB[i] {
			panic("errhygiene: the sentinels must differ in every byte: a shared byte is a byte " +
				"the differential check cannot see")
		}
	}
}

// addr normalizes pointer addresses, which %#v and %p print and which differ per
// run for reasons that have nothing to do with the input.
//
// It cannot hide a leak, and the reason is narrower than it looks: both sentinels
// DO contain hexadecimal digits, so "their alphabet is not hexadecimal" -- which an
// earlier version of this comment claimed -- is false. What is true is that each
// also contains letters this pattern does not accept, so no run of sentinel bytes
// is an address. TestTheSentinelsAreDisjointAndEqualLength asserts it rather than
// leaving it to be believed.
var addr = regexp.MustCompile(`0x[0-9a-fA-F]+`)

// rendered is the result of pushing values through every path that turns them into
// text.
type rendered struct {
	Text  string
	Count int
	Types map[string]bool
}

// renderAll pushes each value through every rendering path this repository can be
// reached by, and returns the concatenation.
//
// It is one shared function rather than a per-driver assertion so that a driver
// cannot under-render: a driver chooses what to produce, never how thoroughly it is
// examined. Values that cannot become text -- an *http.Response, an *App whose
// fields are all unexported -- are skipped and counted as such; the
// RenderersExercised check is what stops something renderable being skipped by
// every driver at once.
func renderAll(values []any) rendered {
	out := rendered{Types: map[string]bool{}}
	var b strings.Builder
	for i, v := range values {
		if v == nil {
			continue
		}
		if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
			continue
		}
		if !renderable(v) {
			continue
		}
		out.Count++
		out.Types[typeKey(v)] = true
		fmt.Fprintf(&b, "#%d %s\n", i, typeKey(v))

		if s, ok := v.(string); ok {
			// A plain string result is its own rendering; DescribeType returns one.
			fmt.Fprintf(&b, "  str=%s\n", s)
			continue
		}

		fmt.Fprintf(&b, "  v=%v\n  plusv=%+v\n  hashv=%#v\n  q=%q\n  s=%s\n  x=%x\n", v, v, v, v, v, v)
		if e, ok := v.(error); ok {
			fmt.Fprintf(&b, "  Error=%s\n", e.Error())
			fmt.Fprintf(&b, "  wrapped=%v\n", fmt.Errorf("outer context: %w", e))
			fmt.Fprintf(&b, "  joined=%v\n", fmt.Errorf("a: %w, b: %w", e, e))
		}
		if s, ok := v.(fmt.Stringer); ok {
			fmt.Fprintf(&b, "  String=%s\n", s.String())
		}
		if g, ok := v.(fmt.GoStringer); ok {
			fmt.Fprintf(&b, "  GoString=%s\n", g.GoString())
		}
		if l, ok := v.(slog.LogValuer); ok {
			fmt.Fprintf(&b, "  LogValue=%v\n", l.LogValue())
		}
		jb, jerr := json.Marshal(v)
		fmt.Fprintf(&b, "  json=%s err=%v\n", jb, jerr)
		var gbuf bytes.Buffer
		gerr := encodeGob(&gbuf, v)
		fmt.Fprintf(&b, "  gob=%x err=%v\n", gbuf.Bytes(), gerr)

		// Nested, because a value that is safe alone has been unsafe inside a
		// struct: fmt consults Formatter and GoStringer per element, and one
		// missing method has been the whole defect before.
		type box struct {
			Value any
			Label string
		}
		fmt.Fprintf(&b, "  boxed=%v %+v %#v\n", box{Value: v}, box{Value: v}, box{Value: v})
		fmt.Fprintf(&b, "  slice=%v map=%v\n", []any{v}, map[string]any{"k": v})

		fmt.Fprintf(&b, "  slogtext=%s\n", slogLine(v, false))
		fmt.Fprintf(&b, "  slogjson=%s\n", slogLine(v, true))
	}
	out.Text = addr.ReplaceAllString(b.String(), "0xADDR")
	return out
}

// renderable reports whether a value has any path to text worth checking.
func renderable(v any) bool {
	switch v.(type) {
	case string, error, fmt.Stringer, fmt.GoStringer, fmt.Formatter, slog.LogValuer, json.Marshaler, gob.GobEncoder:
		return true
	}
	return false
}

func typeKey(v any) string {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.String()
}

// encodeGob encodes and converts a panic into an error. gob returns errors for most
// refusals but panics on a few shapes, and a panic here is a test failure about the
// wrong thing. The panic's own message is text built from the value, so it is kept
// and checked like any other rendering rather than dropped.
func encodeGob(buf *bytes.Buffer, v any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gob panicked: %v", r)
		}
	}()
	return gob.NewEncoder(buf).Encode(v)
}

// slogLine logs v through a real handler. The timestamp is dropped because it is
// the one field that differs between two otherwise identical runs.
func slogLine(v any, asJSON bool) string {
	var buf bytes.Buffer
	drop := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}
	opts := &slog.HandlerOptions{ReplaceAttr: drop}
	var h slog.Handler
	if asJSON {
		h = slog.NewJSONHandler(&buf, opts)
	} else {
		h = slog.NewTextHandler(&buf, opts)
	}
	slog.New(h).Info("rendered", slog.Any("value", v))
	return strings.TrimSpace(buf.String())
}

// embedWindow is the resolution for input EMBEDDED in other text.
//
// Whole-field leaks are caught at one byte by leakedSlots below, which compares
// slots pairwise against both sentinels; this only bounds the search for input
// spliced into a longer string. Four bytes at the same sentinel offset in both runs
// cannot occur by chance in random ciphertext (2^-32 per position, squared by the
// pairing).
//
// The first version of this check used a single six-byte window against one
// sentinel and nothing else, and review put a five-byte plaintext field in Foreign
// that it stepped over. The lesson is not "six was too big": it is that a
// containment check needs its resolution to be a property of the comparison rather
// than a constant somebody picked.
const embedWindow = 4

// leakedSlots compares two runs of the same driver, slot by slot, and returns a
// description of the first leak.
//
// Pairing is what buys the resolution. A single run cannot distinguish a one-byte
// leak from a coincidence, because random ciphertext contains every byte. Two runs
// with byte-disjoint sentinels can: a real leak appears in BOTH, at the same offset
// within each sentinel, and a coincidence appears in one. So:
//
//   - a slot that is exactly a slice of the input, at any length down to one byte,
//     is a leak -- this is the whole-field case, and it is what a plaintext field of
//     any size looks like;
//   - a slot that merely contains embedWindow bytes of the input at the same offset
//     in both runs is a leak -- this is the spliced case.
func leakedSlots(a, b reachable, sentA, sentB string) string {
	if len(a.Texts) != len(b.Texts) {
		return fmt.Sprintf("the driver produced %d reachable slots for one input and %d for the other, "+
			"so its shape depends on the input and slots cannot be compared", len(a.Texts), len(b.Texts))
	}
	for i := range a.Texts {
		ta, tb := a.Texts[i], b.Texts[i]
		if ta == "" && tb == "" {
			continue
		}
		// Whole-field: is the slot exactly a same-offset slice of each sentinel?
		if len(ta) == len(tb) && len(ta) > 0 && len(ta) <= len(sentA) {
			for o := 0; o+len(ta) <= len(sentA); o++ {
				if ta == sentA[o:o+len(ta)] && tb == sentB[o:o+len(tb)] {
					return fmt.Sprintf("reachable slot %s holds %d byte(s) of the input verbatim (%q at "+
						"input offset %d); no reachable field may hold any of it", a.Paths[i], len(ta), ta, o)
				}
			}
		}
		// Spliced: does the slot contain a same-offset window of each sentinel?
		for l := len(sentA); l >= embedWindow; l-- {
			for o := 0; o+l <= len(sentA); o++ {
				if strings.Contains(ta, sentA[o:o+l]) && strings.Contains(tb, sentB[o:o+l]) {
					return fmt.Sprintf("reachable slot %s embeds %d byte(s) of the input (input offset %d)",
						a.Paths[i], l, o)
				}
			}
		}
	}
	return ""
}

// walkBudget bounds the reachable walk. Hitting it is a test failure rather than a
// silent truncation: a driver that returns a graph this large is under-checked, and
// "we looked at some of it" reads identically to "we looked at all of it".
const walkBudget = 200000

// walkDepth bounds the reachable walk's recursion, and is stated here rather than
// buried at the call site for the same reason: a bound that is reached is a
// failure, never a shrug.
const walkDepth = 24

// reachable is what a generic reader can get to without asking a value to render
// itself.
type reachable struct {
	Texts     []string
	Paths     []string
	Truncated bool
}

// reachableText walks every value a driver produced and collects every string and
// byte sequence reachable from it, through unexported fields included.
//
// This is the check the first version of this fixture did not have, and the two
// live holes review found were both here rather than in the rendering matrix:
// reflect.Value.String on an unexported string field, and a custom slog.Handler
// doing the same to an unresolved slog.Any. Neither asks the value to render
// itself, so no list of verbs however long can reach them. The property is stated
// over the representation instead of over the rendering:
//
//	no field reachable from a value this package returns contains the input.
//
// # Why this is not internal/reachable
//
// USOSS-59 ruled that there is one recursive reachability walk, in
// internal/reachable, and this is deliberately not it. That walk answers "what
// bytes are reachable", in any order, for a recombination attack on a single value.
// This one answers a different question: "do two runs of the same driver differ,
// slot for slot". The pairing is what buys the one-byte resolution (see
// leakedSlots), and pairing needs a deterministic slot order -- which means sorted
// map iteration, which internal/reachable deliberately does not do because ordering
// buys its question nothing. Unifying them means changing a security-critical
// shared walk to serve this one, which is a bigger change than either of the
// tickets that produced this file, and is recorded as a follow-up rather than done
// quietly here.
func reachableText(values []any) reachable {
	var out reachable
	seen := map[uintptr]bool{}
	budget := walkBudget

	var walk func(v reflect.Value, path string, depth int)
	walk = func(v reflect.Value, path string, depth int) {
		if budget <= 0 {
			out.Truncated = true
			return
		}
		budget--
		if depth > walkDepth {
			out.Truncated = true
			return
		}
		if !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.String:
			out.Texts = append(out.Texts, v.String())
			out.Paths = append(out.Paths, path)
		case reflect.Slice, reflect.Array:
			if v.Kind() == reflect.Slice && v.IsNil() {
				return
			}
			if v.Type().Elem().Kind() == reflect.Uint8 {
				// Read element by element rather than through Bytes, which has
				// addressability rules an unexported field does not always satisfy.
				b := make([]byte, v.Len())
				for i := range v.Len() {
					// The element kind is Uint8, so Uint() is < 256 by construction; this
					// reads a field's bytes and computes nothing.
					b[i] = byte(v.Index(i).Uint()) //nolint:gosec // reading bytes, not arithmetic
				}
				out.Texts = append(out.Texts, string(b))
				out.Paths = append(out.Paths, path)
				return
			}
			for i := range v.Len() {
				walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1)
			}
		case reflect.Struct:
			for i := range v.NumField() {
				walk(v.Field(i), path+"."+v.Type().Field(i).Name, depth+1)
			}
		case reflect.Pointer:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			walk(v.Elem(), "(*"+path+")", depth+1)
		case reflect.Interface:
			if v.IsNil() {
				return
			}
			walk(v.Elem(), path+".(dyn)", depth+1)
		case reflect.Map:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			// Sorted, because map iteration order is randomised and the two runs
			// have to line up slot for slot.
			keys := v.MapKeys()
			sort.Slice(keys, func(i, j int) bool {
				return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j])
			})
			for _, k := range keys {
				walk(k, path+".key", depth+1)
				walk(v.MapIndex(k), path+".value", depth+1)
			}
		default:
			// Numbers, bools, funcs, channels: nothing textual to read.
		}
	}

	for i, v := range values {
		if v == nil {
			continue
		}
		walk(reflect.ValueOf(v), fmt.Sprintf("#%d(%T)", i, v), 0)
	}
	return out
}

// hostileHandler is a slog.Handler written the way a real one gets written when
// somebody wants "log whatever this is".
//
// It does not call Value.Resolve, so slog.LogValuer never fires, and it reflects
// into whatever it was handed. Both are ordinary: Resolve is easy to forget, and
// generic inspection is the point of such a handler. This is one of the two paths
// review used, and it is in the fixture so that the fix for it is mutation-sensitive
// rather than asserted.
type hostileHandler struct{ out *[]string }

func (h hostileHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h hostileHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h hostileHandler) WithGroup(string) slog.Handler            { return h }

func (h hostileHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		// Deliberately not a.Value.Resolve().
		raw := a.Value.Any()
		*h.out = append(*h.out, fmt.Sprintf("%v", raw))
		got := reachableText([]any{raw})
		*h.out = append(*h.out, got.Texts...)
		return true
	})
	return nil
}

// hostileSlogText logs each value through hostileHandler and returns everything the
// handler could see.
func hostileSlogText(values []any) []string {
	var out []string
	for _, v := range values {
		if v == nil {
			continue
		}
		slog.New(hostileHandler{out: &out}).Info("probe", slog.Any("value", v))
	}
	return out
}

// methodAndTemplateText invokes every exported zero-argument method that can
// produce text on every value a driver produced, and renders each through
// text/template as well.
//
// This is the check review escaped with a zero-argument Foreign.Reveal. The
// derivation had filed the method under Parameterless and congratulated itself;
// nothing called it. And the renderer-coverage check recognised only eight
// hard-coded method names, none of which was Reveal.
//
// The template half is the one that matters and is the reason this is generic
// rather than a longer list of names: an exported zero-argument method is reachable
// BY NAME from a template, so {{.Reveal}} needs no reflection at all. That is
// USOSS-43's live defect in compute.SecretValue, reproduced here against the type
// designed to avoid it. Enumerating the class -- every exported no-arg method
// returning something textual -- is the only shape that covers a method nobody has
// written yet.
func methodAndTemplateText(values []any) reachable {
	var out reachable
	for i, v := range values {
		if v == nil {
			continue
		}
		rv := reflect.ValueOf(v)
		if !rv.IsValid() || (rv.Kind() == reflect.Pointer && rv.IsNil()) {
			continue
		}
		rt := rv.Type()
		for m := range rt.NumMethod() {
			meth := rt.Method(m)
			if meth.Type.NumIn() != 1 || meth.Type.NumOut() == 0 {
				continue
			}
			if !producesText(meth.Type) {
				continue
			}
			key := typeKey(v) + "." + meth.Name

			// Called directly.
			for _, res := range rv.Method(m).Call(nil) {
				out.Texts = append(out.Texts, renderResult(res))
				out.Paths = append(out.Paths, fmt.Sprintf("#%d %s (direct)", i, key))
			}

			// And through a template, bare and one field deep, which is how a
			// zero-argument method gets called without anybody naming it in code.
			for _, tc := range []struct {
				expr string
				data any
			}{
				{"{{." + meth.Name + "}}", v},
				{"{{.V." + meth.Name + "}}", struct{ V any }{v}},
			} {
				tp, err := template.New("t").Parse(tc.expr)
				if err != nil {
					continue
				}
				var b strings.Builder
				if err := tp.Execute(&b, tc.data); err != nil {
					continue
				}
				out.Texts = append(out.Texts, b.String())
				out.Paths = append(out.Paths, fmt.Sprintf("#%d %s (template %s)", i, key, tc.expr))
			}
		}
	}
	return out
}

// producesText mirrors the derivation's canProduceText, over reflect rather than
// go/types: anything that is not a bool or a number is assumed to carry text.
func producesText(ft reflect.Type) bool {
	for i := range ft.NumOut() {
		switch ft.Out(i).Kind() {
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
			continue
		default:
			return true
		}
	}
	return false
}

// renderResult turns one method result into text without asking it to render itself
// where that can be avoided: a string is taken verbatim, bytes verbatim, and
// anything else goes through the reflective walk as well as %v, so a method
// returning a struct that holds the input is caught too.
func renderResult(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 && (v.Kind() == reflect.Array || !v.IsNil()) {
			b := make([]byte, v.Len())
			for i := range v.Len() {
				// The element kind is Uint8, so Uint() is < 256 by construction; this
				// reads a field's bytes and computes nothing.
				b[i] = byte(v.Index(i).Uint()) //nolint:gosec // reading bytes, not arithmetic
			}
			return string(b)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%v", v)
	deep := reachableText([]any{})
	if v.CanInterface() {
		deep = reachableText([]any{v.Interface()})
	}
	for _, s := range deep.Texts {
		b.WriteString("\x00")
		b.WriteString(s)
	}
	return b.String()
}

// labels names n slots for a probe whose output is a flat list.
func labels(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s[%d]", prefix, i)
	}
	return out
}

func firstLineWith(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func firstDiff(a, b string) string {
	as, bs := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range as {
		if i >= len(bs) {
			return "A has an extra line: " + as[i]
		}
		if as[i] != bs[i] {
			return "A: " + as[i] + "\nB: " + bs[i]
		}
	}
	if len(bs) > len(as) {
		return "B has an extra line: " + bs[len(as)]
	}
	return "(the difference is not line-aligned)"
}

// run drives one driver, guarding against a driver that fails the test itself.
func (d Driver) run(t *testing.T, sentinel string) []any {
	t.Helper()
	return d.Run(t, sentinel)
}
