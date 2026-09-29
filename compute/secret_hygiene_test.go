// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// A runnable reproduction for USOSS-43, handed to USOSS-35.
//
// Drop this file in as-is. It FAILS at main@2d538dd and must PASS once
// compute.SecretValue is fixed. Rename it to secret_hygiene_test.go and keep it:
// it is a regression fixture, not a one-off probe.
//
// It names a CLASS rather than the three known paths, because on this ticket
// every fixture that enumerated cases was defeated by the next case. The class is:
//
//	For every exported type in this package that you can hand a string to,
//	no field reachable from the value contains that string, and no template
//	expression over its exported no-argument string methods renders it.
//
// "A type you can hand a string to" is derived from go/types, not listed: any
// exported func taking exactly one string and returning a named type of this
// package. So a second NewSecretValue-shaped constructor added later is covered
// without anybody remembering to add it here.

package compute_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go/importer"
	"go/token"
	"go/types"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"text/template"

	"github.com/conductorone/apphub/compute"
)

// pkgPath is the package under test. If this ever fails to type-check, the test
// fails rather than deriving nothing -- a derivation that returns nothing passes
// every check made over it.
const pkgPath = "github.com/conductorone/apphub/compute"

// material is the string handed to every constructor. It is what must not come
// back out.
const material = "generated-db-password-that-must-not-escape"

// constructors maps a derived "hand it a string" constructor to a call.
//
// The derivation below requires an entry for every constructor it finds and
// rejects an entry that matches none, in both directions. A new constructor with
// no entry fails the test; a renamed one leaves no dead entry silently covering
// nothing.
var constructors = map[string]func(string) any{
	"NewSecretValue": func(s string) any { return compute.NewSecretValue(s) },
}

// deriveStringConstructors asks the type checker which exported functions take
// exactly one string and return a named type of this package.
func deriveStringConstructors(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkg, err := importer.ForCompiler(fset, "source", nil).Import(pkgPath)
	if err != nil {
		t.Fatalf("type-check %s: %v", pkgPath, err)
	}
	var out []string
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		fn, ok := scope.Lookup(name).(*types.Func)
		if !ok || !fn.Exported() {
			continue
		}
		sig := fn.Signature()
		if sig.Recv() != nil || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		if b, ok := sig.Params().At(0).Type().(*types.Basic); !ok || b.Kind() != types.String {
			continue
		}
		named, ok := sig.Results().At(0).Type().(*types.Named)
		if !ok || named.Obj().Pkg() != pkg {
			continue
		}
		out = append(out, fn.Name())
	}
	return out
}

func TestNoStringYouHandComputeComesBackOut(t *testing.T) {
	derived := deriveStringConstructors(t)
	if len(derived) == 0 {
		t.Fatal("derived no string constructors; the derivation is broken and would pass vacuously")
	}
	t.Logf("derived %d string constructor(s): %v", len(derived), derived)

	for _, name := range derived {
		if _, ok := constructors[name]; !ok {
			t.Errorf("%s takes a string and returns a type of this package, and this test does not "+
				"drive it: add it to constructors", name)
		}
	}
	for name := range constructors {
		found := false
		for _, d := range derived {
			if d == name {
				found = true
			}
		}
		if !found {
			t.Errorf("constructors has %q, which matches no derived constructor: it was renamed or "+
				"removed and now covers nothing", name)
		}
	}

	for _, name := range derived {
		build, ok := constructors[name]
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			assertHidesItsInput(t, build(material), material)
		})
	}
}

// assertHidesItsInput is the whole check, and is exported in spirit so it can be
// pointed at a candidate fix.
func assertHidesItsInput(t *testing.T, v any, secret string) {
	t.Helper()

	// 1. Ordinary reflection. No unsafe. Unexported closes Value.Interface and
	//    field setting; it does not close Value.String or Value.Bytes.
	for _, got := range reachableStrings(reflect.ValueOf(v), 0, map[uintptr]bool{}) {
		if strings.Contains(got, secret) {
			t.Errorf("PATH 1: a field reachable by ordinary reflection contains the material. "+
				"%T holds it in the clear; unexported is not a barrier to reflect.Value.String.", v)
			break
		}
	}

	// 2. A slog.Handler that does not call Value.Resolve and reflects into what it
	//    was handed. Both are ordinary things to write, and this is how a debug
	//    dump or a generic log line actually reaches a value.
	var seen []string
	slog.New(walkingHandler{out: &seen}).Info("probe",
		slog.Any("bare", v),
		slog.Any("nested", struct{ V any }{v}),
	)
	if len(seen) == 0 {
		t.Error("the handler saw nothing, so PATH 2 proved nothing")
	}
	for _, got := range seen {
		if strings.Contains(got, secret) {
			t.Errorf("PATH 2: a slog.Handler that reflects into an unresolved value recovered the "+
				"material from %T", v)
			break
		}
	}

	// 3. text/template, over the exported methods this probe can actually
	//    INVOKE: no arguments, returning one value or two with an error second.
	//    Over both the value and the pointer method set, because an earlier
	//    version used reflect.TypeOf(v) alone -- the value set -- and PR #28's
	//    reviewer defeated it in two lines with a pointer-receiver method
	//    rendered over &v, which emitted the plaintext while this test stayed
	//    green. A template is handed whatever the caller has, and a caller very
	//    often has a pointer.
	//
	//    THIS PATH DOES NOT COVER THE CLASS, and it used to claim it did. A
	//    template command may pass ARGUMENTS to its final method, and this probe
	//    cannot construct arguments for an arbitrary signature -- a plausible
	//    zero value is not a plausible argument, and calling a method with
	//    invented arguments is a good way to observe a panic rather than a leak.
	//    So an arg-taking method is template-callable and invisible here.
	//
	//    That gap is closed structurally instead, by the allowlist in
	//    secret_internal_test.go: on a redacting type, an exported method not on
	//    a named list is fatal regardless of arity or result. What this path is
	//    for is the other direction -- it renders real templates over real
	//    values, so it catches a method whose BODY starts leaking while its name
	//    stays on the list. Neither replaces the other.
	valueType := reflect.TypeOf(v)
	tried := 0
	for _, rt := range []reflect.Type{valueType, reflect.PointerTo(valueType)} {
		for i := range rt.NumMethod() {
			m := rt.Method(i)
			if !templateInvocable(m.Type) {
				continue
			}
			tried++
			// The data a template is given has to match the receiver, or the
			// method is not reachable and the check silently proves nothing.
			var bare, nested any = v, struct{ V any }{v}
			if rt.Kind() == reflect.Pointer {
				pv := reflect.New(valueType)
				pv.Elem().Set(reflect.ValueOf(v))
				bare = pv.Interface()
				nested = struct{ V any }{pv.Interface()}
			}
			for _, tc := range []struct {
				expr string
				data any
			}{
				{"{{." + m.Name + "}}", bare},
				{"{{.V." + m.Name + "}}", nested},
			} {
				var b strings.Builder
				tp, err := template.New("t").Parse(tc.expr)
				if err != nil || tp.Execute(&b, tc.data) != nil {
					continue
				}
				if rendersMaterial(b.String(), secret) {
					t.Errorf("PATH 3: text/template %s renders the material over %s. %s is an "+
						"exported method, so any template that walks this value can name it. This "+
						"path needs no reflection. credentials/secret.go:98-102 documents this "+
						"exact hazard as the reason credentials.Reveal is a package function and "+
						"not a method.", tc.expr, rt, m.Name)
				}
			}
		}
	}
	if tried == 0 {
		t.Logf("no method on %T or *%T is invocable with no arguments, so PATH 3 rendered nothing "+
			"for it. That is not a result: an arg-taking method would be template-callable and "+
			"unrendered here. The allowlist in secret_internal_test.go is what makes the absence "+
			"mean something", v, v)
	}
}

// rendersMaterial reports whether out exposes the material.
//
// A thin wrapper so this file's assertions read in its own terms, over the ONE
// leak predicate this package has. It was a plain strings.Contains here, and
// that missed a leak: fmt prints a []byte result as decimal byte values, so a
// method returning []byte(material) rendered "[117 115 111 ...]" and this probe
// scored it clean. MarshalJSON returns ([]byte, error) -- exactly the shape
// text/template renders -- so the blind spot sat on an allowlisted method that
// formats for a living. See compute.LeaksMaterialForTest.
func rendersMaterial(out, secret string) bool {
	return compute.LeaksMaterialForTest(out, secret)
}

// templateInvocable reports whether a template can call this method AND this
// probe can supply what it needs to.
//
// Both halves matter and they are not the same set. text/template will call a
// method with arguments when it is the last element of a command, so
// template-callable is wider than this; what is invocable HERE is the niladic
// subset, because there is no general way to synthesise a meaningful argument.
// The difference between the two sets is the reason the class is carried by the
// structural allowlist and not by this walk. Method obtained from a
// reflect.Type carries the receiver as argument 0.
func templateInvocable(sig reflect.Type) bool {
	if sig.NumIn() != 1 || sig.IsVariadic() {
		return false
	}
	switch sig.NumOut() {
	case 1:
		return true
	case 2:
		// text/template accepts a second result only when it is error.
		return sig.Out(1) == reflect.TypeFor[error]()
	default:
		return false
	}
}

// reachableStrings collects every string and byte sequence reachable from v,
// through unexported fields included.
func reachableStrings(v reflect.Value, depth int, seen map[uintptr]bool) []string {
	if !v.IsValid() || depth > 24 {
		return nil
	}
	var out []string
	switch v.Kind() {
	case reflect.String:
		return []string{v.String()}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range v.Len() {
				b[i] = byte(v.Index(i).Uint())
			}
			return []string{string(b)}
		}
		for i := range v.Len() {
			out = append(out, reachableStrings(v.Index(i), depth+1, seen)...)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			out = append(out, reachableStrings(v.Field(i), depth+1, seen)...)
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		if v.Kind() == reflect.Pointer {
			if seen[v.Pointer()] {
				return nil
			}
			seen[v.Pointer()] = true
		}
		out = append(out, reachableStrings(v.Elem(), depth+1, seen)...)
	case reflect.Map:
		if v.IsNil() || seen[v.Pointer()] {
			return nil
		}
		seen[v.Pointer()] = true
		iter := v.MapRange()
		for iter.Next() {
			out = append(out, reachableStrings(iter.Key(), depth+1, seen)...)
			out = append(out, reachableStrings(iter.Value(), depth+1, seen)...)
		}
	}
	return out
}

type walkingHandler struct{ out *[]string }

func (h walkingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h walkingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h walkingHandler) WithGroup(string) slog.Handler            { return h }

func (h walkingHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		// Deliberately NOT a.Value.Resolve(): forgetting it is the ordinary bug.
		raw := a.Value.Any()
		*h.out = append(*h.out, fmt.Sprintf("%v", raw))
		*h.out = append(*h.out, reachableStrings(reflect.ValueOf(raw), 0, map[uintptr]bool{})...)
		return true
	})
	return nil
}

// ---------------------------------------------------------------------------
// The probe checks itself. A check that fails on everything proves nothing, so
// the shape a fix should have is implemented here and asserted to PASS.
// ---------------------------------------------------------------------------

// fixedSecret is what SecretValue should look like. Two properties, and
// SecretValue has neither:
//
//   - the plaintext is in no single field, and the reversing key is a
//     package-level variable the value does not reference, so a walk that
//     recombines everything it can see does not reverse it either;
//   - the way out is a package FUNCTION, so no template can name it and no
//     embedding promotes it.
//
// This is credentials.Foreign's construction. Copying it is cheaper than
// rediscovering it.
type fixedSecret struct {
	masked []byte
	nonce  [16]byte
}

var probeKey = sync.OnceValue(func() [32]byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k
})

func probeKeystream(nonce [16]byte, n int) []byte {
	key := probeKey()
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, 32+16+8)
	for block := uint64(0); len(out) < n; block++ {
		buf = buf[:0]
		buf = append(buf, key[:]...)
		buf = append(buf, nonce[:]...)
		buf = binary.BigEndian.AppendUint64(buf, block)
		sum := sha256.Sum256(buf)
		out = append(out, sum[:]...)
	}
	return out[:n]
}

func newFixedSecret(s string) fixedSecret {
	if s == "" {
		return fixedSecret{}
	}
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	ks := probeKeystream(nonce, len(s))
	masked := make([]byte, len(s))
	for i := range len(s) {
		masked[i] = s[i] ^ ks[i]
	}
	return fixedSecret{masked: masked, nonce: nonce}
}

func revealFixed(f fixedSecret) string {
	if len(f.masked) == 0 {
		return ""
	}
	ks := probeKeystream(f.nonce, len(f.masked))
	out := make([]byte, len(f.masked))
	for i := range f.masked {
		out[i] = f.masked[i] ^ ks[i]
	}
	return string(out)
}

func (f fixedSecret) String() string   { return "[REDACTED]" }
func (f fixedSecret) GoString() string { return "compute.SecretValue{[REDACTED]}" }
func (f fixedSecret) Format(st fmt.State, _ rune) {
	_, _ = fmt.Fprint(st, "[REDACTED]")
}
func (f fixedSecret) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (f fixedSecret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (f fixedSecret) IsZero() bool                 { return len(f.masked) == 0 }

// TestTheProbeDiscriminates is the half that stops this file from being a check
// that fails on everything. It runs the same three paths against the shape a fix
// should have, and requires them to pass.
func TestTheProbeDiscriminates(t *testing.T) {
	assertHidesItsInput(t, newFixedSecret(material), material)
	if revealFixed(newFixedSecret(material)) != material {
		t.Fatal("the reference shape does not round-trip, so it is not a candidate fix")
	}
}
