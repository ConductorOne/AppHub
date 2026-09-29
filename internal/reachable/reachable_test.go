// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package reachable_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/conductorone/apphub/internal/reachable"
)

const material = "usoss59-reachability-material-39bytes!!"

// holder is the shape that defeated the fixture this package replaces.
//
// One unexported field, of struct type, holding the key. The walk it replaced
// returned nil for a struct field, so moving the key one level down made it
// invisible while every other property still held: the masked bytes still
// differed per value, no field held the plaintext, and a recombination test that
// tried immediate fields as candidate keys tried the wrong two.
type holder struct{ key [32]byte }

type nestedKey struct {
	masked []byte
	nonce  [16]byte
	inner  holder
}

// TestARecombinationSurvivesAKeyHiddenInANestedStruct is the reviewer's
// reproduction, kept permanently. It is a fixture for the WALK, not for either
// secret type: production has no nested holder, and the point is that the walk
// would not have noticed if it did.
func TestARecombinationSurvivesAKeyHiddenInANestedStruct(t *testing.T) {
	t.Parallel()

	var key [32]byte
	copy(key[:], "a-key-hidden-one-level-down------")
	var nonce [16]byte
	copy(nonce[:], "sixteen-byte-non")

	ks := reachable.Keystream(key, nonce[:], len(material))
	masked := make([]byte, len(material))
	for i := range masked {
		masked[i] = material[i] ^ ks[i]
	}

	r, err := reachable.Walk(nestedKey{masked: masked, nonce: nonce, inner: holder{key: key}})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	// The blob lengths the reviewer reported, which is what says the walk went
	// down rather than that it merely returned something.
	var lengths []int
	for _, b := range r.Blobs {
		lengths = append(lengths, len(b.Bytes))
	}
	for _, want := range []int{len(material), 16, 32} {
		found := false
		for _, got := range lengths {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no reachable blob of length %d; the walk did not reach the masked bytes, the "+
				"nonce and the nested key. Found lengths %v", want, lengths)
		}
	}

	attempts := reachable.Recover(r, material)
	if len(attempts) == 0 {
		t.Fatalf("the recovery found nothing against a construction whose key is reachable, so it "+
			"proves nothing about one whose key is not. Blob paths: %v", paths(r))
	}
	for _, a := range attempts {
		t.Logf("recovered: %s (key=%s nonce=%s target=%s)", a.How, a.KeyPath, a.NoncePath, a.TargetPath)
	}
}

// leakThroughAFuncField is the second shape that has defeated a walk here: an
// exported func field, promoted from deep inside, with a same-name direct field
// as a decoy.
//
// The material is in the closure, where reflection cannot follow it, so the walk
// must report the func as UNREADABLE rather than silently returning nothing —
// "there was nothing there" and "I could not look" are different facts, and only
// one of them is safe to build an invariant on.
type deep9 struct {
	l1 struct {
		l2 struct {
			l3 struct {
				l4 struct {
					l5 struct {
						l6 struct {
							l7 struct {
								l8 struct{ Leak func() string }
							}
						}
					}
				}
			}
		}
	}
	// The decoy: same field name, nine levels shallower, holding nothing.
	Leak func() string
}

func TestAFuncFieldIsReportedUnreadableRatherThanSkipped(t *testing.T) {
	t.Parallel()

	var v deep9
	v.l1.l2.l3.l4.l5.l6.l7.l8.Leak = func() string { return material }

	r, err := reachable.Walk(v)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Both the deep one and the decoy, and the deep one by its full path: a walk
	// that stopped at a depth cap would report the decoy and not the other, and
	// the two are indistinguishable if only the count is checked.
	var deep, shallow bool
	for _, u := range r.Unreadable {
		if u.Kind != reflect.Func {
			continue
		}
		switch {
		case strings.Contains(u.Path, ".l8.Leak"):
			deep = true
		case u.Path == "..Leak":
			shallow = true
		}
	}
	if !deep {
		t.Errorf("the func field nine levels down was not reported; a depth-capped walk reports "+
			"the shallow decoy and stops. Unreadable: %v", r.Unreadable)
	}
	if !shallow {
		t.Errorf("the same-name field at depth one was not reported. Unreadable: %v", r.Unreadable)
	}

	// And nothing claims to have read it, because it cannot be read.
	if got := reachable.Recover(r, material); len(got) != 0 {
		t.Errorf("the recovery claims to have reversed material held in a closure: %v", got)
	}
}

func TestTheWalkDescendsEveryContainerKind(t *testing.T) {
	t.Parallel()

	type inner struct{ s string }
	v := struct {
		P   *inner
		S   []inner
		A   [2]inner
		M   map[string]inner
		I   any
		Nil *inner
	}{
		P: &inner{s: "pointer-" + material},
		S: []inner{{s: "slice-" + material}},
		A: [2]inner{{s: "array-" + material}},
		M: map[string]inner{"k": {s: "map-" + material}},
		I: inner{s: "iface-" + material},
	}

	r, err := reachable.Walk(v)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, prefix := range []string{"pointer-", "slice-", "array-", "map-", "iface-"} {
		found := false
		for _, b := range r.Blobs {
			if strings.HasPrefix(string(b.Bytes), prefix) {
				found = true
			}
		}
		if !found {
			t.Errorf("the walk did not reach the %s value; paths were %v", prefix, paths(r))
		}
	}
	if r.Visited < 10 {
		t.Errorf("the walk visited only %d values, which is too few to have descended six fields",
			r.Visited)
	}
}

// TestACycleTerminatesWithoutADepthCap is why the bound is a visited set and not
// a depth: a depth cap would also stop a legitimate deep value, silently.
func TestACycleTerminatesWithoutADepthCap(t *testing.T) {
	t.Parallel()

	type node struct {
		name string
		next *node
	}
	a := &node{name: "a-" + material}
	b := &node{name: "b"}
	a.next, b.next = b, a

	done := make(chan reachable.Result, 1)
	go func() {
		r, err := reachable.Walk(a)
		if err != nil {
			t.Errorf("Walk: %v", err)
		}
		done <- r
	}()
	r := <-done
	found := false
	for _, blob := range r.Blobs {
		if strings.HasPrefix(string(blob.Bytes), "a-") {
			found = true
		}
	}
	if !found {
		t.Errorf("the cycle guard stopped before reading the first node: %v", paths(r))
	}
}

// TestAnEmptyWalkIsNotAPass pins the non-emptiness requirement. A walk that
// silently stops finding things must fail somebody's assertion, and this is where
// callers are told to make it.
func TestAnEmptyWalkIsNotAPass(t *testing.T) {
	t.Parallel()

	r, err := reachable.Walk(struct{}{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(r.Blobs) != 0 {
		t.Errorf("an empty struct produced %d blob(s)", len(r.Blobs))
	}
	if r.Visited == 0 {
		t.Error("Visited is zero even for a struct that was walked, so a caller cannot tell a walk " +
			"that found nothing from a walk that did not run")
	}
}

// TestTheIndependentKeystreamAgreesWithItself is the drift guard for the
// deliberate reimplementation. It pins the derivation against hand-computed
// expectations of its own shape rather than against a package under test, since
// each caller asserts that agreement for its own construction.
func TestTheIndependentKeystreamAgreesWithItself(t *testing.T) {
	t.Parallel()

	var k1, k2 [32]byte
	k1[0], k2[0] = 1, 2
	nonce := []byte("nonce")

	if string(reachable.Keystream(k1, nonce, 64)) == string(reachable.Keystream(k2, nonce, 64)) {
		t.Error("the key does not change the keystream, so this reimplementation cannot attack a " +
			"keyed construction at all")
	}
	if string(reachable.Keystream(k1, nonce, 64)) == string(reachable.Keystream(k1, []byte("other"), 64)) {
		t.Error("the nonce does not change the keystream")
	}
	for _, n := range []int{1, 31, 32, 33, 63, 64, 65, 4096} {
		if got := len(reachable.Keystream(k1, nonce, n)); got != n {
			t.Errorf("Keystream(%d) returned %d bytes; a short keystream leaves a plaintext tail "+
				"that a whole-material comparison does not notice", n, got)
		}
	}
	if !reachable.AgreesWith(reachable.Keystream, k1, nonce, 64) {
		t.Error("AgreesWith disagrees with the function it is comparing against, so it can never " +
			"detect a real divergence")
	}
}

func paths(r reachable.Result) []string {
	out := make([]string, 0, len(r.Blobs))
	for _, b := range r.Blobs {
		out = append(out, b.Path+"("+b.Kind+","+itoa(len(b.Bytes))+")")
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// aliasedViews is the third shape that defeated this walk: the real key held as
// two []byte views over one backing array, ordered so the SHORT one is walked
// first.
//
// Both fields have the same Pointer and the same Type, so a cycle identity of
// (pointer, type) marked the array visited after reading one byte of it and then
// declined to walk the full view. A cycle guard turning into a skip.
//
// The short view is CAP-CLAMPED -- key[:1:1] rather than key[:1] -- and that
// detail is the fixture, not an incidental. My first version used key[:1], which
// has cap 32, so reading to capacity found all 32 bytes from the short view alone
// and the test passed with the cycle identity reverted to (pointer, type). It was
// green for a mechanism it does not name. Found by mutating the two halves
// separately and noticing that only one of them turned it red -- which is the
// whole argument for reverting each half of a fix on its own rather than the fix
// as a unit.
type aliasedViews struct {
	masked []byte
	nonce  [16]byte
	prefix []byte // key[:1:1] -- len 1, CAP 1, same base pointer
	key    []byte // key[:]    -- the whole thing, same backing array
}

func TestAKeyHiddenBehindAShorterAliasOfItselfIsStillFound(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	copy(key, "a-key-behind-a-one-byte-alias---")
	var nonce [16]byte
	copy(nonce[:], "sixteen-byte-non")

	ks := reachable.Keystream([32]byte(key), nonce[:], len(material))
	masked := make([]byte, len(material))
	for i := range masked {
		masked[i] = material[i] ^ ks[i]
	}

	// Cap-clamped, so the capacity read cannot recover the key from this view and
	// the cycle identity is the only thing that lets the walk reach the other one.
	prefix := key[:1:1]
	if cap(prefix) != 1 {
		t.Fatalf("the fixture is not the shape it claims: the short view has cap %d, so reading "+
			"to capacity would find the key without the cycle identity mattering", cap(prefix))
	}
	r, err := reachable.Walk(aliasedViews{masked: masked, nonce: nonce, prefix: prefix, key: key})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !hasBlobOfLength(r, 32) {
		t.Errorf("no 32-byte blob: the walk read the one-byte view and then treated the full view "+
			"as already visited, because both share a pointer and a type. Found %v", paths(r))
	}
	if got := reachable.Recover(r, material); len(got) == 0 {
		t.Fatalf("the recovery found nothing against a construction whose key is reachable through "+
			"an aliased view. Blobs: %v", paths(r))
	}
}

// capacityHidden is the fourth shape: the key lives in the CAPACITY of a
// one-byte view.
//
// Nothing about the value's length mentions it, so widening the cycle identity to
// include Len -- which closes aliasedViews -- leaves this wide open. An adversary
// re-slices to Cap, which reflect permits on a slice from an unexported field
// with no unsafe at all.
type capacityHidden struct {
	masked []byte
	nonce  [16]byte
	view   []byte // len 1, cap 32; the key is the backing array
}

func TestAKeyHiddenInASlicesCapacityIsStillFound(t *testing.T) {
	t.Parallel()

	backing := make([]byte, 32)
	copy(backing, "a-key-hiding-past-the-view-len--")
	var nonce [16]byte
	copy(nonce[:], "sixteen-byte-non")

	ks := reachable.Keystream([32]byte(backing), nonce[:], len(material))
	masked := make([]byte, len(material))
	for i := range masked {
		masked[i] = material[i] ^ ks[i]
	}

	view := backing[:1]
	if len(view) != 1 || cap(view) != 32 {
		t.Fatalf("the fixture is not the shape it claims: len=%d cap=%d", len(view), cap(view))
	}

	r, err := reachable.Walk(capacityHidden{masked: masked, nonce: nonce, view: view})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !hasBlobOfLength(r, 32) {
		t.Errorf("no 32-byte blob: the walk read to Len and the key is past it. Bytes beyond a "+
			"slice's length are reachable through Value.Slice(0, Cap) with no unsafe, so a "+
			"Len-bounded walk chooses its own population. Found %v", paths(r))
	}
	if got := reachable.Recover(r, material); len(got) == 0 {
		t.Fatalf("the recovery found nothing against a key held in a slice's capacity. Blobs: %v",
			paths(r))
	}
}

// capClampedDecoy is the fifth shape, and it exists because a mutation found the
// gap rather than because a reviewer did.
//
// Reverting the identity to (pointer, type, len) -- keeping the len fix and
// dropping cap -- turned no test red, which means the cap component of the
// identity was carrying nothing. Two views can share a pointer, a type AND a
// length while differing in capacity: key[:1:1] and key[:1] are both one byte
// long, and only the second can be re-sliced to 32.
//
// So the decoy is walked first, the guard marks (ptr, typ, len=1) seen, and the
// view that actually exposes the key is skipped. An inert component of a security
// identity is the same defect as an inert hook: it looks like coverage.
type capClampedDecoy struct {
	masked []byte
	nonce  [16]byte
	decoy  []byte // key[:1:1] -- len 1, cap 1
	view   []byte // key[:1]   -- len 1, cap 32; same pointer, same length
}

func TestTwoViewsOfEqualLengthAndDifferentCapacityAreBothWalked(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	copy(key, "a-key-behind-a-cap-clamped-decoy")
	var nonce [16]byte
	copy(nonce[:], "sixteen-byte-non")

	ks := reachable.Keystream([32]byte(key), nonce[:], len(material))
	masked := make([]byte, len(material))
	for i := range masked {
		masked[i] = material[i] ^ ks[i]
	}

	decoy, view := key[:1:1], key[:1]
	if len(decoy) != len(view) || cap(decoy) == cap(view) {
		t.Fatalf("the fixture is not the shape it claims: lens %d/%d caps %d/%d",
			len(decoy), len(view), cap(decoy), cap(view))
	}

	r, err := reachable.Walk(capClampedDecoy{masked: masked, nonce: nonce, decoy: decoy, view: view})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !hasBlobOfLength(r, 32) {
		t.Errorf("no 32-byte blob: the cap-clamped decoy was walked first and the guard treated "+
			"the re-sliceable view as already visited, because the identity does not carry cap. "+
			"Found %v", paths(r))
	}
	if got := reachable.Recover(r, material); len(got) == 0 {
		t.Fatalf("the recovery found nothing. Blobs: %v", paths(r))
	}
}

// TestTheCycleGuardStillTerminatesOnAliasedViews is the other half of widening
// the identity: a guard that now distinguishes more values must still stop.
//
// Worth its own test because the two requirements pull against each other -- the
// fix for a guard that skipped too much is a guard that dedups less, and a guard
// that dedups nothing does not terminate.
func TestTheCycleGuardStillTerminatesOnAliasedViews(t *testing.T) {
	t.Parallel()

	// Many views over one array, every length. Without dedup this is quadratic
	// in reads and still finite; the assertion is that it completes and that the
	// distinct views are actually distinguished.
	backing := make([]byte, 64)
	copy(backing, material)
	views := make([][]byte, 0, 64)
	for i := range 64 {
		views = append(views, backing[:i+1])
	}

	done := make(chan reachable.Result, 1)
	go func() {
		r, err := reachable.Walk(struct{ V [][]byte }{V: views})
		if err != nil {
			t.Errorf("Walk: %v", err)
		}
		done <- r
	}()
	r := <-done

	// Each view is read to capacity, so every one yields the same 64 bytes and
	// the material is found. What matters is that it finished at all.
	if !hasBlobOfLength(r, 64) {
		t.Errorf("64 aliased views produced no 64-byte blob: %v", paths(r))
	}
	if r.Visited < 64 {
		t.Errorf("the walk visited %d values for 64 views, so views were still being deduped away",
			r.Visited)
	}
}

// hasBlobOfLength reports whether the walk found a blob of exactly n bytes.
func hasBlobOfLength(r reachable.Result, n int) bool {
	for _, b := range r.Blobs {
		if len(b.Bytes) == n {
			return true
		}
	}
	return false
}
