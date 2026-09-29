// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/modules"
)

// stubModule is the smallest thing that satisfies Module. Execute is never
// reached by these tests: the registry stores modules, it does not run them.
type stubModule struct {
	modules.BaseModule
}

func newStub(id, category string) *stubModule {
	return &stubModule{BaseModule: modules.NewBaseModule(id, id, "", "", category)}
}

func (m *stubModule) Schema() *modules.JSONSchema { return &modules.JSONSchema{Type: "object"} }

func (m *stubModule) Validate(params map[string]any) error {
	return modules.ValidateDeclaredParams(m.Schema(), params)
}

func (m *stubModule) Execute(context.Context, string, map[string]any) (*modules.Result, error) {
	return &modules.Result{Success: true}, nil
}

var _ modules.Module = (*stubModule)(nil)

func ids(mods []modules.Module) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.ID())
	}
	return out
}

func TestRegistryRegisterAndGet(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()
	deploy := newStub("deploy", "delivery")

	if err := r.Register(deploy); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Get("deploy")
	if !ok {
		t.Fatal("Get(deploy) reported not found")
	}
	if got != modules.Module(deploy) {
		t.Errorf("Get(deploy) returned %v, want the registered instance", got)
	}

	if _, ok := r.Get("nope"); ok {
		t.Error("Get(nope) reported found")
	}
	if _, ok := r.Get(""); ok {
		t.Error("Get(\"\") reported found on an empty registry lookup")
	}
}

func TestRegistryRejectsDuplicateID(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()
	first := newStub("review", "security")
	if err := r.Register(first); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := r.Register(newStub("review", "security"))
	if err == nil {
		t.Fatal("Register accepted a duplicate ID")
	}
	if !strings.Contains(err.Error(), `"review"`) {
		t.Errorf("error %q does not name the conflicting ID", err)
	}

	// The first registration stands: a rejected duplicate must not have
	// displaced what was already there.
	got, ok := r.Get("review")
	if !ok {
		t.Fatal("Get(review) reported not found after a rejected duplicate")
	}
	if got != modules.Module(first) {
		t.Error("the rejected duplicate replaced the registered module")
	}
}

func TestRegistryRejectsUnusableRegistrations(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()

	if err := r.Register(nil); err == nil {
		t.Error("Register(nil) returned no error")
	}
	if err := r.Register(newStub("", "security")); err == nil {
		t.Error("Register of an empty-ID module returned no error")
	}
	if got := len(r.List()); got != 0 {
		t.Errorf("registry holds %d modules after two rejected registrations, want 0", got)
	}
}

// TestRegistryRejectsTypedNil is a regression test: a typed nil is an interface
// value that is not equal to nil, so a `module == nil` check misses it and the
// first method call panics. Before the isNilModule fix this test crashed the
// test binary at Register's call to ID() rather than failing.
//
// It is deliberately in the external test package, because that is where the
// mistake lives: a caller in another package holding a (*T, error) from a
// constructor whose error it did not honour.
func TestRegistryRejectsTypedNil(t *testing.T) {
	t.Parallel()

	t.Run("typed nil pointer", func(t *testing.T) {
		t.Parallel()

		r := modules.NewRegistry()
		var m *stubModule // nil pointer, non-nil Module interface value

		err := r.Register(m)
		if err == nil {
			t.Fatal("Register(typed nil) returned no error")
		}
		if got := len(r.List()); got != 0 {
			t.Errorf("registry holds %d modules after a rejected typed nil, want 0", got)
		}
	})

	t.Run("unhonoured constructor error", func(t *testing.T) {
		t.Parallel()

		r := modules.NewRegistry()

		// The realistic shape of the mistake: the constructor refused to build
		// the module, and the caller registered its zero return anyway.
		m, err := newExampleModule(nil)
		if err == nil {
			t.Fatal("newExampleModule(nil) unexpectedly succeeded")
		}

		if err := r.Register(m); err == nil {
			t.Fatal("Register of an unbuilt module returned no error")
		}
		if got := len(r.List()); got != 0 {
			t.Errorf("registry holds %d modules after a rejected typed nil, want 0", got)
		}
	})

	t.Run("a value-receiver module is not nil", func(t *testing.T) {
		t.Parallel()

		// The nilability check must not reject a legitimate non-pointer
		// implementation, which cannot be nil in the first place.
		r := modules.NewRegistry()
		if err := r.Register(valueModule{id: "value"}); err != nil {
			t.Fatalf("Register(value module): %v", err)
		}
		if _, ok := r.Get("value"); !ok {
			t.Error("Get(value) reported not found")
		}
	})
}

// valueModule implements Module on a value receiver, so registering it exercises
// the non-nilable branch of the nilability check.
type valueModule struct {
	id string
}

func (m valueModule) ID() string                    { return m.id }
func (m valueModule) Name() string                  { return m.id }
func (m valueModule) Description() string           { return "" }
func (m valueModule) Icon() string                  { return "" }
func (m valueModule) Category() string              { return "" }
func (m valueModule) Schema() *modules.JSONSchema   { return &modules.JSONSchema{Type: "object"} }
func (m valueModule) Validate(map[string]any) error { return nil }

func (m valueModule) Execute(context.Context, string, map[string]any) (*modules.Result, error) {
	return &modules.Result{Success: true}, nil
}

var _ modules.Module = valueModule{}

func TestRegistryListIsOrderedByID(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()
	// Registered out of order, so passing cannot be an accident of insertion.
	for _, id := range []string{"review", "deploy", "fix"} {
		if err := r.Register(newStub(id, "any")); err != nil {
			t.Fatalf("Register(%s): %v", id, err)
		}
	}

	want := []string{"deploy", "fix", "review"}
	// Repeated because map iteration order is randomised per range: one pass
	// would agree with an unordered implementation about a third of the time.
	for i := 0; i < 50; i++ {
		got := ids(r.List())
		if len(got) != len(want) {
			t.Fatalf("List() = %v, want %v", got, want)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: List() = %v, want %v", i, got, want)
			}
		}
	}
}

func TestRegistryListByCategory(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()
	for _, m := range []*stubModule{
		newStub("review", "security"),
		newStub("deploy", "delivery"),
		newStub("fix", "security"),
	} {
		if err := r.Register(m); err != nil {
			t.Fatalf("Register(%s): %v", m.ID(), err)
		}
	}

	got := ids(r.ListByCategory("security"))
	want := []string{"fix", "review"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ListByCategory(security) = %v, want %v", got, want)
	}

	// An unknown category is a question with "nothing" as its answer, and the
	// caller should be able to range over the result without a nil check.
	empty := r.ListByCategory("does-not-exist")
	if empty == nil {
		t.Error("ListByCategory of an unknown category returned nil, want an empty slice")
	}
	if len(empty) != 0 {
		t.Errorf("ListByCategory(does-not-exist) = %v, want empty", ids(empty))
	}
}

// The registry is read from request goroutines while start-up may still be
// registering, which is exactly the interleaving the RWMutex exists for. Run
// under -race; without the lock this fails.
func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()

	const writers = 8
	const readers = 8

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			id := string(rune('a' + w))
			if err := r.Register(newStub(id, "any")); err != nil {
				t.Errorf("Register(%s): %v", id, err)
			}
		}(w)
	}

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				r.Get("a")
				r.List()
				r.ListByCategory("any")
			}
		}()
	}

	wg.Wait()

	if got := len(r.List()); got != writers {
		t.Errorf("registry holds %d modules, want %d", got, writers)
	}
}

// A module that reached the registry is wired: the constructor refused to build
// an unconfigured one, so no caller has to ask whether a registered module is
// ready. This test states that invariant where a future change to the wiring
// convention would trip over it.
func TestRegisteredModulesAreAlreadyConfigured(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()

	if _, err := newExampleModule(nil); !errors.Is(err, modules.ErrNotConfigured) {
		t.Fatalf("unconfigured constructor error = %v, want ErrNotConfigured", err)
	}

	m, err := newExampleModule(&recordingSink{})
	if err != nil {
		t.Fatalf("newExampleModule: %v", err)
	}
	if err := r.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Get(exampleModuleID)
	if !ok {
		t.Fatalf("Get(%s) reported not found", exampleModuleID)
	}
	res, err := got.Execute(context.Background(), "user-1", map[string]any{"target": "thing"})
	if err != nil {
		t.Fatalf("Execute on a registered module: %v", err)
	}
	if !res.Success {
		t.Errorf("Execute returned Success=false: %+v", res)
	}
}

// A registered module's identity must not be able to drift.
//
// The Registry is documented as keyed by module ID, it rejects a duplicate ID to
// keep two modules from answering to one key, and its ordering assumes IDs are
// unique. All three are claims about a value that used to be an exported field
// on [modules.BaseModule], so an ordinary assignment after registration broke
// them — no race, no malformed implementation, just a legal cross-package state
// transition through the delivered API.
//
// Two things close it, and the first does not cover the second: BaseModule's
// metadata is private and constructor-only, and the Registry keys off a snapshot
// taken at Register time rather than re-reading the module's own accessor. The
// snapshot is what holds for implementations this package has never seen.

// mutableModule is a Module whose metadata a caller can change at any time. It
// is what an arbitrary third-party implementation may look like, and the
// registry must be correct in its presence rather than trusting it not to.
type mutableModule struct {
	id       string
	category string
}

func (m *mutableModule) ID() string          { return m.id }
func (m *mutableModule) Name() string        { return "mutable" }
func (m *mutableModule) Description() string { return "a module that changes its own identity" }
func (m *mutableModule) Icon() string        { return "science" }
func (m *mutableModule) Category() string    { return m.category }
func (m *mutableModule) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{Type: "object", Properties: map[string]modules.JSONSchemaProperty{}}
}
func (m *mutableModule) Validate(map[string]any) error { return nil }
func (m *mutableModule) Execute(context.Context, string, map[string]any) (*modules.Result, error) {
	return &modules.Result{Success: true}, nil
}

func TestARegisteredModuleStaysUnderTheIDItWasRegisteredWith(t *testing.T) {
	t.Parallel()
	r := modules.NewRegistry()
	m := &mutableModule{id: "before", category: "examples"}
	if err := r.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	m.id = "after"

	got, ok := r.Get("before")
	if !ok {
		t.Fatal(`Get("before") reported not found: the registry followed the module's ` +
			`own accessor instead of the key it registered`)
	}
	if got != modules.Module(m) {
		t.Error(`Get("before") returned a different module`)
	}
	if _, ok := r.Get("after"); ok {
		t.Error(`Get("after") found a module: the registry acquired a key nobody registered`)
	}
}

func TestRegisteredIDsStayUniqueWhenAModuleRenamesItself(t *testing.T) {
	t.Parallel()
	r := modules.NewRegistry()
	first := &mutableModule{id: "first", category: "examples"}
	second := &mutableModule{id: "second", category: "examples"}
	for _, m := range []*mutableModule{first, second} {
		if err := r.Register(m); err != nil {
			t.Fatalf("Register(%s): %v", m.id, err)
		}
	}

	first.id = "second"

	// The registry's own view must still hold both invariants: two keys, and
	// each key still resolving to the module registered under it.
	if _, ok := r.Get("first"); !ok {
		t.Error(`Get("first") reported not found after the module renamed itself`)
	}
	got, ok := r.Get("second")
	if !ok {
		t.Fatal(`Get("second") reported not found`)
	}
	if got != modules.Module(second) {
		t.Error(`Get("second") returned the module that renamed itself into that key`)
	}
	if n := len(r.List()); n != 2 {
		t.Errorf("List returned %d modules, want 2", n)
	}
}

func TestListOrdersByTheRegisteredIDNotTheReportedOne(t *testing.T) {
	t.Parallel()
	r := modules.NewRegistry()
	a := &mutableModule{id: "a", category: "examples"}
	b := &mutableModule{id: "b", category: "examples"}
	for _, m := range []*mutableModule{a, b} {
		if err := r.Register(m); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	// Reverse what the modules report. The registered order must not move.
	a.id, b.id = "z", "a"

	got := r.List()
	if len(got) != 2 {
		t.Fatalf("List returned %d modules, want 2", len(got))
	}
	if got[0] != modules.Module(a) || got[1] != modules.Module(b) {
		t.Error("List reordered by what the modules now report rather than by how they " +
			"were registered")
	}
}

func TestListByCategoryUsesTheRegisteredCategory(t *testing.T) {
	t.Parallel()
	r := modules.NewRegistry()
	m := &mutableModule{id: "m", category: "examples"}
	if err := r.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	m.category = "somewhere-else"

	if got := r.ListByCategory("examples"); len(got) != 1 {
		t.Errorf(`ListByCategory("examples") returned %d modules, want 1: the registry `+
			`followed the module's own accessor`, len(got))
	}
	if got := r.ListByCategory("somewhere-else"); len(got) != 0 {
		t.Errorf(`ListByCategory("somewhere-else") returned %d modules, want 0`, len(got))
	}
}

// TestTheRegistryKeepsItsSnapshotWhenTheModulesAccessorChanges pins the residual
// as a named limit rather than leaving it an implied guarantee.
//
// A custom Module can still *report* an identity that disagrees with the one it
// was registered under — nothing can stop an arbitrary implementation returning
// whatever it likes from ID(). What the registry guarantees is that it does not
// believe it: the key, the ordering and the category filter all come from the
// snapshot taken at Register time. So the disagreement is visible to a caller
// that asks the module, and cannot corrupt the registry.
func TestTheRegistryKeepsItsSnapshotWhenTheModulesAccessorChanges(t *testing.T) {
	t.Parallel()
	r := modules.NewRegistry()
	m := &mutableModule{id: "registered", category: "examples"}
	if err := r.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	m.id, m.category = "renamed", "moved"

	got, ok := r.Get("registered")
	if !ok {
		t.Fatal("the registry lost its snapshot")
	}
	// The residual, asserted rather than described: the module disagrees with
	// the registry, the registry is right, and the disagreement is observable.
	if got.ID() != "renamed" {
		t.Errorf("the module reports ID %q; this test exists because it can report "+
			"anything", got.ID())
	}
	if _, ok := r.Get("renamed"); ok {
		t.Error("the registry adopted the module's new ID")
	}
	if n := len(r.ListByCategory("examples")); n != 1 {
		t.Errorf("ListByCategory dropped the module when it changed its own category (%d)", n)
	}
}

// TestBaseModuleMetadataIsConstructorOnly is the structural half. Re-exporting
// any of BaseModule's fields would reopen the first reproduction for the type
// this package ships, and would do so silently: every existing test would still
// pass.
func TestBaseModuleMetadataIsConstructorOnly(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(modules.BaseModule{})
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("BaseModule.%s is exported: a registered module's metadata must be "+
				"settable only through NewBaseModule", f.Name)
		}
	}
	if typ.NumField() == 0 {
		t.Error("BaseModule has no fields; this check would pass over nothing")
	}
}
