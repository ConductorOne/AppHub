// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// Registry is the set of modules a process can invoke, keyed by module ID.
//
// It is safe for concurrent use. A process registers everything it offers
// during start-up and then serves from the registry -- the two of the source's
// five commands that build a registry at all both do exactly that -- so reads
// dominate and the lock is a sync.RWMutex.
//
// Registration is the only mutation. There is no Unregister and no setter that
// reaches into a registered module, which is what makes a registry read safe
// without the caller synchronising against a concurrent rewiring — see the
// package doc on how a module gets its dependencies.
//
// # The registry does not trust a module's accessors after registration
//
// Every value the registry keys, orders or filters on is **snapshotted at
// [Registry.Register]** and never re-read from the module. That is what makes
// the invariants above true rather than merely intended: a module is free to
// report a different ID or category a moment later — an arbitrary [Module]
// implementation is somebody else's code and can do as it likes — and the
// registry is unaffected, because it stopped asking.
//
// This was a real defect and not a hypothetical one. With the metadata reachable
// as an exported field, `m.ModuleID = "other"` after registration produced a
// [Registry.List] containing two modules reporting one ID, past a duplicate
// check that had already passed. Making [BaseModule]'s fields private closes
// that for the type this package ships; the snapshot closes it for
// implementations this package has never seen, which is the half that keeps
// holding.
//
// The residual, stated rather than implied: a custom module can still *report*
// an identity that disagrees with the one it was registered under. Nothing can
// stop an arbitrary implementation returning whatever it likes from ID(). What
// is guaranteed is that the registry does not believe it, so the disagreement is
// visible to a caller that asks the module and cannot corrupt the registry.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]registration
}

// registration is a module together with the metadata the registry took from it
// at Register time.
//
// Only the values the registry itself uses are snapshotted -- the key, the sort
// order and the category filter. Name, Description and Icon are not, because the
// registry never reads them: storing them would imply a guarantee about values
// nothing here depends on.
type registration struct {
	module   Module
	id       string
	category string
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]registration),
	}
}

// Register adds a module, and fails if its ID is already taken.
//
// The duplicate is an error rather than a silent overwrite because an ID is how
// a stored request names the module that will run it: two modules answering to
// one ID means which of them runs depends on registration order. A caller that
// ignores this error has that ambiguity in its process.
func (r *Registry) Register(module Module) error {
	// isNilModule, not module == nil: see its doc. This has to come before any
	// method call on module, because the panic it prevents is a method call.
	if isNilModule(module) {
		return fmt.Errorf("cannot register a nil module")
	}
	// An empty ID is unnameable in a request and unusable in a stored record, so
	// it is refused here rather than becoming a module nothing can invoke.
	id := module.ID()
	if id == "" {
		return fmt.Errorf("cannot register a module with an empty ID")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[id]; exists {
		return fmt.Errorf("module with ID %q already registered", id)
	}

	// The snapshot. Everything the registry keys, orders or filters on is taken
	// here, once, so nothing below depends on the module still agreeing with it.
	r.modules[id] = registration{module: module, id: id, category: module.Category()}
	return nil
}

// Get returns the module registered under id, and whether there was one.
func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.modules[id]
	if !ok {
		return nil, false
	}
	return reg.module, true
}

// List returns every registered module, ordered by ID.
//
// Ordered because the result is rendered: a listing whose order changes between
// two identical requests is a defect in the caller's output and a flake in its
// tests, and a map has no order to inherit.
func (r *Registry) List() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	regs := make([]registration, 0, len(r.modules))
	for _, reg := range r.modules {
		regs = append(regs, reg)
	}
	return sortedModules(regs)
}

// ListByCategory returns the registered modules in category, ordered by ID.
// An unknown category yields an empty slice, not an error: asking what is in a
// category is a legitimate question with "nothing" as a legitimate answer.
func (r *Registry) ListByCategory(category string) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	regs := make([]registration, 0)
	for _, reg := range r.modules {
		if reg.category == category {
			regs = append(regs, reg)
		}
	}
	return sortedModules(regs)
}

// isNilModule reports whether module is nil, including a typed nil.
//
// A typed nil -- `var m *ExampleModule; r.Register(m)` -- is an interface value
// that is *not* equal to nil: it carries a type and a nil pointer. Comparing
// against nil misses it, and the next method call dereferences the nil pointer
// and panics.
//
// That state is reachable, not academic, and the constructor convention this
// package documents is what makes it reachable: a constructor returns
// (*ExampleModule, error), so a caller that logs the error and carries on --
// or that checks a different error variable by mistake -- has exactly this
// value in hand. Register's contract is to return an error for a module it
// cannot accept, so it has to catch this one too.
//
// reflect is the only way to ask. The kinds listed are the ones that can hold
// nil; anything else (a struct value with value-receiver methods, say) cannot
// be nil and is passed through.
func isNilModule(module Module) bool {
	if module == nil {
		return true
	}
	v := reflect.ValueOf(module)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// sortedModules orders registrations by their registered ID and returns the
// modules.
//
// By the *registered* ID, not the reported one: registered IDs are unique within
// a registry because Register rejected the duplicate, so the order is total and
// stays total. Sorting by what each module currently reports would be sorting by
// a value the module can change, which is how a listing came to contain two
// entries with the same ID.
func sortedModules(regs []registration) []Module {
	sort.Slice(regs, func(i, j int) bool { return regs[i].id < regs[j].id })
	out := make([]Module, 0, len(regs))
	for _, reg := range regs {
		out = append(out, reg.module)
	}
	return out
}
