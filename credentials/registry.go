// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// ProviderRegistry resolves a provider ID to a provider.
//
// Registration is explicit and happens once, at startup, in whatever wiring
// code composes the binary. That is the mechanism that keeps ConductorOne
// optional: a registry that imported its providers would put every provider in
// every adopter's build graph, whereas a registry that is handed them puts in
// only what the operator asked for. Nothing in this package imports a provider.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]CredentialProvider
}

// NewProviderRegistry returns an empty registry. It is empty because nothing in
// this package knows about a provider; the wiring code registers what the
// deployment asked for.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]CredentialProvider)}
}

// ErrDuplicateProvider reports that two providers claim one registry ID. It is
// the sentinel behind DuplicateProviderError.
var ErrDuplicateProvider = errors.New("credentials: a provider is already registered under this ID")

// duplicateProviderMsg is the whole of what a DuplicateProviderError renders,
// besides a count. It is a constant in this repository, which is the property the
// error-content invariant requires.
const duplicateProviderMsg = "credentials: a provider is already registered under this ID; " +
	"the rejected ID is available through DuplicateProviderError.ProviderID"

// DuplicateProviderError reports a rejected registration.
//
// # Why this is a type and not a formatted message
//
// CredentialProvider.ID returns a string and the registry accepts any provider,
// so the ID in a duplicate registration is text this repository did not author --
// an adopter's provider chooses its own. The obvious message names it, and the
// first version of this error did:
//
//	fmt.Errorf("credential provider %q already registered", p.ID())
//
// Review drove one sentinel through ID and read it back out of Error, which makes
// this the same defect as the one CreateNotDeliveredError exists to prevent, at a
// second site. Both are fixed by the same construction rather than by two more
// comments: the ID is held in a Foreign, which no rendering path can format, and
// a caller that wants it asks.
//
//	var dup *credentials.DuplicateProviderError
//	if errors.As(err, &dup) { /* credentials.RevealForeign(dup.ProviderID()) */ }
//
// Registered is carried because a count is permitted by the invariant and is the
// one piece of context that helps without naming anything: it distinguishes "your
// wiring ran twice" from "two providers disagree about a name".
type DuplicateProviderError struct {
	// providerID is the rejected ID. Foreign, not string: see the type comment.
	providerID Foreign
	// registered is how many providers the registry held when it refused.
	registered int
}

// ProviderID returns the rejected registry ID.
//
// It returns a Foreign, so recovering the text is a second deliberate act:
//
//	credentials.RevealForeign(dup.ProviderID())
//
// A string here would be an exported zero-argument method returning caller text,
// which text/template calls by name -- the shape credentials/secret.go warns about
// and USOSS-43 tracks in compute.SecretValue. A template that reaches this method
// gets a placeholder instead.
func (e *DuplicateProviderError) ProviderID() Foreign { return e.providerID }

// Registered returns how many providers were registered when the duplicate was
// refused.
func (e *DuplicateProviderError) Registered() int { return e.registered }

// Error renders a repository constant and a count, and nothing else.
func (e *DuplicateProviderError) Error() string {
	return fmt.Sprintf("%s (%d already registered)", duplicateProviderMsg, e.registered)
}

// Unwrap exposes the sentinel so callers can match with errors.Is.
func (e *DuplicateProviderError) Unwrap() error { return ErrDuplicateProvider }

// Format implements fmt.Formatter for every verb. This is the load-bearing
// method: without it %#v prints the struct and the Foreign inside it -- which is
// itself safe, but only because Foreign is also load-bearing, and depending on one
// layer when two are available is how the previous two rounds went wrong.
func (e *DuplicateProviderError) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, e.Error())
}

// GoString implements fmt.GoStringer. Unreachable through fmt, which consults
// Format first; kept for a direct caller.
func (e *DuplicateProviderError) GoString() string { return e.Error() }

// LogValue implements slog.LogValuer, so a structured logger records the constant
// and the count.
func (e *DuplicateProviderError) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("error", e.Error()),
		slog.Int("registered", e.registered),
	)
}

// Register adds p under its own ID, refusing to replace an existing entry.
//
// Refusing rather than overwriting is the point: a duplicate ID means two
// providers disagree about who owns a name, and silently letting the second one
// win would make which credential you get depend on wiring order.
func (r *ProviderRegistry) Register(p CredentialProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[p.ID()]; exists {
		return &DuplicateProviderError{
			providerID: NewForeign(p.ID()),
			registered: len(r.providers),
		}
	}
	r.providers[p.ID()] = p
	return nil
}

// Get returns the provider registered under id.
func (r *ProviderRegistry) Get(id string) (CredentialProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// List returns every registered provider, in no particular order.
func (r *ProviderRegistry) List() []CredentialProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CredentialProvider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}
