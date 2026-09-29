// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

// The standing error-content invariant, stated over this package by this package.
//
// The invariant, and why the derivation rather than a list, is in
// internal/errhygiene. What is here is the part only this package can write: how
// each of its exported inputs is driven with a sentinel, and a named reason for
// every one that is deliberately not.
//
// It used to be the other way round -- internal/errhygiene named five packages and
// drove them from outside -- and USOSS-52 reversed it so that credentials/c1 could
// hold the same invariant without an import-boundary allowlist entry.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath:             "github.com/conductorone/apphub/credentials",
		Drivers:                drivers,
		RendererExemptions:     rendererExemptions,
		TextProducerExemptions: textProducerExemptions,
	})
}

// Two metadata keys, spelled here rather than imported from credentials/datadog and
// credentials/github.
//
// The sentinel goes in the VALUES, so which keys these are does not matter to the
// check -- and importing two providers into this package's test to borrow two string
// constants would make the core package's tests depend on its providers for no
// benefit. That keys really do render, and values really do not, is pinned by
// TestMetadataRendersKeysAndNotValues below rather than assumed.
const (
	metadataKeyOne = "admin_api_key"
	metadataKeyTwo = "permissions"
)

// sentinelProvider is a CredentialProvider whose ID is the sentinel. Registering
// two of them is the registry half of the invariant.
type sentinelProvider struct{ id string }

func (p sentinelProvider) ID() string   { return p.id }
func (p sentinelProvider) Name() string { return "sentinel" }
func (p sentinelProvider) CreateCredential(context.Context, credentials.CreateRequest) (*credentials.CreateResult, error) {
	return nil, nil
}
func (p sentinelProvider) RevokeCredential(context.Context, string, credentials.Metadata) error {
	return nil
}
func (p sentinelProvider) GetCredentialStatus(context.Context, string, credentials.Metadata) (credentials.CredentialStatus, error) {
	return credentials.CredentialStatusUnknown, nil
}
func (p sentinelProvider) SupportsDynamic() bool { return false }

// rendererExemptions are types that render what they hold on purpose.
//
// Each one is a decision recorded elsewhere in the repository, restated here so that
// a type is never omitted by accident. A type that acquires a rendering method and
// appears in neither a driver's output nor this map fails the RenderersExercised
// check.
var rendererExemptions = map[string]string{
	"credentials.SecretRef": "a SecretRef is a locator and renders as one: its whole purpose is to be " +
		"written into a record, a container definition or a log so an operator can find the material it " +
		"points at. It is not material, no error in this package formats one (verified by search at the " +
		"time of writing), and credentials/secret.go records the handling it does need.",
}

// textProducerExemptions are types with an exported zero-argument text-producing
// method that no driver produces a value of, with the reason.
var textProducerExemptions = map[string]string{
	"credentials.SecretRef": "a SecretRef is a locator and renders as one; it is constructed from " +
		"exported fields rather than from a call, so no driver here produces one, and " +
		"credentials/secret.go records the handling it needs. Same reason as its renderer exemption.",
}

// drivers maps a derived entry point to how it is driven.
//
// The keys are checked against the derivation in both directions: a derived entry
// point with no key here fails, and a key here that matches no derived entry point
// fails. The second direction matters as much as the first, because a renamed
// function otherwise leaves a driver that quietly covers nothing.
var drivers = map[string]errhygiene.Driver{
	// ---- the types whose whole job is refusing to render ----

	"credentials.NewForeign": {Run: func(_ *testing.T, s string) []any {
		return []any{credentials.NewForeign(s)}
	}},
	"credentials.(Foreign).Format": {Run: func(_ *testing.T, s string) []any {
		// Format is reached by the rendering matrix's verbs; producing the value is
		// the driver.
		return []any{credentials.NewForeign(s)}
	}},
	"credentials.(*Foreign).GobDecode": {Run: func(_ *testing.T, s string) []any {
		var f credentials.Foreign
		return []any{f.GobDecode([]byte(s)), f}
	}},
	"credentials.NewSecret": {Run: func(_ *testing.T, s string) []any {
		return []any{credentials.NewSecret(s)}
	}},
	"credentials.(Secret).Format": {Run: func(_ *testing.T, s string) []any {
		return []any{credentials.NewSecret(s)}
	}},
	"credentials.(*Secret).GobDecode": {Run: func(_ *testing.T, s string) []any {
		var sec credentials.Secret
		return []any{sec.GobDecode([]byte(s)), sec}
	}},
	"credentials.(*Secret).UnmarshalJSON": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, in := range []string{
			s,                   // not JSON at all: the reviewer's fourth input
			`"` + s + `"`,       // a JSON string: succeeds, must stay redacted
			`{"k":"` + s + `"}`, // an object where a string was wanted
			`[1,2,"` + s + `"]`, // an array where a string was wanted
			`{"k":` + s + `}`,   // malformed part-way through
		} {
			var sec credentials.Secret
			out = append(out, sec.UnmarshalJSON([]byte(in)), sec)
		}
		return out
	}},
	"credentials.(Metadata).Format": {
		// The sentinel goes in the values. Metadata renders its key set by
		// documented design -- keys are configuration names and are useful in a log
		// -- and TestMetadataRendersKeysAndNotValues pins both halves of that so the
		// exemption is demonstrated rather than asserted here.
		Run: func(_ *testing.T, s string) []any {
			return []any{credentials.Metadata{
				metadataKeyOne: s,
				metadataKeyTwo: s,
			}}
		},
		// Only this driver, and only for the value it returns directly.
		// credentials/secret.go states that a Metadata's values are reachable by
		// reflection and that the type cannot stop code which deliberately walks
		// one. A Metadata reached inside anything else is NOT exempt, and that is
		// the whole difference from the version review defeated.
		ReachableExempt: "credentials.Metadata documents its values as reachable by reflection; this " +
			"driver returns one directly, which is the documented case. Nested Metadata is not exempt.",
	},
	"credentials.(*Metadata).GobDecode": {Run: func(_ *testing.T, s string) []any {
		var m credentials.Metadata
		return []any{m.GobDecode([]byte(s)), m}
	}},
	"credentials.DescribeType": {Run: func(_ *testing.T, s string) []any {
		return []any{
			credentials.DescribeType(credentials.CredentialType(s)),
			credentials.DescribeType(credentials.CredentialType(strings.ToLower(s))),
		}
	}},
	"credentials.NewCreateNotDelivered": {Run: func(_ *testing.T, s string) []any {
		return []any{
			credentials.NewCreateNotDelivered(s, "opaque-handle"),
			credentials.NewCreateNotDelivered("datadog", s),
			credentials.NewCreateNotDelivered(s, s),
		}
	}},
	"credentials.(*CreateNotDeliveredError).Format": {Run: func(_ *testing.T, s string) []any {
		return []any{credentials.NewCreateNotDelivered(s, s)}
	}},

	// ---- the registry ----

	"credentials.(*ProviderRegistry).Register": {Run: func(_ *testing.T, s string) []any {
		r := credentials.NewProviderRegistry()
		first := r.Register(sentinelProvider{id: s})
		dup := r.Register(sentinelProvider{id: s})
		// A second registry, holding no sentinel, is returned so the zero-argument
		// probe can call ProviderRegistry's methods. The sentinel-bearing registry
		// is deliberately NOT returned: a registry stores the IDs it is handed, so
		// walking one finds them by design, and that is the caller's own data
		// structure rather than anything this package renders.
		clean := credentials.NewProviderRegistry()
		_ = clean.Register(sentinelProvider{id: "constant-provider-id"})
		return []any{first, dup, clean}
	}},
	"credentials.(*DuplicateProviderError).Format": {Run: func(_ *testing.T, s string) []any {
		r := credentials.NewProviderRegistry()
		_ = r.Register(sentinelProvider{id: s})
		var dup *credentials.DuplicateProviderError
		err := r.Register(sentinelProvider{id: s})
		if !errors.As(err, &dup) {
			return []any{err}
		}
		return []any{dup}
	}},

	// ---- exemptions ----

	"credentials.Reveal": {Why: "Reveal exists to return credential material; returning it is the " +
		"function's purpose and every call site is the deliberate act. The invariant is about what " +
		"errors render, not about what an explicit accessor returns."},
	"credentials.RevealForeign": {Why: "the same, for foreign text: RevealForeign is the one way out of " +
		"Foreign and is what makes the type usable at all. Driving it would assert the type does not work."},
	"credentials.(*ProviderRegistry).Get": {Why: "returns (CredentialProvider, bool) and no error. A " +
		"caller-supplied ID reaches a map lookup and nothing that renders; the duplicate-ID path, which " +
		"does return an error, is driven through Register."},
	"credentials.CapabilitiesOf": {Why: "returns a Capabilities struct of bools; no error, no text, " +
		"nothing that renders."},
	"credentials.(Capabilities).Supports": {Why: "returns a bool."},

	// The interface methods. These were invisible to the first, syntactic
	// derivation, which is why they are spelled out rather than quietly absent: an
	// interface method has no body in this package, so what it returns is the
	// implementing provider's business and not this package's to hold. Every
	// implementation in this repository -- credentials/datadog, credentials/github
	// and credentials/c1 -- states this invariant over itself, which is where it
	// can actually be enforced. A third-party provider's errors are outside every
	// subject that exists, and the candidate ticket for an adopter-runnable
	// conformance helper is the honest way to reach them.
	"credentials.(CredentialProvider).CreateCredential": {Why: "an interface method: no body here. Every " +
		"implementation in this repository drives its own concrete method under its own subject."},
	"credentials.(CredentialProvider).RevokeCredential": {Why: "an interface method: no body here. Driven " +
		"by each implementation's own subject."},
	"credentials.(CredentialProvider).GetCredentialStatus": {Why: "an interface method: no body here. " +
		"Driven by each implementation's own subject."},
	"credentials.(CreateRecoverer).ResolveCreate": {Why: "an interface method with no implementation " +
		"anywhere in this repository yet -- no ported provider has an idempotent upstream create, which " +
		"is why lifecycle.ProviderPolicy.AllowUnrecoverableIssuance exists. When one implements it, that " +
		"concrete method appears in that package's derivation and needs a driver there."},
}

// TestMetadataRendersKeysAndNotValues demonstrates the one exemption inside a
// driver rather than asserting it.
//
// credentials.Metadata renders its sorted key set on purpose: a key is a
// configuration name chosen from this repository's constants, and "which keys did
// the resolver actually supply?" is the useful half of the debugging information.
// The (Metadata).Format driver therefore puts the sentinel only in values. That
// would be a hole if keys did not really render, or if values secretly did, so both
// halves are pinned here.
func TestMetadataRendersKeysAndNotValues(t *testing.T) {
	const (
		valueSentinel = "Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3Qz3"
		keySentinel   = "Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8Wk8"
	)
	m := credentials.Metadata{metadataKeyOne: valueSentinel, keySentinel: "value"}
	got := m.String()

	if !strings.Contains(got, keySentinel) {
		t.Error("Metadata does not render its keys; the (Metadata).Format driver's exemption assumes " +
			"it does, and would be hiding a value leak if it did not")
	}
	if strings.Contains(got, valueSentinel) {
		t.Errorf("Metadata rendered a value: %s", got)
	}
}
