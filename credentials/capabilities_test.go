// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"context"
	"testing"

	"github.com/conductorone/apphub/credentials"
)

// stubProvider implements the interface and nothing else, standing in for the
// four ported providers that will never declare capabilities.
type stubProvider struct {
	id      string
	dynamic bool
}

func (p stubProvider) ID() string   { return p.id }
func (p stubProvider) Name() string { return p.id }
func (p stubProvider) CreateCredential(context.Context, credentials.CreateRequest) (*credentials.CreateResult, error) {
	return &credentials.CreateResult{PlatformKeyID: "key-1"}, nil
}
func (p stubProvider) RevokeCredential(context.Context, string, credentials.Metadata) error {
	return credentials.ErrRevokeNotSupported
}
func (p stubProvider) GetCredentialStatus(context.Context, string, credentials.Metadata) (credentials.CredentialStatus, error) {
	return credentials.CredentialStatusUnknown, nil
}
func (p stubProvider) SupportsDynamic() bool { return p.dynamic }

// declaringProvider also declares its shape, as a c1 or AWS provider would. It does
// NOT implement CreateRecoverer.
type declaringProvider struct {
	stubProvider
	caps credentials.Capabilities
}

func (p declaringProvider) Capabilities() credentials.Capabilities { return p.caps }

// recoveringProvider declares its shape and actually implements CreateRecoverer.
type recoveringProvider struct {
	declaringProvider
}

func (p recoveringProvider) ResolveCreate(context.Context, string, credentials.Metadata) (*credentials.CreateResult, error) {
	return nil, credentials.ErrCreateNotFound
}

// TestCapabilitiesOfInfersSafelyForUndeclaredProvider is a regression test: the
// earlier inference returned Static and Revoke both true, which is the most
// dangerous combination on offer -- issue a credential the platform must tear down
// itself, through a provider that may not be able to.
func TestCapabilitiesOfInfersSafelyForUndeclaredProvider(t *testing.T) {
	got := credentials.CapabilitiesOf(stubProvider{id: "datadog", dynamic: false})
	want := credentials.Capabilities{
		Dynamic: false, Static: false, Revoke: true, Status: true, Rotate: false, RecoverCreate: false,
	}
	if got != want {
		t.Errorf("CapabilitiesOf() = %+v, want %+v", got, want)
	}
	if got.Supports(credentials.CredentialTypeStatic) {
		t.Error("an undeclared provider must not be assumed to vend static credentials")
	}
	if !got.Revoke {
		t.Error("revoke should be inferred true: attempting an unsupported revoke is cheap, skipping a possible one is not")
	}
	if got.RecoverCreate {
		t.Error("RecoverCreate must not be inferred true; nothing could resolve an ambiguous vend")
	}
}

func TestCapabilitiesOfPrefersDeclaration(t *testing.T) {
	declared := credentials.Capabilities{Dynamic: true, Static: true, Revoke: true, Status: true}
	p := declaringProvider{
		stubProvider: stubProvider{id: "example", dynamic: true},
		caps:         declared,
	}
	if got := credentials.CapabilitiesOf(p); got != declared {
		t.Errorf("CapabilitiesOf() = %+v, want the declaration %+v", got, declared)
	}

	noStatic := declaringProvider{
		stubProvider: stubProvider{id: "example", dynamic: true},
		caps:         credentials.Capabilities{Dynamic: true, Static: false, Revoke: true},
	}
	if credentials.CapabilitiesOf(noStatic).Supports(credentials.CredentialTypeStatic) {
		t.Error("a provider that declares Static: false should not support static")
	}
}

// TestCapabilitiesOfRefusesAnUnbackedRecoverClaim is the regression test for a
// capability a provider could claim without being able to honor it. The earlier
// version of this file asserted the opposite -- it required a false
// RecoverCreate: true declaration to survive -- which is how the bypass reached
// CheckIssuable: such a provider was admitted as recoverable and then could not
// resolve anything, which is precisely the state the write-ahead ordering exists to
// prevent.
func TestCapabilitiesOfRefusesAnUnbackedRecoverClaim(t *testing.T) {
	claimant := declaringProvider{
		stubProvider: stubProvider{id: "liar", dynamic: true},
		caps:         credentials.Capabilities{Dynamic: true, Revoke: true, RecoverCreate: true},
	}
	if _, ok := interface{}(claimant).(credentials.CreateRecoverer); ok {
		t.Fatal("test setup: claimant must not implement CreateRecoverer")
	}
	if credentials.CapabilitiesOf(claimant).RecoverCreate {
		t.Error("a declared RecoverCreate survived without a CreateRecoverer implementation")
	}

	// The same declaration, backed by the interface, is honored.
	honest := recoveringProvider{declaringProvider: claimant}
	if !credentials.CapabilitiesOf(honest).RecoverCreate {
		t.Error("a declared RecoverCreate backed by CreateRecoverer was cleared")
	}

	// And implementing the interface does not grant the capability on its own: the
	// provider still has to declare it, so an implementation added for another
	// reason cannot silently change admission.
	silent := recoveringProvider{
		declaringProvider: declaringProvider{
			stubProvider: stubProvider{id: "silent", dynamic: true},
			caps:         credentials.Capabilities{Dynamic: true, Revoke: true},
		},
	}
	if credentials.CapabilitiesOf(silent).RecoverCreate {
		t.Error("RecoverCreate was inferred from the interface alone, without a declaration")
	}
}

func TestRegistryRefusesDuplicateID(t *testing.T) {
	reg := credentials.NewProviderRegistry()
	if err := reg.Register(stubProvider{id: "github"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(stubProvider{id: "github"}); err == nil {
		t.Error("Register accepted a duplicate ID; wiring order would decide which provider wins")
	}
	if _, ok := reg.Get("github"); !ok {
		t.Error("Get did not find the registered provider")
	}
	if _, ok := reg.Get("datadog"); ok {
		t.Error("Get found a provider that was never registered")
	}
	if n := len(reg.List()); n != 1 {
		t.Errorf("List() returned %d providers, want 1", n)
	}
}

// TestRegistryIsEmptyWithoutRegistration is the c1-optional property expressed as
// a test: a registry nobody hands a provider to has none, so a deployment that
// registers only AWS-native providers cannot reach ConductorOne even by mistake.
func TestRegistryIsEmptyWithoutRegistration(t *testing.T) {
	if n := len(credentials.NewProviderRegistry().List()); n != 0 {
		t.Errorf("a fresh registry has %d providers, want 0", n)
	}
}
