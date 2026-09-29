// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import "context"

// Capabilities describes what a provider can actually do.
//
// SupportsDynamic answers one of the six questions a caller has, and the other
// five are otherwise answered by trying: revoke and inspect the error for
// ErrRevokeNotSupported, ask for status and see whether the answer is Unknown.
// That works, but it means a user interface cannot offer only the operations
// that will succeed, and an operator cannot see a provider's shape without
// vending against it.
//
// So capabilities are declared instead -- through an optional interface, not by
// widening CredentialProvider, because widening the interface would break every
// provider for the benefit of one, while an optional interface leaves every
// ported provider compiling untouched.
type Capabilities struct {
	// Dynamic reports whether the provider can vend auto-expiring credentials.
	Dynamic bool
	// Static reports whether the provider can vend long-lived credentials that
	// the platform tracks and tears down itself.
	Static bool
	// Revoke reports whether RevokeCredential can actually revoke upstream. When
	// false, RevokeCredential returns ErrRevokeNotSupported and the credential
	// can only expire on its own -- which bounds the blast radius of a leak to
	// its TTL and nothing shorter.
	Revoke bool
	// Status reports whether GetCredentialStatus consults the provider. When
	// false, the platform's own record is the only source of truth about
	// liveness.
	Status bool
	// Rotate reports whether the provider can replace the material behind an
	// existing credential without changing its identity. Nothing implements this
	// today; a provider that can is how the platform gets real rotation rather
	// than revoke-and-vend-again.
	Rotate bool

	// RecoverCreate reports whether the provider implements CreateRecoverer: it
	// can answer "did a credential get created for this idempotency key, and what
	// is its handle?" after a vend whose outcome was never observed.
	//
	// Declaring it does not make it so. CapabilitiesOf clears this bit for any
	// provider that does not actually implement CreateRecoverer, because a
	// capability a provider can claim without being able to honor it is not a
	// safety mechanism -- it is a way of getting past one.
	//
	// Without it, a vend that times out leaves a credential that may exist and
	// that the platform has no handle for -- it can be named as unmanaged, but it
	// cannot be revoked. This is the capability that decides whether the lifecycle
	// layer can honestly claim to close that window or only to see it.
	RecoverCreate bool
}

// CreateRecoverer is the optional interface a provider implements to make an
// ambiguous vend resolvable.
//
// It exists because CreateCredential's result is the only place a provider hands
// back the handle needed to revoke, so a vend whose response is lost leaves the
// platform holding an idempotency key and nothing else. GetCredentialStatus
// cannot help: it takes a platform key ID the caller never received.
type CreateRecoverer interface {
	// ResolveCreate reports what became of the vend identified by an idempotency
	// key. It returns the original CreateResult -- including the handle, and,
	// where the upstream permits it, the material -- or ErrCreateNotFound if
	// nothing was created.
	//
	// Implementations must not create anything. This is a lookup, and a
	// "resolve" that mints on a miss would turn a reconciliation pass into a
	// vending loop.
	ResolveCreate(ctx context.Context, idempotencyKey string, metadata Metadata) (*CreateResult, error)
}

// CapabilityReporter is the optional interface a provider implements to declare
// its capabilities. Discovered by type assertion, so implementing it is
// additive.
type CapabilityReporter interface {
	Capabilities() Capabilities
}

// CapabilitiesOf returns what p declares, or an inference for a provider that
// declares nothing.
//
// The inference is not uniformly conservative, because "conservative" points in
// opposite directions depending on what being wrong costs:
//
//   - Revoke and Status are inferred true. Attempting a revoke that is not
//     supported costs one call and an ErrRevokeNotSupported that the lifecycle
//     already handles; skipping a revoke that would have worked leaves a live
//     credential.
//   - Static is inferred false. A static credential is one the platform must
//     tear down itself, so issuing one against a provider whose real capabilities
//     are unknown risks a credential nothing can revoke and nothing can expire.
//     A provider that genuinely vends static credentials says so by implementing
//     CapabilityReporter, which is a reviewable line of code rather than a guess.
//   - Rotate and RecoverCreate are inferred false, because claiming either
//     wrongly means claiming an action happened that did not: a credential
//     reported as rotated but still holding its old material, or an ambiguous
//     vend reported as resolvable when nothing can resolve it.
//
// The earlier version of this function inferred Static and Revoke both true,
// which is the most dangerous combination available and exactly the wrong
// direction to fail.
//
// # Declarations are checked where they can be
//
// RecoverCreate is the one capability with a corresponding Go interface, so it is
// the one capability a declaration cannot lie about: this function clears the bit
// for any provider that does not implement CreateRecoverer. That matters because
// RecoverCreate is what lifecycle.CheckIssuable consults to decide whether an
// ambiguous vend will be resolvable, and a provider that declares it without
// implementing it would be admitted as recoverable and then be unable to recover --
// exactly the state the write-ahead ordering exists to prevent.
//
// The other bits have no interface to check against: every provider has a
// RevokeCredential method whether or not it works, so Revoke can only ever be a
// claim. Where a claim cannot be verified, the fallbacks above are chosen so that
// being lied to is survivable.
func CapabilitiesOf(p CredentialProvider) Capabilities {
	var caps Capabilities
	if r, ok := p.(CapabilityReporter); ok {
		caps = r.Capabilities()
	} else {
		caps = Capabilities{
			Dynamic:       p.SupportsDynamic(),
			Static:        false,
			Revoke:        true,
			Status:        true,
			Rotate:        false,
			RecoverCreate: false,
		}
	}
	if _, ok := p.(CreateRecoverer); !ok {
		caps.RecoverCreate = false
	}
	return caps
}

// Supports reports whether the provider can vend the given credential type.
func (c Capabilities) Supports(t CredentialType) bool {
	switch t {
	case CredentialTypeDynamic:
		return c.Dynamic
	case CredentialTypeStatic:
		return c.Static
	default:
		return false
	}
}
