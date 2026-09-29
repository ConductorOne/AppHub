// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"fmt"
	"io"
	"log/slog"
)

// CreateNotDeliveredError reports the worst outcome a vend can have short of
// silence: the provider created a credential upstream and then could not hand
// the material back.
//
// # Why this is a type and not a formatted message
//
// The handle is the only thing standing between "a credential we can retire"
// and "a credential nobody will ever find", so an error that drops it is
// unacceptable. But the handle is also a value the *upstream* chose, and review
// demonstrated what happens when upstream-chosen text is formatted into an
// error: a Datadog response that returned an administrative key in its data.id
// field produced an error string containing that key, from a provider whose
// stated property was that no response content ever reaches an error.
//
// Both requirements are satisfiable at once, but only by a type. The handle
// lives in a Foreign field that no verb renders and no encoder reaches, and
// a caller that wants it asks for it:
//
//	var nd *credentials.CreateNotDeliveredError
//	if errors.As(err, &nd) {
//		// credentials.RevealForeign(nd.PlatformKeyID()) is the handle; revoke with it.
//	}
//
// A caller that does not ask gets a repository constant and nothing else. This is
// the same construction as Secret, applied to values that are not material but
// are still not ours to echo: refusing to render is a property of the type rather
// than a rule every call site has to remember.
//
// # Why the provider ID is not rendered either
//
// The first version of this error named the provider: the ID is a registry key,
// which the comment on the field below asserted was "ours, a constant, and safe
// to render". CredentialProvider.ID returns a string and any provider may
// register, so that was a claim about the callers rather than about the type, and
// review falsified it by constructing this error with a sentinel provider ID and
// reading it back out of Error. Both fields are Foreign now, and the message is a
// constant. An operator who needs to know which provider it was reads ProviderID
// from the error, which is where the information belongs and where the type can
// guarantee it is complete.
//
// # What a caller should do with one
//
// Treat it as credentials/lifecycle treats PhaseFinalize rather than PhaseVend.
// The two situations carry the same information -- the credential is live and the
// handle is in hand -- so the same disposition applies: retry, and if that fails,
// revoke what was just created while it is still possible. It is strictly better
// than an ambiguous vend, because nothing has to be guessed.
//
// Nothing consumes this yet: there is no Issuer implementation until USOSS-5.
// Wiring it into that implementation is what turns a recoverable situation into a
// recovered one.
type CreateNotDeliveredError struct {
	// providerID is the registry key of the reporting provider. It is Foreign
	// rather than string because a provider chooses its own ID: see the "Why the
	// provider ID is not rendered either" section above.
	providerID Foreign
	// platformKeyID came from the provider's response. Foreign means no fmt verb,
	// no encoding/json and no encoding/gob can reach it, and that a rendering path
	// which formats the field leaks nothing -- which is a stronger guarantee than
	// remembering not to print it.
	platformKeyID Foreign
}

// NewCreateNotDelivered builds the error. providerID is the registry key of the
// provider reporting it; platformKeyID is the handle it received before things
// went wrong.
func NewCreateNotDelivered(providerID, platformKeyID string) *CreateNotDeliveredError {
	return &CreateNotDeliveredError{
		providerID:    NewForeign(providerID),
		platformKeyID: NewForeign(platformKeyID),
	}
}

// PlatformKeyID returns the handle of the credential that was created and not
// delivered.
//
// It returns a Foreign and not a string, and that is the second half of the
// deliberate act: RevealForeign is what turns it into text.
//
//	credentials.RevealForeign(nd.PlatformKeyID())
//
// The reason is the one credentials/secret.go gives for Reveal being a package
// function. An exported zero-argument method returning a string is reachable BY
// NAME from text/template, so {{.PlatformKeyID}} on this error would render the
// handle with no reflection and no mistake by the caller -- which is exactly the
// live defect tracked as USOSS-43 in compute.SecretValue. Returning a Foreign
// closes it by construction: a template that calls this method gets a value whose
// every rendering path is a placeholder.
func (e *CreateNotDeliveredError) PlatformKeyID() Foreign { return e.platformKeyID }

// ProviderID returns the provider that created it. Foreign for the same reason as
// PlatformKeyID; the error's own message does not name it either.
func (e *CreateNotDeliveredError) ProviderID() Foreign { return e.providerID }

// createNotDeliveredMsg is the whole of what this error renders. It is a
// constant in this repository, which is the property the error-content invariant
// requires; the provider and the handle are reached through the accessors.
const createNotDeliveredMsg = "credentials: a provider created a credential and could not deliver its material; " +
	"the provider and the handle are available through CreateNotDeliveredError.ProviderID and " +
	"CreateNotDeliveredError.PlatformKeyID, and the credential must be revoked"

// Error says a credential is live and unrecovered, and where to get the two
// values needed to recover it. It contains neither of them.
func (e *CreateNotDeliveredError) Error() string { return createNotDeliveredMsg }

// Unwrap exposes the sentinel so callers can match with errors.Is without
// reaching for the concrete type.
func (e *CreateNotDeliveredError) Unwrap() error { return ErrCreateNotDelivered }

// Format implements fmt.Formatter for every verb, so %v, %+v, %#v and %q are all
// as safe as Error. Without it, %#v prints the struct and the unexported field
// with it.
func (e *CreateNotDeliveredError) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, e.Error())
}

// GoString implements fmt.GoStringer for the same reason.
//
// It is unreachable through fmt: package fmt consults a Formatter before a
// GoStringer, so Format above already answers %#v, and mutating this method to
// leak the handle changes nothing observable. It is kept for a direct caller, and
// the comment says which of the two is load-bearing so a later reader does not
// delete the wrong one.
func (e *CreateNotDeliveredError) GoString() string { return e.Error() }

// LogValue implements slog.LogValuer.
//
// It records the constant message and the two values as Foreign, so a logger that
// walks the group gets the placeholder for each. Emitting them at all is what
// makes it visible in a log that a handle exists to be recovered; emitting them
// as Foreign is what stops the log line from being the disclosure.
func (e *CreateNotDeliveredError) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("error", e.Error()),
		slog.Any("provider", e.providerID),
		slog.Any("platform_key", e.platformKeyID),
	)
}
